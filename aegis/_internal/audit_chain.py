"""Host-owned in-memory chain linker and compatibility verification."""

from __future__ import annotations

import logging
import math
import re
import threading
import time
import uuid
import warnings
from collections.abc import Mapping
from typing import Any, Literal

from aegis._internal.chain_linker import (
    ChainCoordinates,
    ChainLinkRequest,
)
from aegis._internal.errors import ChainLinkError
from aegis._internal.evidence_finalizer import finalize_legacy_invocation_artifact
from aegis._internal.evidence_profiles import (
    ContentIntegrity,
    EvidenceProfileError,
    verify_content_checksum_v2,
)
from aegis._internal.verification import (
    ChainVerificationReport,
    verify_chain_detailed,
)


logger = logging.getLogger("aegis.audit_chain")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_MAX_CHAIN_ID_LENGTH = 512


class _AuditChainReservation:
    """One reservation whose transitions are serialized by its owner."""

    __slots__ = ("_owner", "coordinates", "state", "content_checksum")

    def __init__(
        self,
        owner: AuditChain,
        coordinates: ChainCoordinates,
    ) -> None:
        self._owner = owner
        self.coordinates = coordinates
        self.state: Literal["RESERVED", "COMMITTED", "ABORTED"] = "RESERVED"
        self.content_checksum: str | None = None

    def commit(self, content_checksum: str) -> None:
        self._owner._commit(self, content_checksum)

    def abort(self) -> None:
        self._owner._abort(self)


class AuditChain:
    """Single-process linker; it provides no crash-persistence guarantee."""

    def __init__(self, chain_id: str | None = None) -> None:
        selected_id = str(uuid.uuid4()) if chain_id is None else chain_id
        if (
            not isinstance(selected_id, str)
            or not selected_id.strip()
            or len(selected_id) > _MAX_CHAIN_ID_LENGTH
        ):
            raise ChainLinkError(
                "Audit chain identity is invalid",
                code="CHAIN_COORDINATES_INVALID",
            )
        self._chain_id = selected_id
        self._condition = threading.Condition()
        self._next_index = 0
        self._last_checksum: str | None = None
        self._outstanding: _AuditChainReservation | None = None
        self._reservations: dict[str, _AuditChainReservation] = {}
        self._artifacts: list[dict[str, Any]] = []

    @property
    def chain_id(self) -> str:
        return self._chain_id

    @property
    def length(self) -> int:
        with self._condition:
            return self._next_index

    @staticmethod
    def _validate_timeout(timeout: object) -> float:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ChainLinkError(
                "Chain reservation timeout is invalid",
                code="CHAIN_LINK_TIMEOUT_INVALID",
            )
        return float(timeout)

    def reserve(
        self,
        request: ChainLinkRequest,
        *,
        timeout: float,
    ) -> _AuditChainReservation:
        """Reserve the next coordinate or fail at the explicit deadline."""
        if not isinstance(request, ChainLinkRequest):
            raise ChainLinkError(
                "Chain link request is invalid",
                code="CHAIN_LINK_REQUEST_INVALID",
            )
        bounded_timeout = self._validate_timeout(timeout)
        deadline = time.monotonic() + bounded_timeout
        with self._condition:
            while self._outstanding is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ChainLinkError(
                        "Chain reservation timed out",
                        code="CHAIN_LINK_TIMEOUT",
                    )
                self._condition.wait(remaining)
            coordinates = ChainCoordinates(
                chain_id=self._chain_id,
                chain_index=self._next_index,
                previous_audit_checksum=self._last_checksum,
                reservation_id=uuid.uuid4().hex,
            )
            reservation = _AuditChainReservation(self, coordinates)
            self._outstanding = reservation
            self._reservations[coordinates.reservation_id] = reservation
            return reservation

    @staticmethod
    def _validate_content_checksum(content_checksum: object) -> str:
        if (
            not isinstance(content_checksum, str)
            or _SHA256_RE.fullmatch(content_checksum) is None
        ):
            raise ChainLinkError(
                "Committed chain link must use a v2 content checksum",
                code="CHAIN_CONTENT_CHECKSUM_INVALID",
            )
        return content_checksum

    def _commit(
        self,
        reservation: _AuditChainReservation,
        content_checksum: object,
    ) -> None:
        checksum = self._validate_content_checksum(content_checksum)
        with self._condition:
            if reservation.state == "COMMITTED":
                if reservation.content_checksum == checksum:
                    return
                raise ChainLinkError(
                    "Reservation was committed with another checksum",
                    code="CHAIN_RESERVATION_CONFLICT",
                )
            if reservation.state == "ABORTED":
                raise ChainLinkError(
                    "Aborted reservation cannot be committed",
                    code="CHAIN_RESERVATION_CONFLICT",
                )
            if self._outstanding is not reservation:
                raise ChainLinkError(
                    "Reservation is not the active chain placement",
                    code="CHAIN_RESERVATION_CONFLICT",
                )
            reservation.state = "COMMITTED"
            reservation.content_checksum = checksum
            self._last_checksum = checksum
            self._next_index += 1
            self._outstanding = None
            self._condition.notify_all()

    def _abort(self, reservation: _AuditChainReservation) -> None:
        with self._condition:
            if reservation.state == "ABORTED":
                return
            if reservation.state == "COMMITTED":
                raise ChainLinkError(
                    "Committed reservation cannot be aborted",
                    code="CHAIN_RESERVATION_CONFLICT",
                )
            if self._outstanding is not reservation:
                raise ChainLinkError(
                    "Reservation is not the active chain placement",
                    code="CHAIN_RESERVATION_CONFLICT",
                )
            reservation.state = "ABORTED"
            self._outstanding = None
            self._condition.notify_all()

    def reconcile(
        self,
        reservation_id: str,
        observed_artifact: Mapping[str, Any] | None,
    ) -> None:
        """Resolve an emit/commit crash window from host-observed sink state."""
        if not isinstance(reservation_id, str):
            raise ChainLinkError(
                "Reservation identity is invalid",
                code="CHAIN_RESERVATION_NOT_FOUND",
            )
        with self._condition:
            reservation = self._reservations.get(reservation_id)
        if reservation is None:
            raise ChainLinkError(
                "Reservation identity is unknown",
                code="CHAIN_RESERVATION_NOT_FOUND",
            )
        if observed_artifact is None:
            reservation.abort()
            return
        if type(observed_artifact) is not dict:
            raise ChainLinkError(
                "Observed artifact contradicts the reservation",
                code="CHAIN_RECONCILIATION_FAILED",
            )
        coordinates = reservation.coordinates
        matches = (
            observed_artifact.get("reservation_id") == coordinates.reservation_id
            and observed_artifact.get("chain_id") == coordinates.chain_id
            and observed_artifact.get("chain_index") == coordinates.chain_index
            and observed_artifact.get("previous_audit_checksum")
            == coordinates.previous_audit_checksum
            and verify_content_checksum_v2(observed_artifact)
            is ContentIntegrity.VALID
        )
        checksum = observed_artifact.get("checksum")
        if not matches or not isinstance(checksum, str):
            raise ChainLinkError(
                "Observed artifact contradicts the reservation",
                code="CHAIN_RECONCILIATION_FAILED",
            )
        reservation.commit(checksum)

    def append(self, artifact: dict[str, Any]) -> dict[str, Any]:
        """Deprecated offline bridge that finalizes through this linker."""
        warnings.warn(
            "AuditChain.append() is deprecated; configure AuditChain as the "
            "AEGIS chain_linker so coordinates are reserved during enforcement.",
            DeprecationWarning,
            stacklevel=2,
        )
        if artifact.get("signature") is not None or "signature_metadata" in artifact:
            raise EvidenceProfileError(
                "A finalized signature cannot be moved into a chain",
                code="EVIDENCE_FINALIZATION_FIELDS_PRESENT",
            )
        detached = {
            key: value
            for key, value in artifact.items()
            if key
            not in {
                "checksum",
                "signature",
                "signature_metadata",
                "signature_status",
                "chain_id",
                "chain_index",
                "previous_audit_checksum",
                "reservation_id",
            }
        }
        finalized = finalize_legacy_invocation_artifact(
            detached,
            entry_point="audit_chain.append",
            mode="offline_chain",
            sink=None,
            failure_mode="raise",
            chain_linker=self,
        )
        artifact.clear()
        artifact.update(finalized)
        with self._condition:
            self._artifacts.append(artifact)
            self._artifacts.sort(key=lambda item: item["chain_index"])
        logger.debug(
            "Artifact appended to chain %s at index %d",
            self._chain_id,
            artifact["chain_index"],
        )
        return artifact

    def verify_detailed(self) -> ChainVerificationReport:
        """Return independent typed verification axes for stored bridge output."""
        with self._condition:
            artifacts = list(self._artifacts)
        return verify_chain_detailed(artifacts)

    def verify(self) -> tuple[bool, list[str]]:
        """Return legacy internal-validity semantics for stored bridge output."""
        report = self.verify_detailed()
        messages = [error.message for error in report.errors]
        with self._condition:
            artifacts = list(self._artifacts)
        for index, artifact in enumerate(artifacts):
            if artifact.get("chain_id") != self._chain_id:
                messages.append(f"Chain index {index}: chain_id mismatch")
            if artifact.get("chain_index") != index and not any(
                "chain_index" in message for message in messages
            ):
                messages.append(
                    f"Chain index {index}: expected chain_index={index}, "
                    f"got {artifact.get('chain_index')}"
                )
        valid = report.internal_valid and not messages
        if not valid:
            logger.warning(
                "Chain %s verification failed: %d error(s)",
                self._chain_id,
                len(messages),
            )
        return valid, messages


def verify_chain(artifacts: object) -> tuple[bool, list[str]]:
    """Deprecated wrapper; ``True`` implies neither authenticity nor completeness."""
    warnings.warn(
        "verify_chain() is deprecated; use verify_chain_detailed(). Its boolean "
        "covers only content integrity and chain continuity, not signature, "
        "anchor, or completeness.",
        DeprecationWarning,
        stacklevel=2,
    )
    report = verify_chain_detailed(artifacts)
    return report.internal_valid, [error.message for error in report.errors]
