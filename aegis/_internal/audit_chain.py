"""Tamper-evident audit chain construction and compatibility verification."""

from __future__ import annotations

import logging
import uuid
import warnings
from typing import Any

from aegis._internal.evidence_profiles import (
    EvidenceProfileError,
    build_content_checksum_v2,
)
from aegis._internal.verification import (
    ChainVerificationReport,
    verify_chain_detailed,
)


logger = logging.getLogger("aegis.audit_chain")


class AuditChain:
    """Build a single-process chain whose links are v2 content checksums."""

    def __init__(self, chain_id: str | None = None) -> None:
        self._chain_id = chain_id or str(uuid.uuid4())
        self._artifacts: list[dict[str, Any]] = []
        self._last_checksum: str | None = None

    @property
    def chain_id(self) -> str:
        return self._chain_id

    @property
    def length(self) -> int:
        return len(self._artifacts)

    def append(self, artifact: dict[str, Any]) -> dict[str, Any]:
        """Attach chain coordinates before rebuilding the v2 content checksum."""
        if artifact.get("signature") is not None or "signature_metadata" in artifact:
            raise EvidenceProfileError(
                "A finalized signature cannot be moved into a chain",
                code="EVIDENCE_FINALIZATION_FIELDS_PRESENT",
            )
        unsigned = {
            key: value
            for key, value in artifact.items()
            if key not in {"checksum", "signature", "signature_metadata"}
        }
        unsigned.update(
            chain_id=self._chain_id,
            chain_index=len(self._artifacts),
            previous_audit_checksum=self._last_checksum,
        )
        finalized = build_content_checksum_v2(unsigned)
        finalized["signature"] = None
        artifact.clear()
        artifact.update(finalized)
        self._last_checksum = artifact["checksum"]
        self._artifacts.append(artifact)
        logger.debug(
            "Artifact appended to chain %s at index %d",
            self._chain_id,
            len(self._artifacts) - 1,
        )
        return artifact

    def verify_detailed(self) -> ChainVerificationReport:
        """Return the independent typed verification axes for this chain."""
        return verify_chain_detailed(self._artifacts)

    def verify(self) -> tuple[bool, list[str]]:
        """Return legacy internal-validity semantics for this chain instance."""
        report = self.verify_detailed()
        messages = [error.message for error in report.errors]
        for index, artifact in enumerate(self._artifacts):
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
