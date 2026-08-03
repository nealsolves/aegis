"""Host-owned chain placement contract consumed by evidence finalization."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from aegis._internal.errors import ChainLinkError


_MAX_LINK_ID_LENGTH = 512
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_COORDINATE_FIELDS = frozenset(
    {
        "chain_id",
        "chain_index",
        "previous_audit_checksum",
        "reservation_id",
    }
)


def _is_bounded_identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value) <= _MAX_LINK_ID_LENGTH
    )


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class ChainLinkRequest:
    """Bounded invocation identity supplied to one host reservation call."""

    attempt_id: int
    artifact_type: Literal["invocation"]
    correlation_id: str | None

    def __post_init__(self) -> None:
        if type(self.attempt_id) is not int or self.attempt_id < 0:
            raise ChainLinkError(
                "Chain link attempt identity is invalid",
                code="CHAIN_LINK_REQUEST_INVALID",
            )
        if self.artifact_type != "invocation":
            raise ChainLinkError(
                "Only invocation evidence may join an invocation chain",
                code="CHAIN_ARTIFACT_INELIGIBLE",
            )
        if self.correlation_id is not None and not _is_bounded_identifier(
            self.correlation_id
        ):
            raise ChainLinkError(
                "Chain link correlation identity is invalid",
                code="CHAIN_LINK_REQUEST_INVALID",
            )


@dataclass(frozen=True, slots=True)
class ChainCoordinates:
    """Complete chain placement covered by content checksum and signature."""

    chain_id: str
    chain_index: int
    previous_audit_checksum: str | None
    reservation_id: str

    def __post_init__(self) -> None:
        if (
            not _is_bounded_identifier(self.chain_id)
            or type(self.chain_index) is not int
            or self.chain_index < 0
            or not _is_bounded_identifier(self.reservation_id)
        ):
            raise ChainLinkError(
                "Invalid chain coordinates",
                code="CHAIN_COORDINATES_INVALID",
            )
        if self.chain_index == 0 and self.previous_audit_checksum is not None:
            raise ChainLinkError(
                "First entry must have no previous checksum",
                code="CHAIN_PREVIOUS_INVALID",
            )
        if self.chain_index > 0 and not _is_sha256(
            self.previous_audit_checksum
        ):
            raise ChainLinkError(
                "Previous v2 content checksum required",
                code="CHAIN_PREVIOUS_INVALID",
            )


class ChainReservation(Protocol):
    """One placement transaction with idempotent terminal operations."""

    @property
    def coordinates(self) -> ChainCoordinates: ...

    def commit(self, content_checksum: str) -> None: ...

    def abort(self) -> None: ...


class ChainLinker(Protocol):
    """Synchronous host boundary for atomic chain placement."""

    def reserve(
        self,
        request: ChainLinkRequest,
        *,
        timeout: float,
    ) -> ChainReservation: ...

    def reconcile(
        self,
        reservation_id: str,
        observed_artifact: Mapping[str, Any] | None,
    ) -> None: ...


def validate_chain_coordinates(value: object) -> ChainCoordinates:
    """Return one complete coordinate value or fail closed with a typed error."""
    if isinstance(value, ChainCoordinates):
        return value
    if not isinstance(value, Mapping) or set(value) != _COORDINATE_FIELDS:
        raise ChainLinkError(
            "Chain coordinates must be one complete closed object",
            code="CHAIN_COORDINATES_INVALID",
        )
    try:
        return ChainCoordinates(
            chain_id=value["chain_id"],
            chain_index=value["chain_index"],
            previous_audit_checksum=value["previous_audit_checksum"],
            reservation_id=value["reservation_id"],
        )
    except ChainLinkError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise ChainLinkError(
            "Chain coordinates contain invalid field values",
            code="CHAIN_COORDINATES_INVALID",
        ) from exc
