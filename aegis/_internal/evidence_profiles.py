"""Construction and verification of v2 evidence content checksums."""

from __future__ import annotations

import hashlib
import hmac
import re
from enum import Enum

from aegis._internal.canonicalization import (
    CANONICALIZATION_PROFILE_V2,
    CanonicalizationError,
    canonicalize_v2,
)
from aegis._internal.compiled_policy import JsonValue
from aegis._internal.errors import AIGCError


_CHECKSUM_RE = re.compile(r"^[a-f0-9]{64}$")
_EXCLUDED_CHECKSUM_FIELDS = frozenset(
    {"checksum", "signature", "signature_metadata", "signature_status"}
)


class ContentIntegrity(str, Enum):
    """Closed content-integrity outcomes shared by evidence verification."""

    VALID = "valid"
    INVALID = "invalid"
    LEGACY = "legacy"
    NOT_EVALUATED = "not_evaluated"


class EvidenceProfileError(AIGCError):
    """Raised when evidence does not declare exactly one supported profile."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message, code=code)


def _require_v2_declaration(artifact: object) -> dict[str, object]:
    if type(artifact) is not dict:
        raise EvidenceProfileError(
            "Evidence must be a plain JSON object",
            code="EVIDENCE_PROFILE_MISMATCH",
        )
    audit_v2 = artifact.get("audit_schema_version") == "2.0"
    workflow_v2 = artifact.get("workflow_schema_version") == "2.0"
    exact_discriminators = (
        audit_v2 ^ workflow_v2
        and set(artifact).intersection(
            {"audit_schema_version", "workflow_schema_version"}
        )
        == ({"audit_schema_version"} if audit_v2 else {"workflow_schema_version"})
    )
    if (
        not exact_discriminators
        or "schema_version" in artifact
        or artifact.get("canonicalization_profile")
        != CANONICALIZATION_PROFILE_V2
    ):
        raise EvidenceProfileError(
            "Evidence does not declare the required v2 profile",
            code="EVIDENCE_PROFILE_MISMATCH",
        )
    return artifact


def _checksum_payload(artifact: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in artifact.items()
        if key not in _EXCLUDED_CHECKSUM_FIELDS
    }


def build_content_checksum_v2(
    unsigned_artifact: object,
) -> dict[str, JsonValue]:
    """Normalize and checksum one already-declared unsigned v2 artifact."""
    artifact = _require_v2_declaration(unsigned_artifact)
    supplied = sorted(_EXCLUDED_CHECKSUM_FIELDS.intersection(artifact))
    if supplied:
        raise EvidenceProfileError(
            "Unsigned evidence contains caller-supplied finalization fields",
            code="EVIDENCE_FINALIZATION_FIELDS_PRESENT",
        )
    canonicalized = canonicalize_v2(artifact)
    normalized = canonicalized.value
    if type(normalized) is not dict:  # pragma: no cover - guarded above
        raise EvidenceProfileError(
            "Evidence must normalize to an object",
            code="EVIDENCE_PROFILE_MISMATCH",
        )
    checksum = hashlib.sha256(canonicalized.data).hexdigest()
    return {**normalized, "checksum": checksum}


def verify_content_checksum_v2(finalized_artifact: object) -> ContentIntegrity:
    """Return checksum validity without mutating or stripping the artifact."""
    try:
        artifact = _require_v2_declaration(finalized_artifact)
        stored_checksum = artifact.get("checksum")
        if (
            not isinstance(stored_checksum, str)
            or _CHECKSUM_RE.fullmatch(stored_checksum) is None
        ):
            return ContentIntegrity.INVALID
        payload = _checksum_payload(artifact)
        recomputed = hashlib.sha256(canonicalize_v2(payload).data).hexdigest()
    except (CanonicalizationError, EvidenceProfileError):
        return ContentIntegrity.INVALID
    return (
        ContentIntegrity.VALID
        if hmac.compare_digest(recomputed, stored_checksum)
        else ContentIntegrity.INVALID
    )
