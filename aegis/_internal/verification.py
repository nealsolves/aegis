"""Typed, independent verification axes for AEGIS evidence chains."""

from __future__ import annotations

import re
import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Sequence

from aegis._internal.evidence_profiles import (
    ContentIntegrity,
    verify_content_checksum_v2,
)
from aegis._internal.external_signing import verify_artifact_detailed
from aegis._internal.legacy import LegacyFeature, is_legacy_authorized
from aegis._internal.signature_models import AnchorStatus, SignatureStatus
from aegis._internal.utils import canonical_json_bytes


_HEX64_RE = re.compile(r"^[a-f0-9]{64}$")
_CHAIN_FIELDS = frozenset(
    {"chain_id", "chain_index", "previous_audit_checksum"}
)


class ChainContinuity(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNCHAINED = "unchained"
    NOT_EVALUATED = "not_evaluated"


class Completeness(str, Enum):
    UNPROVEN = "unproven"
    CHECKPOINT_PROVEN = "checkpoint_proven"
    CONTRADICTED = "contradicted"


@dataclass(frozen=True, slots=True)
class VerificationError:
    code: str
    message: str
    index: int | None = None


@dataclass(frozen=True, slots=True)
class ChainVerificationReport:
    content_integrity: ContentIntegrity
    chain_continuity: ChainContinuity
    signature_status: SignatureStatus
    anchor_status: AnchorStatus
    completeness: Completeness
    errors: tuple[VerificationError, ...] = ()

    @property
    def internal_valid(self) -> bool:
        """Whether evaluated content and continuity are internally valid."""
        return self.content_integrity in {
            ContentIntegrity.VALID,
            ContentIntegrity.NOT_EVALUATED,
        } and self.chain_continuity in {
            ChainContinuity.VALID,
            ChainContinuity.UNCHAINED,
            ChainContinuity.NOT_EVALUATED,
        }


def _error(code: str, message: str, index: int | None = None) -> VerificationError:
    return VerificationError(code=code, message=message, index=index)


def _verify_content(
    artifacts: Sequence[object], errors: list[VerificationError]
) -> ContentIntegrity:
    if not artifacts:
        return ContentIntegrity.NOT_EVALUATED
    result = ContentIntegrity.VALID
    for index, artifact in enumerate(artifacts):
        status = verify_content_checksum_v2(artifact)
        if status is not ContentIntegrity.VALID:
            result = ContentIntegrity.INVALID
            errors.append(
                _error(
                    "CONTENT_CHECKSUM_INVALID",
                    f"Index {index}: artifact checksum mismatch or invalid v2 profile",
                    index,
                )
            )
    return result


def _chain_fields_state(artifact: dict[str, Any]) -> int:
    present = _CHAIN_FIELDS.intersection(artifact)
    if not present:
        return 0
    if present == _CHAIN_FIELDS:
        return 2
    return 1


def _verify_continuity(
    artifacts: Sequence[object],
    errors: list[VerificationError],
    *,
    legacy_mode: bool = False,
) -> ChainContinuity:
    if not artifacts:
        return ChainContinuity.NOT_EVALUATED
    if any(type(artifact) is not dict for artifact in artifacts):
        errors.append(
            _error("ARTIFACT_NOT_OBJECT", "Chain entries must be JSON objects")
        )
        return ChainContinuity.INVALID

    typed_artifacts: Sequence[dict[str, Any]] = artifacts  # type: ignore[assignment]
    if any(
        any(type(key) is not str for key in artifact)
        for artifact in typed_artifacts
    ):
        errors.append(
            _error("ARTIFACT_KEY_INVALID", "Artifact object keys must be strings")
        )
        return ChainContinuity.INVALID
    states = [_chain_fields_state(artifact) for artifact in typed_artifacts]
    if states == [0] * len(states):
        return ChainContinuity.UNCHAINED
    if any(state != 2 for state in states):
        errors.append(
            _error(
                "CHAIN_COORDINATES_INCOMPLETE",
                "Chain coordinates must be complete on every supplied artifact",
            )
        )
        return ChainContinuity.INVALID

    continuity = ChainContinuity.VALID
    first = typed_artifacts[0]
    chain_id = first["chain_id"]
    first_index = first["chain_index"]
    if type(chain_id) is not str or not chain_id:
        errors.append(_error("CHAIN_ID_INVALID", "Index 0: chain_id is invalid", 0))
        continuity = ChainContinuity.INVALID
    if type(first_index) is not int or first_index < 0:
        errors.append(
            _error("CHAIN_INDEX_INVALID", "Index 0: chain_index is invalid", 0)
        )
        return ChainContinuity.INVALID

    first_previous = first["previous_audit_checksum"]
    if first_index == 0:
        if first_previous is not None:
            errors.append(
                _error(
                    "CHAIN_LINK_MISMATCH",
                    "Index 0: previous_audit_checksum must be null",
                    0,
                )
            )
            continuity = ChainContinuity.INVALID
    elif (
        type(first_previous) is not str
        or _HEX64_RE.fullmatch(first_previous) is None
    ):
        errors.append(
            _error(
                "CHAIN_LINK_INVALID",
                f"Index 0: chain_index={first_index} supplied prefix requires a valid previous_audit_checksum",
                0,
            )
        )
        continuity = ChainContinuity.INVALID

    for offset, artifact in enumerate(typed_artifacts):
        expected_index = first_index + offset
        if artifact["chain_index"] != expected_index:
            errors.append(
                _error(
                    "CHAIN_INDEX_MISMATCH",
                    f"Index {offset}: expected chain_index={expected_index}, got {artifact['chain_index']}",
                    offset,
                )
            )
            continuity = ChainContinuity.INVALID
        if artifact["chain_id"] != chain_id:
            errors.append(
                _error(
                    "CHAIN_ID_MISMATCH",
                    f"Index {offset}: chain_id mismatch",
                    offset,
                )
            )
            continuity = ChainContinuity.INVALID
        if offset:
            previous = typed_artifacts[offset - 1]
            expected_previous = previous.get("checksum")
            if legacy_mode and not expected_previous:
                expected_previous = hashlib.sha256(
                    canonical_json_bytes(previous)
                ).hexdigest()
            if artifact["previous_audit_checksum"] != expected_previous:
                errors.append(
                    _error(
                        "CHAIN_LINK_MISMATCH",
                        f"Index {offset}: previous_audit_checksum mismatch (broken link)",
                        offset,
                    )
                )
                continuity = ChainContinuity.INVALID
    return continuity


def _legacy_evidence_kind(artifacts: Sequence[object]) -> LegacyFeature | None:
    """Return the exact legacy schema feature for a homogeneous 1.x set."""
    if not artifacts or any(type(artifact) is not dict for artifact in artifacts):
        return None
    kinds: set[LegacyFeature] = set()
    for artifact in artifacts:
        assert isinstance(artifact, dict)
        audit_version = artifact.get("audit_schema_version")
        workflow_version = artifact.get("workflow_schema_version")
        if (
            isinstance(audit_version, str)
            and audit_version.startswith("1.")
            and "workflow_schema_version" not in artifact
        ):
            kinds.add(LegacyFeature.AUDIT_SCHEMA_1X_VERIFICATION)
        elif (
            isinstance(workflow_version, str)
            and workflow_version.startswith("1.")
            and "audit_schema_version" not in artifact
        ):
            kinds.add(LegacyFeature.WORKFLOW_SCHEMA_1X_VERIFICATION)
        else:
            return None
        checksum = artifact.get("checksum")
        if checksum is not None and checksum != "":
            return None
        profile = artifact.get("canonicalization_profile")
        if profile is not None and profile != "aegis-canonical-json-v1":
            return None
    return next(iter(kinds)) if len(kinds) == 1 else None


_SIGNATURE_PRIORITY = {
    SignatureStatus.INVALID: 5,
    SignatureStatus.REVOKED: 4,
    SignatureStatus.UNKNOWN_KEY: 3,
    SignatureStatus.INDETERMINATE: 2,
    SignatureStatus.UNSIGNED: 1,
    SignatureStatus.VALID: 0,
}
_ANCHOR_PRIORITY = {
    AnchorStatus.INVALID: 3,
    AnchorStatus.UNANCHORED: 2,
    AnchorStatus.NOT_EVALUATED: 1,
    AnchorStatus.ANCHORED: 0,
}


def _worst(values: Iterable[Enum], priority: dict[Any, int], default: Any) -> Any:
    values = tuple(values)
    return max(values, key=priority.__getitem__) if values else default


def _verify_signatures(
    artifacts: Sequence[object],
    signature_verifier: object | None,
    errors: list[VerificationError],
) -> tuple[SignatureStatus, AnchorStatus]:
    if not artifacts:
        return SignatureStatus.UNSIGNED, AnchorStatus.NOT_EVALUATED
    signature_statuses: list[SignatureStatus] = []
    anchor_statuses: list[AnchorStatus] = []
    for index, artifact in enumerate(artifacts):
        if type(artifact) is not dict:
            signature_statuses.append(SignatureStatus.INDETERMINATE)
            anchor_statuses.append(AnchorStatus.NOT_EVALUATED)
            continue
        try:
            result = verify_artifact_detailed(
                artifact,
                verifier=signature_verifier,  # type: ignore[arg-type]
            )
        except Exception:
            errors.append(
                _error(
                    "SIGNATURE_VERIFICATION_ERROR",
                    f"Index {index}: signature verification could not be evaluated",
                    index,
                )
            )
            signature_statuses.append(SignatureStatus.INDETERMINATE)
            anchor_statuses.append(AnchorStatus.NOT_EVALUATED)
        else:
            signature_statuses.append(result.signature_status)
            anchor_statuses.append(result.anchor_status)
    return (
        _worst(signature_statuses, _SIGNATURE_PRIORITY, SignatureStatus.UNSIGNED),
        _worst(anchor_statuses, _ANCHOR_PRIORITY, AnchorStatus.NOT_EVALUATED),
    )


def _apply_anchor_verifier(
    anchor_verifier: object,
    artifacts: Sequence[object],
) -> AnchorStatus:
    if callable(anchor_verifier):
        result = anchor_verifier(tuple(artifacts))
    else:
        verify = getattr(anchor_verifier, "verify")
        result = verify(tuple(artifacts))
    if not isinstance(result, AnchorStatus):
        raise TypeError("anchor verifier must return AnchorStatus")
    return result


def verify_chain_detailed(
    artifacts: object,
    *,
    signature_verifier: object | None = None,
    anchor_verifier: object | None = None,
    legacy_authorization: object | None = None,
) -> ChainVerificationReport:
    """Verify supplied evidence without conflating integrity and completeness."""
    errors: list[VerificationError] = []
    if type(artifacts) is not list:
        supplied: Sequence[object] = [artifacts]
        errors.append(
            _error("CHAIN_INPUT_INVALID", "Artifacts must be supplied as a list")
        )
    else:
        supplied = artifacts

    legacy_kind = _legacy_evidence_kind(supplied)
    legacy_mode = (
        legacy_kind is not None
        and is_legacy_authorized(
            legacy_authorization,
            LegacyFeature.CHECKSUM_FREE_CHAIN_VERIFICATION,
        )
        and is_legacy_authorized(legacy_authorization, legacy_kind)
    )
    content = (
        ContentIntegrity.LEGACY
        if legacy_mode
        else _verify_content(supplied, errors)
    )
    continuity = _verify_continuity(
        supplied,
        errors,
        legacy_mode=legacy_mode,
    )
    signature_status, anchor_status = _verify_signatures(
        supplied, signature_verifier, errors
    )
    if anchor_verifier is not None:
        try:
            anchor_status = _apply_anchor_verifier(anchor_verifier, supplied)
        except Exception:
            errors.append(
                _error(
                    "ANCHOR_VERIFICATION_ERROR",
                    "Anchor verification could not be evaluated",
                )
            )
            anchor_status = AnchorStatus.NOT_EVALUATED

    return ChainVerificationReport(
        content_integrity=content,
        chain_continuity=continuity,
        signature_status=signature_status,
        anchor_status=anchor_status,
        completeness=Completeness.UNPROVEN,
        errors=tuple(errors),
    )
