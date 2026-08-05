"""Typed, independent verification axes for AEGIS evidence chains."""

from __future__ import annotations

from copy import deepcopy
import re
import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Iterable, Sequence

from aegis._internal.canonicalization import CANONICALIZATION_PROFILE_V2
from aegis._internal.chain_checkpoint_verification import (
    evaluate_chain_checkpoints,
    prepare_chain_checkpoint_input,
)
from aegis._internal.checkpoint_models import (
    CheckpointSignatureStatus,
    CheckpointVerificationResult,
)
from aegis._internal.evidence_profiles import (
    ContentIntegrity,
    verify_content_checksum_v2,
)
from aegis._internal.external_signing import verify_artifact_detailed
from aegis._internal.legacy import LegacyFeature, is_legacy_authorized
from aegis._internal.signature_models import AnchorStatus, SignatureStatus
from aegis._internal.signature_models import (
    CANONICALIZATION_VERSION,
    SIGNATURE_METADATA_SCHEMA_VERSION,
    SIGNING_PROFILE,
    SignatureEncoding,
    SignerIdentity,
    validate_encoded_signature,
)
from aegis._internal.utils import canonical_json_bytes
from aegis._internal.verification_contracts import Completeness, VerificationError
from aegis._internal.verification_limits import (
    BoundedVerificationErrors,
    VerificationBudget,
)


_HEX64_RE = re.compile(r"^[a-f0-9]{64}$")
_MAX_CHAIN_IDENTIFIER_LENGTH = 512
_MAX_CHAIN_ARTIFACTS = 1_024
_CHAIN_FIELDS = frozenset(
    {
        "chain_id",
        "chain_index",
        "previous_audit_checksum",
        "reservation_id",
    }
)
_FINALIZER_SIGNATURE_METADATA_FIELDS = frozenset(
    {
        "schema_version",
        "signing_profile",
        "canonicalization_version",
        "canonicalization_profile",
        "payload_type",
        "algorithm",
        "signature_encoding",
        "key_reference",
        "key_version",
        "signed_at",
    }
)
_LEGACY_HMAC_KEY_REFERENCE = "local://legacy-artifact-signer"


def _is_bounded_chain_identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value) <= _MAX_CHAIN_IDENTIFIER_LENGTH
    )


class ChainContinuity(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNCHAINED = "unchained"
    NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True, slots=True)
class ChainVerificationReport:
    content_integrity: ContentIntegrity
    chain_continuity: ChainContinuity
    signature_status: SignatureStatus
    anchor_status: AnchorStatus
    completeness: Completeness
    errors: tuple[VerificationError, ...] = ()
    checkpoint_signature_status: CheckpointSignatureStatus = (
        CheckpointSignatureStatus.NOT_EVALUATED
    )
    checkpoint_anchor_status: AnchorStatus = AnchorStatus.NOT_EVALUATED
    checkpoint_results: tuple[CheckpointVerificationResult, ...] = ()

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
    if not _is_bounded_chain_identifier(chain_id):
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
                f"Index 0: chain_index={first_index} supplied prefix "
                "requires a valid previous_audit_checksum",
                0,
            )
        )
        continuity = ChainContinuity.INVALID

    for offset, artifact in enumerate(typed_artifacts):
        expected_index = first_index + offset
        artifact_index = artifact["chain_index"]
        if type(artifact_index) is not int or artifact_index < 0:
            errors.append(
                _error(
                    "CHAIN_INDEX_INVALID",
                    f"Index {offset}: chain_index is invalid",
                    offset,
                )
            )
            continuity = ChainContinuity.INVALID
        elif artifact_index != expected_index:
            errors.append(
                _error(
                    "CHAIN_INDEX_MISMATCH",
                    f"Index {offset}: expected chain_index={expected_index}, "
                    f"got {artifact_index}",
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
        reservation_id = artifact["reservation_id"]
        if not _is_bounded_chain_identifier(reservation_id):
            errors.append(
                _error(
                    "CHAIN_RESERVATION_ID_INVALID",
                    f"Index {offset}: reservation_id is invalid",
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


def _signature_priority(status: SignatureStatus) -> int:
    if status is SignatureStatus.INVALID:
        return 5
    if status is SignatureStatus.REVOKED:
        return 4
    if status is SignatureStatus.UNKNOWN_KEY:
        return 3
    if status is SignatureStatus.INDETERMINATE:
        return 2
    if status is SignatureStatus.UNSIGNED:
        return 1
    if status is SignatureStatus.VALID:
        return 0
    raise TypeError("signature status is invalid")


def _anchor_priority(status: AnchorStatus) -> int:
    if status is AnchorStatus.INVALID:
        return 3
    if status is AnchorStatus.UNANCHORED:
        return 2
    if status is AnchorStatus.NOT_EVALUATED:
        return 1
    if status is AnchorStatus.ANCHORED:
        return 0
    raise TypeError("anchor status is invalid")


def _worst(
    values: Iterable[Enum],
    priority: Callable[[Any], int],
    default: Any,
) -> Any:
    values = tuple(values)
    return max(values, key=priority) if values else default


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
        declares_v2 = (
            artifact.get("canonicalization_profile")
            == CANONICALIZATION_PROFILE_V2
            or artifact.get("audit_schema_version") == "2.0"
            or artifact.get("workflow_schema_version") == "2.0"
        )
        signature = artifact.get("signature")
        signature_metadata = artifact.get("signature_metadata")
        declared_signature_status = artifact.get("signature_status")
        if "signature_status" in artifact and (
            (
                signature is None
                and (
                    declared_signature_status != "unsigned"
                    or "signature_metadata" in artifact
                )
            )
            or (signature is not None and declared_signature_status != "signed")
        ):
            errors.append(
                _error(
                    "SIGNATURE_METADATA_INVALID",
                    f"Index {index}: signature fields are inconsistent",
                    index,
                )
            )
            signature_statuses.append(SignatureStatus.INDETERMINATE)
            anchor_statuses.append(AnchorStatus.NOT_EVALUATED)
            continue
        if (
            signature is not None
            and type(signature_metadata) is dict
            and "canonicalization_profile" in signature_metadata
        ):
            if not _valid_finalizer_signature_metadata(
                artifact,
                signature_metadata,
            ):
                errors.append(
                    _error(
                        "SIGNATURE_METADATA_INVALID",
                        f"Index {index}: finalizer signature metadata is invalid",
                        index,
                    )
                )
            signature_statuses.append(SignatureStatus.INDETERMINATE)
            anchor_statuses.append(AnchorStatus.NOT_EVALUATED)
            continue
        signature_profile = (
            signature_metadata.get("canonicalization_version")
            if type(signature_metadata) is dict
            else None
        )
        if (
            declares_v2
            and artifact.get("signature") is not None
            and signature_profile != CANONICALIZATION_PROFILE_V2
        ):
            errors.append(
                _error(
                    "SIGNATURE_PROFILE_MISMATCH",
                    f"Index {index}: v2 evidence signature does not declare "
                    "the v2 canonicalization profile",
                    index,
                )
            )
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
        _worst(signature_statuses, _signature_priority, SignatureStatus.UNSIGNED),
        _worst(anchor_statuses, _anchor_priority, AnchorStatus.NOT_EVALUATED),
    )


def _valid_finalizer_signature_metadata(
    artifact: dict[str, Any],
    metadata: dict[str, Any],
) -> bool:
    """Validate B2 metadata without treating its presence as authenticity."""
    expected_payload_type = (
        "workflow_artifact"
        if artifact.get("workflow_schema_version") == "2.0"
        and "audit_schema_version" not in artifact
        else "audit_artifact"
        if artifact.get("audit_schema_version") == "2.0"
        and "workflow_schema_version" not in artifact
        else None
    )
    try:
        encoding = SignatureEncoding(metadata.get("signature_encoding"))
        identity = SignerIdentity(
            algorithm=metadata.get("algorithm"),
            signature_encoding=encoding,
            key_reference=metadata.get("key_reference"),
            key_version=metadata.get("key_version"),
        )
        validate_encoded_signature(artifact.get("signature"), encoding)
    except Exception:
        return False
    signed_at = metadata.get("signed_at")
    legacy_hmac_identity_valid = (
        identity.key_reference != _LEGACY_HMAC_KEY_REFERENCE
        or (
            identity.algorithm == "HMAC-SHA256"
            and identity.signature_encoding is SignatureEncoding.HEX
            and identity.key_version == "1"
            and isinstance(artifact.get("signature"), str)
            and len(artifact["signature"]) == 64
        )
    )
    return (
        set(metadata) == _FINALIZER_SIGNATURE_METADATA_FIELDS
        and artifact.get("signature_status") == "signed"
        and metadata.get("schema_version") == SIGNATURE_METADATA_SCHEMA_VERSION
        and metadata.get("signing_profile") == SIGNING_PROFILE
        and metadata.get("canonicalization_version")
        == CANONICALIZATION_VERSION
        and metadata.get("canonicalization_profile")
        == CANONICALIZATION_PROFILE_V2
        and metadata.get("payload_type") == expected_payload_type
        and not isinstance(signed_at, bool)
        and isinstance(signed_at, int)
        and signed_at >= 0
        and isinstance(identity, SignerIdentity)
        and legacy_hmac_identity_valid
    )


def _apply_anchor_verifier(
    anchor_verifier: object,
    artifacts: Sequence[object],
) -> AnchorStatus:
    if callable(anchor_verifier):
        result = anchor_verifier(tuple(artifacts))
    else:
        result = anchor_verifier.verify(tuple(artifacts))  # type: ignore[attr-defined]
    if not isinstance(result, AnchorStatus):
        raise TypeError("anchor verifier must return AnchorStatus")
    return result


def verify_chain_detailed(
    artifacts: object,
    *,
    signature_verifier: object | None = None,
    anchor_verifier: object | None = None,
    legacy_authorization: object | None = None,
    checkpoints: object = (),
    checkpoint_verifier: object | None = None,
    expected_chain_id: object | None = None,
) -> ChainVerificationReport:
    """Verify supplied evidence without conflating integrity and completeness."""
    errors = BoundedVerificationErrors()
    if type(artifacts) is not list:
        error = _error(
            "CHAIN_INPUT_INVALID", "Artifacts must be supplied as a list"
        )
        return ChainVerificationReport(
            content_integrity=ContentIntegrity.INVALID,
            chain_continuity=ChainContinuity.INVALID,
            signature_status=SignatureStatus.INDETERMINATE,
            anchor_status=AnchorStatus.NOT_EVALUATED,
            completeness=Completeness.UNPROVEN,
            errors=(error,),
        )
    if len(artifacts) > _MAX_CHAIN_ARTIFACTS:
        errors.append(
            _error(
                "CHAIN_VERIFICATION_LIMIT_EXCEEDED",
                "Chain verification input exceeds a configured limit",
            )
        )
        return ChainVerificationReport(
            content_integrity=ContentIntegrity.NOT_EVALUATED,
            chain_continuity=ChainContinuity.NOT_EVALUATED,
            signature_status=SignatureStatus.INDETERMINATE,
            anchor_status=AnchorStatus.NOT_EVALUATED,
            completeness=Completeness.UNPROVEN,
            errors=tuple(errors),
        )

    budget = VerificationBudget()
    checkpoint_errors = BoundedVerificationErrors()
    prepared_checkpoints = prepare_chain_checkpoint_input(
        artifacts,
        checkpoints,
        expected_chain_id,
        budget,
        checkpoint_errors,
    )
    if prepared_checkpoints is None:
        return ChainVerificationReport(
            content_integrity=ContentIntegrity.NOT_EVALUATED,
            chain_continuity=ChainContinuity.NOT_EVALUATED,
            signature_status=SignatureStatus.INDETERMINATE,
            anchor_status=AnchorStatus.NOT_EVALUATED,
            completeness=Completeness.UNPROVEN,
            errors=tuple(checkpoint_errors),
        )

    supplied: Sequence[object] = prepared_checkpoints.artifacts

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
            anchor_status = _apply_anchor_verifier(
                anchor_verifier,
                deepcopy(supplied),
            )
        except Exception:
            errors.append(
                _error(
                    "ANCHOR_VERIFICATION_ERROR",
                    "Anchor verification could not be evaluated",
                )
            )
            anchor_status = AnchorStatus.NOT_EVALUATED

    checkpoint_evaluation = evaluate_chain_checkpoints(
        prepared_checkpoints,
        prepared_checkpoints.artifacts,
        content_valid=content is ContentIntegrity.VALID,
        continuity_valid=continuity is ChainContinuity.VALID,
        verifier=checkpoint_verifier,  # type: ignore[arg-type]
        errors=checkpoint_errors,
    )

    combined_errors = BoundedVerificationErrors()
    for error in sorted(
        checkpoint_errors,
        key=lambda error: -1 if error.index is None else error.index,
    ):
        combined_errors.append(error)
    for error in errors:
        combined_errors.append(error)

    return ChainVerificationReport(
        content_integrity=content,
        chain_continuity=continuity,
        signature_status=signature_status,
        anchor_status=anchor_status,
        completeness=checkpoint_evaluation.completeness,
        errors=tuple(combined_errors),
        checkpoint_signature_status=checkpoint_evaluation.signature_status,
        checkpoint_anchor_status=checkpoint_evaluation.anchor_status,
        checkpoint_results=checkpoint_evaluation.results,
    )
