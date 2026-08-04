"""Explicit, provider-neutral creation of immutable trusted checkpoints."""

from __future__ import annotations

from aegis._internal.canonicalization import SAFE_INTEGER_MAX, canonicalize_v2
from aegis._internal.chain_linker import validate_chain_coordinates
from aegis._internal.checkpoint_models import (
    TrustedChainCheckpoint,
    TrustedWorkflowCheckpoint,
)
from aegis._internal.errors import CheckpointError
from aegis._internal.evidence_finalizer import (
    _audit_validator,
    _workflow_validator,
)
from aegis._internal.evidence_profiles import (
    ContentIntegrity,
    verify_content_checksum_v2,
)
from aegis._internal.external_signing import (
    ExternalArtifactSigner,
    _normalize_identity,
    _normalized_signature,
    _validate_receipt,
)
from aegis._internal.signature_models import (
    CHECKPOINT_CANONICALIZATION_VERSION,
    CHAIN_CHECKPOINT_SIGNING_PROFILE,
    SIGNATURE_METADATA_SCHEMA_VERSION,
    WORKFLOW_CHECKPOINT_SIGNING_PROFILE,
    EvidenceType,
    SignatureEncoding,
    SignatureMetadata,
    SignerIdentity,
    validate_encoded_signature,
)
from aegis._internal.verification_limits import (
    VerificationBudget,
    VerificationInputError,
)


_SIGNATURE_DOMAIN = b"AEGIS-SIGNATURE\x00"
_CHECKPOINT_SCHEMA_VERSION = "1"

_CHAIN_UNSIGNED_KEYS = frozenset(
    {
        "checkpoint_schema_version",
        "checkpoint_profile",
        "canonicalization_profile",
        "chain_id",
        "chain_index",
        "chain_length",
        "artifact_schema_version",
        "artifact_checksum",
        "checkpointed_at",
    }
)
_WORKFLOW_UNSIGNED_KEYS = frozenset(
    {
        "checkpoint_schema_version",
        "checkpoint_profile",
        "canonicalization_profile",
        "workflow_schema_version",
        "session_id",
        "final_status",
        "step_count",
        "invocations",
        "workflow_checksum",
        "checkpointed_at",
    }
)
_SIGNED_FIELDS = frozenset({"signature_metadata", "signature"})


def _input_error() -> CheckpointError:
    return CheckpointError(
        "Checkpoint input is invalid",
        code="CHECKPOINT_INPUT_INVALID",
    )


def _signing_error() -> CheckpointError:
    return CheckpointError(
        "Checkpoint signer did not produce a valid signature",
        code="CHECKPOINT_SIGNING_ERROR",
    )


def _metadata_snapshot(metadata: object) -> tuple[SignatureMetadata, dict[str, object]]:
    if type(metadata) is not SignatureMetadata:
        raise _input_error()
    try:
        snapshot = SignatureMetadata.to_dict(metadata)
        parsed = SignatureMetadata.from_dict(snapshot)
    except Exception:
        raise _input_error() from None
    if parsed != metadata:
        raise _input_error()
    return parsed, snapshot


def _placeholder_signature(encoding: SignatureEncoding) -> str:
    return "00" if encoding is SignatureEncoding.HEX else "AA=="


def _validated_signable_record(
    record: dict[str, object],
    metadata: SignatureMetadata,
    metadata_dict: dict[str, object],
) -> dict[str, object]:
    profile = record.get("checkpoint_profile")
    if profile == CHAIN_CHECKPOINT_SIGNING_PROFILE:
        unsigned_keys = _CHAIN_UNSIGNED_KEYS
        record_type = TrustedChainCheckpoint
        expected_type = EvidenceType.CHAIN_CHECKPOINT
    elif profile == WORKFLOW_CHECKPOINT_SIGNING_PROFILE:
        unsigned_keys = _WORKFLOW_UNSIGNED_KEYS
        record_type = TrustedWorkflowCheckpoint
        expected_type = EvidenceType.WORKFLOW_CHECKPOINT
    else:
        raise _input_error()

    keys = frozenset(record)
    if keys == unsigned_keys:
        candidate = dict(record)
        candidate["signature_metadata"] = dict(metadata_dict)
        candidate["signature"] = _placeholder_signature(
            metadata.signature_encoding
        )
    elif keys == unsigned_keys | _SIGNED_FIELDS:
        if record.get("signature_metadata") != metadata_dict:
            raise _input_error()
        candidate = dict(record)
    else:
        raise _input_error()

    if (
        metadata.signing_profile != profile
        or metadata.canonicalization_version
        != CHECKPOINT_CANONICALIZATION_VERSION
        or metadata.payload_type is not expected_type
        or record.get("canonicalization_profile")
        != CHECKPOINT_CANONICALIZATION_VERSION
        or record.get("checkpointed_at") != metadata.signed_at
    ):
        raise _input_error()

    parsed = record_type.from_dict(candidate)
    signable = parsed.to_dict()
    signable.pop("signature")
    return signable


def _checkpoint_payload(
    unsigned_record: dict[str, object], metadata: SignatureMetadata
) -> bytes:
    """Return the sole canonical signing-byte representation for checkpoints."""
    try:
        VerificationBudget().measure(unsigned_record)
    except VerificationInputError as exc:
        raise _input_error() from exc
    if type(unsigned_record) is not dict:
        raise _input_error()
    parsed_metadata, metadata_dict = _metadata_snapshot(metadata)
    signable = _validated_signable_record(
        unsigned_record,
        parsed_metadata,
        metadata_dict,
    )
    signable["signature_metadata"] = metadata_dict
    try:
        return (
            _SIGNATURE_DOMAIN
            + parsed_metadata.signing_profile.encode("utf-8")
            + b"\x00"
            + parsed_metadata.payload_type.value.encode("utf-8")
            + b"\x00"
            + canonicalize_v2(signable).data
        )
    except Exception as exc:
        raise _input_error() from exc


def _require_checkpointed_at(value: object) -> int:
    if type(value) is not int or not 0 <= value <= SAFE_INTEGER_MAX:
        raise _input_error()
    return value


def _measure_source(value: object) -> None:
    try:
        VerificationBudget().measure(value)
    except VerificationInputError as exc:
        raise CheckpointError(
            "Checkpoint source exceeds a configured limit",
            code="CHECKPOINT_INPUT_INVALID",
        ) from exc


def _valid_chain_source(artifact: dict[str, object]) -> bool:
    try:
        coordinates = validate_chain_coordinates(
            {
                "chain_id": artifact["chain_id"],
                "chain_index": artifact["chain_index"],
                "previous_audit_checksum": artifact[
                    "previous_audit_checksum"
                ],
                "reservation_id": artifact["reservation_id"],
            }
        )
    except Exception:
        return False
    return coordinates.chain_index < SAFE_INTEGER_MAX


def _valid_scope_id(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 512
        and bool(value.strip())
    )


def _valid_workflow_source(workflow: dict[str, object]) -> bool:
    try:
        if not _valid_scope_id(workflow["session_id"]):
            return False
        step_count = workflow["step_count"]
        claim = workflow["invocations"]
        if type(step_count) is not int or type(claim) is not list:
            return False
        if step_count != len(claim):
            return False
        for expected_index, entry in enumerate(claim):
            if (
                type(entry) is not dict
                or entry.keys() != {"step_index", "checksum"}
                or entry["step_index"] != expected_index
            ):
                return False
    except Exception:
        return False
    return True


def _checkpoint_metadata(
    identity: SignerIdentity,
    *,
    profile: str,
    payload_type: EvidenceType,
    checkpointed_at: int,
) -> SignatureMetadata:
    return SignatureMetadata(
        schema_version=SIGNATURE_METADATA_SCHEMA_VERSION,
        signing_profile=profile,
        canonicalization_version=CHECKPOINT_CANONICALIZATION_VERSION,
        payload_type=payload_type,
        algorithm=identity.algorithm,
        signature_encoding=identity.signature_encoding,
        key_reference=identity.key_reference,
        key_version=identity.key_version,
        signed_at=checkpointed_at,
    )


def _sign_checkpoint(
    unsigned_record: dict[str, object],
    signer: ExternalArtifactSigner,
    *,
    profile: str,
    payload_type: EvidenceType,
) -> dict[str, object]:
    try:
        identity = _normalize_identity(signer.signer_identity())
        metadata = _checkpoint_metadata(
            identity,
            profile=profile,
            payload_type=payload_type,
            checkpointed_at=unsigned_record["checkpointed_at"],  # type: ignore[arg-type]
        )
        payload = _checkpoint_payload(unsigned_record, metadata)
        disposable_identity = SignerIdentity(
            identity.algorithm,
            identity.signature_encoding,
            identity.key_reference,
            identity.key_version,
        )
        receipt = signer.sign(payload, disposable_identity)
        _validate_receipt(receipt, identity)
        signature = _normalized_signature(receipt)
        validate_encoded_signature(signature, identity.signature_encoding)
        return {
            **unsigned_record,
            "signature_metadata": metadata.to_dict(),
            "signature": signature,
        }
    except Exception as exc:
        raise _signing_error() from exc


def create_chain_checkpoint(
    artifact: object,
    signer: ExternalArtifactSigner,
    *,
    checkpointed_at: int,
) -> TrustedChainCheckpoint:
    """Sign one finalized, checksum-valid chained invocation explicitly."""
    _measure_source(artifact)
    selected_time = _require_checkpointed_at(checkpointed_at)
    if (
        type(artifact) is not dict
        or not _audit_validator().is_valid(artifact)
        or verify_content_checksum_v2(artifact) is not ContentIntegrity.VALID
        or not _valid_chain_source(artifact)
    ):
        raise CheckpointError(
            "Chain checkpoint source is invalid",
            code="CHECKPOINT_SOURCE_INVALID",
        )
    unsigned_record: dict[str, object] = {
        "checkpoint_schema_version": _CHECKPOINT_SCHEMA_VERSION,
        "checkpoint_profile": CHAIN_CHECKPOINT_SIGNING_PROFILE,
        "canonicalization_profile": CHECKPOINT_CANONICALIZATION_VERSION,
        "chain_id": artifact["chain_id"],
        "chain_index": artifact["chain_index"],
        "chain_length": artifact["chain_index"] + 1,  # type: ignore[operator]
        "artifact_schema_version": artifact["audit_schema_version"],
        "artifact_checksum": artifact["checksum"],
        "checkpointed_at": selected_time,
    }
    signed_record = _sign_checkpoint(
        unsigned_record,
        signer,
        profile=CHAIN_CHECKPOINT_SIGNING_PROFILE,
        payload_type=EvidenceType.CHAIN_CHECKPOINT,
    )
    try:
        return TrustedChainCheckpoint.from_dict(signed_record)
    except Exception as exc:
        raise _signing_error() from exc


def create_workflow_checkpoint(
    workflow: object,
    signer: ExternalArtifactSigner,
    *,
    checkpointed_at: int,
) -> TrustedWorkflowCheckpoint:
    """Sign one finalized, checksum-valid workflow claim explicitly."""
    _measure_source(workflow)
    selected_time = _require_checkpointed_at(checkpointed_at)
    if (
        type(workflow) is not dict
        or not _workflow_validator().is_valid(workflow)
        or verify_content_checksum_v2(workflow) is not ContentIntegrity.VALID
        or not _valid_workflow_source(workflow)
    ):
        raise CheckpointError(
            "Workflow checkpoint source is invalid",
            code="CHECKPOINT_SOURCE_INVALID",
        )
    claim = tuple(
        (entry["step_index"], entry["checksum"])
        for entry in workflow["invocations"]  # type: ignore[union-attr]
    )
    unsigned_record: dict[str, object] = {
        "checkpoint_schema_version": _CHECKPOINT_SCHEMA_VERSION,
        "checkpoint_profile": WORKFLOW_CHECKPOINT_SIGNING_PROFILE,
        "canonicalization_profile": CHECKPOINT_CANONICALIZATION_VERSION,
        "workflow_schema_version": workflow["workflow_schema_version"],
        "session_id": workflow["session_id"],
        "final_status": workflow["status"],
        "step_count": workflow["step_count"],
        "invocations": [
            {"step_index": index, "checksum": checksum}
            for index, checksum in claim
        ],
        "workflow_checksum": workflow["checksum"],
        "checkpointed_at": selected_time,
    }
    signed_record = _sign_checkpoint(
        unsigned_record,
        signer,
        profile=WORKFLOW_CHECKPOINT_SIGNING_PROFILE,
        payload_type=EvidenceType.WORKFLOW_CHECKPOINT,
    )
    try:
        return TrustedWorkflowCheckpoint.from_dict(signed_record)
    except Exception as exc:
        raise _signing_error() from exc
