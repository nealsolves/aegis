"""Immutable value contracts for externally anchored checkpoints."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from aegis._internal.canonicalization import SAFE_INTEGER_MAX
from aegis._internal.errors import (
    CheckpointError,
    SignatureMetadataError,
    SigningContractError,
    VerificationContractError,
)
from aegis._internal.signature_models import (
    CHECKPOINT_CANONICALIZATION_VERSION,
    CHAIN_CHECKPOINT_SIGNING_PROFILE,
    MAX_VERIFICATION_MESSAGE_LENGTH,
    WORKFLOW_CHECKPOINT_SIGNING_PROFILE,
    AnchorStatus,
    ArtifactVerificationResult,
    EvidenceType,
    SignatureEncoding,
    SignatureMetadata,
    SignatureStatus,
    VerificationReasonCode,
    validate_encoded_signature,
)
from aegis._internal.verification_limits import (
    VerificationBudget,
    VerificationInputError,
)


_CHECKPOINT_SCHEMA_VERSION = "1"
_SOURCE_SCHEMA_VERSION = "2.0"
_MAX_SCOPE_ID_LENGTH = 512
_MAX_WORKFLOW_INVOCATIONS = 1_024
_TERMINAL_WORKFLOW_STATUSES = frozenset(
    {"COMPLETED", "FAILED", "CANCELED", "INCOMPLETE"}
)
_HEX64_PATTERN = re.compile(r"[0-9a-f]{64}\Z")

_CHAIN_KEYS = frozenset(
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
        "signature_metadata",
        "signature",
    }
)
_WORKFLOW_KEYS = frozenset(
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
        "signature_metadata",
        "signature",
    }
)
_METADATA_KEYS = frozenset(
    {
        "schema_version",
        "signing_profile",
        "canonicalization_version",
        "payload_type",
        "algorithm",
        "signature_encoding",
        "key_reference",
        "key_version",
        "signed_at",
    }
)
_INVOCATION_KEYS = frozenset({"step_index", "checksum"})


class CheckpointSignatureStatus(str, Enum):
    NOT_EVALUATED = "not_evaluated"
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN_KEY = "unknown_key"
    REVOKED = "revoked"
    INDETERMINATE = "indeterminate"


class CheckpointBindingStatus(str, Enum):
    NOT_EVALUATED = "not_evaluated"
    MATCHED = "matched"
    HISTORICAL = "historical"
    PARTIAL = "partial"
    OUTSIDE = "outside"
    AHEAD = "ahead"
    CONFLICT = "conflict"
    OUT_OF_SCOPE = "out_of_scope"


def _input_error() -> CheckpointError:
    return CheckpointError("Checkpoint record is invalid")


def _profile_error() -> CheckpointError:
    return CheckpointError(
        "Checkpoint profile is invalid",
        code="CHECKPOINT_PROFILE_INVALID",
    )


def _require_plain_string(value: object) -> str:
    if type(value) is not str:
        raise _input_error()
    return value


def _has_lone_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _require_scope_id(value: object) -> str:
    selected = _require_plain_string(value)
    if not 1 <= len(selected) <= _MAX_SCOPE_ID_LENGTH:
        raise _input_error()
    if _has_lone_surrogate(selected) or not selected.strip():
        raise _input_error()
    return selected


def _require_nonnegative_integer(value: object) -> int:
    if type(value) is not int or not 0 <= value <= SAFE_INTEGER_MAX:
        raise _input_error()
    return value


def _require_checksum(value: object) -> str:
    selected = _require_plain_string(value)
    if len(selected) != 64 or _HEX64_PATTERN.fullmatch(selected) is None:
        raise _input_error()
    return selected


def _validate_record_discriminators(
    *,
    checkpoint_schema_version: object,
    checkpoint_profile: object,
    canonicalization_profile: object,
    expected_profile: str,
) -> None:
    version = _require_plain_string(checkpoint_schema_version)
    if version != _CHECKPOINT_SCHEMA_VERSION:
        raise CheckpointError(
            "Checkpoint version is unsupported",
            code="CHECKPOINT_VERSION_UNSUPPORTED",
        )
    profile = _require_plain_string(checkpoint_profile)
    canonicalization = _require_plain_string(canonicalization_profile)
    if (
        profile != expected_profile
        or canonicalization != CHECKPOINT_CANONICALIZATION_VERSION
    ):
        raise _profile_error()


def _is_exact_enum_member(value: object, enum_type: type[Enum]) -> bool:
    return type(value) is enum_type and any(value is member for member in enum_type)


def _metadata_snapshot(
    metadata: object,
    *,
    expected_profile: str,
    expected_type: EvidenceType,
) -> tuple[SignatureMetadata, dict[str, object]]:
    if type(metadata) is not SignatureMetadata:
        raise _input_error()
    try:
        schema_version = metadata.schema_version
        signing_profile = metadata.signing_profile
        canonicalization_version = metadata.canonicalization_version
        payload_type = metadata.payload_type
        algorithm = metadata.algorithm
        signature_encoding = metadata.signature_encoding
        key_reference = metadata.key_reference
        key_version = metadata.key_version
        signed_at = metadata.signed_at
    except Exception:
        raise _input_error() from None
    if (
        type(schema_version) is not str
        or schema_version != "1"
        or type(signing_profile) is not str
        or type(canonicalization_version) is not str
        or not _is_exact_enum_member(payload_type, EvidenceType)
        or type(algorithm) is not str
        or not 1 <= len(algorithm) <= 128
        or not _is_exact_enum_member(signature_encoding, SignatureEncoding)
        or type(key_reference) is not str
        or not 1 <= len(key_reference) <= 512
        or type(key_version) is not str
        or not 1 <= len(key_version) <= 128
        or type(signed_at) is not int
        or not 0 <= signed_at <= SAFE_INTEGER_MAX
    ):
        raise _input_error()
    if (
        signing_profile != expected_profile
        or canonicalization_version != CHECKPOINT_CANONICALIZATION_VERSION
        or payload_type is not expected_type
    ):
        raise _profile_error()
    try:
        snapshot = SignatureMetadata.to_dict(metadata)
        VerificationBudget().measure(snapshot)
        parsed = SignatureMetadata.from_dict(snapshot)
    except Exception:
        raise _input_error() from None
    return parsed, snapshot


def _parse_metadata(
    value: object,
    *,
    expected_profile: str,
    expected_type: EvidenceType,
) -> SignatureMetadata:
    if type(value) is not dict or value.keys() != _METADATA_KEYS:
        raise _input_error()
    if any(
        type(value[field]) is not str
        for field in (
            "signing_profile",
            "canonicalization_version",
            "payload_type",
        )
    ):
        raise _input_error()
    if (
        value["signing_profile"] != expected_profile
        or value["canonicalization_version"]
        != CHECKPOINT_CANONICALIZATION_VERSION
        or value["payload_type"] != expected_type.value
    ):
        raise _profile_error()
    try:
        parsed = SignatureMetadata.from_dict(value)
    except SignatureMetadataError:
        raise _input_error() from None
    parsed, _ = _metadata_snapshot(
        parsed,
        expected_profile=expected_profile,
        expected_type=expected_type,
    )
    return parsed


def _validate_signature(signature: object, metadata: SignatureMetadata) -> str:
    selected = _require_plain_string(signature)
    try:
        validate_encoded_signature(selected, metadata.signature_encoding)
    except SigningContractError:
        raise _input_error() from None
    return selected


def _measure_record(value: object) -> None:
    try:
        VerificationBudget().measure(value)
    except VerificationInputError as exc:
        raise CheckpointError(
            "Checkpoint record exceeds a configured limit",
            code="CHECKPOINT_INPUT_INVALID",
        ) from exc


def _write_slots(instance: object, owner: type[object], values: dict[str, object]) -> None:
    for field, value in values.items():
        vars(owner)[field].__set__(instance, value)


def _read_slots(instance: object, owner: type[object]) -> dict[str, object]:
    try:
        return {
            field: vars(owner)[field].__get__(instance, owner)
            for field in owner.__dataclass_fields__  # type: ignore[attr-defined]
        }
    except Exception:
        raise _input_error() from None


@dataclass(frozen=True, slots=True, init=False)
class TrustedChainCheckpoint:
    checkpoint_schema_version: str
    checkpoint_profile: str
    canonicalization_profile: str
    chain_id: str
    chain_index: int
    chain_length: int
    artifact_schema_version: str
    artifact_checksum: str
    checkpointed_at: int
    signature_metadata: SignatureMetadata
    signature: str

    def __init__(
        self,
        checkpoint_schema_version: str,
        checkpoint_profile: str,
        canonicalization_profile: str,
        chain_id: str,
        chain_index: int,
        chain_length: int,
        artifact_schema_version: str,
        artifact_checksum: str,
        checkpointed_at: int,
        signature_metadata: SignatureMetadata,
        signature: str,
    ) -> None:
        _write_slots(
            self,
            TrustedChainCheckpoint,
            {
                "checkpoint_schema_version": checkpoint_schema_version,
                "checkpoint_profile": checkpoint_profile,
                "canonicalization_profile": canonicalization_profile,
                "chain_id": chain_id,
                "chain_index": chain_index,
                "chain_length": chain_length,
                "artifact_schema_version": artifact_schema_version,
                "artifact_checksum": artifact_checksum,
                "checkpointed_at": checkpointed_at,
                "signature_metadata": signature_metadata,
                "signature": signature,
            },
        )
        TrustedChainCheckpoint.__post_init__(self)

    def __post_init__(self) -> None:
        _, metadata, _ = _validate_chain_instance(self)
        _write_slots(
            self,
            TrustedChainCheckpoint,
            {"signature_metadata": metadata},
        )

    def to_dict(self) -> dict[str, object]:
        if type(self) is not TrustedChainCheckpoint:
            raise _input_error()
        values, _, metadata_dict = _validate_chain_instance(self)
        return {
            "checkpoint_schema_version": values["checkpoint_schema_version"],
            "checkpoint_profile": values["checkpoint_profile"],
            "canonicalization_profile": values["canonicalization_profile"],
            "chain_id": values["chain_id"],
            "chain_index": values["chain_index"],
            "chain_length": values["chain_length"],
            "artifact_schema_version": values["artifact_schema_version"],
            "artifact_checksum": values["artifact_checksum"],
            "checkpointed_at": values["checkpointed_at"],
            "signature_metadata": metadata_dict,
            "signature": values["signature"],
        }

    @classmethod
    def from_dict(cls, value: object) -> TrustedChainCheckpoint:
        _measure_record(value)
        if cls is not TrustedChainCheckpoint:
            raise _input_error()
        if type(value) is not dict or value.keys() != _CHAIN_KEYS:
            raise _input_error()
        _validate_record_discriminators(
            checkpoint_schema_version=value["checkpoint_schema_version"],
            checkpoint_profile=value["checkpoint_profile"],
            canonicalization_profile=value["canonicalization_profile"],
            expected_profile=CHAIN_CHECKPOINT_SIGNING_PROFILE,
        )
        metadata = _parse_metadata(
            value["signature_metadata"],
            expected_profile=CHAIN_CHECKPOINT_SIGNING_PROFILE,
            expected_type=EvidenceType.CHAIN_CHECKPOINT,
        )
        return TrustedChainCheckpoint(
            checkpoint_schema_version=value["checkpoint_schema_version"],
            checkpoint_profile=value["checkpoint_profile"],
            canonicalization_profile=value["canonicalization_profile"],
            chain_id=value["chain_id"],
            chain_index=value["chain_index"],
            chain_length=value["chain_length"],
            artifact_schema_version=value["artifact_schema_version"],
            artifact_checksum=value["artifact_checksum"],
            checkpointed_at=value["checkpointed_at"],
            signature_metadata=metadata,
            signature=value["signature"],
        )


def _validate_chain_instance(
    value: object,
) -> tuple[dict[str, object], SignatureMetadata, dict[str, object]]:
    values = _read_slots(value, TrustedChainCheckpoint)
    _validate_record_discriminators(
        checkpoint_schema_version=values["checkpoint_schema_version"],
        checkpoint_profile=values["checkpoint_profile"],
        canonicalization_profile=values["canonicalization_profile"],
        expected_profile=CHAIN_CHECKPOINT_SIGNING_PROFILE,
    )
    _require_scope_id(values["chain_id"])
    chain_index = _require_nonnegative_integer(values["chain_index"])
    chain_length = _require_nonnegative_integer(values["chain_length"])
    if chain_length != chain_index + 1:
        raise _input_error()
    artifact_schema_version = _require_plain_string(
        values["artifact_schema_version"]
    )
    if artifact_schema_version != _SOURCE_SCHEMA_VERSION:
        raise _input_error()
    _require_checksum(values["artifact_checksum"])
    checkpointed_at = _require_nonnegative_integer(values["checkpointed_at"])
    metadata, metadata_dict = _metadata_snapshot(
        values["signature_metadata"],
        expected_profile=CHAIN_CHECKPOINT_SIGNING_PROFILE,
        expected_type=EvidenceType.CHAIN_CHECKPOINT,
    )
    if checkpointed_at != metadata.signed_at:
        raise _input_error()
    _validate_signature(values["signature"], metadata)
    return values, metadata, metadata_dict


def _parse_workflow_claim(value: object) -> tuple[tuple[int, str], ...]:
    if type(value) is not list or len(value) > _MAX_WORKFLOW_INVOCATIONS:
        raise _input_error()
    claim: list[tuple[int, str]] = []
    for expected_index, entry in enumerate(value):
        if type(entry) is not dict or entry.keys() != _INVOCATION_KEYS:
            raise _input_error()
        step_index = _require_nonnegative_integer(entry["step_index"])
        if step_index != expected_index:
            raise _input_error()
        claim.append((step_index, _require_checksum(entry["checksum"])))
    return tuple(claim)


def _validate_workflow_claim(value: object) -> tuple[tuple[int, str], ...]:
    if type(value) is not tuple or len(value) > _MAX_WORKFLOW_INVOCATIONS:
        raise _input_error()
    for expected_index, entry in enumerate(value):
        if type(entry) is not tuple or len(entry) != 2:
            raise _input_error()
        step_index = _require_nonnegative_integer(entry[0])
        if step_index != expected_index:
            raise _input_error()
        _require_checksum(entry[1])
    return value


@dataclass(frozen=True, slots=True, init=False)
class TrustedWorkflowCheckpoint:
    checkpoint_schema_version: str
    checkpoint_profile: str
    canonicalization_profile: str
    workflow_schema_version: str
    session_id: str
    final_status: str
    step_count: int
    invocations: tuple[tuple[int, str], ...]
    workflow_checksum: str
    checkpointed_at: int
    signature_metadata: SignatureMetadata
    signature: str

    def __init__(
        self,
        checkpoint_schema_version: str,
        checkpoint_profile: str,
        canonicalization_profile: str,
        workflow_schema_version: str,
        session_id: str,
        final_status: str,
        step_count: int,
        invocations: tuple[tuple[int, str], ...],
        workflow_checksum: str,
        checkpointed_at: int,
        signature_metadata: SignatureMetadata,
        signature: str,
    ) -> None:
        _write_slots(
            self,
            TrustedWorkflowCheckpoint,
            {
                "checkpoint_schema_version": checkpoint_schema_version,
                "checkpoint_profile": checkpoint_profile,
                "canonicalization_profile": canonicalization_profile,
                "workflow_schema_version": workflow_schema_version,
                "session_id": session_id,
                "final_status": final_status,
                "step_count": step_count,
                "invocations": invocations,
                "workflow_checksum": workflow_checksum,
                "checkpointed_at": checkpointed_at,
                "signature_metadata": signature_metadata,
                "signature": signature,
            },
        )
        TrustedWorkflowCheckpoint.__post_init__(self)

    def __post_init__(self) -> None:
        _, metadata, _ = _validate_workflow_instance(self)
        _write_slots(
            self,
            TrustedWorkflowCheckpoint,
            {"signature_metadata": metadata},
        )

    def to_dict(self) -> dict[str, object]:
        if type(self) is not TrustedWorkflowCheckpoint:
            raise _input_error()
        values, _, metadata_dict = _validate_workflow_instance(self)
        claim = values["invocations"]
        return {
            "checkpoint_schema_version": values["checkpoint_schema_version"],
            "checkpoint_profile": values["checkpoint_profile"],
            "canonicalization_profile": values["canonicalization_profile"],
            "workflow_schema_version": values["workflow_schema_version"],
            "session_id": values["session_id"],
            "final_status": values["final_status"],
            "step_count": values["step_count"],
            "invocations": [
                {"step_index": step_index, "checksum": checksum}
                for step_index, checksum in claim  # type: ignore[union-attr]
            ],
            "workflow_checksum": values["workflow_checksum"],
            "checkpointed_at": values["checkpointed_at"],
            "signature_metadata": metadata_dict,
            "signature": values["signature"],
        }

    @classmethod
    def from_dict(cls, value: object) -> TrustedWorkflowCheckpoint:
        _measure_record(value)
        if cls is not TrustedWorkflowCheckpoint:
            raise _input_error()
        if type(value) is not dict or value.keys() != _WORKFLOW_KEYS:
            raise _input_error()
        _validate_record_discriminators(
            checkpoint_schema_version=value["checkpoint_schema_version"],
            checkpoint_profile=value["checkpoint_profile"],
            canonicalization_profile=value["canonicalization_profile"],
            expected_profile=WORKFLOW_CHECKPOINT_SIGNING_PROFILE,
        )
        metadata = _parse_metadata(
            value["signature_metadata"],
            expected_profile=WORKFLOW_CHECKPOINT_SIGNING_PROFILE,
            expected_type=EvidenceType.WORKFLOW_CHECKPOINT,
        )
        return TrustedWorkflowCheckpoint(
            checkpoint_schema_version=value["checkpoint_schema_version"],
            checkpoint_profile=value["checkpoint_profile"],
            canonicalization_profile=value["canonicalization_profile"],
            workflow_schema_version=value["workflow_schema_version"],
            session_id=value["session_id"],
            final_status=value["final_status"],
            step_count=value["step_count"],
            invocations=_parse_workflow_claim(value["invocations"]),
            workflow_checksum=value["workflow_checksum"],
            checkpointed_at=value["checkpointed_at"],
            signature_metadata=metadata,
            signature=value["signature"],
        )


def _validate_workflow_instance(
    value: object,
) -> tuple[dict[str, object], SignatureMetadata, dict[str, object]]:
    values = _read_slots(value, TrustedWorkflowCheckpoint)
    _validate_record_discriminators(
        checkpoint_schema_version=values["checkpoint_schema_version"],
        checkpoint_profile=values["checkpoint_profile"],
        canonicalization_profile=values["canonicalization_profile"],
        expected_profile=WORKFLOW_CHECKPOINT_SIGNING_PROFILE,
    )
    workflow_schema_version = _require_plain_string(
        values["workflow_schema_version"]
    )
    if workflow_schema_version != _SOURCE_SCHEMA_VERSION:
        raise _input_error()
    _require_scope_id(values["session_id"])
    status = _require_plain_string(values["final_status"])
    if len(status) > len("INCOMPLETE") or status not in _TERMINAL_WORKFLOW_STATUSES:
        raise _input_error()
    step_count = _require_nonnegative_integer(values["step_count"])
    claim = _validate_workflow_claim(values["invocations"])
    if step_count != len(claim):
        raise _input_error()
    _require_checksum(values["workflow_checksum"])
    checkpointed_at = _require_nonnegative_integer(values["checkpointed_at"])
    metadata, metadata_dict = _metadata_snapshot(
        values["signature_metadata"],
        expected_profile=WORKFLOW_CHECKPOINT_SIGNING_PROFILE,
        expected_type=EvidenceType.WORKFLOW_CHECKPOINT,
    )
    if checkpointed_at != metadata.signed_at:
        raise _input_error()
    _validate_signature(values["signature"], metadata)
    return values, metadata, metadata_dict


CheckpointRecord = TrustedChainCheckpoint | TrustedWorkflowCheckpoint


def _checkpoint_snapshot(value: object) -> CheckpointRecord:
    try:
        if type(value) is TrustedChainCheckpoint:
            snapshot = TrustedChainCheckpoint.to_dict(value)
            return TrustedChainCheckpoint.from_dict(snapshot)
        if type(value) is TrustedWorkflowCheckpoint:
            snapshot = TrustedWorkflowCheckpoint.to_dict(value)
            return TrustedWorkflowCheckpoint.from_dict(snapshot)
    except Exception:
        raise _input_error() from None
    raise _input_error()


def _provider_result_snapshot(
    value: object,
    checkpoint: CheckpointRecord,
) -> ArtifactVerificationResult:
    if type(value) is not ArtifactVerificationResult:
        raise _input_error()
    try:
        signature_status = value.signature_status
        anchor_status = value.anchor_status
        reason_code = value.reason_code
        message = value.message
        source_metadata = value.signature_metadata
    except Exception:
        raise _input_error() from None
    if (
        not _is_exact_enum_member(signature_status, SignatureStatus)
        or not _is_exact_enum_member(anchor_status, AnchorStatus)
        or not _is_exact_enum_member(reason_code, VerificationReasonCode)
        or type(message) is not str
        or len(message) > MAX_VERIFICATION_MESSAGE_LENGTH
    ):
        raise _input_error()

    metadata: SignatureMetadata | None = None
    if source_metadata is not None:
        if type(checkpoint) is TrustedChainCheckpoint:
            expected_profile = CHAIN_CHECKPOINT_SIGNING_PROFILE
            expected_type = EvidenceType.CHAIN_CHECKPOINT
        else:
            expected_profile = WORKFLOW_CHECKPOINT_SIGNING_PROFILE
            expected_type = EvidenceType.WORKFLOW_CHECKPOINT
        try:
            metadata, _ = _metadata_snapshot(
                source_metadata,
                expected_profile=expected_profile,
                expected_type=expected_type,
            )
        except CheckpointError:
            raise _input_error() from None
        if metadata != checkpoint.signature_metadata:
            raise _input_error()

    try:
        return ArtifactVerificationResult(
            signature_status,
            anchor_status,
            reason_code,
            message,
            metadata,
        )
    except VerificationContractError:
        raise _input_error() from None


@dataclass(frozen=True, slots=True, init=False)
class CheckpointVerificationResult:
    input_indexes: tuple[int, ...]
    checkpoint: CheckpointRecord
    scope_id: str
    chain_index: int | None
    signature_result: ArtifactVerificationResult | None
    binding_status: CheckpointBindingStatus

    def __init__(
        self,
        input_indexes: tuple[int, ...],
        checkpoint: CheckpointRecord,
        scope_id: str,
        chain_index: int | None,
        signature_result: ArtifactVerificationResult | None,
        binding_status: CheckpointBindingStatus,
    ) -> None:
        _write_slots(
            self,
            CheckpointVerificationResult,
            {
                "input_indexes": input_indexes,
                "checkpoint": checkpoint,
                "scope_id": scope_id,
                "chain_index": chain_index,
                "signature_result": signature_result,
                "binding_status": binding_status,
            },
        )
        CheckpointVerificationResult.__post_init__(self)

    def __post_init__(self) -> None:
        checkpoint, provider_result = _validate_verification_result_instance(self)
        _write_slots(
            self,
            CheckpointVerificationResult,
            {
                "checkpoint": checkpoint,
                "signature_result": provider_result,
            },
        )


def _validate_verification_result_instance(
    value: object,
) -> tuple[CheckpointRecord, ArtifactVerificationResult | None]:
    values = _read_slots(value, CheckpointVerificationResult)
    input_indexes = values["input_indexes"]
    if (
        type(input_indexes) is not tuple
        or len(input_indexes) == 0
        or any(
            type(index) is not int or not 0 <= index <= SAFE_INTEGER_MAX
            for index in input_indexes
        )
    ):
        raise _input_error()

    checkpoint = _checkpoint_snapshot(values["checkpoint"])
    scope_id = values["scope_id"]
    chain_index = values["chain_index"]
    if type(scope_id) is not str:
        raise _input_error()
    if type(checkpoint) is TrustedChainCheckpoint:
        if (
            scope_id != checkpoint.chain_id
            or type(chain_index) is not int
            or chain_index != checkpoint.chain_index
        ):
            raise _input_error()
    elif scope_id != checkpoint.session_id or chain_index is not None:
        raise _input_error()

    binding_status = values["binding_status"]
    if not _is_exact_enum_member(binding_status, CheckpointBindingStatus):
        raise _input_error()
    source_result = values["signature_result"]
    unevaluated = binding_status in (
        CheckpointBindingStatus.NOT_EVALUATED,
        CheckpointBindingStatus.OUT_OF_SCOPE,
    )
    if (source_result is None) is not unevaluated:
        raise _input_error()
    provider_result = (
        None
        if source_result is None
        else _provider_result_snapshot(source_result, checkpoint)
    )
    return checkpoint, provider_result
