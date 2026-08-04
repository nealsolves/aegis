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
)
from aegis._internal.signature_models import (
    CHECKPOINT_CANONICALIZATION_VERSION,
    CHAIN_CHECKPOINT_SIGNING_PROFILE,
    WORKFLOW_CHECKPOINT_SIGNING_PROFILE,
    ArtifactVerificationResult,
    EvidenceType,
    SignatureMetadata,
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
    if type(value) is not str or any(
        0xD800 <= ord(character) <= 0xDFFF for character in value
    ):
        raise _input_error()
    return value


def _require_scope_id(value: object) -> str:
    selected = _require_plain_string(value)
    if not 1 <= len(selected) <= _MAX_SCOPE_ID_LENGTH or not selected.strip():
        raise _input_error()
    return selected


def _require_nonnegative_integer(value: object) -> int:
    if type(value) is not int or not 0 <= value <= SAFE_INTEGER_MAX:
        raise _input_error()
    return value


def _require_checksum(value: object) -> str:
    selected = _require_plain_string(value)
    if _HEX64_PATTERN.fullmatch(selected) is None:
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


def _metadata_snapshot(
    metadata: object,
    *,
    expected_profile: str,
    expected_type: EvidenceType,
) -> SignatureMetadata:
    if type(metadata) is not SignatureMetadata:
        raise _input_error()
    try:
        snapshot = SignatureMetadata.to_dict(metadata)
        VerificationBudget().measure(snapshot)
    except (AttributeError, SignatureMetadataError, VerificationInputError):
        raise _input_error() from None
    if any(
        type(snapshot[field]) is not str
        for field in (
            "signing_profile",
            "canonicalization_version",
            "payload_type",
        )
    ):
        raise _input_error()
    if (
        snapshot.get("signing_profile") != expected_profile
        or snapshot.get("canonicalization_version")
        != CHECKPOINT_CANONICALIZATION_VERSION
        or snapshot.get("payload_type") != expected_type.value
    ):
        raise _profile_error()
    try:
        return SignatureMetadata.from_dict(snapshot)
    except SignatureMetadataError:
        raise _input_error() from None


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
    return _metadata_snapshot(
        parsed,
        expected_profile=expected_profile,
        expected_type=expected_type,
    )


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


@dataclass(frozen=True, slots=True)
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

    def __post_init__(self) -> None:
        if type(self) is not TrustedChainCheckpoint:
            raise _input_error()
        _validate_record_discriminators(
            checkpoint_schema_version=self.checkpoint_schema_version,
            checkpoint_profile=self.checkpoint_profile,
            canonicalization_profile=self.canonicalization_profile,
            expected_profile=CHAIN_CHECKPOINT_SIGNING_PROFILE,
        )
        _require_scope_id(self.chain_id)
        chain_index = _require_nonnegative_integer(self.chain_index)
        chain_length = _require_nonnegative_integer(self.chain_length)
        if chain_length != chain_index + 1:
            raise _input_error()
        if _require_plain_string(self.artifact_schema_version) != _SOURCE_SCHEMA_VERSION:
            raise _input_error()
        _require_checksum(self.artifact_checksum)
        checkpointed_at = _require_nonnegative_integer(self.checkpointed_at)
        metadata = _metadata_snapshot(
            self.signature_metadata,
            expected_profile=CHAIN_CHECKPOINT_SIGNING_PROFILE,
            expected_type=EvidenceType.CHAIN_CHECKPOINT,
        )
        if checkpointed_at != metadata.signed_at:
            raise _input_error()
        _validate_signature(self.signature, metadata)
        object.__setattr__(self, "signature_metadata", metadata)

    def to_dict(self) -> dict[str, object]:
        return {
            "checkpoint_schema_version": self.checkpoint_schema_version,
            "checkpoint_profile": self.checkpoint_profile,
            "canonicalization_profile": self.canonicalization_profile,
            "chain_id": self.chain_id,
            "chain_index": self.chain_index,
            "chain_length": self.chain_length,
            "artifact_schema_version": self.artifact_schema_version,
            "artifact_checksum": self.artifact_checksum,
            "checkpointed_at": self.checkpointed_at,
            "signature_metadata": SignatureMetadata.to_dict(self.signature_metadata),
            "signature": self.signature,
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
        return cls(
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


@dataclass(frozen=True, slots=True)
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

    def __post_init__(self) -> None:
        if type(self) is not TrustedWorkflowCheckpoint:
            raise _input_error()
        _validate_record_discriminators(
            checkpoint_schema_version=self.checkpoint_schema_version,
            checkpoint_profile=self.checkpoint_profile,
            canonicalization_profile=self.canonicalization_profile,
            expected_profile=WORKFLOW_CHECKPOINT_SIGNING_PROFILE,
        )
        if _require_plain_string(self.workflow_schema_version) != _SOURCE_SCHEMA_VERSION:
            raise _input_error()
        _require_scope_id(self.session_id)
        status = _require_plain_string(self.final_status)
        if status not in _TERMINAL_WORKFLOW_STATUSES:
            raise _input_error()
        step_count = _require_nonnegative_integer(self.step_count)
        claim = _validate_workflow_claim(self.invocations)
        if step_count != len(claim):
            raise _input_error()
        _require_checksum(self.workflow_checksum)
        checkpointed_at = _require_nonnegative_integer(self.checkpointed_at)
        metadata = _metadata_snapshot(
            self.signature_metadata,
            expected_profile=WORKFLOW_CHECKPOINT_SIGNING_PROFILE,
            expected_type=EvidenceType.WORKFLOW_CHECKPOINT,
        )
        if checkpointed_at != metadata.signed_at:
            raise _input_error()
        _validate_signature(self.signature, metadata)
        object.__setattr__(self, "signature_metadata", metadata)

    def to_dict(self) -> dict[str, object]:
        return {
            "checkpoint_schema_version": self.checkpoint_schema_version,
            "checkpoint_profile": self.checkpoint_profile,
            "canonicalization_profile": self.canonicalization_profile,
            "workflow_schema_version": self.workflow_schema_version,
            "session_id": self.session_id,
            "final_status": self.final_status,
            "step_count": self.step_count,
            "invocations": [
                {"step_index": step_index, "checksum": checksum}
                for step_index, checksum in self.invocations
            ],
            "workflow_checksum": self.workflow_checksum,
            "checkpointed_at": self.checkpointed_at,
            "signature_metadata": SignatureMetadata.to_dict(self.signature_metadata),
            "signature": self.signature,
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
        return cls(
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


CheckpointRecord = TrustedChainCheckpoint | TrustedWorkflowCheckpoint


@dataclass(frozen=True, slots=True)
class CheckpointVerificationResult:
    input_indexes: tuple[int, ...]
    checkpoint: CheckpointRecord
    scope_id: str
    chain_index: int | None
    signature_result: ArtifactVerificationResult | None
    binding_status: CheckpointBindingStatus

    def __post_init__(self) -> None:
        if type(self) is not CheckpointVerificationResult:
            raise _input_error()
        if (
            type(self.input_indexes) is not tuple
            or len(self.input_indexes) == 0
            or any(
                type(index) is not int or not 0 <= index <= SAFE_INTEGER_MAX
                for index in self.input_indexes
            )
        ):
            raise _input_error()
        checkpoint_type = type(self.checkpoint)
        if checkpoint_type not in (TrustedChainCheckpoint, TrustedWorkflowCheckpoint):
            raise _input_error()
        if type(self.scope_id) is not str:
            raise _input_error()
        if checkpoint_type is TrustedChainCheckpoint:
            if (
                self.scope_id != self.checkpoint.chain_id
                or type(self.chain_index) is not int
                or self.chain_index != self.checkpoint.chain_index
            ):
                raise _input_error()
        elif self.scope_id != self.checkpoint.session_id or self.chain_index is not None:
            raise _input_error()
        if self.signature_result is not None and type(
            self.signature_result
        ) is not ArtifactVerificationResult:
            raise _input_error()
        if type(self.binding_status) is not CheckpointBindingStatus:
            raise _input_error()
        if self.signature_result is None and self.binding_status not in (
            CheckpointBindingStatus.NOT_EVALUATED,
            CheckpointBindingStatus.OUT_OF_SCOPE,
        ):
            raise _input_error()
