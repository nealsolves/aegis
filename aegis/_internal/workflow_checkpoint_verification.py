"""Bounded preparation and exact binding for one workflow checkpoint."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

from aegis._internal.canonicalization import canonicalize_v2
from aegis._internal.checkpoint_models import (
    CheckpointBindingStatus,
    CheckpointSignatureStatus,
    CheckpointVerificationResult,
    TrustedWorkflowCheckpoint,
)
from aegis._internal.checkpoint_verification import (
    PreparedCheckpoint,
    unavailable_checkpoint_result,
    verify_prepared_checkpoint,
)
from aegis._internal.external_signing import ExternalArtifactVerifier
from aegis._internal.signature_models import (
    AnchorStatus,
    ArtifactVerificationResult,
    SignatureStatus,
)
from aegis._internal.verification_contracts import Completeness, VerificationError
from aegis._internal.verification_limits import (
    BoundedVerificationErrors,
    VerificationBudget,
    VerificationInputError,
)


_MAX_WORKFLOW_INVOCATIONS = 1_024
_INVOCATION_BINDING_FIELDS = frozenset({"step_index", "checksum"})
_WORKFLOW_BINDING_FIELDS = (
    "workflow_schema_version",
    "session_id",
    "status",
    "step_count",
    "invocations",
    "checksum",
)
_MISSING_BINDING_FIELD = object()


@dataclass(frozen=True, slots=True)
class PreparedWorkflowCheckpoint:
    """One reparsed, core-owned workflow checkpoint."""

    record: PreparedCheckpoint


@dataclass(frozen=True, slots=True)
class DetachedWorkflowCheckpointInput:
    """Frozen presence, type policy, and data for one checkpoint input."""

    supplied: bool
    exact_type: bool
    snapshot: object
    measurement: object
    measurement_failed: bool


@dataclass(frozen=True, slots=True)
class CheckpointEvaluation:
    """Checkpoint axes returned to workflow verification."""

    signature_status: CheckpointSignatureStatus
    anchor_status: AnchorStatus
    completeness: Completeness
    results: tuple[CheckpointVerificationResult, ...]


def _error(code: str, message: str, index: int | None = None) -> VerificationError:
    return VerificationError(code=code, message=message, index=index)


def _typed_checkpoint_snapshot(value: TrustedWorkflowCheckpoint) -> object:
    """Guard the only potentially growing field before ``to_dict`` allocates."""
    try:
        claim = value.invocations
    except Exception:
        return None
    if (
        type(claim) is not tuple
        or len(claim) > _MAX_WORKFLOW_INVOCATIONS
        or any(
            type(entry) is not tuple
            or len(entry) != 2
            or type(entry[0]) is not int
            or type(entry[1]) is not str
            for entry in claim
        )
    ):
        return None
    try:
        return TrustedWorkflowCheckpoint.to_dict(value)
    except Exception:
        return None


def _measurement_value(value: object) -> object:
    if type(value) in (dict, list, str, int, float, bool):
        return value
    return None


def detach_workflow_checkpoint_input(
    expected_checkpoint: object | None,
    budget: VerificationBudget,
) -> DetachedWorkflowCheckpointInput:
    """Freeze checkpoint input policy before caller-controlled iteration."""
    if expected_checkpoint is None:
        return DetachedWorkflowCheckpointInput(False, False, None, None, False)
    if type(expected_checkpoint) is TrustedWorkflowCheckpoint:
        snapshot = _typed_checkpoint_snapshot(expected_checkpoint)
        return DetachedWorkflowCheckpointInput(
            True,
            True,
            snapshot,
            snapshot,
            False,
        )

    measurement = _measurement_value(expected_checkpoint)
    probe = VerificationBudget(
        remaining_bytes=budget.remaining_bytes,
        remaining_nodes=budget.remaining_nodes,
    )
    try:
        probe.measure(measurement)
        measurement = deepcopy(measurement)
    except Exception:
        return DetachedWorkflowCheckpointInput(True, False, None, None, True)
    return DetachedWorkflowCheckpointInput(
        True,
        False,
        None,
        measurement,
        False,
    )


def prepare_workflow_checkpoint_input(
    detached: DetachedWorkflowCheckpointInput,
    budget: VerificationBudget,
    errors: BoundedVerificationErrors,
) -> PreparedWorkflowCheckpoint | None:
    """Measure and reparse only one exact workflow checkpoint record."""
    if not detached.supplied:
        return None

    try:
        if detached.measurement_failed:
            raise VerificationInputError
        budget.measure(detached.measurement)
    except VerificationInputError:
        errors.append(
            _error(
                "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED",
                "Workflow verification input exceeds a configured limit",
            )
        )
        return None
    except Exception:
        errors.append(
            _error(
                "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED",
                "Workflow verification input exceeds a configured limit",
            )
        )
        return None

    if not detached.exact_type or detached.snapshot is None:
        errors.append(
            _error(
                "CHECKPOINT_RECORD_INVALID",
                "Checkpoint record is invalid",
                0,
            )
        )
        return None

    try:
        checkpoint = TrustedWorkflowCheckpoint.from_dict(detached.snapshot)
        canonical_record = canonicalize_v2(
            TrustedWorkflowCheckpoint.to_dict(checkpoint)
        ).data
    except Exception:
        errors.append(
            _error(
                "CHECKPOINT_RECORD_INVALID",
                "Checkpoint record is invalid",
                0,
            )
        )
        return None
    return PreparedWorkflowCheckpoint(
        PreparedCheckpoint((0,), checkpoint, canonical_record)
    )


def _checkpoint_signature_status(
    signature_status: SignatureStatus,
) -> CheckpointSignatureStatus:
    mapping = {
        SignatureStatus.VALID: CheckpointSignatureStatus.VALID,
        SignatureStatus.INVALID: CheckpointSignatureStatus.INVALID,
        SignatureStatus.UNKNOWN_KEY: CheckpointSignatureStatus.UNKNOWN_KEY,
        SignatureStatus.REVOKED: CheckpointSignatureStatus.REVOKED,
        SignatureStatus.INDETERMINATE: CheckpointSignatureStatus.INDETERMINATE,
    }
    return mapping.get(
        signature_status,
        CheckpointSignatureStatus.INDETERMINATE,
    )


def _workflow_binding_matches(
    checkpoint: TrustedWorkflowCheckpoint,
    workflow: dict[str, object],
) -> bool:
    if type(workflow) is not dict:
        return False
    values: list[object] = [
        _MISSING_BINDING_FIELD
        for _ in _WORKFLOW_BINDING_FIELDS
    ]
    for key, value in dict.items(workflow):
        field_index = None
        key_type = type(key)
        if key_type is str:
            for index, field in enumerate(_WORKFLOW_BINDING_FIELDS):
                if key == field:
                    field_index = index
                    break
        elif any(
            base is str
            for base in type.__getattribute__(key_type, "__mro__")
        ):
            for field in _WORKFLOW_BINDING_FIELDS:
                if str.__eq__(key, field) is True:
                    return False
        else:
            return False
        if field_index is not None:
            values[field_index] = value
    if any(value is _MISSING_BINDING_FIELD for value in values):
        return False
    (
        workflow_schema_version,
        session_id,
        final_status,
        step_count,
        invocations,
        workflow_checksum,
    ) = values
    if (
        type(workflow_schema_version) is not str
        or type(session_id) is not str
        or type(final_status) is not str
        or type(step_count) is not int
        or type(invocations) is not list
        or type(workflow_checksum) is not str
    ):
        return False
    if workflow_schema_version != checkpoint.workflow_schema_version:
        return False
    if session_id != checkpoint.session_id:
        return False
    if final_status != checkpoint.final_status:
        return False
    if step_count != checkpoint.step_count:
        return False
    if workflow_checksum != checkpoint.workflow_checksum:
        return False
    if len(invocations) != len(checkpoint.invocations):
        return False
    for entry, expected in zip(invocations, checkpoint.invocations):
        if type(entry) is not dict:
            return False
        keys = tuple(entry)
        if (
            len(keys) != 2
            or any(type(key) is not str for key in keys)
            or frozenset(keys) != _INVOCATION_BINDING_FIELDS
        ):
            return False
        step_index = entry["step_index"]
        checksum = entry["checksum"]
        if type(step_index) is not int or type(checksum) is not str:
            return False
        if step_index != expected[0] or checksum != expected[1]:
            return False
    return True


def _result(
    prepared: PreparedCheckpoint,
    binding_status: CheckpointBindingStatus,
    signature_result: ArtifactVerificationResult,
) -> CheckpointVerificationResult:
    checkpoint = prepared.checkpoint
    assert type(checkpoint) is TrustedWorkflowCheckpoint
    return CheckpointVerificationResult(
        input_indexes=prepared.input_indexes,
        checkpoint=checkpoint,
        scope_id=checkpoint.session_id,
        chain_index=None,
        signature_result=signature_result,
        binding_status=binding_status,
    )


def evaluate_workflow_checkpoint(
    prepared: PreparedWorkflowCheckpoint,
    workflow: dict[str, object],
    *,
    workflow_content_valid: bool,
    claim_valid: bool,
    verifier: ExternalArtifactVerifier | None,
    errors: BoundedVerificationErrors,
) -> CheckpointEvaluation:
    """Verify and bind the host-selected checkpoint to one workflow claim."""
    record = prepared.record
    checkpoint = record.checkpoint
    assert type(checkpoint) is TrustedWorkflowCheckpoint
    binding_status = (
        CheckpointBindingStatus.MATCHED
        if _workflow_binding_matches(checkpoint, workflow)
        else CheckpointBindingStatus.CONFLICT
    )

    provider_contract_failed = False
    try:
        signature_result = verify_prepared_checkpoint(record, verifier)
    except Exception:
        errors.append(
            _error(
                "CHECKPOINT_VERIFICATION_ERROR",
                "Checkpoint verification could not be evaluated",
                0,
            )
        )
        signature_result = unavailable_checkpoint_result(record)
        provider_contract_failed = True

    anchored = (
        signature_result.signature_status is SignatureStatus.VALID
        and signature_result.anchor_status is AnchorStatus.ANCHORED
    )
    anchored_conflict = anchored and (
        binding_status is CheckpointBindingStatus.CONFLICT
    )
    anchored_match = anchored and (
        binding_status is CheckpointBindingStatus.MATCHED
    )
    if anchored_conflict:
        errors.append(
            _error(
                "CHECKPOINT_BINDING_CONFLICT",
                "Trusted checkpoint conflicts with supplied workflow evidence",
                0,
            )
        )

    if anchored_conflict:
        completeness = Completeness.CONTRADICTED
    elif anchored_match and not claim_valid:
        completeness = Completeness.CONTRADICTED
    elif anchored_match and workflow_content_valid and claim_valid:
        completeness = Completeness.CHECKPOINT_PROVEN
    else:
        completeness = Completeness.UNPROVEN

    anchor_status = signature_result.anchor_status
    if provider_contract_failed or anchored_conflict:
        anchor_status = AnchorStatus.INVALID
    return CheckpointEvaluation(
        signature_status=_checkpoint_signature_status(
            signature_result.signature_status
        ),
        anchor_status=anchor_status,
        completeness=completeness,
        results=(_result(record, binding_status, signature_result),),
    )


def invalid_workflow_checkpoint_evaluation() -> CheckpointEvaluation:
    """Return fixed axes for a supplied record rejected before verification."""
    return CheckpointEvaluation(
        signature_status=CheckpointSignatureStatus.INDETERMINATE,
        anchor_status=AnchorStatus.INVALID,
        completeness=Completeness.UNPROVEN,
        results=(),
    )
