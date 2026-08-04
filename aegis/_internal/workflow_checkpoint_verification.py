"""Bounded preparation and exact binding for one workflow checkpoint."""

from __future__ import annotations

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


@dataclass(frozen=True, slots=True)
class PreparedWorkflowCheckpoint:
    """One reparsed, core-owned workflow checkpoint."""

    record: PreparedCheckpoint


@dataclass(frozen=True, slots=True)
class DetachedWorkflowCheckpointInput:
    """An early core-owned snapshot of one exact typed checkpoint."""

    snapshot: object


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
) -> DetachedWorkflowCheckpointInput | None:
    """Detach an exact typed checkpoint before caller-controlled iteration."""
    if type(expected_checkpoint) is not TrustedWorkflowCheckpoint:
        return None
    return DetachedWorkflowCheckpointInput(
        _typed_checkpoint_snapshot(expected_checkpoint)
    )


def prepare_workflow_checkpoint_input(
    expected_checkpoint: object | None,
    budget: VerificationBudget,
    errors: BoundedVerificationErrors,
    *,
    detached: DetachedWorkflowCheckpointInput | None = None,
) -> PreparedWorkflowCheckpoint | None:
    """Measure and reparse only one exact workflow checkpoint record."""
    if expected_checkpoint is None:
        return None

    if type(expected_checkpoint) is TrustedWorkflowCheckpoint:
        snapshot = (
            detached.snapshot
            if detached is not None
            else _typed_checkpoint_snapshot(expected_checkpoint)
        )
        measurement = snapshot
    else:
        snapshot = None
        measurement = _measurement_value(expected_checkpoint)

    try:
        budget.measure(measurement)
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

    if snapshot is None:
        errors.append(
            _error(
                "CHECKPOINT_RECORD_INVALID",
                "Checkpoint record is invalid",
                0,
            )
        )
        return None

    try:
        checkpoint = TrustedWorkflowCheckpoint.from_dict(snapshot)
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


def _workflow_binding(
    checkpoint: TrustedWorkflowCheckpoint,
) -> dict[str, object]:
    return {
        "workflow_schema_version": checkpoint.workflow_schema_version,
        "session_id": checkpoint.session_id,
        "final_status": checkpoint.final_status,
        "step_count": checkpoint.step_count,
        "invocations": [
            {"step_index": step_index, "checksum": checksum}
            for step_index, checksum in checkpoint.invocations
        ],
        "workflow_checksum": checkpoint.workflow_checksum,
    }


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
    bound_workflow = {
        "workflow_schema_version": workflow.get("workflow_schema_version"),
        "session_id": workflow.get("session_id"),
        "final_status": workflow.get("status"),
        "step_count": workflow.get("step_count"),
        "invocations": workflow.get("invocations"),
        "workflow_checksum": workflow.get("checksum"),
    }
    binding_status = (
        CheckpointBindingStatus.MATCHED
        if bound_workflow == _workflow_binding(checkpoint)
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
