"""Typed verification for workflow-signed invocation claimed sets."""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
from typing import Any

from aegis._internal.checkpoint_models import (
    CheckpointSignatureStatus,
    CheckpointVerificationResult,
)
from aegis._internal.evidence_profiles import (
    ContentIntegrity,
    verify_content_checksum_v2,
)
from aegis._internal.evidence_finalizer import (
    _audit_validator,
    _workflow_validator,
)
from aegis._internal.signature_models import AnchorStatus, SignatureStatus
from aegis._internal.verification import _verify_signatures
from aegis._internal.verification_contracts import Completeness, VerificationError
from aegis._internal.verification_limits import (
    BoundedVerificationErrors,
    VerificationBudget,
    VerificationInputError,
    _IterableConsumptionError,
    materialize_bounded_iterable,
)
from aegis._internal.workflow_limits import MAX_WORKFLOW_ATTEMPTS
from aegis._internal.workflow_checkpoint_verification import (
    CheckpointEvaluation,
    detach_workflow_checkpoint_input,
    evaluate_workflow_checkpoint,
    invalid_workflow_checkpoint_evaluation,
    prepare_workflow_checkpoint_input,
)


_HEX64_RE = re.compile(r"^[a-f0-9]{64}$")
_CORRELATION_FIELDS = frozenset(
    {"session_id", "step_id", "step_index", "workflow_policy_digest"}
)
_CORRELATION_TRIGGER_FIELDS = frozenset(
    {"step_index", "workflow_policy_digest"}
)
MAX_WORKFLOW_CLAIM_ENTRIES = MAX_WORKFLOW_ATTEMPTS
MAX_WORKFLOW_SUPPLIED_ARTIFACTS = MAX_WORKFLOW_ATTEMPTS
MAX_WORKFLOW_VERIFICATION_BYTES = 4 * 1024 * 1024
MAX_WORKFLOW_VERIFICATION_DEPTH = 32
MAX_WORKFLOW_VERIFICATION_NODES = 65_536
MAX_WORKFLOW_VERIFICATION_ERRORS = 100


class WorkflowClaimStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    LEGACY = "legacy"
    NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True, slots=True)
class WorkflowVerificationReport:
    claim_status: WorkflowClaimStatus
    signature_status: SignatureStatus
    completeness: Completeness
    errors: tuple[VerificationError, ...]
    checkpoint_signature_status: CheckpointSignatureStatus = (
        CheckpointSignatureStatus.NOT_EVALUATED
    )
    checkpoint_anchor_status: AnchorStatus = AnchorStatus.NOT_EVALUATED
    checkpoint_results: tuple[CheckpointVerificationResult, ...] = ()


def _error(code: str, message: str, index: int | None = None) -> VerificationError:
    return VerificationError(code=code, message=message, index=index)


def _report(
    claim_status: WorkflowClaimStatus,
    signature_status: SignatureStatus,
    errors: list[VerificationError],
    checkpoint_evaluation: CheckpointEvaluation | None = None,
) -> WorkflowVerificationReport:
    if checkpoint_evaluation is None:
        checkpoint_evaluation = CheckpointEvaluation(
            signature_status=CheckpointSignatureStatus.NOT_EVALUATED,
            anchor_status=AnchorStatus.NOT_EVALUATED,
            completeness=Completeness.UNPROVEN,
            results=(),
        )
    return WorkflowVerificationReport(
        claim_status=claim_status,
        signature_status=signature_status,
        completeness=checkpoint_evaluation.completeness,
        errors=tuple(errors),
        checkpoint_signature_status=checkpoint_evaluation.signature_status,
        checkpoint_anchor_status=checkpoint_evaluation.anchor_status,
        checkpoint_results=checkpoint_evaluation.results,
    )


def _legacy_workflow(workflow: dict[str, Any]) -> bool:
    version = workflow.get("workflow_schema_version")
    return (
        isinstance(version, str)
        and version.startswith("1.")
        and "audit_schema_version" not in workflow
        and workflow.get("artifact_type") == "workflow"
        and workflow.get("checksum") in {None, ""}
        and workflow.get("canonicalization_profile")
        in {None, "aegis-canonical-json-v1"}
        and workflow.get("signature") in {None, ""}
        and "signature_metadata" not in workflow
        and "step_count" not in workflow
        and "invocations" not in workflow
    )


def _materialize_invocations(
    invocations: object,
    errors: list[VerificationError],
    *,
    budget: VerificationBudget,
) -> list[object] | None:
    try:
        supplied = materialize_bounded_iterable(
            invocations,
            max_items=MAX_WORKFLOW_SUPPLIED_ARTIFACTS,
        )
    except _IterableConsumptionError:
        errors.append(
            _error(
                "WORKFLOW_INVOCATIONS_INPUT_INVALID",
                "Invocations could not be consumed as an ordered iterable",
            )
        )
        return None
    except VerificationInputError:
        errors.append(
            _error(
                "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED",
                "Supplied invocation count exceeds the verifier limit",
            )
        )
        return None
    except Exception:
        errors.append(
            _error(
                "WORKFLOW_INVOCATIONS_INPUT_INVALID",
                "Invocations could not be consumed as an ordered iterable",
            )
        )
        return None

    for artifact in supplied:
        try:
            budget.measure(artifact)
        except VerificationInputError:
            errors.append(
                _error(
                    "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED",
                    "Workflow verification input exceeds a configured limit",
                )
            )
            return None
    try:
        # The documents above charge every child.  This bounded core-owned
        # string charges the remaining JSON list overhead exactly: two bytes,
        # one comma per item, and one container node.
        budget.measure("x" * len(supplied))
    except VerificationInputError:
        errors.append(
            _error(
                "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED",
                "Workflow verification input exceeds a configured limit",
            )
        )
        return None
    try:
        return deepcopy(supplied)
    except Exception:
        errors.append(
            _error(
                "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED",
                "Workflow verification input exceeds a configured limit",
            )
        )
        return None


def _validate_claim(
    workflow: dict[str, Any],
    errors: list[VerificationError],
) -> tuple[int, list[dict[str, Any]]] | None:
    initial_error_count = len(errors)
    session_id = workflow.get("session_id")
    step_count = workflow.get("step_count")
    claim = workflow.get("invocations")
    if not isinstance(session_id, str) or not session_id:
        errors.append(
            _error("WORKFLOW_SESSION_ID_INVALID", "Workflow session_id is invalid")
        )
    if isinstance(step_count, bool) or not isinstance(step_count, int) or step_count < 0:
        errors.append(
            _error("WORKFLOW_STEP_COUNT_INVALID", "Workflow step_count is invalid")
        )
    if type(claim) is not list:
        errors.append(
            _error("WORKFLOW_CLAIM_INVALID", "Workflow invocations claim is invalid")
        )
    if len(errors) != initial_error_count:
        return None
    assert isinstance(step_count, int)
    assert isinstance(claim, list)
    if len(claim) != step_count:
        errors.append(
            _error(
                "WORKFLOW_CLAIM_COUNT_MISMATCH",
                f"Claim contains {len(claim)} entries for step_count={step_count}",
            )
        )
    if (
        step_count > MAX_WORKFLOW_CLAIM_ENTRIES
        or len(claim) > MAX_WORKFLOW_CLAIM_ENTRIES
    ):
        errors.append(
            _error(
                "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED",
                "Workflow claim exceeds the verifier entry limit",
            )
        )
        return None
    typed_claim: list[dict[str, Any]] = []
    for index, item in enumerate(claim):
        if (
            type(item) is not dict
            or set(item) != {"step_index", "checksum"}
            or isinstance(item.get("step_index"), bool)
            or not isinstance(item.get("step_index"), int)
            or item["step_index"] < 0
            or not isinstance(item.get("checksum"), str)
            or _HEX64_RE.fullmatch(item["checksum"]) is None
        ):
            errors.append(
                _error(
                    "WORKFLOW_CLAIM_ENTRY_INVALID",
                    f"Claim entry {index} is invalid",
                    index,
                )
            )
            continue
        typed_claim.append(item)
    if len(typed_claim) == len(claim) and any(
        item["step_index"] != expected_index
        for expected_index, item in enumerate(typed_claim)
    ):
        errors.append(
            _error(
                "WORKFLOW_CLAIM_INDEX_MISMATCH",
                "Workflow claim indices must be ordered and gapless",
            )
        )
    return step_count, typed_claim


def _reject_oversized_workflow_claim(
    workflow: dict[str, Any],
    errors: list[VerificationError],
) -> bool:
    step_count = workflow.get("step_count")
    claim = workflow.get("invocations")
    step_count_valid = type(step_count) is int and step_count >= 0
    claim_type_valid = type(claim) is list
    step_count_oversized = (
        type(step_count) is int
        and step_count > MAX_WORKFLOW_CLAIM_ENTRIES
    )
    claim_oversized = (
        claim_type_valid
        and len(claim) > MAX_WORKFLOW_CLAIM_ENTRIES
    )
    if not step_count_oversized and not claim_oversized:
        return False
    if not step_count_valid:
        errors.append(
            _error(
                "WORKFLOW_STEP_COUNT_INVALID",
                "Workflow step_count is invalid",
            )
        )
    if not claim_type_valid:
        errors.append(
            _error(
                "WORKFLOW_CLAIM_INVALID",
                "Workflow invocations claim is invalid",
            )
        )
    if step_count_valid and claim_type_valid and len(claim) != step_count:
        errors.append(
            _error(
                "WORKFLOW_CLAIM_COUNT_MISMATCH",
                f"Claim contains {len(claim)} entries for step_count={step_count}",
            )
        )
    errors.append(
        _error(
            "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED",
            "Workflow claim exceeds the verifier entry limit",
        )
    )
    return True


def _valid_workflow_correlation(context: object) -> bool:
    if type(context) is not dict or not _CORRELATION_FIELDS.issubset(context):
        return False
    return (
        isinstance(context.get("session_id"), str)
        and 1 <= len(context["session_id"]) <= 512
        and isinstance(context.get("step_id"), str)
        and 1 <= len(context["step_id"]) <= 512
        and type(context.get("step_index")) is int
        and context["step_index"] >= 0
        and isinstance(context.get("workflow_policy_digest"), str)
        and _HEX64_RE.fullmatch(context["workflow_policy_digest"]) is not None
        and (
            "participant_id" not in context
            or (
                isinstance(context["participant_id"], str)
                and 1 <= len(context["participant_id"]) <= 512
            )
        )
    )


def _select_session_invocations(
    supplied: list[object],
    session_id: str,
    errors: list[VerificationError],
) -> list[object]:
    selected: list[object] = []
    for position, artifact in enumerate(supplied):
        if type(artifact) is not dict:
            continue
        context = artifact.get("context")
        correlation_triggers = (
            _CORRELATION_TRIGGER_FIELDS.intersection(context)
            if type(context) is dict
            else set()
        )
        if correlation_triggers and not _valid_workflow_correlation(context):
            errors.append(
                _error(
                    "INVOCATION_CORRELATION_INVALID",
                    f"Supplied invocation at position {position} has invalid "
                    "workflow correlation",
                    position,
                )
            )
            continue
        if (
            _valid_workflow_correlation(context)
            and context.get("session_id") == session_id
        ):
            selected.append(artifact)
    return selected


def _compare_selected(
    selected: list[object],
    step_count: int,
    claim: list[dict[str, Any]],
    errors: list[VerificationError],
) -> None:
    if len(selected) != step_count:
        errors.append(
            _error(
                "WORKFLOW_CLAIM_COUNT_MISMATCH",
                f"Selected {len(selected)} invocation artifacts for "
                f"step_count={step_count}",
            )
        )
    for position, artifact in enumerate(selected):
        assert isinstance(artifact, dict)
        context = artifact.get("context")
        assert isinstance(context, dict)
        if (
            artifact.get("audit_schema_version") != "2.0"
            or "workflow_schema_version" in artifact
        ):
            errors.append(
                _error(
                    "INVOCATION_PROFILE_INVALID",
                    f"Supplied artifact at position {position} is not "
                    "v2 invocation evidence",
                    position,
                )
            )
        try:
            schema_valid = _audit_validator().is_valid(artifact)
        except Exception:
            schema_valid = False
        if not schema_valid:
            errors.append(
                _error(
                    "INVOCATION_SCHEMA_INVALID",
                    f"Supplied invocation at position {position} does not "
                    "match the v2 audit artifact schema",
                    position,
                )
            )
        if not _valid_workflow_correlation(context):
            errors.append(
                _error(
                    "INVOCATION_CORRELATION_INVALID",
                    f"Supplied invocation at position {position} has invalid "
                    "workflow correlation",
                    position,
                )
            )
        step_index = context.get("step_index")
        if (
            isinstance(step_index, bool)
            or not isinstance(step_index, int)
            or step_index < 0
            or step_index != position
        ):
            errors.append(
                _error(
                    "WORKFLOW_CLAIM_INDEX_MISMATCH",
                    f"Supplied position {position} has step_index={step_index!r}",
                    position,
                )
            )
        if verify_content_checksum_v2(artifact) is not ContentIntegrity.VALID:
            errors.append(
                _error(
                    "INVOCATION_CONTENT_INVALID",
                    f"Supplied invocation at position {position} has invalid content",
                    position,
                )
            )
        if position >= len(claim):
            continue
        expected = claim[position]
        if artifact.get("checksum") != expected["checksum"]:
            errors.append(
                _error(
                    "WORKFLOW_CLAIM_CHECKSUM_MISMATCH",
                    f"Supplied invocation checksum mismatch at position {position}",
                    position,
                )
            )


def _verify_workflow_claim(
    workflow: object,
    invocations: object,
    *,
    expected_checkpoint: object | None = None,
    checkpoint_verifier: object | None = None,
) -> WorkflowVerificationReport:
    """Compare one workflow claim with an ordered, session-filtered artifact set."""
    errors: list[VerificationError] = BoundedVerificationErrors()
    if type(workflow) is not dict:
        errors.append(
            _error("WORKFLOW_INPUT_INVALID", "Workflow must be a plain JSON object")
        )
        return _report(
            WorkflowClaimStatus.NOT_EVALUATED,
            SignatureStatus.INDETERMINATE,
            errors,
        )

    budget = VerificationBudget(
        remaining_bytes=MAX_WORKFLOW_VERIFICATION_BYTES,
        remaining_nodes=MAX_WORKFLOW_VERIFICATION_NODES,
    )
    try:
        budget.measure(workflow)
        workflow_snapshot = deepcopy(workflow)
        workflow_signature_snapshot = deepcopy(workflow_snapshot)
    except VerificationInputError:
        errors.append(
            _error(
                "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED",
                "Workflow verification input exceeds a configured limit",
            )
        )
        return _report(
            WorkflowClaimStatus.NOT_EVALUATED,
            SignatureStatus.INDETERMINATE,
            errors,
        )
    except Exception:
        errors.append(
            _error(
                "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED",
                "Workflow verification input exceeds a configured limit",
            )
        )
        return _report(
            WorkflowClaimStatus.NOT_EVALUATED,
            SignatureStatus.INDETERMINATE,
            errors,
        )

    if _reject_oversized_workflow_claim(workflow_snapshot, errors):
        return _report(
            WorkflowClaimStatus.INVALID,
            SignatureStatus.INDETERMINATE,
            errors,
        )

    detached_checkpoint = detach_workflow_checkpoint_input(
        expected_checkpoint,
        budget,
    )
    supplied = _materialize_invocations(
        invocations,
        errors,
        budget=budget,
    )
    if supplied is None:
        return _report(
            WorkflowClaimStatus.NOT_EVALUATED,
            SignatureStatus.INDETERMINATE,
            errors,
        )

    prepared_checkpoint = prepare_workflow_checkpoint_input(
        detached_checkpoint,
        budget,
        errors,
    )
    if any(
        error.code == "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED"
        for error in errors
    ):
        return _report(
            WorkflowClaimStatus.NOT_EVALUATED,
            SignatureStatus.INDETERMINATE,
            errors,
        )

    try:
        signature_status, _ = _verify_signatures(
            (workflow_signature_snapshot,),
            None,
            errors,
        )
    except Exception:
        errors.append(
            _error(
                "SIGNATURE_VERIFICATION_ERROR",
                "Workflow signature metadata could not be evaluated",
            )
        )
        signature_status = SignatureStatus.INDETERMINATE
    workflow_content_valid = False
    if _legacy_workflow(workflow_snapshot):
        claim_status = WorkflowClaimStatus.LEGACY
    else:
        try:
            content_status = verify_content_checksum_v2(workflow_snapshot)
        except Exception:
            content_status = ContentIntegrity.NOT_EVALUATED
        workflow_content_valid = content_status is ContentIntegrity.VALID
        if not workflow_content_valid:
            errors.append(
                _error(
                    "WORKFLOW_CONTENT_INVALID",
                    "Workflow checksum or v2 content profile is invalid",
                )
            )
            claim_status = WorkflowClaimStatus.INVALID
        else:
            initial_error_count = len(errors)
            validated = _validate_claim(workflow_snapshot, errors)

            try:
                workflow_schema_valid = _workflow_validator().is_valid(
                    workflow_snapshot
                )
            except Exception:
                workflow_schema_valid = False
            if not workflow_schema_valid:
                errors.append(
                    _error(
                        "WORKFLOW_SCHEMA_INVALID",
                        "Workflow does not match the v2 workflow artifact schema",
                    )
                )
                claim_status = WorkflowClaimStatus.INVALID
            elif validated is None:
                claim_status = WorkflowClaimStatus.INVALID
            else:
                step_count, claim = validated
                session_id = workflow_snapshot["session_id"]
                assert isinstance(session_id, str)
                selected = _select_session_invocations(
                    supplied,
                    session_id,
                    errors,
                )
                _compare_selected(selected, step_count, claim, errors)
                claim_status = (
                    WorkflowClaimStatus.VALID
                    if len(errors) == initial_error_count
                    else WorkflowClaimStatus.INVALID
                )

    checkpoint_evaluation = None
    if detached_checkpoint.supplied:
        if prepared_checkpoint is None:
            checkpoint_evaluation = invalid_workflow_checkpoint_evaluation()
        else:
            checkpoint_evaluation = evaluate_workflow_checkpoint(
                prepared_checkpoint,
                workflow_snapshot,
                workflow_content_valid=workflow_content_valid,
                claim_valid=claim_status is WorkflowClaimStatus.VALID,
                verifier=checkpoint_verifier,  # type: ignore[arg-type]
                errors=errors,
            )
    return _report(
        claim_status,
        signature_status,
        errors,
        checkpoint_evaluation,
    )


def verify_workflow_claim(
    workflow: object,
    invocations: object,
    *,
    expected_checkpoint: object | None = None,
    checkpoint_verifier: object | None = None,
) -> WorkflowVerificationReport:
    """Return a typed report for every catchable verifier failure."""
    try:
        return _verify_workflow_claim(
            workflow,
            invocations,
            expected_checkpoint=expected_checkpoint,
            checkpoint_verifier=checkpoint_verifier,
        )
    except (MemoryError, RecursionError):
        errors: list[VerificationError] = BoundedVerificationErrors()
        errors.append(
            _error(
                "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED",
                "Workflow verification input exceeds a configured limit",
            )
        )
    except Exception:
        errors = BoundedVerificationErrors()
        errors.append(
            _error(
                "WORKFLOW_VERIFICATION_ERROR",
                "Workflow verification could not be evaluated",
            )
        )
    return _report(
        WorkflowClaimStatus.NOT_EVALUATED,
        SignatureStatus.INDETERMINATE,
        errors,
    )


__all__ = [
    "WorkflowClaimStatus",
    "WorkflowVerificationReport",
    "verify_workflow_claim",
]
