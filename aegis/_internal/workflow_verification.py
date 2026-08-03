"""Typed verification for workflow-signed invocation claimed sets."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from aegis._internal.evidence_profiles import (
    ContentIntegrity,
    verify_content_checksum_v2,
)
from aegis._internal.signature_models import SignatureStatus
from aegis._internal.verification import (
    Completeness,
    VerificationError,
    _verify_signatures,
)


_HEX64_RE = re.compile(r"^[a-f0-9]{64}$")


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


def _error(code: str, message: str, index: int | None = None) -> VerificationError:
    return VerificationError(code=code, message=message, index=index)


def _report(
    claim_status: WorkflowClaimStatus,
    signature_status: SignatureStatus,
    errors: list[VerificationError],
) -> WorkflowVerificationReport:
    return WorkflowVerificationReport(
        claim_status=claim_status,
        signature_status=signature_status,
        completeness=Completeness.UNPROVEN,
        errors=tuple(errors),
    )


def _legacy_workflow(workflow: dict[str, Any]) -> bool:
    version = workflow.get("workflow_schema_version")
    return (
        isinstance(version, str)
        and version.startswith("1.")
        and "audit_schema_version" not in workflow
    )


def _materialize_invocations(
    invocations: object,
    errors: list[VerificationError],
) -> list[object] | None:
    if (
        isinstance(invocations, (str, bytes, bytearray, Mapping))
        or not isinstance(invocations, Iterable)
    ):
        errors.append(
            _error(
                "WORKFLOW_INVOCATIONS_INPUT_INVALID",
                "Invocations must be supplied as an ordered iterable",
            )
        )
        return None
    try:
        return list(invocations)
    except Exception:
        errors.append(
            _error(
                "WORKFLOW_INVOCATIONS_INPUT_INVALID",
                "Invocations could not be consumed as an ordered iterable",
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
    if len(claim) != step_count:
        errors.append(
            _error(
                "WORKFLOW_CLAIM_COUNT_MISMATCH",
                f"Claim contains {len(claim)} entries for step_count={step_count}",
            )
        )
    claimed_indices = [item["step_index"] for item in typed_claim]
    expected_indices = list(range(step_count))
    if len(typed_claim) == len(claim) and claimed_indices != expected_indices:
        errors.append(
            _error(
                "WORKFLOW_CLAIM_INDEX_MISMATCH",
                "Workflow claim indices must be ordered and gapless",
            )
        )
    return step_count, typed_claim


def _select_session_invocations(
    supplied: list[object],
    session_id: str,
) -> list[object]:
    selected: list[object] = []
    for artifact in supplied:
        if type(artifact) is not dict:
            continue
        context = artifact.get("context")
        if type(context) is dict and context.get("session_id") == session_id:
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


def verify_workflow_claim(
    workflow: object,
    invocations: object,
    *,
    expected_checkpoint: None = None,
) -> WorkflowVerificationReport:
    """Compare one workflow claim with an ordered, session-filtered artifact set.

    Issue #46 owns the future ``TrustedWorkflowCheckpoint`` contract. Until
    that type exists, the only accepted checkpoint value is ``None`` and
    completeness cannot be promoted beyond ``UNPROVEN``.
    """
    errors: list[VerificationError] = []
    if type(workflow) is not dict:
        errors.append(
            _error("WORKFLOW_INPUT_INVALID", "Workflow must be a plain JSON object")
        )
        return _report(
            WorkflowClaimStatus.NOT_EVALUATED,
            SignatureStatus.INDETERMINATE,
            errors,
        )

    signature_status, _ = _verify_signatures((workflow,), None, errors)
    if expected_checkpoint is not None:
        errors.append(
            _error(
                "WORKFLOW_CHECKPOINT_UNSUPPORTED",
                "Trusted workflow checkpoints are unavailable until issue #46",
            )
        )
        return _report(
            WorkflowClaimStatus.NOT_EVALUATED,
            signature_status,
            errors,
        )

    if _legacy_workflow(workflow):
        return _report(WorkflowClaimStatus.LEGACY, signature_status, errors)

    if verify_content_checksum_v2(workflow) is not ContentIntegrity.VALID:
        errors.append(
            _error(
                "WORKFLOW_CONTENT_INVALID",
                "Workflow checksum or v2 content profile is invalid",
            )
        )
        return _report(WorkflowClaimStatus.INVALID, signature_status, errors)

    supplied = _materialize_invocations(invocations, errors)
    if supplied is None:
        return _report(
            WorkflowClaimStatus.NOT_EVALUATED,
            signature_status,
            errors,
        )

    initial_error_count = len(errors)
    validated = _validate_claim(workflow, errors)
    if validated is None:
        return _report(WorkflowClaimStatus.INVALID, signature_status, errors)
    step_count, claim = validated
    session_id = workflow["session_id"]
    assert isinstance(session_id, str)
    selected = _select_session_invocations(supplied, session_id)
    _compare_selected(selected, step_count, claim, errors)
    claim_status = (
        WorkflowClaimStatus.VALID
        if len(errors) == initial_error_count
        else WorkflowClaimStatus.INVALID
    )
    return _report(claim_status, signature_status, errors)


__all__ = [
    "WorkflowClaimStatus",
    "WorkflowVerificationReport",
    "verify_workflow_claim",
]
