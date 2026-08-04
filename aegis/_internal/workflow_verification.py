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
from aegis._internal.evidence_finalizer import (
    _audit_validator,
    _workflow_validator,
)
from aegis._internal.signature_models import SignatureStatus
from aegis._internal.verification import (
    Completeness,
    VerificationError,
    _verify_signatures,
)
from aegis._internal.workflow_limits import MAX_WORKFLOW_ATTEMPTS


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


class _VerificationBudgetExceeded(Exception):
    pass


class _BoundedErrors(list[VerificationError]):
    def append(self, error: VerificationError) -> None:
        if len(self) < MAX_WORKFLOW_VERIFICATION_ERRORS:
            super().append(error)


def _measure_json_document(value: object, *, byte_limit: int) -> int:
    """Measure one JSON document iteratively under byte/depth/cycle bounds."""
    total = 0
    scheduled_nodes = 1
    seen_containers: set[int] = set()
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_WORKFLOW_VERIFICATION_DEPTH:
            raise _VerificationBudgetExceeded
        if current is None or isinstance(current, bool):
            total += 5
        elif isinstance(current, str):
            if len(current) > byte_limit - total:
                raise _VerificationBudgetExceeded
            total += len(current.encode("utf-8")) + 2
        elif isinstance(current, int) and not isinstance(current, bool):
            total += 32
        elif isinstance(current, float):
            total += 32
        elif type(current) is list:
            identity = id(current)
            if identity in seen_containers:
                raise _VerificationBudgetExceeded
            seen_containers.add(identity)
            total += 2 + len(current)
            if (
                total > byte_limit
                or len(current)
                > MAX_WORKFLOW_VERIFICATION_NODES - scheduled_nodes
            ):
                raise _VerificationBudgetExceeded
            scheduled_nodes += len(current)
            for item in reversed(current):
                stack.append((item, depth + 1))
        elif type(current) is dict:
            identity = id(current)
            if identity in seen_containers:
                raise _VerificationBudgetExceeded
            seen_containers.add(identity)
            total += 2 + len(current)
            if (
                total > byte_limit
                or len(current)
                > MAX_WORKFLOW_VERIFICATION_NODES - scheduled_nodes
            ):
                raise _VerificationBudgetExceeded
            scheduled_nodes += len(current)
            for key in current:
                if type(key) is not str:
                    raise _VerificationBudgetExceeded
                if len(key) > byte_limit - total:
                    raise _VerificationBudgetExceeded
                total += len(key.encode("utf-8")) + 3
            for item in current.values():
                stack.append((item, depth + 1))
        else:
            raise _VerificationBudgetExceeded
        if total > byte_limit:
            raise _VerificationBudgetExceeded
    return total


def _within_document_budget(
    value: object,
    errors: list[VerificationError],
    *,
    remaining_bytes: int,
) -> int | None:
    try:
        return _measure_json_document(value, byte_limit=remaining_bytes)
    except (
        _VerificationBudgetExceeded,
        MemoryError,
        RecursionError,
        UnicodeError,
        ValueError,
        OverflowError,
    ):
        errors.append(
            _error(
                "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED",
                "Workflow verification input exceeds a configured limit",
            )
        )
        return None


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
    consumed_bytes: int,
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
        iterator = iter(invocations)
    except Exception:
        errors.append(
            _error(
                "WORKFLOW_INVOCATIONS_INPUT_INVALID",
                "Invocations could not be consumed as an ordered iterable",
            )
        )
        return None
    supplied: list[object] = []
    total_bytes = consumed_bytes
    while True:
        try:
            artifact = next(iterator)
        except StopIteration:
            return supplied
        except Exception:
            errors.append(
                _error(
                    "WORKFLOW_INVOCATIONS_INPUT_INVALID",
                    "Invocations could not be consumed as an ordered iterable",
                )
            )
            return None
        if len(supplied) >= MAX_WORKFLOW_SUPPLIED_ARTIFACTS:
            errors.append(
                _error(
                    "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED",
                    "Supplied invocation count exceeds the verifier limit",
                )
            )
            return None
        measured = _within_document_budget(
            artifact,
            errors,
            remaining_bytes=MAX_WORKFLOW_VERIFICATION_BYTES - total_bytes,
        )
        if measured is None:
            return None
        total_bytes += measured
        supplied.append(artifact)


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
    errors: list[VerificationError] = _BoundedErrors()
    if type(workflow) is not dict:
        errors.append(
            _error("WORKFLOW_INPUT_INVALID", "Workflow must be a plain JSON object")
        )
        return _report(
            WorkflowClaimStatus.NOT_EVALUATED,
            SignatureStatus.INDETERMINATE,
            errors,
        )

    workflow_bytes = _within_document_budget(
        workflow,
        errors,
        remaining_bytes=MAX_WORKFLOW_VERIFICATION_BYTES,
    )
    if workflow_bytes is None:
        return _report(
            WorkflowClaimStatus.NOT_EVALUATED,
            SignatureStatus.INDETERMINATE,
            errors,
        )

    try:
        signature_status, _ = _verify_signatures((workflow,), None, errors)
    except Exception:
        errors.append(
            _error(
                "SIGNATURE_VERIFICATION_ERROR",
                "Workflow signature metadata could not be evaluated",
            )
        )
        signature_status = SignatureStatus.INDETERMINATE
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

    try:
        content_status = verify_content_checksum_v2(workflow)
    except Exception:
        content_status = ContentIntegrity.NOT_EVALUATED
    if content_status is not ContentIntegrity.VALID:
        errors.append(
            _error(
                "WORKFLOW_CONTENT_INVALID",
                "Workflow checksum or v2 content profile is invalid",
            )
        )
        return _report(WorkflowClaimStatus.INVALID, signature_status, errors)

    initial_error_count = len(errors)
    validated = _validate_claim(workflow, errors)

    try:
        workflow_schema_valid = _workflow_validator().is_valid(workflow)
    except Exception:
        workflow_schema_valid = False
    if not workflow_schema_valid:
        errors.append(
            _error(
                "WORKFLOW_SCHEMA_INVALID",
                "Workflow does not match the v2 workflow artifact schema",
            )
        )
        return _report(WorkflowClaimStatus.INVALID, signature_status, errors)

    if validated is None:
        return _report(WorkflowClaimStatus.INVALID, signature_status, errors)

    supplied = _materialize_invocations(
        invocations,
        errors,
        consumed_bytes=workflow_bytes,
    )
    if supplied is None:
        return _report(
            WorkflowClaimStatus.NOT_EVALUATED,
            signature_status,
            errors,
        )

    step_count, claim = validated
    session_id = workflow["session_id"]
    assert isinstance(session_id, str)
    selected = _select_session_invocations(supplied, session_id, errors)
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
