"""
workflow doctor — runtime/evidence-aware diagnostics for AEGIS governance targets.

Doctor always starts with lint for the detected target kind, then adds
time-aware and evidence-aware checks that static lint cannot perform.

Each public function returns a list of finding dicts:
    {
        "code":        str,   # machine-readable code
        "severity":    str,   # "ERROR" | "WARNING" | "INFO"
        "message":     str,   # human-readable description
        "next_action": str,   # plain-English guidance
    }

An empty list means no issues found.
The CLI exits 1 only if any finding has severity "ERROR".
"""

from __future__ import annotations

import copy
import json
import re
from datetime import date
from pathlib import Path
from typing import Any

from aegis._internal.errors import (
    PolicyLoadError,
    PolicyValidationError,
)
from aegis._internal.policy_loader import (
    FilePolicyLoader,
    _FileLoadContext,
    _prepare_resolve_compile_policy,
)
from aegis._internal.workflow_lint import (
    _lint_prepared_starter,
    _lint_prepared_policy,
    _prepare_starter_target,
    detect_target_kind,
    lint_workflow_artifact,
    _audit_schema,
)

from jsonschema import Draft7Validator


# ---------------------------------------------------------------------------
# Next-action registry
# ---------------------------------------------------------------------------

_NEXT_ACTIONS: dict[str, str] = {
    "WORKFLOW_INVALID_TRANSITION": (
        "Ensure your workflow follows the correct lifecycle: "
        "open_session() -> enforce_step_pre_call() / enforce_step_post_call() "
        "-> complete() or cancel(). "
        "Call resume() before adding steps when the session is PAUSED."
    ),
    "WORKFLOW_APPROVAL_REQUIRED": (
        "Implement a real approval callback to replace the simulated one in "
        "_request_human_approval(). When approval is denied, call "
        "session.cancel() explicitly. When approved, call session.resume() "
        "before continuing with additional steps."
    ),
    "WORKFLOW_SOURCE_REQUIRED": (
        "Provide context.provenance.source_ids in every invocation context "
        "when using ProvenanceGate(require_source_ids=True). "
        "See docs/INTEGRATION_GUIDE.md for provenance usage."
    ),
    "WORKFLOW_TOOL_BUDGET_EXCEEDED": (
        "Reduce the number of tool_calls in your invocation to stay within "
        "the max_calls limit defined in policy.yaml (tools.allowed_tools). "
        "See policies/policy_dsl_spec.md for tool constraint syntax."
    ),
    "WORKFLOW_STEP_BUDGET_EXCEEDED": (
        "The session reached its max_steps limit defined in the policy workflow "
        "block. Increase max_steps in policy.yaml, or redesign the workflow to "
        "complete within the allowed number of steps."
    ),
    "WORKFLOW_UNREACHABLE_STEP": (
        "Update workflow.allowed_transitions so every step in "
        "workflow.required_sequence can be reached from the first required step, "
        "or remove the unreachable step from the required sequence."
    ),
    "WORKFLOW_DEAD_END_STEP": (
        "Add a valid successor for the non-terminal step in "
        "workflow.allowed_transitions, or shorten workflow.required_sequence so "
        "the step is terminal."
    ),
    "WORKFLOW_REQUIRED_SEQUENCE_IMPOSSIBLE": (
        "Align workflow.required_sequence with workflow.allowed_transitions by "
        "allowing each required consecutive step pair, or reorder the required "
        "sequence to match the declared transition graph."
    ),
    "WORKFLOW_UNBOUNDED_HANDOFF_LOOP": (
        "Break the participant handoff cycle by adding workflow.max_steps, "
        "setting workflow.escalation.require_approval_after_steps, requiring "
        "approval for a role in the cycle, or removing one cyclic handoff."
    ),
    "WORKFLOW_SOURCE_PROVENANCE_WARNING": (
        "Attach context.provenance.source_ids or "
        "steps[i].metadata.governance.source_ids for source-bearing context. "
        "If the step is intentionally non-evidence-bearing, mark that in step "
        "metadata so operators can distinguish generated context from "
        "source-backed evidence."
    ),
    "WORKFLOW_HOOK_DENIED": (
        "A ValidatorHook returned DENY or timed out. Inspect the hook's "
        "denial_reason in the error details. If using the built-in timeout, "
        "increase the hook's timeout_ms or make the hook respond faster."
    ),
    "WORKFLOW_UNSUPPORTED_BINDING": (
        "Remove or rename condition/guard entries that reference unsupported "
        "protocol names (grpc, websocket, soap). Only HTTP/REST adapter "
        "bindings are supported in v0.9.0."
    ),
    "WORKFLOW_SESSION_TOKEN_INVALID": (
        "Ensure callers provide a well-formed, non-replayed session token "
        "in the required precondition field. Use GovernanceSession as a "
        "context manager to manage token lifecycle automatically. "
        "Tokens are single-use; retry with a fresh token if the session "
        "is still open."
    ),
    "WORKFLOW_STARTER_INTEGRITY_ERROR": (
        "Re-run 'aegis workflow init --profile <profile>' to regenerate the "
        "starter, or fix the integrity issue described above. "
        "See the generated README.md in the starter directory for usage."
    ),
    "POLICY_LOAD_ERROR": (
        "Fix the policy file syntax or structure. "
        "See policies/policy_dsl_spec.md for the full policy DSL reference."
    ),
    "POLICY_PATH_OUTSIDE_ROOT": (
        "Select a target contained by the configured policy root, or supply "
        "the intended broader root with 'workflow doctor --policy-root ROOT'."
    ),
    "POLICY_SCHEMA_VALIDATION_ERROR": (
        "Fix the schema violation in policy.yaml. "
        "Run 'aegis policy lint <file>' to list all violations. "
        "See policies/policy_dsl_spec.md for field specifications."
    ),
    "TOOL_CONSTRAINT_VIOLATION": (
        "Fix the tool constraint issue in policy.yaml. "
        "See policies/policy_dsl_spec.md for tool allowlist syntax."
    ),
}

_DEFAULT_NEXT_ACTION = (
    "Review the policy or artifact described above. "
    "See docs/INTEGRATION_GUIDE.md and policies/policy_dsl_spec.md for guidance."
)


def _next_action(code: str) -> str:
    return _NEXT_ACTIONS.get(code, _DEFAULT_NEXT_ACTION)


# ---------------------------------------------------------------------------
# Finding constructors
# ---------------------------------------------------------------------------

def _finding(
    code: str,
    severity: str,
    message: str,
    next_action: str | None = None,
) -> dict:
    return {
        "code": code,
        "severity": severity,
        "message": message,
        "next_action": next_action or _next_action(code),
    }


def _lint_to_doctor(lint_findings: list[dict]) -> list[dict]:
    """Promote lint findings to doctor findings (severity=ERROR for lint errors)."""
    result = []
    for f in lint_findings:
        code = f["code"]
        # Treat all lint failures as ERROR-severity in the doctor context
        result.append(_finding(
            code,
            "ERROR",
            f["message"],
        ))
    return result


# ---------------------------------------------------------------------------
# Policy doctor
# ---------------------------------------------------------------------------

_UNSUPPORTED_PROTOCOLS = frozenset({"grpc", "websocket", "soap"})
_MEMORY_LIKE_KEYS = frozenset({
    "memory",
    "memories",
    "conversation_memory",
    "retrieved_memory",
    "retrieved_context",
    "knowledge_base_context",
})

# Session-token misuse patterns from enforcement.py
_TOKEN_MISUSE_PATTERNS = [
    "SessionPreCallResult cannot be completed via enforce_post_call",
    "token belongs to a different session",
    "token already consumed",
    "token not registered in this session",
    "token fields do not match minted values",
]


def _has_source_ids(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    source_ids = value.get("source_ids")
    return (
        isinstance(source_ids, list)
        and bool(source_ids)
        and all(isinstance(source_id, str) for source_id in source_ids)
    )


def _has_memory_like_key(value: Any) -> bool:
    return isinstance(value, dict) and bool(_MEMORY_LIKE_KEYS & set(value))


def _has_metadata_source_ids(metadata: Any) -> bool:
    if not isinstance(metadata, dict):
        return False
    return (
        _has_source_ids(metadata)
        or _has_source_ids(metadata.get("provenance"))
        or _has_source_ids(metadata.get("governance"))
    )


def _governance_requires_source_ids(governance: Any) -> bool:
    if not isinstance(governance, dict):
        return False
    decision_basis = governance.get("decision_basis") or []
    return (
        governance.get("source_required") is True
        or (
            isinstance(decision_basis, list)
            and "provenance.source_ids" in decision_basis
        )
    )


def _workflow_source_provenance_warnings(artifact: dict[str, Any]) -> list[dict]:
    findings = []
    steps = artifact.get("steps") or []
    if isinstance(steps, list):
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            metadata = step.get("metadata")
            if not isinstance(metadata, dict):
                continue
            governance = metadata.get("governance")
            if (
                _governance_requires_source_ids(governance)
                and not _has_source_ids(governance)
            ):
                step_id = step.get("step_id")
                step_label = step_id if isinstance(step_id, str) else f"index {idx}"
                findings.append(_finding(
                    "WORKFLOW_SOURCE_PROVENANCE_WARNING",
                    "WARNING",
                    "Workflow step metadata declares source-bearing governance "
                    f"for step {step_label!r} but does not include "
                    "metadata.governance.source_ids.",
                    _next_action("WORKFLOW_SOURCE_PROVENANCE_WARNING"),
                ))

    if not findings:
        metadata = artifact.get("metadata")
        if _has_memory_like_key(metadata) and not _has_metadata_source_ids(metadata):
            findings.append(_finding(
                "WORKFLOW_SOURCE_PROVENANCE_WARNING",
                "WARNING",
                "Workflow artifact metadata includes memory-like context keys but "
                "does not include provenance source IDs.",
                _next_action("WORKFLOW_SOURCE_PROVENANCE_WARNING"),
            ))

    return findings


def _audit_source_provenance_warnings(artifact: dict[str, Any]) -> list[dict]:
    context = artifact.get("context")
    if not _has_memory_like_key(context):
        return []
    context_has_sources = (
        isinstance(context, dict)
        and _has_source_ids(context.get("provenance"))
    )
    top_level_has_sources = _has_source_ids(artifact.get("provenance"))
    if context_has_sources or top_level_has_sources:
        return []
    return [_finding(
        "WORKFLOW_SOURCE_PROVENANCE_WARNING",
        "WARNING",
        "Audit artifact context includes memory-like fields but neither "
        "context.provenance.source_ids nor top-level provenance.source_ids is present.",
        _next_action("WORKFLOW_SOURCE_PROVENANCE_WARNING"),
    )]


def _date_failure_finding(exc: PolicyValidationError) -> dict:
    details = dict(exc.details) if isinstance(exc.details, dict) else {}
    effective = details.get("effective_date")
    expiration = details.get("expiration_date")
    today = details.get("today")
    if (
        isinstance(effective, str)
        and isinstance(today, str)
        and today < effective
    ):
        return _finding(
            exc.code,
            "WARNING",
            f"Policy not yet active: effective_date is {effective}, "
            f"today is {today}",
        )
    if (
        isinstance(expiration, str)
        and isinstance(today, str)
        and today > expiration
    ):
        return _finding(
            exc.code,
            "ERROR",
            f"Policy expired: expiration_date is {expiration}, today is {today}",
        )
    return _finding(exc.code, "ERROR", "Policy date validation failed")


def diagnose_workflow_policy(
    path: str,
    *,
    now: date | None = None,
    policy_root: str | Path | None = None,
) -> list[dict]:
    """Run policy diagnostics from one authorized prepared source."""
    today = now or date.today()
    try:
        loader = (
            FilePolicyLoader(policy_root)
            if policy_root is not None
            else None
        )
        result = _prepare_resolve_compile_policy(
            path,
            loader=loader,
            clock=lambda: today,
            capture_date_failures=True,
        )
    except (PolicyLoadError, PolicyValidationError) as exc:
        return [_finding(exc.code, "ERROR", str(exc))]

    if result.prepared is None:
        raise AssertionError("file diagnostics require a prepared source")
    findings = [
        _date_failure_finding(exc)
        for exc in result.date_failures
    ]
    lint_findings = _lint_prepared_policy(
        result.prepared,
        result.compiled,
        target_kind="policy",
        target_label=path,
    )
    findings.extend(_lint_to_doctor(lint_findings))
    raw = copy.deepcopy(result.prepared.raw_policy)

    # Unsupported binding detection
    conditions: dict = raw.get("conditions", {}) or {}
    guards: list = raw.get("guards", []) or []
    guard_condition_names = set()
    for g in guards:
        if isinstance(g, dict):
            cname = g.get("condition", "")
            if cname:
                guard_condition_names.add(cname)

    all_condition_names = set(conditions.keys()) | guard_condition_names
    binding_hits = {
        n for n in all_condition_names
        if any(proto in n.lower() for proto in _UNSUPPORTED_PROTOCOLS)
    }
    if binding_hits:
        findings.append(_finding(
            "WORKFLOW_UNSUPPORTED_BINDING",
            "WARNING",
            f"Policy references condition/guard names that suggest unsupported "
            f"protocol bindings: {sorted(binding_hits)}. "
            "Only HTTP/REST adapter bindings are supported in v0.9.0.",
            _next_action("WORKFLOW_UNSUPPORTED_BINDING"),
        ))

    # Session-token precondition advisory
    pre_conditions = raw.get("pre_conditions", {}) or {}
    pre_required = pre_conditions.get("required", {}) or {}
    if isinstance(pre_required, dict):
        token_keys = {k for k in pre_required if "token" in k.lower()}
    else:
        token_keys = set()

    if token_keys:
        keys_str = ", ".join(sorted(token_keys))
        findings.append(_finding(
            "WORKFLOW_SESSION_TOKEN_INVALID",
            "INFO",
            f"Policy requires session token fields in preconditions: {keys_str}. "
            "Ensure tokens are well-formed and non-replayed; stale or malformed "
            "tokens raise WORKFLOW_SESSION_TOKEN_INVALID at runtime.",
            _next_action("WORKFLOW_SESSION_TOKEN_INVALID"),
        ))

    return findings


# ---------------------------------------------------------------------------
# Starter directory doctor
# ---------------------------------------------------------------------------

_APPROVAL_PATTERNS = [
    re.compile(r"session\.pause\(\)"),
    re.compile(r"_request_human_approval\("),
    re.compile(r"session\.resume\(\)"),
    re.compile(r"session\.cancel\(\)"),
]

_PROVENANCE_PATTERNS = [
    re.compile(r"ProvenanceGate\("),
    re.compile(r"require_source_ids\s*=\s*True"),
    re.compile(r"source_ids"),
]


def diagnose_starter_dir(
    path: str,
    *,
    policy_root: str | Path | None = None,
) -> list[dict]:
    """
    Run doctor diagnostics on a starter directory.

    Steps:
    1. Lint the starter directory
    2. Detect approval checkpoint pattern -> WORKFLOW_APPROVAL_REQUIRED advisory
    3. Detect regulated provenance requirement -> WORKFLOW_SOURCE_REQUIRED advisory
    """
    try:
        prepared = _prepare_starter_target(path, policy_root=policy_root)
    except PolicyLoadError as exc:
        return [_finding(exc.code, "ERROR", str(exc))]

    findings: list[dict] = []

    # 1. Lint
    lint_findings = _lint_prepared_starter(prepared)
    if lint_findings:
        findings.extend(_lint_to_doctor(lint_findings))
        return findings

    # Read workflow_example.py for pattern detection
    p = prepared.directory
    workflow_py = p / "workflow_example.py"
    try:
        source = workflow_py.read_text(encoding="utf-8")
    except OSError:
        return findings

    # 2. Approval checkpoint detection
    approval_hit = any(pat.search(source) for pat in _APPROVAL_PATTERNS)
    if approval_hit:
        findings.append(_finding(
            "WORKFLOW_APPROVAL_REQUIRED",
            "INFO",
            "This starter includes a human approval checkpoint "
            "(session.pause() / session.resume() / session.cancel() pattern). "
            "You must implement a real approval callback to replace the "
            "simulated one in _request_human_approval().",
            _next_action("WORKFLOW_APPROVAL_REQUIRED"),
        ))

    # 3. Provenance / source-required detection
    provenance_hit = any(pat.search(source) for pat in _PROVENANCE_PATTERNS)
    if provenance_hit:
        findings.append(_finding(
            "WORKFLOW_SOURCE_REQUIRED",
            "INFO",
            "This starter requires source IDs in every invocation context "
            "(ProvenanceGate with require_source_ids=True). "
            "Provide context.provenance.source_ids in every enforce_step_pre_call() "
            "invocation, or enforcement will fail with CustomGateViolationError.",
            _next_action("WORKFLOW_SOURCE_REQUIRED"),
        ))

    return findings


# ---------------------------------------------------------------------------
# Workflow artifact doctor
# ---------------------------------------------------------------------------

# Exception type names that map to WORKFLOW_INVALID_TRANSITION.
# Includes SessionStateError and all new PR-08 engine error classes.
_INVALID_TRANSITION_EXCEPTION_TYPES = frozenset({
    "SessionStateError",
    "WorkflowParticipantMismatchError",
    "WorkflowSequenceViolationError",
    "WorkflowTransitionDeniedError",
    "WorkflowRoleViolationError",
    "WorkflowProtocolViolationError",
    "WorkflowHandoffDeniedError",
})

# Exception type names that map directly to their own reason codes.
_EXCEPTION_TYPE_TO_CODE: dict[str, str] = {
    "WorkflowStepBudgetExceededError": "WORKFLOW_STEP_BUDGET_EXCEEDED",
    "WorkflowHookDeniedError": "WORKFLOW_HOOK_DENIED",
}

_LIFECYCLE_FAILURE_PATTERNS = [
    "Invalid session lifecycle transition",
    "cannot call",
    "session is not in",
    "already in terminal state",
    "SessionStateError",
]


def diagnose_workflow_artifact(path: str) -> list[dict]:
    """
    Run doctor diagnostics on a workflow artifact JSON file.

    Steps:
    1. Lint the artifact
    2. Map FAILED + SessionStateError -> WORKFLOW_INVALID_TRANSITION
    3. INCOMPLETE artifacts -> recovery guidance
    """
    findings: list[dict] = []

    # 1. Lint
    lint_findings = lint_workflow_artifact(path)
    if lint_findings:
        findings.extend(_lint_to_doctor(lint_findings))
        return findings

    p = Path(path)
    artifact: dict = json.loads(p.read_text(encoding="utf-8"))
    status = artifact.get("status", "")
    failure_summary = artifact.get("failure_summary") or {}

    if status == "FAILED":
        exc_type = failure_summary.get("exception_type", "")
        msg = failure_summary.get("message", "")

        is_invalid_transition = (
            exc_type in _INVALID_TRANSITION_EXCEPTION_TYPES
            or any(pat.lower() in msg.lower() for pat in _LIFECYCLE_FAILURE_PATTERNS)
        )
        if is_invalid_transition:
            # Build a detail-rich message using any extra context stored in
            # the failure_summary (participant_id, step_id, etc.)
            detail_parts = []
            for detail_key in ("participant_id", "step_id", "from_step", "to_step", "role"):
                val = failure_summary.get(detail_key)
                if val:
                    detail_parts.append(f"{detail_key}={val!r}")
            detail_str = ("; " + ", ".join(detail_parts)) if detail_parts else ""
            findings.append(_finding(
                "WORKFLOW_INVALID_TRANSITION",
                "ERROR",
                f"Workflow session failed due to an invalid lifecycle transition. "
                f"Exception: {exc_type}{detail_str}. Message: {msg or '(none)'}.",
                _next_action("WORKFLOW_INVALID_TRANSITION"),
            ))
        elif exc_type in _EXCEPTION_TYPE_TO_CODE:
            code = _EXCEPTION_TYPE_TO_CODE[exc_type]
            findings.append(_finding(
                code,
                "ERROR",
                f"Workflow session failed: {exc_type}. Message: {msg or '(none)'}.",
                _next_action(code),
            ))
        else:
            findings.append(_finding(
                "POLICY_LOAD_ERROR",
                "ERROR",
                f"Workflow artifact has FAILED status. "
                f"Exception: {exc_type or '(unknown)'}. "
                f"Message: {msg or '(none)'}.",
                _DEFAULT_NEXT_ACTION,
            ))

    elif status == "INCOMPLETE":
        findings.append(_finding(
            "WORKFLOW_INVALID_TRANSITION",
            "WARNING",
            "Workflow artifact is INCOMPLETE. The session exited without a "
            "terminal call. Recovery options: call complete() when the workflow "
            "finishes normally; call cancel() to abandon a paused approval path; "
            "call resume() before adding steps if the session was paused.",
            _next_action("WORKFLOW_INVALID_TRANSITION"),
        ))

    findings.extend(_workflow_source_provenance_warnings(artifact))
    return findings


# ---------------------------------------------------------------------------
# Invocation audit artifact doctor
# ---------------------------------------------------------------------------

_PROVENANCE_FAILURE_CODES = frozenset({
    "PROVENANCE_MISSING",
    "SOURCE_IDS_MISSING",
    "CUSTOM_GATE_VIOLATION",
})

_TOKEN_MISUSE_RE = re.compile(
    "|".join(re.escape(p) for p in _TOKEN_MISUSE_PATTERNS),
    re.IGNORECASE,
)


def diagnose_audit_artifact(path: str) -> list[dict]:
    """
    Run doctor diagnostics on an invocation audit artifact JSON file.

    Maps real runtime failure patterns to frozen PR-06 reason codes.
    """
    findings: list[dict] = []
    p = Path(path)

    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:
        findings.append(_finding(
            "POLICY_LOAD_ERROR",
            "ERROR",
            f"Cannot read audit artifact: {exc}",
        ))
        return findings

    try:
        artifact: Any = json.loads(raw)
    except json.JSONDecodeError as exc:
        findings.append(_finding(
            "POLICY_LOAD_ERROR",
            "ERROR",
            f"JSON parse error in audit artifact: {exc}",
        ))
        return findings

    if not isinstance(artifact, dict):
        findings.append(_finding(
            "POLICY_LOAD_ERROR",
            "ERROR",
            "Audit artifact must be a JSON object.",
        ))
        return findings

    # Schema validation
    schema = _audit_schema()
    validator = Draft7Validator(schema)
    schema_errors = sorted(
        validator.iter_errors(artifact), key=lambda e: list(e.path)
    )
    if schema_errors:
        for err in schema_errors:
            pointer = ".".join(str(s) for s in err.absolute_path) or "$"
            findings.append(_finding(
                "POLICY_SCHEMA_VALIDATION_ERROR",
                "ERROR",
                f"Audit artifact schema violation at {pointer}: {err.message}",
            ))
        return findings

    enforcement_result = artifact.get("enforcement_result", "")
    findings.extend(_audit_source_provenance_warnings(artifact))
    if enforcement_result == "PASS":
        return findings  # No issues

    # FAIL — map to frozen reason codes
    failure_gate = artifact.get("failure_gate", "") or ""
    failure_reason = artifact.get("failure_reason", "") or ""
    failures: list[dict] = artifact.get("failures", []) or []
    failure_codes = {f.get("code", "") for f in failures if isinstance(f, dict)}
    failure_messages = " ".join(
        f.get("message", "") for f in failures if isinstance(f, dict)
    )
    all_failure_text = f"{failure_reason} {failure_messages}".strip()

    mapped = False

    # Source-required: custom_gate_violation with provenance-related codes
    if failure_gate == "custom_gate_violation":
        provenance_hit = bool(
            failure_codes & _PROVENANCE_FAILURE_CODES
            or re.search(
                r"provenance|source.?id", all_failure_text, re.IGNORECASE
            )
        )
        if provenance_hit:
            findings.append(_finding(
                "WORKFLOW_SOURCE_REQUIRED",
                "ERROR",
                f"Invocation failed due to missing source IDs or provenance. "
                f"Failure gate: {failure_gate}. "
                f"Reason: {failure_reason or '(see failures array)'}.",
                _next_action("WORKFLOW_SOURCE_REQUIRED"),
            ))
            mapped = True

    # Tool budget: tool_validation gate
    if failure_gate == "tool_validation":
        findings.append(_finding(
            "WORKFLOW_TOOL_BUDGET_EXCEEDED",
            "ERROR",
            f"Invocation failed due to tool constraint violation. "
            f"Failure gate: {failure_gate}. "
            f"Reason: {failure_reason or '(see failures array)'}.",
            _next_action("WORKFLOW_TOOL_BUDGET_EXCEEDED"),
        ))
        mapped = True

    # Session-token misuse: invocation_validation gate with token pattern
    if failure_gate == "invocation_validation":
        token_hit = bool(_TOKEN_MISUSE_RE.search(all_failure_text))
        if token_hit:
            findings.append(_finding(
                "WORKFLOW_SESSION_TOKEN_INVALID",
                "ERROR",
                f"Invocation failed due to session token misuse. "
                f"Failure gate: {failure_gate}. "
                f"Reason: {failure_reason or '(see failures array)'}.",
                _next_action("WORKFLOW_SESSION_TOKEN_INVALID"),
            ))
            mapped = True

    # Generic fallback
    if not mapped:
        findings.append(_finding(
            "POLICY_LOAD_ERROR",
            "ERROR",
            f"Invocation audit artifact shows FAIL. "
            f"Failure gate: {failure_gate or '(unknown)'}. "
            f"Reason: {failure_reason or '(see failures array)'}.",
            _DEFAULT_NEXT_ACTION,
        ))

    return findings


# ---------------------------------------------------------------------------
# Unified entry-point
# ---------------------------------------------------------------------------

def diagnose_target(
    path: str,
    *,
    kind: str = "auto",
    now: date | None = None,
    policy_root: str | Path | None = None,
) -> list[dict]:
    """
    Run doctor diagnostics on any supported target.

    Args:
        path: Path to the target.
        kind: One of "auto", "policy", "starter_dir", "workflow_artifact",
              "audit_artifact". When "auto", the kind is inferred.
        now:  Date to use for time-aware checks (defaults to today).

    Returns:
        List of finding dicts (empty = no issues).
    """
    if kind == "auto" and Path(path).suffix.lower() in {".yaml", ".yml"}:
        kind = "policy"
    elif kind == "auto":
        detection_path = path
        if policy_root is not None:
            try:
                loader = FilePolicyLoader(policy_root)
                context = _FileLoadContext.create(path, loader.policy_root)
                detection_path = str(
                    loader._canonical_candidate(path, context=context)
                )
            except PolicyLoadError as exc:
                return [_finding(exc.code, "ERROR", str(exc))]
        kind = detect_target_kind(detection_path)

    if kind == "policy":
        return diagnose_workflow_policy(
            path,
            now=now,
            policy_root=policy_root,
        )
    elif kind == "starter_dir":
        return diagnose_starter_dir(path, policy_root=policy_root)
    elif kind == "workflow_artifact":
        return diagnose_workflow_artifact(path)
    elif kind == "audit_artifact":
        return diagnose_audit_artifact(path)
    else:
        return [_finding(
            "POLICY_LOAD_ERROR",
            "ERROR",
            f"Cannot determine target kind for: {path}. "
            "Supported targets: .yaml/.yml policy files, starter directories "
            "(containing policy.yaml + workflow_example.py + README.md), "
            "workflow artifact .json files, and invocation audit artifact .json files.",
        )]
