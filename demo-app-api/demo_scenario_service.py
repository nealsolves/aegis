"""Deterministic AEGIS-backed execution for the three governance roleplays."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis import (
    AIGCError,
    HMACSigner,
    ProvenanceGate,
    WorkflowApprovalRequiredError,
    WorkflowSequenceViolationError,
)
from aegis.workflow_export import export_workflow
from aegis.workflow_trace import reconstruct_trace

from demo_contract import (
    DemoError,
    DemoGateResult,
    ScenarioRunResponse,
    demo_source,
)
from demo_errors import public_demo_error
from demo_fixtures import (
    ATLAS_DEMO_ONLY_SIGNING_KEY,
    FIXTURE_VERSION,
    ScenarioFixture,
    get_fixture,
)
from demo_gates import (
    DemoClinicalScopeGate,
    DemoNorthstarRoleGate,
    DemoPrivacyGate,
)
from demo_registry import SCENARIO_VARIANTS
from demo_runtime import demo_aegis


POLICY_DIR = Path(__file__).resolve().parent / "demo_policies"


@dataclass(frozen=True)
class MeridianStep:
    step_id: str
    participant_id: str
    role: str
    tool_calls: tuple[dict[str, str], ...] = ()


MERIDIAN_STEPS = (
    MeridianStep("invoice_intake", "meridian-invoice-01", "accounts_payable"),
    MeridianStep(
        "vendor_verification",
        "meridian-vendor-01",
        "vendor_verifier",
        ({"name": "fictional_vendor_lookup", "call_id": "mv-verify-01"},),
    ),
    MeridianStep("risk_review", "meridian-risk-01", "risk_reviewer"),
    MeridianStep(
        "payment_preparation",
        "meridian-payment-01",
        "payment_preparer",
        (
            {
                "name": "prepare_no_op_payment_record",
                "call_id": "mv-prepare-01",
            },
        ),
    ),
    MeridianStep("approval", "meridian-approver-01", "finance_approver"),
)


def _reason_code(exc: Exception) -> str:
    details = getattr(exc, "details", None)
    if isinstance(details, dict):
        gate_failures = details.get("custom_gate_failures")
        if isinstance(gate_failures, list) and gate_failures:
            specific = gate_failures[0].get("code")
            if isinstance(specific, str):
                return specific
    artifact = getattr(exc, "audit_artifact", None) or {}
    failures = artifact.get("failures")
    if isinstance(failures, list) and failures:
        specific = failures[0].get("code")
        if isinstance(specific, str):
            return specific
    if isinstance(details, dict) and isinstance(details.get("reason_code"), str):
        return details["reason_code"]
    code = getattr(exc, "code", None)
    if isinstance(code, str):
        return code
    return str(
        artifact.get("metadata", {}).get(
            "reason_code",
            "AEGIS_ENFORCEMENT_FAILED",
        )
    )


def _policy_path(name: str) -> str:
    return f"{name}.yaml"


def _demo_error(reason_code: str) -> DemoError:
    try:
        return DemoError(**public_demo_error(reason_code))
    except KeyError:
        return DemoError(**public_demo_error("AEGIS_ENFORCEMENT_FAILED"))


def _invocation(
    fixture: ScenarioFixture,
    policy_name: str,
    *,
    role: str | None = None,
    tool_calls: tuple[dict[str, str], ...] = (),
) -> dict[str, Any]:
    invocation = {
        "policy_file": _policy_path(policy_name),
        "model_provider": "internal",
        "model_identifier": "deterministic-fixture-v1",
        "role": role or fixture.role,
        "input": {"prompt": fixture.prompt},
        "context": dict(fixture.context),
    }
    if tool_calls:
        invocation["tool_calls"] = [dict(call) for call in tool_calls]
    return invocation


def _evaluated_gate_ids(artifact: dict[str, Any] | None) -> set[str]:
    if not artifact:
        return set()
    metadata = artifact.get("metadata") or {}
    gate_ids: set[str] = set()
    for key in (
        "gates_evaluated",
        "pre_call_gates_evaluated",
        "post_call_gates_evaluated",
    ):
        values = metadata.get(key)
        if isinstance(values, list):
            gate_ids.update(value for value in values if isinstance(value, str))
    return gate_ids


def _gate(
    *,
    name: str,
    phase: str,
    evaluated: bool,
    outcome: str | None,
    reason_code: str | None = None,
) -> DemoGateResult:
    return DemoGateResult(
        name=name,
        phase=phase,
        evaluated=evaluated,
        outcome=outcome,
        reason_code=reason_code,
    )


def _artifact_gate(
    artifact: dict[str, Any],
    *,
    name: str,
    artifact_name: str,
    phase: str,
    failed_reason: str | None = None,
) -> DemoGateResult:
    evaluated = artifact_name in _evaluated_gate_ids(artifact)
    outcome = "FAIL" if evaluated and failed_reason else ("PASS" if evaluated else None)
    return _gate(
        name=name,
        phase=phase,
        evaluated=evaluated,
        outcome=outcome,
        reason_code=failed_reason if evaluated else None,
    )


def _response(
    fixture: ScenarioFixture,
    *,
    gates: list[DemoGateResult],
    decision: str,
    artifact: dict[str, Any] | None,
    workflow_artifact: dict[str, Any] | None = None,
    error: DemoError | None = None,
) -> ScenarioRunResponse:
    return ScenarioRunResponse(
        scenario_id=fixture.scenario_id,
        variant=fixture.variant,
        fixture_version=FIXTURE_VERSION,
        transcript=[dict(entry) for entry in fixture.transcript],
        gates=gates,
        decision=decision,
        artifact=artifact,
        workflow_artifact=workflow_artifact,
        error=error,
        source=demo_source(),
    )


def _run_atlas(fixture: ScenarioFixture) -> ScenarioRunResponse:
    signer = HMACSigner(ATLAS_DEMO_ONLY_SIGNING_KEY)
    governance = demo_aegis(
        POLICY_DIR,
        signer=signer,
        custom_gates=[ProvenanceGate()],
    )
    invocation = _invocation(
        fixture,
        "atlas",
        tool_calls=(
            {"name": "fictional_account_lookup", "call_id": "atlas-lookup-01"},
            {"name": "fictional_refund_review", "call_id": "atlas-review-01"},
        ),
    )

    try:
        pre_call = governance.enforce_pre_call(invocation)
        artifact = governance.enforce_post_call(pre_call, fixture.output)
    except AIGCError as exc:
        artifact = exc.audit_artifact
        if artifact is None:
            raise
        reason = _reason_code(exc)
        return _response(
            fixture,
            gates=[
                _artifact_gate(
                    artifact,
                    name="role_validation",
                    artifact_name="role_validation",
                    phase="pre_call",
                ),
                _artifact_gate(
                    artifact,
                    name="provenance",
                    artifact_name="custom:provenance_gate",
                    phase="post_call",
                    failed_reason=reason,
                ),
                _artifact_gate(
                    artifact,
                    name="output_schema",
                    artifact_name="schema_validation",
                    phase="post_call",
                ),
            ],
            decision="FAIL",
            artifact=artifact,
            error=_demo_error(reason),
        )

    return _response(
        fixture,
        gates=[
            _artifact_gate(
                artifact,
                name="role_validation",
                artifact_name="role_validation",
                phase="pre_call",
            ),
            _artifact_gate(
                artifact,
                name="provenance",
                artifact_name="custom:provenance_gate",
                phase="post_call",
            ),
            _artifact_gate(
                artifact,
                name="output_schema",
                artifact_name="schema_validation",
                phase="post_call",
            ),
        ],
        decision="PASS",
        artifact=artifact,
    )


def _northstar_gates(
    artifact: dict[str, Any],
    *,
    failed_reason: str | None = None,
) -> list[DemoGateResult]:
    risk_evaluated = artifact.get("risk_score") is not None
    return [
        _artifact_gate(
            artifact,
            name="privacy_scope",
            artifact_name="custom:privacy_scope",
            phase="pre_call",
        ),
        _artifact_gate(
            artifact,
            name="role_validation",
            artifact_name="custom:northstar_role",
            phase="pre_call",
            failed_reason=(
                failed_reason if failed_reason == "ROLE_NOT_ALLOWED" else None
            ),
        ),
        _artifact_gate(
            artifact,
            name="clinical_scope",
            artifact_name="custom:clinical_scope",
            phase="post_call",
            failed_reason=(
                failed_reason
                if failed_reason == "PHYSICIAN_APPROVAL_REQUIRED"
                else None
            ),
        ),
        _gate(
            name="risk_scoring",
            phase="post_call",
            evaluated=risk_evaluated,
            outcome="PASS" if risk_evaluated else None,
        ),
    ]


def _run_northstar(fixture: ScenarioFixture) -> ScenarioRunResponse:
    governance = demo_aegis(
        POLICY_DIR,
        custom_gates=[
            DemoPrivacyGate(),
            DemoNorthstarRoleGate(),
            DemoClinicalScopeGate(),
        ],
    )
    invocation = _invocation(
        fixture,
        "northstar",
        tool_calls=(
            {
                "name": "fictional_schedule_lookup",
                "call_id": "northstar-lookup-01",
            },
        ),
    )

    if fixture.variant == "first_attempt":
        try:
            governance.enforce_pre_call(invocation)
        except AIGCError as exc:
            artifact = exc.audit_artifact
            if artifact is None:
                raise
            reason = _reason_code(exc)
            return _response(
                fixture,
                gates=_northstar_gates(artifact, failed_reason=reason),
                decision="FAIL",
                artifact=artifact,
                error=_demo_error(reason),
            )
        raise RuntimeError("Northstar unauthorized role unexpectedly passed")

    if fixture.variant == "authorized_retry":
        caught: AIGCError | None = None
        artifact: dict[str, Any] | None = None
        with governance.open_session(
            session_id="northstar-authorized-retry",
            policy_file=_policy_path("northstar"),
            metadata={"fixture_version": FIXTURE_VERSION},
        ) as session:
            token = session.enforce_step_pre_call(
                invocation,
                step_id="scheduling_summary",
                participant_id=fixture.participant,
            )
            try:
                session.enforce_step_post_call(token, fixture.output)
            except AIGCError as exc:
                if exc.audit_artifact is None:
                    raise
                caught = exc
                artifact = exc.audit_artifact
                session.pause(
                    approval_id="northstar-physician-approval",
                    approver_id="fictional-physician-reviewer",
                    reason="Physician approval is required for clinical scope.",
                )

        if caught is None or artifact is None:
            raise RuntimeError("Northstar clinical-scope rejection did not occur")
        reason = _reason_code(caught)
        return _response(
            fixture,
            gates=_northstar_gates(artifact, failed_reason=reason),
            decision="PAUSED",
            artifact=artifact,
            workflow_artifact=session.workflow_artifact,
            error=_demo_error(reason),
        )

    with governance.open_session(
        session_id="northstar-corrected",
        policy_file=_policy_path("northstar"),
        metadata={"fixture_version": FIXTURE_VERSION},
    ) as session:
        session.pause(
            approval_id="northstar-physician-approval",
            approver_id="fictional-physician-reviewer",
            reason="Physician approval is required for clinical scope.",
        )
        session.resume(
            approval_id="northstar-physician-approval",
            approver_id="fictional-physician-reviewer",
            approval_note="Scheduling-only scope approved.",
        )
        token = session.enforce_step_pre_call(
            invocation,
            step_id="scheduling_summary",
            participant_id=fixture.participant,
        )
        artifact = session.enforce_step_post_call(
            token,
            fixture.output,
            step_metadata={
                "governance": {
                    "approval_checkpoint_id": "northstar-physician-approval",
                    "decision_basis": "scheduling_only",
                    "rationale": "Physician-approved scheduling scope.",
                }
            },
        )
        session.complete()

    return _response(
        fixture,
        gates=_northstar_gates(artifact),
        decision="PASS",
        artifact=artifact,
        workflow_artifact=session.workflow_artifact,
    )


def _meridian_invocation(
    fixture: ScenarioFixture,
    step: MeridianStep,
) -> dict[str, Any]:
    return _invocation(
        fixture,
        "meridian",
        role=step.role,
        tool_calls=step.tool_calls,
    )


def _complete_meridian_step(
    session,
    fixture: ScenarioFixture,
    step: MeridianStep,
) -> dict[str, Any]:
    token = session.enforce_step_pre_call(
        _meridian_invocation(fixture, step),
        step_id=step.step_id,
        participant_id=step.participant_id,
    )
    return session.enforce_step_post_call(
        token,
        fixture.output[step.step_id],
        step_metadata={
            "governance": {
                "decision_basis": "required_sequence",
                "rationale": f"Completed governed step {step.step_id}.",
            }
        },
    )


def _run_meridian(fixture: ScenarioFixture) -> ScenarioRunResponse:
    governance = demo_aegis(POLICY_DIR)
    invocation_artifacts: list[dict[str, Any]] = []

    if fixture.variant == "first_attempt":
        caught: WorkflowSequenceViolationError | None = None
        with governance.open_session(
            session_id="meridian-first-attempt",
            policy_file=_policy_path("meridian"),
            metadata={"fixture_version": FIXTURE_VERSION},
        ) as session:
            invocation_artifacts.append(
                _complete_meridian_step(session, fixture, MERIDIAN_STEPS[0])
            )
            try:
                session.enforce_step_pre_call(
                    _meridian_invocation(fixture, MERIDIAN_STEPS[3]),
                    step_id=MERIDIAN_STEPS[3].step_id,
                    participant_id=MERIDIAN_STEPS[3].participant_id,
                )
            except WorkflowSequenceViolationError as exc:
                caught = exc
                session.pause(
                    approval_id="meridian-sequence-review",
                    approver_id="fictional-finance-reviewer",
                    reason="The required vendor-verification sequence was skipped.",
                )

        if caught is None:
            raise RuntimeError("Meridian sequence violation did not occur")
        reason = _reason_code(caught)
        return _response(
            fixture,
            gates=[
                _gate(
                    name="required_sequence",
                    phase="workflow",
                    evaluated=True,
                    outcome="PAUSED",
                    reason_code=reason,
                )
            ],
            decision="PAUSED",
            artifact=invocation_artifacts[0],
            workflow_artifact=session.workflow_artifact,
            error=_demo_error(reason),
        )

    with governance.open_session(
        session_id="meridian-corrected",
        policy_file=_policy_path("meridian"),
        metadata={"fixture_version": FIXTURE_VERSION},
    ) as session:
        for step in MERIDIAN_STEPS[:4]:
            invocation_artifacts.append(
                _complete_meridian_step(session, fixture, step)
            )

        approval_error: WorkflowApprovalRequiredError | None = None
        try:
            session.enforce_step_pre_call(
                _meridian_invocation(fixture, MERIDIAN_STEPS[4]),
                step_id=MERIDIAN_STEPS[4].step_id,
                participant_id=MERIDIAN_STEPS[4].participant_id,
            )
        except WorkflowApprovalRequiredError as exc:
            approval_error = exc

        if approval_error is None:
            raise RuntimeError("Meridian approval checkpoint did not occur")
        session.resume(
            approval_id=approval_error.details["checkpoint_id"],
            approver_id="fictional-finance-reviewer",
            approval_note="Fictional invoice workflow approved.",
        )
        invocation_artifacts.append(
            _complete_meridian_step(session, fixture, MERIDIAN_STEPS[4])
        )
        session.complete()

    workflow_artifact = session.workflow_artifact
    if workflow_artifact is None:
        raise RuntimeError("Meridian workflow artifact was not finalized")
    trace = reconstruct_trace(workflow_artifact, invocation_artifacts)
    exported = export_workflow(
        [workflow_artifact],
        invocation_artifacts,
        "audit",
    )
    evidence = {
        "invocation_artifacts": invocation_artifacts,
        "trace": trace,
        "export": exported,
    }
    return _response(
        fixture,
        gates=[
            _gate(
                name="required_sequence",
                phase="workflow",
                evaluated=True,
                outcome="PASS",
            ),
            _gate(
                name="approval_checkpoint",
                phase="workflow",
                evaluated=True,
                outcome="PASS",
            ),
            _gate(
                name="workflow_lifecycle",
                phase="workflow",
                evaluated=True,
                outcome="PASS",
            ),
        ],
        decision="PASS",
        artifact=evidence,
        workflow_artifact=workflow_artifact,
    )


def run_scenario(scenario_id: str, variant: str) -> ScenarioRunResponse:
    if variant not in SCENARIO_VARIANTS.get(scenario_id, frozenset()):
        raise ValueError(f"Unknown allowlisted scenario variant: {scenario_id}/{variant}")

    fixture = get_fixture(scenario_id, variant)
    if scenario_id == "atlas":
        return _run_atlas(fixture)
    if scenario_id == "northstar":
        return _run_northstar(fixture)
    if scenario_id == "meridian":
        return _run_meridian(fixture)
    raise ValueError(f"Unknown allowlisted scenario: {scenario_id}")
