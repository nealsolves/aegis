"""PR-11 workflow-governance core contract tests."""
from __future__ import annotations

from pathlib import Path

import pytest

from aegis import (
    AEGIS,
    CallbackAuditSink,
    GovernanceSession,
    InvocationValidationError,
    SessionPreCallResult,
    SessionStateError,
    WorkflowApprovalRequiredError,
    WorkflowHandoffDeniedError,
    WorkflowParticipantMismatchError,
    WorkflowRoleViolationError,
    WorkflowSequenceViolationError,
    WorkflowStepBudgetExceededError,
    WorkflowToolBudgetExceededError,
    WorkflowTransitionDeniedError,
)


POLICY = "tests/golden_replays/golden_policy_v1.yaml"
GOOD_OUTPUT = {"result": "answer", "confidence": 0.95}


def _inv(policy: str = POLICY, role: str = "planner") -> dict:
    return {
        "policy_file": policy,
        "model_provider": "openai",
        "model_identifier": "gpt-4",
        "role": role,
        "input": {"query": "test"},
        "context": {"role_declared": True, "schema_exists": True},
    }


def _workflow_policy(tmp_path: Path) -> str:
    path = tmp_path / "workflow_policy.yaml"
    path.write_text(
        """\
policy_version: "1.0"
roles: [planner, verifier]
pre_conditions:
  required:
    role_declared:
      type: boolean
    schema_exists:
      type: boolean
post_conditions:
  required: [output_schema_valid]
output_schema:
  type: object
  required: [result, confidence]
  properties:
    result: {type: string}
    confidence: {type: number}
workflow:
  max_steps: 3
  max_total_tool_calls: 2
  participants:
    - id: planner-a
      roles: [planner]
      protocols: [local]
    - id: verifier-b
      roles: [verifier]
      protocols: [local]
  required_sequence: [collect, review, finalize]
  allowed_transitions:
    collect: [review]
    review: [finalize]
    finalize: []
  allowed_agent_roles: [planner, verifier]
  handoffs:
    - from: planner-a
      to: verifier-b
""",
        encoding="utf-8",
    )
    return str(path)


def test_open_session_returns_governance_session_and_minimal_two_step_workflow_completes():
    with AEGIS().open_session() as session:
        assert isinstance(session, GovernanceSession)
        for _ in range(2):
            token = session.enforce_step_pre_call(_inv())
            assert isinstance(token, SessionPreCallResult)
            session.enforce_step_post_call(token, GOOD_OUTPUT)
        session.complete()

    assert session.workflow_artifact["status"] == "COMPLETED"
    assert len(session.workflow_artifact["steps"]) == 2


def test_three_step_sequence_with_participants_handoff_and_budget_completes(tmp_path):
    policy = _workflow_policy(tmp_path)
    with AEGIS().open_session(policy_file=policy) as session:
        t1 = session.enforce_step_pre_call(
            _inv(policy, "planner"),
            step_id="collect",
            participant_id="planner-a",
        )
        session.enforce_step_post_call(t1, GOOD_OUTPUT)
        t2 = session.enforce_step_pre_call(
            _inv(policy, "verifier"),
            step_id="review",
            participant_id="verifier-b",
        )
        session.enforce_step_post_call(t2, GOOD_OUTPUT)
        t3 = session.enforce_step_pre_call(
            _inv(policy, "verifier"),
            step_id="finalize",
            participant_id="verifier-b",
        )
        session.enforce_step_post_call(t3, GOOD_OUTPUT)
        session.complete()

    artifact = session.workflow_artifact
    assert artifact["status"] == "COMPLETED"
    assert [s["step_id"] for s in artifact["steps"]] == ["collect", "review", "finalize"]
    assert len(artifact["invocation_audit_checksums"]) == 3


@pytest.mark.parametrize(
    ("operation", "expected_error"),
    [
        ("unknown_step", WorkflowSequenceViolationError),
        ("duplicate_completion", InvocationValidationError),
        ("wrong_session", InvocationValidationError),
        ("missing_participant", WorkflowParticipantMismatchError),
        ("role_mismatch", WorkflowParticipantMismatchError),
        ("disallowed_role", WorkflowRoleViolationError),
        ("bad_transition", WorkflowTransitionDeniedError),
        ("bad_handoff", WorkflowHandoffDeniedError),
    ],
)
def test_workflow_fail_closed_paths(tmp_path, operation, expected_error):
    policy = _workflow_policy(tmp_path)
    aegis = AEGIS()
    with pytest.raises(expected_error):
        with aegis.open_session(policy_file=policy) as session:
            if operation == "unknown_step":
                session.enforce_step_pre_call(_inv(policy), step_id="not-declared", participant_id="planner-a")
            elif operation == "missing_participant":
                session.enforce_step_pre_call(_inv(policy), step_id="collect")
            elif operation == "role_mismatch":
                session.enforce_step_pre_call(_inv(policy, "verifier"), step_id="collect", participant_id="planner-a")
            elif operation == "disallowed_role":
                session._allowed_agent_roles = ["auditor"]
                session.enforce_step_pre_call(_inv(policy), step_id="collect", participant_id="planner-a")
            elif operation == "bad_transition":
                t1 = session.enforce_step_pre_call(_inv(policy), step_id="collect", participant_id="planner-a")
                session.enforce_step_post_call(t1, GOOD_OUTPUT)
                session._allowed_transitions = {"collect": ["finalize"]}
                session.enforce_step_pre_call(_inv(policy, "verifier"), step_id="review", participant_id="verifier-b")
            elif operation == "bad_handoff":
                session._handoffs = [{"from": "verifier-b", "to": "planner-a"}]
                t1 = session.enforce_step_pre_call(_inv(policy), step_id="collect", participant_id="planner-a")
                session.enforce_step_post_call(t1, GOOD_OUTPUT)
                session.enforce_step_pre_call(_inv(policy, "verifier"), step_id="review", participant_id="verifier-b")
            elif operation == "duplicate_completion":
                t1 = session.enforce_step_pre_call(_inv(policy), step_id="collect", participant_id="planner-a")
                session.enforce_step_post_call(t1, GOOD_OUTPUT)
                session.enforce_step_post_call(t1, GOOD_OUTPUT)
            elif operation == "wrong_session":
                t1 = session.enforce_step_pre_call(_inv(policy), step_id="collect", participant_id="planner-a")
                with aegis.open_session(policy_file=policy) as other:
                    other.enforce_step_post_call(t1, GOOD_OUTPUT)


def test_approval_required_path_pauses_and_records_checkpoint(tmp_path):
    policy = _workflow_policy(tmp_path)
    with AEGIS().open_session(policy_file=policy) as session:
        session._escalation = {"require_approval_after_steps": 1}
        t1 = session.enforce_step_pre_call(_inv(policy), step_id="collect", participant_id="planner-a")
        session.enforce_step_post_call(t1, GOOD_OUTPUT)
        with pytest.raises(WorkflowApprovalRequiredError) as exc_info:
            session.enforce_step_pre_call(_inv(policy, "verifier"), step_id="review", participant_id="verifier-b")
        assert session.state == "PAUSED"
        assert exc_info.value.code == "WORKFLOW_APPROVAL_REQUIRED"
        session.resume(approval_id=exc_info.value.details["checkpoint_id"])
        t2 = session.enforce_step_pre_call(_inv(policy, "verifier"), step_id="review", participant_id="verifier-b")
        session.enforce_step_post_call(t2, GOOD_OUTPUT)
        session.cancel()

    checkpoint = session.workflow_artifact["approval_checkpoints"][0]
    assert checkpoint["status"] == "approved"


def test_step_and_tool_budgets_fail_closed(tmp_path):
    policy = _workflow_policy(tmp_path)
    with pytest.raises(WorkflowToolBudgetExceededError):
        with AEGIS().open_session(policy_file=policy) as session:
            inv = _inv(policy)
            inv["tool_calls"] = [{"name": "a"}, {"name": "b"}, {"name": "c"}]
            session.enforce_step_pre_call(inv, step_id="collect", participant_id="planner-a")

    with pytest.raises(WorkflowStepBudgetExceededError):
        with AEGIS().open_session(policy_file=policy) as session:
            for step in ["collect", "review", "finalize"]:
                role = "planner" if step == "collect" else "verifier"
                participant = "planner-a" if step == "collect" else "verifier-b"
                t = session.enforce_step_pre_call(_inv(policy, role), step_id=step, participant_id=participant)
                session.enforce_step_post_call(t, GOOD_OUTPUT)
            session.enforce_step_pre_call(_inv(policy, "verifier"), step_id="extra", participant_id="verifier-b")


def test_workflow_and_invocation_artifacts_are_separate_but_correlated():
    emitted: list[dict] = []
    with AEGIS(sink=CallbackAuditSink(emitted.append)).open_session() as session:
        token = session.enforce_step_pre_call(_inv())
        invocation_artifact = session.enforce_step_post_call(token, GOOD_OUTPUT)
        session.complete()

    workflow_artifact = session.workflow_artifact
    assert invocation_artifact.get("artifact_type") != "workflow"
    assert workflow_artifact["artifact_type"] == "workflow"
    assert workflow_artifact["invocation_audit_checksums"] == [
        workflow_artifact["steps"][0]["invocation_artifact_checksum"]
    ]
    assert len([a for a in emitted if a.get("artifact_type") == "workflow"]) == 1
    assert len([a for a in emitted if a.get("artifact_type") != "workflow"]) == 1


def test_complete_with_pending_authorized_step_fails_closed():
    with pytest.raises(SessionStateError) as exc_info:
        with AEGIS().open_session() as session:
            session.enforce_step_pre_call(_inv())
            session.complete()
    assert exc_info.value.code == "WORKFLOW_INVALID_TRANSITION"
    assert "pending" in str(exc_info.value).lower()


def test_complete_pending_check_fires_before_approval_check():
    # When both a pending Phase-A token AND an unresolved approval checkpoint
    # exist, the pending-results guard must fire first.
    with pytest.raises(SessionStateError) as exc_info:
        with AEGIS().open_session() as session:
            session.enforce_step_pre_call(_inv())
            session.pause(approval_id="chk-order")
            session.complete()
    assert "pending" in str(exc_info.value).lower()
    assert "unresolved approval" not in str(exc_info.value).lower()
