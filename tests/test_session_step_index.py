"""Atomic per-session workflow-attempt index tests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from aegis import AEGIS, InvocationValidationError, SessionStateError
from aegis._internal.errors import GovernanceViolationError
from aegis._internal.outcomes import TerminalClass


POLICY = "tests/golden_replays/golden_policy_v1.yaml"
GOOD_OUTPUT = {"result": "answer", "confidence": 0.95}


def _invocation(*, role: str = "planner") -> dict:
    return {
        "policy_file": POLICY,
        "model_provider": "openai",
        "model_identifier": "gpt-4",
        "role": role,
        "input": {"query": "test"},
        "context": {"role_declared": True, "schema_exists": True},
    }


@pytest.fixture
def session():
    active_session = AEGIS().open_session(session_id="step-index-session")
    try:
        yield active_session
    finally:
        if active_session.workflow_artifact is None:
            active_session.cancel()
            active_session.finalize()


@pytest.fixture
def invocations() -> list[dict]:
    return [_invocation() for _ in range(16)]


def test_concurrent_step_indices_are_gapless_and_unique(session, invocations):
    """Removing atomic allocation would duplicate or skip a successful index."""
    with ThreadPoolExecutor(max_workers=8) as pool:
        handles = list(pool.map(session.enforce_step_pre_call, invocations))

    indices = sorted(handle.step_index for handle in handles)

    assert indices == list(range(len(handles)))


def test_rejected_phase_a_attempt_retains_allocated_index_and_correlation(session):
    """Moving allocation after a Phase A denial would lose attempt zero."""
    with pytest.raises(GovernanceViolationError) as exc_info:
        session.enforce_step_pre_call(_invocation(role="attacker"), step_id="rejected")

    rejected = session._attempts[0]
    assert rejected.step_index == 0
    assert rejected.step_id == "rejected"
    assert rejected.invocation_checksum == exc_info.value.audit_artifact["checksum"]
    assert rejected.terminal is TerminalClass.DENY

    artifact = exc_info.value.audit_artifact
    assert artifact is not None
    correlation = artifact["context"]
    assert correlation["session_id"] == session.session_id
    assert correlation["step_id"] == "rejected"
    assert correlation["step_index"] == 0
    assert correlation["workflow_policy_digest"]

    handle = session.enforce_step_pre_call(_invocation(), step_id="accepted")
    assert handle.step_index == 1


def test_paused_step_rejection_retains_allocated_index(session):
    """Moving allocation after the accepting-state gate would lose attempt zero."""
    session.pause(approval_id="pause-for-index")

    with pytest.raises(SessionStateError):
        session.enforce_step_pre_call(_invocation(), step_id="paused")

    paused = session._attempts[0]
    assert paused.step_index == 0
    assert paused.step_id == "paused"
    assert paused.invocation_checksum is not None
    assert paused.terminal is TerminalClass.DENY


def test_pre_call_validation_failure_includes_workflow_policy_digest():
    """Adding the digest after policy validation would omit it from FAIL evidence."""
    with AEGIS().open_session(
        session_id="invalid-pre-call-session",
        policy_file=POLICY,
    ) as session:
        invalid = _invocation()
        del invalid["role"]

        with pytest.raises(InvocationValidationError) as exc_info:
            session.enforce_step_pre_call(invalid, step_id="missing-role")

        artifact = exc_info.value.audit_artifact
        assert artifact is not None
        assert artifact["context"] == {
            "role_declared": True,
            "schema_exists": True,
            "session_id": session.session_id,
            "step_id": "missing-role",
            "step_index": 0,
            "workflow_policy_digest": session._compiled_policy.policy_digest,
        }
        session.cancel()


def test_invocation_policy_validation_failure_includes_workflow_policy_digest():
    """Skipping authoritative compilation would omit digest from FAIL evidence."""
    runtime = AEGIS()
    authority_session = runtime.open_session(policy_file=POLICY)
    expected_digest = authority_session._compiled_policy.policy_digest
    authority_session.finalize()

    with runtime.open_session(session_id="invocation-policy-invalid") as session:
        invalid = _invocation()
        invalid["context"]["workflow_policy_digest"] = "forged-by-host"
        del invalid["role"]

        with pytest.raises(InvocationValidationError) as exc_info:
            session.enforce_step_pre_call(invalid, step_id="missing-role")

        artifact = exc_info.value.audit_artifact
        assert artifact is not None
        assert artifact["context"] == {
            "role_declared": True,
            "schema_exists": True,
            "session_id": session.session_id,
            "step_id": "missing-role",
            "step_index": 0,
            "workflow_policy_digest": expected_digest,
        }
        session.cancel()


def test_terminal_invocation_correlation_binds_allocated_index_and_policy_digest(session):
    """Dropping a correlation field before finalization would break audit linkage."""
    invocation = _invocation()
    invocation["context"]["workflow_policy_digest"] = "forged-by-host"
    handle = session.enforce_step_pre_call(invocation, step_id="correlated")
    artifact = session.enforce_step_post_call(handle, GOOD_OUTPUT)

    correlation = artifact["context"]
    assert correlation == {
        "role_declared": True,
        "schema_exists": True,
        "session_id": session.session_id,
        "step_id": "correlated",
        "step_index": 0,
        "workflow_policy_digest": handle.policy_digest,
    }
