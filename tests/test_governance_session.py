"""
Public-boundary tests for GovernanceSession and SessionPreCallResult.

All imports from aegis.* only — never aegis._internal.
"""

from __future__ import annotations

import pytest

import aegis
from aegis import (
    AIGC,
    AuditSink,
    AuditSinkError,
    GovernanceSession,
    SessionPreCallResult,
    SessionStateError,
    InvocationValidationError,
)

# ---------------------------------------------------------------------------
# Import boundary — no _internal imports allowed
# ---------------------------------------------------------------------------

def test_governance_session_importable_from_aigc():
    """GovernanceSession is a module-level export of aegis."""
    assert GovernanceSession is aegis.GovernanceSession


def test_session_pre_call_result_importable_from_aigc():
    """SessionPreCallResult is a module-level export of aegis."""
    assert SessionPreCallResult is aegis.SessionPreCallResult


def test_session_state_error_importable_from_aigc():
    """SessionStateError is a module-level export of aegis."""
    assert SessionStateError is aegis.SessionStateError


def test_session_state_error_accepts_specific_code_and_preserves_default():
    """Removing the code override would collapse distinct lifecycle failures."""
    assert SessionStateError("default").code == "WORKFLOW_INVALID_TRANSITION"
    assert (
        SessionStateError("incomplete", code="SESSION_ATTEMPT_INCOMPLETE").code
        == "SESSION_ATTEMPT_INCOMPLETE"
    )


def test_open_session_is_not_module_level():
    """open_session must not exist at the aegis module level — it is instance-scoped."""
    assert not hasattr(aegis, "open_session"), (
        "open_session must not be a module-level aegis export; "
        "use AIGC().open_session(...) instead"
    )


def test_open_session_is_instance_method():
    """AIGC instances must expose open_session as a callable method."""
    a = AIGC()
    assert callable(getattr(a, "open_session", None))

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

POLICY = "tests/golden_replays/golden_policy_v1.yaml"

_BASE_INV = {
    "policy_file": POLICY,
    "model_provider": "openai",
    "model_identifier": "gpt-4",
    "role": "planner",
    "input": {"query": "test"},
    "context": {"role_declared": True, "schema_exists": True},
}

_GOOD_OUTPUT = {"result": "answer", "confidence": 0.95}

# ---------------------------------------------------------------------------
# Golden-path 2-step smoke test
# ---------------------------------------------------------------------------

def test_two_step_golden_path():
    """2-step governed session produces a valid workflow artifact."""
    a = AIGC()
    with a.open_session() as session:
        assert isinstance(session, GovernanceSession)
        for _ in range(2):
            token = session.enforce_step_pre_call(dict(_BASE_INV))
            assert isinstance(token, SessionPreCallResult)
            assert not hasattr(token, "_inner"), "_inner must not exist"
            session.enforce_step_post_call(token, dict(_GOOD_OUTPUT))
        session.complete()

    artifact = session.workflow_artifact
    assert artifact["status"] == "COMPLETED"
    assert artifact["artifact_type"] == "workflow"
    assert len(artifact["steps"]) == 2
    assert len(artifact["invocation_audit_checksums"]) == 2


def test_open_session_as_context_manager_clean_exit():
    """Clean exit without complete() → INCOMPLETE."""
    a = AIGC()
    with a.open_session() as session:
        pass  # no steps, no complete
    assert session.workflow_artifact["status"] == "INCOMPLETE"


def test_open_session_exception_exit_produces_failed():
    """Exception inside context → FAILED artifact, exception re-raised."""
    a = AIGC()
    with pytest.raises(ValueError):
        with a.open_session() as session:
            raise ValueError("deliberate failure")
    assert session.workflow_artifact["status"] == "FAILED"


def test_finalize_with_pending_handle_emits_terminal_canceled_attempt():
    """Closing a live operation must burn it and retain canceled evidence."""
    session = AIGC().open_session(session_id="pending-close-session")
    token = session.enforce_step_pre_call(dict(_BASE_INV), step_id="pending")

    artifact = session.finalize(status="INCOMPLETE")

    assert artifact["status"] == "INCOMPLETE"
    assert token.operation_id not in session._pending_results
    record = session.finalized_attempts()[0]
    assert record.step_index == token.step_index
    assert record.invocation_checksum is not None
    assert record.terminal.value == "execution_failure"


def test_canceled_attempt_delivery_failure_prevents_workflow_claim():
    """Skipping failed cancellation evidence must not fall through to workflow."""
    observed = []

    class RejectingSink(AuditSink):
        def emit(self, artifact):
            observed.append(artifact)
            raise RuntimeError("unavailable")

    governance = AIGC(sink=RejectingSink())
    session = governance.open_session(session_id="pending-delivery-failure")
    token = session.enforce_step_pre_call(dict(_BASE_INV), step_id="pending")

    with pytest.raises(AuditSinkError):
        session.finalize(status="INCOMPLETE")

    assert len(observed) == 1
    assert observed[0]["context"]["step_index"] == token.step_index
    assert observed[0]["enforcement_result"] == "FAIL"
    assert session.workflow_artifact is None
    assert session.finalized_attempts() == ()
    assert governance.evidence_diagnostics().evidence_delivery_failures_total == 1


def test_session_token_rejected_by_module_enforce_post_call():
    """SessionPreCallResult passed to module-level enforce_post_call raises."""
    from aegis import enforce_post_call
    a = AIGC()
    with a.open_session() as session:
        token = session.enforce_step_pre_call(dict(_BASE_INV))
        with pytest.raises(InvocationValidationError):
            enforce_post_call(token, dict(_GOOD_OUTPUT))
        session.enforce_step_post_call(token, dict(_GOOD_OUTPUT))
        session.complete()


def test_session_token_rejected_by_instance_enforce_post_call():
    """SessionPreCallResult passed to AIGC.enforce_post_call raises."""
    a = AIGC()
    with a.open_session() as session:
        token = session.enforce_step_pre_call(dict(_BASE_INV))
        with pytest.raises(InvocationValidationError):
            a.enforce_post_call(token, dict(_GOOD_OUTPUT))
        session.enforce_step_post_call(token, dict(_GOOD_OUTPUT))
        session.complete()


def test_policy_override_propagates_to_artifact():
    """Session-level policy_file override appears in the workflow artifact."""
    a = AIGC()
    inv_no_policy = {k: v for k, v in _BASE_INV.items() if k != "policy_file"}
    with a.open_session(policy_file=POLICY) as session:
        token = session.enforce_step_pre_call(inv_no_policy)
        session.enforce_step_post_call(token, dict(_GOOD_OUTPUT))
        session.complete()
    assert session.workflow_artifact["policy_file"] == POLICY


def test_session_id_is_present_in_artifact():
    """Workflow artifact contains the session_id."""
    a = AIGC()
    with a.open_session(session_id="my-session-99") as session:
        pass
    assert session.workflow_artifact["session_id"] == "my-session-99"
