"""PR-11 session replay and interleaving hardening tests."""
from __future__ import annotations

import pytest

from aegis import AEGIS, AuditSinkError, CallbackAuditSink, InvocationValidationError, SessionStateError


POLICY = "tests/golden_replays/golden_policy_v1.yaml"
GOOD_OUTPUT = {"result": "answer", "confidence": 0.95}


def _inv() -> dict:
    return {
        "policy_file": POLICY,
        "model_provider": "openai",
        "model_identifier": "gpt-4",
        "role": "planner",
        "input": {"query": "test"},
        "context": {"role_declared": True, "schema_exists": True},
    }


def test_same_session_precall_result_completed_twice_is_rejected():
    with AEGIS().open_session() as session:
        token = session.enforce_step_pre_call(_inv())
        session.enforce_step_post_call(token, GOOD_OUTPUT)
        with pytest.raises(InvocationValidationError):
            session.enforce_step_post_call(token, GOOD_OUTPUT)
        session.complete()


def test_same_token_completed_by_another_session_is_rejected():
    aegis = AEGIS()
    with aegis.open_session() as first:
        token = first.enforce_step_pre_call(_inv())
        with aegis.open_session() as second:
            with pytest.raises(InvocationValidationError):
                second.enforce_step_post_call(token, GOOD_OUTPUT)
            second.cancel()
        first.enforce_step_post_call(token, GOOD_OUTPUT)
        first.complete()


def test_nested_session_contexts_finalize_independently():
    aegis = AEGIS()
    with aegis.open_session(session_id="outer") as outer:
        with aegis.open_session(session_id="inner") as inner:
            inner.complete()
        outer.complete()

    assert inner.workflow_artifact["session_id"] == "inner"
    assert inner.workflow_artifact["status"] == "COMPLETED"
    assert outer.workflow_artifact["session_id"] == "outer"
    assert outer.workflow_artifact["status"] == "COMPLETED"


def test_finalization_while_pending_step_exists_fails_closed():
    with pytest.raises(SessionStateError):
        with AEGIS().open_session() as session:
            session.enforce_step_pre_call(_inv())
            session.complete()


def test_sink_failure_during_exception_cleanup_does_not_mask_original_exception():
    def fail_sink(_artifact):
        raise RuntimeError("sink unavailable")

    with pytest.raises(ValueError, match="original"):
        with AEGIS(
            sink=CallbackAuditSink(fail_sink),
            on_sink_failure="raise",
        ).open_session():
            raise ValueError("original")


def test_sink_failure_on_clean_finalize_respects_raise_mode():
    def fail_sink(_artifact):
        raise RuntimeError("sink unavailable")

    with pytest.raises(AuditSinkError):
        with AEGIS(
            sink=CallbackAuditSink(fail_sink),
            on_sink_failure="raise",
        ).open_session() as session:
            session.complete()


def test_pause_resume_interleaving_rejects_new_step_until_resumed():
    with AEGIS().open_session() as session:
        token = session.enforce_step_pre_call(_inv())
        session.pause(approval_id="pause-1")
        with pytest.raises(SessionStateError):
            session.enforce_step_pre_call(_inv())
        session.enforce_step_post_call(token, GOOD_OUTPUT)
        session.resume(approval_id="pause-1")
        session.complete()


@pytest.mark.skip(reason="Concurrent Phase-B calls are not documented as thread-safe in v0.9.0 beta")
def test_concurrent_phase_b_completion_attempt_is_fail_closed():
    """Reserved PR-11 coverage for the future documented thread-safety contract."""
