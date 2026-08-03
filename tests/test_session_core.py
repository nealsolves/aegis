"""
Internal TDD tests for GovernanceSession and SessionPreCallResult.

All imports from aegis._internal — these tests are implementation-level and
run before public exports are wired.
"""

from __future__ import annotations

import dataclasses

import pytest

from aegis._internal.enforcement import AIGC
from aegis._internal.errors import AuditSinkError, InvocationValidationError, SessionStateError
from aegis._internal.session import (
    STATE_COMPLETED,
    STATE_FINALIZED,
    STATE_OPEN,
    STATE_PAUSED,
    GovernanceSession,
    _compute_policy_file,
)
from aegis._internal.sinks import CallbackAuditSink

# ---------------------------------------------------------------------------
# Shared helpers
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


def _aigc() -> AIGC:
    return AIGC()


def _open_session(aegis: AIGC | None = None, **kwargs) -> GovernanceSession:
    a = aegis or _aigc()
    return a.open_session(**kwargs)


# ---------------------------------------------------------------------------
# SessionPreCallResult structure tests
# ---------------------------------------------------------------------------

def test_token_has_no_inner_attribute():
    """`SessionPreCallResult` must not have `_inner` — it's a ticket, not a wrapper."""
    a = _aigc()
    with a.open_session() as session:
        token = session.enforce_step_pre_call(dict(_BASE_INV))
        assert not hasattr(token, "_inner"), "_inner must not exist on SessionPreCallResult"
        session.enforce_step_post_call(token, dict(_GOOD_OUTPUT))
        session.complete()


def test_session_handle_has_no_legacy_token_state():
    a = _aigc()
    with a.open_session() as session:
        token = session.enforce_step_pre_call(dict(_BASE_INV))
        assert "_IS_SESSION_TOKEN" not in token.__slots__
        assert "_token_id" not in token.__slots__
        assert "_consumed" not in token.__slots__
        session.enforce_step_post_call(token, dict(_GOOD_OUTPUT))
        session.complete()


# ---------------------------------------------------------------------------
# Forged wrapper rejection
# ---------------------------------------------------------------------------

def test_forged_wrapper_rejected():
    """Copying a real operation identity with different metadata fails closed."""
    a = _aigc()
    with a.open_session() as session:
        real_token = session.enforce_step_pre_call(dict(_BASE_INV), step_id="real-step")
        forged = dataclasses.replace(real_token, step_id="injected-step")
        with pytest.raises(InvocationValidationError) as exc_info:
            session.enforce_step_post_call(forged, dict(_GOOD_OUTPUT))
        assert exc_info.value.code == "OPERATION_SESSION_METADATA_MISMATCH"
        with pytest.raises(InvocationValidationError) as replay:
            session.enforce_step_post_call(real_token, dict(_GOOD_OUTPUT))
        assert replay.value.code == "OPERATION_NOT_ACTIVE"
        session.cancel()


# ---------------------------------------------------------------------------
# Token consume-order correctness
# ---------------------------------------------------------------------------

def test_token_consumed_on_non_serializable_output_failure():
    """Any attempted session post-call consumes the session token, even on failure."""
    a = _aigc()
    with a.open_session() as session:
        token = session.enforce_step_pre_call(dict(_BASE_INV))
        non_serializable = {"value": float("inf")}
        with pytest.raises(Exception):  # InvocationValidationError or similar
            session.enforce_step_post_call(token, non_serializable)
        assert token.operation_id not in session._pending_results
        with pytest.raises(InvocationValidationError) as replay:
            session.enforce_step_post_call(token, dict(_GOOD_OUTPUT))
        assert replay.value.code == "OPERATION_NOT_ACTIVE"
        session.cancel()


def test_token_consumed_on_schema_validation_failure():
    """Schema-validation failures also clear pending session state deterministically."""
    a = _aigc()
    with a.open_session() as session:
        token = session.enforce_step_pre_call(dict(_BASE_INV))
        with pytest.raises(Exception):  # SchemaValidationError
            session.enforce_step_post_call(token, {"result": "answer"})
        assert token.operation_id not in session._pending_results
        with pytest.raises(InvocationValidationError) as replay:
            session.enforce_step_post_call(token, dict(_GOOD_OUTPUT))
        assert replay.value.code == "OPERATION_NOT_ACTIVE"
        session.cancel()


def test_token_consumed_on_success():
    """After successful completion the operation is no longer pending."""
    a = _aigc()
    with a.open_session() as session:
        token = session.enforce_step_pre_call(dict(_BASE_INV))
        session.enforce_step_post_call(token, dict(_GOOD_OUTPUT))
        assert token.operation_id not in session._pending_results
        session.complete()


def test_second_completion_rejected():
    """Second enforce_step_post_call with same token raises."""
    a = _aigc()
    with a.open_session() as session:
        token = session.enforce_step_pre_call(dict(_BASE_INV))
        session.enforce_step_post_call(token, dict(_GOOD_OUTPUT))
        with pytest.raises(InvocationValidationError):
            session.enforce_step_post_call(token, dict(_GOOD_OUTPUT))
        session.complete()


def test_session_post_call_rejects_wrong_handle_type_with_typed_error():
    a = _aigc()
    with a.open_session() as session:
        with pytest.raises(InvocationValidationError) as exc_info:
            session.enforce_step_post_call(object(), dict(_GOOD_OUTPUT))
        assert exc_info.value.code == "OPERATION_HANDLE_INVALID"
        session.cancel()


# ---------------------------------------------------------------------------
# Cross-session rejection
# ---------------------------------------------------------------------------

def test_cross_session_completion_rejected():
    """Token minted by session A rejected by session B."""
    a = _aigc()
    with a.open_session() as session_a:
        token_a = session_a.enforce_step_pre_call(dict(_BASE_INV))
        with a.open_session() as session_b:
            with pytest.raises(InvocationValidationError, match="different session"):
                session_b.enforce_step_post_call(token_a, dict(_GOOD_OUTPUT))
            session_b.complete()
        session_a.enforce_step_post_call(token_a, dict(_GOOD_OUTPUT))
        session_a.complete()


# ---------------------------------------------------------------------------
# Policy override
# ---------------------------------------------------------------------------

def test_policy_override_applied_to_step():
    """`open_session(policy_file=X)` → each step's enforce_pre_call receives policy_file=X."""
    a = _aigc()
    inv_no_policy = {
        "model_provider": "openai",
        "model_identifier": "gpt-4",
        "role": "planner",
        "input": {"query": "test"},
        "context": {"role_declared": True, "schema_exists": True},
    }
    with a.open_session(policy_file=POLICY) as session:
        # Invocation has no policy_file; session override must supply it
        token = session.enforce_step_pre_call(inv_no_policy)
        inv_artifact = session.enforce_step_post_call(token, dict(_GOOD_OUTPUT))
        assert inv_artifact.get("policy_file") == POLICY
        session.complete()


def test_policy_override_in_artifact():
    """Workflow artifact policy_file matches the session-level override."""
    a = _aigc()
    with a.open_session(policy_file=POLICY) as session:
        token = session.enforce_step_pre_call(dict(_BASE_INV))
        session.enforce_step_post_call(token, dict(_GOOD_OUTPUT))
        session.complete()
    artifact = session.workflow_artifact
    assert artifact["policy_file"] == POLICY


# ---------------------------------------------------------------------------
# policy_file normalization (Finding 2)
# ---------------------------------------------------------------------------

def test_mixed_policy_session_normalizes_null():
    """No session override; steps use different policy_files → artifact policy_file is null."""
    result = _compute_policy_file(
        session_policy_file=None,
        step_policy_files=["policy_a.yaml", "policy_b.yaml"],
    )
    assert result is None


def test_homogeneous_policy_session_preserves_value():
    """No session override; all steps use same policy_file → artifact policy_file is that value."""
    result = _compute_policy_file(
        session_policy_file=None,
        step_policy_files=["policy_a.yaml", "policy_a.yaml"],
    )
    assert result == "policy_a.yaml"


def test_zero_steps_session_normalizes_null():
    """Session finalized as INCOMPLETE with no steps taken → artifact policy_file is null."""
    result = _compute_policy_file(
        session_policy_file=None,
        step_policy_files=[],
    )
    assert result is None


# ---------------------------------------------------------------------------
# Lifecycle: clean exit → INCOMPLETE
# ---------------------------------------------------------------------------

def test_clean_exit_produces_incomplete():
    """`with session:` without `.complete()` → artifact status == 'INCOMPLETE'."""
    a = _aigc()
    with a.open_session() as session:
        pass  # no steps, no complete()
    assert session.state == STATE_FINALIZED
    assert session.workflow_artifact["status"] == "INCOMPLETE"


def test_exception_exit_produces_failed():
    """Exception inside `with session:` → artifact status == 'FAILED', exception re-raised."""
    a = _aigc()
    with pytest.raises(RuntimeError, match="deliberate"):
        with a.open_session() as session:
            raise RuntimeError("deliberate")
    assert session.state == STATE_FINALIZED
    assert session.workflow_artifact["status"] == "FAILED"
    assert session.workflow_artifact["failure_summary"] is not None


# ---------------------------------------------------------------------------
# enforce_post_call guards
# ---------------------------------------------------------------------------

def test_module_level_guard_rejects_session_token():
    """`enforce_post_call(session_token, output)` raises InvocationValidationError."""
    from aegis._internal.enforcement import enforce_post_call
    a = _aigc()
    with a.open_session() as session:
        token = session.enforce_step_pre_call(dict(_BASE_INV))
        with pytest.raises(InvocationValidationError):
            enforce_post_call(token, dict(_GOOD_OUTPUT))
        # clean up: complete the step properly
        session.enforce_step_post_call(token, dict(_GOOD_OUTPUT))
        session.complete()


def test_instance_level_guard_rejects_session_token():
    """`aegis.enforce_post_call(session_token, output)` raises InvocationValidationError."""
    a = _aigc()
    with a.open_session() as session:
        token = session.enforce_step_pre_call(dict(_BASE_INV))
        with pytest.raises(InvocationValidationError):
            a.enforce_post_call(token, dict(_GOOD_OUTPUT))
        session.enforce_step_post_call(token, dict(_GOOD_OUTPUT))
        session.complete()


# ---------------------------------------------------------------------------
# Lifecycle transitions
# ---------------------------------------------------------------------------

def test_lifecycle_transitions():
    """Valid transitions succeed; invalid ones raise SessionStateError."""
    a = _aigc()
    session = a.open_session()
    assert session.state == STATE_OPEN

    # OPEN → PAUSED
    session.pause()
    assert session.state == STATE_PAUSED

    # PAUSED → OPEN
    session.resume()
    assert session.state == STATE_OPEN

    # OPEN → COMPLETED
    session.complete()
    assert session.state == STATE_COMPLETED

    # COMPLETED → COMPLETED (invalid)
    with pytest.raises(SessionStateError):
        session.complete()

    # Finalize from COMPLETED
    session.finalize()
    assert session.state == STATE_FINALIZED

    # FINALIZED → anything (invalid)
    with pytest.raises(SessionStateError):
        session.finalize()


# ---------------------------------------------------------------------------
# Step records use registry values
# ---------------------------------------------------------------------------

def test_step_record_uses_registry_values():
    """Step in workflow artifact uses minted step_id, not any token-supplied value."""
    a = _aigc()
    with a.open_session() as session:
        token = session.enforce_step_pre_call(dict(_BASE_INV), step_id="minted-step-123")
        session.enforce_step_post_call(token, dict(_GOOD_OUTPUT))
        session.complete()
    artifact = session.workflow_artifact
    assert len(artifact["steps"]) == 1
    assert artifact["steps"][0]["step_id"] == "minted-step-123"


# ---------------------------------------------------------------------------
# Two-step smoke test
# ---------------------------------------------------------------------------

def test_two_step_session_smoke():
    """Golden-path 2-step session produces correct artifact."""
    a = AIGC()
    with a.open_session() as session:
        for _ in range(2):
            token = session.enforce_step_pre_call(dict(_BASE_INV))
            assert not hasattr(token, "_inner"), "_inner must not exist"
            session.enforce_step_post_call(token, dict(_GOOD_OUTPUT))
        session.complete()

    assert session.state == STATE_FINALIZED
    artifact = session.workflow_artifact
    assert artifact["status"] == "COMPLETED"
    assert artifact["artifact_type"] == "workflow"
    assert len(artifact["steps"]) == 2
    assert len(artifact["invocation_audit_checksums"]) == 2


# ---------------------------------------------------------------------------
# Finding 1 — PAUSED rejects new steps; PAUSED allows in-flight post_call
# ---------------------------------------------------------------------------

def test_paused_session_rejects_new_step_pre_call():
    """Paused sessions must reject new step authorization (HLD §7.3)."""
    a = _aigc()
    session = a.open_session()
    session.pause()
    with pytest.raises(SessionStateError, match="PAUSED"):
        session.enforce_step_pre_call(dict(_BASE_INV))


def test_paused_session_allows_inflight_post_call():
    """Completing an in-flight step (Phase B) is allowed while PAUSED."""
    a = _aigc()
    session = a.open_session()
    # Phase A while OPEN
    token = session.enforce_step_pre_call(dict(_BASE_INV))
    # Pause between phases
    session.pause()
    # Phase B while PAUSED must succeed — it is not a new step
    session.enforce_step_post_call(token, dict(_GOOD_OUTPUT))
    # Resolve the checkpoint before completing (fail-closed guard)
    session.resume()
    session.complete()
    session.finalize()
    assert session.state == STATE_FINALIZED
    assert session.workflow_artifact["status"] == "COMPLETED"


# ---------------------------------------------------------------------------
# Finding 2 — sink failure_mode="raise" propagates from explicit finalize()
#             but is suppressed when __exit__ is handling an active exception
# ---------------------------------------------------------------------------

def _broken_aigc() -> AIGC:
    """AIGC instance whose sink always raises."""
    def _raise(_artifact: dict) -> None:
        raise RuntimeError("sink is broken")

    return AIGC(
        sink=CallbackAuditSink(_raise),
        on_sink_failure="raise",
    )


def test_finalize_raise_mode_propagates_sink_error():
    """Explicit finalize() with on_sink_failure='raise' must propagate AuditSinkError."""
    a = _broken_aigc()
    session = a.open_session()
    session.complete()
    with pytest.raises(AuditSinkError):
        session.finalize()


def test_exit_exception_path_sink_error_does_not_mask_original():
    """When __exit__ handles an active exception, AuditSinkError must not replace it."""
    a = _broken_aigc()

    class _Sentinel(Exception):
        pass

    with pytest.raises(_Sentinel):
        with a.open_session():
            raise _Sentinel("original")
    # _Sentinel propagates; AuditSinkError is suppressed and logged


# ---------------------------------------------------------------------------
# Finding 3 — explicit finalize() from OPEN/PAUSED emits INCOMPLETE
# ---------------------------------------------------------------------------

def test_explicit_finalize_from_open_emits_incomplete():
    """`finalize()` from OPEN state must emit artifact with status INCOMPLETE."""
    a = _aigc()
    session = a.open_session()
    artifact = session.finalize()
    assert artifact["status"] == "INCOMPLETE"
    assert session.state == STATE_FINALIZED


def test_explicit_finalize_from_paused_emits_incomplete():
    """`finalize()` from PAUSED state must emit artifact with status INCOMPLETE."""
    a = _aigc()
    session = a.open_session()
    session.pause()
    artifact = session.finalize()
    assert artifact["status"] == "INCOMPLETE"
    assert session.state == STATE_FINALIZED
