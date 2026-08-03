"""PR-11 session replay and interleaving hardening tests."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from aegis import (
    AEGIS,
    AuditSinkError,
    CallbackAuditSink,
    InvocationValidationError,
    SessionStateError,
)
from aegis._internal.errors import (
    ToolConstraintViolationError,
    WorkflowSessionTokenInvalidError,
    WorkflowToolBudgetExceededError,
)
from aegis._internal.gates import EnforcementGate, GateResult


POLICY = "tests/golden_replays/golden_policy_v1.yaml"
GOOD_OUTPUT = {"result": "answer", "confidence": 0.95}


class _BlockingPreOutputGate(EnforcementGate):
    def __init__(self, entered: threading.Event, release: threading.Event):
        self._entered = entered
        self._release = release

    @property
    def name(self):
        return "blocking_pre_output"

    @property
    def insertion_point(self):
        return "pre_output"

    def evaluate(self, invocation, policy, context):
        self._entered.set()
        assert self._release.wait(timeout=5)
        return GateResult(passed=True)


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


def test_concurrent_phase_b_completion_attempt_is_fail_closed():
    runtime = AEGIS()
    with runtime.open_session() as session:
        handle = session.enforce_step_pre_call(_inv())
        barrier = threading.Barrier(2)

        def complete_step():
            barrier.wait()
            try:
                session.enforce_step_post_call(handle, GOOD_OUTPUT)
            except InvocationValidationError as exc:
                return exc.code
            return "PASS"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _index: complete_step(), range(2)))

        assert sorted(results) == ["OPERATION_NOT_ACTIVE", "PASS"]
        session.complete()


def test_concurrent_dynamic_tool_calls_respect_per_tool_limit():
    invocation = _inv()
    invocation["policy_file"] = "tests/golden_replays/policy_with_tools.yaml"
    invocation["context"] = {"role_declared": True}

    with AEGIS().open_session() as session:
        handle = session.enforce_step_pre_call(invocation)
        session.register_adapter_step_state(
            handle,
            {
                "dynamic_tool_calls_count": 0,
                "dynamic_tool_calls": [],
            },
        )
        barrier = threading.Barrier(3)

        def authorize_tool(index):
            barrier.wait()
            try:
                session.authorize_step_tool_call(
                    handle,
                    tool_name="search_knowledge_base",
                    tool_call_id=f"call-{index}",
                )
            except ToolConstraintViolationError:
                return "BLOCKED"
            return "ALLOWED"

        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(authorize_tool, range(3)))

        assert sorted(results) == ["ALLOWED", "ALLOWED", "BLOCKED"]
        session.discard_adapter_step(handle)
        session.cancel()


def test_concurrent_dynamic_tool_calls_respect_session_budget():
    with AEGIS().open_session() as session:
        session._max_total_tool_calls = 1
        handle = session.enforce_step_pre_call(_inv())
        session.register_adapter_step_state(
            handle,
            {
                "dynamic_tool_calls_count": 0,
                "dynamic_tool_calls": [],
            },
        )
        barrier = threading.Barrier(2)

        def authorize_tool(index):
            barrier.wait()
            try:
                session.authorize_step_tool_call(
                    handle,
                    tool_name=f"tool-{index}",
                )
            except WorkflowToolBudgetExceededError:
                return "BLOCKED"
            return "ALLOWED"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(authorize_tool, range(2)))

        assert sorted(results) == ["ALLOWED", "BLOCKED"]
        session.discard_adapter_step(handle)
        session.cancel()


def test_phase_b_and_dynamic_authorization_are_serialized():
    with AEGIS().open_session() as session:
        handle = session.enforce_step_pre_call(_inv())
        session.register_adapter_step_state(
            handle,
            {
                "dynamic_tool_calls_count": 0,
                "dynamic_tool_calls": [],
            },
        )
        barrier = threading.Barrier(2)

        def authorize_tool():
            barrier.wait()
            try:
                session.authorize_step_tool_call(handle, tool_name="tool")
            except WorkflowSessionTokenInvalidError:
                return "BLOCKED"
            return "ALLOWED"

        def complete_step():
            barrier.wait()
            session.enforce_step_post_call(handle, GOOD_OUTPUT)
            return "PASS"

        with ThreadPoolExecutor(max_workers=2) as pool:
            authorize_future = pool.submit(authorize_tool)
            complete_future = pool.submit(complete_step)
            authorize_result = authorize_future.result()
            complete_result = complete_future.result()

        assert authorize_result in {"ALLOWED", "BLOCKED"}
        assert complete_result == "PASS"
        assert handle.operation_id not in session._pending_results
        session.complete()


def test_finalize_waits_for_in_flight_phase_b_and_includes_the_step():
    phase_b_entered = threading.Event()
    release_phase_b = threading.Event()
    finalize_started = threading.Event()
    finalize_finished = threading.Event()
    runtime = AEGIS(
        custom_gates=[
            _BlockingPreOutputGate(phase_b_entered, release_phase_b),
        ],
    )
    session = runtime.open_session()
    handle = session.enforce_step_pre_call(_inv())

    def complete_step():
        return session.enforce_step_post_call(handle, GOOD_OUTPUT)

    def finalize_session():
        finalize_started.set()
        artifact = session.finalize()
        finalize_finished.set()
        return artifact

    with ThreadPoolExecutor(max_workers=2) as pool:
        phase_b_future = pool.submit(complete_step)
        assert phase_b_entered.wait(timeout=5)
        finalize_future = pool.submit(finalize_session)
        assert finalize_started.wait(timeout=5)
        assert not finalize_finished.is_set()

        release_phase_b.set()
        assert phase_b_future.result()["enforcement_result"] == "PASS"
        workflow_artifact = finalize_future.result()

    assert finalize_finished.is_set()
    assert len(workflow_artifact["steps"]) == 1
    assert workflow_artifact["steps"][0]["step_id"] == handle.step_id
