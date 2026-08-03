"""Lifecycle and ownership regressions for A3 operation registries."""
from __future__ import annotations

import pytest

from aegis import AEGIS
from aegis._internal.errors import InvocationValidationError

GOLDEN_POLICY = "tests/golden_replays/golden_policy_v1.yaml"


def _invocation():
    return {
        "policy_file": GOLDEN_POLICY,
        "model_provider": "openai",
        "model_identifier": "gpt-4",
        "role": "planner",
        "input": {"query": "test"},
        "context": {"role_declared": True, "schema_exists": True},
    }


def _output():
    return {"result": "ok", "confidence": 0.9}


def test_instance_handle_rejected_by_other_instance():
    first = AEGIS()
    second = AEGIS()
    handle = first.enforce_pre_call(_invocation())

    with pytest.raises(InvocationValidationError) as exc_info:
        second.enforce_post_call(handle, _output())
    assert exc_info.value.code == "OPERATION_ISSUER_MISMATCH"

    assert first.enforce_post_call(
        handle,
        _output(),
    )["enforcement_result"] == "PASS"


def test_session_cancel_removes_pending_operation():
    runtime = AEGIS()
    session = runtime.open_session()
    handle = session.enforce_step_pre_call(_invocation())

    session.cancel()

    with pytest.raises(InvocationValidationError) as exc_info:
        session.enforce_step_post_call(handle, _output())
    assert exc_info.value.code == "OPERATION_NOT_ACTIVE"


def test_session_finalize_removes_pending_operation():
    runtime = AEGIS()
    session = runtime.open_session()
    handle = session.enforce_step_pre_call(_invocation())

    session.finalize()

    with pytest.raises(InvocationValidationError) as exc_info:
        session.enforce_step_post_call(handle, _output())
    assert exc_info.value.code == "OPERATION_NOT_ACTIVE"


def test_discarded_adapter_step_removes_pending_operation():
    runtime = AEGIS()
    session = runtime.open_session()
    handle = session.enforce_step_pre_call(_invocation())

    session.discard_adapter_step(handle)

    with pytest.raises(InvocationValidationError) as exc_info:
        session.enforce_step_post_call(handle, _output())
    assert exc_info.value.code == "OPERATION_NOT_ACTIVE"
    session.cancel()
