"""Process-affine split handle copying and serialization tests."""

from __future__ import annotations

import copy
import multiprocessing
import pickle

import pytest

from aegis._internal.enforcement import (
    configure_module_enforcement,
    enforce_post_call,
    enforce_pre_call,
)
from aegis._internal.errors import InvocationValidationError
from aegis._internal.sinks import CallbackAuditSink


def _consume_in_child(handle, result_queue) -> None:
    try:
        configure_module_enforcement(
            sink=CallbackAuditSink(lambda _artifact: None),
        )
    except RuntimeError:
        # A fork inherits the already-sealed module evidence runtime.
        pass
    try:
        enforce_post_call(handle, _valid_output())
    except InvocationValidationError as exc:
        result_queue.put(exc.code)
    else:
        result_queue.put("PASS")


def _pre_call_invocation() -> dict[str, object]:
    return {
        "policy_file": "tests/golden_replays/golden_policy_v1.yaml",
        "model_provider": "openai",
        "model_identifier": "gpt-4",
        "role": "planner",
        "input": {"query": "test"},
        "context": {"role_declared": True, "schema_exists": True},
    }


def _valid_output() -> dict[str, object]:
    return {"result": "test output", "confidence": 0.95}


@pytest.mark.parametrize(
    "copier",
    [
        copy.copy,
        copy.deepcopy,
        lambda handle: pickle.loads(pickle.dumps(handle)),
    ],
    ids=["copy", "deepcopy", "pickle"],
)
def test_copied_handle_identifies_same_one_shot_operation(copier):
    original = enforce_pre_call(_pre_call_invocation())
    copied = copier(original)

    assert copied == original
    artifact = enforce_post_call(copied, _valid_output())
    assert artifact["enforcement_result"] == "PASS"

    with pytest.raises(InvocationValidationError) as replay_exc:
        enforce_post_call(original, _valid_output())
    assert replay_exc.value.code == "OPERATION_NOT_ACTIVE"


def test_spawned_process_cannot_consume_parent_operation():
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    handle = enforce_pre_call(_pre_call_invocation())

    child = context.Process(
        target=_consume_in_child,
        args=(handle, result_queue),
    )
    child.start()
    child.join(timeout=10)

    assert child.exitcode == 0
    assert result_queue.get(timeout=2) == "OPERATION_PROCESS_MISMATCH"
    assert enforce_post_call(
        handle,
        _valid_output(),
    )["enforcement_result"] == "PASS"
    result_queue.close()


@pytest.mark.skipif(
    "fork" not in multiprocessing.get_all_start_methods(),
    reason="fork start method is unavailable",
)
def test_forked_process_cannot_consume_inherited_operation():
    context = multiprocessing.get_context("fork")
    result_queue = context.Queue()
    handle = enforce_pre_call(_pre_call_invocation())

    child = context.Process(
        target=_consume_in_child,
        args=(handle, result_queue),
    )
    child.start()
    child.join(timeout=10)

    assert child.exitcode == 0
    assert result_queue.get(timeout=2) == "OPERATION_PROCESS_MISMATCH"
    assert enforce_post_call(
        handle,
        _valid_output(),
    )["enforcement_result"] == "PASS"
    result_queue.close()
