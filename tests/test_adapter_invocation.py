"""Security boundaries for broad host invocations accepted by adapters."""

from __future__ import annotations

import math

import pytest

from aegis._internal.adapter_invocation import (
    project_adapter_pre_call_invocation,
)
from aegis._internal.errors import InvocationValidationError


_MAX_ENCODED_BYTES = 1_048_576
_MAX_NODES = 10_000
_MAX_DEPTH = 64


def _nested_output(depth: int) -> dict:
    """Build an object whose root is depth one without recursive test code."""
    value = None
    for _ in range(depth - 2):
        value = [value]
    return {"value": value}


def test_output_at_exact_encoded_byte_limit_is_accepted():
    # Compact UTF-8 JSON for {"x": "<payload>"} has eight framing bytes.
    output = {"x": "a" * (_MAX_ENCODED_BYTES - 8)}
    invocation = {"output": output}

    projected = project_adapter_pre_call_invocation(invocation)

    assert projected == {}
    assert invocation["output"] is output


def test_output_one_byte_past_encoded_limit_is_rejected():
    output = {"x": "a" * (_MAX_ENCODED_BYTES - 7)}

    with pytest.raises(InvocationValidationError) as raised:
        project_adapter_pre_call_invocation({"output": output})

    assert raised.value.details == {
        "field": "output",
        "reason": "encoded_bytes",
        "max_encoded_bytes": _MAX_ENCODED_BYTES,
    }


def test_output_at_exact_node_limit_is_accepted():
    # The root object and its list consume two nodes.
    output = {"values": [None] * (_MAX_NODES - 2)}

    projected = project_adapter_pre_call_invocation({"output": output})

    assert projected == {}


def test_output_one_node_past_limit_is_rejected():
    output = {"values": [None] * (_MAX_NODES - 1)}

    with pytest.raises(InvocationValidationError) as raised:
        project_adapter_pre_call_invocation({"output": output})

    assert raised.value.details == {
        "field": "output",
        "reason": "nodes",
        "max_nodes": _MAX_NODES,
    }


def test_output_at_exact_depth_limit_is_accepted():
    projected = project_adapter_pre_call_invocation(
        {"output": _nested_output(_MAX_DEPTH)}
    )

    assert projected == {}


def test_output_one_level_past_depth_limit_is_rejected():
    with pytest.raises(InvocationValidationError) as raised:
        project_adapter_pre_call_invocation(
            {"output": _nested_output(_MAX_DEPTH + 1)}
        )

    assert raised.value.details == {
        "field": "output",
        "reason": "depth",
        "max_depth": _MAX_DEPTH,
    }


def test_output_accepts_json_booleans_numbers_null_arrays_and_objects():
    output = {
        "boolean": True,
        "integer": 7,
        "number": -2.5,
        "null": None,
        "array": [False, 0, 1.25],
        "object": {"value": "ok"},
    }

    projected = project_adapter_pre_call_invocation({"output": output})

    assert projected == {}


def test_output_rejects_non_string_object_keys():
    with pytest.raises(InvocationValidationError) as raised:
        project_adapter_pre_call_invocation({"output": {1: "value"}})

    assert raised.value.details == {
        "field": "output",
        "reason": "non_string_key",
    }


@pytest.mark.parametrize("number", [math.nan, math.inf, -math.inf])
def test_output_rejects_non_finite_numbers(number):
    with pytest.raises(InvocationValidationError) as raised:
        project_adapter_pre_call_invocation({"output": {"number": number}})

    assert raised.value.details == {
        "field": "output",
        "reason": "non_finite_number",
    }


@pytest.mark.parametrize(
    "serialization_error",
    [
        RecursionError("recursive"),
        OverflowError("overflow"),
        TypeError("type"),
        ValueError("value"),
    ],
)
def test_serializer_failures_are_translated(monkeypatch, serialization_error):
    def fail_serialization(*args, **kwargs):
        raise serialization_error

    monkeypatch.setattr(
        "aegis._internal.adapter_invocation.json.dumps",
        fail_serialization,
    )

    with pytest.raises(InvocationValidationError) as raised:
        project_adapter_pre_call_invocation({"output": {"value": "ok"}})

    assert raised.value.details == {
        "field": "output",
        "reason": "serialization",
    }


@pytest.mark.parametrize(
    "output",
    [
        {"blob": "x" * (5 * 1024 * 1024)},
        _nested_output(10_000),
    ],
    ids=["five-megabytes", "depth-10000"],
)
def test_adversarial_output_is_bounded_before_serialization(monkeypatch, output):
    def fail_if_serialized(*args, **kwargs):
        raise AssertionError("oversized output reached json.dumps")

    monkeypatch.setattr(
        "aegis._internal.adapter_invocation.json.dumps",
        fail_if_serialized,
    )

    with pytest.raises(InvocationValidationError):
        project_adapter_pre_call_invocation({"output": output})
