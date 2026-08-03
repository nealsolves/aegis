"""Regressions for private Phase A/B authorization state."""
from __future__ import annotations

import dataclasses

import pytest

from aegis._internal.enforcement import (
    AIGC,
    enforce_post_call,
    enforce_pre_call,
    enforce_pre_call_async,
)
from aegis._internal.errors import (
    CustomGateViolationError,
    InvocationValidationError,
)
from aegis._internal.gates import EnforcementGate, GateResult

GOLDEN_POLICY = "tests/golden_replays/golden_policy_v1.yaml"
INSERTION_PRE_OUTPUT = "pre_output"


def _pre_call_inv():
    return {
        "policy_file": GOLDEN_POLICY,
        "model_provider": "anthropic",
        "model_identifier": "claude-sonnet-4-5-20250929",
        "role": "planner",
        "input": {"query": "test"},
        "context": {"role_declared": True, "schema_exists": True},
    }


def _valid_output():
    return {"result": "ok", "confidence": 0.9}


class _AlwaysFailPreOutputGate(EnforcementGate):
    @property
    def name(self):
        return "always_fail_pre_output"

    @property
    def insertion_point(self):
        return INSERTION_PRE_OUTPUT

    def evaluate(self, invocation, policy, context):
        return GateResult(
            passed=False,
            failures=[{
                "code": "BLOCKED",
                "message": "always blocked",
                "field": None,
            }],
        )


def test_phase_b_gates_are_not_reachable_from_public_handle():
    issued = enforce_pre_call(
        _pre_call_inv(),
        custom_gates=[_AlwaysFailPreOutputGate()],
    )

    assert "_phase_b_grouped_gates" not in issued.__slots__
    with pytest.raises(CustomGateViolationError):
        enforce_post_call(issued, _valid_output())


def test_instance_phase_b_gate_remains_enforced():
    runtime = AIGC(custom_gates=[_AlwaysFailPreOutputGate()])
    issued = runtime.enforce_pre_call(_pre_call_inv())

    assert "_phase_b_grouped_gates" not in issued.__slots__
    with pytest.raises(CustomGateViolationError):
        runtime.enforce_post_call(issued, _valid_output())


@pytest.mark.asyncio
async def test_async_phase_b_gate_remains_enforced():
    issued = await enforce_pre_call_async(
        _pre_call_inv(),
        custom_gates=[_AlwaysFailPreOutputGate()],
    )

    assert "_phase_b_grouped_gates" not in issued.__slots__
    with pytest.raises(CustomGateViolationError):
        enforce_post_call(issued, _valid_output())


def test_phase_a_evidence_is_not_reachable_from_public_handle():
    issued = enforce_pre_call(_pre_call_inv())
    forbidden = {
        "invocation_snapshot",
        "_frozen_invocation_snapshot",
        "phase_a_metadata",
        "_frozen_phase_a_metadata",
        "resolved_conditions",
        "resolved_guards",
    }

    assert forbidden.isdisjoint(issued.__slots__)
    artifact = enforce_post_call(issued, _valid_output())
    assert artifact["role"] == "planner"
    assert artifact["policy_file"] == GOLDEN_POLICY


def test_replaced_handle_identity_cannot_select_private_evidence():
    issued = enforce_pre_call(_pre_call_inv())
    forged = dataclasses.replace(issued, issuer_id="0" * 32)

    with pytest.raises(InvocationValidationError) as exc_info:
        enforce_post_call(forged, _valid_output())
    assert exc_info.value.code == "OPERATION_ISSUER_MISMATCH"

    artifact = enforce_post_call(issued, _valid_output())
    assert artifact["role"] == "planner"
