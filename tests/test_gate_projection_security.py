"""Security tests for detached custom-gate argument projections."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from aegis._internal.gate_projection import GateProjectionFactory
from aegis._internal.gates import (
    EnforcementGate,
    GateResult,
    INSERTION_POST_AUTHORIZATION,
    run_gates,
)


def _walk_objects(value: object, seen: set[int] | None = None):
    seen = seen or set()
    if id(value) in seen:
        return
    seen.add(id(value))
    yield value
    if isinstance(value, Mapping):
        for item in value.values():
            yield from _walk_objects(item, seen)
    elif isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        for item in value:
            yield from _walk_objects(item, seen)
    for slot in getattr(type(value), "__slots__", ()):
        if isinstance(slot, str) and hasattr(value, slot):
            yield from _walk_objects(getattr(value, slot), seen)


def test_gate_cannot_reach_live_policy_backing_mapping():
    live = {"roles": ["verifier"]}
    projection = GateProjectionFactory.policy_from_mapping(live)
    assert not hasattr(projection, "_data")
    for value in _walk_objects(projection):
        assert value is not live
        assert value is not live["roles"]


class _ObjectGraphMutatingGate(EnforcementGate):
    @property
    def name(self) -> str:
        return "object_graph_mutator"

    @property
    def insertion_point(self) -> str:
        return INSERTION_POST_AUTHORIZATION

    def evaluate(self, invocation, policy, context):
        for root in (invocation, policy, context):
            for value in _walk_objects(root):
                if isinstance(value, dict):
                    value.clear()
                elif isinstance(value, list):
                    value.clear()
        return GateResult(passed=True)


def test_malicious_gate_cannot_mutate_authorization_basis():
    live_invocation: dict[str, Any] = {
        "role": "verifier",
        "context": {"approved": True},
    }
    live_policy: dict[str, Any] = {
        "roles": ["verifier"],
        "conditions": {"approved": True},
    }
    live_context: dict[str, Any] = {"phase": {"authorized": True}}
    run_gates(
        [_ObjectGraphMutatingGate()],
        live_invocation,
        live_policy,
        live_context,
        [],
        [],
    )
    assert live_invocation == {
        "role": "verifier",
        "context": {"approved": True},
    }
    assert live_policy == {
        "roles": ["verifier"],
        "conditions": {"approved": True},
    }
    assert live_context == {"phase": {"authorized": True}}
