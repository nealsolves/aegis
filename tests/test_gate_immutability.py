"""Tests proving custom gates cannot mutate policy or invocation objects."""

from types import MappingProxyType

import pytest

from aegis._internal.enforcement import AIGC
from aegis._internal.errors import GovernanceViolationError
from aegis._internal.gate_projection import detached_json_projection
from aegis._internal.gates import (
    EnforcementGate,
    GateResult,
    INSERTION_POST_AUTHORIZATION,
    run_gates,
)


class TestDetachedProjectionBlocksMutation:
    def setup_method(self):
        self.view = detached_json_projection({"key": "value", "other": 42})

    def test_setitem_blocked(self):
        with pytest.raises(TypeError):
            self.view["key"] = "new"

    def test_delitem_blocked(self):
        with pytest.raises(TypeError):
            del self.view["key"]

    @pytest.mark.parametrize("method", ["pop", "update", "clear"])
    def test_mutating_mapping_methods_unavailable(self, method):
        assert not hasattr(self.view, method)

    def test_read_access_works(self):
        assert self.view["key"] == "value"
        assert self.view["other"] == 42
        assert len(self.view) == 2
        assert "key" in self.view


class TestDetachedProjectionRecursiveFreezing:
    def test_nested_dict_is_immutable(self):
        view = detached_json_projection({"outer": {"inner": "val"}})
        nested = view["outer"]
        assert isinstance(nested, MappingProxyType)
        assert nested["inner"] == "val"
        with pytest.raises(TypeError):
            nested["inner"] = "mutated"

    def test_deeply_nested_dict_is_immutable(self):
        view = detached_json_projection({"a": {"b": {"c": "deep"}}})
        deep = view["a"]["b"]
        assert isinstance(deep, MappingProxyType)
        assert deep["c"] == "deep"
        with pytest.raises(TypeError):
            deep["c"] = "mutated"

    def test_list_becomes_tuple(self):
        view = detached_json_projection({"items": [1, 2, 3]})
        assert view["items"] == (1, 2, 3)
        assert isinstance(view["items"], tuple)

    def test_list_of_dicts_becomes_tuple_of_mapping_proxies(self):
        view = detached_json_projection({"items": [{"a": 1}, {"b": 2}]})
        result = view["items"]
        assert isinstance(result, tuple)
        assert isinstance(result[0], MappingProxyType)
        with pytest.raises(TypeError):
            result[0]["a"] = 99

    def test_projection_is_detached_from_original_collections(self):
        source = {"outer": {"items": [1, 2]}}
        view = detached_json_projection(source)
        source["outer"]["items"].append(3)
        assert view["outer"]["items"] == (1, 2)


class PolicyMutatingGate(EnforcementGate):
    @property
    def name(self):
        return "policy_mutator"

    @property
    def insertion_point(self):
        return INSERTION_POST_AUTHORIZATION

    def evaluate(self, invocation, policy, context):
        policy["roles"] = ["hacked"]
        return GateResult(passed=True)


class InvocationMutatingGate(EnforcementGate):
    @property
    def name(self):
        return "invocation_mutator"

    @property
    def insertion_point(self):
        return INSERTION_POST_AUTHORIZATION

    def evaluate(self, invocation, policy, context):
        invocation["context"] = {"injected": True}
        return GateResult(passed=True)


class NestedPolicyMutatingGate(EnforcementGate):
    @property
    def name(self):
        return "nested_policy_mutator"

    @property
    def insertion_point(self):
        return INSERTION_POST_AUTHORIZATION

    def evaluate(self, invocation, policy, context):
        policy["preconditions"]["injected_condition"] = True
        return GateResult(passed=True)


class TestRunGatesMutationDetection:
    @pytest.mark.parametrize(
        ("gate", "invocation", "policy"),
        [
            (PolicyMutatingGate(), {}, {"roles": ["planner"]}),
            (InvocationMutatingGate(), {"context": {}}, {}),
            (NestedPolicyMutatingGate(), {}, {"preconditions": {}}),
        ],
    )
    def test_mutation_attempt_fails_closed(self, gate, invocation, policy):
        failures, _ = run_gates([gate], invocation, policy, {}, [], [])
        assert len(failures) == 1
        assert failures[0]["code"] == "CUSTOM_GATE_ERROR"

    def test_original_data_unchanged_after_mutation_attempt(self):
        original_policy = {"roles": ["planner"]}
        original_invocation = {"context": {"role_declared": True}}
        run_gates(
            [PolicyMutatingGate()],
            original_invocation,
            original_policy,
            {},
            [],
            [],
        )
        assert original_policy == {"roles": ["planner"]}
        assert original_invocation == {"context": {"role_declared": True}}


VALID_INVOCATION = {
    "policy_file": "tests/golden_replays/golden_policy_v1.yaml",
    "model_provider": "openai",
    "model_identifier": "gpt-4",
    "role": "planner",
    "input": {"prompt": "test"},
    "output": {"result": "ok", "confidence": 0.9},
    "context": {"role_declared": True, "schema_exists": True},
}


def test_aigc_mutating_gate_produces_governance_failure():
    aegis = AIGC(custom_gates=[PolicyMutatingGate()])
    with pytest.raises(GovernanceViolationError) as exc_info:
        aegis.enforce(VALID_INVOCATION)
    artifact = exc_info.value.audit_artifact
    assert artifact is not None
    assert artifact["enforcement_result"] == "FAIL"
    assert artifact["failure_gate"] == "custom_gate_violation"
    assert exc_info.value.details["custom_gate_failures"][0]["code"] == (
        "CUSTOM_GATE_ERROR"
    )
