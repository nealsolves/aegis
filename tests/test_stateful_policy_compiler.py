from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError

import pytest

from aegis._internal.errors import PolicyValidationError, StatefulCompositionError
from aegis._internal.policy_compiler import compile_policy
from aegis._internal.restrictions import RestrictionComparator


def _policy() -> dict:
    return {
        "policy_version": "1.0",
        "roles": ["assistant"],
        "tools": {
            "allowed_tools": [
                {"name": "search", "max_calls": 10},
                {"name": "fetch", "max_calls": 10},
            ]
        },
        "stateful": {
            "contract_version": 1,
            "policy_state_id": "assistant-policy",
            "constraints": [
                {
                    "id": "search-window",
                    "kind": "sliding_window_tool_calls",
                    "tool": "search",
                    "scope": "tenant",
                    "limit": 5,
                    "window_ms": 60_000,
                    "provider_timeout_ms": 100,
                    "retry_horizon_ms": 1000,
                    "on_provider_failure": "deny",
                }
            ],
        },
    }


def _compile(raw: dict):
    return compile_policy(raw, source="stateful-test")


def test_valid_stateful_policy_compiles_to_detached_immutable_values() -> None:
    raw = _policy()
    compiled = _compile(raw)
    raw["stateful"]["constraints"][0]["limit"] = 999

    assert compiled.stateful.contract_version == 1
    assert compiled.stateful.policy_state_id == "assistant-policy"
    constraint = compiled.stateful.constraints[0]
    assert constraint.id == "search-window"
    assert constraint.tool == "search"
    assert constraint.limit == 5
    with pytest.raises(FrozenInstanceError):
        constraint.limit = 10  # type: ignore[misc]


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("contract_version",), 2),
        (("policy_state_id",), "not allowed"),
        (("constraints", 0, "kind"), "quota"),
        (("constraints", 0, "scope"), "session"),
        (("constraints", 0, "on_provider_failure"), "allow"),
        (("constraints", 0, "limit"), True),
        (("constraints", 0, "limit"), "5"),
        (("constraints", 0, "limit"), 0),
        (("constraints", 0, "window_ms"), True),
        (("constraints", 0, "provider_timeout_ms"), 0),
    ],
)
def test_invalid_closed_stateful_fields_fail_compilation(path, value) -> None:
    raw = _policy()
    target = raw["stateful"]
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value

    with pytest.raises(PolicyValidationError):
        _compile(raw)


def test_unknown_fields_and_duplicate_ids_or_tools_fail() -> None:
    unknown = _policy()
    unknown["stateful"]["constraints"][0]["surprise"] = True
    with pytest.raises(PolicyValidationError):
        _compile(unknown)

    duplicate_id = _policy()
    duplicate_id["stateful"]["constraints"].append({
        **duplicate_id["stateful"]["constraints"][0],
        "tool": "fetch",
    })
    with pytest.raises(PolicyValidationError, match="duplicate"):
        _compile(duplicate_id)

    duplicate_tool = _policy()
    duplicate_tool["stateful"]["constraints"].append({
        **duplicate_tool["stateful"]["constraints"][0],
        "id": "other-id",
    })
    with pytest.raises(PolicyValidationError, match="tool"):
        _compile(duplicate_tool)


def test_retry_horizon_must_cover_dispatch_and_constrained_tool_must_be_authorized() -> None:
    horizon = _policy()
    horizon["stateful"]["constraints"][0]["retry_horizon_ms"] = 99
    with pytest.raises(PolicyValidationError, match="retry horizon"):
        _compile(horizon)

    unauthorized = _policy()
    unauthorized["stateful"]["constraints"][0]["tool"] = "not-allowed"
    with pytest.raises(PolicyValidationError, match="tool authority"):
        _compile(unauthorized)


def test_stateful_guard_effect_is_rejected() -> None:
    raw = _policy()
    raw["conditions"] = {"enabled": {"type": "boolean", "default": True}}
    raw["guards"] = [{
        "when": {"condition": "enabled"},
        "then": {"stateful": copy.deepcopy(raw["stateful"])},
    }]

    with pytest.raises(PolicyValidationError) as captured:
        _compile(raw)
    assert captured.value.code == "STATEFUL_GUARD_UNSUPPORTED"


def _candidate(mutator):
    raw = _policy()
    mutator(raw["stateful"], raw["stateful"]["constraints"][0])
    return _compile(raw)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda stateful, constraint: stateful.update(policy_state_id="new-policy"),
        lambda stateful, constraint: constraint.update(id="new-id"),
        lambda stateful, constraint: constraint.update(tool="fetch"),
        lambda stateful, constraint: constraint.update(limit=6),
        lambda stateful, constraint: constraint.update(window_ms=120_000),
        lambda stateful, constraint: constraint.update(provider_timeout_ms=200),
        lambda stateful, constraint: constraint.update(retry_horizon_ms=2000),
    ],
)
def test_stateful_composition_rejects_widening_or_identity_changes(mutator) -> None:
    parent = _compile(_policy())

    with pytest.raises(StatefulCompositionError) as captured:
        RestrictionComparator().assert_effective(parent.authority, _candidate(mutator))
    assert captured.value.code == "STATEFUL_COMPOSITION_WIDENING"


def test_stateful_composition_allows_limit_and_timeout_narrowing() -> None:
    parent = _compile(_policy())
    candidate = _candidate(lambda stateful, constraint: constraint.update(
        limit=4,
        provider_timeout_ms=50,
        retry_horizon_ms=500,
    ))

    RestrictionComparator().assert_effective(parent.authority, candidate)


def test_stateful_composition_rejects_removal() -> None:
    parent = _compile(_policy())
    raw = _policy()
    raw.pop("stateful")

    with pytest.raises(StatefulCompositionError) as captured:
        RestrictionComparator().assert_effective(parent.authority, _compile(raw))
    assert captured.value.code == "STATEFUL_COMPOSITION_WIDENING"
