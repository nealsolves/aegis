"""Tests for policy composition via extends."""

import copy

import pytest
from aegis._internal.policy_loader import compile_composed_policy, load_policy
from aegis._internal.errors import PolicyLoadError, PolicyValidationError


def test_extends_merges_arrays():
    """Child policy appends to base roles array."""
    policy = load_policy("tests/golden_replays/policy_child_extends_base.yaml")

    # Both base and child roles present
    assert "planner" in policy["roles"]
    assert "verifier" in policy["roles"]


def test_extends_replaces_scalars():
    """Child policy_version replaces base."""
    policy = load_policy("tests/golden_replays/policy_child_extends_base.yaml")

    # Child's policy_version overrides base
    assert policy["policy_version"] == "2.0"


def test_extends_merges_nested_dicts():
    """Preconditions from both base and child merge."""
    policy = load_policy("tests/golden_replays/policy_child_extends_base.yaml")

    # Both base and child preconditions present
    assert "role_declared" in policy["pre_conditions"]["required"]
    assert "citations_available" in policy["pre_conditions"]["required"]


def test_extends_inherits_output_schema():
    """Child inherits output_schema from base."""
    policy = load_policy("tests/golden_replays/policy_child_extends_base.yaml")

    # Output schema from base is inherited
    assert "output_schema" in policy
    assert policy["output_schema"]["properties"]["result"]["type"] == "string"


def test_no_extends_field():
    """Regular policy loading without extends works."""
    policy = load_policy("tests/golden_replays/golden_policy_v1.yaml")

    assert policy["policy_version"] == "1.0"
    assert "extends" not in policy


def test_extends_missing_base_fails():
    """Missing base policy file raises error."""
    with pytest.raises(PolicyLoadError) as exc_info:
        load_policy("tests/golden_replays/policy_extends_nonexistent.yaml")

    assert "Policy file does not exist" in str(exc_info.value)


def test_extends_removed_from_final_policy():
    """extends field is removed from merged policy."""
    policy = load_policy("tests/golden_replays/policy_child_extends_base.yaml")

    # extends field should be removed after merging
    assert "extends" not in policy


def test_extends_preserves_postconditions():
    """Postconditions from base are preserved."""
    policy = load_policy("tests/golden_replays/policy_child_extends_base.yaml")

    assert "post_conditions" in policy
    assert "output_schema_valid" in policy["post_conditions"]["required"]


def test_extends_inherits_description():
    """Child can override or inherit description."""
    policy = load_policy("tests/golden_replays/policy_child_extends_base.yaml")

    # Description from base is inherited (child doesn't override it)
    assert "description" in policy
    assert policy["description"] == "Base policy for composition testing"


def test_circular_extends_raises_policy_load_error():
    """Circular extends chain raises PolicyLoadError, not RecursionError."""
    with pytest.raises(PolicyLoadError) as exc_info:
        load_policy("tests/fixtures/policy_cycle_a.yaml")

    # Must be typed governance error, not RecursionError
    assert "Circular extends detected" in str(exc_info.value)
    assert "chain" in exc_info.value.details


def test_multi_level_extends_chain():
    """Multi-level non-cyclic extends chain works (A -> B -> C)."""
    # This tests that visited set is properly passed through the recursion
    # policy_child_extends_base extends policy_base, which is a 2-level chain
    policy = load_policy("tests/golden_replays/policy_child_extends_base.yaml")

    # Should successfully merge without cycle errors
    assert "roles" in policy
    assert "planner" in policy["roles"]  # from base
    assert "verifier" in policy["roles"]  # from child


def test_tool_limit_cannot_increase():
    parent = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "tools": {
            "allowed_tools": [
                {"name": "search", "max_calls": 5},
            ],
        },
    }
    child = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "tools": {
            "allowed_tools": [
                {"name": "search", "max_calls": 6},
            ],
        },
    }

    with pytest.raises(PolicyValidationError) as exc:
        compile_composed_policy(parent, child)

    assert exc.value.code == "POLICY_WIDENING"
    assert exc.value.details["path"] == "tools.allowed_tools"


def test_tool_limit_can_decrease_without_duplicate_ambiguity():
    parent = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "tools": {
            "allowed_tools": [
                {"name": "search", "max_calls": 5},
                {"name": "shell", "max_calls": 2},
            ],
        },
    }
    child = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "tools": {
            "allowed_tools": [
                {"name": "search", "max_calls": 4},
            ],
        },
    }

    compiled = compile_composed_policy(parent, child)

    assert [(item.name, item.max_calls) for item in compiled.tools] == [
        ("search", 4),
    ]


def test_child_cannot_change_risk_scored_to_warn_only():
    parent = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "risk": {"mode": "risk_scored", "threshold": 0.8},
    }
    child = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "risk": {"mode": "warn_only", "threshold": 0.8},
    }

    with pytest.raises(PolicyValidationError) as exc:
        compile_composed_policy(parent, child)

    assert exc.value.code == "POLICY_WIDENING"
    assert exc.value.details["path"] == "risk.mode"


@pytest.mark.parametrize("restricted_field", ["roles", "protocols"])
@pytest.mark.parametrize("erasure", ["missing", "empty"])
def test_composition_cannot_erase_participant_restrictions(
    restricted_field,
    erasure,
):
    participant = {
        "id": "agent-1",
        "roles": ["planner"],
        "protocols": ["local"],
    }
    parent = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "workflow": {"participants": [participant]},
    }
    replacement = copy.deepcopy(participant)
    if erasure == "missing":
        replacement.pop(restricted_field)
    else:
        replacement[restricted_field] = []
    child = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "workflow": {"participants": [replacement]},
    }

    with pytest.raises(PolicyValidationError) as exc:
        compile_composed_policy(parent, child)

    assert exc.value.code == "POLICY_WIDENING"
    assert exc.value.details["path"] == "workflow"


def test_composed_candidate_rejects_duplicate_participant_ids():
    participant = {
        "id": "agent-1",
        "roles": ["planner"],
        "protocols": ["local"],
    }
    parent = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "workflow": {"participants": [participant]},
    }
    child = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "workflow": {"participants": [participant, participant]},
    }

    with pytest.raises(PolicyValidationError) as exc:
        compile_composed_policy(parent, child)

    assert exc.value.code == "WORKFLOW_PARTICIPANT_AMBIGUOUS"


def test_composition_can_remove_some_participant_ids():
    parent = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "workflow": {
            "participants": [
                {
                    "id": "agent-1",
                    "roles": ["planner"],
                    "protocols": ["local"],
                },
                {
                    "id": "agent-2",
                    "roles": ["planner"],
                    "protocols": ["local"],
                },
            ],
        },
    }
    child = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "workflow": {
            "participants": [
                {
                    "id": "agent-1",
                    "roles": ["planner"],
                    "protocols": ["local"],
                },
            ],
        },
    }

    compiled = compile_composed_policy(parent, child)

    assert compiled.authority.restriction_values["workflow"]["participants"] == (
        {
            "id": "agent-1",
            "roles": ("planner",),
            "protocols": ("local",),
        },
    )


def test_composition_cannot_enable_default_disabled_protocol_capability():
    parent = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "workflow": {},
    }
    child = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "workflow": {
            "protocol_constraints": {
                "openai_agents": {"allow_hosted_tools": True},
            },
        },
    }

    with pytest.raises(PolicyValidationError) as exc:
        compile_composed_policy(parent, child)

    assert exc.value.code == "POLICY_WIDENING"
    assert exc.value.details["path"] == "workflow"
