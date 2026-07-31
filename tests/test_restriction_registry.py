"""Security regression tests for the default-deny restriction registry."""

from __future__ import annotations

import copy
import json
from datetime import date, datetime
from pathlib import Path

import pytest

from aegis._internal.errors import PolicyValidationError
from aegis._internal.policy_compiler import compile_policy
from aegis._internal.restrictions import (
    PROTOCOL_CAPABILITY_RULES,
    REGISTRY,
    RestrictionComparator,
    protocol_capability_schema_fields,
    security_sensitive_schema_fields,
)
from aegis._internal.tools import validate_tool_constraints


@pytest.fixture
def base_policy() -> dict:
    return {
        "policy_version": "2.0",
        "roles": ["planner", "reviewer"],
        "conditions": {
            "enterprise": {
                "type": "boolean",
                "required": True,
            },
        },
        "tools": {
            "allowed_tools": [
                {"name": "search", "max_calls": 5},
                {"name": "shell", "max_calls": 2},
            ],
        },
        "retry_policy": {"max_retries": 3, "backoff_ms": 100},
        "risk": {
            "mode": "risk_scored",
            "threshold": 0.8,
            "factors": [
                {
                    "name": "tool-count",
                    "weight": 0.2,
                    "condition": "high_tool_count",
                },
            ],
        },
        "pre_conditions": {
            "required": {
                "approved": {"type": "boolean"},
            },
        },
        "post_conditions": {"required": ["output_schema_valid"]},
        "output_schema": {
            "type": "object",
            "properties": {"result": {"type": "string"}},
            "required": ["result"],
        },
        "workflow": {
            "max_steps": 5,
            "max_total_tool_calls": 10,
            "required_sequence": ["plan", "execute"],
        },
    }


def test_schema_security_markers_have_exact_registry_coverage():
    schema_path = Path("schemas/policy_dsl.schema.json")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    assert security_sensitive_schema_fields(schema) == REGISTRY.fields


def test_protocol_schema_capabilities_have_exact_direction_registry_coverage():
    schema_path = Path("schemas/policy_dsl.schema.json")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    assert protocol_capability_schema_fields(schema) == frozenset(
        PROTOCOL_CAPABILITY_RULES,
    )
    assert {
        path: (rule.default, rule.direction)
        for path, rule in PROTOCOL_CAPABILITY_RULES.items()
    } == {
        "bedrock.require_trace": (False, "require"),
        "bedrock.require_alias_backed_identity": (True, "require"),
        "bedrock.require_alias": (True, "require"),
        "a2a.protocol_version": ("1.0", "exact"),
        "a2a.allowed_protocol_bindings": (
            ("JSONRPC", "HTTP+JSON"),
            "subset",
        ),
        "a2a.require_task_state": (True, "require"),
        "openai_agents.require_trace": (False, "require"),
        "openai_agents.allow_hosted_tools": (False, "allow"),
        "openai_agents.allow_agent_as_tool": (True, "allow"),
        "openai_agents.require_unique_agent_names": (True, "require"),
    }


def test_guard_effect_cannot_add_role(base_policy):
    base_policy["guards"] = [
        {
            "when": {"condition": "enterprise"},
            "then": {"roles": ["admin"]},
        },
    ]

    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(base_policy, source="guard-role")

    assert exc.value.code == "POLICY_WIDENING"
    assert exc.value.details["phase"] == "guard_overlay"


def test_unregistered_security_field_fails_closed(base_policy):
    base_policy["future_authority"] = {"allow": True}

    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(base_policy, source="future-field")

    assert exc.value.code == "RESTRICTION_SEMANTICS_MISSING"
    assert exc.value.details["path"] == "future_authority"


def test_raw_overlay_is_checked_even_when_merge_hides_added_role(base_policy):
    parent = compile_policy(base_policy, source="parent")
    overlay = {
        "composition_strategy": "intersect",
        "roles": ["planner", "admin"],
    }
    effective_raw = copy.deepcopy(base_policy)
    effective_raw["roles"] = ["planner"]
    effective = compile_policy(effective_raw, source="effective")

    with pytest.raises(PolicyValidationError) as exc:
        RestrictionComparator().assert_overlay_and_effective(
            parent=parent,
            overlay=overlay,
            effective=effective,
        )

    assert exc.value.code == "POLICY_WIDENING"
    assert exc.value.details["phase"] == "overlay"
    assert exc.value.details["path"] == "roles"


def test_tool_name_and_limit_must_both_narrow(base_policy):
    parent = compile_policy(base_policy, source="parent")
    candidate_raw = copy.deepcopy(base_policy)
    candidate_raw["tools"]["allowed_tools"] = [
        {"name": "search", "max_calls": 6},
    ]
    candidate = compile_policy(candidate_raw, source="candidate")

    with pytest.raises(PolicyValidationError) as exc:
        RestrictionComparator().assert_effective(parent.authority, candidate)

    assert exc.value.code == "POLICY_WIDENING"
    assert exc.value.details["path"] == "tools.allowed_tools"


@pytest.mark.parametrize(
    ("change", "path"),
    [
        ({"mode": "warn_only"}, "risk.mode"),
        ({"threshold": 0.9}, "risk.threshold"),
        (
            {
                "factors": [
                    {
                        "name": "tool-count",
                        "weight": 0.1,
                        "condition": "high_tool_count",
                    },
                ],
            },
            "risk.factors",
        ),
    ],
)
def test_risk_composition_cannot_weaken(base_policy, change, path):
    parent = compile_policy(base_policy, source="parent")
    candidate_raw = copy.deepcopy(base_policy)
    candidate_raw["risk"].update(change)
    candidate = compile_policy(candidate_raw, source="candidate")

    with pytest.raises(PolicyValidationError) as exc:
        RestrictionComparator().assert_effective(parent.authority, candidate)

    assert exc.value.code == "POLICY_WIDENING"
    assert exc.value.details["path"] == path


def test_output_schema_must_remain_unchanged_without_proven_narrowing(base_policy):
    parent = compile_policy(base_policy, source="parent")
    candidate_raw = copy.deepcopy(base_policy)
    candidate_raw["output_schema"]["properties"]["result"] = {"type": "number"}
    candidate = compile_policy(candidate_raw, source="candidate")

    with pytest.raises(PolicyValidationError) as exc:
        RestrictionComparator().assert_effective(parent.authority, candidate)

    assert exc.value.code == "POLICY_WIDENING"
    assert exc.value.details["path"] == "output_schema"


def test_output_schema_comparison_preserves_json_boolean_number_distinction(
    base_policy,
):
    base_policy["output_schema"]["properties"]["result"] = {"enum": [1]}
    parent = compile_policy(base_policy, source="parent")
    candidate_raw = copy.deepcopy(base_policy)
    candidate_raw["output_schema"]["properties"]["result"] = {"enum": [True]}
    candidate = compile_policy(candidate_raw, source="candidate")

    with pytest.raises(PolicyValidationError) as exc:
        RestrictionComparator().assert_effective(parent.authority, candidate)

    assert exc.value.code == "POLICY_WIDENING"
    assert exc.value.details["path"] == "output_schema"


def test_typed_authority_fields_are_detached_and_immutable(base_policy):
    compiled = compile_policy(base_policy, source="snapshot")
    base_policy["workflow"]["max_steps"] = 100

    assert compiled.authority.workflow["max_steps"] == 5
    with pytest.raises(TypeError):
        compiled.authority.workflow["max_steps"] = 6


def test_tool_validation_consumes_compiled_limits(base_policy):
    compiled = compile_policy(base_policy, source="tools")
    invocation = {
        "tool_calls": [
            {"name": "shell", "call_id": "one"},
            {"name": "shell", "call_id": "two"},
        ],
    }

    result = validate_tool_constraints(invocation, compiled.tools)

    assert result == {"tools_checked": ["shell"], "violations": []}


def test_duplicate_tool_names_are_ambiguous_compile_errors(base_policy):
    base_policy["tools"]["allowed_tools"] = [
        {"name": "search", "max_calls": 1},
        {"name": "search", "max_calls": 5},
    ]

    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(base_policy, source="duplicate-tools")

    assert exc.value.code == "TOOL_CONSTRAINT_AMBIGUOUS"


def test_duplicate_workflow_participant_ids_are_ambiguous_compile_errors(
    base_policy,
):
    base_policy["workflow"]["participants"] = [
        {"id": "agent-1", "roles": ["planner"]},
        {"id": "agent-1", "roles": ["reviewer"]},
    ]

    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(base_policy, source="duplicate-participants")

    assert exc.value.code == "WORKFLOW_PARTICIPANT_AMBIGUOUS"
    assert exc.value.details["path"] == "$.workflow.participants"
    assert exc.value.details["participant_ids"] == ["agent-1"]


@pytest.mark.parametrize(
    ("field", "value", "normalized"),
    [
        ("effective_date", date(2026, 1, 2), "2026-01-02"),
        (
            "expiration_date",
            datetime(2027, 3, 4, 18, 30),
            "2027-03-04",
        ),
    ],
)
def test_loader_supported_dates_have_stable_iso_digest(
    base_policy,
    field,
    value,
    normalized,
):
    date_policy = copy.deepcopy(base_policy)
    date_policy[field] = value
    string_policy = copy.deepcopy(base_policy)
    string_policy[field] = normalized

    compiled_date = compile_policy(date_policy, source="date")
    compiled_string = compile_policy(string_policy, source="string")

    assert compiled_date.policy_digest == compiled_string.policy_digest


def test_non_json_date_outside_supported_root_fields_fails_closed(base_policy):
    base_policy["output_schema"]["properties"]["result"] = {
        "const": date(2026, 1, 2),
    }

    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(base_policy, source="nested-date")

    assert exc.value.code == "POLICY_NON_JSON_VALUE"
    assert exc.value.details["path"] == "$.output_schema.properties.result.const"


def test_existing_condition_contract_cannot_be_replaced(base_policy):
    parent = compile_policy(base_policy, source="parent")
    candidate_raw = copy.deepcopy(base_policy)
    candidate_raw["conditions"]["enterprise"] = {
        "type": "boolean",
        "default": False,
    }
    candidate = compile_policy(candidate_raw, source="candidate")

    with pytest.raises(PolicyValidationError) as exc:
        RestrictionComparator().assert_effective(parent.authority, candidate)

    assert exc.value.code == "POLICY_WIDENING"
    assert exc.value.details["path"] == "conditions"


def test_retry_count_and_timeout_cannot_increase(base_policy):
    parent = compile_policy(base_policy, source="parent")
    for key, value in (("max_retries", 4), ("backoff_ms", 101)):
        candidate_raw = copy.deepcopy(base_policy)
        candidate_raw["retry_policy"][key] = value
        candidate = compile_policy(candidate_raw, source=f"candidate-{key}")

        with pytest.raises(PolicyValidationError) as exc:
            RestrictionComparator().assert_effective(
                parent.authority,
                candidate,
            )

        assert exc.value.code == "POLICY_WIDENING"
        assert exc.value.details["path"] == f"retry_policy.{key}"


@pytest.mark.parametrize("field", ["pre_conditions", "post_conditions"])
def test_required_constraint_cannot_be_removed(base_policy, field):
    parent = compile_policy(base_policy, source="parent")
    candidate_raw = copy.deepcopy(base_policy)
    candidate_raw[field] = {"required": {} if field == "pre_conditions" else []}
    candidate = compile_policy(candidate_raw, source=f"candidate-{field}")

    with pytest.raises(PolicyValidationError) as exc:
        RestrictionComparator().assert_effective(parent.authority, candidate)

    assert exc.value.code == "POLICY_WIDENING"
    assert exc.value.details["path"] == field


def test_workflow_budget_cannot_increase(base_policy):
    parent = compile_policy(base_policy, source="parent")
    candidate_raw = copy.deepcopy(base_policy)
    candidate_raw["workflow"]["max_steps"] = 6
    candidate = compile_policy(candidate_raw, source="candidate-workflow")

    with pytest.raises(PolicyValidationError) as exc:
        RestrictionComparator().assert_effective(parent.authority, candidate)

    assert exc.value.code == "POLICY_WIDENING"
    assert exc.value.details["path"] == "workflow"
