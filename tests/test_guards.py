"""Tests for guard evaluation engine."""

import pytest
from aegis._internal.guards import (
    _evaluate_condition_expression,
    _merge_policy_blocks,
    evaluate_compiled_guards,
    evaluate_guards,
)
from aegis._internal.errors import (
    ConditionResolutionError,
    GuardEvaluationError,
    PolicyValidationError,
)
from aegis._internal.policy_compiler import compile_policy


def test_two_matching_guard_effects_cannot_widen_cumulatively():
    raw = {
        "policy_version": "2.0",
        "roles": ["planner", "reviewer"],
        "conditions": {
            "always": {"type": "boolean", "default": True},
        },
        "tools": {
            "allowed_tools": [
                {"name": "search", "max_calls": 2},
            ],
        },
    }
    raw["guards"] = [
        {
            "when": {"condition": "always"},
            "then": {"roles": ["reviewer"]},
        },
        {
            "when": {"condition": "always"},
            "then": {
                "tools": {
                    "allowed_tools": [
                        {"name": "shell", "max_calls": 1},
                    ],
                },
            },
        },
    ]

    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(raw, source="loaded")

    assert exc.value.code == "POLICY_WIDENING"
    assert exc.value.details["phase"] == "guard_overlay"
    assert exc.value.details["path"] == "tools.allowed_tools"


def test_guard_effect_can_lower_compiled_tool_limit():
    raw = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "conditions": {
            "always": {"type": "boolean", "default": True},
        },
        "tools": {
            "allowed_tools": [
                {"name": "search", "max_calls": 2},
            ],
        },
        "guards": [
            {
                "when": {"condition": "always"},
                "then": {
                    "tools": {
                        "allowed_tools": [
                            {"name": "search", "max_calls": 1},
                        ],
                    },
                },
            },
        ],
    }
    compiled = compile_policy(raw, source="loaded")

    effective, _, _ = evaluate_compiled_guards(
        compiled,
        compiled.guards,
        {},
    )

    assert [(item.name, item.max_calls) for item in effective.tools] == [
        ("search", 1),
    ]


@pytest.mark.parametrize("restricted_field", ["roles", "protocols"])
@pytest.mark.parametrize("erasure", ["missing", "empty"])
def test_guard_effect_cannot_erase_participant_restrictions(
    restricted_field,
    erasure,
):
    participant = {
        "id": "agent-1",
        "roles": ["planner"],
        "protocols": ["local"],
    }
    raw = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "conditions": {
            "always": {"type": "boolean", "default": True},
        },
        "workflow": {"participants": [participant]},
    }
    replacement = dict(participant)
    if erasure == "missing":
        replacement.pop(restricted_field)
    else:
        replacement[restricted_field] = []
    raw["guards"] = [{
        "when": {"condition": "always"},
        "then": {"workflow": {"participants": [replacement]}},
    }]

    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(raw, source="loaded")

    assert exc.value.code == "POLICY_WIDENING"
    assert exc.value.details["phase"] == "guard_overlay"
    assert exc.value.details["path"] == "workflow"


def test_guard_candidate_rejects_duplicate_participant_ids():
    participant = {
        "id": "agent-1",
        "roles": ["planner"],
        "protocols": ["local"],
    }
    raw = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "conditions": {
            "always": {"type": "boolean", "default": True},
        },
        "workflow": {"participants": [participant]},
    }
    raw["guards"] = [{
        "when": {"condition": "always"},
        "then": {
            "workflow": {
                "participants": [participant, participant],
            },
        },
    }]

    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(raw, source="loaded")

    assert exc.value.code == "WORKFLOW_PARTICIPANT_AMBIGUOUS"


def test_guard_cannot_enable_default_disabled_protocol_capability():
    raw = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "conditions": {
            "always": {"type": "boolean", "default": True},
        },
        "workflow": {},
    }
    raw["guards"] = [{
        "when": {"condition": "always"},
        "then": {
            "workflow": {
                "protocol_constraints": {
                    "openai_agents": {"allow_hosted_tools": True},
                },
            },
        },
    }]

    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(raw, source="loaded")

    assert exc.value.code == "POLICY_WIDENING"
    assert exc.value.details["path"] == "workflow"


def test_guard_matches_boolean_condition():
    """Guard with boolean condition that matches."""
    policy = {
        "policy_version": "1.0",
        "roles": ["planner"],
        "conditions": {
            "is_enterprise": {"type": "boolean", "default": False}
        },
        "guards": [
            {
                "when": {"condition": "is_enterprise"},
                "then": {
                    "post_conditions": {
                        "required": ["audit_level_high"]
                    }
                }
            }
        ]
    }
    context = {"is_enterprise": True}
    invocation = {"role": "planner"}

    effective_policy, guards_evaluated, conditions_resolved = evaluate_guards(
        policy, context, invocation
    )

    assert len(guards_evaluated) == 1
    assert guards_evaluated[0]["condition"] == "is_enterprise"
    assert guards_evaluated[0]["matched"] is True
    assert "post_conditions" in effective_policy
    assert "audit_level_high" in effective_policy["post_conditions"]["required"]
    assert conditions_resolved == {"is_enterprise": True}


def test_guard_no_match_boolean_condition():
    """Guard with boolean condition that doesn't match."""
    policy = {
        "policy_version": "1.0",
        "roles": ["planner"],
        "conditions": {
            "is_enterprise": {"type": "boolean", "default": False}
        },
        "guards": [
            {
                "when": {"condition": "is_enterprise"},
                "then": {
                    "post_conditions": {
                        "required": ["audit_level_high"]
                    }
                }
            }
        ]
    }
    context = {"is_enterprise": False}
    invocation = {"role": "planner"}

    effective_policy, guards_evaluated, conditions_resolved = evaluate_guards(
        policy, context, invocation
    )

    assert len(guards_evaluated) == 1
    assert guards_evaluated[0]["condition"] == "is_enterprise"
    assert guards_evaluated[0]["matched"] is False
    # Policy unchanged (guard didn't match)
    assert effective_policy.get("post_conditions") is None
    assert conditions_resolved == {"is_enterprise": False}


def test_guard_matches_role_equality():
    """Guard with role equality check that matches."""
    policy = {
        "policy_version": "1.0",
        "roles": ["planner", "verifier"],
        "guards": [
            {
                "when": {"condition": "role == verifier"},
                "then": {
                    "pre_conditions": {
                        "required": ["citations_available"]
                    }
                }
            }
        ]
    }
    context = {}
    invocation = {"role": "verifier"}

    effective_policy, guards_evaluated, conditions_resolved = evaluate_guards(
        policy, context, invocation
    )

    assert len(guards_evaluated) == 1
    assert guards_evaluated[0]["condition"] == "role == verifier"
    assert guards_evaluated[0]["matched"] is True
    assert "pre_conditions" in effective_policy
    assert "citations_available" in effective_policy["pre_conditions"]["required"]


def test_guard_no_match_role_equality():
    """Guard with role equality check that doesn't match."""
    policy = {
        "policy_version": "1.0",
        "roles": ["planner", "verifier"],
        "guards": [
            {
                "when": {"condition": "role == verifier"},
                "then": {
                    "pre_conditions": {
                        "required": ["citations_available"]
                    }
                }
            }
        ]
    }
    context = {}
    invocation = {"role": "planner"}

    effective_policy, guards_evaluated, conditions_resolved = evaluate_guards(
        policy, context, invocation
    )

    assert len(guards_evaluated) == 1
    assert guards_evaluated[0]["condition"] == "role == verifier"
    assert guards_evaluated[0]["matched"] is False
    assert effective_policy.get("pre_conditions") is None


def test_guard_adds_preconditions():
    """Guard appends to existing preconditions array."""
    policy = {
        "policy_version": "1.0",
        "roles": ["planner"],
        "pre_conditions": {
            "required": ["role_declared"]
        },
        "conditions": {
            "is_enterprise": {"type": "boolean"}
        },
        "guards": [
            {
                "when": {"condition": "is_enterprise"},
                "then": {
                    "pre_conditions": {
                        "required": ["audit_enabled"]
                    }
                }
            }
        ]
    }
    context = {"is_enterprise": True}
    invocation = {"role": "planner"}

    effective_policy, guards_evaluated, conditions_resolved = evaluate_guards(
        policy, context, invocation
    )

    # Both preconditions present (original + guard-added)
    assert set(effective_policy["pre_conditions"]["required"]) == {
        "role_declared",
        "audit_enabled",
    }


def test_guard_adds_postconditions():
    """Guard appends to existing postconditions array."""
    policy = {
        "policy_version": "1.0",
        "roles": ["planner"],
        "post_conditions": {
            "required": ["output_schema_valid"]
        },
        "conditions": {
            "is_enterprise": {"type": "boolean"}
        },
        "guards": [
            {
                "when": {"condition": "is_enterprise"},
                "then": {
                    "post_conditions": {
                        "required": ["pii_redacted"]
                    }
                }
            }
        ]
    }
    context = {"is_enterprise": True}
    invocation = {"role": "planner"}

    effective_policy, guards_evaluated, conditions_resolved = evaluate_guards(
        policy, context, invocation
    )

    assert set(effective_policy["post_conditions"]["required"]) == {
        "output_schema_valid",
        "pii_redacted",
    }


def test_multiple_guards_accumulate():
    """Multiple guards both match and effects combine."""
    policy = {
        "policy_version": "1.0",
        "roles": ["planner"],
        "conditions": {
            "is_enterprise": {"type": "boolean"},
            "audit_enabled": {"type": "boolean"}
        },
        "guards": [
            {
                "when": {"condition": "is_enterprise"},
                "then": {
                    "pre_conditions": {
                        "required": ["enterprise_quota"]
                    }
                }
            },
            {
                "when": {"condition": "audit_enabled"},
                "then": {
                    "post_conditions": {
                        "required": ["audit_written"]
                    }
                }
            }
        ]
    }
    context = {"is_enterprise": True, "audit_enabled": True}
    invocation = {"role": "planner"}

    effective_policy, guards_evaluated, conditions_resolved = evaluate_guards(
        policy, context, invocation
    )

    assert len(guards_evaluated) == 2
    assert all(g["matched"] for g in guards_evaluated)
    assert "enterprise_quota" in effective_policy["pre_conditions"]["required"]
    assert "audit_written" in effective_policy["post_conditions"]["required"]


def test_guard_order_matters():
    """Unknown guard-effect fields fail closed instead of becoming policy."""
    policy = {
        "policy_version": "1.0",
        "roles": ["planner"],
        "conditions": {
            "always_true": {"type": "boolean", "default": True}
        },
        "guards": [
            {
                "when": {"condition": "always_true"},
                "then": {"priority": 1}
            },
            {
                "when": {"condition": "always_true"},
                "then": {"priority": 2}  # Overrides first guard
            }
        ]
    }
    context = {}
    invocation = {"role": "planner"}

    with pytest.raises(PolicyValidationError) as exc:
        evaluate_guards(policy, context, invocation)

    assert exc.value.code == "RESTRICTION_SEMANTICS_MISSING"
    assert exc.value.details["path"] == "priority"


def test_guard_unknown_condition():
    """Unknown condition in guard expression raises error."""
    policy = {
        "policy_version": "1.0",
        "roles": ["planner"],
        "guards": [
            {
                "when": {"condition": "nonexistent_condition"},
                "then": {}
            }
        ]
    }
    context = {}
    invocation = {"role": "planner"}

    with pytest.raises(GuardEvaluationError) as exc_info:
        evaluate_guards(policy, context, invocation)

    assert exc_info.value.code == "GUARD_EVALUATION_ERROR"
    assert "nonexistent_condition" in str(exc_info.value)


def test_no_guards_returns_original_policy():
    """No guards in policy returns original policy unchanged."""
    policy = {
        "policy_version": "1.0",
        "roles": ["planner"]
    }
    context = {}
    invocation = {"role": "planner"}

    effective_policy, guards_evaluated, conditions_resolved = evaluate_guards(
        policy, context, invocation
    )

    assert effective_policy == policy
    assert guards_evaluated == []
    assert conditions_resolved == {}


def test_guard_uses_default_condition():
    """Condition not in context uses default value."""
    policy = {
        "policy_version": "1.0",
        "roles": ["planner"],
        "conditions": {
            "is_enterprise": {"type": "boolean", "default": False}
        },
        "guards": [
            {
                "when": {"condition": "is_enterprise"},
                "then": {
                    "post_conditions": {
                        "required": ["audit_level_high"]
                    }
                }
            }
        ]
    }
    context = {}  # No is_enterprise in context
    invocation = {"role": "planner"}

    effective_policy, guards_evaluated, conditions_resolved = evaluate_guards(
        policy, context, invocation
    )

    assert conditions_resolved == {"is_enterprise": False}
    assert guards_evaluated[0]["matched"] is False
    assert effective_policy.get("post_conditions") is None


def test_guard_with_required_condition_missing():
    """Required condition missing raises ConditionResolutionError."""
    policy = {
        "policy_version": "1.0",
        "roles": ["planner"],
        "conditions": {
            "audit_enabled": {"type": "boolean", "required": True}
        },
        "guards": [
            {
                "when": {"condition": "audit_enabled"},
                "then": {}
            }
        ]
    }
    context = {}  # Missing required condition
    invocation = {"role": "planner"}

    with pytest.raises(ConditionResolutionError) as exc_info:
        evaluate_guards(policy, context, invocation)

    assert exc_info.value.code == "CONDITION_RESOLUTION_ERROR"


def test_merge_policy_blocks_replaces_authorization_roles():
    """_merge_policy_blocks applies a restrictive role subset."""
    base = {"roles": ["planner"]}
    overlay = {"roles": ["verifier"]}

    _merge_policy_blocks(base, overlay)

    assert base["roles"] == ["verifier"]


def test_merge_policy_blocks_replaces_scalars():
    """_merge_policy_blocks replaces scalar values."""
    base = {"policy_version": "1.0"}
    overlay = {"policy_version": "2.0"}

    _merge_policy_blocks(base, overlay)

    assert base["policy_version"] == "2.0"


def test_merge_policy_blocks_recursive_dicts():
    """_merge_policy_blocks recursively merges nested dicts."""
    base = {"pre_conditions": {"required": ["role_declared"]}}
    overlay = {"pre_conditions": {"required": ["schema_exists"]}}

    _merge_policy_blocks(base, overlay)

    assert base["pre_conditions"]["required"] == ["role_declared", "schema_exists"]


def test_evaluate_condition_expression_unsupported_equality():
    """Hyphenated identifier in equality raises parse error."""
    with pytest.raises(GuardEvaluationError) as exc_info:
        _evaluate_condition_expression(
            "model == gpt-4",  # gpt-4 is not a valid identifier
            {},
            {"role": "planner"}
        )

    assert exc_info.value.code == "GUARD_EVALUATION_ERROR"


def test_evaluate_condition_expression_quoted_value():
    """Equality with quoted value works for any left-hand side."""
    result = _evaluate_condition_expression(
        'model == "gpt-4"',
        {},
        {"role": "planner", "context": {"model": "gpt-4"}}
    )
    assert result is True


def test_evaluate_condition_expression_and():
    """AND expression evaluates both operands."""
    result = _evaluate_condition_expression(
        "is_enterprise and audit_enabled",
        {"is_enterprise": True, "audit_enabled": True},
        {"role": "planner"}
    )
    assert result is True

    result = _evaluate_condition_expression(
        "is_enterprise and audit_enabled",
        {"is_enterprise": True, "audit_enabled": False},
        {"role": "planner"}
    )
    assert result is False


def test_evaluate_condition_expression_or():
    """OR expression returns true if either operand is true."""
    result = _evaluate_condition_expression(
        "is_enterprise or is_government",
        {"is_enterprise": False, "is_government": True},
        {"role": "planner"}
    )
    assert result is True

    result = _evaluate_condition_expression(
        "is_enterprise or is_government",
        {"is_enterprise": False, "is_government": False},
        {"role": "planner"}
    )
    assert result is False


def test_evaluate_condition_expression_not():
    """NOT expression negates the operand."""
    result = _evaluate_condition_expression(
        "not is_internal",
        {"is_internal": False},
        {"role": "planner"}
    )
    assert result is True

    result = _evaluate_condition_expression(
        "not is_internal",
        {"is_internal": True},
        {"role": "planner"}
    )
    assert result is False


def test_evaluate_condition_expression_parentheses():
    """Parenthesized expressions control evaluation order."""
    # (false or true) and true -> true
    result = _evaluate_condition_expression(
        "(is_enterprise or is_government) and audit_enabled",
        {"is_enterprise": False, "is_government": True, "audit_enabled": True},
        {"role": "planner"}
    )
    assert result is True

    # false or (true and false) -> false
    result = _evaluate_condition_expression(
        "is_enterprise or (is_government and audit_enabled)",
        {"is_enterprise": False, "is_government": True, "audit_enabled": False},
        {"role": "planner"}
    )
    assert result is False


def test_evaluate_condition_expression_not_equal():
    """Not-equal comparison works."""
    result = _evaluate_condition_expression(
        'role != "admin"',
        {},
        {"role": "planner"}
    )
    assert result is True

    result = _evaluate_condition_expression(
        'role != "planner"',
        {},
        {"role": "planner"}
    )
    assert result is False


def test_evaluate_condition_expression_numeric_comparison():
    """Numeric comparison operators work."""
    result = _evaluate_condition_expression(
        "count > 5",
        {},
        {"role": "planner", "context": {"count": 10}}
    )
    assert result is True

    result = _evaluate_condition_expression(
        "count <= 5",
        {},
        {"role": "planner", "context": {"count": 3}}
    )
    assert result is True


def test_evaluate_condition_expression_complex():
    """Complex compound expression works."""
    result = _evaluate_condition_expression(
        'is_enterprise and (role == "verifier" or audit_enabled)',
        {"is_enterprise": True, "audit_enabled": False},
        {"role": "verifier"}
    )
    assert result is True


def test_evaluate_condition_expression_in_operator_list():
    """The 'in' operator checks membership in a list from context."""
    result = _evaluate_condition_expression(
        '"search" in allowed_tools',
        {},
        {"role": "planner", "context": {"allowed_tools": ["search", "browse"]}}
    )
    assert result is True

    result = _evaluate_condition_expression(
        '"delete" in allowed_tools',
        {},
        {"role": "planner", "context": {"allowed_tools": ["search", "browse"]}}
    )
    assert result is False


def test_evaluate_condition_expression_in_operator_missing_field():
    """The 'in' operator returns False when field is missing."""
    result = _evaluate_condition_expression(
        '"search" in allowed_tools',
        {},
        {"role": "planner", "context": {}}
    )
    assert result is False


def test_evaluate_condition_expression_empty_raises():
    """Empty expression raises error."""
    with pytest.raises(GuardEvaluationError):
        _evaluate_condition_expression("", {}, {"role": "planner"})

    with pytest.raises(GuardEvaluationError):
        _evaluate_condition_expression("   ", {}, {"role": "planner"})


def test_evaluate_condition_expression_gt_lt():
    """Greater-than and less-than work."""
    result = _evaluate_condition_expression(
        "score >= 80",
        {},
        {"role": "planner", "context": {"score": 80}}
    )
    assert result is True

    result = _evaluate_condition_expression(
        "score < 50",
        {},
        {"role": "planner", "context": {"score": 30}}
    )
    assert result is True


def test_guard_with_compound_condition():
    """End-to-end guard with AND expression."""
    policy = {
        "policy_version": "1.0",
        "roles": ["planner"],
        "conditions": {
            "is_enterprise": {"type": "boolean", "default": False},
            "audit_enabled": {"type": "boolean", "default": False},
        },
        "guards": [
            {
                "when": {"condition": "is_enterprise and audit_enabled"},
                "then": {
                    "post_conditions": {
                        "required": ["full_audit"]
                    }
                }
            }
        ]
    }
    # Both true -> guard matches
    context = {"is_enterprise": True, "audit_enabled": True}
    invocation = {"role": "planner"}
    effective, evaluated, _ = evaluate_guards(policy, context, invocation)
    assert evaluated[0]["matched"] is True
    assert "full_audit" in effective["post_conditions"]["required"]

    # One false -> guard does not match
    context2 = {"is_enterprise": True, "audit_enabled": False}
    effective2, evaluated2, _ = evaluate_guards(policy, context2, invocation)
    assert evaluated2[0]["matched"] is False
    assert effective2.get("post_conditions") is None


def test_guard_with_not_condition():
    """End-to-end guard with NOT expression."""
    policy = {
        "policy_version": "1.0",
        "roles": ["planner"],
        "conditions": {
            "is_internal": {"type": "boolean", "default": False},
        },
        "guards": [
            {
                "when": {"condition": "not is_internal"},
                "then": {
                    "pre_conditions": {
                        "required": ["external_auth"]
                    }
                }
            }
        ]
    }
    context = {"is_internal": False}
    invocation = {"role": "planner"}
    effective, evaluated, _ = evaluate_guards(policy, context, invocation)
    assert evaluated[0]["matched"] is True
    assert "external_auth" in effective["pre_conditions"]["required"]


def test_compile_guard_expression_import():
    """compile_guard_expression is importable."""
    from aegis._internal.guards import compile_guard_expression
    ast = compile_guard_expression("is_enterprise and not is_internal")
    assert ast is not None
