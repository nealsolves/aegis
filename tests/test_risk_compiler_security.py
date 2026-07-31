"""Security regressions for compiled risk policy values."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from aegis._internal.compiled_policy import CompiledRiskFactor
from aegis._internal.errors import PolicyValidationError
from aegis._internal.policy_compiler import (
    compile_policy,
    compile_risk_policy,
    resolve_runtime_risk,
)


def _policy_with_risk(**risk: object) -> dict[str, object]:
    return {
        "policy_version": "1.0",
        "roles": ["verifier"],
        "risk": {"mode": "strict", **risk},
    }


class _NonFiniteNormalizingFloat(float):
    """Stores a finite value while normalizing to an attacker-chosen float."""

    def __new__(cls, normalized: float):
        instance = super().__new__(cls, 0.5)
        instance.normalized = normalized
        return instance

    def __float__(self) -> float:
        return self.normalized


@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), -float("inf"), True, "0.9"],
)
def test_security_number_rejects_non_finite_or_coerced_thresholds(value):
    """Changing risk validation back to float coercion must fail this test."""
    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(_policy_with_risk(threshold=value), source="test")

    assert exc.value.code == "RISK_NUMBER_INVALID"


@pytest.mark.parametrize(
    "normalized",
    [float("nan"), float("inf"), -float("inf")],
)
def test_security_number_revalidates_normalized_float_subclass(normalized):
    """A finite-looking subclass must not smuggle a non-finite float."""
    value = _NonFiniteNormalizingFloat(normalized)

    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(_policy_with_risk(threshold=value), source="test")

    assert exc.value.code == "RISK_NUMBER_INVALID"


@pytest.mark.parametrize(
    "value",
    [10**10_000, -(10**10_000)],
    ids=["positive", "negative"],
)
def test_security_number_translates_integer_normalization_overflow(value):
    """Huge Python integers must fail as typed policy errors, not OverflowError."""
    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(_policy_with_risk(threshold=value), source="test")

    assert exc.value.code == "RISK_NUMBER_INVALID"
    assert exc.value.details["path"] == "$.risk.threshold"


@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), -float("inf"), True, "0.4"],
)
def test_factor_weight_rejects_non_finite_or_coerced_values(value):
    """Factor arithmetic must never receive a coerced or non-finite weight."""
    policy = _policy_with_risk(
        factors=[
            {
                "name": "missing-output",
                "weight": value,
                "condition": "no_output_schema",
            }
        ]
    )

    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(policy, source="test")

    assert exc.value.code == "RISK_NUMBER_INVALID"


def test_compile_risk_policy_produces_frozen_typed_factors():
    """Replacing compiled factors with caller-owned mappings must fail."""
    raw = {
        "mode": "risk_scored",
        "threshold": 0.6,
        "factors": [
            {
                "name": "missing-output",
                "weight": 0.4,
                "condition": "no_output_schema",
            }
        ],
    }

    compiled = compile_risk_policy(raw)
    raw["factors"][0]["weight"] = 0.1

    assert compiled.factors == (
        CompiledRiskFactor(
            name="missing-output",
            weight=0.4,
            condition="no_output_schema",
        ),
    )
    with pytest.raises(FrozenInstanceError):
        compiled.factors[0].weight = 0.1


def test_unknown_risk_condition_fails_compilation():
    """Restoring caller-context fallback must not make typos authoritative."""
    with pytest.raises(PolicyValidationError) as exc:
        compile_risk_policy(
            {
                "mode": "strict",
                "factors": [
                    {
                        "name": "typo",
                        "weight": 0.2,
                        "condition": "high_riks",
                    }
                ],
            }
        )

    assert exc.value.code == "RISK_CONDITION_UNKNOWN"


@pytest.fixture
def compiled_risk():
    return compile_risk_policy(
        {
            "mode": "strict",
            "threshold": 0.7,
            "factors": [
                {
                    "name": "missing-output",
                    "weight": 0.2,
                    "condition": "no_output_schema",
                }
            ],
        }
    )


@pytest.mark.parametrize("mode", ["risk_scored", "warn_only"])
def test_runtime_override_cannot_lower_strictness(compiled_risk, mode):
    """A runtime mode override must not weaken strict policy."""
    with pytest.raises(PolicyValidationError) as exc:
        resolve_runtime_risk(compiled_risk, {"mode": mode})

    assert exc.value.code == "RISK_OVERRIDE_WIDENS"


def test_runtime_override_cannot_raise_threshold(compiled_risk):
    """A higher runtime threshold must not permit more risk."""
    with pytest.raises(PolicyValidationError) as exc:
        resolve_runtime_risk(compiled_risk, {"threshold": 0.8})

    assert exc.value.code == "RISK_OVERRIDE_WIDENS"


def test_runtime_override_cannot_remove_or_change_factors(compiled_risk):
    """Dropping or changing a compiled factor must fail closed."""
    with pytest.raises(PolicyValidationError) as removed:
        resolve_runtime_risk(compiled_risk, {"factors": []})
    with pytest.raises(PolicyValidationError) as changed:
        resolve_runtime_risk(
            compiled_risk,
            {
                "factors": [
                    {
                        "name": "missing-output",
                        "weight": 0.1,
                        "condition": "no_output_schema",
                    }
                ]
            },
        )

    assert removed.value.code == "RISK_OVERRIDE_WIDENS"
    assert changed.value.code == "RISK_OVERRIDE_WIDENS"


def test_runtime_override_must_retain_duplicate_factor_multiplicity():
    """Collapsing equal factors would lower their total score contribution."""
    factor = {
        "name": "missing-output",
        "weight": 0.2,
        "condition": "no_output_schema",
    }
    base = compile_risk_policy(
        {
            "mode": "strict",
            "threshold": 0.7,
            "factors": [factor, factor],
        }
    )

    with pytest.raises(PolicyValidationError) as exc:
        resolve_runtime_risk(base, {"factors": [factor]})

    assert exc.value.code == "RISK_OVERRIDE_WIDENS"


def test_runtime_override_may_tighten_mode_threshold_and_add_factor():
    """Rejecting a monotonic override would break the supported runtime API."""
    base = compile_risk_policy(
        {"mode": "warn_only", "threshold": 0.7, "factors": []}
    )

    resolved = resolve_runtime_risk(
        base,
        {
            "mode": "strict",
            "threshold": 0.5,
            "factors": [
                {
                    "name": "missing-guards",
                    "weight": 0.3,
                    "condition": "missing_guards",
                }
            ],
        },
    )

    assert resolved.mode == "strict"
    assert resolved.threshold == 0.5
    assert resolved.critical_ceiling == 0.90
    assert resolved.factors == (
        CompiledRiskFactor(
            name="missing-guards",
            weight=0.3,
            condition="missing_guards",
        ),
    )


def test_runtime_override_cannot_configure_critical_ceiling(compiled_risk):
    """Even an equal-looking override must not make the fixed ceiling mutable."""
    with pytest.raises(PolicyValidationError) as exc:
        resolve_runtime_risk(compiled_risk, {"critical_ceiling": 0.90})

    assert exc.value.code == "RISK_OVERRIDE_WIDENS"


@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), -float("inf"), True, "0.5"],
)
def test_runtime_threshold_revalidates_security_number(compiled_risk, value):
    """Runtime override boundaries must repeat strict numeric validation."""
    with pytest.raises(PolicyValidationError) as exc:
        resolve_runtime_risk(compiled_risk, {"threshold": value})

    assert exc.value.code == "RISK_NUMBER_INVALID"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("minimum", float("nan")),
        ("minimum", float("inf")),
        ("maximum", -float("inf")),
        ("minimum", True),
        ("maximum", "10"),
        ("minLength", True),
        ("maxLength", 2.0),
    ],
)
def test_precondition_limits_reject_non_finite_or_coerced_values(field, value):
    """Typed constraint limits must pass through the strict numeric boundary."""
    declared_type = "string" if "Length" in field else "number"
    policy = {
        "policy_version": "1.0",
        "roles": ["verifier"],
        "pre_conditions": {
            "required": {
                "value": {
                    "type": declared_type,
                    field: value,
                }
            }
        },
    }

    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(policy, source="test")

    assert exc.value.code == "RISK_NUMBER_INVALID"


@pytest.mark.parametrize(
    ("policy_fragment", "path"),
    [
        (
            {"tools": {"allowed_tools": [{"name": "lookup", "max_calls": True}]}},
            "$.tools.allowed_tools.0.max_calls",
        ),
        (
            {"workflow": {"max_steps": 1.0}},
            "$.workflow.max_steps",
        ),
        (
            {"workflow": {"max_total_tool_calls": "5"}},
            "$.workflow.max_total_tool_calls",
        ),
        (
            {
                "workflow": {
                    "escalation": {"require_approval_after_steps": False}
                }
            },
            "$.workflow.escalation.require_approval_after_steps",
        ),
    ],
)
def test_authority_limits_reject_coerced_integer_values(policy_fragment, path):
    """Tool and workflow limits must not rely on JSON Schema coercion rules."""
    policy = {
        "policy_version": "1.0",
        "roles": ["verifier"],
        **policy_fragment,
    }

    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(policy, source="test")

    assert exc.value.code == "RISK_NUMBER_INVALID"
    assert exc.value.details["path"] == path
