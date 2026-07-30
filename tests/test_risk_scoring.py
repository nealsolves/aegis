"""Tests for the risk scoring engine (M2 feature)."""
import pytest
from aegis._internal.compiled_policy import (
    CompiledRiskFactor,
    CompiledRiskPolicy,
)
from aegis._internal.errors import PolicyValidationError
from aegis._internal.policy_compiler import compile_risk_policy
from aegis._internal.risk_scoring import (
    compute_risk_score,
    RISK_MODE_STRICT,
    RISK_MODE_RISK_SCORED,
    RISK_MODE_WARN_ONLY,
    DEFAULT_RISK_THRESHOLD,
    _evaluate_risk_condition,
)


def _base_invocation():
    return {
        "policy_file": "test.yaml",
        "model_provider": "openai",
        "model_identifier": "gpt-4",
        "role": "planner",
        "input": {"prompt": "test"},
        "output": {"result": "ok"},
        "context": {"session_id": "s1"},
    }


def _base_policy():
    return {
        "policy_version": "1.0",
        "roles": ["planner"],
    }


# ── Mode validation ─────────────────────────────────────────────


def test_invalid_risk_mode_raises():
    from aegis._internal.errors import PolicyValidationError
    with pytest.raises(PolicyValidationError, match="Invalid risk mode"):
        compute_risk_score(
            _base_invocation(), _base_policy(),
            risk_config={"mode": "invalid"},
        )


def test_valid_modes_accepted():
    for mode in (RISK_MODE_STRICT, RISK_MODE_RISK_SCORED, RISK_MODE_WARN_ONLY):
        result = compute_risk_score(
            _base_invocation(), _base_policy(),
            risk_config={"mode": mode},
        )
        assert result.mode == mode


# ── Deterministic scoring ────────────────────────────────────────


def test_deterministic_scoring():
    """Same inputs produce identical scores."""
    config = {
        "mode": "strict",
        "threshold": 0.5,
        "factors": [
            {"name": "f1", "weight": 0.3, "condition": "no_output_schema"},
            {"name": "f2", "weight": 0.2, "condition": "missing_guards"},
        ],
    }
    inv = _base_invocation()
    pol = _base_policy()
    r1 = compute_risk_score(inv, pol, risk_config=config)
    r2 = compute_risk_score(inv, pol, risk_config=config)
    assert r1.score == r2.score
    assert r1.basis == r2.basis
    assert r1.exceeded == r2.exceeded


def test_score_clamped_to_unit():
    """Score is clamped to [0.0, 1.0]."""
    config = {
        "mode": "strict",
        "factors": [
            {"name": "f1", "weight": 0.6, "condition": "no_output_schema"},
            {"name": "f2", "weight": 0.6, "condition": "missing_guards"},
        ],
    }
    result = compute_risk_score(_base_invocation(), _base_policy(), risk_config=config)
    assert result.score <= 1.0


# ── Threshold boundaries ────────────────────────────────────────


def test_score_below_threshold_not_exceeded():
    config = {
        "mode": "strict",
        "threshold": 0.9,
        "factors": [
            {"name": "f1", "weight": 0.1, "condition": "no_output_schema"},
        ],
    }
    result = compute_risk_score(_base_invocation(), _base_policy(), risk_config=config)
    assert not result.exceeded
    assert result.score <= result.threshold


def test_score_above_threshold_exceeded():
    config = {
        "mode": "strict",
        "threshold": 0.1,
        "factors": [
            {"name": "f1", "weight": 0.3, "condition": "no_output_schema"},
            {"name": "f2", "weight": 0.3, "condition": "missing_guards"},
        ],
    }
    result = compute_risk_score(_base_invocation(), _base_policy(), risk_config=config)
    assert result.exceeded
    assert result.score > result.threshold


def test_exact_threshold_is_exceeded():
    """Removing the inclusive threshold boundary must fail this test."""
    config = {
        "mode": "strict",
        "threshold": 0.3,
        "factors": [
            {"name": "f1", "weight": 0.3, "condition": "no_output_schema"},
        ],
    }
    result = compute_risk_score(_base_invocation(), _base_policy(), risk_config=config)
    assert result.exceeded


def test_fixed_critical_ceiling_is_inclusive():
    """A score at 0.90 must exceed even a higher policy threshold."""
    risk = compile_risk_policy(
        {
            "mode": "warn_only",
            "threshold": 1.0,
            "factors": [
                {
                    "name": "f1",
                    "weight": 0.9,
                    "condition": "no_output_schema",
                }
            ],
        }
    )

    result = compute_risk_score(_base_invocation(), _base_policy(), risk_config=risk)

    assert result.exceeded
    assert result.threshold == 1.0


def test_caller_constructed_compiled_policy_cannot_raise_critical_ceiling():
    """The scoring boundary must own the fixed 0.90 critical ceiling."""
    risk = CompiledRiskPolicy(
        mode="warn_only",
        threshold=1.0,
        critical_ceiling=1.0,
        factors=(
            CompiledRiskFactor(
                name="f1",
                weight=0.9,
                condition="no_output_schema",
            ),
        ),
    )

    result = compute_risk_score(
        _base_invocation(),
        _base_policy(),
        risk_config=risk,
    )

    assert result.score == 0.9
    assert result.threshold == 1.0
    assert result.exceeded


# ── Factor conditions ────────────────────────────────────────────


def test_no_output_schema_condition():
    assert _evaluate_risk_condition("no_output_schema", {}, {"roles": ["a"]})
    assert not _evaluate_risk_condition(
        "no_output_schema", {}, {"output_schema": {"type": "object"}}
    )


def test_broad_roles_condition():
    assert _evaluate_risk_condition(
        "broad_roles", {}, {"roles": ["a", "b", "c", "d"]}
    )
    assert not _evaluate_risk_condition(
        "broad_roles", {}, {"roles": ["a", "b"]}
    )


def test_missing_guards_condition():
    assert _evaluate_risk_condition("missing_guards", {}, {})
    assert not _evaluate_risk_condition(
        "missing_guards", {}, {"guards": [{"when": {}, "then": {}}]}
    )


def test_external_model_condition():
    assert _evaluate_risk_condition(
        "external_model", {"model_provider": "openai"}, {}
    )
    assert not _evaluate_risk_condition(
        "external_model", {"model_provider": "internal"}, {}
    )


def test_context_key_is_not_an_implicit_risk_condition():
    """Restoring arbitrary context lookup must fail this closed-set test."""
    with pytest.raises(PolicyValidationError) as exc:
        _evaluate_risk_condition(
            "high_risk", {"context": {"high_risk": True}}, {}
        )

    assert exc.value.code == "RISK_CONDITION_UNKNOWN"


def test_compute_risk_score_consumes_compiled_risk_policy():
    """Removing the authoritative compiled input path must fail this test."""
    risk = compile_risk_policy(
        {
            "mode": "risk_scored",
            "threshold": 0.5,
            "factors": [
                {
                    "name": "f1",
                    "weight": 0.3,
                    "condition": "no_output_schema",
                }
            ],
        }
    )

    result = compute_risk_score(_base_invocation(), _base_policy(), risk_config=risk)

    assert result.score == 0.3
    assert result.threshold == 0.5
    assert result.mode == "risk_scored"


# ── Basis recording ─────────────────────────────────────────────


def test_basis_recorded_in_result():
    config = {
        "mode": "strict",
        "factors": [
            {"name": "f1", "weight": 0.3, "condition": "no_output_schema"},
        ],
    }
    result = compute_risk_score(_base_invocation(), _base_policy(), risk_config=config)
    assert len(result.basis) == 1
    assert result.basis[0]["name"] == "f1"
    assert result.basis[0]["triggered"] is True
    assert result.basis[0]["contribution"] == 0.3


def test_to_dict_serialization():
    config = {
        "mode": "risk_scored",
        "threshold": 0.5,
        "factors": [],
    }
    result = compute_risk_score(_base_invocation(), _base_policy(), risk_config=config)
    d = result.to_dict()
    assert d["score"] == result.score
    assert d["mode"] == "risk_scored"
    assert d["threshold"] == 0.5
    assert isinstance(d["basis"], list)


# ── Default config from policy ───────────────────────────────────


def test_config_from_policy_risk_section():
    policy = {
        "policy_version": "1.0",
        "roles": ["planner"],
        "risk": {
            "mode": "warn_only",
            "threshold": 0.4,
            "factors": [
                {"name": "f1", "weight": 0.5, "condition": "no_output_schema"},
            ],
        },
    }
    result = compute_risk_score(_base_invocation(), policy)
    assert result.mode == "warn_only"
    assert result.threshold == 0.4


def test_no_risk_config_returns_default():
    """Without risk config, uses default threshold."""
    result = compute_risk_score(
        _base_invocation(), _base_policy(),
        risk_config={"mode": "strict"},
    )
    assert result.threshold == DEFAULT_RISK_THRESHOLD


def test_empty_factors_zero_score():
    config = {"mode": "strict", "factors": []}
    result = compute_risk_score(_base_invocation(), _base_policy(), risk_config=config)
    assert result.score == 0.0
    assert not result.exceeded
