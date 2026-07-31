"""
Risk scoring engine for AEGIS governance enforcement.

Provides deterministic risk scoring with three modes:
- strict: threshold breach fails closed (raises RiskThresholdError)
- risk_scored: score recorded in audit artifact without blocking
- warn_only: warning logged and recorded without blocking

Risk scores are computed from policy-defined risk factors and
recorded in audit artifact metadata for compliance evidence.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Mapping

from aegis._internal.compiled_policy import (
    CompiledPolicy,
    CompiledRiskFactor,
    CompiledRiskPolicy,
)
from aegis._internal.errors import PolicyValidationError
from aegis._internal.outcomes import NormalizedOutcome, OutcomeNormalizer
from aegis._internal.policy_compiler import (
    CRITICAL_RISK_CEILING,
    compile_risk_policy,
)

logger = logging.getLogger("aegis.risk_scoring")

# Supported risk modes
RISK_MODE_STRICT = "strict"
RISK_MODE_RISK_SCORED = "risk_scored"
RISK_MODE_WARN_ONLY = "warn_only"
VALID_RISK_MODES = (RISK_MODE_STRICT, RISK_MODE_RISK_SCORED, RISK_MODE_WARN_ONLY)

# Default threshold for strict/risk_scored modes
DEFAULT_RISK_THRESHOLD = 0.7


@dataclass(frozen=True, slots=True)
class _RiskPolicyFacts:
    """Minimal compatibility projection for the public scoring helper."""

    roles: tuple[str, ...]
    tools: tuple[object, ...]
    preconditions: tuple[object, ...]
    guards: tuple[object, ...]
    output_validator: object | None


def _compatibility_risk_facts(raw_policy: Mapping[str, Any]) -> _RiskPolicyFacts:
    raw_tools = raw_policy.get("tools") or {}
    raw_preconditions = raw_policy.get("pre_conditions") or {}
    return _RiskPolicyFacts(
        roles=tuple(raw_policy.get("roles") or ()),
        tools=tuple(raw_tools.get("allowed_tools") or ()),
        preconditions=tuple(raw_preconditions.get("required") or ()),
        guards=tuple(raw_policy.get("guards") or ()),
        output_validator=(
            object() if raw_policy.get("output_schema") is not None else None
        ),
    )


class RiskScore:
    """Immutable risk score result with scoring basis evidence."""

    __slots__ = (
        "score",
        "threshold",
        "mode",
        "basis",
        "exceeded",
        "_critical_ceiling",
    )

    def __init__(
        self,
        score: float,
        threshold: float,
        mode: str,
        basis: list[dict[str, Any]],
        critical_ceiling: float = 0.90,
    ) -> None:
        self.score = score
        self.threshold = threshold
        self.mode = mode
        self.basis = basis
        self._critical_ceiling = critical_ceiling
        self.exceeded = score >= threshold

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for audit artifact metadata."""
        return {
            "score": self.score,
            "threshold": self.threshold,
            "mode": self.mode,
            "basis": self.basis,
            "exceeded": self.exceeded,
        }


def normalize_risk_result(score: RiskScore) -> NormalizedOutcome:
    """Convert a risk score to the sole authorization decision for risk."""
    if not isinstance(score, RiskScore):
        return OutcomeNormalizer.invalid("RISK_INVALID_RESULT")
    if score.score >= CRITICAL_RISK_CEILING:
        return OutcomeNormalizer.deny("RISK_CRITICAL_CEILING")
    if score.mode not in VALID_RISK_MODES:
        return OutcomeNormalizer.invalid("RISK_INVALID_MODE")
    if score.mode == RISK_MODE_STRICT and score.exceeded:
        return OutcomeNormalizer.deny("RISK_THRESHOLD_EXCEEDED")
    if score.exceeded:
        return OutcomeNormalizer.warn("RISK_THRESHOLD_WARNING")
    return OutcomeNormalizer.allow("RISK_ACCEPTED")


def _compute_factor_score(
    factor: CompiledRiskFactor,
    invocation: Mapping[str, Any],
    policy: CompiledPolicy | _RiskPolicyFacts,
) -> dict[str, Any]:
    """Compute score contribution for a single risk factor.

    Each factor has:
      - name: identifier
      - weight: 0.0-1.0 contribution weight
      - condition: what triggers this factor

    Returns a basis entry with name, weight, triggered, contribution.
    """
    name = factor.name
    weight = factor.weight
    condition = factor.condition

    triggered = _evaluate_risk_condition(condition, invocation, policy)
    contribution = weight if triggered else 0.0

    return {
        "name": name,
        "weight": weight,
        "triggered": triggered,
        "contribution": contribution,
    }


def _evaluate_risk_condition(
    condition: str,
    invocation: Mapping[str, Any],
    policy: CompiledPolicy | _RiskPolicyFacts | Mapping[str, Any],
) -> bool:
    """Evaluate a risk condition deterministically.

    Supported conditions:
      - "no_output_schema": true if policy lacks output_schema
      - "broad_roles": true if policy has >3 roles
      - "no_preconditions": true if policy lacks pre_conditions.required
      - "high_tool_count": true if >5 tools allowed
      - "missing_guards": true if policy lacks guards
      - "external_model": true if model_provider is not "internal"
    """
    if isinstance(policy, Mapping):
        policy = _compatibility_risk_facts(policy)
    if condition == "no_output_schema":
        return policy.output_validator is None
    if condition == "broad_roles":
        return len(policy.roles) > 3
    if condition == "no_preconditions":
        return not policy.preconditions
    if condition == "high_tool_count":
        return len(policy.tools) > 5
    if condition == "missing_guards":
        return not policy.guards
    if condition == "external_model":
        return invocation.get("model_provider", "") != "internal"
    raise PolicyValidationError(
        f"Unknown risk condition: {condition!r}",
        code="RISK_CONDITION_UNKNOWN",
        details={"condition": condition},
    )


def compute_risk_score(
    invocation: Mapping[str, Any],
    policy: CompiledPolicy | Mapping[str, Any],
    *,
    risk_config: CompiledRiskPolicy | Mapping[str, Any] | None = None,
) -> RiskScore:
    """Compute a deterministic risk score for an invocation.

    :param invocation: The invocation being enforced
    :param policy: The loaded policy
    :param risk_config: Risk configuration from policy or runtime:
        - mode: "strict" | "risk_scored" | "warn_only"
        - threshold: float (default 0.7)
        - factors: list of {name, weight, condition}
    :return: RiskScore with score, threshold, mode, basis
    """
    if not isinstance(policy, CompiledPolicy):
        raw_policy = policy
        compiled_policy = _compatibility_risk_facts(policy)
        if risk_config is None:
            risk_config = raw_policy.get("risk", {})
        if isinstance(risk_config, CompiledRiskPolicy):
            compiled = risk_config
        else:
            compatible = dict(risk_config)
            compatible.setdefault("threshold", DEFAULT_RISK_THRESHOLD)
            compiled = compile_risk_policy(compatible)
        return _compute_risk_score_from_facts(
            invocation,
            compiled_policy,
            compiled,
        )

    if risk_config is None:
        risk_config = policy.risk
    if not isinstance(risk_config, CompiledRiskPolicy):
        compatible = dict(risk_config)
        compatible.setdefault("threshold", DEFAULT_RISK_THRESHOLD)
        risk_config = compile_risk_policy(compatible)
    return compute_compiled_risk_score(
        invocation,
        policy,
        risk_config=risk_config,
    )


def compute_compiled_risk_score(
    invocation: Mapping[str, Any],
    policy: CompiledPolicy,
    *,
    risk_config: CompiledRiskPolicy,
) -> RiskScore:
    """Score only compiler-owned policy and risk values for enforcement."""
    return _compute_risk_score_from_facts(invocation, policy, risk_config)


def _compute_risk_score_from_facts(
    invocation: Mapping[str, Any],
    compiled_policy: CompiledPolicy | _RiskPolicyFacts,
    compiled: CompiledRiskPolicy,
) -> RiskScore:
    """Shared scoring arithmetic after authority projection."""

    mode = compiled.mode
    basis: list[dict[str, Any]] = []
    total_score = 0.0

    for factor in compiled.factors:
        entry = _compute_factor_score(factor, invocation, compiled_policy)
        basis.append(entry)
        total_score += entry["contribution"]

    # Clamp score to [0.0, 1.0]
    total_score = max(0.0, min(1.0, total_score))

    result = RiskScore(
        score=total_score,
        threshold=compiled.threshold,
        mode=mode,
        basis=basis,
        critical_ceiling=CRITICAL_RISK_CEILING,
    )

    logger.debug(
        "Risk score computed: %.3f (threshold=%.3f, mode=%s, exceeded=%s)",
        result.score,
        result.threshold,
        result.mode,
        result.exceeded,
    )

    return result
