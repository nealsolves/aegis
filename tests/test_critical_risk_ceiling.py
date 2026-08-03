"""Closed outcomes for policy thresholds and the fixed critical ceiling."""

import pytest

from aegis._internal.outcomes import TerminalClass
from aegis._internal.risk_scoring import RiskScore, normalize_risk_result


@pytest.mark.parametrize("mode", ["strict", "risk_scored", "warn_only"])
def test_critical_score_blocks_in_every_mode(mode):
    score = RiskScore(score=0.90, threshold=0.99, mode=mode, basis=[])
    outcome = normalize_risk_result(score)
    assert outcome.terminal is TerminalClass.DENY
    assert outcome.reason_code == "RISK_CRITICAL_CEILING"


@pytest.mark.parametrize("mode", ["strict", "risk_scored", "warn_only"])
def test_score_equal_to_policy_threshold_is_exceeded(mode):
    score = RiskScore(score=0.75, threshold=0.75, mode=mode, basis=[])
    assert score.exceeded is True
