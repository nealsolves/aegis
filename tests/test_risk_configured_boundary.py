"""End-to-end closure for explicitly configured zero-factor risk policies."""

import pytest

from aegis import (
    AEGIS,
    enforce_invocation,
    enforce_invocation_async,
    enforce_post_call,
    enforce_pre_call,
)
from aegis._internal.errors import RiskThresholdError


POLICY = """\
policy_version: "1.0"
roles:
  - planner
pre_conditions:
  required:
    approved:
      type: boolean
risk:
  mode: strict
  threshold: 0.0
  factors: []
"""


@pytest.fixture()
def configured_risk_invocation(tmp_path):
    policy = tmp_path / "zero-factor-risk.yaml"
    policy.write_text(POLICY)
    return {
        "policy_file": str(policy),
        "model_provider": "openai",
        "model_identifier": "gpt-4",
        "role": "planner",
        "input": {"prompt": "test"},
        "output": {"result": "ok"},
        "context": {"approved": True},
    }


def _assert_closed_risk_failure(exc: RiskThresholdError) -> None:
    assert exc.details["reason_code"] == "RISK_THRESHOLD_EXCEEDED"
    assert exc.details["score"] == 0.0
    assert exc.audit_artifact["enforcement_result"] == "FAIL"
    assert exc.audit_artifact["failure_gate"] == "risk_scoring"


def test_module_unified_normalizes_configured_empty_factors(
    configured_risk_invocation,
):
    with pytest.raises(RiskThresholdError) as exc_info:
        enforce_invocation(configured_risk_invocation)
    _assert_closed_risk_failure(exc_info.value)


def test_module_split_normalizes_configured_empty_factors(
    configured_risk_invocation,
):
    pre_call = dict(configured_risk_invocation)
    output = pre_call.pop("output")
    token = enforce_pre_call(pre_call)
    with pytest.raises(RiskThresholdError) as exc_info:
        enforce_post_call(token, output)
    _assert_closed_risk_failure(exc_info.value)


@pytest.mark.asyncio
async def test_async_unified_normalizes_configured_empty_factors(
    configured_risk_invocation,
):
    with pytest.raises(RiskThresholdError) as exc_info:
        await enforce_invocation_async(configured_risk_invocation)
    _assert_closed_risk_failure(exc_info.value)


def test_instance_normalizes_configured_empty_factors(
    configured_risk_invocation,
):
    with pytest.raises(RiskThresholdError) as exc_info:
        AEGIS().enforce(configured_risk_invocation)
    _assert_closed_risk_failure(exc_info.value)


def test_session_normalizes_configured_empty_factors(
    configured_risk_invocation,
):
    governance = AEGIS()
    with governance.open_session(
        policy_file=configured_risk_invocation["policy_file"],
    ) as session:
        pre_call = dict(configured_risk_invocation)
        output = pre_call.pop("output")
        token = session.enforce_step_pre_call(pre_call)
        with pytest.raises(RiskThresholdError) as exc_info:
            session.enforce_step_post_call(token, output)
        _assert_closed_risk_failure(exc_info.value)
        session.cancel()
