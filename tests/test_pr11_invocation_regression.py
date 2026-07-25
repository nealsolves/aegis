"""PR-11 invocation-governance regression tests."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from aegis import (
    AEGIS,
    CallbackAuditSink,
    GovernanceViolationError,
    PreconditionError,
    RiskThresholdError,
    SchemaValidationError,
    ToolConstraintViolationError,
)


POLICY = "tests/golden_replays/golden_policy_v1.yaml"
RISK_STRICT = "tests/golden_replays/policy_with_risk.yaml"
RISK_SCORED = "tests/golden_replays/policy_with_risk_scored.yaml"
RISK_WARN = "tests/golden_replays/policy_with_risk_warn.yaml"


def _invocation(policy_file: str = POLICY) -> dict:
    return {
        "policy_file": policy_file,
        "model_provider": "openai",
        "model_identifier": "gpt-4",
        "role": "planner",
        "input": {"query": "test"},
        "output": {"result": "answer", "confidence": 0.95},
        "context": {"role_declared": True, "schema_exists": True},
    }


def test_enforce_invocation_pass_emits_one_artifact():
    artifacts: list[dict] = []
    aegis = AEGIS(sink=CallbackAuditSink(artifacts.append))

    artifact = aegis.enforce(_invocation())

    assert artifact["enforcement_result"] == "PASS"
    assert len(artifacts) == 1
    assert artifacts[0]["enforcement_result"] == "PASS"


@pytest.mark.parametrize(
    ("mutator", "expected_error", "failure_gate"),
    [
        (lambda inv: inv.update({"role": "intruder"}), GovernanceViolationError, "role_validation"),
        (lambda inv: inv["context"].pop("schema_exists"), PreconditionError, "precondition_validation"),
        (lambda inv: inv["context"].update({"schema_exists": "yes"}), PreconditionError, "precondition_validation"),
        (lambda inv: inv.update({"output": {"result": "missing confidence"}}), SchemaValidationError, "schema_validation"),
    ],
)
def test_core_failure_paths_fail_closed_with_typed_artifacts(
    mutator, expected_error, failure_gate
):
    artifacts: list[dict] = []
    inv = _invocation()
    mutator(inv)
    aegis = AEGIS(sink=CallbackAuditSink(artifacts.append))

    with pytest.raises(expected_error) as exc_info:
        aegis.enforce(inv)

    artifact = exc_info.value.audit_artifact
    assert artifact["enforcement_result"] == "FAIL"
    assert artifact["failure_gate"] == failure_gate
    assert artifact["failures"][0]["code"] == type(exc_info.value).__name__
    assert len(artifacts) == 1


def test_tool_constraint_violation_fails_closed(tmp_path: Path):
    policy = tmp_path / "tool_policy.yaml"
    policy.write_text(
        """\
policy_version: "1.0"
roles: [planner]
pre_conditions:
  required:
    role_declared:
      type: boolean
output_schema:
  type: object
  required: [result]
  properties:
    result: {type: string}
tools:
  allowed_tools:
    - name: search
      max_calls: 1
""",
        encoding="utf-8",
    )
    inv = _invocation(str(policy))
    inv["output"] = {"result": "ok"}
    inv["context"] = {"role_declared": True}
    inv["tool_calls"] = [{"name": "search"}, {"name": "search"}]

    with pytest.raises(ToolConstraintViolationError) as exc_info:
        AEGIS().enforce(inv)

    assert exc_info.value.audit_artifact["failure_gate"] == "tool_validation"


@pytest.mark.parametrize(
    ("policy_file", "raises"),
    [(RISK_STRICT, True), (RISK_SCORED, False), (RISK_WARN, False)],
)
def test_risk_modes_preserve_strict_and_nonblocking_semantics(policy_file, raises):
    inv = _invocation(policy_file)
    inv["input"] = {"prompt": "generate report"}
    inv["output"] = {"summary": "report content"}
    inv["context"] = {"session_id": "risk-regression"}
    artifacts: list[dict] = []
    aegis = AEGIS(sink=CallbackAuditSink(artifacts.append))

    if raises:
        with pytest.raises(RiskThresholdError) as exc_info:
            aegis.enforce(copy.deepcopy(inv))
        artifact = exc_info.value.audit_artifact
        assert artifact["failure_gate"] == "risk_scoring"
    else:
        artifact = aegis.enforce(copy.deepcopy(inv))
        assert artifact["enforcement_result"] == "PASS"
        assert artifact["metadata"]["risk_scoring"]["exceeded"] is True
    assert len(artifacts) == 1
    score = artifact["risk_score"] or artifact["metadata"]["risk_scoring"]["score"]
    assert score is not None


def test_audit_checksum_determinism_for_same_invocation():
    first = AEGIS().enforce(_invocation())
    second = AEGIS().enforce(_invocation())

    stable_fields = [
        "policy_file",
        "policy_version",
        "model_provider",
        "model_identifier",
        "role",
        "enforcement_result",
        "input_checksum",
        "output_checksum",
    ]
    assert {field: first[field] for field in stable_fields} == {
        field: second[field] for field in stable_fields
    }
