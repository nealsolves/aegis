"""Closed truth table for custom gate results."""

from aegis._internal.gates import GateResult, normalize_gate_result
from aegis._internal.outcomes import TerminalClass


def test_false_without_failures_denies():
    outcome = normalize_gate_result(
        "g", GateResult(passed=False, failures=[])
    )
    assert outcome.terminal is TerminalClass.DENY
    assert outcome.reason_code == "CUSTOM_GATE_DENIED"
    assert outcome.failures[0].code == "CUSTOM_GATE_DENIED"


def test_true_with_failures_is_invalid():
    outcome = normalize_gate_result(
        "g",
        GateResult(
            passed=True,
            failures=[{"code": "X", "message": "x", "field": None}],
        ),
    )
    assert outcome.terminal is TerminalClass.INVALID_RESULT
    assert outcome.reason_code == "CUSTOM_GATE_INCONSISTENT_RESULT"


def test_non_gate_result_is_execution_failure():
    outcome = normalize_gate_result("g", True)
    assert outcome.terminal is TerminalClass.EXECUTION_FAILURE
    assert outcome.reason_code == "CUSTOM_GATE_INVALID_RETURN"


def test_true_without_failures_allows():
    outcome = normalize_gate_result(
        "g", GateResult(passed=True, metadata={"checked": True})
    )
    assert outcome.terminal is TerminalClass.ALLOW
    assert outcome.metadata["checked"] is True
