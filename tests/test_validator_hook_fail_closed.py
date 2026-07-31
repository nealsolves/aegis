"""Closed outcome tests for validator-hook execution."""

from aegis._internal.outcomes import TerminalClass
from aegis._internal.validator_hook import (
    VALIDATOR_EXECUTION_FAILURE,
    ValidatorHookResult,
    normalize_hook_result,
)


def test_exhausted_execution_failure_denies():
    result = ValidatorHookResult(
        decision=VALIDATOR_EXECUTION_FAILURE,
        reason_code="HOOK_BACKEND_ERROR",
        explanation="validator unavailable",
        hook_id="test-hook",
        hook_version="1.0",
        attempt=2,
        latency_ms=5,
        observed_at=1_722_000_000_000,
    )
    outcome = normalize_hook_result(result)
    assert outcome.terminal is TerminalClass.EXECUTION_FAILURE
    assert outcome.allows_continuation is False


def test_malformed_hook_result_is_invalid():
    outcome = normalize_hook_result({"decision": "allow"})
    assert outcome.terminal is TerminalClass.INVALID_RESULT


def test_unknown_hook_decision_is_invalid():
    result = ValidatorHookResult(
        decision="unexpected",
        reason_code=None,
        explanation=None,
        hook_id="test-hook",
        hook_version="1.0",
        attempt=1,
        latency_ms=1,
        observed_at=1_722_000_000_000,
    )
    assert normalize_hook_result(result).terminal is TerminalClass.INVALID_RESULT
