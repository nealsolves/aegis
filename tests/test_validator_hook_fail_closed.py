"""Closed outcome tests for validator-hook execution."""

from aegis._internal.outcomes import TerminalClass
from aegis._internal.validator_hook import (
    VALIDATOR_ALLOW,
    VALIDATOR_EXECUTION_FAILURE,
    ValidatorHookResult,
    ValidatorHook,
    ValidatorHookEnvelope,
    _call_hook_once,
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


def test_hook_runner_converts_malformed_return_before_field_access():
    class MalformedHook(ValidatorHook):
        hook_id = "malformed-hook"
        hook_version = "1.0"

        def evaluate(self, envelope):
            return {"decision": "allow"}

    result = _call_hook_once(
        MalformedHook(),
        ValidatorHookEnvelope(
            hook_schema_version="1.0",
            session_id="s-1",
            step_id="step-1",
            participant_id=None,
            invocation={},
            deadline_ms=1000,
            observed_at=1_722_000_000_000,
        ),
        attempt=1,
    )
    outcome = normalize_hook_result(result)
    assert outcome.terminal is TerminalClass.INVALID_RESULT
    assert outcome.reason_code == "HOOK_INVALID_RESULT"


def test_hook_runner_converts_exact_result_with_missing_field():
    class CorruptResultHook(ValidatorHook):
        hook_id = "corrupt-result-hook"
        hook_version = "1.0"

        def evaluate(self, envelope):
            result = ValidatorHookResult(
                decision="allow",
                reason_code=None,
                explanation=None,
                hook_id=self.hook_id,
                hook_version=self.hook_version,
                attempt=1,
                latency_ms=1,
                observed_at=envelope.observed_at,
            )
            object.__delattr__(result, "decision")
            return result

    result = _call_hook_once(
        CorruptResultHook(),
        ValidatorHookEnvelope(
            hook_schema_version="1.0",
            session_id="s-1",
            step_id="step-1",
            participant_id=None,
            invocation={},
            deadline_ms=1000,
            observed_at=1_722_000_000_000,
        ),
        attempt=1,
    )
    outcome = normalize_hook_result(result)
    assert outcome.terminal is TerminalClass.INVALID_RESULT
    assert outcome.reason_code == "HOOK_INVALID_RESULT"


def test_stale_allow_result_never_normalizes_to_continuation():
    result = ValidatorHookResult(
        decision=VALIDATOR_ALLOW,
        reason_code=None,
        explanation=None,
        hook_id="stale-hook",
        hook_version="1.0",
        attempt=1,
        latency_ms=1,
        observed_at=1_722_000_000_000,
        stale_result=True,
    )

    outcome = normalize_hook_result(result)

    assert outcome.terminal is TerminalClass.TIMEOUT
    assert outcome.reason_code == "HOOK_STALE_RESULT"
    assert outcome.allows_continuation is False


def test_hook_runner_converts_explicit_stale_allow_to_timeout():
    class StaleAllowHook(ValidatorHook):
        hook_id = "stale-hook"
        hook_version = "1.0"

        def evaluate(self, envelope):
            return ValidatorHookResult(
                decision=VALIDATOR_ALLOW,
                reason_code=None,
                explanation=None,
                hook_id=self.hook_id,
                hook_version=self.hook_version,
                attempt=1,
                latency_ms=1,
                observed_at=envelope.observed_at,
                stale_result=True,
            )

    result = _call_hook_once(
        StaleAllowHook(),
        ValidatorHookEnvelope(
            hook_schema_version="1.0",
            session_id="s-1",
            step_id="step-1",
            participant_id=None,
            invocation={},
            deadline_ms=1000,
            observed_at=1_722_000_000_000,
        ),
        attempt=1,
    )

    assert result.decision == "timeout"
    assert result.reason_code == "HOOK_STALE_RESULT"
    assert normalize_hook_result(result).allows_continuation is False
