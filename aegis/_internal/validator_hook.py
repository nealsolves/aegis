"""
ValidatorHook — typed governance hook contract for workflow steps.

Hooks are evaluated at enforce_step_pre_call() time after invocation-level
governance passes. A DENY or TIMEOUT result fails the step closed.
"""
from __future__ import annotations

import abc
import threading
import time
from dataclasses import dataclass
from typing import Any

from aegis._internal.outcomes import NormalizedOutcome, OutcomeNormalizer

# ---------------------------------------------------------------------------
# Decision constants
# ---------------------------------------------------------------------------

VALIDATOR_ALLOW = "allow"
VALIDATOR_DENY = "deny"
VALIDATOR_WARN = "warn"
VALIDATOR_REVIEW_REQUIRED = "review_required"
VALIDATOR_EXECUTION_FAILURE = "execution_failure"
VALIDATOR_TIMEOUT = "timeout"
_VALIDATOR_INVALID_RESULT = "invalid_result"

_RETRY_ELIGIBLE_DECISIONS = {VALIDATOR_EXECUTION_FAILURE}

# ---------------------------------------------------------------------------
# Envelope and Result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ValidatorHookEnvelope:
    """Versioned, session-bound input to a ValidatorHook.evaluate() call."""

    hook_schema_version: str  # "1.0"
    session_id: str
    step_id: str
    participant_id: str | None
    invocation: dict[str, Any]
    deadline_ms: int
    observed_at: int  # unix milliseconds
    policy_file: str | None = None
    invocation_checksum: str | None = None


@dataclass(frozen=True)
class ValidatorHookResult:
    """Typed, immutable result from a ValidatorHook.evaluate() call."""

    decision: str  # one of VALIDATOR_* constants
    reason_code: str | None
    explanation: str | None
    hook_id: str
    hook_version: str
    attempt: int
    latency_ms: int
    observed_at: int  # unix milliseconds
    stale_result: bool = False
    provenance: str | None = None


def normalize_hook_result(result: object) -> NormalizedOutcome:
    """Convert a final validator-hook result to a closed terminal class."""
    if not isinstance(result, ValidatorHookResult):
        return OutcomeNormalizer.invalid("HOOK_INVALID_RESULT")
    try:
        decision = result.decision
        reason_code = result.reason_code
        if type(decision) is not str:
            return OutcomeNormalizer.invalid("HOOK_INVALID_RESULT")
        if reason_code is not None and type(reason_code) is not str:
            return OutcomeNormalizer.invalid("HOOK_INVALID_RESULT")
    except Exception:  # noqa: BLE001 - untrusted result fields
        return OutcomeNormalizer.invalid("HOOK_INVALID_RESULT")
    if decision == VALIDATOR_ALLOW:
        return OutcomeNormalizer.allow(reason_code or "HOOK_ALLOWED")
    if decision == VALIDATOR_WARN:
        return OutcomeNormalizer.warn(reason_code or "HOOK_WARNING")
    if decision in {VALIDATOR_DENY, VALIDATOR_REVIEW_REQUIRED}:
        return OutcomeNormalizer.deny(reason_code or "HOOK_DENIED")
    if decision == VALIDATOR_TIMEOUT:
        return OutcomeNormalizer.timeout(reason_code or "HOOK_TIMEOUT")
    if decision == VALIDATOR_EXECUTION_FAILURE:
        return OutcomeNormalizer.execution_failure(
            reason_code or "HOOK_EXECUTION_FAILURE"
        )
    if decision == _VALIDATOR_INVALID_RESULT:
        return OutcomeNormalizer.invalid("HOOK_INVALID_RESULT")
    return OutcomeNormalizer.invalid("HOOK_INVALID_DECISION")


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------


class ValidatorHook(abc.ABC):
    """Abstract base for custom workflow validator hooks.

    Subclass this, set hook_id and hook_version, implement evaluate().

    Timeout semantics: if evaluate() does not return within timeout_ms,
    _invoke_hook() returns a TIMEOUT result (fail-closed).

    Retry semantics: on EXECUTION_FAILURE, _invoke_hook() retries up to
    max_retries times. On DENY or TIMEOUT, no retry occurs.

    Class attributes:
        timeout_ms: Per-invocation timeout in milliseconds (class-level
            attribute, not instance).
        max_retries: Max retries on EXECUTION_FAILURE (class-level
            attribute, not instance).
        DENY and REVIEW_REQUIRED decisions are never retried automatically.

    Hook contract: evaluate() must not raise and must not mutate envelope.invocation.

    Thread lifetime warning: once timeout_ms elapses, _invoke_hook() returns a
    TIMEOUT result (fail-closed) and abandons the evaluate() thread. The thread
    continues running as a daemon until it returns naturally or the process exits.
    Implementations must be written to be safe under that condition — they may
    produce side effects or consume resources past the timeout window the caller
    observes.
    """

    hook_id: str
    hook_version: str
    timeout_ms: int = 5000
    max_retries: int = 0

    @abc.abstractmethod
    def evaluate(self, envelope: ValidatorHookEnvelope) -> ValidatorHookResult:
        """Evaluate the hook for a workflow step.

        Must return a ValidatorHookResult. Must not raise — return
        EXECUTION_FAILURE instead.
        """


# ---------------------------------------------------------------------------
# Hook runner with timeout and retry
# ---------------------------------------------------------------------------


def _call_hook_once(
    hook: ValidatorHook,
    envelope: ValidatorHookEnvelope,
    attempt: int,
) -> ValidatorHookResult:
    """Call hook.evaluate() in a daemon thread with timeout_ms enforcement."""
    result_holder: list[object] = []
    exception_holder: list[BaseException] = []

    def _run() -> None:
        try:
            result_holder.append(hook.evaluate(envelope))
        except BaseException as exc:  # noqa: BLE001
            exception_holder.append(exc)

    start_ms = int(time.time() * 1000)
    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(timeout=hook.timeout_ms / 1000.0)
    elapsed_ms = int(time.time() * 1000) - start_ms

    if thread.is_alive():
        return ValidatorHookResult(
            decision=VALIDATOR_TIMEOUT,
            reason_code="HOOK_TIMEOUT",
            explanation=f"Hook {hook.hook_id!r} timed out after {hook.timeout_ms}ms",
            hook_id=hook.hook_id,
            hook_version=hook.hook_version,
            attempt=attempt,
            latency_ms=hook.timeout_ms,
            observed_at=int(time.time() * 1000),
        )

    if exception_holder:
        return ValidatorHookResult(
            decision=VALIDATOR_EXECUTION_FAILURE,
            reason_code="HOOK_EXCEPTION",
            explanation="Hook execution failed",
            hook_id=hook.hook_id,
            hook_version=hook.hook_version,
            attempt=attempt,
            latency_ms=elapsed_ms,
            observed_at=int(time.time() * 1000),
        )

    result = result_holder[0]

    if not _valid_hook_result_shape(result):
        return _invalid_hook_result(hook, attempt, elapsed_ms)

    # Stale-result check: reject results that arrived after the deadline or
    # whose attempt number doesn't match the active attempt.
    # Use TIMEOUT (not EXECUTION_FAILURE) so stale results fail closed — they
    # are not transient errors that warrant retry.
    _absolute_deadline = envelope.observed_at + envelope.deadline_ms
    if result.observed_at > _absolute_deadline or result.attempt != attempt:
        return ValidatorHookResult(
            decision=VALIDATOR_TIMEOUT,
            reason_code="HOOK_STALE_RESULT",
            explanation=(
                f"Hook {hook.hook_id!r} returned a stale result "
                f"(observed_at={result.observed_at}, "
                f"deadline={_absolute_deadline}, attempt={result.attempt} vs {attempt})"
            ),
            hook_id=result.hook_id,
            hook_version=result.hook_version,
            attempt=attempt,
            latency_ms=elapsed_ms,
            observed_at=int(time.time() * 1000),
            stale_result=True,
        )

    return result


def _valid_hook_result_shape(result: object) -> bool:
    """Validate exact field types before stale/retry logic dereferences them."""
    if type(result) is not ValidatorHookResult:
        return False
    return (
        type(result.decision) is str
        and (result.reason_code is None or type(result.reason_code) is str)
        and (result.explanation is None or type(result.explanation) is str)
        and type(result.hook_id) is str
        and type(result.hook_version) is str
        and type(result.attempt) is int
        and type(result.latency_ms) is int
        and type(result.observed_at) is int
        and type(result.stale_result) is bool
        and (result.provenance is None or type(result.provenance) is str)
    )


def _invalid_hook_result(
    hook: ValidatorHook,
    attempt: int,
    latency_ms: int,
) -> ValidatorHookResult:
    hook_id = hook.hook_id if type(hook.hook_id) is str else "unknown-hook"
    hook_version = (
        hook.hook_version if type(hook.hook_version) is str else "unknown"
    )
    return ValidatorHookResult(
        decision=_VALIDATOR_INVALID_RESULT,
        reason_code="HOOK_INVALID_RESULT",
        explanation="Hook returned a malformed result",
        hook_id=hook_id,
        hook_version=hook_version,
        attempt=attempt,
        latency_ms=latency_ms,
        observed_at=int(time.time() * 1000),
    )


def _invoke_hook(
    hook: ValidatorHook,
    envelope: ValidatorHookEnvelope,
) -> ValidatorHookResult:
    """Invoke a hook with timeout and retry semantics.

    Retries up to hook.max_retries times on EXECUTION_FAILURE.
    Returns immediately on any other decision (ALLOW, DENY, WARN, TIMEOUT).
    """
    result = _call_hook_once(hook, envelope, attempt=1)
    for attempt in range(2, hook.max_retries + 2):
        if result.decision not in _RETRY_ELIGIBLE_DECISIONS:
            break
        result = _call_hook_once(hook, envelope, attempt=attempt)
    return result
