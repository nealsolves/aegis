"""
Retry policy enforcement wrapper.

Provides bounded, auditable retry behavior for transient failures.
Opt-in wrapper around enforce_invocation().
"""

from __future__ import annotations

import time
from typing import Any, Mapping, Callable

from aegis._internal.compiled_policy import CompiledRetryPolicy
from aegis._internal.enforcement import (
    AEGIS,
    _PolicyAuthority,
    _module_policy_loader_for_retry,
    _policy_authority_scope,
    enforce_invocation,
)
from aegis._internal.errors import SchemaValidationError, AIGCError
from aegis._internal.policy_loader import (
    PolicyLoaderBase,
    _bind_policy_authority,
    load_resolve_compile_policy,
)


class RetryExhaustedError(AIGCError):
    """Raised when all retry attempts fail."""

    def __init__(self, message: str, *, attempts: int, last_error: Exception):
        super().__init__(
            message,
            code="RETRY_EXHAUSTED",
            details={
                "attempts": attempts,
                "last_error": str(last_error),
                "last_error_type": type(last_error).__name__,
            },
        )
        self.last_error = last_error


_UNINFERABLE = object()


def _infer_enforcement_loader(
    enforcement_fn: Callable[[Mapping[str, Any]], dict[str, Any]],
) -> PolicyLoaderBase | None | object:
    if enforcement_fn is enforce_invocation:
        return _module_policy_loader_for_retry()
    owner = getattr(enforcement_fn, "__self__", None)
    if isinstance(owner, AEGIS):
        return owner._policy_loader
    return _UNINFERABLE


def _retry_policy_authority(
    invocation: Mapping[str, Any],
    *,
    enforcement_fn: Callable[[Mapping[str, Any]], dict[str, Any]],
    policy_loader: PolicyLoaderBase | None,
) -> _PolicyAuthority:
    policy_ref = str(invocation["policy_file"])
    inferred = _infer_enforcement_loader(enforcement_fn)
    if inferred is _UNINFERABLE:
        if policy_loader is None:
            raise ValueError(
                "policy_loader is required when enforcement authority "
                "cannot be inferred"
            )
        return _PolicyAuthority(
            invocation,
            policy_ref,
            policy_ref,
            policy_loader,
        )
    if isinstance(inferred, PolicyLoaderBase):
        if policy_loader is not None and policy_loader is not inferred:
            raise ValueError(
                "policy_loader does not match enforcement authority"
            )
        return _PolicyAuthority(
            invocation,
            policy_ref,
            policy_ref,
            inferred,
        )
    if policy_loader is not None:
        return _PolicyAuthority(
            invocation,
            policy_ref,
            policy_ref,
            policy_loader,
        )
    bound_ref, implicit_loader = _bind_policy_authority(policy_ref, None)
    return _PolicyAuthority(
        invocation,
        policy_ref,
        bound_ref,
        implicit_loader,
    )


def _execute_retry_loop(
    invocation: Mapping[str, Any],
    *,
    enforcement_fn: Callable[[Mapping[str, Any]], dict[str, Any]],
    retry_policy: CompiledRetryPolicy | None,
) -> dict[str, Any]:
    if not retry_policy:
        return enforcement_fn(invocation)

    max_retries = retry_policy.max_retries
    backoff_ms = retry_policy.backoff_ms

    last_error: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            return enforcement_fn(invocation)

        except SchemaValidationError as exc:
            # Retryable error
            last_error = exc

            # Check if more retries available
            if attempt < max_retries:
                # Calculate backoff
                sleep_ms = backoff_ms * (attempt + 1)
                time.sleep(sleep_ms / 1000.0)
                # Retry loop continues
            else:
                # Out of retries
                raise RetryExhaustedError(
                    f"Retry exhausted after {attempt + 1} attempts",
                    attempts=attempt + 1,
                    last_error=exc,
                ) from exc

        except AIGCError:
            # Non-retryable governance error - fail immediately
            raise

    # Should never reach here, but satisfy type checker
    if last_error:  # pragma: no cover
        raise RetryExhaustedError(  # pragma: no cover
            f"Retry exhausted after {max_retries + 1} attempts",
            attempts=max_retries + 1,
            last_error=last_error,
        ) from last_error

    return enforcement_fn(invocation)  # pragma: no cover


def with_retry(
    invocation: Mapping[str, Any],
    *,
    enforcement_fn: Callable[
        [Mapping[str, Any]],
        dict[str, Any],
    ] = enforce_invocation,
    policy_loader: PolicyLoaderBase | None = None,
) -> dict[str, Any]:
    """Execute enforcement with one attested authority across all attempts."""
    if policy_loader is not None and not isinstance(
        policy_loader,
        PolicyLoaderBase,
    ):
        raise TypeError("policy_loader must be a PolicyLoaderBase")
    authority = _retry_policy_authority(
        invocation,
        enforcement_fn=enforcement_fn,
        policy_loader=policy_loader,
    )
    with _policy_authority_scope(authority):
        compiled_policy = load_resolve_compile_policy(
            authority.bound_policy_ref,
            loader=authority.loader,
        )
        return _execute_retry_loop(
            invocation,
            enforcement_fn=enforcement_fn,
            retry_policy=compiled_policy.retry,
        )
