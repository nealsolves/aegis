"""Fail-closed dispatch of compiled stateful policy constraints."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import time
import uuid
from collections import Counter
from dataclasses import fields
from typing import Any, Mapping

from aegis._internal.compiled_policy import CompiledPolicy
from aegis._internal.errors import (
    StateClockUncertainError,
    StateProviderCapacityError,
    StateProviderContractError,
    StateProviderIndeterminateError,
    StateProviderModeError,
    StateProviderRequiredError,
    StateProviderUnavailableError,
    StateResultInvalidError,
    StateScopeRequiredError,
    StatefulLimitDeniedError,
    StatefulPreCallRequiredError,
)
from aegis._internal.stateful_models import (
    SlidingWindowAdmitV1,
    StateAddressV1,
    StateExecutionModeV1,
    StateFailureReasonV1,
    StateIndeterminateMayHaveCommitted,
    StateInvalidRequestNoEffect,
    StateOperationFamilyV1,
    StateProviderDescriptorV1,
    StateScopeDimensionNameV1,
    StateScopeV1,
    StateUnavailableNoEffect,
    WindowApplied,
    WindowRejected,
    bind_operation_fingerprint_v1,
    encode_state_address_v1,
    encode_state_operation_v1,
    validate_state_result_v1,
)


_MAX_DISPATCH_ATTEMPTS = 3
MAX_STATEFUL_DECISIONS = 64
_EVIDENCE_FINGERPRINT_DOMAIN = b"aegis-state-evidence-operation-v1\x00"


def snapshot_provider_descriptor(provider: object | None) -> StateProviderDescriptorV1 | None:
    """Validate and detach a provider descriptor exactly once at construction."""
    if provider is None:
        return None
    describe = getattr(provider, "describe", None)
    if not callable(describe):
        raise StateProviderContractError({"reason": "describe_missing"})
    try:
        descriptor = describe()
    except Exception as exc:
        raise StateProviderContractError({"reason": "describe_failed"}) from exc
    if type(descriptor) is not StateProviderDescriptorV1:
        raise StateProviderContractError({"reason": "descriptor_type"})
    try:
        values = {
            field_info.name: getattr(descriptor, field_info.name)
            for field_info in fields(StateProviderDescriptorV1)
        }
        return StateProviderDescriptorV1(**copy.deepcopy(values))
    except (AttributeError, TypeError, ValueError) as exc:
        raise StateProviderContractError(
            {"reason": "descriptor_fields"}
        ) from exc


def reject_unified_stateful_policy(policy: CompiledPolicy) -> None:
    if policy.stateful is not None:
        raise StatefulPreCallRequiredError()


def _attach_decisions(exc: Exception, decisions: list[dict[str, Any]]) -> None:
    setattr(exc, "stateful_decisions", tuple(copy.deepcopy(decisions)))


def _operation_evidence_fingerprint(request_fingerprint: str) -> str:
    return hashlib.sha256(
        _EVIDENCE_FINGERPRINT_DOMAIN + request_fingerprint.encode("ascii")
    ).hexdigest()


def _base_decision(
    *,
    descriptor: StateProviderDescriptorV1,
    policy: CompiledPolicy,
    constraint: Any,
    operation: SlidingWindowAdmitV1,
) -> dict[str, Any]:
    return {
        "evidence_version": 1,
        "provider_contract_version": descriptor.contract_version,
        "provider_id": descriptor.provider_id,
        "consistency_domain": descriptor.consistency_domain.value,
        "durability_domain": descriptor.durability_domain.value,
        "clock_source": descriptor.clock_source.value,
        "policy_state_id": policy.stateful.policy_state_id,
        "constraint_id": constraint.id,
        "policy_digest": policy.policy_digest,
        "tool": constraint.tool,
        "scope_dimensions": ["tenant", "tool"],
        "requested_units": operation.units,
        "limit": constraint.limit,
        "window_ms": constraint.window_ms,
        "operation_fingerprint": _operation_evidence_fingerprint(
            operation.request_fingerprint
        ),
    }


def _finish_decision(
    base: dict[str, Any],
    *,
    outcome: str,
    reason_code: str,
    attempts: int,
    reconciliation_status: str,
    result: object | None = None,
) -> dict[str, Any]:
    decision = {
        **base,
        "outcome": outcome,
        "reason_code": reason_code,
        "attempt_count": attempts,
        "reconciliation_status": reconciliation_status,
        "control_state_changed": bool(
            getattr(result, "control_state_changed", False)
        ),
    }
    for field in (
        "used", "remaining", "effective_limit", "retry_after_ms",
        "state_version", "provider_time_ms", "provider_record_digest",
    ):
        value = getattr(result, field, None)
        if value is not None:
            decision[field] = value
    return decision


def _preflight(
    *,
    policy: CompiledPolicy,
    provider: object | None,
    descriptor: StateProviderDescriptorV1 | None,
    namespace: str | None,
    scope: StateScopeV1 | None,
    mode: StateExecutionModeV1,
) -> tuple[StateProviderDescriptorV1, StateScopeV1]:
    if policy.stateful is None:
        raise AssertionError("stateful preflight requires a stateful policy")
    if provider is None or descriptor is None:
        raise StateProviderRequiredError()
    if type(scope) is not StateScopeV1:
        raise StateScopeRequiredError({"required_dimensions": ["tenant"]})
    if scope.dimension_names != (StateScopeDimensionNameV1.TENANT,):
        raise StateScopeRequiredError({"required_dimensions": ["tenant"]})
    if type(namespace) is not str or not namespace:
        raise StateProviderContractError({"reason": "namespace_missing"})
    if mode not in descriptor.execution_modes:
        raise StateProviderModeError({"required_mode": mode.value})
    if StateOperationFamilyV1.SLIDING_WINDOW not in descriptor.supported_operations:
        raise StateProviderContractError({"reason": "operation_unsupported"})
    method_name = (
        "execute"
        if mode is StateExecutionModeV1.SYNC
        else "execute_async"
    )
    try:
        dispatch = getattr(provider, method_name)
    except Exception as exc:
        raise StateProviderModeError({"required_mode": mode.value}) from exc
    if not callable(dispatch):
        raise StateProviderModeError({"required_mode": mode.value})

    # Validate every non-mutating compatibility condition before the first
    # provider call so a configuration error cannot partially consume state.
    for constraint in policy.stateful.constraints:
        try:
            address = StateAddressV1(
                namespace, policy.stateful.policy_state_id, constraint.id,
                scope.with_tool(constraint.tool),
            )
        except (TypeError, ValueError) as exc:
            raise StateProviderContractError(
                {"reason": "state_address_invalid"}
            ) from exc
        if len(encode_state_address_v1(address)) > descriptor.max_key_bytes:
            raise StateProviderContractError({"reason": "key_too_large"})
        if constraint.limit > descriptor.max_units:
            raise StateProviderContractError({"reason": "units_unsupported"})
        required_retention_ms = (
            constraint.retry_horizon_ms + constraint.provider_timeout_ms
        )
        if required_retention_ms > descriptor.min_idempotency_retention_ms:
            raise StateProviderContractError(
                {"reason": "idempotency_retention_too_short"}
            )
        if descriptor.clock_resolution_ms > constraint.window_ms:
            raise StateProviderContractError(
                {"reason": "clock_resolution_too_coarse"}
            )
    return descriptor, scope


def _operations(
    policy: CompiledPolicy,
    invocation: Mapping[str, Any],
    namespace: str,
    scope: StateScopeV1,
) -> list[tuple[Any, SlidingWindowAdmitV1]]:
    counts = Counter(
        call.get("name")
        for call in (invocation.get("tool_calls") or ())
        if isinstance(call, Mapping)
    )
    operations = []
    for constraint in sorted(policy.stateful.constraints, key=lambda item: item.id):
        units = counts.get(constraint.tool, 0)
        if not units:
            continue
        operation = SlidingWindowAdmitV1(
            operation_id=uuid.uuid4().hex,
            request_fingerprint="",
            address=StateAddressV1(
                namespace,
                policy.stateful.policy_state_id,
                constraint.id,
                scope.with_tool(constraint.tool),
            ),
            timeout_ms=constraint.provider_timeout_ms,
            retry_horizon_ms=constraint.retry_horizon_ms,
            units=units,
            limit=constraint.limit,
            window_ms=constraint.window_ms,
            counted_unit="tool_call",
        )
        operations.append((constraint, bind_operation_fingerprint_v1(operation)))
    return operations


def _validate_operation_sizes(
    operations: list[tuple[Any, SlidingWindowAdmitV1]],
    descriptor: StateProviderDescriptorV1,
) -> None:
    for _, operation in operations:
        if operation.units > descriptor.max_units:
            raise StateProviderContractError({"reason": "units_unsupported"})
        bounded_size = len(encode_state_operation_v1(operation))
        if bounded_size > descriptor.max_operation_bytes:
            raise StateProviderContractError(
                {"reason": "operation_too_large"}
            )


def _interpret(
    result: object,
    *,
    base: dict[str, Any],
    attempts: int,
    reconciliation_status: str,
) -> tuple[dict[str, Any] | None, Exception | None, bool]:
    """Return (decision, terminal error, retryable)."""
    if type(result) is WindowApplied:
        return _finish_decision(
            base, outcome="admitted", reason_code="STATEFUL_ADMITTED",
            attempts=attempts, reconciliation_status=reconciliation_status,
            result=result,
        ), None, False
    if type(result) is WindowRejected:
        decision = _finish_decision(
            base, outcome="denied", reason_code="STATEFUL_LIMIT_DENIED",
            attempts=attempts, reconciliation_status=reconciliation_status,
            result=result,
        )
        return decision, StatefulLimitDeniedError(
            {"constraint_id": base["constraint_id"], "tool": base["tool"]}
        ), False
    if type(result) is StateUnavailableNoEffect:
        if result.reason is StateFailureReasonV1.STALE_RESULT:
            return None, StateResultInvalidError(
                {"reason": "stale_result"}
            ), False
        if result.reason is StateFailureReasonV1.CLOCK_UNCERTAIN:
            return None, StateClockUncertainError(), False
        if result.reason is StateFailureReasonV1.CAPACITY_EXHAUSTED:
            return None, StateProviderCapacityError(), False
        return None, StateProviderUnavailableError(), True
    if type(result) is StateIndeterminateMayHaveCommitted:
        return None, StateProviderIndeterminateError(), True
    if type(result) is StateInvalidRequestNoEffect:
        if result.reason is StateFailureReasonV1.CLOCK_UNCERTAIN:
            return None, StateClockUncertainError(), False
        if result.reason is StateFailureReasonV1.CAPACITY_EXHAUSTED:
            return None, StateProviderCapacityError(), False
        return None, StateResultInvalidError(
            {"reason": result.reason.value}
        ), False
    return None, StateResultInvalidError({"reason": "unknown_result"}), True


def admit_stateful_sync(
    *,
    policy: CompiledPolicy,
    invocation: Mapping[str, Any],
    provider: object | None,
    descriptor: StateProviderDescriptorV1 | None,
    namespace: str | None,
    scope: StateScopeV1 | None,
) -> list[dict[str, Any]]:
    if policy.stateful is None:
        return []
    descriptor, scope = _preflight(
        policy=policy, provider=provider, descriptor=descriptor,
        namespace=namespace, scope=scope, mode=StateExecutionModeV1.SYNC,
    )
    decisions: list[dict[str, Any]] = []
    operations = _operations(policy, invocation, namespace, scope)
    if len(operations) > MAX_STATEFUL_DECISIONS:
        raise StateProviderContractError({"reason": "evidence_capacity"})
    _validate_operation_sizes(operations, descriptor)
    for constraint, operation in operations:
        base = _base_decision(
            descriptor=descriptor, policy=policy, constraint=constraint,
            operation=operation,
        )
        deadline = time.monotonic() + operation.retry_horizon_ms / 1000
        last_error: Exception = StateProviderIndeterminateError()
        for attempt in range(1, _MAX_DISPATCH_ATTEMPTS + 1):
            if time.monotonic() >= deadline:
                horizon_error = StateProviderIndeterminateError(
                    {"reason": "retry_horizon_exhausted"}
                )
                failure = _finish_decision(
                    base,
                    outcome="denied",
                    reason_code=horizon_error.code,
                    attempts=max(1, attempt - 1),
                    reconciliation_status="failed",
                )
                decisions.append(failure)
                _attach_decisions(horizon_error, decisions)
                raise horizon_error
            started = time.monotonic()
            try:
                raw_result = provider.execute(operation)
                result = validate_state_result_v1(operation, descriptor, raw_result)
                finished = time.monotonic()
                late = (finished - started) * 1000 > operation.timeout_ms
                if late or finished >= deadline:
                    decision = None
                    error = StateProviderIndeterminateError()
                    retryable = True
                else:
                    decision, error, retryable = _interpret(
                        result, base=base, attempts=attempt,
                        reconciliation_status=(
                            "reconciled" if attempt > 1 else "not_required"
                        ),
                    )
            except StateResultInvalidError as exc:
                error = exc
                decision, retryable = None, False
            except Exception:
                error = StateProviderIndeterminateError()
                decision, retryable = None, True
            if decision is not None:
                decisions.append(decision)
                if error is not None:
                    _attach_decisions(error, decisions)
                    raise error
                break
            last_error = error or last_error
            if (
                not retryable
                or attempt == _MAX_DISPATCH_ATTEMPTS
                or time.monotonic() >= deadline
            ):
                failure = _finish_decision(
                    base,
                    outcome="denied",
                    reason_code=getattr(
                        last_error, "code", "STATE_PROVIDER_INDETERMINATE"
                    ),
                    attempts=attempt,
                    reconciliation_status=(
                        "failed" if attempt > 1 else "not_required"
                    ),
                )
                decisions.append(failure)
                _attach_decisions(last_error, decisions)
                raise last_error
    return decisions


async def admit_stateful_async(
    *,
    policy: CompiledPolicy,
    invocation: Mapping[str, Any],
    provider: object | None,
    descriptor: StateProviderDescriptorV1 | None,
    namespace: str | None,
    scope: StateScopeV1 | None,
) -> list[dict[str, Any]]:
    if policy.stateful is None:
        return []
    descriptor, scope = _preflight(
        policy=policy, provider=provider, descriptor=descriptor,
        namespace=namespace, scope=scope, mode=StateExecutionModeV1.ASYNC,
    )
    decisions: list[dict[str, Any]] = []
    operations = _operations(policy, invocation, namespace, scope)
    if len(operations) > MAX_STATEFUL_DECISIONS:
        raise StateProviderContractError({"reason": "evidence_capacity"})
    _validate_operation_sizes(operations, descriptor)
    for constraint, operation in operations:
        base = _base_decision(
            descriptor=descriptor, policy=policy, constraint=constraint,
            operation=operation,
        )
        deadline = time.monotonic() + operation.retry_horizon_ms / 1000
        last_error: Exception = StateProviderIndeterminateError()
        for attempt in range(1, _MAX_DISPATCH_ATTEMPTS + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                horizon_error = StateProviderIndeterminateError(
                    {"reason": "retry_horizon_exhausted"}
                )
                failure = _finish_decision(
                    base,
                    outcome="denied",
                    reason_code=horizon_error.code,
                    attempts=max(1, attempt - 1),
                    reconciliation_status="failed",
                )
                decisions.append(failure)
                _attach_decisions(horizon_error, decisions)
                raise horizon_error
            started = time.monotonic()
            try:
                raw_result = await asyncio.wait_for(
                    provider.execute_async(operation),
                    timeout=min(operation.timeout_ms / 1000, remaining),
                )
                result = validate_state_result_v1(operation, descriptor, raw_result)
                finished = time.monotonic()
                late = (finished - started) * 1000 > operation.timeout_ms
                if late or finished >= deadline:
                    decision = None
                    error = StateProviderIndeterminateError()
                    retryable = True
                else:
                    decision, error, retryable = _interpret(
                        result, base=base, attempts=attempt,
                        reconciliation_status=(
                            "reconciled" if attempt > 1 else "not_required"
                        ),
                    )
            except asyncio.CancelledError:
                error = StateProviderIndeterminateError(
                    {"reason": "caller_cancelled"}
                )
                failure = _finish_decision(
                    base,
                    outcome="denied",
                    reason_code=error.code,
                    attempts=attempt,
                    reconciliation_status="failed",
                )
                decisions.append(failure)
                _attach_decisions(error, decisions)
                raise error from None
            except StateResultInvalidError as exc:
                error = exc
                decision, retryable = None, False
            except Exception:
                error = StateProviderIndeterminateError()
                decision, retryable = None, True
            if decision is not None:
                decisions.append(decision)
                if error is not None:
                    _attach_decisions(error, decisions)
                    raise error
                break
            last_error = error or last_error
            if (
                not retryable
                or attempt == _MAX_DISPATCH_ATTEMPTS
                or time.monotonic() >= deadline
            ):
                failure = _finish_decision(
                    base,
                    outcome="denied",
                    reason_code=getattr(
                        last_error, "code", "STATE_PROVIDER_INDETERMINATE"
                    ),
                    attempts=attempt,
                    reconciliation_status=(
                        "failed" if attempt > 1 else "not_required"
                    ),
                )
                decisions.append(failure)
                _attach_decisions(last_error, decisions)
                raise last_error
    return decisions
