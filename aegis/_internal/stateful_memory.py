"""Bounded, instance-local reference implementation of state provider v1."""

from __future__ import annotations

import hmac
import asyncio
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from aegis._internal.canonicalization import SAFE_INTEGER_MAX
from aegis._internal.stateful_models import (
    CounterApplied,
    CounterIncrementV1,
    QuotaApplied,
    QuotaConsumeV1,
    QuotaRejected,
    ReplayClaimV1,
    ReplayClaimed,
    ReplayDuplicate,
    SlidingWindowAdmitV1,
    StateClockSourceV1,
    StateConsistencyDomainV1,
    StateDurabilityDomainV1,
    StateExecutionModeV1,
    StateFailureReasonV1,
    StateInvalidRequestNoEffect,
    StateOperationFamilyV1,
    StateOperationResultV1,
    StateOperationV1,
    StateProviderClaimV1,
    StateProviderDescriptorV1,
    StateScopeDimensionNameV1,
    StateUnavailableNoEffect,
    WindowApplied,
    WindowRejected,
    encode_state_address_v1,
    operation_fingerprint_v1,
    validate_state_operation_v1,
)


@dataclass(slots=True)
class _ControlState:
    family: StateOperationFamilyV1
    scope_shape: tuple[StateScopeDimensionNameV1, ...]
    counted_unit: str
    fixed_duration_ms: int | None
    strictest_limit: int | None
    value: int = 0
    state_version: int = 0
    last_clock_ms: int | None = None
    events: list[tuple[int, int]] = field(default_factory=list)
    claims: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _IdempotencyRecord:
    request_fingerprint: str
    result: StateOperationResultV1
    first_receipt_ms: int
    retention_ms: int | None


class InMemoryStatefulPolicyProvider:
    """Correctness-oriented process-local provider with bounded storage.

    Sharing one instance shares state across callers in that process. Separate
    instances and process restarts do not share or retain state.
    """

    def __init__(
        self,
        clock_ms: Callable[[], int] | None = None,
        *,
        max_records: int = 10_000,
        max_idempotency_records: int = 50_000,
        max_units: int = SAFE_INTEGER_MAX,
    ) -> None:
        if clock_ms is not None and not callable(clock_ms):
            raise TypeError("clock_ms must be callable")
        if type(max_records) is not int or max_records < 1:
            raise ValueError("max_records must be a positive integer")
        if type(max_idempotency_records) is not int or max_idempotency_records < 1:
            raise ValueError("max_idempotency_records must be a positive integer")
        if type(max_units) is not int or max_units < 1:
            raise ValueError("max_units must be a positive integer")
        self._clock_ms = clock_ms or (lambda: time.monotonic_ns() // 1_000_000)
        self._max_records = max_records
        self._max_idempotency_records = max_idempotency_records
        self._lock = threading.RLock()
        self._controls: dict[bytes, _ControlState] = {}
        self._idempotency: dict[str, _IdempotencyRecord] = {}
        self._last_clock_ms: int | None = None
        self._descriptor = StateProviderDescriptorV1(
            provider_id="aegis-in-memory",
            supported_operations=frozenset(StateOperationFamilyV1),
            execution_modes=frozenset(
                {StateExecutionModeV1.SYNC, StateExecutionModeV1.ASYNC}
            ),
            consistency_domain=StateConsistencyDomainV1.INSTANCE,
            durability_domain=StateDurabilityDomainV1.NONE,
            clock_source=StateClockSourceV1.MONOTONIC,
            clock_id="process-monotonic",
            clock_resolution_ms=1,
            min_idempotency_retention_ms=60_000,
            max_key_bytes=4096,
            max_operation_bytes=16_384,
            max_units=max_units,
            max_records=max_records,
        )
        self._claim = StateProviderClaimV1.from_descriptor(self._descriptor)

    def describe(self) -> StateProviderDescriptorV1:
        return self._descriptor

    def _failure(
        self,
        operation: StateOperationV1,
        reason: StateFailureReasonV1,
        *,
        unavailable: bool = False,
    ) -> StateOperationResultV1:
        result_type = StateUnavailableNoEffect if unavailable else StateInvalidRequestNoEffect
        return result_type(
            operation_id=operation.operation_id,
            request_fingerprint=operation.request_fingerprint,
            provider_claim=self._claim,
            operation_family=operation.family,
            reason=reason,
        )

    def _state_record_count(self) -> int:
        return len(self._controls) + sum(
            len(control.events) + len(control.claims)
            for control in self._controls.values()
        )

    def _sample_clock(self) -> int:
        now = self._clock_ms()
        if type(now) is not int or not 0 <= now <= SAFE_INTEGER_MAX:
            raise ValueError("clock is outside the provider time domain")
        return now

    def _collect_expired_idempotency(self, now_ms: int) -> None:
        self._idempotency = {
            operation_id: record
            for operation_id, record in self._idempotency.items()
            if (
                record.retention_ms is None
                or now_ms - record.first_receipt_ms <= record.retention_ms
            )
        }

    def _store_idempotency(
        self,
        operation: StateOperationV1,
        request_fingerprint: str,
        result: StateOperationResultV1,
        first_receipt_ms: int,
    ) -> None:
        requested_retention = operation.retry_horizon_ms + operation.timeout_ms
        semantic_retention: int | None
        if type(operation) in (CounterIncrementV1, QuotaConsumeV1):
            semantic_retention = None
        elif type(operation) is ReplayClaimV1:
            semantic_retention = operation.ttl_ms
        else:
            assert type(operation) is SlidingWindowAdmitV1
            semantic_retention = operation.window_ms
        self._idempotency[operation.operation_id] = _IdempotencyRecord(
            request_fingerprint=request_fingerprint,
            result=result,
            first_receipt_ms=first_receipt_ms,
            retention_ms=(
                None
                if semantic_retention is None
                else max(
                    self._descriptor.min_idempotency_retention_ms,
                    requested_retention,
                    semantic_retention,
                )
            ),
        )

    @staticmethod
    def _configuration(
        operation: StateOperationV1,
    ) -> tuple[str, int | None, int | None]:
        if type(operation) is CounterIncrementV1:
            return operation.counted_unit, None, None
        if type(operation) is QuotaConsumeV1:
            return operation.counted_unit, None, operation.limit
        if type(operation) is ReplayClaimV1:
            return "claim", operation.ttl_ms, None
        if type(operation) is SlidingWindowAdmitV1:
            return operation.counted_unit, operation.window_ms, operation.limit
        raise TypeError("unsupported operation")

    @staticmethod
    def _configuration_matches(
        control: _ControlState,
        operation: StateOperationV1,
        counted_unit: str,
        fixed_duration_ms: int | None,
    ) -> bool:
        return (
            control.family is operation.family
            and control.scope_shape == operation.address.scope.dimension_names
            and control.counted_unit == counted_unit
            and control.fixed_duration_ms == fixed_duration_ms
        )

    @staticmethod
    def _collect_expired(control: _ControlState, now_ms: int) -> None:
        if control.family is StateOperationFamilyV1.REPLAY_TTL:
            control.claims = {
                key: expiry
                for key, expiry in control.claims.items()
                if now_ms < expiry
            }
        elif control.family is StateOperationFamilyV1.SLIDING_WINDOW:
            assert control.fixed_duration_ms is not None
            lower_bound = now_ms - control.fixed_duration_ms
            control.events = [
                event for event in control.events if event[0] > lower_bound
            ]

    def execute(self, operation: StateOperationV1) -> StateOperationResultV1:
        if type(operation) not in (
            CounterIncrementV1,
            QuotaConsumeV1,
            ReplayClaimV1,
            SlidingWindowAdmitV1,
        ):
            raise TypeError("operation must be an exact version-1 operation")
        receipt_started = time.monotonic()
        try:
            operation = validate_state_operation_v1(operation)
        except (AttributeError, TypeError, ValueError):
            return self._failure(operation, StateFailureReasonV1.INVALID_OPERATION)
        deadline = receipt_started + operation.timeout_ms / 1000

        expected_fingerprint = operation_fingerprint_v1(operation)
        if not hmac.compare_digest(operation.request_fingerprint, expected_fingerprint):
            return self._failure(operation, StateFailureReasonV1.FINGERPRINT_MISMATCH)
        if len(encode_state_address_v1(operation.address)) > self._descriptor.max_key_bytes:
            return self._failure(operation, StateFailureReasonV1.INVALID_OPERATION)
        units = getattr(operation, "units", getattr(operation, "increment", 1))
        if units > self._descriptor.max_units:
            return self._failure(operation, StateFailureReasonV1.INVALID_OPERATION)
        if time.monotonic() >= deadline:
            return self._failure(
                operation,
                StateFailureReasonV1.TIMEOUT,
                unavailable=True,
            )

        with self._lock:
            if time.monotonic() >= deadline:
                return self._failure(
                    operation,
                    StateFailureReasonV1.TIMEOUT,
                    unavailable=True,
                )
            prior = self._idempotency.get(operation.operation_id)
            if prior is not None:
                if hmac.compare_digest(
                    prior.request_fingerprint, expected_fingerprint
                ):
                    return prior.result
                return self._failure(operation, StateFailureReasonV1.OPERATION_ID_CONFLICT)
            try:
                now_ms = self._sample_clock()
            except Exception:
                return self._failure(
                    operation,
                    StateFailureReasonV1.CLOCK_UNCERTAIN,
                    unavailable=True,
                )
            if time.monotonic() >= deadline:
                return self._failure(
                    operation,
                    StateFailureReasonV1.TIMEOUT,
                    unavailable=True,
                )
            if self._last_clock_ms is not None and now_ms < self._last_clock_ms:
                return self._failure(
                    operation,
                    StateFailureReasonV1.CLOCK_UNCERTAIN,
                    unavailable=True,
                )
            self._last_clock_ms = now_ms
            self._collect_expired_idempotency(now_ms)
            if len(self._idempotency) >= self._max_idempotency_records:
                return self._failure(
                    operation,
                    StateFailureReasonV1.CAPACITY_EXHAUSTED,
                    unavailable=True,
                )

            key = encode_state_address_v1(operation.address)
            control = self._controls.get(key)
            counted_unit, fixed_duration_ms, requested_limit = self._configuration(operation)
            if control is not None and not self._configuration_matches(
                control, operation, counted_unit, fixed_duration_ms
            ):
                result = self._failure(
                    operation,
                    StateFailureReasonV1.CONFIGURATION_CONFLICT,
                )
                self._store_idempotency(
                    operation, expected_fingerprint, result, now_ms
                )
                return result

            needs_clock = operation.family in (
                StateOperationFamilyV1.REPLAY_TTL,
                StateOperationFamilyV1.SLIDING_WINDOW,
            )
            if needs_clock:
                if control is not None and (
                    control.last_clock_ms is not None
                    and now_ms < control.last_clock_ms
                ):
                    return self._failure(
                        operation,
                        StateFailureReasonV1.CLOCK_UNCERTAIN,
                        unavailable=True,
                    )
                if control is not None:
                    self._collect_expired(control, now_ms)

            if (
                type(operation) is ReplayClaimV1
                and now_ms is not None
                and now_ms > SAFE_INTEGER_MAX - operation.ttl_ms
            ):
                result = self._failure(
                    operation,
                    StateFailureReasonV1.OVERFLOW,
                )
                self._store_idempotency(
                    operation, expected_fingerprint, result, now_ms
                )
                return result

            first_binding = control is None
            effective_limit = requested_limit
            tightening = False
            if control is not None and requested_limit is not None:
                assert control.strictest_limit is not None
                effective_limit = min(control.strictest_limit, requested_limit)
                tightening = effective_limit < control.strictest_limit

            mutation_records = 0
            will_consume = False
            if type(operation) is CounterIncrementV1:
                will_consume = (
                    control is None
                    or control.value <= SAFE_INTEGER_MAX - operation.increment
                )
            elif type(operation) is QuotaConsumeV1:
                used = 0 if control is None else control.value
                assert effective_limit is not None
                will_consume = used + operation.units <= effective_limit
            elif type(operation) is ReplayClaimV1:
                present = control is not None and operation.claim_key in control.claims
                will_consume = not present
                mutation_records = 1 if will_consume else 0
            elif type(operation) is SlidingWindowAdmitV1:
                used = 0 if control is None else sum(units for _, units in control.events)
                assert effective_limit is not None
                will_consume = used + operation.units <= effective_limit
                mutation_records = 1 if will_consume else 0

            binding_records = 1 if first_binding else 0
            if self._state_record_count() + binding_records + mutation_records > self._max_records:
                return self._failure(
                    operation,
                    StateFailureReasonV1.CAPACITY_EXHAUSTED,
                    unavailable=True,
                )

            if control is None:
                control = _ControlState(
                    family=operation.family,
                    scope_shape=operation.address.scope.dimension_names,
                    counted_unit=counted_unit,
                    fixed_duration_ms=fixed_duration_ms,
                    strictest_limit=requested_limit,
                    last_clock_ms=now_ms,
                )
                self._controls[key] = control
            elif now_ms is not None:
                control.last_clock_ms = now_ms
            if tightening:
                control.strictest_limit = effective_limit
            control_changed = first_binding or tightening

            result: StateOperationResultV1
            if type(operation) is CounterIncrementV1:
                if control.value > SAFE_INTEGER_MAX - operation.increment:
                    result = self._failure(operation, StateFailureReasonV1.OVERFLOW)
                else:
                    control.value += operation.increment
                    control.state_version += 1
                    result = CounterApplied(
                        operation_id=operation.operation_id,
                        request_fingerprint=expected_fingerprint,
                        provider_claim=self._claim,
                        value=control.value,
                        state_version=control.state_version,
                        control_state_changed=control_changed,
                    )
            elif type(operation) is QuotaConsumeV1:
                assert effective_limit is not None
                if control.value + operation.units <= effective_limit:
                    control.value += operation.units
                    control.state_version += 1
                    result = QuotaApplied(
                        operation_id=operation.operation_id,
                        request_fingerprint=expected_fingerprint,
                        provider_claim=self._claim,
                        used=control.value,
                        remaining=effective_limit - control.value,
                        effective_limit=effective_limit,
                        state_version=control.state_version,
                        control_state_changed=control_changed,
                    )
                else:
                    if control_changed:
                        control.state_version += 1
                    result = QuotaRejected(
                        operation_id=operation.operation_id,
                        request_fingerprint=expected_fingerprint,
                        provider_claim=self._claim,
                        used=control.value,
                        effective_limit=effective_limit,
                        state_version=max(1, control.state_version),
                        control_state_changed=control_changed,
                    )
            elif type(operation) is ReplayClaimV1:
                assert now_ms is not None
                existing = control.claims.get(operation.claim_key)
                if existing is not None:
                    result = ReplayDuplicate(
                        operation_id=operation.operation_id,
                        request_fingerprint=expected_fingerprint,
                        provider_claim=self._claim,
                        expires_at_ms=existing,
                        state_version=max(1, control.state_version),
                        provider_time_ms=now_ms,
                        control_state_changed=control_changed,
                    )
                else:
                    expiry = now_ms + operation.ttl_ms
                    control.claims[operation.claim_key] = expiry
                    control.state_version += 1
                    result = ReplayClaimed(
                        operation_id=operation.operation_id,
                        request_fingerprint=expected_fingerprint,
                        provider_claim=self._claim,
                        expires_at_ms=expiry,
                        state_version=control.state_version,
                        provider_time_ms=now_ms,
                        control_state_changed=control_changed,
                    )
            else:
                assert type(operation) is SlidingWindowAdmitV1
                assert now_ms is not None and effective_limit is not None
                used = sum(event_units for _, event_units in control.events)
                if used + operation.units <= effective_limit:
                    control.events.append((now_ms, operation.units))
                    control.state_version += 1
                    new_used = used + operation.units
                    result = WindowApplied(
                        operation_id=operation.operation_id,
                        request_fingerprint=expected_fingerprint,
                        provider_claim=self._claim,
                        used=new_used,
                        remaining=effective_limit - new_used,
                        effective_limit=effective_limit,
                        state_version=control.state_version,
                        provider_time_ms=now_ms,
                        control_state_changed=control_changed,
                    )
                else:
                    retry_after_ms: int | None = None
                    if operation.units <= effective_limit:
                        needed = used + operation.units - effective_limit
                        released = 0
                        for timestamp, event_units in sorted(control.events):
                            released += event_units
                            if released >= needed:
                                retry_after_ms = max(
                                    0,
                                    timestamp + operation.window_ms - now_ms,
                                )
                                break
                    if control_changed:
                        control.state_version += 1
                    result = WindowRejected(
                        operation_id=operation.operation_id,
                        request_fingerprint=expected_fingerprint,
                        provider_claim=self._claim,
                        used=used,
                        effective_limit=effective_limit,
                        retry_after_ms=retry_after_ms,
                        state_version=max(1, control.state_version),
                        provider_time_ms=now_ms,
                        control_state_changed=control_changed,
                    )

            self._store_idempotency(
                operation, expected_fingerprint, result, now_ms
            )
            return result

    async def execute_async(
        self,
        operation: StateOperationV1,
    ) -> StateOperationResultV1:
        return await asyncio.to_thread(self.execute, operation)
