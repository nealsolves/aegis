from __future__ import annotations

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from aegis.stateful import (
    CounterApplied,
    CounterIncrementV1,
    InMemoryStatefulPolicyProvider,
    QuotaApplied,
    QuotaConsumeV1,
    QuotaRejected,
    ReplayClaimV1,
    ReplayClaimed,
    ReplayDuplicate,
    SlidingWindowAdmitV1,
    StateAddressV1,
    StateFailureReasonV1,
    StateInvalidRequestNoEffect,
    StateScopeV1,
    StateUnavailableNoEffect,
    WindowApplied,
    WindowRejected,
    bind_operation_fingerprint_v1,
    operation_fingerprint_v1,
)


class FakeClock:
    def __init__(self, now_ms: int = 10_000) -> None:
        self.now_ms = now_ms

    def __call__(self) -> int:
        return self.now_ms

    def advance(self, milliseconds: int) -> None:
        self.now_ms += milliseconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def provider(clock) -> InMemoryStatefulPolicyProvider:
    return InMemoryStatefulPolicyProvider(clock_ms=clock)


def _address(name: str = "constraint") -> StateAddressV1:
    return StateAddressV1(
        namespace="test-ns",
        policy_state_id="policy-state",
        constraint_id=name,
        scope=StateScopeV1.tenant("tenant-key").with_tool("search"),
    )


def _bind(operation):
    return bind_operation_fingerprint_v1(operation)


def _counter(operation_id: str, increment: int = 1, *, name="counter"):
    return _bind(CounterIncrementV1(
        operation_id=operation_id,
        request_fingerprint="",
        address=_address(name),
        timeout_ms=100,
        retry_horizon_ms=1000,
        increment=increment,
        counted_unit="request",
    ))


def _quota(operation_id: str, units: int, limit: int, *, name="quota"):
    return _bind(QuotaConsumeV1(
        operation_id=operation_id,
        request_fingerprint="",
        address=_address(name),
        timeout_ms=100,
        retry_horizon_ms=1000,
        units=units,
        limit=limit,
        counted_unit="request",
    ))


def _claim(operation_id: str, claim_key: str, ttl_ms: int = 1000, *, name="replay"):
    return _bind(ReplayClaimV1(
        operation_id=operation_id,
        request_fingerprint="",
        address=_address(name),
        timeout_ms=100,
        retry_horizon_ms=1000,
        claim_key=claim_key,
        ttl_ms=ttl_ms,
    ))


def _window(
    operation_id: str,
    units: int = 1,
    limit: int = 3,
    window_ms: int = 1000,
    *,
    name="window",
):
    return _bind(SlidingWindowAdmitV1(
        operation_id=operation_id,
        request_fingerprint="",
        address=_address(name),
        timeout_ms=100,
        retry_horizon_ms=1000,
        units=units,
        limit=limit,
        window_ms=window_ms,
        counted_unit="tool_call",
    ))


def test_counter_is_monotonic_idempotent_and_rejects_overflow(provider) -> None:
    first = provider.execute(_counter("counter-1", 2))
    duplicate = provider.execute(_counter("counter-1", 2))
    second = provider.execute(_counter("counter-2", 3))
    overflow = provider.execute(
        _counter("counter-overflow", 9_007_199_254_740_987)
    )

    assert isinstance(first, CounterApplied) and first.value == 2
    assert duplicate == first
    assert isinstance(second, CounterApplied) and second.value == 5
    assert isinstance(overflow, StateInvalidRequestNoEffect)
    assert overflow.reason is StateFailureReasonV1.OVERFLOW


def test_conflicting_operation_id_is_rejected_without_effect(provider) -> None:
    assert isinstance(provider.execute(_counter("same-id", 2)), CounterApplied)

    conflict = provider.execute(_counter("same-id", 3))
    next_result = provider.execute(_counter("after-conflict", 1))

    assert isinstance(conflict, StateInvalidRequestNoEffect)
    assert conflict.reason is StateFailureReasonV1.OPERATION_ID_CONFLICT
    assert isinstance(next_result, CounterApplied) and next_result.value == 3


def test_forged_fingerprint_is_rejected_and_does_not_reserve_id(provider) -> None:
    valid = _counter("forged-id", 2)
    forged = replace(valid, request_fingerprint="0" * 64)

    rejected = provider.execute(forged)
    applied = provider.execute(valid)

    assert isinstance(rejected, StateInvalidRequestNoEffect)
    assert rejected.reason is StateFailureReasonV1.FINGERPRINT_MISMATCH
    assert isinstance(applied, CounterApplied) and applied.value == 2


@pytest.mark.parametrize(
    ("field", "value"),
    [("increment", 0), ("contract_version", 2)],
)
def test_provider_revalidates_mutated_exact_operation_without_effect(
    provider,
    field,
    value,
) -> None:
    hostile = _counter(f"mutated-{field}")
    object.__setattr__(hostile, field, value)
    object.__setattr__(
        hostile,
        "request_fingerprint",
        operation_fingerprint_v1(hostile),
    )

    rejected = provider.execute(hostile)
    applied = provider.execute(_counter(f"valid-after-{field}"))

    assert isinstance(rejected, StateInvalidRequestNoEffect)
    assert rejected.reason is StateFailureReasonV1.INVALID_OPERATION
    assert isinstance(applied, CounterApplied)
    assert applied.value == 1


def test_quota_is_atomic_and_limit_tightens_monotonically(provider) -> None:
    first = provider.execute(_quota("quota-1", 3, 10))
    tightened = provider.execute(_quota("quota-2", 2, 6))
    old_process = provider.execute(_quota("quota-3", 2, 10))

    assert isinstance(first, QuotaApplied) and first.remaining == 7
    assert isinstance(tightened, QuotaApplied) and tightened.remaining == 1
    assert isinstance(old_process, QuotaRejected)
    assert old_process.used == 5 and old_process.effective_limit == 6


def test_quota_multi_unit_denial_consumes_nothing(provider) -> None:
    assert isinstance(provider.execute(_quota("quota-a", 4, 5)), QuotaApplied)
    denied = provider.execute(_quota("quota-b", 2, 5))
    final = provider.execute(_quota("quota-c", 1, 5))

    assert isinstance(denied, QuotaRejected) and denied.used == 4
    assert isinstance(final, QuotaApplied) and final.used == 5


def test_replay_claim_duplicate_does_not_extend_and_expires_exactly(clock, provider) -> None:
    first = provider.execute(_claim("claim-1", "message-1", ttl_ms=1000))
    clock.advance(900)
    duplicate = provider.execute(_claim("claim-2", "message-1", ttl_ms=1000))
    clock.advance(100)
    renewed = provider.execute(_claim("claim-3", "message-1", ttl_ms=1000))

    assert isinstance(first, ReplayClaimed) and first.expires_at_ms == 11_000
    assert isinstance(duplicate, ReplayDuplicate)
    assert duplicate.expires_at_ms == first.expires_at_ms
    assert isinstance(renewed, ReplayClaimed)
    assert renewed.expires_at_ms == 12_000


def test_replay_ttl_is_fixed_for_control_identity(provider) -> None:
    assert isinstance(provider.execute(_claim("ttl-1", "a", 1000)), ReplayClaimed)
    conflict = provider.execute(_claim("ttl-2", "b", 2000))

    assert isinstance(conflict, StateInvalidRequestNoEffect)
    assert conflict.reason is StateFailureReasonV1.CONFIGURATION_CONFLICT


def test_window_exact_boundary_multi_unit_and_retry_after(clock, provider) -> None:
    assert isinstance(provider.execute(_window("window-1", 2, 3)), WindowApplied)
    clock.advance(200)
    denied = provider.execute(_window("window-2", 2, 3))

    assert isinstance(denied, WindowRejected)
    assert denied.used == 2 and denied.retry_after_ms == 800

    clock.advance(800)
    admitted = provider.execute(_window("window-3", 2, 3))
    assert isinstance(admitted, WindowApplied)
    assert admitted.used == 2


def test_window_request_larger_than_limit_has_no_retry_after(provider) -> None:
    denied = provider.execute(_window("too-large", 4, 3))

    assert isinstance(denied, WindowRejected)
    assert denied.retry_after_ms is None


def test_window_limit_and_duration_mixed_version_rules(provider) -> None:
    assert isinstance(provider.execute(_window("mixed-1", 1, 5, 1000)), WindowApplied)
    tightened = provider.execute(_window("mixed-2", 1, 2, 1000))
    old_limit = provider.execute(_window("mixed-3", 1, 5, 1000))
    changed_window = provider.execute(_window("mixed-4", 1, 2, 2000))

    assert isinstance(tightened, WindowApplied)
    assert isinstance(old_limit, WindowRejected)
    assert old_limit.effective_limit == 2
    assert isinstance(changed_window, StateInvalidRequestNoEffect)


def test_clock_rollback_fails_closed_without_expiring_state(clock, provider) -> None:
    assert isinstance(provider.execute(_window("clock-1", 1, 1)), WindowApplied)
    clock.now_ms -= 1
    rollback = provider.execute(_window("clock-2", 1, 1))

    assert isinstance(rollback, StateUnavailableNoEffect)
    assert rollback.reason is StateFailureReasonV1.CLOCK_UNCERTAIN


def test_concurrent_window_admission_has_no_lost_updates(provider) -> None:
    barrier = threading.Barrier(21)

    def admit(index: int):
        barrier.wait()
        return provider.execute(_window(f"concurrent-{index}", 1, 10))

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(admit, index) for index in range(20)]
        barrier.wait()
        results = [future.result() for future in futures]

    assert sum(isinstance(item, WindowApplied) for item in results) == 10
    assert sum(isinstance(item, WindowRejected) for item in results) == 10


def test_concurrent_exact_duplicates_converge_on_one_result(provider) -> None:
    operation = _counter("duplicate-race", 1)
    barrier = threading.Barrier(11)

    def execute_duplicate():
        barrier.wait()
        return provider.execute(operation)

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(execute_duplicate) for _ in range(10)]
        barrier.wait()
        results = [future.result() for future in futures]

    assert all(item == results[0] for item in results)
    assert results[0].value == 1
    assert provider.execute(_counter("duplicate-after", 1)).value == 2


def test_capacity_exhaustion_is_known_no_effect(clock) -> None:
    provider = InMemoryStatefulPolicyProvider(
        clock_ms=clock,
        max_records=2,
        max_idempotency_records=20,
    )
    assert isinstance(provider.execute(_window("capacity-1", name="one")), WindowApplied)

    exhausted = provider.execute(_window("capacity-2", name="two"))

    assert isinstance(exhausted, StateUnavailableNoEffect)
    assert exhausted.reason is StateFailureReasonV1.CAPACITY_EXHAUSTED


def test_idempotency_records_gc_only_after_declared_retention(clock) -> None:
    provider = InMemoryStatefulPolicyProvider(
        clock_ms=clock,
        max_records=10,
        max_idempotency_records=1,
    )
    first = provider.execute(_window("retained-1"))

    clock.advance(provider.describe().min_idempotency_retention_ms)
    at_boundary = provider.execute(_window("retained-2", name="other"))
    clock.advance(1)
    after_retention = provider.execute(_window("retained-2", name="other"))

    assert isinstance(first, WindowApplied)
    assert isinstance(at_boundary, StateUnavailableNoEffect)
    assert at_boundary.reason is StateFailureReasonV1.CAPACITY_EXHAUSTED
    assert isinstance(after_retention, WindowApplied)


def test_operation_id_is_retained_while_window_effect_is_live(clock) -> None:
    operation = _window("live-window-id", limit=3, window_ms=120_000)
    provider = InMemoryStatefulPolicyProvider(clock_ms=clock)
    first_result = provider.execute(operation)
    clock.advance(60_001)
    provider.execute(_window("gc-trigger", name="other"))

    duplicate = provider.execute(operation)
    next_result = provider.execute(
        _window("live-window-next", limit=3, window_ms=120_000)
    )

    assert duplicate == first_result
    assert isinstance(next_result, WindowApplied)
    assert next_result.used == 2


def test_counter_operation_identity_is_not_garbage_collected(clock) -> None:
    provider = InMemoryStatefulPolicyProvider(
        clock_ms=clock,
        max_idempotency_records=1,
    )
    operation = _counter("permanent-counter-id")
    first = provider.execute(operation)
    clock.advance(60_001)

    exhausted = provider.execute(_counter("new-counter-id", name="other"))
    duplicate = provider.execute(operation)

    assert isinstance(exhausted, StateUnavailableNoEffect)
    assert exhausted.reason is StateFailureReasonV1.CAPACITY_EXHAUSTED
    assert duplicate == first


def test_provider_timeout_is_measured_from_receipt_before_mutation() -> None:
    class SlowOnceClock:
        def __init__(self):
            self.slow = True

        def __call__(self):
            if self.slow:
                self.slow = False
                time.sleep(0.02)
            return 10_000

    provider = InMemoryStatefulPolicyProvider(clock_ms=SlowOnceClock())
    timed = replace(
        _window("timed-out", limit=1),
        request_fingerprint="",
        timeout_ms=1,
    )
    timed = _bind(timed)

    result = provider.execute(timed)
    after = provider.execute(_window("after-timeout", limit=1))

    assert isinstance(result, StateUnavailableNoEffect)
    assert result.reason is StateFailureReasonV1.TIMEOUT
    assert isinstance(after, WindowApplied)


@pytest.mark.asyncio
async def test_async_provider_does_not_block_event_loop() -> None:
    def slow_clock():
        time.sleep(0.05)
        return 10_000

    provider = InMemoryStatefulPolicyProvider(clock_ms=slow_clock)
    started = time.monotonic()
    execution = asyncio.create_task(
        provider.execute_async(_window("nonblocking-async"))
    )

    await asyncio.sleep(0.005)
    responsiveness_ms = (time.monotonic() - started) * 1000
    result = await execution

    assert responsiveness_ms < 30
    assert isinstance(result, WindowApplied)


def test_replay_expiry_overflow_does_not_bind_control_configuration(clock) -> None:
    from aegis._internal.canonicalization import SAFE_INTEGER_MAX

    clock.now_ms = SAFE_INTEGER_MAX - 5
    provider = InMemoryStatefulPolicyProvider(clock_ms=clock)

    overflow = provider.execute(_claim("overflow", "a", ttl_ms=10, name="ttl"))
    valid = provider.execute(_claim("valid", "b", ttl_ms=1, name="ttl"))

    assert isinstance(overflow, StateInvalidRequestNoEffect)
    assert overflow.reason is StateFailureReasonV1.OVERFLOW
    assert isinstance(valid, ReplayClaimed)


@pytest.mark.asyncio
async def test_async_execution_is_semantically_identical(provider) -> None:
    sync_result = provider.execute(_quota("async-sync", 1, 3, name="sync"))
    async_result = await provider.execute_async(
        _quota("async-async", 1, 3, name="async")
    )

    assert isinstance(sync_result, QuotaApplied)
    assert isinstance(async_result, QuotaApplied)
    assert replace(sync_result, operation_id=async_result.operation_id,
                   request_fingerprint=async_result.request_fingerprint) == async_result
