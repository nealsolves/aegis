"""Dependency-free semantic conformance runner for state provider v1."""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from enum import Enum
from typing import Protocol

from aegis._internal.stateful_memory import InMemoryStatefulPolicyProvider
from aegis._internal.canonicalization import SAFE_INTEGER_MAX
from aegis._internal.stateful_models import (
    AsyncStatefulPolicyProviderV1,
    CounterApplied,
    CounterIncrementV1,
    QuotaApplied,
    QuotaConsumeV1,
    QuotaRejected,
    ReplayClaimV1,
    ReplayClaimed,
    ReplayDuplicate,
    SlidingWindowAdmitV1,
    StateAddressV1,
    StateExecutionModeV1,
    StateFailureReasonV1,
    StateInvalidRequestNoEffect,
    StateOperationFamilyV1,
    StateScopeV1,
    StateUnavailableNoEffect,
    StatefulPolicyProviderV1,
    WindowApplied,
    WindowRejected,
    bind_operation_fingerprint_v1,
    operation_fingerprint_v1,
)


class ConformanceScenarioStatusV1(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class ConformanceScenarioResultV1:
    name: str
    status: ConformanceScenarioStatusV1
    mandatory: bool
    reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class StateProviderConformanceReportV1:
    provider_id: str
    contract_version: int
    scenarios: tuple[ConformanceScenarioResultV1, ...]
    fixture_limitations: tuple[str, ...] = ()

    @property
    def passed(self) -> int:
        return sum(
            item.status is ConformanceScenarioStatusV1.PASSED
            for item in self.scenarios
        )

    @property
    def failed(self) -> int:
        return sum(
            item.status is ConformanceScenarioStatusV1.FAILED
            for item in self.scenarios
        )

    @property
    def not_applicable(self) -> int:
        return sum(
            item.status is ConformanceScenarioStatusV1.NOT_APPLICABLE
            for item in self.scenarios
        )

    @property
    def conformant(self) -> bool:
        return all(
            item.status is ConformanceScenarioStatusV1.PASSED
            for item in self.scenarios
            if item.mandatory
        )


class StateProviderConformanceFixtureV1(Protocol):
    fixture_limitations: tuple[str, ...]

    def reset(self) -> None: ...

    def create_clients(
        self,
        count: int,
    ) -> tuple[
        StatefulPolicyProviderV1 | AsyncStatefulPolicyProviderV1,
        ...,
    ]: ...

    def create_capacity_client(
        self,
        max_records: int,
    ) -> StatefulPolicyProviderV1 | AsyncStatefulPolicyProviderV1: ...

    def advance_ms(self, milliseconds: int) -> None: ...


class _ControllableClock:
    def __init__(self) -> None:
        self.now_ms = 1_000_000

    def __call__(self) -> int:
        return self.now_ms


class InMemoryStateProviderConformanceFixture:
    """Reusable fixture proving the reference provider's declared semantics."""

    fixture_limitations = (
        "instance-local consistency only",
        "no durability across provider lifetime",
    )

    def __init__(self) -> None:
        self._clock = _ControllableClock()
        self._provider = InMemoryStatefulPolicyProvider(clock_ms=self._clock)

    def reset(self) -> None:
        self._provider = InMemoryStatefulPolicyProvider(clock_ms=self._clock)

    def create_clients(
        self,
        count: int,
    ) -> tuple[InMemoryStatefulPolicyProvider, ...]:
        return tuple(self._provider for _ in range(count))

    def create_capacity_client(
        self,
        max_records: int,
    ) -> InMemoryStatefulPolicyProvider:
        return InMemoryStatefulPolicyProvider(
            clock_ms=self._clock,
            max_records=max_records,
        )

    def advance_ms(self, milliseconds: int) -> None:
        if type(milliseconds) is not int:
            raise TypeError("milliseconds must be an integer")
        self._clock.now_ms += milliseconds


class _Operations:
    def __init__(self) -> None:
        self._sequence = 0

    def _id(self, prefix: str) -> str:
        self._sequence += 1
        return f"{prefix}-{self._sequence:08d}"

    @staticmethod
    def address(
        constraint: str,
        *,
        tenant: str = "tenant-conformance-secret",
        scope: StateScopeV1 | None = None,
    ) -> StateAddressV1:
        return StateAddressV1(
            namespace="conformance",
            policy_state_id="conformance-policy",
            constraint_id=constraint,
            scope=scope or StateScopeV1.tenant(tenant).with_tool("tool"),
        )

    def counter(self, constraint: str, increment: int = 1) -> CounterIncrementV1:
        return bind_operation_fingerprint_v1(CounterIncrementV1(
            operation_id=self._id("counter"), request_fingerprint="",
            address=self.address(constraint), timeout_ms=100,
            retry_horizon_ms=1000, increment=increment, counted_unit="unit",
        ))

    def quota(self, constraint: str, units: int, limit: int) -> QuotaConsumeV1:
        return bind_operation_fingerprint_v1(QuotaConsumeV1(
            operation_id=self._id("quota"), request_fingerprint="",
            address=self.address(constraint), timeout_ms=100,
            retry_horizon_ms=1000, units=units, limit=limit, counted_unit="unit",
        ))

    def replay(self, constraint: str, claim: str, ttl: int) -> ReplayClaimV1:
        return bind_operation_fingerprint_v1(ReplayClaimV1(
            operation_id=self._id("replay"), request_fingerprint="",
            address=self.address(constraint), timeout_ms=100,
            retry_horizon_ms=1000, claim_key=claim, ttl_ms=ttl,
        ))

    def window(
        self,
        constraint: str,
        units: int,
        limit: int,
        window_ms: int = 1000,
        *,
        tenant: str = "tenant-conformance-secret",
        scope: StateScopeV1 | None = None,
    ) -> SlidingWindowAdmitV1:
        return bind_operation_fingerprint_v1(SlidingWindowAdmitV1(
            operation_id=self._id("window"), request_fingerprint="",
            address=self.address(constraint, tenant=tenant, scope=scope), timeout_ms=100,
            retry_horizon_ms=1000, units=units, limit=limit,
            window_ms=window_ms, counted_unit="tool_call",
        ))


class _FixtureClient:
    """Expose one sync test surface over any declared provider mode."""

    def __init__(self, client, descriptor, async_executor) -> None:
        self._client = client
        self._descriptor = descriptor
        self._async_executor = async_executor

    def describe(self):
        return self._descriptor

    def execute(self, operation):
        if StateExecutionModeV1.SYNC in self._descriptor.execution_modes:
            if not isinstance(self._client, StatefulPolicyProviderV1):
                raise TypeError("fixture client declares sync without execute()")
            return self._client.execute(operation)
        if StateExecutionModeV1.ASYNC in self._descriptor.execution_modes:
            if not isinstance(self._client, AsyncStatefulPolicyProviderV1):
                raise TypeError("fixture client declares async without execute_async()")
            return self._async_executor.run(
                self._client.execute_async(operation)
            )
        raise TypeError("fixture client declares no executable mode")

    async def execute_async(self, operation):
        if StateExecutionModeV1.ASYNC in self._descriptor.execution_modes:
            if not isinstance(self._client, AsyncStatefulPolicyProviderV1):
                raise TypeError("fixture client declares async without execute_async()")
            return await self._client.execute_async(operation)
        if StateExecutionModeV1.SYNC in self._descriptor.execution_modes:
            if not isinstance(self._client, StatefulPolicyProviderV1):
                raise TypeError("fixture client declares sync without execute()")
            return self._client.execute(operation)
        raise TypeError("fixture client declares no executable mode")


class _AsyncExecutor:
    """Keep async-only fixture clients on one event loop for the full run."""

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        self._ready.wait()

    def _serve(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._ready.set()
        self._loop.run_forever()
        self._loop.close()

    def run(self, awaitable):
        return asyncio.run_coroutine_threadsafe(
            awaitable,
            self._loop,
        ).result()

    def close(self) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join()


def run_state_provider_conformance_v1(
    fixture: StateProviderConformanceFixtureV1,
) -> StateProviderConformanceReportV1:
    """Run observable provider semantics without inspecting backend state."""
    operations = _Operations()
    results: list[ConformanceScenarioResultV1] = []
    fixture.reset()
    descriptor = fixture.create_clients(1)[0].describe()
    async_executor = _AsyncExecutor()

    def client():
        return _FixtureClient(
            fixture.create_clients(1)[0],
            descriptor,
            async_executor,
        )

    def scenario(
        name: str,
        function,
        *,
        family: StateOperationFamilyV1 | None = None,
        mandatory: bool = True,
    ) -> None:
        if family is not None and family not in descriptor.supported_operations:
            results.append(ConformanceScenarioResultV1(
                name=name,
                status=ConformanceScenarioStatusV1.NOT_APPLICABLE,
                mandatory=False,
                reason_code="operation_not_declared",
            ))
            return
        fixture.reset()
        try:
            function(client())
        except Exception:
            results.append(ConformanceScenarioResultV1(
                name=name,
                status=ConformanceScenarioStatusV1.FAILED,
                mandatory=mandatory,
                reason_code="scenario_failed",
            ))
        else:
            results.append(ConformanceScenarioResultV1(
                name=name,
                status=ConformanceScenarioStatusV1.PASSED,
                mandatory=mandatory,
            ))

    def counter_monotonic(client) -> None:
        first = client.execute(operations.counter("counter", 2))
        second = client.execute(operations.counter("counter", 3))
        assert isinstance(first, CounterApplied) and first.value == 2
        assert isinstance(second, CounterApplied) and second.value == 5

    scenario(
        "counter_monotonic",
        counter_monotonic,
        family=StateOperationFamilyV1.MONOTONIC_COUNTER,
    )

    def counter_overflow(client) -> None:
        assert isinstance(
            client.execute(operations.counter("counter-overflow", SAFE_INTEGER_MAX)),
            CounterApplied,
        )
        result = client.execute(operations.counter("counter-overflow", 1))
        assert isinstance(result, StateInvalidRequestNoEffect)
        assert result.reason is StateFailureReasonV1.OVERFLOW

    scenario(
        "counter_overflow",
        counter_overflow,
        family=StateOperationFamilyV1.MONOTONIC_COUNTER,
    )

    def counter_invalid_units(client) -> None:
        operation = operations.counter("counter-invalid")
        object.__setattr__(operation, "increment", 0)
        object.__setattr__(
            operation,
            "request_fingerprint",
            operation_fingerprint_v1(operation),
        )
        result = client.execute(operation)
        assert isinstance(result, StateInvalidRequestNoEffect)
        assert result.reason is StateFailureReasonV1.INVALID_OPERATION
        assert client.execute(operations.counter("counter-invalid")).value == 1

    scenario(
        "counter_invalid_units",
        counter_invalid_units,
        family=StateOperationFamilyV1.MONOTONIC_COUNTER,
    )

    def duplicate_idempotency(client) -> None:
        operation = operations.counter("duplicate")
        assert client.execute(operation) == client.execute(operation)

    scenario(
        "duplicate_idempotency",
        duplicate_idempotency,
        family=StateOperationFamilyV1.MONOTONIC_COUNTER,
    )

    def quota_duplicate_idempotency(client) -> None:
        operation = operations.quota("quota-duplicate", 1, 3)
        assert client.execute(operation) == client.execute(operation)

    scenario(
        "quota_duplicate_idempotency",
        quota_duplicate_idempotency,
        family=StateOperationFamilyV1.QUOTA,
    )

    def replay_duplicate_idempotency(client) -> None:
        operation = operations.replay("replay-duplicate", "claim", 1000)
        assert client.execute(operation) == client.execute(operation)

    scenario(
        "replay_duplicate_idempotency",
        replay_duplicate_idempotency,
        family=StateOperationFamilyV1.REPLAY_TTL,
    )

    def window_duplicate_idempotency(client) -> None:
        operation = operations.window("window-duplicate", 1, 3)
        assert client.execute(operation) == client.execute(operation)

    scenario(
        "window_duplicate_idempotency",
        window_duplicate_idempotency,
        family=StateOperationFamilyV1.SLIDING_WINDOW,
    )

    def conflicting_operation_id(client) -> None:
        operation = operations.counter("operation-id-conflict", 1)
        assert isinstance(client.execute(operation), CounterApplied)
        conflict = bind_operation_fingerprint_v1(replace(
            operation,
            request_fingerprint="",
            increment=2,
        ))
        result = client.execute(conflict)
        assert isinstance(result, StateInvalidRequestNoEffect)
        assert result.reason is StateFailureReasonV1.OPERATION_ID_CONFLICT
        after = client.execute(operations.counter("operation-id-conflict", 1))
        assert isinstance(after, CounterApplied) and after.value == 2

    scenario(
        "conflicting_operation_id",
        conflicting_operation_id,
        family=StateOperationFamilyV1.MONOTONIC_COUNTER,
    )

    def quota_conflicting_operation_id(client) -> None:
        operation = operations.quota("quota-id-conflict", 1, 3)
        assert isinstance(client.execute(operation), QuotaApplied)
        conflict = bind_operation_fingerprint_v1(replace(
            operation,
            request_fingerprint="",
            units=2,
        ))
        result = client.execute(conflict)
        assert isinstance(result, StateInvalidRequestNoEffect)
        assert result.reason is StateFailureReasonV1.OPERATION_ID_CONFLICT
        after = client.execute(operations.quota("quota-id-conflict", 1, 3))
        assert isinstance(after, QuotaApplied) and after.used == 2

    scenario(
        "quota_conflicting_operation_id",
        quota_conflicting_operation_id,
        family=StateOperationFamilyV1.QUOTA,
    )

    def replay_conflicting_operation_id(client) -> None:
        operation = operations.replay("replay-id-conflict", "claim-a", 1000)
        assert isinstance(client.execute(operation), ReplayClaimed)
        conflict = bind_operation_fingerprint_v1(replace(
            operation,
            request_fingerprint="",
            claim_key="claim-b",
        ))
        result = client.execute(conflict)
        assert isinstance(result, StateInvalidRequestNoEffect)
        assert result.reason is StateFailureReasonV1.OPERATION_ID_CONFLICT
        after = client.execute(operations.replay(
            "replay-id-conflict", "claim-b", 1000,
        ))
        assert isinstance(after, ReplayClaimed)

    scenario(
        "replay_conflicting_operation_id",
        replay_conflicting_operation_id,
        family=StateOperationFamilyV1.REPLAY_TTL,
    )

    def window_conflicting_operation_id(client) -> None:
        operation = operations.window("window-id-conflict", 1, 3)
        assert isinstance(client.execute(operation), WindowApplied)
        conflict = bind_operation_fingerprint_v1(replace(
            operation,
            request_fingerprint="",
            units=2,
        ))
        result = client.execute(conflict)
        assert isinstance(result, StateInvalidRequestNoEffect)
        assert result.reason is StateFailureReasonV1.OPERATION_ID_CONFLICT
        after = client.execute(operations.window("window-id-conflict", 1, 3))
        assert isinstance(after, WindowApplied) and after.used == 2

    scenario(
        "window_conflicting_operation_id",
        window_conflicting_operation_id,
        family=StateOperationFamilyV1.SLIDING_WINDOW,
    )

    def incompatible_operation_version(client) -> None:
        operation = operations.counter("operation-version")
        object.__setattr__(operation, "contract_version", 2)
        object.__setattr__(
            operation,
            "request_fingerprint",
            operation_fingerprint_v1(operation),
        )
        result = client.execute(operation)
        assert isinstance(result, StateInvalidRequestNoEffect)
        assert result.reason is StateFailureReasonV1.INVALID_OPERATION

    scenario(
        "incompatible_operation_version",
        incompatible_operation_version,
        family=StateOperationFamilyV1.MONOTONIC_COUNTER,
    )

    def fingerprint_conflict(client) -> None:
        operation = operations.counter("fingerprint")
        forged = CounterIncrementV1(
            operation_id=operation.operation_id,
            request_fingerprint="0" * 64,
            address=operation.address,
            timeout_ms=operation.timeout_ms,
            retry_horizon_ms=operation.retry_horizon_ms,
            increment=operation.increment,
            counted_unit=operation.counted_unit,
        )
        result = client.execute(forged)
        assert isinstance(result, StateInvalidRequestNoEffect)
        assert result.reason is StateFailureReasonV1.FINGERPRINT_MISMATCH
        assert isinstance(client.execute(operation), CounterApplied)

    scenario(
        "fingerprint_rejection_no_effect",
        fingerprint_conflict,
        family=StateOperationFamilyV1.MONOTONIC_COUNTER,
    )

    def quota_tightening(client) -> None:
        assert isinstance(client.execute(operations.quota("quota", 3, 10)), QuotaApplied)
        assert isinstance(client.execute(operations.quota("quota", 2, 6)), QuotaApplied)
        result = client.execute(operations.quota("quota", 2, 10))
        assert isinstance(result, QuotaRejected) and result.effective_limit == 6

    scenario(
        "quota_tightening",
        quota_tightening,
        family=StateOperationFamilyV1.QUOTA,
    )

    def quota_boundaries(client) -> None:
        applied = client.execute(operations.quota("quota-boundary", 5, 5))
        rejected = client.execute(operations.quota("quota-boundary", 1, 5))
        assert isinstance(applied, QuotaApplied) and applied.remaining == 0
        assert isinstance(rejected, QuotaRejected) and rejected.used == 5

    scenario(
        "quota_boundaries",
        quota_boundaries,
        family=StateOperationFamilyV1.QUOTA,
    )

    def quota_atomic_units(client) -> None:
        assert isinstance(client.execute(operations.quota("atomic", 4, 5)), QuotaApplied)
        assert isinstance(client.execute(operations.quota("atomic", 2, 5)), QuotaRejected)
        final = client.execute(operations.quota("atomic", 1, 5))
        assert isinstance(final, QuotaApplied) and final.used == 5

    scenario(
        "quota_atomic_multi_unit",
        quota_atomic_units,
        family=StateOperationFamilyV1.QUOTA,
    )

    def replay_exact_expiry(client) -> None:
        first = client.execute(operations.replay("replay", "claim", 1000))
        fixture.advance_ms(999)
        duplicate = client.execute(operations.replay("replay", "claim", 1000))
        fixture.advance_ms(1)
        renewed = client.execute(operations.replay("replay", "claim", 1000))
        assert isinstance(first, ReplayClaimed)
        assert isinstance(duplicate, ReplayDuplicate)
        assert isinstance(renewed, ReplayClaimed)

    scenario(
        "replay_exact_expiry",
        replay_exact_expiry,
        family=StateOperationFamilyV1.REPLAY_TTL,
    )

    def replay_configuration(client) -> None:
        assert isinstance(client.execute(operations.replay("ttl", "a", 1000)), ReplayClaimed)
        result = client.execute(operations.replay("ttl", "b", 2000))
        assert isinstance(result, StateInvalidRequestNoEffect)

    scenario(
        "replay_fixed_ttl",
        replay_configuration,
        family=StateOperationFamilyV1.REPLAY_TTL,
    )

    def window_exact_boundary(client) -> None:
        assert isinstance(client.execute(operations.window("window", 2, 2)), WindowApplied)
        assert isinstance(client.execute(operations.window("window", 1, 2)), WindowRejected)
        fixture.advance_ms(1000)
        assert isinstance(client.execute(operations.window("window", 2, 2)), WindowApplied)

    scenario(
        "window_exact_boundary",
        window_exact_boundary,
        family=StateOperationFamilyV1.SLIDING_WINDOW,
    )

    def window_limit_tightening(client) -> None:
        assert isinstance(client.execute(operations.window("window-limit", 1, 5)), WindowApplied)
        assert isinstance(client.execute(operations.window("window-limit", 1, 2)), WindowApplied)
        old_limit = client.execute(operations.window("window-limit", 1, 5))
        assert isinstance(old_limit, WindowRejected)
        assert old_limit.effective_limit == 2

    scenario(
        "window_limit_tightening",
        window_limit_tightening,
        family=StateOperationFamilyV1.SLIDING_WINDOW,
    )

    def scope_isolation(client) -> None:
        left = client.execute(operations.window("scope", 1, 1, tenant="tenant-left"))
        right = client.execute(operations.window("scope", 1, 1, tenant="tenant-right"))
        assert isinstance(left, WindowApplied) and isinstance(right, WindowApplied)

    scenario(
        "scope_isolation",
        scope_isolation,
        family=StateOperationFamilyV1.SLIDING_WINDOW,
    )

    def all_scope_dimensions_isolated(client) -> None:
        base = {
            "invocation": "invocation-a",
            "participant": "participant-a",
            "session": "session-a",
            "tenant": "tenant-a",
            "tool": "tool-a",
            "policy": "policy-a",
        }
        for dimension in tuple(base):
            changed = dict(base)
            changed[dimension] = f"{dimension}-b"
            left = client.execute(operations.window(
                f"scope-{dimension}", 1, 1,
                scope=StateScopeV1.from_values(**base),
            ))
            right = client.execute(operations.window(
                f"scope-{dimension}", 1, 1,
                scope=StateScopeV1.from_values(**changed),
            ))
            assert isinstance(left, WindowApplied)
            assert isinstance(right, WindowApplied)

    scenario(
        "all_scope_dimensions_isolated",
        all_scope_dimensions_isolated,
        family=StateOperationFamilyV1.SLIDING_WINDOW,
    )

    def clock_rollback(client) -> None:
        assert isinstance(client.execute(operations.window("clock", 1, 1)), WindowApplied)
        fixture.advance_ms(-1)
        result = client.execute(operations.window("clock", 1, 1))
        assert isinstance(result, StateUnavailableNoEffect)
        assert result.reason is StateFailureReasonV1.CLOCK_UNCERTAIN
        fixture.advance_ms(1)

    scenario(
        "clock_rollback",
        clock_rollback,
        family=StateOperationFamilyV1.SLIDING_WINDOW,
    )

    def concurrent_lost_update(_client) -> None:
        clients = tuple(
            _FixtureClient(item, descriptor, async_executor)
            for item in fixture.create_clients(8)
        )
        barrier = threading.Barrier(9)

        def execute(index: int):
            barrier.wait()
            return clients[index].execute(operations.window("race", 1, 4))

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(execute, index) for index in range(8)]
            barrier.wait()
            admissions = [future.result() for future in futures]
        assert sum(isinstance(item, WindowApplied) for item in admissions) == 4
        assert sum(isinstance(item, WindowRejected) for item in admissions) == 4

    scenario(
        "concurrent_lost_update_prevention",
        concurrent_lost_update,
        family=StateOperationFamilyV1.SLIDING_WINDOW,
    )

    def capacity_exhaustion(_client) -> None:
        client = _FixtureClient(
            fixture.create_capacity_client(2),
            descriptor,
            async_executor,
        )
        assert isinstance(client.execute(operations.window("capacity-a", 1, 1)), WindowApplied)
        result = client.execute(operations.window("capacity-b", 1, 1))
        assert isinstance(result, StateUnavailableNoEffect)
        assert result.reason is StateFailureReasonV1.CAPACITY_EXHAUSTED

    scenario(
        "capacity_exhaustion_no_effect",
        capacity_exhaustion,
        family=StateOperationFamilyV1.SLIDING_WINDOW,
    )

    def safe_semantic_gc(client) -> None:
        operation = operations.window("semantic-gc", 1, 3, window_ms=120_000)
        first = client.execute(operation)
        fixture.advance_ms(60_001)
        client.execute(operations.window("semantic-gc-trigger", 1, 1))
        duplicate = client.execute(operation)
        assert duplicate == first

    scenario(
        "safe_semantic_gc",
        safe_semantic_gc,
        family=StateOperationFamilyV1.SLIDING_WINDOW,
    )

    def bounded_redacted_results(client) -> None:
        result = client.execute(operations.window("bounded-result", 1, 1))
        rendered = repr(result)
        assert len(rendered) < 2_000
        assert "tenant-conformance-secret" not in rendered
        assert "object at 0x" not in rendered

    scenario(
        "bounded_redacted_results",
        bounded_redacted_results,
        family=StateOperationFamilyV1.SLIDING_WINDOW,
    )

    if (
        StateExecutionModeV1.SYNC in descriptor.execution_modes
        and StateExecutionModeV1.ASYNC in descriptor.execution_modes
    ):
        def sync_async_equivalence(client) -> None:
            assert isinstance(client, AsyncStatefulPolicyProviderV1)
            sync_result = client.execute(operations.quota("sync", 1, 2))
            async_result = asyncio.run(
                client.execute_async(operations.quota("async", 1, 2))
            )
            assert isinstance(sync_result, QuotaApplied)
            assert isinstance(async_result, QuotaApplied)
            assert sync_result.used == async_result.used == 1

        scenario("sync_async_equivalence", sync_async_equivalence)
    else:
        reason = (
            "async_not_declared"
            if StateExecutionModeV1.ASYNC not in descriptor.execution_modes
            else "sync_not_declared"
        )
        results.append(ConformanceScenarioResultV1(
            name="sync_async_equivalence",
            status=ConformanceScenarioStatusV1.NOT_APPLICABLE,
            mandatory=False,
            reason_code=reason,
        ))

    async_executor.close()
    return StateProviderConformanceReportV1(
        provider_id=descriptor.provider_id,
        contract_version=descriptor.contract_version,
        scenarios=tuple(results),
        fixture_limitations=tuple(fixture.fixture_limitations),
    )
