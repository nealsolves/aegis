from __future__ import annotations

import asyncio
from dataclasses import replace

from aegis.stateful import (
    ConformanceScenarioStatusV1,
    InMemoryStateProviderConformanceFixture,
    QuotaConsumeV1,
    StateExecutionModeV1,
    StateProviderConformanceReportV1,
    bind_operation_fingerprint_v1,
    run_state_provider_conformance_v1,
)


def test_in_memory_provider_passes_every_applicable_conformance_scenario() -> None:
    report = run_state_provider_conformance_v1(
        InMemoryStateProviderConformanceFixture()
    )

    assert isinstance(report, StateProviderConformanceReportV1)
    assert report.conformant is True
    assert report.failed == 0
    assert report.passed >= 20
    assert all(
        scenario.status is ConformanceScenarioStatusV1.PASSED
        for scenario in report.scenarios
        if scenario.mandatory
    )
    assert {
        "counter_monotonic",
        "counter_overflow",
        "counter_invalid_units",
        "quota_tightening",
        "quota_boundaries",
        "replay_exact_expiry",
        "replay_fixed_ttl",
        "window_exact_boundary",
        "window_limit_tightening",
        "duplicate_idempotency",
        "quota_duplicate_idempotency",
        "replay_duplicate_idempotency",
        "window_duplicate_idempotency",
        "conflicting_operation_id",
        "quota_conflicting_operation_id",
        "replay_conflicting_operation_id",
        "window_conflicting_operation_id",
        "incompatible_operation_version",
        "fingerprint_rejection_no_effect",
        "concurrent_lost_update_prevention",
        "clock_rollback",
        "all_scope_dimensions_isolated",
        "safe_semantic_gc",
        "bounded_redacted_results",
        "sync_async_equivalence",
    } <= {scenario.name for scenario in report.scenarios}


def test_report_fields_are_bounded_and_do_not_expose_fixture_objects() -> None:
    fixture = InMemoryStateProviderConformanceFixture()
    report = run_state_provider_conformance_v1(fixture)
    rendered = repr(report)

    assert len(rendered) < 10_000
    assert "tenant-conformance-secret" not in rendered
    assert "object at 0x" not in rendered


def test_conformance_rejects_quota_duplicate_reapplication() -> None:
    class BrokenQuotaClient:
        def __init__(self, client):
            self._client = client
            self._seen: set[str] = set()

        def describe(self):
            return self._client.describe()

        def execute(self, operation):
            if (
                isinstance(operation, QuotaConsumeV1)
                and operation.operation_id in self._seen
            ):
                reapplied = bind_operation_fingerprint_v1(replace(
                    operation,
                    operation_id=f"{operation.operation_id}-reapplied",
                    request_fingerprint="",
                ))
                return self._client.execute(reapplied)
            self._seen.add(operation.operation_id)
            return self._client.execute(operation)

        async def execute_async(self, operation):
            return self.execute(operation)

    class BrokenQuotaFixture(InMemoryStateProviderConformanceFixture):
        def create_clients(self, count):
            return tuple(
                BrokenQuotaClient(client)
                for client in super().create_clients(count)
            )

        def create_capacity_client(self, max_records):
            return BrokenQuotaClient(
                super().create_capacity_client(max_records)
            )

    report = run_state_provider_conformance_v1(BrokenQuotaFixture())

    assert report.conformant is False
    scenario = next(
        item for item in report.scenarios
        if item.name == "quota_duplicate_idempotency"
    )
    assert scenario.status is ConformanceScenarioStatusV1.FAILED


def test_conformance_rejects_hidden_mutation_on_quota_conflict() -> None:
    class MutatingConflictClient:
        def __init__(self, client):
            self._client = client
            self._fingerprints: dict[str, str] = {}

        def describe(self):
            return self._client.describe()

        def execute(self, operation):
            previous = self._fingerprints.get(operation.operation_id)
            self._fingerprints.setdefault(
                operation.operation_id,
                operation.request_fingerprint,
            )
            result = self._client.execute(operation)
            if (
                isinstance(operation, QuotaConsumeV1)
                and previous is not None
                and previous != operation.request_fingerprint
            ):
                hidden = bind_operation_fingerprint_v1(replace(
                    operation,
                    operation_id=f"{operation.operation_id}-hidden",
                    request_fingerprint="",
                ))
                self._client.execute(hidden)
            return result

        async def execute_async(self, operation):
            return self.execute(operation)

    class MutatingConflictFixture(InMemoryStateProviderConformanceFixture):
        def create_clients(self, count):
            return tuple(
                MutatingConflictClient(client)
                for client in super().create_clients(count)
            )

        def create_capacity_client(self, max_records):
            return MutatingConflictClient(
                super().create_capacity_client(max_records)
            )

    report = run_state_provider_conformance_v1(MutatingConflictFixture())

    assert report.conformant is False
    scenario = next(
        item for item in report.scenarios
        if item.name == "quota_conflicting_operation_id"
    )
    assert scenario.status is ConformanceScenarioStatusV1.FAILED


def test_conformance_supports_async_only_provider_fixtures() -> None:
    class AsyncOnlyClient:
        def __init__(self, client):
            self._client = client
            self._loop = None

        def describe(self):
            return replace(
                self._client.describe(),
                execution_modes=frozenset({StateExecutionModeV1.ASYNC}),
            )

        async def execute_async(self, operation):
            loop = asyncio.get_running_loop()
            if self._loop is None:
                self._loop = loop
            elif self._loop is not loop:
                raise RuntimeError("provider client moved across event loops")
            await asyncio.sleep(0)
            return self._client.execute(operation)

    class AsyncOnlyFixture(InMemoryStateProviderConformanceFixture):
        def create_clients(self, count):
            return tuple(
                AsyncOnlyClient(client)
                for client in super().create_clients(count)
            )

        def create_capacity_client(self, max_records):
            return AsyncOnlyClient(
                super().create_capacity_client(max_records)
            )

    report = run_state_provider_conformance_v1(AsyncOnlyFixture())

    assert report.conformant is True
    assert report.failed == 0
    equivalence = next(
        item for item in report.scenarios
        if item.name == "sync_async_equivalence"
    )
    assert equivalence.status is ConformanceScenarioStatusV1.NOT_APPLICABLE
