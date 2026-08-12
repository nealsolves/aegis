from __future__ import annotations

import asyncio
import copy
import json
import time
from dataclasses import replace
from pathlib import Path

import pytest

from aegis import AEGIS, CallbackAuditSink
from aegis.decorators import governed
from aegis.enforcement import enforce_invocation, enforce_pre_call
from aegis.stateful import (
    InMemoryStatefulPolicyProvider,
    StateExecutionModeV1,
    StateFailureReasonV1,
    StateIndeterminateMayHaveCommitted,
    StateProviderIndeterminateError,
    StateProviderClaimV1,
    StateScopeV1,
    StateUnavailableNoEffect,
    StatefulLimitDeniedError,
    StatefulPreCallRequiredError,
    StateProviderRequiredError,
    StateScopeRequiredError,
    WindowApplied,
)


def _policy_file(
    tmp_path,
    *,
    limit: int = 2,
    timeout_ms: int = 100,
    retry_horizon_ms: int = 500,
) -> str:
    policy = {
        "policy_version": "1.0",
        "roles": ["assistant"],
        "tools": {"allowed_tools": [{"name": "search", "max_calls": 10}]},
        "stateful": {
            "contract_version": 1,
            "policy_state_id": "tenant-search-policy",
            "constraints": [{
                "id": "tenant-search-window",
                "kind": "sliding_window_tool_calls",
                "tool": "search",
                "scope": "tenant",
                "limit": limit,
                "window_ms": 60_000,
                "provider_timeout_ms": timeout_ms,
                "retry_horizon_ms": retry_horizon_ms,
                "on_provider_failure": "deny",
            }],
        },
    }
    path = tmp_path / "stateful-policy.yaml"
    path.write_text(json.dumps(policy), encoding="utf-8")
    return str(path)


def _invocation(policy_file: str, *, calls: int = 1, role: str = "assistant"):
    return {
        "policy_file": policy_file,
        "model_provider": "test",
        "model_identifier": "test-model",
        "role": role,
        "input": {},
        "context": {},
        "tool_calls": [{"name": "search", "arguments": {}} for _ in range(calls)],
    }


def _aegis(provider=None, *, namespace: str | None = "prod"):
    artifacts = []
    runtime = AEGIS(
        sink=CallbackAuditSink(artifacts.append),
        state_provider=provider,
        state_namespace=namespace,
    )
    return runtime, artifacts


def test_sliding_window_consumes_after_phase_a_and_denies_before_handle(tmp_path) -> None:
    provider = InMemoryStatefulPolicyProvider()
    runtime, artifacts = _aegis(provider)
    invocation = _invocation(_policy_file(tmp_path, limit=2))
    scope = StateScopeV1.tenant("tenant-secret")

    first = runtime.enforce_pre_call(invocation, state_scope=scope)
    artifact = runtime.enforce_post_call(first, {})
    second = runtime.enforce_pre_call(invocation, state_scope=scope)
    runtime.enforce_post_call(second, {})

    with pytest.raises(StatefulLimitDeniedError) as captured:
        runtime.enforce_pre_call(invocation, state_scope=scope)

    assert captured.value.audit_artifact["enforcement_result"] == "FAIL"
    decision = artifact["metadata"]["stateful_decisions"][0]
    assert decision["outcome"] == "admitted"
    assert decision["requested_units"] == 1
    serialized = json.dumps(artifacts)
    assert "tenant-secret" not in serialized


def test_aggregates_same_tool_calls_into_one_state_operation(tmp_path) -> None:
    class RecordingProvider(InMemoryStatefulPolicyProvider):
        def __init__(self):
            super().__init__()
            self.operations = []

        def execute(self, operation):
            self.operations.append(operation)
            return super().execute(operation)

    provider = RecordingProvider()
    runtime, _ = _aegis(provider)

    handle = runtime.enforce_pre_call(
        _invocation(_policy_file(tmp_path, limit=3), calls=2),
        state_scope=StateScopeV1.tenant("tenant-a"),
    )

    assert handle.operation_id
    assert len(provider.operations) == 1
    assert provider.operations[0].units == 2


def test_one_shot_tool_calls_are_snapshotted_before_multiple_gates(tmp_path) -> None:
    class RecordingProvider(InMemoryStatefulPolicyProvider):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def execute(self, operation):
            self.calls += 1
            return super().execute(operation)

    provider = RecordingProvider()
    runtime, _ = _aegis(provider)
    invocation = _invocation(_policy_file(tmp_path, limit=1), calls=0)
    invocation["tool_calls"] = iter([{"name": "search", "arguments": {}}])

    handle = runtime.enforce_pre_call(
        invocation,
        state_scope=StateScopeV1.tenant("tenant-a"),
    )

    assert handle.operation_id
    assert provider.calls == 1


def test_index_only_tool_call_is_rejected_before_state_admission(tmp_path) -> None:
    class IndexOnlyCall:
        def __getitem__(self, key):
            if key == "name":
                return "search"
            raise KeyError(key)

    class RecordingProvider(InMemoryStatefulPolicyProvider):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def execute(self, operation):
            self.calls += 1
            return super().execute(operation)

    provider = RecordingProvider()
    runtime, _ = _aegis(provider)
    invocation = _invocation(_policy_file(tmp_path), calls=0)
    invocation["tool_calls"] = [IndexOnlyCall()]

    with pytest.raises(Exception) as captured:
        runtime.enforce_pre_call(
            invocation,
            state_scope=StateScopeV1.tenant("tenant-a"),
        )

    assert captured.value.code == "INVOCATION_VALIDATION_ERROR"
    assert provider.calls == 0


def test_missing_provider_scope_and_payload_scope_fail_closed(tmp_path) -> None:
    policy_file = _policy_file(tmp_path)
    invocation = _invocation(policy_file)

    runtime, _ = _aegis(None)
    with pytest.raises(StateProviderRequiredError):
        runtime.enforce_pre_call(
            invocation,
            state_scope=StateScopeV1.tenant("tenant-a"),
        )

    runtime, _ = _aegis(InMemoryStatefulPolicyProvider())
    with pytest.raises(StateScopeRequiredError):
        runtime.enforce_pre_call(invocation)

    attacker_invocation = copy.deepcopy(invocation)
    attacker_invocation["state_scope"] = {"tenant": "attacker-controlled"}
    with pytest.raises(StateScopeRequiredError):
        runtime.enforce_pre_call(attacker_invocation)


def test_stateless_denial_does_not_consume_provider_state(tmp_path) -> None:
    class RecordingProvider(InMemoryStatefulPolicyProvider):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def execute(self, operation):
            self.calls += 1
            return super().execute(operation)

    provider = RecordingProvider()
    runtime, _ = _aegis(provider)

    with pytest.raises(Exception) as captured:
        runtime.enforce_pre_call(
            _invocation(_policy_file(tmp_path), role="unauthorized"),
            state_scope=StateScopeV1.tenant("tenant-a"),
        )

    assert captured.value.code == "ROLE_NOT_ALLOWED"
    assert provider.calls == 0


def test_unified_enforcement_rejects_stateful_policy_before_execution(tmp_path) -> None:
    runtime, _ = _aegis(InMemoryStatefulPolicyProvider())
    invocation = _invocation(_policy_file(tmp_path))
    invocation["output"] = {}

    with pytest.raises(StatefulPreCallRequiredError):
        runtime.enforce(invocation)


def test_module_and_decorator_surfaces_reject_before_user_code(tmp_path) -> None:
    policy_file = _policy_file(tmp_path)
    invocation = _invocation(policy_file)

    with pytest.raises(StatefulPreCallRequiredError):
        enforce_pre_call(invocation)

    unified = {**invocation, "output": {}}
    with pytest.raises(StatefulPreCallRequiredError):
        enforce_invocation(unified)

    calls = []
    with pytest.deprecated_call():
        decorated = governed(
            policy_file=policy_file,
            role="assistant",
            model_provider="test",
            model_identifier="test-model",
            pre_call_enforcement=False,
        )(lambda input_data, context: calls.append(True) or {})

    with pytest.raises(StatefulPreCallRequiredError):
        decorated({}, {})
    assert calls == []


@pytest.mark.asyncio
async def test_deprecated_async_decorator_rejects_before_user_code(tmp_path) -> None:
    calls = []

    async def user_code(input_data, context):
        calls.append(True)
        return {}

    with pytest.deprecated_call():
        decorated = governed(
            policy_file=_policy_file(tmp_path),
            role="assistant",
            model_provider="test",
            model_identifier="test-model",
            pre_call_enforcement=False,
        )(user_code)

    with pytest.raises(StatefulPreCallRequiredError):
        await decorated({}, {})
    assert calls == []


def test_session_uses_detached_trusted_scope(tmp_path) -> None:
    provider = InMemoryStatefulPolicyProvider()
    runtime, _ = _aegis(provider)
    policy_file = _policy_file(tmp_path, limit=1)
    scope = StateScopeV1.tenant("session-tenant")
    session = runtime.open_session(policy_file=policy_file, state_scope=scope)

    first = session.enforce_step_pre_call(_invocation(policy_file))
    artifact = session.enforce_step_post_call(first, {})

    assert artifact["metadata"]["stateful_decisions"][0]["outcome"] == "admitted"
    with pytest.raises(StatefulLimitDeniedError):
        session.enforce_step_pre_call(_invocation(policy_file))


@pytest.mark.asyncio
async def test_async_pre_call_requires_async_mode_and_enforces(tmp_path) -> None:
    policy_file = _policy_file(tmp_path, limit=1)
    scope = StateScopeV1.tenant("async-tenant")
    runtime, _ = _aegis(InMemoryStatefulPolicyProvider())

    handle = await runtime.enforce_pre_call_async(
        _invocation(policy_file), state_scope=scope,
    )
    assert handle.operation_id
    with pytest.raises(StatefulLimitDeniedError):
        await runtime.enforce_pre_call_async(
            _invocation(policy_file), state_scope=scope,
        )

    class SyncOnlyProvider(InMemoryStatefulPolicyProvider):
        def describe(self):
            return replace(
                super().describe(),
                execution_modes=frozenset({StateExecutionModeV1.SYNC}),
            )

    sync_runtime, _ = _aegis(SyncOnlyProvider())
    with pytest.raises(Exception) as captured:
        await sync_runtime.enforce_pre_call_async(
            _invocation(policy_file), state_scope=scope,
        )
    assert captured.value.code == "STATE_PROVIDER_MODE_UNSUPPORTED"


@pytest.mark.asyncio
async def test_async_timeout_reconciles_identical_operation(tmp_path) -> None:
    class AsyncCommitThenTimeout:
        def __init__(self):
            self.inner = InMemoryStatefulPolicyProvider()
            self.operation_ids = []
            self.first = True

        def describe(self):
            return self.inner.describe()

        async def execute_async(self, operation):
            self.operation_ids.append(operation.operation_id)
            result = self.inner.execute(operation)
            if self.first:
                self.first = False
                await asyncio.sleep(1)
            return result

    provider = AsyncCommitThenTimeout()
    runtime, _ = _aegis(provider)
    policy_file = _policy_file(
        tmp_path, limit=1, timeout_ms=10, retry_horizon_ms=100,
    )
    handle = await runtime.enforce_pre_call_async(
        _invocation(policy_file),
        state_scope=StateScopeV1.tenant("tenant-a"),
    )
    artifact = await runtime.enforce_post_call_async(handle, {})

    assert len(provider.operation_ids) == 2
    assert len(set(provider.operation_ids)) == 1
    assert artifact["metadata"]["stateful_decisions"][0][
        "reconciliation_status"
    ] == "reconciled"


@pytest.mark.asyncio
async def test_async_provider_cannot_authorize_by_suppressing_timeout_cancel(
    tmp_path,
) -> None:
    class CancellationSuppressingProvider:
        def __init__(self):
            self.inner = InMemoryStatefulPolicyProvider()
            self.calls = 0

        def describe(self):
            return self.inner.describe()

        async def execute_async(self, operation):
            self.calls += 1
            result = self.inner.execute(operation)
            if self.calls == 1:
                try:
                    await asyncio.sleep(1)
                except asyncio.CancelledError:
                    await asyncio.sleep(0.02)
            return result

    provider = CancellationSuppressingProvider()
    runtime, _ = _aegis(provider)
    handle = await runtime.enforce_pre_call_async(
        _invocation(
            _policy_file(
                tmp_path, limit=1, timeout_ms=10, retry_horizon_ms=100,
            )
        ),
        state_scope=StateScopeV1.tenant("tenant-a"),
    )
    artifact = await runtime.enforce_post_call_async(handle, {})

    assert provider.calls == 2
    assert artifact["metadata"]["stateful_decisions"][0][
        "reconciliation_status"
    ] == "reconciled"


def test_commit_then_exception_reconciles_with_same_operation_identity(tmp_path) -> None:
    class CommitThenExceptionProvider:
        def __init__(self):
            self.inner = InMemoryStatefulPolicyProvider()
            self.operation_ids = []
            self.first = True

        def describe(self):
            return self.inner.describe()

        def execute(self, operation):
            self.operation_ids.append(operation.operation_id)
            result = self.inner.execute(operation)
            if self.first:
                self.first = False
                raise RuntimeError("provider secret must never escape")
            return result

    provider = CommitThenExceptionProvider()
    runtime, _ = _aegis(provider)
    handle = runtime.enforce_pre_call(
        _invocation(_policy_file(tmp_path, limit=1)),
        state_scope=StateScopeV1.tenant("tenant-secret"),
    )
    artifact = runtime.enforce_post_call(handle, {})

    assert len(provider.operation_ids) == 2
    assert len(set(provider.operation_ids)) == 1
    assert artifact["metadata"]["stateful_decisions"][0][
        "reconciliation_status"
    ] == "reconciled"
    assert "provider secret" not in json.dumps(artifact)


def test_indeterminate_result_reconciles_and_malformed_provider_is_redacted(tmp_path) -> None:
    class IndeterminateThenCommit:
        def __init__(self):
            self.inner = InMemoryStatefulPolicyProvider()
            self.first = True

        def describe(self):
            return self.inner.describe()

        def execute(self, operation):
            if self.first:
                self.first = False
                self.inner.execute(operation)
                return StateIndeterminateMayHaveCommitted(
                    operation_id=operation.operation_id,
                    request_fingerprint=operation.request_fingerprint,
                    provider_claim=StateProviderClaimV1.from_descriptor(
                        self.describe()
                    ),
                    operation_family=operation.family,
                    reason=StateFailureReasonV1.POSSIBLE_COMMIT,
                )
            return self.inner.execute(operation)

    class Hostile:
        def __repr__(self):
            raise RuntimeError("repr-secret")

        def __str__(self):
            return "string-secret"

    class MalformedProvider:
        def __init__(self):
            self.inner = InMemoryStatefulPolicyProvider()

        def describe(self):
            return self.inner.describe()

        def execute(self, operation):
            return Hostile()

    policy_file = _policy_file(tmp_path)
    reconcile_runtime, _ = _aegis(IndeterminateThenCommit())
    reconciled = reconcile_runtime.enforce_pre_call(
        _invocation(policy_file),
        state_scope=StateScopeV1.tenant("tenant-a"),
    )
    reconciled_artifact = reconcile_runtime.enforce_post_call(reconciled, {})
    assert reconciled_artifact["metadata"]["stateful_decisions"][0][
        "reconciliation_status"
    ] == "reconciled"

    runtime, artifacts = _aegis(MalformedProvider())
    with pytest.raises(Exception) as captured:
        runtime.enforce_pre_call(
            _invocation(policy_file),
            state_scope=StateScopeV1.tenant("tenant-secret"),
        )

    serialized = json.dumps(captured.value.audit_artifact)
    assert "tenant-secret" not in serialized
    assert "repr-secret" not in serialized
    assert "string-secret" not in serialized


def test_malformed_provider_result_is_terminal_and_never_retried(tmp_path) -> None:
    class MalformedThenAllow:
        def __init__(self):
            self.inner = InMemoryStatefulPolicyProvider()
            self.calls = 0

        def describe(self):
            return self.inner.describe()

        def execute(self, operation):
            self.calls += 1
            if self.calls == 1:
                return object()
            return self.inner.execute(operation)

    provider = MalformedThenAllow()
    runtime, _ = _aegis(provider)

    with pytest.raises(Exception) as captured:
        runtime.enforce_pre_call(
            _invocation(_policy_file(tmp_path)),
            state_scope=StateScopeV1.tenant("tenant-a"),
        )

    assert captured.value.code == "STATE_PROVIDER_RESULT_INVALID"
    assert provider.calls == 1


def test_explicit_stale_result_is_terminal_and_never_authorizes(tmp_path) -> None:
    class StaleThenAllow:
        def __init__(self):
            self.inner = InMemoryStatefulPolicyProvider()
            self.calls = 0
            self.claim = StateProviderClaimV1.from_descriptor(self.describe())

        def describe(self):
            return self.inner.describe()

        def execute(self, operation):
            self.calls += 1
            if self.calls == 1:
                return StateUnavailableNoEffect(
                    operation_id=operation.operation_id,
                    request_fingerprint=operation.request_fingerprint,
                    provider_claim=self.claim,
                    operation_family=operation.family,
                    reason=StateFailureReasonV1.STALE_RESULT,
                )
            return self.inner.execute(operation)

    provider = StaleThenAllow()
    runtime, _ = _aegis(provider)

    with pytest.raises(Exception) as captured:
        runtime.enforce_pre_call(
            _invocation(_policy_file(tmp_path)),
            state_scope=StateScopeV1.tenant("tenant-a"),
        )

    assert captured.value.code == "STATE_PROVIDER_RESULT_INVALID"
    assert captured.value.details == {"reason": "stale_result"}
    assert provider.calls == 1


def test_result_completing_after_retry_horizon_cannot_authorize(tmp_path) -> None:
    class SlowUnavailableThenAllow:
        def __init__(self):
            self.inner = InMemoryStatefulPolicyProvider()
            self.calls = 0
            self.claim = StateProviderClaimV1.from_descriptor(self.describe())

        def describe(self):
            return self.inner.describe()

        def execute(self, operation):
            self.calls += 1
            time.sleep(0.03)
            if self.calls == 1:
                return StateUnavailableNoEffect(
                    operation_id=operation.operation_id,
                    request_fingerprint=operation.request_fingerprint,
                    provider_claim=self.claim,
                    operation_family=operation.family,
                    reason=StateFailureReasonV1.UNAVAILABLE,
                )
            return WindowApplied(
                operation_id=operation.operation_id,
                request_fingerprint=operation.request_fingerprint,
                provider_claim=self.claim,
                used=1,
                remaining=0,
                effective_limit=1,
                state_version=1,
                provider_time_ms=1,
            )

    provider = SlowUnavailableThenAllow()
    runtime, _ = _aegis(provider)

    with pytest.raises(StateProviderIndeterminateError):
        runtime.enforce_pre_call(
            _invocation(
                _policy_file(
                    tmp_path,
                    limit=1,
                    timeout_ms=40,
                    retry_horizon_ms=50,
                )
            ),
            state_scope=StateScopeV1.tenant("tenant-a"),
        )

    assert provider.calls == 2


@pytest.mark.asyncio
async def test_caller_cancellation_returns_indeterminate_without_retry(
    tmp_path,
) -> None:
    class CommitThenBlock:
        def __init__(self):
            self.inner = InMemoryStatefulPolicyProvider()
            self.calls = 0
            self.entered = asyncio.Event()
            self.blocker = asyncio.Event()

        def describe(self):
            return self.inner.describe()

        async def execute_async(self, operation):
            self.calls += 1
            self.inner.execute(operation)
            self.entered.set()
            await self.blocker.wait()

    provider = CommitThenBlock()
    runtime, artifacts = _aegis(provider)
    task = asyncio.create_task(runtime.enforce_pre_call_async(
        _invocation(_policy_file(tmp_path, limit=1)),
        state_scope=StateScopeV1.tenant("tenant-a"),
    ))
    await provider.entered.wait()
    task.cancel()

    with pytest.raises(StateProviderIndeterminateError) as captured:
        await task

    assert provider.calls == 1
    assert captured.value.audit_artifact["metadata"]["stateful_decisions"][0][
        "reason_code"
    ] == "STATE_PROVIDER_INDETERMINATE"
    assert len(artifacts) == 1


def test_constraints_run_in_id_order_and_keep_conservative_partial_consumption(
    tmp_path,
) -> None:
    policy_file = _policy_file(tmp_path, limit=1)
    raw = json.loads(Path(policy_file).read_text(encoding="utf-8"))
    raw["tools"]["allowed_tools"].append({"name": "fetch", "max_calls": 10})
    raw["stateful"]["constraints"][0]["id"] = "a-search"
    raw["stateful"]["constraints"].append({
        **raw["stateful"]["constraints"][0],
        "id": "z-fetch",
        "tool": "fetch",
    })
    Path(policy_file).write_text(json.dumps(raw), encoding="utf-8")

    class RecordingProvider(InMemoryStatefulPolicyProvider):
        def __init__(self):
            super().__init__()
            self.constraint_ids = []

        def execute(self, operation):
            self.constraint_ids.append(operation.address.constraint_id)
            return super().execute(operation)

    provider = RecordingProvider()
    runtime, _ = _aegis(provider)
    scope = StateScopeV1.tenant("tenant-a")
    fetch_only = _invocation(policy_file, calls=0)
    fetch_only["tool_calls"] = [{"name": "fetch"}]
    runtime.enforce_pre_call(fetch_only, state_scope=scope)

    both = _invocation(policy_file)
    both["tool_calls"].append({"name": "fetch"})
    before = len(provider.constraint_ids)
    with pytest.raises(StatefulLimitDeniedError):
        runtime.enforce_pre_call(both, state_scope=scope)

    assert provider.constraint_ids[before:] == ["a-search", "z-fetch"]
    with pytest.raises(StatefulLimitDeniedError):
        runtime.enforce_pre_call(_invocation(policy_file), state_scope=scope)


def test_late_sync_result_requires_exact_reconciliation_and_outage_is_bounded(
    tmp_path,
) -> None:
    class LateCommitProvider:
        def __init__(self):
            self.inner = InMemoryStatefulPolicyProvider()
            self.calls = 0

        def describe(self):
            return self.inner.describe()

        def execute(self, operation):
            self.calls += 1
            result = self.inner.execute(operation)
            if self.calls == 1:
                time.sleep(0.02)
            return result

    policy_file = _policy_file(
        tmp_path, limit=1, timeout_ms=10, retry_horizon_ms=100,
    )
    late = LateCommitProvider()
    runtime, _ = _aegis(late)
    handle = runtime.enforce_pre_call(
        _invocation(policy_file),
        state_scope=StateScopeV1.tenant("tenant-a"),
    )
    artifact = runtime.enforce_post_call(handle, {})
    assert late.calls == 2
    assert artifact["metadata"]["stateful_decisions"][0][
        "reconciliation_status"
    ] == "reconciled"

    class OutageProvider:
        def __init__(self):
            self.inner = InMemoryStatefulPolicyProvider()
            self.calls = 0

        def describe(self):
            return self.inner.describe()

        def execute(self, operation):
            self.calls += 1
            return StateUnavailableNoEffect(
                operation_id=operation.operation_id,
                request_fingerprint=operation.request_fingerprint,
                provider_claim=StateProviderClaimV1.from_descriptor(
                    self.describe()
                ),
                operation_family=operation.family,
                reason=StateFailureReasonV1.UNAVAILABLE,
            )

    outage = OutageProvider()
    outage_runtime, _ = _aegis(outage)
    with pytest.raises(Exception) as captured:
        outage_runtime.enforce_pre_call(
            _invocation(policy_file),
            state_scope=StateScopeV1.tenant("tenant-b"),
        )
    assert captured.value.code == "STATE_PROVIDER_UNAVAILABLE"
    assert outage.calls == 3


def test_provider_descriptor_is_snapshotted_and_namespace_is_validated(
    tmp_path,
) -> None:
    class MutableDescriptorProvider:
        def __init__(self):
            self.inner = InMemoryStatefulPolicyProvider()
            self.descriptor = self.inner.describe()

        def describe(self):
            return self.descriptor

        def execute(self, operation):
            return self.inner.execute(operation)

    provider = MutableDescriptorProvider()
    runtime, _ = _aegis(provider)
    provider.descriptor = replace(
        provider.descriptor,
        execution_modes=frozenset({StateExecutionModeV1.ASYNC}),
    )

    handle = runtime.enforce_pre_call(
        _invocation(_policy_file(tmp_path)),
        state_scope=StateScopeV1.tenant("tenant-a"),
    )
    assert handle.operation_id

    invalid_namespace, _ = _aegis(
        InMemoryStatefulPolicyProvider(), namespace="not a namespace",
    )
    with pytest.raises(Exception) as captured:
        invalid_namespace.enforce_pre_call(
            _invocation(_policy_file(tmp_path)),
            state_scope=StateScopeV1.tenant("tenant-b"),
        )
    assert captured.value.code == "STATE_PROVIDER_CONTRACT_INVALID"


def test_provider_descriptor_constructor_invariants_are_revalidated() -> None:
    class MutatedDescriptorProvider(InMemoryStatefulPolicyProvider):
        def __init__(self):
            super().__init__()
            self.descriptor = super().describe()
            object.__setattr__(self.descriptor, "max_operation_bytes", True)

        def describe(self):
            return self.descriptor

    with pytest.raises(Exception) as captured:
        _aegis(MutatedDescriptorProvider())

    assert captured.value.code == "STATE_PROVIDER_CONTRACT_INVALID"
    assert captured.value.details == {"reason": "descriptor_fields"}


def test_provider_retention_must_cover_retry_horizon_plus_dispatch(tmp_path) -> None:
    class ShortRetentionProvider(InMemoryStatefulPolicyProvider):
        def describe(self):
            return replace(
                super().describe(), min_idempotency_retention_ms=1_050
            )

    runtime, _ = _aegis(ShortRetentionProvider())
    with pytest.raises(Exception) as captured:
        runtime.enforce_pre_call(
            _invocation(
                _policy_file(
                    tmp_path, timeout_ms=100, retry_horizon_ms=1_000,
                )
            ),
            state_scope=StateScopeV1.tenant("tenant-a"),
        )

    assert captured.value.code == "STATE_PROVIDER_CONTRACT_INVALID"


def test_exact_operation_size_is_checked_before_provider_dispatch(tmp_path) -> None:
    class SmallOperationProvider(InMemoryStatefulPolicyProvider):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def describe(self):
            return replace(super().describe(), max_operation_bytes=400)

        def execute(self, operation):
            self.calls += 1
            return super().execute(operation)

    provider = SmallOperationProvider()
    runtime, _ = _aegis(provider)

    with pytest.raises(Exception) as captured:
        runtime.enforce_pre_call(
            _invocation(_policy_file(tmp_path)),
            state_scope=StateScopeV1.tenant("tenant-a"),
        )

    assert captured.value.code == "STATE_PROVIDER_CONTRACT_INVALID"
    assert captured.value.details == {"reason": "operation_too_large"}
    assert provider.calls == 0
