from __future__ import annotations

import json
import time

import pytest

from aegis import AEGIS, CallbackAuditSink
from aegis.stateful import (
    InMemoryStatefulPolicyProvider,
    StateScopeV1,
    StatefulLimitDeniedError,
)


def _policy(tmp_path, *, limit: int = 1, max_calls: int = 5) -> str:
    path = tmp_path / "dynamic-stateful.yaml"
    path.write_text(json.dumps({
        "policy_version": "1.0",
        "roles": ["assistant"],
        "tools": {"allowed_tools": [{"name": "search", "max_calls": max_calls}]},
        "stateful": {
            "contract_version": 1,
            "policy_state_id": "dynamic-policy",
            "constraints": [{
                "id": "search-window",
                "kind": "sliding_window_tool_calls",
                "tool": "search",
                "scope": "tenant",
                "limit": limit,
                "window_ms": 60_000,
                "provider_timeout_ms": 100,
                "retry_horizon_ms": 500,
                "on_provider_failure": "deny",
            }],
        },
    }), encoding="utf-8")
    return str(path)


def _invocation(policy_file: str):
    return {
        "policy_file": policy_file,
        "model_provider": "test",
        "model_identifier": "test-model",
        "role": "assistant",
        "input": {},
        "context": {},
    }


def test_dynamic_tool_admission_occurs_only_at_actual_dispatch(tmp_path) -> None:
    provider = InMemoryStatefulPolicyProvider()
    artifacts = []
    runtime = AEGIS(
        sink=CallbackAuditSink(artifacts.append),
        state_provider=provider,
        state_namespace="prod",
    )
    scope = StateScopeV1.tenant("tenant-secret")
    session = runtime.open_session(
        policy_file=_policy(tmp_path), state_scope=scope,
    )
    assert session._state_scope is not scope

    handle = session.enforce_step_pre_call(_invocation(session._policy_file))
    session.register_adapter_step_state(handle, {})
    session.authorize_step_tool_call(handle, tool_name="search")

    with pytest.raises(StatefulLimitDeniedError) as captured:
        session.authorize_step_tool_call(handle, tool_name="search")

    artifact = captured.value.audit_artifact
    decisions = artifact["metadata"]["stateful_decisions"]
    assert artifact["enforcement_result"] == "FAIL"
    assert artifact["failure_gate"] == "tool_validation"
    assert len(decisions) == 2
    assert decisions[0]["requested_units"] == 1
    assert decisions[0]["outcome"] == "admitted"
    assert decisions[1]["outcome"] == "denied"
    assert artifacts[-1] == artifact
    assert "tenant-secret" not in json.dumps(artifacts)


def test_static_stateful_denial_preserves_session_failure_evidence(tmp_path) -> None:
    artifacts = []
    runtime = AEGIS(
        sink=CallbackAuditSink(artifacts.append),
        state_provider=InMemoryStatefulPolicyProvider(),
        state_namespace="prod",
    )
    policy_file = _policy(tmp_path, limit=1)
    session = runtime.open_session(
        policy_file=policy_file,
        state_scope=StateScopeV1.tenant("tenant-a"),
    )
    invocation = _invocation(policy_file)
    invocation["tool_calls"] = [{"name": "search"}]
    first = session.enforce_step_pre_call(invocation)
    session.enforce_step_post_call(first, {})

    with pytest.raises(StatefulLimitDeniedError) as captured:
        session.enforce_step_pre_call(invocation)

    artifact = captured.value.audit_artifact
    assert artifact["failure_gate"] == "tool_validation"
    assert artifact["metadata"]["stateful_decisions"][0]["outcome"] == "denied"
    assert artifacts[-1] == artifact


def test_canceling_pending_static_admission_preserves_consumed_evidence(
    tmp_path,
) -> None:
    artifacts = []
    runtime = AEGIS(
        sink=CallbackAuditSink(artifacts.append),
        state_provider=InMemoryStatefulPolicyProvider(),
        state_namespace="prod",
    )
    policy_file = _policy(tmp_path, limit=1)
    session = runtime.open_session(
        policy_file=policy_file,
        state_scope=StateScopeV1.tenant("tenant-a"),
    )
    invocation = _invocation(policy_file)
    invocation["tool_calls"] = [{"name": "search"}]
    session.enforce_step_pre_call(invocation)

    session.cancel()

    artifact = artifacts[-1]
    assert artifact["enforcement_result"] == "FAIL"
    assert artifact["metadata"]["stateful_decisions"][0]["outcome"] == "admitted"


def test_unexpected_phase_b_failure_preserves_consumed_stateful_evidence(
    tmp_path,
    monkeypatch,
) -> None:
    artifacts = []
    runtime = AEGIS(
        sink=CallbackAuditSink(artifacts.append),
        state_provider=InMemoryStatefulPolicyProvider(),
        state_namespace="prod",
    )
    policy_file = _policy(tmp_path, limit=1)
    session = runtime.open_session(
        policy_file=policy_file,
        state_scope=StateScopeV1.tenant("tenant-a"),
    )
    invocation = _invocation(policy_file)
    invocation["tool_calls"] = [{"name": "search"}]
    handle = session.enforce_step_pre_call(invocation)

    def fail_phase_b(record, output):
        raise RuntimeError("unexpected phase-b failure")

    monkeypatch.setattr(runtime, "_enforce_consumed_post_call", fail_phase_b)

    with pytest.raises(RuntimeError, match="unexpected phase-b failure"):
        session.enforce_step_post_call(handle, {})

    artifact = artifacts[-1]
    assert artifact["enforcement_result"] == "FAIL"
    assert artifact["metadata"]["stateful_decisions"][0]["outcome"] == "admitted"


def test_static_and_dynamic_session_charging_are_mutually_exclusive(tmp_path) -> None:
    runtime = AEGIS(
        sink=CallbackAuditSink(lambda artifact: None),
        state_provider=InMemoryStatefulPolicyProvider(),
        state_namespace="prod",
    )
    policy_file = _policy(tmp_path, limit=2)
    session = runtime.open_session(
        policy_file=policy_file,
        state_scope=StateScopeV1.tenant("tenant-a"),
    )
    invocation = _invocation(policy_file)
    invocation["tool_calls"] = [{"name": "search"}]
    handle = session.enforce_step_pre_call(invocation)

    with pytest.raises(Exception) as captured:
        session.register_adapter_step_state(handle, {})

    assert captured.value.code == "INVOCATION_VALIDATION_ERROR"


def test_dynamic_state_evidence_capacity_fails_before_provider_dispatch(
    tmp_path,
) -> None:
    class RecordingProvider(InMemoryStatefulPolicyProvider):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def execute(self, operation):
            self.calls += 1
            return super().execute(operation)

    provider = RecordingProvider()
    runtime = AEGIS(
        sink=CallbackAuditSink(lambda artifact: None),
        state_provider=provider,
        state_namespace="prod",
    )
    policy_file = _policy(tmp_path, limit=100, max_calls=100)
    session = runtime.open_session(
        policy_file=policy_file,
        state_scope=StateScopeV1.tenant("tenant-a"),
    )
    handle = session.enforce_step_pre_call(_invocation(policy_file))
    session.register_adapter_step_state(handle, {})
    for index in range(64):
        session.authorize_step_tool_call(
            handle,
            tool_name="search",
            tool_call_id=str(index),
        )

    with pytest.raises(Exception) as captured:
        session.authorize_step_tool_call(
            handle,
            tool_name="search",
            tool_call_id="overflow",
        )

    assert captured.value.code == "STATE_PROVIDER_CONTRACT_INVALID"
    assert provider.calls == 64
    artifact = session.enforce_step_post_call(handle, {})
    assert len(artifact["metadata"]["stateful_decisions"]) == 64


def test_validator_hook_denial_precedes_final_state_admission(tmp_path) -> None:
    from aegis._internal.errors import WorkflowHookDeniedError
    from aegis._internal.validator_hook import (
        VALIDATOR_DENY,
        ValidatorHook,
        ValidatorHookResult,
    )

    class RecordingProvider(InMemoryStatefulPolicyProvider):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def execute(self, operation):
            self.calls += 1
            return super().execute(operation)

    class DenyHook(ValidatorHook):
        hook_id = "deny-before-state"
        hook_version = "1"

        def evaluate(self, envelope):
            return ValidatorHookResult(
                decision=VALIDATOR_DENY,
                reason_code="TEST_DENY",
                explanation=None,
                hook_id=self.hook_id,
                hook_version=self.hook_version,
                attempt=1,
                latency_ms=0,
                observed_at=int(time.time() * 1000),
            )

    provider = RecordingProvider()
    runtime = AEGIS(
        sink=CallbackAuditSink(lambda artifact: None),
        state_provider=provider,
        state_namespace="prod",
    )
    runtime._set_validator_hooks([DenyHook()])
    policy_file = _policy(tmp_path)
    session = runtime.open_session(
        policy_file=policy_file,
        state_scope=StateScopeV1.tenant("tenant-a"),
    )
    invocation = _invocation(policy_file)
    invocation["tool_calls"] = [{"name": "search"}]

    with pytest.raises(WorkflowHookDeniedError):
        session.enforce_step_pre_call(invocation)

    assert provider.calls == 0
