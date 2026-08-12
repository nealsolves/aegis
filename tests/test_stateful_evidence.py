from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from aegis import AEGIS, CallbackAuditSink
from aegis._internal.evidence_profiles import ContentIntegrity, verify_content_checksum_v2
from aegis.stateful import (
    InMemoryStatefulPolicyProvider,
    StateScopeV1,
    StatefulLimitDeniedError,
)


ROOT = Path(__file__).resolve().parents[1]


def _policy(tmp_path) -> str:
    path = tmp_path / "evidence-stateful.yaml"
    path.write_text(json.dumps({
        "policy_version": "1.0",
        "roles": ["assistant"],
        "tools": {"allowed_tools": [{"name": "search", "max_calls": 5}]},
        "stateful": {
            "contract_version": 1,
            "policy_state_id": "evidence-policy",
            "constraints": [{
                "id": "search-window",
                "kind": "sliding_window_tool_calls",
                "tool": "search",
                "scope": "tenant",
                "limit": 1,
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
        "context": {
            "metadata": {
                "stateful_decisions": [{"outcome": "attacker-allow"}],
            },
        },
        "stateful_decisions": [{"outcome": "attacker-allow"}],
        "tool_calls": [{"name": "search"}],
    }


def test_stateful_pass_and_fail_evidence_is_typed_reserved_and_checksum_covered(
    tmp_path,
) -> None:
    emitted = []
    runtime = AEGIS(
        sink=CallbackAuditSink(emitted.append),
        state_provider=InMemoryStatefulPolicyProvider(),
        state_namespace="secret-namespace",
    )
    invocation = _invocation(_policy(tmp_path))
    scope = StateScopeV1.tenant("secret-tenant")

    handle = runtime.enforce_pre_call(invocation, state_scope=scope)
    passed = runtime.enforce_post_call(handle, {})
    decision = passed["metadata"]["stateful_decisions"][0]
    assert decision["outcome"] == "admitted"
    assert decision["evidence_version"] == 1
    assert decision["provider_id"] == "aegis-in-memory"
    assert decision["consistency_domain"] == "instance"
    assert decision["durability_domain"] == "none"
    assert decision["clock_source"] == "monotonic"
    assert verify_content_checksum_v2(passed) is ContentIntegrity.VALID

    tampered = copy.deepcopy(passed)
    tampered["metadata"]["stateful_decisions"][0]["outcome"] = "denied"
    assert verify_content_checksum_v2(tampered) is ContentIntegrity.INVALID

    with pytest.raises(StatefulLimitDeniedError) as captured:
        runtime.enforce_pre_call(invocation, state_scope=scope)
    failed = captured.value.audit_artifact
    assert failed["metadata"]["stateful_decisions"][0]["outcome"] == "denied"

    schema = json.loads(
        (ROOT / "schemas/audit_artifact.schema.json").read_text(encoding="utf-8")
    )
    Draft7Validator(schema).validate(passed)
    Draft7Validator(schema).validate(failed)

    serialized = json.dumps([passed, failed, emitted])
    assert "attacker-allow" not in json.dumps(
        passed["metadata"]["stateful_decisions"]
    )
    assert "secret-tenant" not in serialized
    assert "secret-namespace" not in serialized


def test_audit_schema_copies_remain_identical() -> None:
    assert (ROOT / "schemas/audit_artifact.schema.json").read_bytes() == (
        ROOT / "aegis/schemas/audit_artifact.schema.json"
    ).read_bytes()
