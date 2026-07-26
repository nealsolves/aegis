from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from aegis.audit import checksum
from demo_registry import VERIFIED_ADAPTERS
from main import app


client = TestClient(app)

CASES = [
    ("bedrock", "valid_trace", "PASS"),
    ("openai_agents", "governed_graph", "PASS"),
    ("a2a", "completed_task", "PASS"),
]
NEGATIVE = [
    (
        "bedrock",
        "wrong_alias",
        "WORKFLOW_PROTOCOL_TRACE_ALIAS_MISMATCH",
    ),
    (
        "openai_agents",
        "predeclared_tool_call",
        "WORKFLOW_UNSUPPORTED_BINDING",
    ),
    ("a2a", "grpc_binding", "WORKFLOW_PROTOCOL_GRPC_UNSUPPORTED"),
]


@pytest.mark.parametrize(("adapter_id", "fixture_id", "decision"), CASES)
def test_adapter_positive_release_cases(
    adapter_id: str,
    fixture_id: str,
    decision: str,
):
    """Catches a released adapter that cannot produce authentic PASS evidence."""
    response = client.post(
        f"/api/demo/adapters/{adapter_id}/runs",
        json={"fixture_id": fixture_id},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["adapter_id"] == adapter_id
    assert body["fixture_id"] == fixture_id
    assert body["decision"] == decision
    assert body["error"] is None
    assert body["provider_input"]
    assert body["artifact"]["enforcement_result"] == "PASS"
    assert re.fullmatch(r"[0-9a-f]{64}", body["artifact"]["input_checksum"])
    assert re.fullmatch(r"[0-9a-f]{64}", body["artifact"]["output_checksum"])
    assert body["artifact"]["input_checksum"] == checksum(
        {"prompt": "Record the fixed demonstration plan."},
    )
    assert body["artifact"]["output_checksum"] == checksum(
        {"result": "Plan recorded", "confidence": 0.98},
    )
    assert body["workflow_artifact"]["status"] == "COMPLETED"
    assert body["normalized_evidence"] == (
        body["workflow_artifact"]["steps"][0]["metadata"]
    )


@pytest.mark.parametrize(
    ("adapter_id", "fixture_id", "reason_code"),
    NEGATIVE,
)
def test_adapter_negative_release_cases(
    adapter_id: str,
    fixture_id: str,
    reason_code: str,
):
    """Catches a released adapter that loses its public typed rejection evidence."""
    response = client.post(
        f"/api/demo/adapters/{adapter_id}/runs",
        json={"fixture_id": fixture_id},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["adapter_id"] == adapter_id
    assert body["fixture_id"] == fixture_id
    assert body["decision"] == "FAIL"
    assert body["artifact"] is None
    assert body["error"]["code"] == reason_code
    assert body["normalized_evidence"]["reason_code"] == reason_code
    assert body["workflow_artifact"]["status"] == "FAILED"
    assert body["workflow_artifact"]["steps"] == []


def test_bedrock_keeps_provider_trace_separate_from_redacted_metadata():
    """Catches raw Bedrock trace content leaking into adapter-normalized metadata."""
    response = client.post(
        "/api/demo/adapters/bedrock/runs",
        json={"fixture_id": "valid_trace"},
    )

    assert response.status_code == 200
    body = response.json()
    provider_trace = body["provider_input"]["trace_parts"][0]
    assert (
        provider_trace["trace"]["orchestrationTrace"]["traceId"]
        == "trace-demo-001"
    )
    assert body["normalized_evidence"]["trace_ids"] == ["trace-demo-001"]
    assert body["normalized_evidence"]["trace_alias_matched"] is True

    forbidden_keys = {
        "orchestrationtrace",
        "provider_payload",
        "providerpayload",
        "prompt",
        "raw_trace",
        "trace",
    }

    def nested_text(value):
        if isinstance(value, dict):
            for key, nested_value in value.items():
                assert str(key).lower() not in forbidden_keys
                yield str(key)
                yield from nested_text(nested_value)
        elif isinstance(value, list):
            for item in value:
                yield from nested_text(item)
        elif isinstance(value, str):
            yield value

    normalized_text = "\n".join(nested_text(body["normalized_evidence"])).lower()
    for forbidden in (
        "orchestrationtrace",
        "raw_trace",
        "raw trace",
        "prompt",
        "provider_payload",
        "provider payload",
    ):
        assert forbidden not in normalized_text


def test_openai_agents_uses_the_governed_empty_tool_graph():
    """Catches drift from the fixed, no-execution OpenAI Agents graph fixture."""
    response = client.post(
        "/api/demo/adapters/openai_agents/runs",
        json={"fixture_id": "governed_graph"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["provider_input"]["agent"] == {
        "name": "DemoPlanner",
        "tools": [],
    }
    assert body["normalized_evidence"]["last_agent_name"] == "DemoPlanner"
    assert body["normalized_evidence"]["dynamic_tool_calls_count"] == 0
    assert body["normalized_evidence"]["models_seen"] == []
    assert body["normalized_evidence"]["total_tokens"] == 0


def test_a2a_uses_jsonrpc_and_a_completed_task_envelope():
    """Catches an A2A PASS that is not backed by the fixed compatible task."""
    response = client.post(
        "/api/demo/adapters/a2a/runs",
        json={"fixture_id": "completed_task"},
    )

    assert response.status_code == 200
    body = response.json()
    interface = body["provider_input"]["agent_card"]["supportedInterfaces"][0]
    assert interface["protocolBinding"] == "JSONRPC"
    assert interface["protocolVersion"] == "1.0"
    assert (
        body["provider_input"]["task_envelope"]["status"]["state"]
        == "TASK_STATE_COMPLETED"
    )
    assert body["normalized_evidence"]["protocol_binding"] == "JSONRPC"
    assert body["normalized_evidence"]["task_state"] == "TASK_STATE_COMPLETED"
    assert body["normalized_evidence"]["terminal"] is True


def test_verified_adapters_have_both_release_case_types():
    """Catches a manifest release without both positive and typed-negative coverage."""
    positive_ids = {adapter_id for adapter_id, _, _ in CASES}
    typed_negative_ids = {adapter_id for adapter_id, _, _ in NEGATIVE}

    assert VERIFIED_ADAPTERS <= positive_ids & typed_negative_ids


def test_adapter_routes_reject_unknown_fixture_ids():
    """Catches client-selected fixture names reaching a released adapter runner."""
    response = client.post(
        "/api/demo/adapters/bedrock/runs",
        json={"fixture_id": "not-a-server-fixture"},
    )

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "UNKNOWN_DEMO_ID"
    assert response.json()["detail"]["id_type"] == "fixture_id"
