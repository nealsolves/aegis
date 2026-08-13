from __future__ import annotations

import socket

import pytest
from fastapi.testclient import TestClient

from main import app


client = TestClient(app)

SCENARIO_CASES = [
    ("atlas", "first_attempt", "FAIL"),
    ("atlas", "corrected", "PASS"),
    ("northstar", "first_attempt", "FAIL"),
    ("northstar", "authorized_retry", "PAUSED"),
    ("northstar", "corrected", "PASS"),
    ("meridian", "first_attempt", "FAIL"),
]

ADAPTER_CASES = [
    ("bedrock", "valid_trace", "PASS"),
    ("bedrock", "wrong_alias", "FAIL"),
    ("openai_agents", "governed_graph", "PASS"),
    ("openai_agents", "predeclared_tool_call", "FAIL"),
    ("a2a", "completed_task", "PASS"),
    ("a2a", "grpc_binding", "FAIL"),
]


@pytest.fixture(autouse=True)
def deny_outbound_network(monkeypatch):
    def blocked_connect(*_args, **_kwargs):
        raise AssertionError("demo tests attempted an outbound network call")

    monkeypatch.setattr(socket.socket, "connect", blocked_connect)


def test_every_released_demo_run_matches_manifest_provenance():
    """Catches a released fixture that drifts from the public contract or SDK."""
    manifest_response = client.get("/api/demo/manifest")

    assert manifest_response.status_code == 200
    manifest = manifest_response.json()
    assert manifest["api_contract_version"] == "1"
    assert set(manifest["scenarios"]) == {"atlas", "northstar", "meridian"}
    assert set(manifest["adapters"]) == {"bedrock", "openai_agents", "a2a"}

    runs = []
    for scenario_id, variant, expected_decision in SCENARIO_CASES:
        response = client.post(
            f"/api/demo/scenarios/{scenario_id}/runs",
            json={"variant": variant},
        )

        assert response.status_code == 200
        run = response.json()
        assert run["scenario_id"] == scenario_id
        assert run["variant"] == variant
        assert run["decision"] == expected_decision
        runs.append(run)

    for adapter_id, fixture_id, expected_decision in ADAPTER_CASES:
        response = client.post(
            f"/api/demo/adapters/{adapter_id}/runs",
            json={"fixture_id": fixture_id},
        )

        assert response.status_code == 200
        run = response.json()
        assert run["adapter_id"] == adapter_id
        assert run["fixture_id"] == fixture_id
        assert run["decision"] == expected_decision
        runs.append(run)

    assert all(
        run["source"]["sdk_version"] == manifest["sdk_version"]
        for run in runs
    )
