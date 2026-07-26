from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def test_demo_manifest_reports_versions_and_allowlists():
    """Catches a manifest that exposes stale contract metadata or unverified adapters."""
    response = client.get("/api/demo/manifest")

    assert response.status_code == 200
    body = response.json()
    assert body["api_contract_version"] == "1"
    assert body["sdk_version"] == "0.9.0b1"
    assert body["fixture_set_version"] == "2026-07-25"
    assert body["scenarios"] == ["atlas", "meridian", "northstar"]
    assert body["adapters"] == []


def test_health_reports_demo_contract():
    """Catches health responses that omit the API version clients use for compatibility."""
    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["api_contract_version"] == "1"


def test_demo_routes_reject_unknown_ids_with_structured_detail():
    """Catches routes that let unregistered scenario or adapter IDs reach a runner."""
    scenario = client.post(
        "/api/demo/scenarios/not-a-scenario/runs",
        json={"variant": "first_attempt"},
    )
    variant = client.post(
        "/api/demo/scenarios/atlas/runs",
        json={"variant": "not-a-variant"},
    )
    adapter = client.post(
        "/api/demo/adapters/bedrock/runs",
        json={"fixture_id": "valid_trace"},
    )

    for response in (scenario, variant, adapter):
        assert response.status_code == 422
        assert isinstance(response.json()["detail"], dict)
        assert response.json()["detail"]["code"] == "UNKNOWN_DEMO_ID"


def test_demo_routes_reject_request_paths():
    """Catches request models that silently accept client-selected fixture or policy paths."""
    scenario = client.post(
        "/api/demo/scenarios/atlas/runs",
        json={"variant": "first_attempt", "fixture_path": "/tmp/fixture.json"},
    )
    adapter = client.post(
        "/api/demo/adapters/bedrock/runs",
        json={"fixture_id": "valid_trace", "policy_path": "/tmp/policy.yaml"},
    )

    for response in (scenario, adapter):
        assert response.status_code == 422
        assert isinstance(response.json()["detail"], list)
        assert response.json()["detail"][0]["type"] == "extra_forbidden"
