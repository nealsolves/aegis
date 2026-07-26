"""PR-11 maintained demo lab API coverage."""
from __future__ import annotations

import inspect
import re
from pathlib import Path

from fastapi.testclient import TestClient

import main
from main import app


client = TestClient(app)


def test_demo_api_imports_and_health_route():
    assert app.title == "AEGIS Demo API"
    assert app.version == "0.9.0b1"
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "api_contract_version": "1",
        "sdk_version": "0.9.0b1",
        "source": {
            "branch": None,
            "commit": None,
        },
    }


def test_all_existing_lab_routes_return_deterministic_shapes():
    calls = [
        ("post", "/api/enforce", {"scenario_key": "low_risk_faq", "mode": "risk_scored", "flow": "unified"}),
        ("post", "/api/enforce", {"scenario_key": "low_risk_faq", "mode": "risk_scored", "flow": "split"}),
        ("post", "/api/sign/generate-key", None),
        ("post", "/api/lab8/query-kb", {"scenario_key": "kb_sourced_pass"}),
        ("post", "/api/lab9/compare", {"scenario_key": "low_risk_faq"}),
        ("post", "/api/lab10/split-trace", {"scenario_key": "low_risk_faq"}),
    ]
    for method, path, body in calls:
        response = getattr(client, method)(path, json=body) if body is not None else getattr(client, method)(path)
        assert response.status_code == 200, f"{path}: {response.text}"
        assert isinstance(response.json(), dict)


def test_workflow_lab_success_failure_diagnosis_fix_and_trace_paths():
    minimal = client.post("/api/workflow/v090/run", json={"scenario": "minimal"})
    assert minimal.status_code == 200
    assert minimal.json()["artifact"]["status"] == "COMPLETED"
    assert len(minimal.json()["artifact"]["steps"]) == 2

    failure = client.post("/api/workflow/v090/run", json={"scenario": "failure"})
    assert failure.status_code == 200
    failure_body = failure.json()
    assert failure_body["artifact"]["status"] == "FAILED"
    assert failure_body["error"]
    assert failure_body["run_id"]

    diagnosis = client.get(f"/api/workflow/v090/diagnose?run_id={failure_body['run_id']}")
    assert diagnosis.status_code == 200
    findings = diagnosis.json()["findings"]
    assert "WORKFLOW_SOURCE_REQUIRED" in [finding["code"] for finding in findings]
    assert all(finding.get("next_action") for finding in findings)

    fixed = client.post(
        "/api/workflow/v090/run",
        json={"scenario": "regulated", "run_id": failure_body["run_id"]},
    )
    assert fixed.status_code == 200
    assert fixed.json()["artifact"]["status"] == "COMPLETED"
    assert fixed.json()["error"] is None

    trace = client.get("/api/workflow/v090/trace")
    assert trace.status_code == 200
    trace_body = trace.json()
    assert trace_body["traces"][0]["status"] == "COMPLETED"
    assert trace_body["traces"][0]["unresolved_checksums"] == []


def test_demo_api_routes_do_not_require_external_credentials(monkeypatch):
    for name in [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "A2A_ENDPOINT",
    ]:
        monkeypatch.delenv(name, raising=False)

    response = client.post("/api/workflow/v090/run", json={"scenario": "standard"})
    assert response.status_code == 200
    assert response.json()["artifact"]["status"] == "COMPLETED"


def test_demo_api_uses_public_aegis_imports_only():
    demo_files = [
        Path(main.__file__),
        Path(main.__file__).with_name("workflow_routes.py"),
    ]
    for path in demo_files:
        source = path.read_text(encoding="utf-8")
        assert not re.search(r"^\s*(?:from|import)\s+aegis\._internal\b", source, flags=re.MULTILINE)


def test_workflow_routes_are_real_backend_behavior_not_static_success():
    import workflow_routes

    source = inspect.getsource(workflow_routes.run_workflow)
    assert "AEGIS()" in source
    assert ".open_session(" in source
    assert "status\": \"COMPLETED\"" not in source
