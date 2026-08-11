from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import main
from bounded_yaml import load_bounded_yaml
from demo_errors import DemoPublicError
from demo_limits import REQUEST_BODY_MAX_BYTES
from loaders import InMemoryPolicyLoader


def _boom() -> None:
    raise RuntimeError("/private/secret-policy.yaml traceback marker")


_inner_api = getattr(main, "api", main.app)
if not any(getattr(route, "path", None) == "/_security-test/boom" for route in _inner_api.routes):
    _inner_api.add_api_route("/_security-test/boom", _boom, methods=["GET"])

client = TestClient(main.app, raise_server_exceptions=False)


def _issue_59_reproduction() -> str:
    width = 6
    lines: list[str] = []
    previous: str | None = None
    for name in "abcdefg":
        values = ["x"] * width if previous is None else [f"*{previous}"] * width
        lines.append(f"{name}: &{name} [" + ", ".join(values) + "]")
        previous = name
    body = "\n".join(lines) + "\n"
    assert len(body.encode("utf-8")) == 211
    return body


def _assert_safe_error(response, status: int, code: str) -> str:
    assert response.status_code == status
    detail = response.json()["detail"]
    assert set(detail) == {"code", "message", "request_id"}
    assert detail["code"] == code
    assert response.headers["x-request-id"] == detail["request_id"]
    assert re.fullmatch(r"[0-9a-f]{32}", detail["request_id"])
    return detail["request_id"]


def test_declared_body_limit_runs_before_json_and_pydantic() -> None:
    marker = b"/private/oversized-secret"
    response = client.post(
        "/api/enforce",
        content=marker + (b"x" * REQUEST_BODY_MAX_BYTES),
        headers={"Content-Type": "application/json"},
    )

    _assert_safe_error(response, 413, "REQUEST_BODY_TOO_LARGE")
    assert marker.decode() not in response.text


def test_validation_error_does_not_echo_hostile_input() -> None:
    marker = "/private/secret-policy.yaml"
    response = client.post("/api/enforce", json={"scenario_key": marker})

    _assert_safe_error(response, 422, "INVALID_REQUEST")
    assert marker not in response.text


def test_malformed_json_uses_stable_invalid_request() -> None:
    marker = "/private/malformed-marker"
    response = client.post(
        "/api/enforce",
        content=b'{"scenario_key": "' + marker.encode(),
        headers={"Content-Type": "application/json"},
    )

    _assert_safe_error(response, 422, "INVALID_REQUEST")
    assert marker not in response.text


def test_unknown_route_and_method_have_stable_codes() -> None:
    _assert_safe_error(client.get("/api/not-a-real-route"), 404, "NOT_FOUND")
    _assert_safe_error(client.delete("/health"), 405, "METHOD_NOT_ALLOWED")


def test_unexpected_route_failure_is_normalized_and_correlated_in_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.ERROR, logger="aegis.demo"):
        response = client.get("/_security-test/boom")

    request_id = _assert_safe_error(response, 500, "INTERNAL_ERROR")
    assert "/private/secret-policy.yaml" not in response.text
    matching = [record for record in caplog.records if record.request_id == request_id]
    assert matching
    assert matching[-1].public_code == "INTERNAL_ERROR"


def test_success_replaces_caller_request_id_and_adds_edge_id() -> None:
    response = client.get("/health", headers={"X-Request-ID": "caller-controlled"})

    assert response.status_code == 200
    assert re.fullmatch(r"[0-9a-f]{32}", response.headers["x-request-id"])
    assert response.headers["x-request-id"] != "caller-controlled"


def test_edge_failure_has_cors_for_allowed_origin_only() -> None:
    oversized = b"x" * (REQUEST_BODY_MAX_BYTES + 1)
    allowed = client.post(
        "/api/enforce",
        content=oversized,
        headers={"Origin": "https://nealsolves.github.io"},
    )
    denied = client.post(
        "/api/enforce",
        content=oversized,
        headers={"Origin": "https://attacker.example"},
    )

    _assert_safe_error(allowed, 413, "REQUEST_BODY_TOO_LARGE")
    assert allowed.headers["access-control-allow-origin"] == "https://nealsolves.github.io"
    assert allowed.headers["access-control-expose-headers"] == "X-Request-ID, Retry-After"
    _assert_safe_error(denied, 413, "REQUEST_BODY_TOO_LARGE")
    assert "access-control-allow-origin" not in denied.headers


def test_error_envelope_contains_no_legacy_free_form_detail() -> None:
    response = client.post(
        "/api/sign/enforce",
        content=json.dumps({"scenario_key": "signing_basic", "key": "not-hex"}),
        headers={"Content-Type": "application/json"},
    )

    _assert_safe_error(response, 422, "INVALID_REQUEST")
    assert "not-hex" not in response.text


def test_exact_issue_59_yaml_is_rejected_without_amplified_response() -> None:
    response = client.post(
        "/api/policy/load-inmemory",
        json={"yaml_text": _issue_59_reproduction()},
    )

    _assert_safe_error(response, 422, "YAML_LIMIT_EXCEEDED")
    assert len(response.content) < 1_000


def test_compose_applies_the_same_bound_to_each_document() -> None:
    response = client.post(
        "/api/compose",
        json={
            "parent_yaml": "roles: [reviewer]\n",
            "child_yaml": _issue_59_reproduction(),
            "strategy": "intersect",
        },
    )

    _assert_safe_error(response, 422, "YAML_LIMIT_EXCEEDED")
    assert len(response.content) < 1_000


def test_malformed_yaml_does_not_return_parser_coordinates_or_snippets() -> None:
    marker = "/private/parser-marker"
    response = client.post(
        "/api/policy/load-inmemory",
        json={"yaml_text": f"value: [{marker}"},
    )

    _assert_safe_error(response, 422, "YAML_INVALID")
    assert marker not in response.text
    assert "column" not in response.text.lower()


def test_inmemory_loader_is_bounded_and_returns_detached_mappings() -> None:
    with pytest.raises(DemoPublicError) as caught:
        InMemoryPolicyLoader(_issue_59_reproduction())
    assert caught.value.code == "YAML_LIMIT_EXCEEDED"

    loader = InMemoryPolicyLoader("roles: [reviewer]\n")
    first = loader.load("inline")
    first["roles"].append("mutated")
    assert loader.load("inline") == {"roles": ["reviewer"]}


def test_disk_policy_display_uses_bounded_yaml(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_root = tmp_path / "policies"
    policy_root.mkdir()
    (policy_root / "hostile.yaml").write_text(_issue_59_reproduction(), encoding="utf-8")
    monkeypatch.setattr(main, "SAMPLE_POLICIES_DIR", policy_root)

    response = client.post("/api/policy/load", json={"policy_name": "hostile.yaml"})

    _assert_safe_error(response, 422, "YAML_LIMIT_EXCEEDED")
    assert len(response.content) < 1_000


def test_all_checked_in_demo_policies_fit_the_bounded_contract() -> None:
    demo_root = main.SAMPLE_POLICIES_DIR.parent
    paths = sorted((demo_root / "sample_policies").glob("*.yaml"))
    paths += sorted((demo_root / "demo_policies").glob("*.yaml"))
    assert paths

    for path in paths:
        loaded = load_bounded_yaml(path.read_text(encoding="utf-8"))
        assert isinstance(loaded, dict), path.name
