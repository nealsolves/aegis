from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Any


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.smoke_demo import HttpResponse, main


FRONTEND_URL = "https://pages.example/aegis/"
API_URL = "https://api.example"

HEALTH = {
    "status": "ok",
    "api_contract_version": "1",
    "sdk_version": "0.9.0b1",
    "source": {"branch": "main", "commit": "server-commit"},
}

MANIFEST = {
    "api_contract_version": "1",
    "sdk_version": "0.9.0b1",
    "fixture_set_version": "2026-07-25",
    "scenarios": ["atlas", "meridian", "northstar"],
    "adapters": ["a2a", "bedrock", "openai_agents"],
    "source": {
        "branch": "main",
        "commit": "server-commit",
        "sdk_version": "0.9.0b1",
    },
}

ATLAS_PASS = {
    "scenario_id": "atlas",
    "variant": "corrected",
    "fixture_version": "2026-07-25.1",
    "transcript": [],
    "gates": [],
    "decision": "PASS",
    "artifact": {
        "enforcement_result": "PASS",
        "input_checksum": "a" * 64,
        "output_checksum": "b" * 64,
        "provenance": {"source_ids": ["atlas-policy-BRV-04"]},
    },
    "workflow_artifact": None,
    "error": None,
    "source": {
        "branch": "main",
        "commit": "server-commit",
        "sdk_version": "0.9.0b1",
    },
}


@dataclass(frozen=True)
class Call:
    method: str
    url: str
    json_body: dict[str, Any] | None


class FixedTransport:
    def __init__(self, responses):
        self.responses = defaultdict(list)
        for key, values in responses.items():
            self.responses[key].extend(values)
        self.calls: list[Call] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        json_body: dict[str, Any] | None,
        timeout: float,
    ) -> HttpResponse:
        del timeout
        self.calls.append(Call(method, url, json_body))
        response = self.responses[(method, url)].pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def response(status: int, body: Any) -> HttpResponse:
    return HttpResponse(status=status, body=body)


def arguments() -> list[str]:
    return [
        "--frontend-url",
        FRONTEND_URL,
        "--api-url",
        API_URL,
        "--wake-attempts",
        "3",
        "--wake-delay",
        "0",
    ]


def successful_responses():
    return {
        ("GET", FRONTEND_URL): [response(200, "<!doctype html><title>AEGIS</title>")],
        ("GET", f"{API_URL}/health"): [
            response(503, {"detail": "starting"}),
            response(200, HEALTH),
        ],
        ("GET", f"{API_URL}/api/demo/manifest"): [response(200, MANIFEST)],
        ("POST", f"{API_URL}/api/demo/scenarios/atlas/runs"): [
            response(200, ATLAS_PASS),
        ],
    }


def test_smoke_loads_pages_waits_for_render_and_requires_atlas_provenance():
    """Catches a smoke command that skips wake-up retry or PASS provenance."""
    transport = FixedTransport(successful_responses())

    exit_code = main(arguments(), transport=transport, sleep=lambda _delay: None)

    assert exit_code == 0
    assert transport.calls == [
        Call("GET", FRONTEND_URL, None),
        Call("GET", f"{API_URL}/health", None),
        Call("GET", f"{API_URL}/health", None),
        Call("GET", f"{API_URL}/api/demo/manifest", None),
        Call(
            "POST",
            f"{API_URL}/api/demo/scenarios/atlas/runs",
            {"variant": "corrected"},
        ),
    ]


def test_smoke_returns_nonzero_for_contract_mismatch():
    """Catches acceptance of a backend contract the deployed frontend cannot use."""
    responses = successful_responses()
    responses[("GET", f"{API_URL}/health")] = [
        response(200, {**HEALTH, "api_contract_version": "2"}),
    ]
    transport = FixedTransport(responses)

    assert main(
        arguments(),
        transport=transport,
        sleep=lambda _delay: None,
    ) != 0


def test_smoke_returns_nonzero_after_bounded_api_timeouts():
    """Catches an unbounded or falsely successful Render wake-up loop."""
    responses = successful_responses()
    responses[("GET", f"{API_URL}/health")] = [
        TimeoutError("timed out"),
        TimeoutError("timed out"),
        TimeoutError("timed out"),
    ]
    transport = FixedTransport(responses)

    assert main(
        arguments(),
        transport=transport,
        sleep=lambda _delay: None,
    ) != 0
    assert [
        call for call in transport.calls if call.url.endswith("/health")
    ] == [
        Call("GET", f"{API_URL}/health", None),
        Call("GET", f"{API_URL}/health", None),
        Call("GET", f"{API_URL}/health", None),
    ]


def test_smoke_returns_nonzero_when_pass_artifact_is_missing():
    """Catches PASS being reported without the invocation evidence it promises."""
    responses = successful_responses()
    responses[("POST", f"{API_URL}/api/demo/scenarios/atlas/runs")] = [
        response(200, {**ATLAS_PASS, "artifact": None}),
    ]
    transport = FixedTransport(responses)

    assert main(
        arguments(),
        transport=transport,
        sleep=lambda _delay: None,
    ) != 0
