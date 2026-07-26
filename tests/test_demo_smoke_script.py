from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Any

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.smoke_demo import ARCHITECTURE_VIEWPORTS, HttpResponse, main, parser


FRONTEND_URL = "https://pages.example/aegis/"
API_URL = "https://api.example"
STYLESHEET_URL = f"{FRONTEND_URL}assets/app.css"
MODULE_URL = f"{FRONTEND_URL}assets/app.js"
APP_SHELL = f"""<!doctype html>
<html lang="en">
  <head>
    <link rel="stylesheet" href="{STYLESHEET_URL}">
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="{MODULE_URL}"></script>
  </body>
</html>"""

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


class BrowserCheckRecorder:
    def __init__(self, error: BaseException | None = None):
        self.error = error
        self.calls: list[tuple[str, tuple[tuple[str, int, int], ...], float]] = []

    def __call__(self, frontend_url, viewports, timeout):
        self.calls.append((frontend_url, viewports, timeout))
        if self.error is not None:
            raise self.error


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
        ("GET", FRONTEND_URL): [response(200, APP_SHELL)],
        ("GET", STYLESHEET_URL): [response(200, "body { margin: 0; }")],
        ("GET", MODULE_URL): [response(200, "document.querySelector('#root')")],
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
    browser_check = BrowserCheckRecorder()

    exit_code = main(
        arguments(),
        transport=transport,
        sleep=lambda _delay: None,
        browser_check=browser_check,
    )

    assert exit_code == 0
    assert transport.calls == [
        Call("GET", FRONTEND_URL, None),
        Call("GET", STYLESHEET_URL, None),
        Call("GET", MODULE_URL, None),
        Call("GET", f"{API_URL}/health", None),
        Call("GET", f"{API_URL}/health", None),
        Call("GET", f"{API_URL}/api/demo/manifest", None),
        Call(
            "POST",
            f"{API_URL}/api/demo/scenarios/atlas/runs",
            {"variant": "corrected"},
        ),
    ]
    assert browser_check.calls == [
        (FRONTEND_URL, ARCHITECTURE_VIEWPORTS, 15.0),
    ]


def test_smoke_returns_nonzero_for_generic_html():
    """Catches an unrelated 2xx page being mistaken for the deployed app."""
    responses = successful_responses()
    responses[("GET", FRONTEND_URL)] = [
        response(200, "<!doctype html><title>Example</title><p>Hello</p>"),
    ]

    assert main(
        arguments(),
        transport=FixedTransport(responses),
        sleep=lambda _delay: None,
        browser_check=BrowserCheckRecorder(),
    ) != 0


def test_smoke_returns_nonzero_for_maintenance_html():
    """Catches a hosting maintenance page being mistaken for the deployed app."""
    responses = successful_responses()
    responses[("GET", FRONTEND_URL)] = [
        response(
            200,
            "<!doctype html><title>Maintenance</title>"
            "<div id='root'>Please try again later.</div>",
        ),
    ]

    assert main(
        arguments(),
        transport=FixedTransport(responses),
        sleep=lambda _delay: None,
        browser_check=BrowserCheckRecorder(),
    ) != 0


def test_smoke_returns_nonzero_when_a_required_asset_does_not_load():
    """Catches a Pages shell whose hashed JavaScript bundle is unavailable."""
    responses = successful_responses()
    responses[("GET", MODULE_URL)] = [response(404, "not found")]

    assert main(
        arguments(),
        transport=FixedTransport(responses),
        sleep=lambda _delay: None,
        browser_check=BrowserCheckRecorder(),
    ) != 0


def test_smoke_returns_nonzero_when_built_stylesheet_reference_is_missing():
    """Catches an incomplete production shell with only its module bundle."""
    responses = successful_responses()
    responses[("GET", FRONTEND_URL)] = [
        response(
            200,
            "<!doctype html><div id='root'></div>"
            f"<script type='module' src='{MODULE_URL}'></script>",
        ),
    ]

    assert main(
        arguments(),
        transport=FixedTransport(responses),
        sleep=lambda _delay: None,
        browser_check=BrowserCheckRecorder(),
    ) != 0


def test_smoke_returns_nonzero_when_architecture_browser_check_fails():
    """Catches an app shell that loads but cannot render the Architecture views."""
    browser_check = BrowserCheckRecorder(RuntimeError("phone layout failed"))

    assert main(
        arguments(),
        transport=FixedTransport(successful_responses()),
        sleep=lambda _delay: None,
        browser_check=browser_check,
    ) != 0
    assert browser_check.calls == [
        (FRONTEND_URL, ARCHITECTURE_VIEWPORTS, 15.0),
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


def test_smoke_returns_nonzero_when_provenance_is_absent():
    """Catches PASS evidence with no provenance record."""
    responses = successful_responses()
    artifact = {
        key: value
        for key, value in ATLAS_PASS["artifact"].items()
        if key != "provenance"
    }
    responses[("POST", f"{API_URL}/api/demo/scenarios/atlas/runs")] = [
        response(200, {**ATLAS_PASS, "artifact": artifact}),
    ]

    assert main(
        arguments(),
        transport=FixedTransport(responses),
        sleep=lambda _delay: None,
    ) != 0


def test_smoke_returns_nonzero_when_provenance_source_ids_are_empty():
    """Catches PASS evidence with an empty provenance source list."""
    responses = successful_responses()
    artifact = {
        **ATLAS_PASS["artifact"],
        "provenance": {"source_ids": []},
    }
    responses[("POST", f"{API_URL}/api/demo/scenarios/atlas/runs")] = [
        response(200, {**ATLAS_PASS, "artifact": artifact}),
    ]

    assert main(
        arguments(),
        transport=FixedTransport(responses),
        sleep=lambda _delay: None,
    ) != 0


def test_smoke_returns_nonzero_when_provenance_source_ids_are_blank():
    """Catches whitespace being accepted as artifact source provenance."""
    responses = successful_responses()
    artifact = {
        **ATLAS_PASS["artifact"],
        "provenance": {"source_ids": [" ", "\t"]},
    }
    responses[("POST", f"{API_URL}/api/demo/scenarios/atlas/runs")] = [
        response(200, {**ATLAS_PASS, "artifact": artifact}),
    ]

    assert main(
        arguments(),
        transport=FixedTransport(responses),
        sleep=lambda _delay: None,
    ) != 0


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--wake-delay", "-1"),
        ("--wake-delay", "nan"),
        ("--timeout", "0"),
        ("--timeout", "inf"),
    ],
)
def test_smoke_rejects_invalid_cli_durations(option, value):
    """Catches unbounded or invalid timing values before network work begins."""
    with pytest.raises(SystemExit):
        parser().parse_args([*arguments(), option, value])
