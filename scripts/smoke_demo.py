#!/usr/bin/env python3
"""Post-deployment contract smoke check for the public deterministic demo."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from html.parser import HTMLParser
import json
import math
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Callable, Protocol
from urllib.error import HTTPError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


API_CONTRACT_VERSION = "1"
ARCHITECTURE_VIEWPORTS = (
    ("desktop", 1440, 1000),
    ("phone", 390, 844),
)
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BROWSER_SMOKE_SCRIPT = (
    REPOSITORY_ROOT / "demo-app-react" / "scripts" / "smoke-architecture.mjs"
)


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: Any


class HttpTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        json_body: dict[str, Any] | None,
        timeout: float,
    ) -> HttpResponse: ...


class ArchitectureBrowserCheck(Protocol):
    def __call__(
        self,
        frontend_url: str,
        viewports: tuple[tuple[str, int, int], ...],
        timeout: float,
    ) -> None: ...


class UrllibTransport:
    def request(
        self,
        method: str,
        url: str,
        *,
        json_body: dict[str, Any] | None,
        timeout: float,
    ) -> HttpResponse:
        request_body = (
            json.dumps(json_body).encode("utf-8")
            if json_body is not None
            else None
        )
        headers = {"Accept": "application/json, text/html"}
        if request_body is not None:
            headers["Content-Type"] = "application/json"
        request = Request(
            url,
            data=request_body,
            headers=headers,
            method=method,
        )

        try:
            with urlopen(request, timeout=timeout) as response:
                return HttpResponse(
                    status=response.status,
                    body=_decode_body(
                        response.read(),
                        response.headers.get("Content-Type", ""),
                    ),
                )
        except HTTPError as error:
            return HttpResponse(
                status=error.code,
                body=_decode_body(
                    error.read(),
                    error.headers.get("Content-Type", ""),
                ),
            )


class SmokeFailure(RuntimeError):
    pass


class _AppShellParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.has_root = False
        self.required_assets: list[str] = []
        self.stylesheet_count = 0
        self.module_count = 0

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attributes = dict(attrs)
        if tag == "div" and attributes.get("id") == "root":
            self.has_root = True
        if tag == "link" and "stylesheet" in (
            attributes.get("rel") or ""
        ).lower().split():
            href = attributes.get("href")
            if href:
                self.required_assets.append(href)
                self.stylesheet_count += 1
        if (
            tag == "script"
            and (attributes.get("type") or "").lower() == "module"
        ):
            src = attributes.get("src")
            if src:
                self.required_assets.append(src)
                self.module_count += 1


def _decode_body(raw: bytes, content_type: str) -> Any:
    text = raw.decode("utf-8", errors="replace")
    if "json" not in content_type.lower():
        return text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _record(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SmokeFailure(f"{label} did not return a JSON object.")
    return value


def _verify_app_shell(
    transport: HttpTransport,
    frontend_url: str,
    document: str,
    *,
    timeout: float,
) -> None:
    parser = _AppShellParser()
    parser.feed(document)
    if not parser.has_root:
        raise SmokeFailure("Frontend is not the AEGIS app shell.")
    if parser.stylesheet_count == 0 or parser.module_count == 0:
        raise SmokeFailure(
            "Frontend app shell must reference its stylesheet and module assets."
        )

    frontend_origin = urlparse(frontend_url)
    asset_urls: list[str] = []
    for reference in parser.required_assets:
        asset_url = urljoin(frontend_url, reference)
        asset_origin = urlparse(asset_url)
        if (
            asset_origin.scheme,
            asset_origin.netloc,
        ) != (
            frontend_origin.scheme,
            frontend_origin.netloc,
        ):
            raise SmokeFailure(
                f"Frontend requires a cross-origin asset: {asset_url}."
            )
        if asset_url not in asset_urls:
            asset_urls.append(asset_url)

    for asset_url in asset_urls:
        response = transport.request(
            "GET",
            asset_url,
            json_body=None,
            timeout=timeout,
        )
        if not 200 <= response.status < 300:
            raise SmokeFailure(
                f"Frontend asset returned HTTP {response.status}: {asset_url}."
            )
        if not isinstance(response.body, (str, bytes)) or not response.body:
            raise SmokeFailure(f"Frontend asset was empty: {asset_url}.")


def run_architecture_browser_check(
    frontend_url: str,
    viewports: tuple[tuple[str, int, int], ...],
    timeout: float,
) -> None:
    command = [
        "node",
        str(BROWSER_SMOKE_SCRIPT),
        "--frontend-url",
        frontend_url,
        "--timeout-ms",
        str(round(timeout * 1000)),
    ]
    for name, width, height in viewports:
        command.extend(
            ["--viewport", f"{name}:{width}:{height}"],
        )

    try:
        completed = subprocess.run(
            command,
            cwd=BROWSER_SMOKE_SCRIPT.parent.parent,
            capture_output=True,
            check=False,
            text=True,
            timeout=max(timeout * len(viewports) * 4, 60),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SmokeFailure(
            f"Architecture browser check could not run: {error}"
        ) from error

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise SmokeFailure(
            f"Architecture browser check failed: {detail or 'unknown error'}"
        )


def _request_ready_health(
    transport: HttpTransport,
    health_url: str,
    *,
    attempts: int,
    delay: float,
    timeout: float,
    sleep: Callable[[float], None],
) -> dict[str, Any]:
    last_problem = "no response"

    for attempt in range(attempts):
        try:
            response = transport.request(
                "GET",
                health_url,
                json_body=None,
                timeout=timeout,
            )
            if response.status == 200:
                health = _record(response.body, "Health")
                if health.get("api_contract_version") != API_CONTRACT_VERSION:
                    raise SmokeFailure(
                        "Health contract mismatch: expected "
                        f"{API_CONTRACT_VERSION}, received "
                        f"{health.get('api_contract_version')!r}."
                    )
                if health.get("status") != "ok":
                    raise SmokeFailure(
                        f"Health returned status {health.get('status')!r}."
                    )
                if not isinstance(health.get("sdk_version"), str):
                    raise SmokeFailure("Health omitted sdk_version.")
                return health
            last_problem = f"HTTP {response.status}"
        except SmokeFailure:
            raise
        except Exception as error:
            last_problem = f"{type(error).__name__}: {error}"

        if attempt + 1 < attempts:
            sleep(delay)

    raise SmokeFailure(
        f"Demo API did not become ready after {attempts} attempts "
        f"({last_problem})."
    )


def run_smoke(
    *,
    frontend_url: str,
    api_url: str,
    wake_attempts: int,
    wake_delay: float,
    timeout: float,
    transport: HttpTransport,
    sleep: Callable[[float], None],
    browser_check: ArchitectureBrowserCheck,
) -> None:
    frontend = transport.request(
        "GET",
        frontend_url,
        json_body=None,
        timeout=timeout,
    )
    if not 200 <= frontend.status < 300:
        raise SmokeFailure(f"Frontend returned HTTP {frontend.status}.")
    if not isinstance(frontend.body, str) or not frontend.body.strip():
        raise SmokeFailure("Frontend returned an empty document.")
    _verify_app_shell(
        transport,
        frontend_url,
        frontend.body,
        timeout=timeout,
    )

    api_base = api_url.rstrip("/")
    health = _request_ready_health(
        transport,
        f"{api_base}/health",
        attempts=wake_attempts,
        delay=wake_delay,
        timeout=timeout,
        sleep=sleep,
    )

    manifest_response = transport.request(
        "GET",
        f"{api_base}/api/demo/manifest",
        json_body=None,
        timeout=timeout,
    )
    if manifest_response.status != 200:
        raise SmokeFailure(
            f"Manifest returned HTTP {manifest_response.status}."
        )
    manifest = _record(manifest_response.body, "Manifest")
    if manifest.get("api_contract_version") != API_CONTRACT_VERSION:
        raise SmokeFailure(
            "Manifest contract mismatch: expected "
            f"{API_CONTRACT_VERSION}, received "
            f"{manifest.get('api_contract_version')!r}."
        )
    if manifest.get("sdk_version") != health["sdk_version"]:
        raise SmokeFailure("Health and manifest SDK versions differ.")
    if "atlas" not in manifest.get("scenarios", []):
        raise SmokeFailure("Manifest does not publish the Atlas scenario.")

    run_response = transport.request(
        "POST",
        f"{api_base}/api/demo/scenarios/atlas/runs",
        json_body={"variant": "corrected"},
        timeout=timeout,
    )
    if run_response.status != 200:
        raise SmokeFailure(f"Atlas run returned HTTP {run_response.status}.")
    run = _record(run_response.body, "Atlas run")
    if (
        run.get("scenario_id") != "atlas"
        or run.get("variant") != "corrected"
        or run.get("decision") != "PASS"
    ):
        raise SmokeFailure("Atlas corrected did not return a PASS decision.")

    artifact = _record(run.get("artifact"), "Atlas artifact")
    if artifact.get("enforcement_result") != "PASS":
        raise SmokeFailure("Atlas artifact does not record PASS.")
    provenance = _record(artifact.get("provenance"), "Atlas provenance")
    source_ids = provenance.get("source_ids")
    if (
        not isinstance(source_ids, list)
        or not source_ids
        or not all(
            isinstance(source_id, str) and bool(source_id.strip())
            for source_id in source_ids
        )
    ):
        raise SmokeFailure("Atlas artifact has no source provenance.")

    source = _record(run.get("source"), "Atlas source")
    if source.get("sdk_version") != manifest.get("sdk_version"):
        raise SmokeFailure("Atlas source SDK version differs from manifest.")

    browser_check(frontend_url, ARCHITECTURE_VIEWPORTS, timeout)


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def _nonnegative_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0:
        raise argparse.ArgumentTypeError(
            "must be a nonnegative finite number"
        )
    return parsed


def _positive_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite number")
    return parsed


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description="Verify the deployed AEGIS demo contract and Atlas evidence.",
    )
    command.add_argument("--frontend-url", required=True)
    command.add_argument("--api-url", required=True)
    command.add_argument("--wake-attempts", type=_positive_int, default=7)
    command.add_argument(
        "--wake-delay",
        type=_nonnegative_finite_float,
        default=10.0,
    )
    command.add_argument(
        "--timeout",
        type=_positive_finite_float,
        default=15.0,
    )
    return command


def main(
    argv: list[str] | None = None,
    *,
    transport: HttpTransport | None = None,
    sleep: Callable[[float], None] = time.sleep,
    browser_check: ArchitectureBrowserCheck = run_architecture_browser_check,
) -> int:
    arguments = parser().parse_args(argv)

    try:
        run_smoke(
            frontend_url=arguments.frontend_url,
            api_url=arguments.api_url,
            wake_attempts=arguments.wake_attempts,
            wake_delay=arguments.wake_delay,
            timeout=arguments.timeout,
            transport=transport or UrllibTransport(),
            sleep=sleep,
            browser_check=browser_check,
        )
    except Exception as error:
        print(f"Demo smoke failed: {error}", file=sys.stderr)
        return 1

    print(
        "Demo smoke passed: Pages shell and assets loaded, Architecture rendered "
        "at desktop and phone sizes, API contract 1, and Atlas corrected PASS "
        "artifact verified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
