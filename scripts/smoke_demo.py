#!/usr/bin/env python3
"""Post-deployment contract smoke check for the public deterministic demo."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import sys
import time
from typing import Any, Callable, Protocol
from urllib.error import HTTPError
from urllib.request import Request, urlopen


API_CONTRACT_VERSION = "1"


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
        or not all(isinstance(source_id, str) for source_id in source_ids)
    ):
        raise SmokeFailure("Atlas artifact has no source provenance.")

    source = _record(run.get("source"), "Atlas source")
    if source.get("sdk_version") != manifest.get("sdk_version"):
        raise SmokeFailure("Atlas source SDK version differs from manifest.")


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description="Verify the deployed AEGIS demo contract and Atlas evidence.",
    )
    command.add_argument("--frontend-url", required=True)
    command.add_argument("--api-url", required=True)
    command.add_argument("--wake-attempts", type=_positive_int, default=7)
    command.add_argument("--wake-delay", type=float, default=10.0)
    command.add_argument("--timeout", type=float, default=15.0)
    return command


def main(
    argv: list[str] | None = None,
    *,
    transport: HttpTransport | None = None,
    sleep: Callable[[float], None] = time.sleep,
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
        )
    except Exception as error:
        print(f"Demo smoke failed: {error}", file=sys.stderr)
        return 1

    print(
        "Demo smoke passed: Pages loaded, API contract 1, "
        "Atlas corrected PASS artifact verified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
