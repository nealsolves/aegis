#!/usr/bin/env python3
"""API-only adversarial smoke checks for the hardened public demo edge."""

from __future__ import annotations

import argparse
import http.client
import json
import re
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlsplit


BODY_LIMIT = 65_536
ALLOWED_ORIGIN = "https://nealsolves.github.io"
UNKNOWN_ORIGIN = "https://attacker.example"
HOSTILE_MARKER = "/private/aegis-demo-smoke-secret"
REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")


class SmokeFailure(RuntimeError):
    pass


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str]
    body: bytes

    def json(self) -> object:
        try:
            return json.loads(self.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SmokeFailure(f"HTTP {self.status} did not return JSON") from exc


class Client:
    def __init__(self, api_url: str, timeout: float) -> None:
        parsed = urlsplit(api_url.rstrip("/"))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise SmokeFailure("--api-url must be an absolute HTTP(S) URL")
        self._scheme = parsed.scheme
        self._host = parsed.hostname
        self._port = parsed.port
        self._prefix = parsed.path.rstrip("/")
        self._timeout = timeout

    def _connection(self) -> http.client.HTTPConnection:
        cls = (
            http.client.HTTPSConnection
            if self._scheme == "https"
            else http.client.HTTPConnection
        )
        return cls(self._host, self._port, timeout=self._timeout)

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes = b"",
        headers: Mapping[str, str] | None = None,
        chunked: bool = False,
    ) -> Response:
        connection = self._connection()
        request_headers = dict(headers or {})
        try:
            connection.request(
                method,
                self._prefix + path,
                body=body,
                headers=request_headers,
                encode_chunked=chunked,
            )
            raw = connection.getresponse()
            response = Response(
                raw.status,
                {key.lower(): value for key, value in raw.getheaders()},
                raw.read(),
            )
        finally:
            connection.close()
        if HOSTILE_MARKER.encode() in response.body:
            raise SmokeFailure(f"HTTP {response.status} reflected the hostile marker")
        return response

    def json_request(
        self,
        method: str,
        path: str,
        payload: object,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> Response:
        merged = {"Content-Type": "application/json", **dict(headers or {})}
        return self.request(
            method,
            path,
            body=json.dumps(payload).encode(),
            headers=merged,
        )


def issue_59_payload() -> str:
    lines: list[str] = []
    previous: str | None = None
    for name in "abcdefg":
        values = ["x"] * 6 if previous is None else [f"*{previous}"] * 6
        lines.append(f"{name}: &{name} [" + ", ".join(values) + "]")
        previous = name
    payload = "\n".join(lines) + "\n"
    if len(payload.encode()) != 211:
        raise AssertionError("issue #59 reproduction changed")
    return payload


def require_status(response: Response, expected: int, label: str) -> None:
    if response.status != expected:
        raise SmokeFailure(f"{label}: expected HTTP {expected}, got {response.status}")


def require_safe_error(response: Response, status: int, code: str, label: str) -> None:
    require_status(response, status, label)
    body = response.json()
    if not isinstance(body, dict) or set(body) != {"detail"}:
        raise SmokeFailure(f"{label}: unexpected top-level error fields")
    detail = body["detail"]
    if not isinstance(detail, dict) or set(detail) != {"code", "message", "request_id"}:
        raise SmokeFailure(f"{label}: unsafe error envelope")
    request_id = detail.get("request_id")
    if detail.get("code") != code or not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
        raise SmokeFailure(f"{label}: invalid code or request ID")
    if response.headers.get("x-request-id") != request_id:
        raise SmokeFailure(f"{label}: request ID header/body mismatch")


def run(args: argparse.Namespace) -> None:
    client = Client(args.api_url, args.timeout)

    health = client.request("GET", "/health")
    require_status(health, 200, "health")
    if not isinstance(health.json(), dict) or health.json().get("status") != "ok":
        raise SmokeFailure("health: invalid response")

    declared = client.request(
        "POST",
        "/api/policy/load-inmemory",
        body=b"x" * (BODY_LIMIT + 1),
        headers={"Content-Type": "application/json"},
    )
    require_safe_error(declared, 413, "REQUEST_BODY_TOO_LARGE", "declared body")

    streamed = client.request(
        "POST",
        "/api/policy/load-inmemory",
        body=b"x" * (BODY_LIMIT + 1),
        headers={"Content-Type": "application/json", "Transfer-Encoding": "chunked"},
        chunked=True,
    )
    require_safe_error(streamed, 413, "REQUEST_BODY_TOO_LARGE", "streamed body")

    malformed = client.json_request(
        "POST",
        "/api/policy/load-inmemory",
        {"yaml_text": f"value: [{HOSTILE_MARKER}"},
        headers={"Origin": ALLOWED_ORIGIN},
    )
    require_safe_error(malformed, 422, "YAML_INVALID", "malformed YAML")
    if malformed.headers.get("access-control-allow-origin") != ALLOWED_ORIGIN:
        raise SmokeFailure("allowed origin did not receive CORS on failure")

    expanding = client.json_request(
        "POST",
        "/api/policy/load-inmemory",
        {"yaml_text": issue_59_payload()},
        headers={"Origin": UNKNOWN_ORIGIN},
    )
    require_safe_error(expanding, 422, "YAML_LIMIT_EXCEEDED", "expanding YAML")
    if "access-control-allow-origin" in expanding.headers:
        raise SmokeFailure("unknown origin received an allow-origin header")

    valid = client.json_request(
        "POST",
        "/api/policy/load-inmemory",
        {"yaml_text": "roles: [reviewer]\n"},
    )
    require_status(valid, 200, "valid YAML")
    if not isinstance(valid.json(), dict) or valid.json().get("error") is not None:
        raise SmokeFailure("valid YAML flow did not complete")

    # Run rate exhaustion last: every prior assertion must remain observable.
    denied = False
    for index in range(args.rate_probe_count):
        headers = {}
        if args.expect_forwarding_proxy:
            headers["X-Forwarded-For"] = f"198.51.100.{index % 250 + 1}"
        response = client.request("GET", "/api/scenarios", headers=headers)
        if response.status == 429:
            require_safe_error(response, 429, "RATE_LIMIT_EXCEEDED", "rate limit")
            denied = True
            break
        require_status(response, 200, "rate probe")
    if not denied:
        raise SmokeFailure("rate probe did not reach a deterministic 429")


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("--api-url", required=True)
    command.add_argument("--timeout", type=positive_float, default=10.0)
    command.add_argument("--rate-probe-count", type=positive_int, default=40)
    command.add_argument("--expect-forwarding-proxy", action="store_true")
    return command


def main() -> int:
    try:
        run(parser().parse_args())
    except (OSError, SmokeFailure) as exc:
        print(f"security smoke failed: {exc}", flush=True)
        return 1
    print("security smoke passed", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
