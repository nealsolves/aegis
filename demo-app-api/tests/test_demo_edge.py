from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Awaitable, Callable
from typing import Any

from starlette.middleware.cors import CORSMiddleware

from demo_edge import DemoEdgeMiddleware, TokenBucketLimiter
from demo_limits import REQUEST_BODY_MAX_BYTES


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _scope(
    *,
    method: str = "POST",
    path: str = "/echo",
    headers: list[tuple[bytes, bytes]] | None = None,
    client: tuple[str, int] = ("8.8.8.8", 50000),
) -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "scheme": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "root_path": "",
        "headers": headers or [],
        "client": client,
        "server": ("testserver", 80),
        "state": {},
    }


def _messages(body: bytes = b"") -> list[dict[str, Any]]:
    return [{"type": "http.request", "body": body, "more_body": False}]


async def _invoke(
    app: Any,
    scope: dict[str, Any],
    messages: list[dict[str, Any]] | None = None,
    receive_override: Callable[[], Awaitable[dict[str, Any]]] | None = None,
) -> list[dict[str, Any]]:
    pending = iter(messages or _messages())

    async def receive() -> dict[str, Any]:
        if receive_override is not None:
            return await receive_override()
        try:
            return next(pending)
        except StopIteration:
            return {"type": "http.disconnect"}

    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await app(scope, receive, send)
    return sent


def _response(sent: list[dict[str, Any]]) -> tuple[int, dict[str, str], bytes]:
    start = next(message for message in sent if message["type"] == "http.response.start")
    headers = {
        key.decode("latin-1").lower(): value.decode("latin-1")
        for key, value in start["headers"]
    }
    body = b"".join(
        message.get("body", b"")
        for message in sent
        if message["type"] == "http.response.body"
    )
    return start["status"], headers, body


class RecordingApp:
    def __init__(self, response_headers: list[tuple[bytes, bytes]] | None = None) -> None:
        self.calls = 0
        self.bodies: list[bytes] = []
        self.request_ids: list[str] = []
        self.response_headers = response_headers or []

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        self.calls += 1
        message = await receive()
        self.bodies.append(message.get("body", b""))
        self.request_ids.append(scope["state"]["request_id"])
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": self.response_headers,
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})


def test_per_client_bucket_denies_without_affecting_another_client() -> None:
    clock = FakeClock()
    limiter = TokenBucketLimiter(
        clock=clock,
        client_capacity=2,
        client_refill=1.0,
        global_capacity=100,
        global_refill=100.0,
    )

    assert limiter.admit("client-a")[0]
    assert limiter.admit("client-a")[0]
    admitted, retry_after = limiter.admit("client-a")
    assert not admitted
    assert retry_after == 1
    assert limiter.admit("client-b")[0]


def test_global_denial_does_not_partially_consume_a_new_client() -> None:
    clock = FakeClock()
    limiter = TokenBucketLimiter(
        clock=clock,
        client_capacity=1,
        client_refill=0.01,
        global_capacity=1,
        global_refill=1.0,
    )

    assert limiter.admit("client-a")[0]
    assert not limiter.admit("client-b")[0]
    clock.advance(1.0)
    assert limiter.admit("client-b")[0]


def test_identity_storage_uses_one_overflow_bucket_and_prunes_idle_entries() -> None:
    clock = FakeClock()
    limiter = TokenBucketLimiter(
        clock=clock,
        client_capacity=1,
        client_refill=0.01,
        global_capacity=100,
        global_refill=100.0,
        max_identities=2,
        identity_ttl=10.0,
    )

    assert limiter.admit("client-a")[0]
    assert limiter.admit("client-b")[0]
    assert limiter.admit("overflow-one")[0]
    assert not limiter.admit("overflow-two")[0]
    clock.advance(11.0)
    assert limiter.admit("client-c")[0]


def test_oversized_declared_body_returns_413_without_reading_or_calling_inner() -> None:
    inner = RecordingApp()
    edge = DemoEdgeMiddleware(inner, allowed_origins=())

    async def forbidden_receive() -> dict[str, Any]:
        raise AssertionError("oversized declared body must not be read")

    sent = asyncio.run(
        _invoke(
            edge,
            _scope(headers=[(b"content-length", str(REQUEST_BODY_MAX_BYTES + 1).encode())]),
            receive_override=forbidden_receive,
        )
    )
    status, headers, body = _response(sent)

    assert status == 413
    assert inner.calls == 0
    assert json.loads(body)["detail"]["code"] == "REQUEST_BODY_TOO_LARGE"
    assert headers["x-request-id"] == json.loads(body)["detail"]["request_id"]


def test_streamed_body_limit_counts_across_chunks_even_with_lying_length() -> None:
    inner = RecordingApp()
    edge = DemoEdgeMiddleware(inner, allowed_origins=())
    messages = [
        {"type": "http.request", "body": b"x" * REQUEST_BODY_MAX_BYTES, "more_body": True},
        {"type": "http.request", "body": b"y", "more_body": False},
    ]

    sent = asyncio.run(
        _invoke(edge, _scope(headers=[(b"content-length", b"1")]), messages)
    )
    status, _, body = _response(sent)

    assert status == 413
    assert inner.calls == 0
    assert json.loads(body)["detail"]["code"] == "REQUEST_BODY_TOO_LARGE"


def test_invalid_or_conflicting_content_length_is_rejected_before_read() -> None:
    for headers in (
        [(b"content-length", b"-1")],
        [(b"content-length", b"abc")],
        [(b"content-length", b"1"), (b"content-length", b"2")],
    ):
        inner = RecordingApp()
        edge = DemoEdgeMiddleware(inner, allowed_origins=())

        async def forbidden_receive() -> dict[str, Any]:
            raise AssertionError("invalid content length must not be read")

        sent = asyncio.run(
            _invoke(edge, _scope(headers=headers), receive_override=forbidden_receive)
        )
        status, _, body = _response(sent)
        assert status == 400
        assert inner.calls == 0
        assert json.loads(body)["detail"]["code"] == "INVALID_CONTENT_LENGTH"


def test_non_identity_content_encoding_is_rejected_without_decompression() -> None:
    inner = RecordingApp()
    edge = DemoEdgeMiddleware(inner, allowed_origins=())
    sent = asyncio.run(
        _invoke(edge, _scope(headers=[(b"content-encoding", b"gzip")]), _messages(b"zip"))
    )
    status, _, body = _response(sent)

    assert status == 415
    assert inner.calls == 0
    assert json.loads(body)["detail"]["code"] == "UNSUPPORTED_CONTENT_ENCODING"


def test_body_deadline_covers_the_complete_receive_loop() -> None:
    inner = RecordingApp()
    edge = DemoEdgeMiddleware(inner, allowed_origins=(), body_timeout_seconds=0.01)
    blocker = asyncio.Event()

    async def slow_receive() -> dict[str, Any]:
        await blocker.wait()
        return {"type": "http.request", "body": b"", "more_body": False}

    sent = asyncio.run(_invoke(edge, _scope(), receive_override=slow_receive))
    status, _, body = _response(sent)

    assert status == 408
    assert inner.calls == 0
    assert json.loads(body)["detail"]["code"] == "REQUEST_BODY_TIMEOUT"


def test_accepted_body_is_replayed_once_with_edge_owned_request_id() -> None:
    inner = RecordingApp(response_headers=[(b"x-request-id", b"inner-value")])
    edge = DemoEdgeMiddleware(inner, allowed_origins=())
    payload = b'{"ok":true}'
    sent = asyncio.run(
        _invoke(
            edge,
            _scope(headers=[(b"x-request-id", b"caller-value")]),
            [
                {"type": "http.request", "body": payload[:4], "more_body": True},
                {"type": "http.request", "body": payload[4:], "more_body": False},
            ],
        )
    )
    status, headers, body = _response(sent)

    assert status == 200
    assert body == b"ok"
    assert inner.bodies == [payload]
    assert re.fullmatch(r"[0-9a-f]{32}", inner.request_ids[0])
    assert headers["x-request-id"] == inner.request_ids[0]
    assert headers["x-request-id"] not in {"caller-value", "inner-value"}


def test_rate_admission_wins_before_oversized_header_or_body_work() -> None:
    limiter = TokenBucketLimiter(
        client_capacity=1,
        client_refill=0.01,
        global_capacity=10,
        global_refill=10.0,
    )
    inner = RecordingApp()
    edge = DemoEdgeMiddleware(inner, allowed_origins=(), limiter=limiter)
    asyncio.run(_invoke(edge, _scope(), _messages()))

    async def forbidden_receive() -> dict[str, Any]:
        raise AssertionError("rate-limited request must not inspect the body")

    sent = asyncio.run(
        _invoke(
            edge,
            _scope(headers=[(b"content-length", str(REQUEST_BODY_MAX_BYTES + 1).encode())]),
            receive_override=forbidden_receive,
        )
    )
    status, headers, body = _response(sent)

    assert status == 429
    assert headers["retry-after"] == "100"
    assert json.loads(body)["detail"]["code"] == "RATE_LIMIT_EXCEEDED"


def test_health_and_options_bypass_rate_but_not_body_limit() -> None:
    limiter = TokenBucketLimiter(
        client_capacity=1,
        client_refill=0.01,
        global_capacity=10,
        global_refill=10.0,
    )
    inner = RecordingApp()
    edge = DemoEdgeMiddleware(inner, allowed_origins=(), limiter=limiter)

    assert _response(asyncio.run(_invoke(edge, _scope(method="GET", path="/health"))))[0] == 200
    assert _response(asyncio.run(_invoke(edge, _scope(method="GET", path="/health"))))[0] == 200
    assert _response(asyncio.run(_invoke(edge, _scope(method="OPTIONS"))))[0] == 200
    oversized_health = asyncio.run(
        _invoke(
            edge,
            _scope(
                method="GET",
                path="/health",
                headers=[(b"content-length", str(REQUEST_BODY_MAX_BYTES + 1).encode())],
            ),
        )
    )
    assert _response(oversized_health)[0] == 413
    assert _response(asyncio.run(_invoke(edge, _scope())))[0] == 200
    assert _response(asyncio.run(_invoke(edge, _scope())))[0] == 429


def test_wrong_method_on_health_consumes_rate_admission() -> None:
    limiter = TokenBucketLimiter(
        client_capacity=1,
        client_refill=0.01,
        global_capacity=10,
        global_refill=10.0,
    )
    edge = DemoEdgeMiddleware(RecordingApp(), allowed_origins=(), limiter=limiter)

    assert _response(asyncio.run(_invoke(edge, _scope(method="POST", path="/health"))))[0] == 200
    assert _response(asyncio.run(_invoke(edge, _scope())))[0] == 429


def test_direct_public_peer_cannot_change_identity_with_forwarded_header() -> None:
    limiter = TokenBucketLimiter(
        client_capacity=1,
        client_refill=0.01,
        global_capacity=10,
        global_refill=10.0,
    )
    edge = DemoEdgeMiddleware(RecordingApp(), allowed_origins=(), limiter=limiter)
    first = _scope(headers=[(b"x-forwarded-for", b"1.1.1.1")])
    second = _scope(headers=[(b"x-forwarded-for", b"2.2.2.2")])

    assert _response(asyncio.run(_invoke(edge, first)))[0] == 200
    assert _response(asyncio.run(_invoke(edge, second)))[0] == 429


def test_private_peer_uses_rightmost_valid_forwarded_address() -> None:
    limiter = TokenBucketLimiter(
        client_capacity=1,
        client_refill=0.01,
        global_capacity=10,
        global_refill=10.0,
    )
    edge = DemoEdgeMiddleware(RecordingApp(), allowed_origins=(), limiter=limiter)

    def forwarded(value: bytes) -> dict[str, Any]:
        return _scope(
            headers=[(b"x-forwarded-for", value)],
            client=("127.0.0.1", 50000),
        )

    assert _response(asyncio.run(_invoke(edge, forwarded(b"garbage, 1.1.1.1"))))[0] == 200
    assert _response(asyncio.run(_invoke(edge, forwarded(b"9.9.9.9, 1.1.1.1"))))[0] == 429
    assert _response(asyncio.run(_invoke(edge, forwarded(b"garbage, 2.2.2.2"))))[0] == 200


def test_invalid_rightmost_forwarded_token_falls_back_to_immediate_peer() -> None:
    limiter = TokenBucketLimiter(
        client_capacity=1,
        client_refill=0.01,
        global_capacity=10,
        global_refill=10.0,
    )
    edge = DemoEdgeMiddleware(RecordingApp(), allowed_origins=(), limiter=limiter)

    def forwarded(value: bytes) -> dict[str, Any]:
        return _scope(
            headers=[(b"x-forwarded-for", value)],
            client=("127.0.0.1", 50000),
        )

    first = forwarded(b"1.1.1.1, invalid-rightmost")
    second = forwarded(b"2.2.2.2, invalid-rightmost")
    assert _response(asyncio.run(_invoke(edge, first)))[0] == 200
    assert _response(asyncio.run(_invoke(edge, second)))[0] == 429


def test_edge_failures_apply_cors_only_for_an_allowlisted_origin() -> None:
    allowed = "https://allowed.example"
    edge = DemoEdgeMiddleware(RecordingApp(), allowed_origins=(allowed,))
    oversized = str(REQUEST_BODY_MAX_BYTES + 1).encode()

    allowed_sent = asyncio.run(
        _invoke(
            edge,
            _scope(headers=[(b"origin", allowed.encode()), (b"content-length", oversized)]),
        )
    )
    _, allowed_headers, _ = _response(allowed_sent)
    assert allowed_headers["access-control-allow-origin"] == allowed
    assert "Origin" in allowed_headers["vary"]
    assert allowed_headers["access-control-expose-headers"] == "X-Request-ID, Retry-After"

    denied_sent = asyncio.run(
        _invoke(
            edge,
            _scope(
                headers=[
                    (b"origin", b"https://denied.example"),
                    (b"content-length", oversized),
                ]
            ),
        )
    )
    _, denied_headers, _ = _response(denied_sent)
    assert "access-control-allow-origin" not in denied_headers


def test_preflight_is_body_bounded_then_origin_checked() -> None:
    allowed = "https://allowed.example"
    inner = CORSMiddleware(
        RecordingApp(),
        allow_origins=[allowed],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    edge = DemoEdgeMiddleware(inner, allowed_origins=(allowed,))

    def preflight(origin: str) -> dict[str, Any]:
        return _scope(
            method="OPTIONS",
            headers=[
                (b"origin", origin.encode()),
                (b"access-control-request-method", b"POST"),
            ],
        )

    allowed_sent = asyncio.run(_invoke(edge, preflight(allowed)))
    assert _response(allowed_sent)[0] == 200

    denied_sent = asyncio.run(_invoke(edge, preflight("https://denied.example")))
    status, headers, body = _response(denied_sent)
    assert status == 400
    assert "access-control-allow-origin" not in headers
    assert json.loads(body)["detail"]["code"] == "INVALID_REQUEST"


def test_unexpected_outer_failure_uses_stable_correlated_envelope() -> None:
    async def broken_app(scope: Any, receive: Any, send: Any) -> None:
        raise RuntimeError("/private/secret traceback marker")

    edge = DemoEdgeMiddleware(
        broken_app,
        allowed_origins=("https://allowed.example",),
    )
    sent = asyncio.run(
        _invoke(
            edge,
            _scope(headers=[(b"origin", b"https://allowed.example")]),
        )
    )
    status, headers, body = _response(sent)
    detail = json.loads(body)["detail"]

    assert status == 500
    assert detail["code"] == "INTERNAL_ERROR"
    assert "/private/secret" not in body.decode("utf-8")
    assert headers["x-request-id"] == detail["request_id"]
    assert headers["access-control-allow-origin"] == "https://allowed.example"
