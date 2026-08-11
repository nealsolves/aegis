"""Dependency-free ASGI admission controls for the public demo service."""

from __future__ import annotations

import asyncio
import ipaddress
import math
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from demo_errors import (
    REQUEST_ID,
    log_internal_failure,
    public_error_response,
    safe_demo_message,
)
from demo_limits import (
    CLIENT_RATE_CAPACITY,
    CLIENT_RATE_REFILL_PER_SECOND,
    GLOBAL_RATE_CAPACITY,
    GLOBAL_RATE_REFILL_PER_SECOND,
    RATE_LIMIT_IDENTITY_TTL_SECONDS,
    RATE_LIMIT_MAX_IDENTITIES,
    REQUEST_BODY_MAX_BYTES,
    REQUEST_BODY_READ_TIMEOUT_SECONDS,
)


_DECIMAL_RE = re.compile(r"^[0-9]+$")
_EXPOSE_HEADERS = "X-Request-ID, Retry-After"


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated_at: float
    last_seen: float


class TokenBucketLimiter:
    """Bounded process-local client and global token buckets."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        client_capacity: int = CLIENT_RATE_CAPACITY,
        client_refill: float = CLIENT_RATE_REFILL_PER_SECOND,
        global_capacity: int = GLOBAL_RATE_CAPACITY,
        global_refill: float = GLOBAL_RATE_REFILL_PER_SECOND,
        max_identities: int = RATE_LIMIT_MAX_IDENTITIES,
        identity_ttl: float = RATE_LIMIT_IDENTITY_TTL_SECONDS,
    ) -> None:
        if min(client_capacity, global_capacity, max_identities) < 1:
            raise ValueError("rate-limit capacities must be positive")
        if min(client_refill, global_refill, identity_ttl) <= 0:
            raise ValueError("rate-limit refill and TTL values must be positive")

        self._clock = clock
        self._client_capacity = float(client_capacity)
        self._client_refill = client_refill
        self._global_capacity = float(global_capacity)
        self._global_refill = global_refill
        self._max_identities = max_identities
        self._identity_ttl = identity_ttl
        self._lock = threading.Lock()
        now = clock()
        self._global = _Bucket(self._global_capacity, now, now)
        self._overflow = _Bucket(self._client_capacity, now, now)
        self._clients: dict[str, _Bucket] = {}

    @staticmethod
    def _refill(bucket: _Bucket, now: float, capacity: float, rate: float) -> None:
        elapsed = max(0.0, now - bucket.updated_at)
        bucket.tokens = min(capacity, bucket.tokens + elapsed * rate)
        bucket.updated_at = now

    def _admit(self, identity: str) -> tuple[bool, int, bool]:
        with self._lock:
            now = self._clock()
            expired = [
                key
                for key, bucket in self._clients.items()
                if now - bucket.last_seen >= self._identity_ttl
            ]
            for key in expired:
                del self._clients[key]

            overflow = False
            client = self._clients.get(identity)
            if client is None:
                if len(self._clients) < self._max_identities:
                    client = _Bucket(self._client_capacity, now, now)
                    self._clients[identity] = client
                else:
                    client = self._overflow
                    overflow = True

            self._refill(client, now, self._client_capacity, self._client_refill)
            self._refill(self._global, now, self._global_capacity, self._global_refill)
            client.last_seen = now
            self._global.last_seen = now

            waits: list[float] = []
            if client.tokens < 1.0:
                waits.append((1.0 - client.tokens) / self._client_refill)
            if self._global.tokens < 1.0:
                waits.append((1.0 - self._global.tokens) / self._global_refill)
            if waits:
                return False, max(1, math.ceil(max(waits))), overflow

            client.tokens -= 1.0
            self._global.tokens -= 1.0
            return True, 0, overflow

    def admit(self, identity: str) -> tuple[bool, int]:
        admitted, retry_after, _ = self._admit(identity)
        return admitted, retry_after

    def admit_detailed(self, identity: str) -> tuple[bool, int, bool]:
        """Return admission plus whether bounded overflow storage was used."""

        return self._admit(identity)


class _BodyTooLarge(Exception):
    pass


class _InvalidBodyMessage(Exception):
    pass


class _ClientDisconnected(Exception):
    pass


def _header_values(scope: Scope, name: bytes) -> list[str]:
    return [
        value.decode("latin-1").strip()
        for key, value in scope.get("headers", [])
        if key.lower() == name
    ]


def _single_header(scope: Scope, name: bytes) -> str | None:
    values = _header_values(scope, name)
    if len(values) != 1:
        return None
    return values[0]


def _content_length(scope: Scope) -> int | None:
    values = _header_values(scope, b"content-length")
    if not values:
        return None
    if any(not _DECIMAL_RE.fullmatch(value) for value in values):
        raise ValueError
    if len(set(values)) != 1:
        raise ValueError
    return int(values[0])


def _has_supported_content_encoding(scope: Scope) -> bool:
    values = _header_values(scope, b"content-encoding")
    if not values:
        return True
    codings = [part.strip().lower() for value in values for part in value.split(",")]
    return bool(codings) and all(coding == "identity" for coding in codings)


def _client_identity(scope: Scope) -> tuple[str, str]:
    client = scope.get("client")
    if not client:
        return "unknown", "unknown"
    try:
        peer = ipaddress.ip_address(client[0])
    except ValueError:
        return "unknown", "unknown"

    if peer.is_private or peer.is_loopback:
        forwarded = ",".join(_header_values(scope, b"x-forwarded-for"))
        candidates = [candidate.strip() for candidate in forwarded.split(",") if candidate.strip()]
        if candidates:
            try:
                address = ipaddress.ip_address(candidates[-1])
            except ValueError:
                pass
            else:
                return str(address), "forwarded-rightmost"
    return str(peer), "direct"


class DemoEdgeMiddleware:
    """Apply request admission before CORS and FastAPI parsing."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        allowed_origins: tuple[str, ...],
        limiter: TokenBucketLimiter | None = None,
        body_timeout_seconds: float = REQUEST_BODY_READ_TIMEOUT_SECONDS,
    ) -> None:
        self._app = app
        self._allowed_origins = frozenset(allowed_origins)
        self._limiter = limiter or TokenBucketLimiter()
        self._body_timeout_seconds = body_timeout_seconds

    def _cors_headers(self, scope: Scope) -> dict[str, str]:
        origin = _single_header(scope, b"origin")
        if origin is None or origin not in self._allowed_origins:
            return {}
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Expose-Headers": _EXPOSE_HEADERS,
            "Vary": "Origin",
        }

    async def _emit_error(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        request_id: str,
        status_code: int,
        code: str,
        operation: str,
        identity_source: str,
        error: BaseException | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        response_headers = {**self._cors_headers(scope), **dict(headers or {})}
        log_internal_failure(
            request_id=request_id,
            operation=operation,
            error=error,
            public_code=code,
            method=scope.get("method"),
            identity_source=identity_source,
        )
        response = public_error_response(
            status_code=status_code,
            code=code,
            message=safe_demo_message(code),
            request_id=request_id,
            headers=response_headers,
        )
        await response(scope, receive, send)

    @staticmethod
    async def _collect_body(receive: Receive) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            message_type = message.get("type")
            if message_type == "http.disconnect":
                raise _ClientDisconnected
            if message_type != "http.request":
                raise _InvalidBodyMessage
            body = message.get("body", b"")
            if not isinstance(body, bytes):
                raise _InvalidBodyMessage
            total += len(body)
            if total > REQUEST_BODY_MAX_BYTES:
                raise _BodyTooLarge
            chunks.append(body)
            if not message.get("more_body", False):
                return b"".join(chunks)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        request_id = secrets.token_hex(16)
        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        identity, identity_source = _client_identity(scope)
        state["limiter_identity_source"] = identity_source
        token = REQUEST_ID.set(request_id)

        try:
            method = scope.get("method", "")
            rate_exempt = method == "OPTIONS" or (
                method == "GET" and scope.get("path") == "/health"
            )
            if not rate_exempt:
                admitted, retry_after, used_overflow = self._limiter.admit_detailed(identity)
                if used_overflow:
                    identity_source = "overflow"
                    state["limiter_identity_source"] = identity_source
                if not admitted:
                    await self._emit_error(
                        scope,
                        receive,
                        send,
                        request_id=request_id,
                        status_code=429,
                        code="RATE_LIMIT_EXCEEDED",
                        operation="rate_admission",
                        identity_source=identity_source,
                        headers={"Retry-After": str(retry_after)},
                    )
                    return

            try:
                declared_length = _content_length(scope)
            except ValueError as error:
                await self._emit_error(
                    scope,
                    receive,
                    send,
                    request_id=request_id,
                    status_code=400,
                    code="INVALID_CONTENT_LENGTH",
                    operation="content_length",
                    identity_source=identity_source,
                    error=error,
                )
                return

            if declared_length is not None and declared_length > REQUEST_BODY_MAX_BYTES:
                await self._emit_error(
                    scope,
                    receive,
                    send,
                    request_id=request_id,
                    status_code=413,
                    code="REQUEST_BODY_TOO_LARGE",
                    operation="declared_body_limit",
                    identity_source=identity_source,
                )
                return

            if not _has_supported_content_encoding(scope):
                await self._emit_error(
                    scope,
                    receive,
                    send,
                    request_id=request_id,
                    status_code=415,
                    code="UNSUPPORTED_CONTENT_ENCODING",
                    operation="content_encoding",
                    identity_source=identity_source,
                )
                return

            try:
                body = await asyncio.wait_for(
                    self._collect_body(receive),
                    timeout=self._body_timeout_seconds,
                )
            except _BodyTooLarge:
                await self._emit_error(
                    scope,
                    receive,
                    send,
                    request_id=request_id,
                    status_code=413,
                    code="REQUEST_BODY_TOO_LARGE",
                    operation="streamed_body_limit",
                    identity_source=identity_source,
                )
                return
            except asyncio.TimeoutError as error:
                await self._emit_error(
                    scope,
                    receive,
                    send,
                    request_id=request_id,
                    status_code=408,
                    code="REQUEST_BODY_TIMEOUT",
                    operation="body_receive_timeout",
                    identity_source=identity_source,
                    error=error,
                )
                return
            except _ClientDisconnected:
                return
            except _InvalidBodyMessage as error:
                await self._emit_error(
                    scope,
                    receive,
                    send,
                    request_id=request_id,
                    status_code=400,
                    code="INVALID_REQUEST",
                    operation="body_receive",
                    identity_source=identity_source,
                    error=error,
                )
                return

            is_preflight = (
                method == "OPTIONS"
                and bool(_header_values(scope, b"origin"))
                and bool(_header_values(scope, b"access-control-request-method"))
            )
            if is_preflight:
                origin = _single_header(scope, b"origin")
                if origin not in self._allowed_origins:
                    await self._emit_error(
                        scope,
                        receive,
                        send,
                        request_id=request_id,
                        status_code=400,
                        code="INVALID_REQUEST",
                        operation="cors_preflight",
                        identity_source=identity_source,
                    )
                    return

            replayed = False

            async def replay_receive() -> Message:
                nonlocal replayed
                if replayed:
                    return {"type": "http.disconnect"}
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}

            response_started = False

            async def send_with_request_id(message: Message) -> None:
                nonlocal response_started
                if message["type"] == "http.response.start":
                    response_started = True
                    outgoing = dict(message)
                    outgoing["headers"] = [
                        (key, value)
                        for key, value in message.get("headers", [])
                        if key.lower() != b"x-request-id"
                    ] + [(b"x-request-id", request_id.encode("ascii"))]
                    await send(outgoing)
                    return
                await send(message)

            try:
                await self._app(scope, replay_receive, send_with_request_id)
            except Exception as error:
                log_internal_failure(
                    request_id=request_id,
                    operation="outer_application",
                    error=error,
                    public_code="INTERNAL_ERROR",
                    method=method,
                    identity_source=identity_source,
                )
                if response_started:
                    raise
                response = public_error_response(
                    status_code=500,
                    code="INTERNAL_ERROR",
                    message=safe_demo_message("INTERNAL_ERROR"),
                    request_id=request_id,
                    headers=self._cors_headers(scope),
                )
                await response(scope, replay_receive, send)
        finally:
            REQUEST_ID.reset(token)
