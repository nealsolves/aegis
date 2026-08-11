"""Stable public errors and correlated internal diagnostics for the demo API."""

from __future__ import annotations

import logging
import re
import secrets
from contextvars import ContextVar
from types import MappingProxyType
from typing import Any, Mapping

from starlette.responses import JSONResponse

from demo_limits import INTERNAL_DIAGNOSTIC_MAX_BYTES


REQUEST_ID: ContextVar[str | None] = ContextVar("demo_request_id", default=None)

_REQUEST_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_PUBLIC_MESSAGES = MappingProxyType(
    {
        "INVALID_REQUEST": "Request is invalid.",
        "INVALID_CONTENT_LENGTH": "Content-Length is invalid.",
        "NOT_FOUND": "The requested demo resource was not found.",
        "METHOD_NOT_ALLOWED": "The request method is not allowed.",
        "REQUEST_BODY_TIMEOUT": "Request body was not received in time.",
        "REQUEST_BODY_TOO_LARGE": "Request body exceeds the demo limit.",
        "UNSUPPORTED_CONTENT_ENCODING": "Compressed request bodies are not supported.",
        "YAML_INVALID": "YAML input is invalid.",
        "YAML_UNSUPPORTED_VALUE": "YAML input contains an unsupported value.",
        "YAML_CYCLE_REJECTED": "YAML input contains a recursive value.",
        "YAML_LIMIT_EXCEEDED": "YAML input exceeds the public demo limits.",
        "RESPONSE_TOO_LARGE": "The requested demo response exceeds the public limit.",
        "RATE_LIMIT_EXCEEDED": "Please try again shortly.",
        "DEMO_OPERATION_TIMEOUT": "The demo operation timed out.",
        "DEMO_OPERATION_FAILED": "The demo operation could not be completed.",
        "INTERNAL_ERROR": "The demo service encountered an internal error.",
        "AEGIS_ENFORCEMENT_FAILED": "The governed operation was rejected.",
        "UNKNOWN_DEMO_ID": "The requested demo identifier is not available.",
        "POLICY_NOT_FOUND": "The requested demo policy was not found.",
        "ACCESS_DENIED": "The requested demo resource is not available.",
    }
)

_LOGGER = logging.getLogger("aegis.demo")


class DemoPublicError(Exception):
    """Intentional public failure with a stable code and message."""

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.headers = dict(headers or {})


def safe_demo_message(code: str) -> str:
    """Return the fixed message for an allowlisted public error code."""

    return _PUBLIC_MESSAGES[code]


def _valid_request_id(value: object) -> str | None:
    if isinstance(value, str) and _REQUEST_ID_RE.fullmatch(value):
        return value
    return None


def current_request_id() -> str:
    """Return the active edge request ID, or mint one for non-request calls."""

    current = _valid_request_id(REQUEST_ID.get())
    if current is not None:
        return current
    generated = secrets.token_hex(16)
    REQUEST_ID.set(generated)
    return generated


def request_id_from_scope(scope: Mapping[str, Any]) -> str:
    """Read the edge-owned request ID from ASGI state with a safe fallback."""

    state = scope.get("state")
    if isinstance(state, Mapping):
        scoped = _valid_request_id(state.get("request_id"))
        if scoped is not None:
            return scoped
    return current_request_id()


def public_demo_error(code: str) -> dict[str, str]:
    """Build a safe error object for intentional HTTP-200 demo outcomes."""

    return {
        "code": code,
        "message": safe_demo_message(code),
        "request_id": current_request_id(),
    }


def public_error_response(
    *,
    status_code: int,
    code: str,
    message: str,
    request_id: str,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    """Build the sole public non-2xx response shape."""

    response_headers = {
        key: value
        for key, value in dict(headers or {}).items()
        if key.lower() != "x-request-id"
    }
    response_headers["X-Request-ID"] = request_id
    return JSONResponse(
        status_code=status_code,
        headers=response_headers,
        content={
            "detail": {
                "code": code,
                "message": message,
                "request_id": request_id,
            }
        },
    )


def _escape_controls(value: str) -> str:
    pieces: list[str] = []
    for character in value:
        codepoint = ord(character)
        if codepoint < 32 or codepoint == 127:
            pieces.append(f"\\x{codepoint:02x}")
        else:
            pieces.append(character)
    return "".join(pieces)


def _bounded_diagnostic(error: BaseException | None) -> str:
    if error is None:
        raw = ""
    else:
        raw = f"{type(error).__name__}: {error}"
    escaped = _escape_controls(raw)
    encoded = escaped.encode("utf-8", errors="backslashreplace")
    if len(encoded) <= INTERNAL_DIAGNOSTIC_MAX_BYTES:
        return encoded.decode("utf-8")
    return encoded[:INTERNAL_DIAGNOSTIC_MAX_BYTES].decode("utf-8", errors="ignore")


def log_internal_failure(
    *,
    request_id: str,
    operation: str,
    error: BaseException | None,
    public_code: str,
    method: str | None = None,
    route_template: str | None = None,
    identity_source: str | None = None,
) -> None:
    """Log one bounded, control-safe diagnostic correlated to a request."""

    _LOGGER.error(
        "demo operation failed",
        extra={
            "request_id": request_id,
            "operation": operation,
            "public_code": public_code,
            "exception_class": type(error).__name__ if error is not None else None,
            "method": method,
            "route_template": route_template,
            "identity_source": identity_source,
            "internal_diagnostic": _bounded_diagnostic(error),
        },
    )
