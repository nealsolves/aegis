from __future__ import annotations

import json
import logging
import re

import pytest

from demo_errors import (
    REQUEST_ID,
    current_request_id,
    log_internal_failure,
    public_demo_error,
    public_error_response,
    request_id_from_scope,
    safe_demo_message,
)
from demo_limits import INTERNAL_DIAGNOSTIC_MAX_BYTES


def test_public_error_response_has_only_stable_detail_fields() -> None:
    request_id = "a" * 32

    response = public_error_response(
        status_code=413,
        code="REQUEST_BODY_TOO_LARGE",
        message=safe_demo_message("REQUEST_BODY_TOO_LARGE"),
        request_id=request_id,
    )

    assert json.loads(response.body) == {
        "detail": {
            "code": "REQUEST_BODY_TOO_LARGE",
            "message": "Request body exceeds the demo limit.",
            "request_id": request_id,
        }
    }
    assert response.headers["x-request-id"] == request_id


def test_public_error_response_does_not_allow_header_request_id_override() -> None:
    response = public_error_response(
        status_code=429,
        code="RATE_LIMIT_EXCEEDED",
        message=safe_demo_message("RATE_LIMIT_EXCEEDED"),
        request_id="b" * 32,
        headers={"Retry-After": "3", "X-Request-ID": "caller-controlled"},
    )

    assert response.headers["x-request-id"] == "b" * 32
    assert response.headers["retry-after"] == "3"


def test_public_demo_error_uses_the_active_request_id() -> None:
    token = REQUEST_ID.set("c" * 32)
    try:
        error = public_demo_error("AEGIS_ENFORCEMENT_FAILED")
    finally:
        REQUEST_ID.reset(token)

    assert error == {
        "code": "AEGIS_ENFORCEMENT_FAILED",
        "message": "The governed operation was rejected.",
        "request_id": "c" * 32,
    }


def test_scope_and_fallback_request_ids_are_valid() -> None:
    assert request_id_from_scope({"state": {"request_id": "d" * 32}}) == "d" * 32

    token = REQUEST_ID.set(None)
    try:
        generated = current_request_id()
    finally:
        REQUEST_ID.reset(token)

    assert re.fullmatch(r"[0-9a-f]{32}", generated)


def test_internal_failure_log_is_correlated_control_safe_and_byte_bounded(
    caplog: pytest.LogCaptureFixture,
) -> None:
    diagnostic = "first line\n/private/policy.yaml\n" + ("é" * 9_000)

    with caplog.at_level(logging.ERROR, logger="aegis.demo"):
        log_internal_failure(
            request_id="e" * 32,
            operation="yaml_parse",
            error=ValueError(diagnostic),
            public_code="YAML_INVALID",
            method="POST",
            route_template="/api/policy/load-inmemory",
            identity_source="direct",
        )

    record = caplog.records[-1]
    assert record.getMessage() == "demo operation failed"
    assert record.request_id == "e" * 32
    assert record.public_code == "YAML_INVALID"
    assert record.method == "POST"
    assert record.route_template == "/api/policy/load-inmemory"
    assert record.identity_source == "direct"
    assert "\n" not in record.internal_diagnostic
    assert "\\x0a" in record.internal_diagnostic
    assert len(record.internal_diagnostic.encode("utf-8")) <= INTERNAL_DIAGNOSTIC_MAX_BYTES


def test_unknown_public_error_code_fails_closed() -> None:
    with pytest.raises(KeyError):
        safe_demo_message("CALLER_CONTROLLED")


def test_internal_log_accepts_safe_diagnostic_without_serializing_validation_input(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.ERROR, logger="aegis.demo"):
        log_internal_failure(
            request_id="f" * 32,
            operation="request_validation",
            error=None,
            public_code="INVALID_REQUEST",
            exception_class="RequestValidationError",
            diagnostic="request validation failed",
        )

    record = caplog.records[-1]
    assert record.exception_class == "RequestValidationError"
    assert record.internal_diagnostic == "request validation failed"
