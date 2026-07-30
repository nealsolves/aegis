"""Invocation-shape boundary shared by high-level protocol adapters."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from typing import Any

from aegis._internal.errors import InvocationValidationError


# Adapter host envelopes carry compatibility metadata that is discarded before
# Phase A. Keep validation work bounded independently of core invocation limits.
# Encoded size is compact UTF-8 JSON. A node is the root value or an object
# value/array element (object keys count toward bytes, not nodes). Root depth is
# one. The validator stops as soon as any limit is exceeded.
ADAPTER_OUTPUT_MAX_ENCODED_BYTES = 1_048_576
ADAPTER_OUTPUT_MAX_NODES = 10_000
ADAPTER_OUTPUT_MAX_DEPTH = 64


def _output_error(reason: str, **details: int) -> InvocationValidationError:
    return InvocationValidationError(
        "Adapter invocation field 'output' is not a bounded JSON object",
        details={"field": "output", "reason": reason, **details},
    )


def _add_encoded_bytes(current: int, addition: int) -> int:
    total = current + addition
    if total > ADAPTER_OUTPUT_MAX_ENCODED_BYTES:
        raise _output_error(
            "encoded_bytes",
            max_encoded_bytes=ADAPTER_OUTPUT_MAX_ENCODED_BYTES,
        )
    return total


def _json_string_bytes(value: str, remaining: int) -> int:
    """Return compact UTF-8 JSON string bytes without allocating the encoding."""
    # Every code point consumes at least one byte, plus the two JSON quotes.
    if len(value) + 2 > remaining:
        raise _output_error(
            "encoded_bytes",
            max_encoded_bytes=ADAPTER_OUTPUT_MAX_ENCODED_BYTES,
        )

    total = 2
    for character in value:
        codepoint = ord(character)
        if character in {'"', "\\"} or character in "\b\f\n\r\t":
            width = 2
        elif codepoint < 0x20:
            width = 6
        elif codepoint < 0x80:
            width = 1
        elif codepoint < 0x800:
            width = 2
        elif 0xD800 <= codepoint <= 0xDFFF:
            raise _output_error("invalid_string")
        elif codepoint < 0x10000:
            width = 3
        else:
            width = 4
        total += width
        if total > remaining:
            raise _output_error(
                "encoded_bytes",
                max_encoded_bytes=ADAPTER_OUTPUT_MAX_ENCODED_BYTES,
            )
    return total


def _integer_bytes(value: int, remaining: int) -> int:
    """Return decimal integer bytes with a cheap bound before conversion."""
    sign_bytes = 1 if value < 0 else 0
    # A decimal digit carries fewer than four bits. This lower bound lets an
    # enormous integer fail before Python allocates its full decimal form.
    minimum_digits = max(1, (abs(value).bit_length() + 3) // 4)
    if minimum_digits + sign_bytes > remaining:
        raise _output_error(
            "encoded_bytes",
            max_encoded_bytes=ADAPTER_OUTPUT_MAX_ENCODED_BYTES,
        )
    return len(str(value))


def _validate_bounded_json_object(output: dict[str, Any]) -> None:
    """Validate JSON semantics and limits with an iterative traversal."""
    encoded_bytes = 0
    node_count = 0
    active_containers: set[int] = set()
    # Events are visit(value, depth), dict(iterator, child depth, item index),
    # list(iterator, child depth, item index), and exit(container identity).
    stack: list[tuple[str, Any, int, int]] = [
        ("visit", output, 1, 0)
    ]

    while stack:
        event, value, depth, index = stack.pop()
        if event == "exit":
            active_containers.remove(value)
            continue

        if event == "dict":
            try:
                key, child = next(value)
            except StopIteration:
                continue
            if type(key) is not str:
                raise _output_error("non_string_key")
            if index:
                encoded_bytes = _add_encoded_bytes(encoded_bytes, 1)
            key_bytes = _json_string_bytes(
                key,
                ADAPTER_OUTPUT_MAX_ENCODED_BYTES - encoded_bytes,
            )
            encoded_bytes = _add_encoded_bytes(
                encoded_bytes,
                key_bytes + 1,
            )
            stack.append(("dict", value, depth, index + 1))
            stack.append(("visit", child, depth, 0))
            continue

        if event == "list":
            try:
                child = next(value)
            except StopIteration:
                continue
            if index:
                encoded_bytes = _add_encoded_bytes(encoded_bytes, 1)
            stack.append(("list", value, depth, index + 1))
            stack.append(("visit", child, depth, 0))
            continue

        node_count += 1
        if node_count > ADAPTER_OUTPUT_MAX_NODES:
            raise _output_error(
                "nodes",
                max_nodes=ADAPTER_OUTPUT_MAX_NODES,
            )
        if depth > ADAPTER_OUTPUT_MAX_DEPTH:
            raise _output_error(
                "depth",
                max_depth=ADAPTER_OUTPUT_MAX_DEPTH,
            )

        value_type = type(value)
        if value_type is dict or value_type is list:
            identity = id(value)
            if identity in active_containers:
                raise _output_error("circular_reference")
            active_containers.add(identity)
            encoded_bytes = _add_encoded_bytes(encoded_bytes, 2)
            stack.append(("exit", identity, 0, 0))
            if value_type is dict:
                stack.append(("dict", iter(value.items()), depth + 1, 0))
            else:
                stack.append(("list", iter(value), depth + 1, 0))
            continue

        if value is None:
            encoded_bytes = _add_encoded_bytes(encoded_bytes, 4)
        elif value_type is bool:
            encoded_bytes = _add_encoded_bytes(
                encoded_bytes,
                4 if value else 5,
            )
        elif value_type is int:
            integer_bytes = _integer_bytes(
                value,
                ADAPTER_OUTPUT_MAX_ENCODED_BYTES - encoded_bytes,
            )
            encoded_bytes = _add_encoded_bytes(
                encoded_bytes,
                integer_bytes,
            )
        elif value_type is float:
            if not math.isfinite(value):
                raise _output_error("non_finite_number")
            encoded_bytes = _add_encoded_bytes(
                encoded_bytes,
                len(repr(value)),
            )
        elif value_type is str:
            string_bytes = _json_string_bytes(
                value,
                ADAPTER_OUTPUT_MAX_ENCODED_BYTES - encoded_bytes,
            )
            encoded_bytes = _add_encoded_bytes(encoded_bytes, string_bytes)
        else:
            raise _output_error("invalid_type")


def project_adapter_pre_call_invocation(
    invocation: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a broad adapter invocation and detach its Phase A projection.

    Protocol adapters historically accept the unified invocation shape so host
    integrations can pass one request envelope through prepare/complete. Phase A
    must never receive the optional output value from that broad envelope.
    """
    if not isinstance(invocation, Mapping):
        raise InvocationValidationError(
            "Adapter invocation must be a mapping object",
            details={"received_type": type(invocation).__name__},
        )
    if "output" in invocation:
        output = invocation["output"]
        if not isinstance(output, dict):
            raise InvocationValidationError(
                "Adapter invocation field 'output' must be an object",
                details={"field": "output"},
            )
        try:
            _validate_bounded_json_object(output)
            encoded = json.dumps(
                output,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            if len(encoded) > ADAPTER_OUTPUT_MAX_ENCODED_BYTES:
                raise _output_error(
                    "encoded_bytes",
                    max_encoded_bytes=ADAPTER_OUTPUT_MAX_ENCODED_BYTES,
                )
        except InvocationValidationError:
            raise
        except (
            RecursionError,
            OverflowError,
            TypeError,
            ValueError,
        ) as exc:
            raise InvocationValidationError(
                "Adapter invocation field 'output' must be JSON-serializable",
                details={"field": "output", "reason": "serialization"},
            ) from exc

    projected = dict(invocation)
    projected.pop("output", None)
    return projected
