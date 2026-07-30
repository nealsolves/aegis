"""Invocation-shape boundary shared by high-level protocol adapters."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from aegis._internal.errors import InvocationValidationError


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
            json.dumps(output, allow_nan=False, sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise InvocationValidationError(
                "Adapter invocation field 'output' must be JSON-serializable",
                details={"field": "output"},
            ) from exc

    projected = dict(invocation)
    projected.pop("output", None)
    return projected
