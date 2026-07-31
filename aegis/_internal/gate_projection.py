"""Detached argument projections supplied to custom enforcement gates."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any, cast

from aegis._internal.compiled_policy import CompiledPolicy, JsonValue


def _detached_mapping_key(key: object) -> str:
    """Normalize supported JSON-object keys without polymorphic conversion."""
    if isinstance(key, str):
        return str.__str__(key)
    if isinstance(key, bool):
        return str(bool(key))
    if isinstance(key, int):
        return str(int.__int__(key))
    if isinstance(key, float):
        return str(float.__float__(key))
    raise TypeError(
        f"Unsupported gate projection mapping key: {type(key).__name__}"
    )


def detached_json_projection(value: object) -> JsonValue:
    """Copy JSON-shaped data into a recursively immutable representation."""
    if value is None:
        return value
    if isinstance(value, str):
        return str.__str__(value)
    if isinstance(value, bool):
        return bool(value)
    if isinstance(value, int):
        return int.__int__(value)
    if isinstance(value, float):
        detached = float.__float__(value)
        if not math.isfinite(detached):
            raise TypeError("Gate projection floats must be finite")
        return detached
    if isinstance(value, Mapping):
        copied = {
            _detached_mapping_key(key): detached_json_projection(item)
            for key, item in value.items()
        }
        return cast(JsonValue, MappingProxyType(copied))
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        return cast(JsonValue, tuple(detached_json_projection(v) for v in value))
    raise TypeError(
        f"Unsupported gate projection value: {type(value).__name__}"
    )


def _precondition_projection(item: Any) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    if item.declared_type is not None:
        result["type"] = item.declared_type
    if item.pattern is not None:
        result["pattern"] = item.pattern.source
    if item.enum is not None:
        result["enum"] = list(item.enum)
    if item.min_length is not None:
        result["minLength"] = item.min_length
    if item.max_length is not None:
        result["maxLength"] = item.max_length
    if item.minimum is not None:
        result["minimum"] = item.minimum
    if item.maximum is not None:
        result["maximum"] = item.maximum
    return result


class GateProjectionFactory:
    """Build detached gate inputs without exposing enforcement objects."""

    @staticmethod
    def invocation(source: Mapping[str, Any]) -> Mapping[str, JsonValue]:
        projected = detached_json_projection(source)
        if not isinstance(projected, Mapping):  # pragma: no cover - typed input
            raise TypeError("Gate invocation projection must be a mapping")
        return projected

    @staticmethod
    def policy(compiled: CompiledPolicy) -> Mapping[str, JsonValue]:
        """Project an explicit allowlist of compiler-owned policy fields."""
        projection: dict[str, Any] = {
            "policy_version": compiled.declared_policy_version,
            "roles": list(compiled.roles),
            "conditions": compiled.conditions,
            "tools": {
                "configured": compiled.tools.configured,
                "allowed_tools": [
                    {"name": item.name, "max_calls": item.max_calls}
                    for item in compiled.tools
                ],
            },
            "retry_policy": (
                {
                    "max_retries": compiled.retry.max_retries,
                    "backoff_ms": compiled.retry.backoff_ms,
                }
                if compiled.retry is not None
                else None
            ),
            "risk": {
                "mode": compiled.risk.mode,
                "threshold": compiled.risk.threshold,
                "factors": [
                    {
                        "name": item.name,
                        "weight": item.weight,
                        "condition": item.condition,
                    }
                    for item in compiled.risk.factors
                ],
            },
            "pre_conditions": {
                "required": {
                    item.name: _precondition_projection(item)
                    for item in compiled.preconditions
                }
            },
            "post_conditions": {"required": list(compiled.postconditions)},
            "output_schema": (
                compiled.output_validator.schema
                if compiled.output_validator is not None
                else None
            ),
            "workflow": compiled.workflow,
        }
        return GateProjectionFactory.policy_from_mapping(projection)

    @staticmethod
    def policy_from_mapping(
        source: Mapping[str, Any],
    ) -> Mapping[str, JsonValue]:
        """Detach a compatibility policy mapping before gate delivery."""
        projected = detached_json_projection(source)
        if not isinstance(projected, Mapping):  # pragma: no cover - typed input
            raise TypeError("Gate policy projection must be a mapping")
        return projected

    @staticmethod
    def context(source: Mapping[str, Any]) -> dict[str, JsonValue]:
        """Return a detached mutable context with frozen nested values."""
        return {
            _detached_mapping_key(key): detached_json_projection(value)
            for key, value in source.items()
        }
