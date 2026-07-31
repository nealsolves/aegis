"""Strict canonicalization for the AEGIS v2 evidence domain."""

from __future__ import annotations

import math
from dataclasses import dataclass

import rfc8785

from aegis._internal.compiled_policy import JsonValue
from aegis._internal.errors import AIGCError


SAFE_INTEGER_MAX = 9_007_199_254_740_991
CANONICALIZATION_PROFILE_V2 = "aegis-json-v2"


class CanonicalizationError(AIGCError):
    """Raised when a value is outside the closed v2 JSON domain."""

    def __init__(self, path: str, code: str) -> None:
        super().__init__(
            f"Evidence value is not valid at {path}",
            code=code,
            details={"path": path},
        )


@dataclass(frozen=True, slots=True)
class CanonicalizedValue:
    """A normalized JSON value and its RFC 8785 representation."""

    value: JsonValue
    data: bytes
    profile: str = CANONICALIZATION_PROFILE_V2


def _reject_lone_surrogates(value: object, *, path: str) -> None:
    if isinstance(value, str) and any(
        0xD800 <= ord(character) <= 0xDFFF for character in value
    ):
        raise CanonicalizationError(path, "LONE_SURROGATE")


def normalize_json_v2(value: object, *, path: str = "$") -> JsonValue:
    """Detach *value* into the strict JSON value domain used by v2 evidence."""
    if value is None or isinstance(value, (str, bool)):
        _reject_lone_surrogates(value, path=path)
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > SAFE_INTEGER_MAX:
            raise CanonicalizationError(path, "INTEGER_OUT_OF_RANGE")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError(path, "NON_FINITE_NUMBER")
        return 0 if value == 0 else value
    if type(value) is list:
        return [
            normalize_json_v2(item, path=f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise CanonicalizationError(path, "NON_STRING_KEY")
        for key in value:
            _reject_lone_surrogates(key, path=path)
        return {
            key: normalize_json_v2(item, path=f"{path}.{key}")
            for key, item in value.items()
        }
    raise CanonicalizationError(path, "NON_JSON_VALUE")


def canonicalize_v2(value: object) -> CanonicalizedValue:
    """Normalize *value* and serialize it with RFC 8785."""
    normalized = normalize_json_v2(value)
    try:
        data = rfc8785.dumps(normalized)
    except rfc8785.CanonicalizationError as exc:
        raise CanonicalizationError(
            "$", "RFC8785_SERIALIZATION_FAILED"
        ) from exc
    return CanonicalizedValue(normalized, data, CANONICALIZATION_PROFILE_V2)
