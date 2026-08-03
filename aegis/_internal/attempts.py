"""Bounded identity allocated before an enforcement attempt parses input."""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any


_DEFAULT_MAX_IDENTITY_LENGTH = 512
_MAX_EVIDENCE_STRING_LENGTH = 4096
_MAX_COLLECTION_ITEMS = 1000
_MAX_NESTING_DEPTH = 16


@dataclass(frozen=True, slots=True)
class AttemptEnvelope:
    """Minimum safe evidence identity available for every public attempt."""

    attempt_id: int
    entry_point: str
    mode: str
    started_at: int
    policy_file: str
    model_provider: str
    model_identifier: str
    role: str
    input: Mapping[str, Any]
    output: Mapping[str, Any]
    context: Mapping[str, Any]
    metadata: Mapping[str, Any]
    failure_stage: str
    reason_code: str


def _bounded_string(value: Any, *, limit: int) -> str:
    if isinstance(value, str) and value.strip() and len(value) <= limit:
        return value
    return "unknown"


def _freeze_json(value: Any, *, depth: int = 0) -> Any:
    if depth > _MAX_NESTING_DEPTH:
        raise ValueError("JSON value exceeds attempt-envelope nesting bound")
    if value is None or isinstance(value, (str, bool)):
        if isinstance(value, str) and len(value) > _MAX_EVIDENCE_STRING_LENGTH:
            raise ValueError("JSON string exceeds attempt-envelope bound")
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    if isinstance(value, dict):
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise ValueError("JSON object exceeds attempt-envelope bound")
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object key must be a string")
            frozen[key] = _freeze_json(item, depth=depth + 1)
        return MappingProxyType(frozen)
    if isinstance(value, list):
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise ValueError("JSON array exceeds attempt-envelope bound")
        return tuple(_freeze_json(item, depth=depth + 1) for item in value)
    raise ValueError("value is outside the bounded JSON subset")


def _bounded_mapping(invocation: dict[str, Any], key: str) -> Mapping[str, Any]:
    value = invocation.get(key)
    if not isinstance(value, dict):
        return MappingProxyType({})
    try:
        frozen = _freeze_json(value)
    except (RecursionError, ValueError):
        return MappingProxyType({})
    if not isinstance(frozen, Mapping):  # defensive: the root was checked above
        return MappingProxyType({})
    return frozen


class AttemptFactory:
    """Allocate instance-local, thread-safe monotonic attempt identities."""

    def __init__(
        self,
        *,
        clock: Callable[[], int | float] = time.time,
        max_identity_length: int = _DEFAULT_MAX_IDENTITY_LENGTH,
    ) -> None:
        if (
            not isinstance(max_identity_length, int)
            or isinstance(max_identity_length, bool)
            or max_identity_length < 1
        ):
            raise ValueError("max_identity_length must be a positive integer")
        self._clock = clock
        self._max_identity_length = max_identity_length
        self._lock = threading.Lock()
        self._next_attempt_id = 0

    def allocate(
        self,
        entry_point: str,
        mode: str,
        invocation: object,
    ) -> AttemptEnvelope:
        """Allocate before parsing, copying only bounded safe evidence fields."""
        with self._lock:
            attempt_id = self._next_attempt_id
            self._next_attempt_id += 1

        safe_invocation = invocation if isinstance(invocation, dict) else {}
        limit = self._max_identity_length
        return AttemptEnvelope(
            attempt_id=attempt_id,
            entry_point=_bounded_string(entry_point, limit=limit),
            mode=_bounded_string(mode, limit=limit),
            started_at=int(self._clock()),
            policy_file=_bounded_string(
                safe_invocation.get("policy_file"), limit=limit
            ),
            model_provider=_bounded_string(
                safe_invocation.get("model_provider"), limit=limit
            ),
            model_identifier=_bounded_string(
                safe_invocation.get("model_identifier"), limit=limit
            ),
            role=_bounded_string(safe_invocation.get("role"), limit=limit),
            input=_bounded_mapping(safe_invocation, "input"),
            output=_bounded_mapping(safe_invocation, "output"),
            context=_bounded_mapping(safe_invocation, "context"),
            metadata=_bounded_mapping(safe_invocation, "metadata"),
            failure_stage="attempt_allocation",
            reason_code="ATTEMPT_STARTED",
        )
