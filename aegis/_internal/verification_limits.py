"""Shared bounded-input primitives for evidence verification."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass

from aegis._internal.canonicalization import SAFE_INTEGER_MAX
from aegis._internal.verification_contracts import VerificationError


MAX_VERIFICATION_ERRORS = 100


class VerificationInputError(Exception):
    """Raised when untrusted verification input exceeds its safe domain."""


class _IterableConsumptionError(VerificationInputError):
    """Raised when caller iterable handling fails outside configured limits."""


def materialize_bounded_iterable(
    value: object,
    *,
    max_items: int,
    reject_mappings: bool = True,
) -> list[object]:
    """Consume an iterable with one bounded lookahead and no sizing hooks."""
    if type(max_items) is not int or max_items < 0:
        raise VerificationInputError
    iterable_input_failed = False
    try:
        if isinstance(value, (str, bytes, bytearray)) or (
            reject_mappings and isinstance(value, Mapping)
        ):
            iterable_input_failed = True
        else:
            iterator = iter(value)
    except Exception:
        iterable_input_failed = True
    if iterable_input_failed:
        raise _IterableConsumptionError

    items: list[object] = []
    while True:
        next_failed = False
        try:
            item = next(iterator)
        except StopIteration:
            return items
        except Exception:
            next_failed = True
        if next_failed:
            raise _IterableConsumptionError
        if len(items) >= max_items:
            raise VerificationInputError
        items.append(item)


class BoundedVerificationErrors(list[VerificationError]):
    """Retain only the first bounded set of core-owned verification errors."""

    def append(self, error: VerificationError) -> None:
        if len(self) < MAX_VERIFICATION_ERRORS:
            super().append(error)


def _has_lone_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _measure_json_document(
    value: object,
    *,
    byte_limit: int,
    node_limit: int,
    depth_limit: int,
) -> tuple[int, int]:
    """Measure one exact JSON document without recursive traversal."""
    if byte_limit < 0 or node_limit < 1 or depth_limit < 0:
        raise VerificationInputError

    total_bytes = 0
    scheduled_nodes = 1
    seen_containers: set[int] = set()
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > depth_limit:
            raise VerificationInputError

        if current is None or type(current) is bool:
            total_bytes += 5
        elif type(current) is str:
            if len(current) > byte_limit - total_bytes:
                raise VerificationInputError
            if _has_lone_surrogate(current):
                raise VerificationInputError
            total_bytes += len(current.encode("utf-8")) + 2
        elif type(current) is int:
            if abs(current) > SAFE_INTEGER_MAX:
                raise VerificationInputError
            total_bytes += 32
        elif type(current) is float:
            if not math.isfinite(current):
                raise VerificationInputError
            total_bytes += 32
        elif type(current) is list:
            identity = id(current)
            if identity in seen_containers:
                raise VerificationInputError
            seen_containers.add(identity)
            child_count = len(current)
            total_bytes += 2 + child_count
            if (
                total_bytes > byte_limit
                or (child_count != 0 and depth >= depth_limit)
                or child_count > node_limit - scheduled_nodes
            ):
                raise VerificationInputError
            scheduled_nodes += child_count
            for item in reversed(current):
                stack.append((item, depth + 1))
        elif type(current) is dict:
            identity = id(current)
            if identity in seen_containers:
                raise VerificationInputError
            seen_containers.add(identity)
            child_count = len(current)
            total_bytes += 2 + child_count
            if (
                total_bytes > byte_limit
                or (child_count != 0 and depth >= depth_limit)
                or child_count > node_limit - scheduled_nodes
            ):
                raise VerificationInputError
            scheduled_nodes += child_count
            for key in current:
                if type(key) is not str:
                    raise VerificationInputError
                if len(key) > byte_limit - total_bytes:
                    raise VerificationInputError
                if _has_lone_surrogate(key):
                    raise VerificationInputError
                total_bytes += len(key.encode("utf-8")) + 3
                if total_bytes > byte_limit:
                    raise VerificationInputError
            for item in current.values():
                stack.append((item, depth + 1))
        else:
            raise VerificationInputError

        if total_bytes > byte_limit:
            raise VerificationInputError

    return total_bytes, scheduled_nodes


@dataclass(slots=True)
class VerificationBudget:
    remaining_bytes: int = 4 * 1024 * 1024
    remaining_nodes: int = 65_536

    def measure(self, value: object) -> int:
        try:
            consumed_bytes, consumed_nodes = _measure_json_document(
                value,
                byte_limit=self.remaining_bytes,
                node_limit=self.remaining_nodes,
                depth_limit=32,
            )
        except VerificationInputError:
            raise
        except (MemoryError, UnicodeError, ValueError, OverflowError):
            raise VerificationInputError from None
        self.remaining_bytes -= consumed_bytes
        self.remaining_nodes -= consumed_nodes
        return consumed_bytes
