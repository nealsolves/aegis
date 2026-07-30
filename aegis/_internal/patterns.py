"""Bounded compilation and evaluation for policy-supplied RE2 patterns."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import re2

from aegis._internal.errors import AIGCError, PolicyValidationError


PATTERN_MAX_BYTES = 256
PATTERN_INPUT_MAX_BYTES = 16_384


class PatternInputTooLargeError(AIGCError):
    """Raised before RE2 sees a candidate which exceeds the runtime bound."""

    def __init__(
        self,
        message: str = "Pattern candidate exceeds the UTF-8 byte limit",
        *,
        code: str = "PATTERN_INPUT_TOO_LARGE",
        details: dict | None = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


@dataclass(frozen=True, slots=True)
class CompiledPattern:
    """An immutable RE2 program with bounded candidate evaluation."""

    source: str
    path: str
    _compiled: Any = field(repr=False, compare=False)

    def _require_bounded_string(self, candidate: object) -> str | None:
        if not isinstance(candidate, str):
            return None
        try:
            encoded_length = len(candidate.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise PatternInputTooLargeError(
                "Pattern candidate is not valid UTF-8",
                details={"path": self.path},
            ) from exc
        if encoded_length > PATTERN_INPUT_MAX_BYTES:
            raise PatternInputTooLargeError(
                details={"path": self.path, "max_bytes": PATTERN_INPUT_MAX_BYTES}
            )
        return candidate

    def fullmatch(self, candidate: str) -> bool:
        """Return whether *candidate* fully matches, or fail closed on its bound."""
        bounded = self._require_bounded_string(candidate)
        if bounded is None:
            return False
        return self._compiled.fullmatch(bounded) is not None

    def search(self, candidate: str) -> bool:
        """Apply JSON Schema search semantics with the same candidate bound."""
        bounded = self._require_bounded_string(candidate)
        if bounded is None:
            return False
        return self._compiled.search(bounded) is not None


def compile_pattern(source: str, *, path: str) -> CompiledPattern:
    """Compile one bounded policy pattern with no fallback engine."""
    if not isinstance(source, str):
        raise PolicyValidationError(
            "Invalid pattern length",
            code="PATTERN_INVALID",
            details={"path": path, "max_bytes": PATTERN_MAX_BYTES},
        )
    try:
        encoded_length = len(source.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise PolicyValidationError(
            "Pattern source is not valid UTF-8",
            code="PATTERN_INVALID",
            details={"path": path},
        ) from exc
    if encoded_length > PATTERN_MAX_BYTES:
        raise PolicyValidationError(
            "Invalid pattern length",
            code="PATTERN_INVALID",
            details={"path": path, "max_bytes": PATTERN_MAX_BYTES},
        )
    try:
        compiled = re2.compile(source)
    except re2.error as exc:
        raise PolicyValidationError(
            f"Unsupported policy pattern at {path}",
            code="PATTERN_UNSUPPORTED",
            details={"path": path},
        ) from exc
    return CompiledPattern(source=source, path=path, _compiled=compiled)
