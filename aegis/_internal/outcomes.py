"""Closed terminal outcomes shared by authorization decision points."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from aegis._internal.compiled_policy import JsonValue
from aegis._internal.errors import OutcomeContractError
from aegis._internal.gate_projection import detached_json_projection

MAX_PUBLIC_FAILURE_MESSAGE_LENGTH = 1_024


class TerminalClass(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    DENY = "deny"
    INVALID_RESULT = "invalid_result"
    EXECUTION_FAILURE = "execution_failure"
    TIMEOUT = "timeout"


@dataclass(frozen=True, slots=True)
class FailureRecord:
    code: str
    message: str
    field: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.code, str):
            raise OutcomeContractError("Failure code must be a non-empty string")
        if not isinstance(self.message, str):
            raise OutcomeContractError("Failure message must be a string")
        if self.field is not None and not isinstance(self.field, str):
            raise OutcomeContractError("Failure field must be a string or None")
        code = str.__str__(self.code)
        message = str.__str__(self.message)
        field = str.__str__(self.field) if self.field is not None else None
        if not code:
            raise OutcomeContractError("Failure code must be a non-empty string")
        if len(message) > MAX_PUBLIC_FAILURE_MESSAGE_LENGTH:
            raise OutcomeContractError("Failure message exceeds the public bound")
        object.__setattr__(self, "code", code)
        object.__setattr__(self, "message", message)
        object.__setattr__(self, "field", field)


def _empty_metadata() -> Mapping[str, JsonValue]:
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class NormalizedOutcome:
    terminal: TerminalClass
    reason_code: str
    failures: tuple[FailureRecord, ...] = ()
    metadata: Mapping[str, JsonValue] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        if type(self.terminal) is not TerminalClass:
            raise OutcomeContractError("Outcome terminal must be a TerminalClass")
        if not isinstance(self.reason_code, str) or not self.reason_code:
            raise OutcomeContractError("Outcome reason code must be non-empty")
        if type(self.failures) is not tuple or not all(
            isinstance(item, FailureRecord) for item in self.failures
        ):
            raise OutcomeContractError("Outcome failures must be a frozen tuple")
        if type(self.metadata) is not MappingProxyType:
            raise OutcomeContractError("Outcome metadata must be immutable")
        try:
            detached_metadata = detached_json_projection(self.metadata)
        except TypeError as exc:
            raise OutcomeContractError(
                "Outcome metadata must contain only JSON values"
            ) from exc
        if not isinstance(detached_metadata, Mapping):  # pragma: no cover
            raise OutcomeContractError("Outcome metadata must be a mapping")
        object.__setattr__(self, "metadata", detached_metadata)

    @property
    def allows_continuation(self) -> bool:
        return self.terminal in {TerminalClass.ALLOW, TerminalClass.WARN}


class OutcomeNormalizer:
    """Construct validated outcomes from boundary-facing values."""

    @staticmethod
    def _failure(value: FailureRecord | Mapping[str, Any]) -> FailureRecord:
        if isinstance(value, FailureRecord):
            return value
        if not isinstance(value, Mapping):
            raise OutcomeContractError("Failure entry must be a mapping")
        return FailureRecord(
            code=value.get("code", "INVALID_FAILURE"),
            message=value.get("message", "Invalid failure record"),
            field=value.get("field"),
        )

    @staticmethod
    def _metadata(value: Mapping[str, Any] | None) -> Mapping[str, JsonValue]:
        try:
            projected = detached_json_projection(value or {})
        except TypeError as exc:
            raise OutcomeContractError(
                "Outcome metadata must contain only JSON values"
            ) from exc
        if not isinstance(projected, Mapping):  # pragma: no cover - fixed input
            raise OutcomeContractError("Outcome metadata must be a mapping")
        return projected

    @classmethod
    def outcome(
        cls,
        terminal: TerminalClass,
        reason_code: str,
        *,
        failures: Iterable[FailureRecord | Mapping[str, Any]] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> NormalizedOutcome:
        return NormalizedOutcome(
            terminal=terminal,
            reason_code=reason_code,
            failures=tuple(cls._failure(item) for item in failures),
            metadata=cls._metadata(metadata),
        )

    @classmethod
    def allow(
        cls, reason_code: str, *, metadata: Mapping[str, Any] | None = None
    ) -> NormalizedOutcome:
        return cls.outcome(TerminalClass.ALLOW, reason_code, metadata=metadata)

    @classmethod
    def warn(
        cls, reason_code: str, *, metadata: Mapping[str, Any] | None = None
    ) -> NormalizedOutcome:
        return cls.outcome(TerminalClass.WARN, reason_code, metadata=metadata)

    @classmethod
    def deny(
        cls,
        reason_code: str,
        *,
        failures: Iterable[FailureRecord | Mapping[str, Any]] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> NormalizedOutcome:
        return cls.outcome(
            TerminalClass.DENY,
            reason_code,
            failures=failures,
            metadata=metadata,
        )

    @classmethod
    def invalid(
        cls,
        reason_code: str,
        *,
        failures: Iterable[FailureRecord | Mapping[str, Any]] = (),
    ) -> NormalizedOutcome:
        return cls.outcome(
            TerminalClass.INVALID_RESULT,
            reason_code,
            failures=failures,
        )

    @classmethod
    def execution_failure(
        cls,
        reason_code: str,
        *,
        failures: Iterable[FailureRecord | Mapping[str, Any]] = (),
    ) -> NormalizedOutcome:
        return cls.outcome(
            TerminalClass.EXECUTION_FAILURE,
            reason_code,
            failures=failures,
        )

    @classmethod
    def timeout(cls, reason_code: str) -> NormalizedOutcome:
        return cls.outcome(TerminalClass.TIMEOUT, reason_code)
