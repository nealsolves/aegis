"""Immutable value objects produced by the policy compiler."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field as dataclass_field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Mapping, TypeAlias

from aegis._internal.errors import PreconditionError

if TYPE_CHECKING:
    from aegis._internal.patterns import CompiledPattern


JsonScalar: TypeAlias = None | bool | int | float | str
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


def _freeze_detached(value: Any) -> Any:
    """Recursively freeze a value that is already detached from its caller."""
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _freeze_detached(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_detached(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze_detached(item) for item in value)
    return value


def freeze(value: Any) -> Any:
    """Return a recursively detached, immutable representation of *value*."""
    return _freeze_detached(copy.deepcopy(value))


def _is_json_type(value: Any, declared_type: str) -> bool:
    """Apply JSON type distinctions without Python bool/int coercion."""
    if declared_type == "string":
        return isinstance(value, str)
    if declared_type == "boolean":
        return isinstance(value, bool)
    if declared_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if declared_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if declared_type == "object":
        return isinstance(value, dict)
    if declared_type == "array":
        return isinstance(value, list)
    if declared_type == "null":
        return value is None
    return declared_type == "any"


def _json_equal(left: Any, right: Any) -> bool:
    """Compare detached enum values using JSON rather than Python equality."""
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if isinstance(right, Mapping):
        return isinstance(left, dict) and left.keys() == right.keys() and all(
            _json_equal(left[key], right[key]) for key in left
        )
    if isinstance(right, tuple):
        return isinstance(left, list) and len(left) == len(right) and all(
            _json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    return type(left) is type(right) and left == right


@dataclass(frozen=True, slots=True)
class CompiledToolLimit:
    """A tool authorization with its precompiled call limit."""

    name: str
    max_calls: int


@dataclass(frozen=True, slots=True)
class CompiledRiskFactor:
    """One validated risk contribution with a declared condition."""

    name: str
    weight: float
    condition: str


@dataclass(frozen=True, slots=True)
class CompiledRiskPolicy:
    """Closed risk representation used by scoring and override checks."""

    mode: str
    threshold: float
    critical_ceiling: float
    factors: tuple[CompiledRiskFactor, ...] = ()


@dataclass(frozen=True, slots=True)
class CompiledRetryPolicy:
    """Validated bounds for the compatibility retry wrapper."""

    max_retries: int
    backoff_ms: int


@dataclass(frozen=True, slots=True)
class CompiledGuard:
    """Detached guard source, awaiting semantic guard compilation."""

    when: Mapping[str, JsonValue]
    then: Mapping[str, JsonValue]


@dataclass(frozen=True, slots=True)
class CompiledPrecondition:
    """A required key and its precompiled typed constraints."""

    name: str
    declared_type: str | None
    pattern: CompiledPattern | None = None
    enum: tuple[Any, ...] | None = None
    min_length: int | None = None
    max_length: int | None = None
    minimum: int | float | None = None
    maximum: int | float | None = None
    legacy: bool = False

    def validate(self, context: Mapping[str, Any]) -> None:
        """Validate this precondition against an invocation context."""
        if self.name not in context:
            raise PreconditionError(
                f"Missing required precondition: {self.name}",
                details={"precondition": self.name},
            )

        value = context[self.name]
        if self.legacy:
            if not bool(value):
                raise PreconditionError(
                    f"Missing or false required precondition: {self.name}",
                    details={"precondition": self.name},
                )
            return

        if (
            self.declared_type not in (None, "any")
            and not _is_json_type(value, self.declared_type)
        ):
            raise self._failed(
                value,
                f"is not of declared type {self.declared_type!r}",
            )

        if self.enum is not None and not any(
            _json_equal(value, allowed) for allowed in self.enum
        ):
            raise self._failed(value, "is not one of the allowed values")

        if self.pattern is not None:
            from aegis._internal.patterns import PatternInputTooLargeError

            try:
                matches = self.pattern.fullmatch(value)
            except PatternInputTooLargeError as exc:
                raise PreconditionError(
                    f"Precondition '{self.name}' pattern input is too large",
                    code="PATTERN_INPUT_TOO_LARGE",
                    details={"precondition": self.name},
                ) from exc
            if not matches:
                raise self._failed(value, "does not match the required pattern")

        if self.min_length is not None and len(value) < self.min_length:
            raise self._failed(value, "is shorter than minLength")
        if self.max_length is not None and len(value) > self.max_length:
            raise self._failed(value, "is longer than maxLength")
        if self.minimum is not None and value < self.minimum:
            raise self._failed(value, "is less than minimum")
        if self.maximum is not None and value > self.maximum:
            raise self._failed(value, "is greater than maximum")

    def _failed(self, value: Any, reason: str) -> PreconditionError:
        return PreconditionError(
            f"Precondition '{self.name}' validation failed: {reason}",
            details={"precondition": self.name, "value": value},
        )


@dataclass(frozen=True, slots=True)
class CompiledOutputValidator:
    """Detached output schema and its reusable non-retrieving validator."""

    schema: Mapping[str, JsonValue]
    validator: Any = dataclass_field(repr=False, compare=False)
    patterns: Mapping[str, CompiledPattern] = dataclass_field(
        repr=False,
        compare=False,
    )

    def validate(self, value: Any) -> None:
        """Validate using the stored schema snapshot and compiled RE2 programs."""
        from aegis._internal.schema_compiler import validate_compiled_output

        validate_compiled_output(self, value)


@dataclass(frozen=True, slots=True)
class AuthorityEnvelope:
    """The policy's closed authorization limits for later restriction checks."""

    roles: frozenset[str]
    tools: tuple[CompiledToolLimit, ...]
    risk_mode: str
    risk_threshold: float
    critical_ceiling: float
    registered_fields: frozenset[str]
    restriction_values: Mapping[str, JsonValue]


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    """Detached immutable authorization data consumed by enforcement."""

    policy_digest: str
    source_identity: str
    declared_policy_version: str
    policy_contract_version: str
    pattern_engine: str
    canonicalization_profile: str
    roles: tuple[str, ...]
    tools: tuple[CompiledToolLimit, ...]
    risk: CompiledRiskPolicy
    retry: CompiledRetryPolicy | None
    conditions: Mapping[str, JsonValue]
    guards: tuple[CompiledGuard, ...]
    preconditions: tuple[CompiledPrecondition, ...]
    postconditions: tuple[str, ...]
    output_validator: CompiledOutputValidator | None
    workflow: Mapping[str, JsonValue]
    authority: AuthorityEnvelope
