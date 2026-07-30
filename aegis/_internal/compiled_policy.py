"""Immutable value objects produced by the policy compiler."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, TypeAlias


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


@dataclass(frozen=True, slots=True)
class CompiledToolLimit:
    """A tool authorization with its precompiled call limit."""

    name: str
    max_calls: int


@dataclass(frozen=True, slots=True)
class CompiledRiskPolicy:
    """Initial closed risk representation; richer factors arrive in Task 3."""

    mode: str
    threshold: float
    critical_ceiling: float
    factors: tuple[object, ...] = ()


@dataclass(frozen=True, slots=True)
class CompiledGuard:
    """Detached guard source, awaiting semantic guard compilation."""

    when: Mapping[str, JsonValue]
    then: Mapping[str, JsonValue]


@dataclass(frozen=True, slots=True)
class CompiledPrecondition:
    """Detached precondition source, awaiting typed compilation."""

    name: str
    specification: JsonValue


@dataclass(frozen=True, slots=True)
class CompiledOutputValidator:
    """Detached output schema, awaiting safe Draft 7 validator compilation."""

    schema: Mapping[str, JsonValue]


@dataclass(frozen=True, slots=True)
class AuthorityEnvelope:
    """The policy's closed authorization limits for later restriction checks."""

    roles: frozenset[str]
    tools: tuple[CompiledToolLimit, ...]
    risk_mode: str
    risk_threshold: float
    critical_ceiling: float
    registered_fields: frozenset[str]


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    """Detached immutable authorization data consumed by enforcement."""

    policy_digest: str
    policy_contract_version: str
    pattern_engine: str
    canonicalization_profile: str
    roles: tuple[str, ...]
    tools: tuple[CompiledToolLimit, ...]
    risk: CompiledRiskPolicy
    guards: tuple[CompiledGuard, ...]
    preconditions: tuple[CompiledPrecondition, ...]
    output_validator: CompiledOutputValidator | None
    authority: AuthorityEnvelope
