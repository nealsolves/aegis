"""Versioned, provider-neutral contracts for bounded governance state."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field, fields, replace
from enum import Enum
from typing import Protocol, TypeAlias, runtime_checkable

from aegis._internal.canonicalization import SAFE_INTEGER_MAX, canonicalize_v2
from aegis._internal.errors import StateResultInvalidError


STATE_PROVIDER_CONTRACT_VERSION = 1
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_ADDRESS_DOMAIN = b"aegis-state-address-v1\x00"
_OPERATION_DOMAIN = b"aegis-state-operation-v1\x00"
_RECORD_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_SCOPE_VALUE_BYTES = 512


class StateOperationFamilyV1(str, Enum):
    MONOTONIC_COUNTER = "monotonic_counter"
    QUOTA = "quota"
    REPLAY_TTL = "replay_ttl"
    SLIDING_WINDOW = "sliding_window"


class StateExecutionModeV1(str, Enum):
    SYNC = "sync"
    ASYNC = "async"


class StateConsistencyDomainV1(str, Enum):
    INSTANCE = "instance"
    PROCESS = "process"
    DISTRIBUTED = "distributed"


class StateDurabilityDomainV1(str, Enum):
    NONE = "none"
    PROCESS_LIFETIME = "process_lifetime"
    DURABLE = "durable"


class StateClockSourceV1(str, Enum):
    MONOTONIC = "monotonic"
    COORDINATED = "coordinated"


class StateEffectV1(str, Enum):
    APPLIED = "applied"
    REJECTED_NO_CONSUMPTION = "rejected_no_consumption"
    UNAVAILABLE_NO_EFFECT = "unavailable_no_effect"
    INDETERMINATE_MAY_HAVE_COMMITTED = "indeterminate_may_have_committed"
    INVALID_REQUEST_NO_EFFECT = "invalid_request_no_effect"


class StateFailureReasonV1(str, Enum):
    FINGERPRINT_MISMATCH = "fingerprint_mismatch"
    OPERATION_ID_CONFLICT = "operation_id_conflict"
    INVALID_OPERATION = "invalid_operation"
    CONFIGURATION_CONFLICT = "configuration_conflict"
    OVERFLOW = "overflow"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    CAPACITY_EXHAUSTED = "capacity_exhausted"
    CLOCK_UNCERTAIN = "clock_uncertain"
    POSSIBLE_COMMIT = "possible_commit"
    STALE_RESULT = "stale_result"


class StateScopeDimensionNameV1(str, Enum):
    INVOCATION = "invocation"
    PARTICIPANT = "participant"
    SESSION = "session"
    TENANT = "tenant"
    TOOL = "tool"
    POLICY = "policy"


_SCOPE_ORDER = tuple(StateScopeDimensionNameV1)
_SCOPE_TAGS = {
    name: 0x10 + index for index, name in enumerate(_SCOPE_ORDER)
}


def _require_int(
    name: str,
    value: object,
    *,
    minimum: int = 0,
    maximum: int = SAFE_INTEGER_MAX,
) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be a built-in integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} is outside its allowed range")
    return value


def _require_text(
    name: str,
    value: object,
    *,
    max_bytes: int,
    identifier: bool = False,
) -> str:
    if type(value) is not str or not value:
        raise TypeError(f"{name} must be a non-empty string")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} is not valid UTF-8") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"{name} exceeds its byte limit")
    if identifier and _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{name} is not a safe identifier")
    return value


@dataclass(frozen=True, slots=True)
class StateProviderDescriptorV1:
    provider_id: str
    supported_operations: frozenset[StateOperationFamilyV1]
    execution_modes: frozenset[StateExecutionModeV1]
    consistency_domain: StateConsistencyDomainV1
    durability_domain: StateDurabilityDomainV1
    clock_source: StateClockSourceV1
    clock_id: str
    clock_resolution_ms: int
    min_idempotency_retention_ms: int
    max_key_bytes: int
    max_operation_bytes: int
    max_units: int
    max_records: int
    contract_version: int = STATE_PROVIDER_CONTRACT_VERSION
    clock_discontinuity: str = "fail_closed"

    def __post_init__(self) -> None:
        _require_int("contract_version", self.contract_version, minimum=1, maximum=1)
        _require_text("provider_id", self.provider_id, max_bytes=128, identifier=True)
        _require_text("clock_id", self.clock_id, max_bytes=128, identifier=True)
        if type(self.supported_operations) is not frozenset or not all(
            type(item) is StateOperationFamilyV1
            for item in self.supported_operations
        ):
            raise TypeError("supported_operations must contain operation-family enums")
        if not self.supported_operations:
            raise ValueError("supported_operations cannot be empty")
        if type(self.execution_modes) is not frozenset or not all(
            type(item) is StateExecutionModeV1 for item in self.execution_modes
        ):
            raise TypeError("execution_modes must contain execution-mode enums")
        if not self.execution_modes:
            raise ValueError("execution_modes cannot be empty")
        if type(self.consistency_domain) is not StateConsistencyDomainV1:
            raise TypeError("consistency_domain must be a contract enum")
        if type(self.durability_domain) is not StateDurabilityDomainV1:
            raise TypeError("durability_domain must be a contract enum")
        if type(self.clock_source) is not StateClockSourceV1:
            raise TypeError("clock_source must be a contract enum")
        if self.clock_discontinuity != "fail_closed":
            raise ValueError("clock_discontinuity must be fail_closed")
        _require_int("clock_resolution_ms", self.clock_resolution_ms, minimum=1)
        _require_int(
            "min_idempotency_retention_ms",
            self.min_idempotency_retention_ms,
            minimum=1,
        )
        _require_int("max_key_bytes", self.max_key_bytes, minimum=64)
        _require_int("max_operation_bytes", self.max_operation_bytes, minimum=256)
        _require_int("max_units", self.max_units, minimum=1)
        _require_int("max_records", self.max_records, minimum=1)


@dataclass(frozen=True, slots=True)
class StateProviderClaimV1:
    provider_id: str
    consistency_domain: StateConsistencyDomainV1
    durability_domain: StateDurabilityDomainV1
    clock_source: StateClockSourceV1
    contract_version: int = STATE_PROVIDER_CONTRACT_VERSION

    def __post_init__(self) -> None:
        _require_int("contract_version", self.contract_version, minimum=1, maximum=1)
        _require_text("provider_id", self.provider_id, max_bytes=128, identifier=True)
        if type(self.consistency_domain) is not StateConsistencyDomainV1:
            raise TypeError("consistency_domain must be a contract enum")
        if type(self.durability_domain) is not StateDurabilityDomainV1:
            raise TypeError("durability_domain must be a contract enum")
        if type(self.clock_source) is not StateClockSourceV1:
            raise TypeError("clock_source must be a contract enum")

    @classmethod
    def from_descriptor(
        cls,
        descriptor: StateProviderDescriptorV1,
    ) -> "StateProviderClaimV1":
        return cls(
            provider_id=descriptor.provider_id,
            consistency_domain=descriptor.consistency_domain,
            durability_domain=descriptor.durability_domain,
            clock_source=descriptor.clock_source,
            contract_version=descriptor.contract_version,
        )


@dataclass(frozen=True, slots=True, repr=False)
class StateScopeDimensionV1:
    name: StateScopeDimensionNameV1
    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.name) is not StateScopeDimensionNameV1:
            raise TypeError("scope dimension name must be a contract enum")
        _require_text(
            "scope dimension value",
            self.value,
            max_bytes=_MAX_SCOPE_VALUE_BYTES,
        )

    def __repr__(self) -> str:
        return f"StateScopeDimensionV1(name={self.name.value!r}, value=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class StateScopeV1:
    dimensions: tuple[StateScopeDimensionV1, ...]

    def __post_init__(self) -> None:
        if type(self.dimensions) is not tuple:
            raise TypeError("dimensions must be a tuple")
        by_name: dict[StateScopeDimensionNameV1, StateScopeDimensionV1] = {}
        for dimension in self.dimensions:
            if type(dimension) is not StateScopeDimensionV1:
                raise TypeError("dimensions must contain StateScopeDimensionV1")
            if dimension.name in by_name:
                raise ValueError("scope dimension names cannot repeat")
            by_name[dimension.name] = dimension
        ordered = tuple(by_name[name] for name in _SCOPE_ORDER if name in by_name)
        object.__setattr__(self, "dimensions", ordered)

    def __repr__(self) -> str:
        names = ", ".join(dimension.name.value for dimension in self.dimensions)
        return f"StateScopeV1(dimensions=({names}), values=<redacted>)"

    @property
    def dimension_names(self) -> tuple[StateScopeDimensionNameV1, ...]:
        return tuple(dimension.name for dimension in self.dimensions)

    def value_for(self, name: StateScopeDimensionNameV1) -> str | None:
        for dimension in self.dimensions:
            if dimension.name is name:
                return dimension.value
        return None

    @classmethod
    def tenant(cls, value: str) -> "StateScopeV1":
        return cls((StateScopeDimensionV1(StateScopeDimensionNameV1.TENANT, value),))

    @classmethod
    def from_values(cls, **values: str | None) -> "StateScopeV1":
        unknown = set(values) - {name.value for name in _SCOPE_ORDER}
        if unknown:
            raise TypeError("unsupported state scope dimensions")
        dimensions = tuple(
            StateScopeDimensionV1(name, values[name.value])
            for name in _SCOPE_ORDER
            if values.get(name.value) is not None
        )
        return cls(dimensions)

    def with_dimension(
        self,
        name: StateScopeDimensionNameV1,
        value: str,
    ) -> "StateScopeV1":
        remaining = tuple(item for item in self.dimensions if item.name is not name)
        return StateScopeV1((*remaining, StateScopeDimensionV1(name, value)))

    def with_tool(self, value: str) -> "StateScopeV1":
        return self.with_dimension(StateScopeDimensionNameV1.TOOL, value)

    def with_policy(self, value: str) -> "StateScopeV1":
        return self.with_dimension(StateScopeDimensionNameV1.POLICY, value)


@dataclass(frozen=True, slots=True, repr=False)
class StateAddressV1:
    namespace: str = field(repr=False)
    policy_state_id: str
    constraint_id: str
    scope: StateScopeV1 = field(repr=False)

    def __post_init__(self) -> None:
        _require_text("namespace", self.namespace, max_bytes=128, identifier=True)
        _require_text(
            "policy_state_id", self.policy_state_id, max_bytes=128, identifier=True
        )
        _require_text("constraint_id", self.constraint_id, max_bytes=128, identifier=True)
        if type(self.scope) is not StateScopeV1:
            raise TypeError("scope must be StateScopeV1")

    def __repr__(self) -> str:
        return (
            "StateAddressV1(namespace=<redacted>, "
            f"policy_state_id={self.policy_state_id!r}, "
            f"constraint_id={self.constraint_id!r}, scope={self.scope!r})"
        )

    @classmethod
    def from_dimensions(
        cls,
        namespace: str,
        policy_state_id: str,
        constraint_id: str,
        **values: str | None,
    ) -> "StateAddressV1":
        return cls(namespace, policy_state_id, constraint_id, StateScopeV1.from_values(**values))


def _frame(tag: int, value: str) -> bytes:
    encoded = value.encode("utf-8", errors="strict")
    return bytes((tag,)) + len(encoded).to_bytes(4, "big") + encoded


def encode_state_address_v1(address: StateAddressV1) -> bytes:
    if type(address) is not StateAddressV1:
        raise TypeError("address must be StateAddressV1")
    encoded = bytearray(_ADDRESS_DOMAIN)
    encoded.extend(_frame(0x01, address.namespace))
    encoded.extend(_frame(0x02, address.policy_state_id))
    encoded.extend(_frame(0x03, address.constraint_id))
    for name in _SCOPE_ORDER:
        value = address.scope.value_for(name)
        encoded.extend(bytes((_SCOPE_TAGS[name], 0 if value is None else 1)))
        if value is not None:
            raw = value.encode("utf-8", errors="strict")
            encoded.extend(len(raw).to_bytes(4, "big"))
            encoded.extend(raw)
    return bytes(encoded)


@dataclass(frozen=True, slots=True, kw_only=True)
class _StateOperationBaseV1:
    operation_id: str
    request_fingerprint: str
    address: StateAddressV1
    timeout_ms: int
    retry_horizon_ms: int
    contract_version: int = STATE_PROVIDER_CONTRACT_VERSION

    def __post_init__(self) -> None:
        _require_int("contract_version", self.contract_version, minimum=1, maximum=1)
        _require_text("operation_id", self.operation_id, max_bytes=128, identifier=True)
        if self.request_fingerprint:
            _require_text(
                "request_fingerprint", self.request_fingerprint, max_bytes=64
            )
        if self.request_fingerprint and _FINGERPRINT.fullmatch(self.request_fingerprint) is None:
            raise ValueError("request_fingerprint must be lowercase SHA-256")
        if type(self.address) is not StateAddressV1:
            raise TypeError("address must be StateAddressV1")
        _require_int("timeout_ms", self.timeout_ms, minimum=1)
        _require_int("retry_horizon_ms", self.retry_horizon_ms, minimum=self.timeout_ms)

    @property
    def family(self) -> StateOperationFamilyV1:
        raise NotImplementedError


@dataclass(frozen=True, slots=True, kw_only=True)
class CounterIncrementV1(_StateOperationBaseV1):
    increment: int
    counted_unit: str

    def __post_init__(self) -> None:
        super(CounterIncrementV1, self).__post_init__()
        _require_int("increment", self.increment, minimum=1)
        _require_text("counted_unit", self.counted_unit, max_bytes=64, identifier=True)

    @property
    def family(self) -> StateOperationFamilyV1:
        return StateOperationFamilyV1.MONOTONIC_COUNTER


@dataclass(frozen=True, slots=True, kw_only=True)
class QuotaConsumeV1(_StateOperationBaseV1):
    units: int
    limit: int
    counted_unit: str

    def __post_init__(self) -> None:
        super(QuotaConsumeV1, self).__post_init__()
        _require_int("units", self.units, minimum=1)
        _require_int("limit", self.limit, minimum=1)
        _require_text("counted_unit", self.counted_unit, max_bytes=64, identifier=True)

    @property
    def family(self) -> StateOperationFamilyV1:
        return StateOperationFamilyV1.QUOTA


@dataclass(frozen=True, slots=True, kw_only=True)
class ReplayClaimV1(_StateOperationBaseV1):
    claim_key: str
    ttl_ms: int

    def __post_init__(self) -> None:
        super(ReplayClaimV1, self).__post_init__()
        _require_text("claim_key", self.claim_key, max_bytes=512)
        _require_int("ttl_ms", self.ttl_ms, minimum=1)

    @property
    def family(self) -> StateOperationFamilyV1:
        return StateOperationFamilyV1.REPLAY_TTL


@dataclass(frozen=True, slots=True, kw_only=True)
class SlidingWindowAdmitV1(_StateOperationBaseV1):
    units: int
    limit: int
    window_ms: int
    counted_unit: str

    def __post_init__(self) -> None:
        super(SlidingWindowAdmitV1, self).__post_init__()
        _require_int("units", self.units, minimum=1)
        _require_int("limit", self.limit, minimum=1)
        _require_int("window_ms", self.window_ms, minimum=1)
        _require_text("counted_unit", self.counted_unit, max_bytes=64, identifier=True)

    @property
    def family(self) -> StateOperationFamilyV1:
        return StateOperationFamilyV1.SLIDING_WINDOW


StateOperationV1: TypeAlias = (
    CounterIncrementV1 | QuotaConsumeV1 | ReplayClaimV1 | SlidingWindowAdmitV1
)


def validate_state_operation_v1(
    operation: StateOperationV1,
) -> StateOperationV1:
    """Reconstruct and detach an exact operation at the provider boundary."""
    operation_type = type(operation)
    if operation_type not in (
        CounterIncrementV1,
        QuotaConsumeV1,
        ReplayClaimV1,
        SlidingWindowAdmitV1,
    ):
        raise TypeError("operation must be an exact version-1 operation")
    raw_address = operation.address
    if type(raw_address) is not StateAddressV1:
        raise TypeError("address must be exact")
    raw_scope = raw_address.scope
    if type(raw_scope) is not StateScopeV1:
        raise TypeError("scope must be exact")
    dimensions = tuple(
        StateScopeDimensionV1(dimension.name, dimension.value)
        for dimension in raw_scope.dimensions
    )
    address = StateAddressV1(
        raw_address.namespace,
        raw_address.policy_state_id,
        raw_address.constraint_id,
        StateScopeV1(dimensions),
    )
    values = {
        field_info.name: getattr(operation, field_info.name)
        for field_info in fields(operation_type)
    }
    values["address"] = address
    return operation_type(**values)


def _scope_projection(scope: StateScopeV1) -> dict[str, str | None]:
    return {name.value: scope.value_for(name) for name in _SCOPE_ORDER}


def _operation_projection(operation: StateOperationV1) -> dict[str, object]:
    projection: dict[str, object] = {
        "contract_version": operation.contract_version,
        "operation_family": operation.family.value,
        "operation_id": operation.operation_id,
        "address": {
            "namespace": operation.address.namespace,
            "policy_state_id": operation.address.policy_state_id,
            "constraint_id": operation.address.constraint_id,
            "scope": _scope_projection(operation.address.scope),
        },
        "timeout_ms": operation.timeout_ms,
        "retry_horizon_ms": operation.retry_horizon_ms,
    }
    if type(operation) is CounterIncrementV1:
        projection.update(increment=operation.increment, counted_unit=operation.counted_unit)
    elif type(operation) is QuotaConsumeV1:
        projection.update(
            units=operation.units,
            limit=operation.limit,
            counted_unit=operation.counted_unit,
        )
    elif type(operation) is ReplayClaimV1:
        projection.update(claim_key=operation.claim_key, ttl_ms=operation.ttl_ms)
    elif type(operation) is SlidingWindowAdmitV1:
        projection.update(
            units=operation.units,
            limit=operation.limit,
            window_ms=operation.window_ms,
            counted_unit=operation.counted_unit,
        )
    else:  # pragma: no cover - protected by the closed alias and public helper
        raise TypeError("unsupported state operation type")
    return projection


def operation_fingerprint_v1(operation: StateOperationV1) -> str:
    if type(operation) not in (
        CounterIncrementV1,
        QuotaConsumeV1,
        ReplayClaimV1,
        SlidingWindowAdmitV1,
    ):
        raise TypeError("operation must be an exact version-1 operation")
    canonical = canonicalize_v2(_operation_projection(operation)).data
    return hashlib.sha256(_OPERATION_DOMAIN + canonical).hexdigest()


def encode_state_operation_v1(operation: StateOperationV1) -> bytes:
    """Return the exact bounded canonical version-1 provider wire projection."""
    if type(operation) not in (
        CounterIncrementV1,
        QuotaConsumeV1,
        ReplayClaimV1,
        SlidingWindowAdmitV1,
    ):
        raise TypeError("operation must be an exact version-1 operation")
    projection = _operation_projection(operation)
    projection["request_fingerprint"] = operation.request_fingerprint
    return canonicalize_v2(projection).data


def bind_operation_fingerprint_v1(operation: StateOperationV1) -> StateOperationV1:
    return replace(operation, request_fingerprint=operation_fingerprint_v1(operation))


@dataclass(frozen=True, slots=True, kw_only=True)
class _StateResultBaseV1:
    operation_id: str
    request_fingerprint: str
    provider_claim: StateProviderClaimV1
    control_state_changed: bool = False
    provider_record_digest: str | None = None
    contract_version: int = STATE_PROVIDER_CONTRACT_VERSION

    def __post_init__(self) -> None:
        _require_int("contract_version", self.contract_version, minimum=1, maximum=1)
        _require_text("operation_id", self.operation_id, max_bytes=128, identifier=True)
        _require_text(
            "request_fingerprint", self.request_fingerprint, max_bytes=64
        )
        if _FINGERPRINT.fullmatch(self.request_fingerprint) is None:
            raise ValueError("request_fingerprint must be lowercase SHA-256")
        if type(self.provider_claim) is not StateProviderClaimV1:
            raise TypeError("provider_claim must be StateProviderClaimV1")
        if type(self.control_state_changed) is not bool:
            raise TypeError("control_state_changed must be boolean")
        if self.provider_record_digest is not None:
            _require_text(
                "provider_record_digest",
                self.provider_record_digest,
                max_bytes=64,
            )
            if _RECORD_DIGEST.fullmatch(self.provider_record_digest) is None:
                raise ValueError(
                    "provider_record_digest must be lowercase SHA-256"
                )

    @property
    def family(self) -> StateOperationFamilyV1:
        raise NotImplementedError

    @property
    def effect(self) -> StateEffectV1:
        raise NotImplementedError


@dataclass(frozen=True, slots=True, kw_only=True)
class CounterApplied(_StateResultBaseV1):
    value: int
    state_version: int

    def __post_init__(self) -> None:
        super(CounterApplied, self).__post_init__()
        _require_int("value", self.value)
        _require_int("state_version", self.state_version, minimum=1)

    family = property(lambda self: StateOperationFamilyV1.MONOTONIC_COUNTER)
    effect = property(lambda self: StateEffectV1.APPLIED)


@dataclass(frozen=True, slots=True, kw_only=True)
class QuotaApplied(_StateResultBaseV1):
    used: int
    remaining: int
    effective_limit: int
    state_version: int

    def __post_init__(self) -> None:
        super(QuotaApplied, self).__post_init__()
        for name in ("used", "remaining", "effective_limit"):
            _require_int(name, getattr(self, name))
        _require_int("state_version", self.state_version, minimum=1)

    family = property(lambda self: StateOperationFamilyV1.QUOTA)
    effect = property(lambda self: StateEffectV1.APPLIED)


@dataclass(frozen=True, slots=True, kw_only=True)
class QuotaRejected(_StateResultBaseV1):
    used: int
    effective_limit: int
    state_version: int

    def __post_init__(self) -> None:
        super(QuotaRejected, self).__post_init__()
        _require_int("used", self.used)
        _require_int("effective_limit", self.effective_limit, minimum=1)
        _require_int("state_version", self.state_version, minimum=1)

    family = property(lambda self: StateOperationFamilyV1.QUOTA)
    effect = property(lambda self: StateEffectV1.REJECTED_NO_CONSUMPTION)


@dataclass(frozen=True, slots=True, kw_only=True)
class ReplayClaimed(_StateResultBaseV1):
    expires_at_ms: int
    state_version: int
    provider_time_ms: int

    def __post_init__(self) -> None:
        super(ReplayClaimed, self).__post_init__()
        _require_int("expires_at_ms", self.expires_at_ms)
        _require_int("state_version", self.state_version, minimum=1)
        _require_int("provider_time_ms", self.provider_time_ms)

    family = property(lambda self: StateOperationFamilyV1.REPLAY_TTL)
    effect = property(lambda self: StateEffectV1.APPLIED)


@dataclass(frozen=True, slots=True, kw_only=True)
class ReplayDuplicate(_StateResultBaseV1):
    expires_at_ms: int
    state_version: int
    provider_time_ms: int

    def __post_init__(self) -> None:
        super(ReplayDuplicate, self).__post_init__()
        _require_int("expires_at_ms", self.expires_at_ms)
        _require_int("state_version", self.state_version, minimum=1)
        _require_int("provider_time_ms", self.provider_time_ms)

    family = property(lambda self: StateOperationFamilyV1.REPLAY_TTL)
    effect = property(lambda self: StateEffectV1.REJECTED_NO_CONSUMPTION)


@dataclass(frozen=True, slots=True, kw_only=True)
class WindowApplied(_StateResultBaseV1):
    used: int
    remaining: int
    effective_limit: int
    state_version: int
    provider_time_ms: int

    def __post_init__(self) -> None:
        super(WindowApplied, self).__post_init__()
        for name in ("used", "remaining", "effective_limit", "provider_time_ms"):
            _require_int(name, getattr(self, name))
        _require_int("state_version", self.state_version, minimum=1)

    family = property(lambda self: StateOperationFamilyV1.SLIDING_WINDOW)
    effect = property(lambda self: StateEffectV1.APPLIED)


@dataclass(frozen=True, slots=True, kw_only=True)
class WindowRejected(_StateResultBaseV1):
    used: int
    effective_limit: int
    retry_after_ms: int | None
    state_version: int
    provider_time_ms: int

    def __post_init__(self) -> None:
        super(WindowRejected, self).__post_init__()
        _require_int("used", self.used)
        _require_int("effective_limit", self.effective_limit, minimum=1)
        if self.retry_after_ms is not None:
            _require_int("retry_after_ms", self.retry_after_ms)
        _require_int("state_version", self.state_version, minimum=1)
        _require_int("provider_time_ms", self.provider_time_ms)

    family = property(lambda self: StateOperationFamilyV1.SLIDING_WINDOW)
    effect = property(lambda self: StateEffectV1.REJECTED_NO_CONSUMPTION)


@dataclass(frozen=True, slots=True, kw_only=True)
class StateUnavailableNoEffect(_StateResultBaseV1):
    operation_family: StateOperationFamilyV1
    reason: StateFailureReasonV1

    def __post_init__(self) -> None:
        super(StateUnavailableNoEffect, self).__post_init__()
        if type(self.operation_family) is not StateOperationFamilyV1:
            raise TypeError("operation_family must be a contract enum")
        if type(self.reason) is not StateFailureReasonV1:
            raise TypeError("reason must be a contract enum")
        if self.reason not in {
            StateFailureReasonV1.TIMEOUT,
            StateFailureReasonV1.UNAVAILABLE,
            StateFailureReasonV1.CAPACITY_EXHAUSTED,
            StateFailureReasonV1.CLOCK_UNCERTAIN,
            StateFailureReasonV1.STALE_RESULT,
        }:
            raise ValueError("reason is incompatible with unavailable effect")

    family = property(lambda self: self.operation_family)
    effect = property(lambda self: StateEffectV1.UNAVAILABLE_NO_EFFECT)


@dataclass(frozen=True, slots=True, kw_only=True)
class StateIndeterminateMayHaveCommitted(_StateResultBaseV1):
    operation_family: StateOperationFamilyV1
    reason: StateFailureReasonV1

    def __post_init__(self) -> None:
        super(StateIndeterminateMayHaveCommitted, self).__post_init__()
        if type(self.operation_family) is not StateOperationFamilyV1:
            raise TypeError("operation_family must be a contract enum")
        if type(self.reason) is not StateFailureReasonV1:
            raise TypeError("reason must be a contract enum")
        if self.reason not in {
            StateFailureReasonV1.TIMEOUT,
            StateFailureReasonV1.POSSIBLE_COMMIT,
        }:
            raise ValueError("reason is incompatible with indeterminate effect")

    family = property(lambda self: self.operation_family)
    effect = property(lambda self: StateEffectV1.INDETERMINATE_MAY_HAVE_COMMITTED)


@dataclass(frozen=True, slots=True, kw_only=True)
class StateInvalidRequestNoEffect(_StateResultBaseV1):
    operation_family: StateOperationFamilyV1
    reason: StateFailureReasonV1

    def __post_init__(self) -> None:
        super(StateInvalidRequestNoEffect, self).__post_init__()
        if type(self.operation_family) is not StateOperationFamilyV1:
            raise TypeError("operation_family must be a contract enum")
        if type(self.reason) is not StateFailureReasonV1:
            raise TypeError("reason must be a contract enum")
        if self.reason not in {
            StateFailureReasonV1.FINGERPRINT_MISMATCH,
            StateFailureReasonV1.OPERATION_ID_CONFLICT,
            StateFailureReasonV1.INVALID_OPERATION,
            StateFailureReasonV1.CONFIGURATION_CONFLICT,
            StateFailureReasonV1.OVERFLOW,
        }:
            raise ValueError("reason is incompatible with invalid-request effect")

    family = property(lambda self: self.operation_family)
    effect = property(lambda self: StateEffectV1.INVALID_REQUEST_NO_EFFECT)


StateOperationResultV1: TypeAlias = (
    CounterApplied
    | QuotaApplied
    | QuotaRejected
    | ReplayClaimed
    | ReplayDuplicate
    | WindowApplied
    | WindowRejected
    | StateUnavailableNoEffect
    | StateIndeterminateMayHaveCommitted
    | StateInvalidRequestNoEffect
)


_EXACT_RESULTS = {
    StateOperationFamilyV1.MONOTONIC_COUNTER: (CounterApplied,),
    StateOperationFamilyV1.QUOTA: (QuotaApplied, QuotaRejected),
    StateOperationFamilyV1.REPLAY_TTL: (ReplayClaimed, ReplayDuplicate),
    StateOperationFamilyV1.SLIDING_WINDOW: (WindowApplied, WindowRejected),
}
_COMMON_RESULTS = (
    StateUnavailableNoEffect,
    StateIndeterminateMayHaveCommitted,
    StateInvalidRequestNoEffect,
)


def _reconstruct_state_result_v1(
    result: StateOperationResultV1,
) -> StateOperationResultV1:
    """Re-run constructor validation and detach every provider-owned field."""
    result_type = type(result)
    try:
        claim_raw = result.provider_claim
        if type(claim_raw) is not StateProviderClaimV1:
            raise TypeError("provider_claim must be exact")
        claim = StateProviderClaimV1(
            provider_id=claim_raw.provider_id,
            consistency_domain=claim_raw.consistency_domain,
            durability_domain=claim_raw.durability_domain,
            clock_source=claim_raw.clock_source,
            contract_version=claim_raw.contract_version,
        )
        values = {
            field_info.name: getattr(result, field_info.name)
            for field_info in fields(result_type)
        }
        values["provider_claim"] = claim
        return result_type(**values)
    except (AttributeError, TypeError, ValueError) as exc:
        raise StateResultInvalidError(
            details={"reason": "result_fields"}
        ) from exc


def _validate_result_semantics(
    operation: StateOperationV1,
    result: StateOperationResultV1,
) -> None:
    if type(result) is CounterApplied:
        if type(operation) is not CounterIncrementV1 or result.value < operation.increment:
            raise StateResultInvalidError(details={"reason": "applied_value"})
    elif type(result) is QuotaApplied:
        if type(operation) is not QuotaConsumeV1:
            raise StateResultInvalidError(details={"reason": "wrong_family"})
        if result.effective_limit > operation.limit:
            raise StateResultInvalidError(details={"reason": "effective_limit"})
        if result.used < operation.units or result.used > result.effective_limit:
            raise StateResultInvalidError(details={"reason": "applied_usage"})
        if result.remaining != result.effective_limit - result.used:
            raise StateResultInvalidError(details={"reason": "applied_remaining"})
    elif type(result) is QuotaRejected:
        if type(operation) is not QuotaConsumeV1:
            raise StateResultInvalidError(details={"reason": "wrong_family"})
        if result.effective_limit > operation.limit:
            raise StateResultInvalidError(details={"reason": "effective_limit"})
        if result.used + operation.units <= result.effective_limit:
            raise StateResultInvalidError(details={"reason": "rejection_not_proven"})
    elif type(result) is ReplayClaimed:
        if (
            type(operation) is not ReplayClaimV1
            or result.expires_at_ms != result.provider_time_ms + operation.ttl_ms
        ):
            raise StateResultInvalidError(details={"reason": "claim_expiry"})
    elif type(result) is ReplayDuplicate:
        if type(operation) is not ReplayClaimV1 or not (
            result.provider_time_ms < result.expires_at_ms
            <= result.provider_time_ms + operation.ttl_ms
        ):
            raise StateResultInvalidError(details={"reason": "duplicate_expiry"})
    elif type(result) is WindowApplied:
        if type(operation) is not SlidingWindowAdmitV1:
            raise StateResultInvalidError(details={"reason": "wrong_family"})
        if result.effective_limit > operation.limit:
            raise StateResultInvalidError(details={"reason": "effective_limit"})
        if result.used < operation.units or result.used > result.effective_limit:
            raise StateResultInvalidError(details={"reason": "applied_usage"})
        if result.remaining != result.effective_limit - result.used:
            raise StateResultInvalidError(details={"reason": "applied_remaining"})
    elif type(result) is WindowRejected:
        if type(operation) is not SlidingWindowAdmitV1:
            raise StateResultInvalidError(details={"reason": "wrong_family"})
        if result.effective_limit > operation.limit:
            raise StateResultInvalidError(details={"reason": "effective_limit"})
        if result.used + operation.units <= result.effective_limit:
            raise StateResultInvalidError(details={"reason": "rejection_not_proven"})
        if result.retry_after_ms is not None and (
            result.retry_after_ms > operation.window_ms
            or operation.units > result.effective_limit
        ):
            raise StateResultInvalidError(details={"reason": "retry_after"})


def validate_state_result_v1(
    operation: StateOperationV1,
    descriptor: StateProviderDescriptorV1,
    result: object,
) -> StateOperationResultV1:
    allowed = _EXACT_RESULTS[operation.family] + _COMMON_RESULTS
    if type(result) not in allowed:
        raise StateResultInvalidError(details={"reason": "wrong_result_type"})
    typed = _reconstruct_state_result_v1(result)
    try:
        family = typed.family
        effect = typed.effect
    except BaseException as exc:
        raise StateResultInvalidError(details={"reason": "effect_unreadable"}) from exc
    if type(family) is not StateOperationFamilyV1 or family is not operation.family:
        raise StateResultInvalidError(details={"reason": "wrong_family"})
    if type(effect) is not StateEffectV1:
        raise StateResultInvalidError(details={"reason": "wrong_effect"})
    if typed.contract_version != operation.contract_version:
        raise StateResultInvalidError(details={"reason": "contract_version"})
    if typed.operation_id != operation.operation_id:
        raise StateResultInvalidError(details={"reason": "operation_id"})
    expected_fingerprint = operation_fingerprint_v1(operation)
    if not hmac.compare_digest(operation.request_fingerprint, expected_fingerprint):
        raise StateResultInvalidError(details={"reason": "operation_fingerprint"})
    if not hmac.compare_digest(typed.request_fingerprint, expected_fingerprint):
        raise StateResultInvalidError(details={"reason": "result_fingerprint"})
    expected_claim = StateProviderClaimV1.from_descriptor(descriptor)
    if typed.provider_claim != expected_claim:
        raise StateResultInvalidError(details={"reason": "provider_claim"})
    _validate_result_semantics(operation, typed)
    return typed


@runtime_checkable
class StatefulPolicyProviderV1(Protocol):
    def describe(self) -> StateProviderDescriptorV1: ...

    def execute(self, operation: StateOperationV1) -> StateOperationResultV1: ...


@runtime_checkable
class AsyncStatefulPolicyProviderV1(Protocol):
    def describe(self) -> StateProviderDescriptorV1: ...

    async def execute_async(
        self,
        operation: StateOperationV1,
    ) -> StateOperationResultV1: ...
