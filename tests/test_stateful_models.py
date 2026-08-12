from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from aegis.stateful import (
    AsyncStatefulPolicyProviderV1,
    StateAddressV1,
    StateClockSourceV1,
    StateConsistencyDomainV1,
    StateDurabilityDomainV1,
    StateExecutionModeV1,
    StateOperationFamilyV1,
    StateProviderClaimV1,
    StateProviderDescriptorV1,
    StateResultInvalidError,
    StateScopeDimensionNameV1,
    StateScopeV1,
    StatefulPolicyProviderV1,
    SlidingWindowAdmitV1,
    WindowApplied,
    WindowRejected,
    bind_operation_fingerprint_v1,
    encode_state_address_v1,
    encode_state_operation_v1,
    operation_fingerprint_v1,
    validate_state_result_v1,
)


def _descriptor() -> StateProviderDescriptorV1:
    return StateProviderDescriptorV1(
        provider_id="memory-reference",
        supported_operations=frozenset(StateOperationFamilyV1),
        execution_modes=frozenset(
            {StateExecutionModeV1.SYNC, StateExecutionModeV1.ASYNC}
        ),
        consistency_domain=StateConsistencyDomainV1.INSTANCE,
        durability_domain=StateDurabilityDomainV1.NONE,
        clock_source=StateClockSourceV1.MONOTONIC,
        clock_id="memory-monotonic",
        clock_resolution_ms=1,
        min_idempotency_retention_ms=60_000,
        max_key_bytes=4096,
        max_operation_bytes=16_384,
        max_units=1_000_000,
        max_records=10_000,
    )


def _operation() -> SlidingWindowAdmitV1:
    address = StateAddressV1(
        namespace="production-us",
        policy_state_id="assistant-policy",
        constraint_id="search-window",
        scope=StateScopeV1.tenant("opaque-tenant").with_tool("search"),
    )
    return bind_operation_fingerprint_v1(
        SlidingWindowAdmitV1(
            operation_id="op-0000000000000001",
            request_fingerprint="",
            address=address,
            timeout_ms=100,
            retry_horizon_ms=1000,
            units=2,
            limit=5,
            window_ms=60_000,
            counted_unit="tool_call",
        )
    )


def _claim() -> StateProviderClaimV1:
    descriptor = _descriptor()
    return StateProviderClaimV1.from_descriptor(descriptor)


def test_operation_encoding_is_the_exact_descriptor_size_projection() -> None:
    operation = _operation()

    encoded = encode_state_operation_v1(operation)

    assert isinstance(encoded, bytes)
    assert len(encoded) > len(encode_state_address_v1(operation.address))
    assert b"op-0000000000000001" in encoded


def test_scope_repr_redacts_values_and_is_immutable() -> None:
    scope = StateScopeV1.tenant("tenant-secret").with_tool("search-secret")

    assert "tenant-secret" not in repr(scope)
    assert "search-secret" not in repr(scope)
    assert scope.dimension_names == (
        StateScopeDimensionNameV1.TENANT,
        StateScopeDimensionNameV1.TOOL,
    )
    with pytest.raises(FrozenInstanceError):
        scope.dimensions = ()  # type: ignore[misc]


@pytest.mark.parametrize("value", [True, -1, 1.5, "1"])
def test_operation_rejects_non_builtin_nonnegative_integer_fields(value) -> None:
    operation = _operation()
    with pytest.raises((TypeError, ValueError)):
        replace(operation, timeout_ms=value)


def test_address_encoding_is_order_independent_and_collision_resistant() -> None:
    left = StateAddressV1(
        namespace="a:b",
        policy_state_id="c",
        constraint_id="d",
        scope=StateScopeV1.from_values(tool="f", tenant="e|"),
    )
    reordered = StateAddressV1(
        namespace="a:b",
        policy_state_id="c",
        constraint_id="d",
        scope=StateScopeV1.from_values(tenant="e|", tool="f"),
    )
    shifted = StateAddressV1(
        namespace="a",
        policy_state_id="b:c",
        constraint_id="d",
        scope=StateScopeV1.from_values(tenant="e", tool="|f"),
    )

    assert encode_state_address_v1(left) == encode_state_address_v1(reordered)
    assert encode_state_address_v1(left) != encode_state_address_v1(shifted)
    assert encode_state_address_v1(left).startswith(b"aegis-state-address-v1\x00")


def test_operation_fingerprint_binds_every_authoritative_field() -> None:
    operation = _operation()

    assert operation.request_fingerprint == operation_fingerprint_v1(operation)
    assert len(operation.request_fingerprint) == 64
    assert operation.request_fingerprint.islower()
    for changed in (
        replace(operation, operation_id="op-0000000000000002"),
        replace(operation, timeout_ms=99),
        replace(operation, retry_horizon_ms=999),
        replace(operation, units=1),
        replace(operation, limit=4),
        replace(operation, window_ms=59_999),
        replace(operation, counted_unit="request"),
    ):
        assert operation_fingerprint_v1(changed) != operation.request_fingerprint


def test_address_and_operation_fixed_vectors() -> None:
    operation = _operation()

    assert encode_state_address_v1(operation.address).hex() == (
        "61656769732d73746174652d616464726573732d763100"
        "010000000d70726f64756374696f6e2d7573"
        "0200000010617373697374616e742d706f6c696379"
        "030000000d7365617263682d77696e646f77"
        "10001100120013010000000d6f70617175652d74656e616e74"
        "1401000000067365617263681500"
    )
    assert operation.request_fingerprint == (
        "623acfa7554ba228bc32c52f466bc6fb88a2c3ae6ccbc81617d7eb85aa7274e7"
    )


def test_result_validation_accepts_exact_applied_result() -> None:
    operation = _operation()
    result = WindowApplied(
        operation_id=operation.operation_id,
        request_fingerprint=operation.request_fingerprint,
        provider_claim=_claim(),
        used=2,
        remaining=3,
        effective_limit=5,
        state_version=1,
        provider_time_ms=1234,
        control_state_changed=True,
    )

    validated = validate_state_result_v1(operation, _descriptor(), result)
    assert validated == result
    assert validated is not result


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider_time_ms", -1),
        ("state_version", 0),
        ("control_state_changed", 1),
        ("provider_record_digest", "not-a-digest"),
    ],
)
def test_result_validation_reconstructs_hostile_exact_type(field, value) -> None:
    operation = _operation()
    result = WindowApplied(
        operation_id=operation.operation_id,
        request_fingerprint=operation.request_fingerprint,
        provider_claim=_claim(),
        used=2,
        remaining=3,
        effective_limit=5,
        state_version=1,
        provider_time_ms=1234,
    )
    object.__setattr__(result, field, value)

    with pytest.raises(StateResultInvalidError) as captured:
        validate_state_result_v1(operation, _descriptor(), result)

    assert captured.value.details == {"reason": "result_fields"}


def test_common_result_rejects_reason_from_another_effect_class() -> None:
    from aegis.stateful import StateFailureReasonV1, StateUnavailableNoEffect

    operation = _operation()
    with pytest.raises(ValueError):
        StateUnavailableNoEffect(
            operation_id=operation.operation_id,
            request_fingerprint=operation.request_fingerprint,
            provider_claim=_claim(),
            operation_family=operation.family,
            reason=StateFailureReasonV1.OVERFLOW,
        )


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"used": 6, "remaining": 0}, "applied_usage"),
        ({"used": 2, "remaining": 4}, "applied_remaining"),
        ({"effective_limit": 6, "remaining": 4}, "effective_limit"),
    ],
)
def test_result_validation_rejects_semantically_impossible_allow(
    changes, reason
) -> None:
    operation = _operation()
    fields = dict(
        operation_id=operation.operation_id,
        request_fingerprint=operation.request_fingerprint,
        provider_claim=_claim(),
        used=2,
        remaining=3,
        effective_limit=5,
        state_version=1,
        provider_time_ms=1234,
    )
    fields.update(changes)
    result = WindowApplied(**fields)

    with pytest.raises(StateResultInvalidError) as captured:
        validate_state_result_v1(operation, _descriptor(), result)
    assert captured.value.details == {"reason": reason}


def test_result_validation_rejects_wrong_family_payload(monkeypatch) -> None:
    operation = _operation()
    result = WindowRejected(
        operation_id=operation.operation_id,
        request_fingerprint=operation.request_fingerprint,
        provider_claim=_claim(),
        used=5,
        effective_limit=5,
        retry_after_ms=1000,
        state_version=2,
        provider_time_ms=1234,
        control_state_changed=False,
    )

    monkeypatch.setattr(WindowRejected, "effect", property(lambda self: "applied"))
    with pytest.raises(StateResultInvalidError) as captured:
        validate_state_result_v1(operation, _descriptor(), result)
    assert captured.value.details == {"reason": "wrong_effect"}


def test_provider_protocols_are_runtime_checkable() -> None:
    class Both:
        def describe(self):
            return _descriptor()

        def execute(self, operation):
            raise NotImplementedError

        async def execute_async(self, operation):
            raise NotImplementedError

    provider = Both()
    assert isinstance(provider, StatefulPolicyProviderV1)
    assert isinstance(provider, AsyncStatefulPolicyProviderV1)


def test_stateful_error_types_are_public_and_secret_safe() -> None:
    error = StateResultInvalidError(details={"reason": "wrong_effect"})

    assert error.code == "STATE_PROVIDER_RESULT_INVALID"
    assert error.details == {"reason": "wrong_effect"}
    assert "tenant-secret" not in str(error)
