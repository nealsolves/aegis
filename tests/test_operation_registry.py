"""Atomic process- and issuer-affine operation registry tests."""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from aegis._internal.errors import InvocationValidationError
from aegis._internal.operation_registry import (
    OperationHandle,
    OperationRecord,
    OperationRegistry,
)
from aegis._internal.policy_compiler import compile_policy


@pytest.fixture
def operation_record() -> OperationRecord:
    compiled_policy = compile_policy(
        {
            "policy_version": "1.0",
            "roles": ["operator"],
            "risk": {"mode": "strict", "threshold": 0.8},
        },
        source="operation-registry-test",
    )
    return OperationRecord(
        compiled_policy=compiled_policy,
        invocation_snapshot={"input": {"prompt": "hello"}},
        phase_a_metadata={"correlation_id": "corr-1"},
        grouped_gates={},
    )


def test_issue_binds_handle_to_registry_process_and_policy(operation_record):
    registry = OperationRegistry()

    handle = registry.issue(operation_record)

    assert isinstance(handle, OperationHandle)
    assert handle.operation_id
    assert handle.issuer_id
    assert handle.process_id == os.getpid()
    assert handle.policy_digest == operation_record.compiled_policy.policy_digest
    assert (
        handle.canonicalization_profile
        == operation_record.compiled_policy.canonicalization_profile
    )


def test_exactly_one_concurrent_consumer_wins(operation_record):
    registry = OperationRegistry()
    handle = registry.issue(operation_record)
    barrier = threading.Barrier(2)

    def consume() -> str:
        barrier.wait()
        try:
            registry.consume(handle)
            return "won"
        except InvocationValidationError as exc:
            assert exc.code == "OPERATION_NOT_ACTIVE"
            return "blocked"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: consume(), range(2)))

    assert sorted(results) == ["blocked", "won"]


def test_consume_rejects_handle_from_another_issuer_without_burning_it(
    operation_record,
):
    issuer = OperationRegistry()
    other = OperationRegistry()
    handle = issuer.issue(operation_record)

    with pytest.raises(InvocationValidationError) as exc_info:
        other.consume(handle)

    assert exc_info.value.code == "OPERATION_ISSUER_MISMATCH"
    assert issuer.consume(handle) is operation_record


def test_consume_rejects_handle_from_another_process_without_burning_it(
    operation_record,
):
    registry = OperationRegistry()
    handle = registry.issue(operation_record)
    foreign_process_handle = replace(handle, process_id=handle.process_id + 1)

    with pytest.raises(InvocationValidationError) as exc_info:
        registry.consume(foreign_process_handle)

    assert exc_info.value.code == "OPERATION_PROCESS_MISMATCH"
    assert registry.consume(handle) is operation_record


def test_consume_rejects_unknown_operation_without_burning_known_operation(
    operation_record,
):
    registry = OperationRegistry()
    handle = registry.issue(operation_record)
    unknown = replace(handle, operation_id="unknown-operation")

    with pytest.raises(InvocationValidationError) as exc_info:
        registry.consume(unknown)

    assert exc_info.value.code == "OPERATION_NOT_ACTIVE"
    assert registry.consume(handle) is operation_record


@pytest.mark.parametrize(
    ("field", "value", "expected_code"),
    [
        ("policy_digest", "forged-policy", "OPERATION_POLICY_MISMATCH"),
        (
            "canonicalization_profile",
            "forged-profile",
            "OPERATION_PROFILE_MISMATCH",
        ),
    ],
)
def test_binding_failure_burns_operation(
    operation_record,
    field,
    value,
    expected_code,
):
    registry = OperationRegistry()
    handle = registry.issue(operation_record)
    forged = replace(handle, **{field: value})

    with pytest.raises(InvocationValidationError) as exc_info:
        registry.consume(forged)

    assert exc_info.value.code == expected_code
    with pytest.raises(InvocationValidationError) as replay_exc:
        registry.consume(handle)
    assert replay_exc.value.code == "OPERATION_NOT_ACTIVE"


def test_consume_rejects_non_handle_with_typed_error(operation_record):
    registry = OperationRegistry()
    registry.issue(operation_record)

    with pytest.raises(InvocationValidationError) as exc_info:
        registry.consume(object())

    assert exc_info.value.code == "OPERATION_HANDLE_INVALID"


def test_cancel_removes_operation_once(operation_record):
    registry = OperationRegistry()
    handle = registry.issue(operation_record)

    assert registry.cancel(handle) is True
    assert registry.cancel(handle) is False
    with pytest.raises(InvocationValidationError) as exc_info:
        registry.consume(handle)
    assert exc_info.value.code == "OPERATION_NOT_ACTIVE"


def test_cancel_all_removes_every_pending_operation(operation_record):
    registry = OperationRegistry()
    handles = [registry.issue(operation_record) for _ in range(3)]

    assert registry.cancel_all() == 3
    assert registry.cancel_all() == 0
    for handle in handles:
        with pytest.raises(InvocationValidationError) as exc_info:
            registry.consume(handle)
        assert exc_info.value.code == "OPERATION_NOT_ACTIVE"
