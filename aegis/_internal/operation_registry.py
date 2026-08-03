"""Process- and issuer-affine storage for split enforcement operations."""

from __future__ import annotations

import hmac
import os
import threading
import uuid
from dataclasses import dataclass
from typing import Callable, Mapping, TypeVar

from aegis._internal.compiled_policy import CompiledPolicy, JsonValue
from aegis._internal.errors import InvocationValidationError
from aegis._internal.gates import EnforcementGate

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class OperationHandle:
    """Opaque public identity for one pending split enforcement operation."""

    operation_id: str
    issuer_id: str
    process_id: int
    policy_digest: str
    canonicalization_profile: str


@dataclass(frozen=True, slots=True)
class OperationRecord:
    """Private authorization state retained by the issuing runtime."""

    compiled_policy: CompiledPolicy
    invocation_snapshot: Mapping[str, JsonValue]
    phase_a_metadata: Mapping[str, JsonValue]
    grouped_gates: Mapping[str, tuple[EnforcementGate, ...]]


class OperationRegistry:
    """Issue and atomically consume single-use operation records."""

    def __init__(self) -> None:
        self._issuer_id = uuid.uuid4().hex
        self._process_id = os.getpid()
        self._lock = threading.Lock()
        self._records: dict[str, OperationRecord] = {}

    def issue(self, record: OperationRecord) -> OperationHandle:
        """Retain *record* and return its process-affine public handle."""
        if not isinstance(record, OperationRecord):
            raise TypeError("record must be an OperationRecord")
        with self._lock:
            operation_id = uuid.uuid4().hex
            while operation_id in self._records:
                operation_id = uuid.uuid4().hex
            self._records[operation_id] = record
        return OperationHandle(
            operation_id=operation_id,
            issuer_id=self._issuer_id,
            process_id=self._process_id,
            policy_digest=record.compiled_policy.policy_digest,
            canonicalization_profile=(
                record.compiled_policy.canonicalization_profile
            ),
        )

    def _validate_affinity(self, handle: object) -> OperationHandle:
        if not isinstance(handle, OperationHandle):
            raise InvocationValidationError(
                "Operation handle is invalid",
                code="OPERATION_HANDLE_INVALID",
            )
        if (
            not isinstance(handle.operation_id, str)
            or not isinstance(handle.issuer_id, str)
            or type(handle.process_id) is not int
            or not isinstance(handle.policy_digest, str)
            or not isinstance(handle.canonicalization_profile, str)
        ):
            raise InvocationValidationError(
                "Operation handle fields are invalid",
                code="OPERATION_HANDLE_INVALID",
            )
        if (
            handle.process_id != os.getpid()
            or handle.process_id != self._process_id
        ):
            raise InvocationValidationError(
                "Operation belongs to another process",
                code="OPERATION_PROCESS_MISMATCH",
            )
        if not hmac.compare_digest(handle.issuer_id, self._issuer_id):
            raise InvocationValidationError(
                "Operation belongs to another issuer",
                code="OPERATION_ISSUER_MISMATCH",
            )
        return handle

    @staticmethod
    def _validate_binding(
        handle: OperationHandle,
        record: OperationRecord,
    ) -> None:
        if not hmac.compare_digest(
            handle.policy_digest,
            record.compiled_policy.policy_digest,
        ):
            raise InvocationValidationError(
                "Operation policy binding failed",
                code="OPERATION_POLICY_MISMATCH",
            )
        if (
            handle.canonicalization_profile
            != record.compiled_policy.canonicalization_profile
        ):
            raise InvocationValidationError(
                "Operation profile binding failed",
                code="OPERATION_PROFILE_MISMATCH",
            )

    def consume(self, handle: object) -> OperationRecord:
        """Atomically pop and return the record identified by *handle*."""
        validated = self._validate_affinity(handle)
        with self._lock:
            record = self._records.pop(validated.operation_id, None)
        if record is None:
            raise InvocationValidationError(
                "Operation is unknown or consumed",
                code="OPERATION_NOT_ACTIVE",
            )
        # Binding is checked after pop by design: once process and issuer
        # affinity authenticate an attempt for a live operation ID, even a
        # tampered policy/profile binding burns that one-shot operation.
        self._validate_binding(validated, record)
        return record

    def cancel(self, handle: object) -> bool:
        """Remove one authenticated pending operation if it remains active."""
        validated = self._validate_affinity(handle)
        with self._lock:
            record = self._records.pop(validated.operation_id, None)
        if record is None:
            return False
        self._validate_binding(validated, record)
        return True

    def cancel_operation(self, operation_id: str) -> bool:
        """Remove one operation by ID for its owning runtime's cleanup path."""
        if not isinstance(operation_id, str):
            raise TypeError("operation_id must be a string")
        with self._lock:
            return self._records.pop(operation_id, None) is not None

    def apply(
        self,
        handle: object,
        operation: Callable[[OperationRecord], T],
    ) -> T:
        """Run an internal authorization check against an active record.

        The registry lock remains held for the callback, preventing Phase B
        consumption from racing a dynamic authorization decision.
        """
        validated = self._validate_affinity(handle)
        with self._lock:
            record = self._records.get(validated.operation_id)
            if record is None:
                raise InvocationValidationError(
                    "Operation is unknown or consumed",
                    code="OPERATION_NOT_ACTIVE",
                )
            self._validate_binding(validated, record)
            return operation(record)

    def cancel_all(self) -> int:
        """Remove every pending operation owned by this registry."""
        with self._lock:
            count = len(self._records)
            self._records.clear()
        return count
