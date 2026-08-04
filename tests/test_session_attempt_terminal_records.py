"""Terminal evidence completeness for allocated workflow attempts."""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from aegis import (
    AEGIS,
    AIGCError,
    AuditSink,
    AuditSinkError,
    CallbackAuditSink,
    GateResult,
    INSERTION_PRE_AUTHORIZATION,
    InvocationValidationError,
    SessionStateError,
)
from aegis._internal.evidence_finalizer import finalize_legacy_invocation_artifact
from aegis._internal.gates import EnforcementGate
from aegis._internal.outcomes import TerminalClass


CHECKSUM_ZERO = "0" * 64
CHECKSUM_ONE = "1" * 64


def _invocation(*, context: dict | None = None) -> dict:
    return {
        "policy_file": "tests/golden_replays/golden_policy_v1.yaml",
        "model_provider": "openai",
        "model_identifier": "gpt-4",
        "role": "planner",
        "input": {"query": "test"},
        "context": context
        or {"role_declared": True, "schema_exists": True},
    }


@pytest.fixture
def session():
    return AEGIS().open_session(session_id="terminal-attempt-session")


def test_session_cannot_complete_with_allocated_unfinalized_attempt(session):
    """Removing the completeness guard would sign an omitted attempt."""
    session._allocate_step_index("s1", 1)

    with pytest.raises(SessionStateError) as exc_info:
        session.finalize()

    assert exc_info.value.code == "SESSION_ATTEMPT_INCOMPLETE"


def test_out_of_order_completion_records_by_index(session):
    """Returning insertion order would misstate concurrent attempt order."""
    first = session._allocate_step_index("s1", 1)
    second = session._allocate_step_index("s2", 2)

    session.record_terminal_attempt(second, CHECKSUM_ONE, TerminalClass.DENY)
    session.record_terminal_attempt(first, CHECKSUM_ZERO, TerminalClass.ALLOW)

    assert [record.step_index for record in session.finalized_attempts()] == [0, 1]


@pytest.mark.parametrize("status", ["FAILED", "CANCELED", "INCOMPLETE"])
def test_no_session_status_can_hide_an_allocated_attempt(session, status):
    """Changing status must not bypass the all-attempt completeness rule."""
    session._allocate_step_index("s1", 1)

    with pytest.raises(SessionStateError) as exc_info:
        session.finalize(status=status)

    assert exc_info.value.code == "SESSION_ATTEMPT_INCOMPLETE"


def test_terminal_recorder_rejects_unknown_attempt(session):
    """Accepting an unallocated index would let evidence enter another claim."""
    with pytest.raises(SessionStateError) as exc_info:
        session.record_terminal_attempt(0, CHECKSUM_ZERO, TerminalClass.ALLOW)

    assert exc_info.value.code == "SESSION_ATTEMPT_UNKNOWN"


def test_terminal_recorder_rejects_duplicate_or_conflicting_record(session):
    """Overwriting a terminal record would make one attempt claim two outcomes."""
    index = session._allocate_step_index("s1", 1)
    session.record_terminal_attempt(index, CHECKSUM_ZERO, TerminalClass.ALLOW)

    with pytest.raises(SessionStateError) as duplicate:
        session.record_terminal_attempt(index, CHECKSUM_ZERO, TerminalClass.ALLOW)
    with pytest.raises(SessionStateError) as conflict:
        session.record_terminal_attempt(index, CHECKSUM_ONE, TerminalClass.DENY)

    assert duplicate.value.code == "SESSION_ATTEMPT_DUPLICATE"
    assert conflict.value.code == "SESSION_ATTEMPT_CONFLICT"


def test_successful_invocation_finalization_records_terminal_attempt(session):
    """Dropping the finalizer callback would leave a successful step unfinalized."""
    handle = session.enforce_step_pre_call(_invocation(), step_id="s1")
    artifact = session.enforce_step_post_call(
        handle,
        {"result": "answer", "confidence": 0.95},
    )

    assert session.finalized_attempts() == (
        session._attempts[handle.step_index],
    )
    record = session.finalized_attempts()[0]
    assert record.invocation_checksum == artifact["checksum"]
    assert record.terminal is TerminalClass.ALLOW


def test_completed_session_rejects_failed_attempt(session):
    """A non-allow terminal must prevent a successful workflow claim."""
    index = session._allocate_step_index("s1", 1)
    session.record_terminal_attempt(index, CHECKSUM_ZERO, TerminalClass.DENY)
    session.complete()

    with pytest.raises(SessionStateError) as exc_info:
        session.finalize()

    assert exc_info.value.code == "SESSION_ATTEMPT_NOT_SUCCESSFUL"


def test_all_pending_capabilities_are_burned_before_cancellation_delivery():
    """A first delivery failure must not leave a later authorization live."""
    class RecoveringSink(AuditSink):
        def __init__(self):
            self.fail = True
            self.observed = []

        def emit(self, artifact):
            self.observed.append(artifact)
            if self.fail:
                raise RuntimeError("delivery unavailable")

    sink = RecoveringSink()
    governance = AEGIS(sink=sink)
    session = governance.open_session(session_id="multi-pending-failure")
    handles = [
        session.enforce_step_pre_call(_invocation(), step_id=f"s{index}")
        for index in range(2)
    ]

    with pytest.raises(AuditSinkError):
        session.finalize(status="INCOMPLETE")

    assert all(
        handle.operation_id not in governance._operation_registry._records
        for handle in handles
    )
    assert set(session._pending_results) == {
        handle.operation_id for handle in handles
    }
    assert session.finalized_attempts() == ()
    assert session.workflow_artifact is None
    assert governance.evidence_diagnostics().evidence_delivery_failures_total == 1

    sink.fail = False
    artifact = session.finalize(status="INCOMPLETE")
    assert artifact["status"] == "INCOMPLETE"
    assert len(session.finalized_attempts()) == 2
    assert session._pending_results == {}


def test_internal_phase_b_failure_finalizes_execution_failure(monkeypatch):
    """An unexpected post-consume exception must still terminalize its attempt."""
    emitted = []
    governance = AEGIS(sink=CallbackAuditSink(emitted.append))
    session = governance.open_session(session_id="phase-b-internal-failure")
    handle = session.enforce_step_pre_call(_invocation(), step_id="s1")

    def fail_internal_builder(_record, _output):
        raise RuntimeError("internal evidence builder failed")

    monkeypatch.setattr(
        governance,
        "_enforce_consumed_post_call",
        fail_internal_builder,
    )

    with pytest.raises(RuntimeError, match="internal evidence builder failed"):
        session.enforce_step_post_call(handle, {"result": "unused"})

    record = session.finalized_attempts()[0]
    assert record.step_index == handle.step_index
    assert record.terminal is TerminalClass.EXECUTION_FAILURE
    assert record.invocation_checksum == emitted[0]["checksum"]
    assert handle.operation_id not in session._pending_results

    workflow = session.finalize(status="FAILED")
    assert workflow["status"] == "FAILED"


def test_pending_cancellation_context_is_detached_from_nested_list_mutation():
    """Mutating caller context after Phase A must not alter canceled evidence."""
    emitted = []
    nested_values = ["authorized"]
    governance = AEGIS(sink=CallbackAuditSink(emitted.append))
    session = governance.open_session(session_id="detached-cancel-context")
    session.enforce_step_pre_call(
        _invocation(
            context={
                "role_declared": True,
                "schema_exists": True,
                "nested": {"values": nested_values},
            }
        ),
        step_id="s1",
    )

    nested_values.append("host-mutation")
    session.finalize(status="INCOMPLETE")

    canceled = next(
        artifact
        for artifact in emitted
        if artifact.get("enforcement_result") == "FAIL"
    )
    assert canceled["context"]["nested"]["values"] == ["authorized"]


def test_unexpected_registry_consume_failure_cleans_up_and_emits_once(monkeypatch):
    """A registry exception must not leave a live handle for a second artifact."""
    emitted = []
    governance = AEGIS(sink=CallbackAuditSink(emitted.append))
    session = governance.open_session(session_id="consume-failure-session")
    handle = session.enforce_step_pre_call(_invocation(), step_id="s1")

    def fail_consume(_handle):
        raise RuntimeError("raw-registry-secret")

    monkeypatch.setattr(governance._operation_registry, "consume", fail_consume)

    with pytest.raises(RuntimeError, match="raw-registry-secret"):
        session.enforce_step_post_call(handle, {"result": "unused"})

    invocation_artifacts = [
        artifact for artifact in emitted
        if artifact.get("audit_schema_version") == "2.0"
    ]
    assert len(invocation_artifacts) == 1
    assert "raw-registry-secret" not in str(invocation_artifacts[0])
    assert handle.operation_id not in governance._operation_registry._records
    assert handle.operation_id not in session._pending_results
    assert session.finalized_attempts()[0].terminal is TerminalClass.EXECUTION_FAILURE

    workflow = session.finalize(status="FAILED")
    assert workflow["invocations"] == [
        {"step_index": 0, "checksum": invocation_artifacts[0]["checksum"]}
    ]
    assert len([
        artifact for artifact in emitted
        if artifact.get("audit_schema_version") == "2.0"
    ]) == 1


def test_catchable_post_call_cancellation_cleans_up_and_terminalizes(monkeypatch):
    """CancelledError must unwind after one terminal record, not strand an attempt."""
    emitted = []
    governance = AEGIS(sink=CallbackAuditSink(emitted.append))
    session = governance.open_session(session_id="post-cancel-session")
    handle = session.enforce_step_pre_call(_invocation(), step_id="s1")

    def cancel_phase_b(_record, _output):
        raise asyncio.CancelledError()

    monkeypatch.setattr(governance, "_enforce_consumed_post_call", cancel_phase_b)

    with pytest.raises(asyncio.CancelledError):
        session.enforce_step_post_call(handle, {"result": "unused"})

    assert handle.operation_id not in governance._operation_registry._records
    assert handle.operation_id not in session._pending_results
    assert len(session.finalized_attempts()) == 1
    assert session.finalized_attempts()[0].terminal is TerminalClass.EXECUTION_FAILURE
    assert len([
        artifact for artifact in emitted
        if artifact.get("audit_schema_version") == "2.0"
    ]) == 1
    session.finalize(status="CANCELED")


def test_concurrent_finalizers_reserve_before_only_one_emission():
    """Two finalizers for one index must race before either can double-emit."""
    class FirstEmissionBlocks(AuditSink):
        def __init__(self):
            self.emitted = []
            self.first_entered = threading.Event()
            self.release_first = threading.Event()
            self._lock = threading.Lock()

        def emit(self, artifact):
            with self._lock:
                self.emitted.append(artifact)
                ordinal = len(self.emitted)
            if ordinal == 1:
                self.first_entered.set()
                assert self.release_first.wait(timeout=5)

    sink = FirstEmissionBlocks()
    governance = AEGIS(sink=sink)
    session = governance.open_session(session_id="same-index-race")
    handle = session.enforce_step_pre_call(_invocation(), step_id="s1")
    entry = session._pending_results.pop(handle.operation_id)
    governance._operation_registry.cancel_operation(handle.operation_id)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(session._finalize_canceled_entry, entry)
        assert sink.first_entered.wait(timeout=5)
        second = pool.submit(session._finalize_canceled_entry, entry)
        try:
            with pytest.raises(SessionStateError) as exc_info:
                second.result(timeout=5)
        finally:
            sink.release_first.set()
        first.result(timeout=5)

    assert exc_info.value.code == "SESSION_ATTEMPT_FINALIZING"
    assert len(sink.emitted) == 1
    assert session._attempts[handle.step_index].state.value == "terminal"
    session.finalize(status="CANCELED")


@pytest.mark.parametrize(
    ("step_index", "checksum", "terminal"),
    [
        (False, CHECKSUM_ZERO, TerminalClass.ALLOW),
        (-1, CHECKSUM_ZERO, TerminalClass.ALLOW),
        (0, "z" * 64, TerminalClass.ALLOW),
        (0, CHECKSUM_ZERO, "allow"),
    ],
)
def test_terminal_recorder_rejects_malformed_arguments(
    session,
    step_index,
    checksum,
    terminal,
):
    """Malformed terminal arguments must never advance an allocated record."""
    allocated = session._allocate_step_index("s1", 1)

    with pytest.raises(SessionStateError):
        session.record_terminal_attempt(step_index, checksum, terminal)

    assert session._attempts[allocated].invocation_checksum is None
    assert session._attempts[allocated].terminal is None
    session.record_terminal_attempt(
        allocated,
        CHECKSUM_ZERO,
        TerminalClass.EXECUTION_FAILURE,
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda invocation: invocation["input"].update(number=2**60),
        lambda invocation: invocation["context"].update(text="\ud800"),
    ],
    ids=["unsafe-integer", "lone-surrogate"],
)
def test_non_v2_invocation_is_rejected_before_registry_issuance(mutation):
    """An invocation outside the v2 domain must not mint an operation handle."""
    emitted = []
    governance = AEGIS(sink=CallbackAuditSink(emitted.append))
    session = governance.open_session(session_id="pre-registry-normalization")
    invocation = _invocation()
    mutation(invocation)

    with pytest.raises(AIGCError) as exc_info:
        session.enforce_step_pre_call(invocation, step_id="s1")

    assert exc_info.value.audit_artifact is not None
    assert governance._operation_registry._records == {}
    assert session._pending_results == {}
    assert len(session.finalized_attempts()) == 1
    assert len(emitted) == 1
    session.finalize(status="FAILED")


@pytest.mark.parametrize(
    ("step_id", "participant_id"),
    [
        (object(), None),
        ("\ud800", None),
        ("s1", "\ud800"),
    ],
    ids=["object-step", "unicode-step", "unicode-participant"],
)
def test_invalid_workflow_identity_uses_safe_terminal_evidence(
    step_id,
    participant_id,
):
    """Raw workflow identities must not escape through the terminal fallback."""
    emitted = []
    governance = AEGIS(sink=CallbackAuditSink(emitted.append))
    session = governance.open_session(session_id="safe-identity-session")

    with pytest.raises(InvocationValidationError) as exc_info:
        session.enforce_step_pre_call(
            _invocation(),
            step_id=step_id,
            participant_id=participant_id,
        )

    artifact = exc_info.value.audit_artifact
    assert artifact is not None
    assert artifact["context"]["step_id"] == (
        "s1" if step_id == "s1" else "unknown"
    )
    assert "\\ud800" not in str(artifact)
    assert governance._operation_registry._records == {}
    assert session._pending_results == {}
    assert len(session.finalized_attempts()) == 1
    session.finalize(status="FAILED")


@pytest.mark.parametrize("session_id", ["", "\ud800", object()])
def test_invalid_session_identity_is_rejected_at_open_boundary(session_id):
    """A supplied invalid session identity must not be replaced or retained."""
    emitted = []
    governance = AEGIS(sink=CallbackAuditSink(emitted.append))

    with pytest.raises(InvocationValidationError) as exc_info:
        governance.open_session(session_id=session_id)

    assert exc_info.value.code == "WORKFLOW_SESSION_ID_INVALID"
    assert emitted == []


def test_fallback_delivery_failure_unwraps_internal_abort():
    """The private control-flow abort must never cross the public session API."""
    class FailingSink(AuditSink):
        def emit(self, artifact):
            del artifact
            raise RuntimeError("unavailable")

    session = AEGIS(sink=FailingSink()).open_session(
        session_id="fallback-abort-session"
    )

    with pytest.raises(AuditSinkError):
        session.enforce_step_pre_call(_invocation(), step_id=object())

    assert session.finalized_attempts() == ()


def test_origin_recorder_rejects_wrong_attempt_correlation_before_emission():
    """A terminal artifact cannot claim an index owned by another correlation."""
    emitted = []
    governance = AEGIS(sink=CallbackAuditSink(emitted.append))
    session = governance.open_session(session_id="origin-bound-session")
    attempt = governance._attempt_factory.allocate(
        "test.origin",
        "workflow",
        _invocation(),
    )
    index = session._allocate_step_index("s1", attempt.attempt_id)
    artifact = {
        "policy_file": attempt.policy_file,
        "model_provider": attempt.model_provider,
        "model_identifier": attempt.model_identifier,
        "role": attempt.role,
        "context": {
            "session_id": "other-session",
            "step_id": "s1",
            "step_index": index,
            "workflow_policy_digest": "0" * 64,
        },
        "enforcement_result": "FAIL",
        "failures": [{"code": "CANCELED", "message": "Canceled", "field": None}],
        "failure_gate": "wrapped_function_error",
        "failure_reason": "Canceled",
        "metadata": {"enforcement_mode": "split"},
    }

    with session._attempt_finalization_scope(index, attempt):
        with pytest.raises(SessionStateError) as exc_info:
            finalize_legacy_invocation_artifact(
                artifact,
                attempt=attempt,
                terminal=TerminalClass.EXECUTION_FAILURE,
            )

    assert exc_info.value.code == "SESSION_ATTEMPT_ORIGIN_MISMATCH"
    assert emitted == []
    assert session._attempts[index].state.value == "allocated"


def test_nested_gate_enforcement_cannot_terminalize_outer_session_attempt():
    """Ambient session ownership must not attach to unrelated nested enforcement."""
    nested_emitted = []
    outer_emitted = []
    nested = AEGIS(sink=CallbackAuditSink(nested_emitted.append))

    class NestedEnforcementGate(EnforcementGate):
        @property
        def name(self):
            return "nested-enforcement"

        @property
        def insertion_point(self):
            return INSERTION_PRE_AUTHORIZATION

        def evaluate(self, invocation, policy, context):
            del invocation, policy, context
            nested_invocation = _invocation()
            nested_invocation["output"] = {
                "result": "nested-answer",
                "confidence": 0.95,
            }
            nested.enforce(nested_invocation)
            return GateResult(passed=True)

    governance = AEGIS(
        sink=CallbackAuditSink(outer_emitted.append),
        custom_gates=[NestedEnforcementGate()],
    )
    session = governance.open_session(session_id="nested-origin-session")

    handle = session.enforce_step_pre_call(_invocation(), step_id="outer-step")
    assert session.finalized_attempts() == ()

    outer = session.enforce_step_post_call(
        handle,
        {"result": "answer", "confidence": 0.95},
    )
    assert session.finalized_attempts()[0].invocation_checksum == outer["checksum"]
    assert len(nested_emitted) == 1
    assert len(outer_emitted) == 1
    session.complete()
    session.finalize()
