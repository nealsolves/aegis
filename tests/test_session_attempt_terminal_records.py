"""Terminal evidence completeness for allocated workflow attempts."""

from __future__ import annotations

import pytest

from aegis import (
    AEGIS,
    AuditSink,
    AuditSinkError,
    CallbackAuditSink,
    SessionStateError,
)
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
