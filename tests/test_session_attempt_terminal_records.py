"""Terminal evidence completeness for allocated workflow attempts."""

from __future__ import annotations

import pytest

from aegis import AEGIS, SessionStateError
from aegis._internal.outcomes import TerminalClass


CHECKSUM_ZERO = "0" * 64
CHECKSUM_ONE = "1" * 64


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
    invocation = {
        "policy_file": "tests/golden_replays/golden_policy_v1.yaml",
        "model_provider": "openai",
        "model_identifier": "gpt-4",
        "role": "planner",
        "input": {"query": "test"},
        "context": {"role_declared": True, "schema_exists": True},
    }
    handle = session.enforce_step_pre_call(invocation, step_id="s1")
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
