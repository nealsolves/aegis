"""
Phase 3.2 — Audit sink tests.

Tests: both sink types, sink failure isolation, no-sink default,
set/clear, and that FAIL artifacts are also emitted to the sink.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from aegis._internal.enforcement import enforce_invocation
from aegis._internal.errors import GovernanceViolationError
from aegis._internal.errors import AuditSinkError
from aegis._internal.sinks import (
    AuditSink,
    CallbackAuditSink,
    JsonFileAuditSink,
    emit_to_sink,
    get_audit_sink,
    set_audit_sink,
    set_sink_failure_mode,
    get_sink_failure_mode,
)
from aegis._internal import sinks as sinks_module

POLICY = "tests/golden_replays/golden_policy_v1.yaml"

VALID_INVOCATION = {
    "policy_file": POLICY,
    "model_provider": "anthropic",
    "model_identifier": "claude-sonnet-4-5-20250929",
    "role": "planner",
    "input": {"task": "analyse"},
    "output": {"result": "ok", "confidence": 0.9},
    "context": {"role_declared": True, "schema_exists": True},
}


@pytest.fixture(autouse=True)
def clear_sink():
    """Ensure no sink bleeds between tests."""
    set_audit_sink(None)
    set_sink_failure_mode("log")
    yield
    set_audit_sink(None)
    set_sink_failure_mode("log")


# --- CallbackAuditSink ---

def test_callback_sink_called_on_pass():
    received = []
    set_audit_sink(CallbackAuditSink(received.append))

    enforce_invocation(VALID_INVOCATION)

    assert len(received) == 1
    assert received[0]["enforcement_result"] == "PASS"


def test_callback_sink_called_on_fail():
    received = []
    set_audit_sink(CallbackAuditSink(received.append))

    bad = {**VALID_INVOCATION, "role": "attacker"}
    with pytest.raises(GovernanceViolationError):
        enforce_invocation(bad)

    assert len(received) == 1
    assert received[0]["enforcement_result"] == "FAIL"


def test_callback_sink_receives_complete_artifact():
    received = []
    set_audit_sink(CallbackAuditSink(received.append))

    enforce_invocation(VALID_INVOCATION)

    artifact = received[0]
    for field in ("enforcement_result", "policy_file", "role", "input_checksum", "output_checksum"):
        assert field in artifact, f"Missing field: {field}"


# --- JsonFileAuditSink ---

def test_json_file_sink_writes_jsonl(tmp_path):
    sink_file = tmp_path / "audit.jsonl"
    set_audit_sink(JsonFileAuditSink(sink_file))

    enforce_invocation(VALID_INVOCATION)

    lines = sink_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    artifact = json.loads(lines[0])
    assert artifact["enforcement_result"] == "PASS"


def test_json_file_sink_appends_multiple(tmp_path):
    sink_file = tmp_path / "audit.jsonl"
    set_audit_sink(JsonFileAuditSink(sink_file))

    enforce_invocation(VALID_INVOCATION)
    enforce_invocation(VALID_INVOCATION)

    lines = sink_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2


def test_json_file_sink_fail_artifact_appended(tmp_path):
    sink_file = tmp_path / "audit.jsonl"
    set_audit_sink(JsonFileAuditSink(sink_file))

    bad = {**VALID_INVOCATION, "role": "attacker"}
    with pytest.raises(GovernanceViolationError):
        enforce_invocation(bad)

    lines = sink_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    artifact = json.loads(lines[0])
    assert artifact["enforcement_result"] == "FAIL"


def test_json_file_sink_creates_new_file_with_secure_mode(tmp_path):
    sink_file = tmp_path / "audit.jsonl"
    previous_umask = os.umask(0o022)
    try:
        JsonFileAuditSink(sink_file).emit({"result": "PASS"})
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(sink_file.stat().st_mode) == 0o600


def test_json_file_sink_preserves_existing_content(tmp_path):
    sink_file = tmp_path / "audit.jsonl"
    sink_file.write_text('{"existing":true}\n', encoding="utf-8")

    JsonFileAuditSink(sink_file).emit({"result": "PASS"})

    assert sink_file.read_text(encoding="utf-8") == (
        '{"existing":true}\n{"result": "PASS"}\n'
    )


def test_json_file_sink_rejects_symlink_without_touching_target(tmp_path):
    target = tmp_path / "target.jsonl"
    target.write_bytes(b"original\n")
    link = tmp_path / "audit.jsonl"
    link.symlink_to(target)

    with pytest.raises(AuditSinkError) as exc_info:
        JsonFileAuditSink(link).emit({"result": "PASS"})

    assert exc_info.value.code == "AUDIT_SINK_ERROR"
    assert str(exc_info.value) == "Secure JSONL audit delivery failed"
    assert target.read_bytes() == b"original\n"


def test_json_file_sink_rejects_directory_with_stable_error(tmp_path):
    with pytest.raises(AuditSinkError) as exc_info:
        JsonFileAuditSink(tmp_path).emit({"result": "PASS"})

    assert exc_info.value.code == "AUDIT_SINK_ERROR"
    assert str(exc_info.value) == "Secure JSONL audit delivery failed"
    assert str(tmp_path) not in str(exc_info.value)


def test_json_file_sink_normalizes_invalid_path_value_error():
    with pytest.raises(AuditSinkError) as exc_info:
        JsonFileAuditSink("audit\x00.jsonl").emit({"result": "PASS"})

    assert exc_info.value.code == "AUDIT_SINK_ERROR"
    assert str(exc_info.value) == "Secure JSONL audit delivery failed"
    assert "null" not in str(exc_info.value).lower()


def test_json_file_sink_concurrent_large_appends_remain_complete(tmp_path):
    sink_file = tmp_path / "audit.jsonl"
    sink = JsonFileAuditSink(sink_file)
    records = [
        {"record": index, "payload": str(index) * 20_000}
        for index in range(32)
    ]
    start = Barrier(8)

    def emit_with_synchronized_start(record):
        if record["record"] < 8:
            start.wait()
        sink.emit(record)

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(emit_with_synchronized_start, records))

    written = [json.loads(line) for line in sink_file.read_text().splitlines()]
    assert sorted(record["record"] for record in written) == list(range(32))
    assert all(
        record["payload"] == str(record["record"]) * 20_000
        for record in written
    )


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unsupported")
def test_secure_descriptor_rejects_fifo(tmp_path):
    fifo = tmp_path / "audit.fifo"
    os.mkfifo(fifo)

    with pytest.raises(AuditSinkError):
        sinks_module._open_secure_append_descriptor(fifo)


def test_secure_descriptor_uses_nofollow_when_supported(tmp_path, monkeypatch):
    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("O_NOFOLLOW unsupported")
    sink_file = tmp_path / "audit.jsonl"
    seen_flags = None
    real_open = os.open

    def recording_open(path, flags, mode=0o777):
        nonlocal seen_flags
        seen_flags = flags
        return real_open(path, flags, mode)

    monkeypatch.setattr(sinks_module.os, "open", recording_open)
    descriptor = sinks_module._open_secure_append_descriptor(sink_file)
    os.close(descriptor)

    assert seen_flags is not None
    assert seen_flags & os.O_NOFOLLOW


def test_secure_descriptor_uses_nonblocking_open_to_bound_fifo_race(
    tmp_path,
):
    if not hasattr(os, "O_NONBLOCK") or not hasattr(os, "mkfifo"):
        pytest.skip("O_NONBLOCK unsupported")
    script = """
import os
import sys
from pathlib import Path
from aegis._internal.errors import AuditSinkError
from aegis._internal import sinks

root = Path(sys.argv[1])
path = root / "audit.jsonl"
path.write_bytes(b"regular\\n")
real_open = os.open

def swap_to_fifo_then_open(open_path, flags, mode=0o777):
    path.unlink()
    os.mkfifo(path)
    return real_open(open_path, flags, mode)

sinks.os.open = swap_to_fifo_then_open
try:
    sinks.JsonFileAuditSink(path).emit({"result": "PASS"})
except AuditSinkError:
    print("rejected")
else:
    raise SystemExit("FIFO race was accepted")
"""

    completed = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
        timeout=3,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "rejected\n"


def test_nofollow_blocks_symlink_swap_race(tmp_path, monkeypatch):
    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("O_NOFOLLOW unsupported")
    sink_file = tmp_path / "audit.jsonl"
    sink_file.write_bytes(b"original\n")
    target = tmp_path / "target.jsonl"
    target.write_bytes(b"target\n")
    real_open = os.open

    def swap_then_open(path, flags, mode=0o777):
        sink_file.unlink()
        sink_file.symlink_to(target)
        return real_open(path, flags, mode)

    monkeypatch.setattr(sinks_module.os, "open", swap_then_open)

    with pytest.raises(AuditSinkError):
        JsonFileAuditSink(sink_file).emit({"result": "PASS"})

    assert target.read_bytes() == b"target\n"


def test_no_nofollow_branch_rejects_new_file(tmp_path, monkeypatch):
    monkeypatch.setattr(sinks_module, "_O_NOFOLLOW", None)

    with pytest.raises(AuditSinkError):
        sinks_module._open_secure_append_descriptor(tmp_path / "new.jsonl")


def test_no_nofollow_branch_accepts_unchanged_regular_file(tmp_path, monkeypatch):
    sink_file = tmp_path / "audit.jsonl"
    sink_file.write_bytes(b"existing\n")
    monkeypatch.setattr(sinks_module, "_O_NOFOLLOW", None)

    descriptor = sinks_module._open_secure_append_descriptor(sink_file)
    try:
        os.write(descriptor, b"appended\n")
    finally:
        os.close(descriptor)

    assert sink_file.read_bytes() == b"existing\nappended\n"


def test_no_nofollow_branch_rejects_path_identity_race(tmp_path, monkeypatch):
    sink_file = tmp_path / "audit.jsonl"
    sink_file.write_bytes(b"existing\n")
    original_lstat = sinks_module.os.lstat
    calls = 0

    def changed_identity(path):
        nonlocal calls
        result = original_lstat(path)
        calls += 1
        if calls == 1:
            values = list(result)
            values[1] += 1
            return os.stat_result(values)
        return result

    monkeypatch.setattr(sinks_module, "_O_NOFOLLOW", None)
    monkeypatch.setattr(sinks_module.os, "lstat", changed_identity)

    with pytest.raises(AuditSinkError):
        sinks_module._open_secure_append_descriptor(sink_file)

    assert sink_file.read_bytes() == b"existing\n"


# --- Sink failure isolation ---

class _BrokenSink(AuditSink):
    def emit(self, artifact):
        raise RuntimeError("sink exploded")


def test_sink_failure_does_not_propagate():
    set_audit_sink(_BrokenSink())

    # Enforcement must succeed even if the sink raises
    audit = enforce_invocation(VALID_INVOCATION)
    assert audit["enforcement_result"] == "PASS"


def test_sink_failure_on_fail_does_not_mask_exception():
    set_audit_sink(_BrokenSink())

    bad = {**VALID_INVOCATION, "role": "attacker"}
    with pytest.raises(GovernanceViolationError):
        enforce_invocation(bad)


# --- No sink (default) ---

def test_no_sink_registered_by_default():
    assert get_audit_sink() is None


def test_no_sink_enforcement_returns_normally():
    audit = enforce_invocation(VALID_INVOCATION)
    assert audit["enforcement_result"] == "PASS"


# --- set/clear ---

def test_set_then_clear_sink():
    received = []
    set_audit_sink(CallbackAuditSink(received.append))
    assert get_audit_sink() is not None

    set_audit_sink(None)
    assert get_audit_sink() is None

    enforce_invocation(VALID_INVOCATION)
    assert len(received) == 0


# --- emit_to_sink standalone ---

def test_emit_to_sink_no_op_when_no_sink():
    emit_to_sink({"enforcement_result": "PASS"})  # must not raise


# --- Sink failure modes (D-02 completion) ---

def test_sink_failure_mode_raise_propagates():
    """In 'raise' mode, sink failures propagate as AuditSinkError."""
    set_audit_sink(_BrokenSink())
    set_sink_failure_mode("raise")

    with pytest.raises(AuditSinkError, match="Finalized evidence delivery failed"):
        enforce_invocation(VALID_INVOCATION)


def test_sink_failure_mode_log_does_not_propagate():
    """In 'log' mode, sink failures are logged but not propagated (default)."""
    set_audit_sink(_BrokenSink())
    set_sink_failure_mode("log")

    audit = enforce_invocation(VALID_INVOCATION)
    assert audit["enforcement_result"] == "PASS"


def test_sink_failure_mode_invalid_raises_valueerror():
    """Invalid failure mode raises ValueError."""
    with pytest.raises(ValueError, match="Invalid sink failure mode"):
        set_sink_failure_mode("invalid")


def test_sink_failure_mode_default_is_log():
    """Default failure mode is 'log'."""
    assert get_sink_failure_mode() == "log"


def test_audit_sink_error_has_correct_code():
    """AuditSinkError has the correct error code."""
    err = AuditSinkError("test")
    assert err.code == "AUDIT_SINK_ERROR"


# --- CR-02: Sink isolation in AEGIS class ---

def test_aigc_instance_does_not_mutate_global_sink():
    """AEGIS.enforce() must never touch the global sink state."""
    from aegis import AEGIS

    assert get_audit_sink() is None  # no prior sink
    received = []
    aegis = AEGIS(sink=CallbackAuditSink(received.append))
    aegis.enforce(VALID_INVOCATION)

    assert len(received) == 1
    # Global sink must remain untouched — AEGIS uses per-call sink injection
    assert get_audit_sink() is None


def test_aigc_instance_does_not_leak_to_global_with_previous():
    """AEGIS.enforce() must not affect a previously set global sink."""
    from aegis import AEGIS

    previous_received = []
    previous_sink = CallbackAuditSink(previous_received.append)
    set_audit_sink(previous_sink)

    instance_received = []
    aegis = AEGIS(sink=CallbackAuditSink(instance_received.append))
    aegis.enforce(VALID_INVOCATION)

    assert len(instance_received) == 1
    # Previous global sink must remain unchanged and not have received anything
    assert get_audit_sink() is previous_sink
    assert len(previous_received) == 0


def test_aigc_two_instances_isolated():
    """Two AEGIS instances with different sinks must not interfere."""
    from aegis import AEGIS

    received_a = []
    received_b = []
    aigc_a = AEGIS(sink=CallbackAuditSink(received_a.append))
    aigc_b = AEGIS(sink=CallbackAuditSink(received_b.append))

    aigc_a.enforce(VALID_INVOCATION)
    aigc_b.enforce(VALID_INVOCATION)

    assert len(received_a) == 1
    assert len(received_b) == 1
    # Each sink received only its own instance's artifact
    assert received_a[0] is not received_b[0]


def test_aigc_instance_with_none_sink_does_not_interfere():
    """AEGIS(sink=None) must not receive artifacts from another instance."""
    from aegis import AEGIS

    received = []
    aigc_sinked = AEGIS(sink=CallbackAuditSink(received.append))
    aigc_none = AEGIS()

    aigc_none.enforce(VALID_INVOCATION)
    aigc_sinked.enforce(VALID_INVOCATION)

    # Only the sinked instance's sink should have received an artifact
    assert len(received) == 1


# --- CR-03: on_sink_failure wired into runtime ---

def test_aigc_on_sink_failure_raise_is_effective():
    """AEGIS(on_sink_failure='raise') must actually raise on PASS sink failure."""
    from aegis import AEGIS

    aegis = AEGIS(sink=_BrokenSink(), on_sink_failure="raise")
    with pytest.raises(AuditSinkError, match="Finalized evidence delivery failed"):
        aegis.enforce(VALID_INVOCATION)


def test_aigc_on_sink_failure_log_is_not_a_v2_mode():
    """Best-effort delivery cannot configure an AEGIS v2 instance."""
    from aegis import AEGIS

    with pytest.raises(ValueError, match="only supports 'raise'"):
        AEGIS(sink=_BrokenSink(), on_sink_failure="log")


def test_aigc_does_not_mutate_global_failure_mode():
    """AEGIS.enforce() must never touch the global failure mode."""
    from aegis import AEGIS

    assert get_sink_failure_mode() == "log"  # default
    aegis = AEGIS(sink=CallbackAuditSink(lambda a: None), on_sink_failure="raise")
    aegis.enforce(VALID_INVOCATION)
    assert get_sink_failure_mode() == "log"  # untouched


# --- CR-03: Artifact immutability across sink boundary ---

class _MutatingSink(AuditSink):
    """Sink that attempts to mutate the artifact."""
    def emit(self, artifact):
        artifact["enforcement_result"] = "MUTATED"
        artifact["metadata"]["tampered"] = True


def test_sink_cannot_mutate_caller_artifact():
    """Sink receives a deep copy; mutations must not affect the caller's artifact."""
    set_audit_sink(_MutatingSink())

    audit = enforce_invocation(VALID_INVOCATION)
    assert audit["enforcement_result"] == "PASS"
    assert "tampered" not in audit.get("metadata", {})


def test_sink_cannot_mutate_exception_artifact():
    """Sink mutations must not affect the artifact attached to governance exceptions."""
    set_audit_sink(_MutatingSink())

    bad = {**VALID_INVOCATION, "role": "attacker"}
    with pytest.raises(GovernanceViolationError) as exc_info:
        enforce_invocation(bad)

    assert exc_info.value.audit_artifact["enforcement_result"] == "FAIL"
    assert "tampered" not in exc_info.value.audit_artifact.get("metadata", {})


def test_aigc_sink_cannot_mutate_artifact():
    """AEGIS instance sink receives a deep copy."""
    from aegis import AEGIS

    aegis = AEGIS(sink=_MutatingSink())
    audit = aegis.enforce(VALID_INVOCATION)
    assert audit["enforcement_result"] == "PASS"


# --- CR-04: FAIL artifact preserved when sink raises ---

def test_fail_path_delivery_error_replaces_allow_or_deny_return():
    """A FAIL decision cannot be reported as durable when delivery fails."""
    set_audit_sink(_BrokenSink())
    set_sink_failure_mode("raise")

    bad = {**VALID_INVOCATION, "role": "attacker"}
    with pytest.raises(AuditSinkError) as exc_info:
        enforce_invocation(bad)

    assert exc_info.value.code == "AUDIT_DELIVERY_FAILED"


def test_fail_path_delivery_error_via_aegis_instance():
    """Instance enforcement also fails closed when FAIL evidence is lost."""
    from aegis import AEGIS

    aegis = AEGIS(sink=_BrokenSink(), on_sink_failure="raise")
    bad = {**VALID_INVOCATION, "role": "attacker"}
    with pytest.raises(AuditSinkError) as exc_info:
        aegis.enforce(bad)

    assert exc_info.value.code == "AUDIT_DELIVERY_FAILED"


# --- CR-04: Pre-pipeline FAIL artifact generation ---

def test_pre_pipeline_invocation_validation_has_artifact():
    """InvocationValidationError must carry a FAIL audit artifact."""
    from aegis._internal.errors import InvocationValidationError

    bad = {**VALID_INVOCATION}
    del bad["role"]  # missing required field
    with pytest.raises(InvocationValidationError) as exc_info:
        enforce_invocation(bad)

    assert exc_info.value.audit_artifact is not None
    assert exc_info.value.audit_artifact["enforcement_result"] == "FAIL"
    assert exc_info.value.audit_artifact["failure_gate"] == "invocation_validation"


def test_pre_pipeline_policy_load_error_has_artifact():
    """PolicyLoadError must carry a FAIL audit artifact."""
    from aegis._internal.errors import PolicyLoadError

    bad = {**VALID_INVOCATION, "policy_file": "nonexistent_policy.yaml"}
    with pytest.raises(PolicyLoadError) as exc_info:
        enforce_invocation(bad)

    assert exc_info.value.audit_artifact is not None
    assert exc_info.value.audit_artifact["enforcement_result"] == "FAIL"
    assert exc_info.value.audit_artifact["failure_gate"] == "invocation_validation"


def test_pre_pipeline_aigc_strict_mode_has_artifact():
    """Strict mode PolicyValidationError must carry a FAIL audit artifact."""
    from aegis import AEGIS
    from aegis._internal.errors import PolicyValidationError

    bare_string_inv = {
        **VALID_INVOCATION,
        "policy_file": "tests/fixtures/bare_string_preconditions_policy.yaml",
    }
    aegis = AEGIS(strict_mode=True)
    with pytest.raises(PolicyValidationError) as exc_info:
        aegis.enforce(bare_string_inv)

    assert exc_info.value.audit_artifact is not None
    assert exc_info.value.audit_artifact["enforcement_result"] == "FAIL"


# --- CR-05: Sink failure gate mapping ---

def test_sink_failure_gate_is_schema_valid():
    """AuditSinkError must map to 'sink_emission' gate (schema-valid)."""
    from aegis._internal.enforcement import _map_exception_to_failure_gate

    exc = AuditSinkError("test")
    assert _map_exception_to_failure_gate(exc) == "sink_emission"


# --- CR-06: PolicyCache wired into AEGIS ---

def test_aigc_has_policy_cache():
    """AEGIS instances must have a per-instance PolicyCache."""
    from aegis import AEGIS

    aegis = AEGIS()
    assert hasattr(aegis, 'policy_cache')
    assert aegis.policy_cache is not None


def test_aigc_policy_cache_is_per_instance():
    """Two AEGIS instances must have separate PolicyCache instances."""
    from aegis import AEGIS

    a = AEGIS()
    b = AEGIS()
    assert a.policy_cache is not b.policy_cache
