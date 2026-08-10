# Issue #58 JSONL Sink Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Prevent `JsonFileAuditSink` from following symlinks or creating world-readable audit evidence while preserving fail-closed append delivery.

**Architecture:** Keep the public sink API unchanged. Add a focused internal secure-open boundary that opens the configured path once with append/create flags, uses `O_NOFOLLOW` when available, validates the opened descriptor with `fstat`, and wraps that descriptor for UTF-8 output without reopening by pathname. On platforms without `O_NOFOLLOW`, existing regular files are accepted only when pre-open and post-open identity checks agree; symlinks, races, and new-file creation fail closed because safe creation cannot be guaranteed.

**Tech Stack:** Python standard library (`os`, `stat`, `pathlib`, `json`), pytest.

## Global Constraints

- New files use creation mode `0o600`; existing-file modes are not silently changed.
- Append operations never truncate existing content.
- Unsafe targets and filesystem failures raise stable `AuditSinkError` values without paths or operating-system error text.
- AEGIS remains responsible only for secure local file creation and append; directory ownership, mount controls, rotation, retention, backup, and WORM storage remain host responsibilities.
- No new runtime dependency or public constructor argument is added.

---

### Task 1: Secure descriptor opening and append behavior

**Files:**
- Modify: `aegis/_internal/sinks.py`
- Test: `tests/test_audit_sinks.py`

**Interfaces:**
- Consumes: `JsonFileAuditSink(path: str | Path)` and `emit(audit_artifact: dict[str, Any]) -> None`.
- Produces: an internal descriptor opener returning an append-only writable file descriptor or raising `AuditSinkError`.

- [x] **Step 1: Write failing permission and append-preservation tests**

Add tests that set a permissive `0o022` umask, assert a new file's effective mode is `0o600`, seed an existing regular file, emit once, and assert the original bytes remain followed by exactly one JSON line.

- [x] **Step 2: Run the focused tests and verify RED**

Run: `/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_audit_sinks.py -k 'secure_mode or preserves_existing_content'`

Expected: the mode test fails with `0o644`; append preservation remains a characterization pass.

- [x] **Step 3: Write failing unsafe-target tests**

Add behavior tests for an existing symlink, directory, and FIFO. Each test calls the real sink, asserts `AuditSinkError(code="AUDIT_SINK_ERROR")`, and verifies the symlink target is byte-for-byte unchanged. Skip FIFO creation only where the platform lacks `os.mkfifo`.

- [x] **Step 4: Run the unsafe-target tests and verify RED**

Run: `/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_audit_sinks.py -k 'rejects_symlink or rejects_directory or rejects_fifo'`

Expected: symlink target mutation and raw pathname errors demonstrate the current unsafe behavior.

- [x] **Step 5: Write failing capability and race tests**

Monkeypatch the sink module's capability seam to exercise both branches. Assert the no-`O_NOFOLLOW` branch rejects symlinks and new-file creation, accepts an unchanged existing regular file, and rejects a simulated inode/device mismatch before writing. Assert the supported branch includes `O_NOFOLLOW` in the flags passed to `os.open`.

- [x] **Step 6: Run the capability tests and verify RED**

Run: `/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_audit_sinks.py -k 'nofollow or path_identity'`

Expected: tests fail because no descriptor-opening capability seam exists.

- [x] **Step 7: Implement the minimal secure descriptor boundary**

In `aegis/_internal/sinks.py`, construct `O_WRONLY | O_APPEND | O_CREAT`, add `O_NOFOLLOW` when supported, pass `0o600` to `os.open`, validate `stat.S_ISREG(os.fstat(fd).st_mode)`, and close the descriptor on every rejection. For the unsupported branch, use `lstat` before open, reject missing/symlink/non-regular paths, then compare `(st_dev, st_ino)` from pre-open `lstat` and post-open `fstat`; any mismatch fails closed. Wrap the accepted descriptor with `os.fdopen(..., mode="a", encoding="utf-8")` and write one serialized JSON line without reopening the path.

Catch `OSError` at the sink boundary and raise `AuditSinkError("Secure JSONL audit delivery failed") from None`; do not include the configured path or OS message.

- [x] **Step 8: Run all sink tests and verify GREEN**

Run: `/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_audit_sinks.py tests/test_fail_closed_evidence_delivery.py`

Expected: all tests pass with no new warnings.

### Task 2: Operational boundary documentation

**Files:**
- Modify: `docs/reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md`
- Test: `tests/test_append_only_evidence_guidance.py`

**Interfaces:**
- Consumes: the canonical evidence-operations guide and its maintained-copy checks.
- Produces: explicit secure-local-file versus host-managed lifecycle guidance.

- [x] **Step 1: Add a failing guidance behavior check**

Extend the canonical-guide assertions to require that `JsonFileAuditSink` documents `0600` new-file creation, symlink/non-regular rejection, platform fail-closed behavior, and host ownership of directory permissions, mount options, rotation, retention, backup, and WORM controls.

- [x] **Step 2: Run the guidance test and verify RED**

Run: `/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_append_only_evidence_guidance.py`

Expected: failure because the guide still describes issue #58 as outstanding.

- [x] **Step 3: Update the canonical guide**

Replace the stale #58 disclaimer with the implemented guarantees and the bounded host-responsibility statement. Do not claim durability, immutability, append-only/WORM lifecycle, safe rotation, or directory security.

- [x] **Step 4: Run documentation guards and verify GREEN**

Run: `/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_append_only_evidence_guidance.py tests/test_evidence_claims.py && /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python scripts/check_doc_parity.py`

Expected: all tests pass.

### Task 3: Full verification and publication

**Files:**
- Modify only if verification reveals an in-scope defect.

**Interfaces:**
- Consumes: Tasks 1–2.
- Produces: verified branch and draft pull request closing #58.

- [x] **Step 1: Run static and full test verification**

Run the repository's Python formatting/lint commands discovered from `pyproject.toml`, `git diff --check`, the full Python test suite, and any maintained documentation guard command.

- [x] **Step 2: Review the acceptance criteria line by line**

Map each #58 criterion to a test, implementation branch, or documentation statement. Confirm #51 and #52 remain closed prerequisites and that failures preserve B2's `AuditSinkError` no-allow contract.

- [x] **Step 3: Commit, push, and open a draft PR**

Stage only the plan, sink implementation, focused tests, and canonical documentation changes. Commit with a terse security-fix message, push `codex/issue-58-jsonl-sink-hardening`, and open a draft PR whose body explains the root cause, platform behavior, validation, and `Closes #58`.
