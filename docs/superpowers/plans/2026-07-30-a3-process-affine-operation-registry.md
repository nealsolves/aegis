# A3 Process-Affine Operation Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace portable, check-then-mark split tokens with atomic process- and instance-affine operation handles that are issued once and consumed once.

**Architecture:** Each `AEGIS` instance owns an `OperationRegistry`; module-level APIs use one private module runtime registry. Public `PreCallResult` becomes an opaque identity handle carrying no authorization state. Phase B atomically pops the live operation record before any output validation, so every attempted consumption—successful or not—burns the handle.

**Tech Stack:** Python 3.10+, `threading.Lock`, frozen dataclasses, UUIDs, `os.getpid`, pytest threads and multiprocessing, A1 `CompiledPolicy`, A2 `NormalizedOutcome`.

## Global Constraints

- No token expiry or renewal logic.
- A new operation handle is obtained at the beginning of every operation.
- Handles are process-affine and issuer-instance-affine.
- Cross-process, cross-instance, replayed, copied, pickled, and unknown handles fail closed.
- Consumption is atomic pop-and-own, not check-then-mark.
- Phase B consumes before validating output or any caller-controlled post-call field.
- Cancellation and session finalization remove outstanding records.
- No public handle contains `CompiledPolicy`, invocation snapshots, gates, or signer/sink references.
- ADR-0009 portability and mutable `_consumed` claims are superseded.

---

### Task 1: Implement the locked operation registry

**Files:**
- Create: `aegis/_internal/operation_registry.py`
- Create: `tests/test_operation_registry.py`
- Modify: `aegis/_internal/errors.py`

**Interfaces:**
- Produces: `OperationHandle(operation_id, issuer_id, process_id, policy_digest, canonicalization_profile)`
- Produces: `OperationRecord(compiled_policy, invocation_snapshot, phase_a_metadata, grouped_gates)`
- Produces: `OperationRegistry.issue(record) -> OperationHandle`
- Produces: `OperationRegistry.consume(handle) -> OperationRecord`
- Produces: `OperationRegistry.cancel(handle) -> bool`, `.cancel_all() -> int`

- [ ] **Step 1: Write failing atomic-consumption tests**

```python
def test_exactly_one_concurrent_consumer_wins(operation_record):
    registry = OperationRegistry()
    handle = registry.issue(operation_record)
    barrier = threading.Barrier(2)

    def consume():
        barrier.wait()
        try:
            registry.consume(handle)
            return "won"
        except InvocationValidationError:
            return "blocked"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: consume(), range(2)))
    assert sorted(results) == ["blocked", "won"]
```

Add issuer mismatch, PID mismatch, unknown ID, cancellation, and `cancel_all()` tests.

- [ ] **Step 2: Run and verify missing implementation**

Run: `.venv/bin/pytest tests/test_operation_registry.py -v`

Expected: FAIL on import.

- [ ] **Step 3: Implement atomic pop-and-own**

```python
@dataclass(frozen=True, slots=True)
class OperationHandle:
    operation_id: str
    issuer_id: str
    process_id: int
    policy_digest: str
    canonicalization_profile: str


@dataclass(frozen=True, slots=True)
class OperationRecord:
    compiled_policy: CompiledPolicy
    invocation_snapshot: Mapping[str, JsonValue]
    phase_a_metadata: Mapping[str, JsonValue]
    grouped_gates: Mapping[str, tuple[EnforcementGate, ...]]


class OperationRegistry:
    def __init__(self) -> None:
        self._issuer_id = uuid.uuid4().hex
        self._process_id = os.getpid()
        self._lock = threading.Lock()
        self._records: dict[str, OperationRecord] = {}

    def consume(self, handle: OperationHandle) -> OperationRecord:
        if handle.process_id != os.getpid() or handle.process_id != self._process_id:
            raise InvocationValidationError("Operation belongs to another process", code="OPERATION_PROCESS_MISMATCH")
        if not hmac.compare_digest(handle.issuer_id, self._issuer_id):
            raise InvocationValidationError("Operation belongs to another issuer", code="OPERATION_ISSUER_MISMATCH")
        with self._lock:
            record = self._records.pop(handle.operation_id, None)
        if record is None:
            raise InvocationValidationError("Operation is unknown or consumed", code="OPERATION_NOT_ACTIVE")
        if not hmac.compare_digest(handle.policy_digest, record.compiled_policy.policy_digest):
            raise InvocationValidationError("Operation policy binding failed", code="OPERATION_POLICY_MISMATCH")
        if handle.canonicalization_profile != record.compiled_policy.canonicalization_profile:
            raise InvocationValidationError("Operation profile binding failed", code="OPERATION_PROFILE_MISMATCH")
        return record
```

Change `InvocationValidationError.__init__` to accept keyword
`code: str = "INVOCATION_VALIDATION_ERROR"` so registry failures retain their
specific machine-readable reason.

- [ ] **Step 4: Run registry tests**

Run: `.venv/bin/pytest tests/test_operation_registry.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/operation_registry.py aegis/_internal/errors.py tests/test_operation_registry.py
git commit -m "feat: add atomic operation registry"
```

### Task 2: Replace `PreCallResult` authorization state with an opaque handle

**Files:**
- Modify: `aegis/_internal/enforcement.py`
- Modify: `aegis/enforcement.py`
- Modify: `aegis/__init__.py`
- Modify: `tests/test_precall_result.py`
- Modify: `tests/test_split_enforcement.py`
- Create: `tests/test_process_affine_split.py`

**Interfaces:**
- `PreCallResult` contains only `operation_id`, `issuer_id`, `process_id`, and public correlation IDs.
- Module-level `enforce_pre_call()` issues into `_MODULE_OPERATION_REGISTRY`.
- Module-level `enforce_post_call()` consumes from the same registry.

- [ ] **Step 1: Write failing public-handle tests**

```python
def test_precall_result_contains_no_authorization_state(valid_invocation):
    handle = enforce_pre_call(valid_invocation)
    forbidden = {
        "effective_policy", "resolved_guards", "resolved_conditions",
        "phase_a_metadata", "invocation_snapshot", "_consumed",
        "_phase_b_grouped_gates", "_token_hmac",
    }
    assert forbidden.isdisjoint(handle.__slots__)
```

Add pickle/deepcopy tests that prove a copied handle identifies the same one-shot operation rather than duplicating state.

- [ ] **Step 2: Run and verify the current portable token contract fails**

Run: `.venv/bin/pytest tests/test_precall_result.py tests/test_process_affine_split.py -v`

Expected: FAIL because current `PreCallResult` embeds authorization state and `_consumed`.

- [ ] **Step 3: Define the opaque result**

```python
@dataclass(frozen=True, slots=True)
class PreCallResult:
    operation_id: str
    issuer_id: str
    process_id: int
    correlation_id: str
    policy_digest: str
    canonicalization_profile: str
```

Move every former token field into `OperationRecord`. Keep the public class import path stable.

- [ ] **Step 4: Route module APIs through the registry**

Phase A calls `issue()` only after an allow-class result. Phase B calls `consume()` before type/schema validation of output.

Run: `.venv/bin/pytest tests/test_precall_result.py tests/test_split_enforcement.py tests/test_split_enforcement_edge_cases.py tests/test_process_affine_split.py -v`

Expected: PASS with updated process-affine expectations.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/enforcement.py aegis/enforcement.py aegis/__init__.py tests/test_precall_result.py tests/test_split_enforcement.py tests/test_process_affine_split.py
git commit -m "refactor: make split results process-affine handles"
```

### Task 3: Give each `AEGIS` instance and session an isolated registry

**Files:**
- Modify: `aegis/_internal/enforcement.py`
- Modify: `aegis/_internal/session.py`
- Modify: `tests/test_split_enforcement_aigc_instance.py`
- Modify: `tests/test_governance_session.py`
- Modify: `tests/test_pr11_session_replay_concurrency.py`
- Create: `tests/test_operation_registry_lifecycle.py`

**Interfaces:**
- `AEGIS.__init__()` owns `self._operation_registry`.
- `GovernanceSession` receives the parent instance registry and tracks its issued operation IDs for cleanup.

- [ ] **Step 1: Add cross-instance and cleanup tests**

```python
def test_instance_handle_rejected_by_other_instance(invocation):
    first = AEGIS()
    second = AEGIS()
    handle = first.enforce_pre_call(invocation)
    with pytest.raises(InvocationValidationError) as exc:
        second.enforce_post_call(handle, {"ok": True})
    assert exc.value.code == "OPERATION_ISSUER_MISMATCH"


def test_session_finalize_cancels_pending_handles(session, invocation):
    handle = session.enforce_step_pre_call(invocation)
    session.cancel()
    with pytest.raises(InvocationValidationError) as exc:
        session.enforce_step_post_call(handle, {"ok": True})
    assert exc.value.code == "OPERATION_NOT_ACTIVE"
```

- [ ] **Step 2: Run lifecycle tests**

Run: `.venv/bin/pytest tests/test_operation_registry_lifecycle.py tests/test_split_enforcement_aigc_instance.py tests/test_governance_session.py -v`

Expected: FAIL until instance/session registry ownership is integrated.

- [ ] **Step 3: Integrate instance ownership**

Initialize one registry per `AEGIS`; inject it into sessions. Store only operation IDs in session pending maps and cancel them on discard, cancel, exceptional exit, and finalization.

- [ ] **Step 4: Run concurrency and async variants**

Run: `.venv/bin/pytest tests/test_operation_registry_lifecycle.py tests/test_pr11_session_replay_concurrency.py tests/test_async_enforcement.py tests/test_governance_session.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/enforcement.py aegis/_internal/session.py tests/test_operation_registry_lifecycle.py tests/test_split_enforcement_aigc_instance.py tests/test_governance_session.py tests/test_pr11_session_replay_concurrency.py
git commit -m "fix: isolate and clean up operation registries"
```

### Task 4: Prove cross-process failure and supersede ADR-0009

**Files:**
- Modify: `tests/test_process_affine_split.py`
- Modify: `tests/test_architecture_security_boundaries.py`
- Create: `docs/decisions/ADR-0014-process-affine-operation-registry.md`
- Modify: `docs/decisions/ADR-0009-split-enforcement-model.md`
- Modify: `docs/PUBLIC_INTEGRATION_CONTRACT.md`
- Modify: `docs/architecture/ENFORCEMENT_PIPELINE.md`
- Modify: `docs/migration.md`

**Interfaces:**
- Produces: documented “new handle per operation; no renewal; same process and issuer only” contract.

- [ ] **Step 1: Add spawned-process tests**

Pass a pickled handle to a `multiprocessing.get_context("spawn")` child and assert `OPERATION_PROCESS_MISMATCH`. Add a fork test where supported and assert the child cannot consume the inherited registry record.

- [ ] **Step 2: Run process tests**

Run: `.venv/bin/pytest tests/test_process_affine_split.py -v`

Expected: PASS only with PID checks performed at consumption time.

- [ ] **Step 3: Add an architecture fitness check**

Fail if `PreCallResult` fields include policy/invocation data, `_consumed`, or HMAC-backed portable evidence, or if consumption does `get`/membership before a separate `pop`.

- [ ] **Step 4: Update ADR and public migration docs**

ADR-0014 supersedes ADR-0009 portability, pickle-preserved authorization, and undefined concurrency sections. Document that applications obtain a fresh handle at operation start and never renew it.

- [ ] **Step 5: Run the A3 suite and commit**

Run: `.venv/bin/pytest tests/test_operation_registry.py tests/test_operation_registry_lifecycle.py tests/test_process_affine_split.py tests/test_split_enforcement.py tests/test_governance_session.py tests/test_architecture_security_boundaries.py -v`

Expected: PASS.

```bash
git add tests/test_process_affine_split.py tests/test_architecture_security_boundaries.py docs/decisions/ADR-0014-process-affine-operation-registry.md docs/decisions/ADR-0009-split-enforcement-model.md docs/PUBLIC_INTEGRATION_CONTRACT.md docs/architecture/ENFORCEMENT_PIPELINE.md docs/migration.md
git commit -m "docs: adopt process-affine split operations"
```

## A3 Completion Gate

Run:

```bash
.venv/bin/pytest tests/test_operation_registry.py tests/test_operation_registry_lifecycle.py tests/test_process_affine_split.py tests/test_split_enforcement.py tests/test_split_enforcement_edge_cases.py tests/test_governance_session.py tests/test_architecture_security_boundaries.py -v
.venv/bin/pytest -q
```

Expected: both commands exit `0`; exactly one consumer can own an operation and no operation crosses its issuer process.
