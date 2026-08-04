# B4 Workflow Claimed-Set and Completeness Metadata Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Sign a session-scoped, ordered claim over every allocated invocation
attempt, each backed by one terminal finalized artifact, while reporting
completeness as unproven until #46 supplies an external checkpoint.

**Architecture:** `GovernanceSession` atomically allocates `step_index` before the first authorization gate. Every attempt—allowed, rejected, failed, or canceled—must reach one terminal invocation artifact. The separately signed workflow artifact contains `step_count` and ordered `(step_index, invocation_checksum)` entries; a typed verifier compares that claim with a supplied artifact set.

**Tech Stack:** Python 3.10+, per-session `threading.Lock`, B2 finalizer/workflow signing domain, B1 typed verification, pytest concurrency.

## Global Constraints

- Workflow artifacts never join invocation chains.
- Step indices are zero-based, monotonic, atomic, gapless, and never reused.
- Allocation occurs before the first authorization gate.
- Completion order may differ from index order.
- Every allocated attempt requires one terminal finalized invocation record.
- `step_count` is the allocated-attempt count (`_next_step_index`), not the
  number of surviving/finalized records.
- Workflow signature covers schema/profile, session identity, final status, count, ordered pairs, summaries, and workflow checksum.
- A valid claimed set proves integrity/order of the supplied set, not full historical completeness.
- Only #46 can upgrade completeness from `UNPROVEN` to `CHECKPOINT_PROVEN`.

---

### Task 1: Add atomic per-session attempt indexing

**Files:**
- Modify: `aegis/_internal/session.py`
- Create: `tests/test_session_step_index.py`
- Modify: `tests/test_pr11_session_replay_concurrency.py`

**Interfaces:**
- Produces: `SessionAttempt(step_index, step_id, attempt_id, terminal_artifact_checksum | None)`
- `GovernanceSession._allocate_step_index() -> int`

- [ ] **Step 1: Write concurrent allocation tests**

```python
def test_concurrent_step_indices_are_gapless_and_unique(session, invocations):
    with ThreadPoolExecutor(max_workers=8) as pool:
        handles = list(pool.map(session.enforce_step_pre_call, invocations))
    indices = sorted(handle.step_index for handle in handles)
    assert indices == list(range(len(handles)))
```

Also prove rejected Phase A attempts retain an index and indices follow start/allocation order, not completion order.

- [ ] **Step 2: Run and verify no index contract exists**

Run: `.venv/bin/pytest tests/test_session_step_index.py tests/test_pr11_session_replay_concurrency.py -v`

Expected: FAIL.

- [ ] **Step 3: Implement locked allocation**

```python
@dataclass(frozen=True, slots=True)
class SessionAttempt:
    step_index: int
    step_id: str
    attempt_id: int
    invocation_checksum: str | None
    terminal: TerminalClass | None


def _allocate_step_index(self, step_id: str, attempt_id: int) -> int:
    with self._attempt_lock:
        index = self._next_step_index
        self._next_step_index += 1
        self._attempts[index] = SessionAttempt(index, step_id, attempt_id, None)
        return index
```

Call immediately after minimum `AttemptEnvelope` allocation and before sequence, transition, hook, role, or risk gates.

- [ ] **Step 4: Bind index into invocation correlation metadata**

Every terminal invocation draft includes `session_id`, `step_id`, `step_index`, and workflow policy digest before checksum/signing.

Run: `.venv/bin/pytest tests/test_session_step_index.py tests/test_pr11_session_replay_concurrency.py tests/test_workflow_evidence_signing.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/session.py tests/test_session_step_index.py tests/test_pr11_session_replay_concurrency.py
git commit -m "feat: allocate atomic workflow step indices"
```

### Task 2: Require one terminal finalized record per allocated attempt

**Files:**
- Modify: `aegis/_internal/session.py`
- Modify: `aegis/_internal/evidence_finalizer.py`
- Create: `tests/test_session_attempt_terminal_records.py`
- Modify: `tests/test_governance_session.py`

**Interfaces:**
- Produces: `GovernanceSession.record_terminal_attempt(step_index, invocation_checksum, terminal)`
- Session finalization reads immutable attempt records sorted by index.

- [ ] **Step 1: Write omission and out-of-order tests**

```python
def test_session_cannot_complete_with_allocated_unfinalized_attempt(session):
    session._allocate_step_index("s1", 1)
    with pytest.raises(SessionStateError) as exc:
        session.finalize()
    assert exc.value.code == "SESSION_ATTEMPT_INCOMPLETE"


def test_out_of_order_completion_records_by_index(session):
    # allocate 0 and 1, finalize 1 then 0
    assert [r.step_index for r in session.finalized_attempts()] == [0, 1]


@pytest.mark.parametrize("status", ["FAILED", "CANCELED", "INCOMPLETE"])
def test_no_session_status_can_hide_an_allocated_attempt(session, status):
    session._allocate_step_index("s1", 1)
    with pytest.raises(SessionStateError) as exc:
        session.finalize(status=status)
    assert exc.value.code == "SESSION_ATTEMPT_INCOMPLETE"
```

- [ ] **Step 2: Run and verify `_steps` can omit attempts**

Run: `.venv/bin/pytest tests/test_session_attempt_terminal_records.py tests/test_governance_session.py -v`

Expected: FAIL.

- [ ] **Step 3: Record finalizer callbacks atomically**

After successful invocation evidence emission, the finalizer calls the session-owned recorder with the final v2 checksum. Duplicate, unknown, or conflicting records fail closed.
Allow `SessionStateError` to accept a specific `code` keyword while retaining
`WORKFLOW_INVALID_TRANSITION` as its default.

- [ ] **Step 4: Define session terminal behavior**

Every session status requires all allocated attempts to have a terminal
invocation artifact. `COMPLETED` additionally requires no failed/canceled
attempt and no pending operation handle. Closing a session with an outstanding
handle first burns the handle and finalizes a synthetic, schema-valid
`CANCELED` invocation attempt; rejected Phase A and internal failure attempts
already finalize `DENY`/`EXECUTION_FAILURE` records through B2. If that terminal
artifact cannot be finalized/delivered, workflow finalization raises and emits
only the B2 diagnostics signal—AEGIS must not sign a survivor-derived workflow
claim.

Run: `.venv/bin/pytest tests/test_session_attempt_terminal_records.py tests/test_governance_session.py tests/test_session_core.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/session.py aegis/_internal/evidence_finalizer.py tests/test_session_attempt_terminal_records.py tests/test_governance_session.py
git commit -m "fix: require terminal records for workflow attempts"
```

### Task 3: Build and sign the workflow claimed set

**Files:**
- Modify: `aegis/_internal/session.py`
- Modify: `aegis/_internal/evidence_finalizer.py`
- Modify: both `workflow_artifact.schema.json` copies
- Create: `tests/test_workflow_claimed_set.py`
- Modify: `tests/test_workflow_evidence_signing.py`

**Interfaces:**
- Workflow body contains `step_count: int` and `invocations: list[{"step_index": int, "checksum": str}]`.

- [ ] **Step 1: Write signed-count/order tests**

```python
def test_workflow_claims_every_attempt_in_index_order(finalized_session):
    artifact = finalized_session.finalize()
    assert artifact["step_count"] == len(artifact["invocations"])
    assert [item["step_index"] for item in artifact["invocations"]] == list(range(artifact["step_count"]))
    assert verify_artifact(artifact, signer)


def test_allocated_index_one_cannot_be_relabelled_as_single_step(session):
    session._next_step_index = 2
    session._attempts = {1: terminal_record(index=1)}
    with pytest.raises(SessionStateError):
        session.finalize(status="INCOMPLETE")
```

Mutate count, reorder pairs, remove a failure attempt, duplicate an index, and assert checksum/signature verification fails.

- [ ] **Step 2: Run and verify current summary lacks the claim**

Run: `.venv/bin/pytest tests/test_workflow_claimed_set.py tests/test_workflow_evidence_signing.py -v`

Expected: FAIL.

- [ ] **Step 3: Build the workflow draft from finalized attempt records**

```python
allocated_count = self._next_step_index
records = self.terminal_attempts()
if len(records) != allocated_count:
    raise SessionStateError(code="SESSION_ATTEMPT_INCOMPLETE")
if [record.step_index for record in records] != list(range(allocated_count)):
    raise SessionStateError(code="SESSION_ATTEMPT_GAP")
body["step_count"] = allocated_count
body["invocations"] = [
    {"step_index": record.step_index, "checksum": record.invocation_checksum}
    for record in records
]
```

Use B2 workflow signing domain; workflow checksum/signature cover the entire
claim. The builder never derives `step_count` from `len(records)` without first
proving it equals the immutable allocated count and the indices are exactly
`0..allocated_count-1`.

- [ ] **Step 4: Update both schema copies and parity tests**

Require gap-representable fields structurally; semantic gaplessness remains verifier logic.

Run: `.venv/bin/pytest tests/test_workflow_claimed_set.py tests/test_workflow_evidence_signing.py tests/test_doc_parity_v090_truth.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/session.py aegis/_internal/evidence_finalizer.py schemas/workflow_artifact.schema.json aegis/schemas/workflow_artifact.schema.json tests/test_workflow_claimed_set.py tests/test_workflow_evidence_signing.py
git commit -m "feat: sign workflow invocation claimed sets"
```

### Task 4: Add typed workflow claimed-set verification

**Files:**
- Create: `aegis/_internal/workflow_verification.py`
- Create: `aegis/workflow_verification.py`
- Modify: `aegis/__init__.py`
- Create: `tests/test_workflow_claimed_set_verifier.py`
- Modify: `aegis/_internal/verification.py`

**Interfaces:**
- Produces: `WorkflowClaimStatus`: `VALID`, `INVALID`, `LEGACY`, `NOT_EVALUATED`
- Produces: `verify_workflow_claim(workflow, invocations, *, expected_checkpoint=None) -> WorkflowVerificationReport`
- Reuses B1 `Completeness`.

- [ ] **Step 1: Write supplied-set verification tests**

Test valid set, missing index, duplicate index, wrong session ID, wrong checksum, reordered set, extra supplied artifact, legacy workflow, and valid set without checkpoint.

- [ ] **Step 2: Run and verify verifier is absent**

Run: `.venv/bin/pytest tests/test_workflow_claimed_set_verifier.py -v`

Expected: FAIL on import.

- [ ] **Step 3: Implement independent verification axes**

Define the result before implementing comparison:

```python
class WorkflowClaimStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    LEGACY = "legacy"
    NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True, slots=True)
class WorkflowVerificationReport:
    claim_status: WorkflowClaimStatus
    signature_status: SignatureStatus
    completeness: Completeness
    errors: tuple[VerificationError, ...]
```

Verify workflow content/signature first; select invocation artifacts by
`session_id`; require exact count and gapless indices; compare each v2 checksum
to the signed pair. Return `Completeness.UNPROVEN` when no trusted checkpoint
is supplied.

- [ ] **Step 4: Reserve #46 upgrade point**

Accept no ad-hoc boolean anchor. Define a typed `TrustedWorkflowCheckpoint` protocol import guarded behind #46; until that type exists, `expected_checkpoint` must be `None`.

Run: `.venv/bin/pytest tests/test_workflow_claimed_set_verifier.py tests/test_typed_chain_verification.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/workflow_verification.py aegis/workflow_verification.py aegis/__init__.py aegis/_internal/verification.py tests/test_workflow_claimed_set_verifier.py
git commit -m "feat: verify workflow claimed sets"
```

### Task 5: Document assurance boundaries and freeze #46 inputs

**Files:**
- Modify: `docs/architecture/AEGIS_THREAT_MODEL.md`
- Modify: `docs/architecture/ARCHITECTURAL_INVARIANTS.md`
- Modify: `docs/PUBLIC_INTEGRATION_CONTRACT.md`
- Modify: `docs/reference/WORKFLOW_CLI.md`
- Modify: `docs/reference/WORKFLOW_QUICKSTART.md`
- Modify: `tests/test_architecture_security_boundaries.py`

**Interfaces:**
- Produces stable #46 inputs: invocation content checksum, workflow final checksum, signed step count, ordered claimed set, typed completeness.

- [ ] **Step 1: Add a workflow fitness test**

Fail if session code increments step indices without a lock, signs only successful steps, or builds workflow claims from `_steps` rather than terminal attempt records.

- [ ] **Step 2: Run the boundary test**

Run: `.venv/bin/pytest tests/test_architecture_security_boundaries.py -v`

Expected: PASS only after Tasks 1–4.

- [ ] **Step 3: Update exact assurance language**

Document: “Workflow-signed proves integrity and order of the claimed supplied set. It does not prove the host disclosed every invocation. Completeness remains unproven until a trusted checkpoint binds the expected head/count.”

- [ ] **Step 4: Run B4 and docs truth suites**

Run: `.venv/bin/pytest tests/test_session_step_index.py tests/test_session_attempt_terminal_records.py tests/test_workflow_claimed_set.py tests/test_workflow_claimed_set_verifier.py tests/test_architecture_security_boundaries.py tests/test_doc_parity_v090_truth.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add docs/architecture/AEGIS_THREAT_MODEL.md docs/architecture/ARCHITECTURAL_INVARIANTS.md docs/PUBLIC_INTEGRATION_CONTRACT.md docs/reference/WORKFLOW_CLI.md docs/reference/WORKFLOW_QUICKSTART.md tests/test_architecture_security_boundaries.py
git commit -m "docs: define workflow claimed-set assurance"
```

## B4 Completion Gate

Run:

```bash
.venv/bin/pytest tests/test_session_step_index.py tests/test_session_attempt_terminal_records.py tests/test_workflow_claimed_set.py tests/test_workflow_claimed_set_verifier.py tests/test_workflow_evidence_signing.py tests/test_architecture_security_boundaries.py -v
.venv/bin/pytest -q
```

Expected: both commands exit `0`; B1–B4 are frozen and #46 may implement trusted checkpoint binding without reopening workflow evidence semantics.

## Scoped-review repair cycle (authorized 2026-08-03)

> **For agentic workers:** REQUIRED SUB-SKILL: execute these tasks inline with
> `superpowers:executing-plans` and strict `superpowers:test-driven-development`.

**Goal:** Close the four scoped-review blockers while fixing the admitted
workflow-attempt ceiling at exactly 1,024.

**Architecture:** Treat 1,024 as an atomic pre-allocation admission boundary,
share the runtime limit between production components, and fitness-check schema
literals against it. Align correlation triggering with the audit schema,
enforce traversal budgets before child expansion, and keep exception text out
of signed workflow state.

**Tech stack:** Python 3, pytest, JSON Schema, AEGIS v2 canonicalization and
typed verification results.

### Repair Task 1: Align workflow-correlation selection

**Files:**
- Modify: `aegis/_internal/workflow_verification.py`
- Modify: `tests/test_workflow_claimed_set_verifier.py`

- [ ] Add a regression in which a valid workflow claim is supplied beside a
  schema-valid generic invocation containing only `session_id`; require the
  valid claim to remain `VALID`.
- [ ] Add incomplete triggered-correlation mutants for `step_index` and
  `workflow_policy_digest`; require `INVOCATION_CORRELATION_INVALID`.
- [ ] Run the focused tests and observe the generic-artifact regression fail for
  the current partial-correlation behavior.
- [ ] Introduce a trigger-field set containing only `step_index` and
  `workflow_policy_digest`; validate the quartet only after a trigger appears.
- [ ] Re-run the focused tests and commit the green change.

### Repair Task 2: Bound verifier traversal before expansion

**Files:**
- Modify: `aegis/_internal/workflow_verification.py`
- Modify: `tests/test_workflow_claimed_set_verifier.py`
- Modify: `tests/test_architecture_security_boundaries.py`

- [ ] Add lowered-budget tests proving an oversized exact list and dictionary
  produce a typed budget error before child expansion.
- [ ] Add an architecture mutant that moves the budget check after child-stack
  extension and prove the fitness test rejects it.
- [ ] Run the tests and observe the new cases fail.
- [ ] Add an explicit node budget and preflight container cardinality/minimum
  byte checks before enqueuing children; keep error accumulation bounded.
- [ ] Re-run focused adversarial and fitness tests and commit the green change.

### Repair Task 3: Enforce the 1,024 admitted-attempt ceiling

**Files:**
- Create: `aegis/_internal/workflow_limits.py`
- Modify: `aegis/_internal/session.py`
- Modify: `aegis/_internal/workflow_verification.py`
- Modify: `aegis/schemas/policy_dsl.schema.json`
- Modify: `schemas/policy_dsl.schema.json`
- Modify: `aegis/schemas/workflow_artifact.schema.json`
- Modify: `schemas/workflow_artifact.schema.json`
- Modify: `tests/test_session_step_index.py`
- Modify: `tests/test_workflow_claimed_set.py`
- Modify: `tests/test_architecture_security_boundaries.py`

- [ ] Add a boundary regression with `_next_step_index == 1_024`; the next
  public pre-call must raise typed `SESSION_ATTEMPT_LIMIT_EXCEEDED`, leave the
  count unchanged, allocate no attempt envelope, and emit no partial terminal.
- [ ] Add schema and fitness tests requiring all four schema maxima and the
  runtime constant to equal exactly 1,024.
- [ ] Run the tests and observe the producer/schema mismatch fail.
- [ ] Add `MAX_WORKFLOW_ATTEMPTS = 1_024` to the focused limits module, check it
  under `_attempt_lock` before increment/allocation, and use it in verification.
- [ ] Set policy `workflow.max_steps.maximum`, workflow `step_count.maximum`,
  and workflow `invocations.maxItems` to 1,024 in both schema copies.
- [ ] Re-run boundary, schema-parity, policy compiler, and B4 tests; commit green.

### Repair Task 4: Sanitize exception-path workflow summaries

**Files:**
- Modify: `aegis/_internal/session.py`
- Modify: `tests/test_session_attempt_terminal_records.py`
- Modify: `tests/test_b4_final_correctness.py`

- [ ] Add a context-manager regression that raises
  `RuntimeError("\\ud800")` after an admitted Phase B failure; require one
  terminal invocation, one valid workflow artifact, `FINALIZED`, and propagation
  of the original exception.
- [ ] Run the regression and observe missing workflow finalization.
- [ ] Replace raw exception text with bounded `exception_type` and stable
  `reason_code="SESSION_BODY_EXCEPTION"`; do not retain diagnostic message text
  in signed workflow state.
- [ ] Re-run exception, finalizer, and B4 end-to-end tests; commit green.

### Repair completion and renewed review

- [ ] Run the B4 focused portfolio and full pytest suite.
- [ ] Run `flake8 aegis`, `git diff --check`, schema-copy parity, and package
  build.
- [ ] Update lifecycle evidence with RED/GREEN commands and hashes.
- [ ] Obtain a new scoped security review, then a distinct high-risk convergence
  review. Advance beyond `IMPLEMENTING` only if both report no load-bearing
  residuals.
