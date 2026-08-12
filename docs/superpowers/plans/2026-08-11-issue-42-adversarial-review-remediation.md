# Issue #42 Adversarial Review Remediation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and superpowers:systematic-debugging for each task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every authorization, retry, provider-integrity, session-evidence, sizing, and conformance defect found by the adversarial review of issue #42.

**Architecture:** Normalize caller-controlled tool declarations once before Phase A and reuse that detached snapshot throughout enforcement. Make provider dispatch a deadline-aware state machine with terminal malformed-result handling, reconstruct provider results across a strict validation boundary, retain idempotency for the full semantic lifetime, and preserve bounded state decisions through all session terminal paths. Expand the reusable conformance runner so its conformant verdict covers every normative scenario supported by a provider descriptor.

**Tech Stack:** Python 3.10–3.14, frozen dataclasses, asyncio, monotonic clocks, JSON Schema Draft-07, pytest.

## Global Constraints

- Preserve the approved issue #42 design and public version-1 contract.
- Every ambiguity after provider dispatch fails closed; only an exact validated in-budget `WindowApplied` authorizes.
- Caller-controlled values are normalized and detached once before multiple gates consume them.
- No state admission is rolled back, but every admission or denial must remain represented in bounded terminal evidence.
- The in-memory provider remains dependency-free, instance-local, bounded, and non-durable.
- Preserve the user's pre-existing `.gitignore` change and do not stage or overwrite it.
- Add each regression test before its production change and record the expected red result.

---

### Task 1: Canonical Tool-Call Snapshot and Evidence Capacity

**Files:**
- Modify: `aegis/_internal/enforcement.py`
- Modify: `aegis/_internal/stateful_enforcement.py`
- Modify: `aegis/_internal/session.py`
- Test: `tests/test_stateful_enforcement.py`
- Test: `tests/test_stateful_session.py`

- [ ] Add failing tests for generator and index-only `tool_calls`, caller mutation, static/dynamic double charging, and the sixty-fifth dynamic decision.
- [ ] Verify focused tests fail for missing normalization and preflight.
- [ ] Normalize a bounded concrete sequence of mapping tool calls once at the public pre-call boundary and make both stateless and stateful validation consume it.
- [ ] Reject mixed static/dynamic session charging and preflight the audit decision limit before provider dispatch.
- [ ] Run the focused enforcement and session tests to green.

### Task 2: Dispatch State Machine, Deadlines, Cancellation, and Exact Size

**Files:**
- Modify: `aegis/_internal/stateful_enforcement.py`
- Modify: `aegis/_internal/stateful_models.py`
- Test: `tests/test_stateful_enforcement.py`
- Test: `tests/test_stateful_models.py`

- [ ] Add failing sync and async tests proving malformed results are terminal, retry-horizon overruns cannot authorize, caller cancellation becomes typed indeterminate evidence, and descriptor sizing uses the exact canonical operation projection.
- [ ] Verify all new cases fail for the reviewed reasons.
- [ ] Centralize exact operation encoding/size, make validation failures nonretryable, and check remaining total budget before and after every dispatch.
- [ ] Catch caller cancellation explicitly without detached retries and preserve a bounded indeterminate state decision.
- [ ] Run focused model and enforcement tests to green.

### Task 3: Hostile Result Reconstruction and Explicit Stale Contract

**Files:**
- Modify: `aegis/_internal/stateful_models.py`
- Modify: `aegis/stateful.py`
- Test: `tests/test_stateful_models.py`
- Test: `tests/test_stateful_enforcement.py`

- [ ] Add failing tests for exact-class instances mutated after construction, constructor-bypassed instances, invalid common-result reason/effect combinations, and explicit stale results.
- [ ] Verify the hostile objects cross the current validation boundary.
- [ ] Reconstruct every accepted result through exact primitive field validation and add a closed stale no-effect result/reason that can never authorize or retry.
- [ ] Run hostile model and enforcement tests to green.

### Task 4: Reference Provider Time and Idempotency Semantics

**Files:**
- Modify: `aegis/_internal/stateful_memory.py`
- Test: `tests/test_stateful_provider.py`

- [ ] Add failing tests for a replayed operation during a live window, quota/counter duplicate retention, pre-mutation timeout, and async event-loop responsiveness.
- [ ] Verify the reviewed idempotency and timeout failures.
- [ ] Retain terminal operation records for at least their enforcement semantic lifetime, failing closed at bounded capacity instead of evicting live identities.
- [ ] Measure provider budget from receipt through lock acquisition and return typed no-effect timeout before mutation; make declared async execution non-blocking.
- [ ] Run provider tests to green.

### Task 5: Session Terminal Evidence Integrity

**Files:**
- Modify: `aegis/_internal/session.py`
- Test: `tests/test_stateful_session.py`
- Test: `tests/test_stateful_evidence.py`

- [ ] Add failing tests for static rejection, dynamic denial, pending-step cancellation, and correct failure-gate classification with state decisions preserved.
- [ ] Verify each terminal path currently drops or overwrites evidence.
- [ ] Merge attached and pending state decisions into rejection/cancellation artifacts before burning handles and use the shared failure-gate mapper.
- [ ] Run session and evidence tests to green.

### Task 6: Complete Reusable Conformance Matrix

**Files:**
- Modify: `aegis/_internal/stateful_conformance.py`
- Test: `tests/test_stateful_conformance.py`

- [ ] Add failing assertions for the complete normative scenario name matrix and deliberately broken provider fixtures.
- [ ] Verify the existing runner falsely reports incomplete coverage as conformant.
- [ ] Add descriptor-conditioned mandatory scenarios for overflow/invalid units, boundaries/tightening, exact/conflicting duplicates, configuration/version incompatibility, every scope dimension, concurrency, semantic GC, sync/async equivalence, and bounded redacted reports.
- [ ] Run conformance and provider tests to green.

### Task 7: Public Error Contract and Full Verification

**Files:**
- Modify: `aegis/_internal/restrictions.py`
- Test: `tests/test_stateful_policy_compiler.py`

- [ ] Add a failing test that stateful widening raises `StatefulCompositionError` with its stable code.
- [ ] Implement the typed translation without changing stateless composition failures.
- [ ] Run every stateful test, schema parity checks, lint/type checks configured by the repository, and the full test suite.
- [ ] Request a fresh adversarial code review and resolve every Critical or Important finding.
