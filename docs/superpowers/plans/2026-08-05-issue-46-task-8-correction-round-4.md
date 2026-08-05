# Trusted Checkpoint Correction Round 4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining checkpoint preflight, enum-authenticity, facade lifecycle, exact JSON-native validation, dependency-closure, and callback-CFG gaps.

**Architecture:** Validate a fully materialized placeholder checkpoint before any provider callback; authenticate closed enums through explicit canonical identities that do not depend on mutable Enum registries; eagerly pin the safe checkpoint facade so reload overwrites stale values; and derive security review from exact executed symbol/import/control-flow edges with explicit pure leaves.

**Tech Stack:** Python 3.12, pytest, AST analysis, isolated subprocess probes.

## Global Constraints

- Preserve the exact 137-name top-level public API, ordering, identity, static typing, provider-neutral returns, and hardened result invariant.
- Checkpoint imports and creators execute no ambient filesystem, network, environment, clock, thread, enforcement, session, sink, or retry capabilities.
- Every production change requires a witnessed failing test first.
- Finish with two adversarial reviews, updated report/ledger, and a separate commit; do not push or create a PR.

---

### Task 1: Complete creator preflight

**Files:** `aegis/_internal/checkpoint_signing.py`, `tests/test_checkpoint_creation.py`

- [x] Add both-creator record-field mutation matrices with all five provider counters.
- [x] Witness post-callback model failures.
- [x] Construct and parse a placeholder record before `signer_identity` and map failures to `CHECKPOINT_SOURCE_INVALID`.
- [x] Run creation/vector/atomicity suites.

### Task 2: Registry-independent enum authenticity

**Files:** `aegis/_internal/signature_models.py`, `aegis/_internal/verification.py`, `tests/test_signature_models.py`, `tests/test_chain_checkpoint_verification.py`

- [x] Add forged and EnumMeta registry-mutation cases for every consumed closed enum.
- [x] Witness acceptance through enum iteration or `isinstance`.
- [x] Replace registry-dependent checks with explicit canonical `is` branches.
- [x] Run signature, chain, workflow, and invariant suites.

### Task 3: Facade lifecycle and legacy logging

**Files:** `aegis/__init__.py`, `aegis/_internal/signing.py`, `tests/test_checkpoint_cold_imports.py`, `tests/test_public_api.py`, `tests/test_evidence_finalizer_signing.py`

- [x] Add monkeypatch/import-order/reload tests and a fresh-process stderr regression.
- [x] Witness uncached/stale facade values and lastResort output.
- [x] Pin canonical checkpoint exports on reload and install exactly one NullHandler only on first legacy log.
- [x] Re-run cold probes and public API compatibility.

### Task 4: Exact JSON-native source validation

**Files:** `aegis/_internal/checkpoint_source_validation.py`, `tests/test_checkpoint_creation.py`

- [x] Add subclass, Decimal/Fraction/complex, and hostile-object differential cases before provider spies.
- [x] Witness non-native acceptance or exception paths.
- [x] Require exact JSON-native containers/scalars while retaining ordinary Draft7 integer/newline behavior.
- [x] Run differential and creator suites.

### Task 5: Fail-closed closure and expression CFG

**Files:** `tests/test_architecture_security_boundaries.py`

- [x] Add omitted import/call edges, independent closure cross-check, expression-context callbacks, wrappers, returned callbacks, safe shadows/recursion, and exhaustive-match controls.
- [x] Witness silent closure termination and CFG misses.
- [x] Follow assignment/local/module-import/higher-order/callable-instance edges; require reasoned pure leaves; summarize lexical scopes, SCCs, expression execution, dominance, and callback ceilings.
- [x] Run all architecture/adversarial cases against real roots.

### Task 6: Verification and handoff

**Files:** Task 8 report and progress ledger.

- [x] Run focused/differential/public/creation/checkpoint/chain/workflow/invariant suites.
- [x] Run full pytest, compileall, production/changed-file flake8, and diff checks.
- [x] Perform two adversarial self-reviews and close any findings with RED/GREEN.
- [ ] Update report/ledger and create a separate round-4 commit.
