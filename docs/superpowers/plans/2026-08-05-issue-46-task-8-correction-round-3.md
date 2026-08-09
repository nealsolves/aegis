# Trusted Checkpoint Correction Round 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the cold-import, schema-parity, dependency-closure, static-capability-analysis, enum-authenticity, and signer-spy gaps in the trusted checkpoint boundary.

**Architecture:** Keep checkpoint creation and verification rooted in capability-free pure modules, make the package facade lazy, and validate all trust-boundary data before provider callbacks. Strengthen executable architecture tests so the reviewed closure follows callable/import edges rather than filenames and the control-flow analysis fails closed on unresolved dynamic capabilities.

**Tech Stack:** Python 3.11+, pytest, Draft7 JSON Schema reference tests, `ast`, subprocess import probes.

## Global Constraints

- Preserve the exact public API, object identities, import forms, import order, reload behavior, and type-checking exports.
- Checkpoint cold imports perform no filesystem, network, environment, clock, thread, retry, session, sink, or enforcement work.
- Every production change follows a witnessed RED/GREEN cycle.
- No push or pull request; finish with a new commit and update the Task 8 report and progress ledger.

---

### Task 1: Lazy package facade and cold import proof

**Files:**
- Modify: `aegis/__init__.py`
- Create: `tests/test_checkpoint_cold_imports.py`

**Interfaces:**
- Consumes: existing `aegis.__all__` and public module exports.
- Produces: PEP 562 `__getattr__(name: str) -> object` backed by an immutable export map.

- [ ] Write fresh-subprocess tests that install audit/import probes before importing `aegis.checkpoints` and `aegis.workflow_verification`, and compatibility tests for direct/from/star/reload imports.
- [ ] Run them and record eager forbidden-module/audit-event failures.
- [ ] Replace eager facade imports with immutable lazy export metadata and `TYPE_CHECKING` imports.
- [ ] Run cold-import and public API suites to green.

### Task 2: Exact Draft7 schema parity

**Files:**
- Modify: `aegis/_internal/checkpoint_source_validation.py`
- Modify: `tests/test_checkpoint_creation.py`

**Interfaces:**
- Consumes: packaged audit/workflow Draft7 schemas.
- Produces: pure predicates matching Draft7 integer and regular-expression semantics while retaining checkpoint invariants.

- [ ] Add differential cases for every integer field (integral/non-integral float, bool, bounds) and regex field (terminal newline, Unicode, length), plus creator-level regressions.
- [ ] Run and witness integral-float and terminal-newline mismatches.
- [ ] Implement Draft7 numeric and search-pattern semantics without importing schema/runtime capability modules.
- [ ] Run differential and creator matrices to green.

### Task 3: Canonical enum authenticity

**Files:**
- Modify: `aegis/_internal/signature_models.py`
- Modify: `tests/test_signature_models.py`

**Interfaces:**
- Consumes: closed signing and verification enum classes.
- Produces: exact canonical-member identity checks in `_require_enum`.

- [ ] Add forged equal-but-not-identical members for every closed enum consumed by model/outcome validation.
- [ ] Run and witness current `isinstance` acceptance.
- [ ] Require identity with one of the declared enum members.
- [ ] Run signature and checkpoint verification suites to green.

### Task 4: Recursive reviewed dependency and call closure

**Files:**
- Modify: `tests/test_architecture_security_boundaries.py`

**Interfaces:**
- Consumes: exact public creator/verifier/result callable roots.
- Produces: recursive module/call dependency closure with explicit reviewed-pure leaves.

- [ ] Add fixtures proving all omitted direct edges and indirect helper edges are discovered.
- [ ] Run and witness basename-filter false negatives.
- [ ] Derive the closure from imports and resolved local calls; explicitly classify pure leaves and exclude enforcement paths.
- [ ] Run the architecture suite to green.

### Task 5: Conservative lexical and CFG capability analysis

**Files:**
- Modify: `tests/test_architecture_security_boundaries.py`

**Interfaces:**
- Consumes: Python AST for the reviewed closure.
- Produces: lexical binding/call-target analysis, dominance proof, SCC-aware call ceilings, and fail-closed dynamic resolution.

- [ ] Add adversarial sources for subscript/reflection, local shadows, `try/finally`, `match`, comprehensions/generators, definition-time expressions, aliases, recursive SCCs, loops, indirect `__call__`, conditional/fake preflight, nested defs, async/yield/with/exception/finally.
- [ ] Run and witness each false negative and the safe-shadow false positive.
- [ ] Implement conservative lexical resolution and control-flow summaries over all executable regions.
- [ ] Run adversarial and real-module architecture tests to green.

### Task 6: Provider spy matrix, verification, and handoff

**Files:**
- Modify: `tests/test_checkpoint_creation.py`
- Modify: `.superpowers/sdd/2026-08-04-issue-46-trusted-checkpoints/task-8-report.md`
- Modify: `.superpowers/sdd/2026-08-04-issue-46-trusted-checkpoints/progress.md`

**Interfaces:**
- Consumes: both public checkpoint creators and signer capability spies.
- Produces: malformed/overlimit/cyclic/success coverage with identity/sign/storage/publish/request counts.

- [ ] Add the full two-creator matrix and witness missing assertions/coverage.
- [ ] Implement only missing boundary behavior, then run focused suites.
- [ ] Run full pytest, compileall, flake8, and diff checks; perform two adversarial self-reviews.
- [ ] Update report/ledger and create a separate round-3 commit.
