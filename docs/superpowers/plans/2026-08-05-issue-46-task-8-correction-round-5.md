# Trusted Checkpoint Correction Round 5 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the final callback evaluation-order, exact closure, mutable-reference, lexical-shadow, and checkpoint-facade lifecycle findings.

**Architecture:** Replace call-leaf heuristics with a small path-sensitive execution model that evaluates expressions in Python order and substitutes interprocedural arguments/defaults. Model module initialization as an explicit closure root with a reviewed exact manifest, and keep checkpoint facade objects in a first-import immutable tuple that reloads and PEP 562 fallback cannot replace from a live monkeypatched submodule.

**Tech Stack:** Python 3.12, pytest, AST analysis, isolated subprocess probes.

## Global Constraints

- Work only in the existing trusted-checkpoint worktree and preserve the exact 137-name top-level API and eight checkpoint exports.
- Witness every production/analyzer defect RED before implementation.
- Keep checkpoint imports and creators free of ambient filesystem, network, environment, clock, thread, enforcement, session, sink, and retry capabilities.
- Finish with the complete round-1-through-round-5 fixture corpus, full verification, two adversarial self-reviews, ignored report/ledger updates, and a separate commit without push or PR.

---

### Task 1: Python evaluation order and canonical preflight identity

**Files:**
- Modify: `tests/test_architecture_security_boundaries.py`

- [x] Add named RED fixtures for callback arguments/keywords/stars, reversed conditional expressions, callable wrappers, helper defaults, `TryStar`, and nested combinations.
- [x] Add RED local/fake preflight shadows and GREEN canonical imported/aliased preflight controls.
- [x] Evaluate callees and argument expressions before invocation, branch `IfExp`, and model `TryStar` paths.
- [x] Substitute arguments/defaults through helpers and callable `__call__` summaries while retaining loop/SCC ceilings.

### Task 2: Exact module-init closure and manifest

**Files:**
- Modify: `tests/test_architecture_security_boundaries.py`

- [x] Add RED modules for direct/assignment unresolved callbacks, import-time calls, hidden local-import capabilities, and ordinary/relative reexports.
- [x] Represent module initialization explicitly and follow all executed top-level expressions, imports, assignments, decorators, bases, defaults, and annotations.
- [x] Require every unresolved executed/load edge to carry an explicit reviewed-pure reason or fail closed.
- [x] Freeze an independently reviewed exact symbol/edge/module manifest and compare computed closure equality.

### Task 3: Mutable referents and lexical shadows

**Files:**
- Modify: `tests/test_architecture_security_boundaries.py`

- [x] Add RED imported mutable attribute/subscript/container aliases plus immutable controls.
- [x] Resolve attribute/subscript referents to proven immutable definitions or reject them.
- [x] Add RED nested-shadow leakage and nonlocal/global cases with parameter/local/safe-recursion controls.
- [x] Bind only the nearest lexical scope and preserve path-sensitive candidate sets.

### Task 4: Canonical checkpoint facade lifecycle

**Files:**
- Modify: `aegis/__init__.py`
- Modify: `tests/test_checkpoint_cold_imports.py`

- [x] Add fresh-process RED for submodule monkeypatch followed by package reload, top-level deletion fallback, and concurrent import/reload order.
- [x] Capture a first-import immutable tuple of canonical checkpoint objects and always re-pin/fallback from it.
- [x] Clear stale lazy legacy bindings on reload without consulting monkeypatched live submodules.
- [x] Re-run cold, direct/from/star/reload, identity, static typing, and exact API-order tests.

### Task 5: Verification and final handoff

**Files:**
- Modify: `.superpowers/sdd/2026-08-04-issue-46-trusted-checkpoints/task-8-report.md` (ignored)
- Modify: `.superpowers/sdd/2026-08-04-issue-46-trusted-checkpoints/progress.md` (ignored)

- [x] Run all synthetic architecture fixtures and exact real closure manifest.
- [x] Run public/cold/creation/schema/enum/checkpoint/chain/workflow/invariant suites and full pytest.
- [x] Run compileall, production/changed-file flake8, and diff checks.
- [x] Perform two adversarial reviews replaying every reviewer case; report any unresolved finding before commit.
- [x] Update report/ledger, create a separate round-5 commit, and record its hash without pushing.
