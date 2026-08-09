# Issue 46 Task 8 Correction Round 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:test-driven-development` for every production change. This plan
> is executed inline because it is a correction on an existing isolated task
> branch.

**Goal:** Eliminate referent-mutable checkpoint policy state and cold-creator
filesystem/cache capabilities, then replace the incremental architecture scan
with a restrictive analysis that proves the actual checkpoint trust boundary.

**Architecture:** Security policy becomes executable enum logic and immutable
tuples rather than mappings. Checkpoint creation validates finalized evidence
through a new pure module containing closed structural predicates and existing
checksum verification. Architecture tests derive the checkpoint dependency
closure from public creator/verifier roots and conservatively reject unresolved
capability indirection or callback paths not dominated by bounded preflight.

**Tech Stack:** Python 3.10+, AST/control-flow analysis in tests, subprocess
spies, pytest, immutable tuples/frozensets, and the existing canonical checksum
implementation.

## Global Constraints

- Work only in `codex/issue-46-trusted-checkpoints` at the assigned worktree.
- Add each regression first and witness the intended failure before production
  edits.
- Preserve the exact eight-name checkpoint public API, legacy construction,
  signed vectors, contextual result invariant, and provider neutrality.
- Creators perform no filesystem, threading, caching, clock, environment,
  persistence, enforcement, session, retry, or networking behavior.
- Commit the correction separately without amending or pushing.

---

### Task 1: Remove referent-mutable trust policy

**Files:**

- Modify: `tests/test_checkpoint_public_api.py`
- Modify: `tests/test_checkpoint_verification_boundary.py`
- Modify: `tests/test_chain_checkpoint_verification.py`
- Modify: `aegis/_internal/signature_models.py`
- Modify: `aegis/_internal/external_signing.py`
- Modify: `aegis/_internal/chain_checkpoint_verification.py`
- Modify: `aegis/_internal/verification.py`

**Interfaces:** Replace outcome/message/precedence mappings with
`validate_verification_outcome`, `_safe_reason_message`, and enum-priority
functions. Aggregation consumes a callable priority rather than a mapping.

- [ ] Add referent-mutation tests for all six proxies, including public
  contextual-result and aggregation effects.
- [ ] Run the focused tests and confirm each fails because `gc.get_referents`
  reaches a mutable dictionary.
- [ ] Replace the proxies with exhaustive `match`/branch functions and update
  existing mapping-oriented tests to assert the same closed behavior matrix.
- [ ] Run signature/external/checkpoint/chain tests to GREEN.

### Task 2: Make cold checkpoint creation capability-free

**Files:**

- Create: `aegis/_internal/checkpoint_source_validation.py`
- Modify: `aegis/_internal/checkpoint_signing.py`
- Modify: `tests/test_checkpoint_creation.py`
- Modify: `tests/test_architecture_security_boundaries.py`

**Interfaces:** `is_valid_chain_checkpoint_source(dict) -> bool` and
`is_valid_workflow_checkpoint_source(dict) -> bool` are pure, bounded callers
with no module cache. They preserve the accepted finalized-evidence schema and
checksum contract before any signer callback.

- [ ] Add fresh-process spies that fail if checkpoint creation imports or calls
  schema-file, lock, or validator-cache paths.
- [ ] Add literal valid/invalid parity corpora and a complete runtime signer
  matrix for chain/workflow success, malformed, over-limit, and cyclic input.
- [ ] Witness RED from the current `evidence_finalizer` validator dependency.
- [ ] Implement closed pure structural validators and remove the dependency.
- [ ] Run creation/parity/vector/public tests to GREEN.

### Task 3: Replace the architecture analyzer

**Files:**

- Modify: `tests/test_architecture_security_boundaries.py`

**Interfaces:** The analyzer derives imports reachable from checkpoint public
roots, models bindings per lexical scope, recursively proves immutable module
state, rejects unresolved dynamic capability construction, and proves bounded
preflight dominates signer/verifier callback nodes with explicit call ceilings.

- [ ] Add separate RED fixtures for destructuring, walrus/default/lambda,
  class/comprehension/star/loop/try/conditional bindings, reflective subscripts,
  wrappers/decorators, function-scope mutation, nested state, and callback
  dominance/call-ceiling bypasses; add immutable positive controls.
- [ ] Run the fixture slice and classify every failure as a genuine bypass.
- [ ] Replace incremental alias resolution with scope-aware conservative
  binding and restrictive unresolved-call handling.
- [ ] Derive and assert the reachable local dependency closure from roots.
- [ ] Model branch/loop/dead-code preflight dominance and callback ceilings;
  retain runtime spies as behavior evidence.
- [ ] Run all architecture tests to GREEN without suppressing real modules.

### Task 4: Verification and delivery

**Files:**

- Modify: `.superpowers/sdd/2026-08-04-issue-46-trusted-checkpoints/progress.md`
- Modify: `.superpowers/sdd/2026-08-04-issue-46-trusted-checkpoints/task-8-report.md`

- [ ] Run architecture/public and checkpoint/chain/workflow/invariant suites.
- [ ] Run the full suite, compileall, production and changed-file flake8, and
  diff checks.
- [ ] Perform two independent adversarial reviews: mutable reachability and
  capability/control-flow bypass.
- [ ] Update the ignored report and progress ledger with exact RED/GREEN
  evidence and the correction commit hash.
- [ ] Create one separate correction commit; do not amend, push, or open a PR.
