# A3 Process-Affine Operation Registry — Execution Evidence

Date: 2026-08-03

Change ID: `a3-process-affine-operation-registry`

## Approved intent

- Architecture: `docs/superpowers/specs/2026-07-30-enforcement-core-security-remediation-design.md`
- Ordered implementation plan: `docs/superpowers/plans/2026-07-30-a3-process-affine-operation-registry.md`
- Dependency and execution order: `docs/superpowers/plans/2026-07-30-enforcement-core-plan-index.md`
- Predecessor: B2 merged to `main` in pull request #64 at `c4f9334`.
- Execution authorization: the repository owner requested “Begin A3 work” and approved the isolated A3 worktree on 2026-08-03.

The approved architecture and plan resolve the A3 behavior, boundaries, failure
semantics, public-contract effects, tasks, and acceptance gates. No material
clarification remains open. The plan traces its tasks to the design acceptance
criteria and requires red-green TDD.

## Scope and reversibility

A3 replaces portable split-enforcement authorization tokens with atomic,
process- and issuer-affine operation handles. It changes runtime authorization
and the public split-enforcement contract, adds no external dependency, and
performs no release, deployment, push, or other remote action. The work remains
reversible by reverting the scoped A3 commits before dependent B3 work begins.

## Enhanced gates

High-risk local implementation requires:

- focused red-green tests for every behavior change;
- the A3 completion portfolio and the full pytest suite;
- blocking concurrency, process-affinity, and architecture-boundary tests;
- public-contract, ADR, pipeline, and migration documentation updates;
- a distinct correctness, security, test-adequacy, and convergence review using fresh context.

## Startup and baseline

- Control-plane validation: `.venv/bin/python scripts/policy-engine.py validate --root . --context .../context.json` returned `valid: true`.
- Policy evaluation: high-risk `feature`, `security_sensitive`, and `public_contract_change`; local implementation is `autonomous_with_enhanced_gates`.
- Policy/context/change hashes: `d0416dab300bbcfbf7fba95bb51b1d1aeda7725d945560d0fbb0ce4f3dc6a3fa` / `15b3e95fe8845a50fbf128db0ac7c70afc79a54fa8f4b8c8f75c4f0907025cdc` / `e31bc38d43730c7ee6e7db352cd30ee285cacebd038250960fdd8f53c1aebe7e`.
- Transition `ANALYZED -> IMPLEMENTING`: authorized by the recorded fresh decision and `implementation_authorized` evidence.
- Initial isolated-worktree run found nine demo-copy failures because the worktree could not resolve the already-installed TypeScript parser. Linking the ignored `demo-app-react/node_modules` directory to the main checkout restored the configured environment; all 13 focused demo-copy tests then passed.
- Clean baseline: `python -m pytest -q` completed with 3,680 passed, one skipped, and zero failures.

## Implementation evidence

- Task 1 red: the new registry test module failed to import because
  `aegis._internal.operation_registry` did not exist.
- Task 1 green: atomic consume, affinity, binding, cancel, and cancel-all tests
  passed; commit `659e9b0` added the locked registry and typed registry errors.
- Task 2 red: eight opaque-handle/copy/pickle tests failed against the portable
  token contract.
- Task 2 green: the focused split portfolio passed 118 tests after public
  authorization state, HMAC/sentinel provenance, compiled-policy DTO restore,
  and mutable replay state were removed.
- Task 3 red: four lifecycle tests demonstrated cross-instance acceptance and
  missing cancel/finalize/discard cleanup.
- Task 3 green: per-instance ownership and session lifecycle tests passed; the
  wider session and adapter portfolio passed 318 tests with one skip.
- Task 4 green: process-affinity and architecture deletion-gate tests passed 35
  tests, including spawned and forked child-process rejection.

## Independent review and repairs

The separate correctness, security, test-adequacy, and contract-convergence
review found and repaired:

1. malformed operation fields that could raise raw Python type errors instead
   of typed, audited validation failures;
2. dynamic tool authorization and session finalization races around live
   operations, budgets, and lifecycle state;
3. session wrapper and metadata validation that occurred outside atomic
   consumption and could omit FAIL evidence;
4. session rejection evidence that bypassed configured signing, diagnostics,
   and fail-closed sink delivery;
5. stale portable-token prose in the integration guide and a skipped
   concurrency regression module.

The final fresh-context review reported no Critical, Important, or Minor
findings. It confirmed that every session Phase B rejection uses the instance
evidence boundary and that atomic registry consumption precedes every
caller-controlled wrapper, metadata, and output validation step. The generic
inactive-operation response preserves a foreign session's live operation and
does not disclose whether it is foreign, unknown, or already consumed.

Repair commits: `6c28984` and `d3e461c`.

## Final validation

- A3 completion portfolio: 122 passed.
- Expanded registry/session security portfolio: 134 passed.
- Full test suite: 3,695 passed, zero skipped, zero failures; 17 pre-existing
  warnings were reported.
- Production lint: `python -m flake8 aegis` exited zero.
- Patch hygiene: `git diff --check` exited zero.
- Independent review: no open findings; ready to merge.

No external dependency, release, deployment, push, pull request, or other
remote state change was performed.
