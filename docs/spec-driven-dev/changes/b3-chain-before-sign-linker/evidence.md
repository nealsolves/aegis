# B3 Chain-Before-Sign Linker — Execution Evidence

Date: 2026-08-03

Change ID: `b3-chain-before-sign-linker`

## Approved intent

- Architecture: `docs/superpowers/specs/2026-07-30-enforcement-core-security-remediation-design.md`
- Ordered implementation plan: `docs/superpowers/plans/2026-07-30-b3-chain-before-sign-linker.md`
- Dependency and execution order: `docs/superpowers/plans/2026-07-30-enforcement-core-plan-index.md`
- Predecessor: A3 merged to `main` in pull request #65 at `98bc1ca`.
- Execution authorization: the repository owner requested “Begin B3 work” on 2026-08-03.

The approved architecture and plan resolve B3 behavior, boundaries, failure
semantics, public-contract effects, tasks, and acceptance gates. No material
clarification remains open. The plan requires red-green TDD and four scoped,
independently reviewable implementation commits.

## Scope and reversibility

B3 adds a host-owned synchronous chain-link reservation contract, attaches
complete invocation coordinates before checksum and signature construction,
adapts the in-memory `AuditChain`, and publishes stable verification vectors.
It changes no external dependency, release, deployment, push, pull request, or
other remote state. The work remains reversible by reverting its scoped commits
before dependent B4 work begins.

## Enhanced gates

High-risk local implementation requires:

- focused red-green tests for every behavior change;
- the B3 completion portfolio and the full pytest suite;
- blocking concurrency, chain-ordering, mutation, and schema-parity tests;
- public-contract, ADR, invariant, and threat-model synchronization;
- distinct correctness, security, test-adequacy, and convergence review passes.

## Startup and baseline

- Control-plane validation returned `valid: true`.
- Policy evaluation classified B3 as high-risk `feature`,
  `security_sensitive`, and `public_contract_change`; local implementation is
  `autonomous_with_enhanced_gates`.
- Policy/context/change hashes at authorization:
  `d0416dab300bbcfbf7fba95bb51b1d1aeda7725d945560d0fbb0ce4f3dc6a3fa` /
  `996988c0edde1a44cdd937a8c0f957342b5f223839a6b2717e0abd72a2f72fc6` /
  `079edadcd568eabc391132c587f9e547a0d7f7cf7a8a8d43a739d6c9fc63fb35`.
- Transition `ANALYZED -> IMPLEMENTING` was authorized by the recorded fresh
  decision and `implementation_authorized` evidence.
- Clean isolated-worktree baseline: 3,695 passed with 17 pre-existing warnings
  in 67.20 seconds. The ignored demo `node_modules` link restores the configured
  TypeScript parser without changing tracked source.

## Implementation evidence

- Task 1 red: the new contract test module failed to import because
  `aegis._internal.chain_linker` did not exist.
- Task 1 green: commit `42e42c3` added the frozen request/coordinate values,
  reservation/linker protocols, closed validation, typed errors, and stable
  exports.
- Tasks 2 and 3 red: the ordering, failure-stage, workflow-exclusion,
  concurrency, timeout, idempotency, and reconciliation tests failed against
  the old sign-then-append chain utility.
- Tasks 2 and 3 green: commit `fb67865` established
  reserve/attach/checksum/sign/schema/emit/commit ordering, complete-or-absent
  schema coordinates, fail-closed abort/commit semantics, instance and module
  runtime threading, and the condition-serialized in-memory `AuditChain`.
  These tasks were committed together to preserve a green checkpoint because
  the complete-coordinate schema and linker adaptation were interdependent.
- Task 4 green: commit `6ba5caa` added deterministic key-rotation and
  deletion/reordering vectors and synchronized the public contract, threat
  model, architectural invariants, and ADR-0008 with the #46 checkpoint
  boundary.

## Independent review and repairs

Distinct correctness, security, test-adequacy, and convergence passes reviewed
the complete branch diff against the approved plan. They found and repaired:

1. an explicit empty `AuditChain` identity that silently generated a UUID
   instead of failing the closed identifier contract (`0cc9fee`);
2. offline verification that accepted whitespace-only or overlong chain and
   reservation identities despite constructor and schema rejection
   (`63953be`).

Both repairs followed observed red-green tests. The final fresh-context review
reported no open Critical, Important, or Minor findings. It confirmed complete
coordinate and signature coverage, pre-ack abort and post-ack quarantine,
bounded single-process allocation, reconciliation by observed v2 checksum,
workflow exclusion, stable public exports, schema-copy parity, and the explicit
completeness/checkpoint limitation.

## Final validation

- B3 completion portfolio: 76 passed.
- Full test suite: 3,755 passed, zero failures; the same 17 pre-existing
  warnings were reported.
- Production lint: `python -m flake8 aegis` exited zero.
- Package build: `python -m build` successfully produced the sdist and wheel;
  existing setuptools/license and manifest warnings were non-fatal.
- Schema parity: the root and packaged audit schemas are byte-identical.
- Patch hygiene: `git diff --check` exited zero.
- Targeted documentation/public-API portfolio: 150 passed.
- The non-gating repository parity script retained its three pre-existing
  baseline findings: the tracked A3 evidence file is unclassified and lacks an
  internal-reference disclaimer, and the manifest still declares audit schema
  `1.4` while runtime code declares `2.0`. B3 introduced none of them.
- Remote actions are disabled by project policy; no CI rerun, dependency
  release, deployment, push, pull request, or other remote state change was
  performed.
