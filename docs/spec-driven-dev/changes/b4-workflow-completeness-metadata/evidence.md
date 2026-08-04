# B4 Workflow Completeness Metadata — Execution Evidence

Date: 2026-08-03

Change ID: `b4-workflow-completeness-metadata`

## Approved intent

- Architecture: `docs/superpowers/specs/2026-07-30-enforcement-core-security-remediation-design.md`
- Ordered implementation plan: `docs/superpowers/plans/2026-07-30-b4-workflow-completeness-metadata.md`
- Dependency and execution order: `docs/superpowers/plans/2026-07-30-enforcement-core-plan-index.md`
- Predecessor: B3 merged to `main` in pull request #66 at `83828bf`.
- Execution authorization: the repository owner requested “Start B4 work” on 2026-08-03.

The approved architecture and plan resolve B4 behavior, boundaries, failure
semantics, public-contract effects, tasks, and acceptance gates. The design
resolves Task 1 shorthand in favor of `invocation_checksum` and an allocator
that receives `step_id` plus `attempt_id`. No material clarification remains
open.

## Scope and reversibility

B4 adds atomic workflow-attempt indexing, terminal attempt accounting, a signed
ordered workflow claimed set, and typed claimed-set verification. It changes no
external dependency, release, deployment, push, pull request, or other remote
state. The work remains reversible by reverting its scoped commits before #46
binds trusted checkpoints to the B4 contract.

## Enhanced gates

High-risk local implementation requires:

- focused red-green tests for every behavior change;
- the B4 completion portfolio and the full pytest suite;
- blocking concurrency, omission, ordering, mutation, schema-parity, and public
  contract tests;
- public-contract, invariant, threat-model, CLI, and quickstart synchronization;
- distinct correctness, security, test-adequacy, and convergence review passes.

## Startup and baseline

- Control-plane validation returned `valid: true`.
- Clean isolated-worktree baseline: 3,755 passed with 17 pre-existing warnings
  in 39.02 seconds.
- Policy evaluation and lifecycle authorization are recorded in the companion
  context and transition artifacts.

## Implementation record

Tasks 1-5 were implemented and reviewed in scoped commits. The final
whole-branch review found blocking issues in terminal-attempt finalization,
workflow correlation, verifier resource bounds, and acceptance coverage. One
consolidated TDD repair wave produced these commits:

- `7d841e5` — bind workflow terminal finalization;
- `63c60b3` — bound workflow correlation verification;
- `6ca8630` — freeze workflow correctness boundaries;
- `43dd3f5` — preserve generic session context compatibility.

The repair wave added explicit allocated/finalizing/terminal attempt state,
origin-bound recorder capabilities, pre-registry v2 normalization, bounded
correlation metadata, strict workflow-claim budgets, closed legacy
classification, public handle binding, an end-to-end non-ALLOW matrix, and
five-document assurance fitness checks.

Fresh repair-wave validation was green:

- focused B4 and documentation portfolio: 245 passed;
- full pytest suite: 3,892 passed with 20 known warnings;
- `flake8 aegis`: clean;
- `git diff --check`: clean;
- runtime/source audit and workflow schema copies: byte-identical.

The ignored execution report is retained locally at
`.superpowers/sdd/2026-07-30-b4-workflow-completeness-metadata/final-fix-report.md`.

## Scoped repair authorization and blocker closure

The repository owner selected the exact shared boundary
`MAX_WORKFLOW_ATTEMPTS = 1_024` and authorized the scoped fixes on 2026-08-03.
The design and ordered plan were amended before implementation. The repair was
then completed as small red-green commits:

- `dc3e16e` — distinguish generic session context from workflow correlation;
- `8f76f99` — preflight workflow verification width;
- `dd64f3e` — enforce the atomic 1,024-attempt admission boundary before
  attempt-envelope and step-index allocation, and synchronize both schema
  copies, verifier limits, tests, and public documentation;
- `cee54bd` — sanitize exception-path workflow summaries without copying raw
  exception messages into signed evidence;
- `2b44e44` — reject excessive depth and dictionary-key byte budgets before
  expanding child values;
- `a15fa23` — make the byte-preflight architecture test sensitive to guard
  ordering rather than merely guard presence;
- `4eba16b` — make workflow verification total for catchable hostile scalar
  inputs while preserving process-control `BaseException` propagation.

Request 1,025 is rejected with `SESSION_ATTEMPT_LIMIT_EXCEEDED` while the
attempt factory counter and step-index allocator remain unchanged. The shared
1,024 boundary now governs producer admission, policy and workflow schemas, and
verifier claim/supplied limits. A concurrent boundary probe admitted exactly
one request at index 1,023 and rejected the competing request without allocating
a second envelope.

## Final validation and review

Fresh validation from final production commit `4eba16b` was green:

- exact B4 completion portfolio: 181 passed in 1.78 seconds;
- full pytest suite: 3,906 passed with 20 known warnings in 38.07 seconds;
- `flake8 aegis`: clean;
- `git diff --check`: clean;
- root and packaged audit, workflow, and policy schemas: byte-identical;
- source distribution and wheel build: successful.

The warnings are pre-existing deprecation and policy warnings and do not affect
B4 acceptance. Remote CI is disabled for this local-only change; the required
CI gate is represented by the complete local validation portfolio and package
build, with `ci_reruns` remaining zero.

The distinct scoped security closure review and independent whole-branch
convergence review both reported no critical, important, or minor findings and
returned `Ready: Yes`. The latter initially found the hostile scalar-subclass
escape; commit `4eba16b` fixed it, and the reviewer verified the closure.

All implementation, validation, required-review, CI-equivalent, and convergence
gates are satisfied. B4's implementation lifecycle may advance to `COMPLETE`.
The policy engine authorized each edge from `IMPLEMENTING` through `COMPLETE`;
the exact transition fields and decision hashes are recorded in
`lifecycle-transitions.json`.
This does not claim runtime completeness assurance: that assurance remains
`UNPROVEN` by design until downstream checkpoint work in #46 binds trusted
completeness evidence.

No push, pull request, release, deployment, or other remote action occurred.
