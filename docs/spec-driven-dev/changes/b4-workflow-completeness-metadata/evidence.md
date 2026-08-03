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

## Open scoped re-review blockers

The required single scoped re-review did not authorize lifecycle advancement.
It reproduced four load-bearing residuals in the final repair delta:

1. `_select_session_invocations` treats a generic `session_id` as partial B4
   workflow correlation even though the audit schema uses `step_index` or
   `workflow_policy_digest` as the workflow-correlation trigger. A schema-valid
   unrelated invocation can therefore invalidate an otherwise valid supplied
   workflow set instead of being ignored.
2. `_measure_json_document` pushes every child of an exact list or dictionary
   before enforcing its byte budget, allowing count-sized memory amplification
   before the typed resource-limit result.
3. Workflow schemas cap `step_count` and `invocations` at 10,000, but the
   producer allocates without the same cap. A 10,001-attempt session reaches
   finalization and fails schema validation without emitting a workflow
   artifact.
4. Exception-path session finalization copies raw `str(exc_val)` into
   `failure_summary`. Invalid Unicode can pass into strict v2 normalization,
   emit the invocation terminal exactly once, but strand the workflow in
   `FAILED` without a workflow artifact.

The scoped reviewer reran the focused portfolio (245 passed) and nevertheless
returned `Ready: No`. These findings were adjudicated as real contract and
availability failures, not test-only discrepancies. Under the high-risk review
protocol no second unreviewed repair wave was started. The change remains in
`IMPLEMENTING`; `implementation_tasks_complete`, validation, required-review,
CI, and convergence evidence are intentionally absent.

No push, pull request, release, deployment, or other remote action occurred.
