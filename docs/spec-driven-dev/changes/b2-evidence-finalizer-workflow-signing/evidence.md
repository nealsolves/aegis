# B2 Evidence Finalizer and Workflow Signing — Execution Evidence

Date: 2026-08-03

Change ID: `b2-evidence-finalizer-workflow-signing`

## Approved intent

- Architecture: `docs/superpowers/specs/2026-07-30-enforcement-core-security-remediation-design.md`
- Ordered implementation plan: `docs/superpowers/plans/2026-07-30-b2-evidence-finalizer-workflow-signing.md`
- Dependency and execution order: `docs/superpowers/plans/2026-07-30-enforcement-core-plan-index.md`
- Execution authorization: the repository owner requested “Start B2 work” and approved creation of the isolated B2 worktree on 2026-08-03.

The approved architecture and plan resolve the B2 behavior, boundaries, failure
semantics, public-contract effects, tasks, and acceptance gates. No material
clarification remains open. The plan's task steps trace to the design's B2
acceptance criteria and require red-green TDD.

## Startup and baseline

- Control-plane validation: `.venv/bin/python scripts/policy-engine.py validate --root .` returned `valid: true`.
- Baseline after merging local `main` at `1409335`: `python -m pytest -q` completed with 3,646 passed, one skipped, and zero failures. This includes the 3,633-test merged A2/B1 baseline plus B2 Task 1 tests.
- Initial worktree dependency failure was environmental: nine demo-copy tests could not import the TypeScript parser before the worktree could resolve the root `demo-app-react/node_modules`; all 13 demo-copy policy tests passed after setup.

## Scope and reversibility

B2 changes the authorization/evidence boundary so allow-class results require
successful evidence finalization and acknowledged delivery. It changes the
public sink/failure contract, adds no external dependency, performs no release
or deployment, and is reversible by reverting the scoped B2 commits before A3
begins.

## Enhanced gates

High-risk local implementation requires:

- focused red-green tests for each task;
- the B2 completion suite and the full pytest suite;
- blocking architecture/security-boundary tests;
- public-contract and migration documentation updates;
- a distinct correctness, security, test-adequacy, and convergence review using fresh context.

## Implementation evidence

- Task 1 added bounded, monotonic attempt identity and non-recursive evidence
  diagnostics.
- Task 2 added the single normalize, correlate, checksum, sign, schema-validate,
  and acknowledged-delivery finalizer with separate invocation and workflow
  signing domains.
- Task 3 routed every production invocation, exception, decorator, and session
  evidence path through that finalizer. The blocking AST inventory reports zero
  direct delivery, signing, or v2 checksum bypasses outside the finalizer.
- Task 4 made a sink mandatory for `AEGIS`, added a configure-once sealed module
  runtime, removed mutable failure controls from the v2 public surface, and
  made delivery errors replace any apparent allow- or deny-class completion.
- Task 5 signs workflow evidence, emits the exact returned finalized value, and
  runs the bypass inventory in the security-boundary CI job.

The root and packaged audit/workflow schemas are byte-identical and require an
explicit `signature_status` plus `signature` value. Missing signers produce
`signature_status: "unsigned"` and `signature: null`.

## Review and repairs

A separate post-implementation correctness, security, test-adequacy, and
contract-convergence pass found and repaired:

1. finalizer setup errors that could bypass diagnostics;
2. invented identity metadata for generic legacy signers;
3. raw sink exception text in authorized legacy logging;
4. schemas that did not require explicit signature state;
5. premature wrapping of the established v2 canonicalization error contract;
6. an instance-level legacy `"log"` path that could return a schema-v2 PASS
   after failed delivery.

After repair, v2 instance and module runtimes accept only fail-closed delivery.
Legacy best-effort behavior cannot configure or mutate either runtime. No
Critical, Important, or Minor review finding remains open.

## Final validation

- B2 completion portfolio: `70 passed`.
- Full merged suite: `3,680 passed, 1 skipped`, zero failures.
- `flake8 aegis`: passed.
- Root/package audit schema and workflow schema byte comparison: passed.
- `git diff --check`: passed.
- Documentation parity sections 0A through G and I through O: passed. Section
  H reports the inherited B1/release-candidate mismatch
  `AUDIT_SCHEMA_VERSION '2.0' != manifest audit_schema_version '1.4'`; the same
  single finding reproduces on unchanged local `main` at `1409335`, so it is
  not a B2 regression and was not concealed by changing release truth.

No external dependency, release, deployment, push, or remote state change was
performed.
