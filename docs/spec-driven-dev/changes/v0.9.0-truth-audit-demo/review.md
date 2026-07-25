# v0.9.0 Truth Audit and Demo Review

## Review boundary

- Branch: `feat/v0.9-13-truth-audit-demo`
- Base: `origin/develop` at
  `8be5f5481d5608d15cb232897ef91e90220d83bb`
- Reviewed implementation head:
  `31fbca9cab9eba0f30f7a82f292675f48e316a9d`
- Reviewed binary-diff SHA-256:
  `d43f4b2468d55c5ea1019f21fec8042f0ea7e7f3e0a650ec3ad512ef6f6a56c8`
- Target path: local code lifecycle only; any future pull request may target
  `develop` only after separate remote-action authorization.

## Changed-file inventory

- Root truth and controls: `.claude/rules/aegis-project.md`, `README.md`,
  `PROJECT.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`,
  `RELEASE_GATES.md`, `implementation_status.md`,
  `doc_parity_manifest.yaml`, and `policies/policy_dsl_spec.md`.
- Package schema: `schemas/policy_dsl.schema.json` and
  `aegis/schemas/policy_dsl.schema.json`.
- Demo API: `demo-app-api/main.py` and
  `demo-app-api/tests/test_pr11_all_demo_labs.py`.
- React demo: `demo-app-react/README.md`, `public/portal.html`, the four
  canonical diagram mirrors, `ArchitecturePage.tsx` and its test,
  `helpContent.ts` and its test, and `HelpDrawer.test.tsx`.
- Maintained SDK/architecture/operations documentation:
  `docs/AEGIS_FRAMEWORK.md`, `docs/INTEGRATION_GUIDE.md`,
  `docs/PUBLIC_INTEGRATION_CONTRACT.md`, `docs/USAGE.md`,
  `docs/migration.md`, maintained files under `docs/architecture/`, and the
  maintained workflow/operator references under `docs/reference/`.
- Adapter references: `docs/reference/external/README.md`,
  `A2A_ADAPTER.md`, `BEDROCK_ADAPTER.md`, and
  `OPENAI_AGENTS_ADAPTER.md`; the replaced generic
  `what-is-bedrock.md` was removed.
- Generated architecture: both Mermaid sources, deterministic generator,
  canonical light/dark component and pipeline SVGs, HTML viewers, React
  mirrors, and deletion of four stale unreferenced PNG duplicates.
- Truth enforcement and tests: `scripts/check_doc_parity.py`,
  `scripts/check_brand_and_version_parity.py`,
  `tests/test_doc_parity_v090_truth.py`,
  `tests/test_pr11_release_truth.py`, and
  `tests/test_architecture_diagram_truth.py`.
- Current change records: the design, plan, and files under
  `docs/spec-driven-dev/changes/v0.9.0-truth-audit-demo/` plus the separately
  authorized `v0.9.0-instruction-status-truth/` record.

No file under `docs/articles/`, `docs/audits/`, `docs/decisions/`,
`docs/design/`, `docs/dev/`, `docs/plans/`, or `docs/releases/` changed. No
`.github` workflow, dependency manifest, production configuration, remote
branch, or `main` ref changed.

## Review passes

Distinct passes covered:

- correctness and current-state documentation truth;
- deterministic generated-asset parity and stale-output detection;
- React responsive layout, contextual help fidelity, focus behavior, and
  complex-diagram accessibility;
- Bedrock, A2A, and OpenAI Agents optional-adapter boundaries;
- public-import and no-top-level-adapter-re-export requirements;
- preserved historical records and explicit current/target/historical/
  instruction-system ownership;
- the separately authorized instruction-system correction;
- absence of publication, deployment, remote, and `main` authority.

## Validation

- Package and coverage: `1919 passed, 2 skipped`, `90.32%`.
- Base adapter matrix: `258 passed, 1 expected skip`.
- OpenAI-extra adapter matrix: `277 passed`.
- Demo API: `67 passed`, 2 non-failing warnings.
- React: 17 files and `105 passed`; ESLint and production build passed.
- Policy, documentation parity, brand/version parity, Flake8, deterministic
  diagram `--check`, and full-range `git diff --check`: passed.
- Browser: Architecture light/dark and mobile/desktop, guide interactions,
  Lab 11 success/failure/fix/trace, representative Labs 1 and 8, and a clean
  final browser console were observed.

## Findings and repairs

The first independent review found no Critical issues and three Important
issues:

1. root and packaged schema descriptions plus one release gate still called
   packaged adapters source-only;
2. the root README described only seven labs instead of distinguishing the
   eleven-lab candidate from the potentially lagging live `main` deployment;
3. complex diagram images lacked meaningful screen-reader summaries.

All three were reproduced with failing tests and repaired in `31fbca9`. A
focused independent follow-up found no remaining Critical or Important issues
and returned `Ready to merge — Yes`.

The review also found and repaired three trailing blank lines that initially
failed `git diff --check`. The instruction decision workflow rejected one
premature response because its context had not yet entered
`HUMAN_DECISION_REQUIRED`; no instruction file changed under that invalid
state. The context was materialized, reevaluated, and reauthorized before the
bounded correction.

## Remaining limitations

- Publication is pending and separately authorized. The candidate remains off
  PyPI and `main`.
- Live GitHub Pages may reflect the last `main` build rather than this local
  eleven-lab candidate.
- No live provider credentials or calls were used; adapters were validated
  with deterministic fixtures and the real optional OpenAI SDK surface.
- Byte-for-byte rebuild reproducibility of wheel and sdist is not claimed.
- The stale-generator regression test temporarily edits and restores a
  canonical SVG. Its `finally` restoration and clean-tree check cover normal
  runs; a temporary output root is a non-blocking future hardening item.

## Reversal

Before remote integration, reversal is a normal branch revert or deletion of
the isolated worktree. No migration, data repair, deployment rollback, package
yank, or remote branch cleanup is required because this change modifies no
published artifact, production state, dependency contract, or user data.
