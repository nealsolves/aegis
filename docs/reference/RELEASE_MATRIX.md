# AEGIS Release Matrix

Last verified: 2026-07-25.

This is the canonical release-truth table for AEGIS. It separates the previous
PyPI release, the new package candidate, remote source state, and archived
material.

Source, tags, and release artifacts for versions before `0.9.0` remain in
[`nealsolves/aigc`](https://github.com/nealsolves/aigc). This repository is the
AEGIS `0.9.0`-and-later development home.

Verification snapshot used for this table:

- Current package candidate is `aegis-ai-governance==0.9.0b1`.
- Package metadata and `aegis.__version__` are `0.9.0b1`.
- Import package and CLI remain `aegis`.
- The candidate is not yet published to PyPI.
- Previous PyPI line: `aegis==0.3.3`.
- Candidate implementation merged through PR #17.
- Documentation, diagram, and demo truth is merged through PR #18.
- `origin/develop` is at merge commit
  `fdf3649` (`fdf3649f...`) for the current documentation/demo baseline.
- PR #17 merge commit `8be5f54` remains the package-candidate build baseline.
- The candidate is not on `main` and is not yet published to PyPI.
- A Pending Trusted Publisher is configured for
  `nealsolves/aegis` / `publish.yml` / `pypi`; no upload is authorized.
- The truth-audit adapter, Python, coverage, React, build, API, and browser
  matrix is complete. The current suite is `1923 passed, 2 skipped`.

These source refs identify the inspected beta baseline. Before any merge commit
is used for public beta or release claims, rerun the snapshot commands and
replace the local and remote source refs with the exact target refs.

<!-- markdownlint-disable MD013 -->

| Channel | Version label | Exact ref | Distribution | Included surfaces | Excluded surfaces | Adapter status | Support stance | Test status | Artifact integrity | Build authority | Known limitations |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Previous PyPI release | `aegis==0.3.3` | Historical release dated `2026-04-10`. | `pip install aegis==0.3.3`. | Invocation governance, split enforcement, policy loading, audit artifacts, signing, audit chain utility, lineage, provenance gate, and compliance export. | The v0.9 workflow CLI, starter scaffolds, trace/export operations, and optional adapters. | Not claimed as included. | Previous installable line; no longer the candidate identity. | Historical release evidence. | Historical artifacts are outside this candidate packet. | Historical publisher path. | The `aegis` distribution name cannot be used for the new release. |
| Local beta candidate | `aegis-ai-governance==0.9.0b1` | PR #17 merged at `origin/develop` merge commit `8be5f54`; not on `main`. | Wheel and sdist built locally; after publication, `pip install aegis-ai-governance==0.9.0b1`. | `AEGIS.open_session(...)`, workflow sessions and starters, policy/workflow init, lint, doctor, trace, export, invocation governance, and packaged optional adapter submodules. | Hosted control plane, transport ownership, cloud credentials, provider SDK ownership, tenant isolation, and top-level adapter re-exports. | Bedrock and A2A require no base SDK dependency; OpenAI Agents requires the `openai-agents` extra. Base matrix: 258 passed, 1 expected skip. Extra-enabled matrix: 277 passed. | Merged on `develop`; not on `main` and not yet published to PyPI. | Policy, parity, brand/version, lint, coverage, demo API, React, build, and browser checks passed. Final package suite: 1919 passed, 2 skipped. | Prior candidate artifact evidence remains recorded in the release packet; no published artifact exists. | Pending Trusted Publisher `nealsolves/aegis` / `publish.yml` / `pypi`; no upload authorized. | Publication remains a separate human-authorized action; byte-for-byte local rebuild reproducibility is not established. |
| Current documentation/demo baseline | `v0.9.0 beta source` | PR #20 merged at `origin/develop` merge commit `49c0229`; not on `main`. | Source checkout plus live beta demo at `https://nealsolves.github.io/aegis/`. | Candidate runtime, reconciled maintained docs, regenerated architecture assets, and eleven live labs backed by `https://aegis-demo-api.onrender.com`. | PyPI publication and `main` cutover. | Same candidate adapter contract as the package baseline. | Public beta from `develop`; `main` remains unchanged. | PRs #19 and #20 validation passed; Pages run `30177779500`, Render health/CORS, live Lab 1, live Lab 11, and clean-console checks passed. | No published Python package is implied; the deployed frontend and backend correspond to the recorded `develop` commits. | One-time bounded owner authority covered the feature-branch PRs and beta targets only; default remote authority remains disabled. | Render's free service may cold-start after inactivity; GitHub Actions reports non-blocking Node-runtime deprecation warnings for pinned upstream actions. |
| Previous remote source baseline | `v0.9.0 source beta` | `origin/develop` at `73f1bfc494dd5290a7e579069b3cad72e33457ed`, before PR #16. | Source checkout only. | Workflow beta surfaces present at that exact ref. | Candidate distribution rename, release workflow, and local release-ready evidence. | Ref-specific. | Superseded development baseline. | Baseline suite passed before candidate work. | No candidate artifact digests. | Remote branch process. | Historical comparison row; do not treat this ref as the package candidate. |
| Docs-only draft | `v0.9.0 hardening plan` | `docs/plans/v0.9.0_RELEASE_TRUTH_AND_GOVERNANCE_HARDENING_PLAN.md` is a local planning input in this checkout. | Documentation only. | Requirements RTG-001 through RTG-015 and hardening guidance. | Runtime, schema, CLI, and release claims until implemented and verified. | Planning status only. | Proposed development spec. | Not applicable unless converted into tests or release gates. | Not an artifact integrity record. | Maintainer-authored local plan. | Do not treat plan text as shipped behavior. |
| Archived article | Historical `v0.3.x` narrative | Archived docs under `docs/articles/` and historical audit docs under `docs/audits/`. | Documentation only. | Historical context. | Current release truth and beta support claims. | Historical only unless a current release doc links back with exact status. | Archived or historical input. | Not current verification evidence. | Not an artifact integrity record. | Historical documentation process. | May contain old wording or old metrics; current docs must point back to this matrix. |

<!-- markdownlint-enable MD013 -->
