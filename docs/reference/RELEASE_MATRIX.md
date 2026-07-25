# AEGIS Release Matrix

Last verified: 2026-07-25.

This is the canonical release-truth table for AEGIS. It separates the previous
PyPI release, the new package candidate, remote source state, and archived
material.

Verification snapshot used for this table:

- Current package candidate is `aegis-ai-governance==0.9.0b1`.
- Package metadata and `aegis.__version__` are `0.9.0b1`.
- Import package and CLI remain `aegis`.
- The candidate is not yet published to PyPI.
- Previous PyPI line: `aegis==0.3.3`.
- Candidate implementation and release evidence merged through PR #16 into
  `origin/develop` at `205026ac8368eaa33f532beca376c8974fae786b`.
- Corrected package-author and project-owner metadata is at PR #17 commit
  `b0eeed502cff8722b676b0f0b8d2e15189860982`.
- The current locally validated artifacts were built from that corrected
  candidate commit.
- Final artifact digests and test totals are recorded in the release evidence
  and external E2E report.

These source refs identify the inspected beta baseline. Before any merge commit
is used for public beta or release claims, rerun the snapshot commands and
replace the local and remote source refs with the exact target refs.

<!-- markdownlint-disable MD013 -->

| Channel | Version label | Exact ref | Distribution | Included surfaces | Excluded surfaces | Adapter status | Support stance | Test status | Artifact integrity | Build authority | Known limitations |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Previous PyPI release | `aegis==0.3.3` | Historical release dated `2026-04-10`. | `pip install aegis==0.3.3`. | Invocation governance, split enforcement, policy loading, audit artifacts, signing, audit chain utility, lineage, provenance gate, and compliance export. | The v0.9 workflow CLI, starter scaffolds, trace/export operations, and optional adapters. | Not claimed as included. | Previous installable line; no longer the candidate identity. | Historical release evidence. | Historical artifacts are outside this candidate packet. | Historical publisher path. | The `aegis` distribution name cannot be used for the new release. |
| Local beta candidate | `aegis-ai-governance==0.9.0b1` | PR #16 merged at `origin/develop` commit `205026ac8368eaa33f532beca376c8974fae786b`; corrected package-author and owner evidence is at PR #17 commit `b0eeed502cff8722b676b0f0b8d2e15189860982`. | Wheel and sdist built locally; after publication, `pip install aegis-ai-governance==0.9.0b1`. | `AEGIS.open_session(...)`, workflow sessions and starters, policy/workflow init, lint, doctor, trace, export, invocation governance, and packaged optional adapter submodules. | Hosted control plane, transport ownership, cloud credentials, provider SDK ownership, tenant isolation, and top-level adapter re-exports. | Bedrock and A2A require no base SDK dependency; OpenAI Agents requires the `openai-agents` extra. | Beta candidate under review in PR #17, not yet promoted to `main` or published to PyPI. | Corrected-candidate rerun: `1903 passed, 2 skipped`; full-functionality harness PASS; React `102 passed`, lint PASS, production build PASS, and browser/API smoke PASS; fresh-wheel E2E PASS. | Corrected-author artifact SHA-256 digests are recorded in the release evidence and external E2E report. Independent rebuilds have identical wheel `RECORD` payload hashes but different archive hashes from timestamps; the release workflow builds once and promotes those same artifacts. | Pending Trusted Publisher `nealsolves/aegis` / `publish.yml` / `pypi`; no upload authorized. | Publication remains a separate human-authorized action; byte-for-byte local rebuild reproducibility is not established. |
| Previous remote source baseline | `v0.9.0 source beta` | `origin/develop` at `73f1bfc494dd5290a7e579069b3cad72e33457ed`, before PR #16. | Source checkout only. | Workflow beta surfaces present at that exact ref. | Candidate distribution rename, release workflow, and local release-ready evidence. | Ref-specific. | Superseded development baseline. | Baseline suite passed before candidate work. | No candidate artifact digests. | Remote branch process. | Historical comparison row; do not treat this ref as the package candidate. |
| Docs-only draft | `v0.9.0 hardening plan` | `docs/plans/v0.9.0_RELEASE_TRUTH_AND_GOVERNANCE_HARDENING_PLAN.md` is a local planning input in this checkout. | Documentation only. | Requirements RTG-001 through RTG-015 and hardening guidance. | Runtime, schema, CLI, and release claims until implemented and verified. | Planning status only. | Proposed development spec. | Not applicable unless converted into tests or release gates. | Not an artifact integrity record. | Maintainer-authored local plan. | Do not treat plan text as shipped behavior. |
| Archived article | Historical `v0.3.x` narrative | Archived docs under `docs/articles/` and historical audit docs under `docs/audits/`. | Documentation only. | Historical context. | Current release truth and beta support claims. | Historical only unless a current release doc links back with exact status. | Archived or historical input. | Not current verification evidence. | Not an artifact integrity record. | Historical documentation process. | May contain old wording or old metrics; current docs must point back to this matrix. |

<!-- markdownlint-enable MD013 -->
