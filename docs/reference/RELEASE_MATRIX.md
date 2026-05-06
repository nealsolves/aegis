# AEGIS Release Matrix

Last verified: 2026-05-05.

This is the canonical release-truth table for AEGIS. It separates the package
that users can install from PyPI from source-only beta work, branch-local docs,
and archived material.

Verification snapshot used for this table:

- Current package release is `0.3.3`.
- Package metadata and `aegis.__version__` are `0.3.3`.
- Local `develop`: `9e84d34db79414e1f8db3101735f9ea4fbe3e854`.
- Local `origin/develop`: `9e84d34db79414e1f8db3101735f9ea4fbe3e854`.
- No local `v0.3.3`, `0.3.3`, or `v0.9.0` release tag was observed.
- `python -m pytest --ignore=tests/test_openai_agents_adapter_integration.py --collect-only -q`
  collected `1816 base-package tests`.
- Environments with the optional `openai-agents` extra installed collect `19`
  additional OpenAI Agents integration tests.

These source refs identify the inspected beta baseline. Before any merge commit
is used for public beta or release claims, rerun the snapshot commands and
replace the local and remote source refs with the exact target refs.

<!-- markdownlint-disable MD013 -->

| Channel | Version label | Exact ref | Distribution | Included surfaces | Excluded surfaces | Adapter status | Support stance | Test status | Artifact integrity | Build authority | Known limitations |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| PyPI | `0.3.3` | No local release tag observed for `0.3.3`; package metadata is authoritative in this checkout. | PyPI package via `pip install aegis`. | Invocation governance, split enforcement, policy loading, audit artifacts, signing, audit chain utility, lineage, provenance gate, compliance export. | Source-only workflow beta, workflow CLI, starter scaffolds, and optional adapters are not PyPI release claims. | Not claimed as shipped in PyPI by this matrix. | Current installable package line. | Source checkout currently collects `1816 base-package tests`; package-release proof must be tied to the release artifact before promotion. | Source archive and wheel SHA-256, SBOM, and attestation are not recorded in this checkout. | PyPI build and publisher identity are not recorded in this checkout. | The package remains `0.3.3` until a real package release is cut. |
| Local source beta | `v0.9.0 source-only beta` | Local `develop` at `9e84d34db79414e1f8db3101735f9ea4fbe3e854`. | Source checkout only. | `AEGIS.open_session(...)`, `GovernanceSession`, `SessionPreCallResult`, workflow starters, `aegis policy init`, `aegis workflow init`, `aegis workflow lint`, `aegis workflow doctor`, `aegis workflow trace`, `aegis workflow export`, workflow/session artifacts, and optional adapter submodules. | No hosted control plane, transport ownership, cloud credentials, provider SDK ownership, tenant isolation, or top-level adapter re-exports. | `aegis.bedrock_adapter`, `aegis.a2a_adapter`, and `aegis.openai_agents_adapter` are source-only beta submodules; OpenAI Agents requires the optional `openai-agents` extra. | Beta, source-only, not a PyPI release. | `1816 base-package tests` collected locally; the optional `openai-agents` extra adds `19` integration tests. Adapter tests are fixture-only and do not require external services. | No release archive, wheel digest, SBOM, provenance, or attestation is recorded for the source beta. | Local branch state only until merged through PRs. | Branch-local status can drift; cite the exact ref when making claims. |
| Remote source beta | `v0.9.0 source-only beta` | Local `origin/develop` ref at `9e84d34db79414e1f8db3101735f9ea4fbe3e854`. | Remote branch checkout, not PyPI. | Same beta surfaces as the remote ref contains. | Any local-only untracked files, docs-only plans, and feature branch work not merged to `origin/develop`. | Ref-specific; do not imply an adapter is remote-shipped without checking the exact ref. | Beta branch. | Must be verified from the remote checkout or CI for that ref. | No release artifact integrity record in this checkout. | Remote PR and branch-protection process. | Treat local `develop` and `origin/develop` as separate claims unless their SHAs match. |
| Docs-only draft | `v0.9.0 hardening plan` | `docs/plans/v0.9.0_RELEASE_TRUTH_AND_GOVERNANCE_HARDENING_PLAN.md` is a local planning input in this checkout. | Documentation only. | Requirements RTG-001 through RTG-015 and hardening guidance. | Runtime, schema, CLI, and release claims until implemented and verified. | Planning status only. | Proposed development spec. | Not applicable unless converted into tests or release gates. | Not an artifact integrity record. | Maintainer-authored local plan. | Do not treat plan text as shipped behavior. |
| Archived article | Historical `v0.3.x` narrative | Archived docs under `docs/articles/` and historical audit docs under `docs/audits/`. | Documentation only. | Historical context. | Current release truth and beta support claims. | Historical only unless a current release doc links back with exact status. | Archived or historical input. | Not current verification evidence. | Not an artifact integrity record. | Historical documentation process. | May contain old wording or old metrics; current docs must point back to this matrix. |

<!-- markdownlint-enable MD013 -->
