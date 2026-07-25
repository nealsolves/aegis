# AEGIS Spec-Driven Delivery Bootstrap

**Decision ID:** `BOOTSTRAP-2026-07-24-AEGIS-SDD`

**Date:** 2026-07-24

**Owner and authorizing authority:** Neal Adams

## Intent

Instantiate the control process from
[`nealsolves/spec-driven-dev`](https://github.com/nealsolves/spec-driven-dev)
for the existing AEGIS repository before changing its Python distribution name
or preparing the `v0.9.0` release.

The owner explicitly requested this bootstrap in the active Codex task. That
approval covers this initial instruction-system installation only. Subsequent
instruction-system changes remain `human_required` under the installed
constitution and policy.

## Provenance

| Item | Exact reference |
|---|---|
| AEGIS branch base | `73f1bfc494dd5290a7e579069b3cad72e33457ed` |
| AEGIS base branch | `develop` / `origin/develop` |
| Isolated branch | `feat/v0.9-12-pypi-distribution` |
| spec-driven-dev source | `f34bbcfc72a77e7cf24efe62001e2fd34eb5776c` |
| spec-driven-dev repository | `https://github.com/nealsolves/spec-driven-dev.git` |

The upstream template was validated before instantiation:

- policy validation: PASS;
- upstream unit suite: 165 tests passed;
- AEGIS clean baseline on Python 3.12.13: 1,883 passed and 3 skipped.

## Deterministic Policy Decision

The instantiated engine validated the repository and bootstrap context, then
classified the proposal as a low-risk `instruction_system_change`. As required,
it returned `human_required` rather than allowing the proposed policy to
authorize itself.

The owner's explicit instruction was ingested as the bounded
`authorize_once` response for decision
`DEC-BOOTSTRAP-2026-07-24-AEGIS-SDD-AUTH-instruction_system_change`.
Reevaluation returned `autonomous_with_enhanced_gates`.

| Hash | Value |
|---|---|
| Proposed change | `6434bf6398bd73be9115734efeefd7c6bf8dfe02a343c99496b02cc5cf91d1fa` |
| Installed policy | `5d83cd5cc6626114dc06371750edc25b926cd278e19c45e2f3fdb6018c245f68` |
| Escalation context | `837ab2966321da04bc4735652308e707d4e678eb02907531dfb1634f35c49346` |
| Authorized context | `9c9ee754a1eef6d3734095445fa3b668257f8da985dec254c8dc8bb3ff183450` |

The proposed-change hash is the SHA-256 of the staged installation diff,
excluding `docs/spec-driven-dev/**` because those generated evidence records
embed the hash. The evidence records bind back to that proposal through their
`change_hash` and to the installed controls through their `policy_hash`.

## Brownfield Installation Decision

The behavioral kernel, four control files, schemas, rules, workflows, profiles,
templates, constitution, policy engine, feature-context validator, and bounded
policy requirements are installed in their canonical locations.

AEGIS-specific guidance is preserved in
`.claude/rules/aegis-project.md` and is always routed. The AEGIS README,
application tests, release documentation, and existing implementation ledger
remain application-owned rather than being replaced with reusable-template
content.

This is a brownfield integration of the process, not conversion of AEGIS into a
copy of the reusable template repository.

## Project Facts

| Control | Configured value | Evidence |
|---|---|---|
| Project identity | `AEGIS`, `nealsolves/aegis` | `pyproject.toml`, Git remote |
| Owner | Neal Adams | `pyproject.toml` authors |
| Escalation owner | `neal@nealsolves.com` | `pyproject.toml` authors |
| Profile | `solo` | owner instruction and repository history |
| Spec Kit | disabled; equivalent manual gates allowed | no installed Spec Kit artifacts; existing design/plan process |
| Install | `python -m pip install -e ".[dev]"` | `pyproject.toml`, `CLAUDE.md` |
| Test | `python -m pytest` | `pyproject.toml`, `CLAUDE.md` |
| Lint | `flake8 aegis` | `.flake8`, `CLAUDE.md` |
| Typecheck | `not_applicable` | no configured type-check command |
| Build | `python -m build` | release documentation and Python build metadata |
| Release | `not_applicable` during bootstrap | no tracked release workflow or release command at the base commit |
| Data | public source and synthetic demo data; no regulated data identified | repository source, samples, fixtures, and demo documentation |
| Production data in non-production | prohibited | constitution and project safe default |
| Environment | local development | verified Python 3.12 worktree |
| Remote actions | disabled | no action-specific authority granted |
| Production actions | disabled | no production target or deployment mechanism configured |
| Autonomous spend | USD 0 | safe reversible default; change through project policy |
| External obligation | Apache-2.0 | `pyproject.toml`, `LICENSE` |

## Existing Checkout Protection

The original checkout was inspected without modification:

- 499 tracked files have permission-only changes (`100644` to `100755`);
- four tracked files have local content changes: `PROJECT.md`, `README.md`,
  `demo-app-react/src/App.tsx`, and
  `demo-app-react/src/components/layout/LabTabs.tsx`;
- 111 files are untracked: 21 under `demo-app-react`, 13 under `docs`, 75 under
  `graphify-out`, and two under `policies`;
- none of the 115 local content files exactly matches a blob in any current
  repository commit.

No cleanup, reset, permission normalization, or migration of those local files
is authorized by this bootstrap.

## Release Boundary

PyPI has a pending Trusted Publisher for:

- project `aegis-ai-governance`;
- repository `nealsolves/aegis`;
- workflow `publish.yml`;
- GitHub environment `pypi`.

The pending publisher is evidence of intended release configuration, not
authority to upload. This task must stop at `RELEASE_READY` unless the owner
separately authorizes the exact PyPI publication action.

## Reversal

Revert the bootstrap commit to remove the installed instruction system. The
isolated worktree and branch can be removed independently without changing the
original checkout or its local files.
