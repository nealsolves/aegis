# Classification and Brownfield Evidence

**Change ID:** `v0.9.0-pypi-distribution`

**Observed base:** `fd575f3f5e28e238373284629361476048179016`

**Intent hash:** `bef51b8878459af23fcc52067c038db447cf611afaa41797c6291d87cfee8fb5`

The intent hash is SHA-256 over the exact base commit plus SHA-256 records for
`spec.md`, `plan.md`, and `tasks.md`.

## Observable Facts

| Fact | Value | Confidence | Evidence |
|---|---:|---:|---|
| `documentation_only` | false | 1.0 | package metadata, executable checks, tests, and a release workflow change |
| `modifies_runtime_code` | true | 1.0 | fresh-wheel proof exposed and repaired audit-mode governance metadata leakage in `aegis/_internal/workflow_export.py` |
| `changes_public_contract` | true | 1.0 | install name and published version change |
| `adds_external_dependency` | true | 1.0 | release tooling and pinned GitHub actions are introduced |
| `changes_infrastructure` | true | 1.0 | `.github/workflows/publish.yml` is added |
| `deploys_to_production` | false | 1.0 | task stops before publication |
| `instruction_system_change` | false | 1.0 | installed controls are not modified |

## Current Contract Sources

- `pyproject.toml`: distribution `aegis`, version `0.3.3`, import discovery
  restricted to `aegis` and `aegis.*`, console command `aegis`.
- `aegis/__init__.py`: runtime `__version__ = "0.3.3"`.
- `tests/test_pr11_packaging_smoke.py`: current artifact smoke proof.
- `tests/test_pr11_release_truth.py`,
  `tests/test_v090_contract_freeze.py`, and
  `tests/test_doc_parity_v090_truth.py`: frozen release/document contracts.
- `scripts/check_brand_and_version_parity.py` and
  `scripts/check_doc_parity.py`: executable release-truth checks.
- `scripts/validate_v090_beta_proof.py`,
  `scripts/validate_v090_full_functionality.py`, and
  `scripts/validate_v090_release_freeze.py`: existing source/clean-environment
  proof entry points.

## Maintained Release Surfaces

At minimum, the following current surfaces contain release or installation
truth and require reconciliation:

- `README.md`
- `PROJECT.md`
- `CHANGELOG.md`
- `RELEASE_GATES.md`
- `implementation_status.md`
- `docs/reference/RELEASE_MATRIX.md`
- `docs/PUBLIC_INTEGRATION_CONTRACT.md`
- `docs/reference/WORKFLOW_QUICKSTART.md`
- `docs/reference/SUPPORTED_ENVIRONMENTS.md`
- `docs/reference/OPERATIONS_RUNBOOK.md`
- `docs/releases/v0.9.0-beta-test-evidence.md`
- `demo-app-react/public/portal.html`

Historical articles, audits, superseded plans, and architecture roadmaps remain
unchanged unless a maintained surface links to them as current installation
truth.

## Consumers and Compatibility

- Existing host code imports `aegis`; that import must remain unchanged.
- Existing shell and documentation examples invoke `aegis`; the CLI must remain
  unchanged.
- Existing optional extras are selected from the distribution name and must use
  `aegis-ai-governance[...]` after the change.
- PyPI's pending publisher matches `aegis-ai-governance`,
  `nealsolves/aegis`, `publish.yml`, and environment `pypi`.
- The original dirty checkout is not a consumer of this isolated branch and
  must remain untouched.

## Reversal

Before publication, revert the implementation commits. Remote, release, and
production actions remain disabled by `.claude/project.yaml`, so this local
work cannot publish through policy.

## Implementation Evidence

- Distribution contract tests first failed on `aegis` / `0.3.3`, then passed
  after the metadata change.
- The publishing workflow contract first failed because `publish.yml` was
  absent, then passed with exact action commit pins and job-scoped OIDC.
- Fresh-wheel proof exposed raw governance metadata in audit mode. Regression
  tests reproduced the leak before the implementation was narrowed to preserve
  normalized adapter metadata while redacting the governance subtree.
- Repository suite: `1903 passed, 2 skipped` on Python 3.12.
- Final artifact and installed-workflow details are emitted by
  `scripts/validate_v090_distribution_candidate.py`; publication remains
  prohibited.
