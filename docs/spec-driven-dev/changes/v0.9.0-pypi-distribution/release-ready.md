# AEGIS v0.9.0b1 Release Evidence

**Publication status:** prohibited until a separate exact authorization

## Source

- Branch: `feat/v0.9-12-pypi-distribution`
- Candidate source commit:
  `b27e7fa9a347c77b99ebb9cfa7ff5c6498214583`
- Distribution: `aegis-ai-governance`
- Version: `0.9.0b1`
- Import/CLI: `aegis`

## Artifacts

| File | SHA-256 |
|---|---|
| `aegis_ai_governance-0.9.0b1-py3-none-any.whl` | `fd2b1a2c5283e35313b0f5de3171acdd019bde1d86c8c95df99e3930d1bf3a59` |
| `aegis_ai_governance-0.9.0b1.tar.gz` | `a68672e548553398442fff0d9551cdfc7ca984676064cdcc423816bd5cc0e8af` |

`scripts/validate_v090_distribution_candidate.py` built and inspected both
artifacts, installed the wheel into a new Python 3.12 environment, and rejected
source-checkout import leakage. The clean installation also passed `pip check`.

## Test Evidence

- Repository suite: `1903 passed, 2 skipped`, 14 warnings.
- Focused release suite: `73 passed, 1 skipped`.
- Demo API: `67 passed`.
- Full-functionality harness: PASS.
- Fresh-wheel minimal starter: `COMPLETED`.
- Fresh-wheel standard starter: `COMPLETED` with the expected approved
  `starter-approval-001` checkpoint.
- Regulated path: failure, `WORKFLOW_SOURCE_REQUIRED` doctor diagnosis, fix,
  then `COMPLETED`.
- Trace, audit export, operator export, and compliance-lineage export: PASS,
  with matching session IDs, resolved step checksums, and canonical invocation
  artifact checksum verification.
- Brand/version parity, documentation parity, public-import boundary, release
  freeze, and `flake8 aegis`: PASS.
- React demo: `17` test files and `102` tests PASS; ESLint PASS;
  TypeScript/Vite production build PASS.
- React production browser smoke: PASS against the local FastAPI backend,
  including architecture assets, theme switching, Lab 11 navigation, and a
  completed minimal governed workflow with no browser/runtime/request errors.

## Publishing Evidence

The pending PyPI publisher and workflow agree on:

- project `aegis-ai-governance`;
- repository `nealsolves/aegis`;
- workflow `publish.yml`;
- environment `pypi`.

The release workflow has a separate unprivileged build job, job-scoped OIDC
permission, no token secret, and full-commit action pins. No remote workflow or
OIDC exchange has run.

## Repair Evidence

The fresh-wheel proof found that audit-mode workflow export copied the raw
governance metadata subtree beside its redacted projection. A failing regression
test reproduced the leak. The repair preserves normalized non-governance adapter
metadata and replaces the governance subtree with the allowlisted summary.

Independent review then found stale current installation guidance in the
maintained React portal and three incomplete E2E assertions. Those findings
were reproduced with failing tests and repaired: the portal now identifies the
new unpublished candidate, and the fresh-wheel proof now checks dependencies,
approval evidence, session correlation, and invocation checksums.

A follow-up review found the old distribution name in the optional OpenAI
Agents extra remediation. Runtime errors and every maintained guidance surface
now use `aegis-ai-governance[openai-agents]`, with executable parity coverage.

## Rollback and Gaps

Before publication, revert the five candidate commits or drop the isolated
branch/artifacts. No irreversible action has occurred.

Known non-blocking gaps:

- React checks were not installed locally.
- The live GitHub OIDC/PyPI exchange requires an authorized GitHub Release.
- Setuptools warns that the current license metadata form should move to an
  SPDX expression before its 2027 deprecation cutoff.
