# AEGIS v0.9.0b1 Release Evidence

**Publication status:** prohibited until a separate exact authorization

## Source

- Merged source: PR #16 at `origin/develop` commit
  `205026ac8368eaa33f532beca376c8974fae786b`
- Corrected candidate and artifact source commit:
  `b0eeed502cff8722b676b0f0b8d2e15189860982`
- The corrected candidate updates package authorship and project owner evidence
  from the merged baseline; the following evidence commit changes documentation
  only.
- Distribution: `aegis-ai-governance`
- Version: `0.9.0b1`
- Import/CLI: `aegis`

## Artifacts

Corrected-author verification build on 2026-07-25:

| File | SHA-256 |
|---|---|
| `aegis_ai_governance-0.9.0b1-py3-none-any.whl` | `0692a62c8a68db6091cc9b0799d8d2c0916a82dbe7b2c64db175e8a18c7f7fae` |
| `aegis_ai_governance-0.9.0b1.tar.gz` | `840715e2270604bc5f8f125a82da40d4b3dd551a884d877a0a0a405061a57ad6` |

`scripts/validate_v090_distribution_candidate.py` built and inspected both
artifacts, installed the wheel into a new Python 3.12 environment, and rejected
source-checkout import leakage. The clean installation also passed `pip check`.
Both artifacts embed `Neal Bhattacharya <neal@nealsolves.com>` as the author.
Earlier local artifacts containing superseded author metadata must not be
published.

A second post-merge wheel rebuild produced a different archive SHA-256 while
its embedded `RECORD` matched exactly. The payload is identical, but ZIP
timestamps currently prevent byte-for-byte reproducible wheel hashes. The
release workflow builds once and passes those exact artifacts from validation
to publication; the workflow-produced digests are authoritative for the
published files.

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
- Post-merge rerun on 2026-07-25: all results above remained PASS; the focused
  release suite reported `75 passed, 1 skipped`.

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

The repository owner then corrected the project owner and package author name
to Neal Bhattacharya. The correction covers package metadata, project controls,
constitution and bootstrap authority evidence, implementation status, release
specification, and regression tests.

## Rollback and Gaps

Before publication, close or revert PR #17, revert PR #16 through a reviewed
PR, and discard the local candidate artifacts. No irreversible publication
action has occurred.

Known non-blocking gaps:

- The live GitHub OIDC/PyPI exchange requires an authorized GitHub Release.
- Wheel and sdist archive bytes are not reproducible across independent local
  builds because archive timestamps vary; embedded wheel payload hashes match.
- Setuptools warns that the current license metadata form should move to an
  SPDX expression before its 2027 deprecation cutoff.
