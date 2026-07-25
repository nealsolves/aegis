# AEGIS Main Cutover and PyPI Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Promote the verified `v0.9.0b1` candidate to `main`, move the Render
and GitHub Pages demo deployments to `main`, publish the exact release artifact
to PyPI, and verify every public surface.

**Architecture:** Preserve the validated runtime and demo implementation.
Promote the existing `develop` baseline before changing deployment selectors,
then land a narrow cutover change through the protected
feature → `develop` → `main` PR flow. Publish through the existing GitHub
release and PyPI Trusted Publishing workflow, and bind post-release evidence to
the final commit, tag, distributions, and live deployments.

**Tech Stack:** Python 3.12, pytest, flake8, PyPA build, GitHub Actions,
GitHub Releases, PyPI Trusted Publishing, React 19, TypeScript, Vitest, Vite 8,
FastAPI, GitHub Pages, Render Blueprint.

## Global Constraints

- Candidate version remains `aegis-ai-governance==0.9.0b1`.
- Import package and console command remain `aegis`.
- Remote `develop` and `main` change only through pull requests.
- Promote the verified `develop` baseline before switching Render to `main`.
- The Pages workflow and Render Blueprint must deploy only from `main` after
  cutover.
- PyPI publication must use `.github/workflows/publish.yml` and the `pypi`
  GitHub environment; no local credential upload is permitted.
- The published artifact must be built and validated from the release tag on
  the final `main` candidate.
- Rollback is to restore the selectors to `develop`, restore the Pages
  environment branch policy, and redeploy the last verified source commit.

---

### Task 1: Verify and Promote the Existing Baseline

**Files:**

- Read: `pyproject.toml`
- Read: `.github/workflows/publish.yml`
- Read: `docs/reference/RELEASE_MATRIX.md`

**Interfaces:**

- Consumes: `origin/develop` at the completed beta baseline.
- Produces: a protected PR merge placing that exact baseline on `origin/main`.

- [ ] **Step 1: Freeze the baseline identity**

Run:

```bash
git fetch --prune origin
git rev-parse origin/develop
git rev-parse origin/main
git rev-list --left-right --count origin/main...origin/develop
```

- [ ] **Step 2: Run the complete baseline validation**

Run:

```bash
.venv/bin/python -m pytest -q
.venv/bin/flake8 aegis
(cd demo-app-react && npm test)
(cd demo-app-react && npm run lint)
(cd demo-app-react && VITE_API_URL=https://aegis-demo-api.onrender.com npm run build)
```

- [ ] **Step 3: Build and inspect release artifacts**

Run:

```bash
.venv/bin/python -m build
.venv/bin/python scripts/validate_v090_distribution_candidate.py \
  --dist-dir dist --no-build
```

- [ ] **Step 4: Open and merge the baseline `develop` → `main` PR**

Use the repository PR template. Require exact-candidate CI before merge and
record the merge commit.

### Task 2: Specify the Main-Only Deployment Contract

**Files:**

- Modify: `tests/test_beta_demo_deployment.py`
- Modify: `tests/test_pr11_release_truth.py`
- Modify: `.github/workflows/deploy-demo-react.yml`
- Modify: `demo-app-api/render.yaml`

**Interfaces:**

- Consumes: the existing least-privilege Pages and Render deployment contracts.
- Produces: main-only branch selectors without changing runtime or credential
  boundaries.

- [ ] **Step 1: Write the failing main-only deployment tests**

Change the deployment tests to require:

```python
assert workflow["on"]["push"]["branches"] == ["main"]
assert service["branch"] == "main"
```

The tests must also continue to require pinned actions, no secret access,
frontend tests/lint/build, the Render health path, free plan, and stateless
start/build commands.

- [ ] **Step 2: Verify the tests fail for the expected branch mismatch**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_beta_demo_deployment.py
```

Expected: failures showing `develop` where `main` is required.

- [ ] **Step 3: Implement the minimal selector cutover**

Update:

```yaml
# .github/workflows/deploy-demo-react.yml
on:
  push:
    branches:
      - main
```

and:

```yaml
# demo-app-api/render.yaml
branch: main
```

Rename workflow/job/checkout labels only where they describe the retired
`develop` topology.

- [ ] **Step 4: Verify the deployment contract passes**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_beta_demo_deployment.py
```

### Task 3: Prepare Accurate Release and Deployment Truth

**Files:**

- Modify: `README.md`
- Modify: `PROJECT.md`
- Modify: `CHANGELOG.md`
- Modify: `implementation_status.md`
- Modify: `demo-app-react/README.md`
- Modify: `docs/reference/RELEASE_MATRIX.md`
- Modify: `doc_parity_manifest.yaml`
- Create: `docs/spec-driven-dev/changes/v0.9.0-main-pypi-release/evidence.md`

**Interfaces:**

- Consumes: the exact candidate version, main merge identity, deployment URLs,
  and release workflow.
- Produces: current-state documentation that distinguishes release intent,
  observed deployment, and observed PyPI publication.

- [ ] **Step 1: Update pre-publication release truth**

Replace the retired “not on main” and develop-deployment statements with the
main cutover state. Change the changelog heading to:

```markdown
## [0.9.0b1] — 2026-07-25
```

Do not claim PyPI publication until the workflow has completed successfully.

- [ ] **Step 2: Update executable truth assertions**

Change release-truth tests and parity data so the release commit expects the
main deployment and versioned release state while preserving the beta maturity
classification.

- [ ] **Step 3: Run documentation and release-truth checks**

Run:

```bash
.venv/bin/python -m pytest -q \
  tests/test_pr11_release_truth.py \
  tests/test_doc_parity_v090_truth.py \
  tests/test_beta_demo_deployment.py
.venv/bin/python scripts/check_doc_parity.py
.venv/bin/python scripts/check_brand_and_version_parity.py
.venv/bin/python scripts/validate_v090_release_freeze.py
```

### Task 4: Validate and Deliver the Cutover Change

**Files:**

- Review: all files changed from `origin/develop`.

**Interfaces:**

- Consumes: Tasks 2–3.
- Produces: reviewed PR merges to `develop`, then `main`.

- [ ] **Step 1: Run the complete local validation matrix**

Run the Python suite, flake8, package build/fresh-wheel validation, API tests,
React tests, React lint, and production build.

- [ ] **Step 2: Review the exact diff**

Review correctness, release truth, least privilege, deployment rollback,
frontend/API contract alignment, and absence of unrelated changes.

- [ ] **Step 3: Commit and push only the intended release-cutover files**

Use:

```bash
git commit -m "release: cut over v0.9.0b1 to main"
git push -u origin feat/v0.9-15-main-release
```

- [ ] **Step 4: Merge through the protected branch flow**

Open and merge:

1. `feat/v0.9-15-main-release` → `develop`
2. `develop` → `main`

Require passing exact-candidate CI at both stages.

### Task 5: Verify Main Deployments

**Files:**

- External: Render Blueprint/service configuration.
- External: GitHub `github-pages` environment branch policy.

**Interfaces:**

- Consumes: the final `origin/main` commit.
- Produces: Render and Pages deployments observed from that commit.

- [ ] **Step 1: Switch the Pages environment branch policy**

Add `main`, then remove `develop`, so there is never a branch-policy gap.

- [ ] **Step 2: Confirm Render tracks `main`**

Synchronize the Blueprint if required and verify the service deploy identifies
the final main commit.

- [ ] **Step 3: Verify public backend behavior**

Check `/health`, CORS for the Pages origin, and representative invocation and
workflow endpoints.

- [ ] **Step 4: Verify public frontend behavior**

Check page load, navigation, architecture light/dark views, representative Lab
1 and Lab 11 flows, responsive rendering, and clean browser error logs.

### Task 6: Publish and Verify PyPI

**Files:**

- External: GitHub release `v0.9.0b1`.
- External: PyPI project `aegis-ai-governance`.

**Interfaces:**

- Consumes: final main commit and passing CI.
- Produces: immutable GitHub release, PyPI wheel/sdist, and clean-install proof.

- [ ] **Step 1: Create the GitHub prerelease**

Create tag/release `v0.9.0b1` targeting the exact final `main` commit with
release notes from `CHANGELOG.md`.

- [ ] **Step 2: Wait for Trusted Publishing**

Require the `Publish Python distribution to PyPI` workflow to pass. Record the
run and artifact identity.

- [ ] **Step 3: Verify PyPI identity and files**

Confirm project metadata, version, wheel, and sdist on PyPI. Compare published
file digests with the workflow artifacts where available.

- [ ] **Step 4: Prove clean installation and functionality**

In a new temporary virtual environment:

```bash
python3 -m venv /tmp/aegis-release-verify
/tmp/aegis-release-verify/bin/python -m pip install \
  aegis-ai-governance==0.9.0b1
/tmp/aegis-release-verify/bin/aegis --version
/tmp/aegis-release-verify/bin/python -c \
  "import aegis; assert aegis.__version__ == '0.9.0b1'"
```

Run the packaged smoke validation without importing from the repository
checkout.

### Task 7: Record Final Evidence and Restore Default Authority

**Files:**

- Modify: `docs/spec-driven-dev/changes/v0.9.0-main-pypi-release/evidence.md`
- Modify: current release truth only if observed publication identifiers were
  not known at the release commit.
- Restore locally: `.claude/project.yaml`

**Interfaces:**

- Consumes: merge, deployment, GitHub release, PyPI, and clean-install evidence.
- Produces: a clean repository and truthful final release record.

- [ ] **Step 1: Record exact immutable identifiers**

Record the main commit, tag, PRs, CI runs, Render deployment, Pages deployment,
PyPI version/files/digests, validation counts, and browser checks.

- [ ] **Step 2: Restore bounded authority**

Return `.claude/project.yaml` to its default remote/production-disabled state
and re-run policy validation.

- [ ] **Step 3: Verify final repository and public state**

Run:

```bash
git status --short
git rev-parse origin/main
git rev-parse origin/develop
```

Confirm the live services and installed distribution one final time before
claiming completion.
