# AEGIS Documentation, Diagram, and Beta Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reconcile the requested AEGIS documentation with the v0.9 beta code,
remove component-diagram overflow, and deploy the React/FastAPI beta demo from
`develop` without changing `main`.

**Architecture:** Keep the Python SDK unchanged. Strengthen executable
documentation, diagram-layout, and deployment contracts; regenerate SVGs from
their canonical generator; deploy the stateless FastAPI backend from Render and
the Vite build through GitHub Pages. Treat local implementation and each remote
action as separate policy decisions.

**Tech Stack:** Python 3.12, pytest, PyYAML, JSON Schema, SVG, React 19,
TypeScript, Vitest, Vite 8, FastAPI, GitHub Actions/Pages, Render Blueprint.

## Global Constraints

- Work on `feat/v0.9-14-docs-pages-render`, based on `develop`.
- Do not merge, push, deploy, or open a pull request against `main`.
- GitHub Pages and Render use `develop` only for the beta period.
- Do not claim `aegis-ai-governance==0.9.0b1` is published to PyPI or released.
- Pre-`0.9.0` source, tags, and releases remain in
  `https://github.com/nealsolves/aigc`.
- Do not hand-edit generated SVG files.
- Do not add provider credentials, provider calls, customer data, or a runtime
  dependency.
- Every external action requires a fresh policy evaluation; a prohibited
  outcome stops that action.
- `origin/main` must remain at `0ddcee9bb08c850a340d6938124a415948906c57`.

---

## File Structure

### Create

- `.github/workflows/deploy-demo-react.yml` — build, test, package, and deploy
  the React beta to GitHub Pages from `develop`.
- `tests/test_beta_demo_deployment.py` — static deployment-security and branch
  contract for Pages and Render.
- `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/spec.md` —
  pointer to the approved design.
- `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/plan.md` —
  pointer to this implementation plan.
- `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/tasks.md` —
  acceptance-to-task map.
- `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/context.json`
  — typed policy context for local implementation.
- `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/evaluation.json`
  — deterministic policy evaluation.
- `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/documentation-audit.md`
  — requested-file audit and retain/delete rationale.
- `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/evidence.md`
  — final validation, deployment, and rollback evidence.
- `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/review.md`
  — final independent review findings and repairs.

### Modify

- `docs/superpowers/specs/2026-07-25-aegis-docs-diagrams-beta-deployment-design.md`
  — record written approval.
- `tests/test_doc_parity_v090_truth.py` — enforce release-history ownership and
  current PR #18/repository/deployment truth.
- `tests/test_architecture_diagram_truth.py` — reject conservatively estimated
  text overflow in generated SVG boxes.
- `docs/architecture/diagrams/render_v090_component_diagrams.py` — compact
  text classes and semantic line wrapping for constrained nodes.
- `docs/architecture/diagrams/aegis_v090_beta_component_light.svg` — generated
  light beta component asset.
- `docs/architecture/diagrams/aegis_v090_beta_component_dark.svg` — generated
  dark beta component asset.
- `docs/architecture/diagrams/aegis_architecture_component_light.svg` —
  generated canonical light component asset.
- `docs/architecture/diagrams/aegis_architecture_component.svg` — generated
  canonical dark component asset.
- `demo-app-react/public/diagrams/aegis_architecture_component_light.svg` —
  generated React mirror.
- `demo-app-react/public/diagrams/aegis_architecture_component.svg` — generated
  React mirror.
- `demo-app-api/render.yaml` — Render service branch, free plan, auto-deploy,
  and health-check contract.
- `README.md` — release ownership and observed live beta status.
- `PROJECT.md` — generated-path-aware repository map and current demo
  architecture.
- `docs/AEGIS_FRAMEWORK.md` — pre-v0.9 source ownership.
- `docs/INTEGRATION_GUIDE.md` — pre-v0.9 source ownership and verified examples.
- `docs/PUBLIC_INTEGRATION_CONTRACT.md` — pre-v0.9 source ownership and
  verified examples.
- `docs/USAGE.md` — pre-v0.9 source ownership and verified recipes.
- `docs/reference/RELEASE_MATRIX.md` — PR #18/current-ref truth, prior-repo
  ownership, deployed-demo channel.
- `docs/reference/*.md` and `docs/reference/external/*.md` — only factual,
  link, status, or example corrections demonstrated by the audit.
- `demo-app-react/README.md` — actual Render URL, Pages workflow, `develop`
  beta topology, and future `main` cutover.
- `implementation_status.md` — local/remote/deployed status without implying a
  release.
- `doc_parity_manifest.yaml` — only if the maintained-document checks require
  the new current-state files.

---

### Task 1: Bootstrap Validation and Govern the Local Change

**Files:**

- Modify:
  `docs/superpowers/specs/2026-07-25-aegis-docs-diagrams-beta-deployment-design.md`
- Create:
  `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/spec.md`
- Create:
  `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/plan.md`
- Create:
  `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/tasks.md`
- Create:
  `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/context.json`
- Create:
  `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/evaluation.json`

**Interfaces:**

- Consumes: approved design commit `81ca467`.
- Produces: validated local-implementation authority, routed modules, and
  hashes for the implementation scope.

- [ ] **Step 1: Create the isolated development environment**

Run:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[dev]"
```

Expected: editable package and the configured test/lint dependencies install
without changing tracked files.

- [ ] **Step 2: Record approval and create the governed change artifacts**

Set the design status to `Approved` with `Approved by: Neal Bhattacharya`.
Create the three Markdown pointers and a task map covering documentation,
diagram, deployment configuration, local verification, remote delivery, and
deployed smoke tests.

Create `context.json` with schema version `1`, change ID
`v0.9.0-docs-diagrams-beta-deployment`, workflow family `brownfield`, action
`local_implementation`, and current state `UNCLASSIFIED`. Set these typed
facts: `documentation_only=false`, `modifies_runtime_code=false`,
`changes_public_contract=false`, `changes_infrastructure=true`,
`adds_external_dependency=false`, `deploys_to_production=true`, and
`instruction_system_change=false`.

Compute the immutable approved-scope hash with:

```bash
shasum -a 256 \
  docs/superpowers/specs/2026-07-25-aegis-docs-diagrams-beta-deployment-design.md \
  docs/superpowers/plans/2026-07-25-aegis-docs-diagrams-beta-deployment.md \
  | shasum -a 256
```

Use the command's 64-character digest as `change_hash`. Populate every fact
with the context-schema-required provenance fields, using the approved design,
deployment files, dependency manifests, and exact change hash as sources.

- [ ] **Step 3: Validate and evaluate**

Run:

```bash
.venv/bin/python scripts/policy-engine.py validate --root . --context docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/context.json
.venv/bin/python scripts/policy-engine.py evaluate --root . --context docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/context.json --output docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/evaluation.json
```

Expected: the engine returns a valid local-implementation decision and routes
architecture, security, production-readiness, observability, release,
engineering, testing, documentation, and repository guidance. If it returns
`human_required` or `prohibited`, stop implementation at that exact decision.

- [ ] **Step 4: Verify and commit the approved artifacts**

Run:

```bash
git diff --check
.venv/bin/python scripts/policy-engine.py validate --root . --context docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/context.json
git add docs/superpowers/specs/2026-07-25-aegis-docs-diagrams-beta-deployment-design.md docs/superpowers/plans/2026-07-25-aegis-docs-diagrams-beta-deployment.md docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment
git commit -m "docs: plan beta demo deployment follow-up"
```

Expected: clean validation and a scoped plan/governance commit.

---

### Task 2: Add Documentation and Repository-Truth Regression Tests

**Files:**

- Modify: `tests/test_doc_parity_v090_truth.py`

**Interfaces:**

- Consumes: tracked repository structure, PR #18 merge state, and requested
  maintained-document list.
- Produces: executable assertions that fail before the documentation edits and
  prevent future ownership/deployment drift.

- [ ] **Step 1: Write the failing release-ownership test**

Add:

```python
PRE_V090_HISTORY_DOCS = (
    "README.md",
    "PROJECT.md",
    "docs/AEGIS_FRAMEWORK.md",
    "docs/INTEGRATION_GUIDE.md",
    "docs/PUBLIC_INTEGRATION_CONTRACT.md",
    "docs/USAGE.md",
    "docs/reference/RELEASE_MATRIX.md",
)


def test_pre_v090_release_history_points_to_the_aigc_repository():
    root = SCRIPT_PATH.parents[1]
    release_repo = "https://github.com/nealsolves/aigc"

    for rel in PRE_V090_HISTORY_DOCS:
        text = (root / rel).read_text(encoding="utf-8")
        assert release_repo in text, f"{rel} must identify the pre-v0.9 source"
```

- [ ] **Step 2: Write the failing repository/deployment truth test**

Add:

```python
def test_repo_guide_and_demo_docs_name_the_beta_deployment_sources():
    root = SCRIPT_PATH.parents[1]
    project = (root / "PROJECT.md").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")
    demo = (root / "demo-app-react" / "README.md").read_text(encoding="utf-8")

    for anchor in (
        ".github/workflows/deploy-demo-react.yml",
        "demo-app-api/render.yaml",
        "develop",
        "https://nealsolves.github.io/aegis/",
    ):
        assert anchor in project + readme + demo

    assert "may still show the last `main` build" not in readme
```

Update `test_release_matrix_records_the_merged_unpublished_candidate()` to
require PR #18 merge commit `fdf3649` for current documentation truth while
retaining PR #17/`8be5f54` as the package-candidate build baseline.

- [ ] **Step 3: Run the tests and verify the expected failures**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_doc_parity_v090_truth.py -k "pre_v090 or repo_guide or release_matrix"
```

Expected: failures identify the missing `nealsolves/aigc` links, absent Pages
workflow map entry, stale live-demo wording, and PR #18 matrix truth.

- [ ] **Step 4: Commit the red tests**

Run:

```bash
git add tests/test_doc_parity_v090_truth.py
git commit -m "test: capture documentation and deployment truth gaps"
```

---

### Task 3: Audit and Reconcile the Requested Documentation

**Files:**

- Modify: `README.md`
- Modify: `PROJECT.md`
- Modify: `docs/AEGIS_FRAMEWORK.md`
- Modify: `docs/INTEGRATION_GUIDE.md`
- Modify: `docs/PUBLIC_INTEGRATION_CONTRACT.md`
- Modify: `docs/USAGE.md`
- Modify: `docs/reference/OPERATIONS_RUNBOOK.md`
- Modify: `docs/reference/RELEASE_MATRIX.md`
- Modify: `docs/reference/STARTER_INDEX.md`
- Modify: `docs/reference/STARTER_RECIPES.md`
- Modify: `docs/reference/SUPPORTED_ENVIRONMENTS.md`
- Modify: `docs/reference/TROUBLESHOOTING.md`
- Modify: `docs/reference/WORKFLOW_CLI.md`
- Modify: `docs/reference/WORKFLOW_QUICKSTART.md`
- Modify: `docs/reference/external/A2A_ADAPTER.md`
- Modify: `docs/reference/external/BEDROCK_ADAPTER.md`
- Modify: `docs/reference/external/OPENAI_AGENTS_ADAPTER.md`
- Modify: `docs/reference/external/README.md`
- Create:
  `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/documentation-audit.md`

**Interfaces:**

- Consumes: `aegis.__all__`, public submodules, CLI parser, JSON Schemas,
  `pyproject.toml`, executable tests, and live deployment observations.
- Produces: accurate maintained documentation with a per-file retain/delete
  decision.

- [ ] **Step 1: Generate the requested-file audit inventory**

For every requested file, record:

```text
path | reader/purpose | authoritative code/tests | inbound maintained links |
findings | decision (retain/update/delete)
```

Use these commands as evidence:

```bash
git ls-files 'docs/reference/**/*.md' 'docs/reference/*.md' docs/INTEGRATION_GUIDE.md docs/PUBLIC_INTEGRATION_CONTRACT.md docs/USAGE.md docs/AEGIS_FRAMEWORK.md
rg -n "docs/reference|INTEGRATION_GUIDE|PUBLIC_INTEGRATION_CONTRACT|USAGE.md|AEGIS_FRAMEWORK" --glob '*.md'
rg -n "from aegis|import aegis|aegis workflow|aegis policy" docs/reference docs/INTEGRATION_GUIDE.md docs/PUBLIC_INTEGRATION_CONTRACT.md docs/USAGE.md
```

The initial evidence shows that all requested files have maintained inbound
links and distinct readers. Retain each unless code/example verification
demonstrates obsolete duplication; record “retained, no change” rather than
editing without a finding.

- [ ] **Step 2: Rebuild the repository map from tracked paths**

Update `PROJECT.md` to include:

```text
├── .github/workflows/               Release and beta Pages automation
├── demo-app-api/
│   └── render.yaml                  Render beta-backend blueprint
├── demo-app-react/                  Eleven-lab React beta frontend
```

Preserve the distinction between wheel contents and repository-only assets.
Correct the earlier “walks through the v0.3.x capabilities” statement to
describe Labs 1–7 as historical invocation labs and Labs 8–11 as the v0.9 beta
additions.

- [ ] **Step 3: Add the pre-v0.9 repository boundary**

Add a concise maintained statement to each history-bearing document:

```markdown
Source, tags, and release artifacts for versions before `0.9.0` remain in
[`nealsolves/aigc`](https://github.com/nealsolves/aigc). This repository is the
AEGIS `0.9.0`-and-later development home.
```

Adapt surrounding prose to avoid implying that old tags exist in
`nealsolves/aegis`.

- [ ] **Step 4: Correct current release and demo statements**

Update `docs/reference/RELEASE_MATRIX.md` so that:

- `8be5f54`/PR #17 remains the package-candidate build baseline;
- `fdf3649`/PR #18 is the current `develop` documentation/demo baseline;
- pre-v0.9 releases link to `nealsolves/aigc`; and
- deployment status distinguishes source-configured, backend-live,
  frontend-live, and verified.

Remove the README statement that Pages may show a prior `main` build after the
new beta deployment is observed.

- [ ] **Step 5: Verify examples and public imports**

Run:

```bash
.venv/bin/python scripts/check_public_docs_no_internal_imports.py
.venv/bin/python scripts/check_doc_parity.py
.venv/bin/python -m pytest -q tests/test_doc_parity_v090_truth.py
```

Expected: the red tests from Task 2 pass and no requested guide imports
`aegis._internal`.

- [ ] **Step 6: Review deletions explicitly**

Run:

```bash
git diff --name-status -- docs/reference docs/INTEGRATION_GUIDE.md docs/PUBLIC_INTEGRATION_CONTRACT.md docs/USAGE.md docs/AEGIS_FRAMEWORK.md
```

Expected: every deletion, if any, has a recorded obsolete/duplicate rationale
and all inbound links are repaired. If no file meets that standard, record
“no deletions; each requested document retains a distinct maintained purpose.”

- [ ] **Step 7: Commit the documentation slice**

Run:

```bash
git add README.md PROJECT.md docs/AEGIS_FRAMEWORK.md docs/INTEGRATION_GUIDE.md docs/PUBLIC_INTEGRATION_CONTRACT.md docs/USAGE.md docs/reference docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/documentation-audit.md tests/test_doc_parity_v090_truth.py
git commit -m "docs: reconcile release history and repository truth"
```

---

### Task 4: Add a Failing Diagram-Overflow Regression Test

**Files:**

- Modify: `tests/test_architecture_diagram_truth.py`

**Interfaces:**

- Consumes: generated SVG element order and declared CSS font sizes.
- Produces: conservative text-width validation for every generated layout box.

- [ ] **Step 1: Add the SVG layout estimator**

Add helpers using `xml.etree.ElementTree`:

```python
from html import unescape
from xml.etree import ElementTree


FONT_SIZES = {
    "box-title": 18,
    "box-title-compact": 15,
    "box-sub": 13,
    "box-sub-compact": 11,
    "body": 14,
    "body-plus": 15,
    "small": 12,
    "small-plus": 13,
    "panel-title": 12,
    "section-tag": 12,
}


def _estimated_text_width(text: str, font_size: int) -> float:
    units = 0.0
    for char in unescape(text):
        if char == " ":
            units += 0.32
        elif char in "il.,'|!":
            units += 0.28
        elif char in "MW@":
            units += 0.85
        else:
            units += 0.58
    return units * font_size
```

Parse each generated SVG in document order. For a `<rect>`, associate the
immediately following `<text>` elements until the next `<rect>` or `<path>`.
For box/panel classes, require every line to fit within `width - 24`.

- [ ] **Step 2: Add the failing light/dark test**

```python
def test_component_diagram_text_fits_its_layout_boxes():
    failures = []
    for name in (
        "aegis_architecture_component_light.svg",
        "aegis_architecture_component.svg",
    ):
        failures.extend(_layout_failures(DIAGRAMS / name))

    assert failures == []
```

- [ ] **Step 3: Run and confirm the overflow failures**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_architecture_diagram_truth.py::test_component_diagram_text_fits_its_layout_boxes
```

Expected: the current files fail for constrained labels such as
`FilePolicyLoader`, `AEGIS.open_session()`, `SessionPreCallResult`,
`enforce_invocation()`, and long evidence subtitles.

- [ ] **Step 4: Commit the red regression**

Run:

```bash
git add tests/test_architecture_diagram_truth.py
git commit -m "test: detect architecture diagram text overflow"
```

---

### Task 5: Repair and Regenerate the Component Diagrams

**Files:**

- Modify: `docs/architecture/diagrams/render_v090_component_diagrams.py`
- Modify: generated beta/canonical/React component SVGs listed under File
  Structure.

**Interfaces:**

- Consumes: the existing `node()`/`lines_text()` generator contract.
- Produces: deterministic light/dark SVGs with no conservative overflow
  violations and unchanged architecture semantics.

- [ ] **Step 1: Add compact text classes**

Add CSS and line-height entries:

```python
.box-title-compact {
  fill: THEME_TEXT;
  font-size: 15px;
  font-weight: 600;
}
.box-sub-compact {
  fill: THEME_SUBTEXT;
  font-size: 11px;
  font-weight: 500;
}
```

Extend `node()` with `title_cls="box-title"` and
`subtitle_cls="box-sub"` keyword arguments.

- [ ] **Step 2: Wrap constrained labels semantically**

Use compact classes and explicit lines, including:

```python
node(..., ["FilePolicy", "Loader"], ["or PolicyLoader", "Base"],
     title_cls="box-title-compact", subtitle_cls="box-sub-compact")
node(..., ["AEGIS.", "open_session()"], title_cls="box-title-compact")
node(..., ["Governance", "Session"], title_cls="box-title-compact")
node(..., ["SessionPreCall", "Result"], ["workflow-bound", "split token"],
     title_cls="box-title-compact", subtitle_cls="box-sub-compact")
node(..., ["enforce_", "invocation()"], title_cls="box-title-compact")
node(..., ["AEGIS.", "enforce()"], title_cls="box-title-compact")
node(..., ["ordered gates"], ["auth → output", "→ risk"],
     title_cls="box-title-compact", subtitle_cls="box-sub-compact")
```

Wrap invocation-artifact, sink/signing, lineage/export, and workflow-artifact
subtitles into two or three compact lines. Preserve the exact public API
spelling across adjacent lines.

- [ ] **Step 3: Regenerate all canonical and mirror outputs**

Run:

```bash
.venv/bin/python docs/architecture/diagrams/render_v090_component_diagrams.py
```

Expected: only generator-declared SVG outputs change.

- [ ] **Step 4: Run generator and layout verification**

Run:

```bash
.venv/bin/python docs/architecture/diagrams/render_v090_component_diagrams.py --check
.venv/bin/python -m pytest -q tests/test_architecture_diagram_truth.py
```

Expected: generator check and all architecture tests pass; documentation and
React mirrors are byte-identical.

- [ ] **Step 5: Render and inspect both themes**

Render the two canonical SVGs at 1600 pixels with macOS Quick Look, inspect
full-resolution PNGs, and record:

- no text crosses a rounded-box border;
- no connector obscures a label;
- footer text remains inside the frame;
- light and dark diagrams have identical geometry; and
- architecture content matches the code/public API boundary.

- [ ] **Step 6: Commit the diagram slice**

Run:

```bash
git add tests/test_architecture_diagram_truth.py docs/architecture/diagrams/render_v090_component_diagrams.py docs/architecture/diagrams/aegis_v090_beta_component_light.svg docs/architecture/diagrams/aegis_v090_beta_component_dark.svg docs/architecture/diagrams/aegis_architecture_component_light.svg docs/architecture/diagrams/aegis_architecture_component.svg demo-app-react/public/diagrams/aegis_architecture_component_light.svg demo-app-react/public/diagrams/aegis_architecture_component.svg
git commit -m "fix: prevent architecture diagram text overflow"
```

---

### Task 6: Add Failing Deployment Contract Tests

**Files:**

- Create: `tests/test_beta_demo_deployment.py`

**Interfaces:**

- Consumes: desired Pages and Render configuration.
- Produces: immutable-action, branch, permissions, build, health-check, and
  service-plan contracts.

- [ ] **Step 1: Write the Pages workflow tests**

Use `yaml.BaseLoader` and require:

```python
PINNED_ACTIONS = {
    "actions/checkout": "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
    "actions/setup-node": "49933ea5288caeca8642d1e84afbd3f7d6820020",
    "actions/configure-pages": "983d7736d9b0ae728b81ab479565c72886d7745b",
    "actions/upload-pages-artifact": "7b1f4a764d45c48632c6b24a0339c27f5614fb0b",
    "actions/deploy-pages": "d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e",
}
```

Assert the workflow:

- triggers on `develop` and manual dispatch;
- grants build only `contents: read`;
- grants deploy only `pages: write` and `id-token: write`;
- runs `npm ci`, `npm test`, `npm run lint`, and `npm run build`;
- sets the public Render URL as `VITE_API_URL`;
- uploads `demo-app-react/dist`;
- deploys through the `github-pages` environment; and
- contains no `secrets.` or write-capable contents token.

- [ ] **Step 2: Write the Render Blueprint tests**

Assert the single service equals:

```python
{
    "type": "web",
    "name": "aegis-demo-api",
    "runtime": "python",
    "rootDir": "demo-app-api",
    "branch": "develop",
    "plan": "free",
    "autoDeployTrigger": "commit",
    "healthCheckPath": "/health",
    "buildCommand": "pip install -e ../ && pip install -r requirements.txt",
    "startCommand": "uvicorn main:app --host 0.0.0.0 --port $PORT",
}
```

Also require `PYTHON_VERSION: "3.12"` and no secret environment variables.

- [ ] **Step 3: Run and confirm RED**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_beta_demo_deployment.py
```

Expected: failure because the Pages workflow is absent and Render lacks the
branch, plan, deploy trigger, and health check.

- [ ] **Step 4: Commit the red deployment tests**

Run:

```bash
git add tests/test_beta_demo_deployment.py
git commit -m "test: define beta demo deployment contract"
```

---

### Task 7: Implement the Render and GitHub Pages Configuration

**Files:**

- Create: `.github/workflows/deploy-demo-react.yml`
- Modify: `demo-app-api/render.yaml`
- Modify: `demo-app-react/README.md`
- Modify: `README.md`
- Modify: `PROJECT.md`

**Interfaces:**

- Consumes: Render service `aegis-demo-api` and Vite base `/aegis/`.
- Produces: a tested Pages artifact configured to call the real FastAPI beta
  backend.

- [ ] **Step 1: Update the Render Blueprint**

Implement the exact service mapping from Task 6. Keep CORS in
`demo-app-api/main.py` unchanged because it already allows only
`https://nealsolves.github.io` plus the two local origins.

- [ ] **Step 2: Create the pinned Pages workflow**

Use two jobs:

```yaml
name: Deploy React Beta Demo to GitHub Pages

on:
  workflow_dispatch:
  push:
    branches: [develop]
    paths:
      - "demo-app-react/**"
      - "docs/architecture/diagrams/**"
      - ".github/workflows/deploy-demo-react.yml"

concurrency:
  group: pages-beta
  cancel-in-progress: true
```

The build job checks out, installs Node, runs all React gates, configures
Pages, and uploads `demo-app-react/dist`. The deploy job depends on build,
uses the `github-pages` environment, and runs the pinned deploy action.

Set:

```yaml
env:
  VITE_API_URL: https://aegis-demo-api.onrender.com
```

- [ ] **Step 3: Make deployment documentation exact**

Document:

- backend: `https://aegis-demo-api.onrender.com`;
- frontend: `https://nealsolves.github.io/aegis/`;
- both beta deployments track `develop`;
- Render free instances may cold-start;
- no provider keys are used; and
- switching to `main` is deferred until explicit owner approval.

- [ ] **Step 4: Run GREEN**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_beta_demo_deployment.py
npm --prefix demo-app-react test
npm --prefix demo-app-react run lint
VITE_API_URL=https://aegis-demo-api.onrender.com npm --prefix demo-app-react run build
```

Expected: deployment contract, React tests, lint, and production build pass.

- [ ] **Step 5: Validate the local backend**

Run the FastAPI test suite:

```bash
.venv/bin/python -m pytest -q demo-app-api/tests
```

Then start Uvicorn locally and verify:

```text
GET /health -> 200 {"status":"ok"}
GET /api/scenarios -> 200 with scenario list
POST /api/enforce -> 200 with a real AEGIS artifact or governed error
```

- [ ] **Step 6: Commit the deployment configuration**

Run:

```bash
git add .github/workflows/deploy-demo-react.yml demo-app-api/render.yaml demo-app-react/README.md README.md PROJECT.md tests/test_beta_demo_deployment.py
git commit -m "feat: deploy beta demo from develop"
```

---

### Task 8: Run Complete Local Validation and Review

**Files:**

- Modify:
  `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/evidence.md`
- Create:
  `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/review.md`
- Modify: `implementation_status.md`
- Modify: `doc_parity_manifest.yaml` only if required by the inventory checker.

**Interfaces:**

- Consumes: complete local diff and exact HEAD.
- Produces: current test/review evidence and a clean candidate for remote
  delivery.

- [ ] **Step 1: Run the configured complete gates**

Run:

```bash
.venv/bin/python scripts/policy-engine.py validate --root . --context docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/context.json
.venv/bin/python scripts/check_doc_parity.py
.venv/bin/python scripts/check_brand_and_version_parity.py
.venv/bin/python scripts/check_public_docs_no_internal_imports.py
.venv/bin/python docs/architecture/diagrams/render_v090_component_diagrams.py --check
.venv/bin/python -m pytest
.venv/bin/flake8 aegis
npm --prefix demo-app-react test
npm --prefix demo-app-react run lint
VITE_API_URL=https://aegis-demo-api.onrender.com npm --prefix demo-app-react run build
```

Expected: every configured gate exits zero. Record exact counts rather than
copying an old baseline.

- [ ] **Step 2: Perform the distinct review pass**

Review every changed file for:

- stale async response or shared-write races;
- gate conditions and null safety;
- frontend/backend field alignment;
- GitHub token permissions and immutable actions;
- Render branch, plan, health, and secret boundaries;
- release/publication/deployment overclaims;
- links, paths, examples, and generated-file drift;
- diagram geometry and architecture truth; and
- reversal without `main`.

Record each finding, severity, repair, and verification in `review.md`.

- [ ] **Step 3: Repair findings test-first**

For each behavior/configuration defect, add or sharpen the failing test, observe
the failure, make the smallest repair, and rerun the affected plus complete
portfolio. Do not bundle unrelated cleanup.

- [ ] **Step 4: Refresh status and evidence**

`implementation_status.md` must distinguish:

- local implementation complete;
- feature branch not yet integrated;
- `develop` deployment configuration prepared;
- backend/frontend not live until externally observed; and
- no `main`, PyPI, or release change.

Update the context hashes and lifecycle evidence to the latest local candidate.

- [ ] **Step 5: Commit the reviewed local candidate**

Run:

```bash
git diff --check
git status --short
git add implementation_status.md doc_parity_manifest.yaml docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment
git commit -m "docs: record beta deployment validation evidence"
```

Do not add `doc_parity_manifest.yaml` if it is unchanged.

---

### Task 9: Evaluate and Execute Remote Delivery

**Files:**

- Modify:
  `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/context.json`
- Modify:
  `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/evaluation.json`
- Modify:
  `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/evidence.md`

**Interfaces:**

- Consumes: exact reviewed HEAD and user-approved target `develop`.
- Produces: feature branch, PR to `develop`, merged `develop`, Render service,
  Pages deployment, or an exact policy/authentication blocker.

- [ ] **Step 1: Evaluate `push_branch`**

Change the context action to `push_branch`, refresh the exact change hash, then
run validate/evaluate.

Expected under the current checked-in project configuration:
`remote_actions.enabled: false` may produce `prohibited`. If so, do not push or
work around the control plane; record the exact rule and stop remote execution.

- [ ] **Step 2: Push only when permitted**

When evaluation permits:

```bash
git push -u origin feat/v0.9-14-docs-pages-render
```

Verify the remote branch points to the exact reviewed HEAD.

- [ ] **Step 3: Evaluate and open a PR to `develop`**

Re-evaluate action `open_pull_request`. When permitted, open a PR from
`feat/v0.9-14-docs-pages-render` to `develop`. The title is:

```text
Restore AEGIS beta docs, diagrams, and demo deployment
```

The body lists the six requested workstreams, validation evidence, Render/Pages
topology, rollback, and the explicit `main` exclusion.

- [ ] **Step 4: Verify CI and evaluate merge**

Wait for exact-candidate checks. Re-evaluate `merge_pull_request`; merge only
when permitted and all required checks pass. Verify `origin/develop` contains
the exact PR merge and `origin/main` remains unchanged.

- [ ] **Step 5: Create/synchronize the Render Blueprint**

Use the Render Dashboard Blueprint flow for repository
`https://github.com/nealsolves/aegis` and Blueprint path
`demo-app-api/render.yaml`. Confirm:

- branch `develop`;
- service `aegis-demo-api`;
- free plan;
- auto-deploy on commits;
- health path `/health`;
- no secret prompts; and
- deployed URL `https://aegis-demo-api.onrender.com`.

Observe a live deploy and verify `/health` returns 200 before continuing.

- [ ] **Step 6: Enable GitHub Pages through Actions**

Configure `nealsolves/aegis` Pages source as GitHub Actions. Dispatch
`deploy-demo-react.yml` on `develop` if the merge did not trigger it. Wait for
the build and deployment jobs and record the deployment URL and exact commit.

- [ ] **Step 7: Commit final external-state evidence only through a new PR**

If live URLs or observed state require documentation/evidence changes, make a
new scoped commit on the feature branch (or a new follow-up branch after merge),
re-run affected checks, and use the same permitted PR-to-`develop` path. Never
direct-push `develop`.

---

### Task 10: Verify the Live Beta End to End

**Files:**

- Modify:
  `docs/spec-driven-dev/changes/v0.9.0-docs-diagrams-beta-deployment/evidence.md`
  only if a permitted follow-up PR is available.

**Interfaces:**

- Consumes: live Render and Pages deployments from the same `develop`
  candidate.
- Produces: observed demo readiness or an exact remaining blocker.

- [ ] **Step 1: Verify backend readiness**

Use bounded polling for:

```text
https://aegis-demo-api.onrender.com/health
```

Success is HTTP 200 with `{"status":"ok"}`. A persistent 4xx/5xx, Render
`no-server`, or timeout is failure.

- [ ] **Step 2: Verify the Pages application**

Open:

```text
https://nealsolves.github.io/aegis/
```

Verify the title and React application render instead of GitHub's 404 page.
Confirm all built assets load from `/aegis/`.

- [ ] **Step 3: Exercise representative flows**

In the live browser:

- run Lab 1 enforcement and observe an API-backed result;
- run Lab 11 Minimal and observe a completed workflow artifact;
- trigger and repair the Lab 11 provenance failure;
- build the evidence trace and observe zero unresolved links;
- inspect light and dark Architecture views at desktop and 390x844 mobile; and
- confirm no browser warnings, errors, failed API requests, or horizontal page
  overflow.

- [ ] **Step 4: Verify final Git boundaries**

Run:

```bash
git fetch origin
git rev-parse origin/main
git log -1 --oneline origin/develop
git status --short --branch
```

Expected:

- `origin/main` remains
  `0ddcee9bb08c850a340d6938124a415948906c57`;
- only `develop` received the approved beta change;
- local working state is clean; and
- deployed evidence names the exact `develop` commit.

- [ ] **Step 5: Produce the final handoff**

Report:

- every changed and deleted file;
- retain/delete decision for each requested Markdown document;
- diagram overflow repairs and architecture validation;
- exact local and remote verification results;
- live frontend/backend URLs;
- Render/GitHub configuration and any non-secret prerequisites;
- current branch/PR/deployment state;
- confirmation that `main` is unchanged; and
- any policy, authentication, provider, or platform blocker without
  overstating completion.
