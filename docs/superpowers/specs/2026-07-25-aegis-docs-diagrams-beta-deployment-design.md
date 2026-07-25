# AEGIS Documentation, Diagram, and Beta Deployment Design

**Change ID:** `v0.9.0-docs-diagrams-beta-deployment`

**Status:** Approved

**Approved by:** Neal Bhattacharya

**Target branch:** `develop`

**Working branch:** `feat/v0.9-14-docs-pages-render`

**Explicit exclusion:** Do not merge, push, deploy, or open a pull request
against `main`.

## Purpose

Finish the repository truth audit requested after PR #18, repair the current
component-diagram layout, and restore the public beta demo while `main` remains
frozen. The public demo will temporarily deploy from `develop`; switching both
deployments to `main` is a separate future change requiring explicit owner
approval.

This design extends the already approved
[`2026-07-25-v090-truth-audit-demo-design.md`](2026-07-25-v090-truth-audit-demo-design.md).
It does not reopen completed historical evidence or change the AEGIS runtime
contract.

## Observed State

- Local `develop` is clean and matches `origin/develop` at PR #18 merge commit
  `fdf3649`.
- `origin/main` contains only the repository's initial commit and is 111
  commits behind `develop`.
- `https://nealsolves.github.io/aegis/` returns GitHub Pages' site-not-found
  response.
- The repository has no `gh-pages` branch and no
  `.github/workflows/deploy-demo-react.yml`, although maintained demo
  documentation says that workflow exists.
- `demo-app-api/render.yaml` exists, but it does not select `develop`, declare a
  health check, or select the free instance type.
- `https://aegis-2oaf.onrender.com/health` returns Render's `no-server` 404;
  no backend is currently routed at that documented hostname.
- The light and dark component SVGs are generated deterministically, but visual
  rendering shows text overflow in multiple fixed-width nodes, including public
  API entrypoints, policy-loader nodes, workflow nodes, and evidence subtitles.
- Pre-`0.9.0` release history is described in this repository without clearly
  identifying `nealsolves/aigc` as the source repository for those releases.

## Approaches Considered

### Selected: deploy the beta from `develop`

Build the React app with a GitHub Pages workflow triggered by `develop`, deploy
the artifact through GitHub's supported Pages actions, and configure the Render
service to build the FastAPI backend from `develop`.

This is the only approach that restores the current beta without changing
`main`. It is reversible by changing two branch selectors after the owner
approves the `main` cutover.

### Rejected: wait for `main`

Keeping deployments tied to `main` would preserve a conventional release
topology, but `main` has no application code and is explicitly frozen. It
cannot satisfy the request to restore the demo now.

### Rejected: publish a static or simulated demo only

Publishing the React shell without the real FastAPI backend would violate the
existing v0.9 demo requirement that the UI demonstrate actual AEGIS behavior
and contain no fake backend behavior.

## Documentation Design

### Repository map and README

Rebuild the `PROJECT.md` repository map from tracked paths and current package
boundaries. Include deployment automation and the beta demo topology where it
helps a new contributor understand the repository. Correct statements that
still characterize the demo as only the seven `v0.3.x` labs.

Audit `README.md` against:

1. `pyproject.toml` and `aegis.__version__`;
2. top-level public exports and adapter submodule boundaries;
3. current CLI parser behavior;
4. the current `develop` deployment topology; and
5. the release matrix.

Do not claim that `0.9.0b1` is on PyPI, `main`, or released.

### Pre-0.9.0 release ownership

Current-state documents that narrate releases before `0.9.0` must state that
their source, tags, and release artifacts remain in
[`nealsolves/aigc`](https://github.com/nealsolves/aigc). This repository is the
AEGIS `0.9.0`-and-later development home.

Add the ownership statement where a reader would otherwise reasonably look for
old tags or source:

- `README.md`;
- `PROJECT.md`;
- `docs/AEGIS_FRAMEWORK.md`;
- `docs/INTEGRATION_GUIDE.md`;
- `docs/PUBLIC_INTEGRATION_CONTRACT.md`;
- `docs/USAGE.md`; and
- `docs/reference/RELEASE_MATRIX.md`.

Do not rewrite historical plans, audits, ADRs, or released documentation.

### Requested reference audit

Audit every Markdown file under `docs/reference/` plus:

- `docs/INTEGRATION_GUIDE.md`;
- `docs/PUBLIC_INTEGRATION_CONTRACT.md`;
- `docs/USAGE.md`; and
- `docs/AEGIS_FRAMEWORK.md`.

For each file, verify imports, signatures, CLI flags, schema values, reason
codes, status claims, links, and examples against release code and executable
tests. Retain a document only when it has a distinct durable reader or purpose:

- quickstart;
- task-oriented recipes;
- command reference;
- troubleshooting;
- operations;
- environment support;
- release-channel truth;
- adapter-specific integration; or
- conceptual framework/integration contract.

Delete a file only if its content is obsolete, duplicated without a distinct
reader, and no maintained inbound link requires it. Update all inbound links in
the same change. The current inbound-link inventory shows that every requested
file is referenced, so deletion requires substantive audit evidence rather
than a low reference count.

## Diagram Design

The generator at
`docs/architecture/diagrams/render_v090_component_diagrams.py` remains the only
source of truth. Generated SVGs are never hand-edited.

Repair overflow by:

- adding explicit compact title/subtitle text classes for constrained nodes;
- wrapping long labels into semantic line breaks;
- increasing node widths or redistributing gaps where the surrounding panel
  has room;
- keeping a minimum horizontal text inset in every node; and
- preserving the existing 1600-pixel view box, section order, colors,
  connectors, and light/dark parity.

Add a generator-level regression check that associates generated text with its
layout box and rejects lines whose conservative estimated width exceeds the
box's usable width. The check must cover both themes and must fail against the
current overflowing layout before the generator is changed.

Architecture truth remains:

- the host owns orchestration, model/tool execution, transport, credentials,
  retries, and business state;
- AEGIS owns policy loading, deterministic invocation/workflow governance, and
  evidence;
- invocation and workflow artifacts remain separate and correlated;
- adapters normalize host-supplied evidence and do not own provider SDKs or
  transport; and
- target-state identity/manifest types remain absent from the current beta
  component view.

Regenerate the documentation and React mirror assets, prove byte identity, and
visually inspect both themes at full resolution.

## Deployment Design

### Render backend

Update `demo-app-api/render.yaml` to declare:

- repository branch `develop`;
- `plan: free`;
- `autoDeployTrigger: commit`;
- `healthCheckPath: /health`;
- the existing Python 3.12 runtime;
- no service `rootDir`, because the API build requires the repository-root
  AEGIS package;
- `pip install -e . && pip install -r demo-app-api/requirements.txt`; and
- Uvicorn with `--app-dir demo-app-api`, bound to `$PORT`.

The backend remains stateless and uses only synthetic demo data. It requires no
provider credentials or external model calls. CORS remains restricted to the
public GitHub Pages origin and the existing local development origins.

Create or synchronize the Render Blueprint from
`nealsolves/aegis` using `demo-app-api/render.yaml`, then record the actual
service URL. Replace the non-existent `aegis-2oaf.onrender.com` documentation
claim with the observed deployed URL.

### GitHub Pages frontend

Create `.github/workflows/deploy-demo-react.yml` with:

- `push` on `develop` limited to the React demo, deployment workflow, and
  deployment-relevant diagram paths;
- `workflow_dispatch`;
- a build job using immutable action revisions, Node, `npm ci`, React tests,
  lint, and the production build;
- `contents: read` and `pages: read` only in the build job;
- `VITE_API_URL` set to the observed Render service URL through a repository
  variable or an explicit public build value;
- Pages artifact upload;
- a deployment job with `pages: write` and `id-token: write`;
- the `github-pages` environment; and
- concurrency that cancels superseded beta deployments without interrupting a
  completed deployment.

Enable the repository's Pages source for GitHub Actions. Validate the deployed
site at `https://nealsolves.github.io/aegis/`, not merely the workflow result.

### Future cutover

After the owner approves `main`, a separate change will:

1. switch Render's branch from `develop` to `main`;
2. switch the Pages workflow trigger from `develop` to `main`;
3. update beta deployment wording; and
4. verify both services against the exact `main` commit.

No part of this change performs that cutover.

## Failure Handling

- A failed Render health check prevents the frontend URL from being treated as
  ready.
- A missing or stale frontend API URL fails the Pages build or deployed smoke
  test rather than silently falling back to localhost.
- API, CORS, or frontend console errors are release blockers for the live demo.
- If free Render cold starts delay the first request, validation may use a
  bounded readiness wait; it must not mask a persistent failure.
- If GitHub or Render authentication is unavailable, finish and validate all
  local/remote-ready changes, report the exact external action still required,
  and do not claim deployment.

## Validation

### Documentation and generator

- policy-engine validation and evaluation for this change;
- documentation parity and brand/version checks;
- public-doc internal-import boundary check;
- Markdown link and path validation;
- diagram generator stale-output check;
- diagram layout regression test;
- byte equality between canonical and React diagram mirrors; and
- full-resolution light/dark visual inspection.

### Backend and frontend

- targeted FastAPI demo tests;
- full React unit tests and lint;
- React production build with the deployed API URL;
- backend `/health` and representative lab/workflow endpoints;
- deployed Pages load, navigation, light/dark architecture views, responsive
  layout, representative Lab 1 and Lab 11 flows, and clean browser logs.

### Repository

- configured Python test and lint commands;
- final changed/deleted-file inventory;
- final branch/status check proving no `main` mutation; and
- distinct final review for accuracy, deployment safety, API contracts,
  asynchronous frontend state, and rollback.

## Reversal

- Revert the feature branch commits.
- Disable the Pages workflow or point its trigger back to the approved release
  branch.
- Set Render auto-deploy to `off` or delete the beta service through the Render
  dashboard if the owner chooses to remove it.
- No database, customer data, provider credentials, or irreversible migration
  is involved.

## Acceptance Criteria

- [ ] `PROJECT.md` repository map matches tracked repository and package
      boundaries.
- [ ] `README.md` matches release code and live beta deployment truth.
- [ ] Requested maintained documentation is audited, corrected, or deleted with
      inbound links repaired.
- [ ] Current-state release narratives point pre-`0.9.0` source and releases to
      `nealsolves/aigc`.
- [ ] Component diagrams contain no visually overflowing text in light or dark
      themes and still match the implemented architecture.
- [ ] Generated documentation and React diagram copies are byte-identical.
- [ ] Render deploys the FastAPI backend from `develop` and `/health` passes.
- [ ] GitHub Pages deploys the React beta from `develop`.
- [ ] The live demo completes representative v0.3 and v0.9 workflows without
      console or API errors.
- [ ] Deployment documentation records actual URLs and the temporary
      `develop` topology.
- [ ] `main` is unchanged.
