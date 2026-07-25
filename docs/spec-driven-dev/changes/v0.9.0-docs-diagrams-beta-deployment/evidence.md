# Documentation, Diagram, and Beta Deployment Evidence

**Recorded:** 2026-07-25

**Base:** `origin/develop` at `fdf3649` (PR #18)

**Working branch:** `feat/v0.9-14-docs-pages-render`

## Local Implementation

- Requested documentation audit: 16 files reviewed, 16 retained, 0 deleted.
- Pre-v0.9 source boundary: current history-bearing docs point to
  `https://github.com/nealsolves/aigc`.
- Repository map: release automation, Render Blueprint, and eleven-lab beta
  topology added.
- Component diagrams: generator-only repair, compact type classes, semantic
  wrapping, adjusted widths, and connector rerouting.
- Deployment contract: GitHub Pages builds from `develop`; Render deploys the
  stateless FastAPI service from `develop`.
- `main`: unchanged at `0ddcee9bb08c850a340d6938124a415948906c57`.

## Executable Validation

| Validation | Result |
| --- | --- |
| Full Python suite | `1923 passed, 2 skipped` |
| Demo API suite | `67 passed` |
| React suite | `17 files / 105 tests passed` |
| React lint | passed |
| React production build | passed; public Render URL embedded and no localhost API fallback present |
| Python lint | `flake8 aegis` passed |
| Python build | wheel and sdist built successfully with `--no-isolation` |
| Documentation parity | passed |
| Public-doc import boundary | passed |
| Release freeze checks | passed |
| Diagram generator stale check | passed |
| Diagram overflow regression | both themes passed |
| Canonical/React diagram mirrors | byte-identical |
| Deployment contract | 3 tests passed |
| Policy context validation | valid |
| Local implementation authority | `autonomous_with_enhanced_gates` |

The Python and API suites emitted only pre-existing deprecation/user warnings;
no test failed.

## Visual and Browser Validation

- Light and dark component SVGs were rendered at 1600 pixels and visually
  inspected. No text leaves its box, the workflow token connector no longer
  crosses the workflow-artifact text, and both themes preserve legibility.
- The local production React build loaded at `/aegis/`.
- Lab 1 completed split enforcement with a PASS artifact and risk score.
- Lab 11 minimal workflow completed with two governed steps and a separate
  workflow artifact.
- The supported local origin produced successful CORS preflight and API
  responses. Browser console review showed no errors or warnings.

## Review Repairs

The post-implementation review found and repaired:

1. `rootDir: demo-app-api` made the repository-root AEGIS package unavailable
   to Render. The Blueprint now builds from the repository root and starts
   Uvicorn with `--app-dir demo-app-api`.
2. The Pages build job needed `pages: read` for Pages metadata while preserving
   write privileges exclusively in the deploy job.
3. The Pages workflow omitted the already-required React lint step.
4. A release-truth test still required the retired “last main build” wording.

## Remote Decisions and Current Blocker

The repository policy engine returned:

| Action | Outcome | Rule |
| --- | --- | --- |
| Push feature branch | `prohibited` | `remote_actions_disabled` |
| Open pull request to `develop` | `prohibited` | `remote_actions_disabled` |
| Deploy Render and GitHub Pages | `prohibited` | `production_actions_disabled` |

The exact decisions are stored in `push-evaluation.json`,
`pull-request-evaluation.json`, and `deploy-evaluation.json`. No prohibited
external action was attempted.

Because the feature branch cannot be delivered to `develop`, neither Render
nor GitHub Pages can deploy this source. The public Pages target and backend
therefore remain unverified.

## Deployment Prerequisites After Policy Enablement

1. Push `feat/v0.9-14-docs-pages-render`.
2. Open and merge a pull request into `develop` only.
3. Create or synchronize the Render Blueprint from
   `demo-app-api/render.yaml`; record the assigned `onrender.com` URL.
4. Set the GitHub repository variable `VITE_API_URL` to that public HTTPS URL.
5. Enable GitHub Pages with GitHub Actions as its publishing source.
6. Dispatch or allow the `develop` push to run
   `.github/workflows/deploy-demo-react.yml`.
7. Verify `/health`, API/CORS behavior, all eleven lab routes, console/network
   cleanliness, and `https://nealsolves.github.io/aegis/`.

## Rollback

- Pages: disable the Pages workflow or revert its merge commit on `develop`.
- Render: disable auto-deploy or roll back to the previous Render deploy.
- Branch selectors: remain `develop`; switching to `main` is a separate,
  explicitly approved change only after live beta verification.
