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
5. The Pages job exposed `VITE_API_URL` to unit tests, invalidating the
   localhost-fallback test. The variable is now scoped to the guard and
   production build only.
6. GitHub created the `github-pages` environment with a `main`-only deployment
   policy. It now has one custom branch policy: `develop`.

## Bounded Remote Authority

Before owner approval, the repository policy correctly prohibited remote and
production actions. The owner then authorized one exact operating window:

- source branch: `feat/v0.9-14-docs-pages-render`
- pull request base: `develop`
- deployment targets: the AEGIS Render beta service and
  `nealsolves/aegis` GitHub Pages
- `main`: prohibited

The prior trusted policy evaluated the temporary control-plane proposal at
change hash
`d53275560025bc0f5cd9dbefe62b3e96ae8a882651a2af354daee6c5ce4cdf16`.
The one-time instruction-system and deployment decisions are recorded in the
`remote-authority-*` and `deploy-authority-*` artifacts. The enabled
`.claude/project.yaml` was never committed.

## Remote Delivery

| Action | Result |
| --- | --- | --- |
| Initial delivery | PR #19 merged to `develop` as `9345e1e0415d466b7365509228be073d1b370887` |
| Pages CI repair | PR #20 merged to `develop` as `49c0229f171837c941078ce476b0220286d14a30` |
| Live evidence | PR #21 merged to `develop` as `04f301a0ee46d39d67eeec62d08ea2ffca6371b6` |
| Render Blueprint | `aegis-beta`, ID `exs-d9ijhd4m0tmc73ctfu2g`, branch `develop` |
| Render service | `aegis-demo-api`, ID `srv-d9ijhhvavr4c73avb1ng`, free plan |
| Render deploy | `dep-d9ijhi7avr4c73avb1vg`, commit `9345e1e`, status `Live` |
| Verified Render baseline | `dep-d9ijmobeo5us73ctu700`, commit `04f301a`, status `Live` |
| Backend URL | `https://aegis-demo-api.onrender.com` |
| Pages URL | `https://nealsolves.github.io/aegis/` |
| Pages workflows | runs `30177779500` and `30178022023`, successful from `develop` |
| Pages environment | only custom deployment branch policy is `develop` |
| `main` | unchanged at `0ddcee9bb08c850a340d6938124a415948906c57` |

## Live Verification

- `GET https://aegis-demo-api.onrender.com/health` returned HTTP 200 with
  `{"status":"ok"}`.
- A request with origin `https://nealsolves.github.io` returned
  `access-control-allow-origin: https://nealsolves.github.io`.
- Pages CI passed React tests, lint, production build, artifact upload, and
  deployment.
- The public Architecture route loaded both maintained diagrams and all eleven
  lab links.
- Live Lab 1's missing-role split scenario produced
  `SPLIT_PRE_CALL_ONLY` and blocked in Phase A before model output was consumed.
- Live Lab 11's minimal workflow completed with two governed steps and a
  separate workflow artifact.
- The clean in-app-browser console contained no errors after both live flows.
- Chrome emitted only its extension's asynchronous message-channel noise; the
  same flows were clean in the extension-free browser.

## Rollback

- Pages: disable the Pages workflow or revert its merge commit on `develop`.
- Render: disable auto-deploy or roll back to the previous Render deploy.
- Branch selectors: remain `develop`; switching to `main` is a separate,
  explicitly approved change only after live beta verification.
