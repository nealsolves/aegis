# AEGIS Interactive Demo

Interactive companion to the [AEGIS SDK](https://github.com/nealsolves/aegis) — eleven
hands-on labs for the governance capabilities plus an architecture guide covering
the enforcement pipeline, decorator defaults, and workflow governance surfaces.

**Live demo:** [https://nealsolves.github.io/aegis/](https://nealsolves.github.io/aegis/)

The local app in this branch accompanies the unpublished
`aegis-ai-governance==0.9.0b1` candidate. It uses `import aegis` and the
`aegis` CLI. The candidate is merged on `develop`, not on `main`, so the live
GitHub Pages deployment may still show the last `main` build; PyPI publication
is pending.

## Labs

| Lab | Topic |
| --- | ----- |
| 1 | Risk Scoring — `strict`, `risk_scored`, and `warn_only` modes |
| 2 | Signing & Verification — HMAC-SHA256 artifact signing; tamper detection |
| 3 | Audit Chain — hash-chained artifacts; chain continuity verification |
| 4 | Policy Composition — `intersect`, `union`, and `replace` strategies |
| 5 | Loaders & Versioning — pluggable `PolicyLoader`; policy date enforcement |
| 6 | Custom Gates — `EnforcementGate` plugins at all four pipeline insertion points |
| 7 | Compliance Dashboard — compliance export from a JSONL audit trail |
| 8 | Governed Knowledge Base — provenance enforcement for sourced answers |
| 9 | Governed vs Ungoverned — side-by-side evidence comparison |
| 10 | Split Enforcement — Phase A/Phase B trace explorer |
| 11 | Workflow Lab — v0.9.0 workflow governance, diagnosis, and trace evidence |

## Architecture

The demo has two components in source. Their public deployments follow `main`
and may lag the local `develop` candidate:

- **React frontend** — built with Vite, deployed to GitHub Pages via `.github/workflows/deploy-demo-react.yml` on every push to `main` that touches `demo-app-react/`. The API URL is baked in at build time via the `VITE_API_URL` GitHub secret.
- **FastAPI backend** (`demo-app-api/`) — deployed on Render at `https://aegis-2oaf.onrender.com`. The React app calls this backend for all lab enforcement, signing, chaining, composition, and loader operations. No user API keys are required.

## Development

Start the API:

```bash
cd demo-app-api
python -m uvicorn main:app --reload --port 8000
```

Start the React app:

```bash
cd demo-app-react
npm install
npm run dev
```

## Build

```bash
npm run build
```

Output is in `dist/`. The app is configured with `base: '/aegis/'` for deployment
under `https://nealsolves.github.io/aegis/`.

## Deployment

Pushes to `main` that touch `demo-app-react/` trigger automatic deployment to
GitHub Pages via `.github/workflows/deploy-demo-react.yml`.
