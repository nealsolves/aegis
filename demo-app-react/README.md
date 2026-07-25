# AEGIS Interactive Demo

Interactive companion to the [AEGIS SDK](https://github.com/nealsolves/aegis) — eleven
hands-on labs for the governance capabilities plus an architecture guide covering
the enforcement pipeline, decorator defaults, and workflow governance surfaces.

**Live demo:** [https://nealsolves.github.io/aegis/](https://nealsolves.github.io/aegis/)

The local app accompanies the `aegis-ai-governance==0.9.0b1` public beta. It
uses `import aegis` and the `aegis` CLI. Both public components deploy from
`main`.

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

The demo has two public components:

- **React frontend** — built and tested with Vite, then deployed to GitHub
  Pages by `.github/workflows/deploy-demo-react.yml` after relevant pushes to
  `main`. The public backend URL is baked in from the `VITE_API_URL`
  repository variable.
- **FastAPI backend** (`demo-app-api/`) — defined by
  `demo-app-api/render.yaml` and auto-deployed by Render from `main`. The live
  beta API is
  [https://aegis-demo-api.onrender.com](https://aegis-demo-api.onrender.com).
  The React app calls it for all lab enforcement, signing, chaining,
  composition, loader, and workflow operations. No user API keys are required.

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

Relevant pushes to `main` trigger the beta Pages workflow. Render also tracks
`main`; every release cutover must re-verify the public site and API.
