# AEGIS Documentation, Diagram, and Beta Deployment Tasks

Each task maps to the numbered acceptance contract in `spec.md`.

- [ ] **T1 — Policy context and baseline validation**
  Validate the approved scope, install declared development dependencies, and
  obtain local-implementation authority.
  Acceptance: all.
- [ ] **T2 — Documentation truth audit**
  Audit every requested document against public code, schemas, CLI behavior,
  executable examples, release history, and maintained inbound links.
  Acceptance: 1, 2.
- [ ] **T3 — Documentation reconciliation**
  Update only demonstrated inaccuracies, add the pre-v0.9 repository boundary,
  and record the explicit retain/delete decision for every requested file.
  Acceptance: 1, 2.
- [ ] **T4 — Diagram regression and repair**
  Add a rendered-layout regression, repair the generator, regenerate every
  mirror, and visually inspect both themes.
  Acceptance: 3.
- [ ] **T5 — Beta deployment contract**
  Add develop-based, least-privilege GitHub Pages automation and complete the
  Render Blueprint branch, plan, health, and auto-deploy settings.
  Acceptance: 4, 5.
- [ ] **T6 — Local verification and independent review**
  Run documentation, Python, frontend, backend, build, lint, diagram, and
  deployment-contract validation; repair findings and record evidence.
  Acceptance: all.
- [ ] **T7 — Remote delivery decisions**
  Re-evaluate branch push, pull request, Render deployment, and Pages
  deployment separately; stop any prohibited action.
  Acceptance: 4, 5, 6.
- [ ] **T8 — Live beta verification**
  Verify backend health, API behavior, frontend rendering, browser console,
  CORS, and frontend-to-backend requests at their public URLs.
  Acceptance: 4, 6.
- [ ] **T9 — Future-main handoff**
  Record the separate branch-selector cutover required after explicit owner
  approval; do not perform it here.
  Acceptance: 5.
