# AEGIS v0.9.0 Distribution Tasks

Each implementation task maps to the numbered acceptance criteria in
`spec.md`.

- [ ] **T1 — Policy context and brownfield inventory**
  Record facts, evaluation, affected consumers, maintained documents, and
  current workflow proof.
  Acceptance: all.

- [ ] **T2 — Red metadata tests**
  Add failing tests for distribution name, version, import package, CLI, and
  runtime dependency stability.
  Acceptance: 1, 3.

- [ ] **T3 — Red artifact tests**
  Add failing wheel/sdist filename, metadata, content, and source-isolation
  checks.
  Acceptance: 2, 3.

- [ ] **T4 — Red workflow E2E test**
  Add the fresh-wheel minimal, standard, regulated failure/doctor/fix,
  trace/export journey and observe the expected pre-change failure.
  Acceptance: 3, 4, 5.

- [ ] **T5 — Metadata implementation**
  Change only the distribution name and candidate version; preserve runtime
  dependencies, package discovery, imports, and CLI.
  Acceptance: 1, 3.

- [ ] **T6 — Release-truth alignment**
  Update executable parity checks and maintained release documentation without
  rewriting archived evidence.
  Acceptance: 1, 2, 6.

- [ ] **T7 — Artifact proof implementation**
  Build, inspect, install, and exercise the wheel; emit exact results and
  digests.
  Acceptance: 2, 3, 4, 5, 8.

- [ ] **T8 — Trusted Publishing workflow**
  Add and statically validate the pinned, least-privileged
  `.github/workflows/publish.yml` matching environment `pypi`.
  Acceptance: 7, 8.

- [ ] **T9 — Full validation and review**
  Run all required local suites, review changed files, repair findings, and
  converge.
  Acceptance: all.

- [ ] **T10 — Release-ready packet**
  Record exact candidate artifacts, hashes, tests, known gaps, rollback, and
  prohibited publication action.
  Acceptance: 8, 9.
