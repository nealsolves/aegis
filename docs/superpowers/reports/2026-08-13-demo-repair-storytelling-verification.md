# Demo Repair and Storytelling Verification Report

**Date:** 2026-08-13
**Worktree:** `.worktrees/demo-repair-storytelling`
**Branch:** `codex/demo-repair-storytelling`

## Outcome

The repaired demo API, three scenarios, and twelve lab routes completed their
primary production-build flows. The adversarial pass found and repaired two
material classes of issue: unnamed lab controls and browser-hardcoded Meridian
comparison outcomes. Global SDK validation remains strict, and the Help button
and drawer source files have no diff.

## Automated verification

| Check | Command | Result |
| --- | --- | --- |
| Full Python suite | `demo-app-api/aegis-env/bin/python -m pytest -q` | 5,279 passed; 13 skipped; 67 existing warnings |
| Frontend lint | `npm run lint` | Passed |
| Demo copy policy | `npm run copycheck` | Passed |
| Frontend tests | `npm test -- --run` | 33 files; 320 tests passed |
| Production build | `npm run build` | Passed; 1,783 modules transformed |
| Security smoke | `demo-app-api/aegis-env/bin/python scripts/smoke_demo_security.py --api-url http://127.0.0.1:8000` | Passed |
| Diff whitespace | `git diff --check` | Passed |

The production-like services used for browser acceptance were:

```text
env PYTHONPATH=<worktree> demo-app-api/aegis-env/bin/python -m uvicorn main:app --app-dir demo-app-api --host 127.0.0.1 --port 8000 --no-proxy-headers
npm run preview -- --host 127.0.0.1 --port 5173
```

## Scenario acceptance

| Scenario | Exercised path | Observed result |
| --- | --- | --- |
| Atlas | Wrong covered answer | `FAIL`; `OUTPUT_SCHEMA_VALIDATION_ERROR`; delivery blocked |
| Atlas | Host-owned corrected answer | `PASS`; not covered; `BRV-04` cited |
| Northstar | Scheduling role requests clinical details | `FAIL`; `ROLE_NOT_ALLOWED` |
| Northstar | Authorized nurse retry | `PAUSED`; `PHYSICIAN_APPROVAL_REQUIRED` |
| Northstar | Approved scheduling-only result | `PASS` |
| Meridian | Autonomous payment authorization | Without AEGIS: payment authorized. With AEGIS: unauthorized payment blocked before execution; `FAIL`; `WORKFLOW_SEQUENCE_VIOLATION` |

Pause, resume, replay, concise live announcements, evidence disclosure, artifact
download, and Meridian invocation-to-workflow checksum relationships were also
exercised. Meridian exposes no visitor choice, reviewer, approval checkpoint,
or corrected human-review variant.

## Lab acceptance

| Lab | Primary observation |
| --- | --- |
| 1 Risk Scoring | Split enforcement completed with a returned risk score and semantic PASS |
| 2 Signing | Key generation and signed artifact completed |
| 3 Audit Chain | Server-owned three-entry chain built and verified as continuous |
| 4 Composition | Merge preview rendered; widening was truthfully reported as SDK admission `REJECTED` |
| 5 Loaders | File policy loaded; all policy, YAML, date, and test selectors have explicit names |
| 6 Custom Gates | Authorized session gate returned semantic PASS and gate evidence |
| 7 Compliance | Result and policy filters plus JSON/CSV export controls operated |
| 8 Knowledge Base | Sourced retrieval passed; unsourced retrieval was blocked with `PROVENANCE_MISSING` |
| 9 Governed vs. Ungoverned | High-risk governed path failed while the ungoverned path showed no checks |
| 10 Split Enforcement | Phase A block prevented Phase B and returned FAIL without false completion |
| 11 Workflow | Minimal and standard workflows completed with workflow evidence and checkpoints |
| 12 Adapters | Positive A2A fixture passed; typed-negative fixture failed with `WORKFLOW_PROTOCOL_GRPC_UNSUPPORTED` |

## Accessibility and visual checks

- Light and dark palettes were visually inspected on scenario and lab pages.
- Keyboard Tab focus, visible focus state, Help drawer Escape close, and focus
  restoration were exercised.
- The Help button and drawer remained unchanged.
- Labs 5, 7, 8, 9, and 10 received explicit labels discovered during the
  adversarial pass. Regression tests cover their accessible names.
- IBM Plex Sans remains the UI/explanation typography; monospace remains for
  technical metadata and code.
- CSS includes responsive stacking at 48rem/32rem, 44px experiment targets,
  contained overflow, global `:focus-visible` coverage, and complete
  `prefers-reduced-motion` removal for scenario animations.

## Failure-state checks

The API was intentionally stopped after the Meridian page reached ready state.
Running the comparison produced an explicit fetch alert and left the page at
“No scenario run has completed.” No decision, evidence, or success state was
fabricated.

Contract mismatch, unavailable polling bounds, and malformed response behavior
remain covered by `DemoServiceContext.test.tsx`, `serviceStates.test.tsx`, and
scenario/component parser tests.

## Adversarial review findings and repairs

1. **Unnamed controls:** selectors and fields in Labs 5, 7, 8, 9, and 10 lacked
   programmatic names. Added visible or explicit labels and regression tests.
2. **Browser-authored Meridian outcome:** the two comparison headings were
   hardcoded in React. They now render the `Without AEGIS` and `With AEGIS`
   entries returned by the scenario transcript; a mutation-style regression
   test proves changed server text is displayed and stale hardcoded text is not.
3. **Stale design:** the plan/spec still described a reviewer, approval pause,
   corrected Meridian variant, and no-op terminology. Both documents now match
   the approved autonomous payment story and implemented architecture.

## Residual manual limitations

The current in-app browser automation surface did not expose viewport resizing,
media emulation, or a browser-console stream. Attempts to create a 390px tab
were accepted but rendered at the fixed desktop browser size. Therefore:

- direct 390px visual inspection;
- direct `prefers-reduced-motion` emulation; and
- direct production contract-mismatch/console-stream inspection

remain explicit manual handoff checks. Responsive, reduced-motion, mismatch,
and error contracts have automated coverage and source-level verification, but
this report does not misrepresent them as manually exercised.
