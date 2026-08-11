# Issue #59 Demo API Hardening Verification

**Date:** 2026-08-11
**Branch:** `codex/issue-59-demo-hardening`
**Implementation range:** `e1944bd..HEAD`

## Outcome

The issue #59 implementation and local acceptance matrix pass. The new security suite reports 86 passed, the preserved YAML/load subset reports 7 passed, the frontend reports 313 passed with a clean production build and ESLint run, and the local live adversarial smoke reports `security smoke passed`.

The full demo suite is not represented as green: it currently reports 163 passed and 12 failed. Every remaining failure belongs to a failure category present in the pre-change baseline. The pre-change full-demo baseline was 38 passed and 61 failed.

The Render forwarding-header probe remains a post-deployment release gate. Local smoke verified direct-peer behavior and all other smoke assertions; `--expect-forwarding-proxy` must be run against the deployed service behind its configured ingress before declaring the production deployment verified.

## Acceptance mapping

| Issue criterion | Implementation | Evidence | Observed result / assumption |
| --- | --- | --- | --- |
| Oversized fixed and streamed bodies receive `413` before parsing | `demo_edge.py`, `demo_limits.py` | `test_oversized_declared_body_returns_413_without_reading_or_calling_inner`, `test_streamed_body_limit_counts_across_chunks_even_with_lying_length`, live smoke | Passed. Declared and chunked 65,537-byte requests returned stable `413` envelopes. |
| YAML alias, anchor, depth, scalar, collection, and aggregate limits return stable `422` | `bounded_yaml.py`, `loaders.py`, YAML route migrations | `test_bounded_yaml.py`, route tests in `test_api_security.py` | Passed. Byte, event, expanded graph, cycle, ambiguous type, and response limits are covered. |
| The exact 211-byte amplification payload is rejected | `bounded_yaml.py` | `test_rejects_exact_issue_59_expansion_before_response_amplification`, `test_exact_issue_59_yaml_is_rejected_without_amplified_response`, live smoke | Passed at both in-memory and compose boundaries with bounded stable output. |
| Valid policies and compose/load examples continue to work | bounded loader integrations | seven-test preserved subset; `test_all_checked_in_demo_policies_fit_the_bounded_contract` | Passed: 7 passed in the preserved selector, and every checked-in demo policy fits. |
| Per-client/global `429` and trusted-proxy policy | `demo_edge.py`, single-worker `render.yaml` | limiter/proxy unit tests; local smoke rate probe | Unit and direct local smoke passed, including malformed-rightmost forwarding fallback and method-scoped health exemption. Production rightmost-hop behavior requires `--expect-forwarding-proxy` after deployment. |
| No raw client diagnostics or local policy paths | `demo_errors.py`, `demo_runtime.py`, route/service migrations, `workflow_routes.py`, `publicError.ts` | error, path, workflow, frontend parser/component tests; static searches | Passed. Public errors are fixed three-field objects; logical refs are finalized into evidence; malformed bodies, parser output, subprocess output, status text, and hostile extra fields are not rendered. |
| Correlated bounded server diagnostics | `demo_errors.py`, `demo_edge.py` | `test_unexpected_route_failure_is_normalized_and_correlated_in_logs`, timeout/log tests | Passed. Edge-owned 32-hex request IDs match response headers and bounded log records. |
| No retries of expensive parsing or subprocess work | `bounded_yaml.py`, `_run_demo_subprocess` | YAML unit matrix; `test_workflow_subprocess_timeout_is_bounded_and_safe` | Passed. One subprocess call, fixed 10-second timeout, no retry, stable timeout/failure response. |
| Required route/error/resource/frontend tests | backend and frontend test modules | commands below | Passed for the complete new issue suite and all frontend tests. |
| Deployment limits and monitoring documented | `demo-app-api/README.md`, `SECURITY.md`, `render.yaml`, `smoke_demo_security.py` | documentation review and local smoke | Implemented. One worker and `--no-proxy-headers` are pinned; shared-store scale-out and proxy requirements are explicit. |

## Commands and fresh results

### Static boundary audit

The following searches were run:

```bash
rg -n 'yaml\.(safe_load|full_load|load)\(' demo-app-api --glob '*.py' --glob '!bounded_yaml.py'
rg -n 'HTTPException\([^\n]*detail=(str\(|f")|"error": str\(|stderr|stdout' demo-app-api --glob '*.py'
rg -n 'AEGIS\(' demo-app-api --glob '*.py'
rg -n 'subprocess\.run\(' demo-app-api --glob '*.py'
rg -n 'response\.statusText|typeof detail === .string.|error: string \| null' demo-app-react/src --glob '!**/*.test.*'
```

Observed:

- no direct PyYAML load outside `bounded_yaml.py`;
- no public `str(exc)` or formatted exception detail;
- subprocess stdout/stderr appears only in the bounded internal logging boundary and safe JSON projection;
- demo-owned AEGIS construction is limited to `demo_runtime.py` factories/proxy (plus a loader documentation example);
- the only `subprocess.run` is inside `_run_demo_subprocess`;
- no production frontend status-text/raw-detail/string-outcome pattern remains.

### New backend security suite

```bash
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q \
  demo-app-api/tests/test_demo_errors.py \
  demo-app-api/tests/test_bounded_yaml.py \
  demo-app-api/tests/test_demo_edge.py \
  demo-app-api/tests/test_api_security.py \
  demo-app-api/tests/test_workflow_routes.py
```

Result: **86 passed**.

### Preserved security-adjacent YAML/load selector

```bash
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q \
  demo-app-api/tests/test_api.py -k 'compose or policy_load or load_inmemory'
```

Result: **7 passed, 30 deselected**.

### Frontend

```bash
cd demo-app-react
npm run lint
npm run build
npm test -- --run
```

Results: ESLint passed; TypeScript/Vite production build passed; **31 test files and 313 tests passed**.

### Live local adversarial smoke

Server command:

```bash
PYTHONPATH="$PWD" /Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m uvicorn \
  main:app --app-dir demo-app-api --host 127.0.0.1 --port 8765 --no-proxy-headers
```

Probe command:

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python \
  scripts/smoke_demo_security.py --api-url http://127.0.0.1:8765
```

Result: **security smoke passed**. The probe observed stable 413, 422, and 429 responses, matching request IDs, allowed/denied CORS behavior, a valid YAML flow, no hostile marker reflection, and rate exhaustion last.

## Baseline comparison

| Matrix | Pre-change | Current | Classification |
| --- | ---: | ---: | --- |
| Full `demo-app-api/tests` | 38 passed, 61 failed | 163 passed, 12 failed | No new failure category; new issue tests substantially increase total collection. |
| Touched API/adapter/scenario/workflow files | 28 passed, 50 failed | 70 passed, 11 failed | All 11 current failures appear in the baseline failure list. |
| Preserved YAML/load selector | 7 passed | 7 passed | Unchanged green behavior. |

Remaining full-demo failures by pre-existing root cause:

| Root cause | Current failures | Notes |
| --- | ---: | --- |
| Evidence chain finalization API drift | 4 | `build_content_checksum_v2` rejects finalization fields already present in the demo artifact. |
| A2A constraint mapping drift | 2 | Current SDK returns/accepts an immutable mapping form that the adapter path rejects as not a mapping. |
| Meridian fixture/precondition regex drift | 5 | `NO-OP-PAYMENT-MV-248` does not match the current policy regex; includes the aggregate manifest E2E case. |
| Legacy test constructs AEGIS without required sink | 1 | Direct test construction, outside the demo-owned root-bound factory. |

These failures are not waived as green and are not repaired by issue #59 because they concern enforcement-core/demo compatibility outside the approved hardening scope.

## Final adversarial review closure

The final independent and self-review findings were converted into regression tests before fixes:

- only `GET /health`, not arbitrary methods on the health path, bypasses rate admission;
- an invalid rightmost forwarded token falls back to the immediate peer instead of scanning attacker-controlled values to its left;
- trailing-slash requests no longer escape the public error contract through bare framework redirects;
- unexpected workflow-module exceptions return a stable operation failure and never expose a stale artifact;
- projected doctor findings reject Unix, Windows-drive, and UNC-style absolute paths;
- legacy unknown-scenario validation and frontend error parsing use the same bounded public envelope.

All resulting regressions are included in the 86-test security suite above.

## Security boundaries and deployment assumptions

- Evidence artifacts are never post-redacted. Confidentiality comes from root-bound loaders and logical policy references before checksum/signature finalization.
- The demo limiter is process-local. The production command therefore pins exactly one worker. Multi-worker or multi-instance deployment requires a shared atomic limiter and a new trust review.
- Uvicorn proxy rewriting is disabled. The immediate ingress must strip client-controlled forwarding headers and append the authenticated client hop; the application uses only the rightmost value from a private/loopback immediate peer.
- The live local probe cannot validate managed-ingress header mutation. Run:

  ```bash
  python scripts/smoke_demo_security.py --api-url <deployed-url> --expect-forwarding-proxy
  ```

  as a production release gate.
- These controls apply to the public demo edge only. They do not claim hostile-input resource limits for the enforcement core and do not alter SDK policy semantics.
