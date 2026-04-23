# PR-09 Implementation Code Review

- **Audit date:** 2026-04-19
- **Repository root:** /Users/neal/Documents/_Shenanigans/_myProjects/aigc
- **Base branch:** develop (`7578cab959f9e4dd67e3e163a92e3482067d8c89`)
- **Review branch:** feat/v0.9-09-exports-and-ops (`5764284ae32eec8fd0f23587369a69a774a5d0fc`)
- **Scope reviewed:** aigc/_internal/workflow_trace.py, aigc/_internal/workflow_export.py,
  aigc/_internal/cli.py, aigc/_internal/workflow_lint.py, aigc/_internal/session.py,
  aigc/schemas/workflow_artifact.schema.json, demo-app-api/workflow_routes.py,
  scripts/check_doc_parity.py, docs/reference/WORKFLOW_CLI.md,
  docs/reference/OPERATIONS_RUNBOOK.md, tests/test_workflow_trace.py,
  tests/test_workflow_export.py, tests/test_doc_parity_v090_truth.py, tests/test_cli.py,
  demo-app-api/tests/test_workflow_routes.py, RELEASE_GATES.md, CLAUDE.md,
  docs/dev/pr_context.md, implementation_status.md, docs/PUBLIC_INTEGRATION_CONTRACT.md,
  docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md, README.md, doc_parity_manifest.yaml
- **Commands run:**
  - `git status -sb`
  - `git rev-parse develop && git rev-parse feat/v0.9-09-exports-and-ops`
  - `git log --oneline develop..feat/v0.9-09-exports-and-ops`
  - `git diff --stat develop...feat/v0.9-09-exports-and-ops`
  - `git diff --name-only develop...feat/v0.9-09-exports-and-ops`
  - `git show feat/v0.9-09-exports-and-ops:<file>` (all 7 priority implementation files + selected docs)
  - `git diff develop...feat/v0.9-09-exports-and-ops -- <file>` (lint, schema, session, specific docs)
  - Verified existing worktree at `/Users/neal/Documents/_Shenanigans/_myProjects/aigc/.worktrees/feat-v0.9-09-exports-and-ops` at branch tip (`5764284`)
  - `pip install -e . -q` (in correct worktree)
  - `python -m pytest -q tests/test_workflow_trace.py tests/test_workflow_export.py tests/test_v090_contract_freeze.py tests/test_doc_parity_v090_truth.py tests/test_workflow_doctor.py tests/test_cli.py` (179 tests)
  - `python -m pytest -q` (full suite — 1436 tests)
  - `python -m pytest -q demo-app-api/tests/test_workflow_routes.py` (10 tests)
  - `python scripts/check_doc_parity.py` (exits 1 — 2 parity errors)
  - `flake8 aigc/_internal/` (from worktree — 4 E501 violations)
  - `python3 -c "..."` (inline reproduction of trace/export unresolved divergence)
  - Stale worktree at `/tmp/aigc-pr09-review` removed after discovering it was 2 commits behind

---

## Findings

### F-01 — HIGH — Four flake8 E501 violations in cli.py will fail the CI lint gate

- **Location:** `aigc/_internal/cli.py:378`, `aigc/_internal/cli.py:382`,
  `aigc/_internal/cli.py:439`, `aigc/_internal/cli.py:443`
- **Issue:** Four lines in `_cmd_workflow_trace` and `_cmd_workflow_export` exceed the 100-character
  limit enforced by `.flake8`. Two are the `print(f"ERROR: malformed JSONL line (not valid JSON):
  {line!r}", file=sys.stderr)` statements (101 chars each) and two are the f-string for the
  non-dict case (116 chars each). The CI workflows at `.github/workflows/sdk_ci.yml:68` and
  `.github/workflows/release.yml:38` both run `flake8 aigc` against the whole package. The develop
  branch has zero flake8 violations; these four were introduced by the crash-fix commit
  `fix(pr09): address code-review findings — step-type crash, doc-parity gate, hidden trace failures`.
- **Why it matters:** These violations will fail the CI lint gate on the remote PR. The branch
  cannot merge until they are resolved. This is a blocking issue for the remote push.
- **Evidence:**
  ```
  aigc/_internal/cli.py:378:101: E501 line too long (101 > 100 characters)
  aigc/_internal/cli.py:382:101: E501 line too long (116 > 100 characters)
  aigc/_internal/cli.py:439:101: E501 line too long (101 > 100 characters)
  aigc/_internal/cli.py:443:101: E501 line too long (116 > 100 characters)
  ```
  Running `flake8 aigc/_internal/cli.py` from the develop checkout returns empty (zero violations).
- **Recommended fix:** Split the single-line print calls into multi-line form:
  ```python
  print(
      f"ERROR: malformed JSONL line (not valid JSON): {line!r}",
      file=sys.stderr,
  )
  ```
  The non-dict message at lines 382/443 can similarly be folded into the already-present multi-line
  `print(...)` block that follows.
- **Verification gap or confirming test:** `flake8 aigc` in the worktree reproduces all four
  violations directly. No test enforces flake8 compliance; the CI gate is the only enforcement.

---

### F-02 — HIGH — doc_parity_manifest.yaml test count is stale; README and CHANGELOG use a third stale value; parity check A fails

- **Location:** `doc_parity_manifest.yaml:15`, `README.md:20`, `CHANGELOG.md:86`
- **Issue:** The parity checker produces two confirmed failures:
  ```
  FAIL: [current-state] README.md: expected test count '1369' (from manifest) not found — but doc mentions test counts
  FAIL: [current-state] CHANGELOG.md: expected test count '1369' (from manifest) not found — but doc mentions test counts
  ```
  Three separate values exist for the same quantity: the manifest declares `test_count: 1369`,
  the README at line 20 says `1233 tests`, the CHANGELOG at line 86 also says `1233 tests`, and
  the actual test count collected by pytest on the branch is 1436. PR-09 added 67 tests (1369 to
  1436) without updating the manifest, and neither the manifest nor the docs reflect the
  post-PR-08 baseline of 1369 that was apparently set there.
- **Why it matters:** Check A is part of the mandatory parity gate. The script exits non-zero with
  these two failures. The `.github/workflows/doc_parity.yml` CI job will fail on this branch.
- **Evidence:** `python scripts/check_doc_parity.py` exits 1 with the two errors above.
  `python -m pytest --collect-only -q` shows `1436 tests collected`. Manifest: `test_count: 1369`.
  README line 20: `` `1233 tests` ``. CHANGELOG line 86: `` `1233 tests` ``.
- **Recommended fix:** Update all three sources to agree on 1436:
  - `doc_parity_manifest.yaml:15` — change `1369` to `1436`
  - `README.md:20` — change `1233 tests` to `1436 tests`
  - `CHANGELOG.md:86` — change `1233 tests` to `1436 tests`
- **Verification gap or confirming test:** `python scripts/check_doc_parity.py` confirms the
  failures directly. There is no automated check that the manifest value equals the actual pytest
  count.

---

### F-03 — MEDIUM — `aigc workflow trace` and `aigc workflow export` report different unresolved-checksum sets for the same input when `invocation_audit_checksums` has entries absent from `steps[]`

- **Location:** `aigc/_internal/workflow_trace.py` (full `unresolved` derivation block),
  `aigc/_internal/workflow_export.py:57–68` (`expected` set construction)
- **Issue:** `reconstruct_trace` derives `unresolved_checksums` exclusively from checksums
  referenced in `steps[].invocation_artifact_checksum` that have no matching invocation artifact.
  It does not consult the top-level `invocation_audit_checksums` list. `export_workflow` constructs
  the `expected` set as the union of `invocation_audit_checksums` and all step-level
  `invocation_artifact_checksum` values, then subtracts found artifacts. Consequence: when a
  workflow artifact has a checksum in `invocation_audit_checksums` that corresponds to no `steps[]`
  entry, trace reports zero unresolved checksums while export reports that checksum as unresolved.
  This was confirmed by direct execution:
  ```python
  wa = {..., "steps": [], "invocation_audit_checksums": ["e" * 64]}
  reconstruct_trace(wa, []) -> unresolved_checksums: []
  export_workflow([wa], [], "operator") -> unresolved_invocation_checksums: ["eeee..."]
  ```
  The comment in `workflow_export.py:57-60` states the goal is for "trace and export to report
  the same unresolved set even when the two sources diverge," which indicates the divergence is
  unintentional.
- **Why it matters:** An operator using only `aigc workflow trace` to verify evidence completeness
  could see a clean trace while `aigc workflow export` would surface gaps. This is misleading about
  the completeness of governed evidence. The scenario arises whenever a workflow artifact's summary
  list disagrees with its step list, which can happen with a corrupt or partially-written artifact.
- **Evidence:** Direct Python execution in the worktree confirms the asymmetry. No test in
  `test_workflow_trace.py` covers the case where `invocation_audit_checksums` has a checksum
  not referenced by any `steps[]` entry.
- **Recommended fix:** Either (a) update `reconstruct_trace` to also consult
  `invocation_audit_checksums` and include any unmatched checksums in `unresolved_checksums`, or
  (b) explicitly document the divergence in `WORKFLOW_CLI.md` with a warning that trace only
  surfaces step-level gaps while export checks both step references and the summary list. Option (a)
  preserves the stronger invariant. Option (b) is a documentation-only fix but must include the
  warning to avoid misleading operators.
- **Verification gap or confirming test:** A test case for `reconstruct_trace` with
  `steps=[]` and `invocation_audit_checksums=["e" * 64]` and no matching artifact would pin the
  behavior and document the chosen design.

---

### F-04 — MEDIUM — `GET /trace` demo route has no test coverage

- **Location:** `demo-app-api/workflow_routes.py:292–328` (the `trace_evidence` route handler),
  `demo-app-api/tests/test_workflow_routes.py` (no reference to `/trace`)
- **Issue:** PR-09 adds a `GET /api/workflow/v090/trace` endpoint that runs a real governed session
  with a `JsonFileAuditSink`, then invokes `aigc workflow trace` via subprocess and returns the
  parsed trace. The route raises HTTP 500 if the subprocess fails or returns non-JSON. This is
  the primary demo operator-evidence path required by the plan. None of this behavior is covered
  by any test. The existing test file covers the four other routes (`/run`, `/compare`, `/diagnose`,
  and helper state functions) with 10 tests, but has zero entries for `/trace`.
- **Why it matters:** The `/trace` route exercises the subprocess invocation of `aigc workflow
  trace`, the `JsonFileAuditSink`, JSONL sink writing and reading, and the HTTP 500 error paths.
  A regression in any of these could be introduced without any test catching it. This is the
  route that implements the "operator-facing evidence path using real artifacts" requirement.
- **Evidence:** `grep -n "trace" demo-app-api/tests/test_workflow_routes.py` returns empty.
  `@router.get("/trace")` at `demo-app-api/workflow_routes.py:292` is confirmed present.
  `python -m pytest -q demo-app-api/tests/test_workflow_routes.py` passes 10 tests, none covering
  this route.
- **Recommended fix:** Add at minimum one smoke test:
  - `GET /api/workflow/v090/trace` returns HTTP 200
  - Response contains `"traces"` array with at least one element
  - `traces[0]["trace_schema_version"] == "0.9.0"`
  - At least one step is present in `traces[0]["steps"]`
  A second test that forces the subprocess to fail (e.g., by making the JSONL path unreadable after
  session completion) would cover the HTTP 500 path.
- **Verification gap or confirming test:** The demo test suite at `demo-app-api/tests/` has no
  existing test that exercises this route.

---

### F-05 — LOW — `docs/dev/pr_context.md` "Current State" body is inconsistent with the document's own header and PR-09 Outcomes section

- **Location:** `docs/dev/pr_context.md:4` (header), `docs/dev/pr_context.md:36–47` (Current State)
- **Issue:** The document header says `Status: feat/v0.9-09-exports-and-ops contains PR-01 through
  PR-09`. The `## Current State` section body at line 36 says `PR-01 through PR-08 are complete on
  local develop`. The shipped CLI surface list in that section (lines 40-47) ends at `aigc workflow
  doctor` and does not include `aigc workflow trace` or `aigc workflow export`. A PR-09 Outcomes
  section at the bottom correctly documents what shipped. The inconsistency creates a misleading
  reference for the exact document intended to describe the current beta surface.
- **Why it matters:** This is a documentation tracking artifact, not a functional defect. However,
  `docs/dev/pr_context.md` is one of the canonical source-of-truth documents cited throughout the
  review framework, and internal inconsistency reduces its reliability.
- **Evidence:** `git show feat/v0.9-09-exports-and-ops:docs/dev/pr_context.md | sed -n '1,50p'`
  confirms the header/body mismatch.
- **Recommended fix:** Update the `## Current State` section: change "PR-01 through PR-08 are
  complete on local `develop`" to "PR-01 through PR-09 are complete on
  `feat/v0.9-09-exports-and-ops`" and add `aigc workflow trace` and `aigc workflow export` to the
  shipped CLI surface list.
- **Verification gap or confirming test:** The `check_v090_pr09_contract` parity check correctly
  rejects the stale "Between PR-08 And PR-09" and "PR-09 has not started" patterns if they were
  present, but does not assert that the Current State body CLI list includes the new commands.

---

### F-06 — LOW — `RELEASE_GATES.md` Beta Release Gate has unchecked `PR-09 operator polish lands` item

- **Location:** `RELEASE_GATES.md` (`v0.9.0 Beta Release Gate` section, line ~105)
- **Issue:** The `## v0.9.0 Beta Release Gate` section retains `- [ ] PR-09 operator polish lands`
  (unchecked). The `## PR-09 — Exports and Ops Gate` section above it correctly marks three items
  as checked (`[x]`). The top-level Beta Release Gate tracking item was not promoted when the
  PR-09 deliverables were completed on this branch.
- **Why it matters:** The Beta Release Gate section is the authoritative go/no-go reference.
  Leaving the PR-09 item unchecked makes the release status look incomplete when the branch lands.
  This is a tracking document accuracy issue, not a functional defect.
- **Evidence:** `git show feat/v0.9-09-exports-and-ops:RELEASE_GATES.md | sed -n '100,110p'`
  confirms `- [ ] PR-09 operator polish lands`.
- **Recommended fix:** Change `- [ ] PR-09 operator polish lands` to
  `- [x] PR-09 operator polish lands` in the Beta Release Gate section.
- **Verification gap or confirming test:** The parity checker does not verify the checked state of
  Beta Release Gate items; no test enforces this.

---

## What Was Done Well

**Checksum canonicalization was corrected.** `session.py` previously computed checksums via
`json.dumps(artifact, sort_keys=True, separators=(",", ":"))`. PR-09 replaces this with
`canonical_json_bytes(artifact)` from `aigc._internal.utils`, exactly matching the implementation
in `audit.checksum`. This closes a previously-reported checksum mismatch risk. The
`TestChecksumCorrelationParity` and `TestChecksumCorrelationParityExport` test classes confirm
that integer-valued floats and non-ASCII content both correlate correctly across the audit and
session paths.

**Fail-fast on corrupt artifacts is correctly placed.** Both `reconstruct_trace` and
`export_workflow` validate that each `steps[]` entry is a `dict` before any correlation logic runs
and raise `ValueError` with a `workflow lint` hint. The CLI handlers catch this and exit 1.
`workflow_lint.py` gained the same guard at lines 475-486. The schema at
`aigc/schemas/workflow_artifact.schema.json` was tightened from `"steps": {"type": "array"}` to
`"steps": {"type": "array", "items": {"type": "object"}}`. Schema, lint, trace, and export are
all aligned on this invariant.

**JSONL parsing is fail-fast on line level.** Both CLI commands return exit 1 immediately on the
first malformed JSONL line (bad JSON or non-dict). There is no silent skip that would allow a
partially-written file to produce a misleadingly clean result.

**Audit mode does not leak raw invocation payloads.** `_build_audit` emits only `step_id`,
`participant_id`, `invocation_artifact_checksum`, and `enforcement_result` per step. The full
invocation artifact object is not serialized in audit mode. `test_step_summary_has_enforcement_
result` asserts `"invocation_artifact" not in step`.

**Release-packet stale language was fully cleared.** All seven source-of-truth documents were
inspected for stale "reserved for PR-09", "remain unshipped until PR-09", "planned for PR-09",
"Between PR-08 And PR-09", and "PR-09 has not started" patterns. None were found on the branch.
The parity check O (`check_v090_pr09_contract`) passes with no errors.

**The PR-09 parity check is defined and registered.** `check_v090_pr09_contract` is defined in
`scripts/check_doc_parity.py` and registered as check O in `main()`. Six unit tests in
`test_doc_parity_v090_truth.py` verify that the check accepts valid docs and rejects stale patterns.
All six pass. The check gates on stale-language absence and positive anchors in both the CLI
reference (`WORKFLOW_CLI.md`) and the operations runbook.

**Export integrity accounting uses the union of step refs and `invocation_audit_checksums`.** A
step reference absent from `invocation_audit_checksums` is still treated as unresolved by export.
The `TestExportIntegrityStepReferenceParity` class tests this in four scenarios. The comment in
`workflow_export.py:57-60` explicitly documents the intent.

**The demo `/trace` route uses real governed artifacts.** The route creates a `JsonFileAuditSink`,
runs two real governed steps, then calls `aigc workflow trace` via subprocess. CLI failure and
non-JSON output both raise HTTP 500. No fabricated trace data.

**1436 tests pass.** All 1436 tests pass on the branch with only pre-existing deprecation warnings.
179 of these are from the PR-09 test files, of which 127 are in the directly reviewed files. All
10 demo-app-api tests pass.

---

## Open Questions / Assumptions

1. **Trace/export divergence (F-03) — intentional or oversight?** The comment at
   `workflow_export.py:57-60` explicitly states the intent is for "trace and export to report the
   same unresolved set even when the two sources diverge." This implies the divergence in
   `reconstruct_trace` is an oversight rather than a design choice. If so, F-03 should be treated
   as a bug fix rather than a documentation choice.

2. **Manifest test count update process.** No automated check verifies that `doc_parity_manifest.
   yaml:test_count` equals the actual pytest count. Is updating the manifest a manual step expected
   of each PR author? If so, adding a CI step that fails when manifest count and actual count
   diverge would prevent recurrence.

3. **PR-09 Beta Release Gate item (F-06).** The `- [ ] PR-09 operator polish lands` item may be
   intentionally left unchecked until the branch merges to develop. If so, this is a process
   convention that should be applied at merge time.

---

## Residual Test Gaps

The following cases are not covered by any test on the PR-09 branch:

1. **`GET /trace` demo route** — No test exercises this endpoint at all. The subprocess invocation
   of `aigc workflow trace`, the `JsonFileAuditSink`, JSONL parsing, and the HTTP 500 error path
   are all unverified. This is the highest-priority gap given the route's role as the primary
   operator evidence demo.

2. **Multi-workflow JSONL in trace** — `test_workflow_trace.py` has no test that puts two separate
   workflow artifacts into a single JSONL file and verifies that the returned traces array contains
   two elements with correct session-scoped correlation. The export tests have a `test_multi_session_
   partial_evidence` case; the trace tests do not.

3. **Trace: `invocation_audit_checksums` entry absent from `steps[]`** — No test in
   `test_workflow_trace.py` covers the case where `invocation_audit_checksums` has a checksum with
   no corresponding `steps[]` entry. This would document the behavior described in F-03.

4. **Export: third-type artifact classification** — The export CLI silently places any artifact
   whose `artifact_type != "workflow"` into the `invocation_artifacts` list. A non-workflow,
   non-invocation artifact (e.g., a third type) would be silently treated as an invocation artifact.
   No test documents or checks this behavior.

5. **Explicit sink-failure surfacing vs. missing-checksum inference** — There is no test that
   distinguishes an explicit audit-sink failure from a plain missing-checksum gap. Both surface as
   "unresolved checksums." The plan requires "surface sink failures explicitly"; the current
   implementation infers them from missing checksums rather than emitting a distinct signal.

---

## Merge Verdict

- [ ] Ready
- [x] Ready with fixes
- [ ] Not ready

**Verdict:** Ready with fixes

**Rationale:** The PR-09 implementation is functionally correct and complete against the plan scope.
Both CLI commands work, the checksum canonicalization fix is correct, all seven source-of-truth docs
have been updated, the PR-09 parity check passes, and all 1436 tests pass. The schema, lint, trace,
and export modules are coherently aligned on the corrupt-artifact fail-fast invariant.

Two issues must be resolved before pushing to origin:

1. **F-01** — Four flake8 E501 violations in `cli.py` will fail the CI lint gate. This is a
   trivial fix: split two `print(...)` statements across lines.

2. **F-02** — The `doc_parity_manifest.yaml` test count and its mirrors in `README.md` and
   `CHANGELOG.md` are stale, causing the mandatory doc-parity CI check to fail with two errors.
   Fix requires updating three values from 1233/1369 to 1436.

F-03 (trace/export unresolved divergence) should be resolved before PR-11 freeze, either by
aligning `reconstruct_trace` with `export_workflow`'s union logic or by explicitly documenting
the divergence with a warning in `WORKFLOW_CLI.md`.

F-04 (no test for the `/trace` demo route) should be addressed before PR-11 freeze given the
route's role as the primary demo operator-evidence path.

F-05 and F-06 are documentation tracking updates that should be applied at merge time.
