# Codex Prompt: PR-09 Implementation Review

Use the prompt below as-is with Codex when you want a findings-first review of
the PR-09 implementation, with the review written to `docs/audits` as
Markdown.

```text
Review the PR-09 implementation in the local AIGC repository.

Repository root:
/Users/neal/Documents/_Shenanigans/_myProjects/aegis

Base branch:
develop

Review branch:
feat/v0.9-09-exports-and-ops

Task type:
- Review only
- Do not fix code
- Do not update tests, docs, or schemas
- Only create or update the audit report file under `docs/audits`

Primary deliverable:
- Create a Markdown review report in:
  /Users/neal/Documents/_Shenanigans/_myProjects/aegis/docs/audits
- Use this filename:
  YYYY-MM-DD-pr09-implementation-code-review-codex.md
- Overwrite that file if it already exists
- The report must be complete enough to stand alone without the chat transcript

Working rules:
- Compare `develop...feat/v0.9-09-exports-and-ops`
- Use explicit branch refs in `git diff`, `git log`, and `git show`; avoid changing branches unless required
- If you need to run branch-local tests or inspect branch-only files, prefer a temporary git worktree over disturbing the current worktree
- The worktree may be dirty; do not revert or disturb unrelated local changes
- Treat docs as claims to verify, not truth by assertion
- Use executable evidence and direct code inspection as the primary basis for conclusions
- Prioritize silent evidence loss, hidden CLI crashes, misleading integrity/export claims, fail-open behavior, public-contract drift, release-packet drift, demo evidence fakery, and missing tests
- Ignore tracking-doc edits unless they reveal contract drift, bad gating, or a public-surface inconsistency
- Cite exact file paths and line numbers for every confirmed issue
- Separate confirmed defects from plausible risks and missing coverage
- If no confirmed defects are found, say that explicitly and still document residual risks and test gaps

Canonical review sources:
- docs/dev/pr_context.md
- RELEASE_GATES.md
- docs/plans/AIGC V0.9.0 IMPLEMENTATION_PLAN.md
- implementation_status.md
- CLAUDE.md
- docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md
- docs/architecture/ARCHITECTURAL_INVARIANTS.md
- docs/architecture/AIGC_THREAT_MODEL.md
- docs/PUBLIC_INTEGRATION_CONTRACT.md
- docs/reference/WORKFLOW_CLI.md
- docs/reference/OPERATIONS_RUNBOOK.md
- README.md
- scripts/check_doc_parity.py

Expected PR-09 scope:
- ship `aegis workflow trace` and `aegis workflow export`
- reconstruct workflow timelines from workflow artifacts plus invocation evidence using checksum correlation
- support operator and audit export modes with integrity metadata and verification guidance
- surface sink failures and incomplete exports explicitly, without pretending they are enforcement failures
- keep observability extras optional and avoid turning AIGC into a monitoring platform
- keep audit export compliance-focused and avoid leaking raw invocation payloads there
- provide an operator-facing evidence path that uses real artifacts rather than fabricated demo data
- advance the release packet from "planned for PR-09" to "shipped in PR-09" on the review branch without weakening earlier PR truth checks

Files to prioritize based on the actual diff:
- aegis/_internal/cli.py
- aegis/_internal/workflow_trace.py
- aegis/_internal/workflow_export.py
- aegis/_internal/workflow_lint.py
- aegis/schemas/workflow_artifact.schema.json
- scripts/check_doc_parity.py
- demo-app-api/workflow_routes.py
- docs/reference/WORKFLOW_CLI.md
- docs/reference/OPERATIONS_RUNBOOK.md
- tests/test_workflow_trace.py
- tests/test_workflow_export.py
- tests/test_v090_contract_freeze.py
- tests/test_doc_parity_v090_truth.py
- tests/test_workflow_doctor.py
- tests/test_cli.py
- demo-app-api/tests/test_workflow_routes.py

Known branch details that require explicit verification:
- PR-09 adds new branch-only files `tests/test_workflow_trace.py` and `tests/test_workflow_export.py`
- PR-09 recently fixed a crash on non-dict `steps[]` entries
- PR-09 recently removed a PR-07 doc-parity restriction that previously forbade documenting `workflow trace` and `workflow export`
- PR-09 recently changed the demo evidence route so CLI failures and non-JSON output return HTTP 500 instead of silently succeeding
- The review branch still appears to contain source-of-truth docs that say `workflow trace` / `workflow export` are reserved for PR-09, unshipped until PR-09, or planned-only; verify that drift directly

Execution order:

Phase 1: Establish the baseline
- Capture `git status -sb`
- Capture the exact HEAD SHA for `develop`
- Capture the exact HEAD SHA for `feat/v0.9-09-exports-and-ops`
- Summarize commit history and changed-file scope for `develop...feat/v0.9-09-exports-and-ops`

Phase 2: Extract the intended contract
- Read the PR-09 sections in the plan, release gates, PR context, CLI guide, operations runbook, and public integration contract
- Extract actual acceptance criteria, non-goals, export-integrity expectations, and public-boundary rules before judging implementation
- Pay attention to whether trace/export are supposed to be public beta surfaces on this branch and whether earlier docs still describe them as deferred

Phase 3: Inspect the implementation
- Review CLI wiring, trace reconstruction, export semantics, schema/lint alignment, doc-parity changes, and demo evidence routing
- Confirm whether the implementation is deterministic, honest about evidence gaps, coherent across runtime/tests/docs, and consistent with the frozen public CLI story

Phase 4: Validate behavior
- Run targeted tests that directly exercise PR-09 behavior
- If you cannot run the full targeted bundle, run the strongest focused subset and document exactly what you did and did not run
- Do not claim any test passed unless you actually ran it
- Where useful, run focused reproductions for malformed `steps[]`, unresolved checksums, doc/release drift, and CLI output failures

Phase 5: Write the report
- Write the report to the Markdown file in `docs/audits`
- Keep it findings-first and evidence-based

Minimum commands to run:
- `git status -sb`
- `git rev-parse develop`
- `git rev-parse feat/v0.9-09-exports-and-ops`
- `git log --oneline develop..feat/v0.9-09-exports-and-ops`
- `git diff --stat develop...feat/v0.9-09-exports-and-ops`
- `git diff --name-only develop...feat/v0.9-09-exports-and-ops`
- `git diff develop...feat/v0.9-09-exports-and-ops -- aegis/_internal/cli.py aegis/_internal/workflow_trace.py aegis/_internal/workflow_export.py aegis/_internal/workflow_lint.py aegis/schemas/workflow_artifact.schema.json scripts/check_doc_parity.py demo-app-api/workflow_routes.py docs/reference/WORKFLOW_CLI.md docs/reference/OPERATIONS_RUNBOOK.md`
- `rg -n "workflow trace|workflow export|reserved for PR-09|unshipped until PR-09|planned-only|Deferred To PR-09" README.md CLAUDE.md docs/dev/pr_context.md RELEASE_GATES.md implementation_status.md docs/PUBLIC_INTEGRATION_CONTRACT.md docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md docs/reference/WORKFLOW_CLI.md docs/reference/OPERATIONS_RUNBOOK.md`
- `pytest -q tests/test_workflow_trace.py tests/test_workflow_export.py tests/test_v090_contract_freeze.py tests/test_doc_parity_v090_truth.py tests/test_workflow_doctor.py tests/test_cli.py demo-app-api/tests/test_workflow_routes.py`

Specific review checklist:

1. CLI command contract
- Verify `aegis workflow trace` and `aegis workflow export` are registered under the workflow CLI and match the intended top-level command inventory
- Verify help text, docs, and real argument parsing agree on `--input`, `--output`, and `--mode`
- Verify malformed JSONL lines, non-dict artifacts, missing files, unreadable inputs, and unwritable outputs are handled intentionally and do not produce misleading success
- Verify unresolved checksum cases exit `0` only when the gap is truly advisory, not when the input is structurally corrupt
- Verify new JSON output shapes are stable enough to treat as public contract and call out any missing schema or snapshot protection

2. Trace reconstruction
- Verify checksum correlation uses the same canonicalization as the audit checksum implementation
- Verify sequence numbering follows workflow step order, not invocation-artifact order
- Verify unresolved checksum reporting is derived from the actual workflow step references and does not silently lose gaps
- Verify top-level trace fields preserve session status, timestamps, duration, failure summary, approval checkpoints, and validator-hook evidence
- Verify corrupt or non-dict step entries are surfaced honestly and do not quietly change `step_count`, sequence meaning, or unresolved-gap reporting
- Look for multi-session, duplicate-checksum, or partial-export cases where the trace could look more complete than the evidence actually is

3. Export semantics and integrity
- Verify operator mode embeds the full invocation artifact only in operator mode
- Verify audit mode stays compliance-focused and does not leak raw invocation payloads or unnecessary internal detail
- Verify integrity accounting uses the right expected checksum set and stays consistent with `workflow trace`, `workflow_lint`, and the workflow artifact schema
- Verify `verification_guidance` is concrete and not misleading about what was or was not verified
- Verify unknown or future workflow statuses do not crash export generation and do not corrupt compliance-summary counts
- Verify the export does not overclaim "explicit sink-failure reporting" if it only infers missing evidence indirectly
- Verify sink-failure and incomplete-export handling stay compatible with fail-closed semantics where sinks are required

4. Schema, lint, and doctor coherence
- Verify `aegis/schemas/workflow_artifact.schema.json` and runtime/lint assumptions agree about `steps[]` entry shape
- Verify lint catches corrupt artifacts early enough that trace/export are not forced to guess at bad input
- Verify trace/export behavior does not contradict `workflow doctor` guidance for incomplete or corrupted evidence
- Review `scripts/check_doc_parity.py` to ensure PR-09 documentation is allowed without accidentally weakening pre-PR-09 truth checks more than necessary
- Check whether PR-09 should have added positive parity coverage for the shipped trace/export docs rather than only removing an old PR-07 prohibition

5. Demo and operator path
- Verify the demo evidence route uses a real governed session plus `JsonFileAuditSink`, not fabricated trace data
- Verify the route surfaces CLI failure and non-JSON output as HTTP 500 rather than returning an empty success payload
- Verify the route keeps the operator flow optional and does not become a hidden requirement of the base beta path
- Check whether demo route behavior is actually covered by tests; if not, call that out explicitly

6. Release packet and public-surface drift
- Explicitly inspect `CLAUDE.md`, `docs/dev/pr_context.md`, `RELEASE_GATES.md`, `implementation_status.md`, `docs/PUBLIC_INTEGRATION_CONTRACT.md`, `docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md`, and `README.md`
- Verify the PR-09 branch updates the release packet so trace/export are no longer described as deferred, reserved, or planned-only
- Verify the public integration contract and architecture docs do not contradict the branch's actual CLI surface
- Verify doc-parity and contract-freeze checks still protect the release packet after PR-09 lands
- Call out any place where the branch ships trace/export code while the source-of-truth docs still describe them as unavailable

7. Test quality
- Review whether the tests prove behavior rather than only matching happy-path JSON shapes
- Call out missing tests for:
  - output-path write failures
  - non-workflow dicts being silently treated as invocation artifacts
  - unresolved checksums caused by step references that are absent from `invocation_audit_checksums`
  - duplicate or conflicting invocation-artifact checksums
  - multi-workflow JSONL ordering and correlation edge cases
  - audit-mode payload leakage
  - release-packet alignment after PR-09 lands
  - demo `/trace` route coverage
  - sink-failure explicitness versus mere missing-checksum inference
  - corrupt artifact inputs that should fail rather than be quietly skipped

Required report structure:

# PR-09 Implementation Code Review

- Audit date
- Repository root
- Base branch and commit
- Review branch and commit
- Scope reviewed
- Commands run

## Findings

List confirmed issues first, sorted by severity.

Use one subsection per finding in this format:

### F-XX — <Severity> — <Short title>
- Location: `path:line`
- Issue:
- Why it matters:
- Evidence:
- Recommended fix:
- Verification gap or confirming test:

If there are no confirmed defects, write:
`No confirmed defects found.`

## Open Questions / Assumptions

## Residual Test Gaps

## Merge Verdict
- `Ready`
- `Ready with fixes`
- `Not ready`

Final chat response requirements:
- Start with the full path to the Markdown report you created
- Then summarize the highest-severity findings
- Then state what commands and tests you ran
- Do not paste the full report into chat
```
