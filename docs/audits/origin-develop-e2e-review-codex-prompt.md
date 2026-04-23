# Codex Prompt: `origin/develop` End-to-End Functionality and Doc Alignment Review

Use the prompt below as-is with Codex when you want a full audit of AIGC against
`origin/develop`, with findings written to `docs/audits` before any fixes are
applied.

```text
Audit the AIGC repository against the code and behavior on `origin/develop`.

Objective:
1. Perform an end-to-end review of AIGC functionality.
2. Verify document vs code alignment across the SDK, CLI, schemas, tests, and demo surfaces.
3. If code is correct and documentation is wrong, explicitly make that evaluation and fix the documentation.
4. If code is wrong relative to the intended public contract, fix the code and update docs as needed.
5. Produce a written findings report in `/Users/neal/Documents/_Shenanigans/_myProjects/aigc/docs/audits` before making substantive fixes.

Operating rules:
- Treat the implementation on `origin/develop` as the audit target, not whatever feature branch may currently be checked out.
- If the current working tree is not safely based on `origin/develop`, stop and say so before editing.
- Use executable behavior as the primary source of truth: public code in `aigc/`, JSON schemas, CLI behavior, demo app behavior, and tests.
- Use docs as claims to verify, not as truth by assertion.
- If docs disagree with code and the code is internally consistent, covered by tests, and aligned with the public API/schema, classify that as `DOC_BUG` and fix the docs.
- If code disagrees with the intended contract and tests/docs/schemas support the docs, classify that as `CODE_BUG` and fix the code, then update docs if needed.
- If the evidence is mixed or intent is unclear, classify that as `NEEDS_DECISION`, document it clearly, and do not make speculative behavior changes.
- Do not silently "fix docs to match a bug" unless you can defend that the shipped code is the correct behavior.

Required scope:
- Public SDK API exported from `aigc/__init__.py`
- Unified and split enforcement flows
- Sync and async entry points
- `AIGC` instance API
- `@governed` behavior and defaults
- `InvocationBuilder`
- Policy loading, composition, dates, and validation
- Guards, conditions, role validation, tool constraints, schema validation, postconditions, and risk scoring
- Custom gates and insertion points
- Audit artifact generation and schema alignment
- Audit sinks and sink failure behavior
- Signing and verification
- Audit chain, lineage, provenance, and risk history features
- CLI commands and examples
- Demo app API and React labs as end-to-end product surfaces
- User-facing docs, especially:
  - `README.md`
  - `PROJECT.md`
  - `docs/AIGC_FRAMEWORK.md`
  - `docs/USAGE.md`
  - `docs/INTEGRATION_GUIDE.md`
  - `docs/PUBLIC_INTEGRATION_CONTRACT.md`
  - `docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md`
  - `docs/architecture/ENFORCEMENT_PIPELINE.md`
  - `doc_parity_manifest.yaml`

Execution order:

Phase 1: Establish audit baseline
- Confirm the exact `origin/develop` commit being audited.
- Inspect repo status and identify whether edits can be safely based on `origin/develop`.
- Read the public API surface, parity manifest, major docs, relevant implementation files, representative tests, and demo app surfaces before drawing conclusions.

Phase 2: Write findings report before fixes
- Create a timestamped markdown report in:
  `/Users/neal/Documents/_Shenanigans/_myProjects/aigc/docs/audits`
- Filename format:
  `YYYY-MM-DD-origin-develop-e2e-review.md`
- This report must exist before you make substantive code or documentation fixes.
- The report must include:
  - Audited commit SHA for `origin/develop`
  - Audit date
  - Scope reviewed
  - Methodology and evidence sources
  - Executive summary
  - Findings table
  - Prescriptive remediation plan

Required findings table columns:
- `ID`
- `Area`
- `Severity`
- `Classification` (`DOC_BUG`, `CODE_BUG`, `BOTH_BUG`, `NEEDS_DECISION`, or `NO_ISSUE`)
- `Observed Behavior`
- `Expected / Documented Behavior`
- `Code Evidence`
- `Doc Evidence`
- `Why this evaluation is correct`
- `Required Fix`
- `Status`

For every actual issue:
- Cite concrete file paths and line numbers.
- Name the exact behavior that was verified.
- State whether the code or the docs are authoritative in that case, and why.
- Write the fix in prescriptive language, for example:
  - `Update README quick start to show split enforcement as the default decorator behavior.`
  - `Correct PUBLIC_INTEGRATION_CONTRACT example so typed preconditions match the actual policy DSL.`
  - `Fix enforcement pipeline to emit the documented gate metadata field on FAIL artifacts.`

Phase 3: Apply fixes after the report is written
- Work through the findings in severity order.
- Prefer the narrowest defensible fix.
- If a finding is `DOC_BUG`, update the relevant docs and keep behavior unchanged.
- If a finding is `CODE_BUG`, fix the implementation and update any now-stale docs/tests/examples.
- If a finding is `BOTH_BUG`, repair both sides coherently.
- After each fix, update the report `Status` and add a short note under a `Remediation Applied` section.

Phase 4: Validate
- Run the strongest relevant local verification you can for the areas touched.
- At minimum, run the documentation parity checker if docs changed:
  `python scripts/check_doc_parity.py`
- Run targeted pytest coverage for the touched functional areas.
- If demo app or CLI behavior was changed, run the relevant tests for those surfaces too.
- Do not claim tests passed unless you actually ran them.

Quality bar:
- Be skeptical of stale examples.
- Use tests as evidence of intended shipped behavior, not just implementation detail.
- Prefer public API references over `_internal` details in user-facing docs.
- Preserve user-facing terminology and release framing where still correct.
- Keep fixes surgical and evidence-based.

Final response requirements:
- Start with the path to the findings report you created in `docs/audits`.
- Summarize the highest-severity findings first.
- State what you changed.
- State what verification you ran.
- Call out anything left as `NEEDS_DECISION`.
```
