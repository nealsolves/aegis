# AIGC `v0.9.0` PR-01 through PR-08 Implementation Review Prompt

Use this prompt in Claude Code or Codex.

---

You are reviewing the **local `develop` branch** of the AIGC repository.

Your job is to perform a **deep, evidence-based implementation review of PR-01 through PR-08** for the `v0.9.0` beta train.

This is **not** a lightweight code scan.
This is a **release-contract audit** against the canonical plan, release gates, architectural invariants, and public-surface rules.

You must determine:

1. whether PR-01 through PR-08 are actually implemented in local `develop`
2. whether each PR meets its stated intent, not just partial code presence
3. whether the implementation is coherent across code, CLI, tests, docs, demos, and public API boundaries
4. whether the current state is strong enough for the intended `v0.9.0` beta story
5. what is missing, broken, inconsistent, risky, or only partially landed

Your output must be **thorough, actionable, and testable**.

## Repository and output location

Repository root:

`/Users/neal/Documents/_Shenanigans/_myProjects/aigc`

Write the final report as markdown here:

`/Users/neal/Documents/_Shenanigans/_myProjects/aigc/docs/audits/PR01_PR08_IMPLEMENTATION_REVIEW_LOCAL_DEVELOP.md`

If a file with that exact name already exists, overwrite it.

---

## Canonical review sources

Treat the following as the primary source-of-truth set for this review:

- `docs/plans/AIGC V0.9.0 IMPLEMENTATION_PLAN.md`
- `RELEASE_GATES.md`
- `implementation_status.md`
- `docs/dev/pr_context.md`
- `CLAUDE.md`
- `docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md`
- `docs/architecture/ARCHITECTURAL_INVARIANTS.md`
- `docs/architecture/ENFORCEMENT_PIPELINE.md`
- `docs/PUBLIC_INTEGRATION_CONTRACT.md`
- `README.md`
- `PROJECT.md`
- `CHANGELOG.md`
- `doc_parity_manifest.yaml`

Use these sources to establish intended scope, branch sequencing, public-surface constraints, workflow adoption rules, golden-path expectations, stop-ship criteria, and invariant boundaries.

Important review assumptions you must enforce:

- `v0.9.0` is a **beta** intended to be easy for app teams to drop into a real workflow quickly.
- AIGC must remain an **SDK**, not become a hosted runtime, orchestrator, or transport owner.
- The **host owns orchestration, transport, retries, credentials, business state, tool execution, and provider SDK usage**.
- Public examples, docs, starters, presets, and demo code must use **public APIs only** and must not import from `aigc._internal`.
- The default first-adopter path must succeed **without Bedrock or A2A**.
- Workflow adoption is intended to be **instance-scoped through `AIGC.open_session(...)`**.
- Invocation artifacts must remain separate from workflow or session evidence.
- PR-07 is a **mandatory stop-ship checkpoint**.
- PR-08 is **engine hardening**, not casual scope creep.

Do not merely repeat these claims from docs.
Verify them against the codebase.

---

## PRs in scope

Review these PR goals as implemented in local `develop`:

- **PR-01** — source of truth
- **PR-02** — contract freeze
- **PR-03** — golden-path contract
- **PR-04** — minimal session flow
- **PR-05** — starters and migration
- **PR-06** — doctor and lint
- **PR-07** — beta proof
- **PR-08** — engine hardening

Do **not** review PR-09, PR-10a, PR-10b, or PR-11 except where current code improperly leaks or depends on them.

---

## Review method

Follow this sequence exactly.

### Phase 1 — Establish the intended release contract

Read the canonical plan and release packet first.
Build a compact internal matrix for PR-01 through PR-08 containing:

- PR number
- intended branch name
- stated goal
- required outcomes
- explicit non-goals if present
- dependencies on earlier PRs
- stop-ship or fail-closed implications

Do this before evaluating code.

### Phase 2 — Map implementation to the repo

Identify all relevant implementation surfaces for PR-01 through PR-08, including:

- Python package code
- CLI code and command registration
- starter or scaffold generation code
- session or workflow runtime code
- validators, lint, and doctor logic
- tests and harnesses
- demo app routes and components
- docs and examples
- parity and CI checks
- migration helpers
- public exports and import boundaries

You must find the real implementation paths, not infer them from doc titles.

### Phase 3 — Evaluate PR-by-PR completeness

For each PR from 01 through 08, determine one of these states:

- **COMPLETE** — implemented and aligned with release intent
- **PARTIAL** — some implementation exists, but intent is not fully met
- **MISSING** — little or no real implementation
- **DRIFTED** — implementation exists but violates the intended scope or design contract
- **BLOCKED** — present but undermined by a dependency gap or defect elsewhere

For every conclusion, include hard evidence:

- file paths
- symbol names
- commands
- tests
- exact gaps

Do not mark a PR complete just because docs exist.
Do not mark a PR complete just because code compiles.
The implementation must satisfy the **intent** of the release contract.

### Phase 4 — Validate the first-adopter beta story end to end

Test whether local `develop` can support the intended first-adopter journey for `v0.9.0`:

1. install package in a clean environment
2. run `aigc workflow init`
3. choose minimal or standard starter
4. drop into a simple host-owned workflow
5. reach first PASS
6. inspect trace/evidence
7. hit one understandable failure
8. use `workflow doctor` or `workflow lint`
9. fix and rerun successfully

You must verify whether this story is actually possible in the current repo state.
If not, explain precisely where it breaks.

### Phase 5 — Check invariant compliance

Evaluate whether PR-01 through PR-08 as implemented preserve the architecture and invariants, including at minimum:

- fail-closed behavior
- deterministic governance boundary
- fixed gate ordering
- one artifact per invocation attempt
- public API boundary discipline
- split versus unified enforcement discipline where relevant
- workflow support without platform ownership collapse
- no hidden dependence on `_internal` in public surfaces

If something works but violates an invariant, call it out as a serious finding.

### Phase 6 — Check docs/code/release alignment

Review whether the following are aligned with actual implementation:

- implementation plan
- release gates
- implementation status
- active PR context
- README and onboarding docs
- public integration contract
- changelog claims
- demo guidance
- parity rules

Find and call out:

- docs ahead of implementation
- implementation ahead of docs
- conflicting source-of-truth documents
- stale or misleading beta guidance
- public surface claims that are not actually shipped

### Phase 7 — Produce actionable remediation plan

For every important gap, provide a fix that Claude Code or Codex can execute.
Each remediation item must include:

- severity
- affected PR number
- what is wrong
- why it matters for the beta
- exact files likely needing change
- how to verify the fix
- whether the issue blocks beta readiness

---

## Commands you should run

Use the local repo. Prefer direct inspection over assumptions.
Run whatever is necessary, but at minimum attempt the following where applicable:

```bash
cd /Users/neal/Documents/_Shenanigans/_myProjects/aigc

git branch --show-current
git status --short
rg "workflow init|workflow lint|workflow doctor|workflow trace|open_session|GovernanceSession|SessionPreCallResult|AgentIdentity|AgentCapabilityManifest|ValidatorHook|BedrockTraceAdapter|A2AAdapter" .
rg "aigc\._internal" README.md PROJECT.md docs examples demo-app-react demo-app-api
python -m pytest
flake8 aigc
python scripts/check_doc_parity.py
```

Also run targeted tests or focused grep inspections as needed.
If the full test suite is too large or fails for unrelated reasons, say so clearly and continue with the deepest grounded review possible.

If there are starter flows, demo harnesses, CLI commands, or proof scripts for PR-04 through PR-08, run them when feasible.

---

## What to check for each PR

Use the guidance below as minimum review criteria.

### PR-01 — Source of truth
Check whether:

- the canonical plan exists and is clearly active
- release docs align on PR numbering and branch names
- stale plan variants are marked superseded or historical
- CI truth checks exist and are meaningful
- `origin/main` freeze language and PR-07 stop-ship language are enforced in release docs

### PR-02 — Contract freeze
Check whether:

- session lifecycle, `SessionPreCallResult`, and artifact separation are frozen coherently
- target-state workflow surfaces are fenced correctly against currently shipped runtime claims
- public contract boundaries are explicit and consistent
- no silent contract drift exists between design docs and code/docs/tests

### PR-03 — Golden-path contract
Check whether:

- CLI command names and golden-path docs order are frozen coherently
- starter profile expectations are explicit
- public import rules are enforced by tests or CI
- this PR stayed docs/CI/sentinel only, without sneaking in runtime behavior it explicitly should not contain

### PR-04 — Minimal session flow
Check whether:

- the smallest real governed local workflow path exists
- a host-owned local workflow can open a session and complete a PASS path
- evidence correlation works for the minimal path
- this path is actually usable by a first adopter without Bedrock or A2A

### PR-05 — Starters and migration
Check whether:

- starter scaffolds exist and are usable
- minimal and standard starter choices are real, not placeholder docs only
- invocation-only migration guidance is backed by actual helpers or examples
- starter outputs use public APIs only

### PR-06 — Doctor and lint
Check whether:

- `workflow doctor` and `workflow lint` exist
- they emit stable reason codes
- failure explanations are understandable and actionable
- they identify broken config, invalid transitions, or missing requirements in a way a user can fix

### PR-07 — Beta proof
Check whether:

- stop-ship proof exists for clean install, first PASS, intentional failure, diagnosis, fix, and rerun
- demo and quickstart prove the default adopter journey
- proof tests, harnesses, or scripts exist and are credible
- the default path succeeds without Bedrock or A2A

### PR-08 — Engine hardening
Check whether:

- workflow sequencing is hardened
- approvals/checkpoints/budgets/validator hooks are implemented appropriately
- hardening preserves fail-closed behavior and boundary discipline
- PR-08 did not become undisciplined scope expansion that weakens the beta story

---

## Required report format

Write a markdown report with this exact structure:

```md
# PR-01 through PR-08 Implementation Review — local `develop`

## Executive Verdict

- Overall verdict: READY / NOT READY / CONDITIONALLY READY
- Beta story verdict: PASS / FAIL / PARTIAL
- Stop-ship recommendation: YES / NO
- Highest-risk gaps:
  - ...

## Review Scope and Method

## Source-of-Truth Contract Used

## PR-by-PR Review Matrix

| PR | Goal | Status | Verdict | Key evidence | Blocking gaps |
|----|------|--------|---------|--------------|---------------|

## Detailed Findings by PR

### PR-01 — ...
#### What was expected
#### What exists in local `develop`
#### Evidence
#### Gaps
#### Verdict

### PR-02 — ...
...

## End-to-End First-Adopter Journey Assessment

## Architectural Invariant Compliance Review

## Docs / Code / Release-Packet Alignment Review

## Testability and Verification Gaps

## Actionable Remediation Plan

### Critical
1. ...
   - PR:
   - Why it matters:
   - Likely files to change:
   - How to verify:

### High
...

### Medium
...

## Suggested Next Moves

## Appendix — Commands Run

## Appendix — Key Files Reviewed
```

---

## Evidence rules for the report

- Be specific.
- Use repo-relative file paths.
- Reference concrete symbols, tests, commands, or routes when possible.
- Distinguish between:
  - implemented in code
  - documented only
  - test-covered
  - demo-exposed
  - claimed but unverified
- Call out contradictions explicitly.
- If something cannot be verified, say so.
- Do not pad the report with generic architecture commentary.

---

## Review standard

Be tough.
This is a beta-readiness implementation review, not encouragement.
Do not give credit for intention, only for evidence.
Do not assume that a feature is complete because naming exists.
Do not assume that docs are true because they are written.
Do not assume that tests prove the correct thing unless you inspect their scope.

Prioritize:

1. release intent fidelity
2. first-adopter usability
3. fail-closed architecture integrity
4. public-surface correctness
5. testable remediation

When finished, save the markdown report to the required audit path.
