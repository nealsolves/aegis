# PR-01 through PR-08 Implementation Review — local `develop`

## Executive Verdict

- Overall verdict: NOT READY
- Beta story verdict: PARTIAL
- Stop-ship recommendation: YES
- Highest-risk gaps:
- Release-truth packet is internally inconsistent and currently breaks `python -m pytest` and `python scripts/check_doc_parity.py`.
- PR-07's required failure-and-fix proof is synthetic: the broken asset is not the asset that `workflow doctor` diagnoses or that gets rerun.
- The frozen CLI/public-contract story is contradictory: the plan, `CLAUDE.md`, and HLD freeze `workflow trace` and `workflow export`, while the actual CLI does not ship them and the beta docs say they are PR-09.
- `workflow lint` and `workflow doctor` do not fully meet the advertised PR-06 semantic-coverage contract.
- PR-08 hardening code is strong, but the shipped-vs-planned story for `ValidatorHook` and related surfaces is not coherent, the hook path is effectively dead outside tests, and several new workflow exceptions raised from public methods are not catchable from `aigc` or `aigc.errors`.

## Review Scope and Method

- Audited local repo state at `/Users/neal/Documents/_Shenanigans/_myProjects/aigc` on branch `develop`; `git status --short` showed unrelated untracked `docs/plans/v0.9.0_PR-07_BETA_PROOF_PLAN.md`, which I did not use as source of truth.
- Used the canonical source set named in the request to derive branch sequence, stated goals, dependencies, non-goals, and stop-ship gates before evaluating code.
- Mapped implementation across package/runtime code, CLI registration, starter generation, diagnostics, demo routes/UI, tests, docs, and release-truth scripts.
- Ran repo-local validation commands and targeted proof flows; results are summarized in the appendix.
- Did not review PR-09, PR-10a, PR-10b, or PR-11 except where current `develop` leaks or depends on their scope.

## Source-of-Truth Contract Used

- Branch sequencing and PR goals came primarily from `docs/dev/pr_context.md:14-27` and `docs/plans/AIGC V0.9.0 IMPLEMENTATION_PLAN.md:381-506`.
- Stop-ship requirements came from `docs/plans/AIGC V0.9.0 IMPLEMENTATION_PLAN.md:574-591`, `docs/dev/pr_context.md:108-134`, and `RELEASE_GATES.md:224-237`.
- Architecture and boundary rules were cross-checked against `CLAUDE.md:14-22,125-131`, `docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md:600-628,665-700`, `docs/architecture/ARCHITECTURAL_INVARIANTS.md`, `docs/architecture/ENFORCEMENT_PIPELINE.md`, and `docs/PUBLIC_INTEGRATION_CONTRACT.md:12-35`.
- Public-surface, docs-order, and release-packet claims were cross-checked against `README.md`, `PROJECT.md`, `CHANGELOG.md`, `implementation_status.md`, `RELEASE_GATES.md`, and `tests/test_v090_contract_freeze.py`.

## PR-by-PR Review Matrix

| PR | Goal | Status | Verdict | Key evidence | Blocking gaps |
|----|------|--------|---------|--------------|---------------|
| PR-01 | source of truth | DRIFTED | Release truth packet contradicts itself and fails its own gates | `docs/dev/pr_context.md:1-4,31-134`; `implementation_status.md:14-26,104-135`; `python -m pytest`; `python scripts/check_doc_parity.py` | Realign release docs and restore parity/tests |
| PR-02 | contract freeze | PARTIAL | Core session and artifact contract is implemented, but the freeze is not coherent across docs | `aigc/_internal/enforcement.py:1587-1608,2385-2403`; `aigc/_internal/session.py:64-79,474-489,834-839` | Resolve public/planned contract drift |
| PR-03 | golden-path contract | DRIFTED | Public-import rules are enforced, but CLI contract is not frozen coherently | Plan `385-392`; HLD `667-675`; `CLAUDE.md:117-123`; actual CLI `aigc/_internal/cli.py:453-529` | Decide whether trace/export are beta or PR-09 and align docs/tests |
| PR-04 | minimal session flow | COMPLETE | Real host-owned local governed workflow path exists and passes | `aigc/_internal/session.py:451-501`; proof harness `scripts/validate_v090_beta_proof.py:213-260` | No blocking PR-04-specific gap found |
| PR-05 | starters and migration | COMPLETE | Scaffolds, presets, policy init, and migration path are real and public-import clean | `aigc/_internal/cli.py:394-415,460-482`; starter/migration smoke tests; public import scan | Stale docs and truth-check drift around this work |
| PR-06 | doctor and lint | PARTIAL | Tools exist and codes are stable, but semantic coverage falls short of contract | `aigc/_internal/workflow_lint.py:126-321`; `aigc/_internal/workflow_doctor.py:49-112,340-389` | Add real transition/budget/binding diagnostics or narrow claims |
| PR-07 | beta proof | BLOCKED | Happy-path proof exists, but stop-ship failure/fix proof is synthetic and release gates overclaim | `scripts/validate_v090_beta_proof.py:268-347`; `tests/test_pr07_beta_proof.py:143-234`; `demo-app-api/workflow_routes.py:180-199` | Replace synthetic proof with real broken-asset diagnose-edit-rerun |
| PR-08 | engine hardening | PARTIAL | Hardening code is real, but hook registration is not productized and public exception/export boundaries are incomplete | `aigc/_internal/policy_loader.py:299-531`; `aigc/_internal/session.py:168-171,680-919`; `tests/test_validator_hook.py:15-43,296-306`; `aigc/errors.py:1-47` | Decide whether hooks are truly shipped/internal-only, wire or remove dead hook path, and export or normalize public workflow exceptions |

## Detailed Findings by PR

### PR-01 — Source of truth

#### What was expected

- One active canonical plan and one aligned release packet for PR numbering, branches, goals, exit gates, and stop-ship rules.
- Stale plan variants explicitly marked historical or superseded.
- Meaningful CI truth checks that fail when release docs drift.
- Explicit `origin/main` freeze language and explicit PR-07 stop-ship language.

#### What exists in local `develop`

- The canonical plan exists and older plan variants are correctly marked as superseded.
- The release packet is internally contradictory.
- CI truth checks exist and are meaningful enough to fail on drift.
- Freeze language and PR-07 stop-ship language exist in docs, but the packet that carries them is not internally trustworthy.

#### Evidence

- `docs/plans/AIGC V0.9.0 IMPLEMENTATION_PLAN.md` is the active plan. Older variants are clearly marked historical in the first lines of `docs/plans/AIGC V0.9.0 IMPLEMENTATION_PLAN_DRAFT.md`, `docs/plans/AIGC_v0.9.0_IMPLEMENTATION_PLAN_UPDATED.md`, and `docs/plans/0.9.0 plan backup.md`.
- `docs/dev/pr_context.md:1-4` says PR-08 is complete and PR-09 is next, but `docs/dev/pr_context.md:31-134` is still a PR-07 stop-ship packet with PR-07 scope, exit gate, and out-of-scope notes.
- `implementation_status.md:14-26` and `67-74` say PR-01 through PR-08 are complete, but `implementation_status.md:104-119` leaves every PR-07 deliverable unchecked while `122-135` immediately restates them as checked.
- `RELEASE_GATES.md:122-135` marks the PR-07 checklist green; `RELEASE_GATES.md:143-177` and `224-237` still leave earlier capability gates and beta stop-ship gates unresolved; `RELEASE_GATES.md:181-186` claims a real failure-and-fix proof and no fake backend behavior.
- `tests/test_v090_contract_freeze.py:65-67` asserts the release-truth check must pass. `python -m pytest` failed exactly there, and `python scripts/check_doc_parity.py` failed the same condition against `implementation_status.md`.

#### Gaps

- The current release packet cannot be treated as canonical because it contradicts itself and its own tests.
- PR-07 stop-ship language is present, but the packet claims green in places where the repo is objectively red.
- A contributor reading only the truth packet would not get a reliable answer to “what PR is active/complete right now?”

#### Verdict

- DRIFTED

### PR-02 — Contract freeze

#### What was expected

- Freeze session lifecycle, `SessionPreCallResult`, `AIGC.open_session(...)`, and invocation-vs-workflow artifact separation.
- Keep workflow adoption instance-scoped.
- Make public contract boundaries explicit and consistent.
- Fail closed at Bedrock/A2A boundaries without shipping adapter ownership.

#### What exists in local `develop`

- The core runtime contract is implemented well.
- Session flow is instance-scoped.
- `SessionPreCallResult` is single-use and session-bound.
- Workflow evidence is kept separate from invocation evidence with additive correlation only.
- The documented freeze around that runtime is not coherent across the source-of-truth docs.

#### Evidence

- `AIGC.open_session(...)` is instance-scoped in `aigc/_internal/enforcement.py:2385-2403`; there is no module-level public `open_session`.
- Module-level `enforce_post_call` hard-rejects `SessionPreCallResult` in `aigc/_internal/enforcement.py:1587-1608`.
- `SessionPreCallResult` is a frozen dataclass carrying only workflow token fields in `aigc/_internal/session.py:64-79`.
- Workflow artifacts are separate from invocation artifacts and carry only additive correlation via `session_id`, `step_id`, `participant_id`, and `invocation_audit_checksums` in `aigc/_internal/session.py:474-489,834-839`.
- `tests/test_v090_contract_freeze.py:112-139` freezes the public presence of `GovernanceSession` and `SessionPreCallResult`, and the absence of module-level `open_session`.

#### Gaps

- The runtime contract is stronger than the documentation packet. `CLAUDE.md`, the HLD, the public integration contract, and the PR packet do not fully agree about what is shipped versus planned.
- PR-02 claims the contract is frozen, but later docs still renegotiate workflow CLI, `ValidatorHook`, and adapter boundary surfaces.

#### Verdict

- PARTIAL

### PR-03 — Golden-path contract

#### What was expected

- Freeze CLI command names and first-adopter docs order.
- Freeze starter profiles and starter coverage expectations.
- Enforce public-import-only rules in docs, examples, starters, presets, and demos.
- Keep PR-03 as docs/CI/sentinel work only, not runtime behavior.

#### What exists in local `develop`

- Public-import discipline is strong.
- Starter profile set is real.
- Docs order is documented.
- The CLI contract itself is not frozen coherently: different canonical docs make incompatible claims, and the actual CLI matches only one of them.

#### Evidence

- The plan freezes `aigc policy init`, `aigc workflow init`, `aigc workflow lint`, `aigc workflow doctor`, `aigc workflow trace`, and `aigc workflow export` in `docs/plans/AIGC V0.9.0 IMPLEMENTATION_PLAN.md:385-392`.
- The HLD repeats the same frozen CLI inventory in `docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md:667-675`.
- `CLAUDE.md:14-22,117-123` also treats trace/export and a trace view plus audit/export visibility flow as part of the beta story.
- Actual CLI registration in `aigc/_internal/cli.py:453-529` only exposes `workflow init`, `workflow lint`, and `workflow doctor`; there is no parser for `workflow trace` or `workflow export`.
- Running `python -m aigc workflow trace --help` and `python -m aigc workflow export --help` returned invalid-subcommand errors.
- Release-facing docs then contradict the frozen contract by saying trace/export are later work: `README.md:219-221`, `docs/reference/WORKFLOW_CLI.md:1-11`, `docs/dev/pr_context.md:89-95,115`, and `RELEASE_GATES.md:195-199`.
- Public-import boundary enforcement is real: `rg "aigc\\._internal" README.md PROJECT.md docs examples demo-app-react demo-app-api` found only engineering-plan/audit references, not maintained public code, and `tests/test_v090_contract_freeze.py:178-192` also checks for leakage.
- Sentinel coverage is insufficient: `tests/test_v090_contract_freeze.py:142-176` checks that `workflow` exists and that `init` is present, but it does not assert the full frozen subcommand inventory or help-text shape.

#### Gaps

- The golden-path contract is not actually frozen because the canonical documents disagree about the beta CLI.
- `docs/reference/WORKFLOW_CLI.md` is not reliable contract documentation.
- The sentinel tests are too weak to stop the drift that already happened.

#### Verdict

- DRIFTED

### PR-04 — Minimal session flow

#### What was expected

- Land the smallest governed local workflow path with ordinary session semantics.
- Let a host-owned local `2`-step or `3`-step workflow reach PASS.
- Keep orchestration and provider calls in host code.
- Emit one workflow artifact plus correlated invocation artifacts.

#### What exists in local `develop`

- A real minimal session runtime exists.
- Local minimal and standard starters both run to `COMPLETED`.
- Workflow artifacts are emitted separately with correlated invocation evidence.
- The host still owns orchestration and model-call behavior.

#### Evidence

- `GovernanceSession.finalize()` emits one workflow artifact with correlated invocation checksums in `aigc/_internal/session.py:451-501`.
- Additive correlation fields are injected into each step invocation context in `aigc/_internal/session.py:834-839`.
- The maintained demo keeps orchestration/model simulation in host code: `_sim()` and the surrounding workflow loop live in `demo-app-api/workflow_routes.py:73-75,83-99`.
- `scripts/validate_v090_beta_proof.py:213-260` proves minimal and standard starters from a clean venv and expects `COMPLETED` with 2 and 3 steps respectively; this harness passed locally.

#### Gaps

- No PR-04-specific implementation gap was found.
- Trace visibility remains weak, but that is a later-contract / PR-07 issue, not missing minimal session flow.

#### Verdict

- COMPLETE

### PR-05 — Starters and migration

#### What was expected

- Ship usable starter scaffolds for `minimal`, `standard`, and `regulated-high-assurance`.
- Ship `aigc workflow init` and `aigc policy init`.
- Provide an invocation-only migration path backed by real examples/helpers.
- Keep starter outputs on public APIs only.

#### What exists in local `develop`

- The starter generators exist and work.
- The three profile choices are real.
- The migration path is backed by tests/docs.
- Public-import discipline is respected in starters, docs, and demos.

#### Evidence

- `aigc policy init` is registered in `aigc/_internal/cli.py:394-415`; `aigc workflow init` is registered in `aigc/_internal/cli.py:460-482`.
- Built-in profiles are exactly `minimal`, `standard`, and `regulated-high-assurance` in both parsers.
- `docs/PUBLIC_INTEGRATION_CONTRACT.md:22-25` advertises starter/preset beta surfaces.
- Starter generation, migration examples, and public-import boundary are exercised by `tests/test_starter_smoke.py`, `tests/test_migration_smoke.py`, and `tests/test_pr05_public_import_boundary.py`.
- The clean-env harness and PR-07 tests both execute generated starters successfully.

#### Gaps

- Release docs around this work are stale or wrong. `README.md:52-60`, `PROJECT.md:32-35`, and `docs/reference/WORKFLOW_QUICKSTART.md:7-15` still point users to `feat/v0.9-07-beta-proof`, not local `develop`.
- `docs/reference/WORKFLOW_CLI.md:22-85` documents invalid starter command flags and examples.
- The PR-05 truth gate currently fails because `implementation_status.md` drifted, even though the starter code itself is present.

#### Verdict

- COMPLETE

### PR-06 — Doctor and lint

#### What was expected

- `aigc workflow lint` should cover schema, transitions, bindings, budgets, starter integrity, and public-import safety.
- `aigc workflow doctor` should cover runtime/evidence diagnosis.
- Stable reason codes and next-action guidance should make first failures understandable.

#### What exists in local `develop`

- Both CLI commands exist.
- Stable reason codes and next-action mapping exist.
- Policy, starter directory, workflow artifact, and audit artifact targets are supported.
- The actual semantic coverage is narrower than the PR-06 contract claims.

#### Evidence

- CLI surface exists in `aigc/_internal/cli.py:484-529`, with `--kind` and `--json` support for both commands.
- Stable next-action registry is centralized in `aigc/_internal/workflow_doctor.py:49-112`.
- Policy lint covers file readability, YAML parse, root type, JSON schema validation, date inversion, duplicate tool names, and output-schema validity in `aigc/_internal/workflow_lint.py:126-233`.
- Starter lint only checks required files, non-empty files, nested policy lint, AST parse, and `_internal` imports in `aigc/_internal/workflow_lint.py:245-321`.
- Starter doctor is pattern-based: it infers approval and source-required advisories by regex-scanning `workflow_example.py` in `aigc/_internal/workflow_doctor.py:326-391`.

#### Gaps

- `workflow lint` does not statically validate workflow transitions, workflow budgets, or binding semantics despite the PR-06 contract and `RELEASE_GATES.md:174-177`.
- `workflow doctor` does not actually diagnose a broken starter directory by executing or inspecting the broken delta; it mostly promotes lint results and adds heuristics.
- `docs/reference/TROUBLESHOOTING.md` materially misdescribes behavior: advisory exit codes at `32-34`, nonexistent exceptions at `59-60` and `105-106`, nonexistent starter checksum validation at `141-143`, wrong starter directory names at `199-202` and `237-239`, and inaccurate sample output at `245-249`.

#### Verdict

- PARTIAL

### PR-07 — Beta proof

#### What was expected

- Mandatory stop-ship proof for clean install, first PASS, intentional failure, diagnosis, fix, rerun, and demo parity.
- The default path must succeed without Bedrock or A2A.
- No internal-code reading required.
- No fake backend behavior in the demo.

#### What exists in local `develop`

- A clean-env harness exists and passes locally.
- Proof tests exist and pass locally.
- The happy path is real for minimal and standard starters.
- The failure-and-fix proof is not a faithful proof of the actual adopted asset.

#### Evidence

- `scripts/validate_v090_beta_proof.py` creates a fresh venv, installs the repo editably, and runs minimal, standard, failure, diagnosis, and fix gates in `139-352`; the script passed locally.
- `tests/test_pr07_beta_proof.py` exists and passed in the full suite.
- `pytest demo-app-api/tests -q` passed `55` tests; `npm --prefix demo-app-react test` passed `97` tests; `npm --prefix demo-app-react run build` passed.
- The React workflow lab exposes four tabs at `demo-app-react/src/labs/Lab11WorkflowLab.tsx:54-60`, broadly matching the PR-07 exit-gate shape.

#### Gaps

- The failure path in the clean-env harness is synthetic. `scripts/validate_v090_beta_proof.py:276-307` writes a separate `run_broken.py` helper outside the generated starter; `314-326` then runs `workflow doctor` on the untouched starter directory; `333-345` reruns the untouched generated `run_regulated_workflow`.
- The test file repeats the same synthetic structure. `tests/test_pr07_beta_proof.py:143-172` creates a manual failure path against the policy file, `197-213` runs doctor on the unmodified starter directory, and `228-234` reruns the original unmodified starter.
- The demo route violates the “no fake backend behavior” release rule. `demo-app-api/workflow_routes.py:180-199` explicitly creates a minimal fake starter directory so doctor can detect `WORKFLOW_SOURCE_REQUIRED` by pattern scan.
- `RELEASE_GATES.md:181-186` claims the failure-and-fix path is validated and that no fake backend behavior exists, but the implementation evidence above does not support those claims.
- `RELEASE_GATES.md:122-135` claims the full suite passes, but `python -m pytest` and `python scripts/check_doc_parity.py` currently fail.

#### Verdict

- BLOCKED

### PR-08 — Engine hardening

#### What was expected

- Harden sequencing, approvals, budgets, transitions, handoffs, protocol constraints, and validator hooks.
- Reject widening policy merges.
- Preserve fail-closed behavior and host-owned orchestration boundaries.
- Keep hardening disciplined instead of turning into scope creep.

#### What exists in local `develop`

- Restrictive composition is extensive and fail-closed.
- Session-time hardening for transitions, budgets, handoffs, and protocol evidence is real.
- Hook dispatch code exists with evidence capture and fail-closed outcomes, but there is no supported runtime path that actually registers hooks.
- The hardening is disciplined in code, but its public/contract narration and public exception surface are inconsistent.

#### Evidence

- Restrictive composition is extensive in `aigc/_internal/policy_loader.py:299-531`: max steps, total tool calls, participants, roles, protocols, manifest refs, sequence, allowed transitions, handoffs, escalation, and protocol constraints all reject widening merges.
- Session-time hardening is real in `aigc/_internal/session.py:680-919`: protocol evidence checks, Bedrock alias-backed requirement, A2A `protocolVersion == "1.0"` requirement, gRPC rejection, tool-budget enforcement, and fail-closed validator hook invocation.
- Workflow artifacts now record `approval_checkpoints` and `validator_hook_evidence` in `aigc/_internal/session.py:474-489`.
- The hardening test surface is substantial: `tests/test_engine_hardening.py`, `tests/test_approval_checkpoints.py`, `tests/test_budget_accounting.py`, `tests/test_protocol_enforcement.py`, and `tests/test_validator_hook.py`.
- The actual runtime never populates hooks through a supported path. `GovernanceSession.__init__` hard-sets `self._validator_hooks = []` in `aigc/_internal/session.py:168-171`; `AIGC.__init__` has no `validator_hooks` parameter in `aigc/_internal/enforcement.py:2318-2329`; and `AIGC.open_session()` passes no hook list in `aigc/_internal/enforcement.py:2385-2403`.
- The only observed hook injection path is private-field mutation in tests: `tests/test_validator_hook.py:296-306` constructs `GovernanceSession` directly from `_internal` and sets `session._validator_hooks = list(hooks)`.
- Eight workflow exceptions raised from public session methods are absent from both the public package root and `aigc.errors`. Local repro showed `hasattr(aigc, name) == False` and `hasattr(aigc.errors, name) == False` for `WorkflowParticipantMismatchError`, `WorkflowSequenceViolationError`, `WorkflowTransitionDeniedError`, `WorkflowRoleViolationError`, `WorkflowProtocolViolationError`, `WorkflowHandoffDeniedError`, `WorkflowStepBudgetExceededError`, and `WorkflowHookDeniedError`; compare `aigc/errors.py:1-47`, `aigc/__init__.py:102-180`, and the corresponding raises in `aigc/_internal/session.py:554-772,877-919`.
- Failed Phase B cleanup semantics are inconsistent. `tests/test_session_core.py:103-116` intentionally preserves retryability for output-serializability failures, but local repro against schema-validation failure showed the session token remained in `_pending_results` while the inner `PreCallResult` had already been consumed by `aigc/_internal/enforcement.py:1840-1846`, leaving a dead pending token that cannot complete successfully on retry.

#### Gaps

- The public-surface story is inconsistent. `CLAUDE.md:117-123` treats more of the workflow surface as v0.9.0 additions, while `docs/PUBLIC_INTEGRATION_CONTRACT.md:28-32` and `docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md:619-628` still say `ValidatorHook`, adapters, and even workflow CLI commands remain planned-only beyond the beta line.
- `tests/test_validator_hook.py:15-43` explicitly freezes `ValidatorHook` as internal-only and absent from public constructors. That is coherent with the code, but not with all release-story docs.
- The hook path is effectively dead in product code. PR-08 added dispatch logic in `aigc/_internal/session.py:869-919`, but commit `72430fe` removed the constructor hook parameter and replaced it with `self._validator_hooks = []`, while no alternative runtime injection path was added.
- Public exception hygiene is incomplete. Public workflow methods can raise the eight PR-08 workflow exceptions above, but callers must either catch broad base classes or import `_internal` names, which violates the release-contract requirement that public surfaces be consumable through public APIs only.
- Failed Phase B attempts leave inconsistent token cleanup depending on failure class. That does not currently reproduce as double step completion, but it does leave dead pending tokens for some error paths and makes retry semantics hard to reason about.
- This is not uncontrolled scope creep in code, but it is uncontrolled scope narration in docs, which is a release-contract problem.

#### Verdict

- PARTIAL

## End-to-End First-Adopter Journey Assessment

1. Install package in a clean environment: PARTIAL. `scripts/validate_v090_beta_proof.py` creates a fresh venv and installs the repo editably, and this passed. But it uses `system_site_packages=True` and `--no-deps --no-build-isolation`, so it is weaker than a fully dependency-isolated first-user install proof.
2. Run `aigc workflow init`: PASS. The real CLI exists and generated minimal, standard, and regulated starters in both tests and the harness.
3. Choose minimal or standard starter: PASS. Both are real, run locally, and reached `COMPLETED`.
4. Drop into a simple host-owned workflow: PASS. The starter/demo flows keep orchestration and model-call simulation in host code, not in AIGC.
5. Reach first PASS: PASS. Minimal and standard starters do this.
6. Inspect trace/evidence: PARTIAL. Users can inspect workflow artifacts and correlated invocation checksums, and the React lab has an “Evidence View” tab at `demo-app-react/src/labs/Lab11WorkflowLab.tsx:429-464`. But there is no dedicated `workflow trace` surface, no `workflow export`, and the stop-ship packet is contradictory about whether that visibility is required now or later.
7. Hit one understandable failure: PASS. The regulated provenance requirement produces a real `CustomGateViolationError`.
8. Use `workflow doctor` or `workflow lint`: PARTIAL. `workflow doctor` returns understandable codes, but the PR-07 proof only uses starter-pattern detection; `workflow lint` is not exercised in the proof and its semantic coverage is narrower than promised.
9. Fix and rerun successfully: FAIL as a proof claim. The beta proof does not fix and rerun the broken starter; it reruns the original working starter.

Overall assessment:

- The happy path is real.
- The failure-and-fix story is only partially real and not credibly proven.
- The default adopter path is not strong enough yet for the intended `v0.9.0` beta story because PR-07 is mandatory and not truly satisfied.

## Architectural Invariant Compliance Review

- Fail-closed behavior is preserved in code. Session tokens are guarded in `aigc/_internal/enforcement.py:1587-1608`; protocol and hook failures raise typed workflow errors in `aigc/_internal/session.py:680-919`; widening composition is rejected in `aigc/_internal/policy_loader.py:299-531`.
- Deterministic governance boundary and host ownership are preserved. The host still owns orchestration and model-call behavior, while AIGC owns policy loading and governance checks; demo code reflects this split in `demo-app-api/workflow_routes.py:73-75,83-99`.
- One artifact per invocation attempt with separate workflow evidence is preserved. Workflow artifacts serialize separately and reference invocation checksums rather than collapsing models into one artifact in `aigc/_internal/session.py:474-489`.
- Public API boundary discipline is mostly preserved in code. Public docs/examples/demos do not import `aigc._internal`, and starter lint enforces that in `aigc/_internal/workflow_lint.py:311-320`.
- Public exception boundary discipline is not fully preserved. Several workflow-specific exceptions are raised from public session methods but are not re-exported from `aigc` or `aigc.errors`, forcing callers toward broad base-class catches or `_internal` imports.
- Workflow support does not collapse into platform ownership. No hosted runtime, transport ownership, retry ownership, or credential ownership moved into AIGC.
- Split versus unified enforcement discipline is preserved. Session flow builds on invocation governance rather than bypassing it.
- The main invariant-adjacent concern is demo/proof credibility, not the enforcement core. `demo-app-api/workflow_routes.py:180-199` fabricates a starter directory for doctor, which does not violate the runtime invariants but does violate the release rule that the demo should not fake the beta proof path.

## Docs / Code / Release-Packet Alignment Review

- Conflicting source-of-truth documents:
- `docs/dev/pr_context.md` header/status say PR-08 complete and PR-09 next, but the body is still a PR-07 packet.
- `implementation_status.md` simultaneously says PR-07 is complete, unchecked, and checked.
- `RELEASE_GATES.md` claims green PR-07 proof and full-suite pass while repo-local validation disagrees.
- Docs ahead of implementation:
- The canonical plan and HLD freeze `workflow trace` and `workflow export` as part of the PR-03 beta CLI contract in `docs/plans/AIGC V0.9.0 IMPLEMENTATION_PLAN.md:385-392` and `docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md:667-675`, but the real CLI does not ship them in `aigc/_internal/cli.py:453-529`.
- `CLAUDE.md:19-20` still demands a trace view and audit/export visibility flow for the beta demo.
- Implementation ahead of docs:
- Engine hardening and internal `ValidatorHook` logic exist in code in `aigc/_internal/session.py:865-919`, but `docs/PUBLIC_INTEGRATION_CONTRACT.md:28-32` and `docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md:619-628` still call those planned-only beyond the beta line.
- Stale or misleading onboarding:
- `README.md:52-60`, `PROJECT.md:32-35`, and `docs/reference/WORKFLOW_QUICKSTART.md:7-15` still direct users to the `feat/v0.9-07-beta-proof` branch instead of local `develop`.
- `docs/reference/WORKFLOW_CLI.md:22-85` documents invalid command shapes such as `aigc policy init` without `--profile` and `aigc workflow init --output` instead of `--output-dir`.
- `docs/reference/TROUBLESHOOTING.md:59-60` and `105-106` reference nonexistent exception types; `141-143` describes nonexistent starter checksum validation; `245-249` shows output formatting that the CLI does not emit.
- `docs/reference/OPERATIONS_RUNBOOK.md:82-89` falsely says the beta proof script exercises `workflow lint` and all golden-replay tests.
- Public surface and release metadata mismatches:
- `pyproject.toml:8-25` and `aigc/__init__.py:100` still identify the package as `0.3.3` alpha, while multiple docs speak about a `v0.9.0` beta line available from source. That may be intentional pre-release behavior, but it is not explained cleanly in one place.
- `CHANGELOG.md` has no `v0.9.0` beta section at all; the latest recorded release is still `0.3.3`.
- Demo guidance drift:
- `README.md:198-206` still frames the maintained demo as the `v0.3.x` 7-lab surface even though the repo now also contains workflow beta demo code in `demo-app-react/src/labs/Lab11WorkflowLab.tsx` and `demo-app-api/workflow_routes.py`.

## Testability and Verification Gaps

- The PR-07 harness does not verify a real broken-starter edit, diagnosis, repair, and rerun cycle.
- The clean-env proof reuses host site-packages, so it is weaker than a fully isolated dependency-resolution proof.
- PR-03 sentinel tests do not enforce the full frozen CLI inventory or help-text contract.
- PR-06 tests do not prove static lint coverage for workflow transitions, protocol bindings, or workflow budgets.
- The stop-ship packet claims full-suite success even though one release-truth test currently fails; that means the release gate can be green while the repo is red.

## Actionable Remediation Plan

### Critical

1. Reconcile the release-truth packet and restore parity green.
PR: PR-01, PR-03, PR-07
Why it matters: Beta stop-ship decisions are currently based on contradictory documents, and the repo fails its own truth-check test.
Likely files to change: `docs/dev/pr_context.md`, `implementation_status.md`, `RELEASE_GATES.md`, `docs/plans/AIGC V0.9.0 IMPLEMENTATION_PLAN.md`, `CLAUDE.md`, `docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md`, `docs/PUBLIC_INTEGRATION_CONTRACT.md`
How to verify: `python scripts/check_doc_parity.py`; `python -m pytest tests/test_v090_contract_freeze.py -q`; manual grep confirms one consistent answer for PR-07/PR-08 status, CLI inventory, stop-ship gates, and shipped/planned surfaces.
Blocks beta readiness: YES

2. Replace the synthetic PR-07 proof with a real broken-asset diagnose-edit-rerun proof.
PR: PR-07
Why it matters: PR-07 is mandatory stop-ship. Today’s proof does not prove that a first adopter can repair the actual starter they broke.
Likely files to change: `scripts/validate_v090_beta_proof.py`, `tests/test_pr07_beta_proof.py`, `demo-app-api/workflow_routes.py`, `docs/reference/TROUBLESHOOTING.md`, `docs/reference/OPERATIONS_RUNBOOK.md`
How to verify: In a fresh generated regulated starter, remove `source_ids` in `workflow_example.py`, run it and observe failure, run `aigc workflow doctor` against that same directory, apply the documented fix to that same file, rerun the same directory to `COMPLETED`, and ensure demo/tests/harness all use the same path.
Blocks beta readiness: YES

### High

1. Freeze one coherent CLI contract for the beta and update docs/tests accordingly.
PR: PR-03, PR-07
Why it matters: App teams cannot trust onboarding when the plan, HLD, collaborator contract, CLI reference, and actual CLI disagree about shipped commands.
Likely files to change: `docs/plans/AIGC V0.9.0 IMPLEMENTATION_PLAN.md`, `CLAUDE.md`, `docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md`, `docs/reference/WORKFLOW_CLI.md`, `README.md`, `tests/test_v090_contract_freeze.py`
How to verify: `python -m aigc workflow --help`; `python -m aigc workflow trace --help`; `python -m aigc workflow export --help`; every documented CLI example runs exactly as written.
Blocks beta readiness: YES

2. Either deepen `workflow lint` and `workflow doctor` to meet the PR-06 contract or narrow the contract to what is actually shipped.
PR: PR-06
Why it matters: The beta story promises understandable first failures. Static lint currently misses several classes it claims to cover.
Likely files to change: `aigc/_internal/workflow_lint.py`, `aigc/_internal/workflow_doctor.py`, `tests/test_workflow_lint.py`, `tests/test_workflow_doctor.py`, `docs/reference/TROUBLESHOOTING.md`
How to verify: Add targeted fixtures for invalid transitions, unsupported bindings, workflow budget violations, and broken starter states; assert stable reason codes and next actions from both CLI and direct function tests.
Blocks beta readiness: YES unless the public contract is narrowed first

3. Resolve the `ValidatorHook` and adapter shipped-vs-planned story.
PR: PR-08
Why it matters: The code and tests treat hooks as internal, while several source-of-truth docs imply broader beta scope. That is a public contract ambiguity.
Likely files to change: `CLAUDE.md`, `docs/PUBLIC_INTEGRATION_CONTRACT.md`, `docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md`, `implementation_status.md`, possibly `tests/test_validator_hook.py` if the decision changes
How to verify: `rg "ValidatorHook|BedrockTraceAdapter|A2AAdapter" docs README.md PROJECT.md tests`; all surviving references agree on whether each surface is internal-only, beta, or later.
Blocks beta readiness: YES

4. Decide whether `ValidatorHook` is a real beta capability or dead internal code, then make the runtime match that decision.
PR: PR-08
Why it matters: The current session hook loop is unreachable outside tests because no supported runtime path populates `_validator_hooks`.
Likely files to change: `aigc/_internal/enforcement.py`, `aigc/_internal/session.py`, `tests/test_validator_hook.py`, `docs/PUBLIC_INTEGRATION_CONTRACT.md`, `docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md`
How to verify: Either a supported non-`_internal` configuration path exists and a black-box integration test proves hook invocation through ordinary session creation, or the dead path and related claims/tests are removed and the docs clearly mark hooks as unshipped.
Blocks beta readiness: YES

5. Export or normalize workflow exceptions raised from public session methods.
PR: PR-08
Why it matters: App teams should be able to catch public runtime failures without importing `aigc._internal`.
Likely files to change: `aigc/errors.py`, `aigc/__init__.py`, `aigc/_internal/session.py`, `tests/test_v090_contract_freeze.py`, new public-surface tests
How to verify: `python -c "import aigc, aigc.errors as e; print(hasattr(aigc, 'WorkflowSequenceViolationError'), hasattr(e, 'WorkflowSequenceViolationError'))"`; add one black-box test per exported or normalized public failure family.
Blocks beta readiness: YES

6. Resolve the trace/evidence visibility stop-ship requirement.
PR: PR-03, PR-07, PR-09 leakage
Why it matters: The stop-ship gate currently requires trace/evidence visibility, but the beta contract also says trace/export are PR-09. The user story is undecidable until one of those statements changes.
Likely files to change: `docs/plans/AIGC V0.9.0 IMPLEMENTATION_PLAN.md`, `CLAUDE.md`, `RELEASE_GATES.md`, `demo-app-react/src/labs/Lab11WorkflowLab.tsx`, optionally future PR-09 code if minimal trace support is pulled forward
How to verify: Either the beta gate no longer requires a trace/export surface before PR-09, or a tested trace/evidence surface exists and is linked from quickstart/demo docs.
Blocks beta readiness: YES

### Medium

1. Refresh beta onboarding to point at the real branch/state and real command syntax.
PR: PR-05, PR-07
Why it matters: The implementation is usable, but first adopters will follow stale branch instructions and invalid CLI examples.
Likely files to change: `README.md`, `PROJECT.md`, `docs/reference/WORKFLOW_QUICKSTART.md`, `docs/reference/WORKFLOW_CLI.md`, `docs/reference/TROUBLESHOOTING.md`
How to verify: Follow the docs verbatim in a fresh checkout of local `develop`; no manual correction should be needed.
Blocks beta readiness: NO if fixed alongside the critical items, but it materially weakens the beta story until then

2. Decide how the unreleased beta line should be represented in package metadata and changelog.
PR: PR-07, PR-11
Why it matters: The repo currently speaks about a beta line while package metadata still advertises `0.3.3` alpha and the changelog does not mention the beta track.
Likely files to change: `pyproject.toml`, `aigc/__init__.py`, `CHANGELOG.md`, `README.md`
How to verify: `python -c "import aigc; print(aigc.__version__)"`; inspect `pip show` metadata from an editable install; confirm docs explain whether the mismatch is intentional pre-release state or an oversight.
Blocks beta readiness: NO for local-source adoption, YES for any public beta artifact or published announcement

3. Normalize failed Phase B token cleanup semantics and add black-box retry tests.
PR: PR-08
Why it matters: Some post-call failures leave dead pending tokens while others remain retryable. That is not currently proven to double-complete a step, but it leaves session state harder to reason about and harder to diagnose.
Likely files to change: `aigc/_internal/session.py`, `aigc/_internal/enforcement.py`, `tests/test_session_core.py`, new workflow-session failure-path tests
How to verify: Add targeted tests for output-serializability failure, schema-validation failure, and hook-denied failure that assert `_pending_results`, consumed state, retry behavior, and step/sequence counters are all consistent with the intended contract.
Blocks beta readiness: NO unless the chosen contract is user-visible and undocumented

## Suggested Next Moves

- Stop PR-09 work until PR-01 and PR-07 are repaired. The current repo state does not justify moving past the mandatory stop-ship checkpoint.
- Pick one release story and encode it everywhere: either `v0.9.0` beta excludes trace/export and public validator hooks, or it includes them. The current mixed story is the main source of drift.
- After the docs/contract/proof fixes land, rerun the exact release gate set and only reassess readiness once `python -m pytest`, `flake8 aigc`, `python scripts/check_doc_parity.py`, `pytest demo-app-api/tests -q`, `npm --prefix demo-app-react test`, and `npm --prefix demo-app-react run build` are all green.

## Appendix — Commands Run

- `git branch --show-current` -> `develop`
- `git status --short` -> unrelated untracked `docs/plans/v0.9.0_PR-07_BETA_PROOF_PLAN.md`
- `rg "workflow init|workflow lint|workflow doctor|workflow trace|open_session|GovernanceSession|SessionPreCallResult|AgentIdentity|AgentCapabilityManifest|ValidatorHook|BedrockTraceAdapter|A2AAdapter" .`
- `rg "aigc\\._internal" README.md PROJECT.md docs examples demo-app-react demo-app-api` -> no maintained public example/demo imports from `aigc._internal`
- `python -m pytest` -> `1361` passed, `1` failed; failing test: `tests/test_v090_contract_freeze.py::test_v090_pr05_contract_truth_passes_for_repo`
- `flake8 aigc` -> passed
- `python scripts/check_doc_parity.py` -> failed in the `v0.9.0-pr05` truth check against `implementation_status.md`
- `python scripts/validate_v090_beta_proof.py` -> passed all six gates: `venv_install`, `minimal_quickstart`, `standard_quickstart`, `regulated_failure`, `doctor_diagnosis`, `regulated_fix_rerun`
- `pytest demo-app-api/tests -q` -> `55` passed
- `npm --prefix demo-app-react test` -> `97` passed
- `npm --prefix demo-app-react run build` -> passed
- `python -m aigc workflow --help` -> only `init`, `lint`, and `doctor` subcommands are present
- `python -m aigc workflow trace --help` -> invalid subcommand
- `python -m aigc workflow export --help` -> invalid subcommand
- `python -m aigc policy init --help`
- `python -m aigc workflow lint --help`
- `python -m aigc workflow doctor --help`

## Appendix — Key Files Reviewed

- `docs/plans/AIGC V0.9.0 IMPLEMENTATION_PLAN.md`
- `docs/plans/AIGC V0.9.0 IMPLEMENTATION_PLAN_DRAFT.md`
- `docs/plans/AIGC_v0.9.0_IMPLEMENTATION_PLAN_UPDATED.md`
- `docs/plans/0.9.0 plan backup.md`
- `docs/dev/pr_context.md`
- `implementation_status.md`
- `RELEASE_GATES.md`
- `CLAUDE.md`
- `docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md`
- `docs/architecture/ARCHITECTURAL_INVARIANTS.md`
- `docs/architecture/ENFORCEMENT_PIPELINE.md`
- `docs/PUBLIC_INTEGRATION_CONTRACT.md`
- `docs/reference/WORKFLOW_QUICKSTART.md`
- `docs/reference/WORKFLOW_CLI.md`
- `docs/reference/TROUBLESHOOTING.md`
- `docs/reference/OPERATIONS_RUNBOOK.md`
- `README.md`
- `PROJECT.md`
- `CHANGELOG.md`
- `doc_parity_manifest.yaml`
- `pyproject.toml`
- `aigc/__init__.py`
- `aigc/_internal/cli.py`
- `aigc/_internal/enforcement.py`
- `aigc/_internal/session.py`
- `aigc/_internal/policy_loader.py`
- `aigc/_internal/workflow_init.py`
- `aigc/_internal/policy_init.py`
- `aigc/_internal/starter_templates.py`
- `aigc/_internal/workflow_lint.py`
- `aigc/_internal/workflow_doctor.py`
- `aigc/_internal/validator_hook.py`
- `scripts/check_doc_parity.py`
- `scripts/validate_v090_beta_proof.py`
- `demo-app-api/workflow_routes.py`
- `demo-app-react/src/labs/Lab11WorkflowLab.tsx`
- `tests/test_v090_contract_freeze.py`
- `tests/test_governance_session.py`
- `tests/test_session_core.py`
- `tests/test_starter_smoke.py`
- `tests/test_migration_smoke.py`
- `tests/test_pr07_beta_proof.py`
- `tests/test_workflow_lint.py`
- `tests/test_workflow_doctor.py`
- `tests/test_engine_hardening.py`
- `tests/test_approval_checkpoints.py`
- `tests/test_budget_accounting.py`
- `tests/test_protocol_enforcement.py`
- `tests/test_validator_hook.py`
