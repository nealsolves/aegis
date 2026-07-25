# Instruction-System Change Workflow

## Entry criteria

- Use when a diff changes `CLAUDE.md`, `.claude/*.yaml`,
  `.claude/schemas/`, `.claude/rules/`, `.claude/workflows/`,
  `.claude/profiles/`, `.claude/templates/`, the policy engine, or validators.
- Set `instruction_system_change: true` with diff evidence before evaluation.
- Only the explicitly recorded bootstrap installation may use bootstrap
  authority. After bootstrap, the policy outcome is `human_required` at every
  risk tier.

## Artifacts

- Proposed instruction-system diff and a stable change ID.
- Before and after validation results, changed decision fixtures, and
  control-plane version assessment.
- An optional manual before/after inventory may accompany the record as
  advisory evidence; it is not an automated authorization result.
- Decision packet and authorized response for any post-bootstrap change.

## Gates

- The prior trusted policy at the branch base evaluates the proposed change.
  The proposed policy cannot authorize itself or redefine the evaluator used to
  approve that same revision.
- Both before and after versions must be independently schema-valid and
  internally consistent.
- Automated sensitive-weakening comparison is Phase 2. It is not a
  deterministic MVP gate, and absence of an advisory inventory cannot block or
  grant engine authorization.
- A changed control-plane decision requires a regression fixture. A compatible
  control-plane version increment records the behavior change in
  `control_plane_version`; an
  incompatible schema contract also requires an explicit migration decision.

## Ordered steps

1. Resolve the branch-base commit and load its kernel, four controls, schemas,
   engine, and validators as the prior trusted policy. Record its policy hash.
2. Inventory changed kernel, control, schema, module, engine, validator, and
   test files. If any are present, set the instruction-system fact true.
3. Validate the prior trusted revision without using proposed code or policy.
   If the trusted revision cannot evaluate, stop; do not substitute the proposal.
4. Validate the proposed revision separately and record before and after output.
5. Optionally inventory apparent widenings, narrowings, default changes,
   removed overrides, increased bounds, and newly enabled remote or production
   actions. Label this manual inventory advisory evidence, not a deterministic
   policy result; automated table-based comparison remains Phase 2.
6. Add or update regression fixtures for every changed policy decision and run
   the full policy suite under the intended runtime.
7. Assess schema-version and control-plane version impact. Increment
   `control_plane_version` whenever the accepted control-plane behavior changes;
   record why a documentation-only change does not require it.
8. Evaluate authorization using the prior trusted policy hash. After bootstrap,
   produce the exact `human_required` escalation packet and ingest a fresh,
   authorized response before proceeding.
9. Revalidate the proposed revision and rerun all affected fixtures after any
   response condition or repair. Record both `evaluated_by_policy_hash` and
   `proposed_policy_hash` in the change evidence.
10. Converge only when no proposed rule, code path, or version can provide its
    own approval and the final diff matches the reviewed hashes.

## Evidence

- Branch-base commit, `evaluated_by_policy_hash`, `proposed_policy_hash`,
  context hash, change hash, bootstrap status, and proposed control-plane version.
- Before/after validation, changed-decision regression fixture results,
  authority decision, escalation packet, and response when required. Any manual
  sensitive-change inventory is advisory evidence only.
- Reviewer findings must cite the exact control, decision, or executable path.

## Exit criteria

- Prior trusted policy authorized the final proposed hash, or the recorded
  bootstrap authority explicitly covers this installation.
- All changed decisions have passing fixtures; both revisions validate; required
  version increments and migrations are recorded; no self-authorization remains.
- Post-bootstrap human authority is fresh and scoped to the exact proposal.

## Solo mode

One owner may author and review the change, but cannot manufacture independent
authority. Use a separate adversarial pass against branch-base policy and a
bounded human decision record for post-bootstrap changes. Solo ownership does
not relax the `human_required` MVP outcome.

## Stop/escalation conditions

- Stop in `BLOCKED_POLICY` when the prior trusted policy prohibits the proposal
  or a higher-authority source cannot be satisfied.
- Stop in `BLOCKED_TECHNICAL` when either revision cannot be validated or the
  base revision cannot be reconstructed.
- Enter `HUMAN_DECISION_REQUIRED` for every post-bootstrap proposal.
- Reject a response if its policy, context, or change hash differs from the
  final proposal; reevaluate instead of resuming blindly.
