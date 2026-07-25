# Feature Development Workflow

## Entry criteria

- Use for new or materially changed product behavior after workflow selection
  determines that a feature artifact is required.
- Resolve the active feature from explicit intent and approved artifacts, not
  status alone. Start at `UNCLASSIFIED` with typed facts and provenance.
- The constitution and approved business intent are authoritative; implementation
  begins only after applicable specification gates pass.

## Artifacts

- Constitution check, feature specification, clarification record, plan,
  quality checklist, tasks, analysis result, instruction context, tests,
  implementation diff, review findings, repairs, and convergence evidence.
- Use the feature instruction context template for profile, modules, facts,
  risk, authority, hashes, lifecycle state, and exceptions.

## Gates

- Each lifecycle transition is requested from the engine with current evidence.
- Material acceptance criteria trace through plan, tasks, implementation, tests,
  and review. Activated modules and enhanced gates are mandatory.
- Clarifications are triaged as `inferable`, `reversible_default`, or
  `material_business`; the last category requires an escalation packet and a
  validated response.
- Repair and review remain within configured resource bounds.

## Ordered steps

1. Read the constitution. The agent extracts observable facts with provenance;
   the engine classifies and routes them. Validate context, run evaluation,
   load the returned profiles/modules/workflows, and transition to `CLASSIFIED`.
2. **Specify** user outcomes, acceptance criteria, boundaries, failure behavior,
   data use, operational consequences, and non-goals without choosing accidental
   implementation details. Transition to `SPECIFIED` when `spec_complete`.
3. **Clarify** each ambiguity using repository evidence first. Resolve inferable
   items with citations, apply a configured reversible default when safe, and
   send material business choices through a bounded escalation packet.
4. **Plan** the smallest reversible architecture and implementation approach,
   mapping every activated rule, readiness/data/control profile, migration,
   security, testing, release, and rollback concern. Update the context hashes.
5. Create and verify a **checklist** that tests specification quality and risk
   coverage rather than restating implementation tasks.
6. Create ordered **tasks** that trace to acceptance criteria, include tests
   before behavior, and identify safe checkpoints and rollback.
7. **Analyze** specification, plan, checklist, tasks, facts, and modules for
   contradictions, omissions, unsupported assumptions, and prohibited work.
8. **Implement** test-first: observe the relevant failure, make the smallest
   coherent change, and rerun affected validation. Record deviations immediately.
9. Run policy-activated review, repair every required finding, and repeat within
   resource limits. Reevaluate risk and authority whenever facts or scope change.
10. **Converge** by mapping final behavior and evidence back to the spec, running
    exact candidate checks, refreshing hashes, and following the selected code,
    release, or deployment terminal path.

## Evidence

- Current specification, clarification provenance, reversible defaults,
  decisions, acceptance mapping, plan/checklist/task links, test red/green
  observations, review findings, repairs, and final validation.
- Every decision carries policy, context, and change hashes; any changed hash
  invalidates the configured downstream work.

## Exit criteria

- The selected lifecycle path reaches `COMPLETE`, with intended behavior mapped
  to passing current evidence and no concealed material ambiguity.
- Risk, authority, routes, exceptions, and resource status match the final diff.
- Documentation and status state exactly what was built, not released, or
  deployed; a code-complete result does not imply publication.

## Solo mode

A solo owner may perform product, builder, reviewer, and operational roles when
policy permits. Separate review context from builder conclusions, use automated
gates, and activate specialized review only at the configured risk. Routine
second-human ceremony is not added.

## Stop/escalation conditions

- Stop in `BLOCKED_REQUIREMENT` when authoritative intent is absent and no safe
  reversible default exists.
- Enter `HUMAN_DECISION_REQUIRED` for a material business choice, sensitive data
  purpose, unbounded cost, critical residual risk, or other irreducible authority.
- Stop in `BLOCKED_POLICY` for a prohibited outcome or expired/invalid exception,
  and in `BLOCKED_TECHNICAL` after bounded retries are exhausted.
- If the final implementation cannot converge with the spec, return to the
  earliest invalid artifact; do not edit the spec merely to bless the code.
