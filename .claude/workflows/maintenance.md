# Maintenance Workflow

## Entry criteria

- Use for documentation, formatting, rename, non-behavioral refactor, repository
  hygiene, or similarly bounded work that needs no feature specification.
- Assign a stable maintenance ID after workflow selection. Do not manufacture a
  feature directory merely to satisfy status conventions.
- If observable evidence shows behavior, dependency, security, data, public
  contract, or production impact, switch to the applicable workflow and full path.

## Artifacts

- Maintenance record with ID, type, scope, facts, behavior-impact statement,
  activated modules, risk, authority, hashes, validation, review, and rollback.
- Updated documentation or repository artifacts plus any link/check output.

## Gates

- The reduced lifecycle is `UNCLASSIFIED -> CLASSIFIED -> VALIDATING ->
  REVIEWING -> COMPLETE`; reduced overhead never means skipped validation or review.
- `documentation_only` or non-behavioral scope has repository evidence. Unknown
  material impact fails closed and activates the fuller workflow.
- Validation uses configured commands appropriate to changed artifacts and
  checks that references, formatting, or mechanical transformations are sound.

## Ordered steps

1. Create a maintenance ID and choose one change type: documentation, formatting,
   rename, non-behavioral refactor, hygiene, or another explicitly bounded type.
2. Define scope, exclusions, intended behavior impact, and rollback/reversal.
3. Extract observable facts with path/diff provenance. Validate and evaluate the
   maintenance context; load all always-on and additive modules.
4. If runtime behavior or a material boundary may change, reclassify and move to
   feature, bug-fix, dependency, brownfield, or instruction-system workflow.
5. Make the smallest coherent change, preserving generated-file and repository
   conventions. Do not mix unrelated maintenance into the ID.
6. Run relevant formatting, links, schema, documentation, build, or test checks
   that are configured; record why an application command is not applicable.
7. Review the diff for accidental behavior, broken references, stale status,
   generated drift, sensitive data, and rollback viability.
8. Repair findings, refresh the three hashes, transition through `VALIDATING`
   and `REVIEWING`, then record completion.

## Evidence

- Maintenance ID/type, scope, behavior-impact proof, typed facts, risk,
  authority, modules, validation commands/results, review evidence, rollback,
  policy hash, context hash, change hash, and pull request link when applicable.
- Use an explicit not-applicable entry instead of omitting a configured gate.

## Exit criteria

- Review confirms the bounded scope and no hidden behavior impact.
- Applicable validation passes and links/status are current.
- The maintenance terminal path reaches `COMPLETE` with a fillable maintenance
  record and no invented publication claim.

## Solo mode

A solo developer may execute and review maintenance in one working session.
Keep the review a distinct pass and retain the evidence record; no second-human
approval is added unless policy or an overlay requires it.

## Stop/escalation conditions

- Stop and reclassify when scope ceases to be non-behavioral or touches a routed
  security, data, dependency, production, or instruction-system boundary.
- Stop in `BLOCKED_TECHNICAL` when configured validation cannot run after bounded
  attempts, and in `BLOCKED_POLICY` when requested cleanup would bypass controls.
- Escalate only a material business or authority decision exposed by maintenance,
  not routine file placement or repository conventions.
