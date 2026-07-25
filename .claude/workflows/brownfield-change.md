# Brownfield Change Workflow

## Entry criteria

- Use when changing an existing system whose specification is incomplete,
  contradicted by implementation, or materially constrained by existing consumers.
- Treat specifications as intended behavior and code, tests, stored data,
  telemetry, operations, and consumers as actual behavior evidence.
- Do not label current behavior correct merely because it exists.

## Artifacts

- Actual-behavior discovery record, consumer inventory, characterization tests,
  reconciled specification, migration/deprecation plan, implementation, and review.
- Data and telemetry evidence with provenance and an explicit statement of gaps.

## Gates

- Material existing behavior is characterized before it is changed.
- Consumer impact covers internal/external clients, persisted data, integrations,
  operational processes, support expectations, and public contracts.
- Spec reconciliation explicitly preserves, changes, deprecates, or rejects each
  discovered divergence; accidental behavior receives no silent guarantee.
- Breaking changes require migration and deprecation evidence and applicable
  authority before implementation/release.

## Ordered steps

1. Define the requested outcome and the system boundary to discover. Record the
   base commit, deployed versions if known, environments, and evidence limits.
2. Discover actual behavior from implementation, tests, schemas, stored-data
   shapes, telemetry, incidents, runbooks, support history, and consumer usage.
3. Add characterization tests around material actual behavior, including failure
   and compatibility cases. Record behavior that cannot be reproduced locally.
4. Inventory consumer impact: callers, events, jobs, data readers/writers,
   operators, integrations, documented contracts, and implied support windows.
5. Compare actual behavior, intended specification, and request. Resolve
   inferable discrepancies; escalate materially different business behavior.
6. Reconcile the spec by labeling behavior preserved, corrected, newly intended,
   deprecated, or unsupported, with evidence and acceptance criteria.
7. Extract final facts and evaluate risk, authority, routes, and lifecycle path.
   Treat missing telemetry or data evidence as unknown, not reassuring absence.
8. Design migration and deprecation for affected consumers/data: compatibility
   window, sequencing, observability, rollback, communication, and removal criteria.
9. Implement test-first against characterized and reconciled behavior, then run
   compatibility, migration, operational, and configured test suites.
10. Review consumer/data/telemetry impact, repair findings, refresh hashes, and
    converge through the selected code, release, or deployment path.

## Evidence

- Discovery sources and timestamps, characterization tests, actual-versus-intended
  table, consumer inventory, telemetry/data evidence, spec reconciliation,
  migration/deprecation plan, tests, risk, authority, and hashes.
- Explicitly mark evidence gaps and confidence. Never convert absence of telemetry
  into evidence that no consumer depends on behavior.

## Exit criteria

- The specification explains every material discovered divergence and the final
  behavior is protected by current tests.
- Consumers, data, migration, deprecation, observability, and rollback are
  addressed proportionally to risk.
- The final change follows an authorized lifecycle path without inventing a
  compatibility claim.

## Solo mode

A solo owner may perform discovery and implementation, but must separate the
consumer/spec-convergence review from builder assumptions. Use repository and
runtime evidence to compensate for missing institutional memory.

## Stop/escalation conditions

- Stop in `BLOCKED_REQUIREMENT` when preserving versus changing observed behavior
  has materially different user, commercial, legal, data, or public consequences.
- Stop in `BLOCKED_TECHNICAL` when critical actual behavior cannot be observed
  within bounded effort; scope a safe probe or characterization alternative.
- Escalate irreversible migration, unknown material consumers, or authority
  beyond policy. A deadline is not permission to erase compatibility evidence.
