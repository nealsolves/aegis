# Incident Hotfix Workflow

## Entry criteria

- Use for active or recently stabilized production harm requiring an urgent
  corrective change. Stabilize first; feature delivery and cleanup are secondary.
- Create or link an incident record, identify incident authority, and state which
  normal gates are reduced before any bypass occurs.
- Prefer rollback, traffic isolation, flag disablement, access revocation, or
  other bounded containment when safer than a code change.

## Artifacts

- Incident record, containment/stabilization evidence, reduced-gate decision,
  hotfix diff, focused tests, authority, deployment/rollback plan, monitoring,
  restoration checklist, and root-cause follow-up.
- Specification and regression-test updates that prevent recurrence.

## Gates

- Stabilize first and select the smallest safe change with the narrowest blast
  radius. An urgent deadline does not silently authorize destructive action.
- Reduced gates are explicit, named, time-bounded, authorized, and recorded; no
  silent bypass is permitted. Non-reduced safety and policy gates still apply.
- Deployment/rollback authority, monitoring, and verification criteria exist
  before external action. MVP records decisions but supplies no executor.
- A regression test and restoration of normal gates are required follow-up,
  even if they cannot precede emergency containment.

## Ordered steps

1. Declare the incident, owner, severity, affected services/users/data, timeline,
   and current production state. Protect evidence and communications.
2. Stabilize first using the safest reversible containment within authority.
   Observe results against explicit health and harm-reduction criteria.
3. If a hotfix is necessary, define the smallest safe change and exclusions.
   Avoid refactors, upgrades, and speculative improvements.
4. Extract facts, evaluate risk/authority, and record every reduced gate with
   rationale, scope, expiration, compensating evidence, and restoration owner.
5. Add the fastest credible failing regression test or focused reproduction.
   If impossible before containment, record the exact deferred test obligation.
6. Implement the minimal fix, run focused safety/security/data tests plus every
   gate that was not explicitly reduced, and conduct a fresh adversarial review.
7. Prepare deployment, rollback, monitoring, verification, and communication
   evidence. External execution remains separately configured Phase 2 work.
8. Observe the authorized action. On failure or new harm, trigger rollback and
   preserve the incident state; do not stack unreviewed fixes.
9. After recovery, restore all normal gates and permissions, revoke break-glass
   access, complete regression tests, and update affected specs and runbooks.
10. Perform root cause analysis, record contributing conditions and corrective
    actions, assign owners/dates, and validate that durable fixes follow normal flow.

## Evidence

- Incident timeline, impact, detection, containment, recovery, exact hotfix,
  reduced gates, authority, tests, reviews, deployment/rollback observations,
  monitoring, communications, and the three hashes.
- Root cause, contributors, corrective actions, regression tests, spec updates,
  normal-gate restoration, owners, and follow-up references.

## Exit criteria

- Production harm is stabilized/recovered, verification meets bounded criteria,
  and no temporary authority or reduced gate remains silently active.
- Incident record, regression proof, spec/runbook changes, root cause, and
  corrective work are complete or have owned dated follow-up.
- Lifecycle reflects actual state: rollback, incident, or complete—not optimism.

## Solo mode

A solo operator may hold incident, implementation, review, release, and operations
roles within policy. Use automation and a distinct adversarial pass where time
allows; never fabricate separation or waive an external segregation requirement.

## Stop/escalation conditions

- Escalate irreversible destructive production operations, critical residual
  security risk, sensitive-data exposure decisions, or authority outside policy.
- Enter `ROLLBACK_REQUIRED` when verification breaches rollback criteria and
  `BLOCKED_TECHNICAL` when bounded alternatives cannot stabilize the system.
- A prohibited action remains prohibited during an incident. If emergency
  authority is absent, emit a precise decision packet rather than an open request.
