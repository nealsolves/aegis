# Architecture Rules

## Purpose

Keep structural decisions simple, compatible, reversible, and explicit enough
for implementers and operators to understand their consequences.

## Applicability

Applies to new services or modules, boundary changes, infrastructure changes,
public contracts, storage models, major dependencies, scaling decisions, and
brownfield changes with material structural impact.

## Required inputs

- Approved requirements, current system and consumer behavior, constraints,
  dependency/data flows, deployment topology, capacity signals, and cost limits.
- Existing architecture decisions, contracts, version policy, and evaluated
  facts/risk/authority.

## Mandatory controls

- Use ADR triggers for decisions that are costly to reverse, establish a new
  pattern, add a core technology, change a public boundary, or reject a viable
  alternative. Routine local details need no ADR.
- Prefer simplicity: the least complex design that satisfies current evidence,
  explicit quality attributes, and a credible near-term change path.
- Make technology selection and the buy, build, or adopt choice from fit,
  security, operability, maintainability, ecosystem, licensing, cost, exit path,
  and repository competence—not novelty.
- Define service, module, and data boundaries with ownership and invariants.
  Keep dependency direction explicit and prevent cycles or hidden shared state.
- Preserve API and event compatibility with explicit versioning, deprecation,
  consumer analysis, schema evolution, and mixed-version behavior.
- Analyze failure modes, timeouts, retries, idempotence, degradation, and
  resilience. Avoid retries that amplify overload or duplicate side effects.
- Use measured capacity and cost assumptions. Record traffic, data growth,
  latency, resource, and financial bounds for decisions that depend on them.
- Design for reversibility through flags, adapters, migration phases, rollback,
  or a bounded forward-fix; escalate irreversible material architecture choices.
- Perform brownfield reconciliation across approved intent, code, contracts,
  stored data, consumers, tests, and telemetry before declaring legacy behavior
  wrong.
- Apply diagram proportionality: use a diagram when it clarifies three or more
  boundaries, flows, states, or ownership relationships; keep simple decisions
  in concise prose.

## Evidence

Record the selected design, ADR when triggered, alternatives and consequences,
boundary/flow or dependency evidence, compatibility analysis, failure and
capacity assumptions, cost bounds, and reversal/migration strategy.

## Exceptions

An architectural exception must name the violated constraint, reason, scope,
temporary owner, expiry, compensating control, and exit plan. Material business
intent, public behavior, or irreversible architecture cannot be chosen through
a low-level engineering exception.

## Solo interpretation

A solo owner may make policy-bounded architectural decisions autonomously and
record the evidence once. Use a distinct challenge pass for high-risk decisions;
do not manufacture an approver ceremony where policy grants authority.

## Overlay notes

Security, data, production, regulated, team, or cost overlays may impose
boundaries, technology constraints, approval roles, or retention requirements.
Reconcile them by authority precedence and deny-overrides.

## Completion checklist

- [ ] ADR triggers and alternatives were assessed proportionally.
- [ ] Boundaries, compatibility, dependency direction, and failure modes are
  explicit.
- [ ] Capacity, cost, and reversibility evidence support the decision.
- [ ] Brownfield behavior and overlays were reconciled.
