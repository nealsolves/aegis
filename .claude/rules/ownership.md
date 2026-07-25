# Ownership Rules

## Purpose

Assign decision and operational accountability while allowing policy-bounded
autonomy and a practical solo implementation.

## Applicability

Applies when role ownership affects requirements, architecture, review,
security, data, release, operations, risk, escalation, segregation, or external
obligations. It is routed directly for regulated scope and informs all profiles.

## Required inputs

- Base profile and overlays, named owner/escalation owner, repository authority,
  control mappings, target environments, risk tier, and decision type.
- Required separation or approval duties from law, contract, constitution, and
  regulated overlays.

## Mandatory controls

Assign the responsibilities, even when names repeat:

- The **product role** owns business intent, acceptance outcomes, priorities,
  and material requirement decisions.
- The **architecture role** owns structural decisions, boundaries, compatibility,
  and material tradeoffs.
- The **development role** owns implementation, local validation, traceability,
  repair, and accurate evidence.
- The **review role** challenges correctness, tests, spec alignment, and
  activated domain risks without inheriting builder conclusions.
- The **security role** owns threat/risk interpretation, findings, access, and
  residual-security escalation.
- The **data role** owns classification, purpose, privacy controls, retention,
  processors, and data-risk decisions.
- The **release role** owns candidate identity, readiness, publication authority,
  compatibility, rollback, and release evidence.
- The **operations role** owns production health, monitoring, response, recovery,
  runbooks, and decommissioning.
- The **risk role** owns risk acceptance within its delegated authority and
  routes decisions that exceed it.

Use these operating rules:

- Solo role collapse is allowed: one named person may hold all roles unless a
  higher-authority requirement forbids combination. Responsibilities and
  evidence do not disappear when roles collapse.
- Team separation should assign distinct owners and reviewers for high-risk
  paths, using path-sensitive review rather than requiring every person on every
  change.
- AI advisory status is explicit: agents and models may extract facts, build,
  review, recommend, and act within policy, but they do not possess independent
  legal, commercial, regulatory, or financial authority.
- Policy-bounded autonomy is standing scoped authority, not universal consent.
  Deterministic engineering and bounded risk decisions proceed automatically;
  irreducible authority decisions escalate in a compact packet.
- Regulated overrides supersede solo allowances and team defaults when they
  impose approval, evidence retention, or segregation.

## Evidence

Record the active profile/overlays, named owner per activated responsibility,
authority basis, required separations, review/decision actor, escalation owner,
and any temporary delegation or break-glass event with expiry.

## Exceptions

Role exceptions require the governing source's authority, a time-bounded owner,
compensating oversight, expiry, and revalidation. Project policy cannot override
legal, contractual, constitutional, or regulated segregation.

## Solo interpretation

One person may be accountable for product through operations. Use separate
passes, automated evidence, and risk-triggered challenge instead of fictional
approvers; escalate only the precise decision that exceeds authority.

## Overlay notes

Team overlays add CODEOWNERS/reviewer assignments; regulated overlays may require
true separation and named approvers; prototype overlays restrict environment and
data but do not erase ownership. The most restrictive source wins.

## Completion checklist

- [ ] Every activated responsibility has a named accountable owner.
- [ ] Solo collapse or team separation is explicit and allowed by higher sources.
- [ ] AI actions remain within delegated policy authority.
- [ ] Regulated overrides, delegations, and escalations are recorded.
