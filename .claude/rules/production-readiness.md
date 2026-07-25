# Production Readiness Rules

## Purpose

Scale production controls to operational consequence and permit deployment only
with evidence for safe operation, verification, recovery, and ownership.

## Applicability

Applies to production-impact classifications, infrastructure or schema changes,
releases, incident hotfixes, and any work that may operate against a production
target. MVP evaluates readiness and authority; it does not execute deployments.

## Required inputs

- Target environments, evaluated risk and authority, architecture/data flows,
  operational dependencies, service objectives, and change hash.
- Deployment, migration, rollback, backup, recovery, monitoring, ownership, and
  decommissioning plans that actually exist for the project.

## Mandatory controls

Use the highest applicable readiness level:

| Level | Typical scope | Required posture |
|---|---|---|
| Level 0 | Documentation, local-only prototype, no production path | Mark non-production; validate documentation and reversal. |
| Level 1 | Low-risk change to an existing reversible path | Configured checks, basic health checks, owner, rollback, and bounded verification. |
| Level 2 | Moderate runtime or infrastructure change | Representative staging, monitoring, progressive deployment, tested rollback, capacity and recovery evidence. |
| Level 3 | High-risk boundary, customer-data write, critical infrastructure, or complex migration | Enhanced reviews, explicit production authority, rehearsed rollback/recovery, and full readiness evidence. |

- Keep environments explicit and separated. Manage production infrastructure as
  code where available; review plan/output and prevent console drift.
- Validate configuration per environment, secrets separately, and safe startup
  defaults. Do not infer an unknown deployment command or target.
- Plan migrations for compatibility, sequencing, locking, backfill, mixed
  versions, failure, retry, and reversal. An irreversible migration is critical.
- Use feature flags only with an owner, safe default, exposure plan, observation,
  rollback semantics, and removal date.
- Provide health checks that distinguish process, readiness, and critical
  dependency state without leaking sensitive details.
- Define deployment strategy and rollback criteria before authority evaluation.
  Prefer progressive delivery with automatic pause or rollback for moderate
  risk when the project supports it.
- Verify backup coverage, restore behavior, recovery point/time expectations,
  and dependencies before destructive or data-changing work.
- Establish capacity evidence and degradation limits for affected resources and
  critical journeys.
- Maintain concise runbooks for detection, diagnosis, rollback/recovery,
  escalation, and known failure modes. Assign operational ownership.
- Define production verification and monitoring with bounded success/failure
  criteria tied to the exact release candidate.
- Plan decommissioning for superseded flags, versions, resources, data, access,
  dashboards, and alerts.
- Restrict break-glass operations to explicit authority, minimal scope, recorded
  commands/actions, time limits, revocation, and post-event review.

## Evidence

Record the readiness level and rationale, environment/configuration checks,
IaC or equivalent review, migration/compatibility results, health and capacity
checks, backup/restore evidence, deployment and rollback criteria, runbook and
owner, monitoring, and production verification plan/result when authorized.

## Exceptions

No exception can authorize a critical prohibited deployment, destructive
production action without safeguards, unverified rollback where required, or
unknown production target. Reduced incident gates must be explicit, bounded,
recorded, and restored after stabilization.

## Solo interpretation

A solo owner may hold operational and release roles and deploy within explicit
authority. Repeatable gates and rollback evidence replace routine ceremony;
high-risk or irreversible authority decisions still escalate.

## Overlay notes

Regulated, contractual, security, data, team, or platform overlays may raise the
readiness level, require separation, constrain windows/regions, or add recovery
and retention evidence. They may not lower a policy-derived minimum.

## Completion checklist

- [ ] The readiness level and target environments are explicit.
- [ ] Configuration, migrations, compatibility, flags, health, and capacity are
  verified proportionally.
- [ ] Deployment, rollback, backup, recovery, runbooks, monitoring, and ownership
  evidence are current.
- [ ] Production authority and break-glass constraints are satisfied.
