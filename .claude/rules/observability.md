# Observability Rules

## Purpose

Make changed behavior and failure detectable, diagnosable, and verifiable while
controlling sensitive data, noise, cardinality, retention, and cost.

## Applicability

Applies to production impact, observability impact, AI systems, incidents, new
services, critical journeys, and regulated flows. Minor work receives only the
controls needed to observe its material behavior.

## Required inputs

- User/system journeys, failure modes, service dependencies, data
  classifications, existing telemetry, operational targets, and owners.
- Evaluated risk, target environment, release/deployment intent, and change hash.

## Mandatory controls

Choose the proportional posture:

- **Minor feature:** reuse existing logs and metrics; add telemetry only for a
  new decision, failure, or acceptance signal.
- **Critical journey:** define journey-level signals, failure/latency thresholds,
  dashboards, alerts, and verification.
- **New service:** define logs, metrics, traces, correlation, ownership,
  dashboards, alerts, and initial service objectives.
- **Regulated flow:** add required audit events, access controls, redaction,
  retention, integrity, and evidence handling.

Across the selected posture:

- Emit structured logs for actionable state changes and failures. Use metrics
  for bounded trends and rates, traces for cross-boundary latency/causality, and
  correlation identifiers across relevant components.
- Separate audit events from diagnostic telemetry when integrity, access, or
  retention requirements differ.
- Define SLI measurements and an SLO with rationale for material services; use
  the error budget to inform release pace and repair, not as an automatic waiver.
- Build dashboards around decisions and critical journeys, not every raw signal.
  Alerts need severity, threshold, duration, owner, routing, runbook, and a
  testable response.
- Assign ownership for signals and follow-up. Remove orphaned dashboards,
  alerts, and telemetry during decommissioning.
- Bound cost and cardinality: avoid unbounded labels, user-controlled dimensions,
  payload dumps, and needless high-frequency events. Set retention by purpose.
- Apply redaction before emission and test it with sensitive examples. Never
  rely solely on downstream scrubbing.
- Include telemetry testing in local/integration checks when practical and
  define production verification using safe, authorized observation after
  release or deployment.

## Evidence

Record the selected posture, journeys and failure signals, logs/metrics/traces
or deliberate reuse, audit-event decisions, SLI/SLO/error budget, dashboards,
alerts and owners, cost/cardinality and retention bounds, redaction tests, and
production verification result when applicable.

## Exceptions

An observability exception must name the blind spot, operational consequence,
compensating detection, owner, expiry, and remediation. It cannot suppress
required audit evidence or conceal a high-risk production failure mode.

## Solo interpretation

A solo owner may own signals and response. Prefer a small actionable set over a
large unattended stack; policy, not team size, decides whether enhanced review
or human authority is required.

## Overlay notes

Security, privacy, regulated, contractual, and platform overlays may constrain
fields, access, region, integrity, retention, alerting, or on-call ownership.
Apply stricter requirements without copying sensitive data into evidence.

## Completion checklist

- [ ] The minor feature, critical journey, new service, or regulated flow
  posture is recorded.
- [ ] Signals, correlation, objectives, dashboards, alerts, and ownership are
  proportional and actionable.
- [ ] Cost/cardinality, retention, redaction, and testing were verified.
- [ ] Production verification is defined or recorded when applicable.
