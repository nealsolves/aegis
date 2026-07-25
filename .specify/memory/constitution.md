# Project Constitution

> Starter constitution for an instantiated repository. Replace project
> placeholders through the governed initialization or amendment process; do not
> weaken these principles informally.

## Preamble

This constitution defines the durable principles that govern delivery. External
law and contract remain superior. Within that boundary, this constitution is
superior to feature artifacts, project policy, loaded modules, the root kernel,
and conventional practice.

The objective is safe autonomy: deterministic engineering and policy-bounded
risk decisions proceed without ceremony, while irreducible authority decisions
receive precise human attention.

## Article I — Autonomy Within Authority

Automate by default only inside validated, explicitly configured authority.
Every consequential action must resolve to `autonomous`,
`autonomous_with_enhanced_gates`, `human_required`, or `prohibited`; the most
restrictive applicable outcome wins.

Human intervention is an exception, not a routine stage. It is required only
for material business intent, legal or contractual risk, out-of-policy spending,
regulatory segregation, new sensitive-data use, critical residual security risk,
or irreversible destructive production authority that policy cannot resolve.
A prohibited action cannot be converted into an approval request.

## Article II — Spec-Driven Intent

Approved specifications state intended behavior and acceptance criteria before
non-trivial implementation. Plans describe the chosen approach; tasks provide
traceable execution slices. Maintenance work may use a reduced record and
lifecycle, but it must still state scope, behavior impact, validation, and
reversal.

Implementation, telemetry, stored data, and consumer behavior are evidence of
actual state. When actual and intended behavior diverge, reconcile the approved
artifact deliberately; do not silently treat the implementation as the new
requirement.

## Article III — Test-First Evidence

For behavior changes, create the smallest relevant automated test or
characterization first, run it, and observe the expected failure before changing
production behavior. Then implement the minimum change, rerun affected tests,
and retain reproducible evidence.

Validation depth is proportional to risk and change type. Evidence must map to
acceptance criteria, interfaces, migrations, security boundaries, and rollback
where applicable. A passing assertion that never failed for the missing behavior
does not establish test-first evidence.

## Article IV — Security and Privacy Boundaries

Security and privacy are design constraints. Deny access by default, validate
untrusted inputs and model outputs at boundaries, use least privilege, protect
credentials, and minimize collection and retention of sensitive data.

Authorization, customer data, production access, cryptography, external
dependencies, AI tool use, and regulated scope activate their configured
controls. Unknown material impact fails closed. Sensitive production data must
not enter non-production environments unless an explicit higher-authority policy
permits and controls it.

## Article V — Deterministic Policy

Agents may extract observable facts and cite provenance; deterministic code must
validate those facts and derive classification, risk, routing, authority,
exceptions, resource outcomes, and lifecycle transitions. An agent may not
substitute subjective judgment when the policy engine is unavailable.

Every decision is bound to current policy, context, and change hashes. Unknown,
stale, contradictory, or insufficiently corroborated material evidence blocks
the affected decision. Policy source precedence and deny-overrides cannot be
weakened by a lower-authority artifact.

## Article VI — Reversible Delivery

Prefer small, reviewable, backward-compatible changes with explicit rollback or
reversal. Migration, release, deployment, and destructive operations require
evidence proportional to blast radius, including recovery prerequisites and
post-action verification.

Progressive delivery and automatic rollback may reduce risk when project policy
configures them; their existence must be verified rather than assumed. No code,
release, deployment, compliance, or production-readiness state may be claimed
without evidence for that specific state.

## Article VII — Amendment Discipline

Amendments require a written proposal containing rationale, affected principles,
before/after wording, compatibility and security/privacy impact, migration or
reversal, control-plane version impact, and supporting regression evidence.

During the MVP, post-bootstrap changes to the instruction system are
`human_required` and must be evaluated under the currently trusted revision.
The proposed policy cannot authorize its own weakening. Record the approving
authority, effective date, prior and new hashes, and any follow-up conditions in
the amendment log.

## Governance

- **Version:** 1.0.0
- **Ratified:** 2026-07-24
- **Last amended:** not amended
- **Owner:** Neal Adams
- **Review cadence:** on material obligation or authority change, otherwise at
  least during each project-level control review

### Amendment Log

| Date | Version | Decision reference | Summary | Approved by |
|---|---|---|---|---|
| 2026-07-24 | `1.0.0` | `BOOTSTRAP-2026-07-24-AEGIS-SDD` | Instantiate the spec-driven-dev constitution for AEGIS. | Neal Adams |
