# Release Management Rules

## Purpose

Ensure a release identifies exactly what was validated, can be promoted and
reversed safely, and is published only within configured authority.

## Applicability

Applies to release classification, dependency changes affecting distributed
artifacts, public-contract changes, incidents, production impact, and any intent
to create or promote a release artifact.

## Required inputs

- Versioning policy, release scope, exact candidate commit/change hash, required
  CI and reviews, artifacts, compatibility and migration plans.
- Risk and policy authority decision, target environments, rollback criteria,
  monitoring plan, deprecations, and external obligations.

## Mandatory controls

- Apply the repository's versioning scheme consistently. A breaking public
  contract requires explicit compatibility, migration, and deprecation handling.
- Produce a changelog and release notes that describe user/operator impact,
  risks, migrations, deprecations, and rollback—not an unreviewed commit dump.
- Reevaluate policy authority for the exact release action and target. Local
  implementation authority never implies publication authority.
- Require exact-commit CI on the reviewed candidate. If the candidate changes,
  invalidate relevant validation and review evidence.
- Build artifacts reproducibly where practical, identify them by immutable
  digest, and verify expected contents. Generate SBOM, provenance, and signing
  evidence when policy, ecosystem, or risk requires them.
- Promote the same verified artifacts across environments rather than rebuilding
  mutable equivalents. Record promotion source and target.
- Verify compatibility and migrations for consumers, data, configuration,
  protocols, and mixed versions. State ordering and rollback constraints.
- Use progressive delivery for moderate production risk when project mechanisms
  exist; define observation period, success threshold, pause, and rollback.
- Set rollback criteria before release and ensure the available rollback or
  forward-fix matches data and compatibility realities.
- An emergency release may reduce only explicitly permitted gates. Record the
  incident, exact reductions, authority, validation, monitoring, restoration,
  and follow-up.
- Perform post-publication validation of artifact identity, availability,
  installation/consumption, and declared critical behavior.
- Track deprecation owner, notice, migration path, supported window, telemetry,
  and removal criteria.

## Evidence

Create release evidence containing version and scope, exact-commit CI, reviews,
artifact identifiers/digests, changelog and release notes, SBOM/provenance/
signing applicability, authority, promotion, compatibility and migrations,
progressive-delivery plan, rollback criteria, monitoring, validation, and
deprecation status.

## Exceptions

Release exceptions follow policy and cannot bypass a prohibited outcome,
unknown artifact identity, failed exact-candidate CI, critical residual risk,
or missing required authority. Emergency scope is temporary and incident-bound.

## Solo interpretation

A solo owner may prepare and create low/moderate releases when an instantiated
policy explicitly enables the action. Reusable-template defaults remain remote
disabled, and no second-human ceremony is inferred.

## Overlay notes

Regulated, contractual, security, supply-chain, team, or production overlays may
require retained attestations, independent authority, signing, approved windows,
or longer compatibility periods. Deny-overrides governs conflicts.

## Completion checklist

- [ ] Version, scope, notes, exact candidate, CI, and artifacts are consistent.
- [ ] Authority, compatibility, migrations, promotion, and deprecation are
  resolved.
- [ ] Rollback, monitoring, progressive delivery, and validation are credible.
- [ ] Release evidence is complete for the current hashes.
