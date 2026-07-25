# Release Workflow

## Entry criteria

- Use when intent includes creating or verifying a release artifact. Code
  completion alone does not activate this workflow.
- The candidate has converged, its exact change/commit is identified, and
  release-management plus applicable production/observability modules are loaded.
- Version 1 evaluates release authority and evidence; external execution is
  Phase 2 and no vendor adapter or publication action is supplied here.

## Artifacts

- Completed release-readiness record, version/scope, exact candidate identity,
  CI results, artifact inventory/digests, notes, authority, rollback, monitoring,
  and verification plan/results.
- SBOM, provenance, signing, migration, compatibility, and deprecation records
  when applicable.

## Gates

- Release readiness is complete for the current policy/context/change hashes.
- Required exact-commit CI and reviews pass on the candidate that will be
  released; any candidate change invalidates the affected evidence.
- Authority evaluation permits `create_release`, the configured remote action is
  enabled, and no higher-precedence policy denies it.
- Rollback and monitoring are credible before publication; verification has
  bounded success/failure criteria.

## Ordered steps

1. Freeze and identify the exact candidate commit/change hash. Define version,
   scope, user/operator impact, artifacts, targets, and non-goals.
2. Revalidate/evaluate the current context for `create_release`; load additive
   security, compatibility, production, observability, and compliance controls.
3. Run required reviews and exact-commit CI. Reject stale results or checks run
   against a different merge/release candidate.
4. Build or identify reproducible artifacts and record immutable digests. Verify
   contents, dependencies, SBOM, provenance, and signing applicability.
5. Prepare changelog/release notes, compatibility and migration instructions,
   deprecation status, operator actions, and known limitations.
6. Define promotion/deployment boundary, rollback criteria/mechanism, monitoring,
   observation window, success/failure thresholds, and responsible owner.
7. Complete release readiness and request the `CONVERGING -> RELEASE_READY`
   transition with current evidence.
8. For MVP, stop before any external release action and record the evaluated
   command/target and decision. A Phase 2 executor may act only when separately
   installed, idempotent, and authorized.
9. When an authorized external system supplies publication evidence, verify
   artifact identity, availability/consumption, and critical declared behavior.
10. Transition to `COMPLETE` only with `release_artifact_verified`; otherwise
    record the release-ready state without claiming release.

## Evidence

- Version, scope, exact-commit CI, reviews, artifact digests, notes, SBOM/
  provenance/signing applicability, compatibility, migrations, authority,
  rollback, monitoring, and verification bound to all three hashes.
- If external execution is absent, state `release-ready, not released`.

## Exit criteria

- A release-artifact path reaches `COMPLETE` only after verified external
  publication evidence; otherwise work stops accurately at `RELEASE_READY`.
- Candidate, artifact, CI, authority, notes, rollback, monitoring, and verification
  all refer to the same immutable scope.
- No vendor-specific action or production deployment is implied by this workflow.

## Solo mode

A solo owner may prepare and authorize eligible low/moderate releases when an
instantiated policy enables the action. Exact-candidate automation, fresh review,
rollback, and honest release state replace routine second-person ceremony.

## Stop/escalation conditions

- Stop for stale CI, unknown artifact identity, disabled remote actions, missing
  rollback, prohibited/`human_required` authority, or unresolved required findings.
- Enter `HUMAN_DECISION_REQUIRED` only for the precise authority decision returned
  by policy. Critical prohibited release has no ordinary escalation response.
- Failed post-publication verification enters rollback or incident handling
  according to the configured external mechanism; MVP does not execute either.
