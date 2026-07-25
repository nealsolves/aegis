# Dependency Update Workflow

## Entry criteria

- Use for a direct, transitive, toolchain, CI action, runtime, or base-image
  dependency addition, removal, pin, or version update.
- Record the reason and exact current-to-proposed version delta before changing
  the manifest or lockfile.
- Route runtime-critical, security-relevant, major, or public-contract-affecting
  updates through the corresponding enhanced controls.

## Artifacts

- Dependency change record, manifest/lockfile diff, upstream evidence,
  compatibility tests, supply-chain review, rollback plan, and final decision.
- Release notes or migration guidance when consumer or operator behavior changes.

## Gates

- Changelog, security advisories, maintainer/source posture, and license are
  reviewed for the exact version delta.
- Compatibility tests cover the affected API, runtime, platform, and artifacts.
- The lockfile review explains all changed direct and transitive entries.
- Major or runtime-critical changes have a credible rollback or pinned forward
  alternative before merge/release authority is evaluated.

## Ordered steps

1. State the reason: vulnerability remediation, compatibility, feature need,
   maintenance, support window, performance, or removal. Reject unexplained churn.
2. Record package/source, ecosystem, current version, proposed version, version
   delta, direct/transitive status, runtime/build/dev scope, and affected targets.
3. Review upstream changelog and migration notes across the whole delta, then
   review security advisories, license changes, provenance, maintainer health,
   pinning, and CI-action permissions as applicable.
4. Extract facts and evaluate risk, routes, authority, and review roles. A major,
   new external, security-sensitive, or runtime-critical update is not presumed low.
5. Update manifest and lockfile with the repository's configured tooling only.
   Inspect the lockfile for unexpected packages, sources, checksums, and scripts.
6. Add or update compatibility tests for exercised APIs, serialization/contracts,
   platforms, runtime behavior, build artifacts, and migration paths.
7. Run configured install, build, lint, typecheck, test, scan, and artifact checks.
   Record reproducibility and sandbox/network limitations.
8. Define rollback for major/runtime-critical changes, including lockfile/manifests,
   data or artifact compatibility, and the supported previous version.
9. Review, repair, refresh hashes, update documentation/release notes, and follow
   the selected maintenance, code, or release terminal path.

## Evidence

- Reason, version delta, changelog/security/license sources, dependency and
  action review, lockfile explanation, compatibility tests, scans, risk,
  authority, rollback, and all three hashes.
- Record unsupported platforms, changed licenses, install scripts, transitive
  surprises, and exceptions as findings rather than hiding them in the lockfile.

## Exit criteria

- The exact proposed graph installs reproducibly within configured bounds and
  all applicable tests/scans pass.
- Compatibility, license, supply-chain, documentation, and rollback impacts are
  resolved for the final lockfile hash.
- Publication or release occurs only on its separately authorized path.

## Solo mode

A solo owner may approve low/moderate routine updates within policy. Use a fresh
supply-chain and compatibility review for higher risk; automated update tooling
does not own risk or release authority.

## Stop/escalation conditions

- Stop on an incompatible license, untrusted source, unresolved severe advisory,
  unreviewable generated delta, or missing runtime-critical rollback.
- Escalate a materially different product/vendor commitment, spend beyond the
  configured limit, critical residual security risk, or prohibited dependency.
- Exhausted install/test retries enter `BLOCKED_TECHNICAL`; do not raise bounds
  ad hoc to force convergence.
