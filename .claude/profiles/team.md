# Team Base Profile

## Profile type

This is a **base profile** for repositories with assigned product, engineering,
security, data, platform, release, and operations responsibilities.

## Ownership and review

- Maintain CODEOWNERS or an equivalent path-to-owner map aligned with actual
  repository boundaries; never treat an unmaintained file as proof of review.
- Require high-risk author/approver separation when authority or an overlay
  demands it. Low/moderate work remains automated within configured gates.
- Activate path-sensitive review: security owners for identity/trust boundaries,
  data owners for sensitive processing/schema paths, and platform owners for
  infrastructure, CI, deployment, and production configuration.
- Assign a release authority that can approve the exact candidate and target.
  Merge authority, release authority, and production authority remain distinct.
- Define emergency authority, scope, expiry, break-glass controls, revocation,
  communications, and post-incident review before an incident occurs.

## Operating posture

Agents may build, review, repair, push, and merge within policy. Team membership
does not create a routine approval gate: deterministic decisions continue unless
path ownership, high risk, segregation, or external authority activates one.
Findings and decisions identify the actor, role, evidence, and current hashes.

## Completion check

- CODEOWNERS/equivalent coverage matches sensitive and release paths.
- Author/approver separation is explicit for high-risk scope.
- Security, data, and platform review activation is path-sensitive.
- Release authority and emergency authority are named, bounded, and testable.
