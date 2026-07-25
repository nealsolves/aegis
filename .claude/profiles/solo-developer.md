# Solo Developer Base Profile

## Profile type

This is a **base profile** for a repository with one accountable owner. One
person may hold product, architecture, development, review, security, data,
release, operations, and risk roles unless a higher-authority overlay requires
separation.

## Operating posture

- Automate deterministic engineering and policy-bounded decisions by default.
- Keep automated gates, typed facts, current hashes, and lifecycle evidence even
  when the same person performs every role.
- Use risk-bounded review: a combined fresh pass for low risk, configured general
  and domain passes for moderate risk, and specialized review for high risk.
- Maintain written exceptions with scope, authority, compensating controls,
  expiration, and follow-up; memory or repository ownership is not an exception.
- Require repeatable deployment and rollback mechanisms before production
  permissions are enabled, with monitoring and verification recorded.
- Preserve an audit trail of decisions, tests, reviews, publication, incidents,
  and break-glass use without manufacturing fictional approvers.
- A separate-model challenge is optional for ordinary work and useful for
  adversarial review; configured high-risk review perspectives remain required.

## Authority boundary

There is no default second-human count. Human intervention occurs only for an
irreducible authority decision or a policy/overlay requirement. Solo ownership
does not confer legal, contractual, financial, regulatory, or prohibited-action
authority and does not enable unconfigured remote or production actions.

## Completion check

- The named owner and escalation owner are real and current.
- Role collapse is allowed by every active overlay.
- Automated evidence replaces ceremony without lowering any gate.
- Exceptions, release/deployment mechanisms, and audit records are current.
