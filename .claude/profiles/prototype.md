# Prototype Base Profile

## Profile type

This is a restrictive **base profile** for exploration and learning. Every
artifact and environment carries a visible non-production designation.

## Boundaries

- Use no real regulated data, customer data, or production-derived sensitive
  data. Use synthetic or explicitly approved anonymized fixtures.
- Use no production secrets, credentials, tokens, endpoints, accounts, or
  privileged identities. Prototype credentials are scoped and disposable.
- Make no implied readiness claim: prototype success is not evidence of
  security, reliability, scale, accessibility, supportability, compliance, or
  production readiness.
- Remote collaboration may be configured, but production actions remain disabled.
  A prototype cannot self-promote by changing its label.

## Promotion exit criteria

Promotion requires a separate initialized base profile and fresh policy decision,
approved product intent, data classification, production architecture and threat
review, configured commands/environments, ownership, production readiness,
observability, release/rollback mechanisms, and applicable external controls.
Prototype shortcuts are removed or explicitly remediated; retained code is
reviewed as untrusted brownfield input.

## Completion check

- Non-production labels and environment isolation are visible.
- No real regulated data or production secrets are present.
- Reports state limitations and no implied readiness.
- Promotion exit criteria are unmet or evidenced through a separate workflow.
