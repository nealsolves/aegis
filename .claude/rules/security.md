# Security Rules

## Purpose

Protect trust boundaries, identities, data, software supply chains, and
operational access with controls proportional to observable security impact.

## Applicability

Applies when routed by authentication, authorization, dependency,
infrastructure, credential, data, AI, incident, or instruction-system facts.
Also applies to any newly discovered security boundary regardless of the
initial classification.

## Required inputs

- Fact provenance, data flows, assets, actors, trust boundaries, deployment
  target, and relevant external obligations.
- Authentication and authorization model, secrets/configuration sources,
  dependency/automation manifests, and current findings.
- Risk tier, authority outcome, exception state, and exact change hash.

## Mandatory controls

- Activate threat triggers for new trust boundaries, privileged operations,
  untrusted input, sensitive data, public exposure, new dependencies, AI tools,
  and material infrastructure changes. Record threat boundaries and mitigations.
- Validate and normalize untrusted input at its boundary. Enforce
  authentication and authorization server-side, including object-level access;
  default to least privilege for users, services, CI, and deployment identities.
- Keep secrets out of source, logs, prompts, fixtures, and generated artifacts.
  Use approved secret stores, rotation, scoped credentials, and revocation.
- Prevent SSRF with destination allowlists and network controls; prevent
  injection with structured APIs and escaping; prevent path traversal with
  contained canonical paths; reject unsafe deserialization and untrusted types.
- Use approved cryptography and libraries for encryption, hashing, randomness,
  signing, and transport. Do not design custom cryptography.
- Review dependencies and actions for maintainer, license, pinning, permissions,
  transitive risk, and update path. Treat CI actions as executable dependencies.
- Run configured SAST, dependency scan, and secret scan gates. Trigger container
  and IaC triggers—image scanning, non-root/runtime constraints, manifest
  validation, and least-privilege cloud policy—when those artifacts change.
- Produce an SBOM, provenance, and signing evidence when release policy or risk
  requires them; absence of a configured tool must be recorded, not concealed.
- Track findings and exceptions with severity, confidence, location, violated
  rule, evidence, resolution, owner, and expiry. Critical residual risk cannot
  be waived through an ordinary exception.
- Control privileged access and break-glass use with bounded scope, explicit
  authority, audit evidence, expiry/revocation, and post-use review.
- High-risk solo work requires a distinct solo adversarial review using fresh
  context: spec, diff, tests, threats, and policy rather than builder conclusions.

## Evidence

Record threat decisions, trust/data-flow evidence, authorization tests, scan
results, dependency/action review, credential checks, applicable SBOM,
provenance and signing records, findings, exception decisions, and break-glass
events. Bind evidence to current policy, context, and change hashes.

## Exceptions

Only policy-authorized exceptions are valid. Security-boundary impact,
regulatory impact, credential exposure, unresolved critical findings, and
prohibited operations cannot be silently compensated or downgraded.

## Solo interpretation

One owner may hold implementation and security roles, but must use the required
separate adversarial pass and automated gates. Human intervention occurs only
when the authority outcome requires it, not merely because the repository is
solo-owned.

## Overlay notes

Regulated or contractual overlays can add control mapping, independent approval,
evidence retention, regional constraints, and segregation. External authority
overrides solo allowances and project defaults.

## Completion checklist

- [ ] Threat triggers, trust boundaries, authentication, authorization, and
  least privilege were evaluated.
- [ ] Applicable code, secret, dependency, container, and IaC gates passed.
- [ ] Supply-chain evidence and findings are current and complete.
- [ ] Residual risk and exceptions are within authority.
