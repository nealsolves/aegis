# Engineering Rules

## Purpose

Produce changes that are correct, maintainable, traceable, and safe to reverse
without imposing heavyweight ceremony on routine work.

## Applicability

Always applies to implementation, configuration, generated artifacts, and
behavior-preserving refactors. Apply controls in proportion to the evaluated
risk and the repository's actual runtime boundaries.

## Required inputs

- Approved intent, acceptance criteria, current decision record, and active
  lifecycle state.
- Relevant source, tests, contracts, configuration, dependency manifests, and
  brownfield behavior evidence.
- Repository commands from `project.yaml`; an `unknown` command remains a
  technical gap and is never invented.

## Mandatory controls

- Prefer small, reversible changes with a credible rollback or forward-fix.
  Keep branch, commit, and pull request traceability to the active change ID and
  exact reviewed change hash.
- Use strict tooling already configured by the repository. Strict tooling
  includes compiler, linter, formatter, type checker, and static analyzer gates
  only when configured and applicable.
- Perform boundary validation at every untrusted input, storage, process,
  network, and public-contract boundary. Convert failures to typed errors with
  stable semantics; do not hide errors or expose internal secrets.
- Maintain dependency and configuration discipline: justify additions, pin or
  lock according to repository practice, validate configuration at startup,
  keep secrets out of source, and avoid environment-specific logic drift.
- Emit structured logging at operationally meaningful boundaries. Do not log
  secrets, sensitive payloads, or data prohibited by the privacy module.
- Avoid unsafe casts, unchecked null assumptions, swallowed exceptions, and
  implicit coercion. Any unavoidable unsafe operation needs a narrow scope,
  invariant, test, and rationale.
- Control complexity with cohesive names, explicit interfaces, bounded
  functions, and reuse only where duplication is stable. Generated code must be
  reproducible, identified, and changed through its generator when possible.
- Preserve brownfield compatibility unless approved artifacts explicitly
  authorize a break. Reconcile intended behavior with consumers, stored data,
  telemetry, and characterization tests before changing it.
- Activate review capabilities proportionally: correctness review,
  maintainability review, regression review, concurrency review, performance
  review, and contract review. A tool-equivalent fallback is allowed when a
  named tool is unavailable, but it must produce comparable evidence and record
  the substitution.

## Evidence

Record the changed files and change hash, acceptance-to-implementation mapping,
configured commands and results, relevant review findings, contract or
compatibility checks, and rollback/forward-fix path. For concurrency or
performance-sensitive work, include the scenario, threshold, and observed
result rather than a generic assurance.

## Exceptions

Use the configured exception policy. Record the waived rule, scope, tier,
rationale, owner, expiry, compensating control, and remediation. An exception
cannot suppress a prohibited outcome, higher-authority requirement, or required
security/privacy route.

## Solo interpretation

One person may build and review, but must perform a distinct evidence-based
review pass and rerun affected gates. A separate model or tool may challenge
high-risk assumptions; no routine second-human count is implied.

## Overlay notes

Team, regulated, security, data, and production overlays may require separation
of duties, additional tools, retained evidence, or stricter compatibility
controls. The most restrictive applicable requirement wins.

## Completion checklist

- [ ] The change maps to approved intent and is reversible.
- [ ] Boundaries, errors, configuration, dependencies, and logs were checked.
- [ ] Applicable correctness, regression, contract, concurrency, and
  performance reviews produced current evidence.
- [ ] Findings and exceptions are resolved according to policy.
