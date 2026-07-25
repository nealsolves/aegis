# Testing Rules

## Purpose

Provide the smallest test portfolio that gives credible evidence for changed
behavior, acceptance criteria, contracts, migrations, and material risks.

## Applicability

Always applies. Test depth follows behavior impact and evaluated risk, including
documentation or maintenance checks where executable behavior is unchanged.

## Required inputs

- Acceptance criteria, public and internal contracts, fact/risk decision, and
  the relevant change hash.
- Existing test conventions, production behavior evidence for brownfield work,
  schemas, migration plans, and rollback expectations.
- Configured test commands and permitted test environments.

## Mandatory controls

- Use red before green where practical: first capture a failing acceptance,
  regression, or contract test, then implement the smallest passing change.
  Record why a pre-change failure was not practical for generated, mechanical,
  or already-correct behavior.
- Add characterization tests before changing poorly specified brownfield
  behavior. Preserve or deliberately reconcile observed behavior.
- Select layers deliberately: unit tests for isolated logic, contract tests for
  interfaces, integration tests for collaborating boundaries, and end-to-end
  tests only for critical journeys that require the assembled system.
- State sandbox boundaries and production boundaries. Prefer local, ephemeral,
  fake, or sandbox dependencies. Do not require or run live production tests as
  a general validation rule; production verification uses bounded, authorized,
  non-destructive probes.
- Maintain acceptance and contract mapping so each material criterion points to
  an executable test or a justified non-test verification.
- Test schemas, migrations, and rollback in representative disposable data.
  Verify forward/backward compatibility where mixed versions may coexist.
- Treat snapshots as reviewed contracts: keep them focused, inspect semantic
  changes, and never bulk-accept unexplained output.
- Measure changed-code coverage and risk coverage rather than optimizing a
  repository-wide percentage. Unit tests for every function are explicitly not
  required; test observable decisions and failure paths.
- Preserve determinism by controlling clocks, randomness, ordering, networks,
  and concurrency. Quarantine is not a permanent answer for flaky tests: assign
  an owner, evidence, and bounded remediation.
- Activate performance and resilience triggers for hot paths, capacity changes,
  timeouts, retries, concurrency, failure recovery, or stated service targets.

## Evidence

Record the red/green observation or reason it was inapplicable, test commands,
exact change hash, layer selection, acceptance/contract mapping, relevant
coverage, migration/rollback results, and all flakes or environment limits.

## Exceptions

Missing tests require a policy-valid exception with the untested risk,
compensating verification, owner, expiry, and follow-up. Never use an exception
to mislabel a production experiment as a deterministic test.

## Solo interpretation

A solo developer may execute the portfolio and its review, but should separate
the test-adequacy pass from implementation. High-risk work activates the
configured specialized review even when one person owns every role.

## Overlay notes

Security, data, regulated, production, and public-contract routes may mandate
specific negative cases, retained results, sandbox constraints, or independent
review. Apply those additions without forcing every low-risk change through the
largest portfolio.

## Completion checklist

- [ ] Tests map to changed behavior, acceptance criteria, contracts, and risks.
- [ ] The selected layers and environment boundaries are justified.
- [ ] Flakes, snapshots, migrations, rollback, performance, and resilience were
  addressed where triggered.
- [ ] Current tests pass for the recorded change hash.
