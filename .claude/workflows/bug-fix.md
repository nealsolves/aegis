# Bug-Fix Workflow

## Entry criteria

- Use when observed behavior conflicts with an approved requirement, stable
  contract, established behavior, or safety expectation.
- Identify whether the work is a simple regression, behavior clarification,
  security defect, or incident follow-up before resolving a feature artifact.
- Capture reproduction evidence and affected version/commit; do not assume the
  report identifies the root cause.

## Artifacts

- Bug/change ID, reproduction, expected-versus-actual record, fact context,
  regression or characterization test, minimal fix, review, and rollback note.
- Updated specification or incident record when the defect reveals missing or
  changed intent rather than a simple regression.

## Gates

- Reproduction or a justified, observable characterization exists before code
  changes. Security and incident classifications activate their modules.
- The original risk decision is reevaluated for root cause, fix scope, affected
  data/contracts, and intended target.
- A regression test proves the defect and fix where intended behavior is known;
  a characterization test protects actual behavior while clarification occurs.

## Ordered steps

1. Assign a bug ID, record reporter evidence, environment, affected commit, and
   the smallest deterministic reproduction available.
2. Classify the bug as simple regression, behavior clarification, security
   defect, or incident follow-up. Route security and incident work immediately.
3. Extract current facts from the diff and affected paths, then validate and
   evaluate risk, authority, modules, and lifecycle intent.
4. Compare expected behavior with specification, tests, contracts, telemetry,
   and consumer evidence. If they disagree, preserve the disagreement rather
   than choosing a convenient source.
5. Add a failing regression test for known intent. If intent is unclear, add a
   characterization test and resolve the behavior clarification before changing it.
6. Isolate the root cause and blast radius, including adjacent failure paths,
   concurrency, data, security, compatibility, and operational consequences.
7. Implement the smallest reversible correction. Avoid unrelated cleanup that
   obscures the proof or broadens rollback.
8. Rerun reproduction, affected suites, negative cases, and configured gates.
   Reevaluate facts and risk when the fix changes scope.
9. Perform the policy-activated review, repair findings, update specs/runbooks or
   incident evidence, and converge on the appropriate terminal path.

## Evidence

- Reproduction command or trace, expected and actual behavior sources, root
  cause, affected paths/consumers, red/green test, risk reevaluation, and final
  hashes.
- Record security findings, incident linkage, rollback, reviews, and any
  characterization retained because authoritative behavior remains unresolved.

## Exit criteria

- The defect is no longer reproducible, the regression/characterization suite is
  current, and no affected contract or risk is silently changed.
- Root cause and adjacent risks are addressed or explicitly tracked within
  policy; documentation/specification reflects the accepted behavior.
- The selected lifecycle path reaches `COMPLETE` with fresh evidence.

## Solo mode

One person may reproduce, fix, and review, but should conduct the regression and
root-cause review as a fresh pass. A security defect receives the configured
adversarial security review even in a solo repository.

## Stop/escalation conditions

- Stop in `BLOCKED_REQUIREMENT` when competing expected behaviors are materially
  different and no authority source resolves them.
- Enter `INCIDENT` when the defect is actively harming production or demands
  stabilization; use the incident-hotfix workflow.
- Escalate critical residual security risk, customer/data-use changes, or other
  irreducible authority. Stop after bounded failed repair or reproduction attempts.
