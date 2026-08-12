# ADR-0017: Defer CEL Until After the Stateful Provider Proof

Date: 2026-08-11
Status: Accepted
Owners: Neal

---

## Context

Issue #42 asks whether AEGIS should evaluate CEL only after defining stateful
policy semantics. The stateful provider proof now establishes the missing
atomicity, time, scope, idempotency, availability, migration, and evidence
boundaries. CEL would add an expression language; it would not supply any of
those state guarantees.

## Decision

Do not implement CEL in issue #42. Evaluate it as a separate future change
against the compiled-policy boundary. Any proposal must define a closed input
environment, bounded evaluation resources, deterministic types and errors,
guard/composition behavior, dependency and supply-chain impact, and audit
evidence. CEL expressions must never call providers, mint operation identities,
select trusted scope, relax a stateful constraint, or turn provider failures
into allows.

The current typed guard language remains authoritative. The stateful DSL stays
closed and compiles to immutable constraints before enforcement.

## Consequences

- Issue #42 remains dependency-free and reviewable.
- Provider correctness is not confused with expression evaluation.
- A later CEL design can use the proven provider boundary rather than inventing
  storage semantics inside expressions.

## Validation required for a future CEL ADR

- explicit threat model and resource ceilings;
- non-widening composition proof;
- old-runtime rejection behavior;
- deterministic cross-version evaluation corpus;
- no provider or trusted-scope capabilities in the expression environment;
- full compiler, enforcement, evidence, packaging, and migration tests.

## References

- ADR-0016.
- Issue #42.
- `docs/superpowers/specs/2026-08-11-issue-42-stateful-policy-providers-design.md`.
