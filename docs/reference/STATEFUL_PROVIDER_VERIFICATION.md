# Stateful Provider Verification Map

Issue #42 is implemented in current source with no external backend and no CEL
runtime. The evidence below is local implementation evidence, not production
certification.

| Acceptance area | Implementation evidence |
|---|---|
| Consistency, atomicity, clock, availability, tenancy, failure, migration | ADR-0016; `stateful_models.py`; `stateful_memory.py` |
| Public versioned protocol and results | `aegis.stateful`; `test_stateful_models.py` |
| In-memory provider and conformance | `test_stateful_provider.py`; `test_stateful_conformance.py` |
| End-to-end primitive | compiler, restriction, enforcement, session, and evidence stateful suites |
| Concurrency, retries, duplicates, boundaries, outage, stale/malformed, audit | provider, conformance, enforcement, and evidence stateful suites |
| Non-widening composition | `StatefulRestrictionRule`; `test_stateful_policy_compiler.py` |
| Ownership and deployment guidance | ADR-0016; `STATEFUL_POLICY_PROVIDERS.md` |
| Later CEL decision | ADR-0017; CEL remains unimplemented |

The authoritative final command counts and review records live under
`docs/spec-driven-dev/changes/issue-42-stateful-policy-providers/` after the
exact-candidate validation pass.
