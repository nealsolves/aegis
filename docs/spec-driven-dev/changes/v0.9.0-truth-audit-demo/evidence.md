# v0.9.0 Truth Audit and Demo Analysis Evidence

## Discovery boundary

- Base commit: `8be5f54` (`origin/develop` at worktree creation).
- Isolated branch: `feat/v0.9-13-truth-audit-demo`.
- Evidence sources: maintained documentation, Python and React implementation,
  package metadata, focused tests, diagram generator, and demo assets.
- Evidence gap: no live provider credentials or calls are in scope; adapters are
  validated with deterministic local fakes and optional-extra import coverage.

## Reconciliation

- Package candidate: distribution `aegis-ai-governance`, import and CLI `aegis`,
  version `0.9.0b1`.
- Repository status: candidate changes are merged to `develop`; they are not
  merged to `main`, published to PyPI, or released.
- The React app is a demo and operator learning surface, not a runtime
  dependency of the Python package.
- OpenAI Agents, LangGraph, and Bedrock adapters exist. Provider SDKs remain
  optional integrations.
- Invocation and workflow policy modes both exist; split invocation enforcement
  is the compatibility default.

## Consumer and compatibility assessment

The planned changes correct documentation, generated diagrams, demo copy, and
test harness behavior. They do not change the package's public API, policy
semantics, evidence schema, CLI contract, persistence model, or dependency
manifests. Existing consumers therefore require no migration or deprecation
window. Reversal is a normal branch revert before integration.

## Artifact analysis

The approved design, implementation plan, checklist, tasks, documentation
inventory, routed rules, and current code/tests agree on scope and acceptance.
No material ambiguity remains. The instruction-system status correction is
explicitly excluded until separately authorized.

