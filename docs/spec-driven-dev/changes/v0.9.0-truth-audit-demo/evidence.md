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

## Validation evidence

Validation was run locally on 2026-07-25 from the isolated
`feat/v0.9-13-truth-audit-demo` worktree. No provider credentials were
configured and no provider calls were made.

### Adapters

- Base environment: `258 passed, 1 skipped`. The only skip is the real OpenAI
  Agents integration because the optional SDK is not installed in the base
  environment.
- Isolated Python 3.12 environment with `.[dev,openai-agents]`:
  `277 passed`. The real OpenAI Agents integration ran without making a
  provider call.
- Bedrock and A2A remained dependency-light, and the OpenAI Agents SDK remained
  confined to its declared optional extra.

### Python, policy, and documentation

- Policy validation: passed.
- Documentation parity: passed before this evidence update.
- Brand and version parity: passed.
- Flake8 for `aegis`: passed.
- Full package suite: `1916 passed, 2 skipped, 1 failed`. The only failure is
  the deliberate instruction-guide truth guard added for Task 7; it cannot
  pass until the separately authorized one-file `.claude` correction is
  applied.
- Coverage run with only that pending guard deselected:
  `1916 passed, 2 skipped, 1 deselected`, with `90.32%` package coverage
  against the `90%` gate.
- Demo API suite: `67 passed`, with 2 non-failing warnings.

The canonical final package test count is intentionally not advanced yet.
After the exact Task 7 owner response is validated and the authorized
instruction file is corrected, the expected full-suite result is
`1917 passed, 2 skipped`; that result must be observed before it is recorded as
the release baseline.

### React application

- Vitest: 17 test files, `105 passed`.
- ESLint: passed.
- Production build: passed.

### Assembled browser workflow

The maintained FastAPI backend and Vite React application were run together on
`localhost` and exercised through browser automation:

- Architecture component and enforcement-pipeline diagrams loaded in both
  light and dark themes.
- The Architecture page retained readable containment at 390x844 mobile and
  1440x900 desktop viewports, with no horizontal page overflow.
- Contextual help matched the Architecture page and Labs 1–11. The close
  button, Escape key, backdrop, focus containment, and focus return behaviors
  were exercised successfully.
- Lab 11 Minimal completed with two governed steps and a workflow artifact.
- Lab 11 Failure & Fix first failed for missing provenance, reported
  `WORKFLOW_SOURCE_REQUIRED`, and completed after the documented fix.
- Build Evidence Trace completed with two resolved steps and zero unresolved
  links.
- Governed vs Ungoverned preserved the documented evidence distinction.
- Representative earlier labs reached the real local API: Lab 1 returned PASS
  with split enforcement, and Lab 8 returned PASS with a source-backed,
  allowed provenance gate.
- The final browser console contained no warnings or errors.

The local demo services were stopped after validation.

## Open gate

Task 7 remains open. Policy evaluation
`DEC-v0.9.0-instruction-status-truth-AUTH-instruction_system_change` requires
an exact owner response before `.claude/rules/aegis-project.md` can be edited.
All validation evidence above is complete except the final full-suite rerun
that depends on that protected correction.
