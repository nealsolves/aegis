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
- Final full package suite: `1917 passed, 2 skipped`.
- Coverage run with only that pending guard deselected:
  `1916 passed, 2 skipped, 1 deselected`, with `90.32%` package coverage
  against the `90%` gate.
- Demo API suite: `67 passed`, with 2 non-failing warnings.

The observed `1917` passing tests are recorded as the canonical candidate
baseline. The two skips are expected environment-dependent cases.

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

## Instruction-system decision

Task 7 is resolved. Policy decision
`DEC-v0.9.0-instruction-status-truth-AUTH-instruction_system_change` received
an exact response from Neal Bhattacharya, bound to change hash
`e45c78434e3e9cba9441ececcf467600f19506d80ab6eb3a6d2a8d80864539b6`,
context hash
`b85051520a08e20e4f0db4c06aafe28907accbad04553b3ffc2615fe8a658292`,
and policy hash
`d0416dab300bbcfbf7fba95bb51b1d1aeda7725d945560d0fbb0ce4f3dc6a3fa`.
The result was `autonomous_with_enhanced_gates`.

The first response attempt exposed a preparation error: the generated
escalation had not been materialized into `HUMAN_DECISION_REQUIRED`. No
instruction file was changed under that invalid state. The context was
corrected, reevaluated deterministically, and reauthorized against the fresh
hash before the one approved factual correction was applied.
