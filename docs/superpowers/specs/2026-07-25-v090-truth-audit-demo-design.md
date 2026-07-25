# AEGIS v0.9 Documentation Truth and Demo Architecture Design

**Change ID:** `v0.9.0-truth-audit-demo`

**Status:** Approved

**Approved by:** Neal Bhattacharya

**Target branch:** `develop`

**Explicit exclusion:** No merge, pull request, or direct change to `main`.

## Purpose

Align maintained AEGIS documentation and the React demo with the implemented
`aegis-ai-governance==0.9.0b1` candidate, strengthen executable drift checks,
and verify all optional adapters in their supported dependency environments.

The work is documentation and demo truth maintenance. It does not change the
AEGIS governance runtime or broaden an adapter contract.

## Authoritative Sources

Claims must be reconciled against these sources, in descending order of
specificity:

1. `pyproject.toml` and `aegis.__version__` for distribution identity.
2. Public modules and `aegis.__all__` for import boundaries.
3. JSON Schemas, CLI parser behavior, and runtime implementations for supported
   inputs and commands.
4. Executable tests for frozen behavior and failure semantics.
5. `doc_parity_manifest.yaml` for maintained cross-document values.

Documentation does not redefine behavior when it disagrees with these sources.

## Documentation Scope

### Maintained current-state documentation

Audit and update:

- root onboarding, status, release-gate, and changelog current-state sections;
- SDK framework, usage, integration, and public-contract guides;
- current architecture and enforcement documentation;
- workflow quickstart, CLI, operations, troubleshooting, starter, migration,
  supported-environment, and release-matrix references;
- optional adapter references and their index;
- React architecture copy and contextual help content;
- executable documentation parity checks and their tests.

### Target-state documentation

Keep target-state documents clearly labeled, but correct their
implemented-versus-planned inventories. A target-state document must not call an
already packaged beta surface planned-only, and must not present an internal
surface as public.

### Historical documentation

Do not rewrite plans, audits, ADRs, articles, archived release evidence,
completed design specifications, or completed spec-driven-dev evidence. They
remain historical records even when their contemporary version statements are
old.

### Bedrock reference

Remove the copied general AWS Bedrock page from the AEGIS adapter reference
set. Replace it with `docs/reference/external/BEDROCK_ADAPTER.md`, documenting
the actual `BedrockTraceAdapter` boundary, import path, policy constraints,
alias-backed identity requirement, host responsibilities, redaction behavior,
and failure cases.

## React Architecture Experience

Preserve the existing architecture page structure and visual language:

1. Component View
2. Enforcement Pipeline
3. Key Boundaries

Regenerate light and dark diagram assets from checked-in source. The component
view must show:

- host-owned orchestration, provider/tool calls, transport, credentials, and
  business state;
- policy loading and validation;
- `AEGIS.open_session(...)`, `GovernanceSession`, and
  `SessionPreCallResult`;
- unified and split invocation enforcement;
- separate invocation and workflow evidence;
- workflow lint, doctor, trace, and export tooling;
- optional Bedrock, A2A, and OpenAI Agents normalization adapters.

The diagrams must omit planned public types that are not exported, including
`AgentIdentity`, `AgentCapabilityManifest`, and `ValidatorHook`. Internal
implementation may exist without constituting a public contract.

The pipeline view must preserve the implemented order:

```text
pre_authorization
-> guard evaluation
-> role validation
-> precondition validation
-> tool constraint validation
-> post_authorization
-> host execution boundary for split/session paths
-> pre_output
-> output schema validation
-> postcondition validation
-> post_output
-> risk scoring
-> invocation evidence
-> workflow step/session evidence
```

The page must identify the package as `aegis-ai-governance==0.9.0b1` and the
product line as v0.9 beta, while retaining historical “since v0.3.3” statements
where they identify when split enforcement became the decorator default.

## Contextual Help

Keep the existing help drawer structure and interaction model. Do not turn it
into global documentation navigation.

For Architecture and Labs 1–11:

- use the exact visible page and control labels;
- describe only behavior demonstrated by the current page;
- distinguish invocation evidence from workflow evidence;
- distinguish core enforcement from opt-in utilities;
- explain host ownership and optional adapter boundaries where relevant;
- keep failure-and-fix and operator-tool guidance aligned with actual API and
  CLI behavior.

No layout redesign is required. Accessibility, focus trapping, keyboard close,
backdrop close, and contextual headings must remain intact.

## Documentation Drift Controls

Extend parity validation without turning UI prose into an overly brittle
snapshot. Checks should cover stable contracts:

- distribution name and candidate version;
- source/runtime version agreement;
- public versus submodule-only exports;
- maintained documentation inventory;
- architecture page candidate identity;
- diagram source and generated-asset agreement;
- adapter index and reference availability;
- stable help claims such as split default, host ownership, workflow evidence,
  and adapter optionality.

Generated diagrams must be changed through their generator or declarative
source and reproduced deterministically.

## Adapter Verification

### Base environment

Verify:

- `aegis` imports without provider SDKs;
- Bedrock and A2A adapter submodules import without provider SDK dependencies;
- fixture-based prepare/complete flows pass;
- malformed evidence, unsupported bindings, identity mismatches, stale or
  replayed tokens, and secret-bearing metadata fail closed or are redacted as
  specified;
- OpenAI Agents usage reports the declared optional dependency clearly when the
  extra is absent.

### OpenAI Agents environment

Install the declared `openai-agents` extra in an isolated environment and run
the real-SDK integration suite. Tests must use local fixtures and must not
require credentials, make model calls, or contact production services.

### Complete validation

Run:

- focused adapter suites;
- full Python suite;
- Python lint;
- documentation parity and release-truth checks;
- React unit tests;
- React lint and production build;
- browser validation of both diagram themes, contextual help, responsive
  presentation, keyboard/focus behavior, and representative lab/API flows.

## Failure Handling

No adapter runtime changes are planned. If verification exposes a real adapter
defect, first add or identify a reproducing test, then make the smallest
contract-preserving fix and rerun the affected and complete portfolios.

Broken maintained links, unsupported API examples, stale candidate claims,
non-reproducible diagrams, or skipped required adapter integration are release
truth failures, not documentation warnings.

The OpenAI integration may skip only in the deliberately dependency-free
environment. It must execute in the environment with the declared extra.

## Spec-Driven and Git Boundaries

- Work on `feat/v0.9-13-truth-audit-demo`, based on `origin/develop`.
- Follow the installed spec-driven-dev policy engine and retain lifecycle
  evidence.
- Treat a correction to `.claude/**` as an instruction-system change requiring
  its own bounded owner authorization under the installed constitution.
- Keep commits scoped and reversible.
- Any eventual remote pull request targets `develop` only and requires the
  repository's configured authority.
- Do not merge the branch and do not create or merge anything targeting
  `main`.

## Acceptance Criteria

- [ ] Maintained current-state docs agree with implemented v0.9 beta behavior.
- [ ] Historical records remain unchanged.
- [ ] Target-state inventories distinguish implemented, internal, public, and
      planned surfaces accurately.
- [ ] A focused Bedrock adapter reference replaces the unrelated copied page.
- [ ] React architecture diagrams and copy show only the current beta surface.
- [ ] Architecture and Labs 1–11 retain accurate contextual help.
- [ ] Stable drift checks fail on candidate, diagram, help, or adapter-doc
      regressions.
- [ ] Base adapter tests pass without provider SDK dependencies.
- [ ] OpenAI Agents real-SDK integration runs with the declared extra.
- [ ] Full Python and React validation passes.
- [ ] Browser validation passes in light/dark and relevant responsive states.
- [ ] The change remains isolated from `main`.

## Reversal

Revert this branch's scoped commits. No schema migration, stored-data change,
publication, deployment, or external-system rollback is required.
