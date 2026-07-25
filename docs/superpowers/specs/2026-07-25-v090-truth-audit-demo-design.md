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

## Release-State Truth

Every maintained current-state document must preserve these distinctions:

| Claim | Required truth |
|---|---|
| Product | AEGIS |
| Repository | `nealsolves/aegis` |
| Candidate distribution | `aegis-ai-governance==0.9.0b1` |
| Python import | `aegis` |
| Console command | `aegis` |
| Candidate location | Merged into `origin/develop`; not merged into `main` |
| PyPI state | Pending Trusted Publisher; candidate not published |
| Previous PyPI line | Historical `aegis==0.3.3` |
| Runtime dependency change | None in this documentation/demo task |

A pending publisher is configuration evidence, not publication evidence.
Historical “introduced in v0.3.3” statements remain valid where they describe
the origin of split-by-default behavior, provenance, lineage, or risk history.
They must not be rewritten as current package identity.

Volatile commit, test-count, and artifact claims must be refreshed from the
exact branch or validation run they describe. The implementation must not copy
an old PR state such as “PR #17 under review” after that PR has merged.

## Documentation Scope

The implementation begins with a tracked-document inventory. Every
documentation-like file returned by Git—including Markdown, maintained diagram
HTML/source, and checked-in diagram assets—must be assigned to exactly one of:

1. maintained current-state;
2. maintained target-state;
3. historical evidence or versioned history; or
4. active instruction-system documentation.

No tracked documentation file may remain unclassified. “Reviewed, no change
needed” is a valid result only when its claims were checked against an
authoritative source. The final evidence must record the inventory and changed
paths without copying volatile command output into durable guides.

### Maintained current-state documentation

Audit and update:

- `README.md`, `PROJECT.md`, `CONTRIBUTING.md`, `SECURITY.md`,
  `RELEASE_GATES.md`, `implementation_status.md`, the root architectural
  forwarding stub, and only the unreleased/current-state portion of
  `CHANGELOG.md`;
- SDK framework, usage, integration, and public-contract guides;
- `policies/policy_dsl_spec.md`, which identifies itself as authoritative and
  must cover the implemented workflow DSL rather than only the older invocation
  policy fields;
- current architecture, threat-model, and enforcement documentation;
- workflow quickstart, CLI, operations, troubleshooting, starter, migration,
  supported-environment, and release-matrix references;
- optional adapter references and their index;
- `demo-app-react/README.md`;
- React architecture copy and contextual help content;
- executable documentation parity checks and their tests.

The audit must also correct repository-wide contradictions discovered in these
files, including license identity. `pyproject.toml` and `LICENSE` declare
Apache-2.0, so maintained contributor documentation must not claim MIT.

`SECURITY.md` contains owner commitments rather than executable behavior.
Preserve its existing 0.3.x support and response commitments. Add the
unpublished `0.9.0b1` candidate only as pre-release/testing status; do not infer
or expand a support promise from repository code.

### Target-state documentation

Keep target-state documents clearly labeled, but correct their
implemented-versus-planned inventories. A target-state document must not call an
already packaged beta surface planned-only, and must not present an internal
surface as public.

This includes `docs/architecture/AEGIS_HIGH_LEVEL_DESIGN.md` and any current
roadmap/status table that readers could reasonably interpret as present-state
availability.

### Historical documentation

Do not rewrite plans, audits, ADRs, articles, archived release evidence,
completed design specifications, or completed spec-driven-dev evidence. They
remain historical records even when their contemporary version statements are
old.

`docs/dev/pr_context.md` is a completed PR-10-era development record and is
treated as historical rather than current release truth. Likewise,
`docs/architecture/AEGIS_0.3.0_ARCHITECTURE_DIAGRAM.md` remains a versioned
historical architecture record. Current docs must not route readers to either
file as present-state authority.

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

The checked-in source under `docs/architecture/diagrams/` is canonical. The
React assets under `demo-app-react/public/diagrams/` are generated or mirrored
outputs, not an independent design source. Validation must prove that the React
copies match the canonical outputs selected by `ArchitecturePage`.

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

Both diagrams require useful alternative text and an intelligible unavailable
state. The existing theme switch, horizontal overflow handling, and responsive
container behavior must remain functional.

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
source and reproduced deterministically. The generation command and the
canonical-to-React copy rule must be documented next to the source or in the
maintained architecture documentation.

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

No new runtime dependency is added. Installing the already-declared extra is a
validation action confined to an isolated test environment.

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

The browser pass must include the Architecture guide and every contextual guide
for Labs 1–11. Representative assembled flows must include the Lab 11 successful
workflow, intentional failure-and-fix diagnosis, and evidence-trace path because
those are the v0.9 demo requirements.

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
- The active `.claude/rules/aegis-project.md` currently contains stale package
  status. Correcting only those factual status lines is required for the
  all-maintained-docs goal, but it is an instruction-system change and therefore
  requires its own bounded owner authorization under the installed
  constitution. No other instruction behavior may change under that
  authorization.
- Keep commits scoped and reversible.
- Any eventual remote pull request targets `develop` only and requires the
  repository's configured authority.
- Do not merge the branch and do not create or merge anything targeting
  `main`.

## Acceptance Criteria

- [ ] Maintained current-state docs agree with implemented v0.9 beta behavior.
- [ ] Contributor and security guidance identifies the current package/support
      state and Apache-2.0 license without inventing publication.
- [ ] The authoritative policy DSL guide matches the current schemas, including
      workflow governance.
- [ ] Historical records remain unchanged.
- [ ] Target-state inventories distinguish implemented, internal, public, and
      planned surfaces accurately.
- [ ] A focused Bedrock adapter reference replaces the unrelated copied page.
- [ ] React architecture diagrams and copy show only the current beta surface.
- [ ] Canonical diagram sources reproduce the documentation and React assets.
- [ ] Architecture and Labs 1–11 retain accurate contextual help.
- [ ] Stable drift checks fail on candidate, diagram, help, or adapter-doc
      regressions.
- [ ] Base adapter tests pass without provider SDK dependencies.
- [ ] OpenAI Agents real-SDK integration runs with the declared extra.
- [ ] Full Python and React validation passes.
- [ ] Browser validation passes in light/dark and relevant responsive states.
- [ ] Lab 11 browser validation covers success, failure/fix, and evidence trace.
- [ ] The bounded instruction-guide status correction is separately authorized
      and contains no policy or behavioral change.
- [ ] The change remains isolated from `main`.

## Design-to-Acceptance Map

| Approved design element | Specification section | Primary evidence |
|---|---|---|
| Truth-audited maintained docs | Documentation Scope | parity tests, link checks, reviewed diff |
| Historical records untouched | Historical documentation | path inventory and diff exclusion |
| v0.9 React architecture | React Architecture Experience | page tests, generated assets, browser pass |
| Contextual sidebar help | Contextual Help | help fidelity tests and Labs 0–11 browser pass |
| Stronger parity controls | Documentation Drift Controls | parity checker unit/integration tests |
| Bedrock, A2A, OpenAI adapter tests | Adapter Verification | base and extra-enabled test matrices |
| Host-owned execution boundary | Architecture and adapter sections | diagram/help assertions and adapter docs |
| No merge to `main` | Spec-Driven and Git Boundaries | branch/remote status evidence |

## Reversal

Revert this branch's scoped commits. No schema migration, stored-data change,
publication, deployment, or external-system rollback is required.
