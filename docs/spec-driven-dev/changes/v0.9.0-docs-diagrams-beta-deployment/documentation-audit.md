# Requested Documentation Audit

**Audited:** 2026-07-25

**Code baseline:** `origin/develop` at `fdf3649` (PR #18)

**Candidate:** `aegis-ai-governance==0.9.0b1`

**Scope:** every Markdown file in `docs/reference/` and
`docs/reference/external/`, plus the four requested top-level guides.

## Method

Each document was checked against the public package exports, CLI parser,
packaged and repository schema copies, adapter/session implementations,
demo/backend tests, first-adopter functional tests, release-parity checks, and
maintained Markdown inbound links. The executable checks included:

```text
scripts/check_public_docs_no_internal_imports.py
scripts/check_doc_parity.py
tests/test_doc_parity_v090_truth.py
tests/test_public_api_contract.py
tests/test_cli.py
tests/test_workflow_cli.py
tests/test_workflow_functional.py
tests/test_starter_smoke.py
tests/test_adapter_public_boundary.py
tests/test_bedrock_adapter_contract.py
tests/test_a2a_adapter_contract.py
tests/test_openai_agents_adapter_contract.py
```

The inbound-link counts below count other maintained Markdown files that name
the audited file. A zero count would not alone justify deletion; reader,
overlap, and code truth are decisive.

## File Decisions

| Path | Durable reader and purpose | Authoritative code/tests | Inbound links | Finding | Decision |
| --- | --- | --- | ---: | --- | --- |
| `docs/AEGIS_FRAMEWORK.md` | Product and architecture readers; evolutionary Contract/Control/Check narrative | Public enforcement/session surfaces, audit schemas, architecture truth tests | 8 | Runtime narrative remains accurate; old-release source repository was ambiguous | Retain; add pre-v0.9 repository boundary |
| `docs/INTEGRATION_GUIDE.md` | Host integrators; ownership boundary and integration patterns | Public exports, enforcement/session tests, public-doc import checker | 15 | Examples and ownership boundary match code; old-release source repository was ambiguous | Retain; add pre-v0.9 repository boundary |
| `docs/PUBLIC_INTEGRATION_CONTRACT.md` | First integration and public API reference | `aegis.__all__`, public API contract tests, CLI and adapter boundary tests | 27 | Public names, optional-submodule boundary, and examples match code; old-release source repository was ambiguous | Retain; add pre-v0.9 repository boundary |
| `docs/USAGE.md` | Task-oriented cookbook readers | Enforcement, sink, gate, loader, lineage, compliance, and risk tests | 12 | Recipes match public code and use no internal imports; old-release source repository was ambiguous | Retain; add pre-v0.9 repository boundary |
| `docs/reference/OPERATIONS_RUNBOOK.md` | Maintainers/operators running validation and evidence commands | Validation scripts, `pyproject.toml`, CI workflows | 14 | Commands and beta boundaries remain current | Retain; no change |
| `docs/reference/RELEASE_MATRIX.md` | Maintainers and adopters needing canonical channel/ref truth | Package metadata, `aegis.__version__`, git refs, release parity tests | 7 | Still named PR #17 as the current ref and did not identify the historical repository | Retain; update PR #18 baseline and pre-v0.9 ownership |
| `docs/reference/STARTER_INDEX.md` | New workflow adopters choosing a starter | CLI parser, preset/scaffold generation and smoke tests | 6 | Profiles, links, and positioning match code | Retain; no change |
| `docs/reference/STARTER_RECIPES.md` | Adopters executing/customizing starter profiles | Starter fixtures, scaffold generation, functional and integrity tests | 11 | Commands, generated paths, approvals, and roles match code | Retain; no change |
| `docs/reference/SUPPORTED_ENVIRONMENTS.md` | Installers and maintainers selecting Python/OS/dependencies | `pyproject.toml`, CI matrices, optional-extra tests | 8 | Supported versions and dependency boundaries match manifests | Retain; no change |
| `docs/reference/TROUBLESHOOTING.md` | Operators diagnosing workflow failures | Doctor/lint implementations, frozen reason-code and failure-flow tests | 13 | Reason codes and repair flows match executable behavior | Retain; no change |
| `docs/reference/WORKFLOW_CLI.md` | CLI users needing complete command/field reference | CLI parser, trace/export schemas, CLI and functional tests | 13 | Commands, flags, schema versions, and output fields match code | Retain; no change |
| `docs/reference/WORKFLOW_QUICKSTART.md` | First-time workflow adopters | Minimal starter generation and clean-environment proof | 13 | Default no-credential path and expected completion match tests | Retain; no change |
| `docs/reference/external/A2A_ADAPTER.md` | Advanced A2A host integrators | `aegis.a2a_adapter`, protocol/fixture/public-boundary tests | 7 | Imports, supported bindings, strict validation, and ownership boundary match code | Retain; no change |
| `docs/reference/external/BEDROCK_ADAPTER.md` | Advanced Bedrock host integrators | `aegis.bedrock_adapter`, alias/redaction/replay tests | 6 | Imports, host-owned transport, evidence, and replay behavior match code | Retain; no change |
| `docs/reference/external/OPENAI_AGENTS_ADAPTER.md` | Advanced OpenAI Agents SDK integrators | Optional-extra adapter module and contract/fixture tests | 9 | Installation extra, public methods, HITL, tracing, and rejected surfaces match code | Retain; no change |
| `docs/reference/external/README.md` | Adopters deciding whether and how to use optional adapters | Packaging boundary, top-level export and optional-dependency tests | 38 | Adapter index and “not top-level re-exported” boundary match code | Retain; no change |

## Deletion Decision

No requested Markdown file is deleted. Each has a distinct maintained reader
and purpose, every file has multiple maintained inbound links, and the
executable checks found no obsolete duplicate whose removal would improve the
project. The update therefore corrects demonstrated release-history/ref drift
without creating churn in already-accurate guides.
