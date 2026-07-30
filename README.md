# AEGIS — Auditable Enforcement and Governance for Intelligent Systems

![AEGIS Banner](<graphics/aegis_banner.png>)

AEGIS is a Python SDK for deterministic, fail-closed governance of AI model
invocations. It validates every invocation against a declared policy, enforces
role and schema constraints, evaluates optional custom gates and risk scoring,
and emits checksum-based audit artifacts for every pass or fail path, with
optional signing and audit chaining for tamper-evidence.

Governance in AEGIS is runtime enforcement, not documentation and not prompting.

## At a Glance

- Distribution release: `aegis-ai-governance==0.9.0b1`
- Import: `import aegis`
- CLI: `aegis`
- Release status: public beta
- Source status: released from `main`
- Install: `pip install aegis-ai-governance==0.9.0b1`
- Previous PyPI line: `aegis==0.3.3` (`2026-04-10`)
- Release matrix: [docs/reference/RELEASE_MATRIX.md](docs/reference/RELEASE_MATRIX.md)
- Current release scope: invocation governance plus workflow-aware provenance
  and lineage groundwork, audit schema `v1.4`, `AuditLineage`,
  `ProvenanceGate`, `RiskHistory`, and `@governed` defaults to split enforcement
- Current beta line: `v0.9.0`, packaged as
  `aegis-ai-governance==0.9.0b1`
- Current-source verification baseline: `3138 tests` pass in the public-beta environment,
  including fixture-based optional-adapter coverage;
  coverage remains above the `90%` CI gate

Source, tags, and release artifacts for versions before `0.9.0` remain in
[`nealsolves/aigc`](https://github.com/nealsolves/aigc). This repository is the
AEGIS `0.9.0`-and-later development home.

## Threat Model

AEGIS protects against accidental bypass, misconfiguration, missing policy
inputs, invalid roles, invalid schemas, unsupported workflow transitions,
process-local reuse of split-enforcement handoff tokens, and host integration
mistakes.

AEGIS does not sandbox hostile in-process Python code, contain malicious
dependencies, isolate tenants, protect secrets placed into audit context by the
host, or replace provider, runtime, network, credential, trusted-checkpoint, or
storage controls. A valid signature is not necessarily externally anchored.
HMAC signatures and hash chains provide tamper-evidence, not immutable storage,
trusted time, replay prevention, sequence completeness, certification, or a
compliance determination.

## Why This Repo Exists

Most AI governance guidance stays advisory. AEGIS is opinionated about turning
governance into an executable contract:

- Policies are declarative YAML and validated against JSON Schema.
- Enforcement is deterministic and fail-closed.
- Audit artifacts are mandatory, structured, and checksum-based.
- Governance is model- and provider-agnostic.
- Split enforcement is available when hosts need pre-call authorization before
  token spend.

If a model call cannot be justified by policy and evidenced by an audit record,
AEGIS treats it as invalid.

## Runtime Model

AEGIS sits at the invocation boundary between the host application and the model
provider.

1. The host assembles an invocation and selects a policy.
2. AEGIS loads and resolves the policy, enforces ordered governance gates, and
   computes audit metadata.
3. AEGIS returns or emits a PASS/FAIL audit artifact that can be stored,
   exported, chained, or inspected offline.

Since v0.3.3, split enforcement is the default — Phase A runs before the model
call, Phase B validates output after. Pass `pre_call_enforcement=False` for the
legacy unified mode (deprecated).

The `v0.9.0b1` beta release adds workflow governance built around
`AEGIS.open_session(...)`, `GovernanceSession`, `SessionPreCallResult`,
`aegis workflow init`, `aegis policy init`, `aegis workflow lint`,
`aegis workflow doctor`, `aegis workflow trace`, and
`aegis workflow export`. No external API keys are required for the default
adopter path.

Current release: `aegis-ai-governance==0.9.0b1`. It installs
`import aegis` and the `aegis` CLI from the `main` release source.

Optional Bedrock, A2A, and OpenAI Agents adapters are beta submodules included
in the public-beta wheel. They are not re-exported from top-level `aegis`; the
OpenAI Agents adapter requires
`aegis-ai-governance[openai-agents]`. See the
[release matrix](docs/reference/RELEASE_MATRIX.md) for exact channel and ref
status. The target-state architecture is captured in
`docs/architecture/AEGIS_HIGH_LEVEL_DESIGN.md`.

The current source tree after `0.9.0b1` includes the source-only
`sign_artifact_with_metadata()` and `verify_artifact_detailed()` contracts.
They are not in the published `0.9.0b1` wheel or tag, and no later published
version is assigned yet. The host owns key resolution, credentials, provider
transport, availability behavior, and artifact storage. See the
[public integration contract](docs/PUBLIC_INTEGRATION_CONTRACT.md#38-artifact-signing-and-external-trust-results)
and [ADR-0012](docs/decisions/ADR-0012-external-trust-anchor-signing.md) for the
two-axis signature/anchor contract and its limits.

That source-only line now includes explicit
[AWS KMS](docs/reference/external/AWS_KMS_SIGNING.md) and
[Google Cloud KMS](docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md)
adapters in the same distribution. Install their optional extras with
`python -m pip install -e ".[aws-kms]"` or
`python -m pip install -e ".[gcp-kms]"` from this source checkout. The
supported algorithms are
`RSASSA_PSS_SHA_256`, `ECDSA_SHA_256`, `RSA_SIGN_PSS_2048_SHA256`,
`RSA_SIGN_PSS_3072_SHA256`, `RSA_SIGN_PSS_4096_SHA256`, and
`EC_SIGN_P256_SHA256`. Artifact metadata does not select provider resources;
the host owns exact-pair trust resolution, clients, credentials, retry and
timeout behavior, endpoints, regional/project configuration, IAM, trust
policy, and retained evidence. See
[ADR-0013](docs/decisions/ADR-0013-aws-google-kms-adapters.md) for identity,
rotation, release, and assurance boundaries.

## Workflow Governance (v0.9.0 Beta)

Workflow governance is available in the `v0.9.0b1` beta release. No external
API keys are required. Install the release, then:

```bash
pip install aegis-ai-governance==0.9.0b1
aegis workflow init --profile minimal
cd governance
python workflow_example.py
# Status:  COMPLETED
# Steps:   2
# Session: <uuid>
```

**First-adopter docs (read in this order):**

1. [Workflow Quickstart](docs/reference/WORKFLOW_QUICKSTART.md)
2. [Migration Guide](docs/migration.md)
3. [Troubleshooting](docs/reference/TROUBLESHOOTING.md)
4. [Starter Recipes](docs/reference/STARTER_RECIPES.md)
5. [Workflow CLI Reference](docs/reference/WORKFLOW_CLI.md)
6. [Public API Contract](docs/PUBLIC_INTEGRATION_CONTRACT.md)
7. [Supported Environments](docs/reference/SUPPORTED_ENVIRONMENTS.md)
8. [Operations Runbook](docs/reference/OPERATIONS_RUNBOOK.md)
9. [External Adapter Docs](docs/reference/external/README.md)

## Release Narrative

This is the versioned story of the repo's current state and how it evolved
release by release.

- `0.1.0` (`2026-02-16`): initial SDK with policy loading, role
  allowlists, preconditions, output schema validation, postconditions, and
  deterministic audit artifacts.
- `0.1.1` to `0.1.3` (`2026-02-17` to `2026-02-23`): installation and
  integration stabilization, including context in audit artifacts, absolute
  policy paths, packaged schemas, public API guidance, and the `aegis` PyPI
  package name.
- `0.2.0` (`2026-03-06`): SDK ergonomics and operability with
  instance-scoped `AEGIS`, typed preconditions, exception sanitization, policy
  caching, sink failure modes, audit schema `v1.2`, `InvocationBuilder`,
  AST-based guards, and policy CLI.
- `0.3.0` (`2026-03-15`): governance hardening with risk scoring, artifact
  signing, audit chain utility, pluggable `PolicyLoader`, policy dates,
  telemetry, policy testing, compliance export, and custom gate isolation.
- `0.3.1` (`2026-04-04`): demo parity release where the React demo and FastAPI
  backend became the maintained hands-on surface for all 7 labs.
- `0.3.2` (`2026-04-05`): split enforcement through `enforce_pre_call()` /
  `enforce_post_call()`, `PreCallResult`, split decorator mode, audit schema
  `v1.3`, and post-release security hardening from the 2026-04-05 audit.
- `0.3.3` (`2026-04-10`): workflow-aware provenance and lineage groundwork,
  including audit schema `v1.4` provenance metadata, `AuditLineage`,
  `ProvenanceGate`, `RiskHistory`, and `@governed` defaulting to split
  enforcement.
- `0.9.0b1` (public beta): workflow sessions, starter profiles, diagnostics,
  trace/export operations, and optional adapter submodules, distributed as
  `aegis-ai-governance` while preserving `import aegis` and the `aegis` CLI.

For the full change log, use [CHANGELOG.md](CHANGELOG.md).

## Installation

Install the public beta from PyPI:

```bash
pip install aegis-ai-governance==0.9.0b1
```

For contributor development, install an editable checkout:

```bash
python3 -m venv aegis-env
source aegis-env/bin/activate
pip install -e '.[dev]'
```

This standard source install expects access to PyPI or an internal package
mirror so pip can resolve `setuptools`, `PyYAML`, `jsonschema`, and their
transitive dependencies.

For restricted-network PR-07 proof runs, use
`python scripts/validate_v090_beta_proof.py` instead. That harness creates a
fresh venv with `system_site_packages=True` and installs this checkout with
`pip install --no-deps --no-build-isolation -e .` so it reuses the current
interpreter's installed Python packages without contacting an index.

## Quick Start

Unified enforcement remains the simplest integration path:

```python
from aegis import enforce_invocation

artifact = enforce_invocation(
    {
        "policy_file": "policies/base_policy.yaml",
        "model_provider": "anthropic",
        "model_identifier": "claude-sonnet-4-6",
        "role": "assistant",
        "input": {"query": "Summarize this incident"},
        "output": {"result": "Summary text", "confidence": 0.94},
        "context": {"role_declared": True, "schema_exists": True},
    }
)
```

For new code that needs isolated configuration, use the instance API:

```python
from aegis import AEGIS, JsonFileAuditSink

engine = AEGIS(sink=JsonFileAuditSink("audit.jsonl"))
artifact = engine.enforce(invocation)
```

## Split Enforcement in `v0.3.2`

Split mode lets you authorize before the model call and validate output after
the call:

```python
from aegis import enforce_post_call, enforce_pre_call

pre = enforce_pre_call(
    {
        "policy_file": "policies/base_policy.yaml",
        "model_provider": "anthropic",
        "model_identifier": "claude-sonnet-4-6",
        "role": "assistant",
        "input": {"query": "Summarize this incident"},
        "context": {"role_declared": True, "schema_exists": True},
    }
)

output = model.generate(...)
artifact = enforce_post_call(pre, output)
```

The `@governed` decorator uses split enforcement by default (since v0.3.3):

```python
from aegis import governed

@governed(
    policy_file="policies/base_policy.yaml",
    role="assistant",
    model_provider="anthropic",
    model_identifier="claude-sonnet-4-6",
)
def run_model(input_data, context):
    return model.generate(input_data)
```

Phase A runs before the model call; Phase B validates output after. Pass
`pre_call_enforcement=False` for legacy unified mode (deprecated).

## Interactive Demo

The maintained demo is a React frontend plus FastAPI backend:

- Beta site target:
  [https://nealsolves.github.io/aegis/](https://nealsolves.github.io/aegis/)
- Frontend deployment source:
  `.github/workflows/deploy-demo-react.yml` on `main`
- Backend deployment source: `demo-app-api/render.yaml` on `main`
- Live backend:
  [https://aegis-demo-api.onrender.com](https://aegis-demo-api.onrender.com)
- Public beta source: eleven hands-on labs across risk scoring, signing, audit
  chain, composition, loaders and policy dates, custom gates, compliance
  export, governed knowledge, governed-versus-ungoverned comparison, split
  enforcement, and workflow governance
- Public-beta additions: Lab 8 (Governed Knowledge Base), Lab 9 (Governed
  vs Ungoverned), Lab 10 (Split Enforcement), and Lab 11 (Workflow Governance)
- Purpose: hands-on orientation to both the `v0.3.x` invocation runtime and the
  `v0.9.0b1` workflow-governance public beta

The beta deployment is live from `main`. The Render `/health` endpoint returns
`status: ok` plus Render's deployed Git branch and commit, the Pages origin is
the only public CORS origin, and live browser checks passed for the split
pre-call block in Lab 1 and the two-step workflow artifact in Lab 11.

## CLI Surface

The `aegis` console script exposes three practical commands:

- `aegis policy lint <file...>` for syntax and schema checks
- `aegis policy validate <file...>` for semantic validation, including
  composition and cycle detection
- `aegis compliance export --input audit.jsonl [--output report.json] [--lineage]`
  for offline compliance reporting over stored audit trails; add `--lineage` to
  include DAG-level lineage analysis (node counts, duplicate detection,
  root/leaf/orphan lists, cycle detection)

The `v0.9.0b1` public beta adds `aegis workflow init`,
`aegis policy init`, `aegis workflow lint`, `aegis workflow doctor`,
`aegis workflow trace`, and `aegis workflow export`.

## SDK Package Boundary

The installable runtime SDK is the Python package under `aegis/`. The wheel is
configured by `pyproject.toml` to include `aegis` and `aegis.*`, plus package
data under `aegis/schemas/` and `aegis/py.typed`.

```text
aegis/
├── __init__.py                    Stable top-level public exports
├── enforcement.py                 Invocation and split-enforcement APIs
├── session.py                     v0.9.0-beta workflow session surface
├── workflow_trace.py              v0.9.0-beta trace helpers
├── workflow_export.py             v0.9.0-beta export helpers
├── a2a_adapter.py                 Optional beta A2A adapter
├── bedrock_adapter.py             Optional beta Bedrock adapter
├── openai_agents_adapter.py       Optional beta OpenAI Agents adapter
├── schemas/                       Runtime JSON Schemas packaged with the SDK
└── _internal/                     Private implementation used by public modules
```

Repo folders such as `docs/`, `tests/`, `scripts/`, `examples/`,
`demo-app-api/`, `demo-app-react/`, `policies/`, top-level `schemas/`, and
generated build/cache output are repository, documentation, demo, or maintainer
artifacts. They are not required in the runtime wheel.

## Repo Guide

If you are new to the repo, start here:

| Document | Why it matters |
| -------- | -------------- |
| [PROJECT.md](PROJECT.md) | Best repo-level orientation: architecture diagram, repo map, and release-by-release narrative |
| [Architecture Design](docs/architecture/AEGIS_HIGH_LEVEL_DESIGN.md) | Target-state `1.0.0` architecture contract and invariants |
| [Integration Guide](docs/INTEGRATION_GUIDE.md) | Host integration patterns, split-mode guidance, and compliance checklist |
| [Policy DSL Spec](policies/policy_dsl_spec.md) | Full policy format reference |
| [Cookbook](docs/USAGE.md) | Task-oriented recipes for common integration patterns |
| [Public Integration Contract](docs/PUBLIC_INTEGRATION_CONTRACT.md) | End-to-end runnable integration contract |

## Development Gates

Before release, the repo expects these checks to pass locally:

```bash
python -m pytest --cov=aegis --cov-report=term-missing --cov-fail-under=90
flake8 aegis
npx markdownlint-cli2 "**/*.md"
```
