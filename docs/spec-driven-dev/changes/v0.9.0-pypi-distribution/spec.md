# AEGIS v0.9.0 PyPI Distribution Specification

**Change ID:** `v0.9.0-pypi-distribution`

**Status:** Approved

**Approved by:** Neal Adams

**Approval basis:** The repository owner approved
`aegis-ai-governance`, configured its pending PyPI Trusted Publisher, and
directed this project to proceed through `nealsolves/spec-driven-dev`.

**Target candidate:** `0.9.0b1`

## Problem

The product, repository, import package, and CLI are named AEGIS, but the
`aegis` distribution name is unavailable to this project on PyPI. Ownership of
that distribution name must not block the v0.9.0 workflow beta.

Python distribution names and import package names are separate contracts:

```text
pip install aegis-ai-governance
             |
             +--> import aegis
             +--> aegis workflow ...
```

## Required Contract

| Surface | Required value |
|---|---|
| Product | `AEGIS` |
| Repository | `nealsolves/aegis` |
| PyPI distribution | `aegis-ai-governance` |
| Normalized artifact stem | `aegis_ai_governance` |
| Python import | `aegis` |
| Console command | `aegis` |
| Candidate version | `0.9.0b1` |
| Trusted Publisher workflow | `.github/workflows/publish.yml` |
| Trusted Publisher environment | `pypi` |

The distribution rename must not rename the import package, public API, or
console command.

## Goals

1. Remove the unavailable `aegis` PyPI distribution name as a release blocker.
2. Build matching wheel and source artifacts for
   `aegis-ai-governance==0.9.0b1`.
3. Prove a fresh wheel installation supports the complete default v0.9.0
   workflow journey without importing from the source checkout.
4. Align maintained release documentation and executable parity checks.
5. Add a Trusted Publishing workflow matching the pending PyPI publisher.
6. Stop at `RELEASE_READY`; do not upload without a separate exact publication
   authorization.

## Non-Goals

- Renaming AEGIS, `nealsolves/aegis`, the `aegis` package, or the `aegis` CLI.
- Removing the declared runtime dependencies `PyYAML` or `jsonschema`.
- Publishing an alias or compatibility project named `aegis`.
- Changing workflow governance, schemas, adapters, or runtime behavior.
- Automatically creating a GitHub release or publishing to PyPI.
- Absorbing or cleaning the original checkout's unrelated local changes.

## Package Metadata

`pyproject.toml` is the distribution source of truth:

```toml
[project]
name = "aegis-ai-governance"
version = "0.9.0b1"

[project.scripts]
aegis = "aegis.cli:main"
```

`aegis.__version__` must also be `0.9.0b1`. Executable checks must reject a
mismatch among source metadata, runtime metadata, built artifact metadata,
artifact filenames, and maintained release documentation.

The wheel must continue to contain only the `aegis` runtime package tree,
packaged schemas, `py.typed`, required distribution metadata, and the `aegis`
entry point.

## Installation Contract

```bash
python -m pip install aegis-ai-governance
aegis --help
```

```python
import aegis
from aegis import AEGIS
```

Optional OpenAI Agents integration remains:

```bash
python -m pip install "aegis-ai-governance[openai-agents]"
```

Bedrock and A2A remain usable without adding provider SDKs to the base
installation.

## Fresh-Wheel End-to-End Proof

The proof must use newly built artifacts and a new Python 3.12 virtual
environment. It must not use an editable install, inherit source-checkout
imports, require credentials, or call an external model provider.

The proof must:

1. Build wheel and source distribution artifacts.
2. Verify both normalized filenames and embedded metadata.
3. Install the wheel into a new environment and run `pip check`.
4. Verify `importlib.metadata.version("aegis-ai-governance")`.
5. Verify `aegis.__version__`, `import aegis`, `from aegis import AEGIS`, and
   the `aegis --help` entry point.
6. Verify the imported module resolves inside the new environment rather than
   the source checkout.
7. Generate and complete the `minimal` starter.
8. Generate and complete the `standard` starter with its approval checkpoint.
9. Generate the `regulated-high-assurance` starter, deliberately remove
   required source evidence, observe failure, diagnose
   `WORKFLOW_SOURCE_REQUIRED`, restore the starter, and reach `COMPLETED`.
10. Persist invocation/workflow evidence, trace the session, and export both
    operator and audit views with intact correlation.

## Documentation Contract

Maintained documentation must:

- use `pip install aegis-ai-governance`;
- explain that the distribution installs `import aegis` and the `aegis` CLI;
- identify `0.9.0b1` as beta, not GA;
- distinguish historical `aigc`/`0.3.x` releases from the new distribution;
- align README, PROJECT, changelog, implementation status, release gates,
  release matrix, quickstart, supported environments, and parity checks.

Archived plans and audits may retain historical statements when their archived
status is explicit.

## Trusted Publishing Contract

The workflow must match the confirmed pending publisher:

- project `aegis-ai-governance`;
- repository `nealsolves/aegis`;
- workflow `publish.yml`;
- environment `pypi`.

It must build once, validate the candidate, pass artifacts between jobs, use
GitHub OIDC only in the publish job, and require the protected `pypi`
environment. Third-party actions must be pinned to immutable revisions.

The workflow may prepare publication but must not be dispatched during this
task.

## Failure Conditions

The change fails closed if:

- any metadata source, artifact, or maintained release document disagrees;
- the fresh environment imports from the checkout;
- `pip check` fails or the CLI is missing;
- any required success journey fails;
- the deliberate regulated failure does not fail;
- doctor emits the wrong reason code;
- trace/export loses evidence correlation;
- packaged schemas or `py.typed` are missing;
- the publish workflow grants broader permissions than required.

## Rollback

Before publication, revert the implementation commits. After publication, PyPI
artifacts cannot be replaced; a correction requires a new candidate such as
`0.9.0b2`. A broken release may be yanked, but its version remains permanent.

## Acceptance Criteria

- [ ] Source and runtime metadata identify
  `aegis-ai-governance==0.9.0b1`.
- [ ] Wheel and source distribution metadata and filenames match.
- [ ] Fresh wheel installation provides `import aegis` and the `aegis` CLI.
- [ ] Minimal, standard, and regulated failure/fix journeys pass.
- [ ] Trace and both export modes preserve evidence correlation.
- [ ] Maintained documentation consistently uses the new install name.
- [ ] `publish.yml` matches the pending Trusted Publisher and is least
  privileged.
- [ ] Full Python, API, React, build, and release-parity gates are reported
  with exact evidence.
- [ ] No PyPI upload, GitHub release, remote push, or merge occurs without a
  separate authorization.
