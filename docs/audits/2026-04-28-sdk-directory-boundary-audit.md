# AEGIS SDK Directory Boundary Audit

Date: 2026-04-28

## Scope

This audit identifies repository folders that are not required to be part of
the installable AEGIS runtime SDK wheel.

The SDK wheel boundary is defined by `pyproject.toml`:

- package discovery includes `aegis` and `aegis.*`
- package data includes `aegis/schemas/*.json` and `aegis/py.typed`

Therefore the required runtime SDK directory is `aegis/`, including its private
implementation package `aegis/_internal/` and runtime schema package
`aegis/schemas/`.

## Folders Not Required In The Runtime SDK Wheel

- `.git/`: version-control metadata.
- `.pytest_cache/`: local pytest cache.
- `.pytest_cache/v/`: local pytest cache internals.
- `aegis-env/`: local virtual environment.
- `aegis-env/bin/`: local virtual environment executables.
- `aegis-env/include/`: local virtual environment headers.
- `aegis-env/lib/`: local virtual environment packages.
- `aegis.egg-info/`: generated packaging metadata.
- `aegis/__pycache__/`: generated Python bytecode cache.
- `build/`: generated build output.
- `build/bdist.macosx-11.1-arm64/`: generated platform build output.
- `build/lib/`: generated build copy of package files.
- `demo-app-api/`: demo FastAPI backend.
- `demo-app-api/aegis-env/`: nested local virtual environment.
- `demo-app-api/__pycache__/`: generated Python bytecode cache.
- `demo-app-api/sample_policies/`: demo backend sample policies.
- `demo-app-api/tests/`: demo backend tests.
- `demo-app-react/`: demo React frontend.
- `demo-app-react/dist/`: generated frontend build output.
- `demo-app-react/node_modules/`: installed frontend dependencies.
- `demo-app-react/public/`: demo frontend public assets.
- `demo-app-react/src/`: demo frontend source.
- `docs/`: documentation, plans, ADRs, audits, and architecture material.
- `docs/architecture/`: architecture documentation and diagrams.
- `docs/articles/`: draft article material.
- `docs/audits/`: review artifacts and audit records.
- `docs/decisions/`: ADRs and decision records.
- `docs/design/`: release design specs.
- `docs/dev/`: maintainer and development context.
- `docs/plans/`: release planning artifacts.
- `docs/prs/`: pull request notes and review artifacts.
- `docs/reference/`: user-facing reference docs.
- `docs/superpowers/`: planning/spec artifacts.
- `examples/`: public examples and migration samples.
- `examples/migration/`: migration examples.
- `graphics/`: README and presentation imagery.
- `graphify-out/`: generated analysis output and cache.
- `graphify-out/cache/`: generated analysis cache.
- `graphify-out/converted/`: generated converted source artifacts.
- `policies/`: example/reference policies supplied externally by runtime users.
- `schemas/`: human-facing schema copies; runtime copies live in
  `aegis/schemas/`.
- `scripts/`: maintainer validation and generation scripts.
- `scripts/__pycache__/`: generated Python bytecode cache.
- `tests/`: test suite, fixtures, golden replays, and release contract tests.
- `tests/fixtures/`: test fixtures.
- `tests/golden_replays/`: golden replay fixtures.
- `tests/test_policies/`: test policy fixtures.
- `tests/__pycache__/`: generated Python bytecode cache.

## Notes

- `aegis/_internal/` is private API, but it is still required in the runtime
  SDK wheel because public modules delegate to it.
- `aegis/openai_agents_adapter.py` is part of the source-only beta package
  boundary, but it is optional at runtime and guarded by the `openai-agents`
  extra.
- `MANIFEST.in` intentionally allows some non-runtime folders into the source
  distribution, especially public docs, graphics, policies, schemas, and the
  React demo. That sdist policy is separate from the runtime SDK wheel
  boundary audited here.
