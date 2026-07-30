# AEGIS Supported Environments (v0.9.0 Beta)

This matrix applies to the `aegis-ai-governance==0.9.0b1` public beta.

## Target Python versions (provisional)

| Version | Status |
|---------|--------|
| Python 3.10 | Target / provisional |
| Python 3.11 | Target / provisional |
| Python 3.12 | Target / provisional |
| Python 3.13 | Target / provisional |
| Python 3.14 | Target / provisional |

Python 3.9 and earlier are not tested and not supported.

## Target operating systems (provisional)

| OS | Status |
|----|--------|
| macOS (Apple Silicon and Intel) | Target / provisional |
| Linux (x86-64) | Target / provisional |
| Windows (x86-64) | Target / provisional |

## Required packages

| Package | Minimum version | Purpose |
|---------|----------------|---------|
| `PyYAML` | `>=6.0` | Policy file parsing |
| `jsonschema` | `>=4.18,<5` | Policy and artifact schema validation |
| `google-re2` | `>=1.1.20251105` | Bounded-time policy pattern compilation |

All packages are listed in `pyproject.toml`. Normal source installs require
PyPI access (or an internal mirror). Install with:

```bash
pip install -e .
```

## Security-boundary CI target matrix (provisional)

The blocking `security-boundaries` check targets the policy compiler's RE2
smoke test at every Python and operating-system combination below. This matrix
is provisional: it does not itself expand the support claim. A lane becomes
supported only after its corresponding hosted `security-boundaries` lane
passes.

| Operating system | Python versions |
|------------------|-----------------|
| Ubuntu | 3.10, 3.11, 3.12, 3.13, 3.14 |
| macOS | 3.10, 3.11, 3.12, 3.13, 3.14 |
| Windows | 3.10, 3.11, 3.12, 3.13, 3.14 |

## Development extras

Install with the dev extras to also get the test runner and linter:

```bash
pip install -e ".[dev]"
```

| Package | Purpose |
|---------|---------|
| `pytest` | Test runner |
| `pytest-cov` | Coverage reporting |
| `flake8` | Python linting |

## Restricted-network proof runs

The PR-07 clean-environment proof harness uses a separate maintainer path for
restricted-network environments:

```bash
python scripts/validate_v090_beta_proof.py
```

That harness creates a fresh venv with `system_site_packages=True` and installs
this checkout with `pip install --no-deps --no-build-isolation -e .`, reusing
the current interpreter's installed `setuptools`, `PyYAML`, `jsonschema`, and
their transitive dependencies instead of contacting a package index.

## Not required

The following are explicitly **not required** for the default demo path or for
running any starter:

- External API keys (OpenAI, Anthropic, etc.)
- AWS Bedrock credentials
- A2A (Agent-to-Agent) setup
- `opentelemetry-api` or `opentelemetry-sdk`

`opentelemetry` is an optional integration. When it is not installed, all OTel
instrumentation is a no-op and governance is unaffected.
