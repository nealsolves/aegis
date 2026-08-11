# Issue #43 Compliance Mapping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a fail-closed, evidence-oriented compliance catalog contract with deterministic documentation, a reproducible regulated fixture, and explicit human-review gates for four framework modules.

**Architecture:** Canonical YAML is loaded through a bounded, non-executable loader and validated against a closed JSON Schema plus cross-file semantic rules. A deterministic renderer produces checked-in Markdown, while a publication checker composes schema, evidence-locator, claims, review-date, baseline-drift, generated-parity, and fixture-contract validation. Framework content remains separate from the validator so each inventory can receive focused human review.

**Tech Stack:** Python 3.10+, PyYAML 6+, jsonschema 4.18+, pytest, Git object inspection, GitHub Actions.

## Global Constraints

- Catalog version `1.0.0` maps full commit `a9d0e4967070a11474ab11b23b047a5cde4b0892`, not the published `aegis-ai-governance==0.9.0b1` wheel.
- Catalog YAML is data only and must never select executable code, commands, callbacks, modules, or fixture behavior.
- The only support states are `supported_evidence`, `partial_evidence`, `external_control`, and `not_addressed`; none claims control satisfaction.
- ISO source-derived fields require `licensed_human_review_without_ai_processing` and qualified maintainer input that is never supplied to automated processing.
- EU scope identifiers require qualified legal/compliance authorship and review before evidence mapping begins.
- Publication validation is offline, deterministic for an explicit `--as-of YYYY-MM-DD`, and fails closed.

---

### Task 1: Core Catalog Contract

**Files:**
- Create: `schemas/compliance_mapping.schema.json`
- Create: `scripts/compliance_catalog.py`
- Create: `scripts/check_compliance_catalog.py`
- Create: `scripts/render_compliance_catalog.py`
- Create: `tests/test_compliance_catalog.py`

**Interfaces:**
- Produces: `load_yaml(path: Path) -> dict[str, object]`, `validate_catalog(root: Path, *, module: Path | None, phase: str, as_of: date) -> tuple[CatalogData | None, tuple[Finding, ...]]`, `render_catalog(catalog: CatalogData, output_dir: Path) -> dict[Path, str]`.
- Consumes: `scripts.check_evidence_claims.TextBlock` and `scan_claims` for public prose.

- [ ] Write parameterized failing tests for bounded YAML loading, schema closure, source/control uniqueness, phase-specific mapping rules, status semantics, evidence resolution, claims scanning, review expiry, baseline drift, and generated parity.
- [ ] Run `python -m pytest tests/test_compliance_catalog.py -q` and confirm failures are caused by the absent contract.
- [ ] Implement the strict loader, schema validation, cross-file model, Git-backed evidence resolution, claims adapter, and bounded findings.
- [ ] Run the focused tests until green, then refactor shared model/renderer helpers without changing behavior.
- [ ] Add renderer tests for deterministic ordering, escaping, exact status labels, disclaimers, source pins, review dates, and current-source availability language; confirm red then green.

### Task 2: Regulated Workflow Fixture

**Files:**
- Create: `examples/compliance/regulated_workflow.py`
- Create: `tests/test_compliance_fixture.py`

**Interfaces:**
- Produces: `run(output_dir: Path) -> dict[str, Path]`, writing fixed policy, invocation evidence, and workflow evidence without network access.
- Consumes: public `aegis` APIs only; the checker invokes only this fixed Python-owned harness after baseline validation.

- [ ] Write a failing test that runs the fixture into `tmp_path`, validates produced schemas/checksums, and asserts fixed policy/provenance/workflow fields.
- [ ] Run `python -m pytest tests/test_compliance_fixture.py -q` and confirm it fails because the fixture is absent.
- [ ] Implement deterministic non-production evidence generation with caller-supplied output only and no YAML-selected execution.
- [ ] Add failing negative tests for altered evidence and runtime drift preventing fixture execution; implement the minimal validation hook and rerun focused tests.

### Task 3: Canonical Manifest and Public Claims Policy

**Files:**
- Create: `compliance/catalog.yaml`
- Create: `docs/reference/COMPLIANCE_CLAIMS_AND_TERMINOLOGY.md`
- Modify: `tests/test_compliance_catalog.py`

**Interfaces:**
- Produces: the versioned manifest, exact AEGIS baseline, four-module inventory, review policy, update triggers, and bounded public terminology consumed by all generated pages.

- [ ] Write failing repository-fixture tests for the exact module inventory, baseline channel, runtime paths, disclaimer, review intervals, and claims-safe prose.
- [ ] Add the manifest and terminology guide with the four-state decision table and assurance boundaries.
- [ ] Run `python -m pytest tests/test_compliance_catalog.py -q` and `python scripts/check_evidence_claims.py`.

### Task 4: Framework Modules and Generated Pages

**Files:**
- Create: `compliance/frameworks/nist-ai-rmf-1.0.yaml`
- Create: `compliance/frameworks/iso-iec-42001-2023.yaml`
- Create: `compliance/frameworks/soc2-tsc-2017-revised-2022.yaml`
- Create: `compliance/frameworks/eu-ai-act-2024-1689-amended-2026.yaml`
- Create: `docs/reference/compliance/index.md`
- Generate: `docs/reference/compliance/*.md`

**Interfaces:**
- Each module supplies exact source pins, declared scope/count, review record, and mapping rows consumed by `validate_catalog` and `render_catalog`.

- [ ] Load reviewed NIST and SOC identifier inventories, write scope tests, and run each module through `--phase scope` before adding mappings.
- [ ] Add evidence mappings test-first, requiring positive rows to cite pinned AEGIS evidence and executable tests while gap rows remain evidence-free.
- [ ] Accept ISO identifiers and all source-derived fields only from a licensed qualified maintainer; validate but do not generate or paraphrase them.
- [ ] Accept the EU article/paragraph inventory only from a qualified legal/compliance reviewer; run scope validation before attaching evidence.
- [ ] Render pages and verify byte-for-byte parity.

### Task 5: Publication and Maintenance Integration

**Files:**
- Modify: `.github/workflows/security-boundaries.yml`
- Modify: `.github/workflows/publish.yml`
- Modify: `.github/workflows/deploy-demo-react.yml`
- Modify: `docs/reference/OPERATIONS_RUNBOOK.md`
- Modify: `README.md`
- Modify: `MANIFEST.in`
- Modify: `tests/test_compliance_catalog.py`

**Interfaces:**
- Produces: `python scripts/check_compliance_catalog.py --as-of YYYY-MM-DD` as the single publication gate.

- [ ] Write failing integration tests for required entry-point links, package inclusion, explicit CI review date, unlisted modules, stale pages, missing review provenance, and overdue reviews.
- [ ] Wire the checker into security, release, and demo workflows with one UTC date value per job; document the local commands and catalog boundaries.
- [ ] Run focused compliance tests, claims guard, documentation parity, demo-copy check, flake8, and the complete Python suite.
- [ ] Review the final diff against every acceptance-criteria row in the approved design and record any human-gated publication inputs still missing.
