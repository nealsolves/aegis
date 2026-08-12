# Issue #43 Public-Source Mappings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish NIST AI RMF 1.0 and a citation-only EU AI Act evidence catalog without requiring ISO, SOC 2, or professional review.

**Architecture:** The existing closed YAML catalog remains canonical, but its manifest accepts an explicit active subset and its review record uses four evidence-backed tiers. Two source-pinned modules feed the existing semantic validator and deterministic renderer; the publication gate composes subset, review, source, evidence, fixture, claims, baseline, and generated-page checks.

**Tech Stack:** Python 3.10+, PyYAML, jsonschema Draft 2020-12, pytest, Git object inspection, GitHub Actions, Markdown.

## Global Constraints

- Active modules are NIST AI RMF 1.0 and the citation-only EU AI Act index only.
- ISO/IEC 42001 and SOC 2 remain unpublished under Issues #76 and #77.
- Qualified EU legal review is optional under Issue #78.
- Review tiers are exactly `maintainer_verified`, `community_reviewed`, `qualified_reviewed`, and `unreviewed`.
- The only evidence states are `supported_evidence`, `partial_evidence`, `external_control`, and `not_addressed`.
- EU rows do not determine applicability for adopters, actors, systems, or use cases.
- Catalog validation is offline and deterministic for an explicit `--as-of YYYY-MM-DD`.

---

### Task 1: Active-Subset and Review-Tier Contract

**Files:**
- Modify: `schemas/compliance_mapping.schema.json`
- Modify: `scripts/compliance_catalog.py`
- Modify: `scripts/check_compliance_catalog.py`
- Modify: `scripts/render_compliance_catalog.py`
- Modify: `tests/test_compliance_catalog.py`

**Interfaces:**
- Produces: tier-aware `review` records, explicit active-module validation, EU row metadata validation, and renderer-derived review labels.
- Consumes: the existing `validate_framework_module`, `validate_publication`, and `render_framework` interfaces.

- [ ] Add failing behavior tests for two-module publication, every review tier, qualified-review support, overstatement rejection, EU row metadata, and actual-tier rendering.
- [ ] Run the focused tests and confirm failures are caused by the old four-module/role contract.
- [ ] Update the closed schema and semantic validation with the minimum new fields and tier rules.
- [ ] Update manifest checks and rendering, then run the focused tests green.

### Task 2: NIST AI RMF 1.0 Inventory and Mapping

**Files:**
- Create: `compliance/frameworks/nist-ai-rmf-1.0.yaml`
- Modify: `tests/test_compliance_catalog.py`

**Interfaces:**
- Produces: exactly 72 unique Core subcategory identifiers from GOVERN, MAP, MEASURE, and MANAGE.
- Consumes: pinned AEGIS audit, workflow, policy, test, command, and regulated-fixture evidence locators.

- [ ] Add a failing repository test with the hand-checked 72-identifier set, source pins, status rules, and fixture-link requirement.
- [ ] Run the test and confirm failure because the module is absent.
- [ ] Add the 72-row module with bounded original interpretations and explicit host/gap ownership.
- [ ] Run scope, mapping, and repository tests green.

### Task 3: Citation-Only EU AI Act Inventory and Mapping

**Files:**
- Create: `compliance/frameworks/eu-ai-act-2024-1689-amended-2026.yaml`
- Modify: `tests/test_compliance_catalog.py`

**Interfaces:**
- Produces: a literal bounded article/paragraph identifier set pinned to CELEX `32024R1689` and `32026R1744`.
- Consumes: the same evidence locator model plus per-row inclusion rationale and source-date fields.

- [ ] Add a failing repository test with the exact literal identifier set, expected count, source set, exclusions, non-applicability statement, and effective-date basis.
- [ ] Run the test and confirm failure because the module is absent.
- [ ] Add the citation-only module, using the 2026 amending act for effective-date treatment and never deciding legal applicability.
- [ ] Run scope, mapping, claims, and repository tests green.

### Task 4: Generated Publication and Maintained Entry Points

**Files:**
- Modify: `compliance/catalog.yaml`
- Create: `docs/reference/compliance/index.md`
- Generate: `docs/reference/compliance/nist-ai-rmf-1.0.md`
- Generate: `docs/reference/compliance/eu-ai-act-2024-1689-amended-2026.md`
- Modify: `.github/workflows/security-boundaries.yml`
- Modify: `.github/workflows/publish.yml`
- Modify: `.github/workflows/deploy-demo-react.yml`
- Modify: `README.md`
- Modify: `docs/reference/OPERATIONS_RUNBOOK.md`
- Modify: `MANIFEST.in`
- Modify: `tests/test_compliance_catalog.py`

**Interfaces:**
- Produces: deterministic active pages, a claims-safe catalog index, and `python scripts/check_compliance_catalog.py --as-of <UTC-date>` in maintained CI/public entrypoints.

- [ ] Add failing integration tests for index contents, deferral links, package inclusion, and all CI entrypoints.
- [ ] Update the two-module manifest, baseline pin, docs, package manifest, and workflows.
- [ ] Generate the two pages and run focused catalog, claims, parity, and demo-copy checks.

### Task 5: Exact-Commit Maintainer Review and Verification

**Files:**
- Modify after human review: both framework module review records and regenerated pages.

**Interfaces:**
- Consumes: an identified maintainer, exact reviewed commit SHA, AEGIS PR URL, decision, review date, and source-check confirmation.
- Produces: publishable `maintainer_verified` records without a professional-review claim.

- [ ] Commit the unreviewed implementation snapshot and provide its exact SHA for maintainer review.
- [ ] After an identified maintainer approves that exact snapshot, replace `unreviewed` records with truthful `maintainer_verified` records and regenerate pages.
- [ ] Run the publication checker, focused compliance suite, full pytest suite, flake8, claims checks, and documentation parity checks from a clean worktree.
- [ ] Re-read every Issue #43 acceptance criterion and report any remaining external dependency rather than weakening the gate.
