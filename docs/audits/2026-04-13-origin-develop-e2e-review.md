# AIGC `origin/develop` End-to-End Functionality and Doc Alignment Review

- **Audited commit (`origin/develop`)**: `af0e3fb267fbe4404f33cdf22ebf528480f6aea1`
- **Audit date**: `2026-04-13`
- **Auditor branch**: `audit/origin-develop-e2e-2026-04-13`

## Scope reviewed

- Public SDK API exported from `aegis/__init__.py`
- Unified and split enforcement flows (sync + async)
- `AIGC` instance API and `@governed` defaults
- `InvocationBuilder`
- Policy loading/composition/date validation
- Guards, conditions, role validation, tool constraints, schema validation, postconditions, risk scoring
- Custom gates and insertion points
- Audit artifact generation + schema alignment
- Audit sinks and sink-failure behavior
- Signing/verification
- Audit chain, lineage, provenance, risk history
- CLI commands/tests/examples
- Demo app API and React labs surfaces
- User-facing docs called out in the prompt
- `doc_parity_manifest.yaml` and parity checker behavior

## Methodology and evidence sources

1. Established branch/commit baseline to ensure review anchored to `origin/develop`.
2. Read public API and core enforcement implementation (`aegis/__init__.py`, `aegis/_internal/enforcement.py`, and related internal modules).
3. Cross-checked runtime contracts against JSON schemas in `aegis/schemas/` and mirrored root `schemas/`.
4. Reviewed major documentation surfaces listed in the prompt as claims to verify.
5. Used representative and targeted tests as executable evidence of shipped behavior.
6. Exercised end-user surfaces via local tests for CLI, demo API, and demo React labs.

Primary executable verification run during audit:

- `python scripts/check_doc_parity.py`
- `pytest -q tests/test_public_api.py tests/test_enforcement_pipeline.py tests/test_split_enforcement.py tests/test_split_enforcement_aigc_instance.py tests/test_split_enforcement_edge_cases.py tests/test_async_enforcement.py tests/test_decorators.py tests/test_decorators_split_mode.py tests/test_governed_default_flip.py tests/test_builder.py`
- `pytest -q tests/test_policy_loader.py tests/test_policy_composition.py tests/test_policy_dates.py tests/test_conditions.py tests/test_guards.py tests/test_tools.py tests/test_validation.py tests/test_risk_scoring.py tests/test_custom_gates.py tests/test_custom_gate_failure_mapping.py tests/test_custom_gate_exception_artifacts.py tests/test_custom_gate_metadata.py`
- `pytest -q tests/test_audit_artifact_contract.py tests/test_audit_artifact_split_metadata.py tests/test_audit_sinks.py tests/test_signing.py tests/test_audit_chain.py tests/test_audit_lineage.py tests/test_audit_provenance.py tests/test_risk_history.py tests/test_cli.py tests/test_cli_lineage.py tests/test_compliance_export.py tests/test_chain_schema_compliance.py tests/test_checksum_determinism.py`
- `pytest -q tests` (in `demo-app-api/`)
- `npm test -- --run` (in `demo-app-react/`)

## Executive summary

- Core runtime functionality on `origin/develop` is internally consistent and well-covered by targeted tests across SDK, enforcement flows, audit pipeline, CLI, and demo surfaces.
- The highest-impact mismatches are documentation defects, not implementation defects.
- No evidence was found requiring speculative behavior changes to runtime code for this audit scope.

## Findings table

| ID | Area | Severity | Classification | Observed Behavior | Expected / Documented Behavior | Code Evidence | Doc Evidence | Why this evaluation is correct | Required Fix | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| F-001 | Release framing (`PROJECT.md`) | High | DOC_BUG | The shipped package and changelog indicate `0.3.3` is current. | `PROJECT.md` should not claim `0.3.2` as current. | `aegis/__init__.py:92` (`__version__ = "0.3.3"`); `pyproject.toml:9`; `CHANGELOG.md:10`. | Pre-fix evidence: `PROJECT.md:205-206` said `0.3.2` was current. | Runtime/package metadata and changelog are authoritative release truth; this was stale narrative wording. | Update release-history wording so `0.3.3` is current and `0.3.2` is historical. | Fixed |
| F-002 | Release framing (`PROJECT.md`) | Medium | DOC_BUG | `0.3.3` features are already present and tested in this commit. | `PROJECT.md` should not mark `0.3.3` as "in progress" if shipped. | `aegis/_internal/enforcement.py` includes lineage/provenance/risk-history integrations; tests `tests/test_audit_lineage.py`, `tests/test_audit_provenance.py`, `tests/test_risk_history.py` pass. | Pre-fix evidence: `PROJECT.md:229` labeled `0.3.3` “in progress”. | Executable surface and release metadata show shipped behavior; this wording was stale and misleading. | Change heading/body language from in-progress to released state. | Fixed |
| F-003 | Audit artifact contract wording (`AIGC_HIGH_LEVEL_DESIGN.md`) | High | DOC_BUG | FAIL paths also emit audit artifacts and attach them to raised exceptions. | Design doc should state artifact generation for every enforcement attempt (PASS and FAIL). | `aegis/_internal/enforcement.py:968-985`, `1119-1133` (FAIL artifact generation/attachment). | Pre-fix evidence: `docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md:60`, `:735` described “successful enforcement” only. | Runtime behavior is explicit and tested; “successful only” understated the forensic contract. | Replace “successful enforcement” wording with “every enforcement attempt; PASS returned, FAIL attached to exception”. | Fixed |
| F-004 | Design doc metadata header (`AIGC_HIGH_LEVEL_DESIGN.md`) | Low | DOC_BUG | Document body includes `v0.3.3`/schema `v1.4` content, but header still said `Version: 1.3.0` and older update date. | Header metadata should match the current document state. | `aegis/schemas/audit_artifact.schema.json` supports `schema_version` values including `v1.4`; provenance support in runtime/tests. | Pre-fix evidence: `docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md:5` had stale metadata. | Internal doc inconsistency can create false assumptions about currency/authority. | Update version and last-updated header metadata to current audit date and schema line. | Fixed |
| F-005 | Public integration contract example correctness | Medium | DOC_BUG | Example code referenced `PolicyLoadError` and `yaml.safe_load` without importing them. | Public contract examples should be copy-paste runnable as shown. | `aegis/__init__.py` exports `PolicyLoadError`; runtime loader interface expects real parse path. | Pre-fix evidence: `docs/PUBLIC_INTEGRATION_CONTRACT.md:727-739` omitted imports for used symbols. | This was a direct example defect, not runtime behavior defect. | Add `import yaml` and `PolicyLoadError` import in the snippet. | Fixed |
| F-006 | SDK public API surface | Medium | NO_ISSUE | Exported symbols and wrappers align with docs/test expectations. | Public API should expose stable symbols in `aegis/__init__.py`. | `aegis/__init__.py`; `tests/test_public_api.py` pass. | `README.md`, `docs/USAGE.md`, `docs/PUBLIC_INTEGRATION_CONTRACT.md` API examples align. | Executable tests validate imports/entry points and wrapper behavior. | None. | Verified |
| F-007 | Unified/split enforcement + `@governed` default | Medium | NO_ISSUE | Split mode is default decorator path; unified still supported with deprecation warning path. | Docs claim split-default in `v0.3.3` and legacy unified opt-in. | `aegis/_internal/enforcement.py` decorator logic; tests `tests/test_decorators_split_mode.py`, `tests/test_governed_default_flip.py`, `tests/test_split_enforcement*.py`. | `README.md` and integration docs migration notes describe default flip. | Behavior and docs are aligned; no contract breach observed. | None. | Verified |
| F-008 | Policy/guards/conditions/tools/risk pipeline | Medium | NO_ISSUE | Validation and gate pipeline behavior matches intended fail-closed model. | Docs specify deterministic ordered fail-closed enforcement. | Tests: `tests/test_policy_loader.py`, `test_policy_composition.py`, `test_conditions.py`, `test_guards.py`, `test_tools.py`, `test_risk_scoring.py`, custom gate tests all pass. | `docs/architecture/ENFORCEMENT_PIPELINE.md`, `docs/USAGE.md`. | Breadth of targeted tests indicates no contradictory behavior in reviewed commit. | None. | Verified |
| F-009 | Audit sinks failure behavior | Medium | NO_ISSUE | Sink failures raise dedicated exceptions in line with fail-closed semantics. | Docs claim sink failures are explicit and auditable. | `aegis/_internal/sinks.py`; `tests/test_audit_sinks.py` pass. | `docs/USAGE.md`, integration guidance. | Code/tests and docs are consistent in reviewed scenarios. | None. | Verified |
| F-010 | Signing/verification + chain/lineage/provenance/risk history | Medium | NO_ISSUE | All reviewed governance-evidence features function and validate as tested. | Docs describe shipped `v0.3.3` capability set. | Tests: `test_signing.py`, `test_audit_chain.py`, `test_audit_lineage.py`, `test_audit_provenance.py`, `test_risk_history.py`, `test_chain_schema_compliance.py`. | `README.md`, `PROJECT.md`, `docs/PUBLIC_INTEGRATION_CONTRACT.md`. | Strong test coverage and schema checks support alignment. | None. | Verified |
| F-011 | CLI and demo product surfaces | Medium | NO_ISSUE | CLI and both demo surfaces execute test suites successfully. | User-facing surfaces should reflect runtime semantics. | `tests/test_cli.py`, `tests/test_cli_lineage.py`; `demo-app-api/tests` and `demo-app-react` test runs pass. | README/demo docs position these as maintained walkthrough surfaces. | Executable behavior matched documented purpose in reviewed scope. | None. | Verified |

## Prescriptive remediation plan

1. Fix release-state inconsistencies in `PROJECT.md` (`F-001`, `F-002`) to prevent incorrect release expectations.
2. Correct artifact contract wording and header metadata in `docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md` (`F-003`, `F-004`).
3. Repair import completeness in `docs/PUBLIC_INTEGRATION_CONTRACT.md` example (`F-005`).
4. Re-run doc parity checker and focused tests touching affected surfaces.
5. Update this report with post-fix status and remediation notes.

## Remediation Applied

- `F-001` fixed in `PROJECT.md` by changing `0.3.2` language from “current release” to historical framing (`PROJECT.md:205-206`) and clarifying diagram baseline notes (`PROJECT.md:269-272`).
- `F-002` fixed in `PROJECT.md` by removing “in progress” and adding explicit `0.3.3` release date (`PROJECT.md:229-235`).
- `F-003` fixed in `docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md` by correcting artifact semantics in design principles and glossary (`:60`, `:735`).
- `F-004` fixed in `docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md` by updating header metadata to `Version: 1.4.0` and `Last Updated: 2026-04-13` (`:5`).
- `F-005` fixed in `docs/PUBLIC_INTEGRATION_CONTRACT.md` by adding missing imports to the policy-loader snippet (`:728-730`).
