# PR-02: Audit Schema v1.4 + Provenance Metadata — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional `provenance` object to audit artifacts and bump the schema to v1.4, with full backward compatibility for v1.3 artifacts.

**Architecture:** Add a `provenance` kwarg to `generate_audit_artifact()` that emits `"provenance": null` by default, or a sparse dict of caller-supplied provenance fields when present. The normalizer strips None-valued keys but passes all other values through unchanged — schema validation owns correctness. Both schema copies are updated identically. Enforcement entrypoints (`enforce_invocation`, split mode) are unchanged.

**Tech Stack:** Python 3.11+, JSON Schema Draft-07 (`jsonschema`), `pytest`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `aegis/_internal/audit.py` | Modify | Add `_normalize_provenance()`, `provenance` kwarg, bump version constant |
| `schemas/audit_artifact.schema.json` | Modify | Add `provenance` property definition |
| `aegis/schemas/audit_artifact.schema.json` | Modify | Identical copy of schema change |
| `tests/test_audit_provenance.py` | Create | All 15 provenance tests |
| `tests/test_audit_artifact_contract.py` | Modify | Update `"1.3"` → `"1.4"` version assertion (line 46) |
| `tests/test_audit_artifact_split_metadata.py` | Modify | Update `"1.3"` → `"1.4"` version assertions (lines 65–69) and docstring |
| `tests/test_golden_replay_split.py` | Modify | Update `"1.3"` → `"1.4"` version assertion (line 88) and function name |
| `tests/golden_replays/golden_expected_audit.json` | Modify | Bump `audit_schema_version` to `"1.4"` |
| `tests/golden_replays/golden_expected_split_pass_audit.json` | Modify | Bump `audit_schema_version` to `"1.4"` |
| `tests/golden_replays/golden_expected_split_pre_fail_role_audit.json` | Modify | Bump `audit_schema_version` to `"1.4"` |
| `README.md` | Modify | Update v0.3.3 release row; add provenance to narrative |
| `PROJECT.md` | Modify | Add v0.3.3 in-progress section |
| `CHANGELOG.md` | Modify | Move schema v1.4 from Planned to Added |
| `docs/INTEGRATION_GUIDE.md` | Modify | Add provenance artifact contract section |
| `docs/PUBLIC_INTEGRATION_CONTRACT.md` | Modify | Add provenance contract entry |

---

## Task 1: Add provenance property to both schema files

**Files:**
- Modify: `schemas/audit_artifact.schema.json`
- Modify: `aegis/schemas/audit_artifact.schema.json`

> Both files must always be identical. Make the same edit to both.

- [ ] **Step 1: Insert the `provenance` property into `schemas/audit_artifact.schema.json`**

Find the `"signature"` block (around line 114) and insert `"provenance"` immediately after it, before `"chain_id"`:

```json
    "signature": {
      "type": ["string", "null"],
      "description": "Cryptographic signature of the artifact"
    },
    "provenance": {
      "type": ["object", "null"],
      "description": "Workflow provenance metadata supplied by the caller",
      "minProperties": 1,
      "properties": {
        "source_ids": {
          "type": "array",
          "items": { "type": "string", "minLength": 1 },
          "minItems": 1,
          "uniqueItems": true,
          "maxItems": 1000,
          "description": "Identifiers of source invocations that contributed to this one"
        },
        "derived_from_audit_checksums": {
          "type": "array",
          "items": { "type": "string", "pattern": "^[a-f0-9]{64}$" },
          "minItems": 1,
          "uniqueItems": true,
          "maxItems": 1000,
          "description": "SHA-256 checksums of prior audit artifacts this invocation derived from"
        },
        "compilation_source_hash": {
          "type": "string",
          "pattern": "^[a-f0-9]{64}$",
          "description": "Orchestrator-supplied hash of the raw source compilation set"
        }
      },
      "additionalProperties": false
    },
    "chain_id": {
```

- [ ] **Step 2: Apply the identical change to `aegis/schemas/audit_artifact.schema.json`**

Repeat step 1 exactly in the second schema copy.

- [ ] **Step 3: Verify existing tests still pass**

```bash
python -m pytest -x -q
```

Expected: all existing tests pass. No provenance fields exist yet — schema change is additive and backward-compatible.

- [ ] **Step 4: Commit**

```bash
git add schemas/audit_artifact.schema.json aegis/schemas/audit_artifact.schema.json
git commit -m "feat(schema): add optional provenance property to audit artifact schema v1.4"
```

---

## Task 2: Add `_normalize_provenance()` and `provenance` kwarg (TDD)

**Files:**
- Create: `tests/test_audit_provenance.py`
- Modify: `aegis/_internal/audit.py`

### Step 2a — Write the failing behavior tests

- [ ] **Step 1: Create `tests/test_audit_provenance.py` with tests 1–8**

```python
"""
Tests for audit artifact v1.4 provenance metadata fields.

Verifies:
- generate_audit_artifact() emits "provenance": None by default
- _normalize_provenance() behavior (via generate_audit_artifact)
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import validate, ValidationError

from aegis._internal.audit import generate_audit_artifact

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "audit_artifact.schema.json"
CHECKSUM_A = "a" * 64
CHECKSUM_B = "b" * 64


@pytest.fixture(scope="module")
def audit_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


def _minimal_invocation() -> dict:
    return {
        "policy_file": "tests/golden_replays/golden_policy_v1.yaml",
        "model_provider": "test_provider",
        "model_identifier": "test_model",
        "role": "tester",
        "input": {},
        "output": {},
        "context": {},
    }


def _minimal_policy() -> dict:
    return {"policy_version": "1.0"}


def _make_artifact(provenance=None) -> dict:
    return generate_audit_artifact(
        _minimal_invocation(),
        _minimal_policy(),
        provenance=provenance,
        timestamp=1700000000,
    )


def test_provenance_absent_emits_null():
    """Default: no provenance kwarg → artifact has "provenance": None."""
    artifact = generate_audit_artifact(
        _minimal_invocation(),
        _minimal_policy(),
        timestamp=1700000000,
    )
    assert "provenance" in artifact
    assert artifact["provenance"] is None


def test_provenance_none_kwarg_emits_null():
    """Explicit provenance=None → artifact has "provenance": None."""
    artifact = _make_artifact(provenance=None)
    assert artifact["provenance"] is None


def test_provenance_empty_dict_emits_null():
    """Empty dict normalizes to None."""
    artifact = _make_artifact(provenance={})
    assert artifact["provenance"] is None


def test_provenance_all_none_values_emits_null():
    """Dict with all-None values normalizes to None."""
    artifact = _make_artifact(provenance={
        "source_ids": None,
        "compilation_source_hash": None,
    })
    assert artifact["provenance"] is None


def test_provenance_full_object_emitted():
    """All three keys present → object with all three keys."""
    prov = {
        "source_ids": ["step-1", "step-2"],
        "derived_from_audit_checksums": [CHECKSUM_A],
        "compilation_source_hash": CHECKSUM_B,
    }
    artifact = _make_artifact(provenance=prov)
    assert artifact["provenance"] == prov


def test_provenance_sparse_only_provided_keys():
    """Only source_ids supplied → only source_ids in artifact provenance."""
    artifact = _make_artifact(provenance={"source_ids": ["step-1"]})
    assert artifact["provenance"] == {"source_ids": ["step-1"]}
    assert "derived_from_audit_checksums" not in artifact["provenance"]
    assert "compilation_source_hash" not in artifact["provenance"]


def test_provenance_none_value_pruned_other_key_kept():
    """None value for one key pruned; other key kept."""
    artifact = _make_artifact(provenance={
        "source_ids": ["step-1"],
        "compilation_source_hash": None,
    })
    assert artifact["provenance"] == {"source_ids": ["step-1"]}


def test_provenance_invalid_value_passes_through():
    """Invalid value passes through unchanged; schema validation owns correctness."""
    artifact = _make_artifact(provenance={"source_ids": "bad-not-a-list"})
    assert artifact["provenance"] == {"source_ids": "bad-not-a-list"}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
python -m pytest tests/test_audit_provenance.py -v
```

Expected: all 8 tests fail with `TypeError: generate_audit_artifact() got an unexpected keyword argument 'provenance'` (or similar).

### Step 2b — Implement the changes in `audit.py`

- [ ] **Step 3: Add `_normalize_provenance()` to `aegis/_internal/audit.py`**

Insert this function between `_normalize_failures()` and `generate_audit_artifact()` (around line 97):

```python
def _normalize_provenance(
    provenance: Mapping[str, Any] | None,
) -> "dict[str, Any] | None":
    """
    Normalize a caller-supplied provenance mapping for artifact emission.

    Returns None when provenance is absent, empty, or all-None.
    Returns a sparse dict of present non-None values otherwise.
    Content validation is left to schema validation — values are passed
    through unchanged.
    """
    if provenance is None:
        return None
    out = {k: v for k, v in provenance.items() if v is not None}
    return out if out else None
```

- [ ] **Step 4: Add the `provenance` kwarg to `generate_audit_artifact()`**

In `aegis/_internal/audit.py`, add the kwarg after `risk_score`:

```python
def generate_audit_artifact(
    invocation: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    enforcement_result: str = "PASS",
    failures: Iterable[Mapping[str, Any]] | None = None,
    failure_gate: str | None = None,
    failure_reason: str | None = None,
    metadata: Mapping[str, Any] | None = None,
    timestamp: int | None = None,
    risk_score: float | None = None,
    provenance: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
```

- [ ] **Step 5: Emit `"provenance"` in the return dict**

In the `return { ... }` block of `generate_audit_artifact()`, add `"provenance"` after `"signature": None`:

```python
    return {
        "audit_schema_version": AUDIT_SCHEMA_VERSION,
        "policy_file": invocation["policy_file"],
        "policy_schema_version": POLICY_SCHEMA_VERSION,
        "policy_version": policy.get("policy_version") or "unknown",
        "model_provider": invocation["model_provider"],
        "model_identifier": invocation["model_identifier"],
        "role": invocation["role"],
        "enforcement_result": enforcement_result,
        "failures": failure_list,
        "failure_gate": failure_gate,
        "failure_reason": failure_reason,
        "input_checksum": checksum(invocation["input"]),
        "output_checksum": checksum(invocation["output"]),
        "context": context_dict,
        "timestamp": int(time.time()) if timestamp is None else int(timestamp),
        "metadata": metadata_dict,
        "risk_score": risk_score,
        "signature": None,
        "provenance": _normalize_provenance(provenance),
    }
```

- [ ] **Step 6: Run provenance behavior tests to confirm they pass**

```bash
python -m pytest tests/test_audit_provenance.py -v
```

Expected: all 8 tests pass.

- [ ] **Step 7: Run the full suite to confirm no regressions (version tests will still pass as "1.3" for now)**

```bash
python -m pytest -x -q
```

Expected: all existing tests pass. The new field `"provenance": null` on artifacts does not break any existing tests because existing tests don't assert on that key.

- [ ] **Step 8: Commit**

```bash
git add aegis/_internal/audit.py tests/test_audit_provenance.py
git commit -m "feat(audit): add provenance kwarg and _normalize_provenance() to generate_audit_artifact"
```

---

## Task 3: Bump version constant and fix version-locked tests + golden fixtures

**Files:**
- Modify: `aegis/_internal/audit.py` (line 26)
- Modify: `tests/test_audit_artifact_contract.py` (line 46)
- Modify: `tests/test_audit_artifact_split_metadata.py` (lines 2–8, 65–69)
- Modify: `tests/test_golden_replay_split.py` (lines 83–89)
- Modify: `tests/golden_replays/golden_expected_audit.json`
- Modify: `tests/golden_replays/golden_expected_split_pass_audit.json`
- Modify: `tests/golden_replays/golden_expected_split_pre_fail_role_audit.json`

- [ ] **Step 1: Add the version test to `tests/test_audit_provenance.py`**

Append to the end of the file:

```python
def test_audit_schema_version_is_1_4():
    """Artifact emits audit_schema_version 1.4."""
    artifact = _make_artifact()
    assert artifact["audit_schema_version"] == "1.4"
```

- [ ] **Step 2: Run the version test to confirm it fails**

```bash
python -m pytest tests/test_audit_provenance.py::test_audit_schema_version_is_1_4 -v
```

Expected: FAIL — `AssertionError: assert '1.3' == '1.4'`

- [ ] **Step 3: Bump `AUDIT_SCHEMA_VERSION` in `aegis/_internal/audit.py`**

Change line 26:

```python
AUDIT_SCHEMA_VERSION = "1.4"
```

- [ ] **Step 4: Run the version test — now passes, but locked tests fail**

```bash
python -m pytest tests/test_audit_provenance.py::test_audit_schema_version_is_1_4 -v
```

Expected: PASS.

```bash
python -m pytest tests/test_audit_artifact_contract.py::test_audit_contract tests/test_audit_artifact_split_metadata.py::test_schema_version_is_1_3 tests/test_golden_replay_split.py::test_golden_unified_mode_still_produces_v1_3_artifact -v
```

Expected: all three FAIL (still assert "1.3").

- [ ] **Step 5: Fix `tests/test_audit_artifact_contract.py` line 46**

Change:

```python
    assert audit["audit_schema_version"] == "1.4"
```

- [ ] **Step 6: Fix `tests/test_audit_artifact_split_metadata.py`**

Update the module docstring (top of file):

```python
"""
Tests for audit artifact v1.4 split-enforcement metadata fields.

Verifies that:
- AUDIT_SCHEMA_VERSION is "1.4"
- The audit artifact JSON schema accepts the new optional split metadata
  properties (enforcement_mode, pre_call_gates_evaluated,
  post_call_gates_evaluated, pre_call_timestamp, post_call_timestamp)
- The schema rejects invalid values for enforcement_mode
- Legacy v1.2 metadata keys still validate without modification
  (backward compatibility)
"""
```

Update the test function name and assertions (lines 65–69):

```python
def test_schema_version_is_1_4() -> None:
    """AUDIT_SCHEMA_VERSION constant and generated artifact must be '1.4'."""
    assert AUDIT_SCHEMA_VERSION == "1.4"
    artifact = _make_artifact()
    assert artifact["audit_schema_version"] == "1.4"
```

- [ ] **Step 7: Fix `tests/test_golden_replay_split.py` lines 83–89**

```python
def test_golden_unified_mode_still_produces_v1_4_artifact():
    """Unified mode still works after split refactor, produces v1.4."""
    invocation = _load("golden_invocation_success.json")
    artifact = enforce_invocation(invocation)

    assert artifact["audit_schema_version"] == "1.4"
    assert artifact["metadata"]["enforcement_mode"] == "unified"
```

- [ ] **Step 8: Update `tests/golden_replays/golden_expected_audit.json`**

```json
{
  "audit_schema_version": "1.4",
  "model_provider": "openai",
  "model_identifier": "gpt-test-model",
  "role": "planner",
  "policy_version": "1.0",
  "enforcement_result": "PASS",
  "policy_schema_version": "http://json-schema.org/draft-07/schema#",
  "policy_file": "tests/golden_replays/golden_policy_v1.yaml"
}
```

- [ ] **Step 9: Update `tests/golden_replays/golden_expected_split_pass_audit.json`**

```json
{
  "audit_schema_version": "1.4",
  "model_provider": "openai",
  "model_identifier": "gpt-test-model",
  "role": "planner",
  "policy_version": "1.0",
  "enforcement_result": "PASS",
  "policy_file": "tests/golden_replays/golden_policy_v1.yaml",
  "policy_schema_version": "http://json-schema.org/draft-07/schema#",
  "metadata": {
    "enforcement_mode": "split"
  }
}
```

- [ ] **Step 10: Update `tests/golden_replays/golden_expected_split_pre_fail_role_audit.json`**

```json
{
  "audit_schema_version": "1.4",
  "model_provider": "openai",
  "model_identifier": "gpt-test-model",
  "role": "unauthorized_role",
  "enforcement_result": "FAIL",
  "failure_gate": "role_validation",
  "metadata": {
    "enforcement_mode": "split_pre_call_only"
  }
}
```

- [ ] **Step 11: Run the full test suite — all tests must pass**

```bash
python -m pytest -x -q
```

Expected: all tests pass. If any test still fails on `"1.3"`, grep for it and fix:

```bash
grep -rn '"1\.3"' tests/ --include="*.py"
```

- [ ] **Step 12: Commit**

```bash
git add aegis/_internal/audit.py \
    tests/test_audit_provenance.py \
    tests/test_audit_artifact_contract.py \
    tests/test_audit_artifact_split_metadata.py \
    tests/test_golden_replay_split.py \
    tests/golden_replays/golden_expected_audit.json \
    tests/golden_replays/golden_expected_split_pass_audit.json \
    tests/golden_replays/golden_expected_split_pre_fail_role_audit.json
git commit -m "feat(audit): bump AUDIT_SCHEMA_VERSION to 1.4 and update version-locked tests and fixtures"
```

---

## Task 4: Schema validation tests for provenance

**Files:**
- Modify: `tests/test_audit_provenance.py`

These tests verify the schema rejects invalid provenance shapes. The schema is already updated (Task 1) and the implementation is done (Task 2), so these should pass immediately when written.

- [ ] **Step 1: Append schema validation tests to `tests/test_audit_provenance.py`**

```python
def test_artifact_with_full_provenance_validates(audit_schema: dict):
    """Full provenance object validates against schema v1.4."""
    artifact = _make_artifact(provenance={
        "source_ids": ["step-1"],
        "derived_from_audit_checksums": [CHECKSUM_A],
        "compilation_source_hash": CHECKSUM_B,
    })
    validate(instance=artifact, schema=audit_schema)


def test_artifact_without_provenance_key_validates(audit_schema: dict):
    """v1.3-era artifact (no provenance key) validates under v1.4 schema."""
    artifact = _make_artifact()
    del artifact["provenance"]
    validate(instance=artifact, schema=audit_schema)


def test_artifact_with_null_provenance_validates(audit_schema: dict):
    """provenance: null is schema-valid."""
    artifact = _make_artifact()
    assert artifact["provenance"] is None
    validate(instance=artifact, schema=audit_schema)


def test_schema_rejects_empty_source_ids(audit_schema: dict):
    """provenance.source_ids: [] violates minItems: 1."""
    artifact = _make_artifact(provenance={"source_ids": []})
    with pytest.raises(ValidationError):
        validate(instance=artifact, schema=audit_schema)


def test_schema_rejects_empty_checksums(audit_schema: dict):
    """provenance.derived_from_audit_checksums: [] violates minItems: 1."""
    artifact = _make_artifact(provenance={"derived_from_audit_checksums": []})
    with pytest.raises(ValidationError):
        validate(instance=artifact, schema=audit_schema)


def test_schema_rejects_bad_checksum_pattern(audit_schema: dict):
    """Non-hex entry in checksums array fails SHA-256 pattern."""
    artifact = _make_artifact(provenance={
        "derived_from_audit_checksums": ["not-a-sha256-hash"]
    })
    with pytest.raises(ValidationError):
        validate(instance=artifact, schema=audit_schema)


def test_schema_rejects_bad_compilation_hash(audit_schema: dict):
    """compilation_source_hash with non-hex value fails SHA-256 pattern."""
    artifact = _make_artifact(provenance={"compilation_source_hash": "not-a-sha256"})
    with pytest.raises(ValidationError):
        validate(instance=artifact, schema=audit_schema)
```

- [ ] **Step 2: Run the new tests to confirm they pass**

```bash
python -m pytest tests/test_audit_provenance.py -v
```

Expected: all 15 tests pass.

- [ ] **Step 3: Run the full suite to confirm no regressions**

```bash
python -m pytest -x -q
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add tests/test_audit_provenance.py
git commit -m "test(audit): add schema validation tests for provenance fields"
```

---

## Task 5: Documentation parity

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `README.md`
- Modify: `PROJECT.md`
- Modify: `docs/INTEGRATION_GUIDE.md`
- Modify: `docs/PUBLIC_INTEGRATION_CONTRACT.md`

### CHANGELOG.md

- [ ] **Step 1: Move schema v1.4 from Planned to Added in `CHANGELOG.md`**

Find the `## [Unreleased] — v0.3.3` section (around line 10). Replace:

```markdown
## [Unreleased] — v0.3.3

### Planned (no code changes yet)

- Workflow-aware governance groundwork: ADR-0010 accepted, release contract
  established, PR-01 docs-only branch in review.
- Upcoming: audit schema `v1.4` (additive provenance metadata), `AuditLineage`,
  `ProvenanceGate`, `RiskHistory`, and default flip to
  `@governed(pre_call_enforcement=True)`.
```

With:

```markdown
## [Unreleased] — v0.3.3

### Added

- Audit schema `v1.4`: optional top-level `provenance` object on audit artifacts
  with `source_ids`, `derived_from_audit_checksums`, and
  `compilation_source_hash` fields. All fields are optional; `provenance` is
  absent from the required list so v1.3 artifacts remain valid.
- `generate_audit_artifact()` gains a `provenance` keyword argument. Pass a
  dict with any subset of the three provenance fields. Omit for `null` emission.
  Enforcement entrypoints (`enforce_invocation`, split mode) are unchanged;
  caller-supplied provenance via enforcement APIs is deferred to PR-05.

### Planned

- Workflow-aware governance groundwork: ADR-0010 accepted, release contract
  established, PR-01 and PR-02 complete.
- Upcoming: `AuditLineage`, `ProvenanceGate`, `RiskHistory`, and default flip
  to `@governed(pre_call_enforcement=True)`.
```

### README.md

- [ ] **Step 2: Update the v0.3.3 row in the release table in `README.md`**

Find the release table (around line 63). Change the `v0.3.3` row from:

```markdown
| `0.3.3` | _in planning_ | Workflow-aware governance: provenance metadata, `AuditLineage`, `ProvenanceGate`, `RiskHistory`, and `@governed` default flip to split mode |
```

To:

```markdown
| `0.3.3` | _in progress_ | Workflow-aware governance: audit schema `v1.4` with optional provenance metadata (PR-02 ✓); `AuditLineage`, `ProvenanceGate`, `RiskHistory`, and `@governed` default flip to split mode (upcoming) |
```

### PROJECT.md

- [ ] **Step 3: Add v0.3.3 in-progress section to `PROJECT.md`**

After the `### `0.3.2` — Split enforcement and audit-driven hardening` section (around line 226), add:

```markdown
### `0.3.3` — Governed agentic workflows (in progress)

`0.3.3` extends AIGC from invocation governance to workflow governance.

What has shipped so far:

- audit schema `v1.4`: optional `provenance` object on artifacts — `source_ids`,
  `derived_from_audit_checksums`, `compilation_source_hash`
- `generate_audit_artifact()` accepts a `provenance` kwarg

Upcoming in this release:

- `AuditLineage` module for lineage reconstruction from JSONL audit trails
- `ProvenanceGate` built-in gate for source-aware enforcement
- `RiskHistory` advisory utility for trust tracking over time
- `@governed` default flip to `pre_call_enforcement=True`

```

### docs/INTEGRATION_GUIDE.md

- [ ] **Step 4: Add provenance artifact section to `docs/INTEGRATION_GUIDE.md`**

Before `## 10. Compliance Checklist` (around line 331), insert:

```markdown
## 10. Provenance Metadata (v0.3.3+)

Starting in `v0.3.3`, audit artifacts carry an optional `provenance` field
that records workflow-level lineage information for a governed invocation.

### Artifact field contract

When `provenance` is supplied to `generate_audit_artifact()`, it appears as a
top-level key in the emitted artifact:

```python
from aegis._internal.audit import generate_audit_artifact

artifact = generate_audit_artifact(
    invocation,
    policy,
    provenance={
        "source_ids": ["workflow-step-1", "workflow-step-2"],
        "derived_from_audit_checksums": [prior_audit["input_checksum"]],
        "compilation_source_hash": "e3b0c44298fc1c149afb...",  # 64-char hex
    },
)
# artifact["provenance"] == {
#     "source_ids": ["workflow-step-1", "workflow-step-2"],
#     "derived_from_audit_checksums": [...],
#     "compilation_source_hash": "e3b0c44...",
# }
```

When omitted: `artifact["provenance"]` is `null`.

### Field semantics

| Field | Type | Meaning |
|-------|------|---------|
| `source_ids` | `string[]` | Caller-defined IDs of prior invocations that contributed to this one |
| `derived_from_audit_checksums` | `string[]` | SHA-256 checksums of prior AIGC audit artifacts (lineage graph edges) |
| `compilation_source_hash` | `string` | Orchestrator-supplied hash of the raw source compilation set |

All fields are optional within the object. Only supply the fields you have.
Supply at least one field — an empty provenance object is invalid.

### What is NOT available yet

`enforce_invocation()`, `enforce_pre_call()`, `enforce_post_call()`, and
`AIGC` enforcement methods do not accept caller-supplied provenance in `v0.3.3`.
Provenance-aware enforcement (via `ProvenanceGate`) is added in PR-05.

---

## 11. Compliance Checklist
```

> Note: the old section `## 10. Compliance Checklist` becomes `## 11. Compliance Checklist` — update the heading number only.

### docs/PUBLIC_INTEGRATION_CONTRACT.md

- [ ] **Step 5: Add provenance contract entry to `docs/PUBLIC_INTEGRATION_CONTRACT.md`**

Find `### 3.16 Planned extension points (not yet available)` (around line 856). Insert a new section before it:

```markdown
### 3.16 Provenance metadata (v0.3.3+)

`generate_audit_artifact()` accepts an optional `provenance` keyword argument.
When supplied, the artifact's top-level `provenance` field contains a sparse
dict with any subset of the following fields:

| Field | Type | Constraint |
|-------|------|-----------|
| `source_ids` | `string[]` | `minItems: 1`, `uniqueItems: true`, `maxItems: 1000` |
| `derived_from_audit_checksums` | `string[]` | SHA-256 hex pattern, `minItems: 1`, `uniqueItems: true`, `maxItems: 1000` |
| `compilation_source_hash` | `string` | SHA-256 hex pattern |

**Null/absent semantics:**

- `provenance` absent from artifact: valid (backward-compatible with v1.3)
- `provenance: null`: valid; no provenance was supplied
- `provenance: {}`: invalid; an empty object fails `minProperties: 1`

**Enforcement entrypoints unchanged:** `enforce_invocation()`, split-mode
methods, and `AIGC` methods do not accept a `provenance` argument. Direct
`generate_audit_artifact()` callers may supply it. Enforcement-path provenance
is deferred to PR-05 (`ProvenanceGate`).

---

### 3.17 Planned extension points (not yet available)
```

> Note: renumber the old `3.16` section to `3.17`.

- [ ] **Step 6: Run the full test suite to confirm docs changes broke nothing**

```bash
python -m pytest -x -q
```

Expected: all tests pass.

- [ ] **Step 7: Lint**

```bash
flake8 aegis/
```

Expected: no errors.

- [ ] **Step 8: Commit docs**

```bash
git add CHANGELOG.md README.md PROJECT.md docs/INTEGRATION_GUIDE.md docs/PUBLIC_INTEGRATION_CONTRACT.md
git commit -m "docs: update documentation parity for audit schema v1.4 provenance metadata"
```

---

## Task 6: Final verification

- [ ] **Step 1: Run the full test suite**

```bash
python -m pytest -v
```

Expected: all tests pass. The provenance test file should show 15 tests passing.

- [ ] **Step 2: Confirm provenance tests count**

```bash
python -m pytest tests/test_audit_provenance.py -v --collect-only | grep "test session" -A 50
```

Expected: 15 test items collected.

- [ ] **Step 3: Validate policy schemas (existing CI check)**

```bash
python -c "
import json, yaml, jsonschema
from pathlib import Path
schema = json.load(open('schemas/policy_dsl.schema.json'))
for p in Path('policies').glob('*.yaml'):
    jsonschema.validate(yaml.safe_load(open(p)), schema)
    print(f'OK: {p}')
"
```

Expected: all policies print `OK`.

- [ ] **Step 4: Confirm both schema copies are identical**

```bash
diff schemas/audit_artifact.schema.json aegis/schemas/audit_artifact.schema.json
```

Expected: no output (files are identical).
