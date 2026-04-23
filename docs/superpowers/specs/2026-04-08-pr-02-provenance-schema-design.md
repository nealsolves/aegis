# PR-02 Design: Audit Schema v1.4 + Provenance Metadata

Date: 2026-04-08
Status: Approved
Branch: `feat/v0.3.3-02-provenance-schema`

---

## Context

PR-02 is the second step in the `v0.3.3` workflow-aware SDK release. It
introduces the artifact contract for workflow provenance — three optional fields
that downstream PRs (PR-03 `AuditLineage`, PR-05 `ProvenanceGate`) will build
on.

This PR is additive only. No new required fields. No new enforcement behavior.
Runtime provenance generation and enforcement are deferred to PR-05.

---

## Scope

In scope:

- `audit_artifact.schema.json` updated to v1.4 (both copies)
- `generate_audit_artifact()` gains a `provenance` kwarg
- `_normalize_provenance()` helper in `audit.py`
- `AUDIT_SCHEMA_VERSION` constant bumped to `"1.4"`
- New test file `tests/test_audit_provenance.py` (~15 tests)
- Existing version-locked tests and golden fixtures updated
- Documentation parity across 5 docs

Out of scope:

- Runtime provenance generation from enforcement context (PR-05)
- Sink-time schema validation of provenance content (pre-existing gap,
  deferred to PR-05)
- `AuditLineage` consumption of provenance fields (PR-03)
- `ProvenanceGate` enforcement (PR-05)
- Any changes to `enforce_invocation()`, `enforce_pre_call()`,
  `enforce_post_call()`, or `AEGIS` enforcement methods — these remain
  unchanged; caller-supplied provenance via enforcement entrypoints is
  deferred to PR-05

---

## Exit Gate (from RELEASE_GATES.md)

- schema change is additive only
- no new required fields are introduced
- PASS artifacts remain valid
- FAIL artifacts remain valid
- provenance fields are optional
- schema and artifact contract tests land with the change

---

## Section 1: Schema (`schemas/audit_artifact.schema.json` + `aegis/schemas/audit_artifact.schema.json`)

### Version handling

The `audit_schema_version` property in the schema file stays as `type: string`
with no enum constraint — the schema does not pin a version literal, so v1.3
artifacts without a `provenance` key remain valid under v1.4.

The version bump lives only in `AUDIT_SCHEMA_VERSION = "1.4"` in
`aegis/_internal/audit.py`. The runtime emits `"1.4"`; the schema accepts any
string.

Both schema copies must be updated identically:

- `schemas/audit_artifact.schema.json`
- `aegis/schemas/audit_artifact.schema.json`

### New `provenance` property

Added as a top-level property, not in `required`:

```json
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
}
```

### Field semantics

- `source_ids`: caller-supplied identifiers of prior invocations that
  contributed to this one (workflow-level links)
- `derived_from_audit_checksums`: SHA-256 checksums of prior AEGIS audit
  artifacts (lineage graph edges; distinct from `source_ids`)
- `compilation_source_hash`: orchestrator-supplied hash of the raw source
  compilation set — a distinct concept from `derived_from_audit_checksums`,
  not derivable from it

### Validity rules

- `provenance` absent: valid (backward compat)
- `provenance: null`: valid
- `provenance: {}`: invalid (`minProperties: 1`)
- `provenance` object with at least one present field: valid if field content
  passes pattern/type constraints
- Arrays present but empty: invalid (`minItems: 1` is enforced via the
  `minItems` guard on each array field; note `minProperties: 1` alone does not
  catch `{"source_ids": []}` — the runtime normalizer prunes None values but
  passes empty arrays through for schema to reject)

---

## Section 2: Runtime (`aegis/_internal/audit.py`)

### Constant

```python
AUDIT_SCHEMA_VERSION = "1.4"
```

### Normalization helper

```python
def _normalize_provenance(
    provenance: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if provenance is None:
        return None
    out = {k: v for k, v in provenance.items() if v is not None}
    return out if out else None
```

Rules:

- `None` input → `None`
- Empty dict → `None`
- Dict with all-None values → `None`
- Dict with any non-None value → sparse dict of those values, unchanged
- No coercion, no type-checking — schema validation owns content correctness
- Invalid-but-present values (e.g., `"source_ids": "bad"`) pass through
  unchanged so schema validation surfaces them

### Behaviour table

| Input | Emitted |
|-------|---------|
| `None` | `null` |
| `{}` | `null` |
| `{"source_ids": None}` | `null` |
| `{"source_ids": []}` | `{"source_ids": []}` — schema rejects (`minItems: 1`) |
| `{"source_ids": "bad"}` | `{"source_ids": "bad"}` — schema rejects (not array) |
| `{"source_ids": ["id1"], "compilation_source_hash": None}` | `{"source_ids": ["id1"]}` |
| full provenance dict | sparse dict with all provided non-None values |

### `generate_audit_artifact()` signature change

Add kwarg (alongside `risk_score`):

```python
provenance: Mapping[str, Any] | None = None,
```

Artifact emission (alongside `risk_score` and `signature`):

```python
"provenance": _normalize_provenance(provenance),
```

### Known gap

`enforcement.py` does not schema-validate artifacts before emitting to sinks
(pre-existing condition, not introduced by PR-02). Invalid provenance content
will reach sinks unchanged. Enforcement-layer validation is deferred to PR-05.

---

## Section 3: Tests

### New file: `tests/test_audit_provenance.py`

| # | Test name | What it covers |
|---|-----------|---------------|
| 1 | `test_provenance_absent_emits_null` | default kwarg → `"provenance": null` |
| 2 | `test_provenance_none_kwarg_emits_null` | explicit `provenance=None` → null |
| 3 | `test_provenance_empty_dict_emits_null` | `{}` normalizes to null |
| 4 | `test_provenance_all_none_values_emits_null` | `{"source_ids": None, ...}` → null |
| 5 | `test_provenance_full_object_emitted` | all three keys present → sparse object |
| 6 | `test_provenance_sparse_only_provided_keys` | only `source_ids` supplied → only `source_ids` in artifact |
| 7 | `test_provenance_invalid_value_passes_through` | `{"source_ids": "bad"}` reaches artifact unchanged |
| 8 | `test_artifact_with_full_provenance_validates` | schema v1.4 accepts full provenance object |
| 9 | `test_artifact_without_provenance_key_validates` | v1.3-era artifact (no `provenance` key) validates under v1.4 |
| 10 | `test_artifact_with_null_provenance_validates` | `"provenance": null` is schema-valid |
| 11 | `test_schema_rejects_empty_source_ids` | `{"source_ids": []}` → schema error (`minItems: 1`) |
| 12 | `test_schema_rejects_empty_checksums` | `{"derived_from_audit_checksums": []}` → schema error |
| 13 | `test_schema_rejects_bad_checksum_pattern` | non-hex entry in checksums array → schema error |
| 14 | `test_schema_rejects_bad_compilation_hash` | bad hex for `compilation_source_hash` → schema error |
| 15 | `test_audit_schema_version_is_1_4` | artifact emits `"audit_schema_version": "1.4"` |

### Existing test/fixture updates

| File | Change |
|------|--------|
| `tests/test_audit_artifact_contract.py:46` | `"1.3"` → `"1.4"` version assertion |
| `tests/test_audit_artifact_split_metadata.py:65` | same |
| `tests/test_golden_replay_split.py:83` | same |
| All golden JSON fixtures in `tests/golden_replays/` | add `"provenance": null`, bump `"audit_schema_version"` to `"1.4"` |

---

## Section 4: Documentation Parity

| Doc | Change |
|-----|--------|
| `README.md` | Add `v0.3.3` provenance metadata to what's new / feature highlights |
| `PROJECT.md` | Add provenance metadata to capabilities list |
| `CHANGELOG.md` | Add schema v1.4 entry under upcoming `v0.3.3` |
| `docs/INTEGRATION_GUIDE.md` | Document the emitted `provenance` artifact field contract; note that enforcement entrypoints (`enforce_invocation()`, `enforce_pre_call()`, `enforce_post_call()`, `AEGIS` methods) do not accept caller-supplied provenance until PR-05 |
| `docs/PUBLIC_INTEGRATION_CONTRACT.md` | Document provenance object shape, field semantics, null/absent/object contract; note that direct `generate_audit_artifact()` callers may supply the `provenance` kwarg, but this is not yet wired into the enforcement path |

---

## Files Changed

| File | Type |
|------|------|
| `aegis/_internal/audit.py` | modify |
| `schemas/audit_artifact.schema.json` | modify |
| `aegis/schemas/audit_artifact.schema.json` | modify |
| `tests/test_audit_provenance.py` | new |
| `tests/test_audit_artifact_contract.py` | modify |
| `tests/test_audit_artifact_split_metadata.py` | modify |
| `tests/test_golden_replay_split.py` | modify |
| `tests/golden_replays/*.json` (affected fixtures) | modify |
| `README.md` | modify |
| `PROJECT.md` | modify |
| `CHANGELOG.md` | modify |
| `docs/INTEGRATION_GUIDE.md` | modify |
| `docs/PUBLIC_INTEGRATION_CONTRACT.md` | modify |
