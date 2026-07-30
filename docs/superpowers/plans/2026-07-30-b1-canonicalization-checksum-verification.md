# B1 Canonicalization, Checksum, and Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Define an injective v2 evidence domain, make content checksums mandatory, and replace boolean verification with typed integrity and completeness results.

**Architecture:** `CanonicalizationProfileV2` first normalizes a detached value into the accepted JSON domain, then delegates RFC 8785 byte serialization to `rfc8785`. Checksum, signature, emission, and verification use the same normalized object and named profile. Legacy verification remains separately host-authorized and can never satisfy v2 assurance.

**Tech Stack:** Python 3.10+, `rfc8785>=0.1.4,<0.2`, SHA-256, JSON Schema, frozen dataclasses/enums, pytest.

## Global Constraints

- Profile identifier is exactly `aegis-json-v2`.
- Object keys are strings at every depth.
- Accepted values are null, booleans, strings without lone surrogates, arrays, objects, and finite JSON numbers.
- Reject tuples, sets, bytes, custom containers, non-string keys, NaN, infinities, and integers outside ±9,007,199,254,740,991.
- `-0.0` serializes as `0`; `1` and `1.0` are one JSON number.
- Strings are not Unicode-normalized.
- V2 artifacts require non-null checksum and `canonicalization_profile`.
- V2 never calls legacy `canonical_json_bytes()`.
- A valid supplied prefix reports completeness `UNPROVEN`, not true/complete.
- Legacy verification requires trusted host opt-in and returns legacy/unproven status.

---

### Task 1: Implement strict JSON normalization and RFC 8785 serialization

**Files:**
- Create: `aegis/_internal/canonicalization.py`
- Modify: `pyproject.toml`
- Create: `tests/test_canonicalization_v2.py`
- Modify: `tests/test_checksum_determinism.py`

**Interfaces:**
- Produces: `normalize_json_v2(value: object, *, path: str = "$") -> JsonValue`
- Produces: `canonicalize_v2(value: object) -> CanonicalizedValue`
- Produces: `CanonicalizedValue(value: JsonValue, data: bytes, profile: str)`

- [ ] **Step 1: Write collision and invalid-domain tests**

```python
@pytest.mark.parametrize("value", [
    {1: "a"}, {True: "a"}, {"x": {2: "b"}}, (1, 2), {1, 2},
    b"bytes", {"n": float("nan")}, {"n": float("inf")},
])
def test_v2_rejects_values_outside_closed_json_domain(value):
    with pytest.raises(CanonicalizationError):
        canonicalize_v2(value)


def test_round_trip_keeps_bytes_and_value_identical():
    first = canonicalize_v2({"n": 1.0, "s": "é", "z": -0.0})
    second = canonicalize_v2(json.loads(first.data))
    assert first.data == second.data
    assert first.value == second.value
```

Add RFC 8785 number/string vectors, safe-integer edges, lone surrogates, and mixed-key cases.

- [ ] **Step 2: Run and verify current collisions**

Run: `.venv/bin/pytest tests/test_canonicalization_v2.py tests/test_checksum_determinism.py -v`

Expected: FAIL; current canonicalization stringifies keys and collapses invalid representations.

- [ ] **Step 3: Implement strict recursive normalization**

```python
SAFE_INTEGER_MAX = 9_007_199_254_740_991
CANONICALIZATION_PROFILE_V2 = "aegis-json-v2"


class CanonicalizationError(AIGCError):
    def __init__(self, path: str, code: str) -> None:
        super().__init__(
            f"Evidence value is not valid at {path}",
            code=code,
            details={"path": path},
        )


@dataclass(frozen=True, slots=True)
class CanonicalizedValue:
    value: JsonValue
    data: bytes
    profile: str = CANONICALIZATION_PROFILE_V2


def normalize_json_v2(value: object, *, path: str = "$") -> JsonValue:
    if value is None or isinstance(value, (str, bool)):
        _reject_lone_surrogates(value, path=path)
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > SAFE_INTEGER_MAX:
            raise CanonicalizationError(path, "INTEGER_OUT_OF_RANGE")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError(path, "NON_FINITE_NUMBER")
        return 0 if value == 0 else value
    if type(value) is list:
        return [normalize_json_v2(item, path=f"{path}[{i}]") for i, item in enumerate(value)]
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise CanonicalizationError(path, "NON_STRING_KEY")
        return {key: normalize_json_v2(item, path=f"{path}.{key}") for key, item in value.items()}
    raise CanonicalizationError(path, "NON_JSON_VALUE")
```

- [ ] **Step 4: Serialize only normalized values**

```python
normalized = normalize_json_v2(value)
try:
    data = rfc8785.dumps(normalized)
except rfc8785.CanonicalizationError as exc:
    raise CanonicalizationError("$", "RFC8785_SERIALIZATION_FAILED") from exc
return CanonicalizedValue(normalized, data, CANONICALIZATION_PROFILE_V2)
```

Run: `.venv/bin/pytest tests/test_canonicalization_v2.py tests/test_checksum_determinism.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml aegis/_internal/canonicalization.py tests/test_canonicalization_v2.py tests/test_checksum_determinism.py
git commit -m "feat: add strict v2 evidence canonicalization"
```

### Task 2: Add v2 content checksums and schemas

**Files:**
- Create: `aegis/_internal/evidence_profiles.py`
- Modify: `aegis/_internal/audit.py`
- Modify: `schemas/audit_artifact.schema.json`
- Modify: `aegis/schemas/audit_artifact.schema.json`
- Modify: `schemas/workflow_artifact.schema.json`
- Modify: `aegis/schemas/workflow_artifact.schema.json`
- Create: `tests/test_evidence_checksum_v2.py`
- Modify: `tests/test_audit_artifact_contract.py`

**Interfaces:**
- Produces: `content_checksum_v2(artifact: Mapping[str, Any]) -> tuple[str, dict[str, JsonValue]]`
- Checksum excludes only `checksum`, `signature`, and `signature_metadata`.

- [ ] **Step 1: Write mandatory-checksum and round-trip tests**

```python
def test_content_checksum_covers_chain_and_workflow_metadata():
    artifact = v2_artifact(previous_audit_checksum="a" * 64, step_index=2)
    checksum, normalized = content_checksum_v2(artifact)
    normalized["step_index"] = 3
    assert content_checksum_v2(normalized)[0] != checksum


def test_v2_schema_rejects_missing_checksum():
    artifact = v2_artifact()
    artifact.pop("checksum")
    errors = list(audit_v2_validator.iter_errors(artifact))
    assert errors
```

- [ ] **Step 2: Run and verify current optional-checksum behavior**

Run: `.venv/bin/pytest tests/test_evidence_checksum_v2.py tests/test_audit_artifact_contract.py -v`

Expected: FAIL.

- [ ] **Step 3: Implement checksum construction**

```python
EXCLUDED_CHECKSUM_FIELDS = frozenset({"checksum", "signature", "signature_metadata"})


def content_checksum_v2(artifact):
    candidate = dict(artifact)
    candidate["canonicalization_profile"] = CANONICALIZATION_PROFILE_V2
    payload = {k: v for k, v in candidate.items() if k not in EXCLUDED_CHECKSUM_FIELDS}
    canonical = canonicalize_v2(payload)
    digest = hashlib.sha256(canonical.data).hexdigest()
    normalized = dict(canonical.value)
    normalized["checksum"] = digest
    return digest, normalized
```

- [ ] **Step 4: Advance both schema pairs**

Require `schema_version: "2.0"`, `canonicalization_profile: "aegis-json-v2"`, and a 64-hex checksum. Keep root/packaged copies byte-identical.

Run: `.venv/bin/pytest tests/test_evidence_checksum_v2.py tests/test_audit_artifact_contract.py tests/test_doc_parity_v090_truth.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/evidence_profiles.py aegis/_internal/audit.py schemas/audit_artifact.schema.json aegis/schemas/audit_artifact.schema.json schemas/workflow_artifact.schema.json aegis/schemas/workflow_artifact.schema.json tests/test_evidence_checksum_v2.py tests/test_audit_artifact_contract.py
git commit -m "fix: require v2 evidence content checksums"
```

### Task 3: Introduce typed verification results and strict defaults

**Files:**
- Create: `aegis/_internal/verification.py`
- Modify: `aegis/_internal/audit_chain.py`
- Modify: `aegis/audit_chain.py`
- Modify: `aegis/__init__.py`
- Create: `tests/test_typed_chain_verification.py`
- Modify: `tests/test_audit_chain.py`

**Interfaces:**
- Produces enums: `ContentIntegrity`, `ChainContinuity`, `Completeness`
- Produces: `ChainVerificationReport(content_integrity, chain_continuity, completeness, errors)`
- Produces: `verify_chain_detailed(artifacts, *, allow_legacy=False) -> ChainVerificationReport`
- Preserves `verify_chain(...) -> tuple[bool, list[str]]` only as a deprecated wrapper whose boolean means internal validity, never completeness.

- [ ] **Step 1: Write #50 strict and prefix tests**

```python
def test_missing_checksum_is_invalid_by_default():
    report = verify_chain_detailed([artifact_without_checksum()])
    assert report.content_integrity is ContentIntegrity.INVALID


def test_valid_prefix_never_claims_completeness():
    report = verify_chain_detailed(valid_prefix())
    assert report.chain_continuity is ChainContinuity.VALID
    assert report.completeness is Completeness.UNPROVEN
```

- [ ] **Step 2: Run and verify current bare-boolean semantics**

Run: `.venv/bin/pytest tests/test_typed_chain_verification.py tests/test_audit_chain.py -v`

Expected: FAIL because checksum-free entries and prefixes can return `(True, [])`.

- [ ] **Step 3: Implement closed verification axes**

Normalize malformed input into stable error records. Select canonicalization only from the host-authorized expected profile; artifact content cannot grant legacy mode.

- [ ] **Step 4: Add explicit compatibility wrapper**

The wrapper emits `DeprecationWarning`, returns `False` for invalid content/continuity, and documents that `True` says nothing about completeness.

Run: `.venv/bin/pytest tests/test_typed_chain_verification.py tests/test_audit_chain.py tests/test_public_api.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/verification.py aegis/_internal/audit_chain.py aegis/audit_chain.py aegis/__init__.py tests/test_typed_chain_verification.py tests/test_audit_chain.py
git commit -m "fix: return typed strict chain verification"
```

### Task 4: Enforce the host-only legacy authority boundary

**Files:**
- Create: `aegis/_internal/legacy.py`
- Modify: `aegis/_internal/verification.py`
- Modify: `aegis/_internal/policy_compiler.py`
- Modify: `aegis/_internal/cli.py`
- Create: `tests/test_legacy_authority_boundary.py`
- Modify: `docs/migration.md`
- Modify: `docs/PUBLIC_INTEGRATION_CONTRACT.md`

**Interfaces:**
- Produces: `LegacyAuthorization` created only by trusted API/CLI configuration.
- No policy, artifact, provider, guard, or invocation field can construct it.

- [ ] **Step 1: Add privilege-source tests**

Test policy version strings, artifact profile fields, guard effects, invocation context, and custom providers that request legacy behavior; all remain strict without a host token.

- [ ] **Step 2: Run and verify any implicit fallbacks**

Run: `.venv/bin/pytest tests/test_legacy_authority_boundary.py -v`

Expected: FAIL until authorization is centralized.

- [ ] **Step 3: Implement the trusted capability**

```python
class LegacyAuthorization:
    __slots__ = ("_capability", "features")

    def __init__(self, capability: object, features: frozenset[str]) -> None:
        if capability is not _HOST_LEGACY_CAPABILITY:
            raise TypeError("LegacyAuthorization is host-created only")
        self._capability = capability
        self.features = features
```

Expose one host API factory and explicit CLI flags per feature. Do not infer authorization from data being verified.

- [ ] **Step 4: Run strict/legacy matrix tests**

Run: `.venv/bin/pytest tests/test_legacy_authority_boundary.py tests/test_typed_chain_verification.py tests/test_adversarial_preconditions.py tests/test_cli.py -v`

Expected: PASS; legacy results are marked legacy/unproven.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/legacy.py aegis/_internal/verification.py aegis/_internal/policy_compiler.py aegis/_internal/cli.py tests/test_legacy_authority_boundary.py docs/migration.md docs/PUBLIC_INTEGRATION_CONTRACT.md
git commit -m "fix: make legacy behavior host-authorized only"
```

## B1 Completion Gate

Run:

```bash
.venv/bin/pytest tests/test_canonicalization_v2.py tests/test_evidence_checksum_v2.py tests/test_typed_chain_verification.py tests/test_legacy_authority_boundary.py tests/test_audit_chain.py tests/test_doc_parity_v090_truth.py -v
.venv/bin/pytest -q
```

Expected: both commands exit `0`; #50 is closed within its corrected scope, and B2/B3 consume one stable v2 content-checksum profile.
