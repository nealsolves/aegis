# B1 Canonicalization, Checksum, and Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Define an injective v2 evidence domain, make content checksums mandatory, and replace boolean verification with typed integrity and completeness results.

**Architecture:** `CanonicalizationProfileV2` first normalizes a detached value into the accepted JSON domain, then delegates RFC 8785 byte serialization to `rfc8785`. Checksum, signature, emission, and verification use the same normalized object and named profile. Legacy verification remains separately host-authorized and can never satisfy v2 assurance.

**Tech Stack:** Python 3.10+, `rfc8785>=0.1.4,<0.2`, SHA-256, JSON Schema, frozen dataclasses/enums, pytest.

**Predecessor contract:** B1 starts after A1 freezes
`CompiledPolicy.canonicalization_profile == "aegis-json-v2"` and the closed JSON
value aliases. B1 consumes those names only; it does not otherwise depend on
authorization behavior.

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
- Verification reports five independent axes: content integrity, chain
  continuity, signature status, anchor status, and completeness.
- A checksum builder validates an already-declared v2 profile/version; it never
  writes a profile into an input or promotes a v1 artifact.

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


def test_plain_ascii_v1_and_v2_byte_coincidence_does_not_promote_assurance():
    artifact = {"audit_schema_version": "1.4", "value": "ascii"}
    assert canonical_json_bytes(artifact) == canonicalize_v2(artifact).data
    report = verify_chain_detailed([relabel_and_rechecksum_as_v2(artifact)])
    assert report.signature_status is not SignatureStatus.VALID
```

Add RFC 8785 number/string vectors, safe-integer edges, lone surrogates,
mixed-key cases, all key collisions identified in the review, and property
tests that distinct accepted normalized values never produce the same bytes.

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
- Create: `schemas/workflow_artifact.schema.json`
- Modify: `aegis/schemas/workflow_artifact.schema.json`
- Create: `tests/test_evidence_checksum_v2.py`
- Modify: `tests/test_audit_artifact_contract.py`
- Modify: `tests/golden_replays/golden_expected_audit.json`
- Modify: `tests/golden_replays/golden_expected_split_pass_audit.json`
- Modify: `tests/golden_replays/golden_expected_split_pre_fail_role_audit.json`

**Interfaces:**
- Produces: `build_content_checksum_v2(unsigned_artifact) -> dict[str, JsonValue]`
- Produces: `verify_content_checksum_v2(finalized_artifact) -> ContentIntegrity`
- Checksum excludes only `checksum`, `signature`, and `signature_metadata`.

- [ ] **Step 1: Write mandatory-checksum and round-trip tests**

```python
def test_content_checksum_covers_chain_and_workflow_metadata():
    artifact = v2_artifact(previous_audit_checksum="a" * 64, step_index=2)
    finalized = build_content_checksum_v2(artifact)
    original_checksum = finalized["checksum"]
    candidate = unsigned_copy(finalized)
    candidate["step_index"] = 3
    assert build_content_checksum_v2(candidate)["checksum"] != original_checksum


def test_v2_schema_rejects_missing_checksum():
    artifact = v2_artifact()
    artifact.pop("checksum")
    errors = list(audit_v2_validator.iter_errors(artifact))
    assert errors


def test_checksum_builder_rejects_legacy_profile_instead_of_overwriting_it():
    with pytest.raises(EvidenceProfileError) as exc:
        build_content_checksum_v2({"audit_schema_version": "1.4"})
    assert exc.value.code == "EVIDENCE_PROFILE_MISMATCH"


def test_checksum_verifier_does_not_return_a_signature_stripped_artifact(v2_signed_artifact):
    before = copy.deepcopy(v2_signed_artifact)
    assert verify_content_checksum_v2(v2_signed_artifact) is ContentIntegrity.VALID
    assert v2_signed_artifact == before
```

- [ ] **Step 2: Run and verify current optional-checksum behavior**

Run: `.venv/bin/pytest tests/test_evidence_checksum_v2.py tests/test_audit_artifact_contract.py -v`

Expected: FAIL.

- [ ] **Step 3: Implement checksum construction**

Split construction from verification. `build_content_checksum_v2()` accepts an
unsigned, full artifact that already declares exactly one of
`audit_schema_version: "2.0"` or `workflow_schema_version: "2.0"` and
`canonicalization_profile: "aegis-json-v2"`. It rejects missing, legacy,
conflicting, or unknown values and caller-supplied checksum/signature fields;
then it returns the complete normalized artifact plus its checksum.

`verify_content_checksum_v2()` accepts a full finalized artifact, validates the
same exact declarations, computes over a temporary copy excluding only
`checksum`, `signature`, and `signature_metadata`, and returns a typed status.
It never mutates the artifact and never returns a stripped payload. Profile
selection is host expected-profile input, not artifact-granted authority.

- [ ] **Step 4: Advance both schema pairs**

Require the existing exact discriminator names:
`audit_schema_version: "2.0"` for invocation artifacts and
`workflow_schema_version: "2.0"` for workflow artifacts. There is no generic
`schema_version` field. Preserve `policy_schema_version` as the JSON Schema
dialect URI; do not repurpose it as an AEGIS contract version. Require
`canonicalization_profile: "aegis-json-v2"` and a 64-hex checksum.

Create the missing root workflow schema from the packaged source before
changing both copies, then keep each root/packaged pair byte-identical. In this
same commit migrate all three golden replay files and every test asserting the
old audit/workflow discriminator. The suite may not pass through an
intermediate commit where schemas are 2.0 and goldens are 1.x.

Run: `.venv/bin/pytest tests/test_evidence_checksum_v2.py tests/test_audit_artifact_contract.py tests/test_doc_parity_v090_truth.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/evidence_profiles.py aegis/_internal/audit.py schemas/audit_artifact.schema.json aegis/schemas/audit_artifact.schema.json schemas/workflow_artifact.schema.json aegis/schemas/workflow_artifact.schema.json tests/test_evidence_checksum_v2.py tests/test_audit_artifact_contract.py tests/golden_replays
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
- Modify: `demo-app-api/main.py`
- Modify: `demo-app-api/tests/test_api.py`

**Interfaces:**
- Produces enums: `ContentIntegrity`, `ChainContinuity`, `Completeness`
- Reuses #44 `SignatureStatus` and `AnchorStatus`
- Produces: `ChainVerificationReport(content_integrity, chain_continuity, signature_status, anchor_status, completeness, errors)`
- Produces: `verify_chain_detailed(artifacts, *, signature_verifier=None, anchor_verifier=None, legacy_authorization=None) -> ChainVerificationReport`
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


def test_checksum_valid_unsigned_chain_is_not_authentic(v2_unsigned_prefix):
    report = verify_chain_detailed(v2_unsigned_prefix)
    assert report.content_integrity is ContentIntegrity.VALID
    assert report.signature_status is SignatureStatus.UNSIGNED
    assert report.anchor_status is AnchorStatus.NOT_EVALUATED
```

- [ ] **Step 2: Run and verify current bare-boolean semantics**

Run: `.venv/bin/pytest tests/test_typed_chain_verification.py tests/test_audit_chain.py -v`

Expected: FAIL because checksum-free entries and prefixes can return `(True, [])`.

- [ ] **Step 3: Implement closed verification axes**

Normalize malformed input into stable error records. Select canonicalization
only from the host-authorized expected profile; artifact content cannot grant
legacy mode. Delegate the signature and anchor axes to the #44 closed outcome
model. Content/continuity validity must never imply signature validity or
anchoring, including when legacy and v2 canonical bytes happen to coincide.

- [ ] **Step 4: Add explicit compatibility wrapper**

The wrapper emits `DeprecationWarning`, returns `False` for invalid
content/continuity, and documents that `True` says nothing about signature,
anchor, or completeness. Migrate `demo-app-api/main.py` to
`verify_chain_detailed()` and return all five axes; add a demo regression so the
strict-default API change cannot break the endpoint unnoticed.

Run: `.venv/bin/pytest tests/test_typed_chain_verification.py tests/test_audit_chain.py tests/test_public_api.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/verification.py aegis/_internal/audit_chain.py aegis/audit_chain.py aegis/__init__.py tests/test_typed_chain_verification.py tests/test_audit_chain.py demo-app-api/main.py demo-app-api/tests/test_api.py
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
.venv/bin/pytest tests/test_canonicalization_v2.py tests/test_evidence_checksum_v2.py tests/test_typed_chain_verification.py tests/test_legacy_authority_boundary.py tests/test_audit_chain.py tests/test_doc_parity_v090_truth.py demo-app-api/tests/test_api.py -v
.venv/bin/pytest -q
```

Expected: both commands exit `0`; #50 is closed within its corrected scope,
the demo consumes the strict five-axis result, schema/golden migrations are
atomic, and B2/B3 consume one stable v2 content-checksum profile.
