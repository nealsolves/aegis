# B2 Evidence Finalizer and Workflow Signing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make one finalizer the only path from an enforcement outcome to emitted evidence, routing every PASS, FAIL, early failure, session, and workflow artifact through the checksum/signing stage and refusing allow-class results when configured evidence delivery fails.

**Architecture:** Every public entry allocates an `AttemptEnvelope` before parsing caller input. Enforcement paths produce `EvidenceDraft`; `EvidenceFinalizer` normalizes, checksums, signs, schema-validates, and synchronously emits exactly once. When finalization itself is impossible, `EvidenceDiagnostics` provides the non-recursive counter/log/raise signal.

**Tech Stack:** Python 3.10+, B1 canonicalization/checksum profile, existing AEGIS signer contracts, JSON Schema 2.0, synchronous `AuditSink`, thread-safe counters, pytest.

## Global Constraints

- B1 `aegis-json-v2` and mandatory checksum are frozen.
- Every public enforcement attempt starts with a bounded `AttemptEnvelope`.
- No production module outside `evidence_finalizer.py` calls `emit_to_sink`, constructs v2 checksums, or signs enforcement evidence.
- Finalization order is normalize → correlate → checksum → sign → schema validate → acknowledged emit.
- The exact normalized finalized value is signed, emitted, and returned.
- V2 default `on_sink_failure` is `"raise"`; v2 traffic requires an acknowledged sink.
- A configured sink failure cannot return PASS/WARN or use caller return as fallback.
- `"log"` sink failure remains explicit host-authorized legacy behavior only.
- Missing signer produces explicit unsigned status; no signing branch is silently skipped.
- No raw exception, key, token, signature bytes, schema body, path, or provider response enters public failure messages.
- Instance and module-level APIs use the same finalizer contract. Module-level
  enforcement requires an explicitly configured, then sealed, private runtime;
  absence of that runtime fails before authorization.
- `emit_to_sink` and mutable sink-failure setters are not v2 public APIs. A
  custom gate cannot obtain the finalizer's private delivery capability or
  change the current/future v2 failure mode.

---

### Task 1: Allocate minimum attempt identity and evidence-loss diagnostics

**Files:**
- Create: `aegis/_internal/attempts.py`
- Create: `aegis/_internal/evidence_diagnostics.py`
- Modify: `aegis/_internal/errors.py`
- Create: `tests/test_attempt_envelope.py`
- Create: `tests/test_evidence_diagnostics.py`

**Interfaces:**
- Produces: `AttemptFactory.allocate(entry_point, mode, invocation) -> AttemptEnvelope`
- Produces: `EvidenceDiagnostics.record_finalization_failure(attempt_id, stage, reason_code)`, `.record_delivery_failure(attempt_id, stage, reason_code)`, `.snapshot()`
- Produces: `EvidenceFinalizationError`.

- [ ] **Step 1: Write bounded-identity and counter tests**

```python
def test_attempt_envelope_exists_before_invalid_invocation_is_parsed():
    factory = AttemptFactory()
    envelope = factory.allocate("enforce_invocation", "unified", object())
    assert envelope.attempt_id == 0
    assert envelope.policy_file == "unknown"
    assert envelope.input == {}


def test_diagnostics_increment_and_snapshot_is_read_only(caplog):
    diagnostics = EvidenceDiagnostics()
    diagnostics.record_finalization_failure(7, "checksum", "CANONICALIZATION_FAILED")
    snapshot = diagnostics.snapshot()
    assert snapshot.evidence_finalization_failures_total == 1
    assert "attempt_id=7" in caplog.text
```

- [ ] **Step 2: Run and verify missing modules**

Run: `.venv/bin/pytest tests/test_attempt_envelope.py tests/test_evidence_diagnostics.py -v`

Expected: FAIL on import.

- [ ] **Step 3: Implement the minimum envelope**

```python
@dataclass(frozen=True, slots=True)
class AttemptEnvelope:
    attempt_id: int
    entry_point: str
    mode: str
    started_at: int
    policy_file: str
    model_provider: str
    model_identifier: str
    role: str
    input: Mapping[str, JsonValue]
    output: Mapping[str, JsonValue]
    context: Mapping[str, JsonValue]
    metadata: Mapping[str, JsonValue]
    failure_stage: str
    reason_code: str
```

Use an instance lock for monotonic ID allocation. Copy only bounded non-empty strings; use `"unknown"` and empty mappings otherwise.
Add `EvidenceFinalizationError(code="EVIDENCE_FINALIZATION_FAILED")` and allow
`AuditSinkError` to accept a more specific stable code while retaining its
current default.

- [ ] **Step 4: Implement non-recursive diagnostics**

Counters use one lock. Each record method increments once, writes one structured `ERROR`, and never calls the evidence finalizer.

Run: `.venv/bin/pytest tests/test_attempt_envelope.py tests/test_evidence_diagnostics.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/attempts.py aegis/_internal/evidence_diagnostics.py aegis/_internal/errors.py tests/test_attempt_envelope.py tests/test_evidence_diagnostics.py
git commit -m "feat: add attempt identity and evidence diagnostics"
```

### Task 2: Implement the single evidence finalizer

**Files:**
- Create: `aegis/_internal/evidence_finalizer.py`
- Modify: `aegis/_internal/external_signing.py`
- Modify: `aegis/_internal/signing.py`
- Create: `tests/test_evidence_finalizer.py`
- Create: `tests/test_evidence_finalizer_signing.py`

**Interfaces:**
- Produces: `EvidenceDraft(attempt, terminal, body, failures, metadata, workflow_correlation)`
- Produces: `EvidenceFinalizer.finalize(draft: EvidenceDraft) -> dict[str, JsonValue]`
- Produces: `EvidenceFinalizerConfig(sink, failure_mode, signer, schema_validator)`.

- [ ] **Step 1: Write order and object-identity tests**

```python
def test_finalizer_orders_checksum_sign_schema_emit(recording_components, pass_draft):
    artifact = recording_components.finalizer.finalize(pass_draft)
    assert recording_components.events == ["checksum", "sign", "schema", "emit"]
    assert recording_components.sink.artifact == artifact
    assert recording_components.signer.signed_checksum == artifact["checksum"]
```

Add FAIL, early load failure, unsigned, external signer, HMAC signer, and double-finalization tests.
Assert signing metadata contains `canonicalization_profile:
"aegis-json-v2"` and that changing it invalidates signature verification.

- [ ] **Step 2: Run and verify the finalizer is absent**

Run: `.venv/bin/pytest tests/test_evidence_finalizer.py tests/test_evidence_finalizer_signing.py -v`

Expected: FAIL on import.

- [ ] **Step 3: Implement exact finalization sequence**

```python
@dataclass(frozen=True, slots=True)
class EvidenceDraft:
    attempt: AttemptEnvelope
    terminal: TerminalClass
    artifact_type: Literal["invocation", "workflow"]
    body: Mapping[str, JsonValue]
    failures: tuple[FailureRecord, ...] = ()
    metadata: Mapping[str, JsonValue] = field(default_factory=lambda: MappingProxyType({}))
    workflow_correlation: Mapping[str, JsonValue] = field(default_factory=lambda: MappingProxyType({}))
    chain_eligible: bool = True


@dataclass(frozen=True, slots=True)
class EvidenceFinalizerConfig:
    sink: AuditSink
    failure_mode: Literal["raise"]
    signer: FinalizerSigner | None
    schema_validator: Draft7Validator
    delivery_capability: "_DeliveryCapability"


def finalize(self, draft: EvidenceDraft) -> dict[str, JsonValue]:
    normalized_body = normalize_json_v2(self._build_artifact(draft))
    checksummed = build_content_checksum_v2(normalized_body)
    signed = self._sign_or_mark_unsigned(checksummed)
    self._schema_validator.validate(signed)
    self._emit_acknowledged(signed)
    return copy.deepcopy(signed)
```

Reject caller-supplied `checksum`, `signature`, `signature_metadata`, and finalization markers in drafts.

`_DeliveryCapability` is minted inside `evidence_finalizer.py`, is not exported,
and is required by the internal acknowledged-delivery function. `AuditSink`
remains a public implementation protocol, so hosts may call their own sink
objects directly, but no such call can produce or resume an AEGIS authorization
result. Only `EvidenceFinalizer.finalize()` owns that transition.

- [ ] **Step 4: Make signer selection explicit**

Adapt existing `ArtifactSigner` and `ExternalArtifactSigner` behind one internal `FinalizerSigner` protocol. Unsigned artifacts contain a closed `signature_status: "unsigned"` field; configured signer failure raises `EvidenceFinalizationError`.
The signer metadata copies the top-level canonicalization profile and the
verifier requires the two values to match.

Run: `.venv/bin/pytest tests/test_evidence_finalizer.py tests/test_evidence_finalizer_signing.py tests/test_external_signing.py tests/test_signing.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/evidence_finalizer.py aegis/_internal/external_signing.py aegis/_internal/signing.py tests/test_evidence_finalizer.py tests/test_evidence_finalizer_signing.py
git commit -m "feat: add central evidence finalizer"
```

### Task 3: Route all invocation and exception paths through the finalizer

**Files:**
- Modify: `aegis/_internal/enforcement.py`
- Modify: `aegis/_internal/session.py`
- Modify: `aegis/_internal/decorators.py`
- Modify: `aegis/sinks.py`
- Create: `tests/test_evidence_emission_inventory.py`
- Modify: `tests/test_pre_pipeline_artifact_schema.py`
- Modify: `tests/test_custom_gate_exception_artifacts.py`
- Modify: `tests/test_risk_config_exception_artifacts.py`
- Create: `tests/test_module_level_evidence_runtime.py`

**Interfaces:**
- Consumes: `AttemptFactory`, `EvidenceDraft`, `EvidenceFinalizer`.
- Produces: exactly one finalization attempt for every terminal
  invocation/session path, including module sync/async unified and split APIs.

- [ ] **Step 1: Inventory and freeze current bypass count**

Add an AST test that enumerates every `emit_to_sink`, `sign_artifact`, final
checksum construction, and direct `AuditSink.emit` production call. Resolve
imports/aliases rather than matching only the string
`aegis._internal.sinks`. Initially assert the known violations are non-empty so
the test proves it detects the current architecture.

- [ ] **Step 2: Run inventory and capture all bypasses**

Run: `.venv/bin/pytest tests/test_evidence_emission_inventory.py -v`

Expected: FAIL and list enforcement/session/adapter bypass locations.

- [ ] **Step 3: Replace each bypass with a draft**

Enumerate and migrate every public entry, not only methods that have
`self._finalizer`: module sync/async `enforce_invocation`, module sync/async
pre-call and post-call, instance sync/async unified and split, decorators, and
session step/finalize paths. At each entry:

```python
attempt = self._attempt_factory.allocate("enforce_invocation", "unified", invocation)
try:
    outcome = self._run_enforcement(attempt, invocation)
except BaseException as exc:
    draft = EvidenceDraft.from_exception(attempt, exc)
    artifact = self._finalizer.finalize(draft)
    raise
return self._finalizer.finalize(EvidenceDraft.from_outcome(attempt, outcome))
```

Preserve the original enforcement exception after finalized FAIL evidence succeeds. If evidence fails, raise the evidence error chained from the original.

Module-level functions call a private `_ModuleEnforcementRuntime` containing the
same `AttemptFactory`, `EvidenceDiagnostics`, and `EvidenceFinalizer`. The host
must call `configure_module_enforcement(...)` before first use. The first
enforcement attempt atomically seals the runtime; reconfiguration thereafter
fails. No registered sink means `V2_SINK_REQUIRED`, never PASS without
evidence.

- [ ] **Step 4: Handle genuinely impossible evidence**

Catch finalizer failures once at the public boundary, record diagnostics with safe stage/code, and raise `EvidenceFinalizationError` or `AuditSinkError`. There is no exception-type-specific silent branch.

Run: `.venv/bin/pytest tests/test_evidence_emission_inventory.py tests/test_pre_pipeline_artifact_schema.py tests/test_custom_gate_exception_artifacts.py tests/test_risk_config_exception_artifacts.py tests/test_enforcement_pipeline.py tests/test_async_enforcement.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/enforcement.py aegis/_internal/session.py aegis/_internal/decorators.py aegis/sinks.py tests/test_evidence_emission_inventory.py tests/test_pre_pipeline_artifact_schema.py tests/test_custom_gate_exception_artifacts.py tests/test_risk_config_exception_artifacts.py tests/test_module_level_evidence_runtime.py
git commit -m "refactor: route enforcement evidence through finalizer"
```

### Task 4: Make evidence delivery fail closed by default

**Files:**
- Modify: `aegis/_internal/sinks.py`
- Modify: `aegis/sinks.py`
- Modify: `aegis/__init__.py`
- Modify: `aegis/_internal/enforcement.py`
- Modify: `aegis/_internal/evidence_finalizer.py`
- Modify: `tests/test_audit_sinks.py`
- Create: `tests/test_fail_closed_evidence_delivery.py`
- Modify: `docs/PUBLIC_INTEGRATION_CONTRACT.md`
- Modify: `docs/migration.md`

**Interfaces:**
- `AEGIS(..., sink: AuditSink, on_sink_failure: Literal["raise"] = "raise")`
- V2 construction without a sink raises configuration error before governed traffic.

- [ ] **Step 1: Write broken/missing-sink tests**

```python
def test_broken_sink_cannot_return_pass(valid_invocation):
    aegis = AEGIS(sink=BrokenSink())
    with pytest.raises(AuditSinkError):
        aegis.enforce(valid_invocation)
    assert aegis.evidence_diagnostics().evidence_delivery_failures_total == 1


def test_v2_requires_sink():
    with pytest.raises(ValueError, match="V2_SINK_REQUIRED"):
        AEGIS(sink=None)


def test_module_level_api_without_runtime_fails_closed(valid_invocation):
    reset_module_runtime_for_test()
    with pytest.raises(EvidenceConfigurationError) as exc:
        enforce_invocation(valid_invocation)
    assert exc.value.code == "V2_SINK_REQUIRED"


def test_gate_cannot_downgrade_v2_delivery_mode(configured_module_runtime):
    with pytest.raises(RuntimeError):
        set_sink_failure_mode("log")
```

- [ ] **Step 2: Run and verify current default-log behavior**

Run: `.venv/bin/pytest tests/test_fail_closed_evidence_delivery.py tests/test_audit_sinks.py -v`

Expected: FAIL because the current default logs and returns.

- [ ] **Step 3: Flip the v2 default and require acknowledgement**

Successful synchronous `sink.emit()` return is acknowledgement. Any exception is wrapped as `AuditSinkError(code="AUDIT_DELIVERY_FAILED")`; the finalizer records the delivery counter and does not return the artifact.

- [ ] **Step 4: Preserve only host-authorized legacy log mode**

Remove `emit_to_sink`, `set_sink_failure_mode`, and
`get_sink_failure_mode` from `aegis.sinks.__all__` and the v2 import surface.
The v2 finalizer never reads module-global `_sink_failure_mode`.

If compatibility is retained, move it behind a separately named legacy adapter
that requires B1 `LegacyAuthorization("sink_failure_log")`; it cannot configure
or mutate a v2 instance/module runtime. `set_audit_sink` is deprecated in favor
of the one-time module runtime configurator and is not consulted by v2.
Reject policy/provider/invocation attempts to select legacy behavior.

Run: `.venv/bin/pytest tests/test_fail_closed_evidence_delivery.py tests/test_audit_sinks.py tests/test_legacy_authority_boundary.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/sinks.py aegis/sinks.py aegis/__init__.py aegis/_internal/enforcement.py aegis/_internal/evidence_finalizer.py tests/test_audit_sinks.py tests/test_fail_closed_evidence_delivery.py tests/test_module_level_evidence_runtime.py docs/PUBLIC_INTEGRATION_CONTRACT.md docs/migration.md
git commit -m "fix: fail closed on evidence delivery"
```

### Task 5: Sign workflow/session evidence and enforce the finalizer boundary in CI

**Files:**
- Modify: `aegis/_internal/session.py`
- Modify: `tests/test_governance_session.py`
- Create: `tests/test_workflow_evidence_signing.py`
- Modify: `tests/test_architecture_security_boundaries.py`
- Modify: `.github/workflows/security-boundaries.yml`
- Modify: `docs/architecture/ENFORCEMENT_PIPELINE.md`
- Modify: `docs/architecture/ARCHITECTURAL_INVARIANTS.md`

**Interfaces:**
- Workflow finalization produces an `EvidenceDraft` with signing domain `aegis.workflow.v2`.
- B4 later adds ordered step-count content without changing this boundary.

- [ ] **Step 1: Write unsigned-workflow regression tests for #51**

Assert finalized completed, failed, canceled, and incomplete sessions contain checksum, signature metadata/status, and schema version 2.0, and that the sink received the exact finalized value.

- [ ] **Step 2: Run and verify current unsigned session path**

Run: `.venv/bin/pytest tests/test_workflow_evidence_signing.py tests/test_governance_session.py -v`

Expected: FAIL because session evidence currently bypasses signing.

- [ ] **Step 3: Route workflow evidence through the finalizer**

Use the workflow signing domain and finalizer; do not add it to an invocation chain.

- [ ] **Step 4: Make architecture tests blocking**

The blocking test must fail if any production module outside
`evidence_finalizer.py` reaches acknowledged delivery, imports/calls
`emit_to_sink`, calls a sink's `.emit()` as part of enforcement, calls
`sign_artifact*`, constructs v2 checksum/final fields, or exposes mutable
failure-mode controls. It resolves public re-exports and aliases, asserts the
forbidden names are absent from `aegis.sinks.__all__`, and runs behavioral
coverage over every module/instance/session entry point. Wire it into
`security-boundaries.yml`.

Run: `.venv/bin/pytest tests/test_workflow_evidence_signing.py tests/test_evidence_emission_inventory.py tests/test_architecture_security_boundaries.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/session.py tests/test_governance_session.py tests/test_workflow_evidence_signing.py tests/test_architecture_security_boundaries.py .github/workflows/security-boundaries.yml docs/architecture/ENFORCEMENT_PIPELINE.md docs/architecture/ARCHITECTURAL_INVARIANTS.md
git commit -m "fix: finalize and sign all workflow evidence"
```

## B2 Completion Gate

Run:

```bash
.venv/bin/pytest tests/test_attempt_envelope.py tests/test_evidence_diagnostics.py tests/test_evidence_finalizer.py tests/test_evidence_finalizer_signing.py tests/test_evidence_emission_inventory.py tests/test_fail_closed_evidence_delivery.py tests/test_workflow_evidence_signing.py tests/test_architecture_security_boundaries.py -v
.venv/bin/pytest -q
```

Expected: both commands exit `0`; #51 is closed, no emission/signing bypass remains, and delivery failure cannot return an allow-class result.
