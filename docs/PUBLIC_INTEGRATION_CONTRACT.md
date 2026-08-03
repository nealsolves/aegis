# AEGIS Public Integration Contract

This document is the primary onboarding reference for integrating AEGIS into your system.
It contains a minimal hello-world example, a realistic production integration, the available
extension points, and a troubleshooting/FAQ section.

It describes the public runtime surface packaged in the
`aegis-ai-governance==0.9.0b1` public beta. The distribution name changes,
but integrations continue to use `import aegis` and the `aegis` CLI. The
target-state `1.0.0` architecture contract is captured separately in
[docs/architecture/AEGIS_HIGH_LEVEL_DESIGN.md](architecture/AEGIS_HIGH_LEVEL_DESIGN.md).
The release source is `main`.

Section 3.8 additionally documents #44 contracts implemented in the current
source tree after `0.9.0b1`. Those APIs are not in the published `0.9.0b1`
wheel or tag, and no later published version is assigned yet.

Section 3.10 documents the B4 workflow claimed-set extension as
current-source-only. It is not in the published
`aegis-ai-governance==0.9.0b1` wheel or tag, and no later published version is
assigned.

Source, tags, and release artifacts for versions before `0.9.0` remain in
[`nealsolves/aigc`](https://github.com/nealsolves/aigc). This repository is the
AEGIS `0.9.0`-and-later development home.

The candidate includes `AEGIS.open_session(...)`, `GovernanceSession`, and
`SessionPreCallResult`. This is beta, not yet stable.
There is no module-level `open_session()` convenience — workflow adoption is
always instance-scoped through `AEGIS.open_session(...)`.

See [docs/reference/WORKFLOW_QUICKSTART.md](reference/WORKFLOW_QUICKSTART.md)
for the fastest path to a working workflow with these surfaces.

Also available in the `v0.9.0` beta candidate: `aegis workflow init`,
`aegis policy init`, `aegis workflow lint`, `aegis workflow doctor`,
`aegis.presets.MinimalPreset`, `aegis.presets.StandardPreset`,
`aegis.presets.RegulatedHighAssurancePreset`, `WorkflowStarterIntegrityError`,
and `docs/migration.md` (migration guide from invocation-only to workflow
governance). This is beta, not yet stable.

`aegis.bedrock_adapter`, `aegis.a2a_adapter`, and
`aegis.openai_agents_adapter` are included optional submodules and are not
top-level re-exports. `AgentIdentity`, `AgentCapabilityManifest`, and
`ValidatorHook` remain outside the current public surface.

`aegis workflow trace` and `aegis workflow export` shipped in PR-09 and are part
of the current beta CLI surface.

All public examples, starter packs, presets, demo code, and docs snippets
must use public `aegis` imports only and must not depend on `aegis._internal`.

---

## 1. Hello AEGIS — Minimal Runnable Example

Install and run governance enforcement in under five minutes.

### 1.1 Install

```bash
pip install aegis-ai-governance==0.9.0b1
```

Source contributors may instead install `main` in editable mode with
development dependencies:

```bash
git clone https://github.com/nealsolves/aegis
cd aegis
python -m pip install --upgrade pip setuptools wheel
pip install --no-build-isolation -e '.[dev]'
```

### 1.2 Write a policy

Create `policies/hello_policy.yaml`:

```yaml
policy_version: "1.0"
roles:
  - assistant
pre_conditions:
  required:
    - user_id
output_schema:
  type: object
  required:
    - reply
  properties:
    reply:
      type: string
```

### 1.3 Call `enforce_invocation`

```python
from aegis import (
    JsonFileAuditSink,
    configure_module_enforcement,
    enforce_invocation,
    GovernanceViolationError,
    PreconditionError,
)

configure_module_enforcement(
    sink=JsonFileAuditSink("audit.jsonl"),
)

invocation = {
    "policy_file": "policies/hello_policy.yaml",
    "model_provider": "openai",
    "model_identifier": "gpt-4o",
    "role": "assistant",
    "input": {"prompt": "Hello!"},
    "output": {"reply": "Hello, I am your assistant."},
    "context": {"user_id": "user-001"},
}

artifact = enforce_invocation(invocation)
print(artifact["enforcement_result"])  # PASS
```

The call returns an audit artifact on success and raises a typed exception on any governance
violation. No silent fallbacks. No best-effort checks.

---

## 2. Production Integration

This section builds a single, realistic integration from the ground up: a governed analytics
service that uses the full pre-split governance stack (M2 plus production runtime features).
The additive v0.3.2 split-enforcement APIs are covered separately in Section 3.16. Each
subsection extends the same example rather than introducing a separate one.

### 2.1 Policy with guards, tool constraints, and risk scoring

Create `policies/analyst_policy.yaml`:

```yaml
policy_version: "1.0"
effective_date: "2025-01-01"
expiration_date: "2027-12-31"
roles:
  - analyst
conditions:
  is_enterprise:
    type: boolean
    default: false
pre_conditions:
  required:
    tenant_id:
      type: string
    session_id:
      type: string
output_schema:
  type: object
  required:
    - analysis
  properties:
    analysis:
      type: string
post_conditions:
  required:
    - output_schema_valid
guards:
  - when:
      condition: "is_enterprise"
    then:
      tools:
        allowed_tools:
          - name: internal_search
            max_calls: 10
risk:
  mode: strict
  threshold: 0.7
  factors:
    - name: no_schema
      weight: 0.4
      condition: no_output_schema
    - name: external_provider
      weight: 0.3
      condition: external_model
    - name: broad_access
      weight: 0.3
      condition: broad_roles
```

This policy declares:

- **Typed preconditions**: `tenant_id` and `session_id` must be present strings in context.
- **Output schema**: Model output must contain an `analysis` string.
- **Guards**: When `is_enterprise` is true in context, tool constraints activate, allowing
  `internal_search` with a cap of 10 calls.
- **Risk scoring**: Strict mode with a 0.7 threshold. Three weighted factors evaluate whether
  the policy itself is well-formed (has a schema, uses a narrow role set, runs an internal
  model). If the composite score reaches 0.7, enforcement fails with `RiskThresholdError`.
  Independently, a score at or above 0.90 fails in every risk mode.
- **Policy dates**: Active from 2025-01-01 through 2027-12-31. Loading the policy outside this
  window raises `PolicyValidationError`.

### 2.2 Custom enforcement gate

Custom gates inject governance logic at defined insertion points in the pipeline without
modifying the core enforcement code. This gate enforces tenant isolation:

```python
from aegis import EnforcementGate, GateResult, INSERTION_PRE_AUTHORIZATION


class TenantIsolationGate(EnforcementGate):
    """Verify tenant_id is present before any authorization gate runs."""

    @property
    def name(self) -> str:
        return "tenant_isolation"

    @property
    def insertion_point(self) -> str:
        return INSERTION_PRE_AUTHORIZATION

    def evaluate(self, invocation, policy, context):
        tenant_id = invocation.get("context", {}).get("tenant_id")
        if not tenant_id:
            return GateResult(
                passed=False,
                failures=[{
                    "code": "MISSING_TENANT",
                    "message": "tenant_id is required for all invocations",
                    "field": "context.tenant_id",
                }],
            )
        return GateResult(passed=True, metadata={"verified_tenant": tenant_id})
```

The gate runs at `pre_authorization`, before role validation and precondition checks. It
receives detached, recursively immutable projections of `invocation` and an explicit
allowlist of compiled policy fields. Supplied arguments contain no handle to live AEGIS
enforcement state; this argument guarantee is not an in-process Python sandbox. If the gate
fails, the pipeline stops and a FAIL artifact is generated with the gate's failure details.
The gate's `metadata` dict is merged into the audit artifact's `metadata` on PASS.

Custom gates appear as `"custom:tenant_isolation"` in the artifact's `metadata.gates_evaluated`
list. `passed=False` denies even without a failure list, while `passed=True` plus failures is
an invalid result and denies. Gate metadata is merged into `metadata.custom_gate_metadata`.
If a gate raises an unhandled exception, the pipeline converts it to a sanitized, stable
execution-failure outcome with code `CUSTOM_GATE_ERROR` — governance never crashes.

### 2.3 Application startup

Wire everything together once at startup. The `AEGIS` class is the production entry point —
it owns its sink, signer, gates, and policy cache with no global mutable state:

```python
from aegis import AEGIS, HMACSigner, AuditChain, JsonFileAuditSink

signer = HMACSigner(key=b"your-256-bit-secret-key-here-!!!")
chain = AuditChain(chain_id="analytics-session-001")

aegis = AEGIS(
    sink=JsonFileAuditSink("audit/governance.jsonl"),
    signer=signer,
    chain_linker=chain,
    custom_gates=[TenantIsolationGate()],
)
```

Configuration is immutable after construction. `AEGIS.enforce()` is thread-safe.

- **`sink`**: Every enforcement call (PASS and FAIL) emits an artifact as a JSON line.
- **`signer`**: HMAC-SHA256 signs every artifact automatically — both PASS and FAIL.
- **`chain_linker`**: Reserves host-owned chain coordinates before the content checksum
  and signature are created. `AuditChain` is the bundled single-process implementation.
- **`custom_gates`**: Validated at construction time. Invalid insertion points raise immediately.
- **`on_sink_failure`**: `"raise"` is the only v2 mode and prevents an
  allow-class result when durable evidence was not acknowledged. Legacy
  best-effort delivery cannot configure an `AEGIS` or module runtime.

### 2.4 Building and enforcing invocations

Use `InvocationBuilder` for a fluent, validated construction:

```python
from aegis import InvocationBuilder

invocation = (
    InvocationBuilder()
    .policy("policies/analyst_policy.yaml")
    .model("anthropic", "claude-sonnet-4-6")
    .role("analyst")
    .input({"question": "Summarize Q4 results"})
    .output({"analysis": "Revenue increased 12% QoQ."})
    .context({
        "tenant_id": "acme-corp",
        "session_id": "sess-42",
        "is_enterprise": True,
    })
    .build()
)

artifact = aegis.enforce(invocation)
```

`build()` validates that all required fields are present and raises `InvocationValidationError`
if any are missing. The returned dict is independent — calling `build()` again produces a
new object.

On PASS, `artifact` is a signed audit artifact dict. On failure, a typed exception propagates
with the FAIL artifact attached at `exc.audit_artifact`.

### 2.5 Audit chain for artifact integrity

Configure a host-owned linker at startup for tamper-evident sequencing. The linker reserves
the next placement before checksum construction and signing; successful sink acknowledgement
is followed by commit. Callers do not append or mutate the returned artifact:

```python
artifact = aegis.enforce(invocation)
print(chain.length)  # 1
```

Each linked invocation artifact contains one complete coordinate set:

- `chain_id`: links the artifact to this chain
- `chain_index`: 0-based position in the chain
- `previous_audit_checksum`: prior artifact's v2 content checksum (`null` for the first)
- `reservation_id`: opaque host reservation used for commit/abort reconciliation

`previous_audit_checksum` is the prior artifact’s v2 content checksum; it is never a
signature or storage-provider digest. `AuditChain.append()` remains deprecated for offline
compatibility only; new enforcement code configures `chain_linker` instead.

Inspect the independent verification axes using the sequence read from storage (e.g.,
from the audit sink's JSONL file):

```python
import json
from aegis import verify_chain_detailed

with open("audit/governance.jsonl") as f:
    artifacts = [json.loads(line) for line in f]

report = verify_chain_detailed(artifacts)
assert report.content_integrity.value == "valid"
assert report.chain_continuity.value == "valid"
assert report.completeness.value == "unproven"
```

`verify_chain()` remains a deprecated compatibility wrapper. Its boolean means
only that content and continuity are internally valid; it says nothing about
signature validity, anchoring, or completeness.

### 2.6 Decorator pattern

For simpler call sites that don't need instance-scoped configuration, the `@governed`
decorator wraps a function and runs enforcement transparently:

```python
from aegis import governed, configure_module_enforcement, JsonFileAuditSink

configure_module_enforcement(
    sink=JsonFileAuditSink("audit/governance.jsonl"),
)


@governed(
    policy_file="policies/analyst_policy.yaml",
    role="analyst",
    model_provider="anthropic",
    model_identifier="claude-sonnet-4-6",
)
async def analyze(input_data: dict, context: dict) -> dict:
    result = await llm.generate(input_data, context)
    return {"analysis": result}


output = await analyze(
    {"question": "Summarize Q4 results"},
    {"tenant_id": "acme-corp", "session_id": "sess-42", "is_enterprise": True},
)
```

The decorator captures `input_data` as input, `context` as context, and runs split
enforcement by default (since v0.3.3): Phase A (`enforce_pre_call_async()`) runs before
the wrapped function; Phase B (`enforce_post_call_async()`) validates the return value.
Pass `pre_call_enforcement=False` for legacy unified mode (deprecated).
Governance exceptions propagate unchanged.

The decorator uses the private module runtime. Configure it exactly once before
the first governed call; that first attempt atomically seals it. For
per-instance signers or custom gates, use `AEGIS` directly.

### 2.7 Error handling

Every governance failure raises a typed exception with a FAIL artifact attached:

```python
from aegis import (
    AEGISError,
    GovernanceViolationError,
    PreconditionError,
    SchemaValidationError,
    ToolConstraintViolationError,
    RiskThresholdError,
    CustomGateViolationError,
)

try:
    artifact = aegis.enforce(invocation)
    chain.append(artifact)
except RiskThresholdError as exc:
    # Risk score exceeded threshold in strict mode
    print(f"Risk: {exc.details['score']:.3f} > {exc.details['threshold']:.3f}")
    chain.append(exc.audit_artifact)
except CustomGateViolationError as exc:
    # A custom gate failed (e.g., tenant isolation)
    print(f"Gate failure: {exc}")
    chain.append(exc.audit_artifact)
except ToolConstraintViolationError as exc:
    # Tool not in allowed list or max_calls exceeded
    chain.append(exc.audit_artifact)
except PreconditionError as exc:
    # Required context key missing or wrong type
    chain.append(exc.audit_artifact)
except SchemaValidationError as exc:
    # Model output doesn't match policy output_schema
    chain.append(exc.audit_artifact)
except GovernanceViolationError as exc:
    # Role not in policy, or other governance violation
    chain.append(exc.audit_artifact)
except AEGISError as exc:
    # Catch-all for any governance error
    chain.append(exc.audit_artifact)
```

Every exception carries `exc.audit_artifact` (a complete, signed FAIL artifact),
`exc.code` (machine-readable error code), and `exc.details` (structured metadata).
FAIL artifacts are emitted to the sink before the exception propagates.

### 2.8 Testing your policies

Use the policy testing framework to validate policies in isolation, without a running LLM:

```python
from aegis import PolicyTestCase, PolicyTestSuite, expect_pass, expect_fail

# Quick single-case assertions
expect_pass(PolicyTestCase(
    name="valid analyst call",
    policy_file="policies/analyst_policy.yaml",
    role="analyst",
    input_data={"question": "Summarize Q4"},
    output_data={"analysis": "Revenue grew 12%."},
    context={
        "tenant_id": "acme",
        "session_id": "s-1",
    },
))

expect_fail(
    PolicyTestCase(
        name="unauthorized role rejected",
        policy_file="policies/analyst_policy.yaml",
        role="admin",
        input_data={"question": "Drop tables"},
        output_data={"analysis": "Done."},
        context={"tenant_id": "acme", "session_id": "s-2"},
    ),
    gate="role_validation",
    error_type=GovernanceViolationError,
)

# Batch test suite
suite = PolicyTestSuite("analyst_policy_regression")

suite.add(
    PolicyTestCase(
        name="schema mismatch rejected",
        policy_file="policies/analyst_policy.yaml",
        role="analyst",
        input_data={"question": "Q4?"},
        output_data={"wrong_field": "oops"},
        context={"tenant_id": "acme", "session_id": "s-3"},
    ),
    expected="fail",
)

suite.add(
    PolicyTestCase(
        name="missing precondition rejected",
        policy_file="policies/analyst_policy.yaml",
        role="analyst",
        input_data={"question": "Q4?"},
        output_data={"analysis": "ok"},
        context={},  # missing tenant_id and session_id
    ),
    expected="fail",
)

results = suite.run_all()
assert suite.all_passed(results), "Policy regression detected"
```

`expect_pass` raises `AssertionError` if enforcement fails. `expect_fail` raises if enforcement
passes, and optionally asserts on the specific failure gate and error type. `PolicyTestSuite`
collects cases with expected outcomes and reports whether all expectations were met.

---

## 3. Extension Reference

Each entry below documents a single extension point. For how these compose in a production
integration, see Section 2.

### 3.1 Custom audit sink

Subclass `AuditSink` to send artifacts to any destination:

```python
from aegis import AEGIS, AuditSink
import json


class SQLiteAuditSink(AuditSink):
    def __init__(self, conn):
        self._conn = conn

    def emit(self, artifact: dict) -> None:
        self._conn.execute(
            "INSERT INTO governance_log (artifact) VALUES (?)",
            [json.dumps(artifact)],
        )


governance = AEGIS(sink=SQLiteAuditSink(db_connection))
```

Successful synchronous return from `emit()` is the v2 acknowledgement. Any
exception becomes `AuditSinkError(code="AUDIT_DELIVERY_FAILED")`; no PASS/WARN
artifact is returned. Sinks receive a deep copy and cannot mutate the returned
artifact.

### 3.2 Policy composition via `extends`

Policies can inherit from a base policy using `extends`. The `composition_strategy` field
controls how fields are merged:

```yaml
# policies/child_policy.yaml
extends: "base_policy.yaml"
composition_strategy: "union"
policy_version: "2.0"
roles:
  - analyst
  - reviewer
```

Strategies:

- **default** (no strategy): ordinary arrays append, dicts recurse, scalars replace
- **`union`**: ordinary arrays are combined and deduplicated, dicts recurse, scalars replace
- **`intersect`**: ordinary arrays keep only shared elements, dicts recurse, scalars replace
- **`replace`**: overlay completely replaces base for all specified keys

Security fields do not inherit the generic array behavior. Child `roles`,
`tools.allowed_tools`, and workflow participants are complete replacements
that must remain subsets of parent authority. Once inherited,
`workflow.required_sequence` is exact and cannot be shortened, reordered, or
otherwise replaced. Tool presence is also authoritative: an omitted
`tools.allowed_tools` block is unconfigured, while an explicit empty list
denies every tool.

Load the child policy directly — resolution happens at load time:

```python
from aegis import enforce_invocation
artifact = enforce_invocation({
    "policy_file": "policies/child_policy.yaml",
    ...
})
```

Cycle detection is built-in. If `A` extends `B` extends `A`, loading raises `PolicyLoadError`.

### 3.3 Retry on transient failures

Wrap invocations with `with_retry` for bounded retries on `SchemaValidationError`:

```python
from aegis import with_retry

# retry_policy belongs in the policy YAML, not the invocation payload
artifact = with_retry(invocation)
```

### 3.4 Host tool adapter wrapper

AEGIS does not provide a built-in tool execution adapter. The recommended pattern for governing
tool calls on the host side is to build a thin wrapper that constructs the invocation dict,
enforces governance, and then executes the tool:

```python
from aegis import enforce_invocation


def run_tool_with_governance(tool_name: str, params: dict, base_invocation: dict) -> dict:
    governed_invocation = {
        **base_invocation,
        "input": {"tool": tool_name, "params": params},
        "output": {"status": "tool_call_planned"},
        "tool_calls": [{"name": tool_name, "call_id": "generated-1"}],
    }
    enforce_invocation(governed_invocation)
    return execute_tool(tool_name, params)
```

This pattern keeps governance at the SDK boundary and avoids coupling the tool implementation
to the AEGIS API.

### 3.5 InvocationBuilder

Fluent builder as an alternative to hand-constructing invocation dicts:

```python
from aegis import InvocationBuilder

invocation = (
    InvocationBuilder()
    .policy("policies/my_policy.yaml")
    .model("anthropic", "claude-sonnet-4-6")
    .role("planner")
    .input({"task": "plan investigation"})
    .output({"result": "plan ready", "confidence": 0.95})
    .context({"role_declared": True, "schema_exists": True})
    .tools([{"name": "search", "call_id": "tc-1"}])
    .build()
)
```

`build()` raises `InvocationValidationError` if required fields are missing.

### 3.6 Custom enforcement gates

Inject governance logic at four pipeline insertion points:

| Constant | Runs |
| -------- | ---- |
| `INSERTION_PRE_AUTHORIZATION` | Before guard evaluation, role, precondition, and tool checks |
| `INSERTION_POST_AUTHORIZATION` | After tool constraint validation, before schema validation |
| `INSERTION_PRE_OUTPUT` | Before schema and postcondition validation |
| `INSERTION_POST_OUTPUT` | After all validation, before risk scoring |

```python
from aegis import EnforcementGate, GateResult, INSERTION_POST_OUTPUT


class ComplianceTagGate(EnforcementGate):
    @property
    def name(self):
        return "compliance_tag"

    @property
    def insertion_point(self):
        return INSERTION_POST_OUTPUT

    def evaluate(self, invocation, policy, context):
        return GateResult(passed=True, metadata={"compliance": "sox-compliant"})


aegis = AEGIS(
    sink=JsonFileAuditSink("audit.jsonl"),
    custom_gates=[ComplianceTagGate()],
)
```

Gate metadata is merged into `metadata.custom_gate_metadata` in the audit artifact.
`invocation` and `policy` are detached, recursively immutable `Mapping` projections.
Failures are append-only — a gate cannot suppress earlier failures. Unhandled exceptions
become sanitized execution failures (code `CUSTOM_GATE_ERROR`), never crashes.

### Built-In Gates

The SDK ships `ProvenanceGate` — a workflow-aware built-in gate for source
presence enforcement. Import and register it like any custom gate:

```python
from aegis import AEGIS, JsonFileAuditSink, ProvenanceGate

aegis = AEGIS(
    sink=JsonFileAuditSink("audit.jsonl"),
    custom_gates=[ProvenanceGate()],
)
```

Available built-in gates:

| Gate | Module | Insertion Point | Enforces |
|------|--------|-----------------|---------|
| `ProvenanceGate` | `aegis.provenance_gate` | `pre_output` | `source_ids` present in context provenance |

### 3.7 Risk scoring

Risk scoring evaluates the structural quality of a policy and invocation. Configure it in
the policy YAML:

```yaml
risk:
  mode: strict        # strict | risk_scored | warn_only
  threshold: 0.7
  factors:
    - name: no_schema
      weight: 0.4
      condition: no_output_schema
    - name: broad_access
      weight: 0.3
      condition: broad_roles
    - name: external
      weight: 0.3
      condition: external_model
```

Built-in conditions: `no_output_schema`, `broad_roles` (>3 roles), `no_preconditions`,
`high_tool_count` (>5 tools), `missing_guards`, `external_model` (provider ≠ `"internal"`).
Any other condition name is looked up as a context key.

Modes:

- **`strict`**: Score equal to or above the threshold raises `RiskThresholdError`
- **`risk_scored`**: A policy-threshold breach below 0.90 is recorded as a warning
- **`warn_only`**: A policy-threshold breach below 0.90 is logged and recorded as a warning

The fixed critical ceiling is inclusive: a score at or above `0.90` raises
`RiskThresholdError` in all three modes. `risk_scored` and `warn_only` therefore
cannot be used to bypass a critical score.

The `AEGIS` class accepts `risk_config` as a constructor override; otherwise the policy's
`risk` field is used.

### 3.8 Artifact signing and external trust results

**Release boundary:** the legacy API in this section is published in
`0.9.0b1`. The metadata-aware external signer/verifier contracts are
source-only changes after that release and are not available from the
`aegis-ai-governance==0.9.0b1` installation shown in Section 1.1.

The original `ArtifactSigner` path remains supported. `HMACSigner`,
`sign_artifact()`, automatic `AEGIS(signer=...)` signing, and
`verify_artifact()` retain their existing artifact shape and behavior.
`verify_artifact()` answers only whether the supplied legacy signer verifies
the reconstructed payload:

```python
>>> from aegis import HMACSigner, sign_artifact, verify_artifact
>>> legacy_artifact = {"event": "approved", "signature": None}
>>> legacy_signer = HMACSigner(key=b"demo-only-legacy-key")
>>> _ = sign_artifact(legacy_artifact, legacy_signer)
>>> verify_artifact(legacy_artifact, legacy_signer)
True

```

That `True` is a cryptographic-validity result, not an external-anchor result.
HMAC-SHA256 provides tamper-evidence; it does not provide immutable storage.
Detailed verification reports a valid legacy HMAC artifact as
`VALID / UNANCHORED / LEGACY_SIGNATURE_VALID`. For a valid unknown custom
legacy signer, anchor status is `NOT_EVALUATED`.
When detailed verification calls a legacy signer's `verify()` method, the
adapter must return an exact built-in `bool`. Strings, integers, and objects
with custom truthiness are malformed responses; AEGIS does not evaluate their
truthiness and raises a fixed sanitized `VerificationContractError`.

Use `sign_artifact_with_metadata()` and `verify_artifact_detailed()` when the
host needs a versioned identity and separate signature/anchor results. The
following executable example defines both public protocols. It uses a local
shared key only to keep the example deterministic; a production adapter keeps
credentials and provider transport outside AEGIS.

The public call signatures are:

```python
class ExternalArtifactSigner(Protocol):
    def signer_identity(self) -> SignerIdentity: ...
    def sign(
        self, payload: bytes, identity: SignerIdentity
    ) -> SigningReceipt: ...


class ExternalArtifactVerifier(Protocol):
    def verify(
        self,
        payload: bytes,
        signature: str,
        metadata: SignatureMetadata,
    ) -> ExternalVerificationOutcome: ...


def sign_artifact_with_metadata(
    artifact: dict[str, Any],
    signer: ExternalArtifactSigner,
    *,
    signed_at: int,
) -> dict[str, Any]: ...


def verify_artifact_detailed(
    artifact: Mapping[str, Any],
    *,
    legacy_signer: ArtifactSigner | None = None,
    verifier: ExternalArtifactVerifier | None = None,
) -> ArtifactVerificationResult: ...
```

```python
>>> import hashlib
>>> import hmac
>>> from aegis import (
...     AnchorStatus,
...     ExternalArtifactSigner,
...     ExternalArtifactVerifier,
...     ExternalVerificationOutcome,
...     SignatureEncoding,
...     SignatureStatus,
...     SignerIdentity,
...     SigningReceipt,
...     VerificationReasonCode,
...     sign_artifact_with_metadata,
...     verify_artifact_detailed,
... )
>>> class DemoExternalSigner(ExternalArtifactSigner):
...     def __init__(self, key):
...         self._key = key
...     def signer_identity(self):
...         return SignerIdentity(
...             algorithm="DEMO-SHA256",
...             signature_encoding=SignatureEncoding.HEX,
...             key_reference="demo/audit-key",
...             key_version="version/7",
...         )
...     def sign(self, payload, identity):
...         signature = hmac.new(self._key, payload, hashlib.sha256).hexdigest()
...         return SigningReceipt(
...             signature=signature,
...             algorithm=identity.algorithm,
...             signature_encoding=identity.signature_encoding,
...             key_reference=identity.key_reference,
...             key_version=identity.key_version,
...         )
>>> class DemoExternalVerifier(ExternalArtifactVerifier):
...     def __init__(self, keys, allowed_algorithms, anchored_versions):
...         self._keys = dict(keys)
...         self._allowed_algorithms = set(allowed_algorithms)
...         self._anchored_versions = set(anchored_versions)
...     def verify(self, payload, signature, metadata):
...         identity = (metadata.key_reference, metadata.key_version)
...         key = self._keys.get(identity)
...         if key is None:
...             return ExternalVerificationOutcome(
...                 SignatureStatus.UNKNOWN_KEY,
...                 AnchorStatus.NOT_EVALUATED,
...                 VerificationReasonCode.KEY_UNKNOWN,
...                 "unknown key",
...             )
...         if metadata.algorithm not in self._allowed_algorithms:
...             return ExternalVerificationOutcome(
...                 SignatureStatus.INVALID,
...                 AnchorStatus.NOT_EVALUATED,
...                 VerificationReasonCode.ALGORITHM_NOT_ALLOWED,
...                 "algorithm denied",
...             )
...         expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
...         if not hmac.compare_digest(expected, signature):
...             return ExternalVerificationOutcome(
...                 SignatureStatus.INVALID,
...                 AnchorStatus.NOT_EVALUATED,
...                 VerificationReasonCode.SIGNATURE_INVALID,
...                 "invalid signature",
...             )
...         anchored = identity in self._anchored_versions
...         return ExternalVerificationOutcome(
...             SignatureStatus.VALID,
...             AnchorStatus.ANCHORED if anchored else AnchorStatus.UNANCHORED,
...             (
...                 VerificationReasonCode.SIGNATURE_VALID_ANCHORED
...                 if anchored
...                 else VerificationReasonCode.SIGNATURE_VALID_UNANCHORED
...             ),
...             "verified",
...         )
>>> demo_key = b"demo-only-external-key"
>>> external_signer = DemoExternalSigner(demo_key)
>>> artifact = {
...     "audit_schema_version": "1.4",
...     "event": "approved",
...     "signature": None,
... }
>>> _ = sign_artifact_with_metadata(
...     artifact,
...     external_signer,
...     signed_at=1_721_600_000,
... )
>>> artifact["signature_metadata"]["signed_at"]
1721600000
>>> external_verifier = DemoExternalVerifier(
...     keys={("demo/audit-key", "version/7"): demo_key},
...     allowed_algorithms={"DEMO-SHA256"},
...     anchored_versions={("demo/audit-key", "version/7")},
... )
>>> result = verify_artifact_detailed(artifact, verifier=external_verifier)
>>> result.is_signature_valid
True
>>> result.is_anchored
True

```

The host-configured verifier resolves the exact
`(key_reference, key_version)` pair. AEGIS does not dereference artifact data,
discover provider keys, or treat the metadata-declared algorithm as
authorization. The verifier's trusted configuration decides which keys,
versions, algorithms, and anchors are accepted. `key_reference` is a
non-secret opaque identifier; do not place credentials, secret material,
tokens, unrestricted provider responses, or a locator that AEGIS should
dereference in it.

Source-only provider implementations are available from
`aegis.integrations.aws_kms` and
`aegis.integrations.google_cloud_kms`; they are not top-level re-exports.
Install them from this source checkout with
`python -m pip install -e ".[aws-kms]"` or
`python -m pip install -e ".[gcp-kms]"`. Their complete closed algorithm set
is `RSASSA_PSS_SHA_256`, `ECDSA_SHA_256`,
`RSA_SIGN_PSS_2048_SHA256`, `RSA_SIGN_PSS_3072_SHA256`,
`RSA_SIGN_PSS_4096_SHA256`, and `EC_SIGN_P256_SHA256`.

Artifact metadata does not select provider resources. AWS verification binds
to a host-approved concrete logical-key ARN, which is not a
backing-material version. Google verification binds to an exact
CryptoKeyVersion and either validates checksummed `PublicKey.public_key.data`
or uses a host-retained PEM. The provider guides document client construction,
least privilege, rotation, revocation, outages, and retained evidence:
[AWS KMS](reference/external/AWS_KMS_SIGNING.md) and
[Google Cloud KMS](reference/external/GOOGLE_CLOUD_KMS_SIGNING.md).

`sign_artifact_with_metadata(artifact, signer, *, signed_at)` requires an
explicit non-negative integer Unix second; `bool` is rejected. `signed_at`
records the host's observation of when signing began. It is not trusted time,
timestamp-authority evidence, or replay protection. The signer identity and
receipt pin the same algorithm, encoding, key reference, and immutable key
version. AEGIS attaches `signature_metadata` and `signature` together only
after every value is validated; failure leaves the input unchanged. This
atomic update does not make concurrent signing of the same mutable dictionary
thread-safe. Re-signing and asynchronous signer/verifier contracts are not
supported.

AEGIS keeps an untouched identity snapshot for stored metadata and receipt
comparison, while the signer receives a disposable equal copy. Detailed
verification likewise keeps an untouched parsed metadata snapshot, gives the
verifier a disposable equal copy, and returns the untouched snapshot. Adapter
mutation therefore cannot renegotiate the signing identity or rewrite returned
metadata.

Metadata-aware profile `aegis-signature-v1` signs exactly:

```text
b"AEGIS-SIGNATURE\x00aegis-signature-v1\x00audit_artifact\x00"
+ canonical_json_bytes(artifact_without_signature)
```

The artifact in those canonical bytes includes all nine strict metadata fields:
`schema_version`, `signing_profile`, `canonicalization_version`,
`payload_type`, `algorithm`, `signature_encoding`, `key_reference`,
`key_version`, and `signed_at`. Missing or extra metadata fields are rejected.
The top-level audit schema remains `1.4`; `signature_metadata` is optional and
versioned independently, and `signature` remains `string | null`.

The fixed public values are
`SIGNATURE_METADATA_SCHEMA_VERSION = "1"`,
`SIGNING_PROFILE = "aegis-signature-v1"`, and
`CANONICALIZATION_VERSION = "aegis-canonical-json-v1"`. The closed payload type
is `EvidenceType.AUDIT_ARTIFACT` (`"audit_artifact"`); supported encodings are
`SignatureEncoding.HEX` (`"hex"`) and `SignatureEncoding.BASE64`
(`"base64"`).

The exact metadata-aware lexical and length rules are:

- `algorithm`: 1-128 characters, each from `[A-Za-z0-9._-]`;
- `key_reference`: 1-512 ASCII-printable characters, U+0020 through U+007E
  inclusive;
- `key_version`: 1-128 characters, each from `[A-Za-z0-9._:/-]`;
- encoded signature: 1-16,384 characters;
- hex: lowercase, even-length, prefix-free hexadecimal;
- base64: canonical whitespace-free RFC 4648 base64.

Detailed verification has two independent axes. The complete allowed matrix is:

| Signature status | Anchor status | Allowed reason codes |
| --- | --- | --- |
| `UNSIGNED` | `NOT_EVALUATED` | `UNSIGNED` |
| `VALID` | `NOT_EVALUATED` | `LEGACY_SIGNATURE_VALID` |
| `VALID` | `UNANCHORED` | `LEGACY_SIGNATURE_VALID`, `SIGNATURE_VALID_UNANCHORED` |
| `VALID` | `ANCHORED` | `SIGNATURE_VALID_ANCHORED` |
| `VALID` | `INVALID` | `ANCHOR_INVALID` |
| `INVALID` | `NOT_EVALUATED` | `LEGACY_SIGNATURE_INVALID`, `SIGNATURE_INVALID`, `ALGORITHM_NOT_ALLOWED` |
| `UNKNOWN_KEY` | `NOT_EVALUATED` | `KEY_UNKNOWN` |
| `REVOKED` | `NOT_EVALUATED` | `KEY_REVOKED` |
| `INDETERMINATE` | `NOT_EVALUATED` | `SIGNATURE_METADATA_MISSING`, `VERIFIER_UNAVAILABLE` |

No other combination is valid. A missing verifier returns
`INDETERMINATE / NOT_EVALUATED / VERIFIER_UNAVAILABLE` while preserving the
exact valid parsed metadata in `result.signature_metadata`; a verifier may
return the same result for declared unavailability. An unexpected verifier
exception or impossible response raises sanitized `VerificationContractError`.
Malformed metadata raises `SignatureMetadataError`. Extra field names are
attacker-controlled and are never copied into error details; only bounded
core-owned field identifiers and integer counts are reported. Signing failures
use `ArtifactSigningError` or `SigningContractError`.

| Exception | Stable code |
| --- | --- |
| `SignatureMetadataError` | `SIGNATURE_METADATA_INVALID` |
| `ArtifactSigningError` | `ARTIFACT_SIGNING_ERROR` |
| `SigningContractError` | `SIGNING_CONTRACT_ERROR` |
| `VerificationContractError` | `VERIFICATION_CONTRACT_ERROR` |

Core-generated result messages, exceptions, details, and logs omit canonical
payload bytes, raw signatures, credentials, tokens, secrets,
artifact-declared metadata values, unrestricted provider error text, and raw
provider responses.

`result.signature_metadata` deliberately preserves exact parsed metadata for
forensics and key resolution. That value is untrusted, artifact-declared data.
The contract requires it to be non-secret, but syntactically valid token-like
text is not omitted, hashed, or rewritten. Hosts must apply their own redaction
before logging returned artifact metadata. The host also owns key resolution,
algorithm policy, credentials, provider transport, retry and timeout behavior,
availability policy, and artifact storage.

A valid and anchored result describes this artifact under the configured
verifier. It does not provide trusted time, replay prevention,
sequence-completeness or whole-chain replacement detection, WORM storage,
certification, or a compliance determination. Signer and verifier availability
never weakens or changes the governance decision already recorded by the
artifact.

### 3.9 Typed tamper-evident audit-chain verification

Link enforcement artifacts into a cryptographic chain before they are signed:

```python
from aegis import AEGIS, AuditChain, verify_chain_detailed

chain = AuditChain(chain_id="session-001")
aegis = AEGIS(sink=sink, signer=signer, chain_linker=chain)
artifact_1 = aegis.enforce(invocation_1)
artifact_2 = aegis.enforce(invocation_2)

report = verify_chain_detailed([artifact_1, artifact_2])
```

Each artifact gains `chain_id`, `chain_index`, `previous_audit_checksum`, and
`reservation_id` before its checksum and signature are created. Verification establishes
content integrity and continuity within the sequence supplied by the caller. A reordered
or internally truncated supplied sequence is invalid, but a valid prefix remains internally
valid because the verifier cannot know that a later artifact exists. Hash chaining does not
make storage immutable and cannot detect replacement or tail truncation of an otherwise valid
chain without an external trusted checkpoint. Trusted-head binding to content checksums is
tracked separately in roadmap item #46.

The five result axes are independent: content integrity, chain continuity,
signature status, anchor status, and completeness. A supplied valid prefix is
`unproven`, not complete. V2 verification never selects a legacy profile from
artifact content.

Trusted hosts can create an exact legacy capability with
`create_legacy_authorization(...)`. Checksum-free audit 1.x verification
requires both `LegacyFeature.CHECKSUM_FREE_CHAIN_VERIFICATION` and
`LegacyFeature.AUDIT_SCHEMA_1X_VERIFICATION`; workflow 1.x uses the separate
workflow-schema feature. Authorized results are explicitly `legacy` and
completeness remains `unproven`. Policies, guards, providers, invocation
context, and artifacts cannot construct or imply this capability.

### 3.10 Workflow claimed-set verification

**Current-source-only B4 API:** This section describes the current source tree,
not `aegis-ai-governance==0.9.0b1`. No later published version is assigned.

Every `GovernanceSession` attempt is assigned a gapless `step_index` before
authorization gates run. Finalization requires exactly one terminal invocation
artifact for every allocated attempt, including denied, canceled, and
execution-failure attempts. The v2 workflow artifact carries stable #46 inputs:

- `checksum` — the workflow's final v2 content checksum;
- `step_count` — the signed count of allocated terminal attempts when a signer
  is configured; and
- `invocations` — the ordered pairs of `step_index` and invocation content
  checksum.

The workflow content checksum covers those claim fields. A configured workflow
signature covers them as well; unsigned workflows explicitly report
`signature_status: "unsigned"`.

`steps` and `invocation_audit_checksums` remain timeline conveniences. They are
not the claimed set and a workflow artifact cannot stand in for an invocation
artifact. Workflow artifacts also never join invocation audit chains.

Use `verify_workflow_claim` to compare a workflow claim with an ordered iterable
of candidate invocation artifacts:

```python
from aegis import verify_workflow_claim

report = verify_workflow_claim(workflow_artifact, invocation_artifacts)
print(report.claim_status.value)      # valid | invalid | legacy | not_evaluated
print(report.signature_status.value)  # evaluated independently
print(report.completeness.value)      # unproven
```

Only artifacts whose `context.session_id` matches the workflow are selected.
The verifier requires the exact count, gapless ordered indices, valid v2
invocation profiles and content checksums, and matching claimed checksums. It
does not sort the input; provide the artifacts in workflow index order. Extra
artifacts from another session are ignored, while extra, missing, duplicate, or
reordered artifacts for the workflow invalidate `claim_status`.

`claim_status` validates the workflow's claimed supplied set. It does not
promote `signature_status`, and signature verification has no trusted verifier
argument in this API: a signed workflow is `INDETERMINATE` without one.
`completeness` is always `UNPROVEN` in this release. Passing any non-`None`
`expected_checkpoint` fails closed with `WORKFLOW_CHECKPOINT_UNSUPPORTED` and
returns a `NOT_EVALUATED` claim; #46 owns the future trusted checkpoint contract.

Workflow-signed proves integrity and order of the claimed supplied set. It does
not prove the host disclosed every invocation. Completeness remains unproven
until a trusted checkpoint binds the expected head/count.

The verifier bounds claims and supplied artifacts to 10,000 entries each,
measured input to 4 MiB, nesting to 32 levels, and reports to 100 errors.
Exceeding an input budget fails closed with
`WORKFLOW_VERIFICATION_LIMIT_EXCEEDED`.

### 3.11 Policy date validation

Policies can declare temporal validity:

```yaml
effective_date: "2025-01-01"
expiration_date: "2027-12-31"
```

`load_policy()` validates dates automatically. Loading an expired or not-yet-active policy
raises `PolicyValidationError`. To validate dates independently:

```python
from aegis import validate_policy_dates

evidence = validate_policy_dates(policy_dict)
print(evidence["active"])  # True or raises
```

The `clock` parameter enables deterministic testing:

```python
from datetime import date
evidence = validate_policy_dates(policy, clock=lambda: date(2025, 6, 15))
```

### 3.12 Pluggable policy loaders

Load policies from sources other than the filesystem:

```python
import yaml

from aegis import AEGIS, JsonFileAuditSink, PolicyLoaderBase, PolicyLoadError


class DatabasePolicyLoader(PolicyLoaderBase):
    def __init__(self, db):
        self._db = db

    def load(self, policy_ref: str) -> dict:
        row = self._db.query("SELECT yaml FROM policies WHERE id = ?", [policy_ref])
        if not row:
            raise PolicyLoadError(f"Policy {policy_ref} not found")
        return yaml.safe_load(row["yaml"])


aegis = AEGIS(
    sink=JsonFileAuditSink("audit.jsonl"),
    policy_loader=DatabasePolicyLoader(db),
)
artifact = aegis.enforce(invocation)
```

All loaded policies pass through the same schema validation, date validation, and composition
resolution regardless of source. The `AEGIS` instance caches loaded policies in a per-instance,
thread-safe LRU cache.

### 3.13 Policy testing framework

Test policies in isolation without a running LLM:

```python
from aegis import PolicyTestCase, PolicyTestSuite, expect_pass, expect_fail

expect_pass(PolicyTestCase(name="ok", policy_file="p.yaml", role="planner", ...))
expect_fail(PolicyTestCase(name="bad role", ...), gate="role_validation")

suite = PolicyTestSuite("regression")
suite.add(case_a, expected="pass")
suite.add(case_b, expected="fail")
results = suite.run_all()
assert suite.all_passed(results)
```

See Section 2.8 for a complete example.

### 3.14 OpenTelemetry integration

AEGIS emits OpenTelemetry spans and events when OTel is installed. The enforcement pipeline
instruments itself automatically — each gate execution and enforcement result is recorded as
a span event. Governance is never affected by telemetry; if OTel is absent, all instrumentation
is a no-op.

To activate, install the OTel packages alongside AEGIS:

```bash
pip install opentelemetry-api opentelemetry-sdk
```

No SDK configuration changes are needed. To check availability at runtime:

```python
from aegis.telemetry import is_otel_available

if is_otel_available():
    print("OTel spans will be emitted during enforcement")
```

### 3.15 AEGIS instance configuration

The `AEGIS` class bundles all configuration into an immutable, thread-safe instance:

```python
from aegis import AEGIS

aegis = AEGIS(
    sink=my_sink,                    # AuditSink instance
    on_sink_failure="raise",         # v2 fail-closed default
    strict_mode=True,                # Reject weak policies
    signer=my_signer,                # ArtifactSigner instance
    custom_gates=[gate_a, gate_b],   # EnforcementGate instances
    policy_loader=my_loader,         # PolicyLoaderBase instance
    risk_config=my_risk_config,      # Overrides policy risk field
    redaction_patterns=my_patterns,  # Custom PII redaction
)

artifact = aegis.enforce(invocation)
artifact = await aegis.enforce_async(invocation)
```

The instance owns its policy cache and never mutates global state. Multiple `AEGIS` instances
can coexist in the same process with different configurations.

### 3.16 Split enforcement (v0.3.2+)

Split enforcement divides the pipeline into two phases so that authorization
gates run before the model call and output-side gates run after it. This
avoids spending tokens on invocations that would fail authorization.

**Module-level functions (sync and async):**

```python
enforce_pre_call(invocation: dict) -> PreCallResult
enforce_post_call(pre_call_result: PreCallResult, output: dict) -> dict
enforce_pre_call_async(invocation: dict) -> PreCallResult
enforce_post_call_async(pre_call_result: PreCallResult, output: dict) -> dict
```

The `invocation` dict passed to `enforce_pre_call` uses the same shape as
`enforce_invocation` **except** that the `output` key is omitted — it is not
available until after the model call.

**`PreCallResult` contract:** `PreCallResult` is an immutable, opaque identity
handle produced by `enforce_pre_call`. Authorization state remains in the
issuing runtime's private operation registry. A handle is single-use,
process-affine, and issuer-instance-affine. Call `enforce_post_call` in the
same process and through the same module or `AEGIS` instance that issued it.
Every attempted Phase B consumption burns an authenticated handle, including
output-validation failures.

Copying, deep-copying, or pickling a handle copies the same operation identity;
it never duplicates or transfers authorization. A second use raises
`InvocationValidationError`. There is no renewal API: obtain a fresh handle by
running `enforce_pre_call` at the start of each operation.

**`AEGIS` instance methods:**

```python
aegis.enforce_pre_call(invocation)          # sync
aegis.enforce_post_call(pre_result, output) # sync
await aegis.enforce_pre_call_async(invocation)
await aegis.enforce_post_call_async(pre_result, output)
```

These have the same contract as the module-level functions and respect the
instance's sink, signer, gates, policy loader configuration, and private
operation registry. Handles cannot be exchanged between instances.

**Decorator default (v0.3.3+):**

```python
@governed(
    policy_file="policies/my_policy.yaml",
    role="assistant",
    model_provider="anthropic",
    model_identifier="claude-sonnet-4-6",
)
def run_model(input_data, context):
    return model.generate(input_data)
```

Phase A runs before the wrapped function and blocks execution on failure. Phase B
runs after the function returns.

**Migration from v0.3.2:** Call sites that omit `pre_call_enforcement` now run in
split mode. Call sites that pass `pre_call_enforcement=True` are unchanged. Call
sites that rely on unified mode must add `pre_call_enforcement=False` explicitly;
this emits `DeprecationWarning` and will be removed in a future release. The
direct split APIs (`enforce_pre_call`, `enforce_post_call`) and unified API
(`enforce_invocation`, `enforce_invocation_async`) are unchanged.

### 3.17 Provenance metadata (v0.3.3+)

`generate_audit_artifact()` accepts an optional `provenance` keyword argument.
When supplied, the artifact's top-level `provenance` field contains a sparse
dict with any subset of the following fields:

| Field | Type | Constraint |
|-------|------|-----------|
| `source_ids` | `string[]` | `minItems: 1`, `uniqueItems: true`, `maxItems: 1000` |
| `derived_from_audit_checksums` | `string[]` | SHA-256 hex pattern, `minItems: 1`, `uniqueItems: true`, `maxItems: 1000` |
| `compilation_source_hash` | `string` | SHA-256 hex pattern |

**Null/absent semantics:**

- `provenance: null`: emitted when no provenance was supplied (default); valid under the v1.4 schema
- `provenance: {}`: unreachable via `generate_audit_artifact()` — an empty dict is normalized to `null`; would fail `minProperties: 1` if submitted directly to schema validation
- v1.3 artifacts lacking the `provenance` key entirely: valid (key is not in `required`)

**Enforcement entrypoints (v0.3.3+):** `enforce_invocation()`, split-mode
methods, and `AEGIS` enforcement methods automatically forward
`invocation["context"]["provenance"]` into every emitted audit artifact (PASS
and FAIL). Scalar values are normalized to `null`. No separate `provenance`
argument is accepted at the entrypoint level — supply provenance in the
invocation context dict.

---

### 3.18 AuditLineage (v0.3.3+)

`AuditLineage` is available as `from aegis import AuditLineage`.

**Loading:**

| Method | Signature | Description |
|--------|-----------|-------------|
| `from_jsonl` | `(path: str \| Path) → AuditLineage` | Load JSONL trail |
| `add_artifact` | `(artifact: dict) → str` | Add one artifact; returns checksum |

**Traversal:**

| Method | Returns | Description |
|--------|---------|-------------|
| `get(checksum)` | `dict \| None` | Look up artifact by checksum |
| `checksum_of(artifact)` | `str` | Derive node key (same as add_artifact) |
| `roots()` | `list[dict]` | Artifacts with no declared parents |
| `leaves()` | `list[dict]` | Artifacts with no children |
| `ancestors(checksum)` | `list[dict]` | All upstream artifacts (BFS) |
| `descendants(checksum)` | `list[dict]` | All downstream artifacts (BFS) |

**Integrity:**

| Method | Returns | Description |
|--------|---------|-------------|
| `orphans()` | `list[dict]` | Artifacts with missing parents |
| `has_cycle()` | `bool` | True if graph contains a cycle |

**Node identity:** The node key is `sha256(canonical_json_bytes(artifact_without_chain_fields))`,
where chain fields (`chain_id`, `chain_index`, `previous_audit_checksum`, `reservation_id`,
`checksum`) are
excluded before hashing. This content-only key is stable regardless of whether
the artifact is chain-linked. **Do not use `artifact["checksum"]`** as a lineage
key — that is `AuditChain`'s chain-integrity hash and differs from the lineage node key.
Use `lineage.checksum_of(artifact)` or the return value of `add_artifact()` instead.

**No new dependencies** — standard library only.

---

### 3.19 RiskHistory (v0.3.3+)

`RiskHistory` tracks risk scores over time for a named entity and exposes a
`trajectory()` signal — advisory only, does not affect enforcement.

```python
from aegis import RiskHistory, compute_risk_score

history = RiskHistory("planner:summarize")

for invocation in batch:
    risk = compute_risk_score(invocation, policy, risk_config=risk_cfg)
    history.record(risk)          # accepts RiskScore or float

if len(history.scores) >= 2:
    print(history.trajectory())   # "improving" | "stable" | "degrading"
    print(history.latest)         # most recent score
    print(history.scores)         # (score0, score1, ...) oldest-first tuple
```

**Trajectory classification** is based on first-vs-last delta vs. a configurable
`stability_band` (default `0.05`):

| Return value | Condition |
| ------------ | --------- |
| `"improving"` | latest − first < −stability_band |
| `"stable"` | \|latest − first\| ≤ stability_band |
| `"degrading"` | latest − first > stability_band |

Custom band: `RiskHistory("my-agent", stability_band=0.10)`

---

### 3.20 Planned extension points (not yet available)

The following extension mechanisms appear in architecture documentation but are **not yet
implemented** in the current SDK. Do not attempt to import them:

- `register_validator` — custom postcondition validation functions
- `register_resolver` — dynamic per-invocation policy selection

These are planned for a future release. Use policy guards, custom gates, and composition for
dynamic behavior in the interim.

---

## 4. Troubleshooting / FAQ

### Q: `PolicyLoadError: Policy file not found`

**Cause**: The `policy_file` path in the invocation is incorrect or relative to the wrong
working directory.

**Fix**: Verify the path is correct relative to where you run the process, or use an
absolute path:

```python
from pathlib import Path
invocation["policy_file"] = str(Path(__file__).parent / "policies" / "my_policy.yaml")
```

---

### Q: `PolicyValidationError: Policy does not conform to schema`

**Cause**: The YAML policy file is missing a required field or has an invalid structure.

**Fix**: Validate the policy against the schema:

```python
import json, yaml
from jsonschema import validate
schema = json.load(open("schemas/policy_dsl.schema.json"))
policy = yaml.safe_load(open("policies/my_policy.yaml"))
validate(policy, schema)
```

The schema requires at minimum: `policy_version` and `roles`.

---

### Q: `PolicyValidationError: Policy not yet active` / `Policy has expired`

**Cause**: The policy declares `effective_date` or `expiration_date` and the current date
falls outside the valid range.

**Fix**: Check the policy's date fields:

```python
from aegis import validate_policy_dates
evidence = validate_policy_dates(yaml.safe_load(open("policies/my_policy.yaml")))
print(evidence)  # Shows effective_date, expiration_date, evaluation_date, active
```

Update the policy dates, or remove them to make the policy perpetually active.

---

### Q: `PreconditionError: Required context key missing`

**Cause**: The `context` dict passed to `enforce_invocation` is missing a key declared in
the policy's `pre_conditions.required` list.

**Fix**: Ensure all required context keys are present before calling enforcement:

```python
invocation["context"]["user_id"] = get_user_id()
```

---

### Q: `SchemaValidationError: Output does not match policy output_schema`

**Cause**: The model output (the `output` dict in the invocation) does not conform to the
JSON Schema defined in the policy's `output_schema` field.

**Fix**: Check that all `required` output fields are present and have the correct types.
Enable retry for transient failures via `retry_policy`.

---

### Q: `GovernanceViolationError: Role not in policy roles`

**Cause**: The `role` field in the invocation is not declared in `policy["roles"]`.

**Fix**: Either add the role to the policy's `roles` list, or correct the `role` value
in the invocation.

---

### Q: `ToolConstraintViolationError: Tool not in allowed_tools`

**Cause**: The invocation's `tool_calls` list contains a tool not allowed by the policy.

**Fix**: Either add the tool to `policy.tools.allowed_tools`, or remove the unauthorized
tool call from the invocation.

---

### Q: `RiskThresholdError: Risk score exceeds threshold`

**Cause**: The computed risk score reached the policy's `risk.threshold` in `strict` mode,
or reached the fixed `0.90` critical ceiling in any mode.

**Fix**: Lower the risk factors by strengthening the policy (add output_schema, reduce
roles, add guards). For a non-critical policy-threshold breach, you may raise the threshold
or switch to `risk_scored` or `warn_only` during development. Mode changes do not bypass
the `0.90` critical ceiling:

```yaml
risk:
  mode: warn_only  # Log warnings instead of failing
  threshold: 0.7
```

---

### Q: `CustomGateViolationError: Custom gate failed`

**Cause**: A custom `EnforcementGate` returned `GateResult(passed=False, ...)`.

**Fix**: Check the exception's `details` for the gate name and failure reason. Fix the
condition that caused the gate to fail (e.g., missing tenant_id for a tenant isolation gate).

---

### Q: The `@governed` decorator raises `TypeError` about my function signature

**Cause**: The decorator binds arguments using `inspect.signature()`. It looks
for `input_data` or `input` by name first, then falls back to the first
positional parameter. Similarly, `context` is resolved by name or as the
second positional parameter. Named arguments may appear in any order.

**Fix**: Use named parameters that match the convention. The recommended
signature is:

```python
@governed(policy_file="...", role="...", model_provider="...", model_identifier="...")
def my_function(input_data: dict, context: dict) -> dict:
    ...
```

Reordered named arguments (e.g., `context` before `input_data`) are supported.

---

### Q: Audit artifacts are not appearing in my `JsonFileAuditSink` file

**Cause**: The instance has no acknowledged sink, or the module runtime was not
configured before its first enforcement attempt.

**Fix**: Register the sink once at application startup, before any governed calls:

```python
from aegis import configure_module_enforcement, JsonFileAuditSink
configure_module_enforcement(sink=JsonFileAuditSink("audit.jsonl"))
```

---

### Q: Async enforcement is blocking my event loop

**Cause**: Policy file I/O is dispatched to a thread pool via `asyncio.to_thread`. If
you are using `enforce_invocation` (sync) inside an async context, it will block.

**Fix**: Use `enforce_invocation_async` or `aegis.enforce_async` in async contexts:

```python
from aegis import enforce_invocation_async
artifact = await enforce_invocation_async(invocation)

# Or with AEGIS instance
artifact = await aegis.enforce_async(invocation)
```

---

## 5. Audit Artifact Reference

Every `enforce_invocation` call returns an audit artifact. Stable fields (safe to assert
in tests):

| Field | Description |
| ----- | ----------- |
| `audit_schema_version` | Schema version (e.g., `"1.4"`) |
| `policy_file` | Path to the policy file used |
| `policy_version` | Value of `policy_version` from the policy YAML |
| `policy_schema_version` | JSON Schema draft used to validate the policy |
| `model_provider` | From invocation |
| `model_identifier` | From invocation |
| `role` | From invocation |
| `enforcement_result` | `"PASS"` or `"FAIL"` |
| `metadata` | Dict with `preconditions_satisfied`, `postconditions_satisfied`, `guards_evaluated`, `conditions_resolved`, `schema_validation`, `tool_constraints` |

Fields added by v0.3.0 extension points (present when the feature is active):

| Field | Source | Description |
| ----- | ------ | ----------- |
| `metadata.risk_scoring` | Risk scoring | Dict with `score`, `threshold`, `mode`, `basis`, `exceeded` |
| `signature` | Artifact signing | HMAC-SHA256 hex string (or custom signer output) |
| `chain_id` | Audit chain | Chain identifier |
| `chain_index` | Audit chain | 0-based position in chain |
| `previous_audit_checksum` | Audit chain | Prior artifact's v2 content checksum (null for first); never a signature or storage-provider digest |
| `reservation_id` | Audit chain | Opaque host reservation identifier used for post-ack reconciliation |
| `metadata.custom_gate_metadata` | Custom gates | Dict of gate-specific metadata merged from `GateResult.metadata` |

Source-only field added after the `0.9.0b1` release:

| Field | Source | Description |
| ----- | ------ | ----------- |
| `signature_metadata` | Metadata-aware signing | Optional strict versioned metadata covered by the external signature; untrusted artifact-declared data that hosts must redact before logging; verification and anchor statuses are never persisted |

Fields added by v0.3.2 enforcement-mode metadata:

`metadata.enforcement_mode` is the only field guaranteed on every split
artifact. The remaining phase-specific fields are conditional and appear only
when the corresponding phase completed.

| Field | Description |
| ----- | ----------- |
| `metadata.enforcement_mode` | Present on newly emitted v0.3.2 artifacts; `"unified"`, `"split"`, or `"split_pre_call_only"` |
| `metadata.pre_call_gates_evaluated` | Present after successful Phase A, including wrapped-function-error artifacts |
| `metadata.post_call_gates_evaluated` | Present only when Phase B runs |
| `metadata.pre_call_timestamp` | Present only on artifacts emitted after Phase B runs |
| `metadata.post_call_timestamp` | Present only when Phase B runs |

Volatile fields (do not assert in tests without normalization):

| Field | Description |
| ----- | ----------- |
| `timestamp` | Unix epoch at enforcement time |
| `input_checksum` | SHA-256 of canonical input JSON |
| `output_checksum` | SHA-256 of canonical output JSON |
