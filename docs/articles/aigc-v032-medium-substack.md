# AIGC v0.3.2: Governance at the Invocation Boundary

*Release-accurate to AIGC v0.3.2, shipped 2026-04-05. All code and claims verified against the public repository at [github.com/nealsolves/aigc](https://github.com/nealsolves/aigc).*

---

Most enterprise AI governance does not execute. It advises.

It lives in policy documents, architecture review boards, and prompt instructions. These controls sit outside the runtime path of a model call. When an invocation runs, the governance layer is not present. It is consulted afterward, if at all.

AIGC closes that gap. The Auditable Intelligence Governance Contract is a Python SDK that enforces governance at the exact point where your system meets the model. Not before it. Not after it. At the boundary.

That positioning is deliberate. Everything in v0.3.2 flows from it.

---

## Part 1: Why Most AI Governance Fails at Runtime

Governance failures in AI systems are rarely philosophical. They are architectural.

Most teams already know they need AI governance. The problem is that governance often means one of four weak substitutes:

- A PDF that documents which models are permitted
- A prompt that instructs the model to behave responsibly
- A dashboard that surfaces anomalies after the fact
- A manual review process running parallel to, but not inside, the call path

These controls share one structural weakness. None of them enforce anything at runtime. A governance program that cannot execute is documentation.

Consider the gap concretely. A model call happens. The role is unauthorized. The output violates the declared schema. The tool was not on the allowlist. In a system without runtime enforcement, none of these violations are caught before the output reaches a downstream system that acts on it.

The failure is not that teams don't care about governance. The failure is that governance was never embedded in the execution path.

AIGC treats governance as infrastructure. Every invocation attempt is evaluated against a declared policy, checked through a fixed gate sequence, and produces a structured audit artifact. Pass or fail. Every time.

---

## Part 2: What AIGC Is

AIGC is a provider-agnostic Python SDK. It does not make model calls. It does not replace your orchestration framework. It does not store artifacts on your behalf.

It governs the invocation boundary. The host application retains ownership of orchestration, state management, model execution, and downstream action.

That scope is intentional. A narrower boundary is a more reliable boundary.

### Install

```bash
pip install aigc-sdk
```

The import name is `aigc`. The package name on PyPI is `aigc-sdk`. That distinction matters if you're pinning dependencies.

### Five Governance Invariants

The SDK is built around five properties that are never configurable:

1. Governance must be deterministic
2. Core enforcement must be fail-closed
3. Gate ordering must remain fixed
4. Audit evidence must be tamper-evident
5. Unified mode must remain backward-compatible

These are not guidelines. They are hard constraints enforced in every pipeline execution path.

---

## Part 3: The Architecture

### 3.1 Where AIGC Sits

```
┌────────────────────────────────────────────────┐
│               Host Application                 │
│  (orchestrator, agent, API service)            │
│                                                │
│    ┌──────────────────────────────────────┐    │
│    │         Application Logic            │    │
│    │   (tools, routing, state, UI)        │    │
│    └─────────────────┬────────────────────┘    │
│                      │                        │
│                      ▼                        │
│    ┌──────────────────────────────────────┐    │
│    │  ╔════════════════════════════════╗   │    │
│    │  ║      AIGC Governance SDK      ║   │    │
│    │  ║                               ║   │    │
│    │  ║   Policy ──▶ Enforce ──▶ Audit║   │    │
│    │  ╚════════════════════════════════╝   │    │
│    └─────────────────┬────────────────────┘    │
│                      │                        │
│                      ▼                        │
│    ┌──────────────────────────────────────┐    │
│    │         Model Provider               │    │
│    │  (Anthropic, OpenAI, Bedrock, local) │    │
│    └──────────────────────────────────────┘    │
└────────────────────────────────────────────────┘
```

AIGC operates between application logic and model provider. The host assembles an invocation. AIGC loads the policy, runs the governance pipeline, and emits an audit artifact. The host then decides what to do with the model call and the result.

### 3.2 The Four Core Abstractions

**Policy.** A declarative YAML contract defining governance rules for a class of invocations. Validated against JSON Schema Draft-07 at load time. Versioned and replayable.

**Invocation.** The structured input to the enforcement engine: policy file, model provider, model identifier, role, input, output, and runtime context.

**Enforcement.** The core pipeline that evaluates the invocation against its policy through a fixed gate sequence.

**Audit Artifact.** The tamper-evident record produced by every enforcement call, pass or fail.

### 3.3 The Enforcement Pipeline

This is the fixed gate sequence AIGC runs on every invocation. Gate ordering is a design invariant. It cannot be changed through configuration.

```
enforce_invocation(invocation)
│
├─ 1. LOAD POLICY
│     Parse YAML → validate against policy_dsl.schema.json
│     Fail: PolicyLoadError / PolicyValidationError
│
├─ 2. CUSTOM GATES (pre_authorization)
│     Host-registered gates run before any authorization check
│     Fail: CustomGateViolationError
│
├─ 3. RESOLVE GUARDS
│     Evaluate when/then guard expressions from context
│     Apply additive merge to produce effective_policy
│     Fail: GuardEvaluationError / ConditionResolutionError
│
├─ 4. VALIDATE ROLE
│     Check role ∈ effective_policy["roles"]
│     Fail: GovernanceViolationError
│
├─ 5. VALIDATE PRECONDITIONS
│     Each required key must exist and be truthy in context
│     Fail: PreconditionError
│
├─ 6. VALIDATE TOOL CONSTRAINTS
│     Enforce tool allowlist and per-tool max_calls caps
│     Fail: ToolConstraintViolationError
│
├─ 7. CUSTOM GATES (post_authorization)
│     Host gates after authorization, before output processing
│     Fail: CustomGateViolationError
│
├─ 8. CUSTOM GATES (pre_output)
│     Host gates before output schema validation
│     Fail: CustomGateViolationError
│
├─ 9. VALIDATE OUTPUT SCHEMA
│     Validate output against declared JSON Schema
│     Fail: SchemaValidationError
│
├─ 10. VALIDATE POSTCONDITIONS
│      output_schema_valid and host-declared postconditions
│      Fail: PostconditionError
│
├─ 11. CUSTOM GATES (post_output)
│      Host gates after full output validation
│      Fail: CustomGateViolationError
│
├─ 12. RISK SCORING (optional)
│      Compute factor-weighted risk score
│      strict mode: Fail if score > threshold → RiskThresholdError
│      risk_scored / warn_only: record score, do not block
│
└─ 13. EMIT AUDIT ARTIFACT
       SHA-256 checksums on input and output
       Optional HMAC-SHA256 signing
       Optional audit chain linkage
       Emit to configured sink
```

Every gate either passes or raises a typed exception. There is no partial enforcement. There is no silent mode.

---

## Part 4: Your First Governance Contract

### 4.1 A Minimal Policy

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

This policy declares three things:
- Only the `assistant` role may invoke this model
- `user_id` must be present in context before the call proceeds
- The output must contain a `reply` string

### 4.2 Calling the Enforcement Engine

```python
from aigc import enforce_invocation, GovernanceViolationError, PreconditionError

invocation = {
    "policy_file": "policies/hello_policy.yaml",
    "model_provider": "anthropic",
    "model_identifier": "claude-sonnet-4-6",
    "role": "assistant",
    "input": {"prompt": "Summarize this incident report."},
    "output": {"reply": "The incident was caused by a misconfigured firewall rule."},
    "context": {"user_id": "user-001"},
}

artifact = enforce_invocation(invocation)
print(artifact["enforcement_result"])  # PASS
```

The call returns an audit artifact on success. It raises a typed exception on any violation. No silent fallbacks. No best-effort checks.

### 4.3 What Happens on Failure

```python
# Missing user_id in context
bad_invocation = {**invocation, "context": {}}

try:
    enforce_invocation(bad_invocation)
except PreconditionError as e:
    print(e.audit_artifact["enforcement_result"])  # FAIL
    print(e.audit_artifact["failures"])
    # [{"gate": "precondition_validation", "field": "user_id", ...}]
```

Every typed exception carries a FAIL artifact at `exc.audit_artifact`. The artifact is emitted to the sink before the exception propagates. Evidence exists before the caller handles the error.

---

## Part 5: Production Integration

### 5.1 A Production Policy

Real enterprise policies need more than role allowlists. This policy governs an analytics assistant with tenant isolation, tool constraints, conditional guards, and risk scoring.

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

What this policy enforces at runtime:

- `tenant_id` and `session_id` must be present strings in context
- Output must contain an `analysis` string
- When `is_enterprise` is true, the `internal_search` tool is activated with a 10-call cap
- Composite risk score above 0.7 blocks the invocation in strict mode
- Policy expires 2027-12-31. Loading outside the window raises `PolicyValidationError`

### 5.2 Custom Enforcement Gates

Domain-specific controls belong to the host. AIGC supports custom gates at four fixed insertion points: `pre_authorization`, `post_authorization`, `pre_output`, `post_output`.

This gate enforces tenant isolation before any authorization check runs:

```python
from aigc import EnforcementGate, GateResult, INSERTION_PRE_AUTHORIZATION


class TenantIsolationGate(EnforcementGate):
    """Block invocations missing tenant_id before role validation."""

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
        return GateResult(
            passed=True,
            metadata={"verified_tenant": tenant_id}
        )
```

Key properties:
- The gate receives **read-only views** of policy and invocation data. Mutation attempts are caught and converted to `CUSTOM_GATE_MUTATION` governance failures
- Metadata from `GateResult` is merged into the audit artifact under `metadata.custom_gate_metadata`
- Custom gates appear as `"custom:tenant_isolation"` in `metadata.gates_evaluated`
- Unhandled exceptions inside a gate produce `CUSTOM_GATE_ERROR`. Governance never crashes

### 5.3 Instance-Scoped Runtime Configuration

The `AIGC` class is the production entry point. It owns sink, signer, gates, and policy cache with no global mutable state. Configuration is immutable after construction. `AIGC.enforce()` is thread-safe.

```python
from aigc import AIGC, HMACSigner, AuditChain, JsonFileAuditSink

signer = HMACSigner(key=b"your-256-bit-secret-key-here-!!!")
chain = AuditChain(chain_id="analytics-session-001")

aigc = AIGC(
    sink=JsonFileAuditSink("audit/governance.jsonl"),
    on_sink_failure="log",
    signer=signer,
    custom_gates=[TenantIsolationGate()],
)
```

### 5.4 Building Invocations

`InvocationBuilder` provides a fluent, validated construction API:

```python
from aigc import InvocationBuilder

invocation = (
    InvocationBuilder()
    .policy("policies/analyst_policy.yaml")
    .model("anthropic", "claude-sonnet-4-6")
    .role("analyst")
    .input({"question": "Summarize Q4 revenue performance."})
    .output({"analysis": "Revenue increased 12% QoQ driven by enterprise segment growth."})
    .context({
        "tenant_id": "acme-corp",
        "session_id": "sess-42",
        "is_enterprise": True,
    })
    .build()
)

artifact = aigc.enforce(invocation)
```

`build()` raises `InvocationValidationError` if required fields are missing. The returned dict is independent of the builder.

### 5.5 The Audit Artifact

Every enforcement call produces one artifact. Here is what a PASS artifact looks like:

```json
{
  "audit_schema_version": "1.3",
  "model_provider": "anthropic",
  "model_identifier": "claude-sonnet-4-6",
  "role": "analyst",
  "policy_version": "1.0",
  "policy_file": "policies/analyst_policy.yaml",
  "input_checksum": "a3f8c2d1...sha256",
  "output_checksum": "7b2e19f4...sha256",
  "enforcement_result": "PASS",
  "timestamp": 1744070400,
  "signature": "hmac-sha256:9f3c1a...",
  "metadata": {
    "enforcement_mode": "unified",
    "preconditions_satisfied": ["tenant_id", "session_id"],
    "postconditions_satisfied": ["output_schema_valid"],
    "guards_evaluated": [
      {"condition": "is_enterprise", "matched": true}
    ],
    "tool_constraints": {
      "internal_search": {"max_calls": 10, "calls_made": 2}
    },
    "risk_score": 0.3,
    "custom_gate_metadata": {
      "tenant_isolation": {"verified_tenant": "acme-corp"}
    }
  }
}
```

The artifact is more than a log line. It carries:
- Policy identity and model identity
- SHA-256 checksums of input and output
- Ordered gate metadata showing exactly what ran
- HMAC-SHA256 signature for tamper detection
- Failure details on FAIL (attached to the typed exception)

### 5.6 Audit Chain for Tamper-Evident Sequencing

```python
chain.append(artifact)

# Each artifact gains three fields:
# chain_id, chain_index, previous_audit_checksum

# Verify the full chain after a session
valid, errors = chain.verify()
assert valid, f"Chain integrity broken: {errors}"

# Or verify a chain loaded from the JSONL sink
import json
from aigc import verify_chain

with open("audit/governance.jsonl") as f:
    artifacts = [json.loads(line) for line in f]

valid, errors = verify_chain(artifacts)
```

### 5.7 The Decorator Pattern

For simpler call sites, `@governed` wraps a function and runs enforcement transparently:

```python
from aigc import governed

@governed(
    policy_file="policies/analyst_policy.yaml",
    role="analyst",
    model_provider="anthropic",
    model_identifier="claude-sonnet-4-6",
)
async def analyze(input_data: dict, context: dict) -> dict:
    result = await llm.generate(input_data)
    return {"analysis": result}

output = await analyze(
    input_data={"question": "Summarize Q4 results"},
    context={"tenant_id": "acme-corp", "session_id": "sess-42"},
)
```

The decorator runs the full governance pipeline before returning the function's output. The caller sees the governed result or a typed exception. The audit trail is automatic.

---

## Part 6: Split Enforcement — The v0.3.2 Headline Feature

Prior to v0.3.2, all enforcement happened in a single call. The model had to run before AIGC could evaluate outputs. That meant token spend occurred before authorization was confirmed.

v0.3.2 introduces split enforcement. The model-call boundary moves. The gate ordering does not.

### 6.1 Why This Matters

Split enforcement answers two operationally separate questions:

- "Was this invocation authorized to happen at all?" (Phase A, before the model runs)
- "Did the output satisfy the contract once the model responded?" (Phase B, after the model runs)

For high-volume production systems, this matters in concrete ways. Unauthorized invocations are blocked before token spend. The evidentiary position changes: the enterprise can prove it never authorized the call, not merely that it logged a failure after the model ran.

### 6.2 The Split Enforcement Architecture

```
Host Application
│
├─ Phase A: enforce_pre_call(invocation_without_output)
│   │
│   ├─ 1. Load Policy
│   ├─ 2. Custom Gates (pre_authorization)
│   ├─ 3. Resolve Guards
│   ├─ 4. Validate Role
│   ├─ 5. Validate Preconditions
│   ├─ 6. Validate Tool Constraints
│   └─ 7. Custom Gates (post_authorization)
│        │
│        └─ Returns: PreCallResult (signed handoff token)
│
│   [PHASE BOUNDARY — MODEL CALL HAPPENS HERE]
│   output = model.generate(...)
│
└─ Phase B: enforce_post_call(pre_result, output)
    │
    ├─ Validate PreCallResult token (HMAC + fingerprint)
    ├─ 8. Custom Gates (pre_output)
    ├─ 9. Validate Output Schema
    ├─ 10. Validate Postconditions
    ├─ 11. Custom Gates (post_output)
    ├─ 12. Risk Scoring
    └─ 13. Emit Final Audit Artifact
```

### 6.3 Split Enforcement in Code

```python
from aigc import enforce_pre_call, enforce_post_call

# Assemble the invocation without output (model hasn't run yet)
invocation = {
    "policy_file": "policies/analyst_policy.yaml",
    "model_provider": "anthropic",
    "model_identifier": "claude-sonnet-4-6",
    "role": "analyst",
    "input": {"question": "Summarize Q4 revenue performance."},
    "context": {
        "tenant_id": "acme-corp",
        "session_id": "sess-42",
        "is_enterprise": True,
    },
}

# Phase A: authorize before spending tokens
pre_result = enforce_pre_call(invocation)

# Phase A passed — now call the model
output = model.generate(invocation["input"])

# Phase B: validate output against the contract
artifact = enforce_post_call(pre_result, output)
```

Phase A failure raises a typed exception and emits a FAIL artifact. The model is never called.

### 6.4 PreCallResult: The Handoff Token

`PreCallResult` is the typed handoff token between Phase A and Phase B. It carries signed evidence of what Phase A verified.

It is one-time use. A second call to `enforce_post_call` with the same token raises `InvocationValidationError`. This prevents replay attacks where a valid Phase A result is reused across multiple model outputs.

The token integrity was hardened as part of the 2026-04-05 security audit (six findings, all addressed in v0.3.2):

- Phase B reads effective policy from HMAC-signed evidence. Replacing `_frozen_policy_bytes` after token creation has no effect
- Phase B verifies gate fingerprints against signed evidence. Replacement via `object.__setattr__` is detected and rejected
- A per-token nonce ensures unique HMAC per invocation. Process-local consumption registry blocks deepcopy and pickle clone replay
- FAIL artifact identity fields are sourced from verified evidence bytes, not from mutable runtime state

### 6.5 Split Mode with the Decorator

```python
from aigc import governed

@governed(
    policy_file="policies/analyst_policy.yaml",
    role="analyst",
    model_provider="anthropic",
    model_identifier="claude-sonnet-4-6",
    pre_call_enforcement=True,  # opt-in split mode
)
async def analyze(input_data: dict, context: dict) -> dict:
    result = await llm.generate(input_data)
    return {"analysis": result}
```

With `pre_call_enforcement=True`, Phase A runs before the wrapped function executes. Phase A failure blocks execution entirely. Phase B runs after the function returns. Unified mode remains the default. No migration required.

### 6.6 Audit Schema v1.3

Split enforcement introduced additive metadata fields in the audit artifact. Prior artifacts remain valid. Schema v1.3 is additive, not breaking.

New fields in `metadata`:
- `enforcement_mode`: `"unified"` or `"split"`
- `pre_call_gates_evaluated`: gates evaluated in Phase A
- `post_call_gates_evaluated`: gates evaluated in Phase B
- `pre_call_timestamp`: Phase A completion time
- `post_call_timestamp`: Phase B completion time

New telemetry spans: `aigc.enforce_pre_call` and `aigc.enforce_post_call` with `aigc.enforcement_mode` attribute.

---

## Part 7: The Governance Capability Stack

Below is the full capability surface of AIGC across its release history. Each layer was added without breaking the layer beneath it.

```
┌─────────────────────────────────────────────────────────────┐
│  v0.3.2 — Split Enforcement                                  │
│  enforce_pre_call / enforce_post_call / PreCallResult        │
│  @governed(pre_call_enforcement=True) / audit schema v1.3   │
├─────────────────────────────────────────────────────────────┤
│  v0.3.1 — Interactive Demo                                   │
│  React + FastAPI. 7 labs. No user API keys required         │
├─────────────────────────────────────────────────────────────┤
│  v0.3.0 — Governance Hardening                               │
│  Custom gate isolation / HMAC signing / Tamper-evident chain │
│  Pluggable PolicyLoader / Risk scoring / OTel integration   │
│  Policy testing framework / Compliance export CLI            │
├─────────────────────────────────────────────────────────────┤
│  v0.2.0 — Production Readiness                               │
│  AIGC class / Typed preconditions / Exception sanitization   │
│  Policy caching / AST guard expressions / Policy CLI        │
├─────────────────────────────────────────────────────────────┤
│  v0.1.x — Core Pipeline                                      │
│  enforce_invocation / Fail-closed semantics / Audit artifacts│
│  Role validation / Schema validation / @governed decorator   │
└─────────────────────────────────────────────────────────────┘
```

---

## Part 8: The Interactive Demo

The fastest way to understand AIGC governance in practice is the interactive demo, deployed at [nealsolves.github.io/aigc](https://nealsolves.github.io/aigc).

It is a React application backed by a FastAPI server on Render. No user API keys required. Seven labs, each exercising a specific governance capability against a live enforcement engine.

### Lab 1: Risk Scoring

Explore `strict`, `risk_scored`, and `warn_only` modes. Adjust risk factors and thresholds and watch how the composite score changes the enforcement result. The lab makes clear that risk scoring is not binary: you can block, record, or warn depending on the operational context.

### Lab 2: Signing and Verification

Generate HMAC-SHA256 signed artifacts. Tamper with a field. Watch verification fail. This lab demonstrates the difference between a log and a tamper-evident record. Both contain data. Only one proves integrity.

### Lab 3: Audit Chain

Build a chain of enforcement artifacts. Inspect `chain_index` and `previous_audit_checksum`. Break the chain by tampering with a mid-chain artifact. Verify that the break propagates. This is what forensic auditability looks like in practice.

### Lab 4: Policy Composition

Explore `intersect`, `union`, and `replace` composition strategies. Load a base policy and a child policy. Watch how the effective policy changes depending on the strategy. This lab is directly relevant to multi-tenant deployments where a base organizational policy must compose with tenant-level overrides.

### Lab 5: Loaders and Versioning

Exercise pluggable policy loaders. Test `effective_date` and `expiration_date` enforcement. Load a policy before its effective date and see the typed error. Load a policy after its expiration and see the same. Temporal governance is operational governance.

### Lab 6: Custom Gates

Register gates at `pre_authorization`, `post_authorization`, `pre_output`, and `post_output`. Observe how gate metadata flows into the audit artifact. Deliberately fail a gate and inspect the FAIL artifact structure. Custom gates are the mechanism through which domain-specific controls enter the governance pipeline without forking the SDK.

### Lab 7: Compliance Dashboard

Feed a JSONL audit trail into the compliance export engine. Generate a structured compliance report: pass rates, failure gate breakdown, per-policy summary, per-invocation records. This is what a regulatory submission looks like when governance is infrastructure rather than documentation.

---

## Part 9: What AIGC Does Not Do

Over-claiming governance tools is a real risk. These boundaries are explicit.

AIGC is not a model safety layer that guarantees factual correctness. It is not an autonomous compliance program. It is not a replacement for application-layer authorization. It is not a substitute for human review in high-stakes decisions. It is not a hosted control plane that manages all enterprise governance state.

It is a deterministic enforcement SDK at the AI invocation boundary.

That scope is narrower than some governance marketing. It is also why the project is credible. A tool that claims to solve all AI risk solves none of it. A tool with a defined, enforceable boundary can be integrated, tested, and audited.

---

## Part 10: Where This Fits in Your Stack

The governance pattern in AIGC is not domain-specific. The contracts change. The architecture does not.

**Financial services.** Govern analyst assistants that summarize filings, propose risk notes, or call approved internal search tools. Policy declares which roles may access which tools. Audit artifacts provide the chain of custody for each recommendation.

**Customer support.** Enforce structured response formats, role-specific permissions, and auditable handling of escalations. Results are validated against the output schema before they reach a CRM. Postconditions confirm the required fields are present.

**Clinical decision support.** The host owns the final action. AIGC governs what the model is permitted to propose and validates that the proposal matches the declared contract. A clinician sees a governed output, not a raw model response. The audit trail survives internal review and external investigation.

**Telco operations.** Confidence-based automation requires deterministic boundaries. A model suggesting a network configuration change must pass role validation, precondition checks, output schema validation, and risk scoring before that suggestion reaches an orchestration layer. Graceful degradation requires knowing that governance ran before the action was taken.

In all of these cases, the enterprise gains the same four things:

- Unauthorized invocations blocked deterministically before the model runs
- Output contracts enforced before downstream systems trust the result
- Evidence for both PASS and FAIL paths
- Provider-agnostic governance that survives model swaps and vendor changes

---

## Part 11: Closing

AIGC takes a hard line on where AI governance belongs.

Not in documents. Not in prompts. Not in post-hoc dashboards. In the runtime path of the invocation itself.

In v0.3.2, that principle has matured into a clear architecture: policy as code, deterministic enforcement, unified default mode with opt-in split enforcement, tamper-evident audit artifacts, and an audited, hardened handoff boundary between Phase A and Phase B.

The test suite documents 818 tests. Coverage clears the 90% CI gate. The 2026-04-05 security audit produced six findings, all addressed in this release.

For enterprises, the value is concrete. AIGC does not ask leaders to trust that governance happened. It gives them a way to enforce it, prove it, and inspect it as part of the system that actually made the AI call.

The interactive demo is at [nealsolves.github.io/aigc](https://nealsolves.github.io/aigc).

The SDK is at [github.com/nealsolves/aigc](https://github.com/nealsolves/aigc).

```bash
pip install aigc-sdk
```

---

*All feature references in this article are verified against AIGC v0.3.2 CHANGELOG and architecture documentation. No claims are aspirational.*

---

## Substack Close

If you are working through production AI governance architecture, the next article in this series covers evaluation gates and audit artifact pipelines in operational telco environments. The engineering challenge at that layer is specific: governance must execute at the same speed as the system it governs, across network change cycles measured in seconds, not minutes.

Subscribe to follow the arc.
