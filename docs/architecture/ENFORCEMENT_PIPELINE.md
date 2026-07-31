# AEGIS Enforcement Pipeline

This document describes how governance enforcement occurs for every AI invocation.

The enforcement pipeline is deterministic and fail-closed.

Current public beta: `aegis-ai-governance==0.9.0b1`, released from `main`.
`GovernanceSession` wraps this unchanged invocation pipeline for each workflow
step. The shipped operator surface includes `aegis workflow trace` and
`aegis workflow export`.

Packaged beta public surface: `AEGIS.open_session(...)`, `GovernanceSession`,
`SessionPreCallResult`, workflow init/lint/doctor/trace/export, and optional
adapter submodules.

Internal, not public: `ValidatorHook`.

Not current public types: `AgentIdentity`, `AgentCapabilityManifest`.

---

## High Level Flow

Split enforcement is the default since `v0.3.3`: `@governed` runs Phase A
(authorization gates) before the model call and Phase B (output gates) after.
Unified mode (`enforce_invocation`) is retained as a direct API and as a
deprecated opt-out via `pre_call_enforcement=False` on `@governed`.

```
Application
│
├─ split mode (default for @governed)
│  ▼
│  Phase A / enforce_pre_call
│  ▼
│  Policy Load -> Strict Compile -> pre_authorization -> Guard Evaluation -> Role Validation
│  -> Precondition Validation -> Tool Constraint Validation -> post_authorization
│  ▼
│  Model Call Boundary
│  ▼
│  Phase B / enforce_post_call
│  ▼
│  pre_output -> Output Schema Validation -> Postcondition Validation
│  -> post_output -> Risk Scoring -> Audit Artifact Generation
│
└─ unified mode (direct API / deprecated opt-out)
│  ▼
│  AEGIS Enforcement Engine
│  ▼
│  Policy Load + Strict Compile
│  ▼
│  pre_authorization custom gates
│  ▼
│  Guard Evaluation
│  ▼
│  Role Validation
│  ▼
│  Precondition Validation
│  ▼
│  Tool Constraint Validation
│  ▼
│  post_authorization custom gates
│  ▼
│  pre_output custom gates
│  ▼
│  Output Schema Validation
│  ▼
│  Postcondition Validation
│  ▼
│  post_output custom gates
│  ▼
│  Risk Scoring (if configured)
│  ▼
│  Audit Artifact Generation
```

---

## Pipeline Stages

### 1. Policy Load

The enforcement engine loads the policy file and immediately calls the shared
policy compiler with legacy authority disabled. The resulting
`CompiledPolicy` is the only authorization representation passed into the
pipeline. Public `load_policy()` continues to return a dictionary for callers
that use the loader outside enforcement.

Policy validation includes:

* YAML parsing
* JSON Schema validation
* policy composition
* typed immutable guard-effect compilation and restriction validation
* precompiled typed preconditions and RE2 patterns
* precompiled output-schema validation
* explicit immutable per-field tool, risk, workflow, and authority limits

Invalid policies fail immediately.

The policy is compiled once at each load boundary. Unified, split, async,
instance, adapter, and session paths carry that compiled value forward; no
authorization stage reopens or reinterprets the loaded dictionary.

---

### 2. Guard Evaluation

Conditional guards select compiler-produced `CompiledPolicyOverlay` values.
Runtime evaluation resolves conditions and applies matching typed effects
cumulatively with immutable field operations. It never reconstructs a policy
dictionary or calls the policy compiler.

Example:

```yaml
guards:
  - when:
      condition: "is_enterprise"
    then:
      pre_conditions:
        required:
          - enterprise_flag
```

Guards only add constraints.

They never remove them.

---

### 3. Role Validation

Role authorization determines whether the invocation may proceed.

Example:

```yaml
roles:
  - planner
  - analyst
```

Unlisted roles are rejected.

---

### 4. Precondition Validation

Preconditions validate the invocation context.

Examples:

* session id format
* tenant id presence
* authorization tokens

Authorization requires typed preconditions. Legacy bare-string preconditions
remain available only to explicitly authorized compiler compatibility callers;
enforcement and lint reject them with
`LEGACY_PRECONDITION_FORBIDDEN` at `$.pre_conditions.required`.

Key existence alone is insufficient for typed preconditions.

---

### 5. Tool Constraint Validation

Tool constraints restrict external system access.

Example:

```yaml
tools:
  allowed_tools:
    - name: "web_search"
      max_calls: 2
```

Violations raise `ToolConstraintViolationError` with a FAIL audit artifact.

Tool validation occurs before schema validation.

---

### 6. Output Schema Validation

Model output must match the required structure.

Example:

```json
{
  "type": "object",
  "required": ["result"]
}
```

Invalid output fails governance.

---

### 7. Postcondition Validation

Postconditions verify the final output.

Examples:

* score thresholds
* data completeness
* workflow constraints

Postconditions execute after schema validation.

---

### 8. Audit Artifact Generation

Every enforcement emits a structured artifact.

Artifacts include:

* enforcement result
* failure gate
* metadata
* checksums

Both PASS and FAIL artifacts are emitted.

---

## Pre-Action Boundary Proof

Audit artifacts record the ordered gates that ran before the call boundary.

* Unified mode uses `metadata.gates_evaluated`.
* Split mode uses `metadata.pre_call_gates_evaluated` and, when Phase B runs,
  `metadata.post_call_gates_evaluated`.

Unified example:

Example:

```json
[
  "guard_evaluation",
  "role_validation",
  "precondition_validation",
  "tool_constraint_validation"
]
```

This proves enforcement occurred before action. In split mode, the Phase A list
is the explicit proof that the authorization-side gates completed before the
wrapped model call executed.

The split token carries the exact in-memory `CompiledPolicy`. Pickle/deepcopy
compatibility transfers a canonical typed compiled DTO, reconstructs compiled
value objects without calling `compile_policy()`, and binds Phase B to both the
source `policy_digest` and a domain-separated canonical compiled-DTO content
digest inside HMAC-authenticated Phase A evidence. The digest is verified
before DTO reconstruction and again before Phase B use. Tokens retain no
generic effective-policy map or serialized raw-policy copy.

A policy-backed workflow session pins the exact `CompiledPolicy` created when
the session opens. Step authorization and dynamic tool checks use that pinned
authority (or typed guard-derived restrictions from it), so policy-file changes
cannot mix open-time workflow limits with later authorization rules.

Policy lint uses the same compiler and reports its stable error code and
`details.path`, so diagnostics cannot drift from enforcement semantics.

---

## Custom Enforcement Gates

Custom enforcement gates allow plugins to inject additional governance checks
at defined points in the pipeline. Available since v0.3.0. In split enforcement
mode (v0.3.2+), custom gates are carried across the pre/post boundary and run
during Phase B (`pre_output`, `post_output`) as they do in unified mode.

Gates implement the `EnforcementGate` ABC and return `GateResult` objects.

### Insertion Points

* `pre_authorization` — runs before guard evaluation and role/precondition checks
* `post_authorization` — runs after precondition validation, before output-processing stages
* `pre_output` — runs before output schema validation and postcondition checks
* `post_output` — runs after postcondition validation, before audit artifact generation

### Gate Contract

Gates receive copy-then-freeze projections derived from an explicit allowlist
of compiled fields plus detached invocation and context projections. No gate
argument retains a live policy, invocation, registry, signer, sink, or
operation object. This is an argument-projection guarantee: it prevents a gate
from reaching AEGIS enforcement state through supplied arguments; it is not a
claim that arbitrary in-process Python code is sandboxed.

Every `GateResult` is converted to a closed terminal outcome before
authorization continues. `passed=False` always denies, even when `failures` is
empty. `passed=True` with any failure is an invalid result and denies. Unknown
returns and exceptions become stable fail-closed outcomes without exposing raw
exception text. Only `ALLOW` and `WARN` terminal classes continue.

Custom gates may:

* add failures
* add metadata

Custom gates may NOT:

* remove failures
* bypass enforcement stages

Internal `ValidatorHook` results use the same closed terminal model. Exhausted
execution failures, timeouts, malformed results, unknown decisions, denials,
and review-required results all block a workflow step; only normalized
`ALLOW` and `WARN` results continue.

Risk authorization is also centralized in its normalizer. Equality with the
policy threshold is a breach. Scores at or above the fixed `0.90` critical
ceiling deny in `strict`, `risk_scored`, and `warn_only` modes. Below that
ceiling, threshold breaches deny in `strict` and normalize to `WARN` in the two
non-blocking modes.

---

## Built-In Enforcement Gates

Built-in gates ship with the SDK and can be registered alongside custom gates.

### ProvenanceGate (v0.3.3+)

`ProvenanceGate` runs at the `pre_output` insertion point and blocks
invocations whose runtime context lacks provenance source identifiers.
Provenance from `invocation["context"]["provenance"]` is also forwarded
into every audit artifact (PASS and FAIL), enabling `AuditLineage` to
traverse cross-invocation lineage.

Registration:

```python
from aegis import AEGIS, ProvenanceGate
aegis = AEGIS(custom_gates=[ProvenanceGate()])
```

Failure codes:

* `PROVENANCE_MISSING` — no provenance in `invocation["context"]`, value
  is None/empty, or value is not a Mapping.
* `SOURCE_IDS_MISSING` — provenance exists but `source_ids` is absent,
  empty, or not a list.

---

## Workflow Governance (`0.9.0b1` Public Beta)

The public beta includes the initial `GovernanceSession` primitive.
A session manages:

* step sequencing
* cross-invocation policy enforcement
* tool budgets
* workflow audit artifacts

Invocation artifacts remain one-per-attempt. The separate workflow artifact
correlates step checksums, lifecycle, approvals, and workflow evidence.
