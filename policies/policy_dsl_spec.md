# AEGIS Extended Policy DSL Specification

**Version:** `1.0.0`
**Status:** Authoritative

This document defines the extended policy DSL used by the AEGIS Governance SDK.
It is written for humans, language models, and enforcement agents.

## Scope

This DSL governs:

- role authorization
- precondition and postcondition checks
- conditional guard logic
- tool usage constraints
- retry behavior
- workflow participants, sequencing, transitions, handoffs, budgets,
  escalation, and protocol evidence constraints

The DSL is data, not executable policy code.

The authoritative schema is implemented in both
`schemas/policy_dsl.schema.json` and the packaged
`aegis/schemas/policy_dsl.schema.json`. The
`aegis-ai-governance==0.9.0b1` supports the invocation fields and the
`workflow` section documented below.

## Design Intent

The format is intentionally:

- machine-parseable
- human-readable
- deterministic at enforcement time
- schema-validatable

## Top-Level Structure

```yaml
policy_version: "1.0"
description: "Optional human-readable policy intent"

roles:
  - planner
  - verifier
  - synthesizer

conditions:
  is_enterprise:
    type: boolean
    required: false
    default: false

tools:
  allowed_tools:
    - name: "vector_search"
      max_calls: 2

retry_policy:
  max_retries: 2
  backoff_ms: 500

pre_conditions:
  required:
    - role_declared
    - schema_exists
  optional:
    - is_enterprise

post_conditions:
  required:
    - output_schema_valid

guards:
  - when:
      condition: "is_enterprise"
    then:
      pre_conditions:
        required:
          - enterprise_flag
      post_conditions:
        required:
          - audit_level_high
```

## Field Semantics and Intent

### `policy_version`

Intent: Provide explicit version control for policy evolution.

- Required
- Should follow semantic versioning for compatibility tracking

### `description`

Intent: Record policy purpose for maintainers and auditors.

- Optional
- Recommended for policy governance clarity

### `roles`

Intent: Declare the full role allowlist for the policy boundary.

- Required
- Invocations with undeclared roles must fail enforcement

### `conditions`

Intent: Define named context-driven booleans used by guards.

- Optional
- Values are resolved from invocation context at runtime

Example:

```yaml
conditions:
  premium_enabled:
    type: boolean
    default: false
```

### `tools`

Intent: Constrain tool proposals in model output.

- Optional
- Each tool may define per-invocation call caps

Example:

```yaml
tools:
  allowed_tools:
    - name: "calculate_metrics"
      max_calls: 3
```

### `retry_policy`

Intent: Bound retries to deterministic and auditable behavior.

- Optional
- Retries must be explicit and finite
- Silent retry loops are not allowed

### `pre_conditions` and `post_conditions`

Intent: Define baseline validation gates before and after invocation.

- `required`: must be satisfied
- `optional`: may be used by downstream logic or guards

Preconditions support two formats:

**Typed preconditions** (recommended):

```yaml
pre_conditions:
  required:
    tenant_id:
      type: string
      pattern: "^[A-Z0-9]{8}$"
    score:
      type: number
      minimum: 0
      maximum: 1
```

**Legacy bare-string preconditions** (deprecated):

```yaml
pre_conditions:
  required:
    - role_declared
    - schema_exists
```

Bare-string preconditions emit a `DeprecationWarning` at runtime. Typed
preconditions enforce value constraints (type, pattern, enum, min/max) beyond
key existence.

### `guards`

Intent: Apply conditional policy expansions based on runtime context.

- Evaluated in listed order
- Guard effects should be additive and explicit

Example:

```yaml
guards:
  - when:
      condition: "role == verifier"
    then:
      post_conditions:
        required:
          - verified_signature
```

### `workflow`

Intent: constrain a stateful `GovernanceSession` without making AEGIS the
application's orchestrator.

Implemented workflow fields:

- `max_steps` and `max_total_tool_calls` — session budgets
- `participants` — stable participant IDs with optional roles, protocols, and
  host-owned `manifest_ref` metadata
- `required_sequence` — the required ordered step sequence
- `allowed_transitions` — allowed next-step graph
- `allowed_agent_roles` — workflow-wide role restriction
- `handoffs` — allowed `from`/`to` participant pairs
- `escalation.require_approval_after_steps` and
  `escalation.require_approval_for_roles` — approval policy; resulting
  `approval_checkpoints` are recorded in workflow evidence
- `protocol_constraints` — named constraints for `local`, `bedrock`, `a2a`,
  and `openai_agents` evidence

Example:

```yaml
policy_version: "1.0"
roles:
  - planner
  - reviewer
pre_conditions:
  required:
    source_present:
      type: boolean
workflow:
  max_steps: 3
  max_total_tool_calls: 4
  participants:
    - id: planner-agent
      roles: [planner]
      protocols: [local]
    - id: reviewer-agent
      roles: [reviewer]
      protocols: [local]
  required_sequence:
    - draft
    - review
    - publish
  allowed_transitions:
    draft: [review]
    review: [publish]
    publish: []
  allowed_agent_roles:
    - planner
    - reviewer
  handoffs:
    - from: planner-agent
      to: reviewer-agent
  escalation:
    require_approval_after_steps: 2
    require_approval_for_roles:
      - reviewer
  protocol_constraints:
    local:
      source_ids_required: true
```

Source requirements are expressed through ordinary invocation preconditions or
gates, as shown by `source_present`; `source_constraints` is not a separate DSL
key. The regulated starter combines this pattern with provenance enforcement.

The accepted scaffold profiles are `minimal`, `standard`, and
`regulated-high-assurance`. They are CLI inputs, not policy fields:

```bash
aegis policy init --profile minimal
aegis workflow init --profile standard
aegis workflow lint governance/
aegis workflow doctor governance/
aegis workflow trace --input audit.jsonl
aegis workflow export --input audit.jsonl --mode audit
```

`ValidatorHook` is an internal implementation mechanism in this beta and is not
part of the public policy DSL or public SDK contract.

## Common Use Patterns

### Role-Specific Hardening

```yaml
guards:
  - when:
      condition: "role == verifier"
    then:
      post_conditions:
        required:
          - verified_signature
```

Intent: Add stricter output guarantees for verification workflows.

### Tool-Cap Governance

```yaml
tools:
  allowed_tools:
    - name: "fetch_data"
      max_calls: 1
```

Intent: Prevent excessive tool usage and enforce bounded cost/risk.

### Feature Gating

```yaml
guards:
  - when:
      condition: "premium_enabled"
    then:
      post_conditions:
        required:
          - advanced_proof
```

Intent: Activate stricter checks only when feature flags are enabled.

## Validation and Provenance Requirements

Every policy change should be:

- versioned
- linked to a decision record
- regression-tested with golden replays

The DSL should be validated against:
`schemas/policy_dsl.schema.json`

## JSON Schema Reference

The canonical schema is `schemas/policy_dsl.schema.json`. Always validate
policies against that file. Do not rely on inline copies, which may lag
behind the canonical schema.

Top-level properties defined in the canonical schema:

- `extends` — path to base policy for composition
- `composition_strategy` — merge strategy: `intersect`, `union`, `replace`
- `policy_version` — version string (required)
- `description` — human-readable description
- `effective_date` — activation date (`YYYY-MM-DD`)
- `expiration_date` — expiration date (`YYYY-MM-DD`)
- `roles` — allowed roles (required, non-empty array)
- `conditions` — typed boolean conditions for guards
- `tools` — tool constraints (`allowed_tools` with `name`/`max_calls`)
- `retry_policy` — retry configuration (`max_retries`, `backoff_ms`)
- `risk` — risk scoring configuration (`mode`, `threshold`, `factors`)
- `pre_conditions` — preconditions (typed dict or legacy bare-string list)
- `post_conditions` — postconditions
- `output_schema` — JSON Schema for output validation
- `guards` — conditional policy activation rules
- `workflow` — participants, sequence/transitions, budgets, handoffs,
  escalation approvals, and protocol constraints
- `stateful` — versioned, fail-closed cross-session tool-call constraints

## Stateful policy constraints (current source)

The optional `stateful` section has `contract_version: 1`, one stable
`policy_state_id`, and at most 64 constraints. Version 1 supports only
`kind: sliding_window_tool_calls`, `scope: tenant`, and
`on_provider_failure: deny`. Every constraint names a tool already present in
`tools.allowed_tools` and declares positive bounded `limit`, `window_ms`,
`provider_timeout_ms`, and `retry_horizon_ms`; the retry horizon must cover at
least one dispatch.

Stateful declarations are not permitted inside guard effects. Composition may
lower a limit or shorten a timeout/horizon, but cannot remove a constraint,
raise a limit, lengthen a timeout, or change state IDs, constraint IDs, tool,
scope, kind, window, or failure behavior. See ADR-0016 and
`docs/reference/STATEFUL_POLICY_PROVIDERS.md`.

## Policy inheritance root

`extends` must be a non-empty string. For file-backed policies, the entry and
every transitive parent share one canonical root. Plain
`load_policy("policies/entry.yaml")` selects the entry's lexical parent. An
explicit `FilePolicyLoader("policies")` makes relative entries root-relative
and permits a multi-directory graph only within that root. Canonical symlink
targets must also remain contained; violations use
`POLICY_PATH_OUTSIDE_ROOT` without path-bearing details. Custom loaders cannot
use `extends`.

The diagnostic CLI accepts `--policy-root ROOT`. Descriptor-relative
resistance to a concurrent filesystem writer is a non-goal.
