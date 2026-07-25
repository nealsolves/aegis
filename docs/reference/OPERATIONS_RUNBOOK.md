# AEGIS Operations Runbook (`v0.9.0` Beta)

This runbook covers the `aegis-ai-governance==0.9.0b1` beta candidate. The
candidate is merged on `develop`, not on `main`, and is not yet published to
PyPI.

## Core Validation Commands

```bash
python -m pytest
flake8 aegis
python scripts/check_doc_parity.py
pytest demo-app-api/tests -q
npm --prefix demo-app-react test
npm --prefix demo-app-react run build
```

PR-10d focused local check:

```bash
python -m pytest tests/test_workflow_lint.py tests/test_workflow_doctor.py tests/test_workflow_export.py tests/test_pr10d_research_safety_addendum.py tests/test_validator_hook_internal_examples.py
python -m pytest tests/test_v090_contract_freeze.py tests/test_public_api.py
```

## Clean-Environment Beta Proof

Run the stop-ship harness:

```bash
python scripts/validate_v090_beta_proof.py
```

The harness proves:

1. fresh editable install in a new venv
2. minimal starter -> `COMPLETED`
3. standard starter -> `COMPLETED`
4. regulated starter broken in place -> failure
5. `aegis workflow doctor` on that same starter directory -> `WORKFLOW_SOURCE_REQUIRED`
6. same starter fixed in place -> rerun -> `COMPLETED`

The harness does not claim to run `workflow lint` or the entire golden-replay
suite. Those remain separate commands in the core validation set above.

## Demo Validation

The workflow beta lab is backed by:

- `demo-app-api/workflow_routes.py`
- `demo-app-react/src/labs/Lab11WorkflowLab.tsx`

The failure-and-fix tab should:

1. trigger a real broken regulated starter
2. diagnose that same starter directory
3. rerun the same starter after the fix is restored

## Operator Commands — Trace and Export

`aegis workflow trace` and `aegis workflow export` are the two operator inspection
tools for governed workflow evidence. Both consume a JSONL file produced by an
`AuditSink` and produce JSON output.

### When to use `aegis workflow trace`

Use `workflow trace` to reconstruct a session timeline and verify audit sink
completeness after a workflow run. It shows which steps were resolved (invocation
artifact found in the JSONL) and which were not (possible sink failure).

```bash
aegis workflow trace --input audit.jsonl
aegis workflow trace --input audit.jsonl --output timeline.json
```

### When to use `aegis workflow export --mode operator`

Use `operator` mode for a full technical evidence dump — each step embeds the
entire invocation artifact dict. Appropriate for incident reviews, debugging
governance decisions, or cross-referencing enforcement results with raw model
output.

```bash
aegis workflow export --input audit.jsonl --mode operator --output operator_export.json
```

PR-10d adds `integrity.governance_rationale_count`, the number of steps with a
valid `steps[i].metadata.governance` summary.

### When to use `aegis workflow export --mode audit`

Use `audit` mode for compliance handoff or external audit. Each step includes
`step_id`, `participant_id`, `invocation_artifact_checksum`,
`enforcement_result`, and step `metadata` when present. PR-10d also projects a
redacted `governance` summary from `steps[i].metadata.governance` when the
metadata uses canonical scalar, null, or string-array values. No full
invocation artifact is included.

```bash
aegis workflow export --input audit.jsonl --mode audit --output audit_export.json
```

### Interpreting `unresolved_invocation_checksums`

Both commands report `unresolved_invocation_checksums` in the integrity block.
A checksum appears here when a workflow step references an invocation artifact
by SHA-256 that is not present in the JSONL file. This typically indicates one of:

- an audit sink write failure during the session
- a truncated or partial JSONL export
- a JSONL file that covers only some sessions

Run `aegis workflow doctor` on the individual artifact file to diagnose further.
Both commands exit `0` even when checksums are unresolved — the gap is advisory
evidence, not an enforcement failure. The enforcement decision was already made
at the session layer.

## PR-10d Provenance And Adapter Gates

`workflow lint --json` may include bounded `details` and `witness_trace`
evidence for graph/topology failures. Lint does not emit `severity` or
`next_action`; doctor owns remediation and maps lint findings to `ERROR`.

`WORKFLOW_SOURCE_PROVENANCE_WARNING` is doctor-only and non-blocking by
default. It warns when exact source-bearing governance metadata or memory-like
context lacks `source_ids`.

The Bedrock alias-backed identity, A2A capability/protocol, and OpenAI Agents
capability/dynamic-tool gates are implemented with deterministic fixture tests.
No live provider credentials or calls are required for the adapter matrix.

## Beta Scope Boundaries

Not in the current beta surface:

- `AgentIdentity`
- `AgentCapabilityManifest`
- `ValidatorHook` as a public API
- gRPC workflow transport support

The PR-10d `ValidatorHook` examples are internal tests only and are not public
integration guidance.

Packaged optional submodules:

- `aegis.bedrock_adapter`, including `BedrockTraceAdapter`
- `aegis.a2a_adapter`, including `A2AAdapter`
- `aegis.openai_agents_adapter`, gated by the `openai-agents` extra

They are not top-level `aegis` re-exports. The host owns provider SDK clients,
credentials, transport, retries, orchestration, and model/tool execution.
