# AEGIS Workflow CLI Guide (`v0.9.0` Beta)

These commands ship in the `aegis-ai-governance==0.9.0b1` public beta. They
remain under the `aegis` console command.

The beta CLI covers six workflow-adoption commands:

- `aegis policy init`
- `aegis workflow init`
- `aegis workflow lint`
- `aegis workflow doctor`
- `aegis workflow trace`
- `aegis workflow export`

For `workflow lint`, exit code `0` means no findings and exit code `1` means at
least one static finding. For `workflow doctor`, exit code `0` means no
error-severity findings and exit code `1` means at least one `ERROR`.

For `workflow trace` and `workflow export`, exit code `0` means success even
when checksums are unresolved (unresolved checksums are advisory, not errors);
exit code `1` means the input file was not found, was unreadable, or contained
no workflow artifacts.

The B4 workflow claimed-set material below is current-source-only. It is not in
the published `aegis-ai-governance==0.9.0b1` wheel or tag, and no later
published version is assigned.

Workflow artifacts include the final workflow content checksum, `step_count`,
and ordered `invocations` index/checksum pairs. A configured workflow signature
covers those claim fields. The CLI does not verify a workflow claimed set or
accept a trusted checkpoint. Trace and export correlation is advisory and cannot establish that the supplied evidence
is complete. Workflow-signed proves integrity and order of the claimed supplied
set. It does not prove the host disclosed every invocation. Completeness remains
unproven until a trusted checkpoint binds the expected head/count.
Only valid, anchored, authoritative evidence can then detect divergence;
latest retrieval and checkpoint omission/rollback remain host responsibilities.

The verifier bounds claims and supplied artifacts to 1,024 entries each,
measured input to 4 MiB, nesting to 32 levels, and reports to 100 errors.
Exceeding an input budget fails closed with
`WORKFLOW_VERIFICATION_LIMIT_EXCEEDED`. Trusted checkpoints (issue #46) are
implemented in the current-source Python API — `verify_chain_detailed(...,
expected_chain_id=...)` and `verify_workflow_claim(..., expected_checkpoint=...)`
— but the CLI does not create or verify checkpoints; that binding stays a
programmatic upgrade point. See ADR-0015 and `docs/USAGE.md` Recipe 13.

A session admits at most 1,024 workflow attempts. A later request fails before
attempt-envelope or step-index allocation with
`SESSION_ATTEMPT_LIMIT_EXCEEDED`.

Exception-path workflow summaries contain only a bounded `exception_type` and
stable `SESSION_BODY_EXCEPTION` reason code; raw exception messages are not
signed.

---

## `aegis policy init`

```text
aegis policy init --profile {minimal,standard,regulated-high-assurance} [--output OUTPUT] [--role ROLE]
```

Use this to generate a standalone `policy.yaml` from one of the shipped starter
profiles.

Examples:

```bash
aegis policy init --profile minimal
aegis policy init --profile regulated-high-assurance --output policies/regulated.yaml
aegis policy init --profile standard --role reviewer
```

---

## `aegis workflow init`

```text
aegis workflow init --profile {minimal,standard,regulated-high-assurance} [--output-dir OUTPUT_DIR] [--role ROLE]
```

Generates a starter directory containing `policy.yaml`, `workflow_example.py`,
and `README.md`.

Examples:

```bash
aegis workflow init --profile minimal
aegis workflow init --profile standard --output-dir governance-standard
aegis workflow init --profile regulated-high-assurance --role analyst
```

---

## `aegis workflow lint`

```text
aegis workflow lint [--kind {auto,policy,starter_dir,workflow_artifact}] [--json] targets [targets ...]
```

Static lint for governance targets. In the beta it covers:

- policy schema and YAML validity
- starter integrity
- public-import safety
- impossible workflow budgets
- invalid transition references
- graph/topology conflicts:
  `WORKFLOW_UNREACHABLE_STEP`, `WORKFLOW_DEAD_END_STEP`,
  `WORKFLOW_REQUIRED_SEQUENCE_IMPOSSIBLE`, and
  `WORKFLOW_UNBOUNDED_HANDOFF_LOOP`
- unsupported protocol/binding references

`--json` includes the stable finding keys `code`, `message`, `target_kind`, and
`path`. PR-10d may add bounded `details` and `witness_trace` evidence. Lint does
not emit `severity` or `next_action`; doctor owns remediation.

Examples:

```bash
aegis workflow lint policy.yaml
aegis workflow lint governance/
aegis workflow lint --kind workflow_artifact workflow_artifact.json
aegis workflow lint --json governance/
```

---

## `aegis workflow doctor`

```text
aegis workflow doctor [--kind {auto,policy,starter_dir,workflow_artifact,audit_artifact}] [--json] target
```

Runtime and evidence diagnosis for policy files, starter directories, workflow
artifacts, and invocation audit artifacts.

Doctor maps all lint findings to `ERROR`, attaches `next_action`, and adds
evidence-aware warnings such as `WORKFLOW_SOURCE_PROVENANCE_WARNING`. That
provenance warning is non-blocking by default and does not change doctor exit
behavior unless another finding is `ERROR`.

Examples:

```bash
aegis workflow doctor governance/
aegis workflow doctor workflow_artifact.json
aegis workflow doctor audit.json --kind audit_artifact --json
```

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for reason-code guidance and the
regulated failure-and-fix walkthrough.

---

## `aegis workflow trace`

```text
aegis workflow trace --input FILE [--output FILE]
```

Reconstruct workflow timelines from a JSONL artifact file containing workflow
and invocation artifacts. Outputs a JSON array — one trace object per workflow
session found in the input.

Arguments:

- `--input` — JSONL file containing workflow and invocation artifacts (required)
- `--output` — Write JSON output to this file instead of stdout (optional)

Exit codes:

- `0` — Success (unresolved checksums are advisory — exit 0 even when gaps exist)
- `1` — File not found, unreadable, or contains no workflow artifacts

Output fields per trace object:

| Field | Description |
|-------|-------------|
| `trace_schema_version` | `"0.9.0"` |
| `session_id` | Session identifier from the workflow artifact |
| `status` | `COMPLETED`, `FAILED`, `CANCELED`, or `INCOMPLETE` |
| `step_count` | Number of steps in the workflow |
| `steps[]` | Per-step timeline with resolved/unresolved status |
| `unresolved_checksums` | Checksums that could not be matched to invocation artifacts |
| `failure_summary` | Failure context recorded at session finalization, or `null` |

Each step in `steps[]` includes:

| Field | Description |
|-------|-------------|
| `sequence` | 1-based step position |
| `step_id` | Step identifier |
| `participant_id` | Agent or participant identifier, or `null` |
| `invocation_artifact_checksum` | SHA-256 checksum of the correlated invocation artifact |
| `resolved` | `true` if the invocation artifact was found in the input |
| `invocation_summary` | Key fields from the invocation artifact, or `null` if unresolved |

`unresolved_checksums` indicates sink failures or an incomplete export — the
invocation artifacts referenced by those steps were not present in the JSONL
file. Investigate with `aegis workflow doctor`. A resolved trace is not a
claimed-set verification or checkpoint-backed completeness proof.

Examples:

```bash
aegis workflow trace --input audit.jsonl
aegis workflow trace --input audit.jsonl --output timeline.json
```

---

## `aegis workflow export`

```text
aegis workflow export --input FILE --mode {operator|audit} [--output FILE]
```

Export governed workflow evidence in operator or audit mode.

Arguments:

- `--input` — JSONL file containing workflow and invocation artifacts (required)
- `--mode` — `operator` for a full technical dump; `audit` for compliance-focused step summaries (required)
- `--output` — Write JSON output to this file instead of stdout (optional)

Exit codes:

- `0` — Success (unresolved checksums are advisory — exit 0 even when gaps exist)
- `1` — File not found, unreadable, or contains no workflow artifacts

Modes:

**`operator`** — Embeds the full invocation artifact dict in each step under
`invocation_artifact`. Use for debugging, audit trail reconstruction, or
operator inspection. Output shape:

```json
{
  "export_schema_version": "0.9.0",
  "export_mode": "operator",
  "generated_at": 1700000000,
  "sessions": [{ "steps": [{ "invocation_artifact": { ... } }] }],
  "integrity": {
    "total_workflow_artifacts": 1,
    "total_invocation_artifacts": 1,
    "governance_rationale_count": 0,
    "unresolved_invocation_checksums": [],
    "unresolved_count": 0,
    "verification_guidance": "..."
  }
}
```

**`audit`** — Includes `step_id`, `participant_id`,
`invocation_artifact_checksum`, `enforcement_result`, and step `metadata` when
present. If `steps[i].metadata.governance` contains valid PR-10d rationale
metadata, audit mode also adds a redacted `governance` convenience projection.
Use for compliance reporting and external audit handoff. Output shape:

```json
{
  "export_schema_version": "0.9.0",
  "export_mode": "audit",
  "generated_at": 1700000000,
  "sessions": [{
    "steps": [{
      "enforcement_result": "PASS",
      "governance": {
        "rationale": "approval_required_before_external_handoff",
        "decision_basis": ["allowed_transitions", "approval_checkpoint"],
        "operator_action": "approval_granted",
        "approval_checkpoint_id": "checkpoint-123",
        "source_ids": ["doc-001"],
        "waiver_id": null
      }
    }]
  }],
  "compliance_summary": {
    "total_sessions": 1,
    "COMPLETED": 1, "FAILED": 0, "CANCELED": 0, "INCOMPLETE": 0
  },
  "integrity": {
    "unresolved_invocation_checksums": [],
    "unresolved_count": 0,
    "verification_guidance": "..."
  }
}
```

Governance projection is sourced only from `steps[i].metadata.governance`.
Projection keeps canonical scalar, null, and string-array values for
`rationale`, `decision_basis`, `operator_action`, `approval_checkpoint_id`,
`source_ids`, and `waiver_id`. Nested objects and unsupported payloads are
dropped from the projection. Audit mode does not embed full invocation
artifacts.

`integrity.unresolved_invocation_checksums` lists any invocation artifacts
referenced by workflow steps that were not found in the input JSONL. Investigate
missing evidence with `aegis workflow doctor`. This export does not verify the
signed workflow claim and does not establish completeness.

Examples:

```bash
aegis workflow export --input audit.jsonl --mode operator
aegis workflow export --input audit.jsonl --mode audit --output compliance.json
```
