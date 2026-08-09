# AEGIS Workflow Governance — Quickstart (v0.9.0 Beta)

> This is packaged as the `aegis-ai-governance==0.9.0b1` public beta and
> released from `main`. Install with
> `pip install aegis-ai-governance==0.9.0b1`.

## Prerequisites

- Python 3.10 or later
- Access to PyPI or an internal package mirror:

```bash
pip install aegis-ai-governance==0.9.0b1
```

Source contributors may instead clone `main` and run
`pip install -e ".[dev]"`.

No external API keys, Bedrock credentials, or A2A setup are required. The
minimal starter runs entirely locally.

Restricted-network maintainer validation uses a different path: run
`python scripts/validate_v090_beta_proof.py`. That harness creates a fresh venv
with `system_site_packages=True` and installs this checkout with
`pip install --no-deps --no-build-isolation -e .`, so the proof run reuses the
current interpreter's installed Python packages instead of contacting an index.

## Step 1 — Generate a minimal starter

```bash
aegis workflow init --profile minimal
```

This creates a `governance/` directory containing:

- `policy.yaml` — a governance policy with role, preconditions, and output schema
- `workflow_example.py` — a two-step governed workflow you can run immediately
- `README.md` — usage notes for the generated starter

## Step 2 — Run the starter

```bash
cd governance
python workflow_example.py
```

Expected output:

```
Status:  COMPLETED
Steps:   2
Session: <uuid>
```

> **Current-source-only B4 API:** The workflow claimed-set material below is in
> the current source tree, not `aegis-ai-governance==0.9.0b1`. No later
> published version is assigned.

## What just happened

The starter script exercised the full workflow governance lifecycle in six actions:

1. **`AEGIS.open_session`** — Creates a `GovernanceSession` instance bound to the
   policy file. All subsequent invocations in the workflow run through this
   session. There is no module-level `open_session()`; this is always called on
   an `AEGIS` instance.

2. **`enforce_step_pre_call`** (Step 1) — Runs the pre-call side of governance for
   the first step: loads the policy, evaluates guards, validates role and
   preconditions, and checks tool constraints. Returns a `SessionPreCallResult`
   token that is single-use and must be completed through the owning session.

3. **`enforce_step_post_call`** (Step 1) — Runs the post-call side of governance:
   validates the output schema, evaluates postconditions, scores risk, and
   emits a signed invocation audit artifact correlated to this session.

4. **`enforce_step_pre_call`** (Step 2) — Same pre-call flow for the second step,
   with replay protection. Each step gets its own `SessionPreCallResult`.

5. **`enforce_step_post_call`** (Step 2) — Post-call governance for the second step.

6. **`session.complete()`** — Marks the workflow as successfully finished and
   transitions the session to `COMPLETED`. `session.complete()` only transitions;
   the workflow artifact is emitted by `session.finalize()` or context-manager
   exit.

After the `with` block exits, `session.workflow_artifact` holds the completed
workflow record with `status: COMPLETED`, a step checksum list, the session UUID
that correlates invocation artifacts, a final workflow content checksum, and a
claimed set: signed `step_count` plus ordered `invocations` index/checksum pairs
when a signer is configured. Every allocated attempt has exactly one terminal
invocation artifact; the `steps` list is a convenience summary rather than the
signed claimed set. Workflow artifacts are separate from invocation chains.

Workflow-signed proves integrity and order of the claimed supplied set. It does
not prove the host disclosed every invocation. Completeness remains unproven
until a trusted checkpoint binds the expected head/count. Only valid, anchored,
authoritative evidence can then detect divergence; latest retrieval and
checkpoint omission/rollback remain host responsibilities. The public
`verify_workflow_claim(workflow, invocations)` helper checks claim matching with
independent claim, signature, and completeness results. A signed workflow is
`INDETERMINATE` without a trusted verifier. Trusted checkpoints are implemented
in the current source (issue #46): pass a host-created checkpoint through
`verify_workflow_claim(..., expected_checkpoint=..., checkpoint_verifier=...)`
to promote completeness to `checkpoint_proven` for the expected scope. See
ADR-0015 and `docs/USAGE.md` Recipe 13. This checkpoint surface is
current-source-only and not in the published `0.9.0b1` wheel.

The verifier bounds claims and supplied artifacts to 1,024 entries each,
measured input to 4 MiB, nesting to 32 levels, and reports to 100 errors.
Exceeding an input budget fails closed with
`WORKFLOW_VERIFICATION_LIMIT_EXCEEDED`.

A session admits at most 1,024 workflow attempts. A later request fails before
attempt-envelope or step-index allocation with
`SESSION_ATTEMPT_LIMIT_EXCEEDED`.

Exception-path workflow summaries contain only a bounded `exception_type` and
stable `SESSION_BODY_EXCEPTION` reason code; raw exception messages are not
signed.

## Next steps

- **Run a different profile:** Try `aegis workflow init --profile standard` for a
  three-step workflow with an approval checkpoint (pause/resume). See
  [STARTER_INDEX.md](STARTER_INDEX.md) for all profiles.

- **Diagnose issues:** If your workflow raises an error, run
  `aegis workflow doctor <starter-dir>/` for structured advice. See
  [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for all reason codes.

- **CLI reference:** See [WORKFLOW_CLI.md](WORKFLOW_CLI.md) for full command
  documentation.

- **Migrating existing code:** See [../migration.md](../migration.md) for the
  minimal diff to add workflow governance to an invocation-only integration.
