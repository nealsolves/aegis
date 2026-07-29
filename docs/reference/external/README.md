# External Adapter Reference

This directory contains advanced optional adapter docs:

- `BEDROCK_ADAPTER.md` — `BedrockTraceAdapter` usage, parsed trace evidence,
  alias-backed identity, and host/AEGIS ownership
- `OPENAI_AGENTS_ADAPTER.md` — `OpenAIAgentsAdapter` usage for host-owned `openai-agents` runs, wrapped-tool governance, and trace/approval binding
- `A2A_ADAPTER.md` — `A2AAdapter` usage for host-owned A2A interactions, `TASK_STATE_*` validation, and gRPC rejection
- `AWS_KMS_SIGNING.md` — AWS KMS external artifact signing and verification
- `GOOGLE_CLOUD_KMS_SIGNING.md` — exact-version Google Cloud KMS signing and retained-key verification

All three submodules are packaged in the public beta
`aegis-ai-governance==0.9.0b1` release and are not re-exported from top-level
`aegis`. Bedrock and A2A add no provider dependency; OpenAI Agents uses the
`openai-agents` extra.

The KMS adapters are source-only changes after `0.9.0b1`. They remain in the
same distribution and release path, are not top-level re-exports, and use the
`aws-kms` and `gcp-kms` extras. Artifact metadata does not select provider
resources; the host controls exact-pair trust resolution. Hosts own clients,
credentials, retry/timeout and endpoint configuration, regional/project
configuration, IAM, trust policy, retained evidence, and provider logging
controls.

These are advanced optional materials. Complete the local workflow quickstart
first.
