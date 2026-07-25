# External Adapter Reference

This directory contains advanced optional adapter docs:

- `BEDROCK_ADAPTER.md` — `BedrockTraceAdapter` usage, parsed trace evidence,
  alias-backed identity, and host/AEGIS ownership
- `OPENAI_AGENTS_ADAPTER.md` — `OpenAIAgentsAdapter` usage for host-owned `openai-agents` runs, wrapped-tool governance, and trace/approval binding
- `A2A_ADAPTER.md` — `A2AAdapter` usage for host-owned A2A interactions, `TASK_STATE_*` validation, and gRPC rejection

All three submodules are packaged in the unpublished
`aegis-ai-governance==0.9.0b1` candidate and are not re-exported from top-level
`aegis`. Bedrock and A2A add no provider dependency; OpenAI Agents uses the
`openai-agents` extra.

These are advanced optional materials. Complete the local workflow quickstart
first.
