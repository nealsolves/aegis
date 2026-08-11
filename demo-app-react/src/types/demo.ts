import type { PublicDemoError } from '@/lib/publicError'

export type DemoOutcome = 'PASS' | 'FAIL' | 'PAUSED'
export type ScenarioId = 'atlas' | 'northstar' | 'meridian'
export type AdapterId = 'bedrock' | 'openai_agents' | 'a2a'

export interface DemoSource {
  branch: string | null
  commit: string | null
  sdk_version: string
}

export interface DemoManifest {
  api_contract_version: '1'
  sdk_version: string
  fixture_set_version: string
  scenarios: ScenarioId[]
  adapters: AdapterId[]
  source: DemoSource
}

export interface DemoGateResult {
  name: string
  phase: 'pre_call' | 'post_call' | 'workflow'
  evaluated: boolean
  outcome: DemoOutcome | null
  reason_code: string | null
}

export interface ScenarioRunResponse {
  scenario_id: ScenarioId
  variant: string
  fixture_version: string
  transcript: { speaker: string; text: string }[]
  gates: DemoGateResult[]
  decision: DemoOutcome
  artifact: Record<string, unknown> | null
  workflow_artifact: Record<string, unknown> | null
  error: PublicDemoError | null
  source: DemoSource
}

export interface AdapterRunResponse {
  adapter_id: AdapterId
  fixture_id: string
  provider_input: Record<string, unknown>
  normalized_evidence: Record<string, unknown>
  decision: DemoOutcome
  artifact: Record<string, unknown> | null
  workflow_artifact: Record<string, unknown> | null
  error: PublicDemoError | null
  source: DemoSource
}
