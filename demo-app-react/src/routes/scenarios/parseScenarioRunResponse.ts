import type {
  DemoGateResult,
  DemoOutcome,
  DemoSource,
  ScenarioRunResponse,
} from '@/types/demo'
import type { ScenarioId } from './scenarioContent'
import { parsePublicDemoError } from '@/lib/publicError'

const OUTCOMES: readonly DemoOutcome[] = ['PASS', 'FAIL', 'PAUSED']
const GATE_PHASES: readonly DemoGateResult['phase'][] = [
  'pre_call',
  'post_call',
  'workflow',
]

export class InvalidScenarioRunResponseError extends Error {
  constructor() {
    super('The demo service returned an invalid scenario result.')
    this.name = 'InvalidScenarioRunResponseError'
  }
}

function invalidResponse(): never {
  throw new InvalidScenarioRunResponseError()
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isOutcome(value: unknown): value is DemoOutcome {
  return OUTCOMES.some((outcome) => outcome === value)
}

function isGatePhase(value: unknown): value is DemoGateResult['phase'] {
  return GATE_PHASES.some((phase) => phase === value)
}

function parseTranscript(value: unknown): ScenarioRunResponse['transcript'] {
  if (!Array.isArray(value)) invalidResponse()

  return value.map((entry) => {
    if (
      !isRecord(entry)
      || typeof entry.speaker !== 'string'
      || typeof entry.text !== 'string'
    ) {
      return invalidResponse()
    }

    return {
      speaker: entry.speaker,
      text: entry.text,
    }
  })
}

function parseGate(value: unknown): DemoGateResult {
  if (
    !isRecord(value)
    || typeof value.name !== 'string'
    || !isGatePhase(value.phase)
    || typeof value.evaluated !== 'boolean'
    || !(value.reason_code === null || typeof value.reason_code === 'string')
    || !(value.outcome === null || isOutcome(value.outcome))
    || value.evaluated !== (value.outcome !== null)
  ) {
    return invalidResponse()
  }

  return {
    name: value.name,
    phase: value.phase,
    evaluated: value.evaluated,
    outcome: value.outcome,
    reason_code: value.reason_code,
  }
}

function parseGates(value: unknown): DemoGateResult[] {
  if (!Array.isArray(value)) invalidResponse()
  return value.map(parseGate)
}

function parseNullableRecord(
  value: unknown,
): Record<string, unknown> | null {
  if (value === null) return null
  if (!isRecord(value)) invalidResponse()
  return value
}

function parseError(value: unknown): ScenarioRunResponse['error'] {
  if (value === null) return null
  return parsePublicDemoError(value) ?? invalidResponse()
}

function parseSource(value: unknown): DemoSource {
  if (
    !isRecord(value)
    || !(value.branch === null || typeof value.branch === 'string')
    || !(value.commit === null || typeof value.commit === 'string')
    || typeof value.sdk_version !== 'string'
  ) {
    return invalidResponse()
  }

  return {
    branch: value.branch,
    commit: value.commit,
    sdk_version: value.sdk_version,
  }
}

export function parseScenarioRunResponse(
  value: unknown,
  expected: {
    scenarioId: ScenarioId
    variant: string
  },
): ScenarioRunResponse {
  if (
    !isRecord(value)
    || value.scenario_id !== expected.scenarioId
    || value.variant !== expected.variant
    || typeof value.fixture_version !== 'string'
    || !isOutcome(value.decision)
  ) {
    return invalidResponse()
  }

  return {
    scenario_id: expected.scenarioId,
    variant: expected.variant,
    fixture_version: value.fixture_version,
    transcript: parseTranscript(value.transcript),
    gates: parseGates(value.gates),
    decision: value.decision,
    artifact: parseNullableRecord(value.artifact),
    workflow_artifact: parseNullableRecord(value.workflow_artifact),
    error: parseError(value.error),
    source: parseSource(value.source),
  }
}
