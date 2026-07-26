import type {
  AdapterId,
  AdapterRunResponse,
  DemoOutcome,
  DemoSource,
} from '@/types/demo'

const OUTCOMES: readonly DemoOutcome[] = ['PASS', 'FAIL', 'PAUSED']

export class InvalidAdapterRunResponseError extends Error {
  constructor() {
    super('The demo service returned an invalid adapter result.')
    this.name = 'InvalidAdapterRunResponseError'
  }
}

function invalidResponse(): never {
  throw new InvalidAdapterRunResponseError()
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isOutcome(value: unknown): value is DemoOutcome {
  return OUTCOMES.some(outcome => outcome === value)
}

function parseRecord(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) invalidResponse()
  return value
}

function parseNullableRecord(
  value: unknown,
): Record<string, unknown> | null {
  if (value === null) return null
  return parseRecord(value)
}

function validateNullableReason(record: Record<string, unknown>) {
  if (
    'reason_code' in record
    && !(record.reason_code === null || typeof record.reason_code === 'string')
  ) {
    invalidResponse()
  }
}

function parseError(value: unknown): AdapterRunResponse['error'] {
  if (value === null) return null
  if (
    !isRecord(value)
    || typeof value.code !== 'string'
    || typeof value.message !== 'string'
  ) {
    return invalidResponse()
  }

  return {
    code: value.code,
    message: value.message,
  }
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

export function parseAdapterRunResponse(
  value: unknown,
  expected: {
    adapterId: AdapterId
    fixtureId: string
  },
): AdapterRunResponse {
  if (
    !isRecord(value)
    || value.adapter_id !== expected.adapterId
    || value.fixture_id !== expected.fixtureId
    || !isOutcome(value.decision)
  ) {
    return invalidResponse()
  }

  const providerInput = parseRecord(value.provider_input)
  const normalizedEvidence = parseRecord(value.normalized_evidence)
  const artifact = parseNullableRecord(value.artifact)
  const workflowArtifact = parseNullableRecord(value.workflow_artifact)

  validateNullableReason(normalizedEvidence)
  if (artifact) validateNullableReason(artifact)
  if (workflowArtifact) validateNullableReason(workflowArtifact)

  return {
    adapter_id: expected.adapterId,
    fixture_id: expected.fixtureId,
    provider_input: providerInput,
    normalized_evidence: normalizedEvidence,
    decision: value.decision,
    artifact,
    workflow_artifact: workflowArtifact,
    error: parseError(value.error),
    source: parseSource(value.source),
  }
}
