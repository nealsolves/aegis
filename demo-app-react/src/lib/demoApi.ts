import type {
  AdapterId,
  DemoManifest,
  DemoSource,
  ScenarioId,
} from '@/types/demo'

export const DEFAULT_DEMO_REQUEST_TIMEOUT_MS = 5_000

export class DemoApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
    readonly detail: unknown,
  ) {
    super(message)
    this.name = 'DemoApiError'
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isAbortError(error: unknown) {
  return isRecord(error) && error.name === 'AbortError'
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === 'string'
}

function isNonemptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0
}

function parseSource(value: unknown): DemoSource {
  if (
    !isRecord(value)
    || !isNullableString(value.branch)
    || !isNullableString(value.commit)
    || !isNonemptyString(value.sdk_version)
  ) {
    throw new Error('invalid source')
  }
  return {
    branch: value.branch,
    commit: value.commit,
    sdk_version: value.sdk_version,
  }
}

const SCENARIO_IDS = new Set<ScenarioId>(['atlas', 'northstar', 'meridian'])
const ADAPTER_IDS = new Set<AdapterId>(['bedrock', 'openai_agents', 'a2a'])

function parseIdentifierArray<T extends string>(
  value: unknown,
  allowed: ReadonlySet<T>,
): T[] {
  if (!Array.isArray(value)) throw new Error('invalid identifier array')
  const parsed = value.filter(
    (item): item is T => typeof item === 'string' && allowed.has(item as T),
  )
  if (parsed.length !== value.length || new Set(parsed).size !== parsed.length) {
    throw new Error('invalid identifier')
  }
  return parsed
}

export interface DemoHealth {
  status: 'ok'
  api_contract_version: string
  sdk_version: string
  source: {
    branch: string | null
    commit: string | null
  }
}

export function parseDemoHealth(value: unknown): DemoHealth {
  try {
    if (
      !isRecord(value)
      || value.status !== 'ok'
      || !isNonemptyString(value.api_contract_version)
      || !isNonemptyString(value.sdk_version)
      || !isRecord(value.source)
      || !isNullableString(value.source.branch)
      || !isNullableString(value.source.commit)
    ) {
      throw new Error('invalid health')
    }
    return {
      status: 'ok',
      api_contract_version: value.api_contract_version,
      sdk_version: value.sdk_version,
      source: {
        branch: value.source.branch,
        commit: value.source.commit,
      },
    }
  } catch {
    throw new Error('The demo service returned an invalid health response.')
  }
}

export function parseDemoManifest(value: unknown): DemoManifest {
  try {
    if (
      !isRecord(value)
      || !isNonemptyString(value.api_contract_version)
      || !isNonemptyString(value.sdk_version)
      || !isNonemptyString(value.fixture_set_version)
    ) {
      throw new Error('invalid manifest')
    }
    const source = parseSource(value.source)
    if (source.sdk_version !== value.sdk_version) {
      throw new Error('SDK identity mismatch')
    }
    return {
      api_contract_version: value.api_contract_version as '1',
      sdk_version: value.sdk_version,
      fixture_set_version: value.fixture_set_version,
      scenarios: parseIdentifierArray(value.scenarios, SCENARIO_IDS),
      adapters: parseIdentifierArray(value.adapters, ADAPTER_IDS),
      source,
    }
  } catch {
    throw new Error('The demo service returned an invalid manifest response.')
  }
}

function requestUrl(apiUrl: string, path: string) {
  const base = apiUrl.endsWith('/') ? apiUrl.slice(0, -1) : apiUrl
  const suffix = path.startsWith('/') ? path : `/${path}`
  return `${base}${suffix}`
}

async function parseError(response: Response): Promise<DemoApiError> {
  let body: unknown

  try {
    body = await response.json()
  } catch (error) {
    if (isAbortError(error)) throw error
    body = null
  }

  const detail = isRecord(body) && 'detail' in body ? body.detail : body
  const code = isRecord(detail) && typeof detail.code === 'string'
    ? detail.code
    : `HTTP_${response.status}`
  const message = isRecord(detail) && typeof detail.message === 'string'
    ? detail.message
    : typeof detail === 'string'
      ? detail
      : response.statusText || `Request failed with status ${response.status}`

  return new DemoApiError(message, response.status, code, detail)
}

export async function demoRequest<T>(
  apiUrl: string,
  path: string,
  options?: RequestInit,
  timeoutMs = DEFAULT_DEMO_REQUEST_TIMEOUT_MS,
): Promise<T> {
  const controller = new AbortController()
  const callerSignal = options?.signal
  let callerAbortFallbackTimer: number | null = null
  let rejectCancellation: (reason: unknown) => void = () => undefined
  const cancellation = new Promise<never>((_resolve, reject) => {
    rejectCancellation = reject
  })
  const cancel = (reason: unknown) => {
    if (controller.signal.aborted) return
    controller.abort(reason)
    rejectCancellation(reason)
  }
  const handleCallerAbort = () => {
    const reason = callerSignal?.reason instanceof Error
      ? callerSignal.reason
      : new DOMException('The operation was aborted.', 'AbortError')
    if (!controller.signal.aborted) controller.abort(reason)
    // Native fetch (and adapters that honor AbortSignal) get the first chance
    // to surface their AbortError. The fallback also settles adapters that
    // ignore abort entirely.
    callerAbortFallbackTimer = window.setTimeout(() => {
      rejectCancellation(reason)
    }, 0)
  }
  if (callerSignal?.aborted) handleCallerAbort()
  else callerSignal?.addEventListener('abort', handleCallerAbort, { once: true })

  const timer = window.setTimeout(() => {
    cancel(new DOMException('The demo request timed out.', 'TimeoutError'))
  }, timeoutMs)

  const request = (async () => {
    const response = await fetch(requestUrl(apiUrl, path), {
      ...options,
      signal: controller.signal,
    })

    if (!response.ok) {
      throw await parseError(response)
    }

    return response.json() as Promise<T>
  })()

  try {
    return await Promise.race([request, cancellation])
  } finally {
    window.clearTimeout(timer)
    if (callerAbortFallbackTimer !== null) {
      window.clearTimeout(callerAbortFallbackTimer)
    }
    callerSignal?.removeEventListener('abort', handleCallerAbort)
  }
}
