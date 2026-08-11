export interface PublicDemoError {
  code: string
  message: string
  request_id: string
}

export const INVALID_PUBLIC_DEMO_ERROR_MESSAGE =
  'The demo service returned an invalid error response.'

const CODE_PATTERN = /^[A-Z0-9_]{1,64}$/
const REQUEST_ID_PATTERN = /^[0-9a-f]{32}$/
const CONTROL_PATTERN = /[\u0000-\u001f\u007f]/

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function isAbortError(error: unknown): boolean {
  return typeof error === 'object'
    && error !== null
    && 'name' in error
    && error.name === 'AbortError'
}

export function parsePublicDemoError(value: unknown): PublicDemoError | null {
  if (
    !isRecord(value)
    || typeof value.code !== 'string'
    || !CODE_PATTERN.test(value.code)
    || typeof value.message !== 'string'
    || value.message.length < 1
    || value.message.length > 512
    || CONTROL_PATTERN.test(value.message)
    || typeof value.request_id !== 'string'
    || !REQUEST_ID_PATTERN.test(value.request_id)
  ) {
    return null
  }

  return {
    code: value.code,
    message: value.message,
    request_id: value.request_id,
  }
}

export function formatPublicDemoError(value: unknown): string | null {
  const parsed = parsePublicDemoError(value)
  return parsed
    ? `${parsed.message} (request ${parsed.request_id})`
    : null
}

export async function parsePublicApiError(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json()
    const detail = isRecord(body) ? body.detail : null
    return formatPublicDemoError(detail) ?? `Request failed (${response.status}).`
  } catch (error) {
    if (isAbortError(error)) throw error
    return `Request failed (${response.status}).`
  }
}
