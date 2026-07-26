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

function requestUrl(apiUrl: string, path: string) {
  const base = apiUrl.endsWith('/') ? apiUrl.slice(0, -1) : apiUrl
  const suffix = path.startsWith('/') ? path : `/${path}`
  return `${base}${suffix}`
}

async function parseError(response: Response): Promise<DemoApiError> {
  let body: unknown

  try {
    body = await response.json()
  } catch {
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
): Promise<T> {
  const response = await fetch(requestUrl(apiUrl, path), options)

  if (!response.ok) {
    throw await parseError(response)
  }

  return response.json() as Promise<T>
}
