import {
  DEFAULT_DEMO_REQUEST_TIMEOUT_MS,
  demoRequest,
  DemoApiError,
  parseDemoHealth,
  parseDemoManifest,
} from '@/lib/demoApi'
import type { DemoManifest } from '@/types/demo'

const MANIFEST: DemoManifest = {
  api_contract_version: '1',
  sdk_version: '0.9.0b1',
  fixture_set_version: '2026-07-25',
  scenarios: ['atlas', 'meridian', 'northstar'],
  adapters: ['a2a', 'bedrock', 'openai_agents'],
  source: {
    branch: 'main',
    commit: 'backend-commit',
    sdk_version: '0.9.0b1',
  },
}

function jsonResponse(body: unknown, init?: ResponseInit) {
  return new Response(JSON.stringify(body), {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
}

describe('demoRequest', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('returns the parsed server response without adding demo data', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(MANIFEST)))

    await expect(
      demoRequest<DemoManifest>('/api', '/api/demo/manifest'),
    ).resolves.toEqual(MANIFEST)
  })

  it('preserves only validated structured FastAPI error details', async () => {
    const detail = {
      code: 'UNKNOWN_DEMO_ID',
      message: 'The requested demo identifier is not available.',
      request_id: 'a'.repeat(32),
      diagnostic: '/private/secret',
    }
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(jsonResponse({ detail }, { status: 422 })),
    )

    const request = demoRequest('/api', '/bad')

    await expect(request).rejects.toMatchObject({
      status: 422,
      code: 'UNKNOWN_DEMO_ID',
      message: `The requested demo identifier is not available. (request ${'a'.repeat(32)})`,
      detail: {
        code: 'UNKNOWN_DEMO_ID',
        message: 'The requested demo identifier is not available.',
        request_id: 'a'.repeat(32),
      },
    })
    await expect(request).rejects.toBeInstanceOf(DemoApiError)
  })

  it('does not expose malformed error bodies or status text', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(
        '{"detail":"/private/secret"}',
        { status: 500, statusText: '/private/secret' },
      )),
    )

    await expect(demoRequest('/api', '/bad')).rejects.toMatchObject({
      status: 500,
      code: 'HTTP_500',
      message: 'Request failed (500).',
      detail: null,
    })
  })

  it('propagates AbortError from fetch unchanged', async () => {
    const abortError = new DOMException('The operation was aborted.', 'AbortError')
    const controller = new AbortController()
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation((_input, options: RequestInit | undefined) => (
        new Promise<Response>((_resolve, reject) => {
          options?.signal?.addEventListener('abort', () => reject(abortError))
        })
      )),
    )

    const request = demoRequest('/api', '/health', {
      signal: controller.signal,
    })
    controller.abort()

    await expect(request).rejects.toBe(abortError)
  })

  it('propagates AbortError while parsing an error response body', async () => {
    const abortError = new DOMException('The operation was aborted.', 'AbortError')
    const response = {
      ok: false,
      status: 503,
      statusText: 'Service Unavailable',
      json: vi.fn().mockRejectedValue(abortError),
    } as unknown as Response
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response))

    await expect(demoRequest('/api', '/health')).rejects.toBe(abortError)
  })

  it('returns a mismatched contract value for the service layer to classify', async () => {
    const incompatibleManifest = {
      ...MANIFEST,
      api_contract_version: '2',
    }
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(jsonResponse(incompatibleManifest)),
    )

    await expect(
      demoRequest<{ api_contract_version: string }>('/api', '/api/demo/manifest'),
    ).resolves.toEqual(incompatibleManifest)
  })

  it('times out a fetch that never settles even when it ignores abort', async () => {
    vi.useFakeTimers()
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(() => undefined)))

    const request = demoRequest('/api', '/health')
    const rejection = expect(request).rejects.toMatchObject({
      name: 'TimeoutError',
    })
    await vi.advanceTimersByTimeAsync(DEFAULT_DEMO_REQUEST_TIMEOUT_MS)

    await rejection
    expect(vi.getTimerCount()).toBe(0)
    vi.useRealTimers()
  })

  it('clears timeout and abort-listener resources after a successful request', async () => {
    vi.useFakeTimers()
    const controller = new AbortController()
    const removeListener = vi.spyOn(controller.signal, 'removeEventListener')
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(MANIFEST)))

    await expect(demoRequest('/api', '/api/demo/manifest', {
      signal: controller.signal,
    })).resolves.toEqual(MANIFEST)

    expect(removeListener).toHaveBeenCalledWith('abort', expect.any(Function))
    expect(vi.getTimerCount()).toBe(0)
    vi.useRealTimers()
  })

  it('parses complete health and manifest responses', () => {
    expect(parseDemoHealth({
      status: 'ok',
      api_contract_version: '1',
      sdk_version: '0.9.0b1',
      source: { branch: 'main', commit: 'server-commit' },
    })).toEqual({
      status: 'ok',
      api_contract_version: '1',
      sdk_version: '0.9.0b1',
      source: { branch: 'main', commit: 'server-commit' },
    })
    expect(parseDemoManifest(MANIFEST)).toEqual(MANIFEST)
  })

  it.each([
    ['null health', null],
    ['unknown health status', {
      status: 'warm',
      api_contract_version: '1',
      sdk_version: '0.9.0b1',
      source: { branch: 'main', commit: 'server-commit' },
    }],
    ['health with missing source', {
      status: 'ok',
      api_contract_version: '1',
      sdk_version: '0.9.0b1',
    }],
    ['health with a numeric contract', {
      status: 'ok',
      api_contract_version: 1,
      sdk_version: '0.9.0b1',
      source: { branch: 'main', commit: 'server-commit' },
    }],
  ])('rejects malformed health: %s', (_name, body) => {
    expect(() => parseDemoHealth(body)).toThrow(
      'The demo service returned an invalid health response.',
    )
  })

  it.each([
    ['null manifest', null],
    ['unknown scenario', { ...MANIFEST, scenarios: ['atlas', 'unknown'] }],
    ['unknown adapter', { ...MANIFEST, adapters: ['bedrock', 'unknown'] }],
    ['non-array scenarios', { ...MANIFEST, scenarios: {} }],
    ['missing source', { ...MANIFEST, source: undefined }],
    ['source SDK mismatch', {
      ...MANIFEST,
      source: { ...MANIFEST.source, sdk_version: '0.8.0' },
    }],
  ])('rejects malformed manifest: %s', (_name, body) => {
    expect(() => parseDemoManifest(body)).toThrow(
      'The demo service returned an invalid manifest response.',
    )
  })
})
