import { demoRequest, DemoApiError } from '@/lib/demoApi'
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

  it('preserves structured FastAPI error details', async () => {
    const detail = {
      code: 'UNKNOWN_DEMO_ID',
      message: "Unknown demo scenario_id: 'bad'",
      id_type: 'scenario_id',
      id: 'bad',
    }
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(jsonResponse({ detail }, { status: 422 })),
    )

    const request = demoRequest('/api', '/bad')

    await expect(request).rejects.toMatchObject({
      status: 422,
      code: 'UNKNOWN_DEMO_ID',
      message: "Unknown demo scenario_id: 'bad'",
      detail,
    })
    await expect(request).rejects.toBeInstanceOf(DemoApiError)
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
})
