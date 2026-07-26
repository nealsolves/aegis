import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { AigcProvider } from '@/context/AigcContext'
import {
  DemoServiceProvider,
  useDemoService,
} from '@/context/DemoServiceContext'
import { DemoServiceNotice } from '@/components/service/DemoServiceNotice'
import { demoServiceNoticeCopy } from '@/content/demoCopy'
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

function healthResponse(apiContractVersion = '1') {
  return jsonResponse({
    status: 'ok',
    api_contract_version: apiContractVersion,
    sdk_version: '0.9.0b1',
    source: {
      branch: 'main',
      commit: 'backend-commit',
    },
  })
}

function Probe() {
  const service = useDemoService()

  return (
    <>
      <span data-testid="service-status">{service.status}</span>
      <button
        type="button"
        disabled={service.status !== 'ready'}
      >
        Run scenario
      </button>
      <button type="button" onClick={service.retry}>
        Retry from hook
      </button>
      <DemoServiceNotice />
    </>
  )
}

function renderService() {
  return render(
    <AigcProvider>
      <DemoServiceProvider>
        <Probe />
      </DemoServiceProvider>
    </AigcProvider>,
  )
}

async function advance(milliseconds: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(milliseconds)
  })
}

describe('DemoServiceProvider', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    cleanup()
    vi.clearAllTimers()
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('sources every public service notice string from shared demo copy', () => {
    expect(demoServiceNoticeCopy.starting).toBe(
      'Starting the demo API. Render may need about a minute after a period of inactivity.',
    )
    expect(demoServiceNoticeCopy.retry).toBe('Retry')
    expect(demoServiceNoticeCopy.unavailable('/health')).toBe(
      'The governance run did not complete because the /health operation failed.',
    )
    expect(demoServiceNoticeCopy.unavailable()).toBe(
      'The governance run did not complete because the readiness check operation failed.',
    )
    expect(demoServiceNoticeCopy.mismatch('1', '2')).toBe(
      'Demo API contract mismatch. Frontend contract 1; backend contract 2.',
    )
    expect(demoServiceNoticeCopy.mismatch()).toBe(
      'Demo API contract mismatch. Frontend contract 1; backend contract missing.',
    )
  })

  it('moves checking -> starting -> ready and enables run controls only when ready', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(
        { detail: 'Service Unavailable' },
        { status: 503 },
      ))
      .mockResolvedValueOnce(healthResponse())
      .mockResolvedValueOnce(jsonResponse(MANIFEST))
    vi.stubGlobal('fetch', fetchMock)

    renderService()

    expect(screen.getByTestId('service-status')).toHaveTextContent('checking')
    expect(screen.getByRole('button', { name: 'Run scenario' })).toBeDisabled()

    await advance(0)

    expect(screen.getByTestId('service-status')).toHaveTextContent('starting')
    expect(screen.getByRole('status')).toHaveTextContent(
      demoServiceNoticeCopy.starting,
    )
    expect(screen.getByRole('button', { name: 'Run scenario' })).toBeDisabled()

    await advance(1000)

    expect(screen.getByTestId('service-status')).toHaveTextContent('ready')
    expect(screen.getByRole('button', { name: 'Run scenario' })).toBeEnabled()
  })

  it('stops after the bounded retry schedule and lets the visitor retry', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(
      { detail: 'Service Unavailable' },
      { status: 503 },
    ))
    vi.stubGlobal('fetch', fetchMock)

    renderService()

    for (const delay of [0, 1000, 2000, 4000, 8000, 15000, 30000]) {
      await advance(delay)
    }

    expect(fetchMock).toHaveBeenCalledTimes(7)
    expect(screen.getByTestId('service-status')).toHaveTextContent('unavailable')
    expect(screen.getByRole('status')).toHaveTextContent(
      demoServiceNoticeCopy.unavailable('/health'),
    )

    fetchMock.mockReset()
      .mockResolvedValueOnce(healthResponse())
      .mockResolvedValueOnce(jsonResponse(MANIFEST))
    fireEvent.click(
      screen.getByRole('button', { name: demoServiceNoticeCopy.retry }),
    )

    expect(screen.getByTestId('service-status')).toHaveTextContent('checking')

    await advance(0)

    expect(screen.getByTestId('service-status')).toHaveTextContent('ready')
  })

  it('aborts the previous cycle on manual retry and ignores its stale response', async () => {
    let firstSignal: AbortSignal | null = null
    let resolveFirst: ((response: Response) => void) | null = null
    let requestNumber = 0
    const fetchMock = vi.fn().mockImplementation(
      (_input: RequestInfo | URL, options: RequestInit | undefined) => {
        requestNumber += 1
        if (requestNumber === 1) {
          firstSignal = options?.signal ?? null
          return new Promise<Response>((resolve) => {
            resolveFirst = resolve
          })
        }
        if (requestNumber === 2) return Promise.resolve(healthResponse())
        return Promise.resolve(jsonResponse(MANIFEST))
      },
    )
    vi.stubGlobal('fetch', fetchMock)

    renderService()
    await advance(0)
    fireEvent.click(screen.getByRole('button', { name: 'Retry from hook' }))

    expect((firstSignal as AbortSignal | null)?.aborted).toBe(true)

    await advance(0)
    expect(screen.getByTestId('service-status')).toHaveTextContent('ready')

    await act(async () => {
      resolveFirst?.(jsonResponse(
        { detail: 'Service Unavailable' },
        { status: 503 },
      ))
      await Promise.resolve()
    })

    expect(screen.getByTestId('service-status')).toHaveTextContent('ready')
  })

  it('aborts an in-flight readiness request when unmounted', async () => {
    let requestSignal: AbortSignal | null = null
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(
        (_input: RequestInfo | URL, options: RequestInit | undefined) => {
          requestSignal = options?.signal ?? null
          return new Promise<Response>(() => undefined)
        },
      ),
    )

    const view = renderService()
    await advance(0)
    view.unmount()

    expect((requestSignal as AbortSignal | null)?.aborted).toBe(true)
  })

  it('reports the frontend and backend versions when the manifest contract mismatches', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn()
        .mockResolvedValueOnce(healthResponse())
        .mockResolvedValueOnce(jsonResponse({
          ...MANIFEST,
          api_contract_version: '2',
        })),
    )

    renderService()
    await advance(0)

    expect(screen.getByTestId('service-status')).toHaveTextContent('mismatch')
    expect(screen.getByRole('status')).toHaveAttribute('aria-live', 'polite')
    expect(screen.getByRole('status')).toHaveTextContent(
      demoServiceNoticeCopy.mismatch('1', '2'),
    )
    expect(screen.getByRole('button', { name: 'Run scenario' })).toBeDisabled()
  })
})
