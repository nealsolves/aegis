import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { DemoServiceNotice } from '@/components/service/DemoServiceNotice'
import ScenarioTimeline from '@/routes/scenarios/ScenarioTimeline'
import ScenarioPage from '@/routes/scenarios/ScenarioPage'
import type {
  DemoOutcome,
  ScenarioRunResponse,
} from '@/types/demo'

const serviceState = vi.hoisted(() => ({
  status: 'ready' as
    | 'checking'
    | 'starting'
    | 'ready'
    | 'unavailable'
    | 'mismatch',
  error: null as {
    operation: '/health' | '/api/demo/manifest'
    message: string
    status: number | null
    code: string | null
    frontendContractVersion?: '1'
    backendContractVersion?: string
  } | null,
  retry: vi.fn(),
}))

vi.mock('@/context/AigcContext', () => ({
  useAigc: () => ({
    apiUrl: 'http://demo.test',
    auditHistory: [],
    addAudit: vi.fn(),
    clearHistory: vi.fn(),
  }),
}))

vi.mock('@/context/DemoServiceContext', () => ({
  useDemoService: () => ({
    status: serviceState.status,
    manifest: null,
    error: serviceState.error,
    retry: serviceState.retry,
  }),
}))

const RENDER_WAKE_UP_SENTENCE = (
  'Starting the demo API. Render may need about a minute after a period of inactivity.'
)

const SOURCE = {
  branch: 'main',
  commit: 'server-commit',
  sdk_version: '0.9.0b1',
}

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify(body), {
    headers: { 'Content-Type': 'application/json' },
  })
}

function scenarioResponse(
  decision: DemoOutcome,
  variant: string,
): ScenarioRunResponse {
  const isPass = decision === 'PASS'
  return {
    scenario_id: 'atlas',
    variant,
    fixture_version: '2026-07-25.1',
    transcript: [
      {
        speaker: 'Atlas',
        text: isPass
          ? 'The corrected response cites the supplied policy.'
          : 'The first response omitted the required policy source.',
      },
    ],
    gates: [
      {
        name: 'provenance',
        phase: 'post_call',
        evaluated: true,
        outcome: decision,
        reason_code: isPass ? null : `${decision}_REASON`,
      },
    ],
    decision,
    artifact: {
      enforcement_result: isPass ? 'PASS' : 'FAIL',
      output_checksum: isPass ? 'b'.repeat(64) : 'a'.repeat(64),
      ...(isPass
        ? { provenance: { source_ids: ['atlas-policy-BRV-04'] } }
        : {}),
    },
    workflow_artifact: null,
    error: isPass
      ? null
      : {
          code: `${decision}_REASON`,
          message: `The returned run is ${decision.toLowerCase()}.`,
        },
    source: SOURCE,
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise
  })
  return { promise, resolve }
}

function expectNoCredentialInputs(container: HTMLElement) {
  expect(container.querySelectorAll([
    'input[type="password"]',
    'input[name*="credential" i]',
    'input[name*="secret" i]',
    'input[name*="api-key" i]',
    'input[name*="access-key" i]',
  ].join(','))).toHaveLength(0)
}

function expectWakeUpCopy(container: HTMLElement, present: boolean) {
  if (present) {
    expect(container).toHaveTextContent(RENDER_WAKE_UP_SENTENCE)
    return
  }
  expect(container).not.toHaveTextContent(RENDER_WAKE_UP_SENTENCE)
}

function renderScenarioPage() {
  return render(
    <MemoryRouter initialEntries={['/demo/scenarios/atlas']}>
      <Routes>
        <Route path="/demo/scenarios/:scenarioId" element={<ScenarioPage />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('public demo service states', () => {
  afterEach(() => {
    cleanup()
    serviceState.status = 'ready'
    serviceState.error = null
    serviceState.retry.mockReset()
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('shows the Render wake-up sentence only while the service is starting', () => {
    serviceState.status = 'starting'

    const view = render(<DemoServiceNotice />)

    expect(screen.getByRole('status')).toHaveTextContent(
      RENDER_WAKE_UP_SENTENCE,
    )
    expectWakeUpCopy(view.container, true)
    expectNoCredentialInputs(view.container)
  })

  it('renders a terminal unavailable state without credential entry or wake-up copy', () => {
    serviceState.status = 'unavailable'
    serviceState.error = {
      operation: '/health',
      message: 'Service unavailable',
      status: 503,
      code: 'HTTP_503',
    }

    const view = render(<DemoServiceNotice />)

    expect(screen.getByRole('status')).toHaveTextContent(
      'The governance run did not complete because the /health operation failed.',
    )
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
    expectWakeUpCopy(view.container, false)
    expectNoCredentialInputs(view.container)
  })

  it('renders a contract mismatch without credential entry or wake-up copy', () => {
    serviceState.status = 'mismatch'
    serviceState.error = {
      operation: '/api/demo/manifest',
      message: 'Contract mismatch',
      status: null,
      code: 'API_CONTRACT_MISMATCH',
      frontendContractVersion: '1',
      backendContractVersion: '2',
    }

    const view = render(<DemoServiceNotice />)

    expect(screen.getByRole('status')).toHaveTextContent(
      'Demo API contract mismatch. Frontend contract 1; backend contract 2.',
    )
    expectWakeUpCopy(view.container, false)
    expectNoCredentialInputs(view.container)
  })

  it.each([
    ['FAIL', 'Fail'],
    ['PAUSED', 'Paused'],
    ['PASS', 'Pass'],
  ] as const)(
    'renders the returned AEGIS %s decision without credential entry or wake-up copy',
    (decision, label) => {
      const response = scenarioResponse(decision, 'first_attempt')

      const view = render(
        <ScenarioTimeline response={response} scenarioId="atlas" />,
      )

      const evaluation = screen.getByRole('region', {
        name: 'AEGIS evaluation',
      })
      const overallDecision = within(evaluation)
        .getByText('Overall decision')
        .closest('.scenario-decision')
      expect(within(overallDecision as HTMLElement).getByText(label))
        .toBeInTheDocument()
      expectWakeUpCopy(view.container, false)
      expectNoCredentialInputs(view.container)
    },
  )

  it('keeps the newer PASS when an older FAIL request resolves last', async () => {
    const user = userEvent.setup()
    const older = deferred<Response>()
    const newer = deferred<Response>()
    const fetchMock = vi.fn()
      .mockReturnValueOnce(older.promise)
      .mockReturnValueOnce(newer.promise)
    vi.stubGlobal('fetch', fetchMock)

    const view = renderScenarioPage()
    await user.click(screen.getByRole('radio', {
      name: 'Send the prepared guidance without attaching a policy source',
    }))
    await user.click(screen.getByRole('button', { name: 'Run judgment' }))

    await user.click(screen.getByRole('radio', {
      name: 'Attach the supplied policy source and retry the review',
    }))
    await user.click(screen.getByRole('button', { name: 'Run judgment' }))

    newer.resolve(jsonResponse(scenarioResponse('PASS', 'corrected')))
    expect(await screen.findByText(
      'The corrected response cites the supplied policy.',
    )).toBeInTheDocument()

    older.resolve(jsonResponse(scenarioResponse('FAIL', 'first_attempt')))
    await waitFor(() => {
      expect(screen.queryByText('FAIL_REASON')).not.toBeInTheDocument()
    })
    expect(screen.getAllByText('Pass')).toHaveLength(2)
    expectWakeUpCopy(view.container, false)
    expectNoCredentialInputs(view.container)
  })
})
