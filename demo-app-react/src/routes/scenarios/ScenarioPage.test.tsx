import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Link, MemoryRouter, Route, Routes } from 'react-router-dom'
import type { ScenarioRunResponse } from '@/types/demo'
import ScenarioPage from './ScenarioPage'

const testState = vi.hoisted(() => ({
  serviceStatus: 'ready' as
    | 'checking'
    | 'starting'
    | 'ready'
    | 'unavailable'
    | 'mismatch',
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
    status: testState.serviceStatus,
    manifest: null,
    error: null,
    retry: vi.fn(),
  }),
}))

const SOURCE = {
  branch: 'main',
  commit: 'server-commit',
  sdk_version: '0.9.0b1',
}

const ATLAS_FIRST: ScenarioRunResponse = {
  scenario_id: 'atlas',
  variant: 'first_attempt',
  fixture_version: '2026-07-25.1',
  transcript: [
    { speaker: 'Support lead', text: 'Review fictional case AT-104.' },
    { speaker: 'Atlas', text: 'The answer conflicts with rule BRV-04.' },
  ],
  gates: [
    {
      name: 'approval_precondition',
      phase: 'pre_call',
      evaluated: true,
      outcome: 'PASS',
      reason_code: null,
    },
    {
      name: 'provenance',
      phase: 'post_call',
      evaluated: true,
      outcome: 'PASS',
      reason_code: null,
    },
    {
      name: 'output_schema',
      phase: 'post_call',
      evaluated: true,
      outcome: 'FAIL',
      reason_code: 'OUTPUT_SCHEMA_VALIDATION_ERROR',
    },
  ],
  decision: 'FAIL',
  artifact: {
    enforcement_result: 'FAIL',
    output_checksum: 'a'.repeat(64),
  },
  workflow_artifact: null,
  error: {
    code: 'OUTPUT_SCHEMA_VALIDATION_ERROR',
    message: 'The answer conflicts with rule BRV-04.',
    request_id: 'a'.repeat(32),
  },
  source: SOURCE,
}

const ATLAS_CORRECTED: ScenarioRunResponse = {
  scenario_id: 'atlas',
  variant: 'corrected',
  fixture_version: '2026-07-25.1',
  transcript: [
    {
      speaker: 'Support lead',
      text: 'Retry with the fictional policy source attached.',
    },
    {
      speaker: 'Atlas',
      text: 'The response now cites the supplied policy source.',
    },
  ],
  gates: [
    {
      name: 'approval_precondition',
      phase: 'pre_call',
      evaluated: true,
      outcome: 'PASS',
      reason_code: null,
    },
    {
      name: 'provenance',
      phase: 'post_call',
      evaluated: true,
      outcome: 'PASS',
      reason_code: null,
    },
  ],
  decision: 'PASS',
  artifact: {
    enforcement_result: 'PASS',
    output_checksum: 'b'.repeat(64),
    provenance: { source_ids: ['atlas-policy-BRV-04'] },
  },
  workflow_artifact: null,
  error: null,
  source: SOURCE,
}

const MERIDIAN_FIRST: ScenarioRunResponse = {
  scenario_id: 'meridian',
  variant: 'first_attempt',
  fixture_version: '2026-07-25.1',
  transcript: [
    {
      speaker: 'Meridian AI Assistant',
      text: 'Authorize payment for invoice MV-248.',
    },
    {
      speaker: 'Without AEGIS',
      text: 'Payment authorized.',
    },
    {
      speaker: 'With AEGIS',
      text: 'Unauthorized payment blocked before execution.',
    },
  ],
  gates: [
    {
      name: 'required_sequence',
      phase: 'workflow',
      evaluated: true,
      outcome: 'FAIL',
      reason_code: 'WORKFLOW_SEQUENCE_VIOLATION',
    },
  ],
  decision: 'FAIL',
  artifact: {
    enforcement_result: 'PASS',
    context: { step_id: 'invoice_intake' },
  },
  workflow_artifact: {
    artifact_type: 'workflow',
    status: 'INCOMPLETE',
    steps: [
      {
        step_id: 'invoice_intake',
        invocation_artifact_checksum: 'e'.repeat(64),
      },
    ],
  },
  error: {
    code: 'WORKFLOW_SEQUENCE_VIOLATION',
    message: 'The required sequence was not followed.',
    request_id: 'b'.repeat(32),
  },
  source: SOURCE,
}

const ATLAS_GATE_STATES: ScenarioRunResponse = {
  ...ATLAS_FIRST,
  transcript: [],
  gates: [
    {
      name: 'source_attached',
      phase: 'pre_call',
      evaluated: true,
      outcome: 'PASS',
      reason_code: null,
    },
    {
      name: 'provenance',
      phase: 'post_call',
      evaluated: true,
      outcome: 'FAIL',
      reason_code: 'PROVENANCE_MISSING',
    },
    {
      name: 'workflow_completion',
      phase: 'workflow',
      evaluated: false,
      outcome: null,
      reason_code: null,
    },
  ],
  artifact: null,
  error: null,
}

const MALFORMED_RESPONSE_CASES: [string, unknown][] = [
  ['non-record top level', []],
  ['missing transcript', { ...ATLAS_FIRST, transcript: undefined }],
  ['non-array transcript', { ...ATLAS_FIRST, transcript: {} }],
  [
    'invalid transcript entry',
    {
      ...ATLAS_FIRST,
      transcript: [{ speaker: 'Atlas', text: 42 }],
    },
  ],
  ['missing gates', { ...ATLAS_FIRST, gates: undefined }],
  ['non-array gates', { ...ATLAS_FIRST, gates: {} }],
  [
    'invalid gate phase',
    {
      ...ATLAS_FIRST,
      gates: [{ ...ATLAS_FIRST.gates[0], phase: 'provider' }],
    },
  ],
  [
    'invalid gate outcome',
    {
      ...ATLAS_FIRST,
      gates: [{ ...ATLAS_FIRST.gates[0], outcome: 'UNKNOWN' }],
    },
  ],
  [
    'inconsistent gate evaluation',
    {
      ...ATLAS_FIRST,
      gates: [{
        ...ATLAS_FIRST.gates[0],
        evaluated: false,
        outcome: 'PASS',
      }],
    },
  ],
  ['invalid decision', { ...ATLAS_FIRST, decision: 'UNKNOWN' }],
  ['wrong scenario', { ...ATLAS_FIRST, scenario_id: 'northstar' }],
  ['wrong variant', { ...ATLAS_FIRST, variant: 'corrected' }],
  ['invalid fixture version', { ...ATLAS_FIRST, fixture_version: null }],
  ['array invocation artifact', { ...ATLAS_FIRST, artifact: [] }],
  [
    'array workflow artifact',
    { ...ATLAS_FIRST, workflow_artifact: [] },
  ],
  ['array error', { ...ATLAS_FIRST, error: [] }],
  [
    'invalid error fields',
    { ...ATLAS_FIRST, error: { code: 401, message: 'Invalid' } },
  ],
  ['array source', { ...ATLAS_FIRST, source: [] }],
  [
    'invalid source fields',
    {
      ...ATLAS_FIRST,
      source: { branch: 42, commit: null, sdk_version: '0.9.0b1' },
    },
  ],
]

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify(body), {
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderScenario(scenarioId: string) {
  return render(
    <MemoryRouter initialEntries={[`/demo/scenarios/${scenarioId}`]}>
      <Routes>
        <Route path="/demo/scenarios/:scenarioId" element={<ScenarioPage />} />
      </Routes>
    </MemoryRouter>,
  )
}

function renderSwitchableScenario() {
  return render(
    <MemoryRouter initialEntries={['/demo/scenarios/atlas']}>
      <Link to="/demo/scenarios/northstar">Switch directly to Northstar</Link>
      <Link to="/demo/scenarios/atlas">Switch directly to Atlas</Link>
      <Routes>
        <Route path="/demo/scenarios/:scenarioId" element={<ScenarioPage />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('ScenarioPage', () => {
  beforeEach(() => {
    testState.serviceStatus = 'ready'
  })

  afterEach(() => {
    cleanup()
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('explains the Atlas incident and visitor role before technical results', () => {
    vi.stubGlobal('fetch', vi.fn())
    renderScenario('atlas')

    expect(
      screen.getByRole('heading', { level: 1, name: 'A confident answer can still be wrong' }),
    ).toBeInTheDocument()
    expect(screen.getByText(/You lead customer support at Atlas Travel/i)).toBeInTheDocument()
    expect(
      screen.getByText(/storm policy covers a missed connection/i),
    ).toBeInTheDocument()

    for (const region of [
      'Incident',
      'Your judgment',
      'AEGIS evaluation',
      'Evidence',
    ]) {
      expect(screen.getByRole('heading', { name: region })).toBeInTheDocument()
    }
    expect(screen.getByRole('list', { name: 'Case story' })).toHaveTextContent(
      'BRV-04 says this missed connection is not covered',
    )
  })

  it('intercepts the send choice and evaluates the wrong draft before delivery', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(ATLAS_FIRST))
    vi.stubGlobal('fetch', fetchMock)
    renderScenario('atlas')

    await user.click(screen.getByRole('radio', { name: 'Send the answer as written' }))
    await user.click(screen.getByRole('button', { name: 'Run judgment' }))

    expect(await screen.findAllByText('OUTPUT_SCHEMA_VALIDATION_ERROR'))
      .toHaveLength(2)
    expect(fetchMock).toHaveBeenCalledWith(
      'http://demo.test/api/demo/scenarios/atlas/runs',
      expect.objectContaining({
        body: JSON.stringify({ variant: 'first_attempt' }),
      }),
    )
    expect(screen.getByRole('button', { name: 'Run corrected answer' }))
      .toBeInTheDocument()
  })

  it('disables Run until the deterministic demo service is ready', () => {
    testState.serviceStatus = 'checking'
    vi.stubGlobal('fetch', vi.fn())
    renderScenario('atlas')

    expect(
      screen.getByRole('button', { name: 'Run judgment' }),
    ).toBeDisabled()
    expect(screen.getByText('Waiting for the demo service.')).toHaveTextContent(
      'Waiting for the demo service.',
    )
  })

  it('posts only the selected server variant and renders returned order', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(ATLAS_FIRST))
    vi.stubGlobal('fetch', fetchMock)
    renderScenario('atlas')

    await user.click(
      screen.getByRole('radio', {
        name: 'Pause and let AEGIS check the answer',
      }),
    )
    await user.click(screen.getByRole('button', { name: 'Run judgment' }))

    await waitFor(() => {
      expect(screen.getAllByText('OUTPUT_SCHEMA_VALIDATION_ERROR')).toHaveLength(2)
    })
    expect(fetchMock).toHaveBeenCalledWith(
      'http://demo.test/api/demo/scenarios/atlas/runs',
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ variant: 'first_attempt' }),
        signal: expect.any(AbortSignal),
      }),
    )
    expect(
      Object.keys(JSON.parse(fetchMock.mock.calls[0][1].body as string)),
    ).toEqual(['variant'])

    const evaluation = screen.getByRole('region', { name: 'AEGIS evaluation' })
    const gateNames = within(evaluation)
      .getAllByTestId('gate-name')
      .map((node) => node.textContent)
    expect(gateNames).toEqual([
      'approval precondition',
      'provenance',
      'output schema',
    ])
    const overallDecision = within(evaluation)
      .getByText('Overall decision')
      .closest('.scenario-decision')
    expect(within(overallDecision as HTMLElement).getByText('Fail')).toBeInTheDocument()
    expect(
      screen.getByText('The answer conflicts with rule BRV-04.'),
    ).toBeInTheDocument()
  })

  it.each(MALFORMED_RESPONSE_CASES)(
    'rejects a malformed 200 response: %s',
    async (_caseName, responseBody) => {
      const user = userEvent.setup()
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue(jsonResponse(responseBody)),
      )
      renderScenario('atlas')

      await user.click(
        screen.getByRole('radio', {
          name: 'Pause and let AEGIS check the answer',
        }),
      )
      await user.click(screen.getByRole('button', { name: 'Run judgment' }))

      expect(await screen.findByRole('alert')).toHaveTextContent(
        'The demo service returned an invalid scenario result.',
      )
      expect(screen.queryByText('Pass')).not.toBeInTheDocument()
      expect(screen.queryByText('OUTPUT_SCHEMA_VALIDATION_ERROR')).not.toBeInTheDocument()
      expect(
        screen.queryByRole('heading', { name: 'Invocation artifact' }),
      ).not.toBeInTheDocument()
      expect(
        screen.getByRole('region', { name: 'AEGIS evaluation' }),
      ).toHaveTextContent(
        'Run your judgment to request an evaluation from the demo service.',
      )
    },
  )

  it('shows explanatory text for pass, fail, and unevaluated gates', async () => {
    const user = userEvent.setup()
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(jsonResponse(ATLAS_GATE_STATES)),
    )
    renderScenario('atlas')

    await user.click(
      screen.getByRole('radio', {
        name: 'Pause and let AEGIS check the answer',
      }),
    )
    await user.click(screen.getByRole('button', { name: 'Run judgment' }))

    await screen.findByText('source attached')
    const gates = screen.getAllByTestId('gate-name')
    const passGate = gates[0].closest('.scenario-gate')
    const failGate = gates[1].closest('.scenario-gate')
    const unevaluatedGate = gates[2].closest('.scenario-gate')

    expect(passGate).toHaveTextContent(
      'The returned evaluation passed.',
    )
    expect(failGate).toHaveTextContent(
      'The returned evaluation failed.',
    )
    expect(failGate).toHaveTextContent(
      'PROVENANCE_MISSING',
    )
    expect(unevaluatedGate).toHaveTextContent(
      'This gate was not evaluated in the returned run.',
    )
    expect(within(unevaluatedGate as HTMLElement).queryByText('Reason code'))
      .not.toBeInTheDocument()
  })

  it('downloads exactly the current returned invocation artifact', async () => {
    const user = userEvent.setup()
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(jsonResponse(ATLAS_FIRST))
      .mockResolvedValueOnce(jsonResponse(ATLAS_CORRECTED)))
    const createObjectURL = vi.fn().mockReturnValue('blob:atlas-artifact')
    const revokeObjectURL = vi.fn()
    vi.spyOn(URL, 'createObjectURL').mockImplementation(createObjectURL)
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(revokeObjectURL)
    const anchorClick = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined)
    renderScenario('atlas')

    await user.click(screen.getByRole('radio', {
      name: 'Pause and let AEGIS check the answer',
    }))
    await user.click(screen.getByRole('button', { name: 'Run judgment' }))
    await user.click(await screen.findByRole('button', {
      name: 'Run corrected answer',
    }))
    await user.click(
      await screen.findByRole('button', { name: 'Download invocation artifact' }),
    )

    expect(anchorClick).toHaveBeenCalledTimes(1)
    expect(createObjectURL).toHaveBeenCalledTimes(1)
    const artifactBlob = createObjectURL.mock.calls[0][0] as Blob
    await expect(artifactBlob.text()).resolves.toBe(
      JSON.stringify(ATLAS_CORRECTED.artifact, null, 2),
    )
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:atlas-artifact')
  })

  it('offers the corrected replay only after the blocked first attempt', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(ATLAS_FIRST))
      .mockResolvedValueOnce(jsonResponse(ATLAS_CORRECTED))
    vi.stubGlobal('fetch', fetchMock)
    renderScenario('atlas')

    expect(screen.queryByRole('button', { name: 'Run corrected answer' }))
      .not.toBeInTheDocument()

    await user.click(
      screen.getByRole('radio', {
        name: 'Pause and let AEGIS check the answer',
      }),
    )
    await user.click(screen.getByRole('button', { name: 'Run judgment' }))
    await user.click(await screen.findByRole('button', {
      name: 'Run corrected answer',
    }))
    expect(
      await screen.findByText('The response now cites the supplied policy source.'),
    ).toBeInTheDocument()
    expect(screen.getAllByText('Pass')).toHaveLength(3)
    expect(fetchMock.mock.calls.map((call) => call[1]?.body)).toEqual([
      JSON.stringify({ variant: 'first_attempt' }),
      JSON.stringify({ variant: 'corrected' }),
    ])
  })

  it('aborts the active scenario request when the route unmounts', async () => {
    const user = userEvent.setup()
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(() => undefined)))
    const view = renderScenario('atlas')

    await user.click(
      screen.getByRole('radio', {
        name: 'Pause and let AEGIS check the answer',
      }),
    )
    await user.click(screen.getByRole('button', { name: 'Run judgment' }))
    const fetchMock = vi.mocked(fetch)
    const signal = fetchMock.mock.calls[0][1]?.signal as AbortSignal

    view.unmount()

    expect(signal.aborted).toBe(true)
  })

  it('does not expose authoritative results before a server response', () => {
    vi.stubGlobal('fetch', vi.fn())
    renderScenario('meridian')

    expect(screen.queryByText(/\bPASS\b/)).not.toBeInTheDocument()
    expect(screen.queryByText(/\bFAIL\b/)).not.toBeInTheDocument()
    expect(screen.queryByText(/\bPAUSED\b/)).not.toBeInTheDocument()
    expect(screen.queryByText(/reason code/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/checksum/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/workflow status/i)).not.toBeInTheDocument()
    expect(
      screen.getByRole('region', { name: 'AEGIS evaluation' }),
    ).not.toHaveAttribute('aria-live')
    expect(screen.getByTestId('scenario-result-announcement')).toHaveTextContent(
      'No scenario run has completed.',
    )
  })

  it('runs Meridian as an autonomous comparison without human judgment', async () => {
    const user = userEvent.setup()
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(jsonResponse(MERIDIAN_FIRST)),
    )
    renderScenario('meridian')

    expect(screen.getByRole('heading', {
      level: 1,
      name: 'Can an AI assistant authorize this payment?',
    })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Agentic flow' }))
      .toBeInTheDocument()
    expect(screen.queryByRole('radiogroup')).not.toBeInTheDocument()
    expect(screen.queryByText('Your judgment')).not.toBeInTheDocument()
    expect(screen.queryByText(/you lead accounts payable/i))
      .not.toBeInTheDocument()

    await user.click(screen.getByRole('button', {
      name: 'Run agentic comparison',
    }))

    expect(await screen.findByRole('heading', {
      name: 'Payment authorized.',
    })).toBeInTheDocument()
    expect(screen.getByRole('heading', {
      name: 'Unauthorized payment blocked before execution.',
    })).toBeInTheDocument()
    expect(screen.getByText(/policy is enforced before execution/i))
      .toBeInTheDocument()
    expect(screen.queryByText(/mock payment/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/finance reviewer/i)).not.toBeInTheDocument()
  })

  it('renders Meridian comparison outcomes from the returned transcript', async () => {
    const user = userEvent.setup()
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({
      ...MERIDIAN_FIRST,
      transcript: [
        MERIDIAN_FIRST.transcript[0],
        {
          speaker: 'Without AEGIS',
          text: 'Payment authorization reached the payment system.',
        },
        {
          speaker: 'With AEGIS',
          text: 'Runtime policy stopped payment authorization.',
        },
      ],
    })))
    renderScenario('meridian')

    await user.click(screen.getByRole('button', {
      name: 'Run agentic comparison',
    }))

    expect(await screen.findByRole('heading', {
      name: 'Payment authorization reached the payment system.',
    })).toBeInTheDocument()
    expect(screen.getByRole('heading', {
      name: 'Runtime policy stopped payment authorization.',
    })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Payment authorized.' }))
      .not.toBeInTheDocument()
  })

  it('announces a concise decision and reason outside the detailed result tree', async () => {
    const user = userEvent.setup()
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(ATLAS_FIRST)))
    renderScenario('atlas')

    await user.click(
      screen.getByRole('radio', {
        name: 'Pause and let AEGIS check the answer',
      }),
    )
    await user.click(screen.getByRole('button', { name: 'Run judgment' }))

    const announcement = await screen.findByTestId('scenario-result-announcement')
    expect(announcement).toHaveAttribute('role', 'status')
    expect(announcement).toHaveAttribute('aria-live', 'polite')
    expect(announcement).toHaveAttribute('aria-atomic', 'true')
    expect(announcement).toHaveTextContent(
      'Scenario run complete. Decision: FAIL. Reason: OUTPUT_SCHEMA_VALIDATION_ERROR.',
    )
    expect(announcement).not.toHaveTextContent(
      'The answer conflicts with rule BRV-04.',
    )

    const evaluation = screen.getByRole('region', { name: 'AEGIS evaluation' })
    expect(evaluation).not.toHaveAttribute('aria-live')
    expect(evaluation).not.toHaveAttribute('aria-atomic')
  })

  it('connects a raw Meridian invocation to its matching workflow step', async () => {
    const user = userEvent.setup()
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(jsonResponse(MERIDIAN_FIRST)),
    )
    renderScenario('meridian')

    await user.click(screen.getByRole('button', {
      name: 'Run agentic comparison',
    }))

    expect(
      await screen.findByRole('heading', { name: 'Invocation artifact' }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('heading', { name: 'Workflow artifact' }),
    ).toBeInTheDocument()
    const relationships = screen
      .getByRole('heading', { name: 'Returned artifact relationships' })
      .closest('.scenario-checksum-links')
    expect(within(relationships as HTMLElement).getByText('invoice intake'))
      .toBeInTheDocument()
    expect(within(relationships as HTMLElement).getByText('e'.repeat(64)))
      .toBeInTheDocument()
  })

  it.each([
    [
      'northstar',
      'Northstar clinic scheduling',
      'Keep the scheduling role and allow access to clinical details',
    ],
  ])('renders the %s case from shared scenario content', (
    scenarioId,
    title,
    choice,
  ) => {
    vi.stubGlobal('fetch', vi.fn())
    renderScenario(scenarioId)

    expect(screen.getByRole('heading', { level: 1, name: title })).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: choice })).toBeInTheDocument()
  })

  it.each(['unknown', '__proto__'])(
    'shows a visible not-found page for the unknown scenario ID %s',
    (scenarioId) => {
      vi.stubGlobal('fetch', vi.fn())
      renderScenario(scenarioId)

      expect(
        screen.getByRole('heading', { name: 'Scenario not found' }),
      ).toBeInTheDocument()
      expect(
        screen.queryByRole('heading', { name: 'A confident answer can still be wrong' }),
      ).not.toBeInTheDocument()
    },
  )

  it('clears scenario-local judgment and response when the route ID changes', async () => {
    const user = userEvent.setup()
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(ATLAS_FIRST)))
    renderSwitchableScenario()

    await user.click(
      screen.getByRole('radio', {
        name: 'Pause and let AEGIS check the answer',
      }),
    )
    await user.click(screen.getByRole('button', { name: 'Run judgment' }))
    expect(
      await screen.findByText('The answer conflicts with rule BRV-04.'),
    ).toBeInTheDocument()

    await user.click(
      screen.getByRole('link', { name: 'Switch directly to Northstar' }),
    )

    expect(
      screen.getByRole('heading', { name: 'Northstar clinic scheduling' }),
    ).toBeInTheDocument()
    expect(
      screen.queryByText('The response omitted a required source.'),
    ).not.toBeInTheDocument()
    expect(
      screen.getByRole('radio', {
        name: 'Retry with the authorized nurse role',
      }),
    ).not.toBeChecked()
    expect(screen.getByRole('button', { name: 'Run judgment' })).toBeDisabled()

    await user.click(
      screen.getByRole('link', { name: 'Switch directly to Atlas' }),
    )

    expect(
      screen.queryByText('The response omitted a required source.'),
    ).not.toBeInTheDocument()
    expect(
      screen.getByRole('radio', {
        name: 'Pause and let AEGIS check the answer',
      }),
    ).not.toBeChecked()
    expect(screen.getByRole('button', { name: 'Run judgment' })).toBeDisabled()
  })

  it('does not resurrect a busy request after a route-ID round trip', async () => {
    const user = userEvent.setup()
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(() => undefined)))
    renderSwitchableScenario()

    await user.click(
      screen.getByRole('radio', {
        name: 'Pause and let AEGIS check the answer',
      }),
    )
    await user.click(screen.getByRole('button', { name: 'Run judgment' }))
    expect(screen.getByText('Requesting the server evaluation.')).toHaveTextContent(
      'Requesting the server evaluation.',
    )

    await user.click(
      screen.getByRole('link', { name: 'Switch directly to Northstar' }),
    )
    await user.click(
      screen.getByRole('link', { name: 'Switch directly to Atlas' }),
    )

    expect(
      screen.getByText('Choose your judgment, then run the governed case.'),
    ).toHaveTextContent(
      'Choose your judgment, then run the governed case.',
    )
    expect(screen.getByRole('button', { name: 'Run judgment' })).toBeDisabled()
  })
})
