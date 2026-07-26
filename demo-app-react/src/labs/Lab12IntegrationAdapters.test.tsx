import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { StrictMode } from 'react'
import type { DemoServiceValue } from '@/context/DemoServiceContext'
import type {
  AdapterRunResponse,
  DemoManifest,
} from '@/types/demo'
import Lab12IntegrationAdapters from './Lab12IntegrationAdapters'

let serviceValue: DemoServiceValue

vi.mock('@/context/DemoServiceContext', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/context/DemoServiceContext')>()
  return {
    ...actual,
    useDemoService: () => serviceValue,
  }
})

vi.mock('@/context/AigcContext', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/context/AigcContext')>()
  return {
    ...actual,
    useAigc: () => ({
      apiUrl: 'http://demo.test',
      addAudit: vi.fn(),
      auditHistory: [],
      clearHistory: vi.fn(),
    }),
  }
})

const SOURCE = {
  branch: 'main',
  commit: 'backend-commit',
  sdk_version: '0.9.0b1',
}

const MANIFEST: DemoManifest = {
  api_contract_version: '1',
  sdk_version: '0.9.0b1',
  fixture_set_version: '2026-07-25',
  scenarios: ['atlas', 'meridian', 'northstar'],
  adapters: ['bedrock', 'openai_agents', 'a2a'],
  source: SOURCE,
}

const PASS_RESPONSE: AdapterRunResponse = {
  adapter_id: 'bedrock',
  fixture_id: 'valid_trace',
  provider_input: {
    trace_parts: [{
      agentAliasId: 'ALIASID12B',
      trace: { orchestrationTrace: { traceId: 'trace-returned-1' } },
    }],
  },
  normalized_evidence: {
    trace_ids: ['trace-returned-1'],
    trace_alias_matched: true,
  },
  decision: 'PASS',
  artifact: {
    enforcement_result: 'PASS',
    metadata: {
      pre_call_gates_evaluated: ['role_check', 'custom:bedrock_trace'],
      post_call_gates_evaluated: ['schema_validation'],
    },
  },
  workflow_artifact: {
    artifact_type: 'workflow',
    status: 'COMPLETED',
    steps: [],
  },
  error: null,
  source: SOURCE,
}

const NEGATIVE_RESPONSE: AdapterRunResponse = {
  adapter_id: 'bedrock',
  fixture_id: 'wrong_alias',
  provider_input: {
    trace_parts: [{
      agentAliasId: 'OTHERID12B',
      trace: { orchestrationTrace: { traceId: 'trace-returned-2' } },
    }],
  },
  normalized_evidence: {
    reason_code: 'RETURNED_ALIAS_MISMATCH',
    binding_name: 'bedrock-demo-planner',
  },
  decision: 'FAIL',
  artifact: null,
  workflow_artifact: {
    artifact_type: 'workflow',
    status: 'FAILED',
    steps: [],
  },
  error: {
    code: 'RETURNED_ALIAS_MISMATCH',
    message: 'The returned binding did not match.',
  },
  source: SOURCE,
}

const OPENAI_PASS_RESPONSE: AdapterRunResponse = {
  ...PASS_RESPONSE,
  adapter_id: 'openai_agents',
  fixture_id: 'governed_graph',
}

function readyService(
  adapters: readonly string[] = MANIFEST.adapters,
): DemoServiceValue {
  return {
    status: 'ready',
    manifest: {
      ...MANIFEST,
      adapters: adapters as DemoManifest['adapters'],
    },
    error: null,
    retry: vi.fn(),
  }
}

function jsonResponse(body: unknown, init?: ResponseInit) {
  return new Response(JSON.stringify(body), {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
}

function renderLab(
  onResultHelpContext = vi.fn(),
) {
  return {
    onResultHelpContext,
    ...render(
      <Lab12IntegrationAdapters
        onResultHelpContext={onResultHelpContext}
      />,
    ),
  }
}

describe('Lab12IntegrationAdapters', () => {
  beforeEach(() => {
    serviceValue = readyService()
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(jsonResponse(PASS_RESPONSE)),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('renders only manifest-listed adapters in manifest order with public labels', () => {
    serviceValue = readyService([
      'openai_agents',
      'unreleased_adapter',
      'bedrock',
    ])

    renderLab()

    const tabs = within(
      screen.getByRole('tablist', { name: 'Integration adapters' }),
    ).getAllByRole('tab')
    expect(tabs.map(tab => tab.textContent)).toEqual([
      'OpenAI Agents',
      'Amazon Bedrock',
    ])
    expect(screen.queryByText('unreleased_adapter')).not.toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'A2A' })).not.toBeInTheDocument()
  })

  it('contains no credential, provider-path, endpoint, or free-form fixture fields', () => {
    renderLab()

    expect(document.querySelectorAll('input')).toHaveLength(0)
    expect(screen.queryByLabelText(/credential|api key|access key|secret|token|endpoint|path|provider/i))
      .not.toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Fixture case' }))
      .toBeInTheDocument()
  })

  it('keeps Run disabled until the service is ready with a listed adapter', () => {
    serviceValue = {
      ...readyService(),
      status: 'starting',
    }
    const starting = renderLab()
    expect(screen.getByRole('button', { name: 'Run adapter fixture' }))
      .toBeDisabled()

    starting.unmount()
    serviceValue = readyService([])
    renderLab()
    expect(screen.getByRole('button', { name: 'Run adapter fixture' }))
      .toBeDisabled()
  })

  it('posts only the mapped fixture ID to the selected manifest adapter', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(PASS_RESPONSE))
    vi.stubGlobal('fetch', fetchMock)
    renderLab()

    fireEvent.click(screen.getByRole('button', { name: 'Run adapter fixture' }))

    await screen.findByRole('heading', { name: 'Decision' })
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('http://demo.test/api/demo/adapters/bedrock/runs')
    expect(options.method).toBe('POST')
    expect(JSON.parse(options.body as string)).toEqual({
      fixture_id: 'valid_trace',
    })
  })

  it('keeps native provider input and normalized evidence in distinct ordered panels', async () => {
    renderLab()
    fireEvent.click(screen.getByRole('button', { name: 'Run adapter fixture' }))

    const result = await screen.findByTestId('adapter-result')
    const headings = within(result).getAllByRole('heading', { level: 2 })
    expect(headings.map(heading => heading.textContent)).toEqual([
      'Native fixture',
      'Normalized invocation and evidence',
      'Policy checks',
      'Decision',
      'Artifact',
    ])

    expect(headings[0].closest('section')).toHaveClass(
      'adapter-result-panel--native',
    )
    expect(headings[1].closest('section')).toHaveClass(
      'adapter-result-panel--normalized',
    )
    expect(headings[0].closest('section')).not.toBe(
      headings[1].closest('section'),
    )
    expect(within(headings[0].closest('section')!).getByText(/trace-returned-1/))
      .toBeInTheDocument()
    expect(within(headings[1].closest('section')!).getByText(/trace_alias_matched/))
      .toBeInTheDocument()
    expect(within(headings[2].closest('section')!).getByText(/pre_call_gates_evaluated/))
      .toBeInTheDocument()
  })

  it('announces only the concise adapter decision and reason', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(jsonResponse(NEGATIVE_RESPONSE)),
    )
    renderLab()

    fireEvent.change(screen.getByRole('combobox', { name: 'Fixture case' }), {
      target: { value: 'wrong_alias' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Run adapter fixture' }))

    const announcement = await screen.findByTestId('adapter-result-announcement')
    expect(announcement).toHaveAttribute('role', 'status')
    expect(announcement).toHaveAttribute('aria-live', 'polite')
    expect(announcement).toHaveAttribute('aria-atomic', 'true')
    expect(announcement).toHaveTextContent(
      'Adapter run complete. Decision: FAIL. Reason: RETURNED_ALIAS_MISMATCH.',
    )
    expect(announcement).not.toHaveTextContent('trace-returned-2')

    const result = screen.getByTestId('adapter-result')
    expect(result).not.toHaveAttribute('aria-live')
    expect(result).not.toHaveAttribute('aria-atomic')
  })

  it('derives Result help only from returned reason code and normalized field names', async () => {
    const onResultHelpContext = vi.fn()
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(jsonResponse(NEGATIVE_RESPONSE)),
    )
    renderLab(onResultHelpContext)

    fireEvent.change(screen.getByRole('combobox', { name: 'Fixture case' }), {
      target: { value: 'wrong_alias' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Run adapter fixture' }))

    await screen.findByText('RETURNED_ALIAS_MISMATCH')
    expect(onResultHelpContext).toHaveBeenLastCalledWith({
      reasonCode: 'RETURNED_ALIAS_MISMATCH',
      fields: ['reason_code', 'binding_name'],
    })
  })

  it('clears a returned result and help context when the fixture changes', async () => {
    const { onResultHelpContext } = renderLab()
    fireEvent.click(screen.getByRole('button', { name: 'Run adapter fixture' }))
    expect(await screen.findByTestId('adapter-result')).toBeInTheDocument()

    fireEvent.change(screen.getByRole('combobox', { name: 'Fixture case' }), {
      target: { value: 'wrong_alias' },
    })

    expect(screen.queryByTestId('adapter-result')).not.toBeInTheDocument()
    expect(onResultHelpContext).toHaveBeenLastCalledWith(null)
  })

  it('ignores a stale run when the adapter changes before it resolves', async () => {
    let resolveRun: ((response: Response) => void) | undefined
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(() => new Promise<Response>((resolve) => {
        resolveRun = resolve
      })),
    )
    renderLab()

    fireEvent.click(screen.getByRole('button', { name: 'Run adapter fixture' }))
    fireEvent.click(screen.getByRole('tab', { name: 'OpenAI Agents' }))
    resolveRun?.(jsonResponse(PASS_RESPONSE))

    await waitFor(() => {
      expect(screen.queryByTestId('adapter-result')).not.toBeInTheDocument()
    })
  })

  it('clears settled result and help when the manifest removes the active adapter', async () => {
    const onResultHelpContext = vi.fn()
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(jsonResponse(NEGATIVE_RESPONSE)),
    )
    const view = renderLab(onResultHelpContext)

    fireEvent.change(screen.getByRole('combobox', { name: 'Fixture case' }), {
      target: { value: 'wrong_alias' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Run adapter fixture' }))
    expect(await screen.findByTestId('adapter-result')).toBeInTheDocument()
    expect(onResultHelpContext).toHaveBeenLastCalledWith({
      reasonCode: 'RETURNED_ALIAS_MISMATCH',
      fields: ['reason_code', 'binding_name'],
    })

    serviceValue = readyService(['openai_agents', 'a2a'])
    view.rerender(
      <Lab12IntegrationAdapters
        onResultHelpContext={onResultHelpContext}
      />,
    )

    await waitFor(() => {
      expect(screen.queryByTestId('adapter-result')).not.toBeInTheDocument()
      expect(onResultHelpContext).toHaveBeenLastCalledWith(null)
    })
    expect(
      within(screen.getByRole('tablist', { name: 'Integration adapters' }))
        .getAllByRole('tab')
        .map(tab => tab.textContent),
    ).toEqual(['OpenAI Agents', 'A2A'])
    expect(screen.getByRole('combobox', { name: 'Fixture case' }))
      .toHaveValue('governed_graph')
  })

  it('clears settled result and help when the manifest becomes unavailable', async () => {
    const onResultHelpContext = vi.fn()
    const view = renderLab(onResultHelpContext)

    fireEvent.click(screen.getByRole('button', { name: 'Run adapter fixture' }))
    expect(await screen.findByTestId('adapter-result')).toBeInTheDocument()

    serviceValue = {
      status: 'starting',
      manifest: null,
      error: null,
      retry: vi.fn(),
    }
    view.rerender(
      <Lab12IntegrationAdapters
        onResultHelpContext={onResultHelpContext}
      />,
    )

    await waitFor(() => {
      expect(screen.queryByTestId('adapter-result')).not.toBeInTheDocument()
      expect(onResultHelpContext).toHaveBeenLastCalledWith(null)
    })
    expect(screen.queryByRole('tablist', { name: 'Integration adapters' }))
      .not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Run adapter fixture' }))
      .toBeDisabled()
  })

  it('rejects a late response when the manifest replaces its active adapter', async () => {
    let resolveRun: ((response: Response) => void) | undefined
    const onResultHelpContext = vi.fn()
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(() => new Promise<Response>((resolve) => {
        resolveRun = resolve
      })),
    )
    const view = render(
      <StrictMode>
        <Lab12IntegrationAdapters
          onResultHelpContext={onResultHelpContext}
        />
      </StrictMode>,
    )

    fireEvent.click(screen.getByRole('button', { name: 'Run adapter fixture' }))
    serviceValue = readyService(['openai_agents'])
    view.rerender(
      <StrictMode>
        <Lab12IntegrationAdapters
          onResultHelpContext={onResultHelpContext}
        />
      </StrictMode>,
    )

    await act(async () => {
      resolveRun?.(jsonResponse(PASS_RESPONSE))
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(screen.queryByRole('tab', { name: 'Amazon Bedrock' }))
      .not.toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'OpenAI Agents' }))
      .toHaveAttribute('aria-selected', 'true')
    expect(screen.queryByTestId('adapter-result')).not.toBeInTheDocument()
    expect(onResultHelpContext).toHaveBeenLastCalledWith(null)
  })

  it('preserves a valid result when manifest order changes but effective selection does not', async () => {
    const onResultHelpContext = vi.fn()
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(jsonResponse(OPENAI_PASS_RESPONSE)),
    )
    const view = renderLab(onResultHelpContext)

    fireEvent.click(screen.getByRole('tab', { name: 'OpenAI Agents' }))
    fireEvent.click(screen.getByRole('button', { name: 'Run adapter fixture' }))
    expect(await screen.findByTestId('adapter-result')).toBeInTheDocument()
    const helpCallsBeforeReorder = onResultHelpContext.mock.calls.length

    serviceValue = readyService(['a2a', 'openai_agents', 'bedrock'])
    view.rerender(
      <Lab12IntegrationAdapters
        onResultHelpContext={onResultHelpContext}
      />,
    )

    expect(screen.getByTestId('adapter-result')).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'OpenAI Agents' }))
      .toHaveAttribute('aria-selected', 'true')
    expect(onResultHelpContext).toHaveBeenCalledTimes(helpCallsBeforeReorder)
  })

  it('uses the new adapter default fixture after manifest replacement', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValue(jsonResponse(OPENAI_PASS_RESPONSE))
    vi.stubGlobal('fetch', fetchMock)
    const view = renderLab()

    fireEvent.change(screen.getByRole('combobox', { name: 'Fixture case' }), {
      target: { value: 'wrong_alias' },
    })
    serviceValue = readyService(['openai_agents'])
    view.rerender(<Lab12IntegrationAdapters />)

    expect(screen.getByRole('combobox', { name: 'Fixture case' }))
      .toHaveValue('governed_graph')
    fireEvent.click(screen.getByRole('button', { name: 'Run adapter fixture' }))
    await screen.findByTestId('adapter-result')

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('http://demo.test/api/demo/adapters/openai_agents/runs')
    expect(JSON.parse(options.body as string)).toEqual({
      fixture_id: 'governed_graph',
    })
  })

  it.each([
    ['non-record top level', []],
    ['wrong adapter', { ...PASS_RESPONSE, adapter_id: 'a2a' }],
    ['wrong fixture', { ...PASS_RESPONSE, fixture_id: 'wrong_alias' }],
    ['invalid decision', { ...PASS_RESPONSE, decision: 'ALLOW' }],
    ['array provider input', { ...PASS_RESPONSE, provider_input: [] }],
    ['array normalized evidence', { ...PASS_RESPONSE, normalized_evidence: [] }],
    ['non-null numeric reason', {
      ...PASS_RESPONSE,
      normalized_evidence: { reason_code: 42 },
    }],
    ['array invocation artifact', { ...PASS_RESPONSE, artifact: [] }],
    ['array workflow artifact', { ...PASS_RESPONSE, workflow_artifact: [] }],
    ['array error', { ...PASS_RESPONSE, error: [] }],
    ['invalid error fields', {
      ...PASS_RESPONSE,
      error: { code: null, message: 'bad' },
    }],
    ['array source', { ...PASS_RESPONSE, source: [] }],
    ['invalid source fields', {
      ...PASS_RESPONSE,
      source: { branch: null, commit: null, sdk_version: 9 },
    }],
  ])('treats a malformed 200 as an ordinary error: %s', async (_name, body) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(body)))
    renderLab()

    fireEvent.click(screen.getByRole('button', { name: 'Run adapter fixture' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The demo service returned an invalid adapter result.',
    )
    expect(screen.queryByTestId('adapter-result')).not.toBeInTheDocument()
  })
})
