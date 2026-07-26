import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { AigcProvider } from '@/context/AigcContext'
import {
  DemoServiceProvider,
  useDemoService,
} from '@/context/DemoServiceContext'
import { ThemeProvider } from '@/theme/ThemeContext'
import App from './App'

function jsonResponse(body: unknown, init?: ResponseInit) {
  return new Response(JSON.stringify(body), {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
}

function DemoServiceStatusProbe() {
  const { status } = useDemoService()

  return <output data-testid="app-service-status">{status}</output>
}

function renderRoute(path: string, withServiceStatus = false) {
  window.location.hash = path

  return render(
    <ThemeProvider>
      <AigcProvider>
        <DemoServiceProvider>
          {withServiceStatus && <DemoServiceStatusProbe />}
          <App />
        </DemoServiceProvider>
      </AigcProvider>
    </ThemeProvider>,
  )
}

describe('App routing', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(() => undefined)))
  })

  afterEach(() => {
    cleanup()
    window.location.hash = ''
    vi.unstubAllGlobals()
  })

  it('uses the introduction as the root route', () => {
    renderRoute('#/')

    expect(
      screen.getByRole('heading', {
        name: 'Put policy between the request and the result.',
      }),
    ).toBeInTheDocument()
  })

  it('redirects the legacy architecture route to the demo architecture route', async () => {
    renderRoute('#/architecture')

    await waitFor(() => {
      expect(window.location.hash).toBe('#/demo/architecture')
    })
    expect(
      screen.getByRole('heading', { name: 'Architecture is an ownership contract.' }),
    ).toBeInTheDocument()
  })

  it.each(Array.from({ length: 12 }, (_, index) => index + 1))(
    'keeps /lab/%s stable with exactly one main landmark',
    labId => {
      const { container } = renderRoute(`#/lab/${labId}`)
      expect(container.querySelectorAll('main')).toHaveLength(1)
      expect(
        screen.queryByRole('navigation', { name: 'Lab navigation' }),
      ).not.toBeInTheDocument()
    },
  )

  it('uses capability context instead of historical numbering', () => {
    renderRoute('#/lab/9')
    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'Governed vs. Ungoverned',
      }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('navigation', { name: 'Also in Decisions' }),
    ).toBeInTheDocument()
    expect(screen.getByRole('main')).not.toHaveTextContent(/\bLab\s+\d+\b/)
  })

  it('renders the grouped labs index and the Lab 12 deep link', () => {
    const index = renderRoute('#/demo/labs')
    expect(
      screen.getByRole('heading', {
        name: 'See where governance changes the outcome.',
      }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('heading', { name: 'Systems and workflows' }),
    ).toBeInTheDocument()

    index.unmount()
    renderRoute('#/lab/12')
    expect(
      screen.getByRole('heading', {
        name: 'Inspect normalization at the governance boundary.',
      }),
    ).toBeInTheDocument()
  })

  it('exposes the shared public navigation', () => {
    renderRoute('#/')
    const nav = screen.getByRole('navigation', { name: 'Primary navigation' })

    for (const label of ['What it does', 'Install', 'Open demo', 'FAQ', 'GitHub']) {
      expect(within(nav).getByRole('link', { name: label })).toBeInTheDocument()
    }
  })

  it('shows demo navigation only inside demo, lab, and FAQ routes', () => {
    const root = renderRoute('#/')
    expect(
      screen.queryByRole('navigation', { name: 'Demo navigation' }),
    ).not.toBeInTheDocument()

    root.unmount()
    renderRoute('#/demo/scenarios')
    expect(
      screen.getByRole('navigation', { name: 'Demo navigation' }),
    ).toBeInTheDocument()
  })

  it('derives help from the route instead of defaulting public pages to Lab 1', () => {
    const publicPage = renderRoute('#/faq')
    expect(
      screen.queryByRole('button', { name: 'Open lab guide' }),
    ).not.toBeInTheDocument()

    publicPage.unmount()
    renderRoute('#/demo/architecture')
    expect(
      screen.getByRole('button', { name: 'Open lab guide' }),
    ).toBeInTheDocument()
    expect(
      screen.queryByRole('navigation', { name: 'Lab navigation' }),
    ).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Open lab guide' }))
    expect(
      screen.getByRole('dialog', { name: 'Architecture' }),
    ).toBeInTheDocument()
  })

  it('keeps scenario routes free of the lab Guide launcher', () => {
    renderRoute('#/demo/scenarios/atlas')

    expect(
      screen.queryByRole('button', { name: 'Open lab guide' }),
    ).not.toBeInTheDocument()
  })

  it('shows the Guide launcher only where guide content exists', () => {
    const architecture = renderRoute('#/demo/architecture')
    expect(
      screen.getByRole('button', { name: 'Open lab guide' }),
    ).toBeInTheDocument()

    architecture.unmount()
    renderRoute('#/demo/scenarios/atlas')
    expect(
      screen.queryByRole('button', { name: 'Open lab guide' }),
    ).not.toBeInTheDocument()

    cleanup()
    renderRoute('#/demo/labs')
    expect(
      screen.queryByRole('button', { name: 'Open lab guide' }),
    ).not.toBeInTheDocument()

    cleanup()
    renderRoute('#/lab/9')
    expect(
      screen.getByRole('button', { name: 'Open lab guide' }),
    ).toBeInTheDocument()
  })

  it.each(['#/lab/01', '#/lab/012'])(
    'keeps noncanonical route %s free of the Guide launcher',
    path => {
      renderRoute(path)

      expect(
        screen.queryByRole('button', { name: 'Open lab guide' }),
      ).not.toBeInTheDocument()
    },
  )

  it('does not render an empty demo service strip while readiness is checking', () => {
    const { container } = renderRoute('#/demo/architecture')

    expect(container.querySelector('.demo-service-notice')).not.toBeInTheDocument()
  })

  it('does not render an empty demo service strip when the service is ready', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({
        status: 'ok',
        api_contract_version: '1',
        sdk_version: '0.9.0b1',
        source: {
          branch: 'main',
          commit: 'backend-commit',
        },
      }))
      .mockResolvedValueOnce(jsonResponse({
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
      }))
    vi.stubGlobal('fetch', fetchMock)

    const { container } = renderRoute('#/demo/architecture', true)

    await waitFor(() => {
      expect(screen.getByTestId('app-service-status')).toHaveTextContent('ready')
    })
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(container.querySelector('.demo-service-notice')).not.toBeInTheDocument()
  })
})
