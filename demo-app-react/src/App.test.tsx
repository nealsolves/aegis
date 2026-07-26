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

  it('preserves legacy lab deep links and shows lab tabs only there', () => {
    renderRoute('#/lab/1')

    expect(
      screen.getByRole('button', { name: 'Run Enforcement →' }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('navigation', { name: 'Lab navigation' }),
    ).toBeInTheDocument()
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
    expect(
      screen.getByRole('navigation', { name: 'Lab navigation' }),
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
    expect(screen.getByText('Architecture Guide')).toBeInTheDocument()
  })

  it('keeps scenario routes free of the lab Guide launcher', () => {
    renderRoute('#/demo/scenarios/atlas')

    expect(
      screen.queryByRole('button', { name: 'Open lab guide' }),
    ).not.toBeInTheDocument()
  })

  it('places the shared Guide launcher in a content-reserved rail', () => {
    const { container } = renderRoute('#/demo/architecture')
    const main = container.querySelector('main')
    const rail = container.querySelector('.help-launcher')
    const button = screen.getByRole('button', { name: 'Open lab guide' })

    expect(rail).not.toBeNull()
    expect(main?.previousElementSibling).toBe(rail)
    expect(rail).toContainElement(button)
    expect(button).not.toHaveStyle({ position: 'fixed' })
  })

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
