import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import '@/index.css'
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

  it.each([
    [1, 'Risk Scoring'],
    [2, 'Signing and Verification'],
    [3, 'Audit Chain'],
    [4, 'Policy Composition'],
    [5, 'Loaders and Versioning'],
    [6, 'Custom Gates'],
    [7, 'Compliance Dashboard'],
    [8, 'Governed Knowledge Base'],
    [9, 'Governed vs. Ungoverned'],
    [10, 'Split Enforcement Explorer'],
    [11, 'Workflow Governance'],
    [12, 'Integration Adapters'],
  ])(
    'keeps /lab/%s stable with one main landmark and the public heading "%s"',
    (labId, publicTitle) => {
      const { container } = renderRoute(`#/lab/${labId}`)
      expect(container.querySelectorAll('main')).toHaveLength(1)
      expect(container.querySelectorAll('h1')).toHaveLength(1)
      expect(
        screen.getByRole('heading', { level: 1, name: publicTitle }),
      ).toBeInTheDocument()
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

  it('uses a two-row public header without the removed landing link', () => {
    const { container } = renderRoute('#/')
    const header = container.querySelector<HTMLElement>('.site-header')
    const primary = screen.getByRole('navigation', { name: 'Primary navigation' })

    expect(header).not.toBeNull()
    if (!header) throw new Error('Expected site header')
    expect(header.querySelectorAll(':scope > .site-header__row')).toHaveLength(2)
    expect(
      within(header).getByText(
        'Auditable Enforcement and Governance for Intelligent Systems',
      ),
    ).toBeInTheDocument()
    expect(within(primary).queryByText('What it does')).not.toBeInTheDocument()
    expect(
      within(primary).getByRole('link', { name: 'Open demo' }),
    ).toBeInTheDocument()
    expect(container.querySelector('.site-header__context')).toBeInTheDocument()
  })

  it('marks Demo as the current location without exposing a link on demo routes', () => {
    renderRoute('#/demo/architecture')
    const primary = screen.getByRole('navigation', { name: 'Primary navigation' })
    const demo = within(primary).getByText('Demo')

    expect(demo.tagName).toBe('SPAN')
    expect(demo).toHaveAttribute('aria-current', 'location')
    expect(demo).not.toHaveAttribute('href')
    expect(
      screen.getByRole('navigation', { name: 'Demo navigation' }),
    ).toBeInTheDocument()
  })

  it('keeps Open demo available on the shared FAQ route', () => {
    renderRoute('#/faq')

    expect(
      within(
        screen.getByRole('navigation', { name: 'Primary navigation' }),
      ).getByRole('link', { name: 'Open demo' }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('navigation', { name: 'Demo navigation' }),
    ).toBeInTheDocument()
  })

  it('uses identical fixed row heights across public and demo routes', () => {
    const heights = ['#/', '#/demo/architecture', '#/lab/1', '#/faq'].map(path => {
      const view = renderRoute(path)
      const header = view.container.querySelector<HTMLElement>('.site-header')
      expect(header).not.toBeNull()
      if (!header) throw new Error('Expected site header')
      const rows = [
        ...header.querySelectorAll<HTMLElement>(
          ':scope > .site-header__row',
        ),
      ].map(row => getComputedStyle(row).height)
      view.unmount()
      return rows
    })

    expect(heights.every(rows => rows.length === 2)).toBe(true)
    expect(heights.every(rows => rows[0] === heights[0][0])).toBe(true)
    expect(heights.every(rows => rows[1] === heights[0][1])).toBe(true)
    expect(
      heights.flat().every(height => height !== 'auto' && height !== ''),
    ).toBe(true)
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

  it.each([
    ['#/lab/1/', 'Risk Scoring'],
    ['#/LAB/1', 'Risk Scoring'],
    ['#/demo/architecture/', 'Architecture is an ownership contract.'],
  ])(
    'keeps route-aware chrome aligned with the rendered page at %s',
    (path, heading) => {
      renderRoute(path)

      expect(
        screen.getByRole('heading', { level: 1, name: heading }),
      ).toBeInTheDocument()
      expect(
        screen.getByRole('navigation', { name: 'Demo navigation' }),
      ).toBeInTheDocument()
      expect(
        screen.getByRole('button', { name: 'Open lab guide' }),
      ).toBeInTheDocument()
    },
  )

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
