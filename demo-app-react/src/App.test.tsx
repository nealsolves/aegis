import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { AigcProvider } from '@/context/AigcContext'
import { DemoServiceProvider } from '@/context/DemoServiceContext'
import { ThemeProvider } from '@/theme/ThemeContext'
import App from './App'

function renderRoute(path: string) {
  window.location.hash = path

  return render(
    <ThemeProvider>
      <AigcProvider>
        <DemoServiceProvider>
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
    expect(screen.getByText('Key Boundaries')).toBeInTheDocument()
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
})
