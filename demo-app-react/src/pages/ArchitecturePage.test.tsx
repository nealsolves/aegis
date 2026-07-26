import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ThemeProvider } from '@/theme/ThemeContext'
import ArchitecturePage from './ArchitecturePage'

function setViewportMedia(isMobile: boolean) {
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({
    matches: query === '(max-width: 47.999rem)' ? isMobile : false,
    media: query,
    onchange: null,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })))
}

function renderPage({ isMobile = false }: { isMobile?: boolean } = {}) {
  setViewportMedia(isMobile)
  return render(
    <ThemeProvider>
      <ArchitecturePage />
    </ThemeProvider>
  )
}

describe('ArchitecturePage', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    localStorage.clear()
  })

  it('opens on the semantic How it works thesis', () => {
    renderPage()

    expect(screen.getByRole('tab', { name: 'How it works' })).toHaveAttribute(
      'aria-selected',
      'true',
    )
    expect(screen.getByRole('heading', { name: 'One governed call, clearly owned' })).toBeInTheDocument()
    expect(screen.queryByRole('img', { name: /AEGIS v0.9 beta/i })).not.toBeInTheDocument()
  })

  it('labels the page with the public beta release', () => {
    const { container } = renderPage()
    expect(screen.getByText('AEGIS v0.9 Beta')).toBeInTheDocument()
    expect(screen.getByText('aegis-ai-governance==0.9.0b1')).toBeInTheDocument()
    expect(container).toHaveTextContent(
      'The public beta is released from main and published on PyPI.'
    )
    expect(container).not.toHaveTextContent('The candidate is on develop')
  })

  it('opens progressive detail with responsibility and ownership boundaries', async () => {
    const user = userEvent.setup()
    renderPage()

    await user.click(screen.getAllByRole('button', { name: /AEGIS pre-call policy/i })[0])

    const detail = screen.getByRole('region', { name: /AEGIS pre-call policy details/i })
    expect(detail).toHaveTextContent('Responsibility')
    expect(detail).toHaveTextContent('Owner')
    expect(detail).toHaveTextContent('Public API / artifact')
    expect(detail).toHaveTextContent('AEGIS does not own')
  })

  it('renders theme-aware desktop technical diagrams on demand', async () => {
    const user = userEvent.setup()
    renderPage()

    await user.click(screen.getByRole('tab', { name: 'Technical map' }))

    expect(screen.getByAltText('AEGIS v0.9 beta component architecture')).toHaveAttribute(
      'src',
      expect.stringContaining('aegis_architecture_component_light.svg'),
    )

    await user.click(screen.getByRole('button', { name: 'Enforcement pipeline' }))
    expect(screen.getByAltText('AEGIS v0.9 beta enforcement pipeline')).toHaveAttribute(
      'src',
      expect.stringContaining('aegis_architecture_pipeline_light.svg'),
    )
  })

  it('renders grouped semantic cards without mounting SVG images below 48rem', async () => {
    const user = userEvent.setup()
    renderPage({ isMobile: true })

    await user.click(screen.getByRole('tab', { name: 'Technical map' }))

    expect(screen.queryByRole('img')).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Host-owned execution' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'AEGIS governance' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Evidence and operations' })).toBeInTheDocument()
  })
})
