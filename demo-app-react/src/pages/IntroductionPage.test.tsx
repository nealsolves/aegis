import { render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import '@/index.css'
import IntroductionPage from './IntroductionPage'

function renderPage(path = '/') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <IntroductionPage />
    </MemoryRouter>,
  )
}

describe('IntroductionPage', () => {
  it('leads with the deterministic-wrapper thesis', () => {
    renderPage()

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'The deterministic wrapper around a probabilistic core.',
      }),
    ).toBeInTheDocument()
    expect(screen.getByText(
      'AI works in possibilities. Enterprise systems need a definite decision: '
        + 'allow, block, pause, or escalate. AEGIS enforces your enterprise policy '
        + 'at the boundary—before an AI acts and before its output becomes an '
        + 'operational outcome.',
    )).toBeInTheDocument()
  })

  it('makes enterprise policy the deterministic permission boundary', () => {
    renderPage()

    expect(
      screen.getByRole('heading', {
        name: 'Let AI handle possibility. Make policy decide permission.',
      }),
    ).toBeInTheDocument()
    expect(screen.getByText(/permission resolves against declared, versioned/i))
      .toBeInTheDocument()
    expect(
      screen.getByRole('heading', {
        name: 'Probabilistic core',
      }),
    ).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Deterministic governance' }))
      .toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Enterprise operation' }))
      .toBeInTheDocument()
  })

  it('contrasts the model account with an independent system receipt', () => {
    renderPage()

    expect(
      screen.getByRole('heading', { name: 'An explanation is not a control.' }),
    ).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: "The model's account" }))
      .toBeInTheDocument()
    expect(screen.getByRole('heading', { name: "The system's receipt" }))
      .toBeInTheDocument()
    expect(screen.getByText('Useful clues for understanding behavior'))
      .toBeInTheDocument()
    expect(screen.getByText('Independent evidence of the governance decision'))
      .toBeInTheDocument()
  })

  it('closes the story before offering demo entry points', () => {
    const { container } = renderPage()
    const principle = container.querySelector('.intro-principle')
    const entries = screen.getByRole('region', { name: 'Choose where to start' })

    expect(
      screen.getByRole('heading', { name: 'Governance is infrastructure.' }),
    ).toBeInTheDocument()
    expect(principle).not.toBeNull()
    expect(
      (principle?.compareDocumentPosition(entries) ?? 0)
        & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy()
  })

  it('hands visitors from the principle into the three demo paths', () => {
    renderPage()

    for (const description of [
      'Understand the ownership boundary and technical map.',
      'Follow governed enterprise cases.',
      'Inspect individual controls and evidence.',
    ]) {
      expect(screen.getByText(description)).toBeInTheDocument()
    }
  })

  it('shows the public beta install command', () => {
    renderPage()

    expect(
      screen.getByRole('heading', {
        name: 'Add AEGIS to an AI invocation or agentic workflow you already own.',
      }),
    ).toBeInTheDocument()
    expect(
      screen.getByText('pip install aegis-ai-governance==0.9.0b1'),
    ).toBeInTheDocument()
  })

  it('scrolls route fragment links to the requested introduction section', async () => {
    const scrollIntoView = vi.fn()
    Object.defineProperty(Element.prototype, 'scrollIntoView', {
      configurable: true,
      value: scrollIntoView,
    })

    renderPage('/#install')

    await waitFor(() => {
      expect(scrollIntoView).toHaveBeenCalledTimes(1)
    })

    Reflect.deleteProperty(Element.prototype, 'scrollIntoView')
  })

  it('places the host-owned model call between split enforcement checks', () => {
    renderPage()
    const sample = screen.getByLabelText('Split enforcement Python example')
    const source = sample.textContent ?? ''

    expect(source).toContain('enforce_pre_call')
    expect(source).toContain('enforce_post_call')
    expect(source).toContain('# Host-owned model call')
    expect(source.lastIndexOf('enforce_pre_call')).toBeLessThan(
      source.indexOf('# Host-owned model call'),
    )
    expect(source.indexOf('# Host-owned model call')).toBeLessThan(
      source.lastIndexOf('enforce_post_call'),
    )
  })

  it('offers three meaningful demo entry cards', () => {
    renderPage()
    const entries = screen.getByRole('region', { name: 'Choose where to start' })

    expect(within(entries).getAllByRole('article')).toHaveLength(3)
    for (const label of ['Architecture', 'Scenarios', 'Labs']) {
      expect(within(entries).getByRole('link', { name: label })).toBeInTheDocument()
    }
  })

  it('uses the 44px target contract for each demo entry link', () => {
    renderPage()
    const entries = screen.getByRole('region', { name: 'Choose where to start' })

    for (const label of ['Architecture', 'Scenarios', 'Labs']) {
      const link = within(entries).getByRole('link', { name: label })
      expect(link).toHaveClass('entry-card__link')
      const minimumHeight = getComputedStyle(link).minHeight
      expect(minimumHeight).toMatch(/^\d+(?:\.\d+)?px$/)
      expect(Number.parseFloat(minimumHeight)).toBeGreaterThanOrEqual(44)
    }
  })

  it('keeps the public beta install command on one line inside its own scroller', () => {
    renderPage()
    const command = screen.getByText('pip install aegis-ai-governance==0.9.0b1')
    const container = command.closest('.install-command')

    expect(getComputedStyle(command).whiteSpace).toBe('nowrap')
    expect(container).not.toBeNull()
    expect(getComputedStyle(container as Element).overflowX).toBe('auto')
  })

  it('uses the wide prose contract for section introductions and sources', () => {
    const { container } = renderPage()
    const heading = container.querySelector('.intro-section-heading')
    const source = container.querySelector('.intro-source')

    expect(getComputedStyle(heading as Element).maxWidth).toBe('100ch')
    expect(getComputedStyle(source as Element).maxWidth).toBe('100ch')
  })
})
