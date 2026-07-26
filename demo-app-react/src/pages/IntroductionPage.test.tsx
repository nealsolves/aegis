import { render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import IntroductionPage from './IntroductionPage'

function renderPage(path = '/') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <IntroductionPage />
    </MemoryRouter>,
  )
}

describe('IntroductionPage', () => {
  it('states the workflow governance and host execution boundary', () => {
    const { container } = renderPage()

    expect(container).toHaveTextContent(
      'AEGIS governs participants, step order, handoffs, approvals, budgets, and session lifecycle.',
    )
    expect(container).toHaveTextContent(
      'Your application or agent framework still executes the agents, model calls, and tools.',
    )
  })

  it('compares thought traces with governance records literally', () => {
    renderPage()

    expect(
      screen.getByRole('heading', {
        name: 'Model thought trace: useful for inspection',
      }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('heading', {
        name: 'AEGIS governance record: produced outside the model',
      }),
    ).toBeInTheDocument()
    expect(screen.getByText(/may omit an influence/i)).toBeInTheDocument()
  })

  it('shows the public beta install command', () => {
    renderPage()

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
})
