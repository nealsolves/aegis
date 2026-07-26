import { fireEvent, render, screen, within } from '@testing-library/react'
import { useState } from 'react'
import HelpDrawer, { type ResultHelpContext } from './HelpDrawer'
import { ThemeProvider } from '@/theme/ThemeContext'

function renderDrawer(
  isOpen: boolean,
  onClose = vi.fn(),
  labId = 1,
  resultContext?: ResultHelpContext,
) {
  return render(
    <ThemeProvider>
      <HelpDrawer
        labId={labId}
        isOpen={isOpen}
        onClose={onClose}
        resultContext={resultContext}
      />
    </ThemeProvider>
  )
}

describe('HelpDrawer', () => {
  it('is not in the document when isOpen is false', () => {
    renderDrawer(false)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('renders when isOpen is true', () => {
    renderDrawer(true)
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  it('shows the Lab 1 title from the public catalog', () => {
    renderDrawer(true)
    expect(screen.getByRole('dialog', { name: 'Risk Scoring' })).toBeInTheDocument()
  })

  it('renders the current v0.9 candidate identity in Architecture help', () => {
    renderDrawer(true, vi.fn(), 0)
    expect(screen.getByText(/aegis-ai-governance==0\.9\.0b1/)).toBeInTheDocument()
    expect(screen.getByText(/host owns/i)).toBeInTheDocument()
  })

  it('uses number-free catalog titles for lab guides', () => {
    const { rerender } = renderDrawer(true, vi.fn(), 2)
    expect(screen.getByRole('dialog', {
      name: 'Signing and Verification',
    })).toBeInTheDocument()
    expect(screen.queryByText(/\bLab\s+2\b/)).not.toBeInTheDocument()

    rerender(
      <ThemeProvider>
        <HelpDrawer labId={12} isOpen onClose={vi.fn()} />
      </ThemeProvider>,
    )
    expect(screen.getByRole('dialog', {
      name: 'Integration Adapters',
    })).toBeInTheDocument()
    expect(screen.queryByText(/\bLab\s+12\b/)).not.toBeInTheDocument()
  })

  it('shows at least one step title', () => {
    renderDrawer(true)
    expect(screen.getByText('Choose a Preset Scenario')).toBeInTheDocument()
  })

  it('renders the narrative framework sections for first-time users', () => {
    renderDrawer(true)
    expect(screen.getByText('Why This Matters')).toBeInTheDocument()
    expect(screen.getByText('What This Lab Shows')).toBeInTheDocument()
    expect(screen.getByText('How To Navigate')).toBeInTheDocument()
    expect(screen.getByText('Key Takeaway')).toBeInTheDocument()
  })

  it('calls onClose when the close button is clicked', () => {
    const onClose = vi.fn()
    renderDrawer(true, onClose)
    fireEvent.click(screen.getByRole('button', { name: /close guide/i }))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('calls onClose when Escape is pressed', () => {
    const onClose = vi.fn()
    renderDrawer(true, onClose)
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('calls onClose when the backdrop is clicked', () => {
    const onClose = vi.fn()
    renderDrawer(true, onClose)
    fireEvent.click(screen.getByTestId('help-backdrop'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('renders a glossary toggle when helpContent has glossary', () => {
    renderDrawer(true)
    expect(screen.getByRole('button', { name: /glossary/i })).toBeInTheDocument()
  })

  it('shows a glossary term on toggle open and hides it on toggle close', () => {
    renderDrawer(true)
    const glossaryBtn = screen.getByRole('button', { name: /glossary/i })

    // Term should not be visible before opening
    expect(screen.queryByText('Risk Mode')).not.toBeInTheDocument()

    // Click to open
    fireEvent.click(glossaryBtn)
    expect(screen.getByText('Risk Mode')).toBeInTheDocument()

    // Click to close
    fireEvent.click(glossaryBtn)
    expect(screen.queryByText('Risk Mode')).not.toBeInTheDocument()
  })

  it('renders without crashing when given an invalid labId (falls back to Lab 1)', () => {
    renderDrawer(true, vi.fn(), 99)
    expect(screen.getByRole('dialog', { name: 'Risk Scoring' })).toBeInTheDocument()
  })

  it('focuses Close first and traps forward and backward tab movement', () => {
    const outside = document.createElement('button')
    document.body.append(outside)
    outside.focus()
    renderDrawer(true)

    const dialog = screen.getByRole('dialog')
    const close = screen.getByRole('button', { name: 'Close guide' })
    const focusable = dialog.querySelectorAll<HTMLElement>(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
    )
    const last = focusable[focusable.length - 1]

    expect(close).toHaveFocus()
    last.focus()
    fireEvent.keyDown(document, { key: 'Tab' })
    expect(close).toHaveFocus()

    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true })
    expect(last).toHaveFocus()

    outside.focus()
    fireEvent.keyDown(document, { key: 'Tab' })
    expect(close).toHaveFocus()
    outside.remove()
  })

  it('restores focus to the Guide launcher after closing', () => {
    function Harness() {
      const [isOpen, setIsOpen] = useState(false)
      return (
        <ThemeProvider>
          <button onClick={() => setIsOpen(true)}>Guide launcher</button>
          <HelpDrawer
            labId={12}
            isOpen={isOpen}
            onClose={() => setIsOpen(false)}
          />
        </ThemeProvider>
      )
    }

    render(<Harness />)
    const launcher = screen.getByRole('button', { name: 'Guide launcher' })
    launcher.focus()
    fireEvent.click(launcher)
    expect(screen.getByRole('button', { name: 'Close guide' })).toHaveFocus()

    fireEvent.click(screen.getByRole('button', { name: 'Close guide' }))
    expect(launcher).toHaveFocus()
  })

  it('adds Base Guide and Result tabs only when returned context exists', () => {
    const resultContext = {
      reasonCode: 'RETURNED_REASON',
      fields: ['reason_code', 'trace_ids'],
    }
    renderDrawer(true, vi.fn(), 12, resultContext)

    const tablist = screen.getByRole('tablist', { name: 'Guide views' })
    expect(within(tablist).getByRole('tab', { name: 'Base Guide' }))
      .toHaveAttribute('aria-selected', 'true')
    expect(within(tablist).getByRole('tab', { name: 'Result' }))
      .toBeInTheDocument()
    expect(screen.getByText('Why This Matters')).toBeInTheDocument()

    fireEvent.click(within(tablist).getByRole('tab', { name: 'Result' }))
    expect(screen.getByRole('heading', { name: 'Returned result context' }))
      .toBeInTheDocument()
    expect(screen.getByText('RETURNED_REASON')).toBeInTheDocument()
    expect(screen.getByText('reason_code')).toBeInTheDocument()
    expect(screen.getByText('trace_ids')).toBeInTheDocument()
    expect(within(tablist).getByRole('tab', { name: 'Base Guide' }))
      .toBeInTheDocument()
  })

  it('does not add guide tabs without returned result context', () => {
    renderDrawer(true, vi.fn(), 12)
    expect(screen.queryByRole('tablist', { name: 'Guide views' }))
      .not.toBeInTheDocument()
    expect(screen.getByText('Why This Matters')).toBeInTheDocument()
  })
})
