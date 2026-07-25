import { render, screen } from '@testing-library/react'
import { ThemeProvider } from '@/theme/ThemeContext'
import ArchitecturePage from './ArchitecturePage'

function renderPage() {
  return render(
    <ThemeProvider>
      <ArchitecturePage />
    </ThemeProvider>
  )
}

describe('ArchitecturePage', () => {
  it('renders the Component View section', () => {
    renderPage()
    expect(screen.getByText('Component View')).toBeInTheDocument()
  })

  it('renders the Enforcement Pipeline section', () => {
    renderPage()
    expect(screen.getByText('Enforcement Pipeline')).toBeInTheDocument()
  })

  it('renders the Key Boundaries section', () => {
    renderPage()
    expect(screen.getByText('Key Boundaries')).toBeInTheDocument()
  })

  it('renders the current candidate boundary notes', () => {
    renderPage()
    for (const label of [
      'Host Ownership',
      'Workflow Governance',
      'Invocation Enforcement',
      'Optional Adapters',
      'Evidence Separation',
      'Public API Boundary',
      'Signing and AuditChain',
      'Operator Tooling',
    ]) {
      expect(screen.getByText(label)).toBeInTheDocument()
    }
  })

  it('labels the page with the unpublished beta candidate', () => {
    renderPage()
    expect(screen.getByText('AEGIS v0.9 Beta')).toBeInTheDocument()
    expect(screen.getByText('aegis-ai-governance==0.9.0b1')).toBeInTheDocument()
  })

  it('renders diagram images', () => {
    renderPage()
    const component = screen.getByAltText('AEGIS v0.9 beta component architecture')
    const pipeline = screen.getByAltText('AEGIS v0.9 beta enforcement pipeline')

    expect(component).toHaveAttribute('aria-describedby', 'diagram-01-summary')
    expect(pipeline).toHaveAttribute('aria-describedby', 'diagram-02-summary')
    expect(document.getElementById('diagram-01-summary')).toHaveTextContent(
      /host-controlled execution.*Bedrock.*A2A.*OpenAI Agents.*separate invocation and workflow evidence/i
    )
    expect(document.getElementById('diagram-02-summary')).toHaveTextContent(
      /Phase A.*before the host model call.*Phase B.*ordered output gates.*invocation artifact.*workflow correlation/i
    )
  })
})
