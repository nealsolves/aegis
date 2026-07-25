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
    expect(
      screen.getByAltText('AEGIS v0.9 beta component architecture')
    ).toBeInTheDocument()
    expect(
      screen.getByAltText('AEGIS v0.9 beta enforcement pipeline')
    ).toBeInTheDocument()
  })
})
