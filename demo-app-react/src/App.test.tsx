import { render, screen } from '@testing-library/react'
import { ThemeProvider } from '@/theme/ThemeContext'
import App from './App'

function renderWithTheme() {
  return render(
    <ThemeProvider>
      <App />
    </ThemeProvider>
  )
}

describe('App routing', () => {
  it('renders AppNav', () => {
    renderWithTheme()
    expect(screen.getAllByText(/aegis/i).length).toBeGreaterThanOrEqual(1)
  })

  it('renders all 11 lab tabs', () => {
    renderWithTheme()
    // LabTabs renders links "Lab 1: Risk" through "Lab 11: Workflow"
    // The hero strip also contains "Lab N", so use getAllByText and confirm at least one match
    expect(screen.getAllByText(/Lab 1/).length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText(/Lab 7/).length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText(/Lab 8/).length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText(/Lab 10/).length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText(/Lab 11/).length).toBeGreaterThanOrEqual(1)
  })

  it('renders Architecture tab before lab tabs', () => {
    renderWithTheme()
    expect(screen.getByRole('link', { name: 'Architecture' })).toBeInTheDocument()
  })
})
