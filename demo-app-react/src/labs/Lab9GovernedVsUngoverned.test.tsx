import { fireEvent, render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import Lab9GovernedVsUngoverned from './Lab9GovernedVsUngoverned'

vi.mock('@/context/AigcContext', () => ({
  useAigc: () => ({ apiUrl: 'http://localhost:8000', addAudit: vi.fn(), auditHistory: [] }),
}))

vi.mock('@/hooks/useApi', () => ({
  useApi: () => ({
    call: vi.fn().mockResolvedValue({
      artifact: null,
      governed: {
        artifact: {
          enforcement_result: 'PASS',
          metadata: {
            gates_evaluated: [],
            risk_scoring: { score: 0.1 },
          },
        },
        error: null,
      },
      ungoverned: {
        artifact: { metadata: {} },
        error: null,
      },
      scenario_key: 'low_risk_faq',
    }),
    loading: false,
    error: null,
  }),
}))

describe('Lab9GovernedVsUngoverned', () => {
  it('renders the lab comment line', () => {
    render(<Lab9GovernedVsUngoverned />)
    expect(screen.getByText(/governed vs.*ungoverned/i)).toBeInTheDocument()
  })

  it('renders semantic comparison labels with readable theme-aware text', async () => {
    render(<Lab9GovernedVsUngoverned />)
    fireEvent.click(screen.getByRole('button', { name: /compare/i }))

    const governed = await screen.findByText('Governed', { exact: true })
    const ungoverned = screen.getByText('Ungoverned', { exact: true })

    expect(governed)
      .toHaveClass('text-base')
    expect(ungoverned)
      .toHaveClass('text-base')
    expect(governed).toHaveStyle({ color: 'var(--text-primary)' })
    expect(ungoverned).toHaveStyle({ color: 'var(--text-secondary)' })
  })

  it('renders the Compare button', () => {
    render(<Lab9GovernedVsUngoverned />)
    expect(screen.getByRole('button', { name: /compare/i })).toBeInTheDocument()
  })

  it('gives the comparison scenario selector an accessible name', () => {
    render(<Lab9GovernedVsUngoverned />)
    expect(screen.getByRole('combobox', {
      name: 'Comparison scenario',
    })).toBeInTheDocument()
  })
})
