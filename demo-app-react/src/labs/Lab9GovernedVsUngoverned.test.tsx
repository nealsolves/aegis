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

  it('renders governed and ungoverned panel labels at readable body size', async () => {
    render(<Lab9GovernedVsUngoverned />)
    fireEvent.click(screen.getByRole('button', { name: /compare/i }))

    expect(await screen.findByText('Governed', { exact: true }))
      .toHaveClass('text-base')
    expect(screen.getByText('Ungoverned', { exact: true }))
      .toHaveClass('text-base')
  })

  it('renders the Compare button', () => {
    render(<Lab9GovernedVsUngoverned />)
    expect(screen.getByRole('button', { name: /compare/i })).toBeInTheDocument()
  })
})
