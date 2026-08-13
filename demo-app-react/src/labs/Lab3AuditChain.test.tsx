import { fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import Lab3AuditChain from './Lab3AuditChain'
import { useApi } from '@/hooks/useApi'

vi.mock('@/hooks/useApi', () => ({ useApi: vi.fn() }))

type ApiState = {
  call: (path: string, body?: unknown) => Promise<unknown>
  loading: boolean
  error: string | null
}

const artifact = (index: number) => ({
  enforcement_result: 'PASS' as const,
  model_provider: 'mock',
  model_identifier: 'chain-demo',
  role: 'assistant',
  checksum: String(index + 1).repeat(64),
  chain_id: 'chain-demo',
  chain_index: index,
  previous_audit_checksum: index === 0 ? null : String(index).repeat(64),
})

function mockStates(states: ApiState[]) {
  let calls = 0
  vi.mocked(useApi).mockImplementation(() => {
    const state = states[calls % states.length]
    calls += 1
    return state
  })
}

const state = (overrides: Partial<ApiState> = {}): ApiState => ({
  call: vi.fn().mockResolvedValue(null),
  loading: false,
  error: null,
  ...overrides,
})

beforeEach(() => {
  vi.clearAllMocks()
})

describe('Lab3AuditChain', () => {
  it('shows API failures instead of silently doing nothing', () => {
    mockStates([
      state({ error: 'The server could not build the governed chain.' }),
      state(),
      state(),
    ])

    render(<Lab3AuditChain />)

    expect(screen.getByRole('alert')).toHaveTextContent(
      'The server could not build the governed chain.',
    )
  })

  it('shows every verification axis and the bounded proof claim', async () => {
    const build = vi.fn().mockResolvedValue({
      chain_id: 'chain-demo',
      artifacts: [artifact(0), artifact(1), artifact(2)],
    })
    const verify = vi.fn().mockResolvedValue({
      valid: true,
      content_integrity: 'valid',
      chain_continuity: 'valid',
      signature_status: 'unsigned',
      anchor_status: 'not_evaluated',
      completeness: 'unproven',
      errors: [],
    })
    mockStates([
      state({ call: build }),
      state({ call: verify }),
      state(),
    ])

    render(<Lab3AuditChain />)
    fireEvent.click(screen.getByRole('button', { name: 'Build governed chain' }))
    await screen.findByText('chain-demo…')
    fireEvent.click(screen.getByRole('button', { name: 'Verify Chain' }))

    expect(await screen.findByText('Content integrity')).toBeInTheDocument()
    expect(screen.getByText('Chain continuity')).toBeInTheDocument()
    expect(screen.getByText('Signature')).toBeInTheDocument()
    expect(screen.getByText('Anchor')).toBeInTheDocument()
    expect(screen.getByText('Completeness')).toBeInTheDocument()
    expect(screen.getByText('unproven')).toBeInTheDocument()
    expect(screen.getByText(/does not prove a complete history/i))
      .toBeInTheDocument()
  })
})
