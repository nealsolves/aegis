import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import Lab5Loaders from './Lab5Loaders'

const { callApi } = vi.hoisted(() => ({
  callApi: vi.fn().mockResolvedValue({ policies: ['medical_ai.yaml'] }),
}))

vi.mock('@/hooks/useApi', () => ({
  useApi: () => ({ call: callApi, loading: false, error: null }),
}))

describe('Lab5Loaders', () => {
  it('gives every policy input an accessible name', async () => {
    const user = userEvent.setup()
    render(<Lab5Loaders />)

    expect(await screen.findByRole('combobox', { name: 'Policy file' }))
      .toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'InMemory' }))
    expect(screen.getByRole('textbox', { name: 'Policy YAML' }))
      .toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Versioning' }))
    expect(screen.getByLabelText('Effective date')).toBeInTheDocument()
    expect(screen.getByLabelText('Expiration date')).toBeInTheDocument()
    expect(screen.getByLabelText('Reference date')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Testing' }))
    expect(screen.getByRole('combobox', { name: 'Policy test file' }))
      .toBeInTheDocument()
  })
})
