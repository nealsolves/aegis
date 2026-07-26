import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import OwnershipFlow from './OwnershipFlow'

describe('OwnershipFlow', () => {
  it('keeps six ownership nodes and five connectors in sibling lanes', () => {
    render(<OwnershipFlow selectedNodeId={null} onSelect={() => undefined} />)

    const desktop = screen.getByTestId('ownership-flow-desktop')
    const nodes = desktop.querySelectorAll('[data-flow-node]')
    const lanes = desktop.querySelectorAll('[data-connector-lane]')

    expect(nodes).toHaveLength(6)
    expect(lanes).toHaveLength(5)
    expect(desktop.children).toHaveLength(11)

    Array.from(desktop.children).forEach((child, index) => {
      if (index % 2 === 0) {
        expect(child).toHaveAttribute('data-flow-node')
      } else {
        expect(child).toHaveAttribute('data-connector-lane')
        expect(child.closest('[data-flow-node]')).toBeNull()
      }
    })
  })

  it('uses independent vertical connector markup for the phone flow', () => {
    render(<OwnershipFlow selectedNodeId={null} onSelect={() => undefined} />)

    const mobile = screen.getByTestId('ownership-flow-mobile')
    const lanes = mobile.querySelectorAll('[data-vertical-connector-lane]')

    expect(mobile).not.toBe(screen.getByTestId('ownership-flow-desktop'))
    expect(lanes).toHaveLength(5)
    for (const lane of lanes) {
      expect(lane).toHaveAttribute('data-orientation', 'vertical')
      expect(lane.getAttribute('style') ?? '').not.toMatch(/rotate/i)
      expect(lane.closest('[data-flow-node]')).toBeNull()
    }
  })

  it('summarizes host execution, policy phases, result, and evidence in order', () => {
    render(<OwnershipFlow selectedNodeId={null} onSelect={() => undefined} />)

    expect(screen.getByTestId('ownership-flow-summary')).toHaveTextContent(
      /host request.*pre-call policy.*host executes one model call or workflow step.*post-call policy.*result.*evidence/i,
    )
  })

  it('exposes each stage as a selectable node', async () => {
    const user = userEvent.setup()
    const onSelect = vi.fn()
    render(<OwnershipFlow selectedNodeId={null} onSelect={onSelect} />)

    const desktop = screen.getByTestId('ownership-flow-desktop')
    await user.click(within(desktop).getByRole('button', { name: /AEGIS pre-call policy/i }))

    expect(onSelect).toHaveBeenCalledWith('pre-call-policy')
  })
})
