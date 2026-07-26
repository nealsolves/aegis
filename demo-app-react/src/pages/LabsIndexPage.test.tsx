import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import LabsIndexPage from './LabsIndexPage'

const EXPECTED_GROUPS = {
  Decisions: [
    ['Governed vs. Ungoverned', '/lab/9'],
    ['Split Enforcement', '/lab/10'],
    ['Risk Scoring', '/lab/1'],
  ],
  'Policies and gates': [
    ['Policy Composition', '/lab/4'],
    ['Loaders and Versioning', '/lab/5'],
    ['Custom Gates', '/lab/6'],
  ],
  Evidence: [
    ['Signing and Verification', '/lab/2'],
    ['Audit Chain', '/lab/3'],
    ['Compliance Dashboard', '/lab/7'],
  ],
  'Systems and workflows': [
    ['Governed Knowledge Base', '/lab/8'],
    ['Workflow Governance', '/lab/11'],
    ['Integration Adapters', '/lab/12'],
  ],
} as const

function renderPage() {
  return render(
    <MemoryRouter>
      <LabsIndexPage />
    </MemoryRouter>,
  )
}

describe('LabsIndexPage', () => {
  it('groups every lab under the approved capability heading in exact order', () => {
    renderPage()

    for (const [groupName, expectedLabs] of Object.entries(EXPECTED_GROUPS)) {
      const heading = screen.getByRole('heading', { name: groupName })
      const section = heading.closest('section')
      expect(section).not.toBeNull()

      const links = within(section!).getAllByRole('link')
      expect(links).toHaveLength(expectedLabs.length)
      expect(links.map(link => link.getAttribute('href'))).toEqual(
        expectedLabs.map(([, href]) => href),
      )

      expectedLabs.forEach(([title], index) => {
        expect(links[index]).toHaveTextContent(title)
      })
    }
  })

  it('shows the approved number-free first-visit path', () => {
    renderPage()

    const journey = screen.getByRole('navigation', {
      name: 'First-visit path',
    })
    const links = within(journey).getAllByRole('link')

    expect(links.map(link => link.getAttribute('href'))).toEqual([
      '/lab/9',
      '/lab/10',
      '/lab/11',
    ])
    expect(links.map(link => link.textContent)).toEqual([
      expect.stringContaining('Compare enforcement'),
      expect.stringContaining('Explore checkpoints'),
      expect.stringContaining('Govern the handoff'),
    ])
  })

  it('does not expose historical lab numbers', () => {
    const { container } = renderPage()

    expect(container.textContent).not.toMatch(/\bLab\s+\d+\b/)
  })

  it('preserves every lab destination', () => {
    renderPage()

    const groupedLabs = screen.getByTestId('grouped-labs')
    const destinations = within(groupedLabs)
      .getAllByRole('link')
      .map(link => link.getAttribute('href'))

    expect([...destinations].sort()).toEqual(
      Array.from({ length: 12 }, (_, index) => `/lab/${index + 1}`).sort(),
    )
  })
})
