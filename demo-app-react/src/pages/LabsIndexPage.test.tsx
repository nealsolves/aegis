import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import LabsIndexPage from './LabsIndexPage'

const EXPECTED_GROUPS = {
  Decisions: [
    ['Lab 9', 'Governed vs. Ungoverned', '/lab/9'],
    ['Lab 10', 'Split Enforcement', '/lab/10'],
    ['Lab 1', 'Risk Scoring', '/lab/1'],
  ],
  'Policies and gates': [
    ['Lab 4', 'Policy Composition', '/lab/4'],
    ['Lab 5', 'Loaders and Versioning', '/lab/5'],
    ['Lab 6', 'Custom Gates', '/lab/6'],
  ],
  Evidence: [
    ['Lab 2', 'Signing and Verification', '/lab/2'],
    ['Lab 3', 'Audit Chain', '/lab/3'],
    ['Lab 7', 'Compliance Dashboard', '/lab/7'],
  ],
  'Systems and workflows': [
    ['Lab 8', 'Governed Knowledge Base', '/lab/8'],
    ['Lab 11', 'Workflow Governance', '/lab/11'],
    ['Lab 12', 'Integration Adapters', '/lab/12'],
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
        expectedLabs.map(([, , href]) => href),
      )

      expectedLabs.forEach(([labNumber, title], index) => {
        expect(links[index]).toHaveTextContent(labNumber)
        expect(links[index]).toHaveTextContent(title)
      })
    }
  })

  it('shows the real 9 to 10 to 11 recommended first visit path', () => {
    renderPage()

    const path = screen.getByRole('navigation', {
      name: 'Recommended first visit',
    })
    const links = within(path).getAllByRole('link')

    expect(links.map(link => link.getAttribute('href'))).toEqual([
      '/lab/9',
      '/lab/10',
      '/lab/11',
    ])
    expect(links.map(link => link.textContent)).toEqual([
      expect.stringContaining('9'),
      expect.stringContaining('10'),
      expect.stringContaining('11'),
    ])
  })

  it('preserves every legacy lab destination and adds Lab 12', () => {
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
