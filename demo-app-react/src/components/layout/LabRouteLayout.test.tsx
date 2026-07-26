import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { LABS_BY_ID } from '@/content/labCatalog'
import LabRouteLayout from './LabRouteLayout'

function renderLayout(labId: number) {
  return render(
    <MemoryRouter>
      <LabRouteLayout lab={LABS_BY_ID[labId]}>
        <section aria-label="Experiment">Experiment body</section>
      </LabRouteLayout>
    </MemoryRouter>,
  )
}

describe('LabRouteLayout', () => {
  it('owns one main landmark and a descriptive page heading', () => {
    const { container } = renderLayout(9)
    expect(container.querySelectorAll('main')).toHaveLength(1)
    expect(
      screen.getByRole('heading', { level: 1, name: 'Governed vs. Ungoverned' }),
    ).toBeInTheDocument()
    expect(container.textContent).not.toMatch(/\bLab\s+9\b/)
  })

  it('shows capability context and related labs', () => {
    renderLayout(9)
    const context = screen.getByRole('navigation', { name: 'Lab context' })
    expect(within(context).getByRole('link', { name: 'All labs' }))
      .toHaveAttribute('href', '/demo/labs')
    expect(within(context).getByText('Decisions')).toBeInTheDocument()

    const related = screen.getByRole('navigation', {
      name: 'Also in Decisions',
    })
    expect(within(related).getByRole('link', {
      name: 'Governed vs. Ungoverned',
    })).toHaveAttribute('aria-current', 'page')
    expect(within(related).getByRole('link', {
      name: 'Split Enforcement',
    })).toHaveAttribute('href', '/lab/10')
  })

  it('shows continuation only for the first-visit path', () => {
    const journey = renderLayout(9)
    expect(screen.getByRole('navigation', {
      name: 'Continue the first-visit path',
    })).toHaveTextContent('Explore checkpoints')

    journey.unmount()
    renderLayout(1)
    expect(screen.queryByRole('navigation', {
      name: 'Continue the first-visit path',
    })).not.toBeInTheDocument()
  })

  it('gives experiment buttons the shared 44px target contract', () => {
    const { container } = renderLayout(9)
    expect(container.querySelector('.lab-route__experiment')).toHaveStyle({
      '--lab-experiment-target-size': '2.75rem',
    })
  })
})
