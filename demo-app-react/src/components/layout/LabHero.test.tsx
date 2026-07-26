import { render } from '@testing-library/react'
import { LABS } from '@/content/labCatalog'
import LabHero from './LabHero'

describe('LabHero', () => {
  it.each(LABS)(
    'uses readable light and dark kicker tokens for $title',
    lab => {
      const { container } = render(<LabHero lab={lab} />)
      const hero = container.querySelector<HTMLElement>('.lab-route__hero')

      expect(hero?.style.getPropertyValue('--lab-accent-light'))
        .toBe('var(--ibm-blue-60)')
      expect(hero?.style.getPropertyValue('--lab-accent-dark'))
        .toBe('var(--ibm-cyan-30)')
    },
  )
})
