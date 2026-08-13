import type { CSSProperties, ReactNode } from 'react'
import { ArrowRight } from 'lucide-react'
import { Link } from 'react-router-dom'
import {
  FIRST_VISIT_LABS,
  type LabMeta,
} from '@/content/labCatalog'
import LabContextNav from './LabContextNav'
import LabHero from './LabHero'
import LabRelatedNav from './LabRelatedNav'

export default function LabRouteLayout({
  lab,
  children,
}: {
  lab: LabMeta
  children: ReactNode
}) {
  const nextJourneyLab = lab.journey
    ? FIRST_VISIT_LABS[lab.journey.order]
    : undefined

  return (
    <main className="lab-route">
      <LabContextNav lab={lab} />
      <LabHero lab={lab} />
      <div className="lab-route__layout">
        <div
          className="lab-route__experiment"
          style={{ '--lab-experiment-target-size': '2.75rem' } as CSSProperties}
        >
          <section
            className="lab-operating-rhythm"
            aria-labelledby={`lab-${lab.id}-rhythm-title`}
          >
            <div>
              <p>Four steps, one governed decision</p>
              <h2 id={`lab-${lab.id}-rhythm-title`}>How to use this lab</h2>
            </div>
            <ol>
              <li><span>1</span><strong>Change the inputs</strong></li>
              <li><span>2</span><strong>Run AEGIS</strong></li>
              <li><span>3</span><strong>Understand the decision</strong></li>
              <li><span>4</span><strong>Inspect the evidence</strong></li>
            </ol>
          </section>
          <section className="lab-route__instrument" aria-label="Interactive lab">
            {children}
          </section>
        </div>
        <LabRelatedNav lab={lab} />
      </div>
      {nextJourneyLab && (
        <nav
          className="lab-route__continue"
          aria-label="Continue the first-visit path"
        >
          <p>Continue the first-visit path</p>
          <Link to={nextJourneyLab.path}>
            Next: {nextJourneyLab.journey!.action}
            <ArrowRight aria-hidden="true" />
          </Link>
        </nav>
      )}
    </main>
  )
}
