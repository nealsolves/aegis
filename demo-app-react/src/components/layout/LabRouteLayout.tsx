import type { ReactNode } from 'react'
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
        <div className="lab-route__experiment">{children}</div>
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
