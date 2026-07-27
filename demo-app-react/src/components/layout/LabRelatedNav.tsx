import { ArrowRight } from 'lucide-react'
import { Link } from 'react-router-dom'
import {
  LABS_BY_ID,
  getLabGroup,
  type LabMeta,
} from '@/content/labCatalog'

export default function LabRelatedNav({ lab }: { lab: LabMeta }) {
  const group = getLabGroup(lab.capability)

  return (
    <nav
      className="lab-related"
      aria-label={`Also in ${group.title}`}
    >
      <p>Also in {group.title}</p>
      <ul>
        {group.labIds.map(id => {
          const relatedLab = LABS_BY_ID[id]
          const isCurrent = relatedLab.id === lab.id

          return (
            <li key={relatedLab.id}>
              <Link
                to={relatedLab.path}
                aria-current={isCurrent ? 'page' : undefined}
              >
                {relatedLab.title}
                {!isCurrent && <ArrowRight aria-hidden="true" />}
              </Link>
            </li>
          )
        })}
      </ul>
    </nav>
  )
}
