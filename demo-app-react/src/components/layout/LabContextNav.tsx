import { ChevronRight } from 'lucide-react'
import { Link } from 'react-router-dom'
import { getLabGroup, type LabMeta } from '@/content/labCatalog'

export default function LabContextNav({ lab }: { lab: LabMeta }) {
  const group = getLabGroup(lab.capability)

  return (
    <nav className="lab-context" aria-label="Lab context">
      <div className="lab-context__inner">
        <Link to="/demo/labs">All labs</Link>
        <ChevronRight aria-hidden="true" />
        <span>{group.title}</span>
      </div>
    </nav>
  )
}
