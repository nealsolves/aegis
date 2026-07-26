import { NavLink } from 'react-router-dom'
import { labNavCopy } from '@/content/demoCopy'

interface LabMeta {
  num: number
  short: string
}

export default function LabTabs({ labs }: { labs: readonly LabMeta[] }) {
  return (
    <nav className="lab-nav" aria-label={labNavCopy.ariaLabel}>
      <div className="lab-nav__inner">
        {labs.map((lab) => (
          <NavLink
            key={lab.num}
            to={`/lab/${lab.num}`}
            className={({ isActive }) => (
              isActive ? 'lab-nav__link lab-nav__link--active' : 'lab-nav__link'
            )}
          >
            Lab {lab.num}: {lab.short}
          </NavLink>
        ))}
      </div>
    </nav>
  )
}
