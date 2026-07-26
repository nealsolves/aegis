import { NavLink } from 'react-router-dom'
import { demoNavCopy } from '@/content/demoCopy'

export default function DemoNav() {
  return (
    <nav className="demo-nav" aria-label={demoNavCopy.ariaLabel}>
      <div className="demo-nav__inner">
        {demoNavCopy.links.map((link) => (
          <NavLink
            key={link.label}
            to={link.to}
            className={({ isActive }) => (
              isActive ? 'demo-nav__link demo-nav__link--active' : 'demo-nav__link'
            )}
          >
            {link.label}
          </NavLink>
        ))}
      </div>
    </nav>
  )
}
