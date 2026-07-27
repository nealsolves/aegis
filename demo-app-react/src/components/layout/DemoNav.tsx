import { Link, useLocation } from 'react-router-dom'
import { demoNavCopy } from '@/content/demoCopy'

export default function DemoNav() {
  const { pathname } = useLocation()
  const normalizedPathname = (pathname.replace(/\/+$/, '') || '/').toLowerCase()

  return (
    <nav
      className="demo-nav site-header__row"
      aria-label={demoNavCopy.ariaLabel}
    >
      <div className="demo-nav__inner">
        {demoNavCopy.links.map((link) => {
          const isCurrentDestination = normalizedPathname === link.to
            || normalizedPathname.startsWith(`${link.to}/`)
            || (
              link.to === '/demo/labs'
              && normalizedPathname.startsWith('/lab/')
            )

          return (
            <Link
              key={link.label}
              to={link.to}
              className={isCurrentDestination
                ? 'demo-nav__link demo-nav__link--active'
                : 'demo-nav__link'}
              aria-current={isCurrentDestination ? 'page' : undefined}
            >
              {link.label}
            </Link>
          )
        })}
      </div>
    </nav>
  )
}
