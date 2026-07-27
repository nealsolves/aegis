import { ExternalLink, Moon, Sun } from 'lucide-react'
import { Link } from 'react-router-dom'
import { publicNavCopy } from '@/content/demoCopy'
import { useTheme } from '@/theme/ThemeContext'

export default function AppNav({
  isDemoContext,
  emphasizeDemoLink,
}: {
  isDemoContext: boolean
  emphasizeDemoLink: boolean
}) {
  const { theme, toggleTheme } = useTheme()
  const nextTheme = theme === 'light'
    ? publicNavCopy.theme.dark
    : publicNavCopy.theme.light

  return (
    <nav
      className="public-nav site-header__row"
      aria-label={publicNavCopy.ariaLabel}
    >
      <div className="public-nav__inner">
        <Link
          to="/"
          className="public-nav__brand"
          aria-label={publicNavCopy.brandLabel}
        >
          <strong>{publicNavCopy.brand}</strong>
        </Link>

        <div className="public-nav__links">
          {publicNavCopy.links.map(link => (
            link.id === 'demo' && isDemoContext ? (
              <span
                key={link.id}
                className="public-nav__current"
                aria-current="location"
              >
                {link.currentLabel}
              </span>
            ) : (
              <Link
                key={link.id}
                to={link.to}
                className={link.emphasis && emphasizeDemoLink
                  ? 'public-nav__link public-nav__link--primary'
                  : 'public-nav__link'}
              >
                {link.label}
              </Link>
            )
          ))}
          <a
            href={publicNavCopy.github.href}
            target="_blank"
            rel="noopener noreferrer"
            className="public-nav__link public-nav__external"
          >
            {publicNavCopy.github.label}
            <ExternalLink size={14} aria-hidden="true" />
          </a>
        </div>

        <button
          type="button"
          onClick={toggleTheme}
          className="public-nav__theme"
          aria-label={`${publicNavCopy.theme.switchTo} ${nextTheme} ${publicNavCopy.theme.mode}`}
        >
          {theme === 'dark'
            ? <Moon size={14} aria-hidden="true" />
            : <Sun size={14} aria-hidden="true" />}
          <span>{theme === 'dark' ? publicNavCopy.theme.dark : publicNavCopy.theme.light}</span>
        </button>
      </div>
    </nav>
  )
}
