import { ExternalLink, Moon, Sun } from 'lucide-react'
import { Link } from 'react-router-dom'
import { publicNavCopy } from '@/content/demoCopy'
import { useTheme } from '@/theme/ThemeContext'

export default function AppNav() {
  const { theme, toggleTheme } = useTheme()
  const nextTheme = theme === 'light'
    ? publicNavCopy.theme.dark
    : publicNavCopy.theme.light

  return (
    <nav className="public-nav" aria-label={publicNavCopy.ariaLabel}>
      <div className="public-nav__inner">
        <Link
          to="/"
          className="public-nav__brand"
          aria-label={publicNavCopy.brandLabel}
        >
          <strong>{publicNavCopy.brand}</strong>
          <span>{publicNavCopy.descriptor}</span>
        </Link>

        <div className="public-nav__links">
          {publicNavCopy.links.map((link) => (
            <Link
              key={link.label}
              to={link.to}
              className={link.emphasis
                ? 'public-nav__link public-nav__link--primary'
                : 'public-nav__link'}
            >
              {link.label}
            </Link>
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
