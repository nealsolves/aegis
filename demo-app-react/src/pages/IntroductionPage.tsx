import { useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { introCopy } from '@/content/demoCopy'

const ENTRY_LINK_STYLE = { minHeight: '44px' } as const

export default function IntroductionPage() {
  const { hash } = useLocation()

  useEffect(() => {
    if (!hash.startsWith('#')) return
    document.getElementById(hash.slice(1))?.scrollIntoView({ block: 'start' })
  }, [hash])

  return (
    <main className="intro-page">
      <section className="intro-hero" aria-labelledby="intro-title">
        <div className="intro-shell intro-hero__grid">
          <div className="intro-hero__copy">
            <p className="intro-eyebrow">{introCopy.hero.eyebrow}</p>
            <h1 id="intro-title">{introCopy.hero.title}</h1>
            <p className="intro-lead">{introCopy.hero.lead}</p>
            <div className="intro-boundary">
              <p>{introCopy.hero.workflow}</p>
              <p>{introCopy.hero.host}</p>
            </div>
            <div className="intro-actions">
              {introCopy.hero.actions.map((action) => (
                <Link
                  key={action.label}
                  className={action.emphasis ? 'intro-button intro-button--primary' : 'intro-button'}
                  to={action.to}
                >
                  {action.label}
                </Link>
              ))}
            </div>
          </div>

          <figure className="policy-seam" aria-label={introCopy.hero.callFlowLabel}>
            <figcaption>{introCopy.hero.callFlowLabel}</figcaption>
            <ol>
              {introCopy.hero.callFlow.map((step) => (
                <li
                  key={step.title}
                  className={`policy-seam__step policy-seam__step--${step.kind}`}
                >
                  <span className="policy-seam__owner">{step.owner}</span>
                  <strong>{step.title}</strong>
                  <span>{step.detail}</span>
                </li>
              ))}
            </ol>
          </figure>
        </div>
      </section>

      <section
        id={introCopy.ownership.id}
        className="intro-section"
        aria-labelledby="ownership-title"
      >
        <div className="intro-shell">
          <SectionHeading
            eyebrow={introCopy.ownership.eyebrow}
            id="ownership-title"
            title={introCopy.ownership.title}
            intro={introCopy.ownership.intro}
          />
          <div className="ownership-grid">
            {introCopy.ownership.areas.map((area) => (
              <article key={area.title} className="ownership-card">
                <h3>{area.title}</h3>
                <p>{area.detail}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="intro-section intro-section--surface" aria-labelledby="comparison-title">
        <div className="intro-shell">
          <SectionHeading
            eyebrow={introCopy.comparison.eyebrow}
            id="comparison-title"
            title={introCopy.comparison.title}
            intro={introCopy.comparison.intro}
          />
          <div className="comparison-grid">
            {introCopy.comparison.columns.map((column) => (
              <article key={column.title} className="comparison-card">
                <h3>{column.title}</h3>
                <ul>
                  {column.items.map((item) => <li key={item}>{item}</li>)}
                </ul>
              </article>
            ))}
          </div>
          <p className="intro-source">
            {introCopy.comparison.source.lead}{' '}
            <a
              href={introCopy.comparison.source.href}
              target="_blank"
              rel="noreferrer"
            >
              {introCopy.comparison.source.label}
            </a>
          </p>
        </div>
      </section>

      <section
        id={introCopy.install.id}
        className="intro-section intro-install"
        aria-labelledby="install-title"
      >
        <div className="intro-shell">
          <SectionHeading
            eyebrow={introCopy.install.eyebrow}
            id="install-title"
            title={introCopy.install.title}
            intro={introCopy.install.intro}
          />
          <div className="intro-install__grid">
            <div>
              <div className="install-command">
                <span>{introCopy.install.commandLabel}</span>
                <code>{introCopy.install.command}</code>
              </div>
              <dl className="install-steps">
                {introCopy.install.steps.map((step) => (
                  <div key={step.title}>
                    <dt>{step.title}</dt>
                    <dd>{step.detail}</dd>
                  </div>
                ))}
              </dl>
            </div>
            <pre className="intro-code" aria-label={introCopy.install.sampleLabel}>
              <code>
                {introCopy.install.sampleLines.map((line, index) => (
                  <span
                    key={`${line.kind}-${index}`}
                    className={`intro-code__line intro-code__line--${line.kind}`}
                  >
                    {line.text || ' '}
                  </span>
                ))}
              </code>
            </pre>
          </div>
        </div>
      </section>

      <section
        className="intro-section intro-entries"
        aria-labelledby="entries-title"
        aria-label={introCopy.entries.regionLabel}
      >
        <div className="intro-shell">
          <SectionHeading
            eyebrow={introCopy.entries.eyebrow}
            id="entries-title"
            title={introCopy.entries.title}
            intro={introCopy.entries.intro}
          />
          <div className="entry-grid">
            {introCopy.entries.cards.map((card) => (
              <article key={card.title} className="entry-card">
                <h3>
                  <Link
                    className="entry-card__link"
                    style={ENTRY_LINK_STYLE}
                    to={card.to}
                  >
                    {card.title}
                  </Link>
                </h3>
                <p>{card.description}</p>
              </article>
            ))}
          </div>
          <p className="intro-faq-link">
            {introCopy.entries.faqLead}{' '}
            <Link to={introCopy.entries.faqTo}>{introCopy.entries.faqLabel}</Link>
          </p>
        </div>
      </section>
    </main>
  )
}

function SectionHeading({
  eyebrow,
  id,
  title,
  intro,
}: {
  eyebrow: string
  id: string
  title: string
  intro: string
}) {
  return (
    <header className="intro-section-heading">
      <p className="intro-eyebrow">{eyebrow}</p>
      <h2 id={id}>{title}</h2>
      <p>{intro}</p>
    </header>
  )
}
