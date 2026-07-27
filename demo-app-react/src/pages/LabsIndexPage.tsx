import { ArrowRight } from 'lucide-react'
import { Link } from 'react-router-dom'
import { FIRST_VISIT_LABS, LAB_GROUPS, LABS_BY_ID } from '@/content/labCatalog'

export default function LabsIndexPage() {
  return (
    <main className="labs-index">
      <header className="labs-index__hero">
        <p className="scenario-kicker">Capability labs</p>
        <h1>See where governance changes the outcome.</h1>
        <p>
          Follow a first path through the governance boundary, or go directly
          to the control you want to inspect.
        </p>
      </header>

      <nav className="labs-journey" aria-label="First-visit path">
        <div className="labs-journey__heading">
          <p>First visit</p>
          <h2>Follow one request from decision to workflow.</h2>
        </div>
        <ol>
          {FIRST_VISIT_LABS.map((lab, index) => (
            <li key={lab.id}>
              <Link to={lab.path}>
                <span>{lab.journey!.phase}</span>
                <strong>{lab.journey!.action}</strong>
                <span className="labs-journey__lab-title">{lab.title}</span>
              </Link>
              {index < FIRST_VISIT_LABS.length - 1 && (
                <ArrowRight aria-hidden="true" />
              )}
            </li>
          ))}
        </ol>
      </nav>

      <section
        className="labs-groups"
        data-testid="grouped-labs"
        aria-label="Labs by capability"
      >
        {LAB_GROUPS.map(group => (
          <section
            className="labs-group"
            aria-labelledby={`labs-${group.id}`}
            key={group.id}
          >
            <div className="labs-group__heading">
              <p>Capability group</p>
              <h2 id={`labs-${group.id}`}>{group.title}</h2>
              <h3>{group.question}</h3>
              <p>{group.description}</p>
            </div>
            <div className="labs-group__cards">
              {group.labIds.map(id => {
                const lab = LABS_BY_ID[id]
                return (
                  <Link className="lab-index-card" to={lab.path} key={lab.id}>
                    <strong>{lab.title}</strong>
                    <span>{lab.description}</span>
                    <ArrowRight aria-hidden="true" />
                  </Link>
                )
              })}
            </div>
          </section>
        ))}
      </section>
    </main>
  )
}
