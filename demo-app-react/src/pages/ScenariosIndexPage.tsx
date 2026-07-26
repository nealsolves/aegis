import { ArrowRight } from 'lucide-react'
import { Link } from 'react-router-dom'
import {
  SCENARIO_CONTENT,
  SCENARIO_ORDER,
} from '@/routes/scenarios/scenarioContent'

export default function ScenariosIndexPage() {
  return (
    <main className="scenarios-index">
      <header className="scenarios-index__hero">
        <p className="scenario-kicker">Deterministic roleplay</p>
        <h1>Make the judgment. Inspect the evidence.</h1>
        <p>
          Take a role in three fictional incidents. Your choice selects a
          server-defined run; the current response supplies every AEGIS
          decision, gate, and artifact shown on the page.
        </p>
      </header>

      <section
        className="scenarios-index__list"
        aria-labelledby="scenarios-index-title"
      >
        <div className="scenarios-index__label">
          <span>Case files</span>
          <h2 id="scenarios-index-title">Choose an incident</h2>
        </div>
        <div className="scenarios-index__cards">
          {SCENARIO_ORDER.map((scenarioId, index) => {
            const scenario = SCENARIO_CONTENT[scenarioId]
            return (
              <article className="scenario-index-card" key={scenario.id}>
                <span className="scenario-index-card__number">
                  {String(index + 1).padStart(2, '0')}
                </span>
                <p>{scenario.visitorRole}</p>
                <h3>{scenario.title}</h3>
                <p>{scenario.incident}</p>
                <Link to={`/demo/scenarios/${scenario.id}`}>
                  Open case file
                  <ArrowRight aria-hidden="true" />
                </Link>
              </article>
            )
          })}
        </div>
      </section>
    </main>
  )
}
