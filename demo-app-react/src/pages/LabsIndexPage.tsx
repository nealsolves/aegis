import { ArrowRight } from 'lucide-react'
import { Link } from 'react-router-dom'

const LAB_GROUPS = [
  {
    title: 'Decisions',
    description: 'Compare judgments and see where enforcement changes an AI call.',
    labs: [
      { number: 9, title: 'Governed vs. Ungoverned' },
      { number: 10, title: 'Split Enforcement' },
      { number: 1, title: 'Risk Scoring' },
    ],
  },
  {
    title: 'Policies and gates',
    description: 'Build, load, and extend the rules applied at the governance boundary.',
    labs: [
      { number: 4, title: 'Policy Composition' },
      { number: 5, title: 'Loaders and Versioning' },
      { number: 6, title: 'Custom Gates' },
    ],
  },
  {
    title: 'Evidence',
    description: 'Inspect integrity, audit history, and operator-facing records.',
    labs: [
      { number: 2, title: 'Signing and Verification' },
      { number: 3, title: 'Audit Chain' },
      { number: 7, title: 'Compliance Dashboard' },
    ],
  },
  {
    title: 'Systems and workflows',
    description: 'Govern retrieval, multi-step sessions, and adapter-normalized evidence.',
    labs: [
      { number: 8, title: 'Governed Knowledge Base' },
      { number: 11, title: 'Workflow Governance' },
      { number: 12, title: 'Integration Adapters' },
    ],
  },
] as const

const RECOMMENDED = [
  { number: 9, title: 'Compare the boundary' },
  { number: 10, title: 'See the split' },
  { number: 11, title: 'Govern a workflow' },
] as const

export default function LabsIndexPage() {
  return (
    <main className="labs-index">
      <header className="labs-index__hero">
        <p className="scenario-kicker">Focused controls</p>
        <h1>Choose a governance question.</h1>
        <p>
          Each lab isolates one AEGIS capability. Existing deep links remain
          stable, and the recommended path starts with the product decision
          before moving into enforcement and workflow evidence.
        </p>
      </header>

      <nav
        className="labs-recommended"
        aria-label="Recommended first visit"
      >
        <div className="labs-recommended__heading">
          <p>Recommended first visit</p>
          <h2>Follow the boundary from decision to workflow.</h2>
        </div>
        <ol>
          {RECOMMENDED.map((lab, index) => (
            <li key={lab.number}>
              <Link to={`/lab/${lab.number}`}>
                <span>Lab {lab.number}</span>
                <strong>{lab.title}</strong>
              </Link>
              {index < RECOMMENDED.length - 1 && (
                <ArrowRight aria-hidden="true" />
              )}
            </li>
          ))}
        </ol>
      </nav>

      <div className="labs-groups" data-testid="grouped-labs">
        {LAB_GROUPS.map(group => (
          <section
            className="labs-group"
            aria-labelledby={`labs-${group.title.toLowerCase().replace(/ /g, '-')}`}
            key={group.title}
          >
            <div className="labs-group__heading">
              <h2 id={`labs-${group.title.toLowerCase().replace(/ /g, '-')}`}>
                {group.title}
              </h2>
              <p>{group.description}</p>
            </div>
            <div className="labs-group__cards">
              {group.labs.map(lab => (
                <Link
                  className="lab-index-card"
                  to={`/lab/${lab.number}`}
                  key={lab.number}
                >
                  <span>Lab {lab.number}</span>
                  <strong>{lab.title}</strong>
                  <ArrowRight aria-hidden="true" />
                </Link>
              ))}
            </div>
          </section>
        ))}
      </div>
    </main>
  )
}
