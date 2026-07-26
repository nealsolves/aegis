import type { CSSProperties } from 'react'
import type { LabMeta } from '@/content/labCatalog'

const KICKER_COLORS = {
  '--lab-accent-light': 'var(--ibm-blue-60)',
  '--lab-accent-dark': 'var(--ibm-cyan-30)',
} as CSSProperties

export default function LabHero({ lab }: { lab: LabMeta }) {
  return (
    <header className="lab-route__hero" style={KICKER_COLORS}>
      <p className="scenario-kicker">{lab.eyebrow}</p>
      <h1>{lab.heroTitle}</h1>
      <p>{lab.description}</p>
    </header>
  )
}
