import type { CSSProperties } from 'react'
import { LAB_COLORS, IBM_COLORS } from '@/theme/tokens'
import type { LabMeta } from '@/content/labCatalog'

// Dark-mode overrides for labs whose base color is too dark on a navy bg
const LAB_COLORS_DARK: Record<number, string> = {
  1: IBM_COLORS.blue40,   // blue60 → blue40 (#78a9ff)
  6: IBM_COLORS.teal30,   // teal60 → teal30 (#3ddbd9)
}

// Light-mode overrides for labs whose base color has insufficient contrast on a blue-60 hero bg
const LAB_COLORS_LIGHT: Record<number, string> = {
  1: '#ffffff',           // blue60 (same as bg) → white
  5: '#ffffff',           // cyan30 (too similar to blue-60) → white
  6: IBM_COLORS.teal30,   // teal60 (too dark) → teal30 (#3ddbd9)
  7: '#ffffff',           // blue40 (too similar to blue-60) → white
}

export default function LabHero({ lab }: { lab: LabMeta }) {
  const accentColors = {
    '--lab-accent-light': LAB_COLORS_LIGHT[lab.id]
      ?? LAB_COLORS[lab.id]
      ?? 'var(--ibm-cyan-30)',
    '--lab-accent-dark': LAB_COLORS_DARK[lab.id]
      ?? LAB_COLORS[lab.id]
      ?? 'var(--ibm-blue-40)',
  } as CSSProperties

  return (
    <header className="lab-route__hero" style={accentColors}>
      <p className="scenario-kicker">{lab.eyebrow}</p>
      <h1>{lab.heroTitle}</h1>
      <p>{lab.description}</p>
    </header>
  )
}
