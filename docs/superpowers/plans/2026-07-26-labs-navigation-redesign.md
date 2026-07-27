# Labs Navigation Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace visitor-facing lab numbering with a guided, capability-grouped Labs experience while preserving every legacy route, the Help drawer behavior, and exactly one main landmark per lab page.

**Architecture:** Add a typed lab catalog as the only source of public lab metadata, then have the Labs index, route shell, related navigation, journey continuation, and Help drawer consume it. A shared `LabRouteLayout` will own the number-free hero and the single route-level `<main>` landmark; existing lab bodies remain responsible for their experiments and API state.

**Tech Stack:** React 19, TypeScript 5.9, React Router 7, Vitest 4, Testing Library, Vite 8, existing IBM Plex and IBM Carbon-inspired CSS tokens.

## Global Constraints

- Keep `#/lab/1` through `#/lab/12` unchanged; numeric IDs are compatibility identifiers only.
- Show no `Lab N` numbering in the Labs index, lab route chrome, related navigation, or Help drawer titles and accessible names.
- Preserve the Help drawer launcher, route-specific content, result help, focus trap, Escape behavior, and focus restoration.
- Every `#/lab/1` through `#/lab/12` route must contain exactly one `<main>` and no nested `<main>`.
- Use the demo's existing IBM Plex typography roles, light/dark theme tokens, square-edged layout language, and visible focus treatment.
- Primary labels and controls such as `Without AEGIS` must use readable body/utility text, never eyebrow-sized microcopy.
- Links and buttons must provide a target of at least 44 by 44 CSS pixels.
- Keep status and current-page meaning independent of color alone.
- Fix the Guide launcher to the viewport's bottom-right on routes that already
  have guide content: Architecture and `/lab/1` through `/lab/12`.
- Do not render the Guide launcher on Scenarios, the Labs landing page, FAQ, or
  other routes without existing guide content.
- Keep the fixed launcher clear of viewport safe areas and other fixed controls;
  it must not make underlying controls unreachable.
- Do not implement Vertex AI or Google ADK; keep Integration Adapters structurally ready to add them later.
- Do not change lab execution, API calls, provider claims, policies, artifacts, or workflow behavior.

---

## File map

### New files

- `demo-app-react/src/content/labCatalog.ts` — typed, public lab metadata, capability groups, first-visit journey, and lookup helpers.
- `demo-app-react/src/content/labCatalog.test.ts` — catalog completeness, ordering, route stability, and number-free public-copy tests.
- `demo-app-react/src/components/layout/LabContextNav.tsx` — `All labs › Capability` route context.
- `demo-app-react/src/components/layout/LabRelatedNav.tsx` — links for other labs in the current capability, including `aria-current`.
- `demo-app-react/src/components/layout/LabRouteLayout.tsx` — one-main route shell, hero, experiment region, related navigation, and optional journey continuation.
- `demo-app-react/src/components/layout/LabRouteLayout.test.tsx` — shell semantics, descriptive labels, current state, and continuation behavior.

### Modified files

- `demo-app-react/src/content/demoCopy.ts` — remove the superseded `labRoutesCopy` and `labNavCopy` constants after all consumers move to the catalog.
- `demo-app-react/src/pages/LabsIndexPage.tsx` — render the approved guided capability map from the shared catalog.
- `demo-app-react/src/pages/LabsIndexPage.test.tsx` — assert capability questions, number-free journey copy, route coverage, and no public numbering.
- `demo-app-react/src/components/layout/LabHero.tsx` — render a semantic, number-free hero from `LabMeta`.
- `demo-app-react/src/App.tsx` — remove the global numbered strip and wrap all twelve lab bodies with `LabRouteLayout`.
- `demo-app-react/src/App.test.tsx` — cover all lab deep links, one-main semantics, number-free chrome, removal of the old strip, and route-scoped floating Guide behavior.
- `demo-app-react/src/labs/Lab12IntegrationAdapters.tsx` — replace its nested `<main>` and internal `<h1>` so the shared route shell owns the landmark and page title.
- `demo-app-react/src/components/HelpDrawer.tsx` — derive a number-free dialog title from the shared catalog.
- `demo-app-react/src/components/HelpDrawer.test.tsx` — update title expectations while retaining all interaction regressions.
- `demo-app-react/src/index.css` — replace old lab-strip styles, refine the Labs index, and add responsive route-shell styles.

### Deleted file

- `demo-app-react/src/components/layout/LabTabs.tsx` — the flat numbered twelve-item strip is replaced by capability context and related navigation.

---

### Task 1: Establish the shared lab catalog

**Files:**

- Create: `demo-app-react/src/content/labCatalog.ts`
- Create: `demo-app-react/src/content/labCatalog.test.ts`

**Interfaces:**

- Produces:
  - `type LabCapabilityId`
  - `interface LabMeta`
  - `interface LabCapabilityGroup`
  - `const LABS: readonly LabMeta[]`
  - `const LABS_BY_ID: Readonly<Record<number, LabMeta>>`
  - `const LAB_GROUPS: readonly LabCapabilityGroup[]`
  - `const FIRST_VISIT_LABS: readonly LabMeta[]`
  - `function getLabById(id: number): LabMeta | undefined`
  - `function getLabGroup(capability: LabCapabilityId): LabCapabilityGroup`
- Consumes: no new interfaces.

- [ ] **Step 1: Write the failing catalog tests**

Create `demo-app-react/src/content/labCatalog.test.ts`:

```ts
import {
  FIRST_VISIT_LABS,
  LABS,
  LAB_GROUPS,
  getLabById,
  getLabGroup,
} from './labCatalog'

describe('labCatalog', () => {
  it('contains every stable lab route exactly once', () => {
    expect(LABS.map(lab => lab.id)).toEqual(
      Array.from({ length: 12 }, (_, index) => index + 1),
    )
    expect(new Set(LABS.map(lab => lab.id)).size).toBe(12)
    expect(LABS.map(lab => lab.path)).toEqual(
      Array.from({ length: 12 }, (_, index) => `/lab/${index + 1}`),
    )
  })

  it('groups every lab in the approved capability order', () => {
    expect(LAB_GROUPS.map(group => [group.title, group.question, group.labIds]))
      .toEqual([
        ['Decisions', 'What should happen?', [9, 10, 1]],
        ['Policies and gates', 'Which rules apply?', [4, 5, 6]],
        ['Evidence', 'What can you prove?', [2, 3, 7]],
        ['Systems and workflows', 'How does it connect?', [8, 11, 12]],
      ])
  })

  it('defines the approved number-free first-visit journey', () => {
    expect(
      FIRST_VISIT_LABS.map(lab => [
        lab.id,
        lab.journey?.phase,
        lab.journey?.action,
      ]),
    ).toEqual([
      [9, 'Request', 'Compare enforcement'],
      [10, 'Boundary', 'Explore checkpoints'],
      [11, 'Workflow', 'Govern the handoff'],
    ])
  })

  it('keeps visitor-facing catalog strings free of Lab N labels', () => {
    const publicCopy = [
      ...LABS.flatMap(lab => [
        lab.title,
        lab.heroTitle,
        lab.eyebrow,
        lab.description,
        lab.journey?.phase ?? '',
        lab.journey?.action ?? '',
      ]),
      ...LAB_GROUPS.flatMap(group => [
        group.title,
        group.question,
        group.description,
      ]),
    ].join(' ')

    expect(publicCopy).not.toMatch(/\bLab\s+\d+\b/)
  })

  it('resolves labs and groups through typed lookup helpers', () => {
    expect(getLabById(9)?.heroTitle).toBe('Governed vs. Ungoverned')
    expect(getLabById(99)).toBeUndefined()
    expect(getLabGroup('systems-workflows').labIds).toEqual([8, 11, 12])
  })
})
```

- [ ] **Step 2: Run the catalog test and verify it fails**

Run:

```bash
cd demo-app-react
npm test -- src/content/labCatalog.test.ts
```

Expected: FAIL because `./labCatalog` does not exist.

- [ ] **Step 3: Add the typed catalog**

Create `demo-app-react/src/content/labCatalog.ts` with these public interfaces:

```ts
export type LabCapabilityId =
  | 'decisions'
  | 'policies-gates'
  | 'evidence'
  | 'systems-workflows'

export interface LabJourney {
  order: number
  phase: 'Request' | 'Boundary' | 'Workflow'
  action: string
}

export interface LabMeta {
  id: number
  path: string
  title: string
  shortTitle: string
  heroTitle: string
  capability: LabCapabilityId
  eyebrow: string
  description: string
  journey?: LabJourney
}

export interface LabCapabilityGroup {
  id: LabCapabilityId
  title: string
  question: string
  description: string
  labIds: readonly number[]
}
```

Populate `LABS` with the approved public copy:

```ts
export const LABS: readonly LabMeta[] = [
  {
    id: 1,
    path: '/lab/1',
    title: 'Risk Scoring',
    shortTitle: 'Risk',
    heroTitle: 'Risk Scoring',
    capability: 'decisions',
    eyebrow: 'Decision signal',
    description:
      'See how invocation signals produce a risk score and change enforcement.',
  },
  {
    id: 2,
    path: '/lab/2',
    title: 'Signing and Verification',
    shortTitle: 'Sign',
    heroTitle: 'Signing and Verification',
    capability: 'evidence',
    eyebrow: 'Evidence integrity',
    description:
      'Sign a governance artifact, verify it, and inspect what changes when the record is altered.',
  },
  {
    id: 3,
    path: '/lab/3',
    title: 'Audit Chain',
    shortTitle: 'Chain',
    heroTitle: 'Audit Chain',
    capability: 'evidence',
    eyebrow: 'Evidence history',
    description:
      'Link governance records into an ordered history and verify the chain.',
  },
  {
    id: 4,
    path: '/lab/4',
    title: 'Policy Composition',
    shortTitle: 'Compose',
    heroTitle: 'Policy Composition',
    capability: 'policies-gates',
    eyebrow: 'Policy construction',
    description:
      'Combine policy sources and inspect the rules applied at the boundary.',
  },
  {
    id: 5,
    path: '/lab/5',
    title: 'Loaders and Versioning',
    shortTitle: 'Loaders',
    heroTitle: 'Loaders and Versioning',
    capability: 'policies-gates',
    eyebrow: 'Policy lifecycle',
    description:
      'Load policy definitions and see how versions remain visible in governance evidence.',
  },
  {
    id: 6,
    path: '/lab/6',
    title: 'Custom Gates',
    shortTitle: 'Gates',
    heroTitle: 'Custom Gates',
    capability: 'policies-gates',
    eyebrow: 'Policy extension',
    description:
      'Add a focused governance check and inspect how it changes the decision.',
  },
  {
    id: 7,
    path: '/lab/7',
    title: 'Compliance Dashboard',
    shortTitle: 'Comply',
    heroTitle: 'Compliance Dashboard',
    capability: 'evidence',
    eyebrow: 'Operator evidence',
    description:
      'Review governance records as an operator and inspect the evidence behind each status.',
  },
  {
    id: 8,
    path: '/lab/8',
    title: 'Governed Knowledge Base',
    shortTitle: 'Knowledge base',
    heroTitle: 'Governed Knowledge Base',
    capability: 'systems-workflows',
    eyebrow: 'Governed retrieval',
    description:
      'Apply policy to retrieval and inspect the evidence returned with the knowledge result.',
  },
  {
    id: 9,
    path: '/lab/9',
    title: 'Governed vs. Ungoverned',
    shortTitle: 'Compare',
    heroTitle: 'Governed vs. Ungoverned',
    capability: 'decisions',
    eyebrow: 'Decision boundary',
    description:
      'Run the same request with and without policy enforcement, then compare the outcomes and evidence.',
    journey: { order: 1, phase: 'Request', action: 'Compare enforcement' },
  },
  {
    id: 10,
    path: '/lab/10',
    title: 'Split Enforcement',
    shortTitle: 'Split',
    heroTitle: 'Split Enforcement Explorer',
    capability: 'decisions',
    eyebrow: 'Enforcement boundary',
    description:
      'Inspect the checks before an AI call and the checks applied after a result returns.',
    journey: { order: 2, phase: 'Boundary', action: 'Explore checkpoints' },
  },
  {
    id: 11,
    path: '/lab/11',
    title: 'Workflow Governance',
    shortTitle: 'Workflow',
    heroTitle: 'Workflow Governance',
    capability: 'systems-workflows',
    eyebrow: 'Workflow boundary',
    description:
      'Govern participants, transitions, approvals, and evidence across a multi-step session.',
    journey: { order: 3, phase: 'Workflow', action: 'Govern the handoff' },
  },
  {
    id: 12,
    path: '/lab/12',
    title: 'Integration Adapters',
    shortTitle: 'Adapters',
    heroTitle: 'Integration Adapters',
    capability: 'systems-workflows',
    eyebrow: 'Provider boundary',
    description:
      'Inspect how supported adapters normalize provider and protocol evidence for governance.',
  },
]
```

Use these capability-group definitions:

```ts
export const LAB_GROUPS: readonly LabCapabilityGroup[] = [
  {
    id: 'decisions',
    title: 'Decisions',
    question: 'What should happen?',
    description: 'Compare judgments and see where enforcement changes an AI call.',
    labIds: [9, 10, 1],
  },
  {
    id: 'policies-gates',
    title: 'Policies and gates',
    question: 'Which rules apply?',
    description: 'Build, load, and extend the rules applied at the governance boundary.',
    labIds: [4, 5, 6],
  },
  {
    id: 'evidence',
    title: 'Evidence',
    question: 'What can you prove?',
    description: 'Inspect integrity, audit history, and operator-facing records.',
    labIds: [2, 3, 7],
  },
  {
    id: 'systems-workflows',
    title: 'Systems and workflows',
    question: 'How does it connect?',
    description: 'Govern retrieval, multi-step sessions, and adapter-normalized evidence.',
    labIds: [8, 11, 12],
  },
]
```

Use these lookup implementations:

```ts
export const LABS_BY_ID = Object.freeze(
  Object.fromEntries(LABS.map(lab => [lab.id, lab])),
) as Readonly<Record<number, LabMeta>>

export const FIRST_VISIT_LABS: readonly LabMeta[] = Object.freeze(
  LABS
    .filter(lab => lab.journey !== undefined)
    .sort((left, right) => left.journey!.order - right.journey!.order),
)

export function getLabById(id: number): LabMeta | undefined {
  return LABS_BY_ID[id]
}

export function getLabGroup(
  capability: LabCapabilityId,
): LabCapabilityGroup {
  const group = LAB_GROUPS.find(candidate => candidate.id === capability)
  if (!group) {
    throw new Error(`Unknown lab capability: ${capability}`)
  }
  return group
}
```

- [ ] **Step 4: Run the catalog tests**

Run:

```bash
cd demo-app-react
npm test -- src/content/labCatalog.test.ts
```

Expected: PASS with five tests.

- [ ] **Step 5: Run type checking through the production build**

Run:

```bash
cd demo-app-react
npm run build
```

Expected: PASS. The existing application still uses `labRoutesCopy` until Task
3 moves all route and navigation consumers to the catalog.

- [ ] **Step 6: Commit the catalog**

```bash
git add \
  demo-app-react/src/content/labCatalog.ts \
  demo-app-react/src/content/labCatalog.test.ts
git commit -m "refactor(demo): centralize lab discovery metadata"
```

---

### Task 2: Redesign the Labs index as a guided capability map

**Files:**

- Modify: `demo-app-react/src/pages/LabsIndexPage.tsx`
- Modify: `demo-app-react/src/pages/LabsIndexPage.test.tsx`
- Modify: `demo-app-react/src/index.css:2163-2369`

**Interfaces:**

- Consumes: `LABS_BY_ID`, `LAB_GROUPS`, and `FIRST_VISIT_LABS` from
  `@/content/labCatalog`.
- Produces: a number-free Labs index with navigation regions named
  `First-visit journey` and `Labs by capability`.

- [ ] **Step 1: Replace the index tests with number-free behavior**

Update `LabsIndexPage.test.tsx` to assert:

```ts
const EXPECTED_GROUPS = {
  Decisions: [
    ['Governed vs. Ungoverned', '/lab/9'],
    ['Split Enforcement', '/lab/10'],
    ['Risk Scoring', '/lab/1'],
  ],
  'Policies and gates': [
    ['Policy Composition', '/lab/4'],
    ['Loaders and Versioning', '/lab/5'],
    ['Custom Gates', '/lab/6'],
  ],
  Evidence: [
    ['Signing and Verification', '/lab/2'],
    ['Audit Chain', '/lab/3'],
    ['Compliance Dashboard', '/lab/7'],
  ],
  'Systems and workflows': [
    ['Governed Knowledge Base', '/lab/8'],
    ['Workflow Governance', '/lab/11'],
    ['Integration Adapters', '/lab/12'],
  ],
} as const
```

Add these focused assertions:

```ts
it('shows the approved number-free first-visit journey', () => {
  renderPage()
  const journey = screen.getByRole('navigation', {
    name: 'First-visit journey',
  })
  const links = within(journey).getAllByRole('link')

  expect(links.map(link => link.getAttribute('href'))).toEqual([
    '/lab/9',
    '/lab/10',
    '/lab/11',
  ])
  expect(links.map(link => link.textContent)).toEqual([
    expect.stringContaining('Compare enforcement'),
    expect.stringContaining('Explore checkpoints'),
    expect.stringContaining('Govern the handoff'),
  ])
})

it('does not expose historical lab numbers', () => {
  const { container } = renderPage()
  expect(container.textContent).not.toMatch(/\bLab\s+\d+\b/)
})
```

Retain the existing route-coverage assertion that destinations sort to
`/lab/1` through `/lab/12`.

- [ ] **Step 2: Run the index tests and verify they fail**

Run:

```bash
cd demo-app-react
npm test -- src/pages/LabsIndexPage.test.tsx
```

Expected: FAIL because the current page renders `Lab 9`, `Lab 10`, and other
numbered labels and uses the old heading.

- [ ] **Step 3: Render the approved guided capability map**

Replace local `LAB_GROUPS` and `RECOMMENDED` constants with catalog imports.
Use this structure:

```tsx
<main className="labs-index">
  <header className="labs-index__hero">
    <p className="scenario-kicker">Capability labs</p>
    <h1>See where governance changes the outcome.</h1>
    <p>
      Follow a first journey through the governance boundary, or go directly
      to the control you want to inspect.
    </p>
  </header>

  <nav className="labs-journey" aria-label="First-visit journey">
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
```

Each journey link renders `lab.journey.phase`, `lab.journey.action`, and the
descriptive `lab.title`. Each capability heading renders its `title`,
`question`, and `description`. Each card renders only descriptive copy and its
arrow icon.

- [ ] **Step 4: Refine the index CSS without introducing a new theme**

In `index.css`:

- rename `.labs-recommended*` selectors to `.labs-journey*`;
- keep the connected three-step region as the one visually prominent element;
- set journey and card links to `min-height: 2.75rem`;
- keep primary card titles at `font-size: 1rem` or larger;
- keep group questions at `font-size: clamp(1.25rem, 2vw, 1.625rem)`;
- use existing `--bg-*`, `--text-*`, `--border-ui`, `--ibm-blue-60`, and
  `--ibm-cyan-30` tokens;
- preserve the current one-column collapse below `48rem`;
- make the journey intelligible when arrow icons are hidden on phones.

Do not copy the tiny font sizes used inside the brainstorming wireframe.

- [ ] **Step 5: Run focused index and copy tests**

Run:

```bash
cd demo-app-react
npm test -- src/pages/LabsIndexPage.test.tsx
npm run copycheck
```

Expected: both commands PASS.

- [ ] **Step 6: Commit the number-free index**

```bash
git add \
  demo-app-react/src/pages/LabsIndexPage.tsx \
  demo-app-react/src/pages/LabsIndexPage.test.tsx \
  demo-app-react/src/index.css
git commit -m "feat(demo): guide lab discovery by capability"
```

---

### Task 3: Add the shared lab route shell and single-main landmark

**Files:**

- Create: `demo-app-react/src/components/layout/LabContextNav.tsx`
- Create: `demo-app-react/src/components/layout/LabRelatedNav.tsx`
- Create: `demo-app-react/src/components/layout/LabRouteLayout.tsx`
- Create: `demo-app-react/src/components/layout/LabRouteLayout.test.tsx`
- Modify: `demo-app-react/src/components/layout/LabHero.tsx`
- Delete: `demo-app-react/src/components/layout/LabTabs.tsx`
- Modify: `demo-app-react/src/content/demoCopy.ts:47-89`
- Modify: `demo-app-react/src/App.tsx:8-126`
- Modify: `demo-app-react/src/App.test.tsx:73-106`
- Modify: `demo-app-react/src/labs/Lab12IntegrationAdapters.tsx:318-441`
- Modify: `demo-app-react/src/index.css:175-228,2163-2369,2990-3100`

**Interfaces:**

- Consumes:
  - `LabMeta`, `LABS`, `LABS_BY_ID`, and `getLabGroup` from
    `@/content/labCatalog`;
  - existing lab body components as `children`;
  - optional `onResultHelpContext` behavior remains in Lab 12.
- Produces:
  - `LabContextNav({ lab }: { lab: LabMeta })`
  - `LabRelatedNav({ lab }: { lab: LabMeta })`
  - `LabRouteLayout({ lab, children }: { lab: LabMeta; children: ReactNode })`
  - `LabHero({ lab }: { lab: LabMeta })`

- [ ] **Step 1: Write route-shell component tests**

Create `LabRouteLayout.test.tsx`:

```tsx
import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { LABS_BY_ID } from '@/content/labCatalog'
import LabRouteLayout from './LabRouteLayout'

function renderLayout(labId: number) {
  return render(
    <MemoryRouter>
      <LabRouteLayout lab={LABS_BY_ID[labId]}>
        <section aria-label="Experiment">Experiment body</section>
      </LabRouteLayout>
    </MemoryRouter>,
  )
}

describe('LabRouteLayout', () => {
  it('owns one main landmark and a descriptive page heading', () => {
    const { container } = renderLayout(9)
    expect(container.querySelectorAll('main')).toHaveLength(1)
    expect(
      screen.getByRole('heading', { level: 1, name: 'Governed vs. Ungoverned' }),
    ).toBeInTheDocument()
    expect(container.textContent).not.toMatch(/\bLab\s+9\b/)
  })

  it('shows capability context and related labs', () => {
    renderLayout(9)
    const context = screen.getByRole('navigation', { name: 'Lab context' })
    expect(within(context).getByRole('link', { name: 'All labs' }))
      .toHaveAttribute('href', '/demo/labs')
    expect(within(context).getByText('Decisions')).toBeInTheDocument()

    const related = screen.getByRole('navigation', {
      name: 'Also in Decisions',
    })
    expect(within(related).getByRole('link', {
      name: 'Governed vs. Ungoverned',
    })).toHaveAttribute('aria-current', 'page')
    expect(within(related).getByRole('link', {
      name: 'Split Enforcement',
    })).toHaveAttribute('href', '/lab/10')
  })

  it('shows continuation only for the first-visit path', () => {
    const journey = renderLayout(9)
    expect(screen.getByRole('navigation', {
      name: 'Continue the first-visit path',
    })).toHaveTextContent('Explore checkpoints')

    journey.unmount()
    renderLayout(1)
    expect(screen.queryByRole('navigation', {
      name: 'Continue the first-visit path',
    })).not.toBeInTheDocument()
  })
})
```

- [ ] **Step 2: Write the all-route landmark regression in `App.test.tsx`**

Replace the old “shows lab tabs” test with:

```ts
it.each(Array.from({ length: 12 }, (_, index) => index + 1))(
  'keeps /lab/%s stable with exactly one main landmark',
  labId => {
    const { container } = renderRoute(`#/lab/${labId}`)
    expect(container.querySelectorAll('main')).toHaveLength(1)
    expect(
      screen.queryByRole('navigation', { name: 'Lab navigation' }),
    ).not.toBeInTheDocument()
  },
)
```

Add a descriptive chrome check:

```ts
it('uses capability context instead of historical numbering', () => {
  const { container } = renderRoute('#/lab/9')
  expect(
    screen.getByRole('heading', {
      level: 1,
      name: 'Governed vs. Ungoverned',
    }),
  ).toBeInTheDocument()
  expect(
    screen.getByRole('navigation', { name: 'Also in Decisions' }),
  ).toBeInTheDocument()
  expect(screen.getByRole('main')).not.toHaveTextContent(/\bLab\s+\d+\b/)
})
```

Replace the old `places the shared Guide launcher in a content-reserved rail`
test with route-scoped behavior:

```ts
it('shows the Guide launcher only where guide content exists', () => {
  const architecture = renderRoute('#/demo/architecture')
  expect(
    screen.getByRole('button', { name: 'Open lab guide' }),
  ).toBeInTheDocument()

  architecture.unmount()
  renderRoute('#/demo/scenarios/atlas')
  expect(
    screen.queryByRole('button', { name: 'Open lab guide' }),
  ).not.toBeInTheDocument()

  cleanup()
  renderRoute('#/demo/labs')
  expect(
    screen.queryByRole('button', { name: 'Open lab guide' }),
  ).not.toBeInTheDocument()

  cleanup()
  renderRoute('#/lab/9')
  expect(
    screen.getByRole('button', { name: 'Open lab guide' }),
  ).toBeInTheDocument()
})
```

- [ ] **Step 3: Run focused tests and verify they fail**

Run:

```bash
cd demo-app-react
npm test -- \
  src/components/layout/LabRouteLayout.test.tsx \
  src/App.test.tsx
```

Expected: FAIL because the route-shell components do not exist and legacy lab
routes have zero `<main>` elements.

- [ ] **Step 4: Implement the context and related navigation**

`LabContextNav.tsx` renders:

```tsx
<nav className="lab-context" aria-label="Lab context">
  <div className="lab-context__inner">
    <Link to="/demo/labs">All labs</Link>
    <ChevronRight aria-hidden="true" />
    <span>{group.title}</span>
  </div>
</nav>
```

`LabRelatedNav.tsx` renders all `group.labIds` as links and marks the active one:

```tsx
<nav
  className="lab-related"
  aria-label={`Also in ${group.title}`}
>
  <p>Also in {group.title}</p>
  <ul>
    {group.labIds.map(id => {
      const relatedLab = LABS_BY_ID[id]
      const isCurrent = relatedLab.id === lab.id
      return (
        <li key={relatedLab.id}>
          <Link
            to={relatedLab.path}
            aria-current={isCurrent ? 'page' : undefined}
          >
            {relatedLab.title}
            {!isCurrent && <ArrowRight aria-hidden="true" />}
          </Link>
        </li>
      )
    })}
  </ul>
</nav>
```

- [ ] **Step 5: Convert `LabHero` to semantic, catalog-driven content**

Change its props to `{ lab: LabMeta }`. Continue using `lab.id` for existing
theme-aware accent lookup, but render no numeric text:

```tsx
<header className="lab-route__hero">
  <p className="scenario-kicker">{lab.eyebrow}</p>
  <h1>{lab.heroTitle}</h1>
  <p>{lab.description}</p>
</header>
```

Remove the decorative down-arrow suffix. The application-level Help launcher
remains outside the route shell and will be made viewport-fixed in Step 9.

- [ ] **Step 6: Implement `LabRouteLayout`**

Use this structure:

```tsx
export default function LabRouteLayout({
  lab,
  children,
}: {
  lab: LabMeta
  children: ReactNode
}) {
  const nextJourneyLab = lab.journey
    ? FIRST_VISIT_LABS[lab.journey.order]
    : undefined

  return (
    <main className="lab-route">
      <LabContextNav lab={lab} />
      <LabHero lab={lab} />
      <div className="lab-route__layout">
        <div className="lab-route__experiment">{children}</div>
        <LabRelatedNav lab={lab} />
      </div>
      {nextJourneyLab && (
        <nav
          className="lab-route__continue"
          aria-label="Continue the first-visit path"
        >
          <p>Continue the first-visit path</p>
          <Link to={nextJourneyLab.path}>
            Next: {nextJourneyLab.journey!.action}
            <ArrowRight aria-hidden="true" />
          </Link>
        </nav>
      )}
    </main>
  )
}
```

The array access is intentional: journey order is one-based, so order `1`
selects array index `1`, the next step. The final journey entry produces
`undefined` and therefore no continuation.

- [ ] **Step 7: Wrap all routes and remove the flat strip**

In `App.tsx`:

- import `LABS`, `LABS_BY_ID`, and `getLabById` from the catalog;
- remove `LabTabs`, `LabHero`, and `labRoutesCopy` imports;
- remove `showLabTabs` from `RouteDescriptor` and `describeRoute`;
- remove the application-level `<LabTabs>`;
- wrap each lab body with `LabRouteLayout`.

Retain the existing `helpLabId` route rule: Architecture and known lab routes
have guide content, while Scenarios, the Labs landing page, FAQ, and unknown
routes do not render the launcher.

Inside `AppContent`, define the route bodies after
`handleResultHelpContext` is available:

```tsx
const labRoutes = [
  { lab: LABS_BY_ID[1], body: <Lab1RiskScoring /> },
  { lab: LABS_BY_ID[2], body: <Lab2Signing /> },
  { lab: LABS_BY_ID[3], body: <Lab3AuditChain /> },
  { lab: LABS_BY_ID[4], body: <Lab4Composition /> },
  { lab: LABS_BY_ID[5], body: <Lab5Loaders /> },
  { lab: LABS_BY_ID[6], body: <Lab6CustomGates /> },
  { lab: LABS_BY_ID[7], body: <Lab7Compliance /> },
  { lab: LABS_BY_ID[8], body: <Lab8GovernedKnowledgeBase /> },
  { lab: LABS_BY_ID[9], body: <Lab9GovernedVsUngoverned /> },
  { lab: LABS_BY_ID[10], body: <Lab10SplitEnforcementExplorer /> },
  { lab: LABS_BY_ID[11], body: <Lab11WorkflowLab /> },
  {
    lab: LABS_BY_ID[12],
    body: (
      <Lab12IntegrationAdapters
        onResultHelpContext={handleResultHelpContext}
      />
    ),
  },
] as const
```

Render them as children of the existing `<Routes>`:

```tsx
{labRoutes.map(({ lab, body }) => (
  <Route
    path={lab.path}
    element={<LabRouteLayout lab={lab}>{body}</LabRouteLayout>}
    key={lab.id}
  />
))}
```

In `describeRoute`, replace the `LABS.some` lookup with
`getLabById(labId) !== undefined`.

Continue exporting `LABS` from `App.tsx` if any external test imports it.

Delete `LabTabs.tsx`.

After no production consumer uses them, remove `labRoutesCopy` and `labNavCopy`
from `demoCopy.ts`.

- [ ] **Step 8: Remove Lab 12's nested main and duplicate page title**

In `Lab12IntegrationAdapters.tsx`:

```tsx
// Before
<main className="adapter-lab">
  <header className="adapter-lab__intro">
    <p className="scenario-kicker">Release-gated adapter fixtures</p>
    <h1>Inspect normalization at the governance boundary.</h1>

// After
<div className="adapter-lab">
  <header className="adapter-lab__intro">
    <p className="scenario-kicker">Release-gated adapter fixtures</p>
    <h2>Inspect normalization at the governance boundary.</h2>
```

Change the matching closing `</main>` to `</div>`. Do not change tabs,
manifest filtering, execution, error states, or result-help callbacks.

Update the existing `.adapter-lab__intro h1` selector in `index.css` to
`.adapter-lab__intro h2` without changing its declarations.

- [ ] **Step 9: Add route-shell styles and remove lab-strip styles**

In `index.css`:

- remove `.lab-nav`, `.lab-nav__inner`, `.lab-nav__link`, and active-strip
  selectors while leaving `.demo-nav` behavior intact;
- add `.lab-context`, `.lab-route`, `.lab-route__hero`,
  `.lab-route__layout`, `.lab-route__experiment`, `.lab-related`, and
  `.lab-route__continue`;
- use a desktop grid of `minmax(0, 1fr) minmax(15rem, 19rem)` for experiment
  plus related navigation;
- collapse to one column at `64rem`;
- keep `.lab-route__hero h1` on the same established scale as scenario page
  headings;
- give context, related, and continuation links a minimum height of `2.75rem`;
- set related-link text and experiment-facing labels to at least `1rem`;
- use existing theme tokens only;
- replace the `.help-launcher` reserve-rail declarations with:

```css
.help-launcher {
  position: fixed;
  right: max(1rem, env(safe-area-inset-right));
  bottom: max(1rem, env(safe-area-inset-bottom));
  z-index: 150;
  width: auto;
  min-height: 0;
  margin: 0;
  padding: 0;
}
```

- keep the button target at least `2.75rem` high;
- at `max-width: 30rem`, keep `.help-launcher__button` width `auto` rather
  than stretching it across the viewport;
- keep the launcher below the drawer backdrop (`z-index: 200`) and drawer
  (`z-index: 300`).

- [ ] **Step 10: Run focused route tests**

Run:

```bash
cd demo-app-react
npm test -- \
  src/components/layout/LabRouteLayout.test.tsx \
  src/App.test.tsx \
  src/labs/Lab12IntegrationAdapters.test.tsx
```

Expected: PASS. The parameterized test must prove one `<main>` for each of the
twelve routes.

- [ ] **Step 11: Run build and lint**

Run:

```bash
cd demo-app-react
npm run build
npm run lint
```

Expected: both commands PASS with no remaining `LabTabs`, `labRoutesCopy`, or
`labNavCopy` imports.

- [ ] **Step 12: Commit the shared lab route shell**

```bash
git add \
  demo-app-react/src/App.tsx \
  demo-app-react/src/App.test.tsx \
  demo-app-react/src/components/layout/LabContextNav.tsx \
  demo-app-react/src/components/layout/LabRelatedNav.tsx \
  demo-app-react/src/components/layout/LabRouteLayout.tsx \
  demo-app-react/src/components/layout/LabRouteLayout.test.tsx \
  demo-app-react/src/components/layout/LabHero.tsx \
  demo-app-react/src/components/layout/LabTabs.tsx \
  demo-app-react/src/content/demoCopy.ts \
  demo-app-react/src/labs/Lab12IntegrationAdapters.tsx \
  demo-app-react/src/index.css
git commit -m "feat(demo): add capability-aware lab route shell"
```

---

### Task 4: Remove numbering from Help drawer titles

**Files:**

- Modify: `demo-app-react/src/components/HelpDrawer.tsx:1-48,188-245`
- Modify: `demo-app-react/src/components/HelpDrawer.test.tsx:33-68`
- Modify: `demo-app-react/src/App.test.tsx:116-132`

**Interfaces:**

- Consumes: `getLabById(id: number): LabMeta | undefined`.
- Produces: dialog accessible name and visible title derived from the public
  catalog; all existing Help interactions stay unchanged.

- [ ] **Step 1: Replace numbered title expectations**

Update `HelpDrawer.test.tsx`:

```ts
it('uses number-free catalog titles for lab guides', () => {
  const { rerender } = renderDrawer(true, vi.fn(), 2)
  expect(screen.getByRole('dialog', {
    name: 'Signing and Verification',
  })).toBeInTheDocument()
  expect(screen.queryByText(/\bLab\s+2\b/)).not.toBeInTheDocument()

  rerender(
    <ThemeProvider>
      <HelpDrawer labId={12} isOpen onClose={vi.fn()} />
    </ThemeProvider>,
  )
  expect(screen.getByRole('dialog', {
    name: 'Integration Adapters',
  })).toBeInTheDocument()
  expect(screen.queryByText(/\bLab\s+12\b/)).not.toBeInTheDocument()
})
```

Keep the existing focus trap, Escape, backdrop, glossary, result tabs, and
focus-restoration tests. Update the invalid-ID fallback test to expect a dialog
named `Risk Scoring`.

In `App.test.tsx`, replace the Architecture drawer text assertion with:

```ts
expect(
  screen.getByRole('dialog', { name: 'Architecture' }),
).toBeInTheDocument()
```

- [ ] **Step 2: Run the drawer tests and verify they fail**

Run:

```bash
cd demo-app-react
npm test -- src/components/HelpDrawer.test.tsx
```

Expected: FAIL because the current drawer exposes numbered `LABS_LABEL` text and
uses a generic `aria-label`.

- [ ] **Step 3: Derive the title from the catalog**

In `HelpDrawer.tsx`:

- delete `LABS_LABEL`;
- import `getLabById`;
- derive the public title with an explicit Architecture special case and Risk
  Scoring fallback;
- replace `aria-label="Lab guide"` with
  `aria-labelledby="help-drawer-title"`;
- render a generic eyebrow and semantic title:

```tsx
const publicLab = getLabById(labId) ?? getLabById(1)
const publicTitle = labId === 0
  ? 'Architecture'
  : publicLab?.heroTitle ?? 'Risk Scoring'

// Dialog
aria-labelledby="help-drawer-title"

// Header
<p className="help-drawer__eyebrow">Capability guide</p>
<h2 id="help-drawer-title" className="help-drawer__title">
  {publicTitle}
</h2>
```

Preserve the drawer's existing theme-aware colors. The new classes may retain
the current inline style values; do not refactor unrelated drawer styling.

- [ ] **Step 4: Run all drawer and app tests**

Run:

```bash
cd demo-app-react
npm test -- \
  src/components/HelpDrawer.test.tsx \
  src/App.test.tsx \
  src/labs/Lab12IntegrationAdapters.test.tsx
```

Expected: PASS, including focus trap, focus restoration, result help, and route
title assertions.

- [ ] **Step 5: Commit the Help title change**

```bash
git add \
  demo-app-react/src/App.test.tsx \
  demo-app-react/src/components/HelpDrawer.tsx \
  demo-app-react/src/components/HelpDrawer.test.tsx
git commit -m "fix(demo): remove numbering from lab guide titles"
```

---

### Task 5: Complete regression, accessibility, and visual verification

**Files:**

- Modify if verification exposes a scoped defect:
  - `demo-app-react/src/index.css`
  - the directly responsible component or test from Tasks 2–4
- Do not create unrelated refactors or new product behavior.

**Interfaces:**

- Consumes: the completed catalog, guided index, route shell, and number-free
  Help title.
- Produces: a fully verified implementation matching issue #34 and the approved
  design.

- [ ] **Step 1: Run the complete frontend test suite**

Run:

```bash
cd demo-app-react
npm test
```

Expected: PASS with no skipped or failing Labs, App, Help drawer, or Integration
Adapters tests.

- [ ] **Step 2: Run all static and production gates**

Run:

```bash
cd demo-app-react
npm run lint
npm run copycheck
npm run build
npm run test:smoke
```

Expected: all four commands PASS.

- [ ] **Step 3: Run repository-level demo-copy regressions**

Run from the repository root:

```bash
pytest -q tests/test_demo_copy_policy.py tests/test_beta_demo_deployment.py
```

Expected: PASS.

- [ ] **Step 4: Start the local demo for browser verification**

Run the frontend in a persistent terminal:

```bash
cd demo-app-react
npm run dev -- --host 127.0.0.1
```

Use the URL Vite reports. The Labs index and route chrome do not require a
successful demo API response to verify their layout and semantics.

- [ ] **Step 5: Verify the Labs index at desktop and phone widths**

At `#/demo/labs`, check at `1440×1000` and `390×844`:

- the hero reads `See where governance changes the outcome.`;
- the first-visit path contains no lab numbers;
- all four capability groups and twelve destinations are visible;
- card titles and journey actions are readable body text;
- keyboard focus is visible;
- there is no horizontal overflow;
- light and dark themes both retain sufficient contrast.

Capture one screenshot at each width for review.

- [ ] **Step 6: Verify representative lab pages and the floating Guide**

Check `#/lab/1`, `#/lab/9`, and `#/lab/12` at `1440×1000` and `390×844`:

- `document.querySelectorAll('main').length === 1`;
- no route hero, context, related navigation, or Guide title contains
  `Lab <number>`;
- the descriptive title is the only `<h1>`;
- related navigation is beside content on desktop and below it on phones;
- the Guide launcher stays at the viewport's bottom-right before and after
  scrolling;
- Architecture and the three representative lab routes show the launcher;
- Scenarios, the Labs landing page, and FAQ do not show the launcher;
- the fixed launcher does not collide with other fixed controls or make
  underlying controls unreachable;
- the open drawer does not make controls unreachable;
- focus enters the drawer, remains trapped, and returns to the launcher;
- `Without AEGIS` and comparable experiment labels remain readable;
- Integration Adapters retains its tabs and result-help behavior.

- [ ] **Step 7: Apply only verification-driven corrections**

If a check fails, add or tighten a regression assertion in the directly
responsible test, run it to see the failure, make the smallest CSS or component
change, and rerun that focused test before continuing.

Do not change lab APIs, execution state, or Help content to solve a layout
problem.

- [ ] **Step 8: Rerun the complete gate after any correction**

Run:

```bash
cd demo-app-react
npm test
npm run lint
npm run copycheck
npm run build
```

Expected: all commands PASS.

- [ ] **Step 9: Commit verification-driven corrections, if any**

If Step 7 changed files:

```bash
git add \
  demo-app-react/src/App.tsx \
  demo-app-react/src/App.test.tsx \
  demo-app-react/src/pages/LabsIndexPage.tsx \
  demo-app-react/src/pages/LabsIndexPage.test.tsx \
  demo-app-react/src/components/layout/LabContextNav.tsx \
  demo-app-react/src/components/layout/LabRelatedNav.tsx \
  demo-app-react/src/components/layout/LabRouteLayout.tsx \
  demo-app-react/src/components/layout/LabRouteLayout.test.tsx \
  demo-app-react/src/components/layout/LabHero.tsx \
  demo-app-react/src/components/HelpDrawer.tsx \
  demo-app-react/src/components/HelpDrawer.test.tsx \
  demo-app-react/src/labs/Lab12IntegrationAdapters.tsx \
  demo-app-react/src/index.css
git commit -m "fix(demo): tighten labs accessibility and responsiveness"
```

If Step 7 required no changes, do not create an empty commit.

---

## Final acceptance checklist

- [ ] All twelve stable deep links resolve.
- [ ] All twelve lab routes expose exactly one `<main>`.
- [ ] The Labs index contains every lab exactly once under the approved group.
- [ ] The first-visit path uses outcomes, not route numbers.
- [ ] Route heroes, related navigation, and Help titles contain no `Lab N`.
- [ ] The flat twelve-item lab strip is gone.
- [ ] Help drawer behavior and Integration Adapters result help are unchanged.
- [ ] Primary labels use the established readable type scale.
- [ ] Light/dark contrast, visible focus, and 44px targets are preserved.
- [ ] The Guide launcher stays fixed at bottom-right on eligible routes only,
  with no fixed-control collision or unreachable content.
- [ ] `npm test`, `npm run lint`, `npm run copycheck`, and `npm run build` pass.
