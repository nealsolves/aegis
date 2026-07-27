# Landing Page Boundary Story Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the AEGIS landing-page narrative and two-row header so visitors understand deterministic runtime governance before exploring product mechanics.

**Architecture:** Add a route-aware `SiteHeader` that always renders two fixed-height rows and delegates the existing primary and demo navigation. Keep public copy centralized in `demoCopy.ts`, add only the small presentation fields needed by the evidence comparison and closing principle, and preserve the existing page components and visual language. Verify behavior with React Testing Library first, then use CSS contracts and browser inspection for fixed header geometry, no-wrap installation, full-width prose, theme parity, and responsive overflow.

**Tech Stack:** React 19, TypeScript 5.9, React Router 7, Vitest, Testing Library, CSS, Vite 8

## Global Constraints

- The header always contains exactly two rows and has the same total height on landing, demo, lab, and FAQ routes.
- The first row never wraps; the second row never wraps; narrow layouts use contained horizontal overflow.
- Remove `What it does` from the public navigation.
- Landing row 2 is exactly `Auditable Enforcement and Governance for Intelligent Systems`.
- Demo and lab routes replace `Open demo` with a non-link `Demo` indicator using `aria-current="location"`, a transparent background, and a blue outline.
- `/faq` keeps `Open demo` as a link while showing the demo-navigation row.
- Hero headline is exactly `The deterministic wrapper around a probabilistic core.`
- Hero support is exactly `AI works in possibilities. Enterprise systems need a definite decision: allow, block, pause, or escalate. AEGIS enforces your enterprise policy at the boundary—before an AI acts and before its output becomes an operational outcome.`
- The story closes with `Governance is infrastructure.` immediately before the Architecture, Scenarios, and Labs entry region.
- `pip install aegis-ai-governance==0.9.0b1` never wraps and must not cause page-level horizontal overflow.
- Keep IBM Plex, the current theme tokens, visible focus, reduced-motion behavior, and minimum 44px interactive targets.
- Add no runtime or development dependencies.

## File Structure

- Create `demo-app-react/src/components/layout/SiteHeader.tsx` — compose the route-aware two-row header.
- Modify `demo-app-react/src/App.tsx` — derive demo context and render `SiteHeader`.
- Modify `demo-app-react/src/components/layout/AppNav.tsx` — render the current demo location as a semantic non-link.
- Modify `demo-app-react/src/components/layout/DemoNav.tsx` — mark the demo-navigation track as the fixed second header row.
- Modify `demo-app-react/src/content/demoCopy.ts` — own all approved header and landing copy.
- Modify `demo-app-react/src/pages/IntroductionPage.tsx` — render comparison labels and the closing principle.
- Modify `demo-app-react/src/index.css` — implement constant header geometry, responsive overflow, wider prose, install behavior, and closing-principle styling.
- Modify `demo-app-react/src/App.test.tsx` — cover route-aware header content, semantics, and equal row geometry.
- Modify `demo-app-react/src/pages/IntroductionPage.test.tsx` — cover the approved narrative, section order, and no-wrap command.

---

### Task 1: Route-aware two-row site header

**Files:**
- Create: `demo-app-react/src/components/layout/SiteHeader.tsx`
- Modify: `demo-app-react/src/App.tsx:31-48,98-102`
- Modify: `demo-app-react/src/components/layout/AppNav.tsx:1-61`
- Modify: `demo-app-react/src/components/layout/DemoNav.tsx:1-24`
- Modify: `demo-app-react/src/content/demoCopy.ts:1-29`
- Modify: `demo-app-react/src/index.css:87-212,1208-1248`
- Test: `demo-app-react/src/App.test.tsx:1-165`

**Interfaces:**
- Produces: `SiteHeader({ showDemoNav, isDemoContext }: SiteHeaderProps): JSX.Element`
- Produces: `AppNav({ isDemoContext }: { isDemoContext: boolean }): JSX.Element`
- Extends: `RouteDescriptor` with `isDemoContext: boolean`
- Consumes: existing `DemoNav`, `publicNavCopy`, and `demoNavCopy`

- [ ] **Step 1: Write failing route-aware header tests**

Import the stylesheet in `App.test.tsx`, replace the existing public-navigation test, and add a constant-geometry test:

```tsx
import '@/index.css'

it('uses a two-row public header without the removed landing link', () => {
  const { container } = renderRoute('#/')
  const header = screen.getByRole('banner')
  const primary = screen.getByRole('navigation', { name: 'Primary navigation' })

  expect(header.querySelectorAll(':scope > .site-header__row')).toHaveLength(2)
  expect(
    within(header).getByText(
      'Auditable Enforcement and Governance for Intelligent Systems',
    ),
  ).toBeInTheDocument()
  expect(within(primary).queryByText('What it does')).not.toBeInTheDocument()
  expect(
    within(primary).getByRole('link', { name: 'Open demo' }),
  ).toBeInTheDocument()
  expect(container.querySelector('.site-header__context')).toBeInTheDocument()
})

it('marks Demo as the current location without exposing a link on demo routes', () => {
  renderRoute('#/demo/architecture')
  const primary = screen.getByRole('navigation', { name: 'Primary navigation' })
  const demo = within(primary).getByText('Demo')

  expect(demo.tagName).toBe('SPAN')
  expect(demo).toHaveAttribute('aria-current', 'location')
  expect(demo).not.toHaveAttribute('href')
  expect(
    screen.getByRole('navigation', { name: 'Demo navigation' }),
  ).toBeInTheDocument()
})

it('keeps Open demo available on the shared FAQ route', () => {
  renderRoute('#/faq')

  expect(
    within(
      screen.getByRole('navigation', { name: 'Primary navigation' }),
    ).getByRole('link', { name: 'Open demo' }),
  ).toBeInTheDocument()
  expect(
    screen.getByRole('navigation', { name: 'Demo navigation' }),
  ).toBeInTheDocument()
})

it('uses identical fixed row heights across public and demo routes', () => {
  const heights = ['#/', '#/demo/architecture', '#/lab/1', '#/faq'].map(path => {
    const view = renderRoute(path)
    const rows = [
      ...screen.getByRole('banner').querySelectorAll<HTMLElement>(
        ':scope > .site-header__row',
      ),
    ].map(row => getComputedStyle(row).height)
    view.unmount()
    return rows
  })

  expect(heights.every(rows => rows.length === 2)).toBe(true)
  expect(heights.every(rows => rows[0] === heights[0][0])).toBe(true)
  expect(heights.every(rows => rows[1] === heights[0][1])).toBe(true)
  expect(
    heights.flat().every(height => height !== 'auto' && height !== ''),
  ).toBe(true)
})
```

- [ ] **Step 2: Run the header tests and verify RED**

Run:

```bash
cd demo-app-react
npx vitest run src/App.test.tsx
```

Expected: failures for the missing banner/two-row header, missing full product name, existing `What it does` link, and linked `Open demo` on demo routes.

- [ ] **Step 3: Centralize the revised navigation copy**

Replace the public navigation block in `demoCopy.ts` with:

```ts
export const publicNavCopy = {
  ariaLabel: 'Primary navigation',
  brand: 'AEGIS',
  brandLabel: 'AEGIS home',
  descriptor: 'Auditable Enforcement and Governance for Intelligent Systems',
  links: [
    { id: 'install', label: 'Install', to: '/#install', emphasis: false },
    {
      id: 'demo',
      label: 'Open demo',
      currentLabel: 'Demo',
      to: '/demo/architecture',
      emphasis: true,
    },
    { id: 'faq', label: 'FAQ', to: '/faq', emphasis: false },
  ],
  github: {
    label: 'GitHub',
    href: 'https://github.com/nealsolves/aegis',
  },
  theme: {
    dark: 'dark',
    light: 'light',
    switchTo: 'Switch to',
    mode: 'mode',
  },
} as const
```

- [ ] **Step 4: Add `SiteHeader` and the semantic current-location indicator**

Create `SiteHeader.tsx`:

```tsx
import AppNav from '@/components/layout/AppNav'
import DemoNav from '@/components/layout/DemoNav'
import { publicNavCopy } from '@/content/demoCopy'

interface SiteHeaderProps {
  showDemoNav: boolean
  isDemoContext: boolean
}

export default function SiteHeader({
  showDemoNav,
  isDemoContext,
}: SiteHeaderProps) {
  return (
    <header className="site-header">
      <AppNav isDemoContext={isDemoContext} />
      {showDemoNav ? (
        <DemoNav />
      ) : (
        <div className="site-header__row site-header__context">
          <div className="site-header__context-inner">
            {publicNavCopy.descriptor}
          </div>
        </div>
      )}
    </header>
  )
}
```

Replace `AppNav.tsx` with the complete route-aware component:

```tsx
import { ExternalLink, Moon, Sun } from 'lucide-react'
import { Link } from 'react-router-dom'
import { publicNavCopy } from '@/content/demoCopy'
import { useTheme } from '@/theme/ThemeContext'

export default function AppNav({
  isDemoContext,
}: {
  isDemoContext: boolean
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
                className="public-nav__link public-nav__link--current"
                aria-current="location"
              >
                {link.currentLabel}
              </span>
            ) : (
              <Link
                key={link.id}
                to={link.to}
                className={link.emphasis
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
          <span>
            {theme === 'dark'
              ? publicNavCopy.theme.dark
              : publicNavCopy.theme.light}
          </span>
        </button>
      </div>
    </nav>
  )
}
```

Change the `DemoNav.tsx` root opening tag to:

```tsx
<nav
  className="demo-nav site-header__row"
  aria-label={demoNavCopy.ariaLabel}
>
```

- [ ] **Step 5: Derive demo context in `App.tsx`**

Extend and consume the route descriptor:

```tsx
interface RouteDescriptor {
  helpLabId: number | null
  showDemoNav: boolean
  showDemoService: boolean
  isDemoContext: boolean
}

function describeRoute(pathname: string): RouteDescriptor {
  const normalizedPathname = (pathname.replace(/\/+$/, '') || '/').toLowerCase()
  const knownLab = LABS.find(lab => lab.path === normalizedPathname)
  const isDemoRoute = normalizedPathname.startsWith('/demo/')
  const isLabRoute = normalizedPathname.startsWith('/lab/')

  return {
    helpLabId: normalizedPathname === '/demo/architecture' ? 0 : knownLab?.id ?? null,
    showDemoNav: isDemoRoute || isLabRoute || normalizedPathname === '/faq',
    showDemoService: isDemoRoute || isLabRoute,
    isDemoContext: isDemoRoute || isLabRoute,
  }
}
```

Replace the separate header components in `AppContent`:

```tsx
<SiteHeader
  showDemoNav={route.showDemoNav}
  isDemoContext={route.isDemoContext}
/>
```

- [ ] **Step 6: Implement fixed two-row geometry**

Define explicit track heights and remove the existing wrapping/hiding behavior:

```css
:root {
  --site-header-primary-height: 4rem;
  --site-header-secondary-height: 3.25rem;
}

.site-header {
  flex: 0 0 calc(
    var(--site-header-primary-height) + var(--site-header-secondary-height)
  );
  height: calc(
    var(--site-header-primary-height) + var(--site-header-secondary-height)
  );
  background: var(--bg-nav);
}

.site-header__row {
  height: var(--site-header-secondary-height);
  min-height: var(--site-header-secondary-height);
}

.public-nav.site-header__row {
  height: var(--site-header-primary-height);
  min-height: var(--site-header-primary-height);
  overflow-x: auto;
  overflow-y: hidden;
}

.public-nav__inner,
.demo-nav__inner,
.site-header__context-inner {
  width: max-content;
  min-width: 100%;
  max-width: 1440px;
  height: 100%;
  min-height: 100%;
  margin: 0 auto;
  box-sizing: border-box;
}

.site-header__context {
  overflow-x: auto;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  color: rgba(255, 255, 255, 0.68);
  background: var(--bg-nav);
}

.site-header__context-inner {
  display: flex;
  align-items: center;
  padding: 0.25rem clamp(1rem, 3vw, 2.5rem);
  white-space: nowrap;
}

.public-nav__link--current {
  border-color: var(--ibm-blue-60);
  color: var(--ibm-cyan-30);
  background: transparent;
  cursor: default;
}
```

Delete the `max-width: 960px` rules that wrap/reorder `.public-nav__inner` and
`.public-nav__links`, and delete the `max-width: 680px` rule that hides
`.public-nav__brand span`.

- [ ] **Step 7: Run the header tests and full route test file**

Run:

```bash
cd demo-app-react
npx vitest run src/App.test.tsx
```

Expected: all `App.test.tsx` tests pass with no warnings.

- [ ] **Step 8: Commit the header**

```bash
git add demo-app-react/src/App.tsx \
  demo-app-react/src/App.test.tsx \
  demo-app-react/src/components/layout/AppNav.tsx \
  demo-app-react/src/components/layout/DemoNav.tsx \
  demo-app-react/src/components/layout/SiteHeader.tsx \
  demo-app-react/src/content/demoCopy.ts \
  demo-app-react/src/index.css
git commit -m "feat(demo): stabilize the two-row site header"
```

---

### Task 2: Boundary Story copy and semantic flow

**Files:**
- Modify: `demo-app-react/src/content/demoCopy.ts:31-217`
- Modify: `demo-app-react/src/pages/IntroductionPage.tsx:12-184`
- Test: `demo-app-react/src/pages/IntroductionPage.test.tsx:1-104`

**Interfaces:**
- Extends: `introCopy.comparison.columns[]` with `label: string`
- Produces: `introCopy.principle` with `eyebrow`, `title`, and `intro`
- Consumes: existing `SectionHeading` and entry-card rendering

- [ ] **Step 1: Replace the old introduction assertions with failing Boundary Story tests**

Use literal assertions for approved copy and behavior:

```tsx
it('leads with the deterministic-wrapper thesis', () => {
  renderPage()

  expect(
    screen.getByRole('heading', {
      level: 1,
      name: 'The deterministic wrapper around a probabilistic core.',
    }),
  ).toBeInTheDocument()
  expect(screen.getByText(
    'AI works in possibilities. Enterprise systems need a definite decision: '
      + 'allow, block, pause, or escalate. AEGIS enforces your enterprise policy '
      + 'at the boundary—before an AI acts and before its output becomes an '
      + 'operational outcome.',
  )).toBeInTheDocument()
})

it('makes enterprise policy the deterministic permission boundary', () => {
  renderPage()

  expect(
    screen.getByRole('heading', {
      name: 'Let AI handle possibility. Make policy decide permission.',
    }),
  ).toBeInTheDocument()
  expect(screen.getByText(/permission resolves against declared, versioned/i))
    .toBeInTheDocument()
  expect(screen.getByRole('heading', { name: 'Probabilistic core' }))
    .toBeInTheDocument()
  expect(screen.getByRole('heading', { name: 'Deterministic governance' }))
    .toBeInTheDocument()
  expect(screen.getByRole('heading', { name: 'Enterprise operation' }))
    .toBeInTheDocument()
})

it('contrasts the model account with an independent system receipt', () => {
  renderPage()

  expect(
    screen.getByRole('heading', { name: 'An explanation is not a control.' }),
  ).toBeInTheDocument()
  expect(screen.getByRole('heading', { name: "The model's account" }))
    .toBeInTheDocument()
  expect(screen.getByRole('heading', { name: "The system's receipt" }))
    .toBeInTheDocument()
  expect(screen.getByText('Useful clues for understanding behavior'))
    .toBeInTheDocument()
  expect(screen.getByText('Independent evidence of the governance decision'))
    .toBeInTheDocument()
})

it('closes the story before offering demo entry points', () => {
  const { container } = renderPage()
  const principle = container.querySelector('.intro-principle')
  const entries = screen.getByRole('region', { name: 'Choose where to start' })

  expect(
    screen.getByRole('heading', { name: 'Governance is infrastructure.' }),
  ).toBeInTheDocument()
  expect(principle).not.toBeNull()
  expect(
    principle?.compareDocumentPosition(entries)
      & Node.DOCUMENT_POSITION_FOLLOWING,
  ).toBeTruthy()
})

it('hands visitors from the principle into the three demo paths', () => {
  renderPage()

  for (const description of [
    'Understand the ownership boundary and technical map.',
    'Follow governed enterprise cases.',
    'Inspect individual controls and evidence.',
  ]) {
    expect(screen.getByText(description)).toBeInTheDocument()
  }
})
```

Update the integration-heading test:

```tsx
expect(
  screen.getByRole('heading', {
    name: 'Add AEGIS to an AI invocation or agentic workflow you already own.',
  }),
).toBeInTheDocument()
```

- [ ] **Step 2: Run the introduction tests and verify RED**

Run:

```bash
cd demo-app-react
npx vitest run src/pages/IntroductionPage.test.tsx
```

Expected: failures show the old hero, ownership, comparison, integration, and
closing copy.

- [ ] **Step 3: Replace `introCopy` with the approved narrative**

Within the existing `hero` object, replace `eyebrow`, `title`, `lead`,
`workflow`, and `host` with these exact fields. Do not change `actions` in this
step:

```ts
eyebrow: 'Runtime governance for AI calls and agent workflows',
title: 'The deterministic wrapper around a probabilistic core.',
lead:
  'AI works in possibilities. Enterprise systems need a definite decision: '
  + 'allow, block, pause, or escalate. AEGIS enforces your enterprise policy '
  + 'at the boundary—before an AI acts and before its output becomes an '
  + 'operational outcome.',
workflow:
  'AEGIS applies declared policy to participants, steps, handoffs, approvals, '
  + 'budgets, and session lifecycle.',
host:
  'Your application or agent framework continues to execute models, agents, '
  + 'and tools.',
```

Update the call flow so it directly encodes the wrapper:

```ts
callFlowLabel: 'The governed boundary',
callFlow: [
  {
    owner: 'Enterprise application',
    title: 'Declare the request',
    detail: 'The host supplies the role, input, policy, and runtime context.',
    kind: 'host',
  },
  {
    owner: 'Deterministic pre-call gate',
    title: 'Allow, block, pause, or escalate',
    detail: 'AEGIS applies enterprise policy before the model, agent, or tool runs.',
    kind: 'policy',
  },
  {
    owner: 'Probabilistic core',
    title: 'Execute the model or agent',
    detail: 'The host keeps its provider client, credentials, retries, and business state.',
    kind: 'host-owned',
  },
  {
    owner: 'Deterministic post-call gate',
    title: 'Accept or reject the output',
    detail: 'AEGIS applies output rules before the host uses the result.',
    kind: 'policy',
  },
  {
    owner: 'Independent evidence',
    title: 'Record the governance decision',
    detail: 'The artifact carries reason codes, policy metadata, checksums, and workflow context.',
    kind: 'evidence',
  },
],
```

Use the approved enterprise-boundary section:

```ts
ownership: {
  id: 'what-it-does',
  eyebrow: 'The enterprise boundary',
  title: 'Let AI handle possibility. Make policy decide permission.',
  intro:
    'Models and agents can reason through ambiguity. Enterprise permission '
    + 'resolves against declared, versioned policy before a proposed action '
    + 'becomes an operational outcome.',
  areas: [
    {
      title: 'Probabilistic core',
      detail:
        'Models and agents reason, plan, generate, and propose tool actions '
        + 'across ambiguous situations.',
    },
    {
      title: 'Deterministic governance',
      detail:
        'AEGIS enforces roles, preconditions, tool limits, approvals, budgets, '
        + 'output rules, and risk treatment.',
    },
    {
      title: 'Enterprise operation',
      detail:
        'Your application owns orchestration, credentials, execution, business '
        + 'state, downstream action, and storage of governance evidence.',
    },
  ],
},
```

Use this evidence comparison:

```ts
comparison: {
  eyebrow: 'Independent governance evidence',
  title: 'An explanation is not a control.',
  intro:
    'A thought trace can help a team understand model behavior. It remains an '
    + 'account produced by the system being inspected. Enterprise governance '
    + 'needs a separate record showing which policy ran, what was allowed or '
    + 'blocked, and why.',
  columns: [
    {
      title: "The model's account",
      label: 'Useful clues for understanding behavior',
      items: [
        'Produced by the model being inspected.',
        'Helps with debugging and behavioral inspection.',
        'May omit an influence or construct a plausible explanation after the fact.',
        'Cannot independently authorize or stop an enterprise action.',
        'Does not prove which enterprise policy was executed.',
      ],
    },
    {
      title: "The system's receipt",
      label: 'Independent evidence of the governance decision',
      items: [
        'Produced by AEGIS outside the model.',
        'Tied to a versioned policy and ordered enforcement gates.',
        'Records allow, block, pause, or escalation outcomes.',
        'Can stop a request before execution or reject output before use.',
        'Captures reason codes, checksums, policy metadata, and workflow context.',
      ],
    },
  ],
  source: {
    lead: 'Primary research on thought-trace faithfulness:',
    label: 'Language Models Don’t Always Say What They Think',
    href: 'https://arxiv.org/abs/2305.04388',
  },
},
```

Update the integration and closing copy:

```ts
title:
  'Add AEGIS to an AI invocation or agentic workflow you already own.',
intro:
  'Apply policy before execution and validate the result after it. The '
  + 'host-owned call remains visible between the two checkpoints.',
```

The two fields above replace `introCopy.install.title` and
`introCopy.install.intro`; all other install fields remain unchanged. Add
`principle` between `install` and `entries`:

```ts
principle: {
  eyebrow: 'The operating principle',
  title: 'Governance is infrastructure.',
  intro:
    'Models, providers, and agent frameworks can change. Your governance '
    + 'boundary remains declared, executable, independently observable, and '
    + 'auditable.',
},
```

Replace only `introCopy.entries.intro` with:

```ts
intro:
  'Understand the ownership boundary, follow a governed enterprise case, '
  + 'or inspect one control at a time.',
```

Replace the three existing entry descriptions without changing their titles or
routes:

```ts
description: 'Understand the ownership boundary and technical map.',
description: 'Follow governed enterprise cases.',
description: 'Inspect individual controls and evidence.',
```

- [ ] **Step 4: Render comparison labels and the closing principle**

Add the label under each comparison heading:

```tsx
<article key={column.title} className="comparison-card">
  <h3>{column.title}</h3>
  <p className="comparison-card__label">{column.label}</p>
  <ul>
    {column.items.map(item => <li key={item}>{item}</li>)}
  </ul>
</article>
```

Insert the principle between the install and entry sections:

```tsx
<section
  className="intro-section intro-principle"
  aria-labelledby="principle-title"
>
  <div className="intro-shell">
    <SectionHeading
      eyebrow={introCopy.principle.eyebrow}
      id="principle-title"
      title={introCopy.principle.title}
      intro={introCopy.principle.intro}
    />
  </div>
</section>
```

- [ ] **Step 5: Run the copy checker before accepting the prose**

Run:

```bash
cd demo-app-react
npm run copycheck
```

Expected: exit 0 with no language-policy findings. If a finding appears, revise
only the unapproved supporting sentence that triggered it; do not alter the
user-approved hero headline, hero support, integration headline, or closing
headline.

- [ ] **Step 6: Run the introduction tests and verify GREEN**

Run:

```bash
cd demo-app-react
npx vitest run src/pages/IntroductionPage.test.tsx
```

Expected: all introduction tests pass.

- [ ] **Step 7: Commit the Boundary Story**

```bash
git add demo-app-react/src/content/demoCopy.ts \
  demo-app-react/src/pages/IntroductionPage.tsx \
  demo-app-react/src/pages/IntroductionPage.test.tsx
git commit -m "feat(demo): tell the AEGIS boundary story"
```

---

### Task 3: Full-width prose, responsive installation, and final visual verification

**Files:**
- Modify: `demo-app-react/src/index.css:245-720,1208-1288`
- Modify: `demo-app-react/src/pages/IntroductionPage.test.tsx:1-140`

**Interfaces:**
- Consumes: `.site-header`, `.intro-shell`, `.intro-section-heading`, `.comparison-card__label`, `.install-command`, `.intro-code`, and `.intro-principle`
- Produces: no new TypeScript interfaces

- [ ] **Step 1: Add failing CSS-contract tests**

Append these tests to `IntroductionPage.test.tsx`:

```tsx
it('keeps the public beta install command on one line inside its own scroller', () => {
  renderPage()
  const command = screen.getByText('pip install aegis-ai-governance==0.9.0b1')
  const container = command.closest('.install-command')

  expect(getComputedStyle(command).whiteSpace).toBe('nowrap')
  expect(container).not.toBeNull()
  expect(getComputedStyle(container as Element).overflowX).toBe('auto')
})

it('uses the wide prose contract for section introductions and sources', () => {
  const { container } = renderPage()
  const heading = container.querySelector('.intro-section-heading')
  const source = container.querySelector('.intro-source')

  expect(getComputedStyle(heading as Element).maxWidth).toBe('100ch')
  expect(getComputedStyle(source as Element).maxWidth).toBe('100ch')
})
```

- [ ] **Step 2: Run the CSS-contract tests and verify RED**

Run:

```bash
cd demo-app-react
npx vitest run src/pages/IntroductionPage.test.tsx
```

Expected: the install command reports wrapping/`overflow-wrap: anywhere`, the
container does not scroll itself, and prose remains at `70ch`.

- [ ] **Step 3: Implement the approved layout**

Update the landing CSS with these contracts:

```css
.intro-shell {
  width: min(100% - 2rem, 1360px);
  margin: 0 auto;
}

.intro-hero__grid {
  grid-template-columns: minmax(0, 1.18fr) minmax(20rem, 0.82fr);
  gap: clamp(2.5rem, 6vw, 5rem);
}

.intro-hero__copy {
  max-width: 52rem;
}

.intro-section-heading,
.intro-source {
  max-width: 100ch;
}

.comparison-card__label {
  margin: 0.5rem 0 0;
  color: var(--text-primary);
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.8125rem;
  letter-spacing: 0.03em;
}

.comparison-card ul {
  margin-top: 1.25rem;
}

.intro-install__grid {
  grid-template-columns: minmax(28rem, 1.15fr) minmax(0, 0.85fr);
}

.install-command {
  max-width: 100%;
  overflow-x: auto;
}

.install-command code {
  width: max-content;
  min-width: 100%;
  overflow-wrap: normal;
  white-space: nowrap;
}

.intro-code {
  width: 100%;
}

.intro-principle {
  border-block: 1px solid var(--border-ui);
  background: var(--bg-nav);
}

.intro-principle .intro-eyebrow {
  color: var(--ibm-cyan-30);
}

.intro-principle .intro-section-heading {
  margin-bottom: 0;
}

.intro-principle .intro-section-heading h2 {
  color: #ffffff;
}

.intro-principle .intro-section-heading > p:last-child {
  color: rgba(255, 255, 255, 0.72);
}

.intro-entries {
  padding-top: clamp(4rem, 8vw, 7rem);
}
```

Keep the existing `max-width: 960px` rule that stacks the hero and install
grids. At `max-width: 680px`, retain the one-column cards and full-width hero
actions, but do not add any header wrapping or hide the product name.

- [ ] **Step 4: Run the CSS-contract tests and verify GREEN**

Run:

```bash
cd demo-app-react
npx vitest run src/pages/IntroductionPage.test.tsx
```

Expected: all introduction tests pass, including `white-space: nowrap`,
contained `overflow-x: auto`, and `100ch` prose measures.

- [ ] **Step 5: Run the complete automated verification**

Run these independently and require exit 0 from every command:

```bash
cd demo-app-react
npm test
npm run lint
npm run copycheck
npm run build
npm run test:smoke
```

Expected:

- 30 or more Vitest files pass with zero failing tests.
- ESLint emits no errors.
- Copycheck emits no findings.
- TypeScript and Vite complete a production build.
- Architecture smoke unit tests pass.

- [ ] **Step 6: Inspect the built app at all required widths and themes**

Start the local app:

```bash
cd demo-app-react
npm run dev -- --host 127.0.0.1
```

Inspect `#/`, `#/demo/architecture`, `#/lab/1`, and `#/faq` at `1440×1000`,
`1024×900`, `768×900`, `390×844`, and `320×720`, in both light and dark
themes. At each width:

- record the landing header height and demo header height; require exact pixel
  equality;
- require exactly two visible header rows;
- require no document-level horizontal overflow;
- confirm row-level overflow keeps every header item reachable;
- confirm `Open demo` is filled only on the landing page;
- confirm `Demo` is outlined and non-interactive on demo/lab routes;
- confirm the installation command stays on one line inside its own scroller;
- confirm prose uses the available width without becoming clipped;
- confirm keyboard focus remains visible; and
- confirm the principle section precedes the entry cards.

- [ ] **Step 7: Review the final diff**

Run:

```bash
git diff --check
git status --short
git diff --stat main...HEAD
```

Expected: no whitespace errors, only the planned demo files plus the approved
specification and plan, and no generated `dist` or `node_modules` files.

- [ ] **Step 8: Commit the responsive polish**

```bash
git add demo-app-react/src/index.css \
  demo-app-react/src/pages/IntroductionPage.test.tsx
git commit -m "fix(demo): polish landing responsiveness"
```
