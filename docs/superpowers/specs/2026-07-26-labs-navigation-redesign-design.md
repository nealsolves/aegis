# AEGIS Labs Navigation Redesign

**Date:** 2026-07-26

**Status:** Approved design

**GitHub issue:** [#34 — Add a main landmark to legacy lab routes](https://github.com/nealsolves/aegis/issues/34)

## 1. Purpose

The Labs experience currently exposes historical lab numbers as if they were a
visitor-facing sequence. That creates a false starting-order signal: the
recommended first visit begins at routes 9, 10, and 11, which can make a new
visitor think that eight prerequisites have been skipped.

The redesign will organize Labs by the governance capability a visitor wants to
understand. Lab numbers will remain internal route identifiers so existing deep
links continue to work, but they will no longer appear in the Labs index,
cross-lab navigation, route heroes, or Help drawer titles.

The work also incorporates issue #34. Every public lab deep link must expose
exactly one route-level `<main>` landmark.

### 1.1 Guide launcher scope amendment

After the initial design approval, the Guide launcher requirement changed:

- the launcher is fixed to the bottom-right of the viewport so it remains
  available while the visitor scrolls;
- it appears only on routes that already have guide content: Architecture and
  the twelve individual lab routes;
- it does not appear on Scenarios, the Labs landing page, FAQ, or other routes
  without guide content;
- the drawer content and interaction model remain unchanged.

This user-directed amendment supersedes issue #34's earlier reserve-rail
acceptance criterion.

## 2. Approved direction

Use a **guided capability map**.

The Labs index will contain:

1. a concise hero that explains that visitors may follow a first journey or
   choose a capability directly;
2. a number-free recommended journey:
   - Compare enforcement;
   - Explore checkpoints;
   - Govern the handoff;
3. four capability groups containing every lab.

The journey is guidance, not a prerequisite chain. Returning visitors can go
directly to any capability group or lab.

The following alternatives were considered and rejected:

- a capability directory without a first-visit journey, because it gives new
  visitors too little orientation;
- an interactive goal chooser, because progressive disclosure adds state,
  hidden content, and test cost without enough value for twelve labs.

## 3. Information architecture

### 3.1 Capability groups

#### Decisions

Question: **What should happen?**

- Governed vs. Ungoverned
- Split Enforcement
- Risk Scoring

#### Policies and gates

Question: **Which rules apply?**

- Policy Composition
- Loaders and Versioning
- Custom Gates

#### Evidence

Question: **What can you prove?**

- Signing and Verification
- Audit Chain
- Compliance Dashboard

#### Systems and workflows

Question: **How does it connect?**

- Governed Knowledge Base
- Workflow Governance
- Integration Adapters

### 3.2 Stable routes

The existing `#/lab/1` through `#/lab/12` routes remain unchanged. Numeric IDs
are compatibility identifiers, not public ordering.

Bookmarks, documentation links, automated smoke checks, and external links must
continue to resolve without redirects or URL migrations.

### 3.3 Future provider expansion

Integration Adapters remains a single lab entry in Systems and workflows.
Provider and protocol coverage is represented inside that lab rather than by
adding a new top-level navigation model.

The current A2A coverage may later expand to include:

- Google Vertex AI;
- Google ADK.

That future content addition must not require restoring lab numbers or
redesigning Labs navigation.

## 4. Labs index

### 4.1 Hero

The hero should frame the page around outcomes rather than historical
implementation order.

Approved message direction:

> See where governance changes the outcome.

Supporting copy tells visitors to choose the first journey or go directly to
the control they need.

### 4.2 First-visit journey

The first-visit journey retains the conceptual path represented by the current
routes 9, 10, and 11, but it does not expose those numbers:

1. **Compare enforcement** — Governed vs. Ungoverned;
2. **Explore checkpoints** — Split Enforcement;
3. **Govern the handoff** — Workflow Governance.

The UI may visually connect these three outcomes. It must not label them as
Lab 9, Lab 10, or Lab 11, and must not imply that other labs are prerequisites.

### 4.3 Capability map

Each capability group contains:

- its group name;
- its visitor-facing question;
- a short explanation;
- links to the labs in that group.

Lab links use descriptive titles and optional one-sentence descriptions. They
do not contain visible or assistive-text lab numbers.

The capability map remains fully visible without a filter, accordion, search
interaction, or progressive-disclosure state.

## 5. Individual lab pages

### 5.1 Route context

The current flat, twelve-item lab strip is removed.

Each lab instead receives compact route context:

```text
All labs › Capability group
```

The current capability group is exposed through text and semantics, not color
alone.

### 5.2 Hero

The hero contains:

- a capability-specific eyebrow such as `Decision boundary`;
- the descriptive lab title;
- a concise explanation of what the visitor changes or observes;
- the existing Open Guide action.

The hero must not display `Lab N`, including in screen-reader-only text.

Internal numeric IDs may still select the lab accent color and Help content.

### 5.3 Related labs

Each lab page includes an `Also in <capability>` navigation region.

On desktop, it may appear beside the main experiment when space permits. On
phones, it follows the experiment content in normal document order.

The current lab is identified with `aria-current="page"`. Related destinations
use descriptive titles without numbering.

### 5.4 Journey continuation

Labs in the approved first-visit journey may include a continuation link:

```text
Continue the first-visit journey
Next: Explore pre-call and post-call checkpoints
```

The continuation is supplementary navigation. It does not disable, hide, or
gate other destinations.

### 5.5 Help drawer

The Help drawer's interaction model remains unchanged:

- the launcher remains fixed at the bottom-right of the viewport while its
  eligible page scrolls;
- the launcher is absent from routes without existing guide content;
- focus enters and remains trapped in the open drawer;
- closing returns focus to the launcher;
- route-specific content and result help continue to work;
- the drawer remains usable at desktop and phone widths.

Only its numbered public title changes. For example:

```text
Lab 9 — Governed vs. Ungoverned
```

becomes:

```text
Governed vs. Ungoverned
```

The drawer must not expose the internal route number in its accessible name.

## 6. Shared content model

One shared lab catalog is the source of truth for the index, individual lab
chrome, related navigation, journey continuation, and Help drawer title.

Each catalog entry supplies:

- internal numeric route ID;
- public title;
- existing short title where still needed internally;
- hero title;
- capability-group identifier;
- capability eyebrow;
- capability question;
- concise lab description;
- related-lab membership;
- optional first-visit journey position and action label.

Numeric IDs remain available to:

- resolve `#/lab/:id`;
- look up Help content;
- select existing lab accent colors;
- preserve API or test fixtures that already use lab IDs.

Components must not independently reconstruct public lab names or groups.

## 7. Route and component structure

A shared lab route wrapper will own public lab-page chrome and landmarks. Its
responsibilities are:

- render exactly one route-level `<main>`;
- render the number-free lab hero;
- render the selected lab body;
- render capability context and related navigation;
- render an optional journey-continuation link.

The wrapper must support the Integration Adapters lab's existing result-help
callback without changing its behavior.

The application-level Help launcher and Help drawer remain outside the route
content as they are today.

The Labs index continues to own its own `<main>` landmark.

## 8. Visual system

The redesign follows the established demo design system rather than introducing
a separate Labs theme.

### 8.1 Typography

- Use the demo's existing IBM Plex typography roles and type scale.
- Interactive rows, card titles, navigation links, and experiment labels use
  ordinary readable body or utility sizes.
- Text such as `Without AEGIS` and `With AEGIS` must not be rendered as tiny
  mockup-style microcopy.
- The smallest permitted text is reserved for established eyebrows or metadata,
  not primary labels or controls.
- Text must remain readable at 200% browser zoom without loss of content or
  functionality.

### 8.2 Color

- Reuse existing light- and dark-theme tokens.
- Preserve the established IBM blue and cyan accent behavior.
- Do not introduce hard-coded colors that fail to adapt between themes.
- Hover, selected, and current states must not rely on color alone.
- Text and interactive-control contrast must satisfy the demo's existing WCAG
  AA target.

### 8.3 Layout

- Keep the demo's square-edged, structured visual language.
- Use the connected first-visit journey as the single signature element.
- Keep capability cards and related navigation visually quieter.
- Keep the fixed Guide launcher clear of viewport safe areas and other fixed
  controls.
- At narrow widths, collapse multi-column regions into one logical reading
  order without horizontal scrolling.

### 8.4 Interaction and motion

- Preserve visible keyboard focus on every link and button.
- Interactive links and buttons provide a target of at least 44 by 44 CSS
  pixels.
- Any hover transition has an equivalent focus treatment.
- No new motion is required. If a transition is used, it must respect
  `prefers-reduced-motion`.

## 9. Accessibility

The implementation must satisfy all of the following:

- exactly one `<main>` landmark on each `#/lab/1` through `#/lab/12` route;
- no nested `<main>` landmarks;
- a descriptive heading hierarchy on the Labs index and every lab page;
- named navigation regions for the first-visit journey, route context, and
  related labs;
- `aria-current="page"` on the current related-lab link;
- no numeric lab labels in visible text or accessible names;
- keyboard access to all lab destinations and the Help drawer;
- unchanged Help drawer focus trap and focus restoration;
- sufficient contrast in light and dark modes;
- status and selection conveyed through more than color;
- logical reading and focus order at desktop and phone widths;
- the fixed launcher remains keyboard reachable and does not make underlying
  controls unreachable at desktop or phone widths.

## 10. Error and edge behavior

The redesign does not add asynchronous state or new API calls.

If a catalog entry is missing optional journey metadata, the page omits the
journey continuation without leaving an empty region.

Unknown lab routes retain the application's current routing behavior; adding a
new error route is outside this change.

Existing lab execution, loading, service-unavailable, policy-failure, pass,
block, pause, and result-help states remain owned by their current lab
components.

## 11. Verification

### 11.1 Catalog and index tests

- Every public lab appears exactly once in a capability group.
- Group titles, questions, lab ordering, and destinations match the approved
  information architecture.
- The recommended journey resolves to the existing three destinations in the
  approved conceptual order.
- Rendered index content contains no `Lab N` labels.
- All legacy `#/lab/:id` destinations remain represented.

### 11.2 Route landmark regression

- Render every route from `#/lab/1` through `#/lab/12`.
- Assert that each route contains exactly one `<main>`.
- Assert that the route hero contains the descriptive title without its
  numeric label.

### 11.3 Navigation tests

- The flat twelve-item lab strip is absent.
- Capability context and related navigation match the active route.
- The active related-lab link exposes `aria-current="page"`.
- Journey continuation appears only for catalog entries that define it.
- All navigation links retain their existing deep-link destinations.

### 11.4 Help drawer regression

- The launcher and drawer continue to open, close, trap focus, and restore
  focus.
- The Help title uses the descriptive lab title without `Lab N`.
- Existing route-specific Help and Integration Adapters result-help behavior
  remain intact.

### 11.5 Responsive and visual checks

Check both light and dark themes at desktop and phone widths:

- readable type in cards, experiment rows, and navigation;
- no horizontal overflow;
- the Guide launcher stays at the viewport's bottom-right while scrolling;
- no Guide launcher on routes without existing guide content;
- no collision with other fixed controls or viewport safe areas;
- related navigation moves below experiment content on phones;
- visible focus treatment;
- connected journey remains understandable without depending on arrows or
  color alone.

## 12. Non-goals

This redesign does not:

- change lab execution or governance behavior;
- change Help drawer instructions, glossary, or result-help content beyond the
  title label;
- rename or redirect existing lab URLs;
- implement Vertex AI or Google ADK adapters;
- add search, filtering, completion tracking, prerequisites, or saved progress;
- redesign Architecture, Scenarios, FAQ, or the global demo navigation;
- change provider compatibility claims.

## 13. Definition of done

The work is complete when:

- a first-time visitor can choose a starting journey without seeing a
  prerequisite-like lab number;
- every lab can be discovered through a capability question;
- visible and accessible lab numbering is removed from the index, lab chrome,
  related navigation, and Help titles;
- existing deep links remain stable;
- every public lab route contains exactly one main landmark;
- the Guide drawer behaves exactly as before;
- the Guide launcher remains fixed and visible while scrolling eligible pages;
- pages without guide content do not show the launcher;
- typography, colors, focus, contrast, and responsive behavior match the
  established demo rules;
- desktop and phone verification shows no fixed-control collision or
  unreachable content;
- Integration Adapters can later add Vertex AI and Google ADK content without
  another Labs navigation redesign.
