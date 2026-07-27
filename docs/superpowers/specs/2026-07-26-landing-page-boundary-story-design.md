# AEGIS Landing Page Boundary Story Design

**Date:** 2026-07-26
**Status:** Approved direction; implementation pending

## Purpose

Rewrite and reflow the public landing page so business and technology visitors
understand the enterprise problem before they encounter product mechanics.
The page should establish AEGIS as independently owned runtime governance:
the deterministic wrapper around a probabilistic AI invocation or agentic
workflow.

The page must be precise about the product boundary. AEGIS makes governance
decisions deterministic and auditable; it does not make model reasoning or
model output deterministic.

## Audience and Page Job

The primary audience is enterprise technology, risk, governance, and business
leadership evaluating how AI or agentic systems move into production.

The page has one job: help a visitor understand why enterprise AI governance
must execute in the runtime path, then give that visitor a direct route into the
architecture, scenarios, or labs.

## Narrative Structure

The page will use the approved **Boundary Story**:

1. Establish the tension between probabilistic AI and deterministic enterprise
   permission.
2. Show AEGIS surrounding the invocation boundary before and after execution.
3. Explain which responsibilities remain with the host application and which
   governance responsibilities AEGIS enforces.
4. Distinguish model-generated explanations from independently produced
   governance evidence.
5. Show how AEGIS is added to an invocation or agentic workflow the enterprise
   already owns.
6. Close the narrative with **“Governance is infrastructure.”**
7. Offer Architecture, Scenarios, and Labs as the next paths.

## Navigation

The header will always contain two rows and keep the same total height on every
route. Navigating between the landing page, demo pages, labs, and FAQ must not
shift the page body vertically.

### Landing page

- Row 1: `AEGIS`, `Install`, `Open demo`, `FAQ`, `GitHub`, and theme control.
- Row 2: `Auditable Enforcement and Governance for Intelligent Systems`.
- Remove `What it does`.
- `Open demo` remains the filled primary action.

### Demo and lab routes

- Row 1: `AEGIS`, `Install`, `Demo`, `FAQ`, `GitHub`, and theme control.
- Replace the landing-page product name in row 2 with the existing demo
  navigation: `Architecture`, `Scenarios`, `Labs`, and `FAQ`.
- `Demo` is a non-interactive current-location indicator, not a hyperlink.
- The indicator uses a transparent background, blue outline, and
  `aria-current="location"` semantics.
- The active second-row destination keeps its existing blue underline.

The `/faq` route continues to show the demo-navigation row because it is shared
by the public and demo experiences. On that route, `FAQ` is the current
destination and `Open demo` remains an available link; `Demo` must not be
announced as the current location.

At narrow widths, both rows remain single-line navigation lanes with contained
horizontal overflow. The header must not create a third row or page-level
horizontal overflow. All controls retain a minimum 44px target.

The first-row controls use the same block size whether `Open demo` is a filled
link or `Demo` is an outlined current-location indicator. The landing product
name and the demo navigation occupy the same second-row track with the same
height, border treatment, and vertical alignment.

## Hero

The hero will lead with the product thesis rather than a feature statement.

**Eyebrow:** `Runtime governance for AI calls and agent workflows`

**Headline:** `The deterministic wrapper around a probabilistic core.`

**Supporting copy:**

> AI works in possibilities. Enterprise systems need a definite decision:
> allow, block, pause, or escalate. AEGIS enforces your enterprise policy at
> the boundary—before an AI acts and before its output becomes an operational
> outcome.

The hero retains the two actions, with the demo as the primary route and
installation as the secondary route.

The call-flow visual becomes the page's signature element. It will show a model
call or agent action as the probabilistic core visibly enclosed by:

- deterministic pre-call policy enforcement;
- host-owned model, agent, and tool execution;
- deterministic post-call validation; and
- an external governance record.

This visual encodes the product thesis rather than serving as decoration.

## Enterprise Boundary Section

**Eyebrow:** `The enterprise boundary`

**Headline:** `Let AI handle possibility. Make policy decide permission.`

The explanatory copy must make the distinction explicit:

- Models and agents can reason through ambiguous situations and propose
  outcomes.
- Enterprise permission cannot be left to a probability distribution.
- AEGIS resolves the governance decision against declared, versioned enterprise
  policy at the runtime boundary.
- The host application continues to own orchestration, credentials, execution,
  business state, and downstream action.

The existing three-card structure will be reframed as:

1. **Probabilistic core** — model and agent reasoning, planning, generation, and
   tool proposals.
2. **Deterministic governance** — roles, preconditions, tool limits, approvals,
   budgets, output rules, and risk treatment enforced by AEGIS.
3. **Enterprise operation** — host-owned execution, business state, downstream
   action, and storage of independently generated evidence.

## External Evidence Section

**Eyebrow:** `Independent governance evidence`

**Headline:** `An explanation is not a control.`

**Introductory idea:** A thought trace can help a team understand model
behavior. It is still an account produced by the system being inspected.
Enterprise governance needs a separate record produced outside the model that
shows which policy ran, what was allowed or blocked, and why.

The comparison will use a plain-language analogy that works for business and IT
audiences:

### The model's account

**Supporting label:** `Useful clues for understanding behavior`

- Produced by the model being inspected.
- Helps with debugging and behavioral inspection.
- May omit an influence or construct a plausible explanation after the fact.
- Cannot independently authorize or stop an enterprise action.
- Does not prove which enterprise policy was executed.

### The system's receipt

**Supporting label:** `Independent evidence of the governance decision`

- Produced by AEGIS outside the model.
- Tied to a versioned policy and ordered enforcement gates.
- Records allow, block, pause, or escalation outcomes.
- Can stop a request before execution or reject output before use.
- Captures reason codes, checksums, policy metadata, and workflow context.

The existing thought-trace faithfulness research link remains, but its source
line uses the full prose measure instead of the current narrow column.

## First Integration Section

**Headline:**
`Add AEGIS to an AI invocation or agentic workflow you already own.`

The introductory copy will explain that policy enforcement runs before
execution and output validation runs after it, while the host-owned call remains
visible between those checkpoints.

The install command remains:

`pip install aegis-ai-governance==0.9.0b1`

The install command must never wrap. Its container may scroll horizontally at
small widths without causing page-level overflow.

On desktop, the explanatory and installation column receives more width while
the code sample becomes narrower. On small screens, the columns stack and both
code surfaces contain their own horizontal overflow.

## Closing Principle and Demo Entry

Add a closing principle immediately before the demo-entry cards.

**Headline:** `Governance is infrastructure.`

The supporting copy will explain that models, providers, and agent frameworks
can change while the enterprise-owned governance boundary remains declared,
executable, independently observable, and auditable.

After that conclusion, the page offers:

- **Architecture** — understand the ownership boundary and technical map.
- **Scenarios** — follow governed enterprise cases.
- **Labs** — inspect individual controls and evidence.

## Layout and Responsive Behavior

- Continue using the existing IBM Plex type system and theme tokens.
- Preserve the current restrained IBM-influenced visual language; this is a
  narrative and layout polish, not a wholesale rebrand.
- Increase the landing-page shell from 1200px to the established 1360px product
  width where appropriate.
- Allow section introductions and source lines to use approximately 90–100ch
  rather than the current 70ch half-width constraint.
- Keep headings intentionally bounded for hierarchy, but do not constrain body
  paragraphs to half of the available desktop width.
- Preserve visible keyboard focus, minimum 44px targets, dark-theme contrast,
  and reduced-motion behavior.
- Keep the two-row header at a constant total height across all routes and
  breakpoints. Use horizontal overflow rather than wrapping either row.
- Verify landing and demo headers at 1440px, 1024px, 768px, 390px, and 320px.

## Test and Verification Contract

Implementation will begin with failing tests for these observable behaviors:

1. The public navigation no longer exposes `What it does`.
2. The landing header exposes the full product name on row 2.
3. Demo routes expose a non-link `Demo` current-location indicator.
4. Demo routes replace the product-name row with demo navigation.
5. Landing, demo, lab, and FAQ routes expose the same two-row header height.
6. The hero contains the approved headline and supporting copy.
7. The boundary section states that enterprise permission is resolved by
   declared policy without claiming deterministic model output.
8. The evidence comparison uses `The model's account` and
   `The system's receipt`.
9. The integration headline uses the approved invocation-or-workflow wording.
10. The install command has a no-wrap style contract.
11. The page closes with `Governance is infrastructure.` before the demo-entry
    region.

Fresh verification will include:

- targeted red/green component tests;
- the complete Vitest suite;
- ESLint;
- the demo copy checker;
- the production TypeScript/Vite build; and
- responsive visual inspection in both themes with checks for page-level
  overflow.

## Out of Scope

- Changing AEGIS runtime behavior or API contracts.
- Adding new demo routes or labs.
- Rebranding the broader demo application.
- Adding new analytics, external services, or dependencies.
- Changing the package version or install command.
