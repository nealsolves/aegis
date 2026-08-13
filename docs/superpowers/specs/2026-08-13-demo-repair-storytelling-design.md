# Demo Repair and Documentary Storytelling Design

**Date:** 2026-08-13
**Status:** Approved, amended for the autonomous Meridian flow
**Scope:** Demo API, three public scenarios, twelve labs, shared demo navigation and visual/accessibility foundation

## 1. Objective

Repair every defect found during end-to-end testing without relaxing AEGIS SDK validation globally, then make the demo understandable and engaging for a general audience through active documentary storytelling. The implementation must preserve the updated site's IBM-inspired visual system and the existing floating Help button and Help drawer.

The demo must teach a truthful boundary:

- the host application and AI system execute work and produce candidate output;
- AEGIS evaluates that work against an approved policy at runtime;
- AEGIS can allow, block, pause, and record evidence;
- AEGIS does not discover hidden business rules, call itself an AI model, or rewrite model output.

## 2. Non-negotiable constraints

1. Do not broaden any public SDK schema, constructor, validator, or accepted input type to accommodate demo data.
2. Do not post-process finalized evidence by stripping, rewriting, or recalculating protected fields.
3. Browser state is never authoritative for a decision, reason code, gate result, checksum, chain coordinate, or evidence artifact.
4. The existing `HelpButton` and `HelpDrawer` remain structurally and visually unchanged.
5. Preserve IBM Plex Sans and IBM Plex Mono and the current IBM-inspired palette.
6. Status must never rely on color alone.
7. All scenario motion must have a complete reduced-motion equivalent.
8. Do not add a new animation dependency. Use React state and CSS transitions/animations.

## 3. Strict backend repair design

### 3.1 Meridian fixture and policy

Keep SDK full-match validation unchanged. Meridian supplies a bounded
`payment_request_id` matching `PAYMENT-MV-<digits>` and attempts the
`authorize_payment` action through the real four-step workflow. The autonomous
assistant skips vendor verification and risk review. Without policy-based
governance, the story outcome is **Payment authorized**. With AEGIS enforcing
the workflow policy at runtime, the out-of-sequence authorization fails closed
with `WORKFLOW_SEQUENCE_VIOLATION` before execution. Meridian has no visitor
choice, human approval checkpoint, or corrected human-review variant.

### 3.2 Audit Chain lab

Replace the client-authored incremental chain contract. A single bounded server request creates a complete three-entry chain with an `AuditChain` configured as the AEGIS `chain_linker` before enforcement. A retaining sink captures the already-finalized artifacts. The UI progressively reveals the returned chain entries.

Verification remains a separate public operation over a bounded list of artifacts. Intentional tampering remains a separate operation. The lab must state that it demonstrates internal integrity and continuity, not durable append-only storage, rollback protection, or completeness.

### 3.3 A2A immutable compiler seam

Keep `_a2a_protocol_constraints` strict. Add a private A2A-only projection at the compiled-session seam. It accepts only the compiler-owned immutable A2A constraint representation, recursively validates the closed A2A shape, returns a detached plain dictionary/list structure, and then calls the existing validator. Arbitrary `Mapping` implementations remain rejected.

### 3.4 Generated workflow runtime

Generated starter source remains unchanged. The demo module proxy accepts only the checked-in starter's recognized file-sink intent and a closed allowlist of safe constructor arguments. It creates the actual root-bound `FilePolicyLoader` and server-owned sink itself. Positional arguments, foreign sinks/loaders, signers, chain linkers, and unknown constructor options fail closed.

### 3.5 Policy composition lab

Separate two concepts in API and UI:

- **merge preview:** show what the selected merge strategy produces;
- **AEGIS admission:** load the selected child through a temporary root-bound parent/child policy graph and report whether the public loader/compiler admits it.

The request-selected strategy is authoritative; an embedded child strategy cannot silently override it. Roles and other authorization-bearing declarations remain closed declarations and do not union. Teaching fixtures demonstrate strategy differences using fields whose documented semantics actually vary.

### 3.6 Error contract

Every lab exposes its request failure. A shared frontend error component renders a stable public code or safe message, a specific recovery action, and a request identifier when supplied. Backend logs retain internal detail; public responses never expose paths, exception text, or secrets.

## 4. Documentary scenario engine

### 4.1 Shared narrative sequence

The scenario shell supports two truthful interaction models. Atlas and
Northstar use a visitor-judgment story; Meridian uses an autonomous comparison
with no person in the loop.

The visitor-judgment model uses:

1. **Question** — introduce the person, organization, system, and request.
2. **AI answer or attempted action** — show the deterministic host-supplied candidate.
3. **Consequence and visitor judgment** — explain the concrete risk and ask what the visitor would do.
4. **AEGIS runtime evaluation** — send the real request; show only neutral pending motion before the response.
5. **Decision and evidence** — reveal returned gates in returned order and identify host facts versus AEGIS results.
6. **Correction and replay** — the host/AI changes the input; AEGIS evaluates again.

The visitor choice is a prediction and engagement device. It never manufactures or alters the backend result.

The autonomous-comparison model uses:

1. **Request** — introduce the input received by the AI assistant.
2. **Agent action** — show the action the assistant attempts on its own.
3. **Without AEGIS** — show the consequence when no policy-based governance evaluates the action.
4. **With AEGIS** — run the real governed request and reveal the returned block and evidence.

Both models share the same backend-authoritative evaluation, evidence,
pause/replay controls, live-region behavior, and reduced-motion rules.

### 4.2 Signature layout: governance rail

On wide screens, the human story remains in the left column while a governance rail in the right column shows the runtime boundary. On narrow screens, the active story stage appears first and the governance rail follows in document order. The page uses meaningful numbered chapters because the order is essential.

### 4.3 Motion truth rules

- Before a response, animate only a neutral request handoff or bounded progress indicator.
- After a response, reveal gates in the order returned by the API.
- Never animate toward an assumed status, score, reason, or artifact.
- Motion uses opacity and small transforms and completes quickly; it does not loop.
- Provide a visible pause/replay control for the story reveal.
- `prefers-reduced-motion: reduce` removes spatial movement and reveals the same content immediately.
- Live-region announcements are based on state changes, not animation frames.
- Animation never steals focus or changes reading order.

### 4.4 Atlas story

Atlas asks its AI assistant whether a fictional storm policy covers a missed connection. The ungoverned assistant incorrectly says it is covered. The controlling fictional business rule `BRV-04` says this situation is not covered, and Atlas loses money after honoring the wrong answer.

For the governed replay, Atlas has already converted the approved rule into an enforceable AEGIS policy. The same wrong draft reaches AEGIS before delivery. The policy requires `coverage_decision: not_covered` and `policy_citation: BRV-04`; AEGIS blocks the wrong or uncited draft. Atlas's host/AI revises the answer, and AEGIS evaluates the revision and permits delivery.

### 4.5 Northstar and Meridian

Northstar uses the visitor-judgment sequence for unauthorized access, scoped
retry, physician approval, and corrected scheduling-only output. Meridian uses
the autonomous comparison: its AI assistant attempts to authorize invoice
MV-248 without the required vendor and risk checks; without AEGIS the payment is
authorized, while AEGIS blocks the unauthorized payment before execution.
Both remain wholly fictional and preserve authentic workflow evidence
semantics.

## 5. Shared lab experience contract

All twelve labs follow this learning rhythm:

1. **Change inputs** — state what the visitor controls.
2. **Run AEGIS** — use an explicit action label describing the operation.
3. **Understand** — lead with plain-language meaning and semantic status.
4. **Inspect evidence** — progressively disclose code, YAML, identifiers, and artifacts.

Each lab retains a specialized instrument:

| Lab | Instrument |
| --- | --- |
| 1 Risk scoring | Factor controls and risk gauge |
| 2 Signing | Key input, signing, verification, and tamper comparison |
| 3 Audit chain | Progressive server-generated chain reveal |
| 4 Composition | Merge preview and admission result |
| 5 Loaders | Source, loader, date, and version workbench |
| 6 Custom gates | Gate selector, gate stack, and decision |
| 7 Compliance | Evidence mapping filters and table |
| 8 Knowledge base | Governed retrieval path and sources |
| 9 Governed vs ungoverned | Truthful side-by-side comparison |
| 10 Split enforcement | Pre-call/post-call boundary |
| 11 Workflows | Session state, checkpoints, and replay |
| 12 Adapters | Provider normalization trace |

`LabRouteLayout` provides the shared responsive learning shell, while shared
semantic CSS contracts provide workbench/result sections, status treatment,
error treatment, explanation blocks, metrics, and evidence disclosure. These
presentation rules do not replace specialized lab controls or change the Help
button and drawer.

## 6. Visual system

### 6.1 Typography

- IBM Plex Sans: headings, narrative, descriptions, labels, controls, status explanations, and navigation.
- IBM Plex Mono: code, YAML, checksums, policy identifiers, reason codes, and compact technical metadata only.
- General explanatory text is at least 16px on primary reading surfaces; compact metadata is never the sole explanation.

### 6.2 Color

Keep the current site palette. Lab accent colors organize sections but never communicate pass/fail state. Define contrast-tested semantic tokens for success, failure, warning/pause, information, and neutral states in both light and dark themes. Every status pairs color with an icon and text.

Add an explicit Lab 12 accent entry so every lab has a declared color.

### 6.3 Responsive behavior

- All fixed two-, three-, and four-column lab grids collapse at appropriate breakpoints.
- No primary navigation control is hidden off-screen at 390px.
- Primary actions are full-width when needed on narrow screens.
- Code and tables scroll inside their own labeled regions without forcing page-level horizontal overflow.

## 7. Accessibility

Target WCAG 2.2 AA behavior and additionally provide a 44px product-level target for primary interactive controls.

- Visible `:focus-visible` styling applies to links, buttons, inputs, selects, textareas, summaries, tabs, and custom controls.
- No component uses `outline: none` without an equal or stronger replacement.
- Every control has a programmatic label and associated error/description where applicable.
- Tabs use correct tablist/tab/tabpanel relationships and keyboard behavior.
- Loading uses `aria-busy`; result announcements use concise `aria-live` regions without duplicating full content.
- Focus remains on the initiating action during async work and moves only when required to make a blocking error discoverable.
- Disabled state is not communicated through opacity alone.
- Touch and pointer targets meet the shared target-size rule.

The floating Help button, drawer, focus trap, Escape behavior, contextual result help, and focus restoration remain unchanged.

## 8. Testing and acceptance

Backend acceptance includes focused regression tests for each repaired defect, strict negative-contract tests, all demo API tests, the full SDK suite, and the security smoke checks.

Frontend acceptance includes component tests for scene states, backend-authoritative motion, reduced motion, shared lab primitives, every lab error state, keyboard/focus behavior, responsive class contracts, copy-policy checks, lint, unit tests, and production build.

Manual end-to-end acceptance covers all Atlas/Northstar/Meridian variants, all twelve labs, light/dark themes, keyboard-only use, 390px mobile layout, reduced motion, API unavailable/mismatch states, artifact inspection/download, no browser console errors, and no false success when the API fails.
