# Demo Repair and Documentary Storytelling Implementation Plan

> **Status:** Implementation complete; holistic acceptance in progress.

**Goal:** Repair the demo's backend flows and deliver truthful animated
documentary scenarios plus one accessible visual contract across all twelve
labs without relaxing SDK validation globally.

**Spec:** `docs/superpowers/specs/2026-08-13-demo-repair-storytelling-design.md`

## Global constraints

- Do not relax SDK validation globally.
- Do not mutate or refinalize finalized evidence.
- Do not allow browser state to author decisions, gates, reason codes,
  checksums, chain coordinates, or artifacts.
- Do not change `HelpButton` or `HelpDrawer` markup, styles, behavior, or tests.
- Preserve IBM Plex Sans, IBM Plex Mono, the IBM-inspired palette, visible
  focus, reduced motion, and semantic non-color status cues.
- Preserve the user's existing `.gitignore` modification.

## Completed implementation

- [x] Keep the public SDK validators strict and add only a closed private
  projection for compiler-owned immutable A2A constraints.
- [x] Close the generated-demo capability adapter around recognized starter
  intent; reject foreign loaders, sinks, signers, chain linkers, and kwargs.
- [x] Make the Audit Chain lab build its complete finalized chain server-side.
- [x] Separate composition preview from public-loader admission and report
  widening as a failure rather than false success.
- [x] Replace Atlas's old fixture with the approved missed-connection story and
  enforce `coverage_decision: not_covered` plus `policy_citation: BRV-04`.
- [x] Implement backend-authoritative scenario playback with pause/replay,
  concise live announcements, responsive layout, and reduced-motion support.
- [x] Implement Meridian as a fully autonomous comparison: without AEGIS the
  AI assistant authorizes the payment; with AEGIS the out-of-sequence
  `authorize_payment` action is blocked before execution. No human choice,
  approval checkpoint, or corrected human-review variant remains.
- [x] Apply the shared `LabRouteLayout` presentation and responsive/accessibility
  CSS contracts across all twelve lab routes while preserving each specialized
  instrument.
- [x] Preserve the floating Help button and Help drawer unchanged.
- [x] Add focused backend and frontend regression coverage.
- [x] Pass the full automated baseline: Python, frontend unit tests, lint, copy
  validation, and production build.

## Acceptance status

- [x] Run Atlas, Northstar, and Meridian end to end and verify every available
  variant, returned decision, story control, and evidence relationship.
- [x] Run all twelve labs end to end and verify the primary action, semantic
  result, evidence disclosure, and explicit error behavior.
- [x] Repeat representative flows in light and dark themes and exercise
  keyboard focus, Help drawer Escape/focus restoration, and named controls.
- [ ] Complete a direct 390px and reduced-motion browser-emulation pass. The
  current in-app browser automation surface did not expose viewport or media
  emulation; responsive and reduced-motion contracts are covered in CSS and
  automated tests but remain a manual handoff residual.
- [x] Verify live API request failure, no false success, artifact
  inspection/download, and typed negative results.
- [ ] Complete a direct contract-mismatch and console-stream inspection. Both
  states have automated coverage; the current browser surface did not expose a
  console stream or response-stubbing seam for the production build.
- [x] Run the security smoke check and a fresh complete automated verification.
- [x] Record exact commands, observations, screenshots where useful, and any
  residual limitation in `docs/superpowers/reports/`.
- [x] Perform an adversarial review of the final diff and resolve material
  findings before handoff.
