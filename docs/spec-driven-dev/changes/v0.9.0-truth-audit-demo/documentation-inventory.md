# Documentation Inventory

**Change ID:** `v0.9.0-truth-audit-demo`

**Observed base:** `origin/develop` at `8be5f54`

**Inventory command:**

```bash
git ls-files '*.md' '*.html' '*.mermaid' '*.svg' '*.png'
```

**Tracked results at initial inventory:** 167

The path rules below are mutually exclusive after the named exceptions are
applied. Each tracked result belongs to exactly one class.

## Maintained Current-State Documentation

### Root and product status

- `ARCHITECTURAL_INVARIANTS.md`
- `CHANGELOG.md` (current/unreleased section; released entries are history)
- `CONTRIBUTING.md`
- `PROJECT.md`
- `README.md`
- `RELEASE_GATES.md`
- `SECURITY.md`
- `implementation_status.md`
- `policies/policy_dsl_spec.md`

### Maintained SDK and workflow guides

- `docs/AEGIS_FRAMEWORK.md`
- `docs/INTEGRATION_GUIDE.md`
- `docs/PUBLIC_INTEGRATION_CONTRACT.md`
- `docs/USAGE.md`
- `docs/migration.md`
- `docs/architecture/AEGIS_THREAT_MODEL.md`
- `docs/architecture/ARCHITECTURAL_INVARIANTS.md`
- `docs/architecture/ENFORCEMENT_PIPELINE.md`
- every tracked file under `docs/reference/`

Exception: the existing `docs/reference/external/what-is-bedrock.md` is
classified current but invalid for AEGIS. It will be replaced by
`BEDROCK_ADAPTER.md`, not archived as project evidence.

### Maintained architecture assets

- `docs/architecture/diagrams/aegis_architecture_component.*`
- `docs/architecture/diagrams/aegis_architecture_pipeline.*`
- `docs/architecture/diagrams/aegis_architecture_diagram_dark.html`
- `docs/architecture/diagrams/aegis_architecture_diagram_light.html`
- `docs/architecture/diagrams/aegis_v090_beta_component_*`

The checked-in PNG duplicates are unreferenced generated artifacts. They are
reviewed in this class and may be removed when SVG is confirmed canonical.

### Maintained demo documentation and visual assets

- `demo-app-react/README.md`
- `demo-app-react/index.html`
- `demo-app-react/public/portal.html`
- every tracked file under `demo-app-react/public/diagrams/`
- `demo-app-react/public/favicon.svg`
- `demo-app-react/public/icons.svg`
- `demo-app-react/src/assets/hero.png`
- `demo-app-react/src/assets/vite.svg`
- `graphics/aegis_banner.png`
- `graphics/aegis_logo.png`

The non-diagram image files contain no release or API claims; they are visual
application/branding assets reviewed for classification only.

## Maintained Target-State Documentation

- `docs/architecture/AEGIS_Architecture_Redesign_and_Roadmap.md`
- `docs/architecture/AEGIS_HIGH_LEVEL_DESIGN.md`
- `docs/architecture/diagrams/aegis_v090_full_component_*`

These files may describe future architecture but must distinguish packaged beta,
internal-only, and planned public surfaces.

## Historical or Versioned Evidence

- `docs/architecture/AEGIS_0.3.0_ARCHITECTURE_DIAGRAM.md`
- every tracked file under `docs/articles/`
- every tracked file under `docs/audits/`
- every tracked file under `docs/decisions/`
- every tracked file under `docs/design/`
- every tracked file under `docs/dev/`
- every tracked file under `docs/plans/`
- every tracked file under `docs/releases/`
- `docs/spec-driven-dev/BOOTSTRAP.md`
- every tracked file under
  `docs/spec-driven-dev/changes/v0.9.0-pypi-distribution/`
- existing pre-change files under `docs/superpowers/plans/` and
  `docs/superpowers/specs/`

Exceptions: the current approved spec and plan named below are active artifacts,
not historical inputs:

- `docs/superpowers/specs/2026-07-25-v090-truth-audit-demo-design.md`
- `docs/superpowers/plans/2026-07-25-v090-truth-audit-demo.md`
- `docs/spec-driven-dev/changes/v0.9.0-truth-audit-demo/`

Historical bodies are not rewritten by this change.

## Active Instruction-System Documentation

- `CLAUDE.md`
- every tracked Markdown file under `.claude/`
- `.specify/memory/constitution.md`

Only `.claude/rules/aegis-project.md` contains an identified stale package-status
statement. Its correction is isolated behind a separate instruction-system
decision. No other instruction-system document is changed.

## Review Result Rules

- Current-state files are checked against metadata, public modules, schemas,
  CLI behavior, tests, and current merge/publication evidence.
- Target-state files are checked for explicit availability boundaries.
- Historical files are excluded from current-state rewriting.
- Active instruction files require the installed constitution and policy.
- “Reviewed, no change” is recorded only after the applicable comparison.
