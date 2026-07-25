# AEGIS v0.9 Documentation Truth and Demo Architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every maintained AEGIS document and the React architecture/help
experience accurately describe `aegis-ai-governance==0.9.0b1`, prove the
generated diagrams stay synchronized, and validate all optional adapters in
their supported dependency environments.

**Architecture:** Treat package metadata, public modules, schemas, CLI behavior,
and executable tests as implementation truth. Keep a classified documentation
inventory, encode stable claims in parity tests, generate canonical architecture
assets once and mirror them into the React demo, and keep provider integrations
behind optional adapter submodules. Run the normal documentation/demo change
under one spec-driven context and the factual `.claude` status correction under
a separate, bounded instruction-system authorization.

**Tech Stack:** Python 3.12, pytest, PyYAML, jsonschema, React 19, TypeScript,
Vitest, Vite, SVG, FastAPI, local spec-driven-dev policy engine.

## Global Constraints

- The candidate identity is exactly
  `aegis-ai-governance==0.9.0b1`; the import package and CLI remain `aegis`.
- The candidate is merged into `origin/develop`, is not merged into `main`, and
  is not published to PyPI.
- Historical plans, audits, ADRs, articles, completed design specs, archived
  release evidence, and completed spec-driven-dev records are not rewritten.
- The help drawer remains contextual to Architecture or the current lab.
- AEGIS does not take ownership of provider calls, tools, transport,
  credentials, retries, or business state.
- Bedrock and A2A remain dependency-free optional submodules; OpenAI Agents uses
  the already-declared `openai-agents` extra.
- No new runtime dependency, live provider call, credential, production action,
  publication, or deployment is introduced.
- No push, PR, merge, or direct change targets `main`.
- Remote push or PR creation requires a separate exact authorization from the
  installed repository policy.

---

### Task 1: Establish spec-driven context and documentation inventory

**Files:**

- Create:
  `docs/spec-driven-dev/changes/v0.9.0-truth-audit-demo/spec.md`
- Create:
  `docs/spec-driven-dev/changes/v0.9.0-truth-audit-demo/plan.md`
- Create:
  `docs/spec-driven-dev/changes/v0.9.0-truth-audit-demo/tasks.md`
- Create:
  `docs/spec-driven-dev/changes/v0.9.0-truth-audit-demo/documentation-inventory.md`
- Create:
  `docs/spec-driven-dev/changes/v0.9.0-truth-audit-demo/context.json`
- Create:
  `docs/spec-driven-dev/changes/v0.9.0-truth-audit-demo/evaluation.json`
- Create lifecycle decision/context files under the same directory as
  transitions are authorized.

**Interfaces:**

- Consumes:
  `docs/superpowers/specs/2026-07-25-v090-truth-audit-demo-design.md`,
  this plan, `.claude/*.yaml`, and `scripts/policy-engine.py`.
- Produces: a validated `brownfield` context for `local_implementation`, an
  exact documentation classification, and lifecycle evidence for later tasks.

- [ ] **Step 1: Compute the initial change hash**

Run:

```bash
git diff --binary origin/develop...HEAD | shasum -a 256
```

Record the exact 64-character digest. Use it as `change_hash` and as every
initial fact's `observed_at_change`.

- [ ] **Step 2: Write pointer artifacts without duplicating the approved spec**

`spec.md` must contain:

```markdown
# v0.9.0 Truth Audit and Demo Specification

The approved specification is
[`docs/superpowers/specs/2026-07-25-v090-truth-audit-demo-design.md`](../../../superpowers/specs/2026-07-25-v090-truth-audit-demo-design.md).

This change does not authorize publication, deployment, or any action against
`main`.
```

`plan.md` must point to this plan in the same manner. `tasks.md` must list Tasks
1–9 from this plan as unchecked acceptance-linked work.

- [ ] **Step 3: Classify every tracked documentation-like artifact**

Inventory the results of:

```bash
git ls-files '*.md' '*.html' '*.mermaid' '*.svg' '*.png'
```

Assign every result to exactly one section in
`documentation-inventory.md`: maintained current-state, maintained target-state,
historical/versioned evidence, or active instruction-system documentation.
Record “reviewed/no change” only after checking the file against code, schemas,
or current release evidence.

- [ ] **Step 4: Write the local-implementation policy context**

Use `workflow_family: "brownfield"`, `action: "local_implementation"`,
`current_state: "UNCLASSIFIED"`, no open escalation, and these facts:

```json
{
  "documentation_only": false,
  "modifies_runtime_code": true,
  "changes_public_contract": false,
  "adds_external_dependency": false,
  "deploys_to_production": false,
  "instruction_system_change": false
}
```

Each fact must use the exact change hash from Step 1, cite the approved spec or
inventory, identify `codex-repository-fact-extractor-v1`, and carry confidence
between `0.98` and `1.0`.

- [ ] **Step 5: Validate and evaluate the context**

Run:

```bash
.venv/bin/python scripts/policy-engine.py validate --root . --context docs/spec-driven-dev/changes/v0.9.0-truth-audit-demo/context.json
.venv/bin/python scripts/policy-engine.py evaluate --root . --context docs/spec-driven-dev/changes/v0.9.0-truth-audit-demo/context.json --output docs/spec-driven-dev/changes/v0.9.0-truth-audit-demo/evaluation.json
```

Expected: valid evaluation, feature/brownfield routing, no production or remote
authority, and local implementation allowed at the evaluated risk tier.

- [ ] **Step 6: Transition through the pre-implementation lifecycle**

Create hash-bound evidence for `evaluation_passed`, `spec_complete`,
`material_clarifications_resolved`, `plan_complete`,
`instruction_context_valid`, `tasks_trace_to_acceptance`,
`artifact_analysis_clean`, and `implementation_authorized`. Use
`policy-engine.py transition` for each declared edge through `IMPLEMENTING`.

- [ ] **Step 7: Commit the process checkpoint**

```bash
git add docs/spec-driven-dev/changes/v0.9.0-truth-audit-demo
git commit -m "docs: initialize v0.9 truth audit lifecycle"
```

---

### Task 2: Repair executable release truth and current-state documentation

**Files:**

- Modify: `tests/test_pr11_release_truth.py`
- Modify: `tests/test_doc_parity_v090_truth.py`
- Modify: `demo-app-api/tests/test_pr11_all_demo_labs.py`
- Modify: `scripts/check_doc_parity.py`
- Modify: `scripts/check_brand_and_version_parity.py`
- Modify: `doc_parity_manifest.yaml`
- Modify: `README.md`
- Modify: `PROJECT.md`
- Modify: `CHANGELOG.md` (unreleased section only)
- Modify: `CONTRIBUTING.md`
- Modify: `SECURITY.md`
- Modify: `RELEASE_GATES.md`
- Modify: `implementation_status.md`
- Modify: `demo-app-react/README.md`
- Modify: `demo-app-react/public/portal.html`
- Modify: `demo-app-api/main.py`

**Interfaces:**

- Consumes: `pyproject.toml`, `aegis.__version__`, exact merged commit evidence,
  and the Task 1 inventory.
- Produces: executable candidate identity, licensing, support-state, document
  classification, and demo API metadata checks.

- [ ] **Step 1: Capture the existing interpreter-coupling failure**

Run:

```bash
.venv/bin/python -m pytest tests/test_pr11_release_truth.py::test_brand_and_version_parity_script_passes -q
```

Expected before repair: FAIL because the test invokes the global `python`,
which lacks the active environment's `jsonschema`.

- [ ] **Step 2: Fix the test at the interpreter boundary**

Add `import sys` and change:

```python
["python", "scripts/check_brand_and_version_parity.py"]
```

to:

```python
[sys.executable, "scripts/check_brand_and_version_parity.py"]
```

This follows the existing subprocess pattern in
`tests/test_v090_contract_freeze.py`.

- [ ] **Step 3: Add failing current-candidate assertions**

Add tests that require:

```python
assert manifest["distribution_name"] == "aegis-ai-governance"
assert manifest["version"] == "0.9.0b1"
assert 'version="0.9.0b1"' in demo_api_source
assert "Apache-2.0" in contributing
assert "MIT License" not in contributing
assert "0.9.0b1" in security
assert "pre-release" in security.lower()
```

Add a temporary-repository test proving an unclassified tracked Markdown or
diagram file produces a `[documentation-inventory]` parity error.

- [ ] **Step 4: Run the new tests and observe red**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_pr11_release_truth.py tests/test_doc_parity_v090_truth.py demo-app-api/tests/test_pr11_all_demo_labs.py
```

Expected: the interpreter test is green after Step 2; new distribution,
classification, licensing, security, and demo metadata assertions fail.

- [ ] **Step 5: Extend the manifest and parity checker**

Add stable manifest keys:

```yaml
distribution_name: "aegis-ai-governance"
import_package: "aegis"
console_command: "aegis"
candidate_status: "unpublished-beta"
```

Add `documentation_inventory` lists/patterns for current, target, historical,
and instruction-system documents. Implement checks that:

- parse project name/version from `pyproject.toml`;
- compare runtime `aegis.__version__`;
- fail when a tracked documentation-like file is unclassified;
- stop treating `docs/dev/pr_context.md` as current release state;
- require current docs to say candidate/unpublished and not “PR #17 under
  review”;
- preserve PR-specific functions only as historical regression helpers rather
  than current-state authority.

- [ ] **Step 6: Correct root and demo current-state documentation**

Use these canonical statements:

```markdown
Current candidate: `aegis-ai-governance==0.9.0b1`.
It installs `import aegis` and the `aegis` CLI.
The candidate is on `develop`; it is not on `main` and is not published to PyPI.
```

Make these exact corrections:

- `CONTRIBUTING.md`: Apache-2.0, never MIT.
- `SECURITY.md`: retain existing 0.3.x commitments and label `0.9.0b1` as an
  unpublished pre-release candidate without adding a support promise.
- `implementation_status.md`: record PR #17 merged, pending publication, and
  this truth-audit branch as active local work.
- `demo-app-api/main.py`: set FastAPI metadata to
  `version="0.9.0b1"`.
- `demo-app-react/README.md` and `portal.html`: distinguish the local candidate
  from any `main`-deployed live demo.
- architecture HTML footers: Apache-2.0, never MIT.

- [ ] **Step 7: Run focused truth checks**

```bash
.venv/bin/python -m pytest -q tests/test_pr11_release_truth.py tests/test_doc_parity_v090_truth.py demo-app-api/tests/test_pr11_all_demo_labs.py
.venv/bin/python scripts/check_brand_and_version_parity.py
.venv/bin/python scripts/check_doc_parity.py
```

Expected: PASS.

- [ ] **Step 8: Commit the release-truth slice**

```bash
git add tests/test_pr11_release_truth.py tests/test_doc_parity_v090_truth.py demo-app-api/tests/test_pr11_all_demo_labs.py scripts/check_doc_parity.py scripts/check_brand_and_version_parity.py doc_parity_manifest.yaml README.md PROJECT.md CHANGELOG.md CONTRIBUTING.md SECURITY.md RELEASE_GATES.md implementation_status.md demo-app-react/README.md demo-app-react/public/portal.html demo-app-api/main.py
git commit -m "docs: align v0.9 candidate truth"
```

---

### Task 3: Reconcile maintained SDK, policy, architecture, and operations guides

**Files:**

- Modify: `docs/AEGIS_FRAMEWORK.md`
- Modify: `docs/INTEGRATION_GUIDE.md`
- Modify: `docs/PUBLIC_INTEGRATION_CONTRACT.md`
- Modify: `docs/USAGE.md`
- Modify: `docs/migration.md`
- Modify: `policies/policy_dsl_spec.md`
- Modify: `docs/architecture/AEGIS_HIGH_LEVEL_DESIGN.md`
- Modify: `docs/architecture/AEGIS_Architecture_Redesign_and_Roadmap.md`
- Modify: `docs/architecture/AEGIS_THREAT_MODEL.md`
- Modify: `docs/architecture/ARCHITECTURAL_INVARIANTS.md`
- Modify: `docs/architecture/ENFORCEMENT_PIPELINE.md`
- Modify: `docs/reference/OPERATIONS_RUNBOOK.md`
- Modify: `docs/reference/RELEASE_MATRIX.md`
- Modify: `docs/reference/STARTER_INDEX.md`
- Modify: `docs/reference/STARTER_RECIPES.md`
- Modify: `docs/reference/SUPPORTED_ENVIRONMENTS.md`
- Modify: `docs/reference/TROUBLESHOOTING.md`
- Modify: `docs/reference/WORKFLOW_CLI.md`
- Modify: `docs/reference/WORKFLOW_QUICKSTART.md`
- Test: `tests/test_doc_parity_v090_truth.py`
- Test: `tests/test_v090_contract_freeze.py`

**Interfaces:**

- Consumes: public exports, `schemas/policy_dsl.schema.json`,
  `aegis/schemas/policy_dsl.schema.json`, CLI parser definitions, session and
  workflow tests.
- Produces: maintained public guidance with correct current, internal, and
  target-state boundaries.

- [ ] **Step 1: Add red policy/architecture/reference assertions**

Require the policy DSL guide to name implemented workflow keys and commands:

```python
for anchor in (
    "workflow",
    "participants",
    "sequence",
    "budgets",
    "approval_checkpoints",
    "protocol_constraints",
):
    assert anchor in policy_dsl_spec
```

Require current architecture docs to include `0.9.0b1`,
`GovernanceSession`, `workflow trace`, and `workflow export`, while keeping
`AgentIdentity`, `AgentCapabilityManifest`, and `ValidatorHook` outside the
current public surface.

Require quickstart installation instructions to avoid a nonexistent
`git checkout v0.9.0b1` tag while the candidate is unpublished.

- [ ] **Step 2: Run focused tests and observe red**

```bash
.venv/bin/python -m pytest -q tests/test_doc_parity_v090_truth.py tests/test_v090_contract_freeze.py
```

- [ ] **Step 3: Reconcile the authoritative policy DSL guide**

Describe the schema's implemented invocation and workflow sections, accepted
profiles, budgets, transitions, approvals, source constraints, and protocol
constraints. Examples must validate against the root schema; do not document
internal validator hook classes as public APIs.

- [ ] **Step 4: Reconcile current architecture docs**

Use this availability split:

```markdown
Packaged beta public surface:
`AEGIS.open_session(...)`, `GovernanceSession`, `SessionPreCallResult`,
workflow init/lint/doctor/trace/export, and optional adapter submodules.

Internal, not public:
`ValidatorHook`.

Not current public types:
`AgentIdentity`, `AgentCapabilityManifest`.
```

Preserve v0.3.3 history only where it identifies when invocation capabilities
were introduced.

- [ ] **Step 5: Reconcile onboarding and operator references**

Verify every command against CLI help. Replace unpublished tag instructions
with either an editable local checkout command or the explicit
post-publication install command. Update the release matrix to record:

- `origin/develop` merge commit `8be5f54`;
- PR #17 merged, not under review;
- pending Trusted Publisher;
- no `main` merge and no PyPI upload;
- test counts only after Task 8 produces current evidence.

- [ ] **Step 6: Validate examples and links**

```bash
.venv/bin/python scripts/check_doc_parity.py
.venv/bin/python -m pytest -q tests/test_doc_parity_v090_truth.py tests/test_v090_contract_freeze.py
```

Expected: PASS.

- [ ] **Step 7: Commit the maintained-guide slice**

```bash
git add docs/AEGIS_FRAMEWORK.md docs/INTEGRATION_GUIDE.md docs/PUBLIC_INTEGRATION_CONTRACT.md docs/USAGE.md docs/migration.md policies/policy_dsl_spec.md docs/architecture docs/reference
git commit -m "docs: reconcile v0.9 SDK and workflow guides"
```

---

### Task 4: Publish accurate optional-adapter references

**Files:**

- Create: `docs/reference/external/BEDROCK_ADAPTER.md`
- Modify: `docs/reference/external/A2A_ADAPTER.md`
- Modify: `docs/reference/external/OPENAI_AGENTS_ADAPTER.md`
- Modify: `docs/reference/external/README.md`
- Delete: `docs/reference/external/what-is-bedrock.md`
- Modify: `tests/test_doc_parity_v090_truth.py`
- Modify: `tests/test_pr11_release_truth.py`

**Interfaces:**

- Consumes: `aegis/bedrock_adapter.py`, `aegis/a2a_adapter.py`,
  `aegis/openai_agents_adapter.py`, schemas, and focused adapter tests.
- Produces: one accurate reference per optional adapter and no copied general
  provider documentation.

- [ ] **Step 1: Add failing adapter-reference tests**

Require:

```python
assert (root / "docs/reference/external/BEDROCK_ADAPTER.md").exists()
assert not (root / "docs/reference/external/what-is-bedrock.md").exists()
for name in ("BEDROCK_ADAPTER.md", "A2A_ADAPTER.md", "OPENAI_AGENTS_ADAPTER.md"):
    assert name in adapter_index
```

Require the Bedrock guide to include:

```text
BedrockTraceAdapter
BedrockParticipantBinding
BedrockPreparedStep
agent alias ARN
require_trace
require_alias_backed_identity
host owns
not re-exported
```

- [ ] **Step 2: Run the tests and observe red**

```bash
.venv/bin/python -m pytest -q tests/test_doc_parity_v090_truth.py tests/test_pr11_release_truth.py
```

- [ ] **Step 3: Write the Bedrock adapter guide from code**

Include import, policy, prepare/complete flow, parsed trace evidence, ARN
identity example, redacted metadata, replay rules, failure examples, and the
host/AEGIS ownership table. Do not copy AWS product marketing, model lists, or
live service claims.

- [ ] **Step 4: Correct A2A and OpenAI status wording**

Both are included in `0.9.0b1` as submodules, not “local-only” or top-level
exports. Keep A2A dependency-free and keep OpenAI installation exactly:

```bash
pip install "aegis-ai-governance[openai-agents]"
```

- [ ] **Step 5: Remove the unrelated copied provider page**

Delete only:

```text
docs/reference/external/what-is-bedrock.md
```

It is replaced by the focused adapter guide and is not classified as historical
AEGIS evidence.

- [ ] **Step 6: Run focused docs and adapter tests**

```bash
.venv/bin/python -m pytest -q tests/test_doc_parity_v090_truth.py tests/test_pr11_release_truth.py tests/test_bedrock_adapter.py tests/test_a2a_adapter.py tests/test_openai_agents_adapter.py tests/test_pr11_optional_adapter_boundaries.py
.venv/bin/python scripts/check_doc_parity.py
```

- [ ] **Step 7: Commit the adapter-doc slice**

```bash
git add docs/reference/external tests/test_doc_parity_v090_truth.py tests/test_pr11_release_truth.py
git commit -m "docs: document packaged optional adapters"
```

---

### Task 5: Generate truthful architecture diagrams and update the React page

**Files:**

- Modify:
  `docs/architecture/diagrams/render_v090_component_diagrams.py`
- Modify:
  `docs/architecture/diagrams/aegis_architecture_component.mermaid`
- Modify:
  `docs/architecture/diagrams/aegis_architecture_pipeline.mermaid`
- Modify generated canonical SVGs under
  `docs/architecture/diagrams/aegis_architecture_*.svg`
- Modify generated beta SVGs under
  `docs/architecture/diagrams/aegis_v090_beta_component_*.svg`
- Modify React mirrors under `demo-app-react/public/diagrams/*.svg`
- Modify:
  `docs/architecture/diagrams/aegis_architecture_diagram_dark.html`
- Modify:
  `docs/architecture/diagrams/aegis_architecture_diagram_light.html`
- Delete unreferenced stale PNG duplicates under
  `docs/architecture/diagrams/aegis_v090_*_component_*.png`
- Create: `tests/test_architecture_diagram_truth.py`
- Modify: `demo-app-react/src/pages/ArchitecturePage.tsx`
- Modify: `demo-app-react/src/pages/ArchitecturePage.test.tsx`

**Interfaces:**

- Consumes: the approved diagram node inventory and current public boundary.
- Produces: deterministic light/dark component and pipeline diagrams used by
  both docs and React.

- [ ] **Step 1: Invoke the frontend-design guidance**

Read `frontend-design:frontend-design` before changing the React page. Preserve
the existing IBM Plex/cyan visual language, information hierarchy, and
responsive container.

- [ ] **Step 2: Write red diagram-generation tests**

Test that:

```python
assert "Bedrock adapter" in beta_svg
assert "A2A adapter" in beta_svg
assert "OpenAI Agents adapter" in beta_svg
assert "workflow trace" in beta_svg
assert "workflow export" in beta_svg
assert "AgentIdentity" not in beta_svg
assert "AgentCapabilityManifest" not in beta_svg
assert "ValidatorHook" not in beta_svg
assert docs_dark.read_bytes() == demo_dark.read_bytes()
assert docs_light.read_bytes() == demo_light.read_bytes()
```

Add a subprocess check for:

```bash
.venv/bin/python docs/architecture/diagrams/render_v090_component_diagrams.py --check
```

It must fail when output is stale and must never create `aigc_*` files.

- [ ] **Step 3: Write red React page assertions**

Require `AEGIS v0.9 Beta`, `aegis-ai-governance==0.9.0b1`, Host Ownership,
Workflow Governance, Optional Adapters, Public API Boundary, and current diagram
alt text. Remove the test expecting `AEGIS v0.3.3`.

- [ ] **Step 4: Run red tests**

```bash
.venv/bin/python -m pytest -q tests/test_architecture_diagram_truth.py
cd demo-app-react && npm test -- --run src/pages/ArchitecturePage.test.tsx
```

Expected: FAIL on stale/missing adapter nodes, wrong generator output names,
missing `--check`, and v0.3.3 page copy.

- [ ] **Step 5: Repair the generator**

Refactor the output map so canonical and demo paths use `aegis_*`, not
`aigc_*`. Add OpenAI Agents to the beta adapter band, show Bedrock/A2A/OpenAI as
optional normalization, include workflow trace/export, and remove the stale
planned-only footer.

Add deterministic `--check` behavior:

```python
def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    outputs = architecture_outputs()
    if args.check:
        stale = [
            output_path
            for output_path, expected in outputs.items()
            if not output_path.exists()
            or output_path.read_text(encoding="utf-8") != expected + "\n"
        ]
        return 1 if stale else 0
    for output_path, content in outputs.items():
        write_svg(output_path, content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Extend this renderer to generate both component and pipeline light/dark outputs.
The same output map must write the canonical documentation files and their React
mirrors. Update both Mermaid files to carry the same semantic node inventory;
the Python renderer remains the deterministic asset generator.

- [ ] **Step 6: Update the React architecture copy**

Keep the three-section page. Replace the v0.3.3 page identity with candidate
identity and use boundary cards for:

```text
Host Ownership
Workflow Governance
Invocation Enforcement
Optional Adapters
Evidence Separation
Public API Boundary
Signing and AuditChain
Operator Tooling
```

Historical “split default since v0.3.3” remains in the Invocation Enforcement
card.

- [ ] **Step 7: Generate and verify assets**

```bash
.venv/bin/python docs/architecture/diagrams/render_v090_component_diagrams.py
.venv/bin/python docs/architecture/diagrams/render_v090_component_diagrams.py --check
.venv/bin/python -m pytest -q tests/test_architecture_diagram_truth.py
cd demo-app-react && npm test -- --run src/pages/ArchitecturePage.test.tsx
```

Expected: PASS.

- [ ] **Step 8: Commit the architecture slice**

```bash
git add docs/architecture/diagrams demo-app-react/public/diagrams demo-app-react/src/pages/ArchitecturePage.tsx demo-app-react/src/pages/ArchitecturePage.test.tsx tests/test_architecture_diagram_truth.py
git commit -m "feat: refresh v0.9 demo architecture"
```

---

### Task 6: Update contextual Architecture and Labs 1–11 help

**Files:**

- Modify: `demo-app-react/src/help/helpContent.ts`
- Modify: `demo-app-react/src/help/helpContent.test.ts`
- Modify: `demo-app-react/src/components/HelpDrawer.test.tsx`
- Review without redesign:
  `demo-app-react/src/components/HelpDrawer.tsx`

**Interfaces:**

- Consumes: visible labels in all pages, actual API response fields, and current
  architecture boundaries.
- Produces: accurate contextual help with unchanged drawer interaction.

- [ ] **Step 1: Add failing Architecture help assertions**

Require Architecture content to contain:

```text
aegis-ai-governance==0.9.0b1
host owns
GovernanceSession
invocation artifact
workflow artifact
Bedrock
A2A
OpenAI Agents
submodule
```

Keep assertions for split default, `pre_call_enforcement=False`, signing opt-in,
and ordered `pre_output` gates.

- [ ] **Step 2: Add exact-label fidelity assertions for every lab**

For Labs 1–11, construct content from headings, navigation, steps, tips, and
glossary. Assert exact visible action/preset/tab labels from the corresponding
page. Retain the current Lab 8–11 depth checks and add Lab 11 assertions for:

```text
Run Minimal
Failure & Fix
workflow doctor
Build Evidence Trace
workflow trace
```

- [ ] **Step 3: Run help tests and observe red**

```bash
cd demo-app-react && npm test -- --run src/help/helpContent.test.ts src/components/HelpDrawer.test.tsx
```

- [ ] **Step 4: Update content in place**

Do not add navigation or alter drawer structure. Correct only page-specific
copy, labels, explanations, steps, tips, takeaways, and glossary entries. Keep
the current focus trap, Escape behavior, backdrop behavior, and guide heading.

- [ ] **Step 5: Run the React focused suite**

```bash
cd demo-app-react && npm test -- --run src/help/helpContent.test.ts src/components/HelpDrawer.test.tsx src/pages/ArchitecturePage.test.tsx
```

Expected: PASS.

- [ ] **Step 6: Commit the help slice**

```bash
git add demo-app-react/src/help/helpContent.ts demo-app-react/src/help/helpContent.test.ts demo-app-react/src/components/HelpDrawer.test.tsx
git commit -m "docs: align contextual demo help"
```

---

### Task 7: Apply the separately authorized instruction-guide status correction

**Files:**

- Create:
  `docs/spec-driven-dev/changes/v0.9.0-instruction-status-truth/context.json`
- Create:
  `docs/spec-driven-dev/changes/v0.9.0-instruction-status-truth/evaluation.json`
- Create:
  `docs/spec-driven-dev/changes/v0.9.0-instruction-status-truth/response.json`
- Create:
  `docs/spec-driven-dev/changes/v0.9.0-instruction-status-truth/response-result.json`
- Modify only: `.claude/rules/aegis-project.md`
- Test: `tests/test_doc_parity_v090_truth.py`

**Interfaces:**

- Consumes: the installed constitution and an exact owner response.
- Produces: a factual package-status correction with no change to instruction
  behavior.

- [ ] **Step 1: Add a failing parity assertion**

Require `.claude/rules/aegis-project.md` to contain
`aegis-ai-governance==0.9.0b1`, “not published to PyPI”, and the three optional
adapters, while rejecting “published package version remains 0.3.3”.

- [ ] **Step 2: Create and evaluate a separate instruction context**

Use `workflow_family: "instruction_system"`,
`action: "instruction_system_change"`, and
`instruction_system_change: true`. Bind it to a change hash calculated from the
exact proposed one-file patch.

Run:

```bash
.venv/bin/python scripts/policy-engine.py validate --root . --context docs/spec-driven-dev/changes/v0.9.0-instruction-status-truth/context.json
.venv/bin/python scripts/policy-engine.py evaluate --root . --context docs/spec-driven-dev/changes/v0.9.0-instruction-status-truth/context.json --output docs/spec-driven-dev/changes/v0.9.0-instruction-status-truth/evaluation.json
```

Expected: `human_required` with one bounded `authorize_once` option.

- [ ] **Step 3: Pause for the exact owner response**

Present the generated decision ID, policy/context/change hashes, exact one-file
scope, consequences, and recommended `authorize_once` option. Do not modify
`.claude/**` until Neal Bhattacharya supplies the required response fields.

- [ ] **Step 4: Apply the validated response**

Write the exact response and run:

```bash
.venv/bin/python scripts/policy-engine.py respond --root . --context docs/spec-driven-dev/changes/v0.9.0-instruction-status-truth/context.json --response docs/spec-driven-dev/changes/v0.9.0-instruction-status-truth/response.json --output docs/spec-driven-dev/changes/v0.9.0-instruction-status-truth/response-result.json
```

Expected: `autonomous_with_enhanced_gates`.

- [ ] **Step 5: Make only the authorized factual correction**

Replace the stale source-only/0.3.3 package-status paragraph with:

```markdown
These components are included in the
`aegis-ai-governance==0.9.0b1` candidate on `develop`. The candidate is not
published to PyPI and is not merged into `main`.
```

Do not alter authority, lifecycle, Git, review, testing, or security rules.

- [ ] **Step 6: Validate and commit**

```bash
.venv/bin/python scripts/policy-engine.py validate --root .
.venv/bin/python -m pytest -q tests/test_doc_parity_v090_truth.py
git add .claude/rules/aegis-project.md docs/spec-driven-dev/changes/v0.9.0-instruction-status-truth tests/test_doc_parity_v090_truth.py
git commit -m "docs: correct instruction guide candidate status"
```

---

### Task 8: Validate adapters, Python/React suites, and the assembled demo

**Files:**

- Modify only if a test exposes a defect: focused adapter/runtime file plus its
  reproducing test.
- Modify: `doc_parity_manifest.yaml` with the exact final test count.
- Modify current validation summaries in `implementation_status.md` and
  `docs/reference/RELEASE_MATRIX.md`.
- Record results in:
  `docs/spec-driven-dev/changes/v0.9.0-truth-audit-demo/evidence.md`

**Interfaces:**

- Consumes: all implementation tasks.
- Produces: base and extra-enabled adapter evidence, full local validation, and
  browser evidence.

- [ ] **Step 1: Run the base adapter matrix before installing optional SDKs**

```bash
.venv/bin/python -m pytest -q -rs tests/test_a2a_adapter.py tests/test_bedrock_adapter.py tests/test_openai_agents_adapter.py tests/test_openai_agents_adapter_integration.py tests/test_pr11_optional_adapter_boundaries.py
```

Expected baseline: all fixture/unit tests pass and only the real OpenAI SDK
integration skips because the extra is absent.

- [ ] **Step 2: Create an isolated OpenAI-extra validation environment**

Use a temporary Python 3.12 environment outside the repository:

```bash
ADAPTER_VENV_DIR=$(mktemp -d /private/tmp/aegis-adapter-extra.XXXXXX)
.venv/bin/python -m venv "$ADAPTER_VENV_DIR"
"$ADAPTER_VENV_DIR/bin/python" -m pip install -e ".[dev,openai-agents]"
```

Network access is allowed only for installing the already-declared validation
extra. No credentials are configured.

- [ ] **Step 3: Run the extra-enabled adapter matrix**

In the isolated environment:

```bash
"$ADAPTER_VENV_DIR/bin/python" -m pytest -q -rs tests/test_a2a_adapter.py tests/test_bedrock_adapter.py tests/test_openai_agents_adapter.py tests/test_openai_agents_adapter_integration.py tests/test_pr11_optional_adapter_boundaries.py
```

Expected: the real OpenAI integration executes rather than skips; no test makes
a provider call.

- [ ] **Step 4: Run all configured Python validation**

```bash
.venv/bin/python scripts/policy-engine.py validate --root .
.venv/bin/python scripts/check_doc_parity.py
.venv/bin/python scripts/check_brand_and_version_parity.py
.venv/bin/python -m pytest
.venv/bin/python -m pytest --cov=aegis --cov-fail-under=90
.venv/bin/flake8 aegis
.venv/bin/python -m pytest -q demo-app-api/tests
```

Record exact pass/skip/test counts. Update `doc_parity_manifest.yaml` and only
the maintained current-state summaries that intentionally carry those counts,
then rerun parity and affected tests.

- [ ] **Step 5: Run complete React validation**

```bash
cd demo-app-react
npm test
npm run lint
npm run build
```

Expected: PASS.

- [ ] **Step 6: Invoke the webapp-testing skill and run the local app**

Read `anthropic-skills:webapp-testing`. Start the maintained FastAPI backend and
Vite frontend using their documented local commands. Use browser automation to
verify:

- Architecture component and pipeline images load in dark and light themes;
- mobile and desktop widths retain readable overflow behavior;
- Architecture and Labs 1–11 open the correct contextual guide;
- Escape, close button, backdrop, focus trap, and focus return work;
- Lab 11 Minimal succeeds;
- Failure & Fix exposes the documented diagnosis;
- Build Evidence Trace produces the documented trace view;
- representative Labs 1–10 still call the real local API successfully.

- [ ] **Step 7: If an adapter defect appears, use strict red/green repair**

Do not broaden the adapter contract. Add the smallest reproducing test, confirm
red, make one fix, run focused tests, then rerun Steps 1–4. Record the repair
cycle in spec-driven evidence.

- [ ] **Step 8: Commit validation truth**

```bash
git add doc_parity_manifest.yaml implementation_status.md docs/reference/RELEASE_MATRIX.md docs/spec-driven-dev/changes/v0.9.0-truth-audit-demo/evidence.md
git commit -m "test: record v0.9 truth audit validation"
```

---

### Task 9: Review, converge, and prepare a develop-only handoff

**Files:**

- Modify:
  `docs/spec-driven-dev/changes/v0.9.0-truth-audit-demo/tasks.md`
- Modify:
  `docs/spec-driven-dev/changes/v0.9.0-truth-audit-demo/evidence.md`
- Create:
  `docs/spec-driven-dev/changes/v0.9.0-truth-audit-demo/review.md`
- Create final lifecycle contexts/decisions under the same directory.

**Interfaces:**

- Consumes: exact final diff and validation evidence.
- Produces: reviewed local branch ready for an explicitly authorized PR to
  `develop`, with no `main` action.

- [ ] **Step 1: Invoke verification-before-completion**

Read `superpowers:verification-before-completion`. Rerun every command used to
support a final claim from a clean working tree state.

- [ ] **Step 2: Review every changed file**

Use:

```bash
git diff --name-only origin/develop...HEAD
git diff --check origin/develop...HEAD
git diff --stat origin/develop...HEAD
```

Perform a distinct correctness, documentation-truth, generated-asset,
accessibility, adapter-boundary, public-import, and no-`main` review. Confirm no
historical path changed except the newly created current change evidence.

- [ ] **Step 3: Refresh spec-driven hashes and transition**

Recompute the final change hash, refresh fact/evidence hash bindings, reevaluate,
and authorize:

```text
IMPLEMENTING -> VALIDATING -> REVIEWING -> CONVERGING -> COMPLETE
```

Do not use the release path because this task neither publishes nor releases.

- [ ] **Step 4: Close every task and record review findings**

Mark Tasks 1–9 complete only when their evidence exists. `review.md` must list
changed files, checks, findings, repairs, remaining limitations, reversal, and
the exact branch/base.

- [ ] **Step 5: Commit the final local evidence**

```bash
git add docs/spec-driven-dev/changes/v0.9.0-truth-audit-demo
git commit -m "docs: finalize v0.9 truth audit evidence"
```

- [ ] **Step 6: Stop before remote mutation**

Report the local branch and commits. Do not push, create a PR, merge, publish,
or touch `main`. If the owner requests a remote PR, create a separate
`push_branch`/`open_pull_request` policy context and request exact authorization
for a PR targeting `develop` only.
