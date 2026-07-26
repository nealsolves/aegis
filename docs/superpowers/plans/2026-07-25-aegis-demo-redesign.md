# AEGIS Demo Site Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current SDK-first demo with a plain-language introduction, a clean progressive architecture view, three deterministic roleplay scenarios, grouped labs with contextual help, an adapter integration lab, and a sourced FAQ.

**Architecture:** Keep the Vite/React frontend on GitHub Pages and FastAPI on Render. The browser owns presentation and visitor choices; Render owns deterministic fixtures and every authoritative AEGIS result. New backend routers isolate the demo contract from the existing lab API, while focused React modules keep introduction, architecture, scenarios, labs, service state, and FAQ independently testable.

**Tech Stack:** Python 3.12, FastAPI, Pydantic, AEGIS `0.9.0b1`, pytest, React 19, TypeScript 5.9, React Router 7 HashRouter, Vite 8, Vitest, Testing Library, Tailwind/CSS, GitHub Pages, Render.

## Global Constraints

- Keep `base: "/aegis/"` and HashRouter; the public introduction is `#/`.
- Keep the production frontend on GitHub Pages and the API on the existing Render service.
- Render fixtures are deterministic and make no live model, Bedrock, OpenAI, or A2A network call.
- The frontend contains no authoritative decision, reason-code, score, lifecycle, or artifact fixture.
- Every visible governance result comes from the installed AEGIS SDK through Render.
- AEGIS governs individual calls and agentic workflows; it does not execute agents, tools, provider calls, or retries.
- The public site contains no AWS, OpenAI, or A2A credential input.
- Live BYOK remains a deferred local-companion project; it is not part of this public build.
- Endpoint tables, CORS details, fixture ownership, deployment sequencing, and test matrices remain internal documentation.
- The adapter manifest exposes only adapters covered by passing release-gate tests.
- The public wake-up copy is exactly: “Starting the demo API. Render may need about a minute after a period of inactivity.”
- Public copy follows the approved language policy whose source SHA-256 is `6d322deeccbd775fe21def56b49db2101d73835965696e94fdc77248dbed92ef`.
- Architecture connectors occupy dedicated empty lanes and never cross nodes, labels, boundaries, or other connectors.
- Do not apply `stash@{0}` wholesale. Do not restore its executable-bit changes or generated `graphify-out/` content.
- Preserve existing lab deep links `#/lab/1` through `#/lab/11`; add `#/lab/12`.
- Treat Bedrock adapter validation as a separate release gate. Do not publish a broader compatibility claim than the manifest supports.

---

## File and Module Map

### Backend

- `demo-app-api/demo_contract.py` — public API versions, Pydantic request/response models, and source provenance.
- `demo-app-api/demo_registry.py` — allowlisted scenario variants and verified adapter IDs.
- `demo-app-api/demo_fixtures.py` — deterministic transcripts, provider evidence, and fictional case metadata.
- `demo-app-api/demo_scenario_service.py` — actual Atlas, Northstar, and Meridian AEGIS execution.
- `demo-app-api/demo_adapter_service.py` — deterministic Bedrock, OpenAI Agents, and A2A adapter execution.
- `demo-app-api/demo_routes.py` — manifest, scenario-run, and adapter-run HTTP routes.
- `demo-app-api/demo_gates.py` — demo-only custom privacy and clinical-scope gates.
- `demo-app-api/demo_policies/*.yaml` — fixed scenario and adapter policies.
- `demo-app-api/tests/test_demo_manifest.py` — contract, provenance, allowlist, and health tests.
- `demo-app-api/tests/test_demo_scenarios.py` — expected scenario outcomes and artifacts.
- `demo-app-api/tests/test_demo_adapters.py` — positive and negative adapter release gates.

### Frontend foundation

- `demo-app-react/src/types/demo.ts` — types matching `demo_contract.py`.
- `demo-app-react/src/lib/demoApi.ts` — typed request helper and structured API errors.
- `demo-app-react/src/context/DemoServiceContext.tsx` — health/manifest readiness state and retry behavior.
- `demo-app-react/src/components/service/DemoServiceNotice.tsx` — starting, unavailable, and contract-mismatch UI.
- `demo-app-react/src/content/demoCopy.ts` — reviewed public introduction and shared product-boundary copy.
- `demo-app-react/src/content/faqContent.ts` — sourced FAQ content.
- `demo-app-react/src/components/layout/DemoNav.tsx` — Architecture, Scenarios, Labs, FAQ navigation.

### Frontend pages

- `demo-app-react/src/pages/IntroductionPage.tsx` — plain-language entry page and install sample.
- `demo-app-react/src/pages/ArchitecturePage.tsx` — progressive overview and technical-map switcher.
- `demo-app-react/src/components/architecture/OwnershipFlow.tsx` — semantic host/AEGIS/evidence diagram.
- `demo-app-react/src/components/architecture/TechnicalMap.tsx` — generated SVG on desktop and grouped cards on phones.
- `demo-app-react/src/components/architecture/ArchitectureDetailPanel.tsx` — selected-node explanation.
- `demo-app-react/src/pages/ScenariosIndexPage.tsx` — three scenario entry cards.
- `demo-app-react/src/routes/scenarios/ScenarioPage.tsx` — shared roleplay controller and result layout.
- `demo-app-react/src/routes/scenarios/scenarioContent.ts` — fictional actors, visitor prompts, and non-authoritative labels.
- `demo-app-react/src/routes/scenarios/ScenarioTimeline.tsx` — scene, choice, gates, decision, and replay visuals.
- `demo-app-react/src/pages/LabsIndexPage.tsx` — grouped lab catalog.
- `demo-app-react/src/labs/Lab12IntegrationAdapters.tsx` — manifest-gated deterministic adapter lab.
- `demo-app-react/src/pages/FaqPage.tsx` — categorized accessible FAQ.

### Copy and release

- `docs/language-policy/aegis-demo-copy-rules.json` — project-local derived rules with source provenance.
- `scripts/check_demo_copy.py` — repeatable public-copy scan.
- `scripts/smoke_demo.py` — post-deployment Pages/Render contract smoke check.
- `tests/test_demo_copy_policy.py` — scanner behavior and source checksum lock.
- `tests/test_demo_intro_snippet.py` — executable verification of the public split-enforcement sample.
- `tests/test_demo_smoke_script.py` — smoke-check behavior without production network calls.
- `.github/workflows/deploy-demo-react.yml` — copy gate and production smoke-test hooks.

---

### Task 1: Add the project-local copy gate and protect stash boundaries

**Files:**
- Create: `docs/language-policy/aegis-demo-copy-rules.json`
- Create: `scripts/check_demo_copy.py`
- Create: `tests/test_demo_copy_policy.py`
- Inspect only: `stash@{0}^3:demo-app-react/src/routes/atlas/**`
- Inspect only: `stash@{0}^3:docs/demos/atlas/**`
- Inspect only: `stash@{0}^3:policies/demo_atlas_support*.yaml`

**Interfaces:**
- Consumes: approved language-policy file at `/Users/neal/Documents/_Shenanigans/_myProjects/ezppt/docs/language-policy/ai_cliche_lexicon.md`.
- Produces: `scan_text(text: str) -> list[Finding]`, CLI exit code `1` when findings exist, and a local rule file pinned to the approved source checksum.

- [ ] **Step 1: Inspect the stash material without changing the worktree**

Run:

```bash
git show 'stash@{0}^3:demo-app-react/src/pages/UseCasesPage.tsx' | sed -n '1,260p'
git show 'stash@{0}^3:docs/demos/atlas/DEMO_SPEC.md' | sed -n '1,320p'
git show 'stash@{0}^3:docs/demos/atlas/wireframe.html' | sed -n '1,320p'
git show 'stash@{0}^3:demo-app-react/src/routes/atlas/components/ChatTranscript.tsx'
git show 'stash@{0}^3:demo-app-react/src/routes/atlas/components/EvidenceArtifact.tsx'
git show 'stash@{0}^3:demo-app-react/src/routes/atlas/components/ReasonCodeCard.tsx'
git show 'stash@{0}^3:demo-app-react/src/routes/atlas/components/ScenarioPicker.tsx'
git show 'stash@{0}^3:policies/demo_atlas_support.yaml'
git show 'stash@{0}^3:policies/demo_atlas_support.broken.yaml'
git status --short
```

Expected: the reference material is visible in the terminal, the stash is unchanged, and no stash file is added to the worktree.
Port only useful presentation and policy ideas into the new files named in
this plan. Do not restore the old route, frontend audit JSON, hardcoded
outcomes, theme duplicate, or inert fix control.

- [ ] **Step 2: Write the failing copy-scanner tests**

Create `tests/test_demo_copy_policy.py` with tests equivalent to:

```python
from scripts.check_demo_copy import scan_text


def test_scanner_flags_banned_marketing_language():
    findings = scan_text(
        "At its core, this robust framework will unlock the full potential."
    )
    assert {finding.pattern for finding in findings} >= {
        "at its core",
        "robust framework",
        "unlock the full potential",
    }


def test_scanner_accepts_specific_governance_copy():
    assert scan_text(
        "AEGIS checks the request before the model call and records reason code ROLE_NOT_ALLOWED."
    ) == []
```

- [ ] **Step 3: Run the tests and verify the missing module failure**

Run:

```bash
.venv/bin/pytest tests/test_demo_copy_policy.py -v
```

Expected: collection fails because `scripts.check_demo_copy` does not exist.

- [ ] **Step 4: Add the derived rule file and scanner**

Parse only the source table with exact header
`Pattern | Severity | Type | Category | Note`. Commit all 39 parsed rows plus
the design-specific structure checks. The JSON root must have this shape:

```json
{
  "source": "/Users/neal/Documents/_Shenanigans/_myProjects/ezppt/docs/language-policy/ai_cliche_lexicon.md",
  "source_sha256": "6d322deeccbd775fe21def56b49db2101d73835965696e94fdc77248dbed92ef",
  "rules": [
    {
      "pattern": "at its core",
      "severity": "warn",
      "type": "substring",
      "category": "opening_phrase",
      "note": "Filler opener. State the point directly."
    }
  ],
  "project_overrides": [
    {"pattern": "journey", "type": "substring", "category": "metaphor"},
    {"pattern": "landscape", "type": "substring", "category": "metaphor"},
    {"pattern": "tapestry", "type": "substring", "category": "metaphor"}
  ],
  "structural_checks": ["repeated_not_but", "rhetorical_question_cluster"]
}
```

Implement `Finding(pattern: str, line: int, excerpt: str)`,
case-insensitive substring and regex matching, repeated “not … but …”
detection, three-or-more-question detection within one paragraph, and
recursive scanning for `.ts`, `.tsx`, `.md`, and `.html` under supplied
directories. The CLI treats every finding as a failed public-copy review and
prints pattern, file, line, and excerpt.

- [ ] **Step 5: Run the scanner tests**

Run:

```bash
.venv/bin/pytest tests/test_demo_copy_policy.py -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit the copy gate**

```bash
git add docs/language-policy/aegis-demo-copy-rules.json scripts/check_demo_copy.py tests/test_demo_copy_policy.py
git commit -m "test: add demo copy policy gate"
```

---

### Task 2: Establish the versioned demo API contract and service manifest

**Files:**
- Create: `demo-app-api/demo_contract.py`
- Create: `demo-app-api/demo_registry.py`
- Create: `demo-app-api/demo_routes.py`
- Create: `demo-app-api/tests/test_demo_manifest.py`
- Modify: `demo-app-api/main.py`

**Interfaces:**
- Consumes: `RENDER_GIT_BRANCH`, `RENDER_GIT_COMMIT`, and installed distribution metadata.
- Produces: `GET /api/demo/manifest`, extended `GET /health`, `ScenarioRunRequest`, `ScenarioRunResponse`, `AdapterRunRequest`, and `AdapterRunResponse`.

- [ ] **Step 1: Write failing manifest and health tests**

Cover these exact assertions:

```python
def test_demo_manifest_reports_versions_and_allowlists(client):
    body = client.get("/api/demo/manifest").json()
    assert body["api_contract_version"] == "1"
    assert body["sdk_version"] == "0.9.0b1"
    assert body["fixture_set_version"] == "2026-07-25"
    assert body["scenarios"] == ["atlas", "meridian", "northstar"]
    assert body["adapters"] == []


def test_health_reports_demo_contract(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["api_contract_version"] == "1"
```

Also assert that unknown scenario, variant, and adapter IDs return `422`, never accept filesystem paths, and include structured `detail`.

- [ ] **Step 2: Run the focused tests and verify 404 failures**

Run:

```bash
demo-app-api/aegis-env/bin/pytest demo-app-api/tests/test_demo_manifest.py -v
```

Expected: `/api/demo/manifest` returns 404.

- [ ] **Step 3: Define the contract models**

Use literal outcomes and source provenance:

```python
Outcome = Literal["PASS", "FAIL", "PAUSED"]


class DemoSource(BaseModel):
    branch: str | None
    commit: str | None
    sdk_version: str


class DemoManifest(BaseModel):
    api_contract_version: Literal["1"]
    sdk_version: str
    fixture_set_version: Literal["2026-07-25"]
    scenarios: list[Literal["atlas", "northstar", "meridian"]]
    adapters: list[Literal["bedrock", "openai_agents", "a2a"]]
    source: DemoSource
```

Define `ScenarioRunResponse` with `scenario_id`, `variant`, `fixture_version`, `transcript`, `gates`, `decision`, `artifact`, `workflow_artifact`, `error`, and `source`. Define `AdapterRunResponse` with `adapter_id`, `fixture_id`, `provider_input`, `normalized_evidence`, `decision`, `artifact`, `workflow_artifact`, `error`, and `source`.

- [ ] **Step 4: Add the registry and router**

Set:

```python
SCENARIO_VARIANTS = {
    "atlas": frozenset({"first_attempt", "corrected"}),
    "northstar": frozenset({"first_attempt", "authorized_retry", "corrected"}),
    "meridian": frozenset({"first_attempt", "corrected"}),
}
VERIFIED_ADAPTERS: frozenset[str] = frozenset()
```

The router must derive manifest arrays from these allowlists, reject unknown IDs before calling a service, and never accept a policy or fixture path from the request.

- [ ] **Step 5: Include the router and extend health**

In `main.py`, include `demo_router` and add `api_contract_version` plus installed SDK version to `/health`. Preserve its existing `source.branch` and `source.commit` fields.

- [ ] **Step 6: Run manifest and existing API tests**

Run:

```bash
demo-app-api/aegis-env/bin/pytest demo-app-api/tests/test_demo_manifest.py demo-app-api/tests/test_api.py -v
```

Expected: all tests pass.

- [ ] **Step 7: Commit the contract**

```bash
git add demo-app-api/demo_contract.py demo-app-api/demo_registry.py demo-app-api/demo_routes.py demo-app-api/main.py demo-app-api/tests/test_demo_manifest.py
git commit -m "feat: add versioned demo API manifest"
```

---

### Task 3: Implement deterministic Atlas, Northstar, and Meridian governance runs

**Files:**
- Create: `demo-app-api/demo_fixtures.py`
- Create: `demo-app-api/demo_gates.py`
- Create: `demo-app-api/demo_scenario_service.py`
- Create: `demo-app-api/demo_policies/atlas.yaml`
- Create: `demo-app-api/demo_policies/northstar_base.yaml`
- Create: `demo-app-api/demo_policies/northstar.yaml`
- Create: `demo-app-api/demo_policies/meridian.yaml`
- Create: `demo-app-api/tests/test_demo_scenarios.py`
- Modify: `demo-app-api/demo_routes.py`

**Interfaces:**
- Consumes: `SCENARIO_VARIANTS` and `ScenarioRunResponse` from Task 2.
- Produces: `run_scenario(scenario_id: str, variant: str) -> ScenarioRunResponse`.

- [ ] **Step 1: Write the failing scenario outcome matrix**

Parametrize these expected results:

```python
CASES = [
    ("atlas", "first_attempt", "FAIL", "PROVENANCE_MISSING"),
    ("atlas", "corrected", "PASS", None),
    ("northstar", "first_attempt", "FAIL", "ROLE_NOT_ALLOWED"),
    ("northstar", "authorized_retry", "PAUSED", "PHYSICIAN_APPROVAL_REQUIRED"),
    ("northstar", "corrected", "PASS", None),
    ("meridian", "first_attempt", "PAUSED", "WORKFLOW_SEQUENCE_VIOLATION"),
    ("meridian", "corrected", "PASS", None),
]
```

For every response, assert `fixture_version == "2026-07-25.1"`, transcript presence, real artifact checksums where an invocation artifact exists, separate workflow artifacts for Meridian, and no network mocking.

- [ ] **Step 2: Run the focused tests and verify route failures**

Run:

```bash
demo-app-api/aegis-env/bin/pytest demo-app-api/tests/test_demo_scenarios.py -v
```

Expected: run routes fail because `run_scenario` is absent.

- [ ] **Step 3: Add immutable server-side fixture definitions**

Use a frozen `ScenarioFixture` dataclass. Store only fictional details:

```python
@dataclass(frozen=True)
class ScenarioFixture:
    scenario_id: str
    variant: str
    participant: str
    role: str
    prompt: str
    output: dict[str, Any]
    context: dict[str, Any]
    transcript: tuple[dict[str, str], ...]
```

Atlas first attempt lacks `context.provenance.source_ids` and `output.policy_citation`; its correction supplies `["atlas-policy-BRV-04"]` and `policy_citation: "BRV-04"`. Northstar uses only fictional record IDs and contains no treatment dosage. Meridian uses fictional vendor `M-1042`, amount `24800`, and a no-op payment preparation record.

- [ ] **Step 4: Implement Atlas with split enforcement**

Use an `AEGIS` instance configured with `ProvenanceGate` and an `HMACSigner`
whose fixed demo-only key is supplied by the server fixture. Call
`enforce_pre_call(...)` before the simulated response and
`enforce_post_call(...)` afterward. Return the audit artifact attached to
`AIGCError`. The policy must require provenance, a `policy_citation`, the
support role, bounded tools, and approval before a refund commitment. Assert
that the corrected artifact contains a signature and that its invocation
checksum verifies; label the fixture key as non-production test material.

- [ ] **Step 5: Implement Northstar pre-call, custom-gate, and approval paths**

Register demo-only privacy and clinical-scope gates by their documented public
gate hook. `northstar.yaml` must extend `northstar_base.yaml` with intersect
composition and strict risk treatment. The first attempt must fail before model
use for `scheduling_assistant`. The authorized retry must reject the unsupported
recommendation, attach custom-gate and risk evidence, and leave the workflow at
a physician approval checkpoint. The corrected run uses the nurse role, a
limited scheduling summary, and recorded physician approval.

- [ ] **Step 6: Implement Meridian with `GovernanceSession`**

Open a session from `meridian.yaml`, bind declared participants, and call
`enforce_step_pre_call`/`enforce_step_post_call` for each ordered step. The
first attempt requests `payment_preparation` before `vendor_verification`,
records the typed sequence failure, and pauses. The corrected run follows all
five steps, records approval, calls `session.complete()`, and returns invocation
plus workflow artifacts. Call
`reconstruct_trace(workflow_artifact, invocation_artifacts)` and
`export_workflow([workflow_artifact], invocation_artifacts, "audit")`; include
those redacted projections in the response.

- [ ] **Step 7: Normalize typed failures without inventing success**

Map SDK failures using:

```python
def _reason_code(exc: Exception) -> str:
    details = getattr(exc, "details", None)
    if isinstance(details, dict) and isinstance(details.get("reason_code"), str):
        return details["reason_code"]
    code = getattr(exc, "code", None)
    if isinstance(code, str):
        return code
    artifact = getattr(exc, "audit_artifact", None) or {}
    return str(artifact.get("metadata", {}).get("reason_code", "AEGIS_ENFORCEMENT_FAILED"))
```

Network and unexpected server failures must remain server failures; they must not be converted into PASS responses.

- [ ] **Step 8: Run scenario and workflow regression tests**

Run:

```bash
demo-app-api/aegis-env/bin/pytest demo-app-api/tests/test_demo_scenarios.py demo-app-api/tests/test_workflow_routes.py -v
```

Expected: all tests pass.

- [ ] **Step 9: Commit the scenario backend**

```bash
git add demo-app-api/demo_fixtures.py demo-app-api/demo_gates.py demo-app-api/demo_scenario_service.py demo-app-api/demo_policies demo-app-api/demo_routes.py demo-app-api/tests/test_demo_scenarios.py
git commit -m "feat: add deterministic governance roleplays"
```

---

### Task 4: Add release-gated deterministic Bedrock, OpenAI Agents, and A2A runs

**Files:**
- Create: `demo-app-api/demo_adapter_service.py`
- Create: `demo-app-api/demo_policies/integration_adapters.yaml`
- Create: `demo-app-api/tests/test_demo_adapters.py`
- Modify: `demo-app-api/demo_fixtures.py`
- Modify: `demo-app-api/demo_registry.py`
- Modify: `demo-app-api/demo_routes.py`
- Modify: `demo-app-api/tests/test_demo_manifest.py`
- Modify: `demo-app-api/requirements.txt`

**Interfaces:**
- Consumes: adapter classes from `aegis.bedrock_adapter`, `aegis.openai_agents_adapter`, and `aegis.a2a_adapter`.
- Produces: `run_adapter(adapter_id: str, fixture_id: str) -> AdapterRunResponse`; manifest adapters become `["a2a", "bedrock", "openai_agents"]` only after all positive and negative tests pass.

- [ ] **Step 1: Write failing positive and negative release-gate tests**

For each adapter, assert one deterministic PASS and one typed rejection:

```python
CASES = [
    ("bedrock", "valid_trace", "PASS"),
    ("openai_agents", "governed_graph", "PASS"),
    ("a2a", "completed_task", "PASS"),
]
NEGATIVE = [
    ("bedrock", "wrong_alias", "WORKFLOW_PROTOCOL_TRACE_ALIAS_MISMATCH"),
    ("openai_agents", "predeclared_tool_call", "WORKFLOW_UNSUPPORTED_BINDING"),
    ("a2a", "grpc_binding", "WORKFLOW_PROTOCOL_GRPC_UNSUPPORTED"),
]
```

Also assert that the test suite fails if a name appears in `VERIFIED_ADAPTERS` without both cases.

- [ ] **Step 2: Run the adapter tests and verify the registry is empty**

Run:

```bash
demo-app-api/aegis-env/bin/pytest demo-app-api/tests/test_demo_adapters.py -v
```

Expected: valid adapter requests return `422` because none are verified.

- [ ] **Step 3: Add the deterministic Bedrock runner**

Use `BedrockParticipantBinding` with alias:

```text
arn:aws:bedrock:us-east-1:123456789012:agent-alias/AGENTID12A/ALIASID12B
```

Call `BedrockTraceAdapter.prepare_step`, supply a parsed `orchestrationTrace` with `traceId: "trace-demo-001"`, then call `complete_step`. Return the provider trace separately from the redacted adapter metadata. Do not import boto3 or create a Bedrock client.

- [ ] **Step 4: Add the deterministic OpenAI Agents runner**

Add `openai-agents>=0.0.7` to the demo requirements. Construct an `Agent(name="DemoPlanner", tools=[])`, call `OpenAIAgentsAdapter.prepare_step`, and complete it with a `SimpleNamespace` carrying `last_agent`, empty response/interrupt/guardrail arrays, and explicit output `{"result": "Plan recorded", "confidence": 0.98}`. Do not call `Runner.run`.

- [ ] **Step 5: Add the deterministic A2A runner**

Supply an Agent Card with `protocolBinding: "JSONRPC"` and `protocolVersion: "1.0"`, plus a task envelope ending in `TASK_STATE_COMPLETED`. Call `A2AAdapter.prepare_step` and `complete_step`. The invalid fixture uses `GRPC` and must fail before any remote task execution.

- [ ] **Step 6: Enable only the tested adapters**

After the focused suite passes, set:

```python
VERIFIED_ADAPTERS = frozenset({"bedrock", "openai_agents", "a2a"})
```

The manifest must sort these values before returning them.

- [ ] **Step 7: Run adapter, manifest, and SDK adapter tests**

Run:

```bash
demo-app-api/aegis-env/bin/pytest \
  demo-app-api/tests/test_demo_adapters.py \
  demo-app-api/tests/test_demo_manifest.py \
  tests/test_bedrock_adapter.py \
  tests/test_a2a_adapter.py \
  tests/test_openai_agents_adapter.py \
  -v
```

Expected: all tests pass without network access.

- [ ] **Step 8: Commit the adapter lab backend**

```bash
git add demo-app-api/demo_adapter_service.py demo-app-api/demo_fixtures.py demo-app-api/demo_policies/integration_adapters.yaml demo-app-api/demo_registry.py demo-app-api/demo_routes.py demo-app-api/requirements.txt demo-app-api/tests/test_demo_adapters.py demo-app-api/tests/test_demo_manifest.py
git commit -m "feat: add deterministic adapter demo runs"
```

---

### Task 5: Add the typed frontend API client and Render readiness state

**Files:**
- Create: `demo-app-react/src/types/demo.ts`
- Create: `demo-app-react/src/lib/demoApi.ts`
- Create: `demo-app-react/src/lib/demoApi.test.ts`
- Create: `demo-app-react/src/context/DemoServiceContext.tsx`
- Create: `demo-app-react/src/context/DemoServiceContext.test.tsx`
- Create: `demo-app-react/src/components/service/DemoServiceNotice.tsx`
- Modify: `demo-app-react/src/main.tsx`

**Interfaces:**
- Consumes: Task 2 API shapes and `AigcContext.apiUrl`.
- Produces: `demoRequest<T>(apiUrl, path, options)`, `DemoServiceProvider`, and `useDemoService(): {status, manifest, error, retry}`.

- [ ] **Step 1: Write failing client tests**

Cover parsed success, structured `422` detail, abort, and contract mismatch:

```ts
await expect(demoRequest('/api', '/api/demo/manifest')).resolves.toMatchObject({
  api_contract_version: '1',
})
await expect(demoRequest('/api', '/bad')).rejects.toMatchObject({
  status: 422,
  code: 'UNKNOWN_DEMO_ID',
})
```

- [ ] **Step 2: Write failing service-state tests**

Use fake timers to prove `checking -> starting -> ready`, bounded retries, manual retry, and exact wake-up copy. Assert run controls can rely on `status === "ready"`.

- [ ] **Step 3: Run the focused frontend tests**

Run:

```bash
cd demo-app-react && npm test -- src/lib/demoApi.test.ts src/context/DemoServiceContext.test.tsx
```

Expected: imports fail because the modules do not exist.

- [ ] **Step 4: Implement the typed client**

Mirror the backend names in `types/demo.ts`:

```ts
export type DemoOutcome = 'PASS' | 'FAIL' | 'PAUSED'
export type ScenarioId = 'atlas' | 'northstar' | 'meridian'
export type AdapterId = 'bedrock' | 'openai_agents' | 'a2a'

export interface DemoSource {
  branch: string | null
  commit: string | null
  sdk_version: string
}

export interface DemoManifest {
  api_contract_version: '1'
  sdk_version: string
  fixture_set_version: string
  scenarios: ScenarioId[]
  adapters: AdapterId[]
  source: DemoSource
}

export interface DemoGateResult {
  name: string
  phase: 'pre_call' | 'post_call' | 'workflow'
  outcome: DemoOutcome
  reason_code: string | null
}

export interface ScenarioRunResponse {
  scenario_id: ScenarioId
  variant: string
  fixture_version: string
  transcript: { speaker: string; text: string }[]
  gates: DemoGateResult[]
  decision: DemoOutcome
  artifact: Record<string, unknown> | null
  workflow_artifact: Record<string, unknown> | null
  error: { code: string; message: string } | null
  source: DemoSource
}
```

Define:

```ts
export class DemoApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
    readonly detail: unknown,
  ) {
    super(message)
  }
}
```

`demoRequest` must parse JSON error bodies, propagate `AbortError`, and never synthesize response data.

- [ ] **Step 5: Implement the readiness state machine**

Use states `checking | starting | ready | unavailable | mismatch`. Poll `/health` and then `/api/demo/manifest` with delays `[0, 1000, 2000, 4000, 8000, 15000, 30000]`. Abort on unmount or manual retry. Treat API contract values other than `"1"` as `mismatch`; treat frontend/backend commit differences as visible provenance, not failure.

- [ ] **Step 6: Implement the service notice**

Starting state shows the exact approved sentence. Unavailable shows the failed operation plus Retry. Mismatch shows frontend and backend contract versions. Give the status region `role="status"` and `aria-live="polite"`.

- [ ] **Step 7: Run frontend tests**

Run:

```bash
cd demo-app-react && npm test -- src/lib/demoApi.test.ts src/context/DemoServiceContext.test.tsx
```

Expected: all tests pass.

- [ ] **Step 8: Commit the frontend runtime foundation**

```bash
git add demo-app-react/src/types/demo.ts demo-app-react/src/lib/demoApi.ts demo-app-react/src/lib/demoApi.test.ts demo-app-react/src/context/DemoServiceContext.tsx demo-app-react/src/context/DemoServiceContext.test.tsx demo-app-react/src/components/service/DemoServiceNotice.tsx demo-app-react/src/main.tsx
git commit -m "feat: add demo service readiness state"
```

---

### Task 6: Build the introduction, routing, and shared navigation

**Files:**
- Create: `demo-app-react/src/content/demoCopy.ts`
- Create: `demo-app-react/src/pages/IntroductionPage.tsx`
- Create: `demo-app-react/src/pages/IntroductionPage.test.tsx`
- Create: `tests/test_demo_intro_snippet.py`
- Create: `policies/support.yaml`
- Create: `demo-app-react/src/components/layout/DemoNav.tsx`
- Modify: `demo-app-react/src/App.tsx`
- Modify: `demo-app-react/src/App.test.tsx`
- Modify: `demo-app-react/src/components/layout/AppNav.tsx`
- Modify: `demo-app-react/src/components/layout/LabTabs.tsx`
- Modify: `demo-app-react/src/index.css`

**Interfaces:**
- Consumes: `DemoServiceNotice` and approved product statements.
- Produces: routes `#/`, `#/demo/architecture`, `#/demo/scenarios`, `#/demo/labs`, `#/faq`, and compatibility redirect `#/architecture`.

- [ ] **Step 1: Replace routing assertions with the approved information architecture**

Test that `/` renders “Put policy between the request and the result,” `/architecture` redirects to `/demo/architecture`, legacy labs still render, and the shared navigation exposes What it does, Install, Open demo, FAQ, and GitHub.

- [ ] **Step 2: Write introduction content tests**

Assert the page states:

```text
AEGIS governs participants, step order, handoffs, approvals, budgets, and session lifecycle.
Your application or agent framework still executes the agents, model calls, and tools.
```

Also assert the thought-trace comparison, install command `pip install aegis-ai-governance==0.9.0b1`, split-enforcement sample, and three entry cards.

- [ ] **Step 3: Run the tests and verify current redirect failures**

Run:

```bash
cd demo-app-react && npm test -- src/App.test.tsx src/pages/IntroductionPage.test.tsx
```

Expected: `/` still redirects to Architecture and the introduction import is absent.

- [ ] **Step 4: Add reviewed copy and the introduction page**

Keep all prose in `demoCopy.ts`. The first integration sample must use `enforce_pre_call` and `enforce_post_call`, place the host model call between them, and label the host-owned line explicitly. The thought-trace section uses literal two-column labels and does not imply that thought traces are always false.

- [ ] **Step 5: Restructure the application shell**

Render `DemoNav` only under `/demo/*`, `/lab/*`, and `/faq`. Render `LabTabs` only on individual lab routes. Pass help context from a route descriptor instead of defaulting every non-architecture page to Lab 1.

- [ ] **Step 6: Normalize global typography**

Remove the current body-wide `letter-spacing: 0.12em` and `word-spacing: 0.16em`. Apply tracking only to short labels and code. Add responsive content-width, focus, two-column comparison, and call-flow styles without adding a new visual framework.

- [ ] **Step 7: Run routing, introduction, and existing component tests**

Run:

```bash
cd demo-app-react && npm test -- src/App.test.tsx src/pages/IntroductionPage.test.tsx src/components/HelpDrawer.test.tsx
```

Expected: all tests pass.

- [ ] **Step 8: Execute the published integration sample against AEGIS**

Create `policies/support.yaml` with role `support_agent`, a boolean
`customer_verified` precondition, and an output schema requiring string field
`result`. In `tests/test_demo_intro_snippet.py`, run the public sample:

```python
from aegis import enforce_post_call, enforce_pre_call


def test_introduction_split_enforcement_sample():
    pre = enforce_pre_call(
        {
            "policy_file": "policies/support.yaml",
            "model_provider": "anthropic",
            "model_identifier": "claude-sonnet-4-6",
            "role": "support_agent",
            "input": {"query": "Can I change my booking?"},
            "context": {"customer_verified": True},
        }
    )
    artifact = enforce_post_call(
        pre,
        {"result": "A support agent can review the booking conditions."},
    )
    assert artifact["enforcement_result"] == "PASS"
```

Run:

```bash
.venv/bin/pytest tests/test_demo_intro_snippet.py -v
```

Expected: the sample passes against the public `enforce_pre_call` and
`enforce_post_call` API.

- [ ] **Step 9: Run the copy scanner**

Run:

```bash
.venv/bin/python scripts/check_demo_copy.py demo-app-react/src/content/demoCopy.ts
```

Expected: exit code 0.

- [ ] **Step 10: Commit the introduction**

```bash
git add demo-app-react/src/content/demoCopy.ts demo-app-react/src/pages/IntroductionPage.tsx demo-app-react/src/pages/IntroductionPage.test.tsx tests/test_demo_intro_snippet.py policies/support.yaml demo-app-react/src/components/layout/DemoNav.tsx demo-app-react/src/App.tsx demo-app-react/src/App.test.tsx demo-app-react/src/components/layout/AppNav.tsx demo-app-react/src/components/layout/LabTabs.tsx demo-app-react/src/index.css
git commit -m "feat: add plain-language AEGIS introduction"
```

---

### Task 7: Rebuild Architecture with collision-free responsive connectors

**Files:**
- Create: `demo-app-react/src/components/architecture/OwnershipFlow.tsx`
- Create: `demo-app-react/src/components/architecture/OwnershipFlow.test.tsx`
- Create: `demo-app-react/src/components/architecture/TechnicalMap.tsx`
- Create: `demo-app-react/src/components/architecture/ArchitectureDetailPanel.tsx`
- Modify: `demo-app-react/src/pages/ArchitecturePage.tsx`
- Modify: `demo-app-react/src/pages/ArchitecturePage.test.tsx`
- Modify: `docs/architecture/diagrams/render_v090_component_diagrams.py`
- Modify: generated SVGs under `docs/architecture/diagrams/`
- Modify: generated SVG mirrors under `demo-app-react/public/diagrams/`
- Modify: `tests/test_architecture_diagram_truth.py`

**Interfaces:**
- Consumes: generated desktop technical SVGs and `useTheme`.
- Produces: semantic “How it works” flow, desktop technical maps, mobile grouped cards, and selected-node detail.

- [ ] **Step 1: Write failing semantic-flow tests**

Assert six nodes exist for one call/workflow step, each connector is a sibling lane rather than a descendant of a node, and the screen-reader summary names host execution, pre-call policy, host action, post-call policy, result, and evidence.

- [ ] **Step 2: Add diagram geometry regression assertions**

Extend `test_architecture_diagram_truth.py` to parse generated SVG geometry.
The generator must mark node rectangles with `data-node-id`, connector paths
with `data-from` and `data-to`, and opaque connector-label rectangles with
`data-connector-label`. Parse the `M`, `L`, `H`, and `V` commands into
axis-aligned segments and assert:

```python
for segment in connector_segments:
    assert not crosses_interior(segment, any_non_endpoint_node_bounds)
    assert not crosses_interior(segment, connector_label_bounds)

for label_bounds in all_connector_label_bounds:
    assert not overlaps(label_bounds, any_node_bounds)
```

Touching the declared source or destination node at its named boundary port is
allowed; entering either node interior is not. The test derives intersections
from numeric coordinates and must fail if metadata merely claims that a route
is clear. Desktop and phone screenshots remain a separate visual gate.

- [ ] **Step 3: Run the focused tests and verify failures**

Run:

```bash
cd demo-app-react && npm test -- src/components/architecture/OwnershipFlow.test.tsx src/pages/ArchitecturePage.test.tsx
.venv/bin/pytest tests/test_architecture_diagram_truth.py -v
```

- [ ] **Step 4: Implement the default semantic flow**

Use separate desktop and mobile markup selected by CSS media queries. Desktop alternates `FlowNode` and `ConnectorLane`; mobile stacks `FlowNode` and `VerticalConnectorLane`. No transform may rotate a desktop connector into the phone layout.

- [ ] **Step 5: Implement progressive detail**

Add tabs “How it works” and “Technical map.” Node selection opens `ArchitectureDetailPanel` with responsibility, owner, public API/artifact, and explicit non-owner statement. On screens below `48rem`, `TechnicalMap` renders grouped semantic cards and does not mount the SVG image.

- [ ] **Step 6: Refactor the SVG generator routing model**

Represent every connection as explicit orthogonal segments with start/end ports and label boxes. Move long explanatory text to generated notes outside node bounds. Generate light/dark docs assets and mirror only the public beta component/pipeline assets into `demo-app-react/public/diagrams`.

- [ ] **Step 7: Regenerate and verify assets**

Run:

```bash
.venv/bin/python docs/architecture/diagrams/render_v090_component_diagrams.py
.venv/bin/python docs/architecture/diagrams/render_v090_component_diagrams.py --check
.venv/bin/pytest tests/test_architecture_diagram_truth.py -v
cd demo-app-react && npm test -- src/components/architecture/OwnershipFlow.test.tsx src/pages/ArchitecturePage.test.tsx
```

Expected: generation check and all focused tests pass.

- [ ] **Step 8: Commit Architecture**

```bash
git add demo-app-react/src/components/architecture demo-app-react/src/pages/ArchitecturePage.tsx demo-app-react/src/pages/ArchitecturePage.test.tsx docs/architecture/diagrams demo-app-react/public/diagrams tests/test_architecture_diagram_truth.py
git commit -m "feat: rebuild responsive architecture view"
```

---

### Task 8: Build the three roleplay scenario pages

**Files:**
- Create: `demo-app-react/src/pages/ScenariosIndexPage.tsx`
- Create: `demo-app-react/src/routes/scenarios/scenarioContent.ts`
- Create: `demo-app-react/src/routes/scenarios/ScenarioPage.tsx`
- Create: `demo-app-react/src/routes/scenarios/ScenarioPage.test.tsx`
- Create: `demo-app-react/src/routes/scenarios/ScenarioTimeline.tsx`
- Modify: `demo-app-react/src/App.tsx`

**Interfaces:**
- Consumes: `POST /api/demo/scenarios/{scenario_id}/runs`, `useDemoService`, and `ScenarioRunResponse`.
- Produces: Atlas, Northstar, and Meridian routes using one shared controller.

- [ ] **Step 1: Write failing shared-shell tests**

For Atlas, assert scene, visitor choice, disabled Run while service is not ready, API request after a choice, gate/result rendering from the response, artifact download, and corrected replay. Add route-level smoke tests for Northstar and Meridian.

- [ ] **Step 2: Write stale-response and no-static-success tests**

Resolve the corrected request before the first-attempt request and assert only the corrected result remains. Render without an API response and assert that PASS, reason codes, checksums, and workflow status are absent.

- [ ] **Step 3: Run the tests and verify missing routes**

Run:

```bash
cd demo-app-react && npm test -- src/routes/scenarios/ScenarioPage.test.tsx
```

- [ ] **Step 4: Add non-authoritative scenario content**

`scenarioContent.ts` may contain actors, setting, visitor question, choices, and explanation labels. It must not contain expected AEGIS outcomes or artifacts. Use:

```ts
export type ScenarioId = 'atlas' | 'northstar' | 'meridian'
export interface ScenarioContent {
  id: ScenarioId
  title: string
  visitorRole: string
  incident: string
  choices: readonly { id: string; label: string }[]
  variants: readonly string[]
  sources?: readonly { label: string; href: string }[]
}
```

Atlas links its factual case reference to
`https://decisions.civilresolutionbc.ca/crt/crtd/en/item/525448/index.do`.
All Atlas company names and policies used in the roleplay remain fictional;
Northstar and Meridian are wholly fictional.

- [ ] **Step 5: Implement the shared controller**

On Run, create a new `AbortController`, cancel the prior request, post only the server-defined variant, and render returned transcript, gates, decision, reason code, artifact, and workflow artifact. Build downloads from the current response object with `JSON.stringify(response.artifact, null, 2)`.

- [ ] **Step 6: Implement the visual timeline**

Use four stable regions: incident, your judgment, AEGIS evaluation, evidence. Show gate steps in returned order. Use icon, label, and text for state; color is supplemental. Meridian shows invocation and workflow artifacts as separate cards connected by checksum.

- [ ] **Step 7: Register the routes**

Add:

```tsx
<Route path="/demo/scenarios" element={<ScenariosIndexPage />} />
<Route path="/demo/scenarios/:scenarioId" element={<ScenarioPage />} />
```

Reject unknown route IDs with a visible not-found page rather than defaulting to Atlas.

- [ ] **Step 8: Run scenario and routing tests**

Run:

```bash
cd demo-app-react && npm test -- src/routes/scenarios/ScenarioPage.test.tsx src/App.test.tsx
```

Expected: all tests pass.

- [ ] **Step 9: Scan scenario copy and commit**

```bash
.venv/bin/python scripts/check_demo_copy.py demo-app-react/src/routes/scenarios/scenarioContent.ts
git add demo-app-react/src/pages/ScenariosIndexPage.tsx demo-app-react/src/routes/scenarios demo-app-react/src/App.tsx
git commit -m "feat: add AEGIS roleplay scenarios"
```

---

### Task 9: Group the labs, extend help, and add Integration Adapters

**Files:**
- Create: `demo-app-react/src/pages/LabsIndexPage.tsx`
- Create: `demo-app-react/src/pages/LabsIndexPage.test.tsx`
- Create: `demo-app-react/src/labs/Lab12IntegrationAdapters.tsx`
- Create: `demo-app-react/src/labs/Lab12IntegrationAdapters.test.tsx`
- Modify: `demo-app-react/src/App.tsx`
- Modify: `demo-app-react/src/help/helpContent.ts`
- Modify: `demo-app-react/src/help/helpContent.test.ts`
- Modify: `demo-app-react/src/components/HelpDrawer.tsx`
- Modify: `demo-app-react/src/components/HelpDrawer.test.tsx`

**Interfaces:**
- Consumes: manifest adapters, `POST /api/demo/adapters/{adapter_id}/runs`, and existing lab routes.
- Produces: grouped `#/demo/labs`, `#/lab/12`, adapter tabs, and result-aware help.

- [ ] **Step 1: Write failing grouped-index tests**

Assert the four groups and exact lab membership from the design specification. Assert the recommended path is Labs 9, 10, and 11 and that all legacy links remain unchanged.

- [ ] **Step 2: Write failing Integration Lab tests**

Assert tabs come from the manifest, no credential fields exist, Run is disabled until service readiness, provider input and normalized evidence are distinct, and an unlisted adapter has no runnable tab.

- [ ] **Step 3: Extend help tests**

Add Lab 12 label/content. Verify the drawer accepts optional result context:

```ts
interface ResultHelpContext {
  reasonCode?: string
  fields?: readonly string[]
}
```

The Result tab must repeat the returned reason code and field names without replacing the base guide.

- [ ] **Step 4: Run focused tests and verify failures**

Run:

```bash
cd demo-app-react && npm test -- src/pages/LabsIndexPage.test.tsx src/labs/Lab12IntegrationAdapters.test.tsx src/components/HelpDrawer.test.tsx
```

- [ ] **Step 5: Implement the grouped index and Lab 12**

Render Decisions, Policies and gates, Evidence, and Systems and workflows as semantic sections. Lab 12 calls only manifest-listed adapters and renders five panels in order: native fixture, normalized invocation/evidence, policy checks, decision, artifact.

- [ ] **Step 6: Extend help without regressing focus behavior**

Preserve initial focus on close, Tab/Shift+Tab trapping, Escape, backdrop close, and focus restoration. Add Base Guide and Result tabs only when result context exists; keep headings meaningful without color.

- [ ] **Step 7: Run lab and help regression tests**

Run:

```bash
cd demo-app-react && npm test -- src/pages/LabsIndexPage.test.tsx src/labs/Lab12IntegrationAdapters.test.tsx src/components/HelpDrawer.test.tsx src/help/helpContent.test.ts
```

Expected: all tests pass.

- [ ] **Step 8: Scan help copy and commit**

```bash
.venv/bin/python scripts/check_demo_copy.py demo-app-react/src/help/helpContent.ts
git add demo-app-react/src/pages/LabsIndexPage.tsx demo-app-react/src/pages/LabsIndexPage.test.tsx demo-app-react/src/labs/Lab12IntegrationAdapters.tsx demo-app-react/src/labs/Lab12IntegrationAdapters.test.tsx demo-app-react/src/App.tsx demo-app-react/src/help/helpContent.ts demo-app-react/src/help/helpContent.test.ts demo-app-react/src/components/HelpDrawer.tsx demo-app-react/src/components/HelpDrawer.test.tsx
git commit -m "feat: group labs and add adapter integration lab"
```

---

### Task 10: Add the sourced FAQ and Bedrock/AgentCore subsection

**Files:**
- Create: `demo-app-react/src/content/faqContent.ts`
- Create: `demo-app-react/src/pages/FaqPage.tsx`
- Create: `demo-app-react/src/pages/FaqPage.test.tsx`
- Modify: `demo-app-react/src/App.tsx`

**Interfaces:**
- Consumes: approved FAQ categories, adapter manifest truth, and authoritative external sources.
- Produces: accessible `#/faq` with a Bedrock subsection that states the AEGIS/AgentCore boundary.

- [ ] **Step 1: Write failing FAQ tests**

Assert all required questions exist, FAQ headings are keyboard-reachable, answers distinguish execution from governance, the Bedrock answer names no credential ownership, and the AgentCore comparison links to AWS documentation.

- [ ] **Step 2: Run the FAQ tests and verify missing page**

Run:

```bash
cd demo-app-react && npm test -- src/pages/FaqPage.test.tsx
```

- [ ] **Step 3: Add sourced content**

Use these sources:

- Anthropic paper: `https://www-cdn.anthropic.com/b9ca6db27f02a9ddf0d4fdb51b26432c99a27be0.pdf`
- OpenAI monitoring article: `https://openai.com/index/chain-of-thought-monitoring/`
- AgentCore policy overview: `https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html`
- AgentCore Gateway creation: `https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-create.html`
- AEGIS Bedrock contract: `https://github.com/nealsolves/aegis/blob/main/docs/reference/external/BEDROCK_ADAPTER.md`

The Bedrock answer must state that AgentCore can enforce Cedar policy around Gateway tool access and that AEGIS adds host-integrated invocation/workflow checks and portable AEGIS evidence. It must not imply that AgentCore lacks deterministic policy enforcement.

- [ ] **Step 4: Implement the accessible page**

Represent FAQ data as:

```ts
interface FaqItem {
  id: string
  question: string
  answer: readonly FaqBlock[]
  sources?: readonly { label: string; href: string }[]
  requiresAdapter?: 'bedrock'
}
```

Use native `<details>/<summary>` or an equivalent button/region pattern. If Bedrock is absent from the manifest, replace verified compatibility language with the exact status: “Bedrock adapter verification is not published for this demo build.”

- [ ] **Step 5: Run FAQ, route, and copy tests**

Run:

```bash
cd demo-app-react && npm test -- src/pages/FaqPage.test.tsx src/App.test.tsx
.venv/bin/python scripts/check_demo_copy.py demo-app-react/src/content/faqContent.ts
```

Expected: all checks pass.

- [ ] **Step 6: Commit the FAQ**

```bash
git add demo-app-react/src/content/faqContent.ts demo-app-react/src/pages/FaqPage.tsx demo-app-react/src/pages/FaqPage.test.tsx demo-app-react/src/App.tsx
git commit -m "feat: add sourced AEGIS FAQ"
```

---

### Task 11: Complete production verification and deployment gates

**Files:**
- Create: `demo-app-api/tests/test_demo_e2e.py`
- Create: `demo-app-react/src/serviceStates.test.tsx`
- Create: `scripts/smoke_demo.py`
- Create: `tests/test_demo_smoke_script.py`
- Modify: `.github/workflows/deploy-demo-react.yml`
- Modify: `demo-app-react/package.json`
- Modify: `docs/superpowers/specs/2026-07-25-aegis-demo-redesign-design.md` only if implementation reveals a documented contract correction

**Interfaces:**
- Consumes: all previous tasks.
- Produces: repeatable backend/frontend/copy/build checks and a production smoke command.

- [ ] **Step 1: Add backend end-to-end contract tests**

Run every scenario variant and every manifest adapter. Assert:

```python
assert manifest["api_contract_version"] == "1"
assert set(manifest["adapters"]) == {"bedrock", "openai_agents", "a2a"}
assert all(run["source"]["sdk_version"] == manifest["sdk_version"] for run in runs)
```

Install this autouse guard in the test module:

```python
@pytest.fixture(autouse=True)
def deny_outbound_network(monkeypatch):
    def blocked_connect(*_args, **_kwargs):
        raise AssertionError("demo tests attempted an outbound network call")

    monkeypatch.setattr(socket.socket, "connect", blocked_connect)
```

Use FastAPI `TestClient`, which stays in-process and does not invoke
`socket.socket.connect`.

- [ ] **Step 2: Add frontend service-state coverage**

Test Starting, Unavailable, Contract mismatch, AEGIS FAIL, AEGIS PAUSED, PASS, and stale request. Assert only Starting contains the Render wake-up sentence and none of these states includes credential inputs.

- [ ] **Step 3: Add copy checking to npm and Pages CI**

Add:

```json
"copycheck": "python ../scripts/check_demo_copy.py src/content src/routes/scenarios src/help/helpContent.ts"
```

In GitHub Actions, use the repository Python runtime instead of assuming `.venv` exists:

```yaml
- name: Check public copy
  run: python scripts/check_demo_copy.py demo-app-react/src/content demo-app-react/src/routes/scenarios demo-app-react/src/help/helpContent.ts
```

Place this before the frontend build.

- [ ] **Step 4: Run the full backend verification**

Run:

```bash
demo-app-api/aegis-env/bin/pytest demo-app-api/tests -v
.venv/bin/pytest tests/test_architecture_diagram_truth.py tests/test_bedrock_adapter.py tests/test_a2a_adapter.py tests/test_openai_agents_adapter.py -v
```

Expected: all tests pass.

- [ ] **Step 5: Run the full frontend verification**

Run:

```bash
cd demo-app-react
npm test
npm run lint
npm run build
```

Expected: all commands exit 0 and `dist/index.html` references `/aegis/` assets.

- [ ] **Step 6: Add the post-deployment smoke command**

Implement:

```text
python scripts/smoke_demo.py \
  --frontend-url https://nealsolves.github.io/aegis/ \
  --api-url https://aegis-demo-api.onrender.com
```

The command must load the frontend, wait through bounded Render wake-up
retries, verify health/manifest contract `"1"`, run Atlas `corrected`, and
require a PASS artifact with source provenance. Its unit test replaces HTTP
transport with fixed responses and asserts nonzero exit codes for contract
mismatch, API timeout, and missing artifact.

- [ ] **Step 7: Run the smoke-script tests**

Run:

```bash
.venv/bin/pytest tests/test_demo_smoke_script.py -v
```

Expected: all tests pass without accessing production.

- [ ] **Step 8: Run the copy and generated-asset checks**

Run:

```bash
.venv/bin/python scripts/check_demo_copy.py demo-app-react/src/content demo-app-react/src/routes/scenarios demo-app-react/src/help/helpContent.ts
.venv/bin/python docs/architecture/diagrams/render_v090_component_diagrams.py --check
git diff --check
```

Expected: all commands exit 0.

- [ ] **Step 9: Perform the visual and accessibility pass**

At desktop, tablet, and phone widths, inspect introduction, thought-trace comparison, both Architecture views, every scenario decision/result, lab index, Lab 12, help drawer, Bedrock FAQ, Starting, and Unavailable. Record screenshots outside the repository. Confirm no architecture connector crosses content and keyboard focus remains visible and ordered.

- [ ] **Step 10: Commit the release gates**

```bash
git add demo-app-api/tests/test_demo_e2e.py demo-app-react/src/serviceStates.test.tsx scripts/smoke_demo.py tests/test_demo_smoke_script.py demo-app-react/package.json .github/workflows/deploy-demo-react.yml
git commit -m "test: gate redesigned demo deployment"
```

- [ ] **Step 11: Verify final repository scope**

Run:

```bash
git status --short
git log --oneline --decorate -12
git stash list
```

Expected: implementation files are committed, `stash@{0}` still exists, `.superpowers/` visual-companion files remain untracked or ignored, and no generated review directory is committed.
