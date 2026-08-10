# Issue #43 Evidence-Oriented Compliance Mapping Design

Date: 2026-08-10

Status: Approved design

Issue: [#43 — publish explicit control mappings without certification claims](https://github.com/nealsolves/aegis/issues/43)

Dependency baseline:

- Issue #39 is closed as completed.
- Issue #47 and PR #69 established the maintained-public-copy evidence claims
  guard and the terminology boundaries this design consumes.
- Current `main` is pinned at commit `a9d0e49` for the first catalog version.

## Executive decision

Publish one versioned, evidence-oriented compliance catalog with YAML as the
canonical source. The catalog contains four independently reviewable framework
modules:

- NIST AI Risk Management Framework 1.0;
- ISO/IEC 42001:2023;
- 2017 SOC 2 Trust Services Criteria with revised points of focus — 2022; and
- Regulation (EU) 2024/1689 as amended by Regulation (EU) 2026/1744, limited
  to a declared set of governance, documentation, logging, retention,
  oversight, and post-market obligations.

Each module is complete against its explicitly declared and independently
reviewed scope. A mapping row describes only AEGIS's evidence contribution. It
does not state that a control is implemented, operating effectively,
applicable, compliant, certified, or sufficient for an audit or legal
conclusion.

Generate human-readable Markdown pages from the YAML. Validate shape,
terminology, review metadata, mapping counts, repository evidence locators,
generated-file parity, and a reproducible regulated workflow fixture in CI.
Reuse issue #47's claims rules rather than creating a second general-purpose
claims engine.

This work is a documentation, fixture, and maintenance-control change. It does
not change the AEGIS runtime API, evidence schemas, verification behavior,
storage implementation, or host responsibilities.

## Design principles

1. **Evidence contribution, not control satisfaction.** Every status describes
   what AEGIS contributes to an assessment, never whether an adopter satisfies
   a framework requirement.
2. **Complete against declared scope.** The catalog publishes the reviewed
   scope and expected mapping count. It does not make an unqualified claim of
   exhaustive legal or standards coverage.
3. **Exact source and product baselines.** Each framework source and the AEGIS
   source baseline are versioned and dated.
4. **Human judgment stays human.** CI can prove structure, traceability, and
   reproducibility. It cannot prove legal applicability, licensed-source
   interpretation, reviewer identity, evidence relevance, or operating
   effectiveness.
5. **No executable catalog data.** YAML values are data only. No command,
   expression, callback, module name, or fixture instruction loaded from the
   catalog is executed.
6. **Conservative source handling.** The repository stores identifiers,
   citations, and original non-authoritative interpretations, not copied
   normative text unless reuse rights have been affirmatively established.
7. **Fail closed on publication integrity.** Invalid modules, unresolved
   evidence locators, stale generated pages, prohibited claims, missing review
   records, or overdue reviews fail the compliance-catalog gate.

## Goals

- Give adopters explicit, versioned mappings between AEGIS evidence and four
  recognized frameworks or legal sources.
- Make gaps visible through four fixed evidence-support states.
- Link every positive evidence contribution to concrete policy fields,
  artifact fields, tests, commands, fixtures, or maintained documentation.
- Keep built-in tamper-evidence, external anchoring, checkpoint-backed
  completeness, host-operated append-only retention, and organizational
  conclusions separate.
- Provide a reproducible regulated workflow fixture for referenced evidence.
- Record review dates, next-review dates, source versions, and update triggers.
- Extend the maintained-public-copy guard to the catalog without duplicating
  its core terminology rules.
- Let each framework module receive focused implementation and review.

## Non-goals

- Certifying AEGIS or an adopter against any framework.
- Providing legal advice, a legal applicability decision, an audit opinion, a
  readiness assessment, or evidence of operating effectiveness.
- Implementing missing host, storage, identity, network, key-management,
  tenant-isolation, retention, or organizational controls.
- Mapping the entire EU AI Act.
- Reproducing licensed ISO or AICPA normative text.
- Supplying licensed ISO content to an AI system, including this workflow.
- Adding runtime APIs, schemas, commands, storage providers, schedulers, or
  cloud dependencies.
- Executing commands or verifier logic selected by catalog YAML.
- Authenticating reviewer identity or qualifications in local CI.
- Fetching framework sources or checking URLs during deterministic CI.
- Building a source-monitoring service, attestation service, policy engine, or
  historical catalog registry.
- Claiming that a synthetic fixture demonstrates production effectiveness.

## Product baseline

Catalog version `1.0.0` maps AEGIS current source at commit `a9d0e49`.

The catalog is not a mapping of the published
`aegis-ai-governance==0.9.0b1` wheel. The current source includes external
signing, trusted checkpoints, append-only evidence guidance, and JSONL sink
hardening that postdate the published beta. Every generated page displays the
current-source baseline and links to the release matrix so readers cannot infer
package availability from a source mapping.

The first catalog uses a single current version in the repository. Git history
and tags preserve earlier catalog versions. Parallel immutable version
directories are deferred until a real consumer requires simultaneous in-tree
versions.

Any change to the AEGIS baseline, a framework source version, declared scope,
mapping interpretation, support status, or evidence reference requires a
catalog version bump and review of every affected framework module.

## Repository layout

```text
compliance/
├── catalog.yaml
└── frameworks/
    ├── nist-ai-rmf-1.0.yaml
    ├── iso-iec-42001-2023.yaml
    ├── soc2-tsc-2017-revised-2022.yaml
    └── eu-ai-act-2024-1689-amended-2026.yaml

schemas/
└── compliance_mapping.schema.json

scripts/
├── check_compliance_catalog.py
└── render_compliance_catalog.py

docs/reference/
├── COMPLIANCE_CLAIMS_AND_TERMINOLOGY.md
└── compliance/
    ├── index.md
    ├── nist-ai-rmf-1.0.md
    ├── iso-iec-42001-2023.md
    ├── soc2-tsc-2017-revised-2022.md
    └── eu-ai-act-2024-1689-amended-2026.md

examples/compliance/
└── regulated_workflow.py

tests/
├── test_compliance_catalog.py
└── test_compliance_fixture.py
```

### File responsibilities

- `compliance/catalog.yaml` owns catalog version, AEGIS baseline, module
  inventory, catalog-wide disclaimer, review policy, and update triggers.
- Each framework YAML file owns one framework's source pin, declared scope,
  expected mapping count, review record, and mapping rows.
- `schemas/compliance_mapping.schema.json` defines closed YAML object shapes,
  enums, bounded strings and arrays, and status-specific required fields.
- `scripts/check_compliance_catalog.py` owns strict loading, schema validation,
  cross-file semantics, evidence-locator resolution, review-date enforcement,
  claims scanning, and rendered-output parity.
- `scripts/render_compliance_catalog.py` owns deterministic, escaped Markdown
  generation only.
- `COMPLIANCE_CLAIMS_AND_TERMINOLOGY.md` is the maintained human-authored
  language policy.
- Generated framework pages are public presentation views and are never edited
  by hand.
- `regulated_workflow.py` is the one reproducible public fixture. Its test owns
  execution and assertions; the catalog never controls execution.

## Canonical catalog model

### Catalog manifest

`compliance/catalog.yaml` contains these fields:

```yaml
schema_version: "1.0"
catalog_version: "1.0.0"
catalog_status: current_source
aegis_baseline:
  git_commit: a9d0e49
  distribution_name: aegis-ai-governance
  published_version: 0.9.0b1
  mapped_channel: current_source
  release_matrix: docs/reference/RELEASE_MATRIX.md
framework_modules:
  - compliance/frameworks/nist-ai-rmf-1.0.yaml
  - compliance/frameworks/iso-iec-42001-2023.yaml
  - compliance/frameworks/soc2-tsc-2017-revised-2022.yaml
  - compliance/frameworks/eu-ai-act-2024-1689-amended-2026.yaml
review_policy:
  default_interval_days: 180
  eu_ai_act_interval_days: 90
update_triggers:
  - framework_revision_or_erratum
  - authoritative_amendment_or_guidance
  - aegis_baseline_change
  - referenced_evidence_change
  - claims_policy_change
```

The final manifest contains complete display names, authoritative disclaimer
text, and review metadata in addition to this structural core.

### Framework module

Every framework module contains:

```yaml
framework:
  id: stable-machine-id
  name: Human-readable source name
  version: Exact version or legal baseline
  source_date: YYYY-MM-DD
  authoritative_sources: []
declared_scope:
  summary: Original non-authoritative scope statement
  mapping_unit: Stable identifier type
  expected_mapping_count: 1
  exclusions: []
review:
  reviewed_on: YYYY-MM-DD
  next_review_due: YYYY-MM-DD
  reviewer_role: Qualified maintainer role
  reviewed_in: str
  source_access_method: public_authoritative_source
mappings: []
```

`reviewed_in` records review provenance but local validation does not claim to
authenticate the reviewer. Repository permissions, branch protection, and PR
review establish identity and approval.

For ISO, `source_access_method` must be
`licensed_human_review_without_ai_processing`. Publication is blocked unless a
qualified maintainer records that review. The licensed standard, excerpts,
screenshots, or local file path are never committed or passed to automated
processing.

### Mapping row

Every row contains:

```yaml
- control_id: stable-source-identifier
  source_reference: bounded-source-locator
  aegis_evidence_status: supported_evidence
  interpretation: Original, non-authoritative interpretation
  evidence: []
  host_controls: []
  limitations: []
  retention_assumptions: []
```

Framework-provided titles are included only when their reuse is allowed. A
neutral original label is used otherwise. Normative requirement text is not
stored.

### Evidence references

Evidence references are declarative and use a closed set of kinds:

- `policy_field` — repository path plus JSON Pointer or dotted field locator;
- `artifact_field` — schema or fixture path plus JSON Pointer;
- `test` — Python test path plus exact test function or node identifier;
- `command` — exact maintained documented invocation plus documentation path;
- `fixture` — fixture path plus a fixed scenario identifier; and
- `documentation` — maintained path plus section anchor.

The validator proves that a target and locator exist. It does not claim that
the reference is sufficient or legally relevant. The framework reviewer owns
that judgment.

Catalog values never select executable functions. Fixture tests and command
tests use fixed Python-owned test code, fixed argument arrays, and no shell.

## Support status decision table

The field name is `aegis_evidence_status`, and rendered pages label it “AEGIS
evidence contribution.”

| Status | Meaning | Minimum required content |
| --- | --- | --- |
| `supported_evidence` | AEGIS directly produces concrete technical evidence relevant to the reviewed interpretation. This does not mean the control is satisfied. | At least one artifact, policy, command, or fixture reference; at least one executable test reference; limitations and host controls. |
| `partial_evidence` | AEGIS produces indirect, incomplete, or condition-dependent evidence relevant to part of the reviewed interpretation. | Concrete evidence; an explicit description of the unsupported portion; limitations and host controls. |
| `external_control` | The reviewed interpretation identifies a host, provider, or organizational responsibility for which AEGIS supplies no relevant evidence. | Named external owner and required external control; no positive AEGIS evidence claim. |
| `not_addressed` | The identifier is inside declared scope, but this catalog identifies neither an AEGIS evidence contribution nor a specific implemented external-control mapping. | Explicit gap statement and review note. |

No rendered heading or summary shortens these labels to “supported,”
“compliant,” “covered,” “passed,” or “satisfied.”

## Framework source and scope baselines

### NIST AI RMF

- Source: NIST AI 100-1, Artificial Intelligence Risk Management Framework
  (AI RMF 1.0).
- Version/date: 1.0, 2023-01-26.
- Stable publication identifier: `NIST.AI.100-1` and DOI
  `10.6028/NIST.AI.100-1`.
- Declared scope: every AI RMF 1.0 Core subcategory under GOVERN, MAP,
  MEASURE, and MANAGE.
- The Playbook is supporting guidance and is not a separate mapping inventory.
- A future AI RMF revision triggers a new catalog review; it does not silently
  alter the 1.0 module.

### ISO/IEC 42001

- Source: ISO/IEC 42001:2023, Information technology — Artificial
  intelligence — Management system.
- Version/date: Edition 1, 2023-12.
- Declared scope: the reviewed requirements clauses and Annex A controls
  identified by a qualified maintainer using a licensed copy.
- Only identifiers, permitted titles, citations, and original interpretations
  are published.
- The qualified reviewer performs human-only verification and does not provide
  licensed text to an AI system.
- The module remains unpublished until this review is recorded.

### SOC 2 Trust Services Criteria

- Source: 2017 Trust Services Criteria for Security, Availability, Processing
  Integrity, Confidentiality, and Privacy with revised points of focus — 2022.
- Source owner: AICPA Assurance Services Executive Committee.
- Declared scope: every criterion in the five Trust Services categories for
  the pinned publication.
- Points of focus inform human review but do not become separate mapping rows.
- The module stores identifiers and original interpretations, not copied
  normative text. Source-access and reuse terms are checked during human
  review.
- No use of SOC 2 marks, logos, badges, or wording implies endorsement.

### EU AI Act

- Primary act: Regulation (EU) 2024/1689.
- Amending act: Regulation (EU) 2026/1744 of 8 July 2026, published in OJ L on
  24 July 2026 and in force from 27 July 2026.
- Declared scope: an explicit reviewed list of provisions addressing
  governance, risk management, technical documentation, logging,
  record-retention, transparency, human oversight, provider/deployer duties,
  post-market monitoring, and incident records where an AEGIS evidence mapping
  is intelligible.
- The scope is not the whole Act and is not a legal applicability matrix.
- Each row states relevant actor and system-category conditions without
  deciding that they apply to an adopter.
- Normative legislation is distinguished from non-binding Commission guidance
  and implementation timelines.
- New amendments, corrigenda, delegated acts affecting included provisions, or
  material authoritative guidance trigger review.

## Assurance and ownership boundaries

Each positive mapping preserves the issue #47 separation among five properties:

| Property | AEGIS contribution | Required external boundary |
| --- | --- | --- |
| Artifact integrity | Checksums and bounded verification results | Trusted acquisition and preservation of the expected record |
| Signature and external anchoring | Provider-neutral signature and verifier contracts with explicit anchor outcomes | Key identity, credentials, provider availability, rotation, revocation, and trust policy |
| Checkpoint-backed completeness | Verification against an explicitly supplied expected checkpoint | Checkpoint creation cadence, protected storage, authoritative selection, and rollback defense |
| Append-only retention | No built-in WORM or append-only guarantee | Storage configuration, retention, legal hold, access control, monitoring, backup, and recovery |
| Legal or compliance conclusion | No automatic conclusion | Applicability, control design, operating effectiveness, evidence sufficiency, audit, certification, and legal judgment |

Mappings must identify tenant isolation, identity and IAM, key management,
transport security, retention, organizational process, and model-risk
responsibilities as external, partial, or not addressed where applicable.

## Claims and terminology policy

`docs/reference/COMPLIANCE_CLAIMS_AND_TERMINOLOGY.md` defines:

- the four status meanings and decision table;
- required “evidence contribution” wording;
- the difference between technical evidence, control design, operating
  effectiveness, applicability, and legal conclusions;
- allowed bounded statements;
- prohibited certification, compliance-guarantee, audit-readiness,
  endorsement, and legal-sufficiency claims;
- required non-authoritative and professional-review disclaimers;
- rules against framework logos and badges; and
- examples written as explicit prohibitions so the claims guard does not treat
  them as maintained positive claims.

The implementation reuses `scan_claims(...)` from
`scripts/check_evidence_claims.py`. The compliance checker supplies catalog
prose as bounded text blocks. Generated pages already fall under
`docs/reference/**` and the repository-wide claims guard. The documentation
inventory also classifies `compliance/**` as current maintained content so the
raw canonical files cannot be silently moved outside public-copy review.

Schema `additionalProperties: false` prevents overclaims from moving into an
unknown unscanned field. Every string is either public prose scanned by the
claims rules or constrained metadata such as an enum, identifier, repository
locator, or HTTPS URL.

## Strict loading and rendering

The catalog loader:

- accepts UTF-8 YAML only;
- uses safe scalar types;
- rejects duplicate keys, aliases, custom tags, merge keys, control
  characters, excessive file size, excessive nesting, excessive node count,
  and excessive scalar length;
- rejects unknown properties through the JSON Schema;
- rejects repository paths that are absolute, outside the repository,
  symlinks, special files, or missing; and
- reports bounded diagnostics with repository-relative paths and field
  locations.

The renderer:

- uses no wall-clock timestamps or network data;
- uses fixed framework and mapping ordering;
- normalizes UTF-8 and line endings;
- escapes Markdown table delimiters, links, and raw HTML;
- permits links only from validated source metadata;
- renders disclaimers, exact source pins, catalog version, AEGIS baseline,
  review dates, and update triggers on every framework page; and
- produces byte-stable output for identical input.

CI renders into a temporary directory and compares the result byte-for-byte
with checked-in pages. Focused renderer tests cover ordering, escaping,
disclaimers, status labels, and current-source availability language.

## Validation rules

`scripts/check_compliance_catalog.py` fails when:

- the catalog or a module fails strict loading or schema validation;
- the manifest does not list exactly the four approved modules;
- a framework ID, control ID, or mapping row is duplicated;
- the actual mapping count differs from the reviewed expected count;
- a status omits its required evidence, limitation, gap, or external owner;
- an evidence path or locator cannot be resolved;
- a positive evidence row lacks an executable test reference;
- catalog prose violates the issue #47 claims rules;
- a source version, date, authoritative URL, review date, next-review date, or
  review PR is absent;
- an ISO module lacks the licensed human-review record;
- a review is overdue;
- a generated page differs from deterministic output; or
- the regulated fixture contract fails.

The checker does not fetch URLs. A reachable URL would not prove that a source
interpretation is current. Source review remains a dated human process.

## Regulated workflow fixture

`examples/compliance/regulated_workflow.py` uses public AEGIS APIs and the
existing regulated-high-assurance starter behavior to generate deterministic
policy and evidence artifacts without a live model or network service.

The fixture:

- uses fixed non-production inputs and test-only key material where signing is
  demonstrated;
- writes only to a caller-supplied temporary output directory;
- produces schema-valid evidence used by concrete mapping references;
- contains no secret, credential, provider account, or legal conclusion; and
- states that it is synthetic and does not demonstrate operating
  effectiveness.

`tests/test_compliance_fixture.py` executes the example through a fixed Python
test harness, validates the produced evidence, and asserts the exact fields
referenced by mapping rows. It does not execute command strings taken from
YAML.

## Review and update process

Every module records `reviewed_on`, `next_review_due`, `reviewer_role`,
`reviewed_in`, and `source_access_method`.

Default review cadence is 180 days. The EU AI Act module uses 90 days because
its implementation and amendments are changing more rapidly. Event-driven
review occurs earlier when a manifest update trigger fires.

Review responsibilities are:

- **Framework scope reviewer:** checks the identifier inventory and exclusions
  against the pinned authoritative source.
- **Mapping reviewer:** checks that interpretations are bounded and evidence
  references are relevant without claiming control satisfaction.
- **Claims reviewer:** checks terminology, assurance boundaries, and public
  presentation.
- **ISO qualified maintainer:** performs the source review using licensed
  access without supplying protected content to automated processing.

One person may fill multiple roles except that the ISO licensed-source review
must be explicitly identified. The repository does not claim that a YAML field
authenticates any reviewer. PR review and repository governance provide the
approval record.

An update changes only affected modules unless a catalog-wide contract,
baseline, renderer, or claims-policy change affects all modules. The catalog
version is bumped according to semantic impact:

- patch: evidence locator, wording, or review metadata correction without
  changing meaning or scope;
- minor: new AEGIS evidence, changed support status, or expanded declared
  scope under the same framework version; and
- major: schema incompatibility, framework edition change, or support-status
  semantic change.

## CI integration

Add one compliance-catalog command to the existing documentation/security
gates:

```bash
python scripts/check_compliance_catalog.py
```

The check is deterministic and offline. The existing comprehensive public-copy
guard remains:

```bash
python scripts/check_evidence_claims.py
```

Release and demo workflows call the same commands rather than duplicating
rules. The operations runbook documents both local checks.

## Testing strategy

Implementation follows test-driven development.

### Schema and semantic tests

Cover valid minimal modules and failures for duplicate keys, aliases, custom
tags, unknown keys, malformed dates, invalid enums, duplicate IDs, count
mismatch, missing status-specific fields, unsafe paths, symlinks, missing
locators, oversized input, and overdue reviews.

### Claims tests

Cover permitted evidence-contribution language, every prohibited certification
or compliance-guarantee relationship inherited from issue #47, split YAML
strings, Unicode normalization, status-label shortening, and current-source
versus published-beta wording.

### Renderer tests

Cover deterministic ordering, Markdown and HTML escaping, source links,
disclaimers, review dates, support labels, empty evidence lists, long bounded
text, and byte-for-byte generated-file parity.

### Fixture tests

Run the regulated example in a temporary directory, validate schemas and
checksums, verify applicable signature, chain, and checkpoint states, and
assert each fixture-backed catalog locator. Negative tests prove malformed or
altered evidence is not reported as successful.

### Repository integration tests

Run the catalog checker, claims guard, documentation parity checker, demo-copy
checker, focused Python tests, and the complete Python suite. Catalog changes
do not require frontend changes unless a maintained frontend surface links to
or summarizes the catalog.

## Implementation task boundaries

1. **Core catalog contract:** schema, strict loader, status rules, terminology
   guide, claims integration, renderer, and focused tests.
2. **Regulated fixture:** public example, deterministic evidence generation,
   negative cases, and locator contract tests.
3. **NIST module:** full reviewed AI RMF 1.0 Core scope and generated page.
4. **ISO module:** reviewed clauses and Annex A scope, qualified licensed
   human-review gate, and generated page.
5. **SOC 2 module:** reviewed five-category criteria scope and generated page.
6. **EU AI Act module:** reviewed bounded legal scope against Regulations
   2024/1689 and 2026/1744, actor/applicability conditions, and generated page.
7. **Publication integration:** index, maintained-entry-point links, CI and
   operations-runbook commands, full claims scan, and acceptance traceability.

The core contract and fixture land before framework modules so every framework
task consumes stable validation and real evidence-reference behavior. Each
framework task is independently reviewable and testable.

## Error semantics

Catalog validation distinguishes:

- input or schema failure;
- scope/count failure;
- evidence-locator failure;
- claims-policy failure;
- review-policy failure;
- generated-output drift; and
- fixture-contract failure.

All return non-zero and bounded diagnostics. No infrastructure failure,
missing review, or unavailable source is converted into a clean result or an
evidence-support status.

## Security and maintenance residuals

- A qualified reviewer can still make an interpretive mistake. The catalog is
  non-authoritative and requires adopter validation.
- PR governance, not local YAML, establishes reviewer identity.
- A reviewer can change expected count and mappings together. Human source
  review is the control for scope completeness.
- Claims scanning is a maintenance tripwire, not a natural-language theorem
  prover. New evasive phrasing may require rule updates.
- A synthetic fixture proves reproducibility and field traceability only.
- Existing deployed pages can remain visible after their review date until a
  new deployment occurs. Displayed next-review dates make that residual
  observable.
- URLs can disappear or redirect between reviews. Offline CI intentionally
  does not treat URL reachability as source validity.
- Framework trademarks remain owned by their respective organizations. The
  catalog uses no logos or badges and implies no endorsement.

## Acceptance-criteria traceability

| Issue #43 criterion | Design coverage |
| --- | --- |
| Claims and terminology guide | Maintained claims guide, fixed status semantics, required disclaimers, and issue #47 rule reuse |
| Version/date and authoritative source | Framework metadata, exact product baseline, source pins, and rendered citations |
| Four support classifications | Closed `aegis_evidence_status` enum and decision table |
| Concrete links for positive mappings | Typed evidence references, locator validation, and required executable test references |
| Required gaps | Assurance ownership table plus explicit tenant, IAM, key, retention, transport, organizational, and model-risk responsibilities |
| Regulated workflow fixture | Public deterministic regulated example and field-level contract tests |
| Review dates and update process | Per-module review metadata, 180/90-day cadence, triggers, and semantic catalog versioning |
| Documentation and marketing parity | Catalog claims scan, generated docs under maintained inventory, existing public-copy guard, and CI integration |
| Tamper-evidence versus external controls | Five-property assurance model and mandatory host-control/limitation fields |

## Approval record

The user approved this design on 2026-08-10 after two adversarial reviews and a
full scope reset toward the smallest viable architecture.
