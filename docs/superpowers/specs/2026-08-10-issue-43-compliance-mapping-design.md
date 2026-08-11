# Issue #43 Evidence-Oriented Compliance Mapping Design

Date: 2026-08-10

Status: Approved design

Issue: [#43 — publish explicit control mappings without certification claims](https://github.com/nealsolves/aegis/issues/43)

Dependency baseline:

- Issue #39 is closed as completed.
- Issue #47 and PR #69 established the maintained-public-copy evidence claims
  guard and the terminology boundaries this design consumes.
- The AEGIS runtime baseline is pinned at full commit
  `a9d0e4967070a11474ab11b23b047a5cde4b0892` for the first catalog version.

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

Catalog version `1.0.0` maps AEGIS current source at full commit
`a9d0e4967070a11474ab11b23b047a5cde4b0892`.

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
  git_commit: a9d0e4967070a11474ab11b23b047a5cde4b0892
  distribution_name: aegis-ai-governance
  published_version: 0.9.0b1
  mapped_channel: current_source
  release_matrix: docs/reference/RELEASE_MATRIX.md
  runtime_paths:
    - "aegis/**"
    - "schemas/**"
    - "policies/**"
    - "pyproject.toml"
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

`aegis_baseline.runtime_paths` is the complete tracked source surface imported
or consumed by the regulated fixture. Publication mode compares those paths in
the catalog checkout with the pinned commit and rejects any tracked,
untracked, ignored, or staged difference. A runtime change therefore requires
a new baseline commit and affected-framework review before the fixture or
generated pages can be published against it.

### Framework module

Every framework module contains:

```yaml
framework:
  id: stable-machine-id
  name: Human-readable source name
  version: Exact version or legal baseline
  source_date: YYYY-MM-DD
  authoritative_sources:
    - source_id: stable-source-id
      role: control_source
      title: Human-readable source title
      version: Exact source version
      publication_date: YYYY-MM-DD
      publication_id: Stable DOI, report number, ELI, or edition
      url: https://authoritative.example/source
      accessed_on: YYYY-MM-DD
declared_scope:
  summary: Original non-authoritative scope statement
  mapping_unit: Stable identifier type
  expected_mapping_count: 1
  exclusions: []
review:
  reviewed_on: YYYY-MM-DD
  next_review_due: YYYY-MM-DD
  reviewer_roles: []
  scope_reviewed_in: str
  mapping_reviewed_in: str
  claims_reviewed_in: str
  source_access_method: public_authoritative_source
controls: []
```

`authoritative_sources[].role` is one of `control_source`, `amending_act`,
`official_guidance`, or `metadata`. Only a `control_source` or `amending_act`
source can define a control identifier. Guidance may inform an interpretation
but cannot silently expand the declared scope. `publication_id` is the most
stable identifier supplied by the source owner: DOI or report number for NIST,
edition for ISO, publication title/version for AICPA, and ELI/CELEX identifier
for EU law.

The three `*_reviewed_in` fields record focused pull-request review provenance;
they may contain the same PR URL when one PR includes separately identifiable
scope, mapping, and claims approvals. Local validation does not claim to
authenticate reviewers. Repository permissions, branch protection, and PR
review establish identity and approval.

`reviewer_roles` is a non-empty subset of `framework_scope`,
`evidence_mapping`, `claims`, `iso_licensed_source`, and `eu_legal_scope`.
Each `*_reviewed_in` value, when required by publication mode, is an HTTPS pull
request URL for `nealsolves/aegis`. ISO requires `iso_licensed_source`; the EU
scope gate requires `eu_legal_scope`.

For ISO, `source_access_method` must be
`licensed_human_review_without_ai_processing`. Publication is blocked unless a
qualified maintainer records that review. The licensed standard, excerpts,
screenshots, or local file path are never committed or passed to automated
processing. The qualified maintainer must author or directly supply the
sanitized `control_id`, `source_reference`, `interpretation`, and every other
source-derived limitation or host responsibility for each ISO row. Automated
work may attach repository evidence to that approved input and run mechanical
validation, but it may not generate, infer, or paraphrase ISO requirements.
Publication requires the `iso_licensed_source` role in both the recorded scope
and mapping reviews.

### Control and mapping row

The `controls` array is both the declared identifier inventory and the mapping
collection, avoiding a second list that could drift. Scope review freezes each
`control_id` and `source_reference` before evidence mapping begins. Every row
contains:

```yaml
- control_id: stable-source-identifier
  source_reference:
    source_id: stable-source-id
    locator: Stable clause, criterion, subcategory, article, or paragraph
  mapping:
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

The scope-validation phase requires `control_id` and `source_reference` for
every row and verifies `expected_mapping_count == len(controls)`. The mapping
and publication phases additionally require the complete `mapping` object for
every row. This makes the reviewed control inventory explicit without
duplicating it.

### Evidence references

Evidence references are declarative and use a closed set of kinds:

- `policy_field` — repository path plus JSON Pointer or dotted field locator;
- `artifact_field` — schema or fixture path plus JSON Pointer;
- `test` — Python test path plus exact test function or node identifier;
- `command` — exact maintained documented invocation plus documentation path;
- `fixture` — fixture path plus a fixed scenario identifier; and
- `documentation` — maintained path plus section anchor.

All evidence references share this closed base shape:

```yaml
- kind: artifact_field
  baseline: aegis_source
  path: schemas/audit_artifact.schema.json
  locator: /properties/checksum
  demonstrates: Original bounded statement of the observed evidence
```

`baseline` is one of:

- `aegis_source` — the referenced path and locator must exist at the exact
  `aegis_baseline.git_commit`; or
- `catalog_asset` — the reference is a fixture, generated artifact, catalog
  contract test, or documentation asset introduced with the catalog and is
  resolved in the catalog checkout. It must be a tracked, non-ignored Git file;
  untracked, ignored, intent-to-add, or generated-only local files are not
  evidence.

`command` references additionally contain `invocation`; all other kinds reject
that field. `invocation` is rendered and compared with maintained
documentation, never executed from catalog data. `source_reference.source_id`
must resolve to the module's `authoritative_sources`; evidence paths must be
repository-relative, and `locator` is required for every kind.

The validator proves that a target and locator exist. It does not claim that
the reference is sufficient or legally relevant. The framework reviewer owns
that judgment.

For `aegis_source`, resolution reads the pinned Git object rather than the
working-tree file, and generated links use the full commit SHA. For
`catalog_asset`, resolution uses the strict working-tree path rules and
requires the path to appear as a normal tracked file in `git ls-files`;
generated links are relative to the catalog documentation. Publication also
compares every `aegis_baseline.runtime_paths` entry with the pinned commit and
rejects runtime drift before executing the fixed fixture harness. This
prevents a later source edit from silently changing evidence attributed to the
pinned AEGIS baseline while still allowing tracked regulated-fixture and
catalog-test assets to be cited honestly.

Catalog values never select executable functions. Fixture tests and command
tests use fixed Python-owned test code, fixed argument arrays, and no shell.

## Support status decision table

The field name is `aegis_evidence_status`, and rendered pages label it “AEGIS
evidence contribution.”

| Status | Meaning | Minimum required content |
| --- | --- | --- |
| `supported_evidence` | AEGIS directly produces concrete technical evidence relevant to the reviewed interpretation. This does not mean the control is satisfied. | At least one non-documentation `aegis_source` artifact, policy, command, or test reference; at least one executable test reference; limitations and host controls. A `catalog_asset` may demonstrate reproducibility but cannot be the sole positive basis. |
| `partial_evidence` | AEGIS produces indirect, incomplete, or condition-dependent evidence relevant to part of the reviewed interpretation. | At least one non-documentation `aegis_source` reference; an explicit description of the unsupported portion; an executable test reference; limitations and host controls. A `catalog_asset` cannot be the sole positive basis. |
| `external_control` | The reviewed interpretation identifies a host, provider, or organizational responsibility for which AEGIS supplies no relevant evidence. | `evidence: []`; named external owner and required external control. External explanatory material belongs in `host_controls` or `limitations`. |
| `not_addressed` | The identifier is inside declared scope, but this catalog identifies neither an AEGIS evidence contribution nor a specific implemented external-control mapping. | `evidence: []`; explicit gap statement and review note. Explanatory material belongs in `limitations`. |

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
- The scope-review phase records every Core subcategory identifier as a
  `controls[]` row before evidence mapping starts.
- The Playbook is supporting guidance and is not a separate mapping inventory.
- A future AI RMF revision triggers a new catalog review; it does not silently
  alter the 1.0 module.

### ISO/IEC 42001

- Source: ISO/IEC 42001:2023, Information technology — Artificial
  intelligence — Management system.
- Version/date: Edition 1, 2023-12.
- Declared scope: the reviewed requirements clauses and Annex A controls
  identified by a qualified maintainer using a licensed copy.
- The qualified maintainer freezes the exact clause and Annex A identifier
  inventory through scope validation before any ISO evidence mapping begins.
- The same qualified maintainer completes or explicitly approves every
  source-derived interpretation, limitation, host responsibility, and support
  classification before the module's mapping review is recorded. Automated
  work is limited to attaching AEGIS repository evidence to those sanitized
  human-authored inputs and validating the result.
- Only identifiers, permitted titles, citations, and original interpretations
  are published.
- The qualified reviewer performs human-only authorship and verification and
  does not provide licensed text to an AI system.
- The module remains unpublished until this review is recorded.

### SOC 2 Trust Services Criteria

- Source: 2017 Trust Services Criteria for Security, Availability, Processing
  Integrity, Confidentiality, and Privacy with revised points of focus — 2022.
- Source owner: AICPA Assurance Services Executive Committee.
- Declared scope: every criterion in the five Trust Services categories for
  the pinned publication.
- Scope validation freezes the exact criterion identifiers before evidence
  mapping starts.
- Points of focus inform human review but do not become separate mapping rows.
- The module stores identifiers and original interpretations, not copied
  normative text. Source-access and reuse terms are checked during human
  review.
- No use of SOC 2 marks, logos, badges, or wording implies endorsement.

### EU AI Act

- Primary act: Regulation (EU) 2024/1689.
- Amending act: Regulation (EU) 2026/1744 of 8 July 2026, published in OJ L on
  24 July 2026 and in force from 27 July 2026.
- Declared-scope categories are governance, risk management, technical
  documentation, logging, record-retention, transparency, human oversight,
  provider/deployer duties, post-market monitoring, and incident records where
  an AEGIS evidence mapping is intelligible.
- Before the EU mapping task begins, a qualified EU compliance or legal
  reviewer must author and approve the exact article-and-paragraph inventory
  as `controls[].control_id` and `controls[].source_reference`. The scope phase
  runs `check_compliance_catalog.py --module
  compliance/frameworks/eu-ai-act-2024-1689-amended-2026.yaml --phase scope`.
  Evidence mapping cannot begin until that focused scope check passes and the
  inventory's dedicated PR review is recorded in
  `review.scope_reviewed_in`.
- The approved inventory is the declared scope. Adding or removing an
  identifier after scope approval invalidates that review and requires a new
  scope review before mapping resumes.
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
`docs/reference/**` and the repository-wide claims guard.

Canonical YAML does not enter `doc_parity_manifest.yaml`'s documentation
inventory: the existing comprehensive claims guard intentionally does not
support `.yaml` input. Instead, the mandatory compliance checker strictly
loads every module listed by `compliance/catalog.yaml`, extracts every
schema-designated public prose field with its YAML field location, and passes
those bounded values to `scan_claims(...)`. The publication check fails when a
listed module is missing, an unlisted framework module exists, or catalog prose
cannot be extracted. This gives canonical YAML fail-closed coverage without
teaching the general documentation scanner a second structured-data format.

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

`scripts/check_compliance_catalog.py` has three validation modes:

1. `--module PATH --phase scope` validates one module's strict source metadata,
   unique `controls[].control_id` inventory, source references, exclusions, and
   expected count. Mapping objects and completed review records are not
   required in this pre-review mode.
2. `--module PATH --phase mapping` validates the same scope plus complete
   status-specific mapping objects, baseline-aware evidence locators, and
   catalog-prose claims. Review URLs may remain absent until focused review is
   recorded.
3. The no-module publication mode validates the complete manifest and all four
   modules, requires scope, mapping, and claims review records, enforces review
   dates, verifies all generated pages and the regulated fixture contract, and
   rejects unlisted framework modules.

This separation lets the core, fixture, and four framework tasks remain
focused and green while preserving one strict final publication gate. CI adds
the no-module command only in the publication-integration task; earlier tasks
run their focused unit, scope, or mapping checks.

In their applicable modes, checks fail when:

- the catalog or a module fails strict loading or schema validation;
- publication mode does not list exactly the four approved modules or finds an
  unlisted framework module;
- an `authoritative_sources[].source_id` is duplicated or a control references
  an absent or ambiguous source ID;
- a framework ID, control ID, or mapping row is duplicated;
- the actual mapping count differs from the reviewed expected count;
- a status omits its required evidence, limitation, gap, or external owner;
- a positive status lacks a non-documentation `aegis_source` reference or an
  executable test reference;
- `external_control` or `not_addressed` contains a non-empty `evidence` array;
- an evidence path or locator cannot be resolved;
- a `catalog_asset` is not a normal tracked, non-ignored Git file;
- a tracked, staged, untracked, or ignored path under
  `aegis_baseline.runtime_paths` differs from the pinned commit;
- catalog prose violates the issue #47 claims rules;
- publication mode lacks a source version, date, authoritative URL, review
  date, next-review date, or any required focused review PR;
- an ISO module lacks the licensed human-review record;
- publication mode finds a review overdue as of the supplied validation date;
- a generated page differs from deterministic output; or
- the regulated fixture contract fails.

The checker does not fetch URLs. A reachable URL would not prove that a source
interpretation is current. Source review remains a dated human process.

All modes accept `--as-of YYYY-MM-DD`. Unit and fixture tests always supply it.
Publication CI supplies the current UTC calendar date explicitly. Validation
is reproducible for identical repository input and the same `--as-of` value;
expiry enforcement is intentionally time-dependent across different dates.

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

Every module records `reviewed_on`, `next_review_due`, `reviewer_roles`,
`scope_reviewed_in`, `mapping_reviewed_in`, `claims_reviewed_in`, and
`source_access_method`.

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
- **ISO qualified maintainer:** uses licensed access to author or directly
  supply the sanitized identifier inventory and every source-derived
  interpretation, limitation, host responsibility, and support classification
  without supplying protected content to automated processing; the maintainer
  records both the scope and mapping approvals.

One person may fill multiple roles. For ISO, a qualified maintainer with
licensed access must fill the framework-scope and mapping-review roles, and the
`iso_licensed_source` role must be explicitly recorded for both approvals. The
repository does not claim that a YAML field authenticates any reviewer. PR
review and repository governance provide the approval record.

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
python scripts/check_compliance_catalog.py --as-of "$COMPLIANCE_REVIEW_DATE"
```

The workflow sets `COMPLIANCE_REVIEW_DATE` once from the current UTC calendar
date. The check is offline and reproducible for that explicit date; it is
intentionally date-sensitive so overdue reviews fail publication. The existing
comprehensive public-copy guard remains:

```bash
python scripts/check_evidence_claims.py
```

Release and demo workflows call the same commands rather than duplicating
rules. The operations runbook documents both local checks.

## Testing strategy

Implementation follows test-driven development.

### Schema and semantic tests

Cover valid minimal modules and failures for duplicate keys, aliases, custom
tags, unknown keys, malformed dates, invalid enums, duplicate framework,
source, and control IDs, missing source IDs, count mismatch, missing
status-specific fields, non-empty gap-state evidence, positive rows backed only
by catalog assets, unsafe paths, symlinks, untracked or ignored catalog assets,
missing locators, oversized input, baseline-owned tracked, staged, untracked,
or ignored drift, and overdue reviews. Freeze scope-, mapping-, and
publication-mode requirements separately. Tests resolve `aegis_source`
references from a fixed Git commit fixture, resolve tracked `catalog_asset`
references from the strict
checkout root, reject baseline mismatches, and pass explicit `--as-of` dates
around each expiry boundary.

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
assert each fixture-backed catalog locator. Run the fixture only after the
publication checker proves that all baseline-owned runtime paths match the
pinned commit. Negative tests prove malformed or altered evidence is not
reported as successful and prove that runtime drift prevents fixture
execution.

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
4. **ISO module:** a qualified maintainer with licensed access authors or
   directly supplies the sanitized clauses and Annex A inventory plus every
   source-derived interpretation, limitation, host responsibility, and support
   classification; automated work attaches repository evidence, validates the
   completed module, enforces the human scope-and-mapping approval gate, and
   generates the page.
5. **SOC 2 module:** reviewed five-category criteria scope and generated page.
6. **EU AI Act module:** first obtain qualified approval of the exact
   article-and-paragraph inventory through focused scope validation and review;
   then add mappings against Regulations 2024/1689 and 2026/1744,
   actor/applicability conditions, and the generated page.
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
