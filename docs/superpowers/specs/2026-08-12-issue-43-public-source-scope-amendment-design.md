# Issue #43 Public-Source Scope Amendment Design

## Status and authority

This design incorporates the scope decision recorded in GitHub Issue #43 on
2026-08-12 and supersedes the four-framework publication requirements in
`2026-08-10-issue-43-compliance-mapping-design.md`. Issues #76, #77, and #78
remain independent, non-blocking follow-ups.

## Published scope

The active catalog contains exactly two public-source modules:

- all 72 NIST AI RMF 1.0 Core subcategory identifiers, sourced from NIST AI
  100-1 and the NIST AIRC Core page; and
- a bounded EU AI Act article-and-paragraph citation index sourced from
  Regulation (EU) 2024/1689 and Regulation (EU) 2026/1744.

ISO/IEC 42001 and SOC 2 are absent from the active module list. The maintained
catalog index names their deferral issues without rendering either framework as
a completed mapping.

The EU inventory is selected for technical evidence touchpoints such as risk
records, documentation, logging, oversight, robustness, retention, deployment,
post-market monitoring, and transparency. Inclusion says only why an identifier
is useful in an evidence-contribution index. It never decides whether a person,
organization, actor, system, or use case is within legal scope.

## Review and provenance contract

Every module records one of four tiers: `unreviewed`, `maintainer_verified`,
`community_reviewed`, or `qualified_reviewed`. Publication rejects
`unreviewed`, a pending/rejected decision, missing GitHub identities, a missing
AEGIS PR URL, a missing reviewed commit SHA, or an expired review. Community
review requires a reviewer identity distinct from every contributor identity.
Qualified review additionally requires a bounded qualification basis and an
explicit `self_declared` or `independently_verified` verification status.

The renderer derives its public tier label directly from the machine record;
catalog authors cannot supply a stronger display label. CI checks record shape,
dates, source/scope parity, commit existence, and tier-specific fields. It does
not authenticate identities, credentials, legal correctness, or professional
competence.

Maintainer verification is sufficient for publication. Qualified review is an
optional enhancement under Issue #78.

## Mapping contract

Each row has a source identifier and locator plus exactly one evidence status:
`supported_evidence`, `partial_evidence`, `external_control`, or
`not_addressed`. Positive rows cite pinned AEGIS source evidence and an
executable test. External and not-addressed rows remain evidence-free and name
their owner or gap. Every row states host controls, limitations, and retention
assumptions.

EU rows additionally contain a neutral inclusion rationale and an applicable
source date. The EU module contains an explicit non-applicability statement and
an effective-date basis that accounts for the 2026 amending act.

AEGIS tamper-evidence is described separately from external trust anchors and
host-operated append-only retention. The regulated workflow fixture is cited by
at least one positive row but is never described as production operating
evidence.

## Publication flow

The publication checker loads only the manifest's active subset, validates the
closed schema and semantic rules, resolves evidence against the pinned AEGIS
baseline, checks review expiry and public claims, verifies deterministic page
parity, and runs the fixed regulated fixture contract. Maintained documentation
links to the generated catalog index, which displays active modules and the ISO,
SOC 2, and optional EU qualified-review deferrals.

The final review record must be added only after an identified maintainer has
reviewed the exact mapping commit. Until that sign-off exists, the modules stay
`unreviewed` and the publication gate must fail closed.

## Testing

Tests cover subset publication, tier transitions, qualification support,
overstated labels, exact NIST identifiers/count, bounded EU identifiers/count,
EU rationale/date/non-applicability fields, evidence status semantics, concrete
locators, fixture linkage, generated output parity, maintained entrypoints, and
CI invocation. Full completion requires a clean full-suite run plus the
publication checker against a non-expired reviewed record.

## Adversarial-review remediation amendment

The reviewed commit must contain the same reviewable module content that is
currently being published. Review metadata may differ because it is added only
after review; every other module field must match the recorded commit exactly.
A commit that merely exists, predates the module, or contains different mapping
content is not valid review provenance.

Completed reviews and authoritative-source access dates cannot be later than
the checker's `--as-of` date. A completed review cannot predate the latest
source access date recorded by its module. Qualified review additionally
records a bounded review scope, a qualification-evidence URL, and the identity
that verified that evidence when the verification status is
`independently_verified`. These fields document provenance without claiming
that local CI authenticates credentials.

The maintained claims guide must describe qualified EU review as optional.
NIST `GOVERN-4.2` is partial evidence unless AEGIS gains concrete evidence that
organizational teams document and communicate AI risks and impacts. The
operations runbook runs the compliance checker before Python tests so ordinary
bytecode generation cannot create a false baseline-drift result.

Second-review pressure tests must prove that publication rejects an unrelated
historical commit, future review/access dates, and incomplete qualified-review
support. The exact supported/partial mapping classifications and maintained
documentation are re-read against Issue #43 after automated gates pass.
