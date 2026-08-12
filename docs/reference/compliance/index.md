# Public-source compliance evidence catalog

This non-authoritative catalog describes bounded technical evidence that AEGIS
can record. It does not determine legal applicability, control satisfaction,
operating effectiveness, audit readiness, certification, or legal sufficiency.
Adopters remain responsible for organizational controls, host controls,
deployment evidence, and professional advice they choose to obtain.

## Active modules

- [NIST AI RMF 1.0](nist-ai-rmf-1.0.md) — all 72 Core subcategory identifiers,
  mapped to AEGIS evidence contributions and explicit gaps.
- [EU AI Act citation index](eu-ai-act-2024-1689-amended-2026.md) — a bounded
  article-and-paragraph citation set current through Regulation (EU) 2026/1744.
  It does not determine whether any adopter, actor, system, or use case is
  legally in scope.

Each generated page shows its actual review tier and record. An unreviewed page
is a draft and cannot pass the publication gate. Maintainer verification is
sufficient; community and qualified review are stronger optional provenance
tiers, not prerequisites imposed on this open-source catalog.

## Deferred, non-blocking work

- [Issue #76](https://github.com/nealsolves/aegis/issues/76) — ISO/IEC 42001
  remains unpublished pending a lawful human-authored contribution.
- [Issue #77](https://github.com/nealsolves/aegis/issues/77) — SOC 2 remains
  unpublished pending authoritative access and documented reuse rights.
- [Issue #78](https://github.com/nealsolves/aegis/issues/78) — qualified EU
  legal review is an optional future enhancement.

## Update process

After a framework revision, authoritative amendment or guidance change, AEGIS
baseline change, referenced-evidence change, or claims-policy change:

1. update the canonical YAML and source/access dates;
2. rerun scope and mapping validation for the affected module;
3. regenerate pages with `python scripts/render_compliance_catalog.py`;
4. bind the completed review record to the exact reviewed commit and PR; and
5. run `python scripts/check_compliance_catalog.py --as-of "$(date -u +%F)"`.

Local checks validate record consistency only. GitHub authorship and approval
do not authenticate professional qualifications, legal correctness, or
professional competence.
