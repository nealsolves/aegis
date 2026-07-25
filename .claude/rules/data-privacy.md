# Data Privacy Rules

## Purpose

Limit data collection and use to authorized purposes while making storage,
access, movement, retention, and deletion inspectable and enforceable.

## Applicability

Applies when work reads or writes customer data, changes schemas or data flows,
uses production data, introduces a processor, uses AI with data, or activates a
regulated/privacy overlay.

## Required inputs

- Data classification, purpose, subjects, sources, destinations, processors,
  regions, retention rules, and external obligations.
- Current data-flow evidence, access model, logging/telemetry behavior,
  encryption posture, deletion path, and target environments.
- Evaluated facts, risk, authority, and any privacy assessment.

## Mandatory controls

- Complete data classification before processing a new or changed data class.
  Treat unresolved material classification as `unknown` and fail closed.
- Apply minimization and purpose limitation: collect, derive, transmit, and
  retain only fields needed for the approved use; prevent unapproved secondary
  use.
- Define retention and deletion for source, replicas, caches, backups, logs,
  exports, and processors. Test deletion behavior and record any lawful hold.
- Use approved encryption in transit and at rest, with scoped key access and
  rotation appropriate to classification.
- Enforce access and audit controls for sensitive reads, writes, exports,
  administrative access, and policy changes. Review privileges for least access.
- Use masking, tokenization, or aggregation where full values are unnecessary.
  Respect residency and cross-border restrictions in storage and processing.
- Enforce production-data restrictions: do not copy production data to
  non-production unless policy and authority explicitly permit a protected,
  minimized method. Prefer synthetic test data; sanitize approved samples.
- Prevent PII logging in application logs, traces, errors, analytics, prompts,
  test fixtures, and support artifacts. Validate redaction at emission points.
- Complete a privacy assessment when collection, purpose, sharing, retention,
  sensitive classification, automated decisioning, or subject rights change.
- Review processors for purpose, data scope, location, retention, deletion,
  access, breach duties, and exit path before transfer.
- Treat AI data separately: document prompt/input/output classification,
  provider retention and training settings, regional processing, tool access,
  and deletion capability.
- Maintain data-flow evidence from collection through use, storage, sharing,
  logging, retention, and deletion; update it with the change.

## Evidence

Record the classification and purpose, field-level minimization, data-flow
evidence, processor and residency decisions, access/audit checks, retention and
deletion tests, encryption posture, logging/redaction results, and privacy
assessment when triggered.

## Exceptions

Privacy exceptions require explicit policy authority, scope, owner, expiry,
compensating controls, and external-obligation analysis. A new sensitive-data
use, unsupported regulatory exception, or material legal choice requires human
authority and cannot be normalized as a reversible default.

## Solo interpretation

A solo owner may implement and verify controls within configured authority. Use
a distinct privacy challenge pass for high-risk data changes; do not require a
routine second signer unless an overlay or external obligation does.

## Overlay notes

Regional, contractual, security, regulated, or team overlays may narrow data
use, mandate retention and evidence, add subject-right workflows, or require
separation. The most restrictive applicable control governs.

## Completion checklist

- [ ] Classification, purpose, minimization, and data-flow evidence are current.
- [ ] Access, encryption, residency, retention, deletion, and redaction were
  verified.
- [ ] Production/test data, processors, AI data, and privacy triggers were
  addressed.
- [ ] Residual privacy decisions are within authority.
