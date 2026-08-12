# EU AI Act citation and AEGIS evidence-contribution index

> This non-authoritative catalog describes bounded AEGIS technical evidence contributions. It does not determine applicability, control satisfaction, operating effectiveness, audit outcomes, certification, or legal sufficiency. Adopters remain responsible for their own legal, organizational, host, and operating-environment evidence decisions.

## Catalog and source baseline

- Catalog version: `1.0.0`
- Framework version: `Regulation EU 2024/1689 as amended through Regulation EU 2026/1744` (2026-07-24)
- AEGIS baseline: [`c4f6add076f2c534ada089f90e5c52c38341783c`](https://github.com/nealsolves/aegis/tree/c4f6add076f2c534ada089f90e5c52c38341783c)
- Availability: mapped to current source, not the published `0.9.0b1` wheel; see [docs/reference/RELEASE_MATRIX.md](../RELEASE_MATRIX.md).
- Review tier: `unreviewed`
- Review decision: `pending`
- Reviewed: `not completed`; next review due: `not scheduled`

## Declared scope

Bounded citation index for selected article-and-paragraph locations that intersect with technical governance evidence AEGIS can record or with explicit host and organizational gaps. This is not legal advice.

Mapping unit: selected EU AI Act article-and-paragraph citation.

Expected mapping count: `32`.

Exclusions:

- Territorial scope, actor classification, prohibited-practice screening, and Article 6 or Annex I or Annex III high-risk classification are excluded.
- GPAI duties, conformity assessment, registration, enforcement, penalties, and sector-specific interactions are excluded.
- Recitals, annex contents, national law, implementing acts, delegated acts, and unofficial guidance are excluded.
- No row decides whether a cited duty applies to an adopter, actor, system, or use case.

Applicability boundary:

This citation index does not determine whether any adopter, actor, system, or use case is within the scope of Regulation \(EU\) 2024/1689.

Effective-date basis:

The source set is current through Regulation \(EU\) 2026/1744, published 24 July 2026 and effective 27 July 2026. Article 113, third paragraph, point \(c\), as replaced, schedules Chapter III Sections 1 to 3 for 2 December 2027 for systems classified under Article 6\(2\) and Annex III and 2 August 2028 for systems classified under Article 6\(1\) and Annex I. Other provisions have their own dates. Adopters must consult the official sources; this index does not decide which date applies to any adopter.

## Authoritative sources

- [Regulation EU 2024/1689 Artificial Intelligence Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng) — `CELEX:32024R1689`, version Official Journal text, published 2024-07-12, accessed 2026-08-12.
- [Regulation EU 2026/1744 Digital Omnibus on AI](https://eur-lex.europa.eu/eli/reg/2026/1744/oj/eng) — `CELEX:32026R1744`, version Official Journal text, published 2026-07-24, accessed 2026-08-12.

## Review record

- Contributor GitHub identities: none recorded
- Reviewer GitHub identities: none recorded
- Review scope: not recorded
- Pull request: not recorded
- Reviewed commit: `not recorded`
- Qualification basis: not claimed
- Qualification evidence: not recorded
- Qualification verification: `not applicable`
- Qualification verified by GitHub identity: `not applicable`

Local CI checks record consistency only; it does not authenticate identity, credentials, legal correctness, or professional competence.

## Evidence mappings

### ART-10\(2\)

Source locator: `Article 10, paragraph 2`

Inclusion rationale: Included to make an adjacent organizational or legal responsibility explicit where this catalog identifies no complete AEGIS evidence contribution.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: External control

ART-10\(2\) is retained in this bounded index to show an adjacent legal or organizational responsibility for which no complete AEGIS evidence contribution is identified.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter obtains legal guidance as needed, determines whether ART-10\(2\) applies, implements the required process, and retains operating evidence.

Host controls:

- adopter: Determine applicability and effective dates for ART-10\(2\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-11\(1\)

Source locator: `Article 11, paragraph 1`

Inclusion rationale: Included because AEGIS can record a bounded technical artifact or enforcement result that may contribute evidence concerning this citation.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact relevant to part of ART-11\(1\); legal interpretation, organizational process, and operating effectiveness remain external.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/provenance): The audit contract records bounded provenance for technical evidence.
- test — [tests/test_audit_artifact_contract.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_audit_artifact_contract.py) (aegis_source; locator: test_audit_contract): The audit contract test exercises schema-valid evidence emission.

Unsupported portion: AEGIS does not determine whether ART-11\(1\) applies, satisfy the full cited duty, or operate the required organizational process.

Host controls:

- adopter: Determine applicability and effective dates for ART-11\(1\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-113-third\(c\)

Source locator: `Article 113, third paragraph, point \(c\), as replaced by Article 1\(40\)\(b\)`

Inclusion rationale: Included solely to state the authoritative effective-date basis for the bounded citation set; it does not determine applicability.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: External control

ART-113-third\(c\) is retained in this bounded index to show an adjacent legal or organizational responsibility for which no complete AEGIS evidence contribution is identified.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter obtains legal guidance as needed, determines whether ART-113-third\(c\) applies, implements the required process, and retains operating evidence.

Host controls:

- adopter: Determine applicability and effective dates for ART-113-third\(c\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-12\(1\)

Source locator: `Article 12, paragraph 1`

Inclusion rationale: Included because AEGIS can record a bounded technical artifact or enforcement result that may contribute evidence concerning this citation.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: Supported evidence

AEGIS directly records technical event evidence relevant to ART-12\(1\); this does not establish legal satisfaction or applicability.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/checksum): The audit contract records a checksum before host persistence.
- test — [tests/test_audit_sinks.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_audit_sinks.py) (aegis_source; locator: test_json_file_sink_appends_multiple): The sink test exercises host-file append behavior.
- fixture — [examples/compliance/regulated_workflow.py](../../../examples/compliance/regulated_workflow.py) (catalog_asset; locator: def run\(): The deterministic regulated workflow demonstrates schema-valid audit and workflow evidence without representing production operation.

Host controls:

- adopter: Determine applicability and effective dates for ART-12\(1\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-13\(1\)

Source locator: `Article 13, paragraph 1`

Inclusion rationale: Included because AEGIS can record a bounded technical artifact or enforcement result that may contribute evidence concerning this citation.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact relevant to part of ART-13\(1\); legal interpretation, organizational process, and operating effectiveness remain external.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.

Unsupported portion: AEGIS does not determine whether ART-13\(1\) applies, satisfy the full cited duty, or operate the required organizational process.

Host controls:

- adopter: Determine applicability and effective dates for ART-13\(1\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-14\(1\)

Source locator: `Article 14, paragraph 1`

Inclusion rationale: Included because AEGIS can record a bounded technical artifact or enforcement result that may contribute evidence concerning this citation.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact relevant to part of ART-14\(1\); legal interpretation, organizational process, and operating effectiveness remain external.

Evidence references:

- artifact_field — [schemas/workflow_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/workflow_artifact.schema.json) (aegis_source; locator: /properties/approval_checkpoints): The workflow artifact records approval-checkpoint evidence.
- test — [tests/test_approval_checkpoints.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_approval_checkpoints.py) (aegis_source; locator: test_pause_with_metadata_records_checkpoint): The checkpoint test exercises recorded human-approval metadata.

Unsupported portion: AEGIS does not determine whether ART-14\(1\) applies, satisfy the full cited duty, or operate the required organizational process.

Host controls:

- adopter: Determine applicability and effective dates for ART-14\(1\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-14\(4\)

Source locator: `Article 14, paragraph 4`

Inclusion rationale: Included because AEGIS can record a bounded technical artifact or enforcement result that may contribute evidence concerning this citation.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact relevant to part of ART-14\(4\); legal interpretation, organizational process, and operating effectiveness remain external.

Evidence references:

- artifact_field — [schemas/workflow_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/workflow_artifact.schema.json) (aegis_source; locator: /properties/approval_checkpoints): The workflow artifact records approval-checkpoint evidence.
- test — [tests/test_approval_checkpoints.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_approval_checkpoints.py) (aegis_source; locator: test_pause_with_metadata_records_checkpoint): The checkpoint test exercises recorded human-approval metadata.

Unsupported portion: AEGIS does not determine whether ART-14\(4\) applies, satisfy the full cited duty, or operate the required organizational process.

Host controls:

- adopter: Determine applicability and effective dates for ART-14\(4\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-15\(1\)

Source locator: `Article 15, paragraph 1`

Inclusion rationale: Included because AEGIS can record a bounded technical artifact or enforcement result that may contribute evidence concerning this citation.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact relevant to part of ART-15\(1\); legal interpretation, organizational process, and operating effectiveness remain external.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/signature_metadata): The audit contract records signature metadata when signing is configured.
- test — [tests/test_evidence_checksum_v2.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_evidence_checksum_v2.py) (aegis_source; locator: test_content_checksum_covers_chain_and_workflow_metadata): The checksum test exercises tamper-evident coverage of governance metadata.

Unsupported portion: AEGIS does not determine whether ART-15\(1\) applies, satisfy the full cited duty, or operate the required organizational process.

Host controls:

- adopter: Determine applicability and effective dates for ART-15\(1\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-15\(4\)

Source locator: `Article 15, paragraph 4`

Inclusion rationale: Included because AEGIS can record a bounded technical artifact or enforcement result that may contribute evidence concerning this citation.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact relevant to part of ART-15\(4\); legal interpretation, organizational process, and operating effectiveness remain external.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/signature_metadata): The audit contract records signature metadata when signing is configured.
- test — [tests/test_evidence_checksum_v2.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_evidence_checksum_v2.py) (aegis_source; locator: test_content_checksum_covers_chain_and_workflow_metadata): The checksum test exercises tamper-evident coverage of governance metadata.

Unsupported portion: AEGIS does not determine whether ART-15\(4\) applies, satisfy the full cited duty, or operate the required organizational process.

Host controls:

- adopter: Determine applicability and effective dates for ART-15\(4\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-15\(5\)

Source locator: `Article 15, paragraph 5`

Inclusion rationale: Included because AEGIS can record a bounded technical artifact or enforcement result that may contribute evidence concerning this citation.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact relevant to part of ART-15\(5\); legal interpretation, organizational process, and operating effectiveness remain external.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/signature_metadata): The audit contract records signature metadata when signing is configured.
- test — [tests/test_evidence_checksum_v2.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_evidence_checksum_v2.py) (aegis_source; locator: test_content_checksum_covers_chain_and_workflow_metadata): The checksum test exercises tamper-evident coverage of governance metadata.

Unsupported portion: AEGIS does not determine whether ART-15\(5\) applies, satisfy the full cited duty, or operate the required organizational process.

Host controls:

- adopter: Determine applicability and effective dates for ART-15\(5\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-17\(1\)

Source locator: `Article 17, paragraph 1`

Inclusion rationale: Included because AEGIS can record a bounded technical artifact or enforcement result that may contribute evidence concerning this citation.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact relevant to part of ART-17\(1\); legal interpretation, organizational process, and operating effectiveness remain external.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.

Unsupported portion: AEGIS does not determine whether ART-17\(1\) applies, satisfy the full cited duty, or operate the required organizational process.

Host controls:

- adopter: Determine applicability and effective dates for ART-17\(1\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-18\(1\)

Source locator: `Article 18, paragraph 1`

Inclusion rationale: Included to make an adjacent organizational or legal responsibility explicit where this catalog identifies no complete AEGIS evidence contribution.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: External control

ART-18\(1\) is retained in this bounded index to show an adjacent legal or organizational responsibility for which no complete AEGIS evidence contribution is identified.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter obtains legal guidance as needed, determines whether ART-18\(1\) applies, implements the required process, and retains operating evidence.

Host controls:

- adopter: Determine applicability and effective dates for ART-18\(1\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-19\(1\)

Source locator: `Article 19, paragraph 1`

Inclusion rationale: Included because AEGIS can record a bounded technical artifact or enforcement result that may contribute evidence concerning this citation.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact relevant to part of ART-19\(1\); legal interpretation, organizational process, and operating effectiveness remain external.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/checksum): The audit contract records a checksum before host persistence.
- test — [tests/test_audit_sinks.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_audit_sinks.py) (aegis_source; locator: test_json_file_sink_appends_multiple): The sink test exercises host-file append behavior.

Unsupported portion: AEGIS does not determine whether ART-19\(1\) applies, satisfy the full cited duty, or operate the required organizational process.

Host controls:

- adopter: Determine applicability and effective dates for ART-19\(1\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-21\(1\)

Source locator: `Article 21, paragraph 1`

Inclusion rationale: Included to make an adjacent organizational or legal responsibility explicit where this catalog identifies no complete AEGIS evidence contribution.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: External control

ART-21\(1\) is retained in this bounded index to show an adjacent legal or organizational responsibility for which no complete AEGIS evidence contribution is identified.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter obtains legal guidance as needed, determines whether ART-21\(1\) applies, implements the required process, and retains operating evidence.

Host controls:

- adopter: Determine applicability and effective dates for ART-21\(1\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-26\(1\)

Source locator: `Article 26, paragraph 1`

Inclusion rationale: Included because AEGIS can record a bounded technical artifact or enforcement result that may contribute evidence concerning this citation.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact relevant to part of ART-26\(1\); legal interpretation, organizational process, and operating effectiveness remain external.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.

Unsupported portion: AEGIS does not determine whether ART-26\(1\) applies, satisfy the full cited duty, or operate the required organizational process.

Host controls:

- adopter: Determine applicability and effective dates for ART-26\(1\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-26\(2\)

Source locator: `Article 26, paragraph 2`

Inclusion rationale: Included to make an adjacent organizational or legal responsibility explicit where this catalog identifies no complete AEGIS evidence contribution.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: External control

ART-26\(2\) is retained in this bounded index to show an adjacent legal or organizational responsibility for which no complete AEGIS evidence contribution is identified.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter obtains legal guidance as needed, determines whether ART-26\(2\) applies, implements the required process, and retains operating evidence.

Host controls:

- adopter: Determine applicability and effective dates for ART-26\(2\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-26\(4\)

Source locator: `Article 26, paragraph 4`

Inclusion rationale: Included because AEGIS can record a bounded technical artifact or enforcement result that may contribute evidence concerning this citation.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact relevant to part of ART-26\(4\); legal interpretation, organizational process, and operating effectiveness remain external.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/signature_metadata): The audit contract records signature metadata when signing is configured.
- test — [tests/test_evidence_checksum_v2.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_evidence_checksum_v2.py) (aegis_source; locator: test_content_checksum_covers_chain_and_workflow_metadata): The checksum test exercises tamper-evident coverage of governance metadata.

Unsupported portion: AEGIS does not determine whether ART-26\(4\) applies, satisfy the full cited duty, or operate the required organizational process.

Host controls:

- adopter: Determine applicability and effective dates for ART-26\(4\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-26\(5\)

Source locator: `Article 26, paragraph 5`

Inclusion rationale: Included to make an adjacent organizational or legal responsibility explicit where this catalog identifies no complete AEGIS evidence contribution.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: External control

ART-26\(5\) is retained in this bounded index to show an adjacent legal or organizational responsibility for which no complete AEGIS evidence contribution is identified.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter obtains legal guidance as needed, determines whether ART-26\(5\) applies, implements the required process, and retains operating evidence.

Host controls:

- adopter: Determine applicability and effective dates for ART-26\(5\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-26\(6\)

Source locator: `Article 26, paragraph 6`

Inclusion rationale: Included because AEGIS can record a bounded technical artifact or enforcement result that may contribute evidence concerning this citation.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact relevant to part of ART-26\(6\); legal interpretation, organizational process, and operating effectiveness remain external.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/checksum): The audit contract records a checksum before host persistence.
- test — [tests/test_audit_sinks.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_audit_sinks.py) (aegis_source; locator: test_json_file_sink_appends_multiple): The sink test exercises host-file append behavior.

Unsupported portion: AEGIS does not determine whether ART-26\(6\) applies, satisfy the full cited duty, or operate the required organizational process.

Host controls:

- adopter: Determine applicability and effective dates for ART-26\(6\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-26\(9\)

Source locator: `Article 26, paragraph 9`

Inclusion rationale: Included to make an adjacent organizational or legal responsibility explicit where this catalog identifies no complete AEGIS evidence contribution.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: External control

ART-26\(9\) is retained in this bounded index to show an adjacent legal or organizational responsibility for which no complete AEGIS evidence contribution is identified.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter obtains legal guidance as needed, determines whether ART-26\(9\) applies, implements the required process, and retains operating evidence.

Host controls:

- adopter: Determine applicability and effective dates for ART-26\(9\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-27\(1\)

Source locator: `Article 27, paragraph 1`

Inclusion rationale: Included to make an adjacent organizational or legal responsibility explicit where this catalog identifies no complete AEGIS evidence contribution.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: External control

ART-27\(1\) is retained in this bounded index to show an adjacent legal or organizational responsibility for which no complete AEGIS evidence contribution is identified.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter obtains legal guidance as needed, determines whether ART-27\(1\) applies, implements the required process, and retains operating evidence.

Host controls:

- adopter: Determine applicability and effective dates for ART-27\(1\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-4\(1\)

Source locator: `Article 4, paragraph 1`

Inclusion rationale: Included to make an adjacent organizational or legal responsibility explicit where this catalog identifies no complete AEGIS evidence contribution.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: External control

ART-4\(1\) is retained in this bounded index to show an adjacent legal or organizational responsibility for which no complete AEGIS evidence contribution is identified.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter obtains legal guidance as needed, determines whether ART-4\(1\) applies, implements the required process, and retains operating evidence.

Host controls:

- adopter: Determine applicability and effective dates for ART-4\(1\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-50\(1\)

Source locator: `Article 50, paragraph 1`

Inclusion rationale: Included to make an adjacent organizational or legal responsibility explicit where this catalog identifies no complete AEGIS evidence contribution.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: External control

ART-50\(1\) is retained in this bounded index to show an adjacent legal or organizational responsibility for which no complete AEGIS evidence contribution is identified.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter obtains legal guidance as needed, determines whether ART-50\(1\) applies, implements the required process, and retains operating evidence.

Host controls:

- adopter: Determine applicability and effective dates for ART-50\(1\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-50\(2\)

Source locator: `Article 50, paragraph 2`

Inclusion rationale: Included to make an adjacent organizational or legal responsibility explicit where this catalog identifies no complete AEGIS evidence contribution.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: External control

ART-50\(2\) is retained in this bounded index to show an adjacent legal or organizational responsibility for which no complete AEGIS evidence contribution is identified.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter obtains legal guidance as needed, determines whether ART-50\(2\) applies, implements the required process, and retains operating evidence.

Host controls:

- adopter: Determine applicability and effective dates for ART-50\(2\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-50\(4\)

Source locator: `Article 50, paragraph 4`

Inclusion rationale: Included to make an adjacent organizational or legal responsibility explicit where this catalog identifies no complete AEGIS evidence contribution.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: External control

ART-50\(4\) is retained in this bounded index to show an adjacent legal or organizational responsibility for which no complete AEGIS evidence contribution is identified.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter obtains legal guidance as needed, determines whether ART-50\(4\) applies, implements the required process, and retains operating evidence.

Host controls:

- adopter: Determine applicability and effective dates for ART-50\(4\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-72\(1\)

Source locator: `Article 72, paragraph 1`

Inclusion rationale: Included because AEGIS can record a bounded technical artifact or enforcement result that may contribute evidence concerning this citation.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact relevant to part of ART-72\(1\); legal interpretation, organizational process, and operating effectiveness remain external.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/checksum): The audit contract records a checksum before host persistence.
- test — [tests/test_audit_sinks.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_audit_sinks.py) (aegis_source; locator: test_json_file_sink_appends_multiple): The sink test exercises host-file append behavior.

Unsupported portion: AEGIS does not determine whether ART-72\(1\) applies, satisfy the full cited duty, or operate the required organizational process.

Host controls:

- adopter: Determine applicability and effective dates for ART-72\(1\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-72\(2\)

Source locator: `Article 72, paragraph 2`

Inclusion rationale: Included because AEGIS can record a bounded technical artifact or enforcement result that may contribute evidence concerning this citation.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact relevant to part of ART-72\(2\); legal interpretation, organizational process, and operating effectiveness remain external.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/checksum): The audit contract records a checksum before host persistence.
- test — [tests/test_audit_sinks.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_audit_sinks.py) (aegis_source; locator: test_json_file_sink_appends_multiple): The sink test exercises host-file append behavior.

Unsupported portion: AEGIS does not determine whether ART-72\(2\) applies, satisfy the full cited duty, or operate the required organizational process.

Host controls:

- adopter: Determine applicability and effective dates for ART-72\(2\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-73\(1\)

Source locator: `Article 73, paragraph 1`

Inclusion rationale: Included to make an adjacent organizational or legal responsibility explicit where this catalog identifies no complete AEGIS evidence contribution.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: External control

ART-73\(1\) is retained in this bounded index to show an adjacent legal or organizational responsibility for which no complete AEGIS evidence contribution is identified.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter obtains legal guidance as needed, determines whether ART-73\(1\) applies, implements the required process, and retains operating evidence.

Host controls:

- adopter: Determine applicability and effective dates for ART-73\(1\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-9\(1\)

Source locator: `Article 9, paragraph 1`

Inclusion rationale: Included because AEGIS can record a bounded technical artifact or enforcement result that may contribute evidence concerning this citation.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact relevant to part of ART-9\(1\); legal interpretation, organizational process, and operating effectiveness remain external.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.

Unsupported portion: AEGIS does not determine whether ART-9\(1\) applies, satisfy the full cited duty, or operate the required organizational process.

Host controls:

- adopter: Determine applicability and effective dates for ART-9\(1\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-9\(2\)

Source locator: `Article 9, paragraph 2`

Inclusion rationale: Included because AEGIS can record a bounded technical artifact or enforcement result that may contribute evidence concerning this citation.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact relevant to part of ART-9\(2\); legal interpretation, organizational process, and operating effectiveness remain external.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.

Unsupported portion: AEGIS does not determine whether ART-9\(2\) applies, satisfy the full cited duty, or operate the required organizational process.

Host controls:

- adopter: Determine applicability and effective dates for ART-9\(2\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-9\(6\)

Source locator: `Article 9, paragraph 6`

Inclusion rationale: Included because AEGIS can record a bounded technical artifact or enforcement result that may contribute evidence concerning this citation.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact relevant to part of ART-9\(6\); legal interpretation, organizational process, and operating effectiveness remain external.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.

Unsupported portion: AEGIS does not determine whether ART-9\(6\) applies, satisfy the full cited duty, or operate the required organizational process.

Host controls:

- adopter: Determine applicability and effective dates for ART-9\(6\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

### ART-9\(8\)

Source locator: `Article 9, paragraph 8`

Inclusion rationale: Included because AEGIS can record a bounded technical artifact or enforcement result that may contribute evidence concerning this citation.

Applicable source date: `2026-07-24`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact relevant to part of ART-9\(8\); legal interpretation, organizational process, and operating effectiveness remain external.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.

Unsupported portion: AEGIS does not determine whether ART-9\(8\) applies, satisfy the full cited duty, or operate the required organizational process.

Host controls:

- adopter: Determine applicability and effective dates for ART-9\(8\), assign accountable actors, and assess legal and evidentiary sufficiency.
- host operator: Operate tenant isolation, IAM, key management, transport security, protected retention, and deletion controls.

Limitations:

- This non-authoritative citation index is not legal advice or an applicability determination.
- AEGIS records technical evidence contributions; it does not establish legal sufficiency or production operating effectiveness.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.

Retention assumptions:

- The adopter reconciles Article-specific retention requirements with data-protection, employment, sector, and national law.
- The host preserves artifacts and external trust-anchor receipts under the adopter&\#x27;s approved schedule and access policy.

## Update triggers

- `framework_revision_or_erratum`
- `authoritative_amendment_or_guidance`
- `aegis_baseline_change`
- `referenced_evidence_change`
- `claims_policy_change`
