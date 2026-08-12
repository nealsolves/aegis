# NIST Artificial Intelligence Risk Management Framework 1.0

> This non-authoritative catalog describes bounded AEGIS technical evidence contributions. It does not determine applicability, control satisfaction, operating effectiveness, audit outcomes, certification, or legal sufficiency. Adopters remain responsible for their own legal, organizational, host, and operating-environment evidence decisions.

## Catalog and source baseline

- Catalog version: `1.0.0`
- Framework version: `1.0` (2023-01-26)
- AEGIS baseline: [`c4f6add076f2c534ada089f90e5c52c38341783c`](https://github.com/nealsolves/aegis/tree/c4f6add076f2c534ada089f90e5c52c38341783c)
- Availability: mapped to current source, not the published `0.9.0b1` wheel; see [docs/reference/RELEASE_MATRIX.md](../RELEASE_MATRIX.md).
- Review tier: `unreviewed`
- Review decision: `pending`
- Reviewed: `not completed`; next review due: `not scheduled`

## Declared scope

Complete identifier inventory of the 72 NIST AI RMF 1.0 Core subcategories. Mapping text describes only bounded AEGIS technical evidence contributions and does not state that an outcome is achieved.

Mapping unit: NIST AI RMF 1.0 Core subcategory identifier.

Expected mapping count: `72`.

Exclusions:

- NIST AI RMF categories, function narrative, profiles, and Playbook suggestions are not separate mapping rows.
- Source outcome text is not reproduced; consult the cited NIST sources.

## Authoritative sources

- [Artificial Intelligence Risk Management Framework AI RMF 1.0](https://doi.org/10.6028/NIST.AI.100-1) — `NIST AI 100-1`, version 1.0, published 2023-01-26, accessed 2026-08-12.
- [NIST AI RMF 1.0 Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/) — `NIST AI RMF 1.0 Core, Tables 1-4`, version Tables 1-4, published 2023-01-26, accessed 2026-08-12.

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

### GOVERN-1.1

Source locator: `Core Tables 1-4, GOVERN 1.1 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of GOVERN-1.1; the wider organizational outcome remains outside AEGIS.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with GOVERN-1.1 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether GOVERN-1.1 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### GOVERN-1.2

Source locator: `Core Tables 1-4, GOVERN 1.2 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of GOVERN-1.2; the wider organizational outcome remains outside AEGIS.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with GOVERN-1.2 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether GOVERN-1.2 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### GOVERN-1.3

Source locator: `Core Tables 1-4, GOVERN 1.3 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of GOVERN-1.3; the wider organizational outcome remains outside AEGIS.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with GOVERN-1.3 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether GOVERN-1.3 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### GOVERN-1.4

Source locator: `Core Tables 1-4, GOVERN 1.4 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of GOVERN-1.4; the wider organizational outcome remains outside AEGIS.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.
- fixture — [examples/compliance/regulated_workflow.py](../../../examples/compliance/regulated_workflow.py) (catalog_asset; locator: def run\(): The deterministic regulated workflow demonstrates policy-bound invocation and workflow evidence with explicit governance rationale without representing production operation.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with GOVERN-1.4 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether GOVERN-1.4 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### GOVERN-1.5

Source locator: `Core Tables 1-4, GOVERN 1.5 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of GOVERN-1.5; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/checksum): The audit contract records a checksum before host persistence.
- test — [tests/test_audit_sinks.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_audit_sinks.py) (aegis_source; locator: test_json_file_sink_appends_multiple): The sink test exercises host-file append behavior.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with GOVERN-1.5 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether GOVERN-1.5 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### GOVERN-1.6

Source locator: `Core Tables 1-4, GOVERN 1.6 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of GOVERN-1.6; the wider organizational outcome remains outside AEGIS.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with GOVERN-1.6 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether GOVERN-1.6 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### GOVERN-1.7

Source locator: `Core Tables 1-4, GOVERN 1.7 subcategory`

AEGIS evidence contribution: External control

GOVERN-1.7 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with GOVERN-1.7.

Host controls:

- adopter: Determine whether GOVERN-1.7 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### GOVERN-2.1

Source locator: `Core Tables 1-4, GOVERN 2.1 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of GOVERN-2.1; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/checksum): The audit contract records a canonical content checksum.
- test — [tests/test_audit_artifact_contract.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_audit_artifact_contract.py) (aegis_source; locator: test_audit_contract): The audit contract test exercises schema-valid evidence emission.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with GOVERN-2.1 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether GOVERN-2.1 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### GOVERN-2.2

Source locator: `Core Tables 1-4, GOVERN 2.2 subcategory`

AEGIS evidence contribution: External control

GOVERN-2.2 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with GOVERN-2.2.

Host controls:

- adopter: Determine whether GOVERN-2.2 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### GOVERN-2.3

Source locator: `Core Tables 1-4, GOVERN 2.3 subcategory`

AEGIS evidence contribution: External control

GOVERN-2.3 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with GOVERN-2.3.

Host controls:

- adopter: Determine whether GOVERN-2.3 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### GOVERN-3.1

Source locator: `Core Tables 1-4, GOVERN 3.1 subcategory`

AEGIS evidence contribution: Not addressed

No bounded AEGIS technical evidence contribution is identified for GOVERN-3.1 in this catalog baseline.

Evidence references:

- None identified for this catalog row.

Gap: AEGIS does not implement or evidence the organizational outcome associated with GOVERN-3.1.

Review note: Reassess only when the AEGIS baseline or declared catalog scope changes.

Host controls:

- adopter: Determine whether GOVERN-3.1 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### GOVERN-3.2

Source locator: `Core Tables 1-4, GOVERN 3.2 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of GOVERN-3.2; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/workflow_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/workflow_artifact.schema.json) (aegis_source; locator: /properties/approval_checkpoints): The workflow artifact records approval-checkpoint evidence.
- test — [tests/test_approval_checkpoints.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_approval_checkpoints.py) (aegis_source; locator: test_pause_with_metadata_records_checkpoint): The checkpoint test exercises recorded human-approval metadata.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with GOVERN-3.2 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether GOVERN-3.2 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### GOVERN-4.1

Source locator: `Core Tables 1-4, GOVERN 4.1 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of GOVERN-4.1; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/checksum): The audit contract records a canonical content checksum.
- test — [tests/test_audit_artifact_contract.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_audit_artifact_contract.py) (aegis_source; locator: test_audit_contract): The audit contract test exercises schema-valid evidence emission.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with GOVERN-4.1 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether GOVERN-4.1 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### GOVERN-4.2

Source locator: `Core Tables 1-4, GOVERN 4.2 subcategory`

AEGIS evidence contribution: External control

GOVERN-4.2 concerns an organizational risk-and-impact documentation and communication activity for which this catalog identifies no direct AEGIS evidence contribution.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: Organizational teams document the risks and potential impacts of the AI technology they design, develop, deploy, evaluate, and use, and communicate those impacts more broadly.

Host controls:

- adopter: Determine whether GOVERN-4.2 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### GOVERN-4.3

Source locator: `Core Tables 1-4, GOVERN 4.3 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of GOVERN-4.3; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/checksum): The audit contract records a checksum before host persistence.
- test — [tests/test_audit_sinks.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_audit_sinks.py) (aegis_source; locator: test_json_file_sink_appends_multiple): The sink test exercises host-file append behavior.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with GOVERN-4.3 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether GOVERN-4.3 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### GOVERN-5.1

Source locator: `Core Tables 1-4, GOVERN 5.1 subcategory`

AEGIS evidence contribution: External control

GOVERN-5.1 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with GOVERN-5.1.

Host controls:

- adopter: Determine whether GOVERN-5.1 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### GOVERN-5.2

Source locator: `Core Tables 1-4, GOVERN 5.2 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of GOVERN-5.2; the wider organizational outcome remains outside AEGIS.

Evidence references:

- policy_field — [schemas/policy_dsl.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/policy_dsl.schema.json) (aegis_source; locator: /properties/stateful): The policy contract records bounded stateful enforcement configuration.
- test — [tests/test_stateful_provider.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_stateful_provider.py) (aegis_source; locator: test_counter_is_monotonic_idempotent_and_rejects_overflow): The provider test exercises monotonic, idempotent state admission.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with GOVERN-5.2 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether GOVERN-5.2 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### GOVERN-6.1

Source locator: `Core Tables 1-4, GOVERN 6.1 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of GOVERN-6.1; the wider organizational outcome remains outside AEGIS.

Evidence references:

- policy_field — [schemas/policy_dsl.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/policy_dsl.schema.json) (aegis_source; locator: /properties/stateful): The policy contract records bounded stateful enforcement configuration.
- test — [tests/test_stateful_provider.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_stateful_provider.py) (aegis_source; locator: test_counter_is_monotonic_idempotent_and_rejects_overflow): The provider test exercises monotonic, idempotent state admission.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with GOVERN-6.1 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether GOVERN-6.1 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### GOVERN-6.2

Source locator: `Core Tables 1-4, GOVERN 6.2 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of GOVERN-6.2; the wider organizational outcome remains outside AEGIS.

Evidence references:

- policy_field — [schemas/policy_dsl.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/policy_dsl.schema.json) (aegis_source; locator: /properties/stateful): The policy contract records bounded stateful enforcement configuration.
- test — [tests/test_stateful_provider.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_stateful_provider.py) (aegis_source; locator: test_counter_is_monotonic_idempotent_and_rejects_overflow): The provider test exercises monotonic, idempotent state admission.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with GOVERN-6.2 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether GOVERN-6.2 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MANAGE-1.1

Source locator: `Core Tables 1-4, MANAGE 1.1 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MANAGE-1.1; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/risk_score): The audit contract carries a bounded risk-score field.
- test — [tests/test_risk_scoring.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_risk_scoring.py) (aegis_source; locator: test_compute_risk_score_consumes_compiled_risk_policy): The risk-scoring test exercises policy-bound technical scoring.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MANAGE-1.1 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MANAGE-1.1 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MANAGE-1.2

Source locator: `Core Tables 1-4, MANAGE 1.2 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MANAGE-1.2; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/risk_score): The audit contract carries a bounded risk-score field.
- test — [tests/test_risk_scoring.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_risk_scoring.py) (aegis_source; locator: test_compute_risk_score_consumes_compiled_risk_policy): The risk-scoring test exercises policy-bound technical scoring.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MANAGE-1.2 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MANAGE-1.2 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MANAGE-1.3

Source locator: `Core Tables 1-4, MANAGE 1.3 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MANAGE-1.3; the wider organizational outcome remains outside AEGIS.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MANAGE-1.3 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MANAGE-1.3 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MANAGE-1.4

Source locator: `Core Tables 1-4, MANAGE 1.4 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MANAGE-1.4; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/risk_score): The audit contract carries a bounded risk-score field.
- test — [tests/test_risk_scoring.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_risk_scoring.py) (aegis_source; locator: test_compute_risk_score_consumes_compiled_risk_policy): The risk-scoring test exercises policy-bound technical scoring.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MANAGE-1.4 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MANAGE-1.4 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MANAGE-2.1

Source locator: `Core Tables 1-4, MANAGE 2.1 subcategory`

AEGIS evidence contribution: External control

MANAGE-2.1 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MANAGE-2.1.

Host controls:

- adopter: Determine whether MANAGE-2.1 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MANAGE-2.2

Source locator: `Core Tables 1-4, MANAGE 2.2 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MANAGE-2.2; the wider organizational outcome remains outside AEGIS.

Evidence references:

- policy_field — [schemas/policy_dsl.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/policy_dsl.schema.json) (aegis_source; locator: /properties/stateful): The policy contract records bounded stateful enforcement configuration.
- test — [tests/test_stateful_provider.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_stateful_provider.py) (aegis_source; locator: test_counter_is_monotonic_idempotent_and_rejects_overflow): The provider test exercises monotonic, idempotent state admission.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MANAGE-2.2 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MANAGE-2.2 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MANAGE-2.3

Source locator: `Core Tables 1-4, MANAGE 2.3 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MANAGE-2.3; the wider organizational outcome remains outside AEGIS.

Evidence references:

- policy_field — [schemas/policy_dsl.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/policy_dsl.schema.json) (aegis_source; locator: /properties/stateful): The policy contract records bounded stateful enforcement configuration.
- test — [tests/test_stateful_provider.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_stateful_provider.py) (aegis_source; locator: test_counter_is_monotonic_idempotent_and_rejects_overflow): The provider test exercises monotonic, idempotent state admission.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MANAGE-2.3 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MANAGE-2.3 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MANAGE-2.4

Source locator: `Core Tables 1-4, MANAGE 2.4 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MANAGE-2.4; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/workflow_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/workflow_artifact.schema.json) (aegis_source; locator: /properties/approval_checkpoints): The workflow artifact records approval-checkpoint evidence.
- test — [tests/test_approval_checkpoints.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_approval_checkpoints.py) (aegis_source; locator: test_pause_with_metadata_records_checkpoint): The checkpoint test exercises recorded human-approval metadata.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MANAGE-2.4 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MANAGE-2.4 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MANAGE-3.1

Source locator: `Core Tables 1-4, MANAGE 3.1 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MANAGE-3.1; the wider organizational outcome remains outside AEGIS.

Evidence references:

- policy_field — [schemas/policy_dsl.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/policy_dsl.schema.json) (aegis_source; locator: /properties/stateful): The policy contract records bounded stateful enforcement configuration.
- test — [tests/test_stateful_provider.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_stateful_provider.py) (aegis_source; locator: test_counter_is_monotonic_idempotent_and_rejects_overflow): The provider test exercises monotonic, idempotent state admission.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MANAGE-3.1 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MANAGE-3.1 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MANAGE-3.2

Source locator: `Core Tables 1-4, MANAGE 3.2 subcategory`

AEGIS evidence contribution: External control

MANAGE-3.2 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MANAGE-3.2.

Host controls:

- adopter: Determine whether MANAGE-3.2 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MANAGE-4.1

Source locator: `Core Tables 1-4, MANAGE 4.1 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MANAGE-4.1; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/workflow_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/workflow_artifact.schema.json) (aegis_source; locator: /properties/approval_checkpoints): The workflow artifact records approval-checkpoint evidence.
- test — [tests/test_approval_checkpoints.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_approval_checkpoints.py) (aegis_source; locator: test_pause_with_metadata_records_checkpoint): The checkpoint test exercises recorded human-approval metadata.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MANAGE-4.1 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MANAGE-4.1 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MANAGE-4.2

Source locator: `Core Tables 1-4, MANAGE 4.2 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MANAGE-4.2; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/workflow_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/workflow_artifact.schema.json) (aegis_source; locator: /properties/approval_checkpoints): The workflow artifact records approval-checkpoint evidence.
- test — [tests/test_approval_checkpoints.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_approval_checkpoints.py) (aegis_source; locator: test_pause_with_metadata_records_checkpoint): The checkpoint test exercises recorded human-approval metadata.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MANAGE-4.2 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MANAGE-4.2 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MANAGE-4.3

Source locator: `Core Tables 1-4, MANAGE 4.3 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MANAGE-4.3; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/workflow_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/workflow_artifact.schema.json) (aegis_source; locator: /properties/approval_checkpoints): The workflow artifact records approval-checkpoint evidence.
- test — [tests/test_approval_checkpoints.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_approval_checkpoints.py) (aegis_source; locator: test_pause_with_metadata_records_checkpoint): The checkpoint test exercises recorded human-approval metadata.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MANAGE-4.3 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MANAGE-4.3 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MAP-1.1

Source locator: `Core Tables 1-4, MAP 1.1 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MAP-1.1; the wider organizational outcome remains outside AEGIS.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MAP-1.1 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MAP-1.1 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MAP-1.2

Source locator: `Core Tables 1-4, MAP 1.2 subcategory`

AEGIS evidence contribution: External control

MAP-1.2 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MAP-1.2.

Host controls:

- adopter: Determine whether MAP-1.2 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MAP-1.3

Source locator: `Core Tables 1-4, MAP 1.3 subcategory`

AEGIS evidence contribution: External control

MAP-1.3 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MAP-1.3.

Host controls:

- adopter: Determine whether MAP-1.3 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MAP-1.4

Source locator: `Core Tables 1-4, MAP 1.4 subcategory`

AEGIS evidence contribution: External control

MAP-1.4 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MAP-1.4.

Host controls:

- adopter: Determine whether MAP-1.4 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MAP-1.5

Source locator: `Core Tables 1-4, MAP 1.5 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MAP-1.5; the wider organizational outcome remains outside AEGIS.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MAP-1.5 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MAP-1.5 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MAP-1.6

Source locator: `Core Tables 1-4, MAP 1.6 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MAP-1.6; the wider organizational outcome remains outside AEGIS.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MAP-1.6 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MAP-1.6 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MAP-2.1

Source locator: `Core Tables 1-4, MAP 2.1 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MAP-2.1; the wider organizational outcome remains outside AEGIS.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MAP-2.1 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MAP-2.1 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MAP-2.2

Source locator: `Core Tables 1-4, MAP 2.2 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MAP-2.2; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/workflow_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/workflow_artifact.schema.json) (aegis_source; locator: /properties/approval_checkpoints): The workflow artifact records approval-checkpoint evidence.
- test — [tests/test_approval_checkpoints.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_approval_checkpoints.py) (aegis_source; locator: test_pause_with_metadata_records_checkpoint): The checkpoint test exercises recorded human-approval metadata.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MAP-2.2 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MAP-2.2 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MAP-2.3

Source locator: `Core Tables 1-4, MAP 2.3 subcategory`

AEGIS evidence contribution: External control

MAP-2.3 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MAP-2.3.

Host controls:

- adopter: Determine whether MAP-2.3 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MAP-3.1

Source locator: `Core Tables 1-4, MAP 3.1 subcategory`

AEGIS evidence contribution: External control

MAP-3.1 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MAP-3.1.

Host controls:

- adopter: Determine whether MAP-3.1 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MAP-3.2

Source locator: `Core Tables 1-4, MAP 3.2 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MAP-3.2; the wider organizational outcome remains outside AEGIS.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MAP-3.2 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MAP-3.2 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MAP-3.3

Source locator: `Core Tables 1-4, MAP 3.3 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MAP-3.3; the wider organizational outcome remains outside AEGIS.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MAP-3.3 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MAP-3.3 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MAP-3.4

Source locator: `Core Tables 1-4, MAP 3.4 subcategory`

AEGIS evidence contribution: External control

MAP-3.4 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MAP-3.4.

Host controls:

- adopter: Determine whether MAP-3.4 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MAP-3.5

Source locator: `Core Tables 1-4, MAP 3.5 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MAP-3.5; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/workflow_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/workflow_artifact.schema.json) (aegis_source; locator: /properties/approval_checkpoints): The workflow artifact records approval-checkpoint evidence.
- test — [tests/test_approval_checkpoints.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_approval_checkpoints.py) (aegis_source; locator: test_pause_with_metadata_records_checkpoint): The checkpoint test exercises recorded human-approval metadata.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MAP-3.5 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MAP-3.5 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MAP-4.1

Source locator: `Core Tables 1-4, MAP 4.1 subcategory`

AEGIS evidence contribution: External control

MAP-4.1 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MAP-4.1.

Host controls:

- adopter: Determine whether MAP-4.1 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MAP-4.2

Source locator: `Core Tables 1-4, MAP 4.2 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MAP-4.2; the wider organizational outcome remains outside AEGIS.

Evidence references:

- policy_field — [schemas/invocation_policy.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/invocation_policy.schema.json) (aegis_source; locator: /properties/pre_conditions): The invocation policy contract records bounded preconditions.
- test — [tests/test_conditions.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_conditions.py) (aegis_source; locator: test_resolve_condition_from_context): The condition test exercises policy-bound contextual decisions.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MAP-4.2 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MAP-4.2 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MAP-5.1

Source locator: `Core Tables 1-4, MAP 5.1 subcategory`

AEGIS evidence contribution: External control

MAP-5.1 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MAP-5.1.

Host controls:

- adopter: Determine whether MAP-5.1 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MAP-5.2

Source locator: `Core Tables 1-4, MAP 5.2 subcategory`

AEGIS evidence contribution: External control

MAP-5.2 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MAP-5.2.

Host controls:

- adopter: Determine whether MAP-5.2 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-1.1

Source locator: `Core Tables 1-4, MEASURE 1.1 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MEASURE-1.1; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/risk_score): The audit contract carries a bounded risk-score field.
- test — [tests/test_risk_scoring.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_risk_scoring.py) (aegis_source; locator: test_compute_risk_score_consumes_compiled_risk_policy): The risk-scoring test exercises policy-bound technical scoring.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MEASURE-1.1 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MEASURE-1.1 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-1.2

Source locator: `Core Tables 1-4, MEASURE 1.2 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MEASURE-1.2; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/risk_score): The audit contract carries a bounded risk-score field.
- test — [tests/test_risk_scoring.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_risk_scoring.py) (aegis_source; locator: test_compute_risk_score_consumes_compiled_risk_policy): The risk-scoring test exercises policy-bound technical scoring.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MEASURE-1.2 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MEASURE-1.2 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-1.3

Source locator: `Core Tables 1-4, MEASURE 1.3 subcategory`

AEGIS evidence contribution: External control

MEASURE-1.3 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MEASURE-1.3.

Host controls:

- adopter: Determine whether MEASURE-1.3 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-2.1

Source locator: `Core Tables 1-4, MEASURE 2.1 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MEASURE-2.1; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/checksum): The audit contract records a canonical content checksum.
- test — [tests/test_audit_artifact_contract.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_audit_artifact_contract.py) (aegis_source; locator: test_audit_contract): The audit contract test exercises schema-valid evidence emission.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MEASURE-2.1 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MEASURE-2.1 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-2.10

Source locator: `Core Tables 1-4, MEASURE 2.10 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MEASURE-2.10; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/signature_metadata): The audit contract records signature metadata when signing is configured.
- test — [tests/test_evidence_checksum_v2.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_evidence_checksum_v2.py) (aegis_source; locator: test_content_checksum_covers_chain_and_workflow_metadata): The checksum test exercises tamper-evident coverage of governance metadata.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MEASURE-2.10 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MEASURE-2.10 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-2.11

Source locator: `Core Tables 1-4, MEASURE 2.11 subcategory`

AEGIS evidence contribution: External control

MEASURE-2.11 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MEASURE-2.11.

Host controls:

- adopter: Determine whether MEASURE-2.11 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-2.12

Source locator: `Core Tables 1-4, MEASURE 2.12 subcategory`

AEGIS evidence contribution: Not addressed

No bounded AEGIS technical evidence contribution is identified for MEASURE-2.12 in this catalog baseline.

Evidence references:

- None identified for this catalog row.

Gap: AEGIS does not implement or evidence the organizational outcome associated with MEASURE-2.12.

Review note: Reassess only when the AEGIS baseline or declared catalog scope changes.

Host controls:

- adopter: Determine whether MEASURE-2.12 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-2.13

Source locator: `Core Tables 1-4, MEASURE 2.13 subcategory`

AEGIS evidence contribution: External control

MEASURE-2.13 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MEASURE-2.13.

Host controls:

- adopter: Determine whether MEASURE-2.13 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-2.2

Source locator: `Core Tables 1-4, MEASURE 2.2 subcategory`

AEGIS evidence contribution: External control

MEASURE-2.2 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MEASURE-2.2.

Host controls:

- adopter: Determine whether MEASURE-2.2 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-2.3

Source locator: `Core Tables 1-4, MEASURE 2.3 subcategory`

AEGIS evidence contribution: External control

MEASURE-2.3 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MEASURE-2.3.

Host controls:

- adopter: Determine whether MEASURE-2.3 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-2.4

Source locator: `Core Tables 1-4, MEASURE 2.4 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MEASURE-2.4; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/checksum): The audit contract records a checksum before host persistence.
- test — [tests/test_audit_sinks.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_audit_sinks.py) (aegis_source; locator: test_json_file_sink_appends_multiple): The sink test exercises host-file append behavior.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MEASURE-2.4 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MEASURE-2.4 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-2.5

Source locator: `Core Tables 1-4, MEASURE 2.5 subcategory`

AEGIS evidence contribution: External control

MEASURE-2.5 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MEASURE-2.5.

Host controls:

- adopter: Determine whether MEASURE-2.5 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-2.6

Source locator: `Core Tables 1-4, MEASURE 2.6 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MEASURE-2.6; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/signature_metadata): The audit contract records signature metadata when signing is configured.
- test — [tests/test_evidence_checksum_v2.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_evidence_checksum_v2.py) (aegis_source; locator: test_content_checksum_covers_chain_and_workflow_metadata): The checksum test exercises tamper-evident coverage of governance metadata.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MEASURE-2.6 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MEASURE-2.6 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-2.7

Source locator: `Core Tables 1-4, MEASURE 2.7 subcategory`

AEGIS evidence contribution: Partial evidence

AEGIS records a bounded technical artifact or enforcement decision relevant to part of MEASURE-2.7; the wider organizational outcome remains outside AEGIS.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/signature_metadata): The audit contract records signature metadata when signing is configured.
- test — [tests/test_evidence_checksum_v2.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_evidence_checksum_v2.py) (aegis_source; locator: test_content_checksum_covers_chain_and_workflow_metadata): The checksum test exercises tamper-evident coverage of governance metadata.

Unsupported portion: Governance judgment, operating effectiveness, and the complete organizational process associated with MEASURE-2.7 remain the adopter&\#x27;s responsibility.

Host controls:

- adopter: Determine whether MEASURE-2.7 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-2.8

Source locator: `Core Tables 1-4, MEASURE 2.8 subcategory`

AEGIS evidence contribution: Supported evidence

AEGIS directly records technical governance evidence relevant to MEASURE-2.8; this evidence contribution does not establish that the NIST outcome is achieved.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/provenance): The audit contract records parent evidence provenance.
- test — [tests/test_audit_lineage.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_audit_lineage.py) (aegis_source; locator: test_parent_child_edge_built_from_provenance): The lineage test exercises parent-child evidence relationships.

Host controls:

- adopter: Determine whether MEASURE-2.8 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-2.9

Source locator: `Core Tables 1-4, MEASURE 2.9 subcategory`

AEGIS evidence contribution: External control

MEASURE-2.9 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MEASURE-2.9.

Host controls:

- adopter: Determine whether MEASURE-2.9 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-3.1

Source locator: `Core Tables 1-4, MEASURE 3.1 subcategory`

AEGIS evidence contribution: Supported evidence

AEGIS directly records technical governance evidence relevant to MEASURE-3.1; this evidence contribution does not establish that the NIST outcome is achieved.

Evidence references:

- artifact_field — [schemas/audit_artifact.schema.json](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/schemas/audit_artifact.schema.json) (aegis_source; locator: /properties/provenance): The audit contract records parent evidence provenance.
- test — [tests/test_audit_lineage.py](https://github.com/nealsolves/aegis/blob/c4f6add076f2c534ada089f90e5c52c38341783c/tests/test_audit_lineage.py) (aegis_source; locator: test_parent_child_edge_built_from_provenance): The lineage test exercises parent-child evidence relationships.

Host controls:

- adopter: Determine whether MEASURE-3.1 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-3.2

Source locator: `Core Tables 1-4, MEASURE 3.2 subcategory`

AEGIS evidence contribution: External control

MEASURE-3.2 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MEASURE-3.2.

Host controls:

- adopter: Determine whether MEASURE-3.2 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-3.3

Source locator: `Core Tables 1-4, MEASURE 3.3 subcategory`

AEGIS evidence contribution: External control

MEASURE-3.3 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MEASURE-3.3.

Host controls:

- adopter: Determine whether MEASURE-3.3 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-4.1

Source locator: `Core Tables 1-4, MEASURE 4.1 subcategory`

AEGIS evidence contribution: External control

MEASURE-4.1 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MEASURE-4.1.

Host controls:

- adopter: Determine whether MEASURE-4.1 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-4.2

Source locator: `Core Tables 1-4, MEASURE 4.2 subcategory`

AEGIS evidence contribution: External control

MEASURE-4.2 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MEASURE-4.2.

Host controls:

- adopter: Determine whether MEASURE-4.2 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

### MEASURE-4.3

Source locator: `Core Tables 1-4, MEASURE 4.3 subcategory`

AEGIS evidence contribution: External control

MEASURE-4.3 primarily concerns an organizational, lifecycle, or assessment activity that AEGIS does not operate.

Evidence references:

- None identified for this catalog row.

External owner: adopter

External control: The adopter establishes, resources, performs, and retains evidence for the activity associated with MEASURE-4.3.

Host controls:

- adopter: Determine whether MEASURE-4.3 is relevant, implement the organizational process, and evaluate sufficiency in the deployment context.
- host operator: Operate tenant isolation, IAM, key management, transport security, and protected evidence storage.

Limitations:

- This row is a non-authoritative evidence interpretation, not a statement of NIST outcome satisfaction.
- AEGIS checksums and optional signatures provide tamper-evidence within documented limits. External trust-anchor deployment is a host control. AEGIS does not provide built-in WORM or append-only storage.
- AEGIS does not evaluate model quality, organizational effectiveness, or production operating effectiveness.

Retention assumptions:

- The adopter defines retention periods, access controls, deletion rules, and legal holds.
- The host preserves artifacts and any external trust-anchor receipts outside the governed process boundary.

## Update triggers

- `framework_revision_or_erratum`
- `authoritative_amendment_or_guidance`
- `aegis_baseline_change`
- `referenced_evidence_change`
- `claims_policy_change`
