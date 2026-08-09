# Append-Only Evidence Operations

This is the canonical maintained operator guide for combining AEGIS evidence
contracts with host-operated append-only or write-once-read-many (WORM)
retention. It is provider-neutral: it defines assurance boundaries, roles, and
operational checks, but it does not prescribe provider commands, configuration
recipes, retention periods, or legal conclusions.

The released `aegis-ai-governance==0.9.0b1` package predates the current-source
checkpoint functionality. The checkpoint APIs and results discussed here are
implemented in the current source tree, are not present in the published
`0.9.0b1` wheel or tag, and have no later published version assigned yet.

This guide consumes, without changing, the external signing contract from
[issue #44](https://github.com/nealsolves/aegis/issues/44) and
[ADR-0012](../decisions/ADR-0012-external-trust-anchor-signing.md), and the
trusted-checkpoint contract from
[issue #46](https://github.com/nealsolves/aegis/issues/46) and
[ADR-0015](../decisions/ADR-0015-trusted-checkpoints.md). Those contracts cover
evidence construction and bounded verification results. Every storage,
selection, time, key-management, and operating action around them remains
host-driven.

## Assurance model

Keep these five properties independent in designs, alerts, reports, and audit
statements:

| Property | Bounded meaning | Explicit boundary |
| --- | --- | --- |
| Tamper-evidence | Detects covered modification of the evidence presented to verification | Checksums and hash chains do not make storage immutable and do not prove completeness or trusted time. |
| External anchoring | Relates valid cryptographic proof to a host-approved external identity and exact version | External anchoring does not establish any of the other four assurance properties. |
| Checkpoint-backed completeness | Shows that presented evidence matches a valid, anchored checkpoint for the expected scope | A checkpoint does not prove latest retrieval, future inactivity, or compliance, and does not make storage append-only or WORM. |
| Append-only/WORM retention | Host or provider controls restrict overwrite or deletion for a configured scope and duration | Retention does not validate content or cryptographic authenticity and does not establish historical completeness or legal sufficiency. |
| Legal/compliance status | An organizational conclusion under applicable requirements and evidence | AEGIS does not certify compliance through any technical feature. |

These five axes remain separate throughout the lifecycle.

A valid, anchored checkpoint can produce `checkpoint_proven` when the presented
evidence matches its pinned, expected scope.

A checkpoint does not prove latest retrieval, trusted time, future inactivity,
certification, or compliance.

Evaluate each conclusion independently.

A checkpoint does not make storage append-only or WORM.

These boundaries are cumulative.

Checksums, signatures, and hash chains do not make storage append-only or WORM.
They do not prove that the host retrieved every record.

AEGIS does not create or operate durable storage. AEGIS does not enforce
retention. AEGIS does not choose the latest checkpoint or supply trusted time.
AEGIS does not manage keys or perform backup or recovery. AEGIS does not
certify compliance or make legal determinations.

`JsonFileAuditSink` remains a local JSONL convenience sink. Issue
[#58](https://github.com/nealsolves/aegis/issues/58) tracks its separate symlink
and file-mode hardening work. Nothing in this guide implies that
`JsonFileAuditSink` is durable, append-only, WORM, or hardened storage; issue
#47 does not change or harden it.

## Provider-neutral reference architecture

Every action after AEGIS returns finalized evidence is explicit and
host-driven:

```text
AEGIS finalized evidence
        |
        v
host ingest verification -----> quarantine on invalid/indeterminate input
        |
        v
uniquely named evidence object in append-only/WORM retention
        |
        +----> independently administered checkpoint store
        |             |
        |             +----> protected latest-checkpoint authority
        v
monitored inventory, access, retention, and checkpoint cadence
        |
        v
raw-evidence verification before export or restore promotion
        |
        v
derived export plus manifest and bounded verification results
```

The checkpoint store and latest-checkpoint authority need an administrative or
failure-domain boundary from the evidence writer. They need not use a different
cloud provider, but the same principal must not be able to rewrite evidence,
weaken retention, and roll the accepted checkpoint back without an independent
signal.

No arrow represents automatic AEGIS persistence, retrieval, networking, retry,
scheduling, checkpoint creation, latest-checkpoint selection, or policy
enforcement. Quarantine is a separately authorized retained destination, not
an unprotected temporary directory.

## Ownership matrix

| Capability | AEGIS supplies | Host or provider owns | Organization owns |
| --- | --- | --- | --- |
| Evidence creation | Finalized artifacts and workflow evidence | Capture, routing, and accepted-set ingest | Required evidence classes |
| Tamper-evidence | Checksums, signatures, hash-chain, and verification contracts | Invocation of verification and handling of failures | Acceptance policy |
| External anchoring | Provider-neutral signer/verifier metadata and independent signature and anchor results | Key resolver, clients, credentials, IAM, and availability | Trust policy and approved authorities |
| Checkpoints | Explicit chain and workflow checkpoint records and typed outcomes | Creation cadence, persistence, retrieval, latest-checkpoint selection, and rollback protection | Required checkpoint scope and cadence |
| Retention | No storage control | Object locking, versioning, retention, legal holds, and deletion controls | Retention schedule and legal approval |
| Operations | Bounded verification reports | Monitoring, alerts, export, backup, restore, and drills | Incident ownership and escalation |
| Assurance claims | Narrow technical results | Evidence supplied for assessment | Audit, certification, and legal/compliance conclusions |

## Evidence set and data minimization

Define the complete retained evidence set before enabling retention. It should
include, as applicable:

- finalized invocation artifacts and workflow evidence;
- chain and workflow checkpoints, including historical checkpoints needed for
  investigations;
- export manifests and bounded verification results while retaining the raw
  evidence they describe;
- exact historical public verification material;
- key identity and version, algorithm, anchor disposition, revocation history,
  and resolver-policy history;
- retention and legal-hold policy history; and
- provider control-plane audit evidence needed to investigate access,
  configuration, retention, monitoring, and recovery changes.

The organization defines evidence classes, retention duration, expiry
behavior, legal-hold interaction, permitted deletion authorities, checkpoint
cadence, recovery point objective, recovery time objective, and the external
clock or audit source used for operational timelines. AEGIS neither chooses
nor validates those values.

Minimize and classify sensitive data before finalization. Append-only
retention can make later secret removal, privacy erasure, or redaction
impossible without destroying the retained object, while modifying a finalized
record invalidates its integrity evidence. Credentials and secret key material
must never appear in artifacts, checkpoints, manifests, alerts, or provider
debug logs. Confidentiality, encryption, privacy, and lawful-erasure controls
remain separate from integrity and retention controls.

## Ingest verification

Before committing an object to the accepted retained evidence set, the host
must:

1. Validate the finalized record shape and checksum.
2. Verify chain content and continuity for the supplied scope.
3. Evaluate artifact-signature and external-anchor outcomes when present.
4. Evaluate applicable chain or workflow checkpoints with the host verifier
   and expected scope.
5. Apply explicit host policy to `unproven`, invalid, revoked, unknown-key,
   unanchored, unavailable, and `contradicted` outcomes; never convert them
   into verification success.
6. Quarantine invalid or indeterminate input with bounded diagnostics. Do not
   silently accept it as verified or discard material needed for investigation.
7. Write an accepted object only under a unique, non-overwriting key, then
   record the result needed for inventory and cadence monitoring.

Object keys must be host-generated or constructed from validated, bounded
encodings. Raw artifact fields must not become paths or object keys without
validation. Reject duplicate names rather than overwriting an existing object.

Verification results are observations under a particular trust policy at a
particular time. They do not replace the raw evidence and are not permanent
authority. Re-run verification at export and restore boundaries under the
applicable current and historical policy.

## Retention and object locking

The host or provider implements versioning, object locking, retention expiry,
legal holds, lifecycle behavior, and deletion controls. The organization
approves the retention schedule and legal-hold policy. AEGIS supplies none of
these controls.

Before production use, validate the deployed controls with the actual
operating identities. A successful write is not evidence that retention is
active. Tests must demonstrate that those identities cannot overwrite a
protected record, shorten its retention, remove a legal hold without the
approved authority, or delete it before permitted expiry. Repeat these tests
after material IAM, retention, lifecycle, replication, or recovery changes.

Treat policy and hold history as evidence. Protect changes through approval,
independent logging, and alerts. Do not assume that copying or replicating an
object preserves its lock state, legal hold, expiry, administrative separation,
or monitoring coverage; test each property at every destination.

## Least privilege

Separate these conceptual roles and make their use observable:

- **Evidence writer:** creates new, uniquely named evidence objects only.
- **Evidence reader/verifier:** reads evidence and verification material but
  cannot write payloads or change retention policy.
- **Checkpoint authority:** creates or publishes checkpoints but cannot delete
  evidence.
- **Retention administrator:** configures retention under change control but
  cannot write evidence payloads.
- **Recovery operator:** restores into quarantine but cannot directly promote
  restored data to production.
- **Monitored break-glass administrator:** receives time-bounded emergency
  access with independent approval and immediate alerting.

Providers may express these roles differently. The normative requirement is
separation of capability and observable use, not a particular IAM vocabulary.
Credential issuance, rotation, revocation, and emergency use must preserve
that separation.

## Trusted checkpoint operations

Checkpoint creation is an explicit host call after source evidence has been
finalized and verified. The host must:

1. Set checkpoint cadence from evidence volume, detection needs, and recovery
   objectives.
2. Retain checkpoint records independently of ordinary evidence-writer
   authority.
3. Maintain an expected-scope or latest-checkpoint authority that the ordinary
   evidence writer cannot modify or roll back.
4. Monitor missing, late, omitted, and rolled-back checkpoints.
5. Supply the independently selected expected chain identity or workflow
   checkpoint during verification; evidence objects do not select their own
   authoritative checkpoint.
6. Preserve every checkpoint required for historical investigation and
   recovery.

Latest-checkpoint selection is a host responsibility. AEGIS verifies the
checkpoint the host supplies; it does not discover or assert which checkpoint
is latest. A stale or rolled-back authority is an incident condition, not
`checkpoint_proven` evidence of latest retrieval.

`checkpointed_at` is signed but host-supplied. It cannot independently prove
trusted, monotonic, or recent time. When trusted incident time is required,
retain an external time or control-plane audit source and never infer a
compromise cutoff from `checkpointed_at` alone. The same host-supplied-time
boundary applies to `signed_at`.

## Monitoring

Monitor, correlate, and alert on at least:

- failed, rejected, duplicate-name, overwrite, and delete attempts;
- retention-policy, object-lock, legal-hold, versioning, and lifecycle changes;
- IAM, key-policy, resolver-policy, and break-glass changes or use;
- missing or late checkpoints and rollback of the latest-checkpoint authority;
- invalid, revoked, unknown-key, unanchored, unavailable, `unproven`, or
  `contradicted` verification outcomes;
- inventory or count gaps, unexpected chain heads, and export omissions;
- unexpected reads, bulk exports, disclosure attempts, and abnormal evidence
  access volume;
- backup failures, replication lag, recovery-test failures, and restored
  destinations with weaker controls; and
- provider audit-log loss or unexpected disabling of monitoring.

Alerts must preserve bounded identifiers and reason codes without copying raw
secrets, credentials, unrestricted payloads, or provider debug output into
logs. Define escalation and retry, rejection, quarantine, or fail-closed
responses in host policy; AEGIS does not choose the operational response.

## Export verification

Verify raw retained evidence before transformation:

1. Resolve the authoritative expected scope or checkpoint independently of the
   evidence objects selected for export.
2. Read and verify the raw retained records and applicable checkpoint.
3. Preserve the raw records or stable references; a transformed report must
   not become the only retained evidence.
4. Produce a manifest identifying the selected records, checkpoint,
   verification policy, and bounded verification outcomes.
5. Verify the completed bundle or delivery manifest before release.

Run the command named `aegis compliance export` to create a technical export.
AEGIS does not certify compliance or grant regulatory approval. An export and
its delivery manifest do not prove legal sufficiency or that the source store
was complete. Monitor read and bulk export activity as disclosure-sensitive
operations.

## Backup and disaster recovery

Backups and replicas must preserve the evidence and everything required to
verify it historically:

- raw evidence, checkpoints, and protected latest-scope records;
- exact public keys or other approved retained verification material;
- key identities, versions, algorithms, and disposition history;
- resolver and trust-policy history;
- retention configuration, legal-hold state, and relevant lifecycle history;
- provider control-plane audit evidence; and
- the approved means of using historical verification material.

Some providers require the historical key resource to remain available. Where
the configured adapter and host policy support an approved retained-public-key
path, offline verification may instead be possible. Never destroy an old
provider verification resource before its complete historical verification
requirement ends. Test encryption and recovery-key availability separately
from signature verification.

Use this fail-closed recovery and promotion sequence:

1. Restore into an isolated, separately authorized quarantine destination.
2. Before accepting new writes, confirm that destination's versioning,
   retention, access separation, and monitoring controls.
3. Reconcile object inventory, expected counts, chain scopes, and checkpoints
   against the protected authority.
4. Re-run raw-evidence, signature, anchor, continuity, and checkpoint
   verification using the applicable historical policy and verifier material.
5. Investigate every gap and indeterminate result.
6. Promote only after independent approval, then retain the recovery evidence.

Recovery exercises must explicitly test whether lock state, legal holds,
retention expiry, administrative separation, monitoring, historical key
access, recovery point, and recovery time survive. Copying objects alone proves
none of those properties.

## Key rotation

For planned rotation:

1. Provision and approve a new exact key version or provider identity.
2. Add the new exact identity/version pair and allowed algorithm to host trust
   policy.
3. Retain the old public verification material and disposition for the full
   historical evidence requirement.
4. Keep the old provider verification resource available when the configured
   verifier has no approved offline retained-key path. Do not schedule its
   destruction before historical verification and retention requirements end.
5. Switch new signatures and checkpoints to the new version.
6. Verify both new evidence and representative historical evidence.
7. Retire signing permission separately from historical verification.

Rotation does not require rewriting or re-signing historical evidence.

## Revocation

1. Mark the exact affected identity and version revoked in host policy.
2. Preserve the original evidence, signatures, public verification material,
   disposition history, and revocation reason.
3. Re-run verification so cryptographically valid but revoked signatures
   remain visibly revoked.
4. Apply organizational policy separately to decide whether earlier evidence
   remains acceptable for a specific purpose.

Deletion is not a substitute for revocation history.

## Suspected or confirmed compromise

1. Stop new signing and checkpoint creation with the affected version.
2. Revoke that exact version and protect resolver and retention configuration
   from the suspected principal.
3. Preserve evidence, checkpoints, provider audit records, and external time
   evidence.
4. Determine the incident window from independently trusted evidence. AEGIS
   `signed_at` and `checkpointed_at` fields are host-supplied and cannot alone
   establish the cutoff.
5. Re-verify the affected scope and keep invalid, revoked, unanchored,
   unavailable, `unproven`, and `contradicted` outcomes distinct.
6. Approve a replacement key, update trust policy, and create new checkpoints
   only from re-verified source evidence.
7. Document whether and why pre-compromise signatures remain acceptable.

A new checkpoint cannot retroactively make compromised historical signatures
trustworthy; it can only pin the re-evaluated evidence under the new authority.

## Provider outage

Provider or verifier unavailability never becomes verification success. The
host may use previously approved retained public verification material only
when the issue #44 verifier contract and host policy support it. Otherwise the
result remains indeterminate and follows the adopter's explicit quarantine,
retry, rejection, or fail-closed policy.

During an outage, preserve the input and bounded failure evidence, monitor
checkpoint cadence and backlog, and prevent unverified evidence from entering
the accepted set. After service returns, re-resolve the exact approved key
identity and version, re-run verification, reconcile the backlog and expected
checkpoint scope, and investigate every gap before normal promotion resumes.

## Non-normative provider examples

The following names are **illustrative and non-normative** examples of provider
capabilities that an adopter might evaluate:

- Amazon S3 Object Lock;
- Google Cloud Storage retention policies and Bucket Lock; and
- Azure Blob immutable-storage policies.

These examples do not prescribe a mode, duration, command, SDK call, or IAM
policy, and they do not make any provider capability an AEGIS guarantee.
Validate current provider documentation, regional and account constraints,
lock semantics, versioning, replication, legal-hold behavior, audit coverage,
and recovery behavior before adoption and after material service changes.
