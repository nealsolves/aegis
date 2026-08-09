# Issue #47 Append-Only Evidence Operations and Claims Guidance Design

Date: 2026-08-09

Status: Approved integrated design — self-reviewed and adversarially reviewed

Issue: [#47 — append-only evidence operations and claims guidance](https://github.com/nealsolves/aegis/issues/47)

Parent: [#39 — external trust anchors, KMS-backed signing, and append-only evidence guidance](https://github.com/nealsolves/aegis/issues/39)

Dependency baseline: PR #68 merged issue #46 to `main` at `5de1cc9`.

## Executive decision

Publish one maintained, provider-neutral operations guide at
`docs/reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md`. The guide defines how a
host can combine AEGIS evidence contracts with separately administered
append-only or WORM storage, trusted-checkpoint selection, monitoring,
historical key material, backup, and disaster recovery.

AEGIS continues to own evidence construction and verification contracts only.
It does not create or operate durable storage, enforce retention, choose the
latest checkpoint, supply trusted time, manage keys, or make legal or
compliance determinations.

Add one repository claims guard at `scripts/check_evidence_claims.py`. It scans
all machine-readable documentation classified as `current` in
`doc_parity_manifest.yaml` and all statically extractable production React
copy. The guard rejects language that upgrades checksums, signatures, hash
chains, or checkpoints into immutable-storage, certification, or guaranteed
compliance claims.

This is a documentation and maintenance-control change. It does not modify the
runtime API, evidence schemas, checkpoint behavior, or storage implementation.

## Current baseline

The design consumes the following implemented contracts without changing
them:

- Issue #44 / ADR-0012 provides provider-neutral external signer and verifier
  contracts, stable key identity and version metadata, and independent
  signature and anchor results.
- Issue #46 / ADR-0015 provides explicit chain and workflow checkpoint records,
  host-driven creation, and checkpoint-aware verification with
  `unproven`, `checkpoint_proven`, and `contradicted` completeness outcomes.
- A valid, anchored checkpoint proves that presented evidence matches the
  pinned scope. It does not prove latest retrieval, append-only storage,
  trusted time, future activity, certification, or compliance.
- `JsonFileAuditSink` remains a local JSONL convenience sink. Issue #58 tracks
  its separate symlink and file-mode hardening work. Nothing in issue #47 may
  imply that this sink is durable, append-only, WORM, or hardened storage.

The released `aegis-ai-governance==0.9.0b1` package predates the current-source
checkpoint functionality. Maintained documentation must distinguish released
beta behavior from current source wherever it discusses checkpoints.

## Goals

- Give adopters a provider-neutral operating model for append-only or WORM
  evidence retention.
- Cover retention, object locking, legal holds, least privilege, trusted
  checkpoints, ingest and export verification, monitoring, backup, and
  disaster recovery.
- Provide rotation, revocation, provider-outage, and key-compromise runbooks
  that preserve historical verification.
- Separate AEGIS-supplied controls from host, provider, and organizational
  responsibilities.
- Keep tamper-evidence, external anchoring, checkpoint-backed completeness,
  append-only retention, and legal or compliance conclusions distinct.
- Prevent maintained public copy from drifting into immutable-storage,
  certification, or guaranteed-compliance overclaims.
- Keep provider examples illustrative and non-normative.

## Non-goals

- Adding a storage backend, automatic checkpoint sink, scheduler, latest-record
  registry, key manager, trusted timestamp service, backup engine, or recovery
  engine to AEGIS.
- Hardening `JsonFileAuditSink`; that remains issue #58.
- Choosing retention durations, legal-hold policy, incident cutoffs, or
  compliance mappings for adopters.
- Claiming that a provider feature, configuration example, or AEGIS result is
  sufficient for certification or legal compliance.
- OCR-based inspection of raster artwork or semantic proof over arbitrary
  natural language.
- Scanning public text supplied dynamically by an external runtime service
  rather than maintained in this repository.

## Approaches considered

### Selected: dedicated maintained guide plus repository-wide guard

The dedicated guide provides one canonical operator reference. Maintained
entry points link to it rather than duplicating runbooks. A standalone claims
guard derives its documentation scope from the existing inventory and reuses
the React public-copy extractor.

This keeps operating guidance discoverable, makes ownership boundaries
consistent, and gives CI one explicit command for claims enforcement.

### Rejected: expand the general operations runbook

`docs/reference/OPERATIONS_RUNBOOK.md` already combines release validation,
demo validation, and workflow operator commands. Adding the full evidence
lifecycle would mix distinct audiences and make the runbook harder to maintain.

### Rejected: make an ADR the primary operator artifact

ADRs are historical decision records in this repository. They are the right
authority for #44 and #46 contracts, but not for continuously maintained
storage operations and incident procedures.

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
failure-domain boundary from the evidence writer. They do not have to use a
different cloud provider, but the same principal must not be able to rewrite
evidence, weaken retention, and roll the accepted checkpoint back without an
independent signal.

No arrow in this architecture represents automatic AEGIS persistence,
retrieval, checkpoint selection, networking, retry, scheduling, or policy
enforcement.

## Ownership model

| Capability | AEGIS supplies | Host or provider owns | Organization owns |
| --- | --- | --- | --- |
| Evidence creation | Finalized artifacts and workflow evidence | Capture and routing | Required evidence classes |
| Tamper-evidence | Checksums, signatures, hash-chain and verification contracts | Invocation of verification and handling of failures | Acceptance policy |
| External anchoring | Provider-neutral signer/verifier metadata and results | Key resolver, clients, credentials, IAM, availability | Trust policy and approved authorities |
| Checkpoints | Explicit checkpoint records and typed verification outcomes | Creation cadence, persistence, retrieval, latest selection, rollback protection | Required checkpoint scope and cadence |
| Retention | No storage control | Object locking, versioning, retention, legal holds, deletion controls | Retention schedule and legal approval |
| Operations | Bounded verification reports | Monitoring, alerts, export, backup, restore, drills | Incident ownership and escalation |
| Assurance claims | Narrow technical results | Evidence supplied for assessment | Audit, certification, and legal/compliance conclusions |

## Evidence set and retention policy

The guide treats the retained evidence set as more than invocation JSON:

- finalized invocation artifacts and workflow evidence;
- chain and workflow checkpoints;
- export manifests and bounded verification results;
- exact historical public verification material;
- key identity/version, algorithm, anchor disposition, and resolver-policy
  history;
- retention and legal-hold policy history;
- provider control-plane audit evidence needed to investigate configuration or
  access changes.

Before enabling retention, the adopter defines evidence classes, duration,
expiry behavior, legal-hold interaction, permitted deletion authorities,
checkpoint cadence, required recovery point and recovery time, and the clock
or audit source used for operational timelines. AEGIS does not choose or
validate these values.

Object names must be unique and non-overwriting. A successful write is not
accepted as proof that retention is active: deployment validation must test the
configured inability to overwrite, shorten retention, or delete protected
records using the identities that operate the system.

## Ingest verification boundary

The host verifies evidence before committing it to the retained evidence set:

1. Validate the finalized record shape and checksum.
2. Verify chain content and continuity for the supplied scope.
3. Evaluate artifact signature and external-anchor outcomes when present.
4. Evaluate applicable chain or workflow checkpoints with the host's verifier
   and expected scope.
5. Treat `unproven`, invalid, revoked, unknown-key, unavailable, and
   `contradicted` outcomes according to explicit host policy.
6. Quarantine invalid or indeterminate input with bounded diagnostics. Do not
   silently accept it as verified and do not discard evidence needed for
   investigation.

Quarantine is a separately authorized retained destination, not an unprotected
temporary directory. Its retention and access policy must preserve incident
evidence without allowing quarantined input to enter the accepted evidence set.

Verification results are observations made under a particular trust policy at
a particular time. They do not replace the raw evidence and are not permanent
authority. Export and restore boundaries re-run verification against the
applicable current and historical policy.

## Least privilege and control separation

The guide defines separate conceptual roles:

- evidence writer: create new uniquely named evidence objects only;
- evidence reader/verifier: read evidence and verification material without
  write or retention-policy authority;
- checkpoint authority: create or publish checkpoints without evidence-delete
  authority;
- retention administrator: configure retention under change control without
  evidence-payload write authority;
- recovery operator: restore into quarantine without direct production
  promotion authority;
- monitored break-glass administrator: time-bounded emergency access with
  independent approval and alerting.

Provider implementations may express these roles differently. The normative
requirement is separation of capabilities and observable use, not a particular
provider IAM vocabulary.

## Checkpoint operations

Checkpoint creation remains an explicit host call after source evidence has
been finalized and verified. The guide covers:

- checkpoint cadence based on evidence volume and recovery objectives;
- independent retention of checkpoint records;
- an expected-scope or latest-checkpoint authority protected from the ordinary
  evidence writer;
- monitoring for missing, late, omitted, or rolled-back checkpoints;
- supplying the expected chain identity or workflow checkpoint at verification;
- preserving every checkpoint needed for historical investigation.

`checkpointed_at` is signed but host-supplied. It cannot independently prove
trusted, monotonic, or recent time. An adopter that needs trusted incident time
must retain an external time or control-plane audit source and must not infer a
compromise cutoff from `checkpointed_at` alone.

## Monitoring

The maintained checklist covers at least:

- failed, rejected, duplicate-name, overwrite, and delete attempts;
- retention-policy, object-lock, legal-hold, versioning, and lifecycle changes;
- IAM, key-policy, resolver-policy, and break-glass changes;
- missing or late checkpoints and a latest-checkpoint rollback;
- invalid, revoked, unknown-key, unanchored, unavailable, `unproven`, or
  `contradicted` verification outcomes;
- inventory/count gaps, unexpected chain heads, and export omissions;
- backup failures, replication lag, recovery-test failures, and restored
  storage with weaker controls;
- provider audit-log loss or unexpected disabling of monitoring.

Alerts preserve bounded identifiers and reason codes. They must not introduce
raw secrets, credentials, unrestricted payloads, or provider debug output into
logs.

## Export verification boundary

An export pipeline verifies the raw retained evidence before transformation:

1. Resolve the authoritative expected scope or checkpoint independently of the
   evidence objects being exported.
2. Read and verify the raw retained records and applicable checkpoint.
3. Preserve the raw records or stable references; do not make a transformed
   report the only retained evidence.
4. Produce a manifest that identifies the selected records, checkpoint,
   verification policy, and bounded verification outcomes.
5. Verify the completed bundle or delivery manifest before release.

An `aegis compliance export` command name or a successful export does not
constitute certification, regulatory approval, or proof that the input store
was complete.

## Backup and disaster recovery

Backups and replicas must preserve evidence and the material required to verify
it historically. The backup set includes exact public keys or approved retained
verification material, key identities and dispositions, resolver-policy
history, checkpoints, latest-scope records, retention configuration, and
control-plane audit evidence.

Recovery follows a fail-closed promotion flow:

1. Restore into an isolated quarantine destination.
2. Confirm the destination's versioning, retention, access, and monitoring
   controls before accepting new writes.
3. Reconcile object inventory, expected counts, chain scopes, and checkpoints.
4. Re-run raw evidence, signature, anchor, continuity, and checkpoint
   verification with the applicable historical policy.
5. Investigate every gap or indeterminate result.
6. Promote only after independent approval; record the recovery evidence.

Copying objects does not prove that lock state, legal holds, retention expiry,
or administrative separation survived. Recovery exercises must test those
properties explicitly.

## Key lifecycle runbooks

### Planned rotation

1. Provision and approve a new exact key version or provider identity.
2. Add the new exact pair and allowed algorithm to host trust policy.
3. Retain the old public verification material and disposition for at least the
   full historical evidence requirement.
4. Switch new signatures and checkpoints to the new version.
5. Verify both new evidence and representative historical evidence.
6. Retire signing permission separately from historical verification.

Rotation does not require rewriting or re-signing historical evidence.

### Revocation

1. Mark the exact affected identity/version revoked in host policy.
2. Preserve the original evidence, signatures, public verification material,
   disposition history, and reason for revocation.
3. Re-run verification so cryptographically valid but revoked signatures remain
   visibly revoked.
4. Apply organization policy separately to decide whether earlier evidence is
   acceptable for a particular purpose.

Deletion is not a substitute for revocation history.

### Suspected or confirmed compromise

1. Stop new signing and checkpoint creation with the affected version.
2. Revoke the exact version and protect resolver and retention configuration
   from the suspected principal.
3. Preserve evidence, checkpoints, provider audit records, and external time
   evidence.
4. Determine an incident window from independently trusted evidence. AEGIS
   `signed_at` and `checkpointed_at` fields are host-supplied and cannot alone
   establish the cutoff.
5. Re-verify the affected scope and classify invalid, revoked, unanchored,
   unavailable, `unproven`, and `contradicted` results without collapsing them.
6. Approve a replacement key, update trust policy, and create new checkpoints
   only from re-verified source evidence.
7. Document whether and why pre-compromise signatures remain acceptable.

A new checkpoint cannot retroactively make compromised historical signatures
trustworthy; it can only pin the re-evaluated evidence under the new authority.

### Provider or verifier outage

Provider unavailability never becomes verification success. The host may use
previously approved retained public verification material when the #44
verifier contract and host policy support it. Otherwise the result remains
indeterminate and follows the adopter's quarantine, retry, or fail-closed
policy.

## Assurance language contract

| Property | Bounded meaning | Does not establish |
| --- | --- | --- |
| Tamper-evidence | Detects covered modification of the evidence presented to verification | Storage immutability, completeness, trusted time |
| External anchoring | Relates a valid signature to a host-approved external identity/version | Retention, latest retrieval, certification |
| Checkpoint-backed completeness | Shows that presented evidence matches a valid, anchored checkpoint for the expected scope | That the checkpoint is latest, that no later activity occurred, or that storage is WORM |
| Append-only/WORM retention | Host/provider controls restrict overwrite or deletion for a configured scope and duration | Content correctness, signature validity, or legal sufficiency |
| Legal/compliance status | A conclusion under an organization's requirements and evidence | An automatic result of any AEGIS API, report, command, or storage feature |

Maintained copy uses these properties independently. It must not use one as a
synonym or proof for another.

## Non-normative provider examples

The guide may include a short appendix naming representative provider
capabilities, such as Amazon S3 Object Lock, Google Cloud Storage retention
policies/Bucket Lock, and Azure Blob immutable-storage policies. Every such
example is labeled **illustrative and non-normative**.

The appendix does not prescribe provider modes, durations, commands, SDK calls,
or IAM policies. Adopters must validate current provider documentation,
regional and account constraints, lock semantics, versioning behavior,
replication behavior, legal-hold behavior, and recovery behavior themselves.
Provider terminology checked during design does not become an AEGIS guarantee.

## Canonical guide and maintained cross-links

The new guide is the only full operations runbook for this topic. The following
maintained surfaces receive concise summaries or links rather than copied
procedures:

- `README.md`
- `SECURITY.md`
- `CHANGELOG.md`
- `docs/USAGE.md`
- `docs/INTEGRATION_GUIDE.md`
- `docs/PUBLIC_INTEGRATION_CONTRACT.md`
- `docs/architecture/AEGIS_THREAT_MODEL.md`
- `docs/reference/OPERATIONS_RUNBOOK.md`
- `docs/reference/external/AWS_KMS_SIGNING.md`
- `docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md`
- relevant React help/glossary copy and its tests

Existing React descriptions that call invocation artifacts “immutable records”
are corrected to “finalized” or “tamper-evident” records.

## Claims guard architecture

Add `scripts/check_evidence_claims.py` as the single comprehensive command.
It returns success only when documentation scope resolution, document reading,
React extraction, rule initialization, and all claim checks succeed. The rule
definitions are immutable module-level Python data in this script; no second
policy file or independently drifting rule source is introduced.

### Documentation scope

1. Add a public `collect_repository_files()` helper to
   `scripts/check_doc_parity.py`. It enumerates cached files and untracked,
   non-ignored files with
   `git ls-files --cached --others --exclude-standard`. Update
   `collect_documentation_files()` to filter that shared complete list by the
   documentation suffixes it already owns.
2. Import and call `load_manifest`, `collect_repository_files`, and
   `check_documentation_inventory` from `scripts/check_doc_parity.py`. This
   gives the claims guard the same inventory authority while still letting it
   discover a newly introduced suffix under a broad current pattern such as
   `docs/reference/**`.
3. Fail before scanning if documentation-inventory consistency reports any
   error.
4. Select every repository file matching the `current` patterns and
   no other inventory category by applying the manifest patterns with
   `fnmatch.fnmatch`.
5. Scan machine-readable text in `.md`, `.html`, `.mermaid`, and `.svg` files.
6. Recognize `.png` entries as binary and report them as accounted-for but not
   lexically scanned.
7. Reject a new documentation suffix unless the guard explicitly classifies it
   as scanned text or non-text binary.

Every candidate path must be a regular repository-contained file after
resolution. Symlinks, paths that resolve outside the repository, unreadable
files, and special files fail closed before content is read.

Named resource ceilings bound per-file bytes, aggregate source bytes, file
count, public-copy block count, and extracted output. The initial ceilings are
5 MiB per file, 50 MiB of aggregate source, 10,000 selected files, 250,000
public-copy blocks, and 50 MiB of serialized extractor output. A ceiling breach
is an infrastructure failure, not a clean scan. Normal rule matching uses
bounded text blocks and patterns that avoid nested, ambiguous repetition.

Raster artwork must not be the sole carrier of a security or assurance claim.
Claim-bearing raster text requires a maintained, scanned SVG source, caption,
or alternative-text equivalent. This is an explicit residual and policy, not a
claim that the guard performs OCR.

The guard also asserts that mandatory entry points remain classified as
current, including README, SECURITY, the parity-doc set, the new canonical
guide, operations guidance, public integration guidance, and the maintained
threat model. This prevents accidental manifest reclassification from silently
removing core public surfaces from the scan.

The issue #47 design and implementation-plan files are historical engineering
records, not current claim authority. Their exact paths are added to the
manifest's `historical` category when created.

### React scope

The guard reuses the existing TypeScript compiler-based extraction implemented
for `scripts/check_demo_copy.py`. The shared helpers are exposed with public
script-level names so both commands use the same rules for:

- recursively selecting production `.ts` and `.tsx` files;
- excluding tests, specs, generated content, declarations, and dependencies;
- extracting JSX text, public attributes, public component props, and named
  public static strings;
- joining visible inline markup while preserving source line mapping.

Extractor failure, missing Node/TypeScript support, malformed output, or an
unreadable file fails the guard. Dynamically fetched runtime text is outside
the repository-maintained-copy boundary and is not represented as scanned.
The source-byte and file-count ceilings are applied before the Node subprocess;
the extracted block and output ceilings are enforced before rule evaluation.

### Claim rules

Rules evaluate normalized public text blocks while preserving original path,
line, and excerpt. Normalization covers case, whitespace, inline markup,
hyphen/space variants, and ordinary line wrapping. It also applies Unicode
NFKC normalization, removes claim-splitting zero-width format characters,
decodes HTML character references, preserves Markdown link labels while
discarding their targets, and removes HTML/SVG tags without joining separate
rendered blocks into one claim.

The forbidden relationships include:

- checksum, signature, or hash-chain language that claims evidence or storage
  is immutable, append-only, WORM, unalterable, indelible, tamper-proof,
  deletion-proof, or impossible to rewrite;
- checkpoint language that claims latest retrieval, immutable storage, future
  inactivity, certification, or compliance;
- AEGIS APIs, reports, commands, evidence, or exports described as providing or
  guaranteeing certification, regulatory approval, legal sufficiency, or
  compliance;
- unqualified “immutable audit artifact/record/evidence/log/storage” language
  that assigns a storage property to an in-memory finalized record.

The guard permits:

- explicit bounded negatives such as “does not provide immutable storage” or
  “hash chaining alone does not make storage WORM,” plus bounded contrast forms
  such as “provides tamper-evidence, not immutable storage”;
- legitimate immutable Python values, exact immutable provider key versions,
  immutable release references, and provider feature names;
- command and field names such as `aegis compliance export` and
  `compliance_summary` when they are not assurance conclusions;
- provider capability descriptions that are clearly non-normative and do not
  attribute the control to AEGIS.

Negation handling is relationship-specific. The presence of a nearby word
`not` is not a blanket exemption: “not only does hash chaining provide
immutable storage” remains a finding. Tests freeze the accepted negative forms
and common evasions. A provider label such as “immutable storage” is not a
blanket exemption either: the surrounding block must identify a provider
capability, mark the example non-normative, and avoid attributing that
capability to AEGIS.

### Diagnostics and exit behavior

Every finding includes a stable rule ID, repository-relative path, source line,
and bounded excerpt. Configuration, inventory, extraction, or input failures
produce bounded diagnostics and a non-zero exit. The guard never converts an
infrastructure failure into a clean scan.

## CI integration

Add a dedicated, non-matrix evidence-claims job to
`.github/workflows/security-boundaries.yml` for pull requests and pushes. It
sets up Python and Node, installs the project development dependencies and the
frontend dependencies needed by the TypeScript extractor, and runs:

```bash
python scripts/check_evidence_claims.py
```

The same command is added to release validation and the demo deployment copy
gate. Release validation adds Node setup and installs the frontend dependencies
before invoking the guard; the demo workflow reuses its existing Node setup and
`npm ci` step and installs the Python development dependencies required by the
shared inventory checker. `docs/reference/OPERATIONS_RUNBOOK.md` lists the
guard in the local core validation commands.

The standalone command remains the single comprehensive claims guard; workflow
entries do not implement separate rule sets.

## Testing strategy

Implementation follows test-driven development.

### Rule tests

Add focused tests for every forbidden relationship and every legitimate
control case. The matrix includes:

- checksums, signatures, hash chains, checkpoints, AEGIS APIs, exports, and
  storage as subjects;
- immutable, WORM, append-only, unalterable, indelible, tamper-proof,
  deletion-proof, certified, compliant, and legally sufficient predicates;
- explicit negative disclaimers;
- “not only” pseudo-negation and other nearby-negation traps;
- capitalization, punctuation, multiline, hyphenation, Markdown, HTML, SVG,
  HTML entities, Unicode compatibility forms, zero-width separators, inline
  JSX, and split static-string variants;
- legitimate immutable key versions, frozen values, release references,
  provider feature names, and compliance command/field names.

### Scope and failure tests

Tests prove that:

- all text-bearing files classified current are scanned;
- cached and untracked non-ignored current documents are both scanned locally;
- historical, target-state, and instruction-system files are not claim
  authority;
- mandatory entry points cannot be reclassified away;
- new unsupported documentation suffixes fail closed;
- binary entries are accounted for without pretending OCR occurred;
- React production copy is extracted and tests/generated/internal strings are
  excluded;
- missing manifests, malformed inventory, unreadable files, missing extractor
  support, subprocess failure, and malformed extractor output fail closed;
- symlinks, out-of-root paths, special files, per-file/aggregate byte overflow,
  file-count overflow, extracted-block overflow, and extracted-output overflow
  fail closed before unbounded processing;
- diagnostics retain the correct path and line without leaking unbounded text.

### Documentation contract tests

Extend documentation tests to require:

- every required guide section and ownership boundary;
- direct #44/ADR-0012 and #46/ADR-0015 references;
- the released-beta/current-source distinction;
- the `checkpointed_at` trusted-time disclaimer;
- the five-axis assurance language contract;
- the #58 local JSONL sink disclaimer;
- provider examples labeled illustrative and non-normative;
- rotation, revocation, compromise, export, backup, and DR steps;
- links from each designated maintained entry point.

### Validation commands

The implementation is complete only after fresh successful runs of:

```bash
python -m pytest tests/test_evidence_claims.py tests/test_append_only_evidence_guidance.py tests/test_demo_copy_policy.py -q
python scripts/check_evidence_claims.py
python scripts/check_doc_parity.py
python scripts/check_demo_copy.py --frontend-root demo-app-react/src
python -m compileall scripts/check_evidence_claims.py scripts/check_demo_copy.py scripts/check_doc_parity.py
python -m flake8 scripts/check_evidence_claims.py scripts/check_demo_copy.py
npm --prefix demo-app-react test
python -m pytest -q
flake8 aegis
git diff --check
```

Frontend tests affected by corrected public copy also run through the existing
frontend test command.

## Error and incident semantics

Operational guidance never converts these states into success:

- invalid or malformed evidence;
- revoked or unknown keys;
- verifier or provider unavailability;
- unanchored signatures where anchoring is required;
- `unproven` completeness where checkpoint proof is required;
- `contradicted` checkpoint evidence;
- missing, stale, or rolled-back authoritative checkpoints;
- failed backup, restore, or retention-control validation;
- claims-guard configuration or extraction failure.

The guide instructs hosts to choose quarantine, retry, rejection, or incident
escalation through explicit policy. AEGIS does not choose that operational
policy.

## Security and maintenance residuals

The claims guard is a maintenance tripwire, not a natural-language theorem
prover or production security control. Novel phrasing may require a new rule.
A source owner can change the manifest, guard, and tests together; mandatory
surface assertions and code review are the compensating controls.

The static React extractor covers repository-maintained static copy, not text
returned dynamically by an external service. Raster artwork is not OCR-scanned.
Provider behavior can change after publication, which is why examples remain
non-normative and contain no copied configuration recipes.

Append-only retention still depends on provider behavior, host configuration,
identity separation, monitoring, and recovery practice. Documentation cannot
turn those external controls into an AEGIS guarantee.

## Acceptance-criteria traceability

| Issue #47 criterion | Design coverage |
| --- | --- |
| Retention, object locking, least privilege, checkpoints, verification, backup, and DR | Evidence policy, reference architecture, lifecycle sections, monitoring, and recovery flow |
| Key compromise and rotation with historical verification | Planned rotation, revocation, compromise, outage, and backup-material runbooks |
| Provider-neutral architecture and non-normative examples | Provider-neutral flow and explicitly illustrative appendix |
| Distinguish tamper-evidence, anchoring, append-only retention, and legal/compliance guarantees | Five-property assurance language contract and cross-link updates |
| Automated maintained-copy checks | Manifest-derived documentation scan, React extraction, contextual rules, and CI job |
| Reference #44 and checkpoint child without taking storage ownership | Current baseline, ownership table, checkpoint operations, and non-goals |
| Keep #58 separate | Current baseline, non-goals, guide contract tests, and maintained disclaimers |

## Review requirements

Before the specification is presented for implementation planning, it receives:

1. one full self-review for placeholders, ambiguity, internal consistency,
   acceptance coverage, and scope;
2. one adversarial review for assurance overclaim, trust-boundary collapse,
   key-compromise ambiguity, checkpoint rollback, recovery weakening,
   scanner bypass, false-positive, scope-removal, and fail-open behavior.

Implementation does not begin until the reviewed specification is approved and
a detailed implementation plan is written.

## Completed specification reviews

The required self-review completed on 2026-08-09. It removed an unfinished
test-command placeholder and resolved ambiguity around rule ownership,
inventory reuse, quarantine controls, CI dependencies, and exact validation
commands.

The required adversarial review completed on 2026-08-09. It added full
cached-plus-untracked scope discovery, unknown-suffix detection, path and
symlink rejection, explicit resource ceilings, Unicode/HTML normalization,
pseudo-negation tests, provider-label constraints, untrusted-time handling,
rollback separation, and recovery-control validation.

No blocking or internally contradictory finding remains. The accepted
limitations are recorded in **Security and maintenance residuals** rather than
being represented as properties of the guard or AEGIS.
