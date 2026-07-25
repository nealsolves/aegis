# Documentation Rules

## Purpose

Keep durable intent, decisions, interfaces, operating knowledge, and delivery
status synchronized with actual behavior and evidence.

## Applicability

Always applies. Documentation depth is proportional: a spelling fix may need no
new artifact, while a public contract, architecture, operation, data use, or
release change updates its authoritative record.

## Required inputs

- Approved artifacts, implementation and tests, public interfaces, architecture
  decisions, operational behavior, current status, and selected lifecycle path.
- Existing documentation owners, generation sources, links, and known consumers.

## Mandatory controls

- Treat documentation as done: a change cannot reach `COMPLETE` while affected
  durable documentation or status records are knowingly stale.
- Maintain decision, API, and operations synchronization. Update ADRs, contracts,
  examples, runbooks, configuration references, migrations, and failure behavior
  when the corresponding system behavior changes.
- Keep runbooks actionable with triggers, prerequisites, safe steps, validation,
  rollback/recovery, escalation, ownership, and last verification.
- Mark generated documentation and its source command. Change the generator or
  source rather than hand-editing output; verify reproducibility.
- Keep status honest: distinguish planned, implemented, reviewed, merged,
  released, and deployed. Never infer an active feature or production state from
  a stale status file.
- Link, do not copy authoritative policy, requirements, contracts, and long
  procedures. Avoid divergent duplicates while keeping critical local context.
- Separate durable versus volatile information: durable intent and decisions
  belong in versioned artifacts; transient command output belongs in bounded
  evidence or CI, with a stable summary/reference.
- Enforce Markdown quality with descriptive headings, concise prose, accessible
  tables/lists, fenced-code language where useful, and no accidental secrets.
- Check broken links, anchors, referenced paths, generated navigation, and
  examples affected by renames. External links require a stable authoritative
  target where practical.

## Evidence

Record the documents reviewed/changed, authoritative sources, link and example
checks, generation command/result when applicable, runbook verification, and
status update. A documentation-only change still records its validation and
review evidence.

## Exceptions

A documentation deferral must identify the stale information, affected readers,
temporary safe reference, owner, expiry, and remediation. Do not defer safety,
data, migration, public-contract, or operator-critical instructions past release
without explicit authority.

## Solo interpretation

A solo owner may write and review documentation in one workflow, using a
separate accuracy/link pass. Avoid ceremonial documents with no durable reader
or decision; retain the records needed to resume, operate, and audit safely.

## Overlay notes

Team, regulated, support, release, security, and data overlays may require named
owners, controlled publication, accessibility/localization, retained evidence,
or redaction. They do not turn document existence into proof that a control ran.

## Completion checklist

- [ ] Durable intent, decisions, APIs, operations, and status match actual state.
- [ ] Runbooks and generated documentation are current where triggered.
- [ ] Links, examples, Markdown quality, and sensitive content were checked.
- [ ] Any deferral is policy-valid, owned, and time-bounded.
