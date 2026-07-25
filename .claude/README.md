# Modular Delivery Operating Guide

This directory contains the reusable instruction system that supports the root
kernel. The template is intentionally local and small: Markdown explains the
controls, YAML declares decisions, JSON Schema validates records, and one Python
CLI evaluates policy. It is not a hosted governance service.

## Three Layers

1. **Behavioral kernel** — [`../CLAUDE.md`](../CLAUDE.md) defines authority,
   startup, invariants, lifecycle, routing, escalation, and done.
2. **Guidance** — `rules/`, `workflows/`, `profiles/`, and `templates/` hold
   focused human-readable controls and reusable evidence forms. Evaluation
   activates them additively; a routed module is mandatory.
3. **Control plane** — `project.yaml`, `routing.yaml`, `policy.yaml`, and
   `lifecycle.yaml` are validated data consumed by `scripts/policy-engine.py`.

The Markdown layer explains why and how. The YAML layer says what is configured.
The policy engine computes the consequential decisions; an agent supplies typed,
evidence-backed observations rather than selecting its preferred outcome.

## Startup Sequence

1. Read the root kernel, constitution, and four control files.
2. Determine the workflow family from intent.
3. Resolve a feature only if that workflow needs one; otherwise create a stable
   maintenance/change ID.
4. Extract observable facts with provenance and the current change hash.
5. Validate the configuration and context, then evaluate policy.
6. Load always-on rules plus the returned workflow, profile/overlays, and routes.
7. Record the decision and its policy, context, and change hashes.
8. Ask the engine to authorize each lifecycle transition.

If validation or runtime dependencies fail, record `BLOCKED_TECHNICAL`. Do not
replace the engine with free-form classification. While `module_state` is
`bootstrapping`, missing guidance is permitted only by the approved installation
plan; completed installations must contain every configured module path.

## Four-File Control Plane

| File | Responsibility |
|---|---|
| [`project.yaml`](project.yaml) | Identity, lifecycle, ownership, environments, data posture, project commands, overlays, financial limits, and remote/production permissions. |
| [`routing.yaml`](routing.yaml) | Observable fact catalog, deterministic base/overlay profile paths, workflow selection, fact and action classifications, always-on rules, and additive module routes. |
| [`policy.yaml`](policy.yaml) | Simple risk tiers, deny-overrides authority, clarifications, exceptions, reviews, and bounded resource limits. |
| [`lifecycle.yaml`](lifecycle.yaml) | Normal and exceptional states, allowed transitions, evidence prerequisites, recoveries, and terminal paths. |

Version 1 deliberately keeps these concerns in four files so a solo owner can
read and tune the full control plane. Unknown project values remain explicit;
they are never filled by inference merely to unlock authority.

## Schemas and Policy Engine

The four JSON Schema Draft 2020-12 contracts are:

- [`schemas/project.schema.json`](schemas/project.schema.json)
- [`schemas/routing.schema.json`](schemas/routing.schema.json)
- [`schemas/policy.schema.json`](schemas/policy.schema.json)
- [`schemas/context.schema.json`](schemas/context.schema.json)

`policy.schema.json` also exposes the lifecycle contract. The context schema
contains reusable definitions for facts, evidence, exceptions, escalation
packets, findings, and responses.

The public CLI requires Python 3.11+ with the bounded PyYAML and `jsonschema`
dependencies installed. Prefer the project virtual environment shown below;
`python3` is the supported fallback when it resolves to a compatible environment.
The CLI has exactly four operations:

```bash
.venv/bin/python scripts/policy-engine.py validate --root . [--context PATH]
.venv/bin/python scripts/policy-engine.py evaluate --root . --context PATH [--output PATH]
.venv/bin/python scripts/policy-engine.py transition --root . --context PATH \
  --decision PATH --to STATE [--output PATH]
.venv/bin/python scripts/policy-engine.py respond --root . --context PATH \
  --response PATH [--output PATH]
```

- `policy-engine.py validate` checks schemas, cross-references, lifecycle
  reachability, module paths when installation is complete, and an optional
  context.
- `policy-engine.py evaluate` derives fact- and action-based classifications, risk, routed modules,
  clarifications, exceptions, resource status, authority, and three hashes.
- `policy-engine.py transition` checks a declared state edge, active path,
  evidence, current authority, and hash freshness without mutating source files.
- `policy-engine.py respond` validates a bounded human response, incorporates
  its declared conditions, and reevaluates the blocked decision. Generic
  authority approvals are single-use records scoped to the packet's exact
  action, rules, and three hashes; they cannot override `prohibited`.

PyYAML and `jsonschema` versions are bounded in
[`../requirements-policy.txt`](../requirements-policy.txt). A missing dependency
is a technical block, not permission to improvise policy behavior. Direct CLI
dependency or runtime resource failures emit a single JSON
`BLOCKED_TECHNICAL` record and exit status `3`, without a traceback.

## Project Initialization

The reusable repository starts with `project.lifecycle: unconfigured`, a solo
base profile, no configured environment, unknown application commands, and both
remote and production action switches off. This is **solo-capable**, not
production-enabled.

The project-initialization workflow must derive or collect project identity,
repository, lifecycle, environments, install/test/lint/typecheck/build/release
commands, data classes, authority, financial limits, overlays, deployment and
rollback mechanisms, Spec Kit version, escalation owner, and external
obligations. Preserve any unresolved value as `unknown`. Use the exact
`not_applicable` sentinel, with evidence, only for a repository command or
disabled Spec Kit version that genuinely does not apply; it never authorizes an
action that relies on that command.

Changing lifecycle to `configured` is accepted only after permission-bearing
identity, ownership, repository targets, and data posture are concrete. Parent
authority switches must agree with child permissions. All command entries and
Spec Kit compatibility values must be resolved before configuration. Production
authority also requires a configured target environment, rollback permission,
and concrete `production_actions.deploy_command` and
`production_actions.rollback_command` mechanisms. Incomplete configured
profiles fail validation and evaluation rather than inheriting an autonomous
action-matrix result.

Until initialization validates, policy prohibits push, merge, release,
deployment, and autonomous risk exceptions. Local specification, implementation,
testing, and review remain available according to policy.

## Feature and Maintenance Context

Feature work stores `instruction-context.yaml` below the active
`specs/<NNN>-<feature>/` directory and summarizes the decision in its plan.
Feature selection comes from explicit intent and approved artifacts after the
workflow family is known—not from `implementation_status.md` alone.

Documentation, hygiene, dependency work, repository setup, and other
reduced-overhead work can use `evidence/maintenance/<change-id>/`. A maintenance
record still carries typed facts, risk, authority, hashes, validation, review,
and rollback evidence; it simply uses the shorter declared lifecycle path.

This template ships reusable forms only. It does not create a fake active
feature, maintenance record, or production evidence bundle.

## Delivery Boundary

### MVP

The practical core includes the compact kernel, modular guidance, four YAML
files, four schemas, the four-command local engine, deterministic fact routing,
simple four-tier risk, deny-overrides authority, lifecycle checks, clarification
triage, bounded review/repair, basic escalation responses, safe defaults, and
three-hash freshness.

### Phase 2

After several real-project exercises justify it, operational autonomy may add
execution for PR creation/merge, releases, and deployments; targeted
idempotency; production-readiness integration; stronger human identity checks;
table-based trusted-policy weakening detection; and targeted invalidation.

### Deferred

Advanced assurance remains out of scope until observed failures justify it:
granular dependency invalidation, per-record schemas, dimensional or weighted
risk, broad corroboration policy, full external-action reconciliation,
universal multi-agent orchestration, general semantic policy comparison, and
policy-version migration.

The MVP therefore evaluates release and deployment authority but provides no
vendor-specific adapter, remote-action orchestrator, daemon, database, message
queue, plugin framework, or custom policy language.

## Spec Kit Reference

Spec Kit v0.13.0 is the approved design reference for the specification
lifecycle; see [GitHub Spec Kit](https://github.com/github/spec-kit). This is not a claim that
v0.13.0 is the latest release or that the uninstantiated template has completed
compatibility testing. `project.yaml` records tested and minimum versions as
`unknown` until initialization verifies them. When Spec Kit is disabled, both
may be explicitly `not_applicable`; enabled compatibility requires concrete
tested and minimum versions. Equivalent manual artifacts and gates are allowed
when an installed integration lacks a referenced command.

## Legacy Manifest Mapping

The MVP consolidates the earlier conceptual file layout as follows:

```text
instructions.yaml + classification-rules.yaml -> routing.yaml
project-profile.yaml                           -> project.yaml
authority/risk/exception/resource policy       -> policy.yaml
evidence requirements + state transitions      -> lifecycle.yaml + context schema
```

This is a deliberate reduction in configuration surface, not a compatibility
promise for external tooling that expects the superseded filenames.
