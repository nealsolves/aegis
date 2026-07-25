# Project Initialization Workflow

## Entry criteria

- Use this workflow when `project.lifecycle` is `unconfigured`, when adopting the
  template into a repository, or when a configured project must re-establish its
  delivery boundary.
- Begin with remote actions, production actions, and autonomous risk exceptions
  prohibited. Initialization evidence does not itself grant authority.
- Read the repository, root kernel, constitution, four control files, schemas,
  and operating guide. Treat absent authoritative information as `unknown`.

## Artifacts

- Updated `.claude/project.yaml`, preserving the four-file control-plane shape.
- A recorded initialization change ID and validation/evaluation output.
- Repository evidence for every derived value and an explicit unresolved-items
  list for every value that remains `unknown`.
- No fabricated application, CI, release, deployment, or rollback mechanism.

The initialization record accounts for every leaf field:

| Section | Exact fields |
|---|---|
| Versions | `schema_version`, `control_plane_version`, `instruction_system.module_state` |
| Project | `project.name`, `project.repository`, `project.lifecycle` |
| Delivery | `delivery.base_profile`, `delivery.overlays`, `delivery.owner`, `delivery.escalation_owner` |
| Spec Kit | `spec_kit.enabled`, `spec_kit.design_reference`, `spec_kit.tested_version`, `spec_kit.minimum_version`, `spec_kit.allow_equivalent_manual_gates` |
| Commands | `commands.install`, `commands.test`, `commands.lint`, `commands.typecheck`, `commands.build`, `commands.release` |
| Data | `data.classifications`, `data.regulated_data`, `data.production_data_in_nonproduction` |
| Environments | `environments.configured` |
| Remote | `remote_actions.enabled`, `remote_actions.repository`, `remote_actions.push_branch`, `remote_actions.open_pull_request`, `remote_actions.update_pull_request`, `remote_actions.merge_pull_request`, `remote_actions.create_release` |
| Production | `production_actions.enabled`, `production_actions.target`, `production_actions.deploy`, `production_actions.rollback`, `production_actions.deploy_command`, `production_actions.rollback_command` |
| Financial | `financial_limits.currency`, `financial_limits.autonomous_spend` |
| Obligations | `external_obligations` |

## Gates

- Every `project.yaml` field is collected or derived from strong repository or
  owner evidence: schema and control-plane version; instruction module state;
  project identity, repository target, and project lifecycle; base profile,
  overlays, owner, and escalation owner; Spec Kit compatibility; commands;
  data posture; environments; remote/production authority; financial limits;
  and external obligations.
- All four control files and all four schemas validate together.
- Project lifecycle cannot become `configured` while a permission-relevant
  value is unknown, contradictory, or unsupported.
- The configured profile must pass before push, merge, release, deployment, or
  autonomous risk exceptions can become eligible. Authority evaluation remains
  necessary after initialization.

## Ordered steps

1. Assign a stable initialization change ID and snapshot the current four
   control files. Preserve explicit `unknown` values and reject unsupported keys
   through schema validation; an unknown key is not an extensibility mechanism.
2. Record project identity (`project.name`), repository target
   (`project.repository` and `remote_actions.repository`), and intended project
   lifecycle. Verify that repository identifiers refer to the same target.
3. Select exactly one base profile—solo, team, or prototype—and any additive
   overlays such as the regulated overlay. Record delivery owner and escalation
   owner; never invent either identity.
4. Verify Spec Kit compatibility: enabled status, design reference, tested
   version, minimum version, and whether equivalent manual gates are allowed.
   A design reference is not proof of compatibility.
5. Derive the install, test, lint, typecheck, build, and release commands from
   executable repository configuration. Use `not_applicable` with evidence when
   a command genuinely does not exist; preserve `unknown` only while unresolved,
   and do not create a plausible command merely to pass initialization. An
   action that needs a `not_applicable` command remains prohibited.
6. Record data classifications, whether regulated data is present, and the
   prohibition or explicit policy for production data in non-production.
7. Enumerate allowed environments. For each production target, identify the
   actual deployment mechanism and rollback mechanism; if these mechanisms do
   not exist, keep production permissions disabled.
8. Set remote-action permissions individually: enablement, branch push, pull
   request creation/update/merge, and release creation. Then set production
   permissions individually: enablement, target, deploy, rollback, and concrete
   deploy and rollback commands.
9. Record currency and autonomous financial limits. Zero is the safe default;
   an unknown or unbounded financial commitment cannot be autonomous.
10. Record external obligations, including legal, contractual, regulatory,
    security, privacy, residency, retention, and segregation requirements. Map
    required control overlays without claiming certification.
11. Preserve unknown values and list the evidence needed to resolve them. Do
    not weaken a safe default to make the profile appear complete.
12. Validate the control plane, evaluate an initialization context, and review
    the before/after permissions. Set `project.lifecycle: configured` only when
    the profile is valid; otherwise remain unconfigured and record the block.

## Evidence

- Initialization ID, repository/base commit, source reference for every derived
  field, unresolved unknowns, and the final policy/context/change hashes.
- Before/after values for every remote-action permission, production permission,
  autonomous spend limit, environment, data classification, and overlay.
- Exact output from `policy-engine.py validate` and the evaluated authority for
  any action proposed after initialization.

## Exit criteria

- Every configured project command is concrete or evidenced as
  `not_applicable`; enabled Spec Kit versions and enabled production mechanisms
  are concrete. Any remaining authoritative `unknown` keeps the lifecycle
  unconfigured.
- A configured lifecycle is schema-valid and contains no unresolved value that
  could broaden authority; otherwise the repository safely remains unconfigured.
- Remote or production actions are still disabled unless their exact mechanisms,
  targets, bounds, and permissions were explicitly configured and authorized.

## Solo mode

A solo owner may supply all project and operational facts and hold all base
profile roles. Automated validation, evidence, scoped authority, and explicit
unknowns remain mandatory; one person owning the repository does not turn an
unconfigured target into a production-capable target.

## Stop/escalation conditions

- Stop in `BLOCKED_REQUIREMENT` for materially different project identity,
  data-use, environment, or business choices that repository evidence cannot
  resolve.
- Stop in `BLOCKED_POLICY` if requested permissions conflict with an external
  obligation, regulated overlay, constitution, or prohibition.
- Stop in `BLOCKED_TECHNICAL` if validation or repository fact extraction fails.
- Emit a bounded escalation packet for irreducible authority, including a new
  sensitive data class, nonzero spend limit without an authorized owner, or a
  production/remote permission whose consequences are not safely determined.
