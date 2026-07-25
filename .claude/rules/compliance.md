# Compliance Rules

## Purpose

Translate declared external obligations into framework-neutral, profile-driven,
testable controls and retained evidence without making unsupported assurances.

## Applicability

Applies only when `project.yaml`, an external obligation, or a regulated overlay
declares a control profile. Example frameworks such as SOC 2, ISO 27001, HIPAA,
or PCI DSS do not activate themselves merely because they are mentioned.

## Required inputs

- Declared control profiles, authoritative requirement text, applicability and
  scope, systems/data/regions, responsible owners, and required retention.
- Current implementation, tests, policies, exceptions, external authority, and
  revalidation dates.

## Mandatory controls

- Remain framework-neutral and profile-driven: implement the obligation actually
  declared for the project, not a generic checklist inferred from an industry.
- Create requirement mapping from each applicable obligation to implementation,
  verification evidence, owners, status, and next revalidation.
- Collect evidence from actual execution or authoritative records. Record its
  source, scope, date, change/policy context, result, owner, access, and retention.
- Assign owners for each control and for remediation. A solo profile may combine
  operational roles only where external authority permits it.
- Manage exceptions and compensating controls explicitly: cite the requirement,
  authority, residual risk, scope, expiry, remediation, and proof that the
  compensation operates.
- Apply required evidence retention, access restriction, integrity, deletion,
  and regional handling. Do not retain sensitive payloads merely for convenience.
- Revalidate after material policy, implementation, environment, data, or
  obligation change and by the declared periodic date.
- Preserve external authority. Law, contract, auditor/regulator direction, and
  required segregation cannot be weakened by project or solo defaults.
- Treat SOC 2, ISO 27001, HIPAA, and PCI DSS only as examples requiring their
  own scoped interpretation by authorized owners. Template presence does not
  prove compliance, certification, audit readiness, or control operation.

## Evidence

Maintain the declared profile and scope, requirement mapping, implementation
references, test/operation evidence, owners, exception and compensating-control
records, retention policy, external authority references, and revalidation
status. Distinguish designed, implemented, operating, and independently assessed.

## Exceptions

Only the authority named by the applicable obligation can accept a deviation.
Unsupported regulatory exceptions are critical. An expired exception or failed
compensating control fails closed and must not be represented as compliant.

## Solo interpretation

A solo owner may operate mapped controls and retain evidence when external rules
allow role combination. Required segregation, legal acceptance, certification,
and auditor/regulator judgments remain irreducible authority decisions.

## Overlay notes

The regulated overlay may override solo allowances, prescribe approvers,
retention, tooling, evidence access, or separation. Security, privacy, ownership,
and release modules remain additive rather than replaced by a framework mapping.

## Completion checklist

- [ ] A declared profile and authoritative scope activate every mapped control.
- [ ] Requirements, implementation, evidence, owners, and status are traceable.
- [ ] Exceptions, compensation, retention, and revalidation are current.
- [ ] No template, checklist, or test result is presented as an unsupported
  compliance or certification claim.
