# Compliance Mapping Claims and Terminology

The AEGIS compliance catalog is a non-authoritative map of bounded technical
evidence contributions. It does not decide whether a requirement applies,
whether a control is suitably designed or operating effectively, whether the
available evidence is sufficient, or whether an organization passes an audit
or obtains a legal or certification outcome. Those decisions remain with the
adopter and its chosen reviewers and require evidence from the operating
environment; professional review is not a catalog-publication prerequisite.

The catalog maps the current AEGIS source commit named on each page. It is not
a mapping of the published `aegis-ai-governance==0.9.0b1` wheel. The
[release matrix](RELEASE_MATRIX.md) distinguishes current-source capabilities
from the published beta.

## Evidence contribution states

Every mapping uses one exact AEGIS evidence contribution state:

| State | Meaning | Required boundary |
| --- | --- | --- |
| `supported_evidence` | AEGIS directly produces concrete technical evidence relevant to the reviewed interpretation. | This does not mean the requirement is satisfied. The row identifies limitations and host controls. |
| `partial_evidence` | AEGIS produces indirect, incomplete, or condition-dependent evidence relevant to part of the reviewed interpretation. | The row states the unsupported portion, limitations, and host controls. |
| `external_control` | The reviewed interpretation identifies a host, provider, or organizational responsibility for which AEGIS supplies no relevant evidence. | The evidence list is empty and the responsible external owner and control are named. |
| `not_addressed` | The identifier is in the declared scope, but the catalog identifies neither an AEGIS evidence contribution nor a specific implemented external-control mapping. | The evidence list is empty and the row records the gap and review note. |

Rendered pages label this field “AEGIS evidence contribution.” They do not
shorten a state to language that could imply that a control is covered,
passed, compliant, or satisfied.

## Evidence and conclusions are different things

Technical evidence is an observable policy value, artifact field, verifier
result, test behavior, fixture output, or maintained command contract. A
mapping identifies what that evidence demonstrates and the exact AEGIS source
baseline where it exists.

Control design includes the surrounding people, process, infrastructure, and
configuration that make a control suitable for its intended purpose.
Operating effectiveness is evidence that the complete control actually
operated over a relevant period. Qualified external reviewers retain ownership
of applicability, evidence sufficiency, audit opinions, certification
decisions, and legal conclusions.

## Assurance ownership boundaries

AEGIS checksums and bounded verifier results can contribute evidence about the
integrity of supplied records. A host still owns trusted acquisition and
preservation of the expected record.

AEGIS exposes provider-neutral signing, verification, and anchor outcomes. A
host still owns key identity, credentials, provider availability, rotation,
revocation, and trust policy.

AEGIS can compare supplied workflow evidence with an explicitly supplied
trusted checkpoint. A host still owns checkpoint cadence, protected storage,
authoritative selection, and rollback defense.

AEGIS does not provide built-in WORM or append-only storage. A host still owns
storage configuration, retention, legal hold, access control, monitoring,
backup, and recovery. Tenant isolation, IAM, transport security,
organizational processes, and model-risk decisions also remain host,
provider, or organizational responsibilities unless a row says that a
specific AEGIS artifact contributes bounded evidence.

## Allowed bounded statements

Maintained catalog prose may say that AEGIS records a named field, enforces a
specific policy boundary, emits a particular artifact, verifies supplied
evidence within documented limits, or exposes an explicit verification
outcome. Every positive statement identifies limitations and the surrounding
host responsibilities.

## Prohibited relationships

Prohibited relationships include connecting the product, its artifacts, or
its mappings to organizational certification, guaranteed compliance,
audit-readiness, legal sufficiency, legal applicability decisions, or
operating-effectiveness conclusions. Maintained copy must not imply
framework-owner endorsement. Framework logos, badges, and certification marks
are not used.

The catalog does not convert missing infrastructure, unavailable source
material, an overdue review, or absent human approval into a positive evidence
state. Publication fails closed instead.

## Review expectations

Framework scope reviewers verify identifier inventories and exclusions
against the exact pinned sources. Evidence mapping reviewers evaluate the
relevance and boundaries of repository references. Claims reviewers evaluate
public language and assurance separation.

ISO/IEC 42001 remains unpublished pending the lawful human-authored contribution
tracked in Issue #76; licensed standard text, excerpts, screenshots, and local
file paths are not committed or supplied to automated processing. Maintainer
verification is sufficient for the citation-only EU module. Qualified EU legal
or compliance review is an optional enhancement tracked in Issue #78. Local
catalog fields do not authenticate reviewer identity or credentials;
repository permissions, branch protection, and pull-request review provide the
repository approval record.
