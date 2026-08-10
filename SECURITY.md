# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.9.0b1 | Yes (public beta)  |
| 0.3.x   | Yes                |
| 0.2.x   | Security fixes only |
| 0.1.x   | No                 |

`aegis-ai-governance==0.9.0b1` is the public beta released from `main`. Beta
users receive the same responsible-disclosure handling and response targets
documented below.

## Reporting a Vulnerability

If you discover a security vulnerability in AEGIS, please report it
responsibly.

**Do not open a public issue.**

Email: **<neal@nealsolves.com>**

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** within 48 hours
- **Assessment:** within 7 days
- **Fix or mitigation:** within 30 days for confirmed vulnerabilities

## Scope

AEGIS is a governance enforcement library. Security concerns include:

- Policy bypass or validation circumvention
- Audit artifact tampering or omission
- Determinism violations that could mask governance failures
- Exception handling that silently degrades enforcement

Storage-control or evidence-handling vulnerabilities may be reported through
this process, but host storage configuration remains outside the AEGIS runtime
boundary. For host-owned retention, object locking, checkpoint selection,
historical verification, backup, and recovery, see the
[Append-Only Evidence Operations Guide](docs/reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md).
That guide separates library-produced results from host retention, write
protection, and organizational assurance decisions.

## Disclosure

Confirmed vulnerabilities will be disclosed via GitHub Security Advisories
after a fix is available.
