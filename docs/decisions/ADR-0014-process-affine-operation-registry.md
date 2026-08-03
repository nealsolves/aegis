# ADR-0014: Process-Affine Operation Registry

Date: 2026-08-03
Status: Accepted
Owners: Neal
Supersedes: ADR-0009 sections 4-7 where they describe portable authorization
state, mutable consumption flags, undefined concurrency, or pickle-preserved
authorization.

## Context

Split enforcement must bind Phase B to the exact authority accepted in Phase A.
Embedding that authority in a public PreCallResult made it portable,
inspectable, and dependent on check-then-mark replay state. Copies could carry
authorization beyond the issuing runtime, and concurrent consumers did not
have one atomic ownership boundary.

## Decision

Every AEGIS runtime owns an OperationRegistry. Module-level functions share one
private module registry; each AEGIS instance owns a distinct registry. Phase A
stores compiled policy, invocation evidence, phase-A metadata, and Phase-B gates
in a private OperationRecord, then returns an opaque PreCallResult containing
identity and correlation fields only.

Phase B validates process and issuer affinity, atomically pops the operation
record, and only then validates caller-controlled output. Every authenticated
consumption attempt burns the operation, whether Phase B passes or fails.

Handles obey these rules:

- obtain a fresh handle at the start of every operation;
- use it only with the runtime instance and process that issued it;
- never renew or transfer it;
- copying, deep-copying, or pickling copies identity only and does not create
  another authorization;
- spawned and forked child processes cannot consume a parent handle;
- sessions cancel outstanding operations on discard, cancel, exceptional exit,
  and finalization.

There is no token expiry or renewal mechanism. Liveness is represented solely
by presence in the owning registry.

## Consequences

Atomic pop-and-own makes concurrent consumption deterministic: exactly one
consumer can obtain the record. Public handles contain no compiled policy,
invocation snapshot, gate collection, signer, sink, HMAC, or mutable consumed
flag. A process restart or instance change invalidates outstanding handles, so
applications must start a new operation and rerun Phase A.

Pickle remains supported as identity serialization inside the same live process
and issuer. It is not an authorization portability contract.

## Validation

- concurrent registry tests prove exactly one consumer wins;
- cross-instance tests prove issuer isolation;
- spawn and fork tests prove process isolation;
- lifecycle tests prove session cleanup;
- architecture fitness tests reject legacy portable-token symbols, public
  authorization fields, and non-atomic consumption.
