# ADR-0005: Absolute policy entries under one canonical root

Date: 2026-02-17

Updated: 2026-08-11

Status: Accepted

Owners: Neal

## Context

Consumer projects need absolute entry paths, but an absolute entry must not
silently grant its policy graph access to unrelated filesystem locations.
Relative entries also need a deterministic authority independent of later
working-directory changes.

## Decision

Absolute entry paths remain supported, but they do not authorize inherited targets outside the entry's canonical policy root. `FilePolicyLoader` now requires an explicit root; relative references passed to that loader are root-relative. Containment failures return `POLICY_PATH_OUTSIDE_ROOT` without filesystem paths. Custom retry enforcement callables must receive the same `policy_loader` authority used for enforcement.

For an implicit call such as `load_policy("policies/entry.yaml")`, the lexical
parent (`policies`) is captured as the root. That root governs the entry and
every transitive `extends`. An explicit `FilePolicyLoader("policies")` permits a
deliberate multi-directory tree only while canonical entries and symlink
targets remain inside that root. Custom loaders cannot use `extends`.

Diagnostics select the same namespace with `--policy-root ROOT` on policy
lint/validate and workflow lint/doctor. Error text and details do not disclose
the root, entry, inherited target, schema path, or canonical filesystem path.

## Migration

Before, callers could construct an unbound loader and let a custom retry
callable rediscover policy authority:

```python
loader = FilePolicyLoader()
audit = with_retry(invocation, enforcement_fn=custom_enforce)
```

After, bind and reuse one explicit authority:

```python
loader = FilePolicyLoader("policies")
policy = load_policy("child.yaml", loader=loader)
engine = AEGIS(sink=sink, policy_loader=loader)
audit = with_retry(
    invocation,
    enforcement_fn=custom_enforce,
    policy_loader=loader,
)
```

This is an immediate beta security correction. Relative references supplied to
an explicit loader are now root-relative, and path-bearing load-error details
have been removed.

## Consequences

- Absolute consumer-owned entry paths remain supported.
- Implicit loads use the entry's lexical parent as their immutable root.
- Explicit loaders, AEGIS instances, module enforcement, caches, async calls,
  diagnostics, sessions, and retry attempts retain one authority per operation.
- Canonical traversal and symlink escapes fail before suffix, existence, type,
  mtime, cache, content, or diagnostic inspection.
- Hostile concurrent mutation of filesystem components remains outside the
  guarantee. Descriptor-relative race resistance against a concurrent writer
  is a non-goal.

## Validation

Traversal, absolute escape, symlink escape, cache isolation, async identity,
nested/concurrent enforcement, diagnostics, CLI, retry, schema parity, and
path-free error tests enforce this decision.
