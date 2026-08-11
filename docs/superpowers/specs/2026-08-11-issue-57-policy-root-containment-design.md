# Issue #57 Policy Root Containment Design

**Status:** Approved for implementation planning  
**Date:** 2026-08-11  
**Issue:** [#57 — security: policy extends can escape the configured policy root](https://github.com/nealsolves/aegis/issues/57)

## Problem

File-backed policy composition resolves each `extends` value relative to the
current policy and recursively calls `load_policy()` with the resolved path.
The recursive call does not retain an authority root. A child policy can
therefore load a readable YAML file outside the host's intended policy
directory through `..`, an absolute path, or a symlink.

Cycle detection does not provide containment. It only detects a canonical path
that has already been visited, and it currently runs after the escaping target
has been derived without an authority check.

## Goals

- Give every file-backed load graph one canonical, immutable policy root.
- Resolve and contain the entry policy and every transitive `extends` target
  before opening the target.
- Reject traversal, absolute-path, and symlink escapes with one stable typed
  error contract.
- Preserve source-relative inheritance, composition checks, schema validation,
  date validation, and valid in-root cycle detection.
- Keep direct `load_policy()` convenient while requiring explicit authority for
  inheritance spanning more than the entry policy's directory.
- Prevent cached results loaded under a broad root from satisfying a narrower
  root boundary.
- Preserve custom loaders' existing no-`extends` contract.

## Non-goals

- Supporting `extends` for database, API, or other custom loaders.
- Changing policy merge or restriction semantics.
- Adding a new environment variable or global policy-root setting.
- Solving dependency-aware cache invalidation for changed ancestor files.
- Claiming protection against an attacker who can race and replace filesystem
  components after canonical resolution. The contract is canonical containment
  before target existence/type checks and opening, matching issue #57.

## Authority Root Contract

### Explicit file loader

`FilePolicyLoader` accepts a required `str | Path` `policy_root` constructor
argument. The constructor resolves the root once and retains that canonical
`Path` for the loader's lifetime. A missing or non-directory root raises
`PolicyLoadError(code="POLICY_LOAD_ERROR")` before any policy is loaded. A
read-only `policy_root` property exposes the canonical root for cache identity
and diagnostics that already possess loader authority:

```python
from aegis import AEGIS, FilePolicyLoader, JsonFileAuditSink

engine = AEGIS(
    sink=JsonFileAuditSink("audit.jsonl"),
    policy_loader=FilePolicyLoader("project-policies"),
)
```

Every entry policy and inherited target loaded through that instance must
resolve within the retained root. The root cannot change during recursion.
Calling `FilePolicyLoader.load()` directly continues to return one raw mapping;
callers use `load_policy(..., loader=file_loader)` when they need schema
validation and composition.

### Direct `load_policy()`

When no loader is supplied, `load_policy(policy_file)` creates a bound
`FilePolicyLoader` for that invocation. Its root is the resolved lexical parent
of the entry reference, calculated before resolving the final entry component.

This rule is identical for relative and absolute spellings. For example,
`policies/child.yaml` and `/project/policies/child.yaml` both receive
`/project/policies` as their default authority root.

Resolving the lexical parent separately is security-significant. If
`policies/child.yaml` is a symlink to `/outside/child.yaml`, the configured root
remains `/project/policies`; resolving the entry target to `/outside/child.yaml`
then fails containment. The symlink does not redefine its own authority root.

An application that deliberately keeps parents above or beside the entry
policy must declare the broader boundary explicitly:

```python
policy = load_policy(
    "project-policies/apps/reviewer.yaml",
    loader=FilePolicyLoader("project-policies"),
)
```

This preserves ADR-0005's support for absolute entry paths without preserving
its old implication that an absolute `extends` target is trusted merely because
the caller supplied an absolute entry path.

### Symlink behavior

Both the configured root and candidate paths are fully resolved. Containment is
evaluated between canonical paths. Consequently:

- a symlink whose resolved target stays within the canonical root is allowed;
- an entry-file symlink resolving outside the root is rejected;
- an `extends` symlink resolving outside the root is rejected; and
- an explicitly configured root that is itself a symlink names its resolved
  target directory as the authority root.

## Loader Architecture

Path handling is split into two responsibilities:

1. Resolve a reference to a canonical candidate without opening it.
2. Verify that the canonical candidate is relative to the loader's canonical
   root, then perform extension, existence, and regular-file checks before YAML
   parsing.

The file loader owns both the root and the containment check. Callers cannot
perform a check and then accidentally invoke an unbound loader.

`_resolve_extends()` resolves a source-relative parent through the same bound
file loader used for the entry policy. Its order is:

1. Canonicalize the target.
2. Validate containment.
3. Check the canonical target against the visited set.
4. Open and parse the target.
5. Resolve the target's inheritance with the same loader and visited set.
6. Preserve existing composition compilation and restriction checks.

No recursive call may select the module default loader or derive a fresh root.

`load_policy_async()` gains an optional keyword-only `loader` argument and
passes it to the synchronous boundary in its worker thread. This makes an
explicit multi-directory root available without weakening the async default.

Custom `PolicyLoaderBase` implementations remain opaque-source loaders. A raw
policy returned by a non-file loader that declares `extends` continues to fail
with `PolicyLoadError`; AEGIS does not fall back to the filesystem.

## Failure Contract

A containment failure raises `PolicyLoadError` with:

```python
exc.code == "POLICY_PATH_OUTSIDE_ROOT"
str(exc) == "Policy path is outside the configured policy root"
```

`PolicyLoadError` gains an optional `code` parameter whose default remains
`POLICY_LOAD_ERROR`, preserving all other loading failures.

Containment-error details must not contain the configured root, candidate path,
entry path, `extends` value, or visited chain. This prevents an untrusted policy
from turning path probing into filesystem disclosure through CLI, lint,
enforcement, or audit-facing error surfaces.

Suffix, missing-file, non-file, YAML, schema, composition, and cycle failures
retain their existing codes and messages unless a containment violation takes
precedence. An outside nonexistent target therefore returns
`POLICY_PATH_OUTSIDE_ROOT`, not a missing-file result.

## Cache Boundary

The file-backed `PolicyCache` key includes:

- the canonical authority root;
- the canonical entry policy path; and
- the existing entry-file modification time.

The authority root is part of cache identity even when two requests name the
same entry file. A result admitted by `FilePolicyLoader("/broad")` must never be
returned for `FilePolicyLoader("/broad/narrow")` without reapplying the narrower
boundary.

Custom-loader caching remains unchanged by this issue.

## Public Entry Points

All file-backed entry paths converge on the same boundary:

- `load_policy()`;
- `load_policy_async()`;
- `load_resolve_compile_policy()`;
- `PolicyCache.get_or_load()`;
- module-level enforcement;
- `AEGIS` instance enforcement and sessions; and
- policy lint/validate and workflow diagnostics that use the shared loader.

Entry points that do not accept a loader use the direct-load lexical-parent
default. Entry points already accepting `PolicyLoaderBase` preserve and
propagate an explicitly supplied `FilePolicyLoader`. The async entry point is
extended additively to accept the same loader authority.

## Alternatives Rejected

### Working directory as the implicit root

Using the working directory for relative entries preserves more existing test
fixtures, but it often grants authority over an entire application repository
when the host intended only `policies/`. It also gives relative and absolute
spellings of the same file different roots. This does not form a stable trust
boundary.

### Resolved entry target's parent as the implicit root

Deriving the root after fully resolving the entry makes ordinary paths
consistent, but an entry-file symlink can redirect outside the lexical policy
directory and then nominate the outside directory as its own root. The lexical
parent must be fixed before the final entry component is resolved.

### Require explicit root on every public load

Requiring a root argument for `load_policy()` would be simple and strict, but it
would unnecessarily break standalone policy loads and ADR-0005 absolute-entry
usage. The lexical-parent default is narrow, deterministic, and reversible;
only broader policy graphs require explicit authority.

## Compatibility

Unaffected behavior:

- standalone policies continue to load through relative or absolute paths;
- a child extending a file in its own directory continues to work;
- valid composition and valid in-root cycles retain their existing semantics;
- custom loaders still load standalone policy mappings; and
- all non-containment `PolicyLoadError` instances keep
  `code="POLICY_LOAD_ERROR"`.

Intentional hardening:

- a direct load cannot inherit from a parent or sibling outside the entry
  directory;
- callers with a multi-directory policy tree must pass an explicit
  `FilePolicyLoader(policy_root)`; and
- constructing `FilePolicyLoader()` without a root is no longer valid.

Repository fixtures that intentionally span directories must use an explicit
loader or be reorganized so the fixture structure expresses the intended root.
This is a bounded public-contract change justified by the security boundary.

## Test Strategy

Tests use real temporary files and observable loader behavior. The red phase
first demonstrates the current escape before production changes.

### Containment cases

- direct relative `extends` within the default entry-directory root succeeds;
- direct `../` escape is rejected;
- direct absolute `extends` outside the root is rejected;
- an in-root `extends` symlink to an outside file is rejected;
- an entry-file symlink to an outside file is rejected;
- an in-root symlink resolving to an in-root target succeeds;
- relative and absolute spellings of the same entry enforce the same root;
- a nonexistent outside target fails as containment, without probing details;
- an explicit broader root permits a legitimate multi-directory graph; and
- an entry outside an explicit root is rejected before opening.

### Graph cases

- multi-level inheritance retains the original root at every level;
- a transitive child cannot widen the root;
- valid in-root cycles still raise the existing typed cycle failure; and
- containment takes precedence when a target is both outside the root and
  otherwise cycle-like or missing.

### Entry-point and cache cases

- direct, async, cache, compiler, CLI/lint, and packaged public imports exercise
  the same default boundary;
- AEGIS with an explicit `FilePolicyLoader` preserves that root through cache
  and session loads;
- cache entries are isolated by root; and
- custom loaders still reject `extends` without filesystem access.

### Error-surface cases

- the exception is a `PolicyLoadError`;
- `exc.code` is exactly `POLICY_PATH_OUTSIDE_ROOT`;
- its message is stable; and
- neither the message nor details expose outside, root, or unrelated absolute
  paths.

## Documentation

Implementation updates:

- `docs/USAGE.md` with explicit-root configuration and default-root behavior;
- `docs/INTEGRATION_GUIDE.md` with the policy-tree example's authority root;
- `docs/PUBLIC_INTEGRATION_CONTRACT.md` with the root, symlink, custom-loader,
  and error-code contract;
- `policies/policy_dsl_spec.md` with `extends` path containment semantics; and
- ADR-0005 with a compatibility note that absolute entry paths remain supported
  but do not authorize arbitrary inherited targets.

## Security Review Focus

The adversarial review must verify:

- no recursive path can select a fresh or broader root;
- no check occurs only after YAML content has been opened;
- canonical paths, not lexical prefixes, drive containment;
- symlinks cannot change the authority boundary;
- cache hits cannot bypass a narrower root;
- public errors do not disclose filesystem paths; and
- custom loaders cannot trigger implicit filesystem inheritance.

## Reversal

The change is reversible by reverting the loader, error, cache, tests, and docs
as one scoped commit series. No schema or stored-data migration is involved.
Reversal would restore the reported vulnerability, so a forward fix is preferred
for post-implementation defects unless rollback is required to restore basic
policy loading while a corrected containment implementation is prepared.
