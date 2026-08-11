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

## Threat Assumptions

Policy content and every `extends` value are untrusted. A host may also receive
an untrusted entry reference, but it must then configure an explicit policy root;
the implicit direct-load mode treats selection of the entry reference itself as
a host-authorized act and constrains only that entry's inheritance graph.

The host is responsible for preventing concurrent untrusted mutation of the
configured policy root and its canonical ancestors while a load is in progress.
Canonical resolution followed by opening the canonical target closes traversal
and ordinary symlink escapes, but it is not an `openat`/directory-descriptor
sandbox against a writer racing directory replacement. Supporting hostile
concurrent filesystem mutation would require a separate descriptor-relative,
platform-specific design.

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

Relative entry references supplied to an explicit loader are root-relative,
not working-directory-relative. Absolute entry references remain supported but
must resolve inside the same root. Thus these two calls select the same file:

```python
loader = FilePolicyLoader("/app/project-policies")
load_policy("apps/reviewer.yaml", loader=loader)
load_policy("/app/project-policies/apps/reviewer.yaml", loader=loader)
```

An explicit loader never interprets `"project-policies/apps/reviewer.yaml"`
relative to the process working directory. This gives the loader one stable
namespace regardless of later `chdir()` calls.

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
    "apps/reviewer.yaml",
    loader=FilePolicyLoader("project-policies"),
)
```

This preserves ADR-0005's support for absolute entry paths without preserving
its old implication that an absolute `extends` target is trusted merely because
the caller supplied an absolute entry path.

The implicit form is intentionally not a host-configured allowlist. Passing an
entry reference to plain `load_policy()` authorizes that lexical parent for the
duration of the call. Applications that accept policy references from requests,
jobs, plugins, or other untrusted sources must use an explicit
`FilePolicyLoader`; they must not use the implicit form.

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

Because inheritance resolution precedes full-policy schema validation, the
loader validates the `extends` field before performing path arithmetic. When
the key is present, its value must be a non-empty string. Any other value raises
`PolicyValidationError(code="POLICY_SCHEMA_VALIDATION_ERROR")` with
`details["path"] == "$.extends"`; it must never surface `TypeError`, `OSError`,
or another untyped exception from `pathlib`. Both packaged and repository schema
copies add `minLength: 1` so standalone schema validation matches runtime.

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

`load_resolve_compile_policy()` also gains an optional keyword-only `loader`
argument. A caller-supplied `parsed_policy` is accepted only after the same
loader has resolved and contained its source path; diagnostics may reuse parsed
content but cannot use that optimization to bypass entry containment.

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

Malformed `extends` declarations use `POLICY_SCHEMA_VALIDATION_ERROR`, not the
containment reason code. Path-resolution failures such as a symlink loop are
normalized to `PolicyLoadError(code="POLICY_LOAD_ERROR")` without exposing the
candidate path.

## Cache Boundary

The file-backed `PolicyCache` key includes:

- the canonical authority root;
- the canonical entry policy path; and
- the existing entry-file modification time.

The authority root is part of cache identity even when two requests name the
same entry file. A result admitted by `FilePolicyLoader("/broad")` must never be
returned for `FilePolicyLoader("/broad/narrow")` without reapplying the narrower
boundary.

Cache preflight uses the bound loader in this strict order: resolve the entry,
validate containment, validate its suffix/existence/type, then read its
modification time and consult the cache. Neither `getmtime()`, a cache hit, nor
any caller-level suffix, existence, type, modification-time, or content access
may occur before containment succeeds. Canonicalization itself necessarily
performs the filesystem lookups required to resolve existing symlinks; that is
the sole pre-containment filesystem operation. The implicit path creates its
lexical-parent-bound loader before executing the same preflight.

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

Diagnostic APIs gain optional root authority rather than pre-reading a target:

- `lint_policy(..., policy_root=None)` and `lint_target(..., policy_root=None)`
  create one bound file loader and pass it through the compiler boundary;
- `_lint_policy()`, `_validate_policy()`, and
  `load_resolve_compile_policy()` accept and propagate that loader;
- `aegis policy lint`, `aegis policy validate`, and file-policy forms of
  `aegis workflow lint` accept `--policy-root ROOT`; and
- containment runs before CLI existence checks or `Path.read_text()` calls.

CLI target arguments follow the same namespace rule as the loader. With an
explicit root, relative targets are root-relative:

```console
aegis policy validate --policy-root policies apps/reviewer.yaml
```

This validates `policies/apps/reviewer.yaml` regardless of the process working
directory. Absolute CLI targets are accepted only when canonically contained by
the supplied root.

For `aegis workflow lint`, `--policy-root` applies only to policy targets. An
explicit `--kind policy`, or a `.yaml`/`.yml` target under `--kind auto`, routes
to the shared loader before `detect_target_kind()` performs existence, type, or
content inspection. Supplying `--policy-root` with an explicitly non-policy
kind is a CLI usage error rather than an ignored security option.

When `--policy-root` is omitted, each CLI target uses the same lexical-parent
default as direct loading. A CLI command with multiple targets creates a
separate implicit root per target; one target cannot widen another target's
graph.

Instance enforcement already accepts `policy_loader`. The sealed module-level
runtime adds an optional `policy_loader` parameter to
`configure_module_enforcement()`, and every module-level sync/async enforcement
path uses that configured loader. When omitted, module-level invocation
`policy_file` is a trusted host reference and receives the implicit
lexical-parent root. Hosts that accept an untrusted `policy_file` must configure
`FilePolicyLoader(policy_root)` before the module runtime is sealed.

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

`FilePolicyLoader()` is an exported beta API, so requiring `policy_root` is an
immediate breaking correction. There is no deprecation window: retaining an
unbound constructor would preserve ambiguous authority and make safe concurrent
first-use binding impossible. The release note and changelog must label the
change as security hardening and provide these migrations:

```python
# Before: working-directory-relative, unbounded file loader
loader = FilePolicyLoader()

# After: root-relative, fixed authority
loader = FilePolicyLoader("policies")
load_policy("child.yaml", loader=loader)
AEGIS(sink=sink, policy_loader=loader)
```

Plain `load_policy("policies/standalone.yaml")` remains source-compatible.
Public API snapshot tests are updated deliberately to require the constructor
argument, and distribution tests verify the packaged class, error code, and
schema copy.

## Test Strategy

Tests use real temporary files and observable loader behavior. The red phase
first demonstrates the current escape before production changes.

### Containment cases

- direct relative `extends` within the default entry-directory root succeeds;
- direct `../` escape is rejected;
- direct absolute `extends` outside the root is rejected;
- an absolute `extends` target inside an explicit root succeeds;
- `subdirectory/../base.yaml` that canonicalizes inside the root succeeds;
- an in-root `extends` symlink to an outside file is rejected;
- an in-root directory symlink resolving outside the root is rejected;
- an entry-file symlink to an outside file is rejected;
- an in-root symlink resolving to an in-root target succeeds;
- a symlink loop becomes a sanitized typed load failure;
- relative and absolute spellings of the same entry enforce the same root;
- relative references on an explicit loader resolve from its root after `chdir()`;
- a nonexistent outside target fails as containment, without probing details;
- an explicit broader root permits a legitimate multi-directory graph; and
- an absolute entry outside an explicit root is rejected before opening; and
- a relative `../entry.yaml` traversal outside an explicit root is rejected
  before opening.

### Graph cases

- multi-level inheritance retains the original root at every level;
- a transitive child cannot widen the root;
- valid in-root cycles still raise the existing typed cycle failure; and
- containment takes precedence when a target is both outside the root and
  otherwise cycle-like or missing.

### Entry-point and cache cases

- direct, async, cache, compiler, CLI/lint, and packaged public imports exercise
  the same default boundary;
- CLI `--policy-root` and diagnostic API roots admit the same legitimate
  multi-directory graph as runtime;
- lint and CLI containment occurs before their raw-read and existence paths;
- module-level enforcement uses its sealed configured file loader;
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

Malformed `extends` tests cover `None`, booleans, numbers, mappings, arrays, and
the empty string. Platform tests cover different-drive absolute paths on Windows
and skip only symlink creation when the test account lacks symlink privileges;
traversal and absolute-path coverage remains mandatory on every platform.

## Documentation

Implementation updates:

- `docs/USAGE.md` with explicit-root configuration and default-root behavior;
- `docs/INTEGRATION_GUIDE.md` with the policy-tree example's authority root;
- `docs/PUBLIC_INTEGRATION_CONTRACT.md` with the root, symlink, custom-loader,
  and error-code contract;
- `docs/reference/TROUBLESHOOTING.md` and workflow-doctor next-action guidance
  for `POLICY_PATH_OUTSIDE_ROOT`;
- `policies/policy_dsl_spec.md` with `extends` path containment semantics; and
- ADR-0005 with a compatibility note that absolute entry paths remain supported
  but do not authorize arbitrary inherited targets.

`CHANGELOG.md` records the security fix, the immediate constructor change, the
root-relative explicit-loader namespace, and the migration examples. Public API,
CLI contract, packaged-schema parity, and documentation-parity tests are updated
with the same wording.

## Security Review Focus

The adversarial review must verify:

- no recursive path can select a fresh or broader root;
- no check occurs only after YAML content has been opened;
- canonical paths, not lexical prefixes, drive containment;
- symlinks cannot change the authority boundary;
- cache hits cannot bypass a narrower root;
- public errors do not disclose filesystem paths; and
- custom loaders cannot trigger implicit filesystem inheritance.

The review also verifies that entry references are host-controlled whenever the
implicit root is used and that configured policy directories cannot be mutated
by untrusted principals during a load. Environments requiring hostile-writer
race resistance must not claim that guarantee from this implementation.

## Reversal

The change is reversible by reverting the loader, error, cache, tests, and docs
as one scoped commit series. No stored-data migration is involved. Schema
validation does become stricter: an explicit empty `extends` value is rejected
by the new `minLength: 1` constraint. Reversal would restore the reported
vulnerability, so a forward fix is preferred for post-implementation defects
unless rollback is required to restore basic policy loading while a corrected
containment implementation is prepared.
