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
and diagnostics that already possess loader authority. A relative constructor
argument is resolved against the working directory captured at construction;
later `chdir()` calls cannot alter it:

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

The direct-load algorithm is exact:

1. Capture the working directory once.
2. Form an absolute lexical entry: retain an absolute input as written, or join
   a relative input to that captured working directory without resolving the
   final component.
3. Resolve the absolute lexical entry's parent and construct the bound loader
   with that canonical directory.
4. Pass the absolute lexical entry, not the original relative spelling, to the
   bound loader for canonicalization and containment.

The fourth step prevents rebinding `policies/child.yaml` as
`<root>/policies/child.yaml` after `<root>` is already `/project/policies`.

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

File-backed loading has one private prepare boundary. It canonicalizes and
contains the reference, performs suffix/existence/type checks, opens and parses
the canonical file, and returns a private prepared-source object containing the
canonical source identity and a detached raw mapping. The object carries a
private authority token unique to the bound loader; every consumer rejects a
prepared source whose token does not match that loader. Composition,
compilation, lint, and doctor diagnostics consume that prepared source rather
than reopening or independently parsing a spelling.

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

`load_policy_async()` gains an optional keyword-only `loader` argument. When it
is omitted, the API captures the caller's working directory, forms the absolute
lexical entry, and constructs the implicit bound loader synchronously before it
returns the awaitable and before worker-thread dispatch. The worker receives
that absolute entry and exact loader instance. A `chdir()` after the API call
therefore cannot rebind a queued load. An explicit loader passes through
unchanged. The implementation is a synchronous awaitable factory with a private
async runner, rather than an `async def` whose body would bind only when first
awaited. Callers continue to use `await load_policy_async(...)`. This makes an
explicit multi-directory root available without weakening or delaying the async
default boundary.

`load_resolve_compile_policy()` also gains an optional keyword-only `loader`
argument. Its caller-supplied `parsed_policy` fast path is removed. The compiler
boundary delegates to one private `_prepare_resolve_compile_policy()`
orchestrator and returns only its compiled result. File-backed diagnostics call
that same orchestrator and receive both its loader-minted prepared source and
compiled result; no API accepts an arbitrary mapping or externally supplied
prepared source. Opaque custom loaders always execute their `load()` method and
cannot enter the file-backed prepared-source path.

The private orchestrator accepts the existing validation clock and passes it
through inheritance and date validation. Lint uses the normal clock; workflow
doctor supplies its injected `now` clock. One doctor invocation prepares the
policy once and passes the prepared and compiled views into internal lint and
advisory helpers, so invoking lint as a phase of doctor cannot reopen the source
or validate it against a different date.

Custom `PolicyLoaderBase` implementations remain opaque-source loaders. A raw
policy returned by a non-file loader that declares `extends` continues to fail
with `PolicyLoadError`; AEGIS does not fall back to the filesystem. For an
opaque custom loader, key presence takes precedence over the file loader's
early `extends` type validation: even a malformed value reports that inheritance
is unsupported by that loader and triggers no path operation.

## Failure Contract

A containment failure raises `PolicyLoadError` with:

```python
exc.code == "POLICY_PATH_OUTSIDE_ROOT"
str(exc) == "Policy path is outside the configured policy root"
```

`PolicyLoadError` gains an optional `code` parameter whose default remains
`POLICY_LOAD_ERROR`, preserving all other loading failures.

Every public failure reached while preparing or resolving a file-backed policy
graph follows one path-confidentiality rule. Its message, details, cause,
context, and formatted traceback must not contain the configured root,
canonical or lexical candidate, entry path, `extends` value, visited chain, or
installed schema path. JSON pointers, validator names, YAML line/column
locations, and non-path semantic evidence remain available. A CLI may label a
result with the exact target spelling supplied by its host, but the exception
does not echo or canonicalize it.

Suffix, missing-file, non-file, YAML, schema, composition, and cycle failures
retain their existing codes and semantic meaning, but path-bearing text and
details are removed. The in-root cycle failure uses the stable path-free message
`"Circular policy inheritance detected"` with `code="POLICY_LOAD_ERROR"`.
Underlying `OSError`, `RuntimeError`, parser, or resolver exceptions are
normalized without retaining a path-bearing `__cause__` or `__context__`; the
normalized exception must be constructed and raised outside the active handler
when necessary. An outside nonexistent target still returns
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
- `with_retry()` policy discovery;
- module-level enforcement;
- `AEGIS` instance enforcement and sessions; and
- policy lint/validate, workflow lint, and workflow doctor diagnostics,
  including the nested policy in a starter directory.

Entry points that do not accept a loader use the direct-load lexical-parent
default. Entry points already accepting `PolicyLoaderBase` preserve and
propagate an explicitly supplied `FilePolicyLoader`. The async entry point is
extended additively to accept the same loader authority.

Diagnostic APIs gain optional root authority rather than pre-reading a target:

- `lint_policy(..., policy_root=None)` and `lint_target(..., policy_root=None)`
  create one bound file loader and obtain prepared and compiled views from the
  shared private orchestrator;
- `lint_starter_dir(..., policy_root=None)` passes the same authority to its
  nested `policy.yaml`;
- `diagnose_workflow_policy(..., policy_root=None)`,
  `diagnose_starter_dir(..., policy_root=None)`, and
  `diagnose_target(..., policy_root=None)` reuse that prepared source for raw
  lint rules, advisory checks, and semantic compilation rather than reading the
  path again, while preserving their injected `now` date;
- `_lint_policy()`, `_validate_policy()`, and
  `load_resolve_compile_policy()` accept and propagate that loader;
- `aegis policy lint`, `aegis policy validate`, and file-policy forms of
  `aegis workflow lint` and `aegis workflow doctor` accept
  `--policy-root ROOT`; and
- policy containment runs before any CLI existence check or `Path.read_text()`
  call for that policy source.

CLI target arguments follow the same namespace rule as the loader. With an
explicit root, relative targets are root-relative:

```console
aegis policy validate --policy-root policies apps/reviewer.yaml
```

This validates `apps/reviewer.yaml` relative to the canonical root selected by
`policies`. A relative `--policy-root` is resolved from the CLI process's
initial working directory; callers requiring launch-directory independence use
an absolute root. Once bound, target resolution is independent of later working
directory changes. Absolute CLI targets are accepted only when canonically
contained by the supplied root.

For `aegis workflow lint` and `aegis workflow doctor`, `--policy-root` applies
to policy targets and to the nested `policy.yaml` of starter-directory targets.
Relative policy and starter-directory targets are root-relative when this
option is present. An explicit `--kind policy`, or a `.yaml`/`.yml` target under
`--kind auto`, routes to the shared loader before `detect_target_kind()`
performs existence, type, or content inspection. A possible starter-directory
target is canonically contained as a directory under the same root before
fixture detection performs metadata checks; its nested policy is then prepared
through the configured root before it is opened. Supplying `--policy-root` with
an explicit artifact kind is a CLI usage error rather than an ignored security
option.

When `--policy-root` is omitted for a starter directory, selection of the
starter target is the host-authorized act. The diagnostic canonicalizes that
directory, validates that it is a directory, and constructs a loader rooted at
the canonical starter directory itself. Its nested `policy.yaml` is passed as
an absolute lexical entry to that loader. Thus `starters/foo/policy.yaml` cannot
inherit from `starters/bar/policy.yaml` merely because the CLI target was
spelled `starters/foo`; sibling authority requires an explicit broader root.

When `--policy-root` is omitted, each policy-file CLI target uses the same
lexical-parent default as direct loading, while each starter target uses the
narrowed starter-directory rule above. A CLI command with multiple targets
creates a separate implicit root per target; one target cannot widen another
target's graph.

Instance enforcement already accepts `policy_loader`. The sealed module-level
runtime adds an optional `policy_loader` parameter to
`configure_module_enforcement()`, and every module-level sync/async enforcement
path uses that configured loader. When omitted, module-level invocation
`policy_file` is a trusted host reference and receives the implicit
lexical-parent root. The module entry boundary constructs that invocation-bound
loader once and uses the same instance for the entire sync/async operation.
Hosts that accept an untrusted `policy_file` must configure
`FilePolicyLoader(policy_root)` before the module runtime is sealed.

`with_retry()` no longer performs an independent unbound policy load. Retry
policy discovery uses authority inferred from the enforcement function or
explicitly attested by the host:

- the default module-level enforcement function uses the loader sealed in the
  module runtime when present; when it is `None`, `with_retry()` constructs one
  invocation-bound lexical-parent loader and supplies that exact instance to
  discovery and every enforcement attempt through a private context-bound
  override;
- a bound `AEGIS` enforcement method uses that instance's configured loader, or
  the same context-bound implicit-loader mechanism when its loader is `None`;
  and
- an arbitrary injected enforcement callable accepts a keyword-only
  `policy_loader` whose use by that callable is attested by the host.

The private override is created from the invocation's `policy_file` using the
exact direct-load algorithm. Module and instance enforcement consult it only
when their configured loader is `None`; it can never replace or widen an
explicitly configured loader, and it is cleared after the retry operation.

If both an inferable enforcement loader and `policy_loader` are present, they
must be the same loader instance or the call raises
`ValueError("policy_loader does not match enforcement authority")` before policy
access. An arbitrary callable whose authority cannot be inferred must receive
an explicit `policy_loader`; omission raises
`ValueError("policy_loader is required when enforcement authority cannot be inferred")`.
A host that wants the ordinary implicit boundary can construct the
lexical-parent-bound loader before supplying the callable. Retry discovery and
attempted enforcement therefore cannot diverge because of an independent
library-selected default; a custom callable's declared authority remains a host
responsibility.

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
  `FilePolicyLoader(policy_root)`;
- constructing `FilePolicyLoader()` without a root is no longer valid;
- path-bearing fields and text are removed from all public file-backed loader
  failures, including cycle and missing inherited-policy failures; and
- `with_retry()` with an arbitrary enforcement callable requires an explicit
  `policy_loader` because its enforcement authority cannot be inferred.

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

# Custom retry enforcement must declare the same authority
with_retry(invocation, enforcement_fn=custom_enforce, policy_loader=loader)
```

Plain `load_policy("policies/standalone.yaml")` remains source-compatible.
Public API snapshot tests are updated deliberately to require the constructor
argument and the custom-retry authority parameter. Distribution tests verify
the packaged class, error code, and schema copy. Diagnostic consumers that
previously relied on absolute paths in exception details must use their own
host-known target label; canonical filesystem paths are no longer public
diagnostic data.

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
- a multi-component implicit entry such as `policies/child.yaml` is not rebound
  as `policies/policies/child.yaml`;
- relative references on an explicit loader resolve from its root after `chdir()`;
- a no-loader async call captures its implicit root before returning the
  awaitable and is unaffected by `chdir()` before `await` or worker execution;
- a relative explicit root binds to the constructor's captured working
  directory, while an absolute root is launch-directory independent;
- a nonexistent outside target fails as containment, without probing details;
- an explicit broader root permits a legitimate multi-directory graph;
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
- lint, validate, workflow lint, and workflow doctor containment occurs before
  policy raw-read and existence paths;
- a same-named policy in the working directory and explicit root proves that
  diagnostics open and compile only the root-authorized source;
- arbitrary caller-supplied parsed mappings and opaque custom loaders cannot
  enter the file-backed prepared-source path;
- a prepared source minted by one file loader is rejected by a different loader,
  including another loader configured with the same canonical root;
- starter lint and doctor propagate the root to their nested `policy.yaml`;
- an explicit-root starter-directory symlink outside the root is rejected before
  fixture detection or nested-policy metadata access;
- an implicit `starters/foo` target roots its nested policy at `starters/foo`,
  so it cannot inherit from `starters/bar` without an explicit broader root;
- doctor prepares a policy only once and its injected `now` value governs both
  lint and semantic date validation;
- module-level enforcement uses its sealed configured file loader;
- AEGIS with an explicit `FilePolicyLoader` preserves that root through cache
  and session loads;
- `with_retry()` uses the sealed module loader or bound AEGIS loader, rejects a
  conflicting explicit loader, and requires authority for arbitrary callables;
- module and AEGIS retry with no configured loader reuse one exact
  invocation-bound loader for discovery and every attempt, and clear it after
  success or failure;
- cache entries are isolated by root; and
- custom loaders still reject `extends` without filesystem access.

### Error-surface cases

- the exception is a `PolicyLoadError`;
- `exc.code` is exactly `POLICY_PATH_OUTSIDE_ROOT`;
- its message is stable; and
- neither the message, details, cause, context, nor formatted exception chain
  exposes the configured root, candidate, entry, `extends`, visited, or schema
  path values.

The same confidentiality assertions cover an in-root self-cycle, a missing or
non-file inherited target, malformed inherited YAML, schema failure, and a
symlink-resolution loop through direct, lint/CLI, doctor, retry, and enforcement
surfaces. Cycle detection retains its typed semantics while using the new stable
path-free message.

Malformed `extends` tests cover `None`, booleans, numbers, mappings, arrays, and
the empty string. Platform tests cover different-drive absolute paths on Windows
and skip only symlink creation when the test account lacks symlink privileges;
traversal and absolute-path coverage remains mandatory on every platform.

## Documentation

Implementation updates:

- `docs/USAGE.md` with explicit-root configuration, default-root behavior, and
  `with_retry()` authority propagation;
- `docs/INTEGRATION_GUIDE.md` with the policy-tree example's authority root;
- `docs/PUBLIC_INTEGRATION_CONTRACT.md` with the root, symlink, custom-loader,
  retry-loader, prepared-source, and path-free error contract;
- `docs/reference/TROUBLESHOOTING.md` and workflow-doctor next-action guidance
  for `POLICY_PATH_OUTSIDE_ROOT`, including `workflow doctor --policy-root`;
- `policies/policy_dsl_spec.md` with `extends` path containment semantics; and
- ADR-0005 with a compatibility note that absolute entry paths remain supported
  but do not authorize arbitrary inherited targets.

`CHANGELOG.md` records the security fix, the immediate constructor change, the
root-relative explicit-loader namespace, removal of path-bearing error details,
the retry-loader requirement, and the migration examples. Public API, CLI
contract, packaged-schema parity, and documentation-parity tests are updated
with the same wording.

## Security Review Focus

The adversarial review must verify:

- no recursive path can select a fresh or broader root;
- no check occurs only after YAML content has been opened;
- canonical paths, not lexical prefixes, drive containment;
- symlinks cannot change the authority boundary;
- cache hits cannot bypass a narrower root;
- prepared diagnostic content is the exact mapping opened by the bound loader;
- retry and workflow diagnostics cannot select an unbound loader;
- public file-backed error objects and their exception chains do not disclose
  protected policy-path values; and
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
