# A1 Final Consolidated Fix Wave 2 Report

Date: 2026-07-30

Branch: `codex/a1-compiled-policy`

Starting revision: `f0fbf1052f25351de4584e112e37156d1e94d80f`

## Scope

This final whole-branch review wave addressed the five authorized findings
without changing the approved A1 plan, architecture specification, plan index,
or progress ledger:

1. explicit `tools.allowed_tools: []` collapsed with an absent tool declaration;
2. a matched guard role subset was appended to parent roles instead of becoming
   the effective authorization set;
3. inherited `workflow.required_sequence` could be shortened;
4. file lint and runtime compilation disagreed for `extends`;
5. `CompiledPattern` exposed a caller-reachable mutable RE2 program.

The approved plan, architecture specification, progress ledger, and all five
task reports were re-read before implementation. Work followed the
test-driven-development, systematic-debugging, root-cause-tracing, and
verification-before-completion procedures.

## Baseline

Command:

```bash
.venv/bin/python -m pytest -q
```

Result before wave-2 changes:

```text
3441 passed, 1 skipped, 13 warnings in 60.68s
```

## Root-cause analysis

### Tool presence

The compiler used `(policy.get("tools") or {}).get("allowed_tools", ())`.
Consequently both an absent field and an explicit empty allowlist compiled to
the same empty tuple, while runtime validation skipped every falsey tuple.
Presence was also absent from authority envelopes, overlays, and authenticated
compiled DTOs.

### Role effects

Both static policy composition and guard-effect application treated `roles` as
a generic additive list. The comparator proved that the declared child list
was a subset, but the effective merge reintroduced every parent role.

### Required workflow sequence

Composition validation treated a child sequence as valid when it was merely a
subsequence of the inherited sequence. Generic append/replace behavior also
allowed the effective sequence to differ from the inherited obligation.

### File lint

The workflow and CLI lint paths compiled the directly parsed child mapping.
They did not resolve the child's source-relative `extends` chain through
`load_policy()`, so widening, missing-base, cycle, and inherited-field
decisions could disagree with runtime.

### Pattern runtime mutability

`CompiledPattern` retained the mutable RE2 object in its `_compiled` field.
Although the dataclass was frozen, the handle remained reachable from compiled
authorization output and could be mutated with `object.__setattr__`.

## RED evidence

A single focused regression file was added for the five findings:

```bash
.venv/bin/python -m pytest -q tests/test_a1_final_fix_wave_2.py
```

Correct pre-implementation result:

```text
15 failed, 1 passed in 0.72s
```

Failure coverage:

- 2 tool-presence/runtime and authenticated-DTO cases;
- 3 static, matched, and cumulative role-subset cases;
- 3 newly failing exact-sequence cases, with the already fail-closed guard
  shortening case providing the one passing control;
- 4 file-lint/runtime parity cases for widening, nested relative inheritance,
  missing bases, and cycles;
- 3 pattern-surface, pinned-session, and authenticated-DTO cases.

## Implementation and GREEN evidence

### Presence-aware tool authority

- Added immutable `CompiledToolPolicy(configured, allowed_tools)`.
- Carried the type through `CompiledPolicy`, `AuthorityEnvelope`, and guard
  overlays.
- Compiled actual `allowed_tools` field presence rather than truthiness.
- Made runtime tool validation accept only `CompiledToolPolicy`.
- Preserved absent/unconfigured compatibility while treating configured empty
  as deny-all.
- Bound root and overlay presence to authenticated compiled DTO content.

### Restrictive authorization-list semantics

- Registered complete replacement merge behavior for `roles`,
  `allowed_tools`, workflow participants, and `required_sequence`.
- Kept ordinary-list append/intersect/union behavior and its tests.
- Applied a matched role subset as the effective role tuple.
- Preserved cumulative unrelated effects while validating the final cumulative
  authority against the loaded envelope.

### Exact inherited sequence

- An omitted child sequence inherits the parent value.
- Any explicit inherited-sequence change, including shortening, clearing,
  reordering, or replacement, is `POLICY_WIDENING`.
- Typed guard workflow merging replaces `required_sequence`, after which the
  workflow restriction rule proves exact inherited authority.

### Extends-aware diagnostics

- File lint resolves source-relative `extends` before compilation.
- Standalone lint still compiles the parsed mapping directly, preserving the
  existing stable date-inversion and numeric-risk diagnostic codes.
- Architecture fitness permits the diagnostic load only when its assigned
  result flows directly to the next compiler call without reassignment.
- Negative fitness fixtures prove that load-without-compile and enforcement
  load/compile paths remain forbidden.

### Opaque authenticated patterns

- `CompiledPattern` now contains only frozen authenticated metadata: source,
  path, program digest, and fixed source/input bounds.
- RE2 handles live in a bounded private digest-keyed cache.
- Each evaluation authenticates metadata and verifies cached program bytes and
  RE2 source.
- Missing or corrupted private cache entries are safely rebuilt from
  authenticated metadata; invalid metadata fails closed with
  `PATTERN_PROGRAM_INTEGRITY_ERROR`.
- Compiled DTO reconstruction restores authenticated metadata rather than
  recompiling an unauthenticated raw pattern string.
- Output-schema runtime integrity uses the same verifier without reaching into
  a pattern object.

Focused result after implementation:

```text
16 passed in 0.32s
```

Direct cache-corruption and metadata-integrity coverage:

```bash
.venv/bin/python -m pytest -q \
  tests/test_safe_pattern_compiler.py \
  tests/test_a1_final_fix_wave_2.py
```

```text
32 passed in 0.39s
```

The cache tests corrupt both private program bytes and the cached RE2 handle
and prove safe replacement; a separate test mutates authenticated metadata and
proves fail-closed evaluation.

## Affected regression evidence

Tools, restriction registry, composition, policy loading, guards, and compiled
guard programs:

```text
181 passed in 1.14s
```

Workflow lint, CLI lint, and focused wave-2 cases:

```text
102 passed in 0.66s
```

Patterns, adversarial preconditions, output-schema integrity, compiled DTO
reconstruction, split enforcement, sessions, and focused wave-2 cases:

```text
182 passed in 2.29s
```

Architecture fitness, engine hardening, and focused wave-2 cases after the
narrow diagnostic-load fitness rule:

```text
76 passed in 1.31s
```

## Independent-review hardening

The final independent diff review found two additional hardening gaps inside
the authorized lint and pattern-integrity scope.

First, the diagnostic-load architecture allowance rejected load-without-
compile but did not reject an intervening raw-policy consumer. The isolated
negative fixture produced the expected RED result:

```text
1 failed, 13 deselected in 0.04s
```

The direct-flow proof now rejects every loaded-name read before compilation
and every intervening early exit. Six isolated fixtures cover an authorization
call, attribute read, subscript read, `get()` read, alias assignment, and a
branch/early return. Load-without-compile and enforcement load/compile remain
forbidden.

Second, a forged cache object with the expected `pattern` attribute but
permissive match methods passed the initial cache check, including after
coordinated concurrent corruption. The two adversarial cases produced the
expected RED result:

```text
2 failed, 30 deselected in 0.17s
```

Cache entries are now frozen. The cache accepts only the exact concrete
google-re2 compiled-handle type with authenticated source and program
metadata. Lookup, integrity verification or rebuild, and `fullmatch`/`search`
evaluation occur inside one private lock-managed helper that returns only the
boolean decision, never the handle.

Focused GREEN after both independent-review fixes:

```text
88 passed in 1.10s
```

The A1 security gate reported `163 passed in 1.88s`.

## Final verification

Full repository suite:

```bash
.venv/bin/python -m pytest -q
```

```text
3474 passed, 1 skipped, 13 warnings in 50.10s
```

The warnings are the repository's existing user/deprecation warning cases.

Changed production modules, the new wave-2 regression file, the architecture
fitness test, and otherwise lint-clean changed tests:

```bash
.venv/bin/python -m flake8 \
  aegis/_internal/cli.py \
  aegis/_internal/compiled_policy.py \
  aegis/_internal/enforcement.py \
  aegis/_internal/guards.py \
  aegis/_internal/patterns.py \
  aegis/_internal/policy_compiler.py \
  aegis/_internal/policy_loader.py \
  aegis/_internal/restrictions.py \
  aegis/_internal/schema_compiler.py \
  aegis/_internal/tools.py \
  aegis/_internal/workflow_lint.py \
  tests/test_a1_final_fix_wave_2.py \
  tests/test_architecture_security_boundaries.py \
  tests/test_composition_semantics.py \
  tests/test_guards.py \
  tests/test_policy_composition.py \
  tests/test_safe_pattern_compiler.py \
  tests/test_tools.py
```

Result: exit 0.

A broader changed-file lint probe also included
`tests/test_engine_hardening.py` and `tests/test_policy_loader.py`; it reported
only their existing unrelated whole-file E402/F401/E501 debt, at lines not
modified by this wave. The repository's prior task report already records that
whole-tree test lint debt.

Security, schema, public API, and documentation assertion suites:

```text
231 passed in 2.66s
```

Repository gates:

- `scripts/check_doc_parity.py`: all documentation parity checks passed;
- `scripts/check_brand_and_version_parity.py`: passed;
- `scripts/check_public_docs_no_internal_imports.py`: passed;
- policy schema byte parity (`cmp -s`): passed;
- `python -m compileall -q aegis tests/test_a1_final_fix_wave_2.py`: passed;
- `git diff --check`: passed.

## Documentation and compatibility

The integration guide, public integration contract, and architectural
invariants now distinguish ordinary-list composition from the field-specific
security rules. They also document explicit empty tool allowlists as deny-all
and inherited workflow sequences as exact.

Legacy standalone lint diagnostics were preserved. Runtime authorization has
no raw tool-policy compatibility branch. Existing public policy-loading and
integration surfaces remain unchanged.

## Remaining concerns

No open correctness or security concern remains for the five authorized
findings. The only observed non-green static output is the pre-existing lint
debt in two legacy test files described above; it is unrelated to modified
lines and was not expanded into this security fix wave.
