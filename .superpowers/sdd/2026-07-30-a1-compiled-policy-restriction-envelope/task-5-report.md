# Task 5 Report — Route enforcement and lint through compiled policies

Date: 2026-07-30

## Result

All policy-load enforcement boundaries now compile immediately with
`allow_legacy=False`. Unified, split, async, instance, adapter/session, dynamic
tool, risk, guard, precondition, postcondition, output, and workflow paths
consume `CompiledPolicy` fields. `load_policy()` retains its public dictionary
return outside authorization.

Split Phase A stores the exact in-memory compiled authority for Phase B.
Pickle/deepcopy compatibility uses a canonical typed compiled DTO, reconstructs
the compiled value objects without `compile_policy()`, and authenticates the
effective `policy_digest`. No raw/full policy snapshot is stored on
`CompiledPolicy`.

Workflow/policy lint invokes the shared compiler and preserves stable compiler
codes and `details.path`.

## Controller ruling applied

The controller ruled that `CompiledPolicy` must not retain a raw/full policy
snapshot, even frozen or audit-only. Audit and custom-gate projections therefore
derive only from compiled metadata and normalized authority values. Serialized
split transfer uses a compiled DTO rather than a policy-shaped input that would
be recompiled or reinterpreted.

## TDD evidence

Initial RED:

```text
.venv/bin/pytest tests/test_enforcement_compiled_policy_boundary.py \
  tests/test_architecture_security_boundaries.py -v

8 failed
```

The failures demonstrated all intended breaks:

- unified, split, instance, async, and session paths accepted a loader-valid
  legacy precondition instead of strict compilation
- `_run_phase_a` / `_run_phase_b` read raw policy mappings
- enforcement called `load_policy()` outside the immediate compile helper
- tool validation retained an authorization-time raw mapping branch

Risk-scoring RED:

```text
.venv/bin/pytest \
  tests/test_architecture_security_boundaries.py::test_authorization_functions_do_not_read_raw_policy_mappings -v

1 failed (four raw risk-policy reads)
```

Lint RED:

```text
.venv/bin/pytest \
  tests/test_workflow_lint.py::TestLintPolicy::test_duplicate_allowed_tool_returns_finding \
  tests/test_workflow_lint.py::TestLintPolicy::test_compiler_error_preserves_stable_code_and_path -v

2 failed
```

Final architecture GREEN:

```text
.venv/bin/pytest tests/test_enforcement_compiled_policy_boundary.py \
  tests/test_architecture_security_boundaries.py -v

8 passed
```

## Final verification

Exact broad Task 5 suite:

```text
.venv/bin/pytest tests/test_policy_compiler.py \
  tests/test_adversarial_preconditions.py \
  tests/test_safe_pattern_compiler.py \
  tests/test_safe_output_schema.py \
  tests/test_risk_compiler_security.py \
  tests/test_restriction_registry.py \
  tests/test_enforcement_compiled_policy_boundary.py \
  tests/test_policy_loader.py \
  tests/test_enforcement_pipeline.py \
  tests/test_async_enforcement.py \
  tests/test_workflow_lint.py -v

260 passed
```

A1 completion gate:

```text
.venv/bin/pytest tests/test_policy_compiler.py \
  tests/test_adversarial_preconditions.py \
  tests/test_safe_pattern_compiler.py \
  tests/test_safe_output_schema.py \
  tests/test_risk_compiler_security.py \
  tests/test_restriction_registry.py \
  tests/test_architecture_security_boundaries.py -v

142 passed
```

Full suite:

```text
.venv/bin/pytest -q

3339 passed, 1 skipped, 13 warnings
```

Lint and repository checks:

```text
.venv/bin/flake8 aegis <all Task 5 changed tests>
# exit 0

.venv/bin/python scripts/check_doc_parity.py
# PASSED: all documentation parity checks OK

.venv/bin/python scripts/check_brand_and_version_parity.py
# PASS

.venv/bin/python scripts/check_public_docs_no_internal_imports.py
# PASS

git diff --check
# exit 0
```

Whole-tree `flake8 aegis tests` still reports unrelated pre-existing lint debt
across legacy test files. Production code and every test changed by Task 5 are
clean.

## Compatibility migrations

- Legacy bare-string preconditions now fail at the compiler boundary with
  `LEGACY_PRECONDITION_FORBIDDEN`; tests that previously expected non-strict
  runtime acceptance were updated to the strict compiler contract.
- YAML-native non-JSON schema values now fail earlier with
  `POLICY_NON_JSON_VALUE` and a FAIL artifact instead of reaching token-freeze
  compatibility handling.
- A legacy widening `warn_only` instance risk override fixture was changed to a
  tighten-compatible `strict` override, preserving the Task 4 invariant.
- Public direct risk-scoring helpers retain raw-mapping compatibility outside
  authorization by projecting only the risk facts they require.
- A subprocess-only test now uses `sys.executable`, eliminating dependence on a
  `python` alias absent from the test environment.

## Concerns

- Full-suite warnings are existing strict-mode/deprecation warnings; no new test
  failures remain.
- The canonical compiled DTO intentionally reconstructs RE2 patterns and the
  non-retrieving output validator from already-compiled sources after
  pickle/deepcopy. It never calls `compile_policy()` or admits new authority.

## Fix round 1 — independent security review

The review's one Critical and five Important findings were reproduced first as
10 failing regressions. The fix makes every enforcement handoff typed,
authenticated, and closed against raw-policy re-entry:

- Split enforcement now authenticates a domain-separated SHA-256 digest of the
  complete canonical compiled DTO inside the Phase A HMAC evidence. Phase B
  verifies both the evidence and the reconstructed DTO content before use.
- Guards compile their conditions and restriction overlays exactly once at the
  policy compiler boundary. Runtime guard evaluation resolves only compiled
  conditions and applies typed, cumulative overlays.
- `AuthorityEnvelope` contains explicit immutable authority fields; the generic
  `restriction_values` snapshot and its reconstruction path were removed.
  `PreCallResult` likewise no longer carries an effective-policy mapping or
  frozen-policy compatibility bytes.
- `GovernanceSession` pins the exact `CompiledPolicy` opened by the session and
  routes each step through the compiled-policy enforcement entrypoint. Policy
  file changes after session creation cannot alter step authorization.
- CLI and workflow lint now defer policy semantics to the compiler and preserve
  stable compiler error codes and paths.
- The architecture fitness suite now checks every enforcement-relevant module
  for compile/load bypasses, raw compiled-policy indexing, policy-shaped
  mappings, banned snapshots, and untyped compiled-policy boundaries. Synthetic
  violations prove the checks detect the reviewed failure modes.

Verification:

```text
.venv/bin/pytest tests/test_task5_fix_round1.py -q
19 passed

.venv/bin/pytest tests/test_architecture_security_boundaries.py -q
5 passed

.venv/bin/pytest tests/test_guards.py tests/test_restriction_registry.py -q
62 passed

.venv/bin/pytest tests/test_v0_3_2_audit_round2.py \
  tests/test_v0_3_2_regressions.py \
  tests/test_final_audit_2026_04_05.py \
  tests/test_release_audit_2026_04_05.py \
  tests/test_audit_round3_2026_04_05.py \
  tests/test_deep_review_2026_04_05.py -q
117 passed

# Focused architecture, security, enforcement, compiler, session, CLI, and
# historical audit aggregate:
591 passed
```

Changed-scope `flake8`, documentation parity, brand/version parity, public-doc
boundary checks, and `git diff --check` all pass. Per the round instruction, the
full repository suite was not rerun.

Compatibility migrations in this round:

- Tests constructing raw `CompiledGuard(when=..., then=...)` values now enter
  through the compiler boundary and assert typed compiled overlays.
- Historical token tests no longer construct or assert the removed generic
  restriction map and frozen effective-policy fields.
- Invalid lint-time risk numbers now report the compiler's stable
  `RISK_NUMBER_INVALID` diagnostic.
- The public raw-mapping risk helper remains available outside authorization;
  compiled enforcement uses the typed risk scorer exclusively.

Residual considerations:

- Custom gates receive a transient, derived policy-shaped projection solely for
  their longstanding public callback contract. It is never stored and cannot
  re-enter authorization.
- Cross-process DTO reconstruction rebuilds validators from authenticated
  compiled sources only after the content digest verifies. No policy compiler,
  loader, or raw restriction interpreter is reachable from that path.
- No known security blocker remains from this review.

## Fix round 2 — session validation and semantic fitness

The two remaining Important findings were reproduced before implementation:
both pinned-session validation tests failed, and four isolated analyzer fixtures
each demonstrated one independent false negative.

Session enforcement now routes ordinary and pinned compiled pre-calls through
one `_prepare_pre_call_policy()` boundary. It validates the split invocation and
strict-policy invariants exactly once, then attaches and emits the same typed
pre-pipeline FAIL artifact on either entrypoint. The ordinary path supplies no
policy and therefore loads through the existing cache/compiler boundary; the
session path supplies its exact pinned `CompiledPolicy`, so it performs no
reload or recompilation. Pre-call invocations containing `output` are rejected
with `INVOCATION_VALIDATION_ERROR`, and strict pinned sessions reject policies
without required preconditions with the existing
`POLICY_SCHEMA_VALIDATION_ERROR` details.

The architecture analyzer now:

- resolves imported and local aliases for compile, load, and reload-capable
  entrypoints;
- distinguishes a public reload in a pinned-policy branch from the legitimate
  unpinned fallback branch;
- propagates `CompiledPolicy` identity from guaranteed annotations, typed
  attributes, typed returns, and assignments before checking `.get()` and
  subscript access;
- rejects retained `Mapping[str, Any]` authority fields structurally, regardless
  of their name, while allowing the explicit `PreCallResult` invocation/evidence
  mappings and `Mapping[str, JsonValue]` typed DTO fields; and
- scans the enforcement, compiler/loader, conditions, guards/gates, restriction,
  schema, session, tool, validator, provenance, risk, retry, lint, and CLI
  authorization modules.

Verification:

```text
.venv/bin/pytest tests/test_task5_fix_round2.py -q
2 passed

.venv/bin/pytest tests/test_architecture_security_boundaries.py -q
11 passed

# Session, strict mode, invocation validation, and split-entrypoint suites:
120 passed

# Focused Task 5, architecture, security, enforcement, compiler, session, CLI,
# and historical audit aggregate:
657 passed
```

Changed-scope `flake8`, documentation parity, brand/version parity, public-doc
boundary checks, and `git diff --check` pass. Per the round instruction, the
full repository suite was not rerun.

Residual considerations:

- The analyzer intentionally treats only annotations that guarantee a
  `CompiledPolicy` as compiled authority. Public compatibility helpers whose
  union types also admit raw mappings remain outside authorization and do not
  produce false positives.
- Reload-entrypoint analysis is control-flow aware for the session's pinned
  `is None` / `is not None` branches; a reload not proven to be on the unpinned
  branch fails closed.
- No known production blocker remains from this review.
