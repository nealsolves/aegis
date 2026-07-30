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
