# A1 Compiled Policy and Restriction Envelope Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace enforcement-time interpretation of raw policy dictionaries with one immutable compiled policy that rejects ambiguous constraints and proves composition and guard effects cannot widen authority.

**Architecture:** `PolicyCompiler` converts a schema-valid raw mapping into `CompiledPolicy`; `RestrictionComparator` checks raw overlays and merged/effective candidates against a closed authority envelope. Enforcement consumes only compiled accessors. Public `load_policy()` may keep returning dictionaries for compatibility, but no authorization path may use that result without compilation.

**Tech Stack:** Python 3.10+, frozen dataclasses, `MappingProxyType`, `google-re2`, `jsonschema` Draft 7 plus `referencing.Registry`, PyYAML, pytest.

## Global Constraints

- Policy schema advances to `2.0`; root and packaged schema copies remain byte-for-byte identical.
- `google-re2` is required; there is no Python `re` fallback.
- Pattern source is limited to 256 UTF-8 bytes; candidate values are limited to 16,384 UTF-8 bytes.
- Type-specific precondition keywords without `type` are compile errors.
- Numeric security values reject booleans, strings, NaN, and infinities.
- Unknown risk conditions and unknown security-sensitive policy fields fail compilation.
- Runtime risk overrides are tighten-only.
- Same-document JSON Schema fragments are allowed; all external/document-relative retrieval is forbidden.
- Critical score ceiling is the fixed finite value `0.90`.
- Legacy behavior is host-selected only and never enabled by policy content.

---

### Task 1: Add compiler value objects and dependency boundaries

**Files:**
- Create: `aegis/_internal/compiled_policy.py`
- Create: `aegis/_internal/policy_compiler.py`
- Modify: `aegis/_internal/errors.py`
- Modify: `pyproject.toml`
- Modify: `docs/reference/SUPPORTED_ENVIRONMENTS.md`
- Test: `tests/test_policy_compiler.py`

**Interfaces:**
- Produces: `compile_policy(raw_policy: Mapping[str, Any], *, source: str, allow_legacy: bool = False) -> CompiledPolicy`
- Produces: `CompiledPolicy.policy_digest`, `.roles`, `.tools`, `.risk`, `.guards`, `.preconditions`, `.output_validator`, `.authority`, `.canonicalization_profile`
- Consumes later: A2 outcome normalization, A3 operation handles, B1 canonicalization profile.

- [ ] **Step 1: Write failing immutability and dependency tests**

```python
def test_compile_policy_returns_detached_immutable_snapshot(valid_policy):
    raw = copy.deepcopy(valid_policy)
    compiled = compile_policy(raw, source="test")
    raw["roles"].append("admin")
    assert compiled.roles == ("verifier",)
    assert not hasattr(compiled, "raw")


def test_compiled_policy_records_closed_profiles(valid_policy):
    compiled = compile_policy(valid_policy, source="test")
    assert compiled.policy_schema_version == "2.0"
    assert compiled.pattern_engine == "google-re2"
    assert compiled.canonicalization_profile == "aegis-json-v2"
```

- [ ] **Step 2: Run the focused tests and verify the missing-module failure**

Run: `.venv/bin/pytest tests/test_policy_compiler.py -v`

Expected: FAIL because `aegis._internal.policy_compiler` does not exist.

- [ ] **Step 3: Add exact core models and compiler entry point**

```python
JsonScalar: TypeAlias = None | bool | int | float | str
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


@dataclass(frozen=True, slots=True)
class AuthorityEnvelope:
    roles: frozenset[str]
    tools: frozenset[str]
    risk_mode: str
    risk_threshold: float
    critical_ceiling: float
    registered_fields: frozenset[str]


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    policy_digest: str
    policy_schema_version: str
    pattern_engine: str
    canonicalization_profile: str
    roles: tuple[str, ...]
    tools: tuple[str, ...]
    risk: "CompiledRiskPolicy"
    guards: tuple["CompiledGuard", ...]
    preconditions: tuple["CompiledPrecondition", ...]
    output_validator: "CompiledOutputValidator | None"
    authority: AuthorityEnvelope


def compile_policy(
    raw_policy: Mapping[str, Any],
    *,
    source: str,
    allow_legacy: bool = False,
) -> CompiledPolicy:
    detached = copy.deepcopy(dict(raw_policy))
    _validate_policy_schema(detached, allow_legacy=allow_legacy)
    return _compile_validated_policy(detached, source=source)
```

Use a recursive freezer that copies before wrapping; never store a proxy over caller-owned containers.
Update compiler-facing exceptions to accept stable, specific codes without
changing their defaults:

```python
class PolicyValidationError(GovernanceViolationError):
    def __init__(
        self,
        message: str,
        *,
        code: str = "POLICY_SCHEMA_VALIDATION_ERROR",
        details: dict | None = None,
    ) -> None:
        super().__init__(message, code=code, details=details)
```

Apply the same optional-code pattern to `PreconditionError` and
`SchemaValidationError`.

- [ ] **Step 4: Add and verify dependencies**

Add:

```toml
dependencies = [
  "PyYAML>=6.0",
  "jsonschema>=4.18,<5",
  "google-re2>=1.1.20251105",
]
```

Run: `.venv/bin/pip install -e '.[dev]'`

Run: `.venv/bin/pytest tests/test_policy_compiler.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml aegis/_internal/compiled_policy.py aegis/_internal/policy_compiler.py aegis/_internal/errors.py tests/test_policy_compiler.py docs/reference/SUPPORTED_ENVIRONMENTS.md
git commit -m "feat: add immutable compiled policy boundary"
```

### Task 2: Compile typed preconditions, RE2 patterns, and safe output schemas

**Files:**
- Create: `aegis/_internal/patterns.py`
- Create: `aegis/_internal/schema_compiler.py`
- Modify: `aegis/_internal/policy_compiler.py`
- Modify: `aegis/_internal/validator.py`
- Modify: `schemas/policy_dsl.schema.json`
- Modify: `aegis/schemas/policy_dsl.schema.json`
- Test: `tests/test_adversarial_preconditions.py`
- Test: `tests/test_safe_pattern_compiler.py`
- Test: `tests/test_safe_output_schema.py`

**Interfaces:**
- Produces: `CompiledPattern.fullmatch(candidate: str) -> bool`
- Produces: `compile_output_schema(schema: Mapping[str, Any]) -> CompiledOutputValidator`
- Produces: `CompiledPrecondition.validate(context: Mapping[str, Any]) -> None`

- [ ] **Step 1: Add failing regression tests for #53 and pattern bounds**

```python
@pytest.mark.parametrize("spec", [
    {"pattern": "^APPROVED-[0-9]{6}$"},
    {"minLength": 2},
    {"minimum": 100},
])
def test_type_specific_keyword_without_type_is_compile_error(spec):
    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(policy_with_precondition(spec), source="test")
    assert exc.value.code == "PRECONDITION_TYPE_REQUIRED"


def test_candidate_over_16384_bytes_fails_closed():
    pattern = compile_pattern("^x+$", path="$.pre_conditions.required.code.pattern")
    with pytest.raises(PatternInputTooLargeError):
        pattern.fullmatch("x" * 16_385)
```

Also add cases for RE2-supported alternation and repetition, unsupported lookaround/backreferences, non-string pattern candidates, and exact 256/257-byte source boundaries.

- [ ] **Step 2: Run the tests and verify they fail on current permissive behavior**

Run: `.venv/bin/pytest tests/test_adversarial_preconditions.py tests/test_safe_pattern_compiler.py tests/test_safe_output_schema.py -v`

Expected: FAIL for mismatched-type bypasses, missing compiler modules, and remote `$ref`.

- [ ] **Step 3: Implement the bounded RE2 wrapper**

```python
PATTERN_MAX_BYTES = 256
PATTERN_INPUT_MAX_BYTES = 16_384


@dataclass(frozen=True, slots=True)
class CompiledPattern:
    source: str
    path: str
    _compiled: Any = field(repr=False, compare=False)

    def fullmatch(self, candidate: str) -> bool:
        if not isinstance(candidate, str):
            return False
        if len(candidate.encode("utf-8")) > PATTERN_INPUT_MAX_BYTES:
            raise PatternInputTooLargeError(code="PATTERN_INPUT_TOO_LARGE")
        return self._compiled.fullmatch(candidate) is not None


def compile_pattern(source: str, *, path: str) -> CompiledPattern:
    if not isinstance(source, str) or len(source.encode("utf-8")) > PATTERN_MAX_BYTES:
        raise PolicyValidationError("Invalid pattern length", code="PATTERN_INVALID")
    try:
        return CompiledPattern(source, path, re2.compile(source))
    except re2.error as exc:
        raise PolicyValidationError(
            f"Unsupported policy pattern at {path}",
            code="PATTERN_UNSUPPORTED",
        ) from exc
```

- [ ] **Step 4: Implement non-retrieving Draft 7 compilation**

Recursively reject `$ref` values that do not start with `#`, reject incompatible `$schema`, then construct one reusable validator:

```python
def compile_output_schema(schema: Mapping[str, Any]) -> CompiledOutputValidator:
    detached = copy.deepcopy(dict(schema))
    _reject_external_refs(detached, path="$")
    Draft7Validator.check_schema(detached)
    validator = Draft7Validator(detached, registry=Registry())
    return CompiledOutputValidator(schema=_freeze(detached), validator=validator)
```

`CompiledOutputValidator.validate(value)` calls the stored validator, converts
the first deterministic error to `SchemaValidationError`, and never re-reads a
schema mapping. `CompiledPrecondition` stores the required key, declared JSON
type, optional `CompiledPattern`, enum tuple, and numeric/string bounds; its
`validate(context)` checks declared type before any type-specific constraint.

Replace runtime `jsonschema.validate()` calls with the compiled validator. Map oversized pattern candidates to `SchemaValidationError(code="PATTERN_INPUT_TOO_LARGE")`.

- [ ] **Step 5: Update both schema copies, run parity and regression suites, then commit**

Run: `.venv/bin/pytest tests/test_adversarial_preconditions.py tests/test_safe_pattern_compiler.py tests/test_safe_output_schema.py tests/test_validation.py tests/test_doc_parity_v090_truth.py -v`

Expected: PASS and byte-for-byte policy-schema parity.

```bash
git add aegis/_internal/patterns.py aegis/_internal/schema_compiler.py aegis/_internal/policy_compiler.py aegis/_internal/validator.py schemas/policy_dsl.schema.json aegis/schemas/policy_dsl.schema.json tests/test_adversarial_preconditions.py tests/test_safe_pattern_compiler.py tests/test_safe_output_schema.py
git commit -m "fix: compile bounded policy constraints"
```

### Task 3: Compile finite risk, declared conditions, retry, and tighten-only overrides

**Files:**
- Modify: `aegis/_internal/compiled_policy.py`
- Modify: `aegis/_internal/policy_compiler.py`
- Modify: `aegis/_internal/risk_scoring.py`
- Modify: `aegis/_internal/retry.py`
- Modify: both `policy_dsl.schema.json` copies
- Test: `tests/test_risk_compiler_security.py`
- Test: `tests/test_risk_scoring.py`
- Test: `tests/test_retry.py`

**Interfaces:**
- Produces: `compile_risk_policy(raw: Mapping[str, Any]) -> CompiledRiskPolicy`
- Produces: `resolve_runtime_risk(base: CompiledRiskPolicy, override: Mapping[str, Any] | None) -> CompiledRiskPolicy`

- [ ] **Step 1: Write failing tests for #54, undeclared conditions, and downgrades**

```python
@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), True, "0.9"])
def test_security_number_rejects_non_finite_or_coerced_values(value):
    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(policy_with_threshold(value), source="test")
    assert exc.value.code == "RISK_NUMBER_INVALID"


def test_runtime_override_cannot_lower_strictness(compiled_policy):
    with pytest.raises(PolicyValidationError) as exc:
        resolve_runtime_risk(compiled_policy.risk, {"mode": "warn_only"})
    assert exc.value.code == "RISK_OVERRIDE_WIDENS"
```

- [ ] **Step 2: Verify the current implementation fails**

Run: `.venv/bin/pytest tests/test_risk_compiler_security.py tests/test_risk_scoring.py tests/test_retry.py -v`

Expected: FAIL because `float()` accepts strings/booleans and NaN bypasses comparison.

- [ ] **Step 3: Add strict primitive and condition compilation**

```python
@dataclass(frozen=True, slots=True)
class CompiledRiskFactor:
    name: str
    weight: float
    condition: str


@dataclass(frozen=True, slots=True)
class CompiledRiskPolicy:
    mode: str
    threshold: float
    critical_ceiling: float
    factors: tuple[CompiledRiskFactor, ...]


def require_finite_number(value: object, *, path: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PolicyValidationError("Security number must be numeric", code="RISK_NUMBER_INVALID")
    normalized = float(value)
    if not math.isfinite(normalized) or not minimum <= normalized <= maximum:
        raise PolicyValidationError("Security number out of range", code="RISK_NUMBER_INVALID")
    return normalized
```

Compile conditions only from the built-in registry plus explicitly registered host condition providers. Remove context-key fallback from `_evaluate_risk_condition`.

- [ ] **Step 4: Implement tighten-only override ordering**

Use `strict > risk_scored > warn_only`; a runtime mode must be at least as strict, a threshold may only decrease, factors may only be retained or added, and the fixed `0.90` critical ceiling is not configurable.

Run: `.venv/bin/pytest tests/test_risk_compiler_security.py tests/test_risk_scoring.py tests/test_retry.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/compiled_policy.py aegis/_internal/policy_compiler.py aegis/_internal/risk_scoring.py aegis/_internal/retry.py schemas/policy_dsl.schema.json aegis/schemas/policy_dsl.schema.json tests/test_risk_compiler_security.py tests/test_risk_scoring.py tests/test_retry.py
git commit -m "fix: compile finite tighten-only risk policy"
```

### Task 4: Add default-deny restriction registry and guard-effect comparison

**Files:**
- Create: `aegis/_internal/restrictions.py`
- Modify: `aegis/_internal/policy_loader.py`
- Modify: `aegis/_internal/guards.py`
- Modify: `aegis/_internal/policy_compiler.py`
- Test: `tests/test_restriction_registry.py`
- Test: `tests/test_policy_composition.py`
- Test: `tests/test_guards.py`

**Interfaces:**
- Produces: `RestrictionRegistry.compare(parent, candidate, *, path, phase) -> None`
- Produces: `RestrictionComparator.assert_overlay_and_effective(parent, overlay, effective) -> None`

- [ ] **Step 1: Write failing widening and unknown-field tests**

```python
def test_guard_effect_cannot_add_role(base_policy):
    child = with_guard_effect(base_policy, {"roles": ["admin"]})
    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(child, source="child")
    assert exc.value.code == "POLICY_WIDENING"


def test_unregistered_security_field_fails_closed(base_policy):
    base_policy["future_authority"] = {"allow": True}
    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(base_policy, source="test")
    assert exc.value.code == "RESTRICTION_SEMANTICS_MISSING"
```

- [ ] **Step 2: Run the composition suites and record current widening failures**

Run: `.venv/bin/pytest tests/test_restriction_registry.py tests/test_policy_composition.py tests/test_guards.py -v`

Expected: FAIL for roles, tools, risk mode, and guard-effect smuggling.

- [ ] **Step 3: Implement explicit field semantics**

```python
REGISTRY = RestrictionRegistry({
    "roles": SetSubsetRule(),
    "tools.allowed_tools": ToolSubsetRule(),
    "risk.mode": OrderedStrictnessRule(("warn_only", "risk_scored", "strict")),
    "risk.threshold": NumericMaximumRule(),  # candidate <= parent
    "pre_conditions": RequirementsSupersetRule(),
    "post_conditions": RequirementsSupersetRule(),
    "output_schema": SchemaRestrictionRule(),
    "workflow": WorkflowRestrictionRule(),
})
```

Every schema field marked security-sensitive must have one registered rule. The schema/compiler fitness test fails if the sets diverge.

- [ ] **Step 4: Compare raw overlay and effective result, including every guard effect**

Call:

```python
comparator.assert_overlay_and_effective(
    parent=compiled_parent,
    overlay=raw_child,
    effective=compiled_merged,
)
```

Compile each `then` effect as a candidate overlay and compare its effective policy against the loaded policy before storing the guard.

Run: `.venv/bin/pytest tests/test_restriction_registry.py tests/test_policy_composition.py tests/test_guards.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/restrictions.py aegis/_internal/policy_loader.py aegis/_internal/guards.py aegis/_internal/policy_compiler.py tests/test_restriction_registry.py tests/test_policy_composition.py tests/test_guards.py
git commit -m "fix: make policy restriction semantics default deny"
```

### Task 5: Route enforcement and lint through compiled policies

**Files:**
- Modify: `aegis/_internal/enforcement.py`
- Modify: `aegis/_internal/workflow_lint.py`
- Modify: `aegis/_internal/cli.py`
- Create: `tests/test_enforcement_compiled_policy_boundary.py`
- Create: `tests/test_architecture_security_boundaries.py`
- Modify: `docs/architecture/ENFORCEMENT_PIPELINE.md`
- Modify: `docs/architecture/ARCHITECTURAL_INVARIANTS.md`

**Interfaces:**
- Consumes: `compile_policy(...) -> CompiledPolicy`
- Produces for A2/A3: every enforcement entry carries a `CompiledPolicy`, never a raw mapping.

- [ ] **Step 1: Add a failing architecture fitness test**

Parse production ASTs and fail when authorization functions access `policy.get`, index raw `policy[...]`, or call `load_policy()` without immediately compiling. Allow raw-policy access only in loader/compiler modules.

- [ ] **Step 2: Run the fitness test and capture current violations**

Run: `.venv/bin/pytest tests/test_enforcement_compiled_policy_boundary.py tests/test_architecture_security_boundaries.py -v`

Expected: FAIL with current enforcement call sites.

- [ ] **Step 3: Integrate compilation once per load**

Introduce:

```python
def _load_compiled_policy(policy_file: str, *, loader: PolicyLoaderBase | None) -> CompiledPolicy:
    raw = load_policy(policy_file, loader=loader)
    return compile_policy(raw, source=policy_file, allow_legacy=False)
```

Pass the compiled object through unified, split, async, instance, and session paths. Lint calls the same compiler and renders compiler error paths/codes.

- [ ] **Step 4: Run A1 and broad compatibility tests**

Run: `.venv/bin/pytest tests/test_policy_compiler.py tests/test_adversarial_preconditions.py tests/test_safe_pattern_compiler.py tests/test_safe_output_schema.py tests/test_risk_compiler_security.py tests/test_restriction_registry.py tests/test_enforcement_compiled_policy_boundary.py tests/test_policy_loader.py tests/test_enforcement_pipeline.py tests/test_async_enforcement.py tests/test_workflow_lint.py -v`

Expected: PASS.

- [ ] **Step 5: Update docs and commit**

```bash
git add aegis/_internal/enforcement.py aegis/_internal/workflow_lint.py aegis/_internal/cli.py tests/test_enforcement_compiled_policy_boundary.py tests/test_architecture_security_boundaries.py docs/architecture/ENFORCEMENT_PIPELINE.md docs/architecture/ARCHITECTURAL_INVARIANTS.md
git commit -m "refactor: enforce only compiled policies"
```

## A1 Completion Gate

Run:

```bash
.venv/bin/pytest tests/test_policy_compiler.py tests/test_adversarial_preconditions.py tests/test_safe_pattern_compiler.py tests/test_safe_output_schema.py tests/test_risk_compiler_security.py tests/test_restriction_registry.py tests/test_architecture_security_boundaries.py -v
.venv/bin/pytest -q
```

Expected: both commands exit `0`; issues #53, #54, and #56 have regression coverage; A2 and A3 may now consume the frozen interfaces.
