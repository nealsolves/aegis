# A2 Closed Outcomes and Gate Projection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ensure custom gates, validator hooks, and risk evaluation can authorize only through explicit closed allow outcomes while exposing no argument-reachable handle to live enforcement state.

**Architecture:** `GateProjectionFactory` creates detached recursively immutable inputs. `OutcomeNormalizer` converts every gate/hook/risk result or exception into one closed terminal class; only `ALLOW` and `WARN` continue. Enforcement consumes the normalized outcome instead of interpreting booleans, failures lists, or string decisions independently.

**Tech Stack:** Python 3.10+, frozen dataclasses, enums, `MappingProxyType`, pytest, A1 `CompiledPolicy`.

## Global Constraints

- A1 is complete and enforcement receives only `CompiledPolicy`.
- `_ImmutableView` is removed.
- Gate inputs contain no live policy, invocation, registry, signer, sink, or operation references.
- `GateResult.passed=False` always denies, including with an empty failures list.
- `passed=True` with failures is `INVALID_RESULT` and denies.
- Exceptions and unknown decisions deny with stable sanitized codes.
- Exhausted `ValidatorHook` execution failures deny.
- A score at or above `0.90` denies in every risk mode.
- Gate isolation is an argument-projection guarantee, not a Python sandbox claim.

---

### Task 1: Build detached immutable gate projections

**Files:**
- Create: `aegis/_internal/gate_projection.py`
- Modify: `aegis/_internal/gates.py`
- Modify: `tests/test_gate_immutability.py`
- Create: `tests/test_gate_projection_security.py`

**Interfaces:**
- Produces: `GateProjectionFactory.invocation(source) -> Mapping[str, JsonValue]`
- Produces: `GateProjectionFactory.policy(compiled: CompiledPolicy) -> Mapping[str, JsonValue]`
- Produces: `GateProjectionFactory.context(source) -> dict[str, JsonValue]`

- [ ] **Step 1: Reproduce the `_ImmutableView._data` escape**

```python
def test_gate_cannot_reach_live_policy_backing_mapping():
    live = {"roles": ["verifier"]}
    projection = GateProjectionFactory.policy_from_mapping(live)
    assert not hasattr(projection, "_data")
    for value in _walk_objects(projection):
        assert value is not live
        assert value is not live["roles"]
```

Add a malicious gate that mutates every nested collection it can discover and assert the authorization basis is unchanged.

- [ ] **Step 2: Run and verify the current view fails**

Run: `.venv/bin/pytest tests/test_gate_immutability.py tests/test_gate_projection_security.py -v`

Expected: FAIL because `_ImmutableView._data` exposes the original mapping.

- [ ] **Step 3: Implement copy-then-freeze projection**

```python
def detached_json_projection(value: object) -> JsonValue:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, Mapping):
        copied = {str(k): detached_json_projection(v) for k, v in value.items()}
        return MappingProxyType(copied)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(detached_json_projection(v) for v in value)
    raise TypeError(f"Unsupported gate projection value: {type(value).__name__}")
```

Construct the policy projection from an explicit allowlist of `CompiledPolicy` fields, not `compiled.raw`.

- [ ] **Step 4: Remove `_ImmutableView` and update the gate docstring**

State: “supplied projections cannot mutate AEGIS enforcement state.” Remove any claim that arbitrary in-process gate code cannot mutate unrelated globals.

Run: `.venv/bin/pytest tests/test_gate_immutability.py tests/test_gate_projection_security.py tests/test_custom_gates.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/gate_projection.py aegis/_internal/gates.py tests/test_gate_immutability.py tests/test_gate_projection_security.py
git commit -m "fix: isolate custom gates from live enforcement state"
```

### Task 2: Add the closed terminal outcome model

**Files:**
- Create: `aegis/_internal/outcomes.py`
- Modify: `aegis/_internal/errors.py`
- Create: `tests/test_outcome_normalizer.py`

**Interfaces:**
- Produces: `TerminalClass` enum: `ALLOW`, `WARN`, `DENY`, `INVALID_RESULT`, `EXECUTION_FAILURE`, `TIMEOUT`
- Produces: `NormalizedOutcome(terminal, reason_code, failures, metadata)`
- Produces: `OutcomeNormalizer`; property `.allows_continuation` is true only for `ALLOW`/`WARN`.

- [ ] **Step 1: Write the terminal truth-table tests**

```python
@pytest.mark.parametrize(
    ("terminal", "allowed"),
    [
        (TerminalClass.ALLOW, True),
        (TerminalClass.WARN, True),
        (TerminalClass.DENY, False),
        (TerminalClass.INVALID_RESULT, False),
        (TerminalClass.EXECUTION_FAILURE, False),
        (TerminalClass.TIMEOUT, False),
    ],
)
def test_only_closed_allow_classes_continue(terminal, allowed):
    assert NormalizedOutcome(terminal, "TEST").allows_continuation is allowed
```

- [ ] **Step 2: Run and verify the module is absent**

Run: `.venv/bin/pytest tests/test_outcome_normalizer.py -v`

Expected: FAIL on import.

- [ ] **Step 3: Implement immutable normalized outcomes**

```python
class TerminalClass(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    DENY = "deny"
    INVALID_RESULT = "invalid_result"
    EXECUTION_FAILURE = "execution_failure"
    TIMEOUT = "timeout"


@dataclass(frozen=True, slots=True)
class FailureRecord:
    code: str
    message: str
    field: str | None = None


@dataclass(frozen=True, slots=True)
class NormalizedOutcome:
    terminal: TerminalClass
    reason_code: str
    failures: tuple[FailureRecord, ...] = ()
    metadata: Mapping[str, JsonValue] = field(default_factory=lambda: MappingProxyType({}))

    @property
    def allows_continuation(self) -> bool:
        return self.terminal in {TerminalClass.ALLOW, TerminalClass.WARN}
```

Reject construction with unknown terminal values, mutable metadata, or unbounded public messages.

- [ ] **Step 4: Run tests**

Run: `.venv/bin/pytest tests/test_outcome_normalizer.py tests/test_errors.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/outcomes.py aegis/_internal/errors.py tests/test_outcome_normalizer.py
git commit -m "feat: add closed authorization outcomes"
```

### Task 3: Normalize custom-gate results fail closed

**Files:**
- Modify: `aegis/_internal/gates.py`
- Modify: `aegis/_internal/enforcement.py`
- Modify: `tests/test_custom_gate_failure_mapping.py`
- Modify: `tests/test_custom_gate_exception_artifacts.py`
- Create: `tests/test_custom_gate_result_consistency.py`

**Interfaces:**
- Produces: `normalize_gate_result(gate_id: str, result: object) -> NormalizedOutcome`
- Consumes: `GateProjectionFactory`, `OutcomeNormalizer`.

- [ ] **Step 1: Write failing contradictory/empty-failure tests**

```python
def test_false_without_failures_denies():
    outcome = normalize_gate_result("g", GateResult(passed=False, failures=[]))
    assert outcome.terminal is TerminalClass.DENY
    assert outcome.reason_code == "CUSTOM_GATE_DENIED"


def test_true_with_failures_is_invalid():
    outcome = normalize_gate_result(
        "g",
        GateResult(passed=True, failures=[{"code": "X", "message": "x", "field": None}]),
    )
    assert outcome.terminal is TerminalClass.INVALID_RESULT
```

- [ ] **Step 2: Run and verify the empty-failure bypass**

Run: `.venv/bin/pytest tests/test_custom_gate_result_consistency.py tests/test_custom_gate_failure_mapping.py -v`

Expected: FAIL because current code acts only on `result.failures`.

- [ ] **Step 3: Implement the gate result truth table**

```python
if not isinstance(result, GateResult):
    return execution_failure("CUSTOM_GATE_INVALID_RETURN")
if result.passed is False:
    return deny("CUSTOM_GATE_DENIED", failures=result.failures or (_synthetic_denial(gate_id),))
if result.failures:
    return invalid("CUSTOM_GATE_INCONSISTENT_RESULT", failures=result.failures)
return allow_or_warn(result.metadata)
```

Gate exceptions map to `EXECUTION_FAILURE`; mutation attempts are not inferred by matching exception strings.

- [ ] **Step 4: Integrate normalized continuation checks**

Replace every “if failures” or truthy decision branch with:

```python
outcome = normalize_gate_result(gate_id, result)
if not outcome.allows_continuation:
    raise CustomGateViolationError.from_outcome(outcome)
```

Run: `.venv/bin/pytest tests/test_custom_gate_result_consistency.py tests/test_custom_gate_failure_mapping.py tests/test_custom_gate_exception_artifacts.py tests/test_custom_gates.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/gates.py aegis/_internal/enforcement.py tests/test_custom_gate_result_consistency.py tests/test_custom_gate_failure_mapping.py tests/test_custom_gate_exception_artifacts.py
git commit -m "fix: normalize custom gates fail closed"
```

### Task 4: Normalize hook and risk decisions

**Files:**
- Modify: `aegis/_internal/validator_hook.py`
- Modify: `aegis/_internal/risk_scoring.py`
- Modify: `aegis/_internal/enforcement.py`
- Modify: `aegis/_internal/session.py`
- Modify: `tests/test_validator_hook.py`
- Create: `tests/test_validator_hook_fail_closed.py`
- Modify: `tests/test_risk_scoring.py`
- Create: `tests/test_critical_risk_ceiling.py`

**Interfaces:**
- Produces: `normalize_hook_result(result) -> NormalizedOutcome`
- Produces: `normalize_risk_result(score: RiskScore) -> NormalizedOutcome`

- [ ] **Step 1: Add #55 and critical-ceiling failing tests**

```python
def test_exhausted_execution_failure_denies():
    result = ValidatorHookResult(
        decision=VALIDATOR_EXECUTION_FAILURE,
        reason_code="HOOK_BACKEND_ERROR",
        explanation="validator unavailable",
        hook_id="test-hook",
        hook_version="1.0",
        attempt=2,
        latency_ms=5,
        observed_at=1_722_000_000_000,
    )
    assert normalize_hook_result(result).terminal is TerminalClass.EXECUTION_FAILURE


@pytest.mark.parametrize("mode", ["strict", "risk_scored", "warn_only"])
def test_critical_score_blocks_in_every_mode(mode):
    score = RiskScore(score=0.90, threshold=0.99, mode=mode, basis=[])
    assert normalize_risk_result(score).terminal is TerminalClass.DENY


@pytest.mark.parametrize("mode", ["strict", "risk_scored", "warn_only"])
def test_score_equal_to_policy_threshold_is_exceeded(mode):
    score = RiskScore(score=0.75, threshold=0.75, mode=mode, basis=[])
    assert score.exceeded is True
```

- [ ] **Step 2: Run and verify current fail-open behavior**

Run: `.venv/bin/pytest tests/test_validator_hook_fail_closed.py tests/test_critical_risk_ceiling.py -v`

Expected: FAIL for exhausted execution failure and non-strict critical scores.

- [ ] **Step 3: Implement hook normalization**

Map `ALLOW -> ALLOW`, `WARN -> WARN`, `DENY/REVIEW_REQUIRED -> DENY`, `TIMEOUT -> TIMEOUT`, and final `EXECUTION_FAILURE -> EXECUTION_FAILURE`. Unknown or malformed results map to `INVALID_RESULT`.

- [ ] **Step 4: Implement the risk decision**

First change `RiskScore.exceeded` to `score >= threshold`; equality is a
threshold breach. Then replace the live branch in every unified, split, async,
instance, and session authorization path—including the decision currently in
`enforcement.py`—with `normalize_risk_result(score)`. No authorization path
outside that normalizer may branch directly on `score.exceeded` or
`score.mode` after this task.

```python
CRITICAL_RISK_CEILING = 0.90

if score.score >= CRITICAL_RISK_CEILING:
    return deny("RISK_CRITICAL_CEILING")
if score.mode == RISK_MODE_STRICT and score.exceeded:
    return deny("RISK_THRESHOLD_EXCEEDED")
if score.exceeded:
    return warn("RISK_THRESHOLD_WARNING")
return allow("RISK_ACCEPTED")
```

Run: `.venv/bin/pytest tests/test_validator_hook.py tests/test_validator_hook_fail_closed.py tests/test_risk_scoring.py tests/test_critical_risk_ceiling.py tests/test_session_core.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/validator_hook.py aegis/_internal/risk_scoring.py aegis/_internal/enforcement.py aegis/_internal/session.py tests/test_validator_hook.py tests/test_validator_hook_fail_closed.py tests/test_risk_scoring.py tests/test_critical_risk_ceiling.py
git commit -m "fix: close hook and critical-risk outcomes"
```

### Task 5: Add blocking boundary tests and documentation

**Files:**
- Modify: `tests/test_architecture_security_boundaries.py`
- Modify: `.github/workflows/security-boundaries.yml`
- Modify: `docs/architecture/ENFORCEMENT_PIPELINE.md`
- Modify: `docs/architecture/ARCHITECTURAL_INVARIANTS.md`
- Modify: `docs/PUBLIC_INTEGRATION_CONTRACT.md`

**Interfaces:**
- Produces: blocking `gate-projection-boundary` and `enforcement-boundaries` test markers.

- [ ] **Step 1: Extend AST fitness tests**

Fail if `_ImmutableView` exists, a gate call receives `CompiledPolicy` directly, or enforcement branches on raw custom/hook decision strings after normalization.

- [ ] **Step 2: Run the fitness tests**

Run: `.venv/bin/pytest tests/test_architecture_security_boundaries.py -v`

Expected: PASS only after Tasks 1–4.

- [ ] **Step 3: Wire the named CI gate**

Add a required workflow step:

```yaml
- name: gate-projection-boundary
  run: .venv/bin/pytest tests/test_architecture_security_boundaries.py -v
```

- [ ] **Step 4: Update contracts and run A2 regression**

Run: `.venv/bin/pytest tests/test_gate_immutability.py tests/test_gate_projection_security.py tests/test_outcome_normalizer.py tests/test_custom_gate_result_consistency.py tests/test_validator_hook_fail_closed.py tests/test_critical_risk_ceiling.py tests/test_architecture_security_boundaries.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/test_architecture_security_boundaries.py .github/workflows/security-boundaries.yml docs/architecture/ENFORCEMENT_PIPELINE.md docs/architecture/ARCHITECTURAL_INVARIANTS.md docs/PUBLIC_INTEGRATION_CONTRACT.md
git commit -m "test: enforce closed outcome architecture"
```

## A2 Completion Gate

Run:

```bash
.venv/bin/pytest tests/test_gate_immutability.py tests/test_gate_projection_security.py tests/test_outcome_normalizer.py tests/test_custom_gate_result_consistency.py tests/test_validator_hook_fail_closed.py tests/test_critical_risk_ceiling.py tests/test_architecture_security_boundaries.py -v
.venv/bin/pytest -q
```

Expected: both commands exit `0`; no custom gate, hook, or risk path can authorize without a closed allow-class outcome.
