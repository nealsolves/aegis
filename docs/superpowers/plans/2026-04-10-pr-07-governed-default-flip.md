# PR-07: `@governed` Default Flip to `pre_call_enforcement=True` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Flip the `@governed` decorator's default from `pre_call_enforcement=False` to `pre_call_enforcement=True`, making split enforcement the standard execution model for v0.3.3+, while keeping `pre_call_enforcement=False` available as a deprecated legacy opt-out.

**Architecture:** Add a module-level `_UNSET` sentinel in `aegis/_internal/decorators.py`. The `governed()` factory detects whether `pre_call_enforcement` was supplied by the caller: absent → `True` (new default); explicitly `False` → emit `DeprecationWarning` then use unified mode; explicitly `True` → use split mode (no change). No changes to `enforcement.py` or the test golden replays; the enforcement pipeline is unchanged. Five migration tests confirm the new default, the legacy opt-out, and the deprecation warning.

**Tech Stack:** Python 3.11+, `pytest`, `pytest-asyncio` (asyncio_mode = "auto")

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `aegis/_internal/decorators.py` | Modify | Add sentinel, deprecation warning, flip default, update docstring |
| `tests/test_governed_default_flip.py` | Create | 5 migration tests |
| `CHANGELOG.md` | Modify | Add Changed entry, remove "Upcoming" planned line |
| `README.md` | Modify | Remove explicit `pre_call_enforcement=True` from decorator example |
| `docs/INTEGRATION_GUIDE.md` | Modify | Change "opt in" language to "default" + add opt-out note |
| `docs/PUBLIC_INTEGRATION_CONTRACT.md` | Modify | Change opt-in contract to opt-out/migration contract |
| `docs/architecture/ARCHITECTURAL_INVARIANTS.md` | Modify | Update "do not opt in" language |
| `PROJECT.md` | Modify | Move from "Upcoming" to landed capability |
| `RELEASE_GATES.md` | Modify | Check off all PR-07 gates |

---

## Task 1: Create the feature branch

**Files:** none

- [ ] **Step 1: Branch from develop**

```bash
git checkout develop
git checkout -b feat/v0.3.3-07-governed-default-flip
```

Expected: now on `feat/v0.3.3-07-governed-default-flip`, clean working tree.

---

## Task 2: Write the 5 migration tests

**Files:**
- Create: `tests/test_governed_default_flip.py`

These tests must be written before touching `decorators.py` — they will fail on
the current code because the default is still `False`.

- [ ] **Step 1: Create `tests/test_governed_default_flip.py`**

```python
"""
PR-07 migration tests: @governed default flip to pre_call_enforcement=True.

Verifies:
1. Default (no flag) is now split enforcement — Phase A runs before fn.
2. Explicit pre_call_enforcement=True continues to work identically.
3. Explicit pre_call_enforcement=False still runs fn before governance (legacy opt-out).
4. Explicit pre_call_enforcement=False emits DeprecationWarning.
5. Async: default is also split enforcement — Phase A runs before fn.
"""

from __future__ import annotations

import warnings

import pytest

from aegis._internal.decorators import governed
from aegis._internal.errors import GovernanceViolationError

POLICY = "tests/golden_replays/golden_policy_v1.yaml"
PROVIDER = "anthropic"
MODEL = "claude-sonnet-4-5-20250929"
ROLE = "planner"

VALID_INPUT = {"task": "analyse system"}
VALID_CONTEXT = {"role_declared": True, "schema_exists": True}
VALID_OUTPUT = {"result": "analysis complete", "confidence": 0.95}


def test_default_is_split_enforcement_sync():
    """Without the flag, Phase A runs before fn; bad role blocks fn execution."""
    side_effects: list[str] = []

    @governed(
        policy_file=POLICY,
        role="unauthorized_role",
        model_provider=PROVIDER,
        model_identifier=MODEL,
    )
    def guarded_fn(input_data, context):
        side_effects.append("called")
        return VALID_OUTPUT

    with pytest.raises(GovernanceViolationError):
        guarded_fn(VALID_INPUT, VALID_CONTEXT)

    assert side_effects == [], (
        "Default mode must run Phase A before fn; Phase A failure must block fn"
    )


def test_explicit_true_unchanged():
    """Explicit pre_call_enforcement=True still produces the same result as before."""
    @governed(
        policy_file=POLICY,
        role=ROLE,
        model_provider=PROVIDER,
        model_identifier=MODEL,
        pre_call_enforcement=True,
    )
    def fn(input_data, context):
        return VALID_OUTPUT

    result = fn(VALID_INPUT, VALID_CONTEXT)
    assert result == VALID_OUTPUT


def test_explicit_false_preserves_legacy_behavior():
    """pre_call_enforcement=False still calls fn before governance (legacy unified mode)."""
    side_effects: list[str] = []

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)

        @governed(
            policy_file=POLICY,
            role="unauthorized_role",
            model_provider=PROVIDER,
            model_identifier=MODEL,
            pre_call_enforcement=False,
        )
        def legacy_fn(input_data, context):
            side_effects.append("called")
            return VALID_OUTPUT

    with pytest.raises(GovernanceViolationError):
        legacy_fn(VALID_INPUT, VALID_CONTEXT)

    assert side_effects == ["called"], (
        "Legacy mode must call fn before governance validates role"
    )


def test_explicit_false_emits_deprecation_warning():
    """pre_call_enforcement=False emits DeprecationWarning at decoration time."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        @governed(
            policy_file=POLICY,
            role=ROLE,
            model_provider=PROVIDER,
            model_identifier=MODEL,
            pre_call_enforcement=False,
        )
        def fn(input_data, context):
            return VALID_OUTPUT

    deprecation_warnings = [
        x for x in w if issubclass(x.category, DeprecationWarning)
    ]
    assert len(deprecation_warnings) == 1
    assert "pre_call_enforcement=False" in str(deprecation_warnings[0].message)


@pytest.mark.asyncio
async def test_async_default_is_split_enforcement():
    """Async: default mode (no flag) runs Phase A before fn."""
    side_effects: list[str] = []

    @governed(
        policy_file=POLICY,
        role="unauthorized_role",
        model_provider=PROVIDER,
        model_identifier=MODEL,
    )
    async def async_fn(input_data, context):
        side_effects.append("called")
        return VALID_OUTPUT

    with pytest.raises(GovernanceViolationError):
        await async_fn(VALID_INPUT, VALID_CONTEXT)

    assert side_effects == [], (
        "Async default mode must run Phase A before fn"
    )
```

- [ ] **Step 2: Run the tests to confirm they fail**

```bash
python -m pytest tests/test_governed_default_flip.py -v
```

Expected output: **FAIL** on `test_default_is_split_enforcement_sync` and
`test_async_default_is_split_enforcement` (both currently use unified mode, so
`side_effects` is `["called"]` instead of `[]`). `test_explicit_false_emits_deprecation_warning`
also fails (no warning emitted yet).

`test_explicit_true_unchanged` and `test_explicit_false_preserves_legacy_behavior` may already pass —
that's fine. We need at least 3 red tests before proceeding.

---

## Task 3: Implement the default flip in `decorators.py`

**Files:**
- Modify: `aegis/_internal/decorators.py`

- [ ] **Step 1: Read the current file**

Open `aegis/_internal/decorators.py`. The key changes are at the top and in the
`governed()` signature (around lines 87–118).

- [ ] **Step 2: Add `import warnings` to the imports block**

In the imports block (after line 43 `import logging`), add:

```python
import warnings
```

The full import section should read:

```python
import asyncio
import functools
import inspect
import logging
import warnings
from typing import Any, Callable
```

- [ ] **Step 3: Add the `_UNSET` sentinel before `governed()`**

After the `logger = logging.getLogger("aegis.decorators")` line (line 45), add:

```python
_UNSET = object()  # sentinel: distinguishes "omitted" from explicit False
```

- [ ] **Step 4: Update the `governed()` signature and add sentinel logic**

Change the function signature and the first body lines. The current signature is:

```python
def governed(
    policy_file: str,
    role: str,
    model_provider: str,
    model_identifier: str,
    *,
    pre_call_enforcement: bool = False,
) -> Callable:
```

Replace the entire `governed()` function header through the docstring's closing `"""`,
plus add the sentinel logic immediately after the docstring:

```python
def governed(
    policy_file: str,
    role: str,
    model_provider: str,
    model_identifier: str,
    *,
    pre_call_enforcement: bool = _UNSET,  # type: ignore[assignment]
) -> Callable:
    """
    Decorator factory that wraps a function with AEGIS governance enforcement.

    Since v0.3.3, *pre_call_enforcement* defaults to ``True`` (split mode).

    When *pre_call_enforcement* is ``True`` (default), governance runs in two phases:

    * **Phase A** (pre-call): ``enforce_pre_call()`` validates policy,
      role, preconditions, guards, and tool constraints *before* the
      wrapped function executes.  If Phase A fails the function is
      **not** called.
    * **Phase B** (post-call): ``enforce_post_call()`` validates the
      function's output against schema and postconditions.

    When *pre_call_enforcement* is ``False``, the legacy unified mode is used:
    the wrapped function is called first; if it succeeds, the return value and
    call arguments are assembled into an invocation and passed through
    ``enforce_invocation``.  Passing ``False`` explicitly emits a
    ``DeprecationWarning``; this opt-out will be removed in a future release.

    :param policy_file: Path to governance policy YAML
    :param role: Invocation role (must be declared in the policy's roles list)
    :param model_provider: Model provider identifier (e.g. "anthropic")
    :param model_identifier: Model identifier (e.g. "claude-sonnet-4-5-20250929")
    :param pre_call_enforcement: If True (default), run split pre/post enforcement.
        Pass False for legacy unified mode (deprecated).
    :return: Decorated function
    """
    if pre_call_enforcement is _UNSET:
        pre_call_enforcement = True
    elif not pre_call_enforcement:
        warnings.warn(
            "@governed: pre_call_enforcement=False is deprecated. "
            "Split enforcement is now the default since v0.3.3. "
            "Remove pre_call_enforcement=False to accept the new default, "
            "or keep it as an explicit legacy opt-out (will be removed in a future release).",
            DeprecationWarning,
            stacklevel=2,
        )
    def decorator(fn: Callable) -> Callable:
```

The rest of `decorator(fn)` and its inner wrappers are **unchanged**.

- [ ] **Step 5: Run the migration tests to confirm they pass**

```bash
python -m pytest tests/test_governed_default_flip.py -v
```

Expected: **5 PASSED**.

- [ ] **Step 6: Run the full test suite to confirm no regressions**

```bash
python -m pytest -x
```

Expected: all existing tests pass. `test_decorators.py` module-level decorated
functions omit `pre_call_enforcement` — they now run in split mode, and all their
test assertions remain valid (valid invocations still succeed, bad roles still fail,
schema violations still raise).

- [ ] **Step 7: Run the linter**

```bash
flake8 aegis
```

Expected: no errors.

- [ ] **Step 8: Commit the runtime change**

```bash
git add aegis/_internal/decorators.py tests/test_governed_default_flip.py
git commit -m "feat(decorators): flip @governed default to pre_call_enforcement=True (PR-07)

Split enforcement is now the default execution model for @governed.
Passing pre_call_enforcement=False explicitly still works but emits
DeprecationWarning. Five migration tests land with the change."
```

---

## Task 4: Update `CHANGELOG.md`

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add a `Changed` section to `[Unreleased] — v0.3.3` and update `Planned`**

Find the `### Planned` section (currently around line 54) under `[Unreleased] — v0.3.3`.
Add a `### Changed` section immediately before `### Planned`, then update the
`Planned` section:

```markdown
### Changed

- **`@governed` default flip**: `pre_call_enforcement` now defaults to `True`.
  Split enforcement (Phase A before the model call, Phase B after) is the standard
  execution model for `v0.3.3+`. Existing call sites that omit `pre_call_enforcement`
  will now run in split mode.

  **Migration:** No change required for call sites that already pass
  `pre_call_enforcement=True`. Call sites that rely on unified mode must add
  `pre_call_enforcement=False` explicitly — this opt-out remains functional but
  emits `DeprecationWarning` and will be removed in a future release. Call sites
  that pass no flag and are unaffected by ordering (i.e., the fn has no side effects
  detectable before governance completes) can leave their code unchanged.

### Planned

- Workflow-aware governance groundwork: ADR-0010 accepted, release contract
  established, PR-01 through PR-07 complete.
```

Remove the old `Planned` entry:
```
- Upcoming: default flip to `@governed(pre_call_enforcement=True)`.
```

- [ ] **Step 2: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): record @governed default flip under v0.3.3 Changed"
```

---

## Task 5: Update `README.md`

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the decorator example (around line 137)**

The current block reads:

```
The decorator also supports split mode:

```python
from aegis import governed

@governed(
    policy_file="policies/base_policy.yaml",
    role="assistant",
    model_provider="anthropic",
    model_identifier="claude-sonnet-4-6",
    pre_call_enforcement=True,
)
def run_model(input_data, context):
    return model.generate(input_data)
```
```

Replace with:

```
The `@governed` decorator uses split enforcement by default (since v0.3.3):

```python
from aegis import governed

@governed(
    policy_file="policies/base_policy.yaml",
    role="assistant",
    model_provider="anthropic",
    model_identifier="claude-sonnet-4-6",
)
def run_model(input_data, context):
    return model.generate(input_data)
```

Phase A runs before the model call; Phase B validates output after. To keep the
legacy unified mode, pass `pre_call_enforcement=False` explicitly (deprecated).
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs(readme): update decorator example to reflect split-mode default"
```

---

## Task 6: Update `docs/INTEGRATION_GUIDE.md`

**Files:**
- Modify: `docs/INTEGRATION_GUIDE.md`

- [ ] **Step 1: Update the Decorator pattern section (around line 307)**

The current block reads:

```
### Decorator pattern

For decorator-based call sites, opt in with `pre_call_enforcement=True`:

```python
from aegis import governed

@governed(
    policy_file="policies/planner.yaml",
    role="planner",
    model_provider="anthropic",
    model_identifier="claude-sonnet-4-6",
    pre_call_enforcement=True,
)
async def plan_investigation(input_data: dict, context: dict) -> dict:
    return await llm.generate(input_data)
```

Phase A runs before the function body executes. If phase A fails, the function
is never called. Phase B runs after the function returns. Without
`pre_call_enforcement=True`, `@governed` behaves identically to previous releases.
```

Replace with:

```
### Decorator pattern

Since v0.3.3, `@governed` uses split enforcement by default:

```python
from aegis import governed

@governed(
    policy_file="policies/planner.yaml",
    role="planner",
    model_provider="anthropic",
    model_identifier="claude-sonnet-4-6",
)
async def plan_investigation(input_data: dict, context: dict) -> dict:
    return await llm.generate(input_data)
```

Phase A runs before the function body executes. If phase A fails, the function
is never called. Phase B runs after the function returns.

To use the legacy unified mode (function executes first, then governance validates):

```python
@governed(
    policy_file="policies/planner.yaml",
    role="planner",
    model_provider="anthropic",
    model_identifier="claude-sonnet-4-6",
    pre_call_enforcement=False,  # deprecated; will be removed in a future release
)
async def plan_investigation(input_data: dict, context: dict) -> dict:
    return await llm.generate(input_data)
```
```

- [ ] **Step 2: Commit**

```bash
git add docs/INTEGRATION_GUIDE.md
git commit -m "docs(integration-guide): update decorator section to reflect split-mode default"
```

---

## Task 7: Update `docs/PUBLIC_INTEGRATION_CONTRACT.md`

**Files:**
- Modify: `docs/PUBLIC_INTEGRATION_CONTRACT.md`

- [ ] **Step 1: Update the split enforcement decorator block (around line 851)**

The current block reads:

```
**Decorator opt-in:**

```python
@governed(
    policy_file="policies/my_policy.yaml",
    role="assistant",
    model_provider="anthropic",
    model_identifier="claude-sonnet-4-6",
    pre_call_enforcement=True,
)
def run_model(input_data, context):
    return model.generate(input_data)
```

When `pre_call_enforcement=True`, phase A runs before the wrapped function and
blocks execution on failure. Phase B runs after the function returns. Without
this parameter, `@governed` behaves identically to previous releases.

**Compatibility:** Unified mode (`enforce_invocation`, `enforce_invocation_async`,
`@governed` without `pre_call_enforcement`) is unchanged. No migration is
required for existing integrations.
```

Replace with:

```
**Decorator default (v0.3.3+):**

```python
@governed(
    policy_file="policies/my_policy.yaml",
    role="assistant",
    model_provider="anthropic",
    model_identifier="claude-sonnet-4-6",
)
def run_model(input_data, context):
    return model.generate(input_data)
```

Phase A runs before the wrapped function and blocks execution on failure. Phase B
runs after the function returns.

**Migration from v0.3.2:** Call sites that omit `pre_call_enforcement` now run in
split mode. Call sites that pass `pre_call_enforcement=True` are unchanged. Call
sites that rely on unified mode must add `pre_call_enforcement=False` explicitly;
this emits `DeprecationWarning` and will be removed in a future release. The
direct split APIs (`enforce_pre_call`, `enforce_post_call`) and unified API
(`enforce_invocation`, `enforce_invocation_async`) are unchanged.
```

- [ ] **Step 2: Commit**

```bash
git add docs/PUBLIC_INTEGRATION_CONTRACT.md
git commit -m "docs(contract): update split enforcement from opt-in to default contract"
```

---

## Task 8: Update `docs/architecture/ARCHITECTURAL_INVARIANTS.md`

**Files:**
- Modify: `docs/architecture/ARCHITECTURAL_INVARIANTS.md`

- [ ] **Step 1: Update the "Hosts that do not opt in" line (around line 255)**

Find and replace the single line:

```
Hosts that do not opt in to split mode are unaffected by this addition.
```

With:

```
Hosts using legacy unified mode via `pre_call_enforcement=False` are unaffected
by split mode internals; the pipeline ordering and artifact contract are unchanged.
```

- [ ] **Step 2: Commit**

```bash
git add docs/architecture/ARCHITECTURAL_INVARIANTS.md
git commit -m "docs(invariants): update split mode language to reflect default flip"
```

---

## Task 9: Update `PROJECT.md`

**Files:**
- Modify: `PROJECT.md`

- [ ] **Step 1: Move the default flip from "Upcoming" to the landed capability list (around line 244)**

Find the "Upcoming in this release" block:

```
Upcoming in this release:

- `@governed` default flip to `pre_call_enforcement=True`
```

Replace with (appending to the bullet list above it):

```
- `@governed` defaults to `pre_call_enforcement=True` — split enforcement is the
  standard execution model; legacy unified mode via `pre_call_enforcement=False`
  remains available but emits `DeprecationWarning` (PR-07)
```

And delete the now-empty "Upcoming in this release:" section heading.

- [ ] **Step 2: Commit**

```bash
git add PROJECT.md
git commit -m "docs(project): record @governed default flip as landed in v0.3.3"
```

---

## Task 10: Check off release gates in `RELEASE_GATES.md`

**Files:**
- Modify: `RELEASE_GATES.md`

- [ ] **Step 1: Mark PR-07 gates complete**

Find the PR-07 block:

```markdown
### PR-07 — Default Flip to Pre-Call Enforcement

- [ ] `@governed` defaults to `pre_call_enforcement=True`
- [ ] explicit `pre_call_enforcement=False` opt-out remains available
- [ ] one artifact per invocation attempt is preserved
- [ ] gate ordering is preserved
- [ ] migration tests land with the change
```

Replace all `- [ ]` with `- [x]`:

```markdown
### PR-07 — Default Flip to Pre-Call Enforcement

- [x] `@governed` defaults to `pre_call_enforcement=True`
- [x] explicit `pre_call_enforcement=False` opt-out remains available
- [x] one artifact per invocation attempt is preserved
- [x] gate ordering is preserved
- [x] migration tests land with the change
```

Also update the final release gate:
```markdown
- [ ] pre-call governance is the default execution model
```
→
```markdown
- [x] pre-call governance is the default execution model
```

- [ ] **Step 2: Commit**

```bash
git add RELEASE_GATES.md
git commit -m "docs(release-gates): check off all PR-07 gates"
```

---

## Task 11: Final verification

**Files:** none (read-only verification)

- [ ] **Step 1: Run the full test suite**

```bash
python -m pytest
```

Expected: all tests pass. Watch for any test that asserts
`enforcement_mode == "unified"` on a default-decorated function — those would
be regressions. There are none currently; confirm before merging.

- [ ] **Step 2: Run the linter**

```bash
flake8 aegis
```

Expected: no errors.

- [ ] **Step 3: Validate policy schemas**

```bash
python -c "
import json, yaml, jsonschema
from pathlib import Path
schema = json.load(open('schemas/policy_dsl.schema.json'))
for p in Path('policies').glob('*.yaml'):
    jsonschema.validate(yaml.safe_load(open(p)), schema)
    print(f'OK: {p}')
"
```

Expected: all `OK`.

- [ ] **Step 4: Review git log**

```bash
git log --oneline develop..HEAD
```

Expected: 8 commits (1 runtime + 7 docs).

---

## Self-Review Checklist

**Spec coverage:**

| Spec requirement | Task |
|-----------------|------|
| `@governed` defaults to `pre_call_enforcement=True` | Task 3 |
| explicit `pre_call_enforcement=False` opt-out remains available | Task 3 |
| one artifact per invocation attempt is preserved | Invariant — no enforcement change; split mode already produces one artifact |
| gate ordering is preserved | Invariant — no enforcement change |
| migration tests land with the change | Task 2 |
| `README.md` updated | Task 5 |
| `PROJECT.md` updated | Task 9 |
| `CHANGELOG.md` updated | Task 4 |
| `docs/INTEGRATION_GUIDE.md` updated | Task 6 |
| `docs/PUBLIC_INTEGRATION_CONTRACT.md` updated | Task 7 |
| `docs/architecture/AEGIS_HIGH_LEVEL_DESIGN.md` updated | Not needed — no `pre_call_enforcement` or split mode mentions in that file |
| `docs/architecture/ARCHITECTURAL_INVARIANTS.md` updated | Task 8 |

**Placeholder scan:** No TBD, TODO, or "similar to" patterns in this plan.

**Type consistency:** `_UNSET` sentinel is defined once at module level; the `elif not pre_call_enforcement` branch handles both `False` and any falsy value consistently.
