# Design: Re-scope the checkpoint architecture tripwire (Issue #46, Task 8)

> **STATUS: ABANDONED — NOT IMPLEMENTED (2026-08-06).** The human decision was
> to stop fixing Task 8, accept the existing `a8738ee` analyzer as-is (with its
> documented residuals), and move to Task 9. This re-scope was never built. It
> is retained only as a record of the approach explored and why it was dropped.
> Two reasons: (1) the round-by-round grind was judged not worth further effort;
> (2) the design's Section 3 premise is stale — the pre-existing
> `_checkpoint_callable_dependency_closure` /
> `test_every_callable_closure_module_is_capability_reviewed` infrastructure
> already scans `canonicalization`, `chain_linker`, and `evidence_profiles`,
> which Section 3 claims are "currently unscanned." See the SDD ledger
> (`.superpowers/sdd/2026-08-04-issue-46-trusted-checkpoints/progress.md`) for
> the accepted residuals and compensating control.

- **Date:** 2026-08-06
- **Status:** ABANDONED — not implemented (was: Approved design, pending spec review)
- **Scope:** `tests/test_architecture_security_boundaries.py` — the two AST entry
  points `_checkpoint_boundary_violations_for_source` and
  `_checkpoint_callback_order_violations_for_source`, their supporting helpers,
  the scanned-module set, and their guard/regression tests.
- **Human decisions this design implements:** D-46-08-R7 = *Stop + re-scope the
  tripwire*; contract = *Allowlist conformance*; closure = *A-full* (full
  in-package transitive closure).

## Problem

The current tripwire attempts sound static taint analysis of arbitrary future
edits to the checkpoint modules by enumerating *unsafe syntactic shapes*. Three
consecutive adversarial rounds (5, 6, 7) each found new shapes the enumeration
did not cover (dict/attribute/method-dispatch aliases, capability-returning
methods, container/attribute-stored capabilities). The approach cannot converge:
proving that an arbitrary expression does not evaluate to a capability is
undecidable, so any denylist of shapes is perpetually incomplete and fails
*open* (returns "no violation" for source that actually violates).

The human decision is to stop the round-by-round grind and re-scope to a
robustly bounded check that **fails closed by default**, plus documented
reliance on code review for anything outside the bounded surface.

## Design principle

Stop trying to prove an expression is safe. Instead, assert the checkpoint
modules stay inside a small, explicitly permitted vocabulary of *mechanisms*,
and **trip on everything else**. Every rule below is an allowlist: unknown or
unrecognized constructs fail closed. This deliberately trades **false-positive
churn** (benign edits may trip the tripwire until an allowlist entry is added in
a reviewed change) for the **elimination of fail-opens**. That tradeoff is the
explicit intent of decision D-46-08-R7.

## Why the obvious simpler idea was rejected

An earlier draft proposed a *denylist* of capability tokens (`open`, `eval`,
`__builtins__`, …). An adversarial review of that draft rejected it: the set of
dangerous reflection names is open-ended
(`().__class__.__bases__[0].__subclasses__()` reaches any builtin via
`__bases__`, which no fixed list fully covers), so a name denylist is the same
whack-a-mole transposed from the syntactic axis to the name axis. It cannot
converge and contradicts the chosen "allowlist conformance" contract. The design
below is therefore an allowlist of *mechanisms*, not a denylist of *names*.

## Section 1 — Capability containment (allowlist of mechanisms)

Replaces the taint tracer in `_checkpoint_boundary_violations_for_source`. Three
closed rules evaluated over every scanned module (see Section 3 for the set):

1. **Import allowlist.** A scanned module may import only from an explicit
   permitted set: safe standard-library modules actually used by the checkpoint
   path (e.g. `__future__`, `typing`, `enum`, `dataclasses`, `hashlib`, `hmac`,
   `json`) plus the in-package (`aegis.*`) modules that are themselves in the
   scanned set. Any other import trips. This subsumes and replaces the existing
   `_FORBIDDEN_CHECKPOINT_IMPORT_PREFIXES` denylist.
2. **Reflection ban.** Any `ast.Attribute` whose attribute name matches the
   dunder pattern `__.*__`, and any reference to `getattr`, `setattr`,
   `delattr`, `vars`, `globals`, or `locals`, trips — except a tiny allowlist of
   dunder attribute names populated only from real production need, one
   documented comment per entry. (Production uses `type(x) is dict`,
   `.to_dict()`, `.keys()`, `.value`; none are dunder attribute *access*, so few
   or zero exceptions are expected. Method *definitions* named `__init__`/`__eq__`
   are `FunctionDef` names, not attribute access, and are unaffected.)
3. **Builtin-call allowlist.** A bare-name call that resolves to a Python builtin
   (a free `Name` that matches `builtins`, is not locally bound, imported, or
   defined in the module) must be in an allowlisted safe subset (e.g. `type`,
   `len`, `dict`, `tuple`, `frozenset`, `set`, `list`, `enumerate`, `isinstance`,
   `bool`, `str`, `int`, `sorted`, `range`, `min`, `max`). Because builtins are a
   closed, version-stable set, this is a genuine allowlist: `eval`, `exec`,
   `compile`, `open`, `__import__`, `input`, `breakpoint`, `getattr`, `setattr`,
   `delattr`, `globals`, `locals`, `vars` all fall outside it and trip.

The existing mutable-global containment (the immutable-referent rule in
`_deeply_immutable_global`, already passing) is retained unchanged.

## Section 2 — Preflight ordering

Replaces the taint/alias resolution in
`_checkpoint_callback_order_violations_for_source` with three rules:

1. **Indirection ban.** Within the analyzed function, the boundary callable
   (matched by name/attribute) may appear only as the direct callee of a `Call`.
   Any other position — assigned to a variable, stored in a container, returned,
   passed as an argument, subscripted — trips. This is the surviving win from the
   prior rounds: it kills every aliasing/wrapping shape at the source, because
   indirecting a callable requires referencing it in a non-call position.
2. **Boundary-presence assertion.** The check fails closed if the analyzed
   function contains **zero** direct boundary calls. Relocating the boundary call
   (e.g. moving `signer.sign(...)` into a helper) is an ordinary refactor that
   would otherwise make the check pass vacuously; the presence assertion turns
   that into a trip, forcing either a reviewed update of the
   `(function, boundary)` tuple or a revert.
3. **Fail-closed dominance.** Each direct boundary call must be dominated by an
   unconditional preflight call occupying one of a small allowlist of
   provably-dominating positions (e.g. an earlier statement in the same block; a
   function-top statement before any boundary call). Anything not on the
   allowlist — assert-gated, `contextlib.suppress`-gated, conditional-only, or
   nested in a skippable block — trips. Because the direction is fail-closed,
   mistakes in this allowlist yield false positives, never fail-opens.

## Section 3 — Self-closing module set

The scanned set stops being "three named files + a `*checkpoint*.py` glob + a
hand-listed tail." Instead:

1. **Anchor** at the public checkpoint facade (`aegis/checkpoints.py`) and the
   verification entry modules.
2. **Import-closure invariant (test).** Every in-package (`aegis.*`) import in
   every scanned module must target a module that is also in the scanned set. If
   a scanned module imports an in-package module not in the set, that trips — so
   the set is provably import-closed. A new helper module
   (`aegis/_internal/signing_helpers.py`) cannot be reached without being added
   to the set, and being in the set means it is scanned under Section 1.
3. **Consequence (A-full).** Full in-package transitive closure. This pulls
   `canonicalization.py`, `chain_linker.py`, `evidence_profiles.py`, and their
   transitive in-package imports into the scanned set — they are reachable from
   checkpoint creation today and currently unscanned. Each must then conform to
   Section 1. The one-time conformance cost is bounded because these are pure
   data-transform modules; A-full is chosen over a bounded "near-the-boundary"
   closure to avoid a heuristic that could itself be wrong.

## Section 4 — Scope statement (documented reliance on review)

The design doc and the two entry-point docstrings state plainly what the
tripwire does **not** prove, so it is not over-trusted:

- It does **not** prove the preflight still *validates* anything. A preflight
  body could be gutted while all three ordering proxies stay green. Behavioral
  tests and code review own that property.
- It does **not** defend against a source owner who edits the checkpoint modules
  *and* the test's allowlists together. This is the accepted residual, unchanged
  from prior rounds: an attacker who can rewrite `aegis._internal` already
  exceeds any checkpoint-API authority.
- The convergence claim is scoped honestly: the design defeats the
  aliasing/wrapping, out-of-set-module, and boundary-relocation families that
  actually recurred — not "any conceivable construct." Exotic reflection chains
  and out-of-set modules are closed by Sections 1 and 3 respectively; anything
  beyond that folds into the accepted source-owner residual.

## Testing approach (witnessed TDD)

- Every current RED (violation) test must still trip under the new checks and is
  retained as regression coverage, including the four round-7-adversarial shapes
  (dict-value alias, attribute-stored handler, method-dispatched capability,
  attribute-stored capability).
- New RED tests are added for the newly closed families: out-of-set module
  import (import-closure trip), relocated boundary (presence-assertion trip),
  reflection-name access (reflection-ban trip), non-allowlisted builtin call, and
  non-allowlisted import.
- Shape-specific accept-tests that existed only to demonstrate the taint
  tracer's *precision* are pruned; the production-conformance guards
  (`test_checkpoint_trust_boundary_modules_pass_robust_capability_analysis` and
  `test_checkpoint_real_callbacks_remain_after_preflight_under_alias_analysis`)
  are retained and must remain green after the scanned set expands.
- Each change follows RED → GREEN → REFACTOR with the failure observed before
  the fix. Gates: full suite via `../../.venv/bin/python -m pytest`, `compileall`,
  and `flake8` on changed files.

## Out of scope

- No change to production checkpoint creation/verification behavior; this is a
  test-only re-scope of the tripwire.
- Task 9 (ADR-0015 documenting the tripwire contract, README, CHANGELOG) remains
  gated behind acceptance of this re-scope.
- Task 10 (final adversarial verification) remains gated.

## Acceptance

The re-scope is accepted when fresh independent regular and adversarial
acceptance reviews both pass: the adversarial reviewer's aliasing/wrapping/
relocation/out-of-set shape attacks must all trip (fail closed), and the
production-conformance guards must remain green with no false positives on the
real checkpoint modules.
