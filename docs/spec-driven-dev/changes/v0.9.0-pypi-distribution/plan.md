# AEGIS v0.9.0 Distribution Implementation Plan

**Change ID:** `v0.9.0-pypi-distribution`

**Workflow:** Brownfield release preparation

**Strategy:** Characterize the existing source-only release contract, introduce
the new distribution contract test-first, build once, and prove the installed
wheel in a source-isolated environment. Publication remains out of scope.

## Phase 1 — Classification and Characterization

1. Record typed facts and evaluate policy for the approved specification.
2. Characterize current metadata, release-parity checks, package contents, and
   the existing PR-11 packaging proof.
3. Inventory maintained documents that state the install name or current
   release.
4. Inventory the exact default workflow journey and its CLI/script entry
   points.

Exit gate: policy evaluation, brownfield inventory, and affected-consumer list
are recorded.

## Phase 2 — Failing Distribution Contracts

1. Add a test asserting source distribution name `aegis-ai-governance`.
2. Add a test asserting source/runtime version `0.9.0b1`.
3. Add artifact tests for wheel/sdist filenames, metadata, entry point,
   dependencies, schemas, and `py.typed`.
4. Add a fresh-wheel test that rejects checkout imports.
5. Add or extend the end-to-end workflow proof for minimal, standard,
   regulated failure/doctor/fix, trace, and exports.
6. Run each new contract and observe its expected pre-implementation failure.

Exit gate: red evidence exists for every changed contract.

## Phase 3 — Minimal Metadata and Release Truth

1. Change `pyproject.toml` project name and version.
2. Change `aegis.__version__`.
3. Update parity scripts and their tests without weakening existing frozen
   public contracts.
4. Update maintained documentation identified in Phase 1.
5. Keep runtime dependencies and import/CLI/package discovery unchanged.

Exit gate: focused source metadata and release-truth tests pass.

## Phase 4 — Reproducible Artifact Proof

1. Add `build` and `twine` only to release/dev tooling where required; do not
   add them to runtime dependencies.
2. Build wheel and source distribution into an isolated output directory.
3. Validate artifacts with `twine check` and direct metadata inspection.
4. Install the wheel in a new Python 3.12 environment.
5. Execute the complete specification journey with source isolation.
6. Produce a machine-readable and human-readable proof summary.

Exit gate: artifact and workflow proof passes from the built wheel.

## Phase 5 — Trusted Publishing Workflow

1. Add `.github/workflows/publish.yml`.
2. Pin all actions to immutable revisions.
3. Build and validate in a job with read-only repository permissions.
4. Transfer artifacts to a separate publish job.
5. Grant `id-token: write` only to the publish job.
6. Bind the publish job to environment `pypi`.
7. Validate tag/version equality and artifact hashes before publication.
8. Test workflow structure locally; do not trigger it.

Exit gate: workflow matches the pending publisher and policy keeps
`create_release` prohibited.

## Phase 6 — Validation, Review, and Release Readiness

Run and record:

1. spec-driven policy validation and lifecycle gates;
2. focused metadata/artifact/E2E tests;
3. full Python suite;
4. Python lint;
5. demo API suite;
6. React suite and production build;
7. clean artifact rebuild and digest calculation;
8. package metadata validation;
9. dependency and workflow security review;
10. independent correctness, test-adequacy, and convergence review.

Resolve all bugs and material risks. Stop at `RELEASE_READY` with exact
artifact identity, checks, digests, rollback, and the separately disabled
publication action.
