# AEGIS v0.9.0b1 Main Cutover and PyPI Release Evidence

**Change ID:** `v0.9.0-main-pypi-release`

**Owner approval:** Neal Bhattacharya explicitly requested the `main`
deployment cutover, PyPI publication, live Render and Pages verification, and
thorough functional testing in Codex task
`019f9b8a-ebdb-7fd3-b090-562f25745b56`.

## Frozen baseline

- `origin/develop`: `f2d9acfad4c584d94e1bd0a335e0321c34be7378`
- `origin/main`: `0ddcee9bb08c850a340d6938124a415948906c57`
- Candidate: `aegis-ai-governance==0.9.0b1`
- Python: 1,923 passed, 2 skipped
- React: 105 passed
- Flake8: passed
- React lint: passed
- React production build: passed with
  `VITE_API_URL=https://aegis-demo-api.onrender.com`
- Fresh-wheel end-to-end validation: passed
- Baseline wheel SHA-256:
  `79545eb2c1ce66282ef25935f594bcc9d56cd42f688aa3ae99105e9bd116b69b`
- Baseline sdist SHA-256:
  `a3fd356a8c5b8c471bdf8423600f47809291bb0eddaf4aa60da02956a6324656`

## Bounded authority

The default remote and production controls were valid and disabled at the
branch base. The proposed temporary configuration is also valid and permits
only repository PR/release operations plus the named AEGIS public-demo
deployment and rollback mechanisms. The exact proposed diff hash is:

`8c5b9fa0505e6a14252c2733dbe6c4163928dc797b661c48a686999424a97b67`

The temporary configuration was restored to the default disabled state before
the final verification pass.

## Promotion, deployment, and publication

PR #23 promoted the verified `origin/develop` baseline to `main` at merge
commit `22457bcaeef89495031ac8a01a22d3c36e9818ee`. This made the Pages and
Trusted Publishing workflows available on the protected default branch before
the main-only selector cutover.

PRs #24 and #25 promoted the main-only deployment selector cutover through
`develop` and `main`. PRs #26 and #27 then corrected stale prerelease copy
found by the live browser check. The resulting `main` merge commit was
`b72436c3d1dfe2ab7dabf23962bbd07dd1d4b077`.

The GitHub Pages production environment was changed from a `develop` branch
policy to a `main` branch policy. Pages runs `30179744636` and `30179937483`
completed successfully, with the latter publishing the corrected portal from
`main`.

## Main-only cutover pre-merge proof

- Default project authority restored and verified unchanged before the final
  full-suite run.
- Python: 1,923 passed, 2 skipped, 14 warnings.
- Demo API: 67 passed.
- React: 105 passed.
- Flake8: passed for `aegis`, matching `publish.yml`.
- React lint: passed.
- React production build: passed with
  `VITE_API_URL=https://aegis-demo-api.onrender.com`.
- Documentation parity, brand/version parity, public-import boundary,
  release-freeze, and deterministic diagram regeneration: passed.
- Clean-environment quickstart harness: all gates passed in 0.55 seconds,
  below the 900-second budget.
- Fresh isolated wheel workflow: dependency check, minimal, standard, and
  regulated profiles, doctor/fix loop, trace, audit/operator/compliance
  exports, and credential-removal checks passed.
- Final local pre-merge wheel SHA-256:
  `ddcdf1343b93586da682e3fa8072881a63872f06eeeaf960632372168997c030`
- Final local pre-merge sdist SHA-256:
  `d819f23bf8e027aa9f0e678ac25adf153b95837b8ba350f4352d11ca2e1e25c7`

## Publication and installed-package proof

The first prerelease workflow run, `30180008202`, failed safely during its
fresh-wheel proof before any upload. The Python 3.12 runner did not have the
declared setuptools build backend available to the non-isolated build step.
PRs #28 and #29 added the backend explicitly, retained editable source test
dependencies without installing a physical source package, and added a
workflow regression test. The repair reached `main` at
`c116b1cfd4a953b153d1d5c3eb117b23116d22f7`.

Replacement Trusted Publishing run `30180227219` passed validation, the full
test suite, package build, fresh-wheel isolation, artifact handoff, and PyPI
publication. GitHub prerelease `v0.9.0b1` and PyPI distribution
`aegis-ai-governance==0.9.0b1` both resolve to that release source.

- Published wheel SHA-256:
  `7d86b4e6fccdef777b215ea95ae440636038c397044bd371b10e1f3bc43125b7`
- Published sdist SHA-256:
  `a85c59fb28e2f7f13697c0fb3fc090d02dc69d1e91da57a3ed8c920b9c25ce26`
- The workflow artifacts and PyPI JSON digests match exactly.
- A clean Python 3.12 environment installed the public PyPI wheel from outside
  the repository; both distribution and runtime versions reported `0.9.0b1`,
  and the imported package path was inside that environment's
  `site-packages`.
- `aegis --help`, `aegis workflow init --profile minimal`, and the generated
  two-step starter workflow completed successfully.

## Final functional evidence

- Python: 1,925 passed, 2 skipped, 14 warnings.
- Demo API: 68 passed.
- React: 105 passed; lint and production build passed.
- The live Pages portal stated that the beta is released from `main` and
  published on PyPI.
- Live Lab 1 produced the expected split pre-call block with no browser console
  errors.
- Live Lab 11 completed its minimal two-step governed workflow with no browser
  console errors.
- The public Render health endpoint remained healthy. It now exposes Render's
  `RENDER_GIT_BRANCH` and `RENDER_GIT_COMMIT` values so the final live response
  is an externally observable proof of the branch selector and deployed
  revision.
- The default project authority file is restored and has no repository diff.

The final Render branch and commit are verified from the live `/health`
response after this observability change reaches `main`; that response is the
authoritative deployment record because recording it in another commit would
itself create a newer deployable revision.
