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

The temporary configuration will be restored to the default disabled state
after release and deployment verification.

## Promotion, deployment, and publication

PR #23 promoted the verified `origin/develop` baseline to `main` at merge
commit `22457bcaeef89495031ac8a01a22d3c36e9818ee`. This made the Pages and
Trusted Publishing workflows available on the protected default branch before
the main-only selector cutover.

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

Final remote commit, deployment, workflow, and PyPI artifact identifiers remain
pending observed evidence.
