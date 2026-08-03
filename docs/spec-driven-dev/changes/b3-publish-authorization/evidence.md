# B3 Publish Authorization — Execution Evidence

Date: 2026-08-03

Change ID: `b3-publish-authorization`

## Human authority

- The repository owner selected option 2: push the B3 branch and create a pull
  request.
- After the standing remote-action prohibition was reported, the owner replied
  `authorized`.
- Scope is bounded by `proposal.md`; no merge, release, deployment, production
  action, or permanent control-plane widening is authorized.

## Validation

- Prior trusted base: B3 completion commit `9263d0c`; the committed standing
  controls disable every remote action.
- Prior control-plane validation returned `valid: true`.
- `evaluated_by_policy_hash`:
  `d0416dab300bbcfbf7fba95bb51b1d1aeda7725d945560d0fbb0ce4f3dc6a3fa`.
- Proposed temporary `policy_hash`:
  `8c9a52cd45cee4c75d72650d5c41dc2ae089992fb447f649f69ddad67d3fb5c9`.
- Change/context hashes at the human decision:
  `510b159ba64c865c4a971e22420f1bf13c101af0b85b443d8c6dd6cb6df48018` /
  `98033906e867a98c164fcfd8ba745e52c531f17a24d60b75fcc9cdcee8a8f4e2`.
- The prior trusted policy returned `human_required`; the recorded owner
  response selected `authorize_once`, and deterministic response ingestion
  returned `autonomous_with_enhanced_gates`.
- The temporary proposed control plane returned `valid: true`.
- The affected policy fixture passed 6 tests against the temporary expected
  value. A direct closed-scope assertion confirmed only branch push and PR
  creation were enabled; update, merge, release, production deployment, and
  all other production actions remained disabled.
- The control-plane version remains unchanged because the temporary diff is
  excluded from commits and the final persisted behavior remains disabled.

## Outcome

The remote operation did not begin. `gh auth status` reported that the active
`nealsolves` GitHub token is invalid, so the required publishing prerequisite
failed before any push or PR creation. The temporary control and fixture diffs
were restored to their committed disabled values. Restored-state validation
passed, and no branch data was sent to a remote.
