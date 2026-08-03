# B3 Publish Authorization Retry

Date: 2026-08-03

Change ID: `b3-publish-authorization-retry`

After GitHub CLI authentication completed, the repository owner issued a
second explicit `authorized` instruction. This fresh authorization permits one
retry that pushes `codex/b3-chain-before-sign-linker` and opens one draft pull
request against `main` in `nealsolves/aegis`.

The retry temporarily enables only `remote_actions.enabled`, `push_branch`, and
`open_pull_request` in the local control plane. Update, merge, release, and all
production actions remain disabled. The temporary control diff is excluded
from commits and restored immediately after the push and PR attempt. The
persisted control-plane version and disabled defaults remain unchanged.
