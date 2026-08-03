# B3 Publish Authorization

Date: 2026-08-03

Change ID: `b3-publish-authorization`

The repository owner selected finishing option 2 and then explicitly authorized
the required policy change. The authorization is scoped to pushing
`codex/b3-chain-before-sign-linker` at commit `9263d0c` or its evidence-only
successor and opening one draft pull request against `main` in
`nealsolves/aegis`.

The operational change temporarily sets these local controls to `true`:

- `remote_actions.enabled`
- `remote_actions.push_branch`
- `remote_actions.open_pull_request`

All other remote and production actions remain disabled. The temporary control
diff is not committed or included in the pull request. After the push and PR
creation attempt, the three controls are restored to `false` and the restored
control plane is revalidated. This is a one-time operational authorization, not
a standing expansion of future remote-action authority.

The committed control-plane version remains unchanged because the repository's
persisted behavior and schema are unchanged. The before/temporary/after
validation and decision outputs are recorded in the execution evidence.
