# Clients

Everything outside the daemon is **untrusted** ([design principle 1](../product.md#design-principles)):
clients make the workflow pleasant, the daemon makes it safe.

## Client list

| Client | Role |
|---|---|
| `writ` CLI | `request`, `sign`, `refuse`, `close`, `ls`, `revoke`, `unseal`, `init` (wires a repo: [repo setup](#repo-setup-on-an-agent-host)), `git` and `exec` (git, or a program, with that wiring) |
| Agent skill | Teaches the agent the ticket workflow: think through the scope before coding, write a ticket (task, plan, repos, branches, limits, template), submit it with `writ request`, wait for my decision; on refusal, revise using my feedback; on an out-of-ticket denial, submit an amendment; when done, `writ close` with a summary. Everything the agent writes in a ticket is shown to me as-is and never trusted by the policy engine |
| `writ try` | Borrowed from secrets-dispatcher: sets up a temporary local daemon and wires one repo, then restores everything on Ctrl-C. `--dry-run` lists every change first |
| `writ-sign` | `gpg.ssh.program` shim: `-Y sign` → daemon (the gateway's `writ-sign git <repo>` command for the repo in `writ.repo`, reached at `writ.url` with the SSH command git uses: `GIT_SSH_COMMAND`, then `core.sshCommand`, never a plain `ssh`), with the parent commits and trees the daemon needs to see which paths the commit touches ([Gateway](gateway.md#signing)); everything else (`-Y verify`, `find-principals`) → real `ssh-keygen` |
| Session agent (optional) | Holds the session key; on a Mac it can live in the Secure Enclave (no Touch ID) so it can't be copied |
| Harness integration | Omega Code requests a lease when an agent session starts and wires the repo's git config |
| Approvers | v1: `writ sign` + Secretive. Later: own Mac SE app, iPhone app |

Code: `crates/writ-cli` (`writ`), `crates/writ-sign` (`writ-sign`), `skill/writ/` (the
skill). The approver side of the CLI is described in [Approvals](approvals.md).

`writ` reads its settings from flags or environment variables: `WRIT_URL` (agents' listener,
`ssh://host:port` or `unix:<path>`), `WRIT_APPROVAL_URL` (approval listener: `https://host:port`, `ssh://host:port` or `unix:<path>`),
`WRIT_APPROVAL_KEY` (the approval key's public half, default `~/.writ/approver.pub`),
`WRIT_APPROVAL_AGENT` (its agent socket, default `SSH_AUTH_SOCK`), `WRIT_HOME` (default
`~/.writ`), `WRIT_KNOWN_HOSTS` (default `~/.writ/known_hosts`, where the daemon's host key
is pinned; `writd host-key` prints it), `WRIT_TLS_PINS` (default `~/.writ/tls_pins`, lines
`[host]:port SHA256:…` pinning the HTTPS certificate; `writd tls-fingerprint` prints it) and
`WRIT_READER` (default `~/.writ/reader`: the key the approval API lets in; `writ reader
[<name>]` makes it on first use and prints the line for the daemon's `readers` file), and
`WRIT_SSH_KEYGEN` (the ssh-keygen `writ sign` runs, an absolute path; default
`/usr/bin/ssh-keygen`, never looked up in `PATH`). It never reads `~/.ssh` or uses the user's ssh-agent
for connections: it would offer personal keys to the daemon. Exit statuses: 0 done, 1 error,
3 rejected by policy, 4 refused, 5 expired or withdrawn, 6 not signed (`writ sign` answered no).

Denial reasons from the daemon reach the agent: `writ-sign` prints them on stderr (escaped,
like any text from elsewhere) before exiting 1, and git shows them; git shows the gateway's
rejection message after a push. When ssh itself fails (the gateway refuses an expired, revoked
or unknown certificate during authentication, where SSH can't say why), `writ-sign` reads the
session certificate named in the SSH command and says whether there is no lease, an expired
one, or one the daemon refused: a convenience, the daemon decided already.

## Repo setup on an agent host

`writ init <repo>` wires the repository it runs in, in one of two modes. Both use the same
settings (`writ_cli::wiring::settings`), and what `writ init` did is recorded in
`<git common dir>/writ/config`: never in the working tree, so it can't be committed.

**Wrapper mode (the default)**: nothing in the repo's git config changes. The agent runs every
git command through `writ git …` (commit, rebase, cherry-pick, `commit --amend`, fetch, push,
log…), or a program that runs git through `writ exec -- <program>`; the settings below reach
git through the environment (`GIT_CONFIG_COUNT`, git ≥ 2.31, and `GIT_SSH_COMMAND`), for that
process and what git runs (`writ-sign`, `ssh`, hooks). The operator's own `git`, in the same
clone and working tree, keeps the operator's keys, email and remotes; a plain `git push writ`
finds no such remote. Commits a command rewrites (a rebase) are signed again, one signature
each from `max_signatures`.

**Whole repo** (`writ init <repo> --whole-repo`): the same settings written in the repo's
config, for a clone dedicated to an agent (a VM, a container); plain `git` is then the agent's
git. The values they replace are recorded first.

`writ init --undo` takes either back exactly: the record removed, and in whole-repo mode every
key restored as it was. Good practice for the operator (their own keys, guardrails in the
agent's configuration): the [operator guide](../guides/operator.md).

```ini
# The settings, as --whole-repo writes them (writ init omega-code); <home> is WRIT_HOME
[remote "writ"]
    url = ssh://git@writ.home:2222/omega-code.git
    fetch = +refs/heads/*:refs/remotes/writ/*
[writ]
    url = ssh://git@writ.home:2222      # where writ-sign sends commits to sign
    repo = omega-code                   # the repo they are for (a registry name)
[gpg]
    format = ssh
[gpg "ssh"]
    program = /path/to/writ-sign        # next to `writ`, or `writ-sign` in PATH
[user]
    signingkey = <home>/sessions/current/signing_key.pub
    email = user+agent@example.org      # --email, or the lease's when it allows one
[commit]
    gpgSign = true
[tag]
    gpgSign = false                     # tags are never signed by the daemon
[core]
    sshCommand = ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none -i '<home>/sessions/current/key' -o 'CertificateFile=<home>/sessions/current/key-cert.pub' -o 'UserKnownHostsFile=<home>/known_hosts' -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes
```

Paths are absolute and quoted for `sh`, and point at `<home>/sessions/current`: a wired repo
follows whichever lease is current. In wrapper mode they are computed each time from
`WRIT_HOME`, and the email is the current lease's unless `--email` was given. Each commit
needs a `Writ: <lease>` trailer when the repo's `ticket_link` is `trailer`
(`git commit --trailer "Writ: wrt_…"`); `writ init` prints the current lease's. Only `ssh://`
endpoints for now (a Unix socket comes with local mode).

The SSH command never reaches the user's own SSH setup: no `~/.ssh/config` (`-F /dev/null`), no
other key and no agent (`IdentitiesOnly`, `IdentityAgent=none`: Secretive's keys are never
offered), no prompt (`BatchMode`), and only the daemon's pinned host key (`known_hosts`, no
global file). `writ-sign` uses the same command (`GIT_SSH_COMMAND`, then `core.sshCommand`)
and refuses to sign when neither is set: it never falls back to a plain `ssh`.

Agents never get a git remote pointing at the real upstream (GitHub, Codeberg, Forgejo…)
with credentials. With `gateway` or
`proxy` push modes, `writ init` can also write the [URL rewrite](gateway.md#url-rewrite) so
`origin` keeps working (in wrapper mode, passed the same way: `writ git push origin` goes
through the daemon, the operator's `git push origin` doesn't).
