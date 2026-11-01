# Clients

Everything outside the daemon is **untrusted** ([design principle 1](../product.md#design-principles)):
clients make the workflow pleasant, the daemon makes it safe.

## Client list

| Client | Role |
|---|---|
| `writ` CLI | `request`, `sign`, `refuse`, `close`, `ls`, `revoke`, `unseal`, `init` (wires a repo's remote, URL rewrite and signing config) |
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

```ini
# .git/config (written by `writ init` or the harness)
[remote "writ"]
    url = ssh://git@writ.home:2222/omega-code
[writ]
    url = ssh://git@writ.home:2222      # where writ-sign sends commits to sign
    repo = omega-code                   # the repo they are for (a registry name)
[gpg]
    format = ssh
[gpg "ssh"]
    program = writ-sign
[user]
    signingkey = key::<agent public key>
[core]
    sshCommand = ssh -F /dev/null -o IdentitiesOnly=yes -o IdentityAgent=none -i ~/.writ/sessions/current/key -o CertificateFile=~/.writ/sessions/current/key-cert.pub -o UserKnownHostsFile=~/.writ/known_hosts -o StrictHostKeyChecking=yes
```

The SSH command never reaches the user's own SSH setup: no `~/.ssh/config` (`-F /dev/null`), no
other key and no agent (`IdentitiesOnly`, `IdentityAgent=none`: Secretive's keys are never
offered), and only the daemon's pinned host key (`~/.writ/known_hosts`). `writ-sign` uses the
same command (`GIT_SSH_COMMAND`, then `core.sshCommand`) and refuses to sign when neither is
set: it never falls back to a plain `ssh`.

Agents never get a remote pointing at the real forge with credentials. With `gateway` or
`proxy` push modes, `writ init` can also write the [URL rewrite](gateway.md#url-rewrite) so
`origin` keeps working.
