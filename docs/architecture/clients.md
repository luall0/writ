# Clients

Everything outside the daemon is **untrusted** ([design principle 1](../product.md#design-principles)):
clients make the workflow pleasant, the daemon makes it safe.

## Client list

| Client | Role |
|---|---|
| `writ` CLI | `request`, `sign`, `refuse`, `close`, `ls`, `revoke`, `unseal`, `init` (wires a repo's remote, URL rewrite and signing config) |
| Agent skill | Teaches the agent the ticket workflow: think through the scope before coding, write a ticket (task, plan, repos, branches, limits, template), submit it with `writ request`, wait for my decision; on refusal, revise using my feedback; on an out-of-ticket denial, submit an amendment; when done, `writ close` with a summary. Everything the agent writes in a ticket is shown to me as-is and never trusted by the policy engine |
| `writ try` | Borrowed from secrets-dispatcher: sets up a temporary local daemon and wires one repo, then restores everything on Ctrl-C. `--dry-run` lists every change first |
| `writ-sign` | `gpg.ssh.program` shim: `-Y sign` → daemon; `-Y verify` / `find-principals` → real `ssh-keygen` |
| Session agent (optional) | Holds the session key; on a Mac it can live in the Secure Enclave (no Touch ID) so it can't be copied |
| Harness integration | Omega Code requests a lease when an agent session starts and wires the repo's git config |
| Approvers | v1: `writ sign` + Secretive. Later: own Mac SE app, iPhone app |

Code: `crates/writ-cli` (`writ`), `crates/writ-sign` (`writ-sign`), `skill/writ/` (the
skill). The approver side of the CLI is described in [Approvals](approvals.md).

Denial reasons from the daemon reach the agent unchanged: `writ-sign` prints them on stderr
before exiting 1, and git shows the gateway's rejection message after a push.

## Repo setup on an agent host

```ini
# .git/config (written by `writ init` or the harness)
[remote "writ"]
    url = ssh://git@writ.home:2222/omega-code
[gpg]
    format = ssh
[gpg "ssh"]
    program = writ-sign
[user]
    signingkey = key::<agent public key>
[core]
    sshCommand = ssh -i ~/.writ/sessions/current/key -o CertificateFile=~/.writ/sessions/current/key-cert.pub
```

Agents never get a remote pointing at the real forge with credentials. With `gateway` or
`proxy` push modes, `writ init` can also write the [URL rewrite](gateway.md#url-rewrite) so
`origin` keeps working.
