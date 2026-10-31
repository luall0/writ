# Gateway, mirrors and upstream

The daemon is the agents' git remote and the only thing that pushes upstream. That is what
makes repo, destination ref and pushed content strong, forge-agnostic checks
([threat model, boundary 2](../threat-model.md#2-policy-strong-because-the-daemon-is-the-git-server)).

Code: `crates/writ-gateway` (SSH server), `crates/writ-git` (mirrors, quarantine, upstream).

## Gateway (SSH server)

The single entry point to the daemon. It serves connections from any `Transport`, with what
the `CallerAttestor` says about each caller (a caller it can't attest is turned away), and
each listener has a role:

| Listener (role) | SSH user and authentication | Commands |
|---|---|---|
| agents | `git` + an **SSH user certificate** issued by the daemon for an active lease ([Identity](identity.md#session-identity)) | **git** `upload-pack` (fetch) and `receive-pack` (push), so a plain `git fetch/push writ` works; **sign** for the `writ-sign` shim (full commit object in, armored SSHSIG out) |
| agents | `writ` + a plain key: the session key of a ticket | **lease** commands: `writ request` (submit the ticket on stdin), `writ wait <id>` |
| approvals (SSH) | any user, a key listed in the daemon's `readers` file (a certificate is refused) | the approval API: `writ info`, `ls`, `show`, `approve`, `refuse`, `revoke` ([Approvals](approvals.md#reaching-the-daemon)) |
| approvals (HTTPS) | mutual TLS 1.3: the daemon's pinned self-signed certificate, and a client certificate for a key in `readers` | the same API as `GET`/`POST` routes (`crates/writ-gateway/src/https.rs`) |

Each listener accepts connections only from its configured sources (`allow` in
`writd.yaml`, required on the agents' TCP listeners), and bounds what any peer can make it
hold (`crates/writ-gateway/src/limits.rs`): 256 open connections per listener and 16 per
source address, 20 seconds to authenticate (or to finish the TLS handshake), 4 channels at
once per SSH connection, 30 seconds to send a request body, 10 minutes without traffic. A
denial before authentication (a source not allowed, no free slot, a key not in `readers`,
a refused certificate) writes one audit line per source and minute, with the count of the
others; text the peer chose (a certificate's key id) is cut to 64 characters.

A certificate is checked twice: when it is presented (CA, validity, deny list, principal
`git`, then the approval service finds its single active lease and checks the caller,
logged as `connect`) and before each command, with the operation the command needs (fetch,
push, commit_sign). When a lease ends (revoked, expired, exhausted), the gateway drops every
open session of its certificate. Replies of `writ` commands are one JSON line on stdout
(`writ_proto`), with the reason on stderr when they fail.

Every request goes through the [policy engine](policy-and-state.md#policy-engine) before
anything else happens. Git itself is not reimplemented: the daemon shells out to
`git upload-pack` / `git receive-pack` / `git index-pack` against its own repositories.

Anything else is refused with a reason on stderr, and logged (event `command`). Repos are
registry names, with or without `.git` (`omega-code.git`), never paths; git runs only on a repo
in the lease's `scope.repos`, at `<repos_root>/<name>.git`. Only `GIT_PROTOCOL` is taken from
the client's environment, and git runs with a clean environment (`PATH` and `TMPDIR` only),
without the daemon user's system or global git config.

## Push checks in git's quarantine

`git receive-pack` keeps the pushed objects in a quarantine directory and runs the
pre-receive hook before any ref moves ([Q31](../decisions.md)). The gateway starts it with
`core.hooksPath` set to its own hooks directory; the hook (`writd hook pre-receive`) only
forwards the ref updates and a per-push token to the daemon over a private Unix socket in
its state directory. The daemon looks the token up (which lease, which repo), decides, and
answers `ok` or `deny <reason>`. It checks the lease again at that point (state, deny list,
expiry, caller, the push operation, the repo still in the lease): a lease revoked or expired
while the pack was coming in moves no ref, and revoking a lease forgets its pushes in
progress. Input the daemon can't read whole (over 1 MiB, cut short,
not UTF-8, a line that isn't a ref update) is refused, never decided on in part. Until M4, the
check is the repo's own `protected_refs` from the registry, matched ignoring case. Every refusal is logged (event
`push`, denied, with the refs) before the hook is answered. On a refusal git drops the
quarantine and shows the agent `remote: writ: <reason>`. The commit checks against the ledger (M4) run at the same point,
on the quarantined objects. Any failure to reach the daemon refuses the push.

## Repo mirrors

One bare mirror per registered repo. Used to serve fetches, receive pushes into a quarantine,
and validate packs. Synced from upstream on fetch, on push, and periodically (no webhooks,
[Q19](../decisions.md)).

## Upstream pusher

Pushes accepted refs to the real forge with the daemon's own credentials, over **SSH** (key
via the [signer](signer.md)) or **HTTPS** (token from the sealed keystore), depending on the
repo's `upstream` URL ([Q4](../decisions.md)). The mirror's refs are updated **only after**
upstream accepted the push.

## Push modes (per repo)

Each repo in the [registry](../lease-model.md#repo-registry-daemon-config-admin-approved)
chooses which push modes are allowed. Default: `gateway` only.

| Mode | How the agent pushes | What the daemon sees and checks | Needs |
|---|---|---|---|
| `gateway` (default) | To the daemon's mirror; the daemon pushes upstream | Repo, refs, force push, **every commit against the ledger**, size | Repo registered with a mirror |
| `proxy` | SSH to the daemon, which relays the stream to the forge with its own key | Repo path (from the `git-receive-pack '<path>'` command), ref updates (old → new, so force push too), size, and **every commit against the ledger** (pack buffered and indexed in a temporary quarantine before relaying) | No mirror; temporary disk for the pack |
| `direct_ssh` | The daemon lends a per-lease ssh-agent socket; the agent talks to the forge itself | Destination host (`session-bind`), user, limits, TTL. **Not** the repo, refs or content | Upstream key that the forge scopes to this repo (deploy key), or explicit `allow_account_wide: true` |

Why `direct_ssh` needs a repo-scoped key: the repo path is sent inside the encrypted SSH
session, after authentication. The agent socket only sees "sign this auth challenge for
github.com", so with an account-wide key the agent could push to any of my repos on that
forge. Only the forge can scope it, through a deploy key.

The step-by-step of each mode is in [Flows](../flows.md#3-push) (3, 3b, 3c).

## URL rewrite

`gateway` and `proxy` keep the plain `git push origin` habit with a URL rewrite written by
`writ init`:

```ini
[url "ssh://git@writ.home:2222/github.com/user/"]
    insteadOf = git@github.com:user/
```

The agent keeps `origin` pointing at GitHub; git transparently routes it through the daemon.
The full git config of an agent host is in [Clients](clients.md#repo-setup-on-an-agent-host).
