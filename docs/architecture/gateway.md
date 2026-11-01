# Gateway, mirrors and upstream

The daemon is the agents' git remote and the only thing that pushes upstream. That is what
makes repo, destination ref and pushed content strong, remote-agnostic checks
([threat model, boundary 2](../threat-model.md#2-policy-strong-because-the-daemon-is-the-git-server)).

Code: `crates/writ-gateway` (SSH server), `crates/writ-git` (mirrors, quarantine, upstream).

## Gateway (SSH server)

The single entry point to the daemon. It serves connections from any `Transport`, with what
the `CallerAttestor` says about each caller (a caller it can't attest is turned away), and
each listener has a role:

| Listener (role) | SSH user and authentication | Commands |
|---|---|---|
| agents | `git` + an **SSH user certificate** issued by the daemon for an active lease ([Identity](identity.md#session-identity)) | **git** `upload-pack` (fetch) and `receive-pack` (push), so a plain `git fetch/push writ` works; **sign** for the `writ-sign` shim: `writ-sign git <repo>` (the commit and its evidence in, armored SSHSIG out; [signing](#signing)) |
| agents | `writ` + a plain key: the session key of a ticket | **lease** commands: `writ request` (submit the ticket on stdin), `writ wait <id>` |
| approvals (SSH) | any user, a key listed in the daemon's `readers` file (a certificate is refused) | the approval API: `writ info`, `ls`, `show`, `approve`, `refuse`, `revoke` ([Approvals](approvals.md#reaching-the-daemon)) |
| approvals (HTTPS) | mutual TLS 1.3: the daemon's pinned self-signed certificate, and a client certificate for a key in `readers` | the same API as `GET`/`POST` routes (`crates/writ-gateway/src/https.rs`) |

Each listener accepts connections only from its configured sources (`allow` in
`writd.yaml`, required on the agents' TCP listeners), and bounds what any peer can make it
hold (`crates/writ-gateway/src/limits.rs`): 256 open connections per listener and 16 per
source address (an IPv6 host counts as its /64), 20 seconds to authenticate (or to finish the TLS handshake), 4 channels at
once per SSH connection, 30 seconds to send a request body (60 seconds for a sign request's,
up to 16 MiB), 16 sign requests held at once by the whole daemon and 4 by
one lease (`sign_requests.per_lease` in `writd.yaml`, 1 to 16), 10 minutes without traffic. A
denial before authentication (a source not allowed, no free slot, a key not in `readers`,
a refused certificate) writes one audit line per source and minute, at most 60 a minute in
all, with the count of the others; text the peer chose (a certificate's key id) is cut to 64 characters.

The SSH algorithms are listed by the gateway, never left to the library's defaults:
mlkem768x25519-sha256 or curve25519-sha256 key exchange with strict kex, chacha20-poly1305
or aes256-gcm, Ed25519 and ECDSA P-256 keys (host, session and reader keys), no compression
(RFC 4253 `zlib` would decompress before authentication), nothing with SHA-1. `git
receive-pack` runs with `receive.fsckObjects` and `transfer.fsckObjects` (a malformed object,
a `.git` or `.gitmodules` trick, never lands in a repository other leases fetch from) and
`receive.maxInputSize` set to the lease's `max_push_size`.

A certificate is checked twice: when it is presented (CA, validity, deny list, principal
`git`, no critical option, then the approval service finds its single active lease and checks the caller,
logged as `connect`) and before each command, with the operation the command needs (fetch,
push; a signature is checked whole by `Service::sign`, which logs it once). When a lease ends (revoked, expired, exhausted), the gateway drops every
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

## Signing

`writ-sign git <repo>` ([Flows § 2](../flows.md#2-signed-commit)): the repo is a registry
name (git config `writ.repo` on the agent host), the body a `writ-sign/1` request
(`writ_proto::sign`): the object git asked to sign, then the first parent commit and the trees
the daemon needs to compute the paths the commit touches. Before reading it, the gateway asks
`Service::may_sign` whether the certificate's lease is active, allows `commit_sign` and names
the repo (a refusal is logged, and a violation revokes a lease with `on_violation:
revoke_lease`; an allowed request gets its line from `Service::sign`), so a certificate whose
lease can't sign there costs no decoding, hashing or walk. The body is bounded (16 MiB, 100,000
objects) and decoded strictly at the edge (`exec/sign.rs`), then, off the async threads:

1. The object's kind from its first bytes (a commit, a tag, anything else: the policy refuses
   a tag as a violation, anything else as malformed); a commit parsed
   strictly by `writ_git::commit` (only the layout git writes, no signature already in it).
2. Its committer email and `Writ:` trailers (found as git finds them), and its touched paths
   (`writ_git::paths`): every evidence object is read only by the id computed from its bytes,
   so the agent can leave objects out (the paths are then unknown) but can't change them. A
   commit adding a `.git` entry (in any case, with the characters HFS+ ignores, NTFS's
   trailing dots and spaces or short name, as git's `verify_path` reads it) is refused
   whatever `paths_check` says; an agent leaving that tree out hides it, and the push-time
   `fsck` stops it then (M4).
3. `Service::sign`, in three phases ([Policy and state](policy-and-state.md#policy-engine)):
   under the service's lock, the single active lease, the policy's `decide_sign` and the
   signature counted; outside it, the signature through the `Signer` (its queue and
   deadline) with the template's `signing_key`; under the lock again, the lease checked once
   more, then the audit line and the commit recorded in the ledger. The ledger holds the id
   of the commit git writes with the signature in it (`writ_git::signed`).
4. The armored SSHSIG on stdout, or `writ: <reason>` on stderr; `writ-sign` shows it to the
   agent, escaped. A violation under `on_violation: revoke_lease` revokes the lease; its other
   sessions are dropped at once, this one once the agent has the reason.

An unreadable body or commit is refused by the gateway itself, logged as a `sign` denial.

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

Pushes accepted refs to the real remote with the daemon's own credentials, over **SSH** (key
via the [signer](signer.md)) or **HTTPS** (token from the sealed keystore), depending on the
repo's `upstream` URL ([Q4](../decisions.md)). The mirror's refs are updated **only after**
upstream accepted the push.

## Push modes (per repo)

Each repo in the [registry](../lease-model.md#repo-registry-daemon-config-admin-approved)
chooses which push modes are allowed. Default: `gateway` only.

| Mode | How the agent pushes | What the daemon sees and checks | Needs |
|---|---|---|---|
| `gateway` (default) | To the daemon's mirror; the daemon pushes upstream | Repo, refs, force push, **every commit against the ledger**, size | Repo registered with a mirror |
| `proxy` | SSH to the daemon, which relays the stream to the remote with its own key | Repo path (from the `git-receive-pack '<path>'` command), ref updates (old → new, so force push too), size, and **every commit against the ledger** (pack buffered and indexed in a temporary quarantine before relaying) | No mirror; temporary disk for the pack |
| `direct_ssh` | The daemon lends a per-lease ssh-agent socket; the agent talks to the remote itself | Destination host (`session-bind`), user, limits, TTL. **Not** the repo, refs or content | Upstream key that the remote scopes to this repo (deploy key), or explicit `allow_account_wide: true` |

Why `direct_ssh` needs a repo-scoped key: the repo path is sent inside the encrypted SSH
session, after authentication. The agent socket only sees "sign this auth challenge for
github.com", so with an account-wide key the agent could push to any of my repos on that
remote. Only the remote can scope it, through a deploy key.

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
