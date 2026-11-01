# Gateway, mirrors and upstream

The daemon is the agents' git remote and the only thing that pushes upstream. That is what
makes repo, destination ref and pushed content strong, remote-agnostic checks
([threat model, boundary 2](../threat-model.md#2-policy-strong-because-the-daemon-is-the-git-server)).

Code: `crates/writ-gateway` (SSH server), `crates/writ-mirror` (the daemon's git, mirrors,
upstream), `crates/writ-git` (objects an agent sends).

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
(RFC 4253 `zlib` would decompress before authentication), nothing with SHA-1. git runs
through `writ_mirror::git::command` ([the daemon's git](#the-daemons-git)); `git
receive-pack` also gets `receive.maxInputSize` set to the lease's `max_push_size`.

A certificate is checked twice: when it is presented (CA, validity, deny list, principal
`git`, no critical option, then the approval service finds its single active lease and checks the caller,
logged as `connect`) and before each command, with the operation the command needs: a
fetch is decided whole by `Service::fetch` (the policy's `decide_fetch` and one operation of
the rate window, under one lock, one `fetch` line), a push is checked for its operation (and
decided whole at the pre-receive hook), a signature is checked whole by `Service::sign`,
which logs it once. When a lease ends (revoked, expired, exhausted), the gateway drops every
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
`core.hooksPath` set to its own hooks directory, after checking the lease cheaply
(`Service::may_push`: active, `push`, the repo; only a refusal is logged). The hook (`writd
hook pre-receive`) only forwards a per-push token, the quarantine git made
(`GIT_QUARANTINE_PATH`, none for a push that only deletes) and the ref updates to the daemon
over a private Unix socket in its state directory, and answers git with what the daemon says
(`ok` or `deny <reason>`). Input the daemon can't read whole (over 1 MiB, cut short, not
UTF-8, a line that isn't a ref update, more than 1,000 updates) is refused, never decided on
in part. Any failure to reach the daemon refuses the push. The daemon then:

1. looks the token up (which lease, which repo, which connection) and checks the lease again
   (`Service::may_push`): a lease revoked or expired while the pack was coming in moves no
   ref, nothing is read for it, and revoking a lease forgets its pushes in progress;
2. holds the repo's mirror (no sync, no other push) until `receive-pack` has moved the refs
   and exited;
3. reads the push from the objects git verified (`writ_mirror::quarantine`), believing the
   quarantine path only if it is a directory, not a link, right under the mirror's `objects`
   with git's prefix, and running git there with `GIT_QUARANTINE_PATH` set (nothing it runs
   can move a ref):
   - each new tip is a commit;
   - the commits no ref of the mirror reaches (`rev-list --not --all`), at most the lease's
     `max_signatures` (and 10,000): more means some aren't signed under it;
   - for each update, whether it is a fast-forward (`merge-base --is-ancestor`), and for a new
     ref whether the mirror has one with the same name ignoring case;
   - the pack's size on disk;
   - for each new commit, the paths it touches, computed again with `writ_git::paths` from
     these objects (the commit without its signature, its first parent, the trees that
     differ; at most 16 MiB of objects), as a digest;
4. decides with `Service::push`, under one lock: every new commit looked up in the ledger,
   `decide_push` (refs, protected refs, branches, force pushes and deletions, every commit
   signed under this lease for this repo with the same paths as at signing, size, count,
   rate), then the push taken from the lease's count and rate; one `push` line, allowed or
   denied with its code and the refs;
5. looks at the lease once more (a revocation that came while the push was read stops it
   here), then pushes upstream from the quarantine ([Upstream](#upstream)); only once the
   remote took it does the hook answer `ok`, and git move the mirror's refs. A remote that
   refuses (upstream moved, its own hook, any error) gets the push refused with its reason
   (`upstream refused the push: …`, cut and cleaned), logged as a `push` denial; the mirror
   never holds a ref the remote didn't take, and is marked stale after every upstream push.

On a refusal git drops the quarantine and shows the agent `remote: writ: <reason>`; a
violation under `on_violation: revoke_lease` revokes the lease, and its other sessions are
dropped. A push git refuses before its hook runs (a pack over `receive.maxInputSize`, an
object `fsck` refuses) is logged by the gateway when `receive-pack` ends: the client sent ref
updates and no decision was made.

## The daemon's git

Every git the daemon runs (`upload-pack`, `receive-pack`, syncs, reads of a quarantine) goes
through one builder, `writ_mirror::git::command`: a clean environment (`PATH` and `TMPDIR`
only), no system or global config, no prompt, ssh as the only transport (`protocol.allow =
never` but ssh, `GIT_ALLOW_PROTOCOL=ssh`), and every setting Writ relies on stated on the
command line rather than left to git's defaults:

- every object checked (`transfer`, `fetch` and `receive.fsckObjects`), and the `fsck`
  messages git only warns about raised to errors where they matter: a tree entry named
  `.git`, `.` or `..`, an empty or absolute name, a null id (`hasDotgit`, `hasDot`,
  `hasDotdot`, `emptyName`, `fullPathname`, `nullSha1`), whether the objects come from an
  agent or from upstream;
- a fetched pack kept whole (`fetch.unpackLimit = 1`): its objects land only once all are
  checked;
- no hook but the gateway's own pre-receive (`core.hooksPath`), no submodule, no automatic
  maintenance, no credential helper, no file system monitor;
- `upload-pack` serves only what refs reach (no `allow*SHA1InWant`, no filter);
  `receive-pack` takes no shallow update and no push option, and leaves deletions and force
  pushes to the pre-receive hook.

## Repo mirrors

One bare mirror per registered repo, `<state>/repos/<name>.git`, used to serve fetches and to
receive pushes into a quarantine (`crates/writ-mirror`). The daemon creates it at startup in
the repo's `object_format`, with reftable refs (no loose ref files to collide by case on
APFS), under a temporary name moved in place; a directory already there must be exactly that
(a bare repository, that object format, reftable, not a link) or the daemon refuses to start.

A **sync** fetches upstream's branches and tags, nothing else (`+refs/heads/*` and
`+refs/tags/*`), with `--atomic` (every ref moves, or none) and `--prune` (a ref upstream
deleted goes). It runs on a fetch and on a push when the mirror is older than `fresh_for`
(10 s), and in the background every `sync_every` (5 min) (no webhooks,
[Q19](../decisions.md)). One lock per mirror serializes syncs and pushes; concurrent callers
wait for one sync and find the mirror fresh; at most 4 syncs run at once, daemon-wide. A sync
that fails leaves the mirror's refs as they were, removes its partial pack, and marks the
mirror stale; the fetch or push that asked for it is refused with the reason (fail closed).
Past 50 packs, a sync repacks the mirror.

Upstream is semi-trusted (the operator's remote, but one that can be compromised, behind a
network that can be hostile), so what a sync takes from it is checked and bounded:

| What | Bound |
|---|---|
| Who it is | the host key pinned by the operator in `mirrors.known_hosts` (`StrictHostKeyChecking=yes`, nothing learned) |
| What it sends | `mirrors.max_fetch` bytes (1 GiB) per sync, counted by the relay (git has no limit of its own on a fetch); `mirrors.timeout` (5 min) for the whole sync, then git, the relay and ssh are killed as a process group |
| Its objects | `fsck`, with the checks above at error level; a pack lands whole or not at all |
| Its refs | branches and tags only; all or none |
| Its object format | the registry's: git refuses a remote in another (`mismatched algorithms`) |
| What it says | an error's text cut to 2,000 characters, hidden characters dropped, one line: it reaches the audit log and an agent's terminal |

## Upstream

The daemon reaches upstream over **SSH** with the repo's `upstream_credential`, a key in the
[signer](signer.md) (its own queue: 8 waiting, 10 s each). **HTTPS** with a token from the
keystore comes in M4.5 ([Q4](../decisions.md)); until then an `https://` upstream is refused at
startup.

- The URL is the registry's `ssh://[user@]host[:port]/path`, read strictly (a plain host
  name or address, no quote, nothing an option could start with).
- git runs the system's OpenSSH (`mirrors.ssh`, `/usr/bin/ssh` by default, by absolute path)
  with `-F /dev/null` and every option that matters stated: the pinned host keys only (as the
  daemon rewrote them: plain host names or `[host]:port`, no wildcard, hashed name or marker,
  no DSA key), public key authentication only, no forwarding, proxy, control socket or local
  command, `BatchMode`.
- The key never leaves the signer: for each operation the daemon serves an **ssh-agent
  socket** (`writ_mirror::agent`) in a private directory, offering only that repo's key,
  signing through the `Signer`; it takes 4 connections, makes 4 signatures, reads messages up
  to 256 KiB within 30 s each, answers anything but "list keys" and "sign" with a failure, and
  is removed when the operation ends.
- What upstream sends goes through the **relay** (`writd upstream-ssh <max bytes> <ssh> …`),
  git's ssh program: it runs ssh and counts the bytes, killing it past the cap.

`writd upstream-keys <writd.yaml>` prints each credential's public key and the repos that use
it, to add on each remote ([operator guide](../guides/operator.md#upstream-keys-and-host-keys)).

Accepted pushes go to upstream with the same credential, from the push's quarantine (git
reads its objects there), before the mirror's refs move: `git push --atomic` (every ref, or
none) with `--force-with-lease=<ref>:<old>` for each ref (`<old>` what the agent's push started
from, empty for a new ref), so a ref upstream moved since the mirror's sync is refused by the
remote's state rather than overwritten, and the agent fetches, rebases, has the commits signed
again and pushes again. The mirror's refs are updated **only after** upstream accepted the
push. Before each push `receive-pack` starts from a mirror synced unless fresh.

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
