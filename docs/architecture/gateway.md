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
| agents | `git` + an **SSH user certificate** issued by the daemon for an active lease ([Identity](identity.md#session-identity)) | **git** `upload-pack` (fetch) and `receive-pack` (push), so a plain `git fetch/push writ` works; **sign** for the `writ-sign` shim: `writ-sign git <repo>` or `writ-sign openpgp <repo>` (the commit and its evidence in, the armored SSHSIG or OpenPGP signature out; [signing](#signing)) |
| agents | `writ` + a plain key: the session key of a ticket | **lease** commands: `writ request` (submit the ticket on stdin), `writ request --dry-run` (every check a submission gets, nothing stored), `writ policy <repo>` (what a ticket for that repo may ask), `writ wait <id>` (it ends with its answer, or when its channel or connection does), `writ close <lease>` (its summary on stdin) |
| approvals (SSH) | any user, a key listed in the daemon's `readers` file (a certificate is refused) | the approval API: `writ info`, `ls`, `show`, `approve`, `refuse`, `revoke` ([Approvals](approvals.md#reaching-the-daemon)) |
| approvals (HTTPS) | mutual TLS 1.3: the daemon's pinned self-signed certificate, and a client certificate for a key in `readers` | the same API as `GET`/`POST` routes (`crates/writ-gateway/src/https.rs`) |

Each listener accepts connections only from its configured sources (`allow` in
`writd.yaml`, required on the agents' TCP listeners), and bounds what any peer can make it
hold (`crates/writ-gateway/src/limits.rs`): 256 open connections per listener and 16 per
source address (an IPv6 host counts as its /64), 20 seconds from the accept to be
authenticated (the SSH handshake and the authentication together, or the TLS handshake; then
10 seconds for each HTTPS request's headers), 4 channels at once per SSH connection and one
command per channel (each of these refusals logged, coalesced per source), 30 seconds to
send a request body (60 seconds for a sign request's, up to 16 MiB), 16 sign requests held at
once by the whole daemon and 4 by one lease (`sign_requests.per_lease` in `writd.yaml`, 1 to 16), 10 minutes without traffic. A
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
in the lease's `scope.repos`, at `<repos_root>/<name>.git`. Nothing is taken from the client's
environment (every SSH `env` request is refused, `GIT_PROTOCOL` included), and git runs with a
clean environment (`PATH` and `TMPDIR` only), without the daemon user's system or global git
config. So `upload-pack` speaks protocol v0 whatever the client asks: in v2, git ignores
`uploadpack.allow*SHA1InWant` and serves any object the mirror holds by its id (a commit on a
branch deleted upstream, still in the mirror's objects). A client asking for v2 gets v0 (git
falls back on its own: clones, fetches, `ls-remote`, shallow clones work as before; a
`--filter` clone is made whole, the gateway advertising no filter). `receive-pack` has no v2:
a push is v0 either way.

## Signing

`writ-sign git <repo>`, or `writ-sign openpgp <repo>` for a lease whose key signs in OpenPGP
([Flows § 2](../flows.md#2-signed-commit); a format that isn't the lease's key's is denied,
`signature_format`: [signer](signer.md#openpgp-keys)): the repo is a registry
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
   `fsck` stops it then (M4). So is a tree entry with a mode git doesn't write (only
   `100644`, `100755`, `120000`, `40000` and `160000` are read): git reads a mode by its
   type bits, so `40755` or a zero-padded `040000` is a directory to it, and a walk reading
   it as a file would miss what is under it (`.github/evil.yml` listed as `.github`, inside
   `expected_paths: ["*"]`). Left out, that tree too is stopped by the push-time `fsck`
   (`badFilemode`, `zeroPaddedFilemode` at error level).
3. `Service::sign`, in three phases ([Policy and state](policy-and-state.md#policy-engine)):
   under the service's lock, the single active lease, the policy's `decide_sign` and the
   signature counted; outside it, the signature through the `Signer` (its queue and
   deadline) with the template's `signing_key`; under the lock again, the lease checked once
   more (and its fit with the template in force), then the audit line and the commit recorded in the ledger. The ledger holds the id
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
   and exited: released at its exit, not when the client has read its output (a client that
   keeps its SSH window shut holds nothing; what is left of the output gets 30 s, then the
   channel closes); at once when the push is refused (no ref moves), and 10 s after the
   hook's yes at the latest (`REF_UPDATE_GRACE`: the refs move at once, but a report larger
   than the pipe, which the client doesn't read, keeps `receive-pack` from exiting; a ref
   update later than that checks its old value and fails rather than moving past the
   decision);
3. reads the push from the objects git verified (`writ_mirror::quarantine`), within 10
   minutes in all (`LOCAL_WORK_DEADLINE`, each git killed with its group past it), believing the
   quarantine path only if it is a directory, not a link, right under the mirror's `objects`
   with git's prefix, and running git there with `GIT_QUARANTINE_PATH` set (nothing it runs
   can move a ref):
   - each new tip is a commit;
   - the commits no ref of the mirror reaches (`rev-list --not --all`), at most the lease's
     `max_signatures` (and 10,000): more means some aren't signed under it;
   - for each update, whether it is a fast-forward (`merge-base --is-ancestor`), and for a new
     ref whether the mirror has one with the same name ignoring case;
   - the pack's size on disk;
   - for each new commit the ledger holds for this lease and repo with its paths
     (`Service::paths_to_check`, a read), the paths it touches, computed again with
     `writ_git::paths` from these objects (the commit without its signature, its first
     parent, the trees that differ; at most 16 MiB of objects), as a digest. The others are
     never walked: a commit nobody signed here is refused whatever it touches, and one
     signed with its paths unknown has nothing to compare;
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
   never holds a ref the remote didn't take, and is marked stale after every upstream push;
6. once upstream took the push, for a repo whose `ticket_link` is `notes`, its commits wait
   for their note, and the repo's notes job starts ([Notes](#notes)): off the hook's path, it
   never delays the agent.

On a refusal git drops the quarantine and shows the agent `remote: writ: <reason>`; a
violation under `on_violation: revoke_lease` revokes the lease, and its other sessions are
dropped. A push git refuses before its hook runs (a pack over `receive.maxInputSize`, an
object `fsck` refuses) is logged by the gateway when `receive-pack` ends: the client sent ref
updates and no decision was made; the mirror is then marked stale, so the next sync prunes
anything git kept without a decision.

git takes a push with no check at all when it finds no pre-receive hook, so the hook is never
left to chance: the hooks directory is an absolute path (the gateway refuses to start on a
relative one: git would look it up inside the repository), and `receive-pack` doesn't start
for a push whose hook isn't a regular file its owner can run (git skips a hook it can't
execute, as silently as a missing one): the push is refused and logged.

## The daemon's git

Every git the daemon runs (`upload-pack`, `receive-pack`, syncs, reads of a quarantine) goes
through one builder, `writ_mirror::git::command`: a clean environment (`PATH` and `TMPDIR`
only), no system or global config, no prompt, no transport at all (`protocol.allow = never`)
except the one an upstream operation allows for itself, `ssh` or `https`
(`protocol.<it>.allow`, `GIT_ALLOW_PROTOCOL=<it>`), and every setting Writ relies on stated on
the command line rather than left to git's defaults:

- every object checked (`transfer`, `fetch` and `receive.fsckObjects`), and the `fsck`
  messages git only warns about raised to errors where they matter: a tree entry named
  `.git`, `.` or `..`, an empty or absolute name, a null id, a mode git doesn't write or a
  zero-padded one (`hasDotgit`, `hasDot`, `hasDotdot`, `emptyName`, `fullPathname`,
  `nullSha1`, `badFilemode`, `zeroPaddedFilemode`), whether the objects come from an agent
  or from upstream (so the paths walk never meets a tree git reads otherwise than it does;
  an upstream whose history holds such a tree can't be mirrored);
- a fetched pack kept whole (`fetch.unpackLimit = 1`): its objects land only once all are
  checked;
- no hook but the gateway's own pre-receive (`core.hooksPath`), no submodule, no automatic
  maintenance, no credential helper (but the daemon's own, for an HTTPS upstream's
  operation), no file system monitor;
- `upload-pack` serves only what refs reach, in protocol v0 (above): a commit reachable from a
  ref may be asked for by its id (`uploadpack.allowReachableSHA1InWant`, so `git fetch writ
  <sha>` works), any other object is refused ("not our ref"); no filter;
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
wait for one sync and find the mirror fresh; at most 4 syncs run at once, daemon-wide. A caller
waits for the lock at most twice `mirrors.timeout` plus 10 minutes (what a holder doing its
job takes: a wait for a sync slot, itself at most `mirrors.timeout`, one upstream operation,
and a repack or the reading of a push); past it the fetch or push is refused, `the mirror is
busy`, never left waiting. A sync that fails, or is dropped, leaves the mirror's refs as they
were, removes its partial pack, and marks the mirror stale; a mirror a start cut short while
creating it (`.<name>.git.new-…`) is removed at the next start; the fetch or push that asked for it is refused with the reason (fail closed).
Past 50 packs, a sync repacks the mirror.

Upstream is semi-trusted (the operator's remote, but one that can be compromised, behind a
network that can be hostile), so what a sync takes from it is checked and bounded:

| What | Bound |
|---|---|
| Who it is | `ssh://`: the host key pinned by the operator in `mirrors.known_hosts` (`StrictHostKeyChecking=yes`, nothing learned); `https://`: a certificate for its host from the system's CAs, or from those in `mirrors.ca_certs`, and no redirect |
| What it sends | `mirrors.max_fetch` bytes (1 GiB) per sync, counted by the relay (`ssh://`) or the proxy (`https://`), git having no limit of its own on a fetch; `mirrors.timeout` (5 min) for the whole sync, then git, the relay and ssh are killed as a process group |
| Its objects | `fsck`, with the checks above at error level; a pack lands whole or not at all |
| Its refs | branches and tags only; all or none |
| Its object format | the registry's: git refuses a remote in another (`mismatched algorithms`) |
| What it says | an error's text cut to 2,000 characters, hidden characters dropped, one line, an HTTPS upstream's token taken out: it reaches the audit log and an agent's terminal |

## Upstream

The repo's `upstream` URL picks the way ([Q4](../decisions.md)): **SSH** (`ssh://`) with the
repo's `upstream_credential`, a key in the [signer](signer.md) (its own queue: 8 waiting, 10 s
each), or **HTTPS** (`https://`) with the token of that id from the keystore
([below](#https-with-a-token)). Either way git does the protocol, and what the daemon gives it
serves that one operation.

### SSH with a key

- The URL is the registry's `ssh://[user@]host[:port]/path`, read strictly (a plain host
  name or address, no quote, nothing an option could start with).
- git (`mirrors.git`, `/usr/bin/git` by default, by absolute path, like everything the daemon
  runs on its mirrors) runs the system's OpenSSH (`mirrors.ssh`, `/usr/bin/ssh` by default)
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
- Its sockets live in `<state>/mirror/sockets/`, a private directory; leftovers are removed
  at startup.

`writd upstream-keys <writd.yaml>` prints each credential's public key and the repos that use
it, to add on each remote ([operator guide](../operators/setup.md#upstream-keys-and-host-keys)).

### HTTPS with a token

For remotes reached over HTTPS only. A token can't sign: unlike an SSH key it has to reach
git, so it reaches only the daemon's own git, for one operation, and only for the registry's
host ([operator guide](../operators/setup.md#https-upstreams-and-tokens)).

- The URL is the registry's `https://[user@]host[:port]/path`, read strictly: a plain host
  name or address, no password (refused: the token is in the keystore), no query or fragment.
  Never `http://`.
- The token (1 to 1,024 printable ASCII characters, no space) is in the keystore: sealed
  (`tokens/<id>.age`, added from the Mac with [`writ admin token <id>`](approvals.md#writ-admin-token),
  used at once), or, in the development keystore, alone in `<keys>/tokens/<id>` (0600,
  written by the operator). It is read into memory wiped on drop, never printed. In the
  sealed keystore a missing one doesn't stop the unseal: the repo's syncs and pushes are
  refused with "add it with `writ admin token <id>`" until it is added; a malformed one is
  refused when it is added. (The development keystore still stops on a missing one.) One
  credential id is a key or a token, never both.
- git gets it from its credential helper, the daemon's own program
  (`writd upstream-credential <socket> <operation>`), which asks a **credential socket**
  (`writ_mirror::credential`) served for the operation in a private directory: it answers
  only `protocol=https` and the registry's host and port, 4 times at most, 8 connections,
  4 KiB requests within 30 s, and goes when the operation ends. The token reaches git through
  pipes: never a command line, an environment variable, a URL, the mirror's config or a file.
  The user name sent with it is the URL's, or `writ` (GitHub, GitLab, Forgejo and Gitea take
  any name with a token).
- git reaches upstream only through a **SOCKS5 proxy** (`writ_mirror::proxy`,
  `http.proxy=socks5h://localhost/<socket>`) served for the operation on a Unix socket in the
  same private directory: it connects only to the registry's host and port, at most 16
  times, and counts what upstream sends across all its tunnels against `mirrors.max_fetch`,
  ending every tunnel past it. TLS stays end to end between git and upstream: the proxy relays
  ciphertext. git 2.47 or newer (older ones drop the socket path from `http.proxy`).
- git's HTTPS is stated too: the certificate verified (`http.sslVerify`), against
  `mirrors.ca_certs` when the operator gave one (an authority file of 1 to 1,000 PEM
  certificates and nothing else, rewritten by the daemon, `http.sslCAInfo`) and those alone
  (`http.sslCAPath` an empty private directory, emptied at every start: curl built with a
  default CA directory, as Debian's is, keeps trusting it when only the file is named), the
  system's CAs otherwise; no
  redirect (`http.followRedirects=false`: the token never follows one); no extra header,
  cookie, empty authentication, prompt or other credential helper; an empty private `HOME`
  (no `.netrc`).
- Whatever upstream says has the token taken out before it reaches an error: a hostile
  upstream received it, and could print it back.

### Pushing upstream

Accepted pushes go to upstream with the same credential, from the push's quarantine (git
reads its objects there), before the mirror's refs move: `git push --atomic` (every ref, or
none) with `--force-with-lease=<ref>:<old>` for each ref (`<old>` what the agent's push started
from, empty for a new ref), so a ref upstream moved since the mirror's sync is refused by the
remote's state rather than overwritten, and the agent fetches, rebases, has the commits signed
again and pushes again. The mirror's refs are updated **only after** upstream accepted the
push. Before each push `receive-pack` starts from a mirror synced unless fresh.

## Notes

A repo with `ticket_link: notes` ([lease model](../lease-model.md#rules)) gets each pushed
commit's lease on the remote without changing the commit: a git note, `Writ: <lease id>` (the
trailer's text), written by the daemon from its ledger, under the repo's `notes_ref`:
`refs/notes/commits` by default (git's own notes ref: `git log` shows it, and it is the only
one Forgejo and Gitea show on a commit's page and in their notes API, checked on Forgejo
13), or `refs/notes/writ`, Writ's notes apart from anyone else's. The commit keeps its hash and its signature: a note is a separate commit on a
separate ref, which names the commits it annotates by their ids and never contains them
([Q25](../decisions.md)).

1. **Waiting.** Once upstream took a push, `Service::notes_to_write` marks its commits (the
   ledger's entries for that lease and repo; every one of a push is) as waiting for their note,
   with the credential of that push, which will push the note (the repo's `upstream_credential`
   today, [M11](../roadmap.md#m11--multi-user-daemon) may make it the user's). A note already
   written stays written.
2. **The notes job** (`writ-gateway/src/notes.rs`) starts after the push and takes the
   repo's mirror lock, so it runs once the push's `receive-pack` gave the mirror back, and
   never beside another push or sync of the repo. It writes every note waiting on the repo, at
   most 10,000 (`writ_mirror::MAX_NOTES`; the rest go with the next push), one batch per
   credential: one note per commit, a `Writ:` line per lease it waits under.
3. **Writing** (`writ_mirror` `mirror/notes.rs`): the batch becomes a commit of its own (a
   tree naming each annotated commit's id, each note at most 64 KiB, no parent), merged into
   the mirror's notes ref with `git notes merge -s union`: a note a commit already has (a
   person's under `refs/notes/commits` too) is kept exactly as written, paragraphs and blank
   lines included, the daemon's line after it as a paragraph of its own (a blank line
   between, as `git notes append` writes it). A line the commit's note already holds (a
   retry, or upstream's ref fetched) is left out of the batch first, read in one
   `cat-file --batch`, so no line is written twice. A notes ref upstream doesn't have
   (`ls-remote`: deleted there, or the repo now points at another remote) is started afresh
   from the batch, never put back from the mirror's copy. Notes commits are **unsigned**, by
   `writd <writd@writ.invalid>`: no remote verifies or shows a notes commit's signature, and
   the ledger, not the note, is the reference.
4. **Pushing**: the notes ref upstream, without force, with the batch's credential
   (anything but the repo's is refused). A remote whose notes ref moved meanwhile refuses it
   (`fetch first`, `non-fast-forward`): that one ref is fetched from upstream into the mirror's
   (forced: upstream's is the one to build on; checked and bounded like a sync, its partial
   pack removed when it fails), the batch merged into it again, and the push tried once more;
   a second refusal is the job's failure. All of it within one operation: `mirrors.timeout`
   for what reaches upstream, 10 minutes for the local work.
5. **The outcome**: pushed, the notes are marked written and each lease gets an allowed
   `notes` line (`count`, `key`: the credential, `refs`); not pushed (refused, unreachable,
   the mirror busy), each lease gets a denied one with the reason, and the notes stay waiting:
   the repo's next push writes them, or the next reconcile. The branch push stands either way:
   its commits are upstream and in the ledger.
6. **The reconcile** (`Gateway::reconcile_notes`), after each sync of a notes repo's mirror
   (`writd`: at start, then every `sync_every`; not after a failed sync): the ledger's commits
   for the repo with no note state (the newest 100,000), looked up in the mirror in one
   `git cat-file --batch-check`; those it holds are upstream's (only upstream's objects and
   those of pushes upstream took reach the mirror), recorded as waiting with the repo's
   credential; then the notes job, for those and every note still waiting. It catches a push
   whose notes were never recorded (the daemon stopped between upstream taking it and the
   record), commits pushed before the repo asked for notes (a backfill: switching a repo to
   `notes` notes the commits the daemon signed and pushed before), and notes a failed job left
   waiting, without waiting for another push. A commit signed and never pushed gets no note.

The mirror's sync takes branches and tags only, never a notes ref: git refuses a fetch naming
a ref upstream doesn't have (a repo without notes yet), so the notes job keeps the mirror's
notes ref in step itself. Agents fetch it from the mirror like any ref
(`git fetch origin refs/notes/commits:refs/notes/commits` through the URL rewrite) and can
never push it, nor any ref outside `refs/heads/` (`ref`). The job never needs the annotated commits, only a repository holding
the notes ref: M9's `proxy` mode writes notes the same way, from a notes-only repository.

What remotes do with notes: all keep them; Forgejo and Gitea show those under
`refs/notes/commits` on the commit page, GitHub's web interface shows none
(`git fetch origin refs/notes/commits:refs/notes/commits`, then `git log`; for
`refs/notes/writ`, `git log --notes=writ`).

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
`writ init`: the clone's `origin` URL, exactly as it was when wired (recorded as
`writ.origin`), rewritten to the daemon's repo:

```ini
[url "ssh://git@writ.home:2222/omega-code.git"]
    insteadOf = git@github.com:user/omega-code.git
```

The agent keeps `origin` pointing at GitHub; under the wiring, git routes `push origin` and
`fetch origin` through the daemon. In wrapper mode the rewrite travels with the other settings
in `writ git`'s environment, so the operator's plain git still reaches GitHub itself; in
whole-repo mode it is in the clone's config, and `writ init` says so. Only that one URL is
rewritten, never in a global config, and a clone without `origin` gets no rewrite. The full
git config of an agent host is in [Clients](clients.md#repo-setup-on-an-agent-host).
