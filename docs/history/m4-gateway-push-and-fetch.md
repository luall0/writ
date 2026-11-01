# M4 — Gateway push and fetch

[Flows § 3 and § 4](../flows.md#3-push) in `gateway` mode, upstream over SSH, against a test
remote (local Forgejo or Gitea in Docker) and one throwaway GitHub repo.

- One bare mirror per registered repo; sync on fetch, on push and periodically.
- Push into quarantine; checks: lease covers push and repo, ref matches the branches, protected
  refs, no force push unless allowed, every new commit in the ledger for this lease, size.
- Upstream pusher with the upstream credential from the `Signer`; mirror refs updated only
  after upstream accepted; upstream rejections relayed to the agent.
- `writ init` writes the [URL rewrite](../architecture/gateway.md#url-rewrite).
- From the M2.6 security review: mirrors use the reftable ref format, and an update whose name
  differs only in case from an existing ref is refused; `receive.fsckObjects` stays on; decide
  and consume a push under one store transaction, with the rate window and expiry checked there
  too.
- From M3: each new commit's touched paths computed again from the objects git verified in
  the quarantine, and the push refused when they differ from what was checked at signing; the
  ledger keeps what signing saw (a schema migration).
- From the review after M3: the quarantine walk reuses `writ_git::paths`; `receive.fsck.hasDotgit
  = error` in every mirror; each mirror created with its repo's `--object-format`, and the first
  sync refuses a remote whose format isn't the registry's; no network I/O under the service's
  state lock.
- From the review after M3.5 ([M3.6](m3.6-review-after-m3.5.md)): a fetch goes through
  `decide_fetch` and consumes `Counter::Fetch` in the same store transaction; a lease holder's
  connections are bounded (decide here); revocation latency measured with pushes and fetches in
  flight.
- Added during the milestone, by the user: **harden the mirror sync as much as possible**
  (upstream treated as untrusted input), and **the ssh client configurable** (`mirrors.ssh`)
  for systems that keep OpenSSH elsewhere.

**Status:** done on 2026-11-01, in six `feat:` steps, a `test:` commit (`make e2e`) and this
`docs:` commit; every acceptance item is exercised by `make test` and `make e2e`. **One check
is left for the user**: the throwaway GitHub repo ([manual checks](../guides/manual-checks.md#a-throwaway-github-repo-m4)),
which needs a GitHub account and a deploy key.

The plan and its eight decisions (D1 to D8, below) were agreed with the user before any code;
the user asked one question on the way (does the URL rewrite break the operator's own pushes?
No in wrapper mode; in whole-repo mode by design, now said by `writ init`).

## What was done

**Step 1, mirrors and the way to upstream** (`writ-mirror`, new). One git builder for every
git the daemon runs (the gateway's too): clean environment, no system or global config, ssh as
the only transport, `fsckObjects` everywhere with `hasDotgit`, `hasDot`, `hasDotdot`,
`emptyName`, `fullPathname` and `nullSha1` at error level, packs kept whole
(`fetch.unpackLimit = 1`), no submodule, hook, maintenance or credential helper. One bare
mirror per repo, created by `writd` in the repo's object format with reftable refs under a
temporary name (or checked to be exactly that, not a link). A sync is `git fetch --porcelain
--atomic --prune` of branches and tags only; one lock per mirror, fresh for
`mirrors.fresh_for`, 4 syncs at once; a failed sync leaves the refs as they were, its partial
pack removed, the mirror stale. Upstream over the system's OpenSSH (`mirrors.ssh`) with every
option stated, the operator's pinned host keys only (`mirrors.known_hosts`, rewritten by the
daemon), the credential served for one operation by an ssh-agent socket signing through its
own `Signer` queue (4 connections, 4 signatures, 256 KiB messages), the bytes capped by a
relay (`writd upstream-ssh`) and the process group killed past `mirrors.timeout`. `writd
upstream-keys`; a background sync every `mirrors.sync_every`. A test remote (an SSH server in
the test process, which can hang or flood) for `make test`.

**Step 2, fetches through the policy and the mirror.** `Service::fetch`: the lease,
`decide_fetch`, one operation of the rate window, under one lock, one line; then the mirror
synced unless fresh, refused with its reason when the sync fails. A sync points the mirror's
`HEAD` at upstream's default branch (`ls-remote --symref`). `AuditEvent::denial` now sets the
result itself (the new path had logged a denial as allowed).

**Step 3, every push check in git's quarantine.** The hook forwards git's quarantine path,
believed only right under the mirror's `objects`. `Service::may_push` checks the lease cheaply
at `receive-pack`'s start and at the hook; the mirror is held from the decision until
`receive-pack` exits; `writ_mirror::quarantine` reads the push from what git verified (each
tip a commit, the new commits up to the lease's `max_signatures`, fast-forwards, case twins,
the size, each commit's paths computed again with `writ_git::paths` from the commit without its
signature); `Service::push` looks every commit up in the ledger, decides, and takes the push
from the count and rate, under one lock, one line. The policy refuses a ref twice ignoring case
or with a twin, and a commit whose paths changed since signing (`paths_changed`); the ledger
keeps the paths' digest (schema 4). A push git refuses before its hook is logged by the
gateway.

**Step 4, accepted pushes go upstream before the mirror moves.** The lease looked at once
more, then `git push --atomic --porcelain --force-with-lease=<ref>:<old>` from the quarantine;
only then does the hook say `ok`. A remote's refusal comes back with its reason, cut and
cleaned, and is logged; the mirror never holds a ref the remote refused, and is marked stale
after every upstream push. `receive-pack` starts from a synced mirror.

**Step 5, `writ init` rewrites `origin`.** The clone's `origin` URL, as it was, recorded and
rewritten to the daemon (`url.<daemon>/<repo>.git.insteadOf`): in `writ git`'s environment in
wrapper mode, in the clone's config in whole-repo mode (said by `writ init`, undone by
`--undo`).

**Step 6, connections and revocation.** A lease holder's allowed `connect` lines coalesced past
60 a minute on their own budget (`service/coalesced.rs`, rule 9 updated); revocation measured
with a fetch and a push stuck on upstream.

**Step 7, `make e2e`** (`tool/e2e.sh`): a throwaway Forgejo 13.0.5 in Docker on random local
ports, a user and a token made in the container, a repository and a deploy key made through its
API, its host key pinned, and the flow run through the real daemon code (`e2e_forgejo.rs`).

**Docs**: this page, the gateway page (the daemon's git, mirrors, upstream, push checks, URL
rewrite), flows § 3 and § 4, policy and state (the new facts, schema 4, coalesced connections),
the security inventory (pinned hosts, what upstream sends, the agent socket, the hook's
quarantine line, pushed objects), the threat model (boundary 7, a residual risk, guarantee
rows), the operator guide (upstream keys and host keys, `origin` rewritten), the manual check
for GitHub, the decision log, AGENTS.md rule 9.

**Numbers**: 78 files changed by the six steps, about 6,700 lines added (2,900 in
`writ-mirror`). New tests: 24 in `writ-mirror`, 3 in `writ-git`, 2 in `writ-core`, 1 in
`writ-approval`, 1 in `writ-store`, 2 in `writ-cli`, 1 in `writd`'s config; 23 integration
scenarios (`mirror_sync.rs` 10, `push_checks.rs` 6, `upstream_push.rs` 3,
`revocation_in_flight.rs` 1, `gateway_git.rs` 2) and `e2e_forgejo.rs`.

## Decisions

Each has its row in the [decision log](../decisions.md) (2026-11-01) where it isn't only this
milestone's detail:

- **D1, a new crate `writ-mirror`**: `writ-git` stays pure.
- **D2, OpenSSH and a one-operation agent socket served from the `Signer`**: the key never
  leaves the signer; M10's `direct_ssh` needs the same kind of socket. The ssh client is
  configurable (`mirrors.ssh`, an absolute path checked at startup), asked by the user.
- **D3, upstream host keys pinned by the operator**, nothing learned on first use.
- **D4, always `--atomic`** upstream, with `--force-with-lease` on what the agent's push
  started from.
- **D5, a push already sent upstream lands** even if a revocation comes meanwhile; the lease
  is checked right before it leaves. A new residual risk, approved by the user.
- **D6, a lease holder's connections coalesced** per lease rather than counted as operations.
- **D7, an in-process test remote** for `make test`, Forgejo in Docker for `make e2e`, GitHub
  by hand.
- **D8, a mirror fresh for 10 s**, synced every 5 min in the background (both settable).
- **The sync hardened as untrusted input** (the user's request, its list in the decision log),
  and a failed sync refuses the fetch or push that needed it (fail closed).
- **A refused upstream push keeps its slot** of the lease's count and rate (it errs toward
  less, like a failed signature).
- **The mirror follows upstream's `HEAD`** (a clone of it checks out the default branch).
- **The mirror is marked stale after every upstream push** rather than trusting that git's ref
  update matched (the exit code of `receive-pack` doesn't say).

## Findings

- **git has no limit on what a fetch takes in**: `transfer.maxInputSize` and
  `fetch.maxInputSize` are ignored by `git fetch` (git 2.54); hence the byte-capping relay.
- **git 2.54's transfer `fsck` is strict**: `receive.fsckObjects` already refuses a `.git`
  tree entry (only `git fsck` warns), so the roadmap's note was about the wrong command; the
  explicit error settings stay, so a default doesn't decide.
- **A mirror created with no config points `HEAD` at `master`**: a clone of it checked out
  nothing; a sync now follows upstream's `HEAD`.
- **`receive-pack` exits 0 when `fsck` or the size cap refuses a pack** (it reports the
  failure to the client): the gateway logs such a push from the bytes the client sent and the
  hook never deciding.
- **A push from inside the pre-receive hook to a local-path upstream fails**
  ("ref updates forbidden inside quarantine environment"): git's local transport passes
  `GIT_QUARANTINE_PATH` to the receiving side. The daemon only pushes over ssh, where nothing
  of its environment crosses.
- **macOS can leak a fresh listening socket into a child spawned at that moment** (no
  `SOCK_CLOEXEC`: the flag is set just after `socket()`): an agent socket's listener can live
  in an unrelated child for a while. Harmless (nobody accepts past the cap, the file is
  removed); the test says so instead of assuming a refusal.
- **`AuditEvent::denial` didn't set the result**: the new fetch path logged a denial as
  `allowed`; fixed at its source rather than in each caller.
- **`writ init --undo` puts values back at the end of the config**: values are equal, their
  order isn't (git config's CLI can't insert); the test fixture orders its entries so the
  comparison stays exact.

## The security checklist, for M4

1. **Inputs**: new ones (the pinned host keys, what upstream sends on a sync and on a push,
   the agent socket, the hook's quarantine line, the pushed objects as read in the quarantine)
   are in the [inventory](../security.md#untrusted-inputs) with their bounds and hostile tests
   (`malformed_or_dangerous_objects_from_upstream_never_land`,
   `a_sync_past_the_byte_cap_is_refused_on_both_sides`,
   `an_upstream_that_never_answers_is_cut_at_the_deadline`,
   `another_host_key_or_an_unpinned_host_is_refused`, `anything_but_a_plain_pin_refuses_the_file`,
   `another_key_or_another_request_gets_a_failure`, `only_a_quarantine_of_the_mirror_is_believed`,
   `the_remote_s_refusal_reaches_the_agent_and_never_the_mirror`); costly reads come after
   `may_push`.
2. **Authority**: no new way to grant; pushes and fetches now go through the policy, the
   ledger and the rate. `writd.yaml` and the known_hosts file are authority files.
3. **Fail closed**: an unpinned host, a missing credential, an `https://` upstream, a foreign
   directory stop the start; a failed sync refuses the fetch or push; any failed read of a push,
   unknown paths where signing knew them, more commits than the lease signed, a non-commit tip,
   any upstream failure refuse the push with the mirror unchanged.
4. **Audit**: one line per fetch and push decision, a denial line when upstream refuses, git's
   own refusals logged; a lease's allowed connections coalesced past 60 a minute, every one
   counted (rule 9 updated, with the user).
5. **Revocation**: the lease is checked at `receive-pack`'s start, at the hook, and right before
   the upstream push; a revocation completes in 7 to 10 ms with a fetch and a push stuck on
   upstream, waiting for neither.
6. **Secrets**: the upstream credential stays in the `Signer` (its own queue), reached through
   a private, short-lived agent socket; only its public key is written.
7. **Display**: what upstream says reaches the agent and the log cut to 2,000 characters,
   hidden characters dropped, on one line; `writ init` shows the `origin` URL cleaned.
8. **Dependencies**: no new crate; `writ-mirror` and the test crate use crates already in the
   tree (`rustix`, `ssh-key`, `ureq`, `base64ct`, `rusqlite`); the Forgejo image is pinned in
   `tool/e2e.sh`.
9. **Guarantees**: the pushing guarantees are wired (no longer only in the policy core); the
   ledger guarantee widened to the paths; tests added to five rows.
10. **Threat model**: boundary 7 (daemon and upstream), one residual risk (a push already on
    its way upstream lands despite a revocation, D5, with the user), the `.git` residual risk
    removed and the SHA-1 risk's push-time mitigation in place.

## Acceptance

- [x] `git push origin agent/x` from a wired repo reaches the remote; `git fetch` works through
      the daemon; the agent host holds no remote credential.
  *With the real `writd` and `writ init` (`wrapper_mode_signs_through_writ_git_and_leaves_the_operator_s_git_alone`:
  `writ git fetch origin` and `writ git push origin` go through the daemon and the branch lands
  upstream, while the operator's plain `origin` is untouched; `whole_repo_mode_…`: plain `git
  push origin` through the daemon); `a_push_reaches_upstream_with_the_daemon_s_credential_only`
  (the agent's key can't reach the remote, only its session is on its disk); against Forgejo in
  `make e2e` (`pushes_and_fetches_go_through_the_daemon_to_forgejo`, a deploy key the daemon
  holds). **GitHub: pending**, the [manual check](../guides/manual-checks.md#a-throwaway-github-repo-m4)
  needs the user's account.*
- [x] Each is denied with a readable reason and nothing reaches upstream: a protected ref, a
      branch outside the lease, a force push, a commit not signed under this lease (including
      one signed under another lease, and an unsigned local commit under a signed one), a pack
      over `max_push_size`, a fetch without `fetch`.
  *`push_checks.rs`: each refusal asserts git's status, the reason the agent reads, the audit
  line's code, the ref absent from the mirror, and the allowed push beside it accepted (also a
  ref differing only in case, and paths changed since signing, by editing the ledger);
  `fetch_and_push_through_the_gateway` (protected refs); `a_fetch_goes_through_the_policy_and_counts_against_the_rate`
  (no `fetch`: code `operation`). The pack over the size is refused by git before the hook, and
  logged.*
- [x] Upstream moved → the push is rejected with the remote's reason; fetch, rebase, re-sign
      and push again succeeds.
  *`upstream_moved_the_push_is_refused_then_fetch_rebase_re_sign_and_push_again`: the remote
  moves the ref between the daemon's sync and its push, the agent reads `upstream refused the
  push: … stale info`, then fetches, rebases, signs again and pushes; and against Forgejo in
  `make e2e`, upstream moved through its API.*
- [x] The mirror never holds refs the remote refused.
  *The same scenario and `the_remote_s_refusal_reaches_the_agent_and_never_the_mirror` (a hook
  on the remote refusing, its words relayed with escapes neutralized): the mirror's ref and
  objects unchanged after each refusal.*
- [x] A lease holder looping fetches or connections is refused past `max_ops_per_minute` (or
      its lines coalesced), and a revocation still completes at once meanwhile.
  *Fetches: two a minute pass, the third is refused (code `rate`). Connections: 60 lines, the
  rest counted and written when the minute is over (`a_lease_s_connections_are_counted_past_sixty_lines_a_minute`,
  fake clock). Revocation: `a_revocation_completes_at_once_with_fetches_and_pushes_in_flight`
  (7 to 10 ms over five runs on the Mac, audit fsync included; both clients ended, nothing
  landed).*
