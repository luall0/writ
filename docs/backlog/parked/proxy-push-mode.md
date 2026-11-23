# `proxy` push mode

**Status:** parked (2026-11-15). **Area:** Gateway, Upstream. **Kind:** feature.

This page explains why we are not building it, and what would make us reconsider. It was M9
on the roadmap (gone since v1 closed); its keys (`push_modes`) leave the policy in
[M7.9.6](../../history/m7.9.6-upgrades.md)'s format 2.

## The idea

A repo pushed with no mirror: the daemon relays the agent's push to the remote with its own
credential, after checking the ref updates and, from the pack buffered in a temporary
quarantine, every new commit against the ledger ([Q22, Q23](../../decisions.md)). For
repositories too big to keep a full mirror of.

## Why a relay can't keep the gateway's guarantees

Without a mirror the daemon sees only the pack the agent sends and upstream's ref
advertisement, never upstream's history:

- **Which commits are new:** the agent builds the pack. A commit whose parent upstream holds
  but no advertised ref reaches (left by a force-push and not yet collected, under a hidden ref
  such as `refs/pull/*`, or a fork's object on GitHub) passes upstream's connectivity check,
  so commits nobody signed land on the branch. Refusing every missing parent refuses ordinary
  pushes too (a branch started from `main~3`): only the commit graph tells them apart.
- **The touched paths:** they are computed from the first parent's trees, which are
  upstream's and not in the pack (`no-thin` only keeps deltas inside the pack).
- **Fast-forwards:** proven only when the path from the new tip to the old one is in the pack.
- **A relay passes what it doesn't parse:** push options (a remote's own actions:
  `merge_request.create`, `ci.skip`), `shallow` lines and capabilities would need Writ's own
  parser of the push protocol on the security path, where git's `receive-pack` does it in
  gateway mode.

## What the spike found (2026-11-15)

The alternative kept the gateway and lightened its mirror: commits and trees only
(`--filter=blob:none`), fetches relayed upstream. A spike ran it with real git, 2.47.3 (the
daemon's, Debian 13) and 2.54, with SHA-1 and SHA-256: an upstream with history, a hidden ref
and notes; a blobless mirror; an agent's full clone; a pre-receive hook running the daemon's
checks in git's quarantine, then the upstream push from it; every lazy fetch made to fail.

- **What held, on commits and trees alone:** the blobless sync with the gateway's `fsck`
  settings; new commits, a tip's type, fast-forwards and touched paths for a modify, add,
  rename, revert, copy, copy from history and merge; the upstream push (`--atomic`,
  `--force-with-lease`); the notes ref fetched with its blobs (`--no-filter`) beside the
  filtered refs. Hostile packs were refused as in gateway mode: a commit on a hidden commit
  or tree not sent (`missing necessary objects`), a `.git` entry (`hasDotgit`), a mode git
  doesn't write (`badFilemode`); a hidden commit that is sent counts as new.
- **What it needed changed:**
  1. `receive.fsckObjects` off for such a mirror (git's `--strict` requires every blob a new
     tree names, unchanged ones included: every push failed), its checks run in the hook
     with `git index-pack --fsck-objects` and the gateway's error list instead;
  2. `no-thin` added to `receive-pack`'s advertisement by the gateway (stock `receive-pack`
     never advertises it; a thin pack's deltas name blobs the mirror lacks);
  3. the daemon's upstream push with `--no-thin`;
  4. `GIT_NO_LAZY_FETCH=1` on every git run on that mirror.
- **What it costs:** pushes larger on both legs (a small change to a large file sends the
  whole file), fetches dependent on upstream every time, git rewritten in the protocol, and
  git behaviours with missing objects that the security path would rest on.
- **Not covered:** real remotes' filter support (`uploadpack.allowFilter`), the fetch relay,
  Writ's own Rust readers on a partial mirror, notes merging, a large repository's numbers.

## What would make us reconsider

A real repository too big for a full mirror. The blobless mirror is then the starting point,
with the four changes above and the uncovered points settled first; the relay is not.
