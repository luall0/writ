# writ-mirror

The daemon's repositories and its way to upstream (M4, HTTPS in M4.5): one bare mirror per
registered repo, synced from upstream, and the one builder every git the daemon runs goes
through.

## What it does

- **git** (`git`): the daemon's `git` (`mirrors.git`, an absolute path) — a clean environment, no system or global config, no
  prompt, no transport but the one an upstream operation allows (`ssh` or `https`), and the
  checks Writ relies on stated explicitly
  (`fsckObjects` everywhere, `.git`, `.`, `..`, empty and absolute tree entries at error level,
  packs kept whole, no submodule, hook, maintenance or credential helper). The gateway runs
  `upload-pack` and `receive-pack` through it.
- **Mirrors** (`Mirrors`, `mirror/open.rs`, `sync.rs`, `push.rs`, `access.rs`,
  `classify.rs`): created by the daemon in the repo's object format with reftable refs (or
  checked to be exactly that), one lock per mirror (waited on with a deadline: busy past it),
  synced with `git fetch --atomic --prune` of upstream's branches and tags only; fresh for
  `fresh_for`, at most 4 syncs at once; a failed sync leaves the refs as they were, its
  partial pack removed, the mirror stale.
- **Upstream** (`upstream`, `known_hosts`, `agent`, `relay`): `ssh://` URLs read strictly; the
  system's OpenSSH with every option stated (`-F /dev/null`), host keys pinned by the operator
  (no wildcard, hashed name or marker); the credential served for one operation by an
  ssh-agent socket that signs through the `Signer` (one key, 4 connections, 4 signatures, 256
  KiB messages); what upstream sends capped in bytes by the relay (`writd upstream-ssh`, git
  has no limit of its own) and in time (the whole process group killed past the deadline).
- **HTTPS upstream** (`upstream`, `credential`, `proxy`): `https://` URLs read strictly (no
  password, query or fragment); the token (`UpstreamToken`, wiped, never printed) handed to
  git for one operation by a credential socket that answers only the registry's host
  (`writd upstream-credential`, git's helper: never a command line, environment, URL or
  file); git reaching upstream only through a one-operation SOCKS5 proxy on a Unix socket that
  connects only to the registry's host and port and caps what upstream sends; the
  certificate verified (the system's CAs, or `mirrors.ca_certs` alone: an empty CA directory
  beside them), no redirect, no other
  helper, cookie, header or `.netrc`; the token taken out of whatever upstream says.

Tested with the real `git` and `ssh` in `crates/writ-integration/tests/mirror_sync.rs`
(against a test remote: hostile objects, another object format or host key, too many bytes,
no answer), and over HTTPS in `https_upstream.rs` (another certificate, a refused token, a
redirect, too many bytes, no answer, the token printed back).

## Scope

- No policy: whether a lease may fetch or push is the approval service's decision; this crate
  only does what the gateway asks once it is decided.
- No key: SSH credentials stay in the `Signer`; tokens come from the daemon's keystore and
  only reach the daemon's own git, for one operation.

## Depends on

`writ-core` (registry types), `writ-crypto` (randomness, key types), `writ-platform`
(private files), `writ-signer` (the `Signer` trait).

## Docs

[Gateway](../../docs/architecture/gateway.md#repo-mirrors), [Flows](../../docs/flows.md) § 3
and § 4, [Security](../../docs/security.md#untrusted-inputs).
