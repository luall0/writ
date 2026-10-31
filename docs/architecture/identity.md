# Identity

Who is calling the daemon, and how much that can be trusted
([threat model, boundary 1](../threat-model.md#1-agent--daemon-session-certificate)).

Code: the CA in `crates/writ-crypto`, certificate checks in `crates/writ-gateway`.

## Session identity

1. The harness/CLI generates an **ephemeral session key** (ed25519, or Secure Enclave on a
   Mac).
2. The lease request is sent over a connection authenticated with that key (SSH user
   `writ`), so the submitter proves it holds it; the ticket records its fingerprint.
3. On approval, the daemon issues an **SSH user certificate** for that key: valid until the
   lease expires, key ID = lease ID.
4. The gateway trusts only its own CA, and only for user `git`. Revoking a lease revokes the
   certificate (in-memory deny list, rebuilt from the store at startup) and drops its open
   sessions. A certificate is valid from 60 s before approval (clock skew) to `expires_at`.

Standard SSH tooling then works out of the box: `git` uses the key + cert via
`core.sshCommand` ([Clients](clients.md#repo-setup-on-an-agent-host)).

Everything between agents and the daemon goes over this one SSH channel: git, signing, lease
commands ([Q16](../decisions.md)). Possession of the session key = identity, bounded by the
lease scope and TTL.

## Local mode: process chain checks

Borrowed from secrets-dispatcher. On the Unix socket, the daemon resolves the caller from the
kernel and walks its ancestry, so a lease can require "caller descends from this Omega Code
session".

- Match on the **executable path** (and on macOS the code signature) only: it's resolved by
  the kernel.
- Process name and arguments are advisory: a process can change them itself, so they never
  decide anything.
- Track processes by pid + pidversion to avoid PID reuse.

In local mode, the lease is also revoked when the session's root process exits
([lifecycle](../lease-model.md#lifecycle)). The watches live in memory, so the daemon watches
every bound lease again when it starts: a process that ended while it was down revokes its
lease at once, and a session it can't watch any more revokes it too. An amendment keeps the
lease's whole subject (session key and process). The certificate goes on the deny list before
anything that can fail, so a revocation is never lost to a store or log error.

None of this is special-cased in the core: the Unix socket is a `Transport`, the ancestry is
produced by a `CallerAttestor` as `CallerFacts`, exit notices come from a `SessionWatcher`, and
`writ-core` checks the lease's caller constraint against the facts, denying when a fact is
missing ([Platform interfaces](platform.md#caller-facts-and-the-policy)). The macOS
implementations live in `writ-platform-macos`; a Linux one can be added the same way.
