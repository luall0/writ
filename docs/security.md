# Security conventions

How every change keeps Writ secure. [AGENTS.md](../AGENTS.md) holds the hard rules; the
[threat model](threat-model.md) says what Writ defends and what it doesn't; this page is the
working rulebook between them: the patterns every change follows, each with **why** and
**how it is checked**. Written at the [M2.6 security checkup](history/m2.6-security-checkup.md).

Writ is a security tool: a convention here is not a style. A change that can't follow one
changes this page in the same change, with a row in the [decision log](decisions.md) and, if
it weakens a guarantee or adds a residual risk, the [threat model](threat-model.md) and the
user's go-ahead (hard rule 12).

## How it is enforced

| Check | What it enforces | Where |
|---|---|---|
| `make ci` | Everything below, as one target: GitHub Actions runs it on Linux for every push and pull request; the `pre-push` hook (`make hooks`) runs it on the Mac | `Makefile`, `.github/workflows/ci.yml`, `tool/git-hooks/pre-push`, `tool/install-hooks.sh` |
| clippy (`-D warnings`) | No `unwrap`/`expect`/`panic!`, unchecked indexing, slicing or truncating casts outside tests; no unchecked arithmetic in `writ-core`, `writ-crypto`, `writ-proto`; no `unsafe` | `Cargo.toml` `[workspace.lints]`, each crate's `lib.rs` |
| `tool/check-rules.py` | A file's test module ends it (so nothing escapes the rules below); no bare `is_err()`/`!success()` in tests, no unmarked sleep in tests, no `if let Ok(… .lock())` that skips work, no relative program path in production code, no unexplained `#[allow]` of a denied lint, no `cfg(target_os)` outside the platform code, no prints in libraries | `make check` |
| `tool/check-deps.py` | Clients never depend on daemon crates (hard rule 1) | `make check` |
| `tool/check-features.py` | No `testing` or `dev-keystore` feature in a shipped binary's graph (checks itself on the test crate) | `make check` |
| `tool/check-guarantees.py` | Every guarantee names tests that exist and aren't ignored | `make check` |
| `cargo deny` | Advisories, yanked crates, sources, banned crates, licenses | `deny.toml`, `make check` |
| Review | Everything a script can't see: the checklist below | every change |

## The security checklist

Every milestone's history page answers these, one line each, and every change that touches
one of them answers it in its commit message. "Not touched" is a valid answer; silence isn't.

1. **Inputs.** Does it add or change an untrusted input (a field, a command, a file, a
   header)? It is in the [inventory](#untrusted-inputs), with its size, time and count
   bounds, its parser, and a hostile-input test.
2. **Authority.** Does it add a way to grant, widen or read? It goes through an approver
   signature (grants), a reader key (reads), or a template (scope), never a flag or a client
   check (hard rules 1, 5).
3. **Fail closed.** Every error, unknown value, poisoned lock and missing fact denies;
   fallbacks go toward deny ([details](#fail-closed-in-practice)).
4. **Audit.** Every allow, deny, grant, refusal, revocation and admin change writes its line;
   grants first, reductions never blocked ([details](#grants-reductions-and-the-audit-log)).
5. **Revocation.** Does it hold a decision anywhere (memory, a token, a session)? A
   revocation reaches it, and it is rebuilt from the store at startup.
6. **Secrets.** No key, token or passphrase in an error, a log, a reply, `Debug`, or a file
   others can read; zeroized; moved, never copied ([details](#secrets)).
7. **Display.** Does agent or daemon text reach a terminal or a notification? It is escaped,
   bounded, and never mistaken for Writ's own words ([details](#what-people-see)).
8. **Dependencies.** A new crate or feature follows [the dependency rules](#dependencies).
9. **Guarantees.** A guarantee touched has its tests in the registry, trying to break it.
10. **Threat model.** A new trust boundary, residual risk or weaker guarantee is written in
    the threat model in the same change, with the user's go-ahead.

## Untrusted inputs

Everything here comes from someone the daemon doesn't trust (an agent, a network peer, a
reader with `decisions: open`). Each has a bound, a strict parser, and a hostile-input test.

| Input | From | Bounds | Parsed by |
|---|---|---|---|
| TCP connection | anyone who reaches a listener | `allow` ranges (required on agents' TCP), 256 per listener, 16 per source (an IPv6 /64), 20 s to authenticate, 10 min idle; denials logged once per source and minute, 60 lines a minute in all | `writ_core::net`, `writ-gateway/src/limits.rs` |
| SSH handshake and auth | the same | listed algorithms only, publickey only, 6 attempts, certificate checks (CA, type, validity, principal, no critical option, deny list) | russh with `preferred_algorithms`, `writ_crypto::ca` |
| SSH exec line and env | authenticated peers | exact command grammar, repo names validated, only `GIT_PROTOCOL` (< 64 chars, `[A-Za-z0-9=:.]`), 4 channels per connection | `writ_proto::Command`, `writ-gateway/src/command.rs` |
| Request bodies (SSH stdin, HTTPS) | agents, readers | 256 KiB (`MAX_BODY`), 30 s | `writ_proto` envelope, `deny_unknown_fields` |
| Ticket YAML | agents | the body bound, one document, no anchors/aliases/merge keys, depth 32, 50,000 nodes, strict booleans; text bounds (title 200 one line, task 4,000 / 100 lines, plan 50 × 500 one line, 100 paths, caller fields); `ttl` ≥ 5 min; 2 pending per session key, 10 submissions/min per address, `max_pending` in all | `writ_core::yaml`, `fit` |
| Canonical tickets and decisions | approver clients | decode then re-encode to the same bytes | `writ_core::canonical` |
| SSHSIGs | approver clients | namespace, keys compared whole, accepted key types, `sk-` user presence | `writ_crypto::sshsig`, `allowed_signers` |
| TLS client certificates | HTTPS peers | TLS 1.3, a reader's Ed25519 key, handshake signature checked | `writ_crypto::tls::ReaderVerifier` |
| Pre-receive input | git, on an agent's push | 1 MiB, cut-short refused, every line an exact update | `writ-gateway/src/hook` |
| Pushed objects | agents | `fsckObjects`, `receive.maxInputSize` = the lease's `max_push_size` | git, configured by the gateway |
| Commit bytes to sign | lease holders | `MAX_SIGN_INPUT` | `writ-gateway/src/exec/sign.rs` (M3: parsed by the daemon) |
| Caller facts | the kernel, via the attestor | never what the client claims | `CallerAttestor` implementations |
| Config and authority files | the operator | owner, mode, no link, regular file, 1 MiB | `writ_platform::fs::read_authority` |

A new input is added here in the same change.

## Fail closed in practice

- **No fallback toward allow.** `unwrap_or(0)`, `unwrap_or_default()`, `map_or(true, …)` and
  friends are allowed only when the fallback denies (an empty list, `true` meaning
  "revoked"). A conversion that can't fail in practice still fails the request if it does
  (`map_err(internal)?`), never a default value.
- **A poisoned lock** either fails the request (state), or is recovered with
  `PoisonError::into_inner` when the work is a reduction of privilege (dropping sessions,
  forgetting a push). `if let Ok(lock)` that skips work needs a `// poisoned: <why>` comment
  showing that skipping is the safe side (checked).
- **Missing facts deny**: no process chain, no source address where a list is set, an
  unknown key type, an unreadable row.
- **Accept loops never end on one connection's error**: every listener (each transport,
  and the gateway's own hook socket) accepts through `writ_platform::transport::accept_retrying`,
  which retries transient errors (out of descriptors, a reset before the accept); only a
  broken listener stops it.
- **The deny list is checked at every decision point** (connection, each command, the
  pre-receive hook), not only at connection.

## Grants, reductions and the audit log

- **Grants and allows are logged first** (`Service::logged`): no line, no grant.
- **Reductions of privilege never wait for the log** (`Service::reduced`): revocation,
  withdrawal, expiry, exhaustion and an ended session are applied either way; the
  certificate goes on the deny list first, before anything that can fail; the line is
  written first when possible, otherwise kept in memory (bounded) and written once the log
  can take it.
- **Denials before authentication are coalesced** per source and minute, with a global budget
  of 60 lines a minute, and a count: every denial is counted, and a flood from many sources
  can't fill the disk either.
- **A per-source limit counts sources by group** (`writ_core::net::source_group`): an IPv6
  host holds a whole /64 and would otherwise be 2^64 sources.
- **Every refusal is a line**, wherever it happens: a refused TLS handshake, a plain key for a
  user that takes a certificate, a source not allowed, as much as a lease decision.
- **The audit log is plain data**: no field can hold a secret, hidden characters are
  escaped, a failed write never glues lines together, the file is `0600`.
- **The daemon's own log stays bounded**: what any peer can trigger is logged at `debug`
  (the audit line is the record), and an audit-log outage is reported once, not per line;
  a lasting accept failure is reported once per accept, when its pause reaches a second.

## Revocation and enforcement state

- **Anything that enforces a lease and lives in memory is rebuilt from the store at
  startup**: the deny list, the session watches (a session that can't be watched revokes
  its lease).
- **A decision made earlier is checked again when it takes effect**: the pre-receive hook
  re-authorizes the lease; a revoked lease's pushes in progress are forgotten.
- **An amendment keeps the lease's whole subject** (session key and bound process).

## Files that grant authority, and secrets

- **Authority files** (`writd.yaml`, the policy, `approvers`, `readers`) are read with
  `read_authority`: no link followed, never blocking (a FIFO), a regular file of the
  daemon's user, writable by nobody else.
- **Secrets** (bot token, wrapped key, keystore keys) are read with `read_secret`: the same,
  readable by nobody else, bounded, zeroized.
- **Created files** are private from creation (`0600`, `create_new`, directories `0700` with
  `DirBuilder::mode`), never through a link, never overwritten.

## Secrets

- A secret has its own type, zeroized on drop, with a redacting `Debug` (hard rule 3).
- A secret never enters an error, a log line, a reply, the audit log or a notification; a
  library error that might hold one is replaced by a short word. Tests scan for them
  (`looks_secret`, `errors_and_debug_never_contain_the_token`).
- Key material moves into the library that needs it; no other copy is kept.
- A token travels in clear only to this machine (Telegram's `http` base: loopback only), and
  never through a proxy named in the environment (`proxy(None)`, tested in a child process
  with every proxy variable set).
- No `log` → `tracing` bridge: libraries such as ureq log URLs that hold tokens
  (`cargo deny` bans the bridges).

## What people see

- **Agent and daemon text is escaped** before any terminal: `display::clean`/`clean_lines`
  turn every hidden character into a visible `\u{…}`. The hidden set is generated from
  Unicode categories (`tool/gen-hidden-chars.py`), never written by hand.
- **The trusted display is bounded** (40 lines per agent field unless `--full`) and **ends
  on the enforced terms**, right above the prompt. Lists are quoted so two different lists
  never read the same.
- **Enforced identities are ASCII** (committer emails), so look-alikes and invisibles can't
  pass for another.
- **No agent text leaves the network** in a notification, and nothing in a notification
  grants anything.
- **Unsigned words are labeled**: feedback from a refusal nobody signed reaches the agent and
  the revision marked as such.
- **A confirmation flag needs an explicit target** (`writ sign --yes <id>`).

## Library defaults are never the decision

What a library or a build feature happens to accept is not a policy. Each is stated in code,
with a test:

- YAML: `writ_core::yaml::options` (no anchors, aliases, merge keys, includes or variable
  interpolation; strict booleans; bounded).
- SSH: `preferred_algorithms` in the gateway (no compression, modern kex, AEAD, Ed25519 and
  P-256 keys).
- TLS: 1.3 only, ring, pinned server certificate, reader client certificates.
- Key types: approvers (`APPROVER_KEY_TYPES`), readers (Ed25519), session keys (Ed25519,
  P-256); `sk-` approvals need user presence.
- Certificates: critical options refused.
- git: a clean environment, no system or global config, the gateway's own hooks,
  `fsckObjects`, a size cap.

## Subprocesses

- **By absolute path**, or a `// PATH: <why>` comment saying why `PATH` is trusted there
  (the daemon's own git; the agent host's own tools) (checked).
- **A clean environment** (`env_clear`, then only what is needed).
- **No argument can start with `-`** where a value is user-chosen (hosts, users, URLs).
- **The strictest flags**: `ssh-keygen -Y sign -U` (agent only), `git upload-pack --strict`.

## Cryptography

- Approvals and admin changes are SSHSIGs (namespace `writ-approval`) over canonical bytes by
  a key in `approvers` (hard rule 5); keys are compared whole, never by fingerprint.
- One key, one purpose: the approval key signs, the reader key opens the approval API, the
  session key identifies a lease, the CA key issues certificates. Never reuse one for
  another; the daemon refuses to start with a key listed both in `approvers` and `readers`.
- Randomness comes from the OS and fails rather than falls back.
- Certificate validity is the lease's; serials are random and unique; a time that doesn't
  fit fails the grant.

## Code

- **No panic on hostile input**: no `unwrap`/`expect`/`panic!`, no unchecked index, slice or
  truncating cast outside tests (clippy); `.get()`, `split_at_checked`, `strip_prefix`
  instead. An `#[allow]` says why it can't fail, on the line above (checked).
- **No unchecked arithmetic** in the crates that parse and compute limits (`writ-core`,
  `writ-crypto`, `writ-proto`): `checked_*` or `saturating_*`. Release builds keep overflow
  checks.
- **No `unsafe`** (`unsafe_code = "deny"`); safe wrappers (`rustix`) for system calls.
- **Parse, don't validate**: untrusted strings become validated newtypes at the edge.
- **Compare security values exactly**: never `Path ==` (it normalizes), never a fingerprint
  where the whole key is at hand, case-insensitively where a file system folds case (refs;
  repo names, which name mirrors, are unique ignoring case).

## Dependencies

- A new crate needs a row in [stack.md](stack.md) ("Decided", with the reason), the fewest
  features it needs (`default-features = false` when possible), and `cargo deny` passing.
- Prefer a crate already in the tree; prefer ring/rustls for cryptography; never `openssl`,
  `native-tls`, `rsa` or a `log` bridge (`deny.toml`).
- An advisory is never ignored silently: `deny.toml` lists each accepted one with its reason,
  and the decision log has its row.
- `Cargo.lock` is committed and every build is `--locked`; the toolchain is pinned.
- No third-party GitHub Action: CI runs `make ci` with git and the runner's tools.
- How to upgrade anything, and what to do when an advisory appears:
  [dependency upgrades](guides/dependency-upgrades.md).

## Tests

The hardened-test rules are in [testing.md](testing.md#hardened-tests). For security:

- **Every denial asserts its exact code or variant** (`DenyCode`, `RefusalCode`,
  `LifecycleError`…), or an exit status's exact code. `// any error: <why>` marks the rare
  opaque failure (checked).
- **Every limit is tested on both sides**, at the limit and one past it.
- **Hostile input is tried** wherever input is untrusted: escapes, bidi, tag characters,
  look-alikes, path-like names, cut-short and oversized input, a link or a FIFO in place of
  a file.
- **Refusals are proven to be the check's doing**: the allowed case runs next to the denial.
- **No test depends on time passing**: signals, `FakeClock`, paused tokio time; a poll says
  what it waits for (`// poll:`, checked).

## Guarantees and their tests

The [threat model's guarantees](threat-model.md#what-writ-guarantees) table is the registry:
each guarantee names the tests that try to break it, checked by `tool/check-guarantees.py`. A
new guarantee, or a change to one, updates the table and its tests in the same change. A
guarantee that a later milestone brings says so (`planned: M<n>`) and is the only kind
allowed without a test.

## Known gaps

What this page doesn't cover yet, with the milestone that does: process hardening (no core
dumps, no debugger attach, secrets out of swap: M5), the TLS key behind the `Signer` (M5,
M7.5), the shared `~/.writ/sessions/current` pointer (M6/M7), macOS-only code tested only by
the pre-push hook (CI is Linux). The [residual risks](threat-model.md#residual-risks-v1) list
the rest.
