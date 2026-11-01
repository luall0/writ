# Code conventions

How the code in this repo is written. [AGENTS.md](../AGENTS.md) holds the hard rules (what must
never happen); the [security conventions](security.md) hold the security rules every change
follows; this page holds the conventions that keep the code uniform, so a reader finds
things where they expect them. Written at the [M2.5 checkup](history/m2.5-code-quality-checkup.md);
`make check` enforces what a script can check, and review enforces the rest.

A change that breaks a convention either fixes the code or changes this page, in the same
change, with a row in the [decision log](decisions.md) when the reason isn't obvious.

## Crates

- **One crate per role**, named `writ-<part>` ([overview](architecture/overview.md#repository-layout)).
  The [dependency directions](architecture/overview.md#dependency-directions) are checked by
  `tool/check-deps.py`.
- **Every crate has a `README.md`**: what it does, what it doesn't (its scope), what it may
  depend on, where its design is documented. A new crate gets one in the same change.
- **Libraries expose modules, not a flat root.** A crate's root re-exports only the few types
  every user needs (`writ_store::{Store, AuditLog, …}`); the rest is reached through its module
  (`writ_core::policy::Denial`). Don't re-export another crate's items.
- **`writ-core` is pure**: no I/O, no clock, no randomness. Time comes in as `now: Timestamp`,
  randomness as bytes (`TicketId::from_parts`).
- **Test support lives behind a `testing` feature** (`writ-platform`, `writ-store`,
  `writ-signer`, `writ-approval`): fakes, contract suites, builders, test-only constructors
  (`Store::open_in_memory`). A crate's own tests turn it on through a dev-dependency on itself.
  Production code never enables it. `make check` also lints each library alone, so code that
  only compiles with the feature can't hide.
- **Dependencies**: versions once in the root `Cargo.toml`, `dep.workspace = true` in the crate.
  A dependency nothing uses is removed. Each crate in [stack.md](stack.md) is "Decided" before
  it is relied on.

## Modules

- **One concern per file.** When a file holds several (an interface and its implementations,
  a service's callers, a transport and its routing), it becomes a module with sub-files.
- **Layout `name.rs` + `name/part.rs`**, never `mod.rs` (except `tests/common/mod.rs`, Cargo's
  convention for shared test code). Checked by `tool/check-rules.py`.
- **`name.rs` is the module's front door**: its `//!` header, the shared types, and `mod`
  lines. Sub-files hold the pieces.
- **Every file starts with a `//!` header**: what it is, and its trust stance when it handles
  untrusted input ("agent-written text, shown as-is", "clients are untrusted").
- **An interface is a module, each implementation a file in it**
  ([platform.md](architecture/platform.md)):

  ```
  notify.rs              trait Notifier, Notification, Priority, Notifiers (the fan-out)
  notify/telegram.rs     TelegramNotifier, BotToken
  transport.rs           trait Transport, Connection, PeerInfo
  transport/tcp.rs       TcpTransport
  ```

  Implementations are reached by their full path (`writ_platform::notify::telegram::TelegramNotifier`):
  the path says which one. Platform-only implementations go in `writ-platform-<os>` crates,
  laid out the same way. Every interface has a contract suite (`writ_platform::contract`) and a
  fake (`writ_platform::testing`), and every implementation passes the suite.
- **A large type with many callers is split by caller**, each file with its own `impl` block:
  `writ_approval::Service` is `service.rs` (state, helpers) + `service/{agent,approver,gateway,sweep}.rs`.
- **Functions stay short**: past ~60 lines, or seven arguments, split them or bundle the
  arguments in a struct (`Approving`, `Refusing`).

## Visibility

- **As private as possible**: `pub(crate)` or `pub(super)` unless another crate uses it. A
  `pub` item nobody outside uses is narrowed.
- **Fields are `pub` on plain data** (messages, events, records) and private on types that
  hold an invariant (`BotToken`, `TlsIdentity`, `Service`): build those through their
  constructor.
- **Dead code is removed**, not commented out or kept "for later".

## Types

- **Parse, don't validate.** Every identifier, name, unit and pattern is a newtype that can
  only hold a valid value (`RepoName`, `TicketId`, `Duration`, `RefPattern`); it is parsed at
  the edge (YAML, a command line, a CLI flag) and never re-checked. Its parser is its
  `FromStr`; serde and clap go through it.
- **One name for a thing, one source for its text**: an enum's wire name, `Display` and
  `FromStr` agree, and a test says so (`operation_names_are_the_same_everywhere`).
- **Enums over booleans and strings** for anything with a fixed set of values (`Newlines::Keep`,
  `display::Field`, `Approvals::Https`).
- **Deterministic collections** wherever order can show: `BTreeSet`/`BTreeMap` in anything
  serialized, signed or displayed.
- **Strict input**: `#[serde(deny_unknown_fields)]` on everything deserialized; canonical
  documents implement `writ_core::canonical::Canonical` and decode only from their exact bytes.
- **One source for a fact.** What can be read from an object is read from it where it is
  used, not carried beside it in fields that must agree (`Signing` holds the commit, and the
  service reads the committer, trailers and format from it: `SignObject`). An enum of the
  cases beats two `Option`s that are `Some` together.
- **No parameter that is always one value**: a constant the callee owns (the SSHSIG namespace
  `git` in `Service::sign`) is one less input to trust.

## Errors

- **`thiserror` in libraries, `anyhow` only in binaries** (hard rule 11).
- **An error enum is named after its crate or domain**: `CryptoError`, `GatewayError`,
  `StoreError`, `PlatformError`, `ServiceError`; in `writ-core`, one per domain
  (`LifecycleError`, `FitError`, `CanonicalError`). Never a bare `Error`: `writd` imports many.
- **One variant per cause** the caller may handle or a test may check (`LeaseNotActive`,
  `SessionKeyChanged`), not a catch-all `String`; a refusal carries a stable code
  (`ServiceError::Refused { code: RefusalCode, .. }`) beside its message. **Each limit has its
  own variant** (`PathsError::TooManyEntries`, `TooManyPaths`, `PathTooLong`,
  `TooManyBytes`), so a test can tell which one fired.
- **A message says what was checked, nothing more**: an error that names a format
  (`name <email> time zone`) comes from a parser that checks all of it.
- **Causes are kept**: `#[from]` / `#[source]`, never `e.to_string()` into a `String` variant.
- **Messages**: lowercase, no trailing period, they name the object (`invalid repo name "x":
  …`, `lease wrt_… is revoked`); several reasons are joined with `; `, or listed one per line.
  A sentence meant for the agent (a denial's hint) is the exception and is written as one.
- **What a client sees is decided at the boundary.** The approval service returns
  `ServiceError`; the gateway converts it to the wire `ApiError`, logs an internal cause there
  and sends only "internal error". No internal detail, path or secret reaches a client.
- **Fail closed** (hard rule 2): a poisoned lock, an unreadable row, a failed clock deny.
- **Binaries add context to every I/O error** (`.with_context(|| format!("cannot read {}",
  path.display()))`): the user sees which file.

## Secrets

- **A secret has its own type** that zeroizes on drop (`Zeroizing`) and prints
  `Type(<redacted>)` in `Debug` (`BotToken`, `Passphrase`, `DataKey`). Types that hold one
  derive no `Debug`, or write a redacting one.
- **A secret never enters an error, a log line or the audit log**: error texts of libraries
  that can embed it (a URL holding a token) are replaced by a short word (`transport_failure`).
  Tests check it (`errors_and_debug_never_contain_the_token`, `looks_secret`).
- **Files holding secrets are private**: created `0600` with `create_new` (never overwritten,
  never through a link), directories `0700` from creation; a secret file handed to the daemon
  is read with `writ_platform::fs::read_secret` (no link followed, never blocking on a FIFO,
  a regular file of the daemon's user, readable by nobody else, bounded, zeroized), and a
  file that grants authority with `read_authority` (the same, writable by nobody else).
  Client side: `writ-cli`'s `session` (`create_private_dir`, `write_private`, `load_key`).
- **Key material moves, it isn't copied**: when a library takes ownership (rustls), no other
  copy is kept.

## Logging and the audit log

- **The audit log records decisions; logs are diagnostics.** Every allow, deny, grant,
  refusal, revocation and admin change writes one audit line (hard rule 9), through the
  service's typed helpers (`Service::logged`, `gateway_denied`). A log line never replaces one.
- **Audit before change** for grants (`Service::logged`): the line is written (and synced)
  before the state changes; if the change then fails, a `denied` line follows. **Reductions
  of privilege never wait for the log** (`Service::reduced`): applied either way, the line
  kept and retried ([decisions](decisions.md)).
- **Libraries log with `tracing`** (`tracing::warn!(error = %e, "notification failed")`):
  lowercase message, facts as fields. They never print: `tool/check-rules.py` refuses
  `println!`/`eprintln!` in library code. The one exception is a program's own output (the
  pre-receive hook's stderr, which git shows the agent).
- **Only `writd` installs a subscriber**: stderr, filtered by `WRIT_LOG` (`info` by default).
- **Binaries print their output** (`writ`'s display, `writd host-key`) and a single error line
  (`writ: <error chain>`).

## Async and threads

- **Nothing blocks the runtime**: SQLite, fsync, file I/O and blocking HTTP run in
  `spawn_blocking` (`Gateway::authorize`, `api::blocking`). No lock is held across an `.await`.
- **Nothing slow under the service's state lock**: no signer call, device, network or
  subprocess while it is held, since every approval, revocation and decision waits on it.
  Decide under the lock, act outside, check again under the lock. The software signer in
  `Service::sign` is the known exception until [M3.5](roadmap.md#m35--signing-outside-the-lock).
- **Bounded everything** from untrusted peers: every read has a limit and refuses past it
  (`MAX_BODY`, `MAX_SIGN_INPUT`, `MAX_HOOK_INPUT`), handshakes and headers have timeouts, and a
  cut-short input is refused rather than decided on in part.
- **One worker, not a thread per event** for background work (the notification worker).

## Clients

- **Settings passed through the environment reach every child process** (`GIT_CONFIG_*`,
  `GIT_SSH_COMMAND` from `writ git` / `writ exec`). A client that acts on them checks that it
  runs in the context they were made for, and refuses with both sides named otherwise
  (`writ-sign` and `writ.gitdir`). A convenience, never a boundary: the daemon decides.

## Comments and docs

- **Every public item that isn't obvious from its name and type has a doc comment**; contract
  enums document every variant (`DenyCode`, `EventKind`, `Outcome`, `State`: their text is a
  stable contract). Self-describing fields need none (`missing_docs` is not enabled for that
  reason).
- **Comments say why, not what**: the reason for a limit, a refusal, an ordering.
- **Rustdoc links point at items**; documentation pages are named in plain text
  (`docs/flows.md` § 1), since relative paths don't resolve in rustdoc.
- **No milestone promises in code comments** beyond "until M<n>" on a known stopgap; the
  history and the roadmap hold the plan.
- **Docs change with the code** (hard rule 15): behavior → its page, a decision → the
  decision log.

## Tests

The rules for tests (determinism, what each level tests, how to try to break a guarantee) are
in [testing.md](testing.md). In short: no test depends on time passing, on order it doesn't
control, or on unseeded randomness; every denial asserts its exact code or error variant;
every limit is tested on both sides; shared fixtures come from the test kits
(`writ_platform::testing`, `writ_approval::testing`, `writ-integration`), not copies.
