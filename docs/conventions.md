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
  `writ-signer`, `writ-approval`, `writ-alloc`, `writ-mirror`, `writ-crypto`): fakes, contract suites, builders, test-only constructors
  (`Store::open_in_memory`). A crate's own tests turn it on through a dev-dependency on itself.
  Production code never enables it. `make check` also lints each library alone (`LIBRARIES`
  in the Makefile, the platform crates with them), so code that only compiles with the
  feature can't hide.
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
- **A type that stands for a check's result has private fields** and is made only by the
  check (`CheckedAdmin`, `CheckedToken`): holding one proves the check ran, whatever order
  its callers call things in. It isn't `Clone` (what holds one moves it), and every public
  call that acts on what was checked takes it (`Service::replace_ca` takes the rotation's).
- **One function for one job across crates**: what two clients both need (the terminal
  escaping, a URL's parsing) lives once, in the crate they share (`writ_core::text::escaped`),
  so the two can't drift (`writ-sign` once took a port `writ` refused).

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
  and sends only "internal error". No internal detail, path or secret reaches a client. A
  lease holder's denial is built with `Denial::new(code, reason)`, and an internal failure on
  its path is `Denial::internal()` (one wording, "internal error in the daemon", the cause in
  the daemon's log).
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
- **Every binary frees through the wiping allocator**: `writ_alloc::Wiping` is the
  `#[global_allocator]` of `writd`, `writ` and `writ-sign` (checked by `tool/check-rules.py`,
  and by a test in each binary), so a library's freed copy of a secret is zeroed too. A new
  binary that handles a secret sets it the same way. It doesn't replace the rules below: they
  end a secret's life when its owner is done, not when its memory happens to be freed.
- **A buffer that will hold a secret never grows by itself**: a `Vec` or `String` that grows
  frees its smaller buffer, a copy of the secret in each (the wiping allocator zeroes it, but
  Writ's own secrets don't rely on it). Size it up front
  (`String::with_capacity`), or grow it into a new `Zeroizing` buffer by hand
  (`limits::read_within`).
- **A secret's file is written whole**: to a private temporary file beside it, synced, then
  linked into place (never over a file there) and the directory synced; the temporary file
  removed whatever happens (`keystore::write_private`).
- **Redaction covers every form a secret comes back in** (as is, and as the protocol sends it:
  `base64(user:token)` for HTTP Basic), and runs again after the text is cleaned: a hidden
  character inside the secret is stripped by the cleaning and would rebuild it.

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
  Decide under the lock, act outside, check again under the lock, against the policy in force
  too (`Service::sign`'s three phases). What is reserved in the first phase is never given
  back on failure. **Nor under any other lock a change needs**: a value read under a lock for
  a slow call is copied out first: `match self.lock().get(..) { Some(&v) => slow(v) }` holds
  the guard for the whole arm (`Service::openpgp_created`). Work done under the lock is
  bounded by the input's bounds (the path match by the ticket's), cheap checks first.
- **A request that changes state runs to its end**: on a task of its own, never inside a
  future its transport drops when the client goes away (hyper drops an HTTPS request's on
  EOF); only the reply is lost. **A wait for a client ends with it**: raced against its
  channel (`writ wait`).
- **A task that serves connections owns them**: in a `JoinSet` its abort ends, never spawned
  loose (dropping a `JoinHandle` detaches the task, it doesn't stop it). **A background task
  is supervised** (`writd`'s `supervise`: the sweeper, the mirrors' sync): one that ends is
  logged and started again, one that keeps ending stops the daemon in order, and the orderly
  stop ends them first.
- **Bounded everything** from untrusted peers: every read has a limit and refuses past it
  (`MAX_BODY`, `MAX_SIGN_INPUT`, `MAX_HOOK_INPUT`), handshakes and headers have timeouts, and a
  cut-short input is refused rather than decided on in part.
- **One worker, not a thread per event** for background work (the notification worker).

## Clients

- **Settings passed through the environment reach every child process** (`GIT_CONFIG_*`,
  `GIT_SSH_COMMAND` from `writ git` / `writ exec`). A client that acts on them checks that it
  runs in the context they were made for, and refuses with both sides named otherwise
  (`writ-sign` and `writ.gitdir`). A convenience, never a boundary: the daemon decides.
- **A client file that pins trust** (`known_hosts`, `tls_pins`) is the user's (or root's)
  and writable by nobody else, checked on the file opened (`client::read_pins`): whoever could
  rewrite a pin could stand in for the daemon.
- **What the trusted display prints fits 80 columns, row by row** (`display::WIDTH`): agent
  text goes through `display::block` or `display::cut`, each continuation behind the gutter;
  the terminal never wraps a row.

## Installers are guided

What sets a machine up (`make install`, `make uninstall`, each setup in `deploy/setups/`)
is written for the person running it, who may not know Writ yet (asked by the user, M7.5):

- **Every choice is asked on the terminal**, one question at a time, each with what it means
  in plain words, the values it takes and what Enter keeps (`ask`, `choose_one`,
  `choose_approver` in `deploy/frame.sh`), drawn by `writ prompt` with `writ`'s widgets (a
  select of the values it takes, text, a confirm; M7.9.5) when the build's `writ` is there,
  else as plain lines. A wrong answer is said and asked again, never a
  failure the person has to start over from. Nothing the person must know beforehand (a
  variable, a flag, a path convention) is needed to get through.
- **Nothing changes before one confirmation**: the answers and every change, in order (the
  dry run's list, `planned`), then `Install?` / `Upgrade?` / `Uninstall?`. Anything but yes
  leaves the machine as it was.
- **Deleting for good is typed out** (`delete`), never a yes.
- **Variables answer the same questions for scripts and tests** (no terminal), each checked
  as a typed answer would be; the guide lists them apart ("Without a terminal"), never as the
  way to install. A setup's question and its variable come together: `setup_questions` asks,
  `setup_answers` says what was chosen.
- Each setup says what it is in one line (`# writ-setup-about:`), shown where the setup is
  chosen.

## Comments and docs

- **Every public item that isn't obvious from its name and type has a doc comment**; contract
  enums document every variant (`DenyCode`, `EventKind`, `Outcome`, `State`: their text is a
  stable contract). Self-describing fields need none (`missing_docs` is not enabled for that
  reason).
- **Comments say why, not what**: the reason for a limit, a refusal, an ordering.
- **Rustdoc links point at items**; documentation pages are named in plain text
  (`docs/flows.md` § 1), since relative paths don't resolve in rustdoc.
- **No milestone promises in code comments** beyond "until M<n>" on a known stopgap; the
  history and the backlog hold the plan.
- **Docs change with the code** (hard rule 15): behavior → its page, a decision → the
  decision log.

## Configuration keys

The [operator documentation](operators/README.md) is the operator's reference: a key missing
there, or described as it was, is a bug. A change that adds, removes, renames or changes a
key, a value, a default or a bound of `writd.yaml`, `policy.yaml` or the ticket file, or an
environment variable a binary reads, does in the same change (hard rule 19):

1. **The struct that parses it**: its default and its bound, checked at load with an error
   naming the key.
2. **Its reference row** (`docs/operators/writd-yaml.md`, `policy-yaml.md`, `ticket.md`,
   `clients.md`): the value, the default, the bound and what it does, or that its effect isn't
   built yet and from which milestone.
3. **Its file's template** (`docs/operators/templates/`): set if required, commented out at
   its default otherwise.
4. **A test that sets it and checks its effect**: an integration test (`crates/writ-integration`)
   or an end-to-end scenario, named in the
   [configuration coverage registry](testing.md#configuration-coverage-every-key); a parser's
   unit test is not enough. A key accepted before its effect is built names the backlog
   idea that brings it (for instance `planned: [detached deployment](backlog/detached-deployment.md)`) until its effect exists.
5. **The examples** that show it: the [development configuration](../dev/writd.yaml), the
   [lease model](lease-model.md), a guide.

A value this build can't honor at all (a Unix socket before local mode, `ticket_link: notes`
before M4.7) is refused at start with the milestone that brings it, never taken and ignored.

Checked: `make test` fails when a key the parser takes has no reference row, no registry row
or no line in its template, when a row names a key the parser doesn't take, when an
enumerated value isn't in its row, or when a template doesn't parse as written and with every
commented-out setting taken in (`writd`'s and `writ-core`'s `every_…_key_is_in_the_operator_reference`
and `the_…_template_parses_…`); `make check` fails when a test the registry names doesn't
exist, or a planned milestone is already done (`tool/check-config.py`).

## Format changes

A change to what the daemon keeps across an upgrade comes with the way to carry it over, in
the same change (M7.9.6):

- **The state** (a table, a column, what a row holds): `STATE_VERSION` goes up by one, the
  schema of a new database takes the change, and `writ-store`'s `STEPS` gains the step from
  the version before, run in one transaction, never touching a ticket's signed bytes. The
  schema it starts from is kept frozen in `crates/writ-store/tests/schemas/v<N>.sql` (never
  edited afterwards), and a test migrates a database written by it, with rows in every table,
  and reads every row back. A ticket format change (`writ-ticket/N`) is a state change too.
- **The policy** (a key removed, renamed, or read differently): the policy's `format` goes up
  by one, and `writ_core::config::migrate` gains the rewrite from the format before, or the
  reason naming each key it can't carry over. The daemon never reads an older format: it is
  only ever rewritten, and the rewrite is signed (`writ migrate`).

Either one also gets its line under `### Upgrading` in the [changelog](#versions-and-the-changelog).

## Versions and the changelog

Writ has one version, `[workspace.package] version` in the root `Cargo.toml`; every crate
takes it (`version.workspace = true`). It is SemVer (M7.9.8):

- **Before 1.0**, a milestone's close is a minor version (`0.N.0`), and a fix released on
  its own between two milestones a patch. **1.0.0** closed v1 (after M7.9.9, detached
  deployment and non-exportable session keys moved to the backlog).
- **From 1.0**, a major version is an upgrade that owes a signed `writ migrate` (a policy
  format change), or one where a `writ` of the previous major can't talk to the new `writd`.
  A new feature is a minor version, a fix a patch. A state step alone is neither: it
  migrates by itself after a copy.

[`CHANGELOG.md`](../CHANGELOG.md), at the root, is written by hand for the person who runs
Writ, under the [operator writing rules](#writing-operator-docs):

- **A change people see adds its line under `## Unreleased`, in the same change**, as rule 15
  asks of the docs: a command, flag, key, value, default or bound added, changed or removed;
  a behavior or a refusal changed; a step an upgrade needs; a security fix. A refactor, a
  test, or a page for developers adds none.
- **The sections**, each `### <name>`, in this order, each once, each a list: Upgrading,
  Added, Changed, Deprecated, Removed, Fixed, Security. A line says what changed for the
  reader in a sentence or two, and links to its history page or doc for the rest.
- **Every release starts with `### Upgrading`**: the state version, the policy format,
  whether `writ migrate` is owed, whether a `writ` and a `writd` of the two versions can talk
  (the protocol's messages refuse fields they don't know, so two versions talk only when no
  message changed between them), and the steps, in order.
- **A release** is made by the closing commit of a milestone or a backlog idea (or a patch's): `## Unreleased`
  becomes `## <version> — <YYYY-MM-DD>`, a new empty `## Unreleased` goes above it, and the
  workspace's version moves to it (`cargo update --workspace` then updates `Cargo.lock`),
  all in that one commit.

Checked: `make check` fails when the file is out of shape (its headings, an unknown section,
one out of order or empty, a release without `### Upgrading` first), when a version is
released twice or the releases aren't newest first in version and date, when the newest
release isn't the workspace's version (so the version moves only with its release), or
when a crate has a version of its own (`tool/check-changelog.py`, its tests in
`tool/check-changelog-test.py`). That each change people see has its line is for review.

## Writing operator docs

The [operator documentation](operators/README.md) is read by a person setting Writ up or
fixing it, often in a hurry. It must stay readable by a human. The design pages (`architecture/`,
`threat-model.md`, `security.md`) can be dense; these can't. A change that touches a page in
`docs/operators/` follows these rules, and review checks them.

**Sentences**

- **One idea per sentence.** Short sentences. No chains of clauses joined by colons and
  semicolons; no parentheses inside parentheses. If a sentence needs a second colon, split it.
- **Plain words, addressed to the reader**: "you sign", "your machine", "the daemon refuses".
  Not "the approver's machine" when the reader is the approver.
- **Say each thing once.** A rule that applies to several keys or pages is written in one
  place and linked (the "after `writd init`" note in `writd-yaml.md`, the terms in the index).
- **Define a recurring term once**, in the index's "Words used in these pages", and use it
  without re-explaining it.

**Guides** (`setup.md`, `sealing.md`, `recovery.md`, `hardening.md`, `good-practice.md`)

- **Action first**: a bold line saying what to do, then the command, then what to expect
  (what it asks, what it prints, what to check). Numbered steps for a sequence.
- **The reason in one line**, with a link for more ([threat model](threat-model.md),
  [architecture](architecture/overview.md)). The guide says what to do; the design pages
  say why.
- **Tables and lists for choices and comparisons** (wrapper vs whole repo, boot vs sealed,
  a token per remote), not a paragraph that walks through each case.
- **A page starts with what it is for** in a sentence or two, and the index routes by task
  ("I want to…").

**References** (`writd-yaml.md`, `policy-yaml.md`, `ticket.md`, `clients.md`)

- **One table per section, four columns**: Key, Accepts, Default, What it does. "Accepts"
  holds the type, the bounds and every enumerated value; "Default" the default, or
  **required**.
- **Short cells**: one or two sentences. An explanation longer than that goes in a list or a
  short subsection under the table, linked from the cell (`ticket_link`,
  `paths_check`, `allow`).
- **The page's common rules first**, as a short bulleted list: when the file is read, unknown
  keys refused, units, who may write it.
- **Machine-checked shape** (configuration keys above): every line starting with `` | ` `` on
  these pages is read as a key row, so value explanations are lists, never another table
  whose first cell is in backticks.

**Status**

- **Not built yet** is said in bold with a link to its backlog page ("**Not built yet**
  ([detached deployment](backlog/detached-deployment.md))"), and nowhere else: no milestone
  history, no internal names (crates, functions, test names) unless the reader needs them.
- **Commands the pipeline runs keep their exact text** (hard rule 18): every `sh` block of a
  page listed in [commands the docs show](end-to-end.md#commands-the-docs-show) is run by
  `make e2e`. Reword around a command, never the command. No `<!-- e2e -->` marker or other
  tooling comment on these pages: the link lives in that table. A command the pipeline doesn't
  run goes in a `text` block, or the page leaves the table.

## Tests

The rules for tests (determinism, what each level tests, how to try to break a guarantee) are
in [testing.md](testing.md). In short: no test depends on time passing, on order it doesn't
control, or on unseeded randomness; every denial asserts its exact code or error variant;
every limit is tested on both sides; shared fixtures come from the test kits
(`writ_platform::testing`, `writ_approval::testing`, `writ-integration`), not copies.
