# Testing

Run everything with `make test`; lint, format, dependency directions and source rules with
`make check`. Writ is a security boundary: a missing deny is a bug as serious as a crash, and
a test that passes by luck is no test at all.

## Three levels

| Level | What it tests | Needs | Runs in |
|---|---|---|---|
| **Unit** | One crate alone: its unit tests (`#[cfg(test)]`) and its `tests/`, on the platform fakes (`writ_platform::testing`) and the test kits (`writ_approval::testing`) | nothing | `make test` |
| **Integration** | The crates and the binaries together (`crates/writ-integration`): the real `writd`, `writ` and `writ-sign`, the real `git` and OpenSSH, a throwaway `ssh-agent` standing in for the approver's, a fake Telegram Bot API; temporary `HOME` and git config | the local tools only (checked at start: `git` ≥ 2.34, OpenSSH ≥ 8.9, `nc`) | `make test` |
| **End to end** | Real external services: a test remote in Docker, a throwaway GitHub repo (from M4) | Docker, network | `make e2e` |

Each milestone's acceptance items become integration scenarios (end-to-end ones from M4).
What needs a human stays manual: the approver's real agent (`make test-agent`, Touch ID) and
the [manual checks](guides/manual-checks.md).

## Hardened tests

These rules hold for every test, at every level.

- **Deterministic.** A test checks the same thing every run, whatever the machine's speed:
  - **No waiting on time.** Never `sleep` and then assert. Wait for a signal: a condvar
    (`RecordingNotifier::wait_for`, `FakeTelegram::wait_for`), a channel, a broadcast
    (`Service::subscribe_revocations`), a process's exit, a log line. Only what gives no
    signal (another process's socket appearing) is polled, through one helper
    (`writ_platform::testing::eventually`) with a deadline (`WAIT_LIMIT`) that fails the test.
    A deadline bounds how long a test looks; it never decides what the test checks. "Still
    pending after 50 ms" is fine because pending is the only possible outcome, not because
    50 ms is enough.
  - **No real clock** where the code takes one: the service runs on `FakeClock`, moved by
    hand. (The gateway tests use the system clock, because russh checks certificate validity
    against it itself; nothing in them waits on time.)
  - **No order it doesn't control**: ordered collections, ordered delivery (the notification
    worker delivers in order, so "a rejected ticket never notifies" is checked by the next
    notification being the valid ticket's).
  - **No fixed ports**: bind port 0 and read the port back (the daemon logs the ports it bound;
    the fixture reads them).
  - **No unseeded randomness** in what a test asserts. Generated keys and ids are fine
    (nothing depends on their value); property tests are seeded (below).
- **Adversarial.** A test tries to break the check, not to exercise it:
  - every denial asserts **its exact code or error variant** (`DenyCode::ProtectedRef`,
    `RefusalCode::Signature`, `LifecycleError::SessionKeyChanged`), or an exit status's exact
    code, never just `is_err()` or `!success()`. Where the error really is opaque (a TLS or
    SSH library's failure), the assertion says so in a `// any error: <why>` comment, and
    `tool/check-rules.py` refuses a bare one;
  - no sleep: a poll for something that gives no signal says what it polls in a
    `// poll: <why>` comment (checked by `tool/check-rules.py`);
  - every limit is tested **on both sides**: one below allowed, at the limit denied (counts,
    sizes, expiry to the second, input lengths);
  - every allowed case next to its denials passes, so the denial is the check's doing and not
    a broken fixture;
  - hostile input is tried where input is untrusted: escape sequences and bidi controls in
    every agent-written field, cut-short and oversized input, path-like names.
- **Fixtures are shared, not copied**: the test kits and the integration harness hold the
  service setup, the approver's signatures, the agent, the daemon. A fixture edited for a test
  asserts the edit applied, so a drifted fixture fails instead of weakening the test.

## Property tests

`proptest` runs in two passes, both in `make test`:

1. **Fixed seed**: the same inputs every run, plus every case in
   `crates/writ-core/tests/properties.proptest-regressions` (each failure ever found).
2. **Random seed**: new inputs each run. The seed is printed
   (`proptest seed: … (replay with WRIT_PROPTEST_SEED=…)`), so a failure is replayed exactly
   with `make test-props SEED=<seed>`; the failing case is also saved to the regressions file,
   which is committed, so the fixed pass checks it from then on.

| Area | What to test |
|---|---|
| `writ-core` | Table-driven tests for every policy decision (allowed and denied, with the reason). Property tests (`proptest`): narrowing never widens; a ticket outside every template is never accepted; two matching leases deny; counters never exceed limits. Canonical encoding pinned by fixtures in `crates/writ-core/tests/fixtures/`. Lifecycle: every transition allowed by the [state diagram](lease-model.md#lifecycle), every other one refused. |
| `writ-crypto` | SSHSIG round trips for each algorithm; signatures from real `ssh-keygen`, directly and through a throwaway `ssh-agent`, verify (`crates/writ-integration/tests/interop.rs`) (opt-in: a key in your own agent, `make test-agent KEY=<.pub>`; never a stored fixture of a real key); wrong namespace, wrong bytes, unknown key refused. Certificates: expiry, serial, key ID = lease ID, revocation. |
| `writ-store` | Leases and ledger across a database reopen; the audit log only grows and never contains a secret (scan entries for key material, passphrases, tokens). |
| `writ-git` | Against the real `git` (`tests/real_git.rs`, SHA-1 and SHA-256 repositories): commits it writes parse (merges, another encoding); touched paths equal `git diff-tree` (changes, added and removed directories, a file becoming a directory, a mode change, an empty commit, a root commit, a merge with a resolved conflict); the signed commit's id is the one git writes; trailers equal `git interpret-trailers --parse`. Hostile evidence: objects swapped or mislabeled, malformed trees, shared subtrees (bounded walk), depth on both sides. M4: quarantine (a pack's new commits found exactly; size bound enforced; quarantine removed on every path). |
| `writ-gateway` | In-process server with a temporary CA and temporary repositories, driven by real `git` and `ssh`: fetch, push, sign, lease commands, each denial with its message. |
| `writ-signer` | The software backend against the `Signer` contract suite (`writ_signer::contract`, shared, so later backends run the same ones); keys it refuses; nothing of a key in `Debug` or errors. M5: sealed keystore unreadable without the passphrase. |
| `writ-approval` | The approval service on the platform fakes (`RecordingNotifier`, `FakeWatcher`) and a manual clock: rejection before the approver, approval and certificate, every approval that must be refused (unknown key, other namespace, other bytes, widening, non-canonical bytes), narrowing, refusal and revision, revocation, `decisions: signed` and `open`, expiry, session binding, deny list across a restart, audit log without secrets. |
| `writ-platform*` | One contract suite per interface (`Transport`, `CallerAttestor`, `SessionWatcher`, `KeystoreUnlock`, `Notifier`), run by every implementation, portable or platform-only. Fakes for each, used by the core crates' tests, so the core is tested without any real platform. Platform-only suites run on their OS (`cfg`-gated). |
| Clients | `writ sign`'s display neutralizes control sequences; `writ-sign` forwards verify calls to `ssh-keygen`, prints denial reasons escaped and explains a refused session from its certificate; `writ init` writes exactly the documented config (`writes_exactly_the_documented_config`), in wrapper mode through the environment after the caller's own entries; in `writ_init.rs`, the operator's git (key, email, remotes) untouched beside `writ git`, a rebase signed again, `--undo` restoring the config exactly. |
| Integration | `crates/writ-integration`: each milestone's acceptance scenarios with the real binaries and local tools. |
| End to end | A test remote (Forgejo or Gitea in Docker) for upstream: the M4+ acceptance scenarios scripted. Not part of `make test` (needs Docker): `make e2e`. |

The integration scenarios (`crates/writ-integration/tests/`) run the real `git` and `ssh`
against an in-process gateway (`gateway_git.rs`; `signed_commits.rs` for signing, every
denial with the reason git prints), the real `writd` in repos wired by `writ init`
(`writ_init.rs`), the real `writd` binary with the real `writ`
CLI, approver signatures from `ssh-keygen` through a throwaway `ssh-agent` and a fake
Telegram Bot API (`ticket_flow.rs`), and the OpenSSH tools against `writ-crypto`
(`interop.rs`). They run the binaries as they ship: `make test` builds them first on their
own (`-p writd -p writ-cli -p writ-sign`, in `target/bins`, `writd` with the `dev-keystore`
feature the tests need) and names the directory in `WRIT_BIN_DIR`, so no `testing` feature
of another crate is compiled into the `writd` under test (`tool/check-features.py` checks the
shipped graph in `make check`).

`make ci` (`make check` then `make test`) is the one definition of green: GitHub Actions runs
it on Linux for every push and pull request (`.github/workflows/ci.yml`, no third-party
action), and the `pre-push` hook (`make hooks`) runs it on the Mac, where macOS-only code is
tested. `make hooks` installs stubs in `.git/hooks` rather than setting a local
`core.hooksPath`, which would turn off a global one.
The gateway's own tests (`crates/writ-gateway/tests/`) run on the fakes only: an in-memory
transport, a fake attestor, an in-process SSH client and an in-process HTTPS client pinning
the certificate. The end-to-end tests approve over SSH in one scenario and over HTTPS in the
others.

Every crate is testable without network or Docker. Tests never touch the
user's real `~/.ssh`, git config or ssh-agent (except `make test-agent`, run by hand): they set `HOME`, `GIT_CONFIG_GLOBAL` and
`GIT_CONFIG_NOSYSTEM`, and use generated keys.

## Guarantee tests

Each line of [What Writ guarantees](threat-model.md#what-writ-guarantees) names the tests that
try to break it (the guarantee registry), wherever they live: `writ-core/tests/guarantees.rs`
at the policy level, then the service, the gateway and the integration scenarios.
`tool/check-guarantees.py` (in `make check`) fails if a named test doesn't exist or is
`#[ignore]`d, or if a guarantee has neither a test nor the milestone that brings one
(`planned: M7.5`). When a guarantee is added, its tests come in the same change.
