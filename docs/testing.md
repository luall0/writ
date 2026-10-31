# Testing

Run everything with `make test`; lint, format and dependency-direction checks with
`make check`. Writ is a security boundary: a missing deny is a bug as serious as a crash.

| Area | What to test |
|---|---|
| `writ-core` | Table-driven tests for every policy decision (allowed and denied, with the reason). Property tests (`proptest`): narrowing never widens; a ticket outside every template is never accepted; two matching leases deny; counters never exceed limits. Canonical encoding pinned by fixtures in `crates/writ-core/tests/fixtures/`. Lifecycle: every transition allowed by the [state diagram](lease-model.md#lifecycle), every other one refused. |
| `writ-crypto` | SSHSIG round trips for each algorithm; signatures from real `ssh-keygen` and from Secretive (recorded fixtures) verify; wrong namespace, wrong bytes, unknown key refused. Certificates: expiry, serial, key ID = lease ID, revocation. |
| `writ-store` | Leases and ledger across a database reopen; the audit log only grows and never contains a secret (scan entries for key material, passphrases, tokens). |
| `writ-git` | Commit parsing against objects made by real `git` (signed, unsigned, merge, odd encodings, trailers). Quarantine: a pack's new commits found exactly; size bound enforced; quarantine removed on every path. |
| `writ-gateway` | In-process server with a temporary CA and temporary repositories, driven by real `git` and `ssh`: fetch, push, sign, lease commands, each denial with its message. |
| `writ-signer` | The software backend against the `Signer` contract tests (shared, so later backends run the same ones); sealed keystore unreadable without the passphrase. |
| `writ-platform*` | One contract suite per interface (`Transport`, `CallerAttestor`, `SessionWatcher`, `KeystoreUnlock`, `Notifier`), run by every implementation, portable or platform-only. Fakes for each, used by the core crates' tests, so the core is tested without any real platform. Platform-only suites run on their OS (`cfg`-gated). |
| Clients | `writ sign`'s display neutralizes control sequences; `writ-sign` forwards verify calls to `ssh-keygen` and prints denial reasons; `writ init` writes exactly the documented config. |
| End to end | A test forge (Forgejo or Gitea in Docker) for upstream: the M4+ acceptance scenarios scripted. Not part of `make test` (needs Docker): `make e2e`. |

Every crate except the binaries is testable without network or Docker. Tests never touch the
user's real `~/.ssh`, git config or Secretive: they set `HOME`, `GIT_CONFIG_GLOBAL` and
`GIT_CONFIG_NOSYSTEM`, and use generated keys.

## Guarantee tests

Each line of [What Writ guarantees](threat-model.md#what-writ-guarantees) has a test that
tries to break it, in `tests/guarantees/` (or the crate that owns it), named after the
guarantee. When a new guarantee is added to the threat model, its test comes in the same
change.
