# Changelog

What changed in each release of Writ, for the person who runs it. Every release says what an
upgrade asks of you under **Upgrading**. The details live in the
[history](docs/history/README.md), one page per milestone.

Versions follow [SemVer](https://semver.org/). Before 1.0, each milestone is a minor version
and a fix between two milestones is a patch. From 1.0, a major version is an upgrade that
needs `writ migrate`, or one where the previous `writ` can no longer talk to the new `writd`.
The rules for this file are in the [conventions](docs/conventions.md#versions-and-the-changelog).

## Unreleased

### Changed

- The questions of `writ admin key add` and `writ admin repo add`, and the backends line of
  `writ admin key list`, name each key backend for what it is: `Secure Enclave (se-cryptokit)`
  rather than `se-cryptokit` alone. `backend=` and `--backend` still take the name.
- `writ admin template add` says what `require_session` means when it asks: turned on, every
  agent must be started through Writ (`writ run -- claude`). It stays off by default.
- The [quick start](docs/operators/quick-start.md) says that starting the agent under
  `writ run` is optional, unless the template asks for it.

## 0.3.2 — 2026-11-20

Two fixes to the approval popup.

### Upgrading

- **State version 13, policy format 2**, as in 0.3.1: nothing migrates, and no `writ migrate`
  is owed.
- **No message between `writ` and `writd` changed**: a `writ` 0.3.1 and a `writd` 0.3.2 still
  talk, and `writ` says the versions differ. Install both together anyway.
- **Run `make install`.** It puts the new `writ` and `writ-popup` in place and starts the
  popup again. The two go together: an older popup ignores the new `reached` event and keeps
  the message it showed.

### Fixed

- The approval popup kept saying it couldn't reach the daemon after it reached it again:
  `writ sign --ui` now says so (a new `reached` event), and the message goes
  ([clients](docs/architecture/clients.md#the-approval-popup-m78)).
- In the approval popup, a scroll pushed past the end of a path tree you clicked into moved
  the whole window. The window now holds still until the pointer leaves the tree.

## 0.3.1 — 2026-11-16

Fixes after 0.3.0: a size limit in its unit, more values for shell completion, fish
completion set up by `make install`; the dependencies and the Rust toolchain upgraded.

### Upgrading

- **State version 13, policy format 2**, as in 0.3.0: nothing migrates, and no `writ migrate`
  is owed.
- **No message changed**: a `writ` 0.3.0 and a `writd` 0.3.1 still talk, and `writ` says the
  versions differ. Install both together anyway.
- **Run `make install`.** It now builds with Rust 1.100.0 (rustup fetches it the first time),
  and sets up fish completion it skipped before. If you added a `writ.fish` to
  `~/.config/fish/completions` by hand, fish reads that one first: remove it to use the
  installed one.

### Added

- Shell completion offers more values: the files of `writ admin show` and `apply` (policy,
  approvers, readers), the phases of `writ mark`, the agents of `writ init --agents` (one more
  after each comma), the operations of `writ sign --drop-op`, the repos of `writ init` and
  `writ sign --drop-repo`, the running leases of `writ init --lease`, and the daemon's key
  backends for `--backend` of `writ admin key rotate`, `tls rotate` and `ca rotate`
  ([clients](docs/operators/clients.md#shell-completion)).

### Changed

- `writ sign`, the approval popup and `writ policy` show a size limit in its unit (`50 MB`,
  `1 GiB`) instead of in bytes; a size that isn't a whole number of a unit shows its exact
  bytes beside it (`1.5 KiB (1500 bytes)`), so a limit never reads rounded.

### Fixed

- `make install` set up no fish completion: fish doesn't name its completion directories
  when asked without its config. The installer now finds them, and when fish has none it
  writes `writ.fish` in your own `~/.config/fish/completions`; `make uninstall` takes it
  back ([install](docs/operators/install.md)).

## 0.3.0 — 2026-11-16

Shell completion
([M7.9.9](docs/history/m7.9.9-shell-completion.md)).

### Upgrading

- **State version 13, policy format 2**, as in 0.2.0: nothing migrates, and no `writ migrate`
  is owed.
- **No message changed**: a `writ` 0.2.0 and a `writd` 0.3.0 still talk, and `writ` says the
  versions differ. Install both together anyway.
- **Run `make install`.** It also writes shell completion for each shell that names a
  completion directory, and says the line to add for one that doesn't.

### Added

- Shell completion for `writ` in bash, zsh and fish: commands, flags, and the daemon's values
  (the tickets waiting, the leases running, the policy's names), read live with your reader
  key. `writ completions <shell>` prints the line to add
  ([clients](docs/operators/clients.md#shell-completion)).
- `make install` sets shell completion up for each shell that names a completion directory,
  and says the line to add for one that doesn't. An upgrade writes the files again, and
  `make uninstall` removes them ([install](docs/operators/install.md)).

### Changed

- `writ prompt`, the installer's, no longer shows in `writ --help` or completion.

## 0.2.0 — 2026-11-16

Versions and this changelog
([M7.9.8](docs/history/m7.9.8-versions-and-changelog.md)).

### Upgrading

- **State version 13, policy format 2**, as in 0.1.0: nothing migrates, and no `writ migrate`
  is owed.
- **Install `writ` and `writd` together.** Every reply of `writd` now names its version, and
  a `writ` before this release can't read those replies.
- **Run `make install`.** It now says `Upgrading Writ: 0.1.0 → 0.2.0.` and shows these notes
  before your go. On a terminal it then runs `writ unseal` for you.

### Added

- This changelog, and a version for Writ: 0.1.0 was the first one.
- `writ --version`, `writd --version` and `writ-sign --version` print the version.
- `writ` says once when the daemon's version isn't its own, and names both versions when it
  can't read a reply.
- `make install` says which version it installs. Over an install, it says which version
  replaces which and shows the changelog's Upgrading notes in between, before your go
  ([install](docs/operators/install.md#upgrade)).

## 0.1.0 — 2026-11-15

The first numbered release: everything built through
[M7.9.7](docs/history/m7.9.7-fetch-without-a-signature.md). Installs made before it had no
version.

### Upgrading

- **State version 13, policy format 2.**
- **Install `writ` and `writd` together.** The protocol refuses fields it doesn't know. A
  `writ` and a `writd` from different builds may not talk.
- **Run `make install`.** It runs `writd check-upgrade` first and tells you what the start
  will do. The state moves to version 13 after a copy in `backups/`.
- **Then run `writ unseal`.** If your policy is still format 1 (an install from before
  [M7.9.6](docs/history/m7.9.6-upgrades.md)), the daemon serves nothing until you run
  `writ migrate` and sign it.

### Added

- Tickets, leases, templates and the repo registry, with every decision in the audit log
  ([M1](docs/history/m1-lease-model-and-policy-core.md),
  [M2](docs/history/m2-ticket-flow.md)).
- `writ request`, `sign`, `refuse`, `revoke` and `ls`, over the approval API on SSH or
  HTTPS, with Telegram notifications ([M2](docs/history/m2-ticket-flow.md)).
- Commits signed by the daemon through `writ-sign`, checked against the lease and recorded in
  the ledger ([M3](docs/history/m3-signed-commits.md),
  [M5.5](docs/history/m5.5-signature-formats-and-key-algorithms.md): SSH and OpenPGP
  signatures, Ed25519, P-256, P-384 and RSA keys).
- Pushes and fetches through the daemon's gateway, every push checked before it goes upstream,
  over SSH or HTTPS ([M4](docs/history/m4-gateway-push-and-fetch.md),
  [M4.5](docs/history/m4.5-https-upstream.md)), through a proxy if needed
  ([M7.2](docs/history/m7.2-upstream-proxies.md)); the lease of each commit in git notes if
  you ask ([M4.7](docs/history/m4.7-ticket-link-in-git-notes.md)).
- A sealed keystore, `writd init` and `writ unseal`, and signed admin changes to approvers,
  readers, templates and repos ([M5](docs/history/m5-sealed-start-and-signed-admin-changes.md));
  managing all of it with `writ admin` ([M6.2](docs/history/m6.2-managing-the-daemon-from-the-cli.md)).
- The agent skill installed by `writ init`, amendments, renewals, `writ close` and its report
  ([M6](docs/history/m6-agent-skill-amendments-renewals-and-close.md)), workspaces of several
  repositories ([M6.1](docs/history/m6.1-multi-repo-workspaces.md)) and one ticket over
  several of them ([M6.1.5](docs/history/m6.1.5-per-repository-tickets.md)).
- Local mode on the Mac and on Linux, with `writ run` tying a lease to the agent it starts
  ([M7](docs/history/m7-local-mode-on-the-mac.md),
  [M7.1](docs/history/m7.1-local-mode-on-linux.md)), and the guided `make install`.
- On the Mac: keys and secrets in the Secure Enclave
  ([M7.5](docs/history/m7.5-secure-enclave-signer.md),
  [M7.6](docs/history/m7.6-hardware-wrapped-secrets.md)) and the approval popup
  ([M7.8](docs/history/m7.8-approval-popup-on-the-mac.md),
  [M7.9.5](docs/history/m7.9.5-operator-experience.md)).
- Upgrades: the state migrated after a copy, policy format changes signed with
  `writ migrate`, and `writd check-upgrade` ([M7.9.6](docs/history/m7.9.6-upgrades.md)).
- A fetch with no signature: `unsigned_fetch` on a template, and `writ git fetch` and `pull`
  asking for such a lease themselves
  ([M7.9.7](docs/history/m7.9.7-fetch-without-a-signature.md)).

### Removed

- The `proxy` and `direct_ssh` push modes. Every push goes through the gateway
  ([M7.9.6](docs/history/m7.9.6-upgrades.md)).

### Security

- Memory freed by `writd`, `writ` and `writ-sign` is wiped, so no library leaves a copy of a
  secret behind ([M5.7](docs/history/m5.7-memory-wiped-on-free.md)).
- Security reviews of the code, every finding fixed with its test
  ([M2.6](docs/history/m2.6-security-checkup.md),
  [M3.6](docs/history/m3.6-review-after-m3.5.md),
  [M4.6](docs/history/m4.6-review-after-m4.5.md),
  [M5.6](docs/history/m5.6-review-after-m5.5.md),
  [M7.7](docs/history/m7.7-review-after-m7.6.md)).
