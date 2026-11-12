# M0 — Protocol spike (go/no-go)

Answer the questions that could change the stack or the design before writing the real
daemon: the SSH, SSHSIG and git pieces of the gateway, and which Secure Enclave signer local
mode can have without a paid Apple Developer account. **Verdict: go**, and local mode's
signer is a CryptoKit Secure Enclave key under a dedicated `_writd` user ([Q33](../decisions.md)).

**Status:** done on 2026-10-31. One check of Plan B couldn't run (copying the key blob to
another Mac, no second Mac available); accepted on Apple's documentation: Secure Enclave keys
can't leave the Secure Enclave of the Mac that made them.

Throwaway code was fine, but it lived in the workspace created by the
[initialization guide](../guides/initialization.md), with `make check` / `make test`.

Acceptance checklist, all must pass:
- [x] A russh server with an in-memory CA accepts a key + user certificate it issued, and
      refuses: an unknown CA, an expired certificate, a revoked serial, a plain key.
  *`crates/writd/tests/spike.rs` `only_valid_session_certificates_get_in`, with real `ssh`:
  also refuses a certificate not valid yet. Unit checks in
  `crates/writ-crypto/tests/interop.rs` `certificates_are_issued_and_checked` (wrong
  principal too).*
- [x] Through that server, plain `git clone`, `git fetch` and `git push` work against a local
      bare repository (shelling out to `git upload-pack` / `git receive-pack`), with
      `core.sshCommand` pointing at the key and certificate.
  *`fetch_and_push_through_the_gateway`. Protocol v2 works (`GIT_PROTOCOL` is the only
  environment variable taken from the client). Also checked by hand with the `writd spike`
  binary and a key + certificate from `writd spike-cert`.*
- [x] The server can read the ref update lines of a push and reject it with a message that
      git shows to the user.
  *Through git's pre-receive hook, called back into the daemon (see Decisions). Git shows
  `remote: writ: refs/heads/main is protected` and `! [remote rejected] HEAD -> main
  (pre-receive hook declined)`; the bare repo's refs are unchanged.*
- [x] A commit signed with an SSHSIG built in Rust (ed25519 and P-256 software keys) passes
      `git verify-commit` with an `allowed_signers` file.
  *`ed25519_…` and `p256_commits_signed_by_the_daemon_verify_with_git`: `Good "git" signature
  for agent@writ`. Also `rust_signatures_verify_with_ssh_keygen` (`ssh-keygen -Y verify`).*
- [x] A shim set as `gpg.ssh.program` receives git's `-Y sign` call and returns a signature
      git accepts; `-Y verify` is forwarded to the real `ssh-keygen`.
  *`writ-sign` sends the object over the gateway's `writ-sign git` command. `git
  verify-commit` in the same tests goes through the shim's forwarding. With a revoked
  certificate, `git commit -S` fails with `writ-sign: the daemon refused to sign`.*
- [x] Rust verifies an SSHSIG made through an **ssh-agent** (`ssh-keygen -Y sign -n
      writ-approval` with only the public key, the way approvers sign) and rejects the same
      signature under another namespace or over other bytes.
  *`agent_held_keys_sign_approvals_rust_verifies` runs in `make test` against a throwaway
  `ssh-agent` with generated ed25519 and P-256 keys. With a hardware-backed key in your own
  agent (Secure Enclave, YubiKey…): `make test-agent KEY=<public key .pub>
  [AGENT=<socket>]`, which signs a fresh random message and keeps nothing. Run by hand on
  2026-10-31 with a Secure Enclave P-256 key: passes. Nothing of the user's key is stored in
  the repo.*
- [x] The same SSH protocol works over a Unix socket (added in M0 for local mode, M7).
  *`the_same_protocol_works_over_a_unix_socket`: `russh::server::run_stream` on a
  `UnixStream`, the client through `ProxyCommand='nc -U …'`; clone, push and the protected
  ref refusal all work.*
- [x] Results and versions written here.
- [x] **Secure Enclave signer without a paid Apple account**
      ([macOS Secure Enclave](../architecture/macos-secure-enclave.md)): a small test program in
      `spikes/secure-enclave/` (Swift, outside the Cargo workspace; archived in commit
      `3485f40`) runs the checks of each
      plan, in the doc's order, stopping at the first that passes:
  - [x] Plan A, Xcode Personal Team + keychain access group: every check in its list.
    *Works (the capability, launch, key creation, signing with no prompt in 6–7 ms) but
    **fails isolation**: other code, reusing the profile and signed with my Apple Development
    identity, used the key with no prompt. Profile lasts 7 days. Reboot, lock, LaunchAgent
    and renewal checks not run once isolation failed. Moved to the backlog for a paid account.*
  - [x] If A fails: Plan B, CryptoKit key + dedicated `_writd` user: every check in its list,
        including the keybag question (role account, or hidden standard user).
    *Passes with a role account: key created by a LaunchDaemon as `_writd`, signing with no
    prompt (8–44 ms), with the screen locked, after a reboot and while nobody is logged in;
    my user can't read, use, attach to, signal or replace anything. With FileVault there is
    no "before login" state: the daemon starts at the first login after boot. Copying the
    blob to another Mac not run (no second Mac).*
  - [x] If A and B fail: Plan D's YubiKey PIN caching per PC/SC session.
    *Not needed: Plan B passed.*
  - [x] The result recorded: the backend for [M7.5](../roadmap.md#m75--secure-enclave-signer-on-the-mac)
        and how the daemon runs in [M7](m7-local-mode-on-the-mac.md) (app bundle or dedicated
        user), in the [decision log](../decisions.md) (settles Q27); the doc's status, its ⚠️
        marks and its "What doesn't work" list updated.
    *`se-cryptokit` under a `_writd` LaunchDaemon ([Q33](../decisions.md)); results in
    [macOS Secure Enclave](../architecture/macos-secure-enclave.md#m0-results) and
    the [Secure Enclave results](#secure-enclave-results) below.*
## What was done

- Cargo workspace per the [initialization guide](../guides/initialization.md): `writ-core`
  (empty until M1), `writ-crypto`, `writ-gateway`, `writd`, `writ-sign`; `Makefile`
  (`check`, `test`, `fmt`, `run`), `tool/check-deps.py` for the dependency directions,
  `clippy.toml` allowing `unwrap`/`expect`/`panic` in tests.
- `writ-crypto`: SSHSIG split into `signed_data` → raw signature → `assemble`, the shape the
  `Signer` interface needs; the certificate authority and `validate_user_certificate` with
  one error per reason.
- `writ-gateway`: certificate-only authentication, an allow-list of exec commands
  (`git-upload-pack '<repo>'`, `git-receive-pack '<repo>'`, `writ-sign git`), repo names
  never paths, refused commands answered with a reason on stderr, TCP and Unix socket
  listeners.
- `writd spike <state> <addr|unix:path>` and `writd spike-cert` for trying it by hand (test
  keys only); `writd hook pre-receive` for git's hook.
- `writ-sign`: finds the daemon from `git config writ.url` and the SSH command git uses
  (`GIT_SSH_COMMAND`, `core.sshCommand`, `ssh`).
- `make check` and `make test` pass: 16 tests and one opt-in (unit, `ssh-keygen` and `ssh-agent` interop, 5 end-to-end with
  real `git` and `ssh`, about 4 s). About 2,000 lines of Rust.

## Versions

| | Version |
|---|---|
| git | 2.54.0 (Apple Git-157) |
| OpenSSH | 10.5p1 |
| Rust | 1.99.1 |
| russh | 0.65.0, `ring` backend (default features off) |
| ssh-key | 0.7.0-rc.11, pinned exactly because russh pins it: same `Certificate` and key types |
| tokio | 1.54.1 |

## Decisions

- **Push checks run in git's own quarantine.** `git receive-pack` stores the pushed objects
  in a quarantine and runs the pre-receive hook before any ref moves. The gateway runs it
  with `core.hooksPath` pointing at its own hook, which forwards the ref updates and a
  per-push token to the daemon over a private Unix socket (in the 0700 state directory); the
  daemon decides, and git drops the quarantine on refusal. This gives `gateway` mode the
  quarantine of the design without reimplementing receive-pack's protocol, and the later
  ledger check can walk the new commits there (`git rev-list <new> --not --all`). Recorded as
  [Q31](../decisions.md). `proxy` mode (M9) still needs its own pack handling.
- **The shim reaches the daemon with git's own SSH command** and a new `writ.url` git
  setting, so commit signing uses the same key, certificate and known hosts as fetch and push.
- **Crates:** `tokio`, `thiserror`, `anyhow` decided; the other proposed crates are decided
  when the milestone that needs them starts ([Q28](../decisions.md#open-questions)).

## Findings

- **Unix socket paths are short** (104 bytes on macOS with the terminator). The hook socket
  lives in the state directory, so a deep state directory failed with an unclear error;
  `Gateway::start` now refuses it with a clear message. Keep it in mind for local mode's
  client socket (`~/Library/Application Support/Writ/writd.sock` fits).
- `ssh-key` is a release candidate, pinned by russh. Upgrading russh will move it too.
- `UnwrapErr(SysRng)` panics if the system random source fails; acceptable (nothing can be
  signed safely then), noted for the review of M1.
- Integration tests need the workspace binaries built (`writ-sign` is another package's
  binary): `make test` builds them first.

- Secure Enclave spike, archived in git and removed from the tree: `git show
  3485f40:spikes/secure-enclave/README.md` (and the rest of `spikes/secure-enclave/` at
  `3485f40`): the Plan A Xcode project, the `se-cryptokit` tool, the `_writd` install and
  uninstall scripts. M7 and M7.5 start from them.

## Secure Enclave results

2026-10-31, M1 Pro, macOS 27.2, Xcode 27.1, FileVault on.

The only manual step for Plan A was picking the Personal Team in Signing & Capabilities;
builds then ran from the command line.

### Plan A

| Check | Result |
|---|---|
| Capability accepted for a Personal Team on macOS | ✅ The profile grants `keychain-access-groups = TEAMID.*` |
| App launches with the profile embedded | ✅ (Gatekeeper's `spctl` says "rejected": only matters for distribution) |
| Key creation and signing, no prompt | ✅ 6–7 ms per signature |
| Profile expiry | ⚠️ **7 days** (created 2026-10-31, expires 2026-11-07), this Mac only |
| A binary without the entitlement can't use the key | ✅ `-34018` |
| An ad-hoc binary claiming the entitlement | ✅ killed at launch (exit 137) |
| **Other code, same profile, signed with my Apple Development identity** | ❌ **can use the key**, no prompt |
| Reboot, screen locked, LaunchAgent, renewed profile | not run yet |

The access group binds the key to *my team's* signature, not to the daemon. Anything running
as my user can sign with my team: the Apple Development identity's private key is in my login
keychain and `codesign` used it without a prompt, and Xcode's account session lets
`xcodebuild -allowProvisioningUpdates` make profiles without one. Development builds also get
`com.apple.security.get-task-allow`, so a debugger running as my user may attach to the
daemon. Against agents running as my user, Plan A alone fails requirement 3.

### Plan C (CryptoKit blob, my user)

| Check | Result |
|---|---|
| Key creation and signing with no entitlement, no prompt | ✅ ad-hoc signed binary, 8 ms |
| Another binary (other code identity) uses the same blob | ✅ works: the blob is bound to the Mac, not the app (as expected) |
| A corrupted blob | ⚠️ **crashes the process** inside CryptoKit (`try!` → `invalidParameter`) instead of throwing |

### Plan B (CryptoKit blob, dedicated `_writd` user)

| Check | Result |
|---|---|
| Key creation as `_writd` from a LaunchDaemon | ✅ role account (uid 450, no shell, hidden), no prompt |
| Signing as `_writd` while I'm logged in | ✅ 8–22 ms |
| My user can't read the blob | ✅ `Permission denied` (directory and file) |
| My user can't use the blob with the same binary | ✅ `Permission denied` |
| My user can't attach to the daemon | ✅ `lldb`: "process is running as user '_writd'" |
| My user can't signal, replace the binary or the LaunchDaemon | ✅ `operation not permitted` / root-owned |
| Signing with my screen locked | ✅ locked 3 min (13:49:52–13:52:51Z), Mac awake: signed every 10 s, 14–44 ms. With the lid closed the Mac sleeps (`Clamshell Sleep`) and the daemon simply pauses, then carries on at wake |
| Signing after a reboot | ✅ With FileVault on, nothing runs before the first login unlocks the disk (no "before login" state on this Mac). Booted 13:54:59Z; the daemon started at the login (13:56:14Z) and signed at once (console user still `none`), then every 10 s; first signatures 170–420 ms, then 17–30 ms |
| Signing while nobody is logged in (after logging out) | ✅ logged out 13:59–14:02Z: 15 signatures, all ok (16–71 ms), console user `none` |
| Copying the blob to another Mac fails | not run (no second Mac) |

**Plan B is the local-mode signer.** Plan D wasn't needed.
