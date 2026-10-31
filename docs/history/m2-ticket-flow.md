# M2 — Ticket flow: request, sign, refuse, revoke

[Flows § 1](../flows.md#1-ticket-submit-review-sign-or-refuse) and
[§ 5](../flows.md#5-revoke--expire) end to end, against a local `writd` with software keys
(unsealed dev keystore, test only). Settles [Q29](../decisions.md).

- `writ-platform`: the `Transport`, `CallerAttestor`, `SessionWatcher`, `KeystoreUnlock` and
  `Notifier` traits, with their contract test suites and fakes, and one portable
  implementation each (TCP, network attestor, no-op watcher, passphrase unlock, ~~ntfy~~
  Telegram). `writd/src/platform.rs` builds them from the config
  ([Platform interfaces](../architecture/platform.md)).
- `writd` serving the gateway's lease commands and the approval API.
- `writ request` (session key generation, ticket file in, waits for the decision), `writ ls`,
  `writ revoke`.
- `writ sign` as the [trusted display](../architecture/approvals.md#writ-sign-the-trusted-display)
  (control sequences neutralized, diff vs previous revision), signing through the
  `ssh-agent` socket of Secretive; narrowing flags; `writ refuse` with feedback.
- Certificates issued on approval, valid until `expires_at`; revocation through the deny list.
- ~~ntfy~~ A notification (Telegram) when a ticket waits.
- Added during the milestone: the approval API over HTTPS as well as SSH, each transport
  enabled or disabled in the config ([Q29](../decisions.md)).

**Status:** done on 2026-10-31 (HTTPS approval API added the same day, at the user's request).
The Secretive check ran by hand the same day: approving with Touch ID works over HTTPS and
SSH.

Acceptance checklist, all must pass:
- [x] A ticket outside every template is rejected before reaching me, with the reason.
  *`crates/writ-approval/tests/service.rs`
  `a_ticket_outside_every_template_is_rejected_before_reaching_the_approver`: every reason
  returned, nothing stored, no notification, `submit denied` logged. End to end
  (`crates/writd/tests/ticket_flow.rs`): the real `writ request` exits 3 with "branch main
  is not within the template's branches".*
- [x] Signed with Secretive → the agent side receives the lease and a certificate the gateway
      accepts; refused → the agent side receives my feedback, and revision n+1 shows it.
  *`ticket_flow.rs` `rejected_signed_narrowed_and_refused_tickets_end_to_end`, with the real
  binaries: `writ request` waits in the background; the fake Telegram API gets "Ticket
  waiting: Add OAuth login"; `writ sign <id> --max-signatures 5 --drop-op push`, answered
  `y`, signs through `ssh-keygen` and a throwaway `ssh-agent`; `writ request` exits 0 with
  "The approver narrowed the ticket", writes `key` (0600), `key-cert.pub`, `lease.json`
  (narrowed) and `sessions/current`; real `git ls-remote` over real `ssh` with that
  certificate succeeds. `writ refuse <id> -m "Don't touch billing"` (signed) makes the
  waiting `writ request` exit 4 printing the feedback; the revision (`revises: <id>`) shown
  by `writ sign` has "revision 2", "Feedback on revision 1", the feedback and "Changes since
  revision 1". **By hand with Secretive**, run on 2026-10-31 with the dedicated approval key
  (Touch ID), following [Manual checks](../guides/manual-checks.md#approving-with-secretive-touch-id):
  `writ request` received the lease (`Lease … granted until …`), with the approval sent over
  HTTPS and over SSH.*
- [x] A signature by a key not in `approvers`, under another namespace, or over different
      bytes is refused; a narrowed ticket that widens anything is refused.
  *`service.rs` `approvals_by_other_keys_namespaces_or_bytes_and_widenings_are_refused`: a
  stranger's key, namespace `git`, a signature over other bytes, `max_signatures` raised,
  and non-canonical bytes are each refused with their reason, the ticket stays pending, five
  `grant denied` lines. An empty signature under `decisions: open` is refused too
  (`open_decisions_need_no_signature_but_check_one_given`).*
- [x] After `writ revoke` or expiry, the certificate is refused on the next connection and
      open sessions are dropped.
  *`ticket_flow.rs` `revocation_and_expiry_drop_sessions_and_refuse_the_certificate` (the
  approver side over HTTPS this time): a real
  `ssh … git-upload-pack` session stays open, `writ revoke` ends it within 5 s, and the next
  `git ls-remote` is refused; a 4 s lease's open session ends by itself and its certificate
  is refused afterwards. On the fakes: `crates/writ-gateway/tests/gateway.rs`
  `revoking_drops_open_sessions_and_refuses_the_next_connection`; the service's deny list
  and announcements in `a_revocation_puts_the_certificate_on_the_deny_list_and_announces_it`,
  `expiry_ends_pending_tickets_and_leases` and `the_deny_list_survives_a_restart`.*
- [x] Every grant, refusal, revocation and denial is in the audit log.
  *Each service test asserts its lines (`grant`, `refuse`, `revoke`, `expire`, `submit`,
  `connect`, `sign`/`push` allowed and denied); `the_audit_log_holds_every_decision_and_no_secret`
  scans the log for key material and signatures. Both end-to-end tests check the real
  daemon's `audit.jsonl` the same way.*
- [x] The gateway, the policy and the approval API only see the platform traits: their tests
      run on the fakes, and no `#[cfg(target_os)]` exists outside `writd/src/platform.rs`.
  *`writ-gateway`'s tests use `FakeTransport`, `FakeAttestor` and an in-process SSH client
  (role separation, an unattestable caller turned away, the whole flow over the protocol);
  the HTTPS approval API is tested the same way, with an in-process HTTPS client pinning the
  certificate (same commands, unknown routes, body bound, wrong pin, unattestable caller);
  `writ-approval`'s use `RecordingNotifier`, `FakeWatcher` and a manual clock. `grep -rn
  target_os crates` finds only a comment in `writd/src/platform.rs`. `tool/check-deps.py`
  now also keeps `writ-proto` and `writ-platform` off the daemon crates.*

## What was done

- `writ-platform` (about 3,400 lines with its tests): the five traits; `TcpTransport`,
  `NetworkAttestor`, `NoSessionWatcher`, `PassphraseUnlock` (data key wrapped by age's scrypt
  recipient, 0600, no overwrite), `TelegramNotifier` (Bot API `sendMessage`, plain text, the
  token never in an error or `Debug`) and `Notifiers`; fakes and contract suites behind the
  `testing` feature. 58 tests; each suite was checked to fail on a deliberately broken
  implementation.
- `writ-proto`: the exec commands (`writ request`, `wait`, `info`, `ls`, `show`, `approve`,
  `refuse`, `revoke`) and their JSON bodies in an `{"ok"}` / `{"error"}` envelope.
- `writ-approval`: `Service`, which submits, waits, shows, approves (SSHSIG, narrowing, fit,
  certificate), refuses, revokes, authorizes certificates for the gateway, sweeps expiry,
  revokes a session-bound lease when its process exits, and logs all of it.
- `writ-gateway`: serves any `Transport` with a role (agents, approvals), attests each
  caller, two SSH users (`git` with a certificate, `writ` with a plain key), certificates
  checked against the service at connection and before each command, open sessions dropped
  when a lease ends.
- The approval API over HTTPS (`writ-gateway::https`): the same commands as REST-like routes
  (`writ_proto::Command::http_route`), TLS 1.3 with a self-signed certificate from the
  keystore, callers attested like SSH ones. `transports.approvals.ssh` and `.https` are each
  optional; with both disabled `writd` refuses to start. `writd tls-fingerprint` prints the
  pin.
- `writ-cli` (`writ`): `request`, `wait`, `ls`, `sign` (trusted display, diff, narrowing
  flags, `[y]es / [n]o / [r]efuse`), `refuse`, `revoke`; a russh client pinning the host key
  from `~/.writ/known_hosts` (TCP or Unix socket endpoints), an HTTPS client pinning the
  certificate from `~/.writ/tls_pins`, never using `~/.ssh`.
- `writd run <writd.yaml>` and `writd host-key`; `config.rs`, `platform.rs`; a dev keystore
  refused by release builds; `make run` on `dev/writd.yaml`. The M0 `spike` commands are
  gone, and their end-to-end tests now get every certificate from a signed lease.
- `writ-core::signed` (refusal and revocation documents), `writ-crypto::allowed_signers`
  (options honored or refused, never ignored), panic-free randomness, `writ-store` schema 2
  (session key, certificate) with a migration from 1, a `connect` audit event.
- `make check` and `make test` pass: 203 tests and one opt-in (104 new), about 25 s. About
  20,600 lines of Rust in all (about 10,600 new).

## Decisions

All in the [decision log](../decisions.md):

- Q29: the approval API is the gateway's SSH protocol on its own listener (host key pinned)
  and HTTPS (self-signed certificate pinned), each enabled or disabled in the config. Ports
  2222 agents, 2223 approvals over SSH, 8443 approvals over HTTPS.
- `decisions: signed | open` for refusals and revocations, default `signed`.
- Two SSH users on the agents' listener; submitting proves possession of the session key.
- A session-bound lease needs a watcher.
- Notifications are notifier-agnostic, Telegram in v1 (ntfy dropped, at the user's request).
- Crates: `clap`, `age` 0.11, `ureq`, `zeroize`, `rustls` 0.23 (`ring`), `hyper` 1, `rcgen`;
  randomness never panics.

## Findings

- **`age` 0.12 and russh 0.65 can't share a workspace**: both reach the `kem` crate, one
  through `ml-kem` 0.2 (needs `0.3.0-pre.0`), the other through `ml-kem` 0.3 (needs
  `0.3.0`), and Cargo unifies the two. `age` 0.11 doesn't use `ml-kem`.
- **OpenSSH falls back from a refused certificate to the plain key**, which the agents'
  listener accepts for submissions. With one user, a revoked certificate would get in as a
  submitter. Hence the separate `writ` user.
- **A watcher may call back at once** (the process already exited), while the service holds
  its lock: the callback revokes from another thread.
- The 103-byte Unix socket limit (M0) bites again: `writd run` refuses a state directory too
  deep for its hook socket, clearly. Keep `state_dir` short.
- Telegram counts its 4,096-character limit in UTF-16 code units; the notifier caps there.
- **The manual check found log noise**: `writ` dropped its SSH connections without a
  disconnect, so the daemon logged `session ended with an error: early eof` after every
  command. `writ` now disconnects properly, and the daemon no longer logs a client going away
  (EOF, reset, broken pipe, disconnect) as an error. The end-to-end test asserts the daemon's
  log stays free of errors.
