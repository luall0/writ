# M5 — Sealed start and signed admin changes

[Signer and sealing](../architecture/signer.md#startup-and-sealing),
[Flows § 7](../flows.md#7-daemon-startup-sealed). From here, Writ may hold real credentials:
its secrets are encrypted at rest, a start needs the approver (the passphrase and a signature),
and the files that grant authority change only by an approver's signature.

Settled with the user before building (`10fa383`, then `c966685`, `db6e600`, `288004b`; the
[decision log](../decisions.md) has the rows):

- **The keystore**: an age X25519 identity wrapped with the passphrase (scrypt), and **each
  secret its own age file** to that identity's recipient (the CA key, the agent signing keys,
  the upstream credentials, the tokens, the authority MAC's key), read through one seam
  (`SecretFiles`), so M7.6's hardware recipients plug in with no format change. Public halves
  in clear beside them.
- **The boot tier**: the SSH host key and the HTTPS approval API's TLS key and certificate, in
  their own directory, readable at a sealed start (a sealed daemon must prove who it is to the
  client bringing the passphrase); nothing else is. Its residual risk is in the threat model.
- **The notification token**, the operator's choice: `boot` (a restart is announced, an
  unseal confirmed by the real daemon only) or `sealed` (nothing sent until unsealed).
- **`writ unseal`**: the passphrase and an approver's signature over `writ-unseal/1`, bound to
  the daemon's host key and a nonce drawn at each start; the signature checked before scrypt.
- **Admin changes** (`writ admin show|apply`, `writ-admin/1` naming the version it replaces),
  applied live; the versions in force in the state, bound to the keystore by a MAC over their
  head; the files written back, a hand edit set aside and never applied; `writd recover` on
  the host with the passphrase for any authority file.
- **Keys and tokens through admin changes** (step 5): a signed policy naming a key the
  keystore lacks makes it, and the running signer takes it through `Signer::add_key` (chosen
  by the user over rebuilding the signer; M5.5 and M7.5 may reshape the key-creation verb);
  the keystore's identity stays open after unseal (a residual risk); a token comes from the
  Mac encrypted, as `writ-token/1` `{id, previous, sealed}`.
- **Process hardening** (step 6): every `writd` process that holds a secret (`run`, `init`,
  `recover`, the credential helper), only per process, never a setting of the whole system;
  the steps nothing but the process decides (no core dump, no debugger) required in a release
  build, memory locking best effort (the host's lock limit decides).
- **Tests**: the end-to-end pipeline on the sealed keystore; the integration tests on the
  development keystore, plus dedicated sealed scenarios.

## What was done

One commit per step on `main`, each with `make ci` (and `make e2e` when a binary changed):

1. **The keystore's format** (`ed605b1`): `writd init` (the passphrase twice, at least 12
   characters, refused on an existing keystore, nothing left behind on a failure), one age
   file per secret behind `SecretFiles`, the boot tier, `keystore: { sealed: { dir, boot } }`,
   `writ_crypto::passphrase` (no echo, one line of stdin otherwise).
2. **The TLS key behind the `Signer`** (`9ae8486`): `tls-01` (P-256) in the boot tier, its
   own `Signer` queue, the self-signed certificate made through it, rustls signing each
   handshake through an adapter (`writ_crypto::tls::remote`, `writ_signer::tls::TlsSigner`)
   off the async threads; no PEM key file anywhere.
3. **The sealed start and `writ unseal`** (`fb03ee4`): every request but `info` and `unseal`
   refused with "daemon sealed" (logged, coalesced per source), `writ-unseal/1`, the service
   sealed until `Service::unseal`, the leases reloaded, the notification token's two modes.
4. **Admin changes** (`c966685` docs, `2ae9f92`): `writ_core::authority`, `writ-admin/1`, the
   store's `authority` tables under an HMAC-SHA-256 head, `writ admin show|apply` over SSH and
   HTTPS, applied live (policy and approver snapshots, readers checked per command and request,
   `Mirrors::with_registry`), the files written back, hand edits set aside, `writd recover`,
   `docs/operators/recovery.md`.
5. **Keys and tokens** (`db6e600` docs, `204fea7`): `Signer::add_key` and its contract,
   `keystore::Live`, keys made by a signed policy (`AdminApplied.created`), `writ admin
   token` (`writ-token/1`, `writ_crypto::sealed`, `GET /v1/tokens/<id>`, `POST /v1/tokens`),
   a missing token no longer stopping the unseal (`MirrorError::NoToken`; a sealed notifier
   stays off), tokens used at once.
6. **Process hardening** (`288004b` docs, `8cdd6ab`): `ProcessHardening` and its contract
   suite, `NoHardening`, the new crates `writ-platform-linux` (rustix, no `unsafe`) and
   `writ-platform-macos` (`ptrace` and `proc_pidinfo` in its one `unsafe` module),
   `docs/operators/hardening.md`.
7. **The end-to-end pipeline on the sealed keystore** (`6a42538`): the operator guide in its
   new order (approvers and readers, `writd init`, the print commands, `writd run`, `writ
   unseal`, `writ admin token`), run as written by `make e2e`; no development keystore in the
   e2e images; the restarting scenarios unseal again.
8. **Docs and history**: this page.

## Findings

- **A fresh development keystore failed its first `make run`** (`9bc0206`): since step 4 the
  daemon asks for the authority key before anything made the keys directory. The integration
  tests and the end-to-end setup never saw it: both ran `writd upstream-keys` (which makes the
  directory) before the first start. Found by the manual hardening check.
- **`PT_DENY_ATTACH` kills a process already traced**: checked first (`proc_pidinfo`), so a
  debug build can still be developed under `lldb`; a traced release build refuses to start.
- **A signed commit waits for the approver's Touch ID**: when nobody is there, git's signing
  agent times out ("communication with agent failed"); nothing to change in Writ.
- **`lldb -p` on a process that denied attaching says "attach failed: lost connection"**, not
  "Operation not permitted": its debug server is refused and drops.

## The security checklist, for M5

1. **Inputs**: new, each in the [inventory](../security.md#untrusted-inputs) with its bounds
   and hostile test: the unseal request (`an_unseal_needs_an_approver_signature_over_this_daemon_and_this_boot`),
   an admin change (`an_unsigned_wrongly_signed_or_stale_change_is_refused_and_logged`), a
   token change (`an_unsigned_wrongly_signed_or_malformed_token_is_refused_and_logged`), the
   sealed keystore's files (`a_replaced_or_foreign_file_is_refused_by_name`), the authority
   versions in the state (`a_text_changed_under_its_digest_or_a_missing_version_is_corrupt`),
   a file given to `writd recover`.
2. **Authority**: the policy, approvers and readers change only by an approver's signature or
   on the host with the passphrase; a token only by an approver's signature; a key only by a
   signed policy. Unsealing needs both the passphrase and an approver's signature.
3. **Fail closed**: sealed, every request but `info` and `unseal` is refused; a stale,
   replayed, unsigned or unparsable change or token is refused; a version failing the MAC
   keeps the daemon sealed; a required hardening step that fails stops the process.
4. **Audit**: `seal`, `unseal`, every admin change, token change, refusal, set-aside file and
   recovery is a line, written before the change; created keys in the change's line; the
   token and the passphrase never.
5. **Revocation**: leases reload at unseal and expire on time; a removed reader is turned away
   on its live connections; a tightened template denies its leases at once.
6. **Secrets**: every secret but the boot tier's sealed at rest; the TLS key only in the boot
   tier and its `Signer`; the passphrase and tokens wiped once read, never logged; tokens in
   clear nowhere on the daemon's host; no core dump, no debugger, memory locked where the host
   allows it.
7. **What people see**: the admin diff and every printed key cleaned of what a terminal
   would act on; the hardening warnings name their fix.
8. **Dependencies**: `age` 0.11 and `bech32` (M2's), `age-core` in tests, `hmac`, `libc` 0.2
   for `writ-platform-macos`, rustix's `mm` and `thread` for Linux: all already in the tree
   ([stack](../stack.md)).
9. **Guarantees**: new rows, each with its tests: the keys directory reveals no key; sealed,
   nothing is served; unsealing and admin changes need an approver; tokens from an approver
   only, never in clear, never replayed, and keys made by a signed policy used at once; no
   core dump and no debugger, or the process doesn't run.
10. **Threat model**: residual risks written with the user's go-ahead: the boot tier readable
    at rest; the bot token with `token: boot`; the passphrase in buffers Writ doesn't wipe; a
    restored backup of the state; the keystore identity kept open after unseal; memory
    locking best effort. Open question Q38 (binding the secret files to the state) added.

## Acceptance

- [x] While sealed, every request fails closed with "daemon sealed", and is logged.
  *`while_sealed_every_request_fails_closed_with_daemon_sealed` (service, every command),
  `while_sealed_every_request_fails_closed_with_daemon_sealed_and_is_logged` (integration,
  real binaries, SSH and HTTPS, the coalesced audit lines); end to end, scenario 16 and
  every scenario's stack, which now starts sealed.*
- [x] Unsealing needs both the right passphrase and a valid approver signature over this
      boot's `writ-unseal/1`; either alone, or a signature from an earlier boot or for
      another daemon, fails and is logged.
  *`an_unseal_needs_an_approver_signature_over_this_daemon_and_this_boot` (another daemon,
  another boot, a stranger's key, another namespace),
  `unsealing_needs_both_the_passphrase_and_an_approver_signature` (integration), 
  `an_unseal_the_audit_log_cannot_take_keeps_the_daemon_sealed`; end to end, a wrong
  passphrase over HTTPS refused, then unsealed over SSH.*
- [x] The keys directory alone reveals no key (checked by inspecting it at rest); the boot
      directory holds only the host key, the TLS key and certificate, and the notification
      token when the operator chose `boot`.
  *`the_keys_directory_alone_reveals_no_key` (every file listed, no private key in clear,
  each secret an age file to the recipient, modes); end to end,
  `writd_init_makes_a_sealed_keystore_that_reveals_no_key_at_rest` inspects both
  directories in the container.*
- [x] Each secret is its own age file; a test adds a second recipient (a fake) for one secret
      and reads it back with no change to the keystore code.
  *`a_second_recipient_for_one_secret_reads_it_back_through_the_same_code` (a fake
  recipient's stanza beside the X25519 one, read through `SecretFiles` alone).*
- [x] A restart keeps active leases working after unseal; their certificates still expire on
      time.
  *`a_restart_keeps_active_leases_working_after_unseal` (integration, sealed); end to end,
  scenario 10 (the daemon's container restarted, unsealed, the lease, mirror and ledger
  kept) and scenario 15.*
- [x] An unsigned or wrongly signed admin change is refused, so is one made against a version
      no longer in force; a signed one applies live and is logged; a hand-edited authority
      file is never applied (set aside, the text in force written back); a version altered
      at rest stops the unseal.
  *`an_unsigned_wrongly_signed_or_stale_change_is_refused_and_logged`,
  `a_signed_change_of_the_approvers_applies_at_once_and_is_logged`,
  `a_signed_change_applies_at_once_and_is_written_back_to_its_file` (SSH and HTTPS),
  `a_reader_removed_is_turned_away_at_once_and_a_tightened_template_denies_its_leases`,
  `a_hand_edited_file_is_set_aside_at_the_next_start_and_never_applied`,
  `versions_whose_mac_is_not_the_keystore_s_keep_the_daemon_sealed`,
  `a_version_altered_at_rest_keeps_the_daemon_sealed_and_writd_recover_needs_the_passphrase`;
  end to end, scenario 16 (`writ admin show` and `apply`) and scenario 15 (a policy
  change).*
- [x] A policy change naming a new signing key or upstream credential creates it, gives its
      public key, and signs or reaches upstream with it at once (`Signer::add_key`, passing the
      contract suite); `writ admin token` adds a token that never appears in clear on the
      daemon host and is used at once; a replayed or stale `writ-token/1` is refused; an
      `https://` repo without its token is refused with the reason, the daemon unsealed.
  *`a_policy_naming_new_keys_creates_them_and_uses_them_at_once` (granted at once and after
  a restart), `add_key_contract` through every backend and behind a queue,
  `a_token_added_from_the_mac_is_used_at_once_and_never_in_clear_on_disk` (real HTTPS: refused
  before, fetched at once after, rotated, kept across a restart),
  `a_signed_token_against_the_file_in_force_is_logged_and_a_replay_is_stale`,
  `a_sealed_notifier_token_starts_its_notifier_when_added`; end to end, the operator setup
  adds the `https` token this way and scenario 13 checks it is in clear nowhere.*
- [x] `writd recover` replaces the policy, approvers or readers only with the passphrase,
      checked like an admin change, and is logged; without the passphrase it changes nothing.
  *`a_version_altered_at_rest_keeps_the_daemon_sealed_and_writd_recover_needs_the_passphrase`
  (integration); end to end, scenario 16 (a wrong passphrase refused, the right one putting
  the first approvers back, the line in the audit log).*
- [x] The TLS key is only in the boot tier and the `Signer`: no PEM key file, no copy outside
      the `Signer`; HTTPS approvals work as in M2, with the certificate pinned from
      `writd tls-fingerprint`.
  *`a_tls_key_is_p256_and_signs_raw_halves_that_verify`, `der_signatures_are_minimal_integers`,
  `only_a_well_formed_p256_signature_gives_halves`; every HTTPS approval of the integration
  and end-to-end runs goes through it; scenario 16 checks the boot tier holds `tls-01`
  (OpenSSH P-256) and no PEM key.*
- [x] The running daemon leaves no core dump when it crashes and refuses a debugger
      attaching to it (`lldb -p`, `gdb -p` as the same user), or doesn't start (release
      build); its memory is locked where the host's lock limit allows it, a warning with the
      fix otherwise (checked on macOS and on Linux).
  *The contract on each implementation: `the_linux_hardening_passes_the_contract_and_does_what_it_says`
  (run in a Linux container as root, as a user under a 64 KiB lock limit, and unlimited),
  `the_macos_hardening_passes_the_contract_and_does_what_it_says`,
  `a_traced_process_is_refused_in_release_and_skipped_in_debug_never_killed`,
  `a_refused_step_stops_the_process_and_a_warning_does_not`; end to end, the sealed daemon's
  `/proc` (owned by root while it runs as `writ`, its memory unreadable to `writ`, core limit
  0, `VmLck` above 0). On the Mac, by hand ([manual checks](../guides/manual-checks.md)):
  `lldb -p` on the development daemon refused (attach failed), checked by the user on
  2026-11-03.*

## Left for later milestones

Each is now an item, with its acceptance, in the milestone that brings it:

- `docs/operators/recovery.md`'s platform commands: the macOS ones in
  [M7](../roadmap.md#m7--local-mode-on-the-mac) (launchd label, paths), the Docker ones in
  [M8](../roadmap.md#m8--detached-deployment) (paths in the image, its user).
- `writd recover` checking the daemon is stopped (today it assumes it; two writers would
  refuse each other's versions): [M7](../roadmap.md#m7--local-mode-on-the-mac), where a
  service manager starts the daemon.
- Q38, binding each sealed secret file to the state (the recipient is public): settled before
  building [M8](../roadmap.md#m8--detached-deployment), where the keys directory sits on a
  volume.
