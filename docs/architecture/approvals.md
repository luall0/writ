# Approvals

Code: `crates/writ-approval` (API), `crates/writ-crypto` (SSHSIG verification), `writ sign` /
`writ refuse` / `writ unseal` in `crates/writ-cli`.

## Approval service

Approvals are **signer-agnostic**: an approval is an **SSHSIG** over the canonical lease
content, namespace `writ-approval`, made by any SSH key listed in the daemon's `approvers`
file (same format as git's `allowed_signers`) ([Q20](../decisions.md)).

| Approver | How it signs | When |
|---|---|---|
| `writ sign` on the Mac + **Secretive** | `ssh-keygen -Y sign -n writ-approval` through Secretive's agent → Touch ID | v1 |
| YubiKey FIDO2 (`sk-ssh-ed25519`) | Same command, touch on the key | Any time, also a good backup approver |
| Own Mac Secure Enclave app | Same SSHSIG format, own UI showing the lease | Later |
| iPhone app (Secure Enclave + Face ID) | Same SSHSIG format | Later |

- The daemon only verifies signatures; it never cares which tool produced them. Swapping
  Secretive for our own signer later is just adding a key to `approvers`.
- Use a **dedicated approval key** in Secretive, with "require authentication" on, and never
  temporarily unlocked. The namespace already prevents reusing a git signature as an
  approval, but a separate key keeps things clean.
- Notifications (a `Notifier`: Telegram in v1) only tell me something is waiting. A
  notification click is never an approval ([Q7/Q13](../decisions.md)).
- Admin changes (approvers, templates, repo registry) and unsealing also require a signed
  approval.

## `writ sign`: the trusted display

Secretive's Touch ID prompt doesn't show the ticket. `writ sign` must print the full ticket
(task, plan, repos, ops, branches, limits, template, diff vs the previous revision) before
triggering the signature; it is the trusted display
([threat model, boundary 4](../threat-model.md#4-approvals-approver-signatures)).

- The ticket text is agent-written and possibly prompt-injected. Before printing it, `writ
  sign` neutralizes terminal control sequences and other invisible characters so an agent
  can't hide or overwrite part of the ticket on screen. Warnings (e.g. `direct_ssh` with an
  account-wide key) are printed by `writ sign` itself, never taken from the ticket.
- It signs exactly the canonical bytes it displayed (fetched from the daemon, then decoded and
  re-encoded locally to check they match).

## Reaching the daemon

The approval API has two transports, each enabled or disabled in `writd.yaml`
(`transports.approvals.ssh`, `transports.approvals.https`; not both disabled), with the same
commands, bodies and replies ([Q29](../decisions.md)):

- **SSH** on its own listener (port 2223 in detached mode): `writ` pins the daemon's host key
  in `~/.writ/known_hosts` and connects as user `writ` with a throwaway key.
- **HTTPS** (port 8443): TLS 1.3 with the daemon's self-signed certificate, pinned by its
  SHA-256 fingerprint in `~/.writ/tls_pins` (`writd tls-fingerprint` prints it; no
  certificate authority is trusted). Routes: `GET /v1/info`, `GET /v1/tickets[?all=true]`,
  `GET /v1/tickets/<id>`, `POST /v1/tickets/<id>/approve`, `…/refuse`, `…/revoke`; JSON
  bodies, replies in the `{"ok"}` / `{"error"}` envelope (HTTP 200, or 422 when the
  command failed, 404 for an unknown route).

`writ` picks the transport from `WRIT_APPROVAL_URL` (`ssh://…`, `unix:…` or `https://…`).
Neither connection is authenticated, and neither grants anything: approvals
(and, with `decisions: signed`, refusals and revocations) are SSHSIGs the approval service
verifies. Commands: `writ info`, `writ ls [--all]`, `writ show <id>`, `writ approve <id>`,
`writ refuse <id>`, `writ revoke <id>` (`writ_proto::Command`). Signatures are made with
`ssh-keygen -Y sign -n writ-approval -f <approval key .pub>` against the approver's agent
socket (`WRIT_APPROVAL_AGENT`, else `SSH_AUTH_SOCK`): only the dedicated approval key is used.

## Refusing and revoking

`writ sign` can also **refuse with feedback** (or `writ refuse <id> -m …`). A refusal can't
grant anything. Whether it needs a signature is the daemon's `decisions` setting:

- `signed` (default): an SSHSIG over the canonical `writ-refusal/1` document (ticket id and
  feedback), one Touch ID. Revocations the same, over `writ-revocation/1`.
- `open`: anyone who reaches the approval listener may refuse or revoke; a signature that is
  given is still checked. A residual risk (denial of service only,
  [threat model](../threat-model.md#residual-risks-v1)).

The feedback goes back to the agent and is shown next to its next revision, labeled as
recorded by the daemon. `writ revoke` on a pending ticket withdraws it.

## Narrowing

`writ sign` can **narrow** the ticket before signing (interactive, or flags such as
`--ttl 2h`, `--drop-repo`). The signature covers the narrowed ticket; the daemon checks it
only narrows what was submitted (strict subset, [Q26](../decisions.md)) and returns the final
lease to the agent. No dedicated app needed in v1.

The whole exchange is [Flows § 1](../flows.md#1-ticket-submit-review-sign-or-refuse).

`writ sign` prints the ticket with every agent-written field behind a `│` gutter, control,
bidi and invisible characters shown as `\u{…}`, then the changes since the previous revision
(or from the lease terms an amendment replaces), then what the narrowing flags changed, and
asks `[y]es / [n]o / [r]efuse`. Narrowing flags: `--ttl`, `--drop-repo`, `--drop-op`,
`--branch`, `--drop-email`, `--max-signatures`, `--max-pushes`, `--max-ops-per-minute`,
`--max-push-size`, `--no-force-push`, `--revoke-on-violation`; each can only narrow.
