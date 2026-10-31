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

- An approver key is Ed25519 or ECDSA P-256, or their security-key forms (`sk-…`); any other
  type in `approvers` fails the file at startup. A security-key signature must carry the
  user-presence flag (the key was touched), as sshd requires by default: a credential made
  `no-touch-required` is refused. A repeated option in `approvers` is refused.
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
- The display is bounded: each agent field shows at most 40 lines (runs of blank lines
  collapsed), then how many more there are (`writ sign --full` shows everything). Expected
  paths are shown under the enforced scope, one quoted item per line, and lists are quoted
  so two different lists never read the same. The enforced terms (id, template, expiry,
  repos, operations, branches, force push, emails, expected paths, limits) are repeated in a
  short summary right before the prompt: no amount of agent text can push what gets signed
  off the screen.
- `writ sign --yes` (sign without asking) needs a named ticket: it never signs whichever
  ticket happens to be the only one waiting.
- It signs exactly the canonical bytes it displayed (fetched from the daemon, then decoded and
  re-encoded locally to check they match).

## Reaching the daemon

The approval API has two transports, each enabled or disabled in `writd.yaml`
(`transports.approvals.ssh`, `transports.approvals.https`; not both disabled), with the same
commands, bodies and replies ([Q29](../decisions.md)):

- **SSH** on its own listener (port 2223 in detached mode): `writ` pins the daemon's host key
  in `~/.writ/known_hosts` and connects as user `writ` with its **reader key**.
- **HTTPS** (port 8443): TLS 1.3 with the daemon's self-signed certificate, pinned by its
  SHA-256 fingerprint in `~/.writ/tls_pins` (`writd tls-fingerprint` prints it; no
  certificate authority is trusted), and a client certificate made from the reader key
  (mutual TLS). Routes: `GET /v1/info`, `GET /v1/tickets[?all=true]`,
  `GET /v1/tickets/<id>`, `POST /v1/tickets/<id>/approve`, `…/refuse`, `…/revoke`; JSON
  bodies, replies in the `{"ok"}` / `{"error"}` envelope (HTTP 200, or 422 when the
  command failed, 404 for an unknown route).

`writ` picks the transport from `WRIT_APPROVAL_URL` (`ssh://…`, `unix:…` or `https://…`).

**Only readers reach the API.** The reader key is an Ed25519 client key `writ reader`
generates on the approver's machine (`~/.writ/reader`, 0600) and prints as a line for the
daemon's `readers` file (`<name> ssh-ed25519 …`). It is never the approval key: Secretive's
key is only ever used through `ssh-keygen -Y sign` (hard rule 8). Without it, anyone who
reached the listener could read every ticket (task, plan, repos, leases). The connection
still grants nothing: approvals (and, with `decisions: signed`, refusals and revocations)
are SSHSIGs the approval service verifies. `writ ls --all` returns the 200 most recent
tickets. Commands: `writ info`, `writ ls [--all]`, `writ show <id>`, `writ approve <id>`,
`writ refuse <id>`, `writ revoke <id>` (`writ_proto::Command`). Signatures are made with
`ssh-keygen -Y sign -U -n writ-approval -f <approval key .pub>` against the approver's agent
socket (`WRIT_APPROVAL_AGENT`, else `SSH_AUTH_SOCK`): only the dedicated approval key is used,
`-U` makes ssh-keygen sign with the agent only (never a private key file beside the `.pub`),
and ssh-keygen runs by its absolute path (`/usr/bin/ssh-keygen`, or `WRIT_SSH_KEYGEN`) with a
clean environment, never found through `PATH`. Text from the daemon or from ssh-keygen is
escaped like agent text before it reaches the terminal.

## Refusing and revoking

`writ sign` can also **refuse with feedback** (or `writ refuse <id> -m …`). A refusal can't
grant anything. Whether it needs a signature is the daemon's `decisions` setting:

- `signed` (default): an SSHSIG over the canonical `writ-refusal/1` document (ticket id and
  feedback), one Touch ID. Revocations the same, over `writ-revocation/1`.
- `open`: any reader may refuse or revoke without a signature; a signature that is given is
  still checked. The daemon records who signed a refusal: an unsigned one reaches the agent
  labeled as such (`writ wait` says the feedback may not be the approver's words), and its
  feedback enters the revision as `[not signed by an approver] …`. A residual risk (denial of service only,
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
