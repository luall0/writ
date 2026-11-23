# Detached deployment

**Status:** specified (M8 on the roadmap until 2026-11-23, when v1 was closed without it).
**Area:** Deployment, Clients. **Kind:** feature. **Size:** L.

## Problem

Writ runs in local mode only: the daemon on the machine the agents run on (the Mac, or a
Linux workstation). An agent on another host (a VM, a server on the LAN) can't use it, and the
daemon can't live on a server of its own, apart from the agents it serves.
[Deployment](../architecture/deployment.md) describes detached mode; nothing packages it yet.

## Proposal

The daemon on the homelab, in Docker, agents anywhere on the LAN or VPN, every machine set up
with the guided installer: `detached` on the daemon host, `client` on the approver's Mac and
on each agent host.

- `deploy/Dockerfile` (non-root, minimal image) and `deploy/compose.yaml` with the two
  volumes, the gateway's port and the approval transports in use (SSH, HTTPS). **Builds on
  M4.1's test image** (`e2e/`: the pinned Rust builder stage, the Debian 13 runtime with git ≥
  2.45 and OpenSSH), decided with the user in M4.1: harden it (non-root, minimal, read-only
  where it can be) rather than start over, and `make e2e` then runs against the deploy image.
- **The deploy image builds the binaries in release** (found by the
  [M7.7 review](../history/m7.7-review-after-m7.6.md), `X-6`): the test image builds them in
  debug, where a traced `writd` only warns and the release-only refusals (the development
  keystore among them) are missing.
- Notifications (the configured `Notifier`) for sealed restarts, denials and violations
  (waiting tickets already notify since M2).
- Backup guidance for the ledger and the audit log.
- **`docker stop` is an orderly stop** (found by the
  [M5.6 review](../history/m5.6-review-after-m5.5.md), L16): the SIGTERM handling M7 added,
  checked in the container (tini forwards it under `init: true`), within compose's
  `stop_grace_period`.
- **Q38 first** ([open questions](../decisions.md#open-questions), left open by M5): the
  keystore's recipient is public, so whoever can write the keys directory, here a Docker
  volume, can plant a secret of their choosing. Settled with the user before building:
  whether each sealed secret file is bound to the state (e.g. a MAC over its digest with the
  authority key, checked at unseal and on every live read); if kept, it is built here.
- **Q38 covers the public authority files too** (found by the
  [M7.7 review](../history/m7.7-review-after-m7.6.md), `S-9`): as worded it binds only secret
  files, while the keys directory also holds `ca-retired.pub` (a CA written there is trusted
  until its deadline), `ca.backend` (auto-unseal's check) and `recipients/*.pub`.
- **The recovery guide's Docker commands**: `docs/operators/recovery.md`'s placeholders (the
  paths in the image, its user) filled in, and run end to end against the deploy image.
- **`recovery.md` run by the pipeline word for word** (owed since the
  [M7.7 review](../history/m7.7-review-after-m7.6.md), `X-4`): the page joins
  [commands the docs show](../end-to-end.md#commands-the-docs-show), its every `sh` block a
  scenario's.
- **`install.md` run by the pipeline** (owed since
  [M7.9](../history/m7.9-local-mode-checked-on-the-mac.md), which ran its `local` setup by
  hand: `sudo`, launchd): its `make install` and `make uninstall` run by the scenarios that
  set the agents' containers up with the `client` setup, and the page joins
  [commands the docs show](../end-to-end.md#commands-the-docs-show).
- **The installer's `detached` setup**, on the daemon host, with M7's frame (the setup
  question, `DRY_RUN=1`, the manifest, the upgrade, `make uninstall`): the image built
  (`make docker`); one directory holding `deploy/compose.yaml` and a `writd.yaml` from the
  detached preset, the approval transports and the `allow` lists asked for (or given:
  `APPROVALS=ssh,https`, `AGENTS_ALLOW=<cidr>…`); the two volumes; `writd init` in the
  container, the passphrase on the terminal; the approver's public key in `approvers`; the
  stack started. It ends by printing what each client pins (the host key, the TLS
  fingerprint) and the `make install` to run on them. Upgrading rebuilds the image and
  restarts the stack in order, the volumes kept. `make uninstall` takes the stack down and
  removes the image and the files it made, the volumes kept unless `delete` is typed at its
  question. Guided like the `local` setup ([conventions](../conventions.md#installers-are-guided)).
- **The `client` setup settles how an HTTPS client checks the daemon's name** (the gap the
  [M7.7 review](../history/m7.7-review-after-m7.6.md) documented, `L-1`): over HTTPS `writ`
  authenticates the TLS certificate, never the host key the daemon names itself by; settled
  before detached approvers rely on HTTPS.
- **The installer's `client` setup**, on each machine that uses a detached daemon (the
  approver's Mac, an agent VM): `writ` and `writ-sign` on the `PATH`, `~/.writ/` with the
  daemon's endpoints, its host key and TLS certificate pinned (asked at the prompt, each
  checked against the daemon before anything is written; variables answer without a
  terminal), and on the approver's machine (asked whether it is one) the approval key and the
  reader key (`writ reader`), printing the line for the daemon's `readers`. `make uninstall`
  takes it back and asks the repos question as in M7.

## Scope and non-goals

- Detached is only the detached
  [configuration preset](../architecture/platform.md#configuration-presets) and packaging: no
  change to the core crates beyond bug fixes.
- One operator, as everywhere in Writ ([multi-user](multi-user.md) is its own idea).

## Design

The core already serves both modes ([platform](../architecture/platform.md)): the gateway and
both approval transports over TCP, the software signer, the sealed start. What is new is
packaging (the image, the compose file), the installer's two setups, and Q38.

## Threat model impact

- The keys directory sits on a Docker volume: whoever can write it can plant a secret (Q38).
- Agents reach the gateway over TCP: a session key copied off an agent host works from any
  address the gateway admits, until its lease ends. [Non-exportable session
  keys](non-exportable-session-keys.md) and [source-address pinning](README.md#source-address-pinning)
  narrow it; in local mode the socket and the process chain already refuse a copied key.

## Open questions

- Q38, above: settled with the user before building.

## Acceptance

- [ ] `docker compose up` on the homelab → sealed → `writ unseal` from the Mac → agents on a
      VM and on the Mac both work under their own leases at the same time.
- [ ] A container restart notifies me and fails closed until unsealed.
- [ ] `docker stop` stops the daemon in order (the `stopping` line in its log), not killed
      at the grace period's end.
- [ ] Only port 2222 and the approval transports in use (2223 SSH, 8443 HTTPS) are exposed;
      the process runs as non-root, from release builds (a traced start refused).
- [ ] Detached is only the detached [configuration preset](../architecture/platform.md#configuration-presets)
      and packaging: no change to the core crates beyond bug fixes.
- [ ] Q38 settled before building; if kept, a secret file planted or swapped in the keys
      directory (a key with its matching `.pub`, a token), or a public authority file
      (`ca-retired.pub`, `ca.backend`, `recipients/*.pub`), stops the unseal, naming the file.
- [ ] The recovery guide's Docker steps run as written, end to end (`make e2e`), the page in
      the pipeline's table.
- [ ] The first item above set up with the guided installer only: `detached` picked on the
      homelab, `client` on the Mac and on the VM, nothing else by hand but `writ unseal` and
      the `readers` line; the setup question on each offers only what that OS can install.
- [ ] `make e2e` sets its agents' containers up with the `client` setup (its variables, no
      terminal), and its daemon from the compose file and the `writd.yaml` the `detached`
      setup writes; a client given a host key or TLS pin the daemon doesn't have writes
      nothing and says why.
- [ ] `make uninstall` takes each setup back, checked against a listing taken before: the
      volumes kept unless `delete` is typed, the clients' repos question as in M7.

## Plan

Written when the user picks it.
