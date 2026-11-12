# Deployment

## Detached (Docker)

```yaml
services:
  writd:
    image: writ/writd
    ports:
      - "2222:2222"   # gateway (SSH, agents)
      - "2223:2223"   # approval API over SSH (optional; firewall it to the approver)
      - "8443:8443"   # approval API over HTTPS (optional; firewall it to the approver)
    volumes:
      - writ-data:/var/lib/writ        # mirrors, leases, ledger, audit
      - writ-keys:/var/lib/writ/keys   # software signer only
    # devices:
    #   - /dev/bus/usb                   # YubiKey backend, later
```

Files: `deploy/Dockerfile`, `deploy/compose.yaml`.

Network exposure: **LAN + VPN only** ([Q21](../decisions.md)). Nothing is published to the
internet.

## Daemon host hardening

The daemon host is the crown jewel: it holds agent keys, upstream credentials and mirrors
([threat model, boundary 5](../threat-model.md#5-daemon-host-the-crown-jewel)).

- Dedicated host or VM
- Container running as non-root
- Minimal exposed ports: the gateway, and only the approval transports in use (SSH, HTTPS, or both)
- Backups of the ledger and the audit log
- YubiKey backend as soon as practical
- The `writ-keys` volume only ever holds the encrypted keystore; the daemon starts sealed
  ([Signer and sealing](signer.md#startup-and-sealing))

## Local (Mac)

The same `writd`, built natively, listening on a Unix socket (with
[process chain checks](identity.md#local-mode-process-chain-checks)) and started by launchd,
isolated from my user: a LaunchDaemon running as the dedicated role user `_writd`, as the M0
spike decided ([macOS Secure Enclave](macos-secure-enclave.md#m0-results)). The Mac must stay
awake for agents to work while I'm away (lid open, or on power with a display); with FileVault
the daemon starts at the first login after a boot. It is
the local [configuration preset](platform.md#configuration-presets), with the macOS
implementations plugged in. Installed by the [installer](#installing-and-uninstalling)'s
`local` setup (`deploy/setups/local-macos.sh`, [the operator's page](../operators/install.md)):

| What | Where | Owner, mode |
|---|---|---|
| The role user and its group, the sockets' group (you in it) | `_writd` (an id from 450 to 499, no shell, hidden), `_writ` | — |
| The binaries, ad-hoc signed with the hardened runtime, identifiers `dev.writ.<name>` | `/opt/writ/bin`, on `PATH` through `/etc/paths.d/writ` | root:wheel 0755, every directory on the way root's (the installer refuses one you could write: a swapped `writd` would run as `_writd`) |
| The daemon's directory: `writd.yaml` (root's), `policy.yaml`, `approvers`, `readers`, `keys/`, `boot/`, `state/` | `/var/db/writ` | `_writd` 0700 |
| The sockets (agents', approvals') | `/Library/Application Support/Writ/run` | `_writd:_writ` 0750 |
| The log (stdout and stderr) | `/Library/Logs/Writ/writd.log` | `_writd:_writ` 0640 |
| The LaunchDaemon | `/Library/LaunchDaemons/dev.writ.writd.plist`: `UserName _writd`, `RunAtLoad`, `KeepAlive` on an unsuccessful exit only (an orderly stop stays stopped), `ExitTimeOut` 330 s (the orderly stop's waits: `mirrors.timeout` and its margin), `Umask` 077 | root:wheel 0644 |
| The installer's manifest | `/Library/Application Support/Writ/install.manifest` | root:wheel 0644 |
| Your client | `~/.writ`: `known_hosts` (`writ-local <host key>`), `config` (the two sockets), `reader`, `approver.pub` | yours |

Built in [M7](../history/m7-local-mode-on-the-mac.md).

## Local (Linux)

The same on a Linux workstation: a systemd system service running as the dedicated system
user `writd`, its state in `/var/lib/writ` (`0700`), the agents' socket in `/run/writ/`
reachable through a `writ` group my user is in, with the Linux process chain (`SO_PEERCRED`
and `/proc`) and a pidfd watcher. Installed by the installer's `local` setup. Built in
[M7.1](../roadmap.md#m71--local-mode-on-linux).

## Installing and uninstalling

One installer for every setup: `make install` asks which setup to install, offering only
those this build has on this OS (`SETUP=<name>` answers without asking), and
`make uninstall` takes back whichever was installed.

| Setup | Where | What it installs | Built in |
|---|---|---|---|
| `local` | The Mac | The `_writd` user, the binaries, the LaunchDaemon, `writd init`, my user's `~/.writ/` | [M7](../history/m7-local-mode-on-the-mac.md) |
| `local` | A Linux workstation | The `writd` user and `writ` group, the binaries, the systemd unit, `writd init`, my user's `~/.writ/` | [M7.1](../roadmap.md#m71--local-mode-on-linux) |
| `detached` | The daemon host (Linux, Docker) | The image, the compose file and `writd.yaml`, the volumes, `writd init`, the stack started | [M8](../roadmap.md#m8--detached-deployment) |
| `client` | A machine using a detached daemon (the approver's Mac, an agent host) | `writ` and `writ-sign`, `~/.writ/` with the daemon's endpoints and pins, the approval and reader keys on the approver's machine | [M8](../roadmap.md#m8--detached-deployment) |

Every setup shares the same frame (`deploy/install.sh`, `deploy/frame.sh`; each setup a file of
its own in `deploy/setups/`, whose header names it, its OS and its manifest's path):

- `DRY_RUN=1` lists every change and makes none.
- The installer runs as my user and asks `sudo` only for the steps that need root; secrets
  (the keystore's passphrase) are asked on the terminal, never stored or passed as an
  argument.
- It writes a manifest as it goes, each change recorded as soon as it is made, so a failed
  install stops and says what was done, and the uninstall removes exactly what was made,
  newest first, nothing else. The uninstall reads the manifest as root, so it trusts it only
  root-owned and written by root alone, and acts on a path only if it is one of the setup's
  own (anything else is named and left as it is).
- Run again, it upgrades: new binaries (or image), the daemon restarted in order, the
  keystore, state, configuration and pins kept.
- `make uninstall` keeps the daemon's data (keystore, state, ledger, audit log, or the Docker
  volumes) unless `PURGE=1` is confirmed on the terminal. On a machine where agents work, it
  lists the repos `writ init` wired (`~/.writ/repos`) and asks whether to take Writ out of
  them too: yes runs `writ init --undo` in each, as my user; no leaves them wired and names
  them. With no terminal, `REPOS=undo` or `REPOS=keep` answers, or it refuses.
