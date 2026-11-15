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
| The LaunchDaemon | `/Library/LaunchDaemons/dev.writ.writd.plist`: `UserName _writd`, `RunAtLoad`, `KeepAlive` on an unsuccessful exit only (an orderly stop stays stopped), `ExitTimeOut` 330 s (the orderly stop waits once, at most `mirrors.timeout` and 5 s, never past 320 s: [flows § 8](../flows.md#8-daemon-stop); a `mirrors.timeout` over 315 s is cut there, said at start), `Umask` 077 | root:wheel 0644 |
| The installer's manifest | `/Library/Application Support/Writ/install.manifest` | root:wheel 0644 |
| Your client | `~/.writ`: `known_hosts` (`writ-local <host key>`), `config` (the two sockets), `reader`, `approver.pub` | yours |
| The approval popup (M7.8, `POPUP=yes`, the default) | `~/Library/LaunchAgents/dev.writ.popup.plist`: `/opt/writ/bin/writ-popup`, `WRIT_HOME` and `WRIT_APPROVAL_AGENT` (the install's answer, the installer's `SSH_AUTH_SOCK` by default, else Secretive's socket), `LimitLoadToSessionType Aqua`, `RunAtLoad`, `KeepAlive`; started in your GUI session (`gui/<uid>`); `POPUP=no` recorded in the manifest as `choice popup no`, so an upgrade doesn't start it | yours, 0600 |

Built in [M7](../history/m7-local-mode-on-the-mac.md); the popup in [M7.8](../history/m7.8-approval-popup-on-the-mac.md).

## Local (Linux)

The same on a Linux workstation: a systemd system service running as the dedicated system
user `writd`, isolated from my user, with the Linux process chain (the peer's pidfd and
`/proc`, read by the daemon's capped process reader) and a pidfd watcher
([platform](platform.md#the-linux-process-chain-and-session-watcher)). It is the local
[configuration preset](platform.md#configuration-presets) with the Linux implementations
plugged in, installed by the [installer](#installing-and-uninstalling)'s `local` setup
(`deploy/setups/local-linux.sh`, [the operator's page](../operators/install.md)). Linux 6.5 or
later, with systemd.

| What | Where | Owner, mode |
|---|---|---|
| The system user and its own group, the sockets' group (you in it) | `writd` (a system id, no login shell, home `/var/lib/writ`), `writ` | — |
| The binaries | `/usr/local/bin` (`writd`, `writ`, `writ-sign`), on every `PATH` already | root:root 0755 (the installer refuses a directory on the way you could write: a swapped `writd` would run as `writd`, with its capability) |
| The configuration | `/etc/writ/writd.yaml` (its paths absolute) | root:root 0644 |
| The keys and state: `policy.yaml`, `approvers`, `readers`, `keys/`, `boot/`, `state/` | `/var/lib/writ` | `writd` 0700 |
| The sockets (agents', approvals') | `/run/writ`, made by systemd at each start (`RuntimeDirectory`) | `writd:writ` 0750 |
| The log | the journal (`journalctl -u writd`) | — |
| The service | `/etc/systemd/system/writd.service`, enabled and started | root:root 0644 |
| The installer's manifest | `/etc/writ/install.manifest` | root:root 0644 |
| Your client | `~/.writ`: `known_hosts` (`writ-local <host key>`), `config` (the two sockets), `reader`, `approver.pub` | yours |

The unit runs `writd run /etc/writ/writd.yaml` as `User=writd`, `Group=writ`, with systemd's
sandboxing: `NoNewPrivileges`, `ProtectSystem=strict` (the file system read-only but
`/var/lib/writ` and `/run/writ`), `ProtectHome`, `PrivateTmp`, `PrivateDevices`, the kernel's
tunables, modules, logs and cgroups protected, no new namespaces, `UMask=0077`, the address
families Unix and IP only. **One capability**, `CAP_SYS_PTRACE`, the bounding set and ambient,
for the process reader alone: `writd` starts it first and then drops every capability, before
it reads a secret. `ptrace` and `process_vm_readv`/`writev` are refused by the unit's system
call filter, and the reader installs a stricter one of its own (its socket, `readlink`, its
memory, its exit: [platform](platform.md#the-linux-process-chain-and-session-watcher)). Never `ProtectProc=invisible` or
`PrivatePIDs`: the daemon must see the agents' processes. `LimitMEMLOCK=infinity` (the memory
lock), `LimitCORE=0`. `Restart=on-failure` (an orderly stop stays stopped), `TimeoutStopSec`
330 s (the orderly stop's one wait, never past 320 s, as on the Mac), `KillMode=mixed` (SIGTERM to `writd` alone, so its reader
outlives the stop's waits).

Built in [M7.1](../history/m7.1-local-mode-on-linux.md).

## Installing and uninstalling

One installer for every setup: `make install` asks which setup to install, offering only
those this build has on this OS, each said in a line; the installer is guided
([conventions](../conventions.md#installers-are-guided): every choice asked, the changes
listed, nothing done before a confirmation; variables answer without a terminal), and
`make uninstall` takes back whichever was installed.

| Setup | Where | What it installs | Built in |
|---|---|---|---|
| `local` | The Mac | The `_writd` user, the binaries, the LaunchDaemon, `writd init`, my user's `~/.writ/` | [M7](../history/m7-local-mode-on-the-mac.md) |
| `local` | A Linux workstation | The `writd` user and `writ` group, the binaries, the systemd unit, `writd init`, my user's `~/.writ/` | [M7.1](../history/m7.1-local-mode-on-linux.md) |
| `detached` | The daemon host (Linux, Docker) | The image, the compose file and `writd.yaml`, the volumes, `writd init`, the stack started | [M8](../roadmap.md#m8--detached-deployment) |
| `client` | A machine using a detached daemon (the approver's Mac, an agent host) | `writ` and `writ-sign`, `~/.writ/` with the daemon's endpoints and pins, the approval and reader keys on the approver's machine | [M8](../roadmap.md#m8--detached-deployment) |

Every setup shares the same frame (`deploy/install.sh`, `deploy/frame.sh`; each setup a file of
its own in `deploy/setups/`, whose header names it, its OS and its manifest's path):

- Guided: the setup and each setup's own questions asked (`setup_questions`), then the
  answers and every change in order (the dry run's list), then one confirmation; `DRY_RUN=1`
  lists the changes and makes none.
- The installer runs as my user and asks `sudo` only for the steps that need root; secrets
  (the keystore's passphrase) are asked on the terminal, never stored or passed as an
  argument. A root-owned file is written from the installer's stdin through `sudo tee`
  beside its place, then given its mode and owner and renamed over it (`put_root`): never
  through a temporary file of mine, which an agent running as me could change while `sudo`
  waits for the password. The approval key's `.pub` is read once: the line `approvers` and
  `~/.writ/approver.pub` get, and the fingerprint the summary shows, come from that read.
- It writes a manifest as it goes, each change recorded as soon as it is made, so a failed
  install stops and says what was done, and the uninstall removes exactly what was made,
  newest first, nothing else. The uninstall reads the manifest as root, so it trusts it only
  root-owned and written by root alone, and acts on a path only if it is one of the setup's
  own (anything else is named and left as it is).
- The daemon's data directory is recorded `newdata` when made and `data` once `writd init`
  has made the keystore: the uninstall of an install stopped between the two removes it
  whole, so a later install never takes a half-made one for kept data. A reinstall on kept
  data asks no approval key (the kept `approvers` stand).
- Run again, it upgrades: new binaries (or image), the LaunchDaemon's plist or the systemd
  unit written again (a hardening change reaches existing installs), the daemon restarted in
  order, the keystore, state, configuration and pins kept. When `writ` changed, it says that
  sessions bound under the old one (`writ run`) must be started again: their root's
  executable is no longer the one their leases were bound to.
- **What an upgrade carries over** (M7.9.6): `writd check-upgrade <writd.yaml>`, the new
  binary's dry run, run as the daemon's user while the old daemon still runs. It reads
  `writd.yaml` as a start would, copies the state (read only, SQLite's own copy) into a private
  temporary directory and runs the migration steps there, and reads the policy in force from
  the copy as a start would (sealed: a report, nothing acted on). It says what the start will
  migrate (the state's versions, after a copy in `<state_dir>/backups/`), whether the policy's
  migration will wait for a signature (`writ migrate`) and whether the daemon has its rewrite,
  and what blocks: a `writd.yaml` key this binary doesn't read, a state newer than it or one no
  step migrates, a step that fails, a policy it can't start with. Exit 1 on a block, the state
  left as it was (the copy removed).
  The installer runs it first on an upgrade, as the daemon's user, from a copy of the new
  `writd` in a directory of root's under `/tmp` (one you can write, an agent of yours could
  swap for a program that would run as the daemon's user), in a dry run too; a block stops the
  upgrade, nothing changed. After the restart, on a terminal, it runs `writ unseal` (unless the
  daemon opened itself) and `writ migrate` as you, each its own approval; declined, failed or
  without a terminal, it says what to run.
- `make uninstall` asks whether to delete the daemon's data (keystore, state, ledger, audit
  log, or the Docker volumes): kept on Enter, deleted once `delete` is typed (`PURGE=1`
  without a terminal is refused: a deletion needs a person); then lists what it takes back
  and asks for the go. On a machine where agents work, it
  lists the repos `writ init` wired (`~/.writ/repos`) and asks whether to take Writ out of
  them too: yes runs `writ init --undo` in each, as my user; no leaves them wired and names
  them. With no terminal, `REPOS=undo` or `REPOS=keep` answers, or it refuses.
