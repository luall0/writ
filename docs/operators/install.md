# Installing Writ on your machine

One command sets up local mode: the daemon runs on your machine, a Mac or a Linux
workstation, under a user of its own, and your agents reach it on a socket. A second command
takes it all back.

## Before you start

- Your approval key, and its public half in a file. On the Mac, in Secretive
  ([Approving with Secretive](../guides/manual-checks.md#approving-with-secretive-touch-id)).
  On Linux, a key that asks for a touch (a FIDO key such as `sk-ssh-ed25519`, or one on a
  YubiKey) is best: your agents run as you, and could use a key that doesn't ask.
- The repository checked out, with Rust installed (the build uses the version the repository
  pins).
- `sudo` that asks for your password. It must ask: that password is what keeps your agents,
  which run as you, away from the daemon's keys.
- On Linux: systemd, and Linux 6.5 or later (Debian 13, Ubuntu 24.04 and their successors have
  it). The daemon checks this when it starts and says what is missing.

## Install

```sh
make install SETUP=local APPROVER=~/.ssh/writ-approval.pub
```

It builds the release binaries, then asks `sudo` for each step that needs root, and asks
you to choose the keystore's passphrase. Write the passphrase down somewhere safe: nothing
opens the keystore without it.

To see every change before anything is done:

```sh
make install SETUP=local APPROVER=~/.ssh/writ-approval.pub DRY_RUN=1
```

Without `SETUP`, it asks which setup to install, offering only the ones this machine can have.

On the Mac it also asks where the key of the HTTPS approval API is made: `software` (Enter),
or `se-cryptokit`, the Mac's Secure Enclave, which makes the key and never lets it out. HTTPS
is off in this setup, but the key is there if you turn it on later, and `writ admin tls rotate
--backend` moves it either way. Without a terminal, `TLS_BACKEND` answers:

```sh
make install SETUP=local APPROVER=~/.ssh/writ-approval.pub TLS_BACKEND=se-cryptokit
```

## What it sets up

On the Mac:

| What | Where |
|---|---|
| A user for the daemon, hidden, with no shell | `_writd` |
| A group for the agents' sockets, with you in it | `_writ` |
| The binaries, owned by root | `/opt/writ/bin` (`writd`, `writ`, `writ-sign`, and `writ-se`, the helper `writd` starts for keys in the Secure Enclave), on your `PATH` through `/etc/paths.d/writ` |
| The daemon's keys, state and configuration, readable by the daemon only | `/var/db/writ` |
| The sockets the agents and you connect to | `/Library/Application Support/Writ/run` |
| The daemon's log, readable by you | `/Library/Logs/Writ/writd.log` |
| The daemon, started at boot | the LaunchDaemon `dev.writ.writd` |
| Your client: the daemon's host key pinned, the endpoints set, your reader key | `~/.writ` (`known_hosts`, `config`, `reader`, `approver.pub`) |

On Linux:

| What | Where |
|---|---|
| A system user for the daemon, with no shell and no login | `writd` |
| A group for the agents' sockets, with you in it | `writ` |
| The binaries, owned by root, already on your `PATH` | `/usr/local/bin` (`writd`, `writ`, `writ-sign`) |
| The daemon's configuration, owned by root | `/etc/writ/writd.yaml` |
| The daemon's keys and state, readable by the daemon only | `/var/lib/writ` |
| The sockets the agents and you connect to, made by systemd at each start | `/run/writ` |
| The daemon, started at boot | the systemd service `writd` (`/etc/systemd/system/writd.service`) |
| The daemon's log | the journal: `journalctl -u writd` |
| Your client: the daemon's host key pinned, the endpoints set, your reader key | `~/.writ` (`known_hosts`, `config`, `reader`, `approver.pub`) |

On Linux the service can hold one privilege, `CAP_SYS_PTRACE`, so the daemon can see which
programs your agents run (Linux shows another user's programs only to a process that has it).
Only a small helper of the daemon keeps it; the daemon itself drops it before it reads any key.

The starting policy has no repository. You add them from your machine with `writ admin`.

## After the install

1. On the Mac, open a new terminal, so `/opt/writ/bin` is on your `PATH`. On Linux, log in
   again (or run `newgrp writ`): your new group, which opens the daemon's sockets, applies to
   new logins only.
2. Unseal the daemon: `writ unseal`. It asks for the passphrase, then your approval key (Touch
   ID on the Mac). You do this again after each restart of the machine.
3. Add a key, a host, a repo and a template with `writ admin`
   ([Daily operations](sealing.md)), then run `writ init <repo>` in a clone.
4. Start each agent through `writ run`, for example `writ run -- claude`. Its leases are then
   bound to that session ([Client settings](clients.md#binding-a-lease-to-its-session-local-mode)).

## Upgrade

Run `make install` again. It stops the daemon cleanly, replaces the binaries and starts it
again. The keystore, the state, the configuration and your pins are kept. Unseal again
afterwards. If `writ` changed, it says so: run `writ skill update --all` to update the agent
skill in every repository `writ init` set up.

## If the install stops

It says which step failed. What it had done is in its manifest
(`/Library/Application Support/Writ/install.manifest` on the Mac, `/etc/writ/install.manifest`
on Linux): `make uninstall` takes it back.

## Uninstall

```sh
make uninstall
```

It stops the daemon and removes everything the install made, and nothing else: on Linux, your
membership of the `writ` group too.

- **The repositories `writ init` set up**: it lists them and asks whether to take Writ out of
  them too. Answer before anything changes. Once `writ` is gone, only a new install can take
  them back. Without a terminal, say it with `REPOS=undo` or `REPOS=keep`.
- **The daemon's data** (the keystore, the leases, the ledger, the audit log) and your reader
  key are kept, so a later `make install` picks them up again. To delete them too, run
  `make uninstall PURGE=1`: it lists what it deletes and asks you to type `delete`.
- `DRY_RUN=1` lists what it would do and does nothing.
