# Installing Writ on your Mac

One command sets up local mode: the daemon runs on your Mac, under a user of its own, and
your agents reach it on a socket. A second command takes it all back.

## Before you start

- Your approval key in Secretive, and its public half in a file
  ([Approving with Secretive](../guides/manual-checks.md#approving-with-secretive-touch-id)).
- The repository checked out, with Rust installed (the build uses the version the repository
  pins).
- `sudo` that asks for your password. It must ask: that password is what keeps your agents,
  which run as you, away from the daemon's keys.

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

Without `SETUP`, it asks which setup to install, offering only the ones this Mac can have.

## What it sets up

| What | Where |
|---|---|
| A user for the daemon, hidden, with no shell | `_writd` |
| A group for the agents' sockets, with you in it | `_writ` |
| The binaries, owned by root | `/opt/writ/bin` (`writd`, `writ`, `writ-sign`), on your `PATH` through `/etc/paths.d/writ` |
| The daemon's keys, state and configuration, readable by the daemon only | `/var/db/writ` |
| The sockets the agents and you connect to | `/Library/Application Support/Writ/run` |
| The daemon's log, readable by you | `/Library/Logs/Writ/writd.log` |
| The daemon, started at boot | the LaunchDaemon `dev.writ.writd` |
| Your client: the daemon's host key pinned, the endpoints set, your reader key | `~/.writ` (`known_hosts`, `config`, `reader`, `approver.pub`) |

The starting policy has no repository. You add them from your machine with `writ admin`.

## After the install

1. Open a new terminal, so `/opt/writ/bin` is on your `PATH`.
2. Unseal the daemon: `writ unseal`. It asks for the passphrase, then Touch ID. You do this
   again after each restart of the Mac.
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
(`/Library/Application Support/Writ/install.manifest`): `make uninstall` takes it back.

## Uninstall

```sh
make uninstall
```

It stops the daemon and removes everything the install made, and nothing else.

- **The repositories `writ init` set up**: it lists them and asks whether to take Writ out of
  them too. Answer before anything changes. Once `writ` is gone, only a new install can take
  them back. Without a terminal, say it with `REPOS=undo` or `REPOS=keep`.
- **The daemon's data** (the keystore, the leases, the ledger, the audit log) and your reader
  key are kept, so a later `make install` picks them up again. To delete them too, run
  `make uninstall PURGE=1`: it lists what it deletes and asks you to type `delete`.
- `DRY_RUN=1` lists what it would do and does nothing.
