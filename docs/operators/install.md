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
- `sudo` that asks for your password. It must ask, or your agents, which run as you, could
  use it too. The password alone doesn't keep them away: an agent that can change your
  shell's files can wrap the commands you type, and one that can write the checkout can change
  what gets installed. So install and upgrade from a checkout your agents don't work in, with
  no agent running.
- On Linux: systemd, and Linux 6.5 or later (Debian 13, Ubuntu 24.04 and their successors have
  it). The daemon checks this when it starts and says what is missing.

## Install

```sh
make install
```

It builds the release binaries, then asks its questions, one at a time, each with what it
means and what Enter keeps:

1. **The setup**: the ones this machine can have, each said in a line (today, `local`).
2. **Your approval key**: the path to its public half, the `.pub`. A path that isn't one is
   asked again. The installer reads that file once, and nothing else of yours. Your answers
   show the key by its fingerprint: check it is your key's. When the daemon's data is kept
   from an earlier install, this isn't asked: the approval keys kept with it stay.
3. On the Mac, **where the key of the HTTPS approval API is made**: `software`, or
   `se-cryptokit`, the Mac's Secure Enclave, which makes the key and never lets it out. HTTPS
   is off in this setup; the key serves it if you turn it on later. A key in the Secure
   Enclave is made by the daemon itself when it first starts, never by the installer: one
   made outside the daemon wouldn't sign for it.
4. On the Mac, **where your agents' first signing key, `agent-01`, is made**: `software` (an
   Ed25519 key) or `se-cryptokit` (a P-256 key in the Secure Enclave). On Linux it is an
   Ed25519 key in software, the only backend there.
5. On the Mac, **the approval popup**: `yes` (Enter) starts it at each login. When a ticket
   waits for your signature, a window comes up in front of every app, full-screen ones too,
   with the whole ticket and two buttons, Sign and Decline. Then **the socket of the agent
   that holds your approval key**: Enter takes Secretive's. `no` installs the popup's program
   and starts nothing: you sign with `writ sign` in a terminal.

Then it shows your answers and **every change it will make, in order**, and asks `Install?`.
Nothing is done before you answer `y`; anything else leaves the machine as it was. It then
asks `sudo` for each step that needs root, and asks you to choose the keystore's passphrase.
Root's files are handed to `sudo` directly, never through a file of yours.
Write the passphrase down somewhere safe: nothing opens the keystore without it.

Both choices can be changed later from your machine: `writ admin tls rotate --backend` moves
the HTTPS key, `writ admin key rotate --backend` moves a signing key
([Daily operations](sealing.md)).

## What it sets up

On the Mac:

| What | Where |
|---|---|
| A user for the daemon, hidden, with no shell | `_writd` |
| A group for the agents' sockets, with you in it | `_writ` |
| The binaries, owned by root | `/opt/writ/bin` (`writd`, `writ`, `writ-sign`, `writ-se`, the helper `writd` starts for keys in the Secure Enclave, and `writ-popup`, the approval popup), on your `PATH` through `/etc/paths.d/writ` |
| The daemon's keys, state and configuration, readable by the daemon only | `/var/db/writ` |
| The sockets the agents and you connect to | `/Library/Application Support/Writ/run` |
| The daemon's log, readable by you | `/Library/Logs/Writ/writd.log` |
| The daemon, started at boot | the LaunchDaemon `dev.writ.writd` |
| Your client: the daemon's host key pinned, the endpoints set, your reader key | `~/.writ` (`known_hosts`, `config`, `reader`, `approver.pub`) |
| The approval popup, started at each login in your session (unless you answered `no`) | the LaunchAgent `dev.writ.popup` (`~/Library/LaunchAgents/dev.writ.popup.plist`) |

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

The starting policy declares your agents' first signing key, `agent-01`, and no repository.
You add repositories from your machine with `writ admin`.

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
5. On the Mac, the approval popup is already running: the next ticket an agent submits comes
   up in its window ([The approval popup](clients.md#the-approval-popup-on-the-mac)).

## Upgrade

Run `make install` again. It says what an upgrade does and lists its changes, then asks
`Upgrade?`. Yes stops the daemon cleanly, replaces the binaries, writes the LaunchDaemon's
plist (the systemd unit on Linux) again with this version's settings, and starts it again. The
keystore, the state, the configuration and your pins are kept. Unseal again afterwards. On the
Mac, the approval popup is stopped and started again with its settings kept; an install made
before the popup existed gets it, through Secretive's agent (or the one `APPROVAL_AGENT`
names), unless you upgrade with `POPUP=no`, and an install where you answered `no` stays
without it. If `writ` changed, it says so:

- Agents started with `writ run` before the upgrade are bound to the old `writ`. Their leases
  are refused from then on. Start each agent again, then request a new lease.
- Run `writ skill update --all` to update the agent skill in every repository `writ init` set
  up.

## If the install stops

It says which step failed. What it had done is in its manifest
(`/Library/Application Support/Writ/install.manifest` on the Mac, `/etc/writ/install.manifest`
on Linux): `make uninstall` takes it back. A keystore that failed to be made goes too, whatever
you answer about the daemon's data: the next install makes a new one.

## Uninstall

```sh
make uninstall
```

It asks its questions first, then lists what it takes back and asks `Uninstall?`. Nothing
changes before you answer `y`. It stops the daemon and removes everything the install made,
and nothing else: on the Mac, the approval popup too (stopped, its LaunchAgent removed); on
Linux, your membership of the `writ` group too.

- **The repositories `writ init` set up**: it lists them and asks whether to take Writ out of
  them too. Once `writ` is gone, only a new install can take them back.
- **The daemon's data** (the keystore, the leases, the ledger, the audit log) and your reader
  key: it lists them and asks. Enter keeps them, so a later `make install` picks them up
  again; type `delete` to delete them for good.

## Without a terminal

For a script, each question has a variable that answers it, checked as an answer typed would
be. With no terminal there is no summary and no `Install?`: the variables are the answers, so
give every one.

| Variable | Answers |
|---|---|
| `SETUP=local` | The setup |
| `APPROVER=<path to the .pub>` | Your approval key |
| `TLS_BACKEND=software\|se-cryptokit` | Where the HTTPS key is made (the Mac; `software` when left out) |
| `CA_BACKEND=software\|se-cryptokit` | Where the SSH CA's key is made, the one that signs each lease's certificate (the Mac; `software` when left out) |
| `UNSEAL=passphrase\|se-cryptokit` | What opens the keystore: a passphrase, or the Mac's Secure Enclave with no passphrase (`passphrase` when left out) |
| `RECOVERY=<age1…>` | With `UNSEAL=se-cryptokit`: the recovery key's recipient, from `writ recovery new` (required then; on a terminal, Enter makes one) |
| `AUTO_UNSEAL=no\|yes` | Whether the daemon opens itself at each start: only with `CA_BACKEND`, `AGENT_BACKEND` and `UNSEAL` all `se-cryptokit` (`no` when left out) |
| `AGENT_BACKEND=software\|se-cryptokit` | Where `agent-01` is made (the Mac; `software` when left out) |
| `POPUP=yes\|no` | Whether the approval popup starts at each login (the Mac; `yes` when left out) |
| `APPROVAL_AGENT=<socket path>` | With `POPUP=yes`: the socket of the agent that holds your approval key, an absolute path (Secretive's when left out) |
| `DRY_RUN=1` | Only list the changes, make none |
| `REPOS=undo\|keep` | The uninstall's question about the repositories `writ init` set up |
| `PURGE=1` | Delete the daemon's data at the uninstall: this one still needs a terminal, where you type `delete` |
