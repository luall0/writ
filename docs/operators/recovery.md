# Recovery: getting access back

What to do when something that opens or runs the daemon is lost: an approval key, a reader
key, the Mac that held both, the keystore's passphrase, or a file that changed on the host. It
starts with what to prepare **before** anything is lost, because some losses can't be undone
after.

The model, in one paragraph. After `writd init`, the daemon holds the files that grant
authority (the policy, `approvers`, `readers`) as versions in force in its state, under a MAC
keyed by a secret of the keystore ([sealing](sealing.md)). They change only by an approver's
signed admin change (`writ admin apply`, over the approval API) or by `writd recover` on the
daemon host, with the passphrase. The files `writd.yaml` names are written back with the text
in force; editing one by hand changes nothing (it is set aside at the next start).

## Before anything is lost

| Prepare | Why | How |
|---|---|---|
| A second approver key | Losing the only one leaves no signed way to change anything | A YubiKey (`ssh-keygen -t ed25519-sk`), added with `writ admin apply approvers` while you still can |
| A second reader key | A lost Mac takes its reader key, and nobody reaches the approval API without one | `writ reader <name>` on another machine, added with `writ admin apply readers` |
| The passphrase, somewhere else than your head | Nothing recovers the keystore without it; `writd recover` needs it too | A password manager |
| Backups of the state and the keys | A lost disk loses the leases, the ledger, the audit log and the keys | `state_dir` (copy `leases.db` with `sqlite3 leases.db .backup`, not while it is written), `keystore.sealed.dir` (encrypted: safe to copy anywhere), the boot tier (secret: keep it as such) |
| The current files, outside the host | To edit and recover from | `writ admin show policy > policy.yaml` (and `approvers`, `readers`) from your machine |

## What happened, and what to do

| You lost / found | You still have | Do |
|---|---|---|
| One approver key | Another approver key | `writ admin apply approvers` without the lost key, signed with the other one |
| Every approver key | The passphrase and the host | [Recover](#writd-recover-step-by-step) `approvers` with a new key |
| One reader key | Another reader key | `writ admin apply readers` without it |
| Every reader key (a lost Mac: both kinds of key) | The passphrase and the host | [Recover](#writd-recover-step-by-step) `readers` (and `approvers`) with new keys |
| A file edited by hand on the host | — | It was set aside at the start (`<file>.unapplied-<time>`, in the log and the audit log) and never applied. To apply it: `writ admin apply` from your machine, or [recover](#writd-recover-step-by-step) with it |
| The daemon refuses to unseal: "altered at rest" | The passphrase and the host | Someone changed the versions in force in the state without the keystore's key. Find out how (the audit log, the host's own logs), then [recover](#writd-recover-step-by-step) each file you trust, or put back a backup of `state_dir` |
| The daemon refuses to start: "no authority files in force" | The files | The state lost its versions (a new or emptied `state_dir`). Put back a backup of `state_dir`; a state that never had any takes a fresh `writd init` |
| The passphrase | — | The keystore can't be opened, by design, and `writd recover` can't run. Start over: a new `writd init` in empty directories (and a new `state_dir`), the new keys registered on the remotes (`writd upstream-keys`, `writd signing-keys`), new pins on the clients, the leases gone. From M7.6, the offline recovery identity opens the keystore instead |
| The keys directory, the boot tier, or the whole host | A backup of each | Put them back as they were (same paths, the daemon's user owning them, modes kept), then start and unseal |

A note on backups: putting `state_dir` back from an older copy puts older versions in force
(they carry a valid MAC: they were the keystore's). That is how a backup works; it is also why
the backup must be kept as carefully as the state itself.

## `writd recover`, step by step

`writd recover <writd.yaml> <policy|approvers|readers> <file>` puts `<file>` in force from the
daemon host. It needs the host and the passphrase, which together open every secret already:
it gives nobody anything new.

1. **Stop the daemon.** Two writers on one state would refuse each other's versions.
2. **Write the file.** Start from the text in force, which is in the file `writd.yaml` names
   (written back by the daemon). For `approvers`: the new approval key's line
   (`<name> <public key>`); for `readers`: the line `writ reader <name>` printed on the new
   machine. Keep the file owned by the daemon's user, not writable by group or others.
3. **Run it, as the daemon's user** (see [the platforms](#the-daemons-user-on-each-platform)):

   ```sh
   writd recover writd.yaml approvers approvers.new
   ```

   It asks for the passphrase (one line of stdin when it isn't a terminal), checks the file as
   an admin change would (it parses; there is still an approver and a reader; no key is both),
   records it as a new version under the keystore's MAC, writes one `admin` line to the audit
   log ("recovered on the host"), and writes the text to the file `writd.yaml` names. A wrong
   passphrase changes nothing.
4. **Start the daemon and unseal it** with the new key: `writ unseal --key <new key>.pub`.
5. **Check:** `writ admin show approvers` from your machine shows the recovered version; the
   audit log has its line.

## The daemon's user on each platform

`writd recover` (like `writd init`) runs as the user the daemon runs as, so the files it writes
stay that user's and the keystore stays readable by the daemon only. Never run it as root on
files the daemon owns: the daemon refuses files owned by another user than itself or root,
and a root-owned file the daemon can't rewrite stops the write-back.

### macOS, local mode

From [M7](../roadmap.md#m7--local-mode-on-the-mac), the local daemon is a LaunchDaemon running
as the dedicated user `_writd`, isolated from your user (your user can't read its files, by
design). Its label and paths are the ones M7's installer sets; with that layout:

```sh
sudo launchctl bootout system/<label>               # 1. stop the daemon
sudo -u _writd cp approvers.new <its directory>/    # 2. the file, owned by _writd
sudo -u _writd writd recover <its writd.yaml> approvers <its directory>/approvers.new
sudo launchctl bootstrap system /Library/LaunchDaemons/<label>.plist   # 4. start it
writ unseal --key ~/.writ/new-approval.pub          #    and unseal from your user
```

`sudo -u _writd` asks for your password: an admin account is needed, which is the line between
you and the daemon's keys (your user must not have passwordless `sudo`,
[threat model](../threat-model.md#6-local-mode-the-daemon-vs-my-own-user)). Until M7 the
daemon runs as your own user while it is developed (M0 to M6): run `writd recover` as
yourself, after stopping the `writd run` you started.

### Docker, detached mode

From [M8](../roadmap.md#m8--detached-deployment), the daemon runs in its container as the
image's non-root user, with the state and the keys in volumes. Run `writd recover` in a
one-off container of the same image, as that user, with the same volumes, the daemon's
container stopped:

```sh
docker compose stop writd                                       # 1.
docker compose cp approvers.new writd:/var/lib/writ/approvers.new   # 2.
docker compose run --rm -it writd writd recover /etc/writ/writd.yaml approvers /var/lib/writ/approvers.new
docker compose start writd                                      # 4.
writ unseal --key ~/.writ/new-approval.pub
```

`-it` gives the passphrase prompt a terminal. A copied file may come in owned by root: set its
owner to the image's user first (`docker compose run --rm --user root writd chown …`), never
run `writd recover` itself as root.

### Linux, natively

A dedicated system user (for example `writd`), the daemon under systemd:

```sh
sudo systemctl stop writd                                       # 1.
sudo install -o writd -g writd -m 0644 approvers.new /var/lib/writ/approvers.new   # 2.
sudo -u writd writd recover /etc/writ/writd.yaml approvers /var/lib/writ/approvers.new
sudo systemctl start writd                                      # 4.
writ unseal --key ~/.writ/new-approval.pub
```

## What recovery can't do

- Open the keystore without the passphrase (or, from M7.6, the offline recovery identity).
- Bring back leases, the ledger or the audit log from a lost `state_dir`: only its backup can.
- Undo what a lost key did while it was valid: a lost approval key could sign until it was
  removed; read the audit log (`grant`, `admin` lines) for what it approved, and revoke
  (`writ revoke`) what you don't recognize.
