# Recovery

What to do when you lose an approval key, a reader key, the Mac that held both, or the
passphrase. Read [before anything is lost](#before-anything-is-lost) first: some losses can't
be fixed afterwards.

## Before anything is lost

| Prepare | Why | How |
|---|---|---|
| A second approval key | With only one, losing it leaves no way to sign any change | A YubiKey (`ssh-keygen -t ed25519-sk`), added with `writ admin apply approvers` |
| A second reader key | A lost Mac takes its reader key, and without one nobody reaches the approval API | `writ reader <name>` on another machine, added with `writ admin apply readers` |
| The passphrase, written down somewhere safe | Nothing opens the keystore without it, not even `writd recover` | A password manager |
| Backups | A lost disk loses the leases, the ledger, the audit log and the keys | `state_dir` (copy `leases.db` with `sqlite3 leases.db .backup`), `keystore.sealed.dir` (encrypted: safe anywhere), the boot directory (secret: keep it safe) |
| A copy of the current files | Something to edit and recover from | `writ admin show policy > policy.yaml`, and the same for `approvers` and `readers` |

## What happened, and what to do

| What happened | Do |
|---|---|
| Lost one approval key, you still have another | `writ admin apply approvers` without the lost key, signed with the other one |
| Lost every approval key | [`writd recover`](#writd-recover-step-by-step) `approvers` with a new key |
| Lost one reader key, you still have another | `writ admin apply readers` without the lost key |
| Lost every reader key (a lost Mac usually means both kinds) | [`writd recover`](#writd-recover-step-by-step) `readers`, and `approvers` if needed |
| Found `<file>.unapplied-<time>` on the host | Someone edited that file by hand. It was never applied. To apply it: `writ admin apply`, or `writd recover` |
| The daemon won't unseal: "altered at rest" | Someone changed the daemon's copies of the files without the keystore. Find out how (audit log, host logs). Then `writd recover` the file that was altered, from a copy you trust: it shows you the other two and asks whether you trust them (step 3 below). Or restore a backup of `state_dir` |
| The daemon won't start: "no authority files in force" | Its state lost its copies (a new or emptied `state_dir`). Restore a backup of `state_dir`, or run `writd init` if it was never initialized |
| Lost the passphrase | It can't be recovered, by design. [Start over](#starting-over) |
| Lost the keys directory, the boot directory or the host, and you have backups | Restore them at the same paths, same owner, same modes. Then start and unseal |

**About backups:** restoring an older `state_dir` also restores the older policy, approvers
and readers it held. That's how a backup works, and why it must be guarded like the state
itself.

## `writd recover`, step by step

`writd recover <writd.yaml> <policy|approvers|readers> <file>` puts `<file>` in force, from the
daemon host. It needs access to the host and the passphrase. Together they already open every
secret, so it gives nobody anything new.

1. **Stop the daemon.**
2. **Write the new file.** Start from the current file on the host: the daemon keeps it up to
   date. For `approvers`, add the new key's line `<name> <public key>`. For `readers`, add the
   line `writ reader <name>` printed on the new machine. Keep the file owned by the daemon's
   user and not writable by group or others.
3. **Run it, as the daemon's user** ([how, per platform](#the-daemons-user-on-each-platform)):

   ```sh
   writd recover writd.yaml approvers approvers.new
   ```

   It asks for the passphrase, then checks the file like a signed change would: it must
   parse, keep at least one approver and one reader, and no key may be both. Then it puts the
   file in force, writes an `admin` line to the audit log ("recovered on the host"), and
   writes the file back. A wrong passphrase changes nothing.

   After "altered at rest", it also shows you the other two files as the daemon's state holds
   them, since nothing vouches for them any more, and asks `Trust them and seal all three
   with this keystore? [y/N]`. Read them. Answer `y` only if they are what you expect: all
   three are then sealed again. Any other answer changes nothing. If one of them is wrong
   too, answer no and recover that one first.
4. **Start the daemon and unseal it** with the new key: `writ unseal --key <new key>.pub`.
5. **Check** from your machine: `writ admin show approvers` shows the new version.

## Starting over

Without the passphrase, the keystore is lost:

1. Run `writd init` in empty directories, with a new `state_dir`.
2. Register the new keys on the remotes: `writd upstream-keys`, `writd signing-keys`.
3. Pin the daemon's new identity on every client ([setup, step 7](setup.md#on-the-daemon-host)).

The leases are gone. From M7.6, an offline recovery identity will open the keystore instead.

## The daemon's user on each platform

Run `writd recover` (and `writd init`) as the daemon's user, **never as root**. The daemon
refuses files owned by any user but itself or root, and can't rewrite the files root owns.

Until M7, the daemon runs as your own user: stop your `writd run`, and run `writd recover` as
yourself.

### macOS, local mode (M7)

The daemon is a LaunchDaemon running as the dedicated user `_writd`. Your user can't read its
files, by design. The label and paths are the ones M7's installer sets:

```sh
sudo launchctl bootout system/<label>               # 1. stop the daemon
sudo -u _writd cp approvers.new <its directory>/    # 2. the file, owned by _writd
sudo -u _writd writd recover <its writd.yaml> approvers <its directory>/approvers.new
sudo launchctl bootstrap system /Library/LaunchDaemons/<label>.plist   # 4. start it
writ unseal --key ~/.writ/new-approval.pub          #    and unseal from your user
```

`sudo` asks for your password. That password is what separates you (and any agent running as
you) from the daemon's keys, so your user must not have passwordless `sudo`
([threat model](../threat-model.md#6-local-mode-the-daemon-vs-my-own-user)).

### Docker, detached mode (M8)

The daemon runs in its container as the image's non-root user, its state and keys in volumes.
Run `writd recover` in a one-off container of the same image, with the same volumes, while the
daemon's container is stopped:

```sh
docker compose stop writd                                       # 1.
docker compose cp approvers.new writd:/var/lib/writ/approvers.new   # 2.
docker compose run --rm -it writd writd recover /etc/writ/writd.yaml approvers /var/lib/writ/approvers.new
docker compose start writd                                      # 4.
writ unseal --key ~/.writ/new-approval.pub
```

- `-it` gives the passphrase prompt a terminal.
- A copied file may arrive owned by root. Fix its owner first
  (`docker compose run --rm --user root writd chown …`), but never run `writd recover` itself
  as root.

### Linux, natively

The daemon runs under systemd as a dedicated system user, for example `writd`:

```sh
sudo systemctl stop writd                                       # 1.
sudo install -o writd -g writd -m 0644 approvers.new /var/lib/writ/approvers.new   # 2.
sudo -u writd writd recover /etc/writ/writd.yaml approvers /var/lib/writ/approvers.new
sudo systemctl start writd                                      # 4.
writ unseal --key ~/.writ/new-approval.pub
```

## What recovery can't do

- Open the keystore without the passphrase.
- Bring back leases, the ledger or the audit log from a lost `state_dir`. Only a backup can.
- Undo what a lost key did while it was still listed. Read the audit log's `grant` and `admin`
  lines for what it approved, and `writ revoke` what you don't recognize.
