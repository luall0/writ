# Recovery

What to do when you lose an approval key, a reader key, the Mac that held both, or the
passphrase. Read [before anything is lost](#before-anything-is-lost) first: some losses can't
be fixed afterwards.

## Before anything is lost

| Prepare | Why | How |
|---|---|---|
| A second approval key | With only one, losing it leaves no way to sign any change | A YubiKey (`ssh-keygen -t ed25519-sk`), added with `writ admin apply approvers` |
| A second reader key | A lost Mac takes its reader key, and without one nobody reaches the approval API | `writ reader <name>` on another machine, added with `writ admin apply readers` |
| The passphrase, written down somewhere safe | Without it or the recovery key, nothing opens the keystore, not even `writd recover` | A password manager |
| A recovery key, kept offline | It opens the keystore when the passphrase is lost, or the Mac's Secure Enclave is | `writ recovery new`, then `writ admin recipient add recovery recipient=<age1…>` ([how](sealing.md#the-recovery-key-and-the-secure-enclave)); check it now and then with `writ recovery check` |
| Backups | A lost disk loses the leases, the ledger, the audit log and the keys | `state_dir` (copy `leases.db` with `sqlite3 leases.db .backup`), `keystore.sealed.dir` (encrypted: it opens with the passphrase or a recovery key it held, even one you replaced since, so drop old copies when you [take one out](sealing.md#removing-or-replacing-a-way-in)), the boot directory (secret: keep it safe) |
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
| Lost the passphrase, and you declared a recovery key | `writd recover` takes the recovery key where it asks for the passphrase. The passphrase stays as it was: to change it, start over |
| Lost the Mac's Secure Enclave key (a new Mac, a wiped one), and you declared a recovery key | [`writd recover`](#writd-recover-step-by-step) `policy`, with the recovery key and a policy that no longer names the lost key: it asks for a new passphrase, and the keystore opens with it from then on |
| Lost the passphrase and had no recovery key | It can't be recovered, by design. [Start over](#starting-over) |
| Lost the keys directory, the boot directory or the host, and you have backups | Restore them at the same paths, same owner, same modes. Then start and unseal |

**About backups:** restoring an older `state_dir` also restores the older policy, approvers
and readers it held. That's how a backup works, and why it must be guarded like the state
itself.

## `writd recover`, step by step

`writd recover <writd.yaml> <policy|approvers|readers> <file>` puts `<file>` in force, from the
daemon host. It needs access to the host and the passphrase, or the recovery key. Together
they already open every secret, so it gives nobody anything new. The Secure Enclave alone is
never enough: on a keystore it opens, `writd recover` takes the recovery key only.

1. **Stop the daemon.** `writd recover` refuses to run while it runs, and says so:
   `writd (pid 812) holds …/writd.lock: stop the daemon first`.
2. **Write the new file.** Start from the current file on the host: the daemon keeps it up to
   date. For `approvers`, add the new key's line `<name> <public key>`. For `readers`, add the
   line `writ reader <name>` printed on the new machine. Keep the file owned by the daemon's
   user and not writable by group or others.
3. **Run it, as the daemon's user** ([how, per platform](#the-daemons-user-on-each-platform)):

   ```sh
   writd recover writd.yaml approvers approvers.new
   ```

   It asks for the passphrase or the recovery key (paste the line `writ recovery new` printed),
   then checks the file like a signed change would: it must
   parse, keep at least one approver and one reader, and no key may be both. Then it puts the
   file in force, writes an `admin` line to the audit log ("recovered on the host"), and
   writes the file back. A wrong passphrase changes nothing.

   After "altered at rest", it also shows you the other two files as the daemon's state holds
   them, since nothing vouches for them any more, and asks `Trust them and seal all three
   with this keystore? [y/N]`. Read them. Answer `y` only if they are what you expect: all
   three are then sealed again. Any other answer changes nothing: every question comes
   before the keystore is touched. If one of them is wrong too, answer no and recover that
   one first.

   Recovering a `policy` also brings the keystore in line with its `recipients`. A Secure
   Enclave key the policy no longer names, and that the Mac no longer opens, is dropped. If no
   Secure Enclave key is left, it asks for a new passphrase, twice: from then on, `writ unseal`
   asks for it. When the policy takes a way in out (a key dropped, the recovery key replaced
   or removed), every secret is sealed to a new internal key, as a signed change does
   ([what that takes back](sealing.md#removing-or-replacing-a-way-in)); if you gave the
   recovery key on a keystore that has a passphrase, it asks for a new passphrase for it.

   A recovered `policy` that declares a key the keystore doesn't have yet gets it made. One in
   the Mac's Secure Enclave is made by the daemon when it next starts, not by `writd
   recover`: it says the key is owed, and `writd signing-keys` prints it once the daemon has
   started.
4. **Start the daemon and unseal it** with the new key: `writ unseal --key <new key>.pub`.
5. **Check** from your machine: `writ admin show approvers` shows the new version.

## Starting over

Without the passphrase, the keystore is lost:

1. Run `writd init` in empty directories, with a new `state_dir`.
2. Register the new keys on the remotes: `writd upstream-keys`, `writd signing-keys`. A key in
   the Mac's Secure Enclave is made when the daemon first starts: start it first.
3. Pin the daemon's new identity on every client ([setup, step 7](setup.md#on-the-daemon-host)).

The leases are gone. With a [recovery key](sealing.md#the-recovery-key-and-the-secure-enclave)
declared beforehand, you never get here: `writd recover` takes it instead of the passphrase.

## The daemon's user on each platform

Run `writd recover` (and `writd init`) as the daemon's user, **never as root**. The daemon
refuses files owned by any user but itself or root, and can't rewrite the files root owns.

With the development daemon (`make run`), it is your own user: stop it, and run
`writd recover` as yourself.

### macOS, local mode (M7)

The daemon is a LaunchDaemon running as the dedicated user `_writd`. Your user can't read its
files, by design. The label and paths are the ones `make install` sets
([Installing on your machine](install.md)):

```sh
sudo launchctl bootout system/dev.writ.writd                         # 1. stop the daemon
sudo -u _writd cp approvers.new /var/db/writ/approvers.new           # 2. the file, owned by _writd
sudo -u _writd /opt/writ/bin/writd recover /var/db/writ/writd.yaml approvers /var/db/writ/approvers.new
sudo launchctl bootstrap system /Library/LaunchDaemons/dev.writ.writd.plist   # 4. start it
writ unseal --key ~/.writ/new-approval.pub                           #    and unseal from your user
```

Step 2 copies from a place `_writd` can read: a file in your home isn't, so put it in `/tmp`
first (`cp approvers.new /tmp/`, then `sudo -u _writd cp /tmp/approvers.new …`). The daemon's
log is `/Library/Logs/Writ/writd.log`.

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

### Linux, local mode (M7.1)

The daemon is the systemd service `writd`, running as the system user `writd`. Your user
can't read its files, by design. The paths are the ones `make install` sets
([Installing on your machine](install.md)):

```sh
sudo systemctl stop writd                                       # 1. stop the daemon
sudo install -o writd -g writd -m 0644 approvers.new /var/lib/writ/approvers.new   # 2. the file, owned by writd
sudo -u writd /usr/local/bin/writd recover /etc/writ/writd.yaml approvers /var/lib/writ/approvers.new
sudo systemctl start writd                                      # 4. start it
writ unseal --key ~/.writ/new-approval.pub                      #    and unseal from your user
```

`writd recover` runs without the service's capability (it needs none). The daemon's log is
`journalctl -u writd`.

`sudo` asks for your password. That password is what separates you (and any agent running as
you) from the daemon's keys, so your user must not have passwordless `sudo`
([threat model](../threat-model.md#6-local-mode-the-daemon-vs-my-own-user)).

## What recovery can't do

- Open the keystore without the passphrase or the recovery key.
- Bring back leases, the ledger or the audit log from a lost `state_dir`. Only a backup can.
- Undo what a lost key did while it was still listed. Read the audit log's `grant` and `admin`
  lines for what it approved, and `writ revoke` what you don't recognize.
