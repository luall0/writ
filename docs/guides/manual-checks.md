# Manual checks

Checks that need a person: a Touch ID, a hardware key. `make test` covers everything else
with generated keys and throwaway agents; these run the same code with your real approver.
They only use the development daemon (`make run`), test keys and the throwaway `demo` repo.

## Approving with Secretive (Touch ID)

[M2](../history/m2-ticket-flow.md)'s acceptance item "signed with Secretive". `writ sign`,
`writ refuse` and `writ revoke` sign through Secretive's agent with your dedicated approval
key, and nothing else. Each signature is one Touch ID.

You need Secretive with a dedicated approval key ("Require authentication" on), and three
terminals at the repo root.

**1. Your approval public key.** In Secretive, select the approval key and copy its public
key (the files are also in
`~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/PublicKeys/`). Save it as
the client's approval key, and list it as the daemon's approver:

```sh
mkdir -p dev/data/client
pbpaste > dev/data/client/approver.pub          # the copied public key line
echo "me $(cat dev/data/client/approver.pub)" > dev/approvers
```

Both stay out of git (`dev/data/` and `dev/approvers` are ignored). Never put a private key
there: only the public line.

**2. Pin the daemon** (host key for SSH, certificate fingerprint for HTTPS), and make the
client's reader key, listed in `dev/readers` (only readers reach the approval API):

```sh
make dev-client
```

**3. Terminal 1: the daemon.**

```sh
make run
```

It prints its host key, TLS fingerprint, your approver's fingerprint (check it matches the
key in Secretive) and its listeners: agents on 2222, approvals on 2223 (SSH) and 8443
(HTTPS).

**4. Terminal 2: the agent side.** Submit `dev/ticket.yaml` and wait for the decision:

```sh
source dev/client.env
cargo run -q -p writ-cli -- request dev/ticket.yaml
```

It prints the ticket id and waits.

**5. Terminal 3: the approver side.** Review and sign:

```sh
source dev/client.env
cargo run -q -p writ-cli -- sign
```

The ticket is shown first (agent text behind `│`). Answer `y`: Secretive asks for Touch ID.
Terminal 2 then prints `Lease wrt_… granted until …` and exits 0; the session is in
`dev/data/client/sessions/<id>/` (`key`, `key-cert.pub`, `lease.json`).

`dev/client.env` uses HTTPS for the approval API. To check SSH too, run step 5 again with
`WRIT_APPROVAL_URL=ssh://127.0.0.1:2223`.

**5b. Optional: a commit signed under the lease** ([M3](../history/m3-signed-commits.md);
covered by `make test`, nothing here needs Touch ID). In terminal 2, in a throwaway repo:

```sh
writ="$PWD/target/debug/writ"; cargo build -q -p writ-cli -p writ-sign
cd "$(mktemp -d)" && git init -q && "$writ" init demo      # wrapper mode
echo hi > notes.txt && "$writ" git add notes.txt
"$writ" git commit -m "Manual check" --trailer "Writ: <lease id>"   # signed, no prompt
echo "agent@writ.invalid $(cat "$WRIT_HOME/sessions/current/signing_key.pub")" > allowed
git -c gpg.ssh.allowedSignersFile=allowed verify-commit HEAD
cd -
```

Without the trailer, or with another email (`"$writ" git -c user.email=… commit …`), git
prints the daemon's reason and no commit is made.

**6. Refuse and revoke** (also signed: `decisions: signed` in `dev/writd.yaml`):

```sh
# terminal 2: submit again
cargo run -q -p writ-cli -- request dev/ticket.yaml
# terminal 3: refuse it (Touch ID); terminal 2 prints the feedback and exits 4
cargo run -q -p writ-cli -- ls
cargo run -q -p writ-cli -- refuse <pending id> -m "Manual check: refused on purpose"
# terminal 3: revoke the lease from step 5 (Touch ID)
cargo run -q -p writ-cli -- revoke <active lease id>
```

**7. What to check.**

- Every signature asked for Touch ID, and Secretive named the approval key, never another.
- Answering `n` at the prompt signs nothing (`Nothing signed.`, exit 6).
- Cancelling Touch ID fails the command (`ssh-keygen could not sign`), and the ticket stays
  pending (`writ ls`).
- `dev/data/audit.jsonl` has `grant allowed`, `refuse done` and `revoke done` lines whose
  `approver` is your key's fingerprint, and no key material.

**8. Clean up.** Stop `make run` (Ctrl-C), then:

```sh
rm -rf dev/data dev/approvers
```

When it passes, note it under the acceptance item in
[the M2 history page](../history/m2-ticket-flow.md).

## The approval popup (M7.8)

[M7.8](../history/m7.8-approval-popup-on-the-mac.md)'s manual check: what only a person in
front of the Mac sees. `make test` and `make e2e` prove `writ sign --ui` (what is shown, what
an answer signs); this checks the window `writ-popup` draws around it. Set up steps 1 to 3 of
[Approving with Secretive](#approving-with-secretive-touch-id) first (the daemon running in
terminal 1).

**1. Terminal 3: the popup**, against the development daemon, with your approval key:

```text
cargo build -q -p writ-cli && sh tool/build-writ-popup.sh target/debug
source dev/client.env
target/debug/writ-popup
```

No Dock icon and no window: nothing waits.

**2. A ticket while an app is full screen.** Put any app full screen (a browser, the
terminal), then in terminal 2 submit `dev/ticket.yaml` (`cargo run -q -p writ-cli -- request
dev/ticket.yaml`). Check, one by one:

- [ ] the window comes up over the full-screen app, and also on another space (switch to
      one with Ctrl-→ while it is up);
- [ ] no rail (one ticket); the centre shows the header ("Ends in …", the clock time beside
      it), every term as a tile, the paths as a tree (Tree / List and the filter work), the
      details folded (they open); the agent's task and plan in the right pane, which scrolls
      on its own; **Copy as text** gives the text `writ sign <id> --full` prints; the time
      left counts down;
- [ ] in light and in dark mode (System Settings, Appearance) it reads well;
- [ ] Sign and Decline are greyed for about a second, then usable;
- [ ] Return and Space typed while it is up press nothing (no button takes the focus);
- [ ] Sign brings Secretive's Touch ID prompt over the window; once touched, terminal 2 prints
      `Lease wrt_… granted` and the window goes.

**3. Several at once, and Decline.** Submit three tickets in a row (the same command three
times, `--no-wait`):

- [ ] the rail shows three badges, the oldest shown and ringed; pointing at one shows its
      title and repositories; a click shows it, and back;
- [ ] Decline, then Refuse with the feedback empty: Touch ID, then the next ticket comes up,
      two left in the list; `writ wait <id>` for the refused one prints *Declined in the
      approval popup, with no feedback.*;
- [ ] Decline, type a reason, Refuse: the agent reads that reason;
- [ ] Sign, then cancel Touch ID: the window says the signature failed and keeps the ticket,
      its buttons back after a second.
- [ ] An amendment (`amends: <lease>` in a ticket, one path added to its `expected_paths`)
      opens on what changes: that path alone added, in green, and how many stay; its task
      before and after in the right pane.
- [ ] A ticket over two repositories: the lease's strip, then one card per repository with
      its own terms and paths; an amendment changing one of them marks that card CHANGES and
      folds the other, its changes captioned with the repository.
- [ ] A ticket with many paths (a hundred, some long) and a long plan: the paths card
      scrolls inside itself, every path whole; the plan scrolls in its pane; Sign stays in
      sight.

**4. A ticket that goes away.** Submit one, and while it is shown, withdraw it from terminal 2
(`cargo run -q -p writ-cli -- revoke <id>`, with `dev/client.env`): the window goes. Submit one
more and close the window with its close button: nothing is signed, `writ ls` still lists it,
and the popup doesn't show it again (`writ sign` in a terminal still reaches it).

**5. The daemon stopped and started again** (Ctrl-C in terminal 1, then `make run`): the popup
says it can't reach the daemon, then picks up what waits once it is back. Quit it with Ctrl-C
in terminal 3.

Run by the user to close M7.8 (2026-11-15, its acceptance items on
[its history page](../history/m7.8-approval-popup-on-the-mac.md#acceptance)); run it again
after a change to `writ-popup` or `writ sign --ui`. The popup installed by `make install`
(started at login) is checked with [local mode on the Mac](#local-mode-on-the-mac-m7).

## A throwaway GitHub repo (M4)

[M4](../history/m4-gateway-push-and-fetch.md)'s acceptance against a real hosted remote:
pushes and fetches through the daemon to GitHub, with a deploy key the daemon holds. `make
e2e` runs the same agent commands against Forgejo in Docker; this one needs your GitHub account, so it
is done by hand. Use a **throwaway private repository**, never a real one.

**The quick way.** With the repository created (step 1) and your approval key saved (step 1
of [Approving with Secretive](#approving-with-secretive-touch-id)):

```sh
make github-check REPO=<you>/writ-throwaway                                # steps 2 to 8
make github-check REPO=<you>/writ-throwaway EMAIL=<you+agent@example.org>  # and "Verified"
```

`tool/github-check.sh` sets a daemon up from nothing in a temporary directory (nothing in
`dev/` changes), runs steps 2 to 8 with the commands below, prints each check as `ok` or
`FAIL`, and removes what it made, `agent/manual-check` on GitHub included. Your approval key
signs once (the ticket); your GitHub SSH key does your side: the clone before `writ init`,
reading GitHub's branches to compare, the "upstream moves" commit (pushed from a second clone
instead of the web editor) and the branch's deletion. Each use of one of your keys is
announced right before it happens (`[your GitHub key #n] why`, `[your approval key] why`) and
listed in the summary, so a confirmation without such a line is not the script's. With [`gh`](https://cli.github.com/) installed and
logged in it adds and removes the deploy key (and the signing key, for "Verified")
itself; otherwise it prints each key and waits while you add it. `EMAIL` must be one of your
account's verified emails: it becomes the lease's committer email. The steps by hand follow.

**1. The repository.** On GitHub, create a private repository (say `writ-throwaway`) with a
README, so it has a `main`.

**2. Point the development daemon at it** (edits to tracked files, taken back in step 9):

```sh
sed -i '' 's|ssh://git@remote.invalid/demo.git|ssh://git@github.com/<you>/writ-throwaway.git|' dev/policy.yaml
sed -i '' 's|  remote.invalid: \[.*\]|  github.com: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"]|' dev/policy.yaml
```

It pins GitHub's host key in the policy's `upstream_hosts`. Check that key against GitHub's
published fingerprints (Settings docs, "GitHub's SSH key fingerprints":
`SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU` for Ed25519) with
`echo 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl' | ssh-keygen -lf -`.

**3. The daemon's credential, as a deploy key.**

```sh
cargo run -q -p writd --features dev-keystore -- upstream-keys dev/writd.yaml
```

Add the printed `upstream-dev-01` key to the repository: Settings → Deploy keys → Add, with
**Allow write access**.

**4. Run the daemon and get a lease** (steps 1 to 5 of
[Approving with Secretive](#approving-with-secretive-touch-id): `make dev-client`, `make run`,
`writ request dev/ticket.yaml`, `writ sign`). Its log shows `mirror created repo=demo`, then
a sync of `main` (and nothing about `remote.invalid`).

**5. An agent's clone.** In terminal 2 (with `dev/client.env` sourced), put the built `writ`
first in `PATH`, clone with your own access, then wire it:

```sh
cargo build -q -p writ-cli -p writ-sign && export PATH="$PWD/target/debug:$PATH"
git clone -q git@github.com:<you>/writ-throwaway.git "$(mktemp -d)/w" && cd "$_"
```

<!-- e2e: crates/writ-e2e/tests/scenarios/wrapper_mode.rs -->
```sh
writ init demo --agents claude   # prints that `writ git push origin` goes through the daemon
writ git fetch origin   # through the daemon
git checkout -q -b agent/manual-check origin/main
echo hi > notes.txt && writ git add notes.txt
writ git commit -m "Manual check" --trailer "Writ: <lease id>"
writ git push origin HEAD:refs/heads/agent/manual-check
```

`make e2e` runs these steps (5 to 7) with the same commands against Forgejo
(`wrapper_mode`, [end-to-end](../end-to-end.md#commands-the-docs-show)).

**6. Upstream moves.** On GitHub, on `agent/manual-check`, add a file (`theirs.txt`, any
content) in the web editor and commit; another file than the agent's, so the rebase below
applies cleanly (editing `notes.txt` there makes it conflict: resolve it, then `writ git
add notes.txt && writ git rebase --continue`, which signs the commit again). Then:

<!-- e2e: crates/writ-e2e/tests/scenarios/wrapper_mode.rs -->
```sh
echo more >> notes.txt && writ git commit -qam "Second" --trailer "Writ: <lease id>"
writ git push origin HEAD:refs/heads/agent/manual-check    # rejected: upstream moved
writ git fetch origin && writ git rebase origin/agent/manual-check   # signed again
writ git push origin HEAD:refs/heads/agent/manual-check    # accepted
```

**7. Refused pushes.** `main` is protected in `dev/policy.yaml`, and a plain commit isn't
signed under the lease; `main` on GitHub doesn't move:

<!-- e2e: crates/writ-e2e/tests/scenarios/wrapper_mode.rs -->
```sh
writ git push origin HEAD:refs/heads/main                  # refused: main is protected
git commit -q --allow-empty --no-gpg-sign -m "Unsigned"
writ git push origin HEAD:refs/heads/agent/manual-check    # refused: not signed under the lease
```

**8. What to check.**

- GitHub shows `agent/manual-check` with your commits, by `agent@writ.invalid`.
- `git -C dev/data/repos/demo.git for-each-ref` never shows a ref GitHub refused.
- `dev/data/audit.jsonl` has `push allowed` lines for the accepted pushes, `push denied`
  for the refused ones (with the remote's reason for the rejection in step 6), and no key.
- The agent side holds no GitHub credential: `dev/data/client/sessions/` holds only the
  session key and certificate, and `writ git push` worked without your SSH agent.
- "Verified": GitHub shows a commit as verified when its signing key is a **signing** key on
  your account (`writd signing-keys dev/writd.yaml` prints it) and its committer email is
  one of your account's **verified** emails. `agent@writ.invalid` can't be one (GitHub
  verifies by mail): set the template's `committer_emails` to an address of yours (a
  `+agent` one) first, or let `make github-check … EMAIL=<address>` do it. Commits pushed
  before the key is on the account show as unverified, those after as "Verified". (GitHub
  asks no proof; Forgejo does: `make e2e`'s `verified_commits`.)

**9. Clean up.** Stop `make run`, delete the deploy key and the repository on GitHub, then:

```sh
git checkout dev/policy.yaml
rm -rf dev/data dev/approvers
```

When it passes, note it under the acceptance item in
[the M4 history page](../history/m4-gateway-push-and-fetch.md).

## Approval key through your own agent (any key)

`make test-agent KEY=<public key .pub> [AGENT=<socket>]` signs a random message with a key in
your agent and verifies it in Rust (checked in [M0](../history/m0-protocol-spike.md) with a
Secure Enclave key). It doesn't need the daemon.

## Process hardening on the Mac (M5)

The contract suite checks the core limit and that the hardening reports each step; a
debugger being refused needs a real one. With the development daemon running (`make run`):

```sh
lldb -p "$(pgrep -n writd)" --batch -o detach    # refused: attach failed (lost connection)
```

Then start one under the debugger (`lldb -- target/debug/writd run dev/writd.yaml`, `run`):
a debug build keeps running, its log saying `PT_DENY_ATTACH` was skipped because the process
is traced; a release build (`cargo build --release -p writd`, then under `lldb` the same way)
refuses to start, saying it is traced. When both pass, note it under the acceptance item in M5's history page.

## A real agent end to end (M6)

The checks with a real agent (OpenCode, Claude Code…) on a throwaway GitHub repository, its
prompts never naming Writ: one task from prompt to pushed branch with one Touch ID, a custom
committer name, then a refusal, an amendment and a renewal handled from the skill alone. Their
own page: [manual checks with a real agent](manual-checks-e2e.md).

## Local mode on the Mac (M7)

The installer's frame and its `local` setup run in `make test` against a fake root; this is
the real thing, on your Mac, with `sudo` and Touch ID. It changes your system: run it on a
Mac where you can reboot. It was [M7.9](../history/m7.9-local-mode-checked-on-the-mac.md)
(run by the user, 2026-11-15, with M7.5 and M7.6 in place, their steps here); run it again
after a change to the installer, launchd's files or the Secure Enclave signer.

**1. Before.** Keep what is there now, to compare with after the uninstall:

```sh
sudo sh -c 'ls -la /opt /etc/paths.d /var/db /Library/LaunchDaemons /Library/Logs "/Library/Application Support"; dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID' > ~/writ-before.txt
ls -la ~/.writ >> ~/writ-before.txt 2>&1
```

**2. Install**, guided: every question answered at the prompt, then again (an upgrade):

```sh
make install    # Enter (local), a wrong path then ~/.ssh/writ-approval.pub, se-cryptokit for
                # the TLS key, the SSH CA and agent-01; the keystore: passphrase (Enter);
                # the summary lists every change: answer n
make install    # the same answers, then y: the passphrase asked, the keystore made
make install    # an upgrade: its changes listed, y; the keystore kept
```

Check that the summary named the Secure Enclave for both keys, and that `writ admin key list`
shows `agent-01` as `signing ssh p256` once unsealed.

**3. Unseal and use it.** In a new terminal: `writ unseal` (Touch ID), then add a repo from
the [GitHub manual check](#a-throwaway-github-repo-m4)'s throwaway repository with
`writ admin`, `writ init <repo>` in a clone, and run an agent under `writ run -- <agent>`:
its ticket shows `caller descends from "<the agent's program>" (pid …, signed …), started by
writ` (the agent `writ run` started, M7.7); its
commit and push work. From another terminal (outside the session), `writ git fetch` in the
same clone is refused (`caller`). Quit the agent: `writ ls` shows the lease revoked.

**3b. The Secure Enclave (M7.5).** The template signs with `agent-01`, made in the Secure
Enclave at step 2: its commit verifies with `git verify-commit` against `writ admin key show
agent-01 --public`, with no prompt. Lock the screen (Ctrl-Cmd-Q) with an agent working: its
commits still sign. Then from your machine:

```sh
writ admin key add agent-pgp use=signing format=openpgp algorithm=p256 backend=se-cryptokit "uids=Agent <agent@example.com>" --yes
writ admin tls rotate --backend se-cryptokit --yes   # over SSH here: the pin line printed
writ admin key list                                  # ends with: backends: software (…); se-cryptokit (p256)
```

A template switched to `agent-pgp` signs a commit that `gpg --verify` accepts once its
certificate (`writ admin key show agent-pgp --public`) is imported.

**3c. Hardware-wrapped secrets and auto-unseal (M7.6).** On this Mac's real Secure Enclave
(the integration tests ran it against a fake helper):

```text
writ recovery new                                   # on a machine that isn't online if you can; write it down
writ admin recipient add recovery recipient=<age1…> --yes
writ recovery check                                 # paste the key: "Recovery key checked"
writ admin recipient add se-01 backend=se-cryptokit --yes
writ admin token <id>                               # an https:// repo's token: encrypted to se-01 and the recovery key
```

- Restart the daemon (`sudo launchctl kickstart -k system/dev.writ.writd`), then `writ
  unseal`: it says the hardware opens the keystore and asks no passphrase, only Touch ID.
- An agent's HTTPS push works with no prompt; lock the screen (Ctrl-Cmd-Q) and push again:
  it still works. `sudo cat /var/db/writ/keys/tokens/<id>.age` shows only `piv-p256` and
  `X25519` stanzas; as your user, `cat /var/db/writ/keys/recipients/se-01.blob` is refused.
- The idle daemon holds no token: with the agent stopped, `sudo vmmap -wide "$(pgrep -n
  writd)"` runs, and `sudo lldb -p` is refused (`PT_DENY_ATTACH`); the per-use unwrap is
  what the integration tests prove (`the_token_is_unwrapped_for_each_operation_…`).
- Follow [the sealing guide's auto-unseal section](../operators/sealing.md#starting-without-a-human-auto-unseal-m76)
  as written: `writ admin auto-unseal status` lists what is missing; rotate the CA and each
  key it names with `--backend se-cryptokit`; `on`; restart the daemon: its log says
  `unsealed automatically`, Telegram says "writd unsealed automatically", and `writ admin key
  list` answers with no `writ unseal`. Reboot the Mac: after login the daemon is open.
- `writ admin auto-unseal off`, restart: it waits for `writ unseal` again.

A fresh `make install` can ask all this up front: `se-cryptokit` for the CA key and
`agent-01`, the keystore opened by `se-cryptokit` (Enter at the recovery key makes one, shown
once), and `yes` to auto-unseal: the install ends with the daemon open, no `writ unseal`.

**Device keys made by the daemon** (found on the first real install, 2026-11-14): a fresh
`make install` with `se-cryptokit` for the TLS key, the CA and `agent-01`. `writd init`'s
output says each is owed; the daemon's log at its first start says each one `made on
se-cryptokit at the daemon's start` (`/Library/Logs/Writ/writd.log`), and `sudo ls
/var/db/writ/keys` shows no `to-make.json` left.
`writ unseal`, then a ticket signed in the popup and in `writ sign`: the lease is granted
(before the fix: `internal error in the daemon`, `the helper refused: sign-failed` in the
log), and the agent's first signed commit verifies. On an install made before the fix,
the unseal's audit log names each Secure Enclave key `writd init` made as unusable, with its
rotate command; after each rotation it signs.

**4. The daemon is out of your reach:**

```sh
cat /var/db/writ/keys/identity.age            # Permission denied
cat /var/db/writ/keys/signing/agent-01        # Permission denied (its blob: _writd's alone)
lldb -p "$(pgrep -n writd)" --batch -o detach # attach failed
```

**5. Stop and recover.** `sudo launchctl kill TERM system/dev.writ.writd`: the log
(`/Library/Logs/Writ/writd.log`) says `stopping signal="SIGTERM"`, then `stopped`, and the
daemon stays stopped. While it runs, `writd recover` is refused naming its pid; stopped, the
[recovery guide's macOS steps](../operators/recovery.md#macos-local-mode-m7) run as written.
Reboot the Mac: after logging in, the daemon is running again (sealed): `writ unseal`; an
agent's commit signs again in the Secure Enclave, with no prompt.

**6. Uninstall** and compare:

```sh
make uninstall                      # the wired repos: y; the data: Enter (kept); its go: y
sudo sh -c 'ls -la /opt /etc/paths.d /var/db /Library/LaunchDaemons /Library/Logs "/Library/Application Support"; dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID' > ~/writ-after.txt
ls -la ~/.writ >> ~/writ-after.txt 2>&1
diff ~/writ-before.txt ~/writ-after.txt   # /var/db/writ (kept) and ~/.writ/reader; directory times aside
make install && make uninstall      # installed as in step 2; then type delete, and y
```

After the purge, the diff with `~/writ-before.txt` shows only directory times, and the
repository wired in step 3 is as it was before its `writ init`.

## Local mode on Linux (M7.1)

The `local` setup on Linux runs in `make test` against a fake root (its unit checked by
`systemd-analyze verify`), and the daemon itself, laid out as the setup lays it out, in
end-to-end scenario 24; this is the real install, on a Debian 13 machine without Writ (a VM
you can reboot), with systemd and `sudo`. M7.1 was closed before it ran: when every step
passes, tick the three acceptance items left open on
[its history page](../history/m7.1-local-mode-on-linux.md#acceptance).

**1. Before.** Keep what is there now, to compare with after the uninstall:

```sh
sudo sh -c 'ls -la /usr/local/bin /etc /etc/systemd/system /var/lib; getent passwd; getent group' > ~/writ-before.txt
ls -la ~/.writ >> ~/writ-before.txt 2>&1
```

**2. Install**, then again (an upgrade):

```sh
make install    # Enter (local), ~/.ssh/writ-approval.pub; the summary lists every change: n
make install    # the same answers, then y: the passphrase asked, the keystore made
make install    # an upgrade: its changes listed, y; the keystore kept
```

**3. Unseal and use it.** Log in again (the `writ` group), then `writ unseal`, add a repo
from the [GitHub manual check](#a-throwaway-github-repo-m4)'s throwaway repository with
`writ admin`, `writ init <repo>` in a clone, and run an agent under `writ run -- <agent>`: its
ticket shows `caller descends from "<the agent's program>" (pid …), started by writ`; its
commit and push work.
From another terminal, `writ git fetch` in the same clone is refused (`caller`). Under the
session, a command in a bubblewrap sandbox is served
(`bwrap --ro-bind / / --dev /dev --proc /proc --bind /run/writ /run/writ --unshare-pid writ git fetch`
in the clone), and its process is marked `unbindable` in the audit line
(`sudo journalctl -u writd` names the audit log: `/var/lib/writ/state/audit.jsonl`). Quit the
agent: `writ ls` shows the lease revoked.

**4. The daemon is out of your reach:**

```sh
cat /var/lib/writ/keys/identity.age                      # Permission denied
gdb -batch -p "$(pgrep -x -f '/usr/local/bin/writd run /etc/writ/writd.yaml')"   # ptrace: Operation not permitted
strace -p "$(pgrep -x -f '/usr/local/bin/writd proc-reader')"                    # Operation not permitted
sudo grep ^Cap /proc/"$(pgrep -x -f '/usr/local/bin/writd run /etc/writ/writd.yaml')"/status   # CapPrm and CapEff 0
```

**5. Stop and recover.** `sudo systemctl stop writd`: `journalctl -u writd` says
`stopping signal="SIGTERM"`, then `stopped`, and the service stays stopped. While it runs,
`writd recover` is refused naming its pid; stopped, the
[recovery guide's Linux steps](../operators/recovery.md#linux-local-mode-m71) run as written.
`sudo systemctl start writd`, then reboot: the daemon is running again (sealed): `writ unseal`.

**6. Uninstall** and compare:

```sh
make uninstall                      # the wired repos: y; the data: Enter (kept); its go: y
sudo sh -c 'ls -la /usr/local/bin /etc /etc/systemd/system /var/lib; getent passwd; getent group' > ~/writ-after.txt
ls -la ~/.writ >> ~/writ-after.txt 2>&1
diff ~/writ-before.txt ~/writ-after.txt   # /var/lib/writ (kept) and ~/.writ/reader; directory times aside
make install && make uninstall      # installed as in step 2; then type delete, and y
```

After the purge, the diff with `~/writ-before.txt` shows only directory times, and the
repository wired in step 3 is as it was before its `writ init`.
