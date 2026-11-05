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
