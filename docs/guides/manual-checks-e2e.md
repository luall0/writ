# Manual checks with a real agent (M6)

[M6](../history/m6-agent-skill-amendments-renewals-and-close.md)'s two acceptance items that
need a real agent and your Touch ID. First, one task goes from prompt to pushed branch with one
signature, and you are away while the agent works. Second, the agent handles a refusal, an
amendment and a renewal using only the skill. `make test` and `make e2e` run each piece with
scripted agents. Here a real agent (OpenCode, Claude Code…) finds the skill and decides what
to do: **the prompts never mention Writ**. The repo's setup (the skill, the line in
`AGENTS.md`) is what tells the agent.

You need Secretive with your approval key, a **throwaway private GitHub repository** with a
`main` (here `<you>/writ-throwaway`, cloned next to this repo as `../writ-throwaway`), Node.js
and npm on this Mac (the task is a small TypeScript server), and three terminals: the daemon,
you (the approver, at this repo's root) and the agent.

**0. Reset the throwaway clone**, if an earlier run left its wiring, branches or files. In
`../writ-throwaway`, with the earlier run's `WRIT_HOME` if it is still set:

```sh
writ init --undo                     # if it is still wired
git checkout -q main && git reset -q --hard origin/main && git clean -qfdx
git branch | grep -v main | xargs -n1 git branch -D   # the agent's local branches
git status --short                   # nothing
```

Delete the earlier run's branches on GitHub too, and set `main` back to its first commit if
an earlier check 2 merged into it.

**1. A fresh development daemon.** From nothing, at this repo's root:

```sh
rm -rf dev/data dev/approvers dev/readers         # an earlier setup, if any
mkdir -p dev/data/client
pbpaste > dev/data/client/approver.pub            # your approval key's public line, from Secretive
echo "me $(cat dev/data/client/approver.pub)" > dev/approvers
```

**2. Point it at the GitHub repository** (edits to tracked files, taken back in step 10).
The development policy already names every commit: `committer_name: "Writ agent 1"`, neither
yours nor your git's. Every commit the agent signs must carry it.

```sh
sed -i '' 's|ssh://git@remote.invalid/demo.git|ssh://git@github.com/<you>/writ-throwaway.git|' dev/policy.yaml
grep -A1 committer_emails dev/policy.yaml   # committer_name: "Writ agent 1", right under the email
sed -i '' 's|  remote.invalid: \[.*\]|  github.com: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"]|' dev/policy.yaml
cargo run -q -p writd --features dev-keystore -- upstream-keys dev/writd.yaml
```

Check GitHub's key as in [step 2 of the GitHub check](manual-checks.md#a-throwaway-github-repo-m4). Add the
printed `upstream-dev-01` key to the repository: Settings → Deploy keys → Add, with **Allow
write access**. A fresh `dev/data` makes a new key: delete the deploy key of an earlier setup.

**3. Pin the daemon, then run it.** At this repo's root, then in terminal 1:

```sh
make dev-client
make run
```

**4. Your side** (terminal 2, at this repo's root):

```sh
cargo build -q -p writ-cli -p writ-sign
source dev/client.env && export PATH="$PWD/target/debug:$PATH"
```

**5. The agent's side** (terminal 3, at this repo's root). The agent gets a Writ home of its
own with only the daemon's pinned host key in it. Your approval key and your reader key stay
in `dev/data/client`.

```sh
mkdir -p dev/data/agent && grep ':2222 ' dev/data/client/known_hosts > dev/data/agent/known_hosts
export PATH="$PWD/target/debug:$PATH" WRIT_HOME="$PWD/dev/data/agent" WRIT_URL=ssh://127.0.0.1:2222
cd ../writ-throwaway
writ init demo --agents opencode --agents-md   # or claude, agents, cursor: where your agent finds skills
writ policy                                    # what your agent will see: the committer name too
```

`writ init` says the committer email will be the lease's: don't pass `--email`. `--agents-md`
writes `AGENTS.md` with one line pointing at the skill; it stays untracked (the agent may
commit it: a warning in the report, nothing worse). Start the agent from this terminal, so it
inherits `PATH`, `WRIT_HOME` and `WRIT_URL`. Your own git in this clone doesn't change:
`git push` still goes to GitHub with your key. Only `writ git` goes through the daemon. The
agent still runs as your user and could read `dev/data/client`. Keeping it out of your files
is M7's work.

**6. Check 1: one Touch ID, then you're away.** Give the agent this task:

```text
Create a small TypeScript Express server in this repository. It has one endpoint, GET /health,
answering 200 with {"status": "ok"}, and a middleware that sets an X-Request-Id header on every
response: the request's own X-Request-Id when it sends one, a new random UUID otherwise.
Add tests with Jest and supertest for the endpoint and for both cases of the middleware, run
by `npm test`; a package.json with `build`, `start` and `test` scripts; a tsconfig.json; and a
.gitignore that keeps node_modules and the build output out. Run the tests before committing,
and push the work for review. Work alone: I'm away, and nobody will answer a question.
```

When the agent waits for its ticket, sign it in terminal 2. `writ sign` shows the ticket:
read it (the branch, the files, the estimate), answer `y` and confirm with Touch ID.

```sh
writ sign
```

Then leave the agent alone until it says it closed the lease. Then check:

- You confirmed Touch ID once in all.
- The agent asked before it worked: in the audit log, its `policy` and `dry_run` lines come
  before its `submit`, and the report's coding time is the real work (minutes, not the few
  seconds of a commit made after the fact, as in the first run).

  ```sh
  jq -c 'select(.event | IN("policy", "dry_run", "submit", "grant", "sign", "push", "close")) | [.time, .event, .result, .lease]' dev/data/audit.jsonl
  ```

- On GitHub, a branch of the agent's own (within `agent/*`, not `main`) has its commits, by
  `Writ agent 1` <`agent@writ.invalid`> as author and committer, each with a
  `Writ: <lease id>` trailer, though your git's `user.name` is yours. `main` hasn't moved. CI
  isn't set up: `npm test` passes in a fresh clone of the branch.

  ```sh
  git -C ../writ-throwaway log -3 --format='%an | %cn | %ae' origin/<the agent's branch>
  ```

- `writ ls --all` shows the lease as `closed`.
- The report the agent printed matches `writ report <lease id>` and the audit log: one
  `sign allowed` per commit, one `push allowed` per push, and the same denials:

  ```sh
  jq -c 'select(.lease == "<lease id>") | [.event, .result, .code]' dev/data/audit.jsonl
  ```

- In terminal 3, `writ check .opencode/skills/writ/timings.md` exits 0, and the file has the
  run under `demo`.

**7. The custom name, by hand** (one more Touch ID, not part of check 1). Another name
than the lease's is refused, and `writ git` sets the right one whatever your git says. In
terminal 3, in `../writ-throwaway`, take a short lease for `agent/manual-check`
(`dev/ticket.yaml`), sign it in terminal 2 (`writ sign`), then:

```sh
writ request ../writ/dev/ticket.yaml          # terminal 3; terminal 2: writ sign
export WRIT_SESSION=<lease id>                # as printed
git switch -q -c agent/manual-check
GIT_COMMITTER_NAME="Someone Else" writ git commit -q --allow-empty -m "Other name" --trailer "Writ: $WRIT_SESSION"
GIT_AUTHOR_NAME="Someone Else" writ git commit -q --allow-empty -m "Other name" --trailer "Writ: $WRIT_SESSION"
writ git -c user.name="Someone Else" commit -q --allow-empty -m "Own name" --trailer "Writ: $WRIT_SESSION"
```

- The first two are refused: `committer name "Someone Else" is not the lease's
  committer_name "Writ agent 1"`, then the same for the author, each with the hint to
  commit through `writ git`. The audit log has `sign denied` lines with the codes
  `committer_name` and `author_name`.
- The third is refused the same way: git's `-c` wins over the wiring's setting, so the
  commit asks to be signed under `Someone Else`, and the daemon says no. Then commit without
  any of them, and `git log` shows `Writ agent 1 | Writ agent 1`:

  ```sh
  writ git commit -q --allow-empty -m "Lease's name" --trailer "Writ: $WRIT_SESSION"
  git log -1 --format='%an | %cn'
  ```
- Optional, to see the name doesn't decide "Verified": with the template's
  `committer_emails` set to a verified address of your GitHub account (a `+agent` one) and
  the daemon's signing key added to your account as a signing key (`writd signing-keys
  dev/writd.yaml`), a pushed commit shows "Verified" while named `Writ agent 1`.

Then put the clone back and close the lease:

```sh
git switch -q main && git branch -D agent/manual-check
writ close --summary "Committer name check"
unset WRIT_SESSION
```

**8. Merge it.** On GitHub, merge the agent's branch into `main` (a pull request), so check 2
starts from the server. In terminal 3: `git checkout -q main && git pull -q`.

**9. Check 2: a refusal, an amendment and a renewal.** Give the agent this task, in a new
session:

```text
Two separate changes to this server, each on its own branch so they can be reviewed apart:
first, a GitHub Actions workflow that installs the dependencies, builds and runs the tests on
every push; second, a CONTRIBUTING.md that explains how to install, run the server and run the
tests. Push both. Then, as if review asked for a fix: add the Node.js version the project
needs to CONTRIBUTING.md and commit it; our CI is slow, so wait 20 minutes (sleep) before you
push that fix, then push it. Work alone: I'm away, and nobody will answer a question.
```

Then answer each ticket in terminal 2. Each answer is one Touch ID:

1. **The first ticket: refuse it.** The agent prints your feedback (exit 4) and should send
   the ticket again with `ticket.revises`.

   ```sh
   writ ls
   writ refuse <ticket id> -m "Refused on purpose: list the exact files in expected_paths, and ask for 30m at most."
   ```

2. **The revised ticket: sign it narrowed** to the workflow's branch only (one of the
   branches it asks for, as `writ sign` shows them) and to 20 minutes. Then note the lease's
   end in `writ ls`.

   ```sh
   writ sign --branch <the workflow's branch> --ttl 20m
   writ ls
   ```

3. **The amendment.** Pushing the CONTRIBUTING branch is refused (`branch`). The agent should
   ask for an amendment (`ticket.amends`), which `writ sign` shows. Sign it. Then `writ ls`
   still shows the lease's end from step 2.

   ```sh
   writ sign
   writ ls
   ```

4. **The renewal.** After its wait, the fix's push is refused: the lease expired. The agent
   should ask for a renewal (`ticket.renews`). `writ sign` shows the original ticket, the
   chain and what was used. Sign it.

   ```sh
   writ sign
   ```

   The agent should set `WRIT_SESSION` to the new lease and push. The commit signed under the
   first lease goes out under the renewal. Then it closes the renewal.

Then check:

- You confirmed Touch ID four times: the refusal, the revised ticket, the amendment and the
  renewal.
- The agent did each step from the skill: it never asked you, never pushed another way, and
  read `writ policy` and the timings file before writing its ticket. If its shell timed out
  while `writ request` waited, it carried on with `writ wait`.
- `writ ls --all` shows the first ticket `refused`, the amendment `applied`, the first lease
  `renewed` and the renewal `closed`.
- The audit log has a `push denied` line with the code `branch`. The fix's commit (on GitHub)
  is in a `sign allowed` line of the first lease, and its push in a `push allowed` line of the
  renewal:

  ```sh
  jq -c 'select(.event == "sign" or .event == "push") | [.event, .result, .code, .lease]' dev/data/audit.jsonl
  grep <commit id> dev/data/audit.jsonl
  ```

- `writ report <renewal id>` covers the whole chain, with both leases' commits and pushes.
- `timings.md` has a new run, with one renewal, and `writ check` still exits 0 on it.
- Every commit of check 2 is named `Writ agent 1` too, the renewal's included (the
  name is the template's, the same across the chain).

**10. Clean up.** In terminal 3 (still in `../writ-throwaway`), take the wiring, the skill and
the pointer back. `writ init --undo` keeps `timings.md`, so the second line deletes it.

```sh
writ init --undo
rm -r .opencode
```

Stop `make run`, then delete the branches and the deploy key on GitHub. At this repo's root:

```sh
git checkout dev/policy.yaml
rm -rf dev/data dev/approvers dev/readers
```

When both checks pass, note it under the first two acceptance items of
[M6's history page](../history/m6-agent-skill-amendments-renewals-and-close.md).
