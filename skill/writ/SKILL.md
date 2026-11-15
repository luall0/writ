---
name: writ
description: Use before running any git command, fetch and pull included, in a repository wired for Writ (it has a `writ` remote, or `writ git` works in it), and at the start of every task that will change files there, before editing anything, and again at each new request after an earlier one in this conversation had a lease (a small follow-up amends the running lease; a different task, or any request after a close, needs a new ticket). Writ gives you a signed, scoped, time-boxed lease to sign commits and push; this skill is how to see what the repository allows, ask for a lease, work under it, amend or renew it, and close it with a report.
---

<!-- Written by `writ init` and replaced by the next one: never edit this file. What you learn
goes in the timings file named below. -->

# Working under a Writ lease

Your commits are signed, and your pushes reach the remote, only through the Writ daemon,
under a **lease**: a ticket you write and a human signs. The daemon checks every commit and
push against it. You never hold a credential or a signing key, and you never need one.

The timings file for this repository: `{{TIMINGS}}`. Read it before writing a ticket.

## Rules

- **The ticket comes first.** Read the code as much as you need to scope the task, but edit
  no file before your lease is granted: the human approves the plan, not finished work, and
  the lease's time measures the work.
- **Each new request starts here**, even in a conversation where an earlier one already
  had a lease. While that lease still runs, a small follow-up to its work (a fix, a tweak,
  one more file the human asks for) stays under it: if it needs more than the lease allows,
  submit an amendment (section 5). A different task gets a ticket of its own: close the
  running lease first (step 6). A closed lease is over: the next request, however small, is
  a new ticket. When unsure which it is, ask the human.
- Run every git command through `writ git …` (`writ git commit`, `writ git push`,
  `writ git fetch`, `writ git rebase` …), **the fetch before any ticket too** (step 0).
  Plain `git` has no lease and goes around Writ. In a clone wired with `--whole-repo`, plain
  `git` is the same as `writ git`.
- A program that runs git itself (a script, a release tool) runs as
  `writ exec -- <program> <args>`.
- Work on a branch of your own, never on the default branch or a protected one.
- After a grant, set `WRIT_SESSION` to your lease for every command (`writ request` prints the
  line: `export WRIT_SESSION=wrt_…`). Another agent may share this host and its `current`
  lease; `WRIT_SESSION` keeps your work under your own lease.
- Never put a secret, a token or a key in a ticket, a commit message or a summary.
- Never try to reach the remote another way, or to work around a denial. A denial is the
  lease doing its job: amend, renew or ask the human.
- Never edit this file. Add notes to the timings file only (see below).

## 0. Fetch before you plan

To see whether upstream moved, or to start from a clean tree, fetch through Writ before you
read the code to plan, with no ticket:

```sh
writ git fetch origin
writ git pull --ff-only origin <default branch>
```

With no lease, `writ git fetch` and `writ git pull` ask for a fetch-only lease themselves
when the repository allows it (`writ policy` shows a template with `signature: none`),
and close it once git returns: nothing to sign, nothing to close, nothing to record. Use
`--ff-only`: a merge commit needs a signature, which only a lease gives. If the repository
doesn't allow it, the fetch is refused: plan from what you have, and fetch once your lease
is granted (step 4).

## 1. See what the repository allows

```sh
writ policy
```

It prints, from the daemon, what a ticket for this repository may ask: the templates, and
for each the operations, the branch patterns, the committer emails, the most time and
counts; the protected refs; whether each commit needs a `Writ: <lease>` trailer. A ticket
that asks for anything outside it is rejected. Read it before every ticket: it can change.

## 2. Think, estimate, then write the ticket

1. Read the timings file: how long work on this repository took, how many commits and
   pushes, how long CI rounds took, and how far estimates were from the real time.
2. Work out the scope before writing code:
   - **The branch:** a new one for this task, inside a pattern `writ policy` lists (for
     `agent/*`: `agent/<short-task-name>`). Never the default branch, never a protected ref.
   - **The operations:** `fetch`, `commit_sign` and `push`. The pushed branch is how the
     human sees your work: ask for `push` unless you were told not to push.
   - **The committer email:** one `writ policy` lists. Writ sets it for your commits from the
     lease, and the committer name too when the policy sets one: never set `user.name` or
     `user.email` yourself.
   - **The files** you expect to touch (`expected_paths`, in the repository's block).
3. Estimate each phase: `coding` (writing the change), `checks` (what you run before
   committing: tests, linters, a full CI locally), `ci` (waiting on the remote's CI after your
   pushes, with the fixes it brings). Then ask for a `ttl` that covers the estimate with a
   margin from the timings file, within the template's most, and counts (`max_signatures`,
   `max_pushes`) that cover the rounds you expect.

Write the ticket to a file (`ticket.yaml`), outside the repository or in a path git ignores:

```yaml
common:
  committer_emails: ["agent@example.org"]
repos:
  my-repo:                             # the repository's name, as `writ policy` shows it
    operations: [fetch, commit_sign, push]
    branches: ["agent/oauth-login"]
    expected_paths: ["src/auth/**", "tests/auth/**"]
    limits: { max_signatures: 10, max_pushes: 4 }
ticket:
  title: "Add OAuth login"             # one line
  task: "What you were asked to do, in a few lines"
  plan: ["Callback route", "Token storage", "Tests"]
  estimate: { coding: 40m, checks: 15m, ci: 30m }
limits:
  ttl: 2h
```

`common` and `limits` are the lease's; the repository's terms and counts go in its block
under `repos`. Every key is optional except `repos` (with the repository's `operations`),
`ticket.title` and `ticket.task`. When `writ policy` lists several templates your terms
could fit, name the one you mean in the repository's block (`template: <name>`). The human
reads every word: be precise and honest; ask for what the task needs, no more.

## 3. Check, submit and wait

Check the file on this host first, then have the daemon check it without submitting it:

```sh
writ check ticket.yaml
writ request --dry-run ticket.yaml
```

`writ check` checks the file's shape (keys, text bounds, durations, the estimate). The dry
run runs every check a submission gets (the templates, the limits, the lease it amends or
renews) and submits nothing. Each exits 3 with every problem: fix them, check again. Then
submit:

```sh
writ request ticket.yaml
```

It waits for the human's decision and exits with:

| Exit | Meaning | What to do |
|---|---|---|
| 0 | Granted | `export WRIT_SESSION=<lease>` as printed, then work |
| 3 | Rejected by policy (fits no template) | Fix the ticket from the reasons printed, submit again |
| 4 | Refused by the human, with feedback | Revise: the same file, changed as the feedback says, with `ticket.revises: <id>`; submit again |
| 5 | Expired before a decision, or withdrawn | Ask the human, or submit again |

If your shell can't wait that long, `writ request --no-wait ticket.yaml` returns once it is
submitted, and `writ wait <id>` waits for the decision (with the same exits): run it again
until it ends.

## 4. Work under the lease

- Create your branch first: `writ git fetch origin`, then
  `writ git switch -c <branch> origin/<default branch>`.
- Commit with `writ git commit`. When `writ policy` says commits need a trailer, add it to
  each: `writ git commit --trailer "Writ: <lease>"`.
- Push with `writ git push origin <branch>` (or the `writ` remote). If the remote moved,
  `writ git fetch`, rebase, and push again: rebased commits are signed again.
- When a phase ends without a commit or a push (your local checks finished, a CI round is
  over), mark it: `writ mark checks`, `writ mark ci`, `writ mark coding`. The report uses
  the marks.

## 5. When a denial or the clock stops you

- **Outside the ticket** (a branch, a repo, a file, an operation it doesn't allow): submit an
  **amendment**, the ticket with what you need and `ticket.amends: <lease>`, saying why in
  `task`. Your lease keeps running while the human decides; the denied operation isn't
  replayed: do it again once the amendment is signed. An amendment never adds time.
- **A committer or author email refused**: the repository's wiring uses another email than
  your lease allows. Commit with the lease's: `writ git -c user.email=<email> commit …`, and
  tell the human in your summary.
- **A committer or author name refused** (`committer_name`, `author_name`): something set
  another name than the lease's (`GIT_AUTHOR_NAME`, `GIT_COMMITTER_NAME`, a `-c user.name`).
  Commit through plain `writ git commit`, which sets the lease's.
- **Out of time or of counts** (`expired`, `exhausted`, a `limit` on a repository's
  signatures or pushes, or about to be): submit a
  **renewal**, the same scope (or narrower) with `ticket.renews: <lease>` and a new `ttl` and
  counts. It works up to `writ policy`'s "renew within" after the lease ended. Once signed it is a new
  lease: set `WRIT_SESSION` to its id. It can push the commits your earlier lease signed.
- **The session ended** (`writ git` refuses it: it ended, closed or renewed): if you closed
  it, you are working without a lease; stop editing and start at step 1 with a new ticket.
  If it was renewed, set `WRIT_SESSION` to the renewal's lease.
- **Anything else** (`not_active`, `config`, the daemon sealed): stop and tell the human.

## 6. Close, and learn

Close the lease after the **final push**, once the task is finished and nothing is left
to push: the remote's CI passed (or you were told not to wait for it) and no fix is pending.
A push in the middle of the task (a CI round, a fix after review) is not the end: keep the
lease, and a follow-up the human asks for before you close stays under it (amended if it
needs more). Close too if you stop for good, always with a short summary:

```sh
writ close --summary "What was done, what is left, anything the human should check"
```

`writ close` prints the activity report (commits, pushes, denials, time used against the
estimate, phase by phase) and records the run in the timings file. Close the last lease of a
renewed chain: the report covers the whole chain. Close a lease that expired too: the run
still counts.

Then, if something explains the figures (a CI that takes 25 minutes a round, a test suite
that needs a database, a reviewer who asks for small commits), add one line under the
repository's `notes:` in the timings file, starting with `- `. Keep notes short and factual;
`writ close` keeps only the latest few. Never edit the rest of the file. Then check it:

```sh
writ check {{TIMINGS}}
```

It names every line `writ close` would drop or rewrite (exit 3), so you can fix your note
before it is lost.

## 7. The next task

A closed lease is over: `unset WRIT_SESSION`, and never set it back. The next request,
whatever its size, starts again at step 1 with a new ticket, before any edit. (A follow-up
that comes before the close stays under the running lease, amended if it needs more.)
