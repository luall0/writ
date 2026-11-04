---
name: writ-workspace
description: Use at the start of any task that will change files in this folder's repositories (a Writ workspace: `writ git -C <repository>` works in each), before editing anything. Writ gives you one signed, scoped, time-boxed lease to sign commits and push in the repositories your task needs; this skill is how to see what each repository allows, ask for the lease, work under it, amend or renew it, and close it with a report.
---

<!-- Written by `writ init` and replaced by the next one: never edit this file. What you learn
goes in the timings file named below. -->

# Working under a Writ lease, across a workspace

This folder holds several git repositories, each wired for Writ. Your commits are signed,
and your pushes reach the remotes, only through the Writ daemon, under one **lease**: a
ticket you write and a human signs, naming every repository your task touches. The daemon
checks every commit and push against it. You never hold a credential or a signing key, and
you never need one.

The repositories here, each with its name in the daemon's registry (the name a ticket uses):

{{REPOS}}

The timings file for this workspace: `{{TIMINGS}}`. Read it before writing a ticket.

## Rules

- **The ticket comes first.** Read the code as much as you need to scope the task, but edit
  no file before your lease is granted: the human approves the plan, not finished work, and
  the lease's time measures the work.
- **One ticket for the task**, naming every repository it changes (`scope.repos`), and no
  repository it doesn't.
- Run every git command through `writ git -C <folder> …`, the folder being the repository's
  in the list above (`writ git -C api commit`, `writ git -C web push`…). Plain `git` has no
  lease. From inside a repository's folder, `writ git …` works too. At this folder itself,
  `writ git` lists the repositories (it is no repository of its own unless the list above
  has `.`).
- A program that runs git itself (a script, a release tool) runs in one repository at a time:
  `writ exec -C <folder> -- <program> <args>`. Never one program across several repositories
  at once.
- Work on a branch of your own in each repository, never on the default branch or a protected
  one.
- After a grant, set `WRIT_SESSION` to your lease for every command (`writ request` prints the
  line: `export WRIT_SESSION=wrt_…`). Another agent may share this host and its `current`
  lease; `WRIT_SESSION` keeps your work under your own lease.
- Never put a secret, a token or a key in a ticket, a commit message or a summary.
- Never try to reach a remote another way, or to work around a denial. A denial is the
  lease doing its job: amend, renew or ask the human.
- Never edit this file. Add notes to the timings file only (see below).

## 1. See what each repository allows

For each repository the task touches, by its registry name:

```sh
writ policy <repo>
```

It prints, from the daemon, what a ticket for that repository may ask: the templates, and
for each the operations, the branch patterns, the committer emails, the most time and
counts; the protected refs; whether each commit needs a `Writ: <lease>` trailer. Repositories
can differ: one may need the trailer and another not, and a ticket naming several
repositories must fit one template that allows them all. A ticket that asks for anything
outside it is rejected. Read it before every ticket: it can change.

## 2. Think, estimate, then write the ticket

1. Read the timings file: how long work in these repositories took (a section per
   repository, and one per set of repositories worked on together, such as `api + web`),
   how many commits and pushes, how long CI rounds took, and how far estimates were from the
   real time.
2. Work out the scope before writing code:
   - **The repositories:** every one the task changes, by registry name.
   - **The branch:** a new one for this task, inside a pattern `writ policy` lists (for
     `agent/*`: `agent/<short-task-name>`). The same branch name in each repository keeps
     the ticket short. Never a default branch, never a protected ref.
   - **The operations:** `fetch`, `commit_sign` and `push`. The pushed branches are how the
     human sees your work: ask for `push` unless you were told not to push.
   - **The committer email:** one `writ policy` lists for every repository named. Writ sets
     it for your commits from the lease, and the committer name too when the policy sets
     one: never set `user.name` or `user.email` yourself.
   - **The files** you expect to touch (`expected_paths`), in every repository.
3. Estimate each phase over all the repositories: `coding` (writing the change), `checks`
   (what you run before committing: tests, linters, a full CI locally), `ci` (waiting on the
   remotes' CI after your pushes, with the fixes it brings). Then ask for a `ttl` that covers
   the estimate with a margin from the timings file, within the template's most, and counts
   (`max_signatures`, `max_pushes`) that cover every repository's rounds together: they are
   the lease's, not each repository's.

Write the ticket to a file (`ticket.yaml`), outside every repository (this folder is fine
when the list above has no `.`), or in a path git ignores:

```yaml
scope:
  repos: [api, web]                    # every repository the task changes, as `writ policy` names them
  operations: [fetch, commit_sign, push]
  branches: ["agent/oauth-login"]
  committer_emails: ["agent@example.org"]
ticket:
  title: "Add OAuth login"             # one line
  task: "What you were asked to do, in a few lines"
  plan: ["api: callback route", "api: token storage", "web: login button", "Tests"]
  expected_paths: ["src/auth/**", "tests/auth/**", "app/login/**"]
  estimate: { coding: 1h, checks: 20m, ci: 30m }
limits:
  ttl: 3h
  max_signatures: 16
  max_pushes: 6
```

Every key is optional except `scope.repos`, `scope.operations`, `ticket.title` and
`ticket.task`. When `writ policy` lists several templates, name the one you mean with
`template: <name>` at the top. The human reads every word: be precise and honest; ask for
what the task needs, no more.

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

- In each repository, create your branch first: `writ git -C <folder> fetch origin`, then
  `writ git -C <folder> switch -c <branch> origin/<default branch>`.
- Commit with `writ git -C <folder> commit`. When `writ policy <repo>` says that
  repository's commits need a trailer, add it to each of its commits:
  `writ git -C <folder> commit --trailer "Writ: <lease>"`.
- Push with `writ git -C <folder> push origin <branch>` (or the `writ` remote). If a remote
  moved, fetch, rebase, and push again: rebased commits are signed again.
- When a phase ends without a commit or a push (your local checks finished, a CI round is
  over), mark it, from this folder: `writ mark checks`, `writ mark ci`, `writ mark coding`.
  The report uses the marks.

## 5. When a denial or the clock stops you

- **Outside the ticket** (a branch, a repository, a file, an operation it doesn't allow):
  submit an **amendment**, the ticket with what you need and `ticket.amends: <lease>`, saying
  why in `task`. A repository the task turns out to need is added this way. Your lease keeps
  running while the human decides; the denied operation isn't replayed: do it again once the
  amendment is signed. An amendment never adds time.
- **A committer or author email refused**: a repository's wiring uses another email than
  your lease allows. Commit with the lease's:
  `writ git -C <folder> -c user.email=<email> commit …`, and tell the human in your summary.
- **A committer or author name refused** (`committer_name`, `author_name`): something set
  another name than the lease's (`GIT_AUTHOR_NAME`, `GIT_COMMITTER_NAME`, a `-c user.name`).
  Commit through plain `writ git -C <folder> commit`, which sets the lease's.
- **Out of time or of counts** (`expired`, `exhausted`, or about to be): submit a **renewal**,
  the same scope (or narrower) with `ticket.renews: <lease>` and a new `ttl` and counts. It
  works up to `writ policy`'s "renew within" after the lease ended. Once signed it is a new
  lease: set `WRIT_SESSION` to its id. It can push the commits your earlier lease signed.
- **`writ git` refuses an option** before the command: git's own options go before the
  command (`-C`, `-c`, `--git-dir`…), the command's after it. Write it the way git takes it.
- **Anything else** (`not_active`, `config`, the daemon sealed): stop and tell the human.

## 6. Close, and learn

When the work is pushed (or you stop for good), close the lease with a short summary, from
this folder:

```sh
writ close --summary "What was done in each repository, what is left, anything the human should check"
```

`writ close` prints the activity report (commits and pushes in every repository, denials,
time used against the estimate, phase by phase) and records the run in the timings file,
under the repositories the lease named. Close the last lease of a renewed chain: the report
covers the whole chain. Close a lease that expired too: the run still counts.

Then, if something explains the figures (a CI that takes 25 minutes a round, a test suite
that needs a database, a reviewer who asks for small commits), add one line under that
section's `notes:` in the timings file, starting with `- `. Keep notes short and factual;
`writ close` keeps only the latest few. Never edit the rest of the file. Then check it:

```sh
writ check {{TIMINGS}}
```

It names every line `writ close` would drop or rewrite (exit 3), so you can fix your note
before it is lost.
