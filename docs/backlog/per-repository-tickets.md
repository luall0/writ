# Per-repository tickets

**Status:** specified up to its open questions; picked as
[M6.1.5](../roadmap.md#m615--per-repository-tickets). **Area:** Lease model, Approvals,
Clients. **Kind:** feature. **Size:** L.

## Problem

A workspace task ([M6.1](../history/m6.1-multi-repo-workspaces.md)) touches several
repositories, and they rarely share one policy: the API's template allows `push` on
`agent/*`, the web app's only `review/*`, the docs repository `commit_sign` alone. Today a
ticket has one scope for all its repos and must fit one template that allows every one of
them. So a multi-repo ticket either asks for the union (rejected) or for the intersection (too
narrow for the task).

## Proposal

A ticket says what is common to the whole lease, then what each repository gets. Each part
fits a template that allows its repository, and it stays one ticket: one approval, one lease,
one session, one TTL. **No key is ever overridden**: the approver reads each term in one
place and never has to merge two in their head.

Already decided with the user (the decision log's M6.1.5 row):

- **Counts per repository only** (`max_signatures`, `max_pushes`, `max_push_size`), each
  within its repository's template; no lease-wide cap, the approver sees each and the sum.
- **Lease-wide terms, the strictest template wins**: the TTL at most the smallest `max_ttl`,
  `max_ops_per_minute` at most the smallest, `max_renewals` the smallest, the strictest
  `on_violation`.
- **One signing key per lease**: parts whose templates name different keys are rejected,
  each template and key named.
- **Otherwise, one lease per repository**, as the workspace skill says.
- **Both skills** (`writ` and `writ-workspace`) rewritten for the new layout, their examples
  checked by `writ check` in a test.

To decide: **the layout** (below), then the [open questions](#open-questions).

## The layout: four propositions

Every proposition is written for the same task, so they can be compared: an API (`api`,
template `backend`: push on `agent/*`) and a web app (`web`, template `frontend`: push on
`review/*` only), one committer email, three hours. A single-repository ticket follows each.

What stays as it is in all four: `ticket.title`, `task`, `plan`, `estimate`, `amends`,
`renews`, `revises`; `origin_hint`; `caller`; `limits.ttl` and `limits.max_ops_per_minute`
(the lease's). What moves: `template`, `ticket.expected_paths` and the counts go per
repository (each repository has its own template and its own files); `on_violation` stays
lease-wide (it revokes the whole lease).

### A. Fixed places: the lease's terms, then each repository's

Each key has one place, always the same: what is about the lease (the agent's identity, time,
rate, what happens on a violation) at the top, what is about a repository (its template,
operations, branches, files, counts) in its block. Nothing is shared between blocks.

```yaml
scope:                                   # the lease's, for every repository
  committer_emails: ["agent@example.org"]
repos:                                   # each repository's own terms
  api:
    template: backend
    operations: [fetch, commit_sign, push]
    branches: ["agent/login"]
    expected_paths: ["src/auth/**"]
    limits: { max_signatures: 10, max_pushes: 4 }
  web:
    template: frontend
    operations: [fetch, commit_sign, push]
    branches: ["review/login"]
    expected_paths: ["app/login/**"]
    limits: { max_signatures: 6, max_pushes: 2 }
ticket:
  title: "Login across the API and the web app"
  task: "…"
  estimate: { coding: 1h, checks: 20m, ci: 30m }
limits: { ttl: 3h }                      # the lease's: time and rate
```

One repository:

```yaml
scope:
  committer_emails: ["agent@example.org"]
repos:
  my-repo:
    operations: [fetch, commit_sign, push]
    branches: ["agent/oauth-login"]
    expected_paths: ["src/auth/**"]
    limits: { max_signatures: 10, max_pushes: 4 }
ticket: { title: "Add OAuth login", task: "…" }
limits: { ttl: 2h }
```

`writ sign` shows the lease's terms once, then one block per repository, in the same order as
the file.

- **For:** one rule to learn ("about the lease, or about a repository"); the screen and the
  file have the same shape; a key in the wrong place is refused, naming where it goes; one
  repository is just one block.
- **Against:** terms the repositories share (`operations`, often) are written in each block.

### B. A common scope added to by each repository

`scope` holds what every repository gets; each repository's block may only **add** to the
lists (operations, branches, files, emails), never remove or replace. Scalars (template,
counts, `force_push`) are per repository only.

```yaml
scope:                                   # every repository gets these
  operations: [fetch, commit_sign]
  committer_emails: ["agent@example.org"]
repos:
  api:                                   # … plus these
    template: backend
    operations: [push]
    branches: ["agent/login"]
    expected_paths: ["src/auth/**"]
    limits: { max_signatures: 10, max_pushes: 4 }
  web:
    template: frontend
    operations: [push]
    branches: ["review/login"]
    expected_paths: ["app/login/**"]
    limits: { max_signatures: 6, max_pushes: 2 }
limits: { ttl: 3h }
```

`writ sign` shows the common terms, then each repository's additions, then (to remove any
doubt) each repository's whole scope.

- **For:** short when the repositories share a lot; never a conflict (a union can't contradict).
- **Against:** a repository's operations are in two places, so the reviewer adds them up;
  the full scope on screen makes it readable, but the file isn't.

### C. Each key either common or per repository, chosen by the ticket

A key may be written in `scope` (it then holds for every repository) or in repositories'
blocks, never both: a key in `scope` and in a block is refused. The counts and the template
are always per repository.

```yaml
scope:
  operations: [fetch, commit_sign, push] # common: no block may say operations
  committer_emails: ["agent@example.org"]
repos:
  api:
    template: backend
    branches: ["agent/login"]            # per repository: not in scope
    expected_paths: ["src/auth/**"]
    limits: { max_signatures: 10, max_pushes: 4 }
  web:
    template: frontend
    branches: ["review/login"]
    expected_paths: ["app/login/**"]
    limits: { max_signatures: 6, max_pushes: 2 }
limits: { ttl: 3h }
```

`writ sign` shows the common terms, then each repository's.

- **For:** the shortest; nothing is merged, each key has one value.
- **Against:** the place of a key changes from one ticket to the next, so the reviewer looks
  in both every time; more ways to write the same ticket (harder for the skills to teach and
  for `writ check` to explain).

### D. Repositories only, nothing common

No `scope` at all: every term is in a repository's block, the email too; only `ticket` and
`limits` (time, rate) are the lease's.

```yaml
repos:
  api:
    template: backend
    operations: [fetch, commit_sign, push]
    branches: ["agent/login"]
    committer_emails: ["agent@example.org"]
    expected_paths: ["src/auth/**"]
    limits: { max_signatures: 10, max_pushes: 4 }
  web:
    template: frontend
    operations: [fetch, commit_sign, push]
    branches: ["review/login"]
    committer_emails: ["agent@example.org"]
    expected_paths: ["app/login/**"]
    limits: { max_signatures: 6, max_pushes: 2 }
limits: { ttl: 3h }
```

- **For:** the simplest model; each block reads alone; different emails per repository
  possible.
- **Against:** the most repetition; the agent's identity (one key per lease, so one signer)
  is repeated and could differ between blocks for no reason.

### Recommendation: A

Each term has one fixed place, so the reviewer always knows where to look, the screen
mirrors the file, and a misplaced key gets a precise refusal. The repetition it costs is in
`operations` only, which is short, and seeing each repository's operations whole is what the
review needs. The email stays common because the lease signs with one key: one identity.

## Open questions

1. **The layout:** A, B, C or D (recommended: A).
2. **The committer email:** common to the lease (A, B, C) or per repository (D, or added to
   A's blocks)? Recommended: common, since there is one signing key per lease; a repository
   that needs another email gets its own lease.
3. **Today's layout** (`scope.repos` a list, the other keys in `scope`, `limits` holding the
   counts, `ticket.expected_paths`):
   - (a) still read, converted to the new one (every repository given the same terms), and
     shown converted; refused when mixed with the new keys. Recommended: tickets written
     before, and agents still on the old skill, keep working.
   - (b) refused in new tickets, with a message naming the new place of each key; leases
     already granted still read.
4. **`template` at the top for one repository:** keep `template:` at the top as a shortcut
   when the ticket names one repository, or only in the block? Recommended: only in the
   block (one place, A's rule), the top-level key refused in the new layout.
5. **Narrowing flags:** `--branch api:agent/x`, `--drop-op web:push`, `--max-pushes api:2`,
   a flag without a repository applying to every repository (recommended), or one flag per
   repository required when the ticket has several?

## Design

- `writ-core`: the ticket's scope as lease terms plus one part per repository
  (`writ-ticket/3`); the fit per part against its template (the template named, or the only
  one allowing the repository and fitting), plus the lease-wide terms against every part's
  template and the one signing key; narrowing, renewals and amendments per part; every sign
  and push request checked against its repository's part, counts kept per repository.
- `writ-store`: counts per lease and repository; the old kind read for leases granted before.
- `writ-cli`: `writ sign`'s display (the lease's terms, then each repository, within 78
  columns), narrowing per repository, `writ policy` for several repositories (each template's
  signing key and lease-wide terms, whether one ticket can cover them), `writ check` naming
  each problem's repository and place, both skills.
- Docs: [the ticket file](../operators/ticket.md) and its template, the configuration
  registry (rule 19), the security inventory's ticket row (repositories per ticket, bytes),
  [lease model](../lease-model.md), [approvals](../architecture/approvals.md).

## Threat model impact

No new actor or asset. A ticket naming more repositories is reviewed in one approval: the
display must keep each repository's terms as visible as a one-repository ticket's (the
78-column, escaped, bounded display; a bound on repositories per ticket). The strictest
template wins for the lease's terms, so pairing a strict template with a lax one never
loosens the strict one.

## Acceptance

In the [roadmap](../roadmap.md#m615--per-repository-tickets).
