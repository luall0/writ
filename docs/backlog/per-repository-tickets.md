# Per-repository tickets

**Status:** specified up to one open question; picked as
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

A ticket gives what is common to the whole lease, then what each repository gets. Each
repository's terms fit a template that allows that repository, and it stays one ticket: one
approval, one lease, one session, one TTL. **No key is ever overridden**: each term has one
fixed place, so the approver reads it there and never merges two in their head.

Decided with the user (the decision log's M6.1.5 rows):

- **The layout: fixed places** (proposition A of four; the others below). `common:` holds
  the lease's terms (it replaces `scope:`), `repos:` one block per repository.
- **The committer email is common** (`common.committer_emails`): the lease signs with one
  key, so it has one identity. It moves to each repository's block with
  [a signing key per repository in one lease](README.md#a-signing-key-per-repository-in-one-lease).
- **A new ticket version, the old layout refused.** `writ-ticket/3`; a ticket in today's
  layout (`scope`, `limits.max_signatures`, `ticket.expected_paths`…) is refused, naming the
  new place of each key. Writ isn't deployed anywhere yet: no conversion, and the state's
  version moves too (a daemon finding an older state refuses to start, as since M6).
- **Counts per repository only** (`max_signatures`, `max_pushes`, `max_push_size`), each
  within its repository's template; no lease-wide cap, the approver sees each and the sum.
- **Lease-wide terms, the strictest template wins**: the TTL at most the smallest `max_ttl`,
  `max_ops_per_minute` at most the smallest, `max_renewals` the smallest, the strictest
  `on_violation`.
- **One signing key per lease**: repositories whose templates name different keys are
  rejected, each template and key named.
- **Otherwise, one lease per repository**, as the workspace skill says.
- **Narrowing per repository**: `--branch api:agent/x`, `--drop-op web:push`,
  `--max-pushes api:2`…; a flag without a repository applies to every repository.
- **Both skills** (`writ` and `writ-workspace`) rewritten for the new layout, their examples
  checked by `writ check` in a test.

To decide: [`template` in the ticket](#open-questions).

## The layout

```yaml
common:                                  # the lease's, for every repository
  committer_emails: ["agent@example.org"]
repos:                                   # each repository's own terms
  api:
    template: backend                    # see the open question
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

One repository is one block:

```yaml
common:
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

Where each key lives:

| Place | Keys |
|---|---|
| Top level (the lease's) | `common.committer_emails`; `ticket.title`, `task`, `plan`, `estimate`, `amends`, `renews`, `revises`; `limits.ttl`, `limits.max_ops_per_minute`; `on_violation`; `origin_hint`; `caller.*` |
| `repos.<name>` (one block per repository, at least one) | `template`, `operations`, `branches`, `force_push`, `expected_paths`, `limits.max_signatures`, `limits.max_pushes`, `limits.max_push_size` |
| Gone | `template` at the top, `scope.*` (now `common` and the blocks), `ticket.expected_paths` and the counts in the top `limits` (now in the blocks): each refused, naming its new place |

`writ sign` shows the lease's terms once, then one block per repository, in the file's order,
within 78 columns.

### The propositions not chosen

Kept for the record; each was written for the same task.

- **B. A common scope added to by each repository**: `scope` holds what every repository
  gets, each block may only add to the lists. Short, but a repository's operations are in two
  places, so the reviewer adds them up.
- **C. Each key either common or per repository, chosen by the ticket, never both.** The
  shortest, but a key's place changes from one ticket to the next, so the reviewer looks in
  both every time, and there are more ways to write one ticket.
- **D. Repositories only, nothing common.** The simplest model, the most repetition; the
  agent's one identity repeated in every block, free to differ for no reason.

## Open questions

1. **`template` in the ticket.** Templates are the daemon's configuration: the operator writes
   them, the agent never changes one. The ticket's `template` only picks among the templates
   the operator allows for a repository, and today it is optional: when exactly one template
   allows the repository and fits, the daemon picks it and the agent writes nothing. It is
   needed only when several fit, for example a `quick-fix` template (30 minutes,
   `commit_sign`) and a `feature` template (4 hours, `push`) both on the repository: the
   daemon then refuses to guess (fail closed: a silent pick would choose a signing key and
   limits nobody asked for) and the ticket must name one.
   - (a) Keep `template` optional in each repository's block, needed only when several
     templates fit that repository. Recommended: the operator keeps several templates per
     repository (quick fixes beside features), and the approver sees which one applies.
   - (b) Drop it from the ticket: a repository may be allowed by one template only (the
     policy refused otherwise; with M6.2, `repos.<name>.templates` holding at most one).
     Simpler tickets, but one kind of work per repository.

## Design

- `writ-core`: the ticket as the lease's terms (`common`, `ticket`, `limits`) plus one part
  per repository (`writ-ticket/3`, the only kind read: no conversion of the old one); the fit per part against its template (the template named, or the only
  one allowing the repository and fitting), plus the lease-wide terms against every part's
  template and the one signing key; narrowing, renewals and amendments per part; every sign
  and push request checked against its repository's part, counts kept per repository.
- `writ-store`: counts per lease and repository; a new state version (an older state
  refused at start, as since M6).
- `writ-cli`: `writ check` and the dry run refusing the old layout, naming each key's new
  place; `writ sign`'s display (the lease's terms, then each repository, within 78
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
