# The ticket file

What an agent writes to ask for a lease: `writ request <ticket.yaml>` (or `-` for stdin).
Start from the [template](templates/ticket.yaml).

A ticket gives **the lease's terms first, then each repository's**. Each term has one place,
and nothing overrides anything, so you read each term where it is:

- `common`, `limits`, `on_violation`, `caller`: for the whole lease (one committer identity,
  one end, one rate).
- `repos.<repo>`: one block per repository, checked against a template that allows that
  repository. Two repositories can fit two templates.

The agent writes it, so **nothing in it is trusted**. The daemon checks each repository's
block against a template and fills in the rest: id, time, session key, each repository's
template, the templates' committer emails and signing key, and every limit left out. Then
it shows you the ticket, and you sign it, narrow it or refuse it. The full signed ticket and
its lifecycle: [lease model](../lease-model.md#the-ticket-the-agent-writes).

- **One ticket, one signing key.** The templates of the repositories that sign must name the
  same signing key and the same `committer_name`. Otherwise the ticket is refused, and the
  agent asks one lease per repository.
- **The lease's limits are the strictest of its templates'.** Its TTL is within every
  template's `max_ttl`, and its rate within every `max_ops_per_minute`.
- **The layout before `writ-ticket/3` is refused** (`scope:`, `template:` at the top, the
  counts in `limits`, `ticket.expected_paths`), and the error names each key's new place.

- **Unknown keys are refused**, and every error names its key.
- **The text is shown to you as written** (with terminal control sequences neutralized by
  `writ sign`). The daemon never acts on it, except `expected_paths`.
- **The text is bounded**, so a ticket stays readable:

  | Field | Limit |
  |---|---|
  | Title | 200 characters, one line |
  | Task | 4,000 characters, 100 lines |
  | Plan | 50 steps, each one line of 500 characters |
  | Expected paths | 100 per repository, 16 KiB in all |
  | Repositories | 16 |

## Keys

| Key | Accepts | Default | What it does |
|---|---|---|---|
| `origin_hint` | Text | — | Where the agent runs (`macbook-user`). Shown to you, never checked |
| `common.committer_emails` | Emails | those every signing repository's template allows | The emails commits may carry as committer and as author, within each signing repository's template (with no repository signing, each one still an email one of the lease's templates allows) |
| `repos.<repo>.template` | Template name | the only one that allows the repo and fits | The template this repository's terms fit. Required when several do. A template that doesn't allow the repository is refused |
| `repos.<repo>.operations` | `fetch`, `commit_sign`, `push` | **required** | The operations in this repository, within its template's |
| `repos.<repo>.branches` | Branch patterns | `[]` | Each within one of the template's patterns, at most 50. Needed for `commit_sign` and `push` |
| `repos.<repo>.force_push` | Boolean | `false` | Force pushes and branch deletions, if the template allows them |
| `repos.<repo>.expected_paths` | Path globs | `[]` | The files the work should touch in this repository (`src/auth/**`): `*` and `?` within a directory, `**` across. At most 100 patterns per repository, 16 KiB for every repository together, each at most 1,024 bytes with 16 of `*`, `?`, `[`, `{`. Compared with each commit per the template's `paths_check`. Required if the template sets `require_expected_paths` |
| `repos.<repo>.limits.max_signatures` | Count | the template's | At most the template's |
| `repos.<repo>.limits.max_pushes` | Count | the template's | At most the template's |
| `repos.<repo>.limits.max_push_size` | Size | the template's | At most the template's, at least 1 byte with `push` |
| `ticket.title` | Text | **required** | One line. Shown first, to you and in notifications |
| `ticket.task` | Text | **required** | What the agent was asked to do |
| `ticket.plan` | List of steps | `[]` | The agent's steps, in order |
| `ticket.estimate` | `coding`, `checks`, `ci`: each a duration, all optional | — | How long the agent thinks the work takes: writing the change, the checks it runs before committing, waiting on remote CI after its pushes. Each at most `30d`. Shown to you beside the TTL asked, and in the activity report beside the real time. Never checked |
| `ticket.amends` | Lease id | — | Replaces the terms of an active lease of the same session, once signed. Changes the terms, not the time: it ends when its lease ends |
| `ticket.renews` | Lease id | — | More time for a lease of the same session. [Renewals](#renewals) |
| `ticket.revises` | Ticket id | — | A new version of a refused ticket of the same session. You see the earlier feedback beside it |
| `limits.ttl` | Duration | the smallest `max_ttl` of the templates | How long the lease lasts, counted from submission. At least the daemon's `min_ttl` (`5m` by default), at most every template's `max_ttl` |
| `limits.max_ops_per_minute` | Count | the smallest of the templates' | The lease's rate, every repository together. At most every template's |
| `on_violation` | `deny_and_notify` or `revoke_lease` | `deny_and_notify` | What happens when the agent tries something out of scope, in any repository, besides the denial. `revoke_lease`: the lease is revoked at the first violation. You may make it stricter when signing, never looser |
| `caller.descends_from.executable` | Absolute path | — | The process every caller of the lease must descend from. [Caller](#caller-local-mode) |
| `caller.descends_from.pid` | Number | — | That process's id |
| `caller.descends_from.generation` | Number | — | Its pid generation (`pidversion`), so a reused pid doesn't match |
| `caller.descends_from.code_identity.signing_id` | Text | — | Its code-signing identifier must match too |
| `caller.descends_from.code_identity.team_id` | Text | — | And its team id |

## Renewals

A renewal asks for more time for the same work. You sign it like any ticket.

- It names a lease of the same session that is active, or that expired or was used up less
  than the daemon's `renew_grace` ago (`24h` by default). A revoked, closed or already renewed
  lease can't be renewed.
- Each repository keeps its template in the lease. Its `ttl` and limits are new, within the
  templates.
- Its terms stay the same or narrower: repositories, and in each one operations, branches,
  expected paths and `force_push`; committer emails, `on_violation`. Committer emails and
  expected paths left out are the lease's.
- Once you sign it, it is a lease of its own, and the renewed lease ends at once
  (`renewed`). The new lease may push the commits the renewed one signed.
- Each template's `max_renewals` caps how many renewals one lease's chain may have: the
  strictest holds.
- `writ sign` shows you the original ticket, the renewals so far, the time used in all, and
  what changed.

## `caller` (local mode)

Set by a harness, not by hand: it binds the lease to the processes the harness started.

- Only local mode can check it ([M7](../roadmap.md#m7--local-mode-on-the-mac)). Under the
  `network` attestor there are no process facts, so a lease with a `caller` is denied
  everything (`caller`).
- `executable` is a normalized path of at most 1024 bytes, compared byte for byte.
