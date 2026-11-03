# The ticket file

What an agent writes to ask for a lease: `writ request <ticket.yaml>` (or `-` for stdin).
Start from the [template](templates/ticket.yaml).

The agent writes it, so **nothing in it is trusted**. The daemon checks the scope against a
template and fills in the rest: id, time, session key, the template's committer emails and
signing key, and every limit left out. Then it shows you the ticket, and you sign it, narrow
it or refuse it. The full signed ticket and its lifecycle:
[lease model](../lease-model.md#the-ticket-the-agent-writes).

- **Unknown keys are refused**, and every error names its key.
- **The text is shown to you as written** (with terminal control sequences neutralized by
  `writ sign`). The daemon never acts on it, except `expected_paths`.
- **The text is bounded**, so a ticket stays readable:

  | Field | Limit |
  |---|---|
  | Title | 200 characters, one line |
  | Task | 4,000 characters, 100 lines |
  | Plan | 50 steps, each one line of 500 characters |
  | Expected paths | 100 |

## Keys

| Key | Accepts | Default | What it does |
|---|---|---|---|
| `template` | Template name | the only one it fits | The template to fit. Required if the ticket fits several |
| `origin_hint` | Text | — | Where the agent runs (`macbook-user`). Shown to you, never checked |
| `scope.repos` | Repo names | **required** | The repos the lease may use, within the template's |
| `scope.operations` | `fetch`, `commit_sign`, `push` | **required** | The operations, within the template's |
| `scope.branches` | Branch patterns | `[]` | Each within one of the template's patterns. Needed for `commit_sign` and `push` |
| `scope.force_push` | Boolean | `false` | Force pushes and branch deletions, if the template allows them |
| `scope.committer_emails` | Emails | the template's | The emails commits may carry as committer and as author, within the template's |
| `ticket.title` | Text | **required** | One line. Shown first, to you and in notifications |
| `ticket.task` | Text | **required** | What the agent was asked to do |
| `ticket.plan` | List of steps | `[]` | The agent's steps, in order |
| `ticket.expected_paths` | Path globs | `[]` | The files the work should touch (`src/auth/**`): `*` and `?` within a directory, `**` across. Compared with each commit per the template's `paths_check`. Required if the template sets `require_expected_paths` |
| `ticket.amends` | Lease id | — | Replaces the terms of an active lease of the same session, once signed. Changes the scope, not the time |
| `ticket.revises` | Ticket id | — | A new version of a refused ticket of the same session. You see the earlier feedback beside it |
| `limits.ttl` | Duration | the template's `max_ttl` | How long the lease lasts, counted from submission. At least the daemon's `min_ttl` (`5m` by default), at most the template's `max_ttl` |
| `limits.max_signatures` | Count | the template's | At most the template's |
| `limits.max_pushes` | Count | the template's | At most the template's |
| `limits.max_ops_per_minute` | Count | the template's | At most the template's |
| `limits.max_push_size` | Size | the template's | At most the template's |
| `on_violation` | `deny_and_notify` or `revoke_lease` | `deny_and_notify` | What happens when the agent tries something out of scope, besides the denial. `revoke_lease`: the lease is revoked at the first violation. You may make it stricter when signing, never looser |
| `caller.descends_from.executable` | Absolute path | — | The process every caller of the lease must descend from. [Caller](#caller-local-mode) |
| `caller.descends_from.pid` | Number | — | That process's id |
| `caller.descends_from.generation` | Number | — | Its pid generation (`pidversion`), so a reused pid doesn't match |
| `caller.descends_from.code_identity.signing_id` | Text | — | Its code-signing identifier must match too |
| `caller.descends_from.code_identity.team_id` | Text | — | And its team id |

## `caller` (local mode)

Set by a harness, not by hand: it binds the lease to the processes the harness started.

- Only local mode can check it ([M7](../roadmap.md#m7--local-mode-on-the-mac)). Under the
  `network` attestor there are no process facts, so a lease with a `caller` is denied
  everything (`caller`).
- `executable` is a normalized path of at most 1024 bytes, compared byte for byte.
