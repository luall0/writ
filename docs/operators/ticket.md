# The ticket file

What an agent may write in the ticket it submits (`writ request <ticket.yaml>`, or `-` for
stdin). The agent writes it, so nothing here is trusted: the daemon checks the structured
scope against a template, completes the ticket (id, time, session key, the template's
committer emails and signing key, every omitted limit) and shows it to the approver, who
signs it, narrows it or refuses it. The complete ticket the approver signs, its canonical
encoding and its lifecycle: [lease model](../lease-model.md#the-ticket-the-agent-writes).

- A file to start from: the [template](templates/ticket.yaml) (every key, optional ones
  commented out at their default).
- **Unknown keys are refused**; every error names its key.
- Text is bounded so a ticket stays reviewable: title 200 characters on one line, task
  4,000 characters on at most 100 lines, plan 50 one-line steps of 500, 100 expected paths.
  It is shown as-is (control sequences neutralized by `writ sign`) and never read by the
  policy, except `expected_paths`.

| Key | Value (default) | What it does |
|---|---|---|
| `template` | Template name (the only one it fits) | The template to fit. Omitted, the daemon picks the single template the ticket fits; a ticket that fits several must name one |
| `origin_hint` | Text, optional | Where the agent runs (`macbook-user`): advisory, shown to the approver, never checked |
| `caller.descends_from.executable` | Absolute path | Local mode: the lease is usable only by processes descending from this one (a harness sets it). A normalized path, at most 1024 bytes, compared byte for byte. Under the `network` attestor no process facts exist, so a lease with a `caller` denies everything (`caller`): fail closed |
| `caller.descends_from.pid` | Number | The ancestor's process id |
| `caller.descends_from.generation` | Number | The ancestor's pid generation (`pidversion`): a reused pid doesn't match |
| `caller.descends_from.code_identity.signing_id` | Text | Optional: the ancestor's code-signing identifier must match too |
| `caller.descends_from.code_identity.team_id` | Text, optional | And its team id |
| `scope.repos` | List of repo names, **required** | The repos the lease may use: within the template's |
| `scope.operations` | List of `fetch`, `commit_sign`, `push`, **required** | Within the template's |
| `scope.branches` | List of branch patterns (`[]`) | Each within one of the template's patterns. Needed for `commit_sign` and `push` |
| `scope.force_push` | Boolean (`false`) | Non-fast-forward pushes and branch deletions; only if the template allows them |
| `scope.committer_emails` | List of emails (the template's) | The committer emails commits may carry: within the template's |
| `ticket.title` | Text, **required** | One line, shown first to the approver and in notifications |
| `ticket.task` | Text, **required** | What the agent is asked to do |
| `ticket.plan` | List of steps (`[]`) | The agent's steps, in order |
| `ticket.expected_paths` | List of path globs (`[]`) | The files the work should touch (`src/auth/**`): `*` and `?` within one directory, `**` across. Compared with each commit's touched paths per the template's `paths_check`; required if the template sets `require_expected_paths` |
| `ticket.amends` | Lease id, optional | An amendment: the active lease (of the same session) whose terms this ticket replaces once signed. It changes scope, not time |
| `ticket.revises` | Ticket id, optional | A revision of a refused ticket, from the same session: the approver sees the earlier feedback beside it |
| `limits.ttl` | Duration, at least `5m` (the template's `max_ttl`) | How long the lease lasts, counted from submission |
| `limits.max_signatures` | Count (the template's) | At most the template's |
| `limits.max_pushes` | Count (the template's) | At most the template's |
| `limits.max_ops_per_minute` | Count (the template's) | At most the template's |
| `limits.max_push_size` | Size (the template's) | At most the template's |
| `on_violation` | `deny_and_notify` or `revoke_lease` (`deny_and_notify`) | What an out-of-scope request does besides being denied: `revoke_lease` revokes the lease at the first violation. The approver may make it stricter when signing, never looser |
