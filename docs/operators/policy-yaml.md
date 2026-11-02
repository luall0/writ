# `policy.yaml`: the repo registry and the templates

Every key of the policy file `writd.yaml`'s `policy` names: the **repo registry** (`repos`,
hard per-repo limits no lease can exceed) and the **templates** (`templates`, the largest
ticket each accepts; every ticket must fit one). The [lease model](../lease-model.md) explains
how they combine with tickets; this page lists what can be written.

- Read at start; an authority file (0644 or stricter, owned by the daemon's user). Changing
  it will be an admin change with a signed approval ([M5](../roadmap.md#m5--sealed-start-and-signed-admin-changes));
  today, edit it and restart. A lease is used only while it still fits its template under the
  current file: tighten a template and its leases are denied (`config`) until amended.
- **Unknown keys are refused**; every error names its key
  (`templates.quick-fix.max_ttl: invalid duration "1 hour"`).
- Repo and template names: the map keys (`repos.<name>`, `templates.<name>`). Repo names are
  unique ignoring case (a repo's mirror is `<name>.git`, and APFS ignores case).
- Patterns, durations and sizes: [patterns and units](../lease-model.md#patterns-and-units).

A file to start from: the [template](templates/policy.yaml) (every key, optional ones
commented out at their default). Examples: the [development policy](../../dev/policy.yaml) (`make run`), and the
[end-to-end one](../../e2e/config/policy.yaml).

## The repo registry: `repos.<name>`

| Key | Value (default) | What it does |
|---|---|---|
| `repos.<name>.upstream` | URL, **required** | Where the daemon fetches and pushes: `ssh://[user@]host[:port]/path` with a key from its signer, or `https://[user@]host[:port]/path` with a token from its keystore. Printable ASCII; never `http://`, never a password in the URL, no user or host starting with `-` ([gateway](../architecture/gateway.md#upstream)) |
| `repos.<name>.upstream_credential` | Key id, **required** | The credential for `upstream`: an SSH key in the daemon's signer (`writd upstream-keys` prints it, to add on the remote, a deploy key at best), or for `https://` a token in `<keystore>/tokens/<id>` ([setup](setup.md#https-upstreams-and-tokens)). One id is a key or a token, never both. The daemon refuses to start without it |
| `repos.<name>.protected_refs` | List of ref patterns (`[]`) | Refs no lease may push, whatever its branches: full refs (`refs/heads/main`, `refs/tags/*`), matched ignoring case. With an account-wide upstream key, this registry is the only per-repo boundary |
| `repos.<name>.push_modes` | List of `gateway`, `proxy`, `direct_ssh` (`[gateway]`) | How pushes may reach upstream ([push modes](../architecture/gateway.md#push-modes-per-repo)); a lease uses only a mode both its repo and its template allow. `gateway`: through the daemon's mirror, every check in the quarantine. `proxy`: relayed with the same checks and no mirror, **not built yet** ([M9](../roadmap.md#m9--proxy-push-mode)). `direct_ssh`: the agent pushes itself with a lent deploy key, **not built yet** ([M10](../roadmap.md#m10--direct_ssh-push-mode)). Today a repo without `gateway` refuses every push (`push_mode`) |
| `repos.<name>.ticket_link` | `ledger_only`, `trailer` or `notes` (`ledger_only`) | How a commit names its lease on the remote ([Q25](../decisions.md)). `ledger_only`: nothing in the commit; the daemon's ledger links every commit it signs to its lease (the default: many projects' commit conventions don't allow an extra trailer). `trailer`: every commit carries exactly one `Writ: <lease id>` trailer, checked before signing (`ticket_link` denial otherwise); the daemon never adds it, that would change the commit. `notes`: a git note (`Writ: <lease id>`) under `notes_ref`, written by the daemon and pushed upstream after each push, the commit untouched ([notes](../architecture/gateway.md#notes)); the upstream credential must be allowed to push that ref ([setup](setup.md#notes-on-the-remote)) |
| `repos.<name>.notes_ref` | `commits` or `writ` (`commits`) | Only with `ticket_link: notes` (refused otherwise): the ref notes go under. `commits`: `refs/notes/commits`, git's own, which `git log` shows and the only one Forgejo and Gitea show on a commit's page (GitHub's web interface shows none); notes already there keep their lines. `writ`: `refs/notes/writ`, Writ's notes apart from anyone else's, read with `git log --notes=writ` |
| `repos.<name>.object_format` | `sha1` or `sha256` (`sha1`) | The repository's object format: commits are signed only in it, and a mirror whose upstream has the other one is refused. GitHub and most remotes have SHA-1 repositories only |
| `repos.<name>.direct_ssh.hosts` | List of host names | Required with the `direct_ssh` push mode, refused without it: the hosts the lent key may reach. **Not used yet** ([M10](../roadmap.md#m10--direct_ssh-push-mode)) |
| `repos.<name>.direct_ssh.allow_account_wide` | Boolean (`false`) | Whether `direct_ssh` may lend a key that isn't repo-scoped (shown as a warning to the approver). **Not used yet** ([M10](../roadmap.md#m10--direct_ssh-push-mode)) |

## Templates: `templates.<name>`

Every limit is required, so a template never caps by accident. A ticket names its template,
or fits exactly one; a ticket that fits none is rejected before it reaches the approver, with
every reason sent back to the agent.

| Key | Value (default) | What it does |
|---|---|---|
| `templates.<name>.repos` | List of repo names, **at least one** | The repos a ticket may ask for: each in the registry |
| `templates.<name>.operations` | List of `fetch`, `commit_sign`, `push`, **at least one** | The operations a ticket may ask for |
| `templates.<name>.branches` | List of branch patterns (`[]`) | The branches a ticket may ask for (`agent/*`, `agent/fix-*`, an exact name): short names, one trailing `*` at most. Required with `commit_sign` or `push` |
| `templates.<name>.push_modes` | List of `gateway`, `proxy`, `direct_ssh` (`[gateway]`) | The push modes a lease under it may use, within its repo's `push_modes` (`proxy` from M9, `direct_ssh` from M10) |
| `templates.<name>.force_push` | Boolean (`false`) | Whether a ticket may ask for force pushes (non-fast-forward updates and branch deletions) |
| `templates.<name>.committer_emails` | List of emails (`[]`) | The committer emails a ticket may use: printable ASCII. Required with `commit_sign` |
| `templates.<name>.signing_key` | Key id | The key in the daemon's signer that signs commits under this template (`writd signing-keys` prints it, to add on the account). Required with `commit_sign` |
| `templates.<name>.max_ttl` | Duration, at least `5m`, **required** | The longest lease, counted from submission (time waiting for the approver counts) |
| `templates.<name>.max_signatures` | Count, **required** | The most commits one lease may have signed |
| `templates.<name>.max_pushes` | Count, **required** | The most pushes one lease may make |
| `templates.<name>.max_ops_per_minute` | Count, at least 1, **required** | The rate of a lease's signatures, pushes and fetches together |
| `templates.<name>.max_push_size` | Size, **required** | The largest pack one push may send |
| `templates.<name>.paths_check` | `off`, `warn` or `deny` (`warn`) | Compares the files each commit touches with the ticket's `expected_paths`. `warn`: signs, and records a warning in the `sign` audit line. `deny`: refuses to sign (`paths`), also when the touched paths can't be computed. `off`: no comparison. A ticket without `expected_paths` is never compared |
| `templates.<name>.require_expected_paths` | Boolean (`false`) | Whether a ticket must list `expected_paths`: without them it fits no template with this set |
