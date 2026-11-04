# `policy.yaml`

Three sections:

- **`repos`**, the repo registry: each repo agents may use, and hard limits no lease can go
  past.
- **`templates`**: the largest ticket each one accepts. Every ticket must fit a template.
- **`signing_keys`**: the user ids of each OpenPGP signing key. Optional.

How they combine with tickets: [lease model](../lease-model.md). Start from the
[template](templates/policy.yaml). Examples: the [development policy](../../dev/policy.yaml)
(`make run`) and the [end-to-end one](../../e2e/config/policy.yaml).

- **Changing it:** after `writd init`, only through
  [`writ admin apply policy`](sealing.md#changing-the-policy-the-approvers-or-the-readers)
  (or [`writd recover`](recovery.md) on the host). Editing the file on the host does nothing.
- **Effect of a change:** immediate. A lease is used only while it still fits its template:
  tighten a template, and its active leases are denied (`config`) until amended. A repo whose
  entry changes gets its mirror reopened.
- **Unknown keys are refused**, and every error names its key:
  `templates.quick-fix.max_ttl: invalid duration "1 hour"`.
- **Names** are the map keys (`repos.<name>`, `templates.<name>`, `signing_keys.<id>`). Repo
  names must be unique ignoring case.
- **Patterns, durations, sizes:** [patterns and units](../lease-model.md#patterns-and-units).

## The repo registry: `repos.<name>`

| Key | Accepts | Default | What it does |
|---|---|---|---|
| `repos.<name>.upstream` | URL | **required** | Where the daemon fetches and pushes: `ssh://[user@]host[:port]/path` or `https://[user@]host[:port]/path`. Printable ASCII. Never `http://`, never a password in the URL, no user or host starting with `-` ([gateway](../architecture/gateway.md#upstream)) |
| `repos.<name>.upstream_credential` | Key id | **required** | The SSH key (`writd upstream-keys` prints it) or, for `https://`, the token ([how](setup.md#https-upstreams-and-tokens)) the daemon uses for `upstream`. An id is a key or a token, never both. Declared with its kind and algorithm in [M6.2](../roadmap.md#m62--managing-the-daemon-from-the-cli) |
| `repos.<name>.protected_refs` | Ref patterns | `[]` | Refs no lease may push, whatever its branches: full refs (`refs/heads/main`, `refs/tags/*`), ignoring case |
| `repos.<name>.push_modes` | `gateway`, `proxy`, `direct_ssh` | `[gateway]` | How pushes may reach upstream. [Push modes](#push-modes) |
| `repos.<name>.ticket_link` | `ledger_only`, `trailer` or `notes` | `ledger_only` | How a commit shows its lease on the remote. [Linking commits](#linking-commits-to-leases-ticket_link) |
| `repos.<name>.notes_ref` | `commits` or `writ` | `commits` | With `ticket_link: notes` only. `commits`: `refs/notes/commits`, git's own, shown by `git log`, Forgejo and Gitea. `writ`: `refs/notes/writ`, kept apart, read with `git log --notes=writ` |
| `repos.<name>.object_format` | `sha1` or `sha256` | `sha1` | The repository's object format. A mirror whose upstream uses the other one is refused. Most remotes, GitHub included, only have `sha1` |
| `repos.<name>.direct_ssh.hosts` | Host names | — | Required with the `direct_ssh` push mode, refused without it: the hosts the lent key may reach. **Not used yet** ([M10](../roadmap.md#m10--direct_ssh-push-mode)) |
| `repos.<name>.direct_ssh.allow_account_wide` | Boolean | `false` | Whether `direct_ssh` may lend a key that isn't limited to this repo (the approver sees a warning). **Not used yet** ([M10](../roadmap.md#m10--direct_ssh-push-mode)) |

### Push modes

A lease may only use a mode both its repo and its template allow
([details](../architecture/gateway.md#push-modes-per-repo)).

- **gateway**: through the daemon's mirror, with every check. The only one built today: a repo
  without it refuses every push (`push_mode`).
- **proxy**: relayed by the daemon with the same checks, no mirror. **Not built yet**
  ([M9](../roadmap.md#m9--proxy-push-mode)).
- **direct_ssh**: the agent pushes itself with a lent deploy key. **Not built yet**
  ([M10](../roadmap.md#m10--direct_ssh-push-mode)).

### Linking commits to leases (`ticket_link`)

The daemon's ledger always records which lease signed each commit. `ticket_link` adds a
visible link on the remote ([Q25](../decisions.md)):

- **ledger_only** (default): nothing in the commit. Many projects' commit conventions don't
  allow an extra trailer.
- **trailer**: every commit must carry exactly one `Writ: <lease id>` trailer, checked before
  signing (denied with `ticket_link` otherwise). The agent writes it; the daemon never adds it,
  because that would change the commit.
- **notes**: the daemon adds a git note `Writ: <lease id>` and pushes it after each push. The
  commit is untouched. The upstream credential must be allowed to push the notes ref
  ([setup](setup.md#notes-on-the-remote)).

## Templates: `templates.<name>`

Every limit is required, so a template never caps anything by accident. A ticket names its
template, or fits exactly one. A ticket that fits none is rejected before it reaches you, and
the agent gets every reason.

| Key | Accepts | Default | What it does |
|---|---|---|---|
| `templates.<name>.repos` | Repo names, at least one | **required** | The repos a ticket may ask for. Each must be in the registry. In [M6.2](../roadmap.md#m62--managing-the-daemon-from-the-cli) each repo names its templates instead |
| `templates.<name>.operations` | `fetch`, `commit_sign`, `push`, at least one | **required** | The operations a ticket may ask for |
| `templates.<name>.branches` | Branch patterns | `[]` | The branches a ticket may ask for: short names, at most one trailing `*` (`agent/*`, `agent/fix-*`). Required with `commit_sign` or `push` |
| `templates.<name>.push_modes` | `gateway`, `proxy`, `direct_ssh` | `[gateway]` | The [push modes](#push-modes) its leases may use, within each repo's |
| `templates.<name>.force_push` | Boolean | `false` | Whether a ticket may ask for force pushes and branch deletions |
| `templates.<name>.committer_emails` | Emails | `[]` | The emails a ticket may use as a commit's committer and author (printable ASCII). Required with `commit_sign` |
| `templates.<name>.committer_name` | A name, 1 to 100 characters | none | The name every commit signed under the template must carry, as author and committer, exactly. The agent's git is set to it from the lease (`writ git`, a whole-repo clone), and a commit with another name is refused (`committer_name`, `author_name`). No control, newline or invisible character, no `<` or `>`, and no space or `. , : ; " ' \` at either end (git strips them). Not set: the name isn't checked. A name doesn't decide whether a remote shows a commit as verified (the email and the key do); it keeps an agent from signing as someone else by name. With an OpenPGP key, each of its user ids for the template's emails must carry this name |
| `templates.<name>.signing_key` | Key id | — | The key that signs commits under this template (`writd signing-keys` prints it). Required with `commit_sign` |
| `templates.<name>.max_ttl` | Duration, at least `writd.yaml`'s `min_ttl` | **required** | The longest lease, counted from submission: time waiting for you counts |
| `templates.<name>.max_signatures` | Count | **required** | The most commits one lease may sign |
| `templates.<name>.max_pushes` | Count | **required** | The most pushes one lease may make |
| `templates.<name>.max_ops_per_minute` | Count, at least 1 | **required** | The most signatures, pushes and fetches one lease may make per minute, all together |
| `templates.<name>.max_push_size` | Size | **required** | The largest pack one push may send: at least 1 byte when the template allows `push` (git would read 0 as no limit). Lowering it applies to the leases already granted too |
| `templates.<name>.paths_check` | `off`, `warn` or `deny` | `warn` | Compares the files each commit touches with the ticket's `expected_paths`. [Paths check](#paths-check) |
| `templates.<name>.require_expected_paths` | Boolean | `false` | Whether a ticket must list `expected_paths` to fit this template |
| `templates.<name>.max_renewals` | Count | no limit | How many [renewals](ticket.md#renewals) one lease's chain may have. Each renewal is signed anyway; this caps how long one task can run |

### Paths check

Only for tickets that list `expected_paths`; others are never compared.

- **off**: no comparison.
- **warn** (default): the commit is signed, and the `sign` audit line records a warning.
- **deny**: the commit isn't signed (`paths`). Also when the touched paths can't be computed.

## OpenPGP user ids: `signing_keys.<id>`

A key's format, algorithm and backend are declared in
[`writd.yaml`'s `signing_keys`](writd-yaml.md#signing-keys-signing_keysid). The identities
an OpenPGP key carries are here, because binding an email to a key is an admin change.

| Key | Accepts | Default | What it does |
|---|---|---|---|
| `signing_keys.<id>.uids` | 1 to 16 user ids, `Name <local@domain>` or `<local@domain>`, printable ASCII | **required** | The user ids the key's certificate carries. Each must be unique |

The daemon refuses the policy, naming the field, when:

- a template's `signing_key` isn't declared in `writd.yaml`;
- a template allows a committer email that no user id of its OpenPGP key carries (remotes would
  show those commits as unverified);
- `<id>` isn't declared in `writd.yaml`, or is declared `format: ssh`.
