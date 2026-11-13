# `policy.yaml`

Six sections, and one setting:

- **`keys`**: every key the policy names, each declared with what it is for. Signing keys sign
  commits under a template; upstream credentials reach a repo's upstream.
- **`upstream_hosts`**: the host keys the daemon accepts from each `ssh://` upstream.
- **`proxies`**: the proxies a repo's upstream can be reached through, for remotes that only
  answer from some addresses, or only inside a network such as Tor.
- **`recipients`**: what the daemon's keystore is locked to besides its passphrase: a key in
  the Mac's Secure Enclave, and an offline recovery key.
- **`repos`**, the repo registry: each repo agents may use, its hard limits, and the
  templates its tickets may use.
- **`templates`**: the most a ticket may ask in a repo that names the template.
- **`unseal`**: whether the daemon waits for you after a start (the default), or opens itself
  ([starting without a human](sealing.md#starting-without-a-human-auto-unseal-m76)).

How they combine with tickets: [lease model](../lease-model.md). Start from the
[template](templates/policy.yaml). Examples: the [development policy](../../dev/policy.yaml)
(`make run`) and the [end-to-end one](../../e2e/config/policy.yaml).

- **Changing it:** after `writd init`, only by a signed change from your machine:
  [`writ admin repo|template|key|host|proxy|recipient`](sealing.md#changing-the-policy-the-approvers-or-the-readers)
  entry by entry (`add`, `edit`, `set <name> <field>=<value>`, `remove`), or `writ admin
  apply policy` for the whole file ([`writd recover`](recovery.md) on the host, as a last
  resort). Editing the file on the host does nothing.
- **Effect of a change:** immediate. A lease is used only while it still fits its templates:
  tighten a template, or take it off a repo, and its active leases are denied (`config`)
  until amended. A repo whose entry changes gets its mirror reopened. A key the change
  declares is made at once.
- **Unknown keys are refused**, and every error names its key:
  `templates.quick-fix.max_ttl: invalid duration "1 hour"`. The fields that moved in M6.2
  (`templates.<name>.repos`, a top-level `signing_keys`) are refused naming their new place.
- **Names** are the map keys (`keys.<id>`, `proxies.<name>`, `recipients.<name>`, `repos.<name>`,
  `templates.<name>`). Repo names must be unique ignoring case.
- **Patterns, durations, sizes:** [patterns and units](../lease-model.md#patterns-and-units).

## Keys: `keys.<id>`

Every key a template's `signing_key` or a repo's `upstream_credential` names is declared here.
Nothing about a key is guessed: a name that isn't declared, or is declared for another use,
refuses the policy. The change that declares a key makes it in the keystore (sealed like the
others) and its answer prints the public half; a token is never made, `writ admin token
<id>` adds it. What a key is (its use, kind, format, algorithm, backend) can't change: declare
a new key under another id.

| Key | Accepts | Default | What it does |
|---|---|---|---|
| `keys.<id>.use` | `signing` or `upstream` | **required** | What the key is for: signing commits under a template, or reaching a repo's upstream |
| `keys.<id>.kind` | `ssh` or `token` | **required** for `upstream`, refused for `signing` | An upstream credential's kind: an SSH key for `ssh://` upstreams, a token for `https://` ones |
| `keys.<id>.format` | `ssh` or `openpgp` | **required** for `signing`, refused otherwise | The format a signing key signs commits in (git's `gpg.format`) |
| `keys.<id>.algorithm` | `ed25519`, `p256`, `p384`, `rsa3072`, `rsa4096` | **required** for a signing key and an `ssh` credential, refused for a token | The key's algorithm. RSA keys are 3072 or 4096 bits (some remotes take only RSA upstream keys). Which combinations a backend signs: [hashes](#hashes) |
| `keys.<id>.hash` | `sha256`, `sha384`, `sha512` | the strongest allowed | A signing key's hash. A combination the format, algorithm and backend don't take is refused, never adjusted. Refused for an upstream credential |
| `keys.<id>.uids` | 1 to 16 user ids, `Name <local@domain>` or `<local@domain>`, printable ASCII | none | An OpenPGP signing key's identities: its certificate carries them. Each is unique. Every committer email a template signing with the key allows needs one, as `<committer_name> <email>` when the template sets a name. Refused for any other key |
| `keys.<id>.host` | A host name or address | **required** for a `token`, refused otherwise | The only host the token is sent to: a repo using it must have its `https://` upstream there, a proxy using it as its password must be there (compared ignoring case). One token is a repo's or a proxy's, never both |
| `keys.<id>.backend` | `software`, `se-cryptokit` | `software` | Where the key lives. `software`: the daemon's memory, from its sealed keystore. `se-cryptokit` (on a Mac, from M7.5): the Mac's Secure Enclave, which makes the key and never lets it out; `p256` keys only, signing (either format) or `ssh` upstream credentials; the keystore keeps the key's blob, usable only by this Mac's Secure Enclave. A backend this daemon doesn't have (`se-cryptokit` on Linux) refuses the policy. Moving a key to another backend makes a new key: `writ admin key rotate` |

The policy, or the start, is refused, naming the key and the reason, when the format,
algorithm, hash and backend don't go together, or when the keystore holds the key with
another algorithm or format.

### Hashes

- **`ssh`:** `sha256` or `sha512` for every algorithm (the SSHSIG's hash). An RSA key signs
  as `rsa-sha2-256` or `rsa-sha2-512` to match.
- **`openpgp`:** `sha256`, `sha384` or `sha512` for `ed25519` and RSA. `p256` signs with
  `sha256` only, `p384` with `sha384` only.

## Upstream host keys: `upstream_hosts.<host>`

The daemon's ssh accepts an `ssh://` upstream only with a key pinned here: nothing is learned
on first use. `writ admin host add` scans a host (with your signature) and shows its keys to
compare with the ones the remote publishes; pinning them is a second signed change.

| Key | Accepts | Default | What it does |
|---|---|---|---|
| `upstream_hosts.<host>` | 1 to 16 host keys, `<type> <base64>` as OpenSSH writes them (no comment) | — | The keys `<host>` may present. `<host>` is as ssh looks it up: `github.com`, or `"[forgejo.home]:2222"` off port 22. Plain names and addresses only: no wildcard, negation, hashed name or `@cert-authority`. Types: `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, `ssh-rsa`; never DSA. At most 256 hosts. Every `ssh://` repo's host must be here; a host no repo uses yet is fine |

## Proxies: `proxies.<name>`

A repo naming a proxy (`repos.<name>.proxy`) has everything the daemon sends its upstream go
through it: syncs, pushes, notes and the host key scan. The daemon only asks the proxy for a
tunnel to the repo's host and port, so TLS (`https://`) or SSH (`ssh://`, with the host key
pinned) stays end to end: the proxy sees encrypted bytes only. The proxy resolves the
upstream's name, never the daemon, so a name only the proxy's network knows works, and so does
a Tor onion service ([example](setup.md#a-remote-behind-a-proxy)).

| Key | Accepts | Default | What it does |
|---|---|---|---|
| `proxies.<name>.url` | `socks5://[user@]host:port` or `http://[user@]host:port` | **required** | The proxy: SOCKS5, or an HTTP proxy that takes `CONNECT`. The port is required. No password in the URL (it is the `credential`), no path. `socks5h://`, `https://` and SOCKS4 are refused. Tor: `socks5://127.0.0.1:9050` |
| `proxies.<name>.credential` | Key id | none | The password, with the URL's user: **required** when the URL names a user, refused otherwise. A key declared with `use: upstream`, `kind: token` and `host` the proxy's host, added with `writ admin token <id>`. Until it is added, the repos behind the proxy reach nothing. It goes to the proxy in clear (SOCKS5 and HTTP send it so): use one only on a network you trust |
| `proxies.<name>.connect_timeout` | Duration, 1s to 5m | `30s` | The longest reaching upstream through the proxy may take, its answer and the tunnel's opening. Raise it for Tor (`2m`) |

At most 64 proxies. A proxy a repo names can't be removed.

## Recipients: `recipients.<name>`

The keystore holds every secret the daemon has. Without recipients, the passphrase you type
at `writ unseal` opens it. Recipients add other ways in:

- **A hardware key** (`backend: se-cryptokit`): the daemon makes a key in the Mac's Secure
  Enclave when the change that declares it applies, and prints its `age1se1…` recipient. From
  then on the keystore opens with that key: `writ unseal` asks for no passphrase, only your
  signature. Tokens are unlocked by the device each time they are used, and never sit in the
  daemon's memory. The key can't be copied off the Mac.
- **The recovery key** (`recipient: age1…`): an age key you keep offline, on paper or a spare
  device. It opens everything if the Mac or its Secure Enclave is lost
  ([recovery](recovery.md)). Make one with `writ recovery new`, ideally on a machine that
  isn't online, or with `age-keygen`; check you can still open it with `writ recovery check`.

| Key | Accepts | Default | What it does |
|---|---|---|---|
| `recipients.<name>.backend` | `se-cryptokit` | one of `backend` or `recipient` **required** | A hardware key, made by the daemon in that device. Never changes: to replace one, add another and remove the old one |
| `recipients.<name>.recipient` | An age X25519 recipient, `age1…` | one of `backend` or `recipient` **required** | The recovery key's public half. Change it to replace the recovery key: everything is locked to the new one at once |

- At most 8 recipients, and at most one recovery key.
- A hardware key needs the recovery key beside it: one lost device must not lose everything.
- The last hardware key can't be removed: going back to a passphrase is [`writd recover`](recovery.md).
- Without a hardware key, the recovery key is optional: it lets you recover a keystore whose
  passphrase was lost.

## The repo registry: `repos.<name>`

| Key | Accepts | Default | What it does |
|---|---|---|---|
| `repos.<name>.upstream` | URL | **required** | Where the daemon fetches and pushes: `ssh://[user@]host[:port]/path` or `https://[user@]host[:port]/path`. Printable ASCII. Never `http://`, never a password in the URL, no user or host starting with `-` ([gateway](../architecture/gateway.md#upstream)) |
| `repos.<name>.upstream_credential` | Key id | **required** | The key the daemon reaches `upstream` with: declared in [`keys`](#keys-keysid) with `use: upstream`, `kind: ssh` for an `ssh://` upstream (`writd upstream-keys` prints its public half) or `kind: token` for an `https://` one, on the URL's host ([how](setup.md#https-upstreams-and-tokens)) |
| `repos.<name>.proxy` | Proxy name | none | The [proxy](#proxies-proxiesname) everything the daemon sends `upstream` goes through. Not set: the daemon connects to upstream itself |
| `repos.<name>.templates` | Template names | **required** | The templates whose tickets may reach the repo: each must exist. `[]` closes the repo (registered, with its mirror and credential, while every ticket for it is refused, and `writ policy` says so). A template no repo names is valid, unused |
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

Every limit is required, so a template never caps anything by accident. A template doesn't
list repos: each repo names the templates it allows (`repos.<name>.templates`). Each repo of a
ticket is checked against a template that repo allows: the ticket names it in that repo's
block, or the repo's terms fit exactly one. A repo that fits none rejects the ticket before
it reaches you, and the agent gets every reason.

One ticket may use several templates, one per repo. Then:

- **The lease's time and rate are the strictest.** Its TTL is within every template's
  `max_ttl`, its rate within every `max_ops_per_minute`, and its renewals within the smallest
  `max_renewals`.
- **The repos that sign share one key.** Their templates must name the same `signing_key`
  and the same `committer_name`. Otherwise the agent asks one lease per repo.
- **Counts stay per repo.** Each repo's signatures, pushes and push size are within its own
  template's. A lease over three repos may sign up to the sum of their counts: you see each
  one when you sign.

| Key | Accepts | Default | What it does |
|---|---|---|---|
| `templates.<name>.operations` | `fetch`, `commit_sign`, `push`, at least one | **required** | The operations a ticket may ask for in a repo |
| `templates.<name>.branches` | Branch patterns | `[]` | The branches a ticket may ask for: short names, at most one trailing `*` (`agent/*`, `agent/fix-*`). Required with `commit_sign` or `push` |
| `templates.<name>.push_modes` | `gateway`, `proxy`, `direct_ssh` | `[gateway]` | The [push modes](#push-modes) its leases may use, within each repo's |
| `templates.<name>.force_push` | Boolean | `false` | Whether a ticket may ask for force pushes and branch deletions |
| `templates.<name>.committer_emails` | Emails | `[]` | The emails a ticket may use as a commit's committer and author (printable ASCII). Required with `commit_sign` |
| `templates.<name>.committer_name` | A name, 1 to 100 characters | none | The name every commit signed under the template must carry, as author and committer, exactly. The agent's git is set to it from the lease (`writ git`, a whole-repo clone), and a commit with another name is refused (`committer_name`, `author_name`). No control, newline or invisible character, no `<` or `>`, and no space or `. , : ; " ' \` at either end (git strips them). Not set: the name isn't checked. A name doesn't decide whether a remote shows a commit as verified (the email and the key do); it keeps an agent from signing as someone else by name. With an OpenPGP key, each of its user ids for the template's emails must carry this name |
| `templates.<name>.signing_key` | Key id | — | The key that signs commits under this template: declared in [`keys`](#keys-keysid) with `use: signing` (`writd signing-keys` prints it). Required with `commit_sign` |
| `templates.<name>.max_ttl` | Duration, at least `writd.yaml`'s `min_ttl` | **required** | The longest lease, counted from submission: time waiting for you counts |
| `templates.<name>.max_signatures` | Count | **required** | The most commits one lease may sign in each repo under this template |
| `templates.<name>.max_pushes` | Count | **required** | The most pushes one lease may make in each repo under this template |
| `templates.<name>.max_ops_per_minute` | Count, at least 1 | **required** | The most signatures, pushes and fetches one lease may make per minute, all together and in every repo. A lease over several templates gets the smallest |
| `templates.<name>.max_push_size` | Size | **required** | The largest pack one push may send in a repo under this template: at least 1 byte when the template allows `push` (git would read 0 as no limit). Lowering it applies to the leases already granted too |
| `templates.<name>.paths_check` | `off`, `warn` or `deny` | `warn` | Compares the files each commit touches with the `expected_paths` of its repo in the ticket. [Paths check](#paths-check) |
| `templates.<name>.require_expected_paths` | Boolean | `false` | Whether a repo's block must list `expected_paths` to fit this template |
| `templates.<name>.require_session` | Boolean | `false` | Local mode: whether a ticket must be bound to an agent session (`caller`, written by `writ run`). Without one it is refused (`session`). The session is always one `writ run` started: a binding to any other process is refused too. Leave it off on a detached daemon: a bound lease is denied everything over TCP |
| `templates.<name>.max_renewals` | Count | no limit | How many [renewals](ticket.md#renewals) one lease's chain may have. A lease over several templates gets the smallest. Each renewal is signed anyway; this caps how long one task can run |

### Paths check

Only for the repos whose block in the ticket lists `expected_paths`; others are never
compared. Each repo's commits are compared with that repo's paths.

- **off**: no comparison.
- **warn** (default): the commit is signed, and the `sign` audit line records a warning.
- **deny**: the commit isn't signed (`paths`). Also when the touched paths can't be computed.

## Starting on its own: `unseal`

| Key | Accepts | Default | What it does |
|---|---|---|---|
| `unseal` | `approver` or `auto` | `approver` | `approver`: after every start the daemon waits for `writ unseal`. `auto`: it opens itself with no one, through the Mac's Secure Enclave. Only taken when every key and secret is in hardware: change it with `writ admin auto-unseal on`, which says what is missing first ([how](sealing.md#starting-without-a-human-auto-unseal-m76)) |
