# Managing the daemon from the CLI

**Status:** done in [M6.2](../history/m6.2-managing-the-daemon-from-the-cli.md).
**Area:** Administration, Signers, Upstream, Clients. **Kind:** improvement. **Size:** L.

## Problem

Setting the daemon up and changing it later is spread across host files, host commands and
signed changes, and the keys aren't described the same way:

- **Signing keys are declared, upstream credentials are guessed.** A signing key is declared
  in `writd.yaml` (format, algorithm, hash, backend), with its OpenPGP user ids in
  `policy.yaml`: one key, two files. An upstream credential is declared nowhere: the policy's
  `upstream_credential: <id>` alone decides it. An SSH key or a token is guessed from the
  URL's scheme, the SSH key is always Ed25519 and made without being asked for, and a missing
  token shows up at the first sync. There is no way to choose the algorithm (some remotes take
  only RSA keys), no place to say an upstream key lives in hardware (M7.5, M7.6, a YubiKey
  later), and a typo in a signed policy change makes a new key instead of being refused.
- **What lives in a host file needs host access and a restart.** `writd.yaml` is read at
  start, and the upstream host keys (`mirrors.known_hosts`) are a host file too. Adding a key
  or a repo on a new host means editing a file on the daemon host (`sudo -u _writd` in local
  mode, `docker exec` or a volume in detached mode), restarting, and unsealing again.
- **The public keys come only from the host.** `writd signing-keys` and `writd upstream-keys`
  run on the daemon host, as its user, with the path of its `writd.yaml`. In local mode on
  the Mac that is `sudo -u _writd /usr/local/bin/writd upstream-keys /var/db/writ/writd.yaml`
  just to copy a public key into a remote's settings.
- **Templates point at repos**, the wrong way round: everything about a repo isn't in its
  entry, removing a repo means editing every template that lists it (and a template left with
  none is invalid), and the diff the approver signs for "this repo may now take quick fixes"
  is an edit inside a template's list.
- **Every change is a whole file.** `writ admin show` and `writ admin apply` take the full
  policy text: fine for a large edit, heavy for one field, and every required template limit
  has to be written by hand, its bounds looked up in the reference.

## Proposal

What the operator sees, once M6.2 is built:

```sh
writ admin repo add omega-code          # step by step: URL, credential, host key, templates…
writ admin key show forgejo-home        # the public half, to paste into the remote
writ admin template add quick-fix --from feature-branch
writ admin template set quick-fix max_ttl=2h branches+=agent/hotfix-*
writ admin repo set omega-code templates=          # pause the repo
writ admin host add forgejo.home:2222              # pin an upstream host key
```

- **Every key declared in the signed policy**, signing keys and upstream credentials alike,
  in one `keys:` section. `writd.yaml` keeps only what belongs to the host.
- **Upstream host keys pinned through signed changes**: the daemon fetches the key, the
  operator compares its fingerprint with the one the remote publishes, and signs.
- **Repos name their templates** (`repos.<name>.templates`); templates become profiles that
  don't list repos. An empty list pauses a repo.
- **`writ admin <noun> <verb>`** for repos, templates, keys and upstream hosts: read with the
  reader key, change with one signature, step by step or one field at a time.
- Everything works the same from the approver's machine in local and detached mode, with no
  host access, no restart and no unseal.

## Scope and non-goals

- In: the policy's new shape (keys, upstream hosts, repos naming templates), replacing the old
  one; the daemon's new reads and checks on the approval API; the `writ admin`
  nouns and verbs; the guided flows; the docs and the end-to-end scenarios.
- Not a repo tightening a template for itself (`feature-branch`, but only `agent/omega-*` on
  this repo): a template used by one repo only does that already.
- Not renaming a repo or a template: remove it and add it again (a repo's name is its mirror's
  directory and is in its leases).
- Not editing `approvers` and `readers` field by field: they stay whole files through
  `writ admin show` and `apply`, which also stay for large policy edits.
- Not the boot tier (the SSH host key, the TLS key) or the CA key: they are the daemon's own,
  not the policy's.
- Policy still lives only in the daemon (hard rule 1): `writ` builds a policy text and shows
  the diff; the daemon parses and checks it exactly as it checks `writ admin apply`.

## Design

### The policy's new shape

```yaml
keys:
  agent-ed25519-01: { use: signing, format: ssh, algorithm: ed25519 }
  agent-pgp-01:
    use: signing
    format: openpgp
    algorithm: rsa4096
    hash: sha512                       # optional: the strongest allowed
    uids: ["Writ agent <user+agent@example.org>"]
  forgejo-home:     { use: upstream, kind: ssh, algorithm: ed25519 }
  azure-repo:       { use: upstream, kind: ssh, algorithm: rsa4096 }
  github-token:     { use: upstream, kind: token, host: github.com }

upstream_hosts:
  "[forgejo.home]:2222": ["ssh-ed25519 AAAA…"]
  github.com: ["ssh-ed25519 AAAA…"]

repos:
  omega-code:
    upstream: ssh://git@forgejo.home:2222/user/omega-code.git
    upstream_credential: forgejo-home
    protected_refs: ["refs/heads/main"]
    templates: [feature-branch, quick-fix]

templates:
  feature-branch:                      # no `repos:` any more
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    signing_key: agent-ed25519-01
    ...
```

- **`keys.<id>`**: `use` (`signing` or `upstream`) and `backend` (`software` by default) for
  every key. A signing key: `format`, `algorithm`, `hash` and, for OpenPGP, `uids`, as
  `writd.yaml` and `policy.yaml` hold them today. An upstream credential: `kind` (`ssh` or
  `token`); an `ssh` one its `algorithm` (Ed25519, P-256, P-384, RSA 3072 or 4096); a `token`
  one the `host` it may be sent to.
- **Checked when a change is applied and at every start, refused with the field named,
  never adjusted:** a template's `signing_key` that isn't a declared `signing` key; a repo's
  `upstream_credential` that isn't a declared `upstream` one, or whose kind doesn't match its
  URL (`ssh://` needs `kind: ssh`, `https://` a `token`); a token whose `host` isn't the
  repo's; a repo on a host with no `upstream_hosts` pin (an `ssh://` one); a backend this
  daemon doesn't have; a combination the backend can't sign (M5.5's check, unchanged).
- **The change that declares a key makes it**, sealed to the keystore's recipient as today's
  live creation does, and its answer carries the public half. `writd init` makes the keys
  its first policy declares. A token is never made: `writ admin token <id>` adds it to a
  declared `token` key. Every declared key then exists, so `writd keys create` goes.
- **`upstream_hosts`**: the pins `mirrors.known_hosts` holds today, in the same form and with
  the same refusals (no wildcards, hashed names or `@cert-authority`). In the policy rather
  than an admin target of its own, so adding a repo on a new host is one signed change.
- **`repos.<name>.templates`**: the templates whose tickets may reach the repo. A ticket fits
  a template when every repo it names lists that template (M6.1's multi-repo tickets
  included). `[]` keeps the repo registered, with its mirror and its credential, while no
  ticket fits it; `writ policy <repo>` says it is closed. A template no repo names is valid
  (a profile not used yet).
- **`writd.yaml` keeps the host's settings**: paths, listeners, limits, mirrors (without
  `known_hosts`), notifiers, and later the hardware backends this host has and how to reach
  them.

### No move from the old shape

Writ isn't deployed anywhere yet, so the new shape replaces the old one outright, as
M6.1.5's tickets did: no conversion, no old field read. `templates.<name>.repos`, the
policy's `signing_keys`, `writd.yaml`'s `signing_keys` and `mirrors.known_hosts` are refused
wherever they appear (the policy files `writd init` and `writd recover` read, every admin
change, `writd.yaml` at start), each naming its new place. The state version moves to 10: a
state directory written before M6.2 is refused and started again.

### The daemon's new operations

On the approval API, counted against the approval API's rates and each logged (hard rule 9):

- **Reads**, with a reader key: each noun's entries from the policy in force, and for each key its public half,
  fingerprint and OpenPGP certificate, what uses it, and for a token only whether it is
  there. Only while unsealed: the sealed daemon answers what it answers today; `writd
  signing-keys` and `writd upstream-keys` stay the host's way to read the public halves with
  no unseal, from the policy in force.
- **A host key scan** (`writ admin host add`), **signed by an approver**: the request is a
  `writ-scan/1` document naming the daemon (its host key's fingerprint), the host, the port
  and a one-use nonce the daemon handed out, signed in the `writ-approval` namespace by a key
  in `approvers` (hard rule 5); with [multi-user](multi-user.md), only an admin's key. A reader key alone can't make
  the daemon reach a host, so the scan can't be used to probe the daemon's network. The
  daemon opens an SSH connection to that host and port, reads the host keys it offers and
  closes, bounded in time (`mirrors.scan_timeout`, 30 s a handshake) and size: one handshake
  per host key algorithm Writ verifies (Ed25519, ECDSA P-256 and P-384; RSA and P-521 hosts
  give their keys as `keys=`, see the [decision log](../decisions.md)), with the daemon's own
  SSH library (russh, in `writ-mirror`), each dropped before any authentication.
  `writ admin host rescan <host>` scans a pinned host again when its keys changed: each key
  shown against the pin, then one signed change replacing it. The keys are shown with their fingerprints, never pinned
  by the scan: a second signed change pins them, once the operator has compared them with
  the remote's published ones. Two Touch IDs for a new host, which is rare.
- **An upstream check** (`writ admin repo check <repo>`, run by `repo add` once the key is
  registered), with a reader key: it only reaches an upstream the signed policy already
  names. with the repo's credential and the daemon's hardened git, a fetch of the refs
  and a receive-pack connection that pushes nothing (as `git push --dry-run` does), so read
  and write access are both proven with nothing changed upstream; then the first sync, and
  the object format compared with the policy's. What upstream says comes back escaped and
  bounded.

### The commands

`writ admin repo|template|key|host`, the same verbs for each:

| Verb | What it does |
|---|---|
| `list`, `show <name>` | Read only, with the reader key. `key show <id>` prints the public half alone with `--public`, for a pipe or `pbcopy` |
| `add <name> [<field>=<value>…]` | Step by step: each field asked in order, with its bounds and default, the ones given on the command line not asked |
| `edit <name>` | Step by step, each prompt filled with the current value (Enter keeps it) |
| `set <name> <field>=<value>…` | Only the fields named, no prompts |
| `remove <name>` | What it affects shown first, then confirmed |
| `key rotate <id>`, `repo check <repo>` | Below |

- **Fields are the policy's own keys**, the names of the [operator reference](../operators/policy-yaml.md):
  `field=value` replaces, `field+=value` and `field-=value` add to and take from a list,
  `field!` unsets an optional field, `field=` empties a list. One syntax for every noun, so no
  flag per field.
- **Every command is one signed change**: `writ` builds the new policy text from the version
  in force, in Writ's canonical layout (one writer in `writ-core`, the fields in the operator
  reference's order; a hand-written policy's comments are dropped by the first field command,
  whose diff shows the reformat), shows the diff on the trusted display, signs a `writ-admin/2` naming that version
  (one Touch ID), and the daemon applies it or refuses it with every reason. A change made in
  between makes it refused (the version it names is no longer in force): run it again.
- **No terminal**: `add` and `edit` ask nothing; `add` refuses unless every required field is
  given, naming the missing ones; `remove` refuses unless `--yes` is given. `--yes` answers
  `remove`'s questions (the confirmation, and a key's id typed again) and nothing else: the
  effects are still printed, and the change still needs the approver's signature.
- **What can't change**: a key's `use`, `kind`, `format`, `algorithm` and `backend` are the
  key itself; `set` refuses them and points to `key rotate`. Its `uids`, `hash` (within what
  the format allows) and a token's `host` can change.
- **`remove`**: a template a repo names, a key a template or a repo uses, or a host a repo
  needs is refused, naming them. A repo with active leases lists the leases that end before
  asking.
- **A removed key is deleted**: when the change applies, its sealed file is wiped from the
  keystore, and declaring the same id again makes a new key. Since that can't be undone,
  `key remove` asks for the key's id to be typed again before the signature (a mistyped id
  stops it, nothing sent). The removal's audit line keeps the public half and the
  fingerprint, so commits the key signed can still be verified.
- **`key rotate <id>`**: a new key declared like the old one (`<id>` with a new suffix, or a
  name given), its public half printed to register; then, in a second signed change once it
  is registered, every repo or template that used the old key switched to it. A signing
  key's leases stop fitting with the switch and are amended (the remote must keep the old
  public key for the old commits to stay verified, which the command says). The old key then
  stays declared, unused, until `key remove` deletes it, which `rotate` offers at its end.

### The guided flows

- **`repo add`**: the name; the upstream URL, checked as the daemon checks it; the host, and
  if it has no pin a signed scan, its fingerprints and the question "do they match what the
  remote publishes?" (the pin then goes in the same change as the repo); the credential, an existing one or a new one (its kind from the URL, its
  algorithm asked, Ed25519 offered); the templates, from the list; protected refs, push modes,
  ticket link and object format, defaults shown. One diff, one signature. Then the new key's
  public half and where to register it (a deploy key with write access, or the token to add
  with `writ admin token`), "press Enter once it is added", and the upstream check.
- **`template add`**: the operations first, then only the fields they need (`commit_sign`
  asks for branches, committer emails, the signing key and its user ids); every limit with
  its bounds; `--from <template>` starts from another one's values.
- **`key add`**: its use, then the fields that use takes; the public half printed; for a
  token, `writ admin token <id>` run next.
- **`host add`**: the scan's signature, the fingerprints, the question, the pin's signature.
- **`key remove`**: what uses it (refused if anything does), the id typed again, the
  signature, the file deleted.

The prompts are a convenience: what the operator types goes into a policy text the daemon
checks whole, like any other change.

## Threat model impact

- **Stronger:** key declarations and upstream host pins move from host files to text an
  approver signed. Today whoever can write `writd.yaml` or `mirrors.known_hosts` on the host
  can change a key's declared hash or pin a host key of their own for an upstream (and so
  receive its pushes); after M6.2 neither changes without a signature, and a token can only
  reach its declared host.
- **New untrusted inputs** (each joins the [security inventory](../security.md) with its
  bounds and a hostile-input test): the host keys a scan reads from the network (shown,
  escaped, never pinned by the scan), what upstream answers to a check (escaped, bounded),
  the operator's `field=value` input (parsed by the daemon as policy text; the client's
  parsing is only for the prompts), and the `writ-scan/1` document (verified like any
  approval: its daemon, its nonce used once).
- **New reads on the approval API:** the public halves (not secret; readers already see the
  policy with `writ admin show`), and two operations that make the daemon open outbound
  connections, each bounded in time, size and rate, and logged: a scan, only with an
  approver's signature over its host and port (an admin's with multi-user), so a reader key can't
  probe the daemon's network; and a check, only to an upstream the signed policy names.
- **A signed removal deletes a key for good:** a mistaken one loses it (an upstream key is
  made again and registered again; a signing key's old commits stay verifiable from the
  public half in the audit log). The id typed again and the diff on the trusted display stand
  in front of it; the keystore's backup is the way back.
- **Unchanged:** every change needs an approver's signature over the whole new text, naming
  the version it replaces; the trusted display shows the diff; no secret crosses the API (a
  token still goes through `writ admin token`, encrypted on the approver's machine).

## Open questions

Settled with the user before writing the plan:

- **The host key scan** needs an approver's signature (`writ-scan/1`), an admin's with multi-user;
  not limited to some ports, since no reader key can ask for one.
- **A removed key is deleted**, after its id is typed again; `--yes` answers that question
  too, for scripts and the end-to-end scenarios.
- **The field names** are `use` (`signing`, `upstream`) and `kind` (`ssh`, `token`).
- **`--yes`** answers `remove`'s questions without a terminal, never the signature.
- **`writ admin show` and `apply`** stay for the whole policy beside the field commands: large
  edits, a policy copied between daemons, a review in an editor.

Settled with the user on 2026-11-05, starting M6.2:

- **The policy text `writ` builds** is in Writ's canonical layout, from one writer in
  `writ-core`: a hand-written policy's comments go with the first field command, and `show`
  and `apply` still take any text.
- **No backward compatibility**: Writ isn't deployed, so the old shape is refused, not
  converted, and the state version moves to 10.
- **The scan** uses russh in the daemon (`writ-mirror`), one handshake per host key
  algorithm, rather than `ssh-keyscan`.

None is open; new ones go here.

## Acceptance

[M6.2's checklist](../history/m6.2-managing-the-daemon-from-the-cli.md#acceptance).

## Plan

Each step leaves Writ working, `make ci` and `make e2e` passing.

1. **The policy's new shape in `writ-core`**: `keys`, `upstream_hosts`, `repos.<name>.templates`,
   the fit rule read from the repos, every check and its refusal, the old fields refused by
   name; the canonical writer, read back to the same policy. The state version moves to 10.
2. **The daemon on the new shape**: keys made by the change that declares them (upstream
   keys of every algorithm), `writd init` from the policy, the host pins from it,
   `writd.yaml`'s `signing_keys` and `mirrors.known_hosts` gone, `writd keys create` removed,
   `writd signing-keys` and `upstream-keys` reading the policy in force.
3. **The reads**: the approval API's reads, `writ admin <noun> list|show`, `key show --public`.
4. **Field edits**: `set` and `remove` for every noun, the `field=value` syntax, the diff and
   the signature, the refusals.
5. **The guided flows**: `add` and `edit` for every noun, `template add --from`, `key rotate`.
6. **The daemon's checks**: the signed host key scan (`writ-scan/1`, its nonce, `host add`),
   the upstream check (`repo check`, the end of `repo add`).
7. **Docs and the pipeline**: the operator reference and guides rewritten for the new
   commands and the new configuration layout (`writd.yaml` the host's, the policy everything
   else, `writ admin` the way to change it), the scenarios for every new command and syntax
   with their registry rows, the end-to-end pipeline's own setup done through the commands.
