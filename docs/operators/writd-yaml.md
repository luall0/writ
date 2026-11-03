# `writd.yaml`: the daemon's configuration

Every key `writd` reads from its configuration file, with its default, its bounds and what it
does. The file is read once, at start (`writd run writd.yaml`; the printing commands
`writd host-key`, `tls-fingerprint`, `upstream-keys`, `signing-keys` read it too); a change
takes effect at the next start.

- **Authority file**: whoever can write it decides who may connect and which files grant
  authority. 0644 or stricter, owned by the daemon's user; the daemon refuses it otherwise.
- **Unknown keys are refused**, and every error names its key
  (`mirrors.timeout: 61m, must be from 10s to 1h`).
- **Relative paths** are relative to the file's directory, so `writd run writd.yaml` from
  that directory and `writd run /etc/writ/writd.yaml` from anywhere read the same files.
- **Durations**: a number and one unit, `s`, `m`, `h` or `d` (`90s`, `5m`). **Sizes**: bytes,
  or a number and `KB`, `MB`, `GB` (powers of 10) or `KiB`, `MiB`, `GiB`.

A file to start from: the [template](templates/writd.yaml) (every key, optional ones commented
out at their default). Examples: the [development configuration](../../dev/writd.yaml) (`make run`); the
[end-to-end one](../../e2e/config/writd.yaml) is a real deployment's shape.

## Files and access

| Key | Value (default) | What it does |
|---|---|---|
| `state_dir` | Path, **required** | The daemon's state: `leases.db` (leases, ledger), `audit.jsonl` (the [audit log](../architecture/policy-and-state.md#audit-log)), `repos/` (the mirrors), `run/` and `mirror/` (sockets). Back it up; keep it on a local disk |
| `policy` | Path, **required** | The repo registry and the templates: [`policy.yaml`](policy-yaml.md). An authority file. Read by `writd init` (or the development keystore's first start) as the first version in force; after that, the daemon holds the versions in force in its state and writes this file back with the text in force: it changes only by `writ admin apply` or [`writd recover`](recovery.md), and a hand edit is set aside at the next start, never applied |
| `approvers` | Path, **required** | Who may sign tickets, refusals, revocations and proofs: one `<name> <public key>` per line (`allowed_signers` format), the approval keys (Secretive's dedicated key). An authority file. Read by `writd init` (or the development keystore's first start) as the first version in force; after that, the daemon holds the versions in force in its state and writes this file back with the text in force: it changes only by `writ admin apply` or [`writd recover`](recovery.md), and a hand edit is set aside at the next start, never applied |
| `readers` | Path, **required** | Who may use the approval API (`writ ls`, `sign`, `refuse`, `revoke`, `prove-key`): one line per reader key, as `writ reader <name>` prints it. Reading is not approving: a reader still needs a key in `approvers` to sign. An authority file. Read by `writd init` (or the development keystore's first start) as the first version in force; after that, the daemon holds the versions in force in its state and writes this file back with the text in force: it changes only by `writ admin apply` or [`writd recover`](recovery.md), and a hand edit is set aside at the next start, never applied |
| `keystore.sealed.dir` | Path, **required** with a sealed keystore | The sealed keystore, made by `writd init` (0700): every secret but the boot tier's, each its own age file encrypted to the keystore's recipient (`recipient`), whose identity the passphrase wraps (`identity.age`); the public halves beside them (`.pub`). The CA key, the agent signing keys, the upstream credentials. Copied alone, it reveals no key. The daemon starts sealed: `writ unseal` opens it (M5) |
| `keystore.sealed.boot` | Path, **required** with a sealed keystore | The boot tier (0700): the keys a sealed daemon authenticates itself with, readable at start: the SSH host key (`host`) and the HTTPS approval API's TLS key and certificate. Its own directory, so it can live apart from `dir` (another volume, a Docker secret): a copy of it, with an intercepted `writ unseal`, lets someone pose as the daemon ([threat model](../threat-model.md#residual-risks-v1)) |
| `keystore.dev` | Path, instead of `sealed` | The development keystore: plain key files in this directory, generated on first start (the agent signing keys, the upstream credentials, the host and TLS keys), and `tokens/<id>` for `https://` upstreams. Only a debug build with the `dev-keystore` feature takes it: **refused by release builds**. For tests and development |

## Approvals and tickets

| Key | Value (default) | What it does |
|---|---|---|
| `decisions` | `signed` or `open` (`signed`) | Whether refusals and revocations need an approver's signature. `signed`: an SSHSIG by a key in `approvers`, like an approval. `open`: anyone who reaches the approval API (a reader) may refuse or revoke; the agent sees the refusal's feedback prefixed `[not signed by an approver]`. Approvals are always signed |
| `max_pending` | 1 or more (`20`) | Tickets waiting for the approver at once, daemon-wide; past it a submission is refused until one is decided or expires. One session key holds at most 2 anyway |
| `min_ttl` | 10s to 1d (`5m`) | The shortest TTL a ticket may ask for (`limits.ttl`), and the least a template's `max_ttl` may be (checked at load and on every policy change). A pending ticket holds one of the approver's waiting slots until it expires, so with `max_pending` it caps how often submitters can notify the approver: 20 slots for 5 minutes, about 4 notifications a minute. Lower it only where the approver accepts more: at 10 s only the `submissions` rates bound them. The approver may still narrow a lease below it when signing |
| `submissions.per_source` | 1 to 1000 (`10`) | Tickets one source may submit a minute (an IPv4 address, an IPv6 host by its /64; local mode: one source). Every refusal is counted in the audit log |
| `submissions.in_all` | 1 to 10000 (`60`) | Tickets all sources together may submit a minute |
| `sign_requests.per_lease` | 1 to 16 (`4`) | Commit sign requests one lease may have held at once (16 daemon-wide); one more is refused at once, never queued |

## Mirrors and upstream

How the daemon reaches each repo's `upstream` ([gateway](../architecture/gateway.md#upstream)).
Its programs are named by absolute path, never looked up in `PATH`, and checked at start.

| Key | Value (default) | What it does |
|---|---|---|
| `mirrors.known_hosts` | Path, **required** | The remotes' SSH host keys, pinned by hand, one line per host (`github.com ssh-ed25519 AAAA…`, `[forgejo.home]:2222 …`). The daemon refuses to start when an `ssh://` upstream's host has no pin, and refuses a sync when the host shows another key. Wildcards, hashed names and `@cert-authority` lines are refused. An authority file ([setup](setup.md#upstream-keys-and-host-keys)) |
| `mirrors.ca_certs` | Path (the system's CAs) | `https://` upstreams: the PEM file of the CAs their certificates must chain to. Set, it **replaces** the system's (its directory too): a self-hosted remote behind your own CA. An authority file ([setup](setup.md#https-upstreams-and-tokens)) |
| `mirrors.git` | Absolute path (`/usr/bin/git`) | The git the daemon runs on its mirrors and with upstream: 2.45 or newer, 2.47 for `https://` upstreams |
| `mirrors.ssh` | Absolute path (`/usr/bin/ssh`) | The OpenSSH client the daemon reaches `ssh://` upstreams with |
| `mirrors.fresh_for` | 0s to 1h (`10s`) | A mirror synced this recently serves a fetch or a push without asking upstream again. `0s`: every fetch and push asks upstream first |
| `mirrors.sync_every` | 10s to 1d (`5m`) | The background sync of every mirror, with or without agents |
| `mirrors.timeout` | 10s to 1h (`5m`) | One sync or upstream push; past it, git and ssh are killed and the operation fails. A first sync of a large repository may need more |
| `mirrors.max_fetch` | 1MiB to 64GiB (`1GiB`) | The most one sync takes from upstream, over SSH and HTTPS alike; past it the sync fails and the mirror stays as it was |

## Listeners

`transports` names where the daemon listens. Each entry of the three lists is a **listener**:

| Key | Value (default) | What it does |
|---|---|---|
| `transports.agents` | List of listeners, **at least one** | The agents' gateway: ticket submission (`writ request`, user `writ`), git fetch and push, commit signing (user `git`, a session certificate). Detached mode: port `2222` |
| `transports.approvals.ssh` | List of listeners (`[]`, disabled) | The approval API over SSH (`ssh://host:port` for `writ`). Port `2223` |
| `transports.approvals.https` | List of listeners (`[]`, disabled) | The approval API over HTTPS, the daemon's own certificate pinned by its fingerprint (`writd tls-fingerprint`). Port `8443`. `ssh` and `https` may each be disabled, **not both**: nothing could ever be approved |
| `<listener>.tcp` | `host:port` | A TCP listener. Exactly one of `tcp` and `unix` |
| `<listener>.unix` | Path | A Unix socket. **Refused at start by this build**: Unix sockets come with local mode ([M7](../roadmap.md#m7--local-mode-on-the-mac)) |
| `<listener>.allow` | List of addresses or CIDR ranges | Who may connect (TCP only, never empty, no host bits set: `10.0.0.0/24`, not `10.0.0.1/24`). **Required on an agents' TCP listener**: anyone who reaches it could submit tickets, so allowing everyone is written out (`0.0.0.0/0`, `::/0`). Optional on the approval listeners (only readers get in anyway). A connection from elsewhere is closed before any authentication, and counted in the audit log |

## Platform

| Key | Value (default) | What it does |
|---|---|---|
| `attestor` | `network` or `macos_process_chain`, **required** | Who the caller is beyond its certificate ([platform](../architecture/platform.md)). `network`: its source address only (detached mode). `macos_process_chain`: the kernel-resolved process chain, which a ticket's `caller` constraint is checked against; **refused at start by this build** ([M7](../roadmap.md#m7--local-mode-on-the-mac)) |
| `session_watcher` | `none` or `macos`, **required** | Whether a lease is revoked when its agent's session process exits. `macos`: **refused at start by this build** ([M7](../roadmap.md#m7--local-mode-on-the-mac)) |

## Notifications

`notifiers` is a list (`[]`, none); each entry names one kind. A notification says a ticket
is waiting (title and id): never a way to approve, which only `writ sign` does.

| Key | Value (default) | What it does |
|---|---|---|
| `notifiers[].telegram.token.boot` | Path, one of `boot` and `sealed` **required** | The bot token in a file of its own (the token alone, mode 0600), read at start: put it in the boot tier's directory. A sealed restart is notified at once ("writd started, sealed"), and "writd unsealed" comes only from the real daemon: no such message after a `writ unseal` that said it worked means something answered in the daemon's place. Whoever holds the file can send messages as the bot ([threat model](../threat-model.md#residual-risks-v1)) |
| `notifiers[].telegram.token.sealed` | Key id, one of `boot` and `sealed` **required** | The bot token sealed with the other secrets (`tokens/<id>.age`, added with `writ admin token <id>`; in the development keystore, the file `tokens/<id>`), read at unseal: nothing is sent before. Missing at unseal, the notifier stays off (a warning) until `writ admin token <id>` adds it, which starts it at once. The choice has no default: it depends on the deployment ([setup](setup.md)) |
| `notifiers[].telegram.chat_id` | String, **required** | The chat to send to: a numeric id (`"-100123"`, quoted), or `@channelname` |
| `notifiers[].telegram.api_base` | URL (`https://api.telegram.org`) | Another Bot API server (self-hosted): `https://`, or `http://` to this machine only (the token travels in the URL path); no credentials, path, query or fragment |

## Environment

| Variable | Value (default) | What it does |
|---|---|---|
| `WRIT_LOG` | A `tracing` filter (`info`) | The daemon's diagnostics on stderr (`warn`, `debug`, `writ_gateway=debug`…). Diagnostics only: decisions are in the audit log, whatever this says |
