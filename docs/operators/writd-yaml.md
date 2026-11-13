# `writd.yaml`

The daemon's configuration. Start from the [template](templates/writd.yaml). Examples: the
[development configuration](../../dev/writd.yaml) (`make run`) and the
[end-to-end one](../../e2e/config/writd.yaml), shaped like a real deployment.

- **The host's settings only:** paths, listeners, limits, the mirrors' programs and bounds,
  notifiers. The keys and the upstream host keys are the [policy's](policy-yaml.md), changed
  by signed changes. `signing_keys` and `mirrors.known_hosts`, from before M6.2, are refused,
  naming their new place.
- **Read at start.** A change takes effect at the next start. The `writd host-key`,
  `tls-fingerprint`, `upstream-keys` and `signing-keys` commands read it too.
- **An authority file:** owned by the daemon's user, mode 0644 or stricter.
- **Unknown keys are refused**, and every error names its key:
  `mirrors.timeout: 61m, must be from 10s to 1h`.
- **Relative paths** are relative to this file's directory.
- **Durations:** a number and `s`, `m`, `h` or `d` (`90s`, `5m`).
- **Sizes:** bytes, or a number and `KB`, `MB`, `GB` (×1000) or `KiB`, `MiB`, `GiB` (×1024).

## Files and access

| Key | Accepts | Default | What it does |
|---|---|---|---|
| `state_dir` | Path | **required** | The daemon's state: `leases.db` (leases, ledger), `audit.jsonl` (the [audit log](../architecture/policy-and-state.md#audit-log)), the mirrors, sockets, and `writd.lock` (held by the running daemon, so `writd recover` waits for it to stop). Back it up. Keep it on a local disk |
| `policy` | Path | **required** | The keys, upstream host keys, repos and templates: [`policy.yaml`](policy-yaml.md). An authority file, [kept by the daemon after `writd init`](#policy-approvers-and-readers-after-writd-init) |
| `approvers` | Path | **required** | The keys that may sign tickets, refusals, revocations and proofs: one `<name> <public key>` per line. An authority file, [kept by the daemon after `writd init`](#policy-approvers-and-readers-after-writd-init) |
| `readers` | Path | **required** | The keys that may use the approval API: one line per key, as `writ reader <name>` prints it. A reader still needs an approval key to sign. An authority file, [kept by the daemon after `writd init`](#policy-approvers-and-readers-after-writd-init) |
| `keystore.sealed.dir` | Path | **required** (sealed keystore) | Every secret, each in its own encrypted file, made by `writd init` (0700). Safe to copy: it reveals nothing without the passphrase |
| `keystore.sealed.boot` | Path | **required** (sealed keystore) | The SSH host key and the TLS key, readable before unseal (0700). Keep it apart from `dir` if you can ([why](sealing.md#how-the-keystore-works)) |
| `keystore.dev` | Path | — | Instead of `sealed`, for tests and development: plain key files, created on first start. **Refused by release builds** |

### Policy, approvers and readers after `writd init`

These three files are read once, by `writd init` (or the development keystore's first start).
After that the daemon keeps its own copy and writes it back to these paths. A hand edit is
moved aside at the next start, never applied. To change them, from your machine:
[`writ admin repo|template|key|host|proxy`](sealing.md#changing-the-policy-the-approvers-or-the-readers)
for the policy's entries, `writ admin apply` for a whole file; or
[`writd recover`](recovery.md) on the host.

## Approvals and tickets

| Key | Accepts | Default | What it does |
|---|---|---|---|
| `decisions` | `signed` or `open` | `signed` | Whether refusals and revocations need your signature. `signed`: like an approval. `open`: any reader may refuse or revoke, and the agent sees the refusal marked `[not signed by an approver]`. Approvals are always signed |
| `max_pending` | 1 or more | `20` | Tickets waiting for you at once, across the daemon. Past it, new tickets are refused. One session key holds at most 2 |
| `min_ttl` | 10s to 1d | `5m` | The shortest lease a ticket may ask for, and the smallest `max_ttl` a template may set. [Why it matters](#min_ttl-and-notifications) |
| `submissions.per_source` | 1 to 1000 | `10` | Tickets one source may submit per minute (a `writ policy` read and a `writ request --dry-run` count as one each). A source is an IPv4 address, an IPv6 /64, or the one local client in local mode |
| `submissions.in_all` | 1 to 10000 | `60` | Tickets all sources together may submit per minute (reads and dry runs counted the same way) |
| `max_active_per_source` | 1 or more | no limit | Active leases one source may hold at once. Set `1` on a host meant for one agent: then its agents can't reach each other's leases. An amendment or a renewal doesn't count twice. Checked when a ticket arrives and again when you sign it |
| `renew_grace` | 0s to 7d | `24h` | How long after its end an expired or used-up lease can still be [renewed](ticket.md#renewals). `0s`: only a lease still running can be |
| `sign_requests.per_lease` | 1 to 16 | `4` | Commit signatures one lease may have in progress at once (16 across the daemon). One more is refused, not queued |

### `min_ttl` and notifications

A waiting ticket takes one of the `max_pending` slots until it expires. So together they cap
how often agents can notify you: 20 slots for 5 minutes is about 4 notifications a minute.
Lower `min_ttl` only if you accept more. You can still sign a lease shorter than it.

## Mirrors and upstream

How the daemon reaches each repo's `upstream` ([gateway](../architecture/gateway.md#upstream)).
Programs are named by absolute path, never looked up in `PATH`. `signers.*` and
`session_launcher` are checked at start; `mirrors.git` and `mirrors.ssh` when the mirrors
open, at unseal (a wrong path then refuses the unseal, naming it).

| Key | Accepts | Default | What it does |
|---|---|---|---|
| `mirrors.ca_certs` | Path | the system's CAs | For `https://` upstreams behind your own CA: a PEM file that **replaces** the system's CAs. An authority file ([how](setup.md#https-upstreams-and-tokens)) |
| `mirrors.git` | Absolute path | `/usr/bin/git` | The git the daemon runs: 2.45 or newer, 2.47 for `https://` upstreams |
| `mirrors.ssh` | Absolute path | `/usr/bin/ssh` | The OpenSSH client for `ssh://` upstreams |
| `mirrors.fresh_for` | 0s to 1h | `10s` | A mirror synced this recently serves fetches and pushes without asking upstream again. `0s`: always ask |
| `mirrors.sync_every` | 10s to 1d | `5m` | How often every mirror syncs in the background |
| `mirrors.timeout` | 10s to 1h | `5m` | The longest one sync or push to upstream may take. Raise it for a first sync of a large repository. A stopping daemon cuts one still running after 320 s |
| `mirrors.max_fetch` | 1MiB to 64GiB | `1GiB` | The most one sync (or push, notes push or check) may download from upstream, over SSH or HTTPS, all its connections together. Past it, the operation fails and the mirror stays as it was |
| `mirrors.scan_timeout` | 1s to 5m | `30s` | The longest one handshake of a host key scan (`writ admin host add`) may take: raise it for a host slow to answer. A scan makes up to three, one per key algorithm |

## Key backends

The programs the key backends other than `software` run (a key's backend is chosen in the
policy: [`keys.<id>.backend`](policy-yaml.md#keys-keysid)). Each is checked at start when a
key lives on its backend: the daemon refuses to start, naming the path and why, when the
program is missing or the device isn't there.

| Key | Accepts | Default | What it does |
|---|---|---|---|
| `signers.se_cryptokit.helper` | Path (made absolute) | `writ-se` beside `writd` | The Secure Enclave helper on the Mac (`se-cryptokit`), installed by `make install` beside `writd`. Set it only if you keep it elsewhere |

## Listeners

Where the daemon listens. Each of the three lists holds **listeners**: `{ tcp: "host:port",
allow: [...] }`.

| Key | Accepts | Default | What it does |
|---|---|---|---|
| `transports.agents` | Listeners, at least one | **required** | Where agents submit tickets, fetch, push and sign commits. Port `2222` in detached mode |
| `transports.approvals.ssh` | Listeners | `[]` (off) | The approval API over SSH (`ssh://host:port`). Port `2223` |
| `transports.approvals.https` | Listeners | `[]` (off) | The approval API over HTTPS, with the daemon's own pinned certificate. Port `8443`. `ssh` and `https` can't both be off: nothing could be approved |
| `<listener>.tcp` | An address and port, literal (`127.0.0.1:2222`, `[::1]:2222`) | — | A TCP listener. Exactly one of `tcp` and `unix`. A host name is refused: it is never resolved |
| `<listener>.unix` | Path | — | A Unix socket (local mode), at most 103 bytes; relative to `writd.yaml`'s directory. Its directory must already exist, owned by the daemon's user or root, and nobody but its owner may write it: it decides who can connect (on the Mac, `_writd:_writ` `0750`; on Linux, `/run/writ`, `writd:writ` `0750`, made by systemd). The daemon makes the socket `0660` and replaces an old socket left there, never anything else. Needs `attestor: macos_process_chain` or `linux_process_chain`: the `network` attestor can't attest its callers, so it is refused at start |
| `<listener>.allow` | Addresses or CIDR ranges | — | Who may connect. [Rules](#allow) |

### `allow`

- **Required on an agents' TCP listener**: anyone who reaches it could submit tickets. To allow
  everyone, write it out: `0.0.0.0/0`, `::/0`.
- Optional on the approval listeners: only readers get in anyway.
- Never empty, and no host bits in a range: `10.0.0.0/24`, not `10.0.0.1/24`.
- A connection from elsewhere is closed before any authentication, and counted in the audit
  log.

## Platform

| Key | Accepts | Default | What it does |
|---|---|---|---|
| `attestor` | `network`, `macos_process_chain` or `linux_process_chain` | **required** | How the daemon identifies a caller beyond its certificate ([platform](../architecture/platform.md)). `network`: its source address (detached mode). `macos_process_chain` (local mode, macOS builds only) and `linux_process_chain` (local mode, Linux builds only): for a caller on a Unix socket, the processes it descends from as the kernel knows them, checked against a lease's `caller`; for a TCP caller, its source address only, so a lease with a `caller` refuses it. `linux_process_chain` needs Linux 6.5 or later and a `/proc` without `hidepid` (else the daemon doesn't start, and says which), and `CAP_SYS_PTRACE` at start to read the processes of other users than its own: the systemd unit gives it, and only the daemon's process reader keeps it ([deployment](../architecture/deployment.md#local-linux)) |
| `session_watcher` | `none`, `macos` or `linux` | **required** | Whether a lease is revoked when its agent's session ends. `macos` (macOS builds only) and `linux` (Linux builds only, Linux 5.3 or later): a lease with a `caller` is revoked when that process ends. `none`: such a lease is never granted |
| `session_launcher` | Absolute path, written with links resolved | `writ` beside `writd` | Local mode: the `writ` that starts your agents (`writ run`). A lease binds only to a process this program started, as the kernel names it. Only root or the daemon's user may be able to change it or its directories, or the daemon doesn't start. Read only when an agents' listener is a Unix socket ([session binding](#session-binding)) |

### Session binding

- The daemon recognises the `writ` that starts a session by its path, not by its
  signature: an ad hoc signature names itself, so it proves nothing.
- `make install` puts `writ` beside `writd`, owned by root: the default fits it.
- Set the key only if you install `writ` somewhere else.

## Notifications

`notifiers` is a list, empty by default. Each entry is one Telegram bot. A notification says a
ticket is waiting (its id and template, never the agent's words). It is never a way to
approve: only `writ sign` is. Each entry is checked when the daemon reads `writd.yaml`: a
mistake stops the start, rather than leave you without notifications.

| Key | Accepts | Default | What it does |
|---|---|---|---|
| `notifiers[].telegram.token.boot` | Path | one of `boot` or `sealed` **required** | The bot token in its own file (mode 0600), in the boot directory, read at start. [Boot or sealed?](sealing.md#the-notification-token-boot-or-sealed) |
| `notifiers[].telegram.token.sealed` | Key id | one of `boot` or `sealed` **required** | The bot token stored with the other secrets, added with `writ admin token <id>` and read at unseal. If it's missing at unseal, the notifier stays off (a warning) until you add it. One id per notifier: two notifiers can't share one |
| `notifiers[].telegram.chat_id` | Text | **required** | The chat: a numeric id, quoted (`"-100123"`), or `@channelname` |
| `notifiers[].telegram.api_base` | URL | `https://api.telegram.org` | Another Bot API server: `https://`, or `http://` to this machine only (the token travels in the URL). No credentials, path, query or fragment |

## Environment

| Variable | Accepts | Default | What it does |
|---|---|---|---|
| `WRIT_LOG` | A `tracing` filter | `info` | The daemon's diagnostics on stderr (`warn`, `debug`, `writ_gateway=debug`…). Decisions always go to the audit log, whatever this says |
