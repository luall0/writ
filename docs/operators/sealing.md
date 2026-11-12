# Daily operations

Once the daemon runs: unseal it after a restart, change what it allows, add tokens.

## How the keystore works

Every secret the daemon holds is encrypted on disk: the CA key, the agent signing keys, the
upstream keys and tokens. The daemon always starts **sealed**: it can't use any of them until
you unseal it.

`writd init` makes two directories:

| Directory | Holds | Copied by someone else |
|---|---|---|
| `keystore.sealed.dir` | Every secret, encrypted | Reveals nothing without the passphrase |
| `keystore.sealed.boot` | The SSH host key and the TLS key, not encrypted: the daemon needs them to prove who it is before it is unsealed | They could pose as the daemon, and catch your passphrase at the next `writ unseal` |

So keep the boot directory apart from the keys directory if you can: another volume, a Docker
secret ([threat model](../threat-model.md#residual-risks-v1)).

## Unsealing

After every start of the daemon, from your machine:

```sh
writ unseal
```

It shows which daemon and which start you are unsealing, then asks for the passphrase and one
Touch ID. Both are needed.

- Until then, everything but `writ info` and `writ unseal` is refused with "daemon sealed".
- A signature unseals that one start of that daemon, never another.
- Active leases come back as they were. Their expiry doesn't move.

## Changing the policy, the approvers or the readers

After `writd init`, the daemon keeps its own copy of `policy.yaml`, `approvers` and
`readers`. **Editing the files on the host does nothing**: at the next start, an edited file
is moved aside (`<file>.unapplied-<time>`) and the daemon's copy is written back.

**The policy, entry by entry**, from your machine. The same verbs for each of its five
nouns, `repo`, `template`, `key`, `host` and `proxy`:

```sh
writ admin repo list                       # one line per entry (a reader key is enough)
writ admin repo show <repo>                # the entry as the policy writes it, and what uses it
writ admin repo add <repo>                 # each field asked, then one signature
writ admin repo edit <repo>                # each field asked, Enter keeping it
writ admin template set <template> max_ttl=2h branches+=fix/*   # only the fields named
writ admin key remove <id>                 # refused while something uses it
```

- `set` takes the policy's own field names: `field=value` replaces, `field+=value` and
  `field-=value` add to or take from a list, `field!` leaves an optional field out, `field=`
  empties a list.
- Each change is shown as a diff, then signed once. If the policy changed in between
  (someone else applied a change), yours is refused: run the command again.
- `writ admin key rotate <id>`: a new key like the old one, its public half printed; once
  you registered it, every repo and template switches to it; then the old key can go.
- `writ admin host add <host>` and `writ admin host rescan <host>`: the daemon scans the
  host, you compare its keys with the ones the remote publishes, then a second signature
  pins them. For a host behind a [proxy](setup.md#a-remote-behind-a-proxy), add `proxy=<name>`
  to `host add` (or to `repo add` with the repo's other fields); `host rescan` goes through
  the proxy the host's repos share, or the one `--proxy <name>` names.
- `writ admin repo check <repo>`: the repo's upstream reached with its key, read and write
  access proven, nothing pushed.

**A whole file**: the approvers, the readers, or the policy in one go:

```sh
writ admin show approvers > approvers     # the version in force
$EDITOR approvers
writ admin apply approvers approvers      # shows what changes, then one signature
```

Every change applies at once, and the daemon writes the file back on the host (the policy
in Writ's own layout, comments dropped, once `writ admin <noun>` changed it).

What a policy change does:

- **A key it declares**: the daemon makes it, and `writ` prints its public half to register
  on the remote (a token: add it with `writ admin token`).
- **A key it no longer declares**: deleted for good once the change applies (its public half
  kept in the audit log). `key remove` asks you to type its id first.
- **A tighter template**: its active leases are denied until amended.
- **A changed repo**: its mirror is reopened. Other repos keep theirs. `templates: []`
  closes a repo: every ticket for it is refused.

Lost every approval or reader key? See [recovery](recovery.md).

## Adding or rotating a token

For an `https://` repo, or a notifier with `token: { sealed: <id> }`. The daemon must be
unsealed:

```sh
writ admin token <id>      # asks for the token (no echo), then one signature
```

The token is encrypted on your machine before it is sent. The daemon stores it as
`tokens/<id>.age` and uses it at once. Run the command again to rotate it.

## The notification token: boot or sealed

A Telegram notifier's token (`notifiers[].telegram.token`) has no default: you choose where it
lives.

| | `token: { boot: <file> }` | `token: { sealed: <id> }` |
|---|---|---|
| Stored | In its own file (mode 0600) in the boot directory | With the other secrets, added with `writ admin token <id>` |
| After a restart | "writd started, sealed", at once | Nothing until you unseal |
| After `writ unseal` | "writd unsealed" | "writd unsealed" |
| If the boot directory is copied | The copier can send messages as the bot | Nothing |

- **Choose `boot`** if the daemon restarts unattended: you want to know it is waiting for you.
  Bonus: "writd unsealed" can only come from the real daemon. If `writ unseal` says it worked
  and that message doesn't come, something answered in the daemon's place.
- **Choose `sealed`** if the bot's token matters more to you than a missed restart.

## Starting without a human: auto-unseal (M7.6)

Not built yet: [M7.6](../roadmap.md#m76--hardware-wrapped-secrets) brings it. What it will
require, so you can plan:

- **Opt-in:** `unseal: auto` in `writd.yaml`. Never the default.
- **Hardware for every secret:** every signing key (agent keys, `ssh://` credentials, the CA
  key) in a hardware backend, and every stored secret (tokens, the keystore's own identity)
  wrapped to hardware only: Secure Enclave, TPM, YubiKey or a cloud KMS. Only the notification
  token and the boot directory's host and TLS keys may stay software files.
- **An offline recovery identity**, made first and kept on paper or a spare device. It
  recovers the keystore if the hardware is lost, and `writd recover` takes it instead of the
  passphrase. The hardware alone never replaces a signed change.
- **No silent downgrade:** if anything is still software, the daemon refuses to start and
  names it.

The trade-off: anyone who can restart the daemon, or steal the whole machine, gets a running
daemon without asking you. Leases still need your signature, and every automatic start is
logged and notified.
