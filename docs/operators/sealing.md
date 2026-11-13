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
Touch ID. Both are needed. With a [Secure Enclave key](#the-recovery-key-and-the-secure-enclave),
it says so and asks for no passphrase: the Touch ID alone, and the Mac's Secure Enclave opens
the keystore.

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
  you registered it, every repo and template switches to it; then the old key can go. Add
  `--backend se-cryptokit` to make the new key in the Mac's Secure Enclave (a `p256` key
  only), or `--backend software` to come back: a key never changes backend, so moving it is
  a rotation. `writ admin key list` ends with the backends this daemon has.
- `writ admin key add <id> … backend=se-cryptokit` declares a new key in the Secure Enclave;
  on a terminal, `add` asks for the backend when the daemon has more than one.
- `writ admin tls rotate` gives the HTTPS approval API a new key and certificate, in force at
  once. Add `--backend se-cryptokit` to make the key in the Mac's Secure Enclave, or
  `--backend software` to come back. Run over HTTPS, it replaces your own pin and checks it;
  over SSH, it prints the line to pin. Every other approver's `writ` is then refused until
  its `~/.writ/tls_pins` holds the new line: print it with `writd tls-fingerprint writd.yaml`
  on the daemon's host. If you think someone copied the daemon's boot tier, rotate, then
  re-pin from that command on the host, not from what `writ` printed: a copy of the old key
  could have answered for the daemon.
- `writ admin ca rotate` gives the daemon's SSH certificate authority a new key, in force at
  once: it signs the certificates of every lease approved from then on. Add `--backend
  se-cryptokit` to make the key in the Mac's Secure Enclave, or `--backend software` to come
  back. Leases approved before keep working until they end. `writ admin ca show` says which
  CA is in force and which older ones are still trusted, until when.
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

## The recovery key and the Secure Enclave

The passphrase opens the keystore. Two more ways in can be added, as entries of the policy's
`recipients` ([reference](policy-yaml.md#recipients-recipientsname)):

**A recovery key**, kept offline, opens everything if the passphrase or the Mac is lost.

```sh
writ recovery new          # prints the key once: write it down, then clear the screen
writ admin recipient add recovery recipient=<age1…>   # the line it printed, one signature
writ recovery check        # asks for the key, proves it opens the keystore
```

- Run `writ recovery new` on a machine that isn't online if you can: the key is printed,
  never saved. `age-keygen` makes one too.
- `writ recovery check` opens a challenge the daemon made for that key, on your machine.
  Nothing secret is sent. Run it from time to time: a key you can't find is no recovery.
- To replace it: `writ admin recipient set recovery recipient=<new age1…>`. The old key stops
  opening the keystore at once.

**A key in the Mac's Secure Enclave** (local mode on a Mac): the keystore then opens with no
passphrase, and tokens are unlocked by the Secure Enclave each time they are used.

```text
writ admin recipient add se-01 backend=se-cryptokit
```

- The recovery key must be declared first: one lost Mac must not lose every secret.
- From the next restart, `writ unseal` asks for no passphrase: only your signature.
- The last hardware key can't be removed. Going back to a passphrase is
  [`writd recover`](recovery.md), on the daemon's host.

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

With auto-unseal, the daemon opens itself after every start, with no one: no `writ unseal`.
It is off unless you turn it on, and it can be turned on only when nothing on the daemon's
Mac opens a secret without you:

- every signing key, every `ssh://` upstream key and the SSH CA in the Secure Enclave;
- the keystore opened by the Secure Enclave, with a recovery key kept offline (no passphrase);
- the tokens, which then are locked to the Secure Enclave and the recovery key.

The SSH host key, the TLS key and a notifier's token kept in the boot directory may stay
software: they only identify the daemon.

**The trade-off:** anyone who can restart the daemon, or takes the whole Mac, gets it
running without asking you. Leases still need your signature and fit their templates, and
every automatic start is logged and notified ("writd unsealed automatically").

### Turning it on, step by step

1. **See what is missing.** It says each thing, and the command that fixes it:

   ```text
   writ admin auto-unseal status
   ```

2. **The recovery key,** if you have none yet ([above](#the-recovery-key-and-the-secure-enclave)):
   `writ recovery new` on a machine that isn't online, written down, then
   `writ admin recipient add recovery recipient=<age1…>` and `writ recovery check`.
3. **The keystore on the Secure Enclave:** `writ admin recipient add se-01
   backend=se-cryptokit`. Unseal once by hand after it (`writ unseal`): from then on it asks
   for no passphrase.
4. **The CA and each key on the Secure Enclave:** `writ admin ca rotate --backend
   se-cryptokit`, and `writ admin key rotate <id> --backend se-cryptokit` for each key
   `status` names (register each new public half where the old one was: your remote's
   signing keys, its deploy keys).
5. **Check, then turn it on:**

   ```text
   writ admin auto-unseal status      # "Everything is in hardware"
   writ admin auto-unseal on          # one Touch ID
   ```

6. **Check the daemon took it:** restart it (`sudo launchctl kickstart -k system/dev.writ.writd`);
   its log says `unsealed automatically`, and `writ admin key list` answers with no
   `writ unseal`.

`writ admin auto-unseal on` is refused while anything is still in software, naming each one,
and so is a policy change that sets `unseal: auto` by hand. If something becomes software
again behind the daemon's back, it refuses to start and says what. To start it by hand
instead, put in force a policy with `unseal: approver` with [`writd recover`](recovery.md),
which takes the recovery key, never the Secure Enclave alone.

`writ admin auto-unseal off` turns it off: after the next start, the daemon waits for
`writ unseal` again.

The installer asks all this on a Mac (`make install`): what opens the keystore, the recovery
key, and auto-unseal when the CA and `agent-01` are on the Secure Enclave.
