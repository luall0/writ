# Sealing, unsealing and recovery

The daemon keeps every secret it holds (the CA key, the agent signing keys, the upstream
credentials and tokens) in a **sealed keystore**: each secret its own age file, opened only
when an approver unseals the daemon. This page is what an operator does about it: making the
keystore, choosing where the notification token lives, unsealing after each start, getting
access back when a key is lost, and (from M7.6) starting without a human.

## Making the keystore

Once, on the daemon host, as the daemon's user, beside a `writd.yaml` whose `keystore` is
`sealed` ([reference](writd-yaml.md)):

```sh
writd init writd.yaml
```

It asks for the passphrase twice (12 characters at least; keep it in a password manager: it
opens every secret, and nothing recovers a lost one), and prints what to pin on the clients
and register on the remotes. The two directories it fills:

- `keystore.sealed.dir`: every secret, encrypted. A copy of it alone reveals no key.
- `keystore.sealed.boot`: the **boot tier**, the keys the daemon authenticates itself with
  before it is unsealed (the SSH host key, the HTTPS approval API's TLS key). Readable at
  start, by design. Keep it apart from the keys directory where you can (another volume, a
  Docker secret): a copy of it, together with an intercepted `writ unseal`, would let someone
  pose as the daemon and receive the passphrase ([threat model](../threat-model.md#residual-risks-v1)).

## The notification token: boot or sealed

`notifiers[].telegram.token` has no default: you choose.

| | `token: { boot: <file> }` | `token: { sealed: <id> }` |
|---|---|---|
| Where | A file of its own (the token alone, mode 0600), in the boot tier's directory | Sealed with the other secrets (`writ admin token <id>`) |
| After a restart | "writd started, sealed" at once | Nothing until unsealed |
| After `writ unseal` | "writd unsealed", from the real daemon only: if `writ unseal` said it worked and no such message comes, something answered in the daemon's place | "writd unsealed" |
| If the boot tier is copied | Whoever has it can send messages as the bot | Nothing |

`boot` suits a daemon that restarts unattended (you want to know it is waiting); `sealed`
suits one where the bot's token matters more than a missed restart.

## Unsealing

After every start the daemon is sealed: every request but `writ info` and `writ unseal` is
refused with "daemon sealed", and logged. On your machine, with the approval key in its agent:

```sh
writ unseal
```

It shows the daemon and the start it unseals, asks for the passphrase, and asks your approval
key for one signature (Touch ID with Secretive). Both are needed: the signature is checked
first, then the passphrase. A signature is good for that start of that daemon only. Active
leases are served again as soon as it is open; their certificates still expire when they did.

## Changing the policy, the approvers or the readers

After `writd init`, `policy.yaml`, `approvers` and `readers` change only through signed admin
changes, applied at once:

```sh
writ admin show approvers > approvers     # the version in force
$EDITOR approvers
writ admin apply approvers approvers      # shows what changes, then one signature
```

The daemon writes the text in force back to its files on the host; editing them there changes
nothing (a hand edit is set aside at the next start, never applied).

## Getting access back

The whole guide is [recovery](recovery.md). In short, to keep from locking yourself out:

- enroll a **second approver key** from the start (a YubiKey, `sk-ssh-ed25519`), and a second
  reader key on another machine;
- if every approver or reader key is lost anyway: `writd recover <writd.yaml>
  <policy|approvers|readers> <file>` on the daemon host, as its user, with the daemon stopped.
  It asks for the keystore's passphrase, checks the file like an admin change, puts it in force
  and logs it. It is also the way to apply a file you edited on the host. It needs both the
  host and the passphrase, which together open every secret already, so it gives nobody
  anything new. On macOS's local mode it runs as `_writd`, in Docker in a one-off container:
  [the platforms](recovery.md#the-daemons-user-on-each-platform).
- if the passphrase is lost too, the keystore can't be opened: a new `writd init`, new keys to
  register on the remotes, the leases gone. M7.6's recovery identity (below) is the safeguard.

## Starting without a human: auto-unseal (M7.6)

Not in this build: [M7.6](../roadmap.md#m76--hardware-wrapped-secrets) brings it, with a
step-by-step guide here. What it will require, so you can plan for it:

- **Opt-in:** `unseal: auto` in `writd.yaml`. Never the default.
- **Hardware for everything that can open or use a secret,** so nothing on the host opens one
  without a human:
  - every signing key in a hardware backend: the agent signing keys, the `ssh://` upstream
    credentials, the CA key;
  - every secret in the store wrapped only to hardware recipients (the Secure Enclave, a TPM,
    a YubiKey, a cloud KMS): the upstream tokens, the key protecting the authority files, the
    keystore's identity itself;
  - except the notification token (it may stay in the boot tier) and the boot tier's
    transport keys (the SSH host key, the TLS key), which may stay software files; keeping
    them in hardware too is possible and recommended.
- **A recovery identity** made and checked first: an age identity kept offline (paper, a spare
  device), to which every secret is also wrapped. It alone recovers the keystore if the
  hardware is lost, and `writd recover` takes it instead of a passphrase in this mode (never
  the hardware alone: host access must not replace signed admin changes).
- **Refused, never adjusted:** if anything above is still software, the daemon refuses to
  start and names each key or secret that isn't hardware-protected.
- **What you give up:** anyone who can restart the daemon, or who takes the whole machine with
  its hardware, gets a running daemon without asking you. Leases still need your signature and
  fit their templates; the start is logged (`unseal`, "automatic") and notified.
