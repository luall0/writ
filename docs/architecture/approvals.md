# Approvals

Code: `crates/writ-approval` (API), `crates/writ-crypto` (SSHSIG verification), `writ sign` /
`writ refuse` / `writ prove-key` / `writ unseal` in `crates/writ-cli`.

## Approval service

Approvals are **signer-agnostic**: an approval is an **SSHSIG** over the canonical lease
content, namespace `writ-approval`, made by any SSH key listed in the daemon's `approvers`
file (same format as git's `allowed_signers`) ([Q20](../decisions.md)).

| Approver | How it signs | When |
|---|---|---|
| `writ sign` on the Mac + **Secretive** | `ssh-keygen -Y sign -n writ-approval` through Secretive's agent → Touch ID | v1 |
| YubiKey FIDO2 (`sk-ssh-ed25519`) | Same command, touch on the key | Any time, also a good backup approver |
| Own Mac Secure Enclave app | Same SSHSIG format, own UI showing the lease | Later |
| iPhone app (Secure Enclave + Face ID) | Same SSHSIG format | Later |

- An approver key is Ed25519 or ECDSA P-256, or their security-key forms (`sk-…`); any other
  type in `approvers` fails the file at startup. A security-key signature must carry the
  user-presence flag (the key was touched), as sshd requires by default: a credential made
  `no-touch-required` is refused. A repeated option in `approvers` is refused.
- The daemon only verifies signatures; it never cares which tool produced them. Swapping
  Secretive for our own signer later is just adding a key to `approvers`.
- Use a **dedicated approval key** in Secretive, with "require authentication" on, and never
  temporarily unlocked. The namespace already prevents reusing a git signature as an
  approval, but a separate key keeps things clean.
- Notifications (a `Notifier`: Telegram in v1) only tell me something is waiting. A
  notification click is never an approval ([Q7/Q13](../decisions.md)).
- Admin changes (approvers, readers, templates, repo registry) and unsealing also require a
  signed approval ([admin changes](#admin-changes), [`writ unseal`](#writ-unseal)).

## `writ sign`: the trusted display

Secretive's Touch ID prompt doesn't show the ticket. `writ sign` must print the full ticket
(task, plan, repos, ops, branches, limits, templates, diff vs the previous revision) before
triggering the signature; it is the trusted display
([threat model, boundary 4](../threat-model.md#4-approvals-approver-signatures)).

- The ticket text is agent-written and possibly prompt-injected. Before printing it, `writ
  sign` neutralizes terminal control sequences and other invisible characters so an agent
  can't hide or overwrite part of the ticket on screen. Warnings (e.g. `direct_ssh` with an
  account-wide key) are printed by `writ sign` itself, never taken from the ticket.
- The display is bounded in both directions. Every row fits 78 columns (a non-ASCII
  character counted as two), so an 80-column terminal never wraps one: a longer line is cut
  into rows by `writ sign`, between words (only a word longer than a row is cut inside, so
  an id or a name never reads as two), each continuation behind the gutter, so a row the
  terminal made can't start with agent text that reads like one of `writ sign`'s
  (`  repos  …`). Each agent field shows at most 40 rows (runs of blank lines collapsed),
  then how many more there are (`writ sign --full` shows everything); the expected paths
  too, under their repository's enforced terms, one quoted item per line. Lists are quoted
  so two different lists never read the same.
- The enforced terms come in two parts, as the ticket gives them (M6.1.5): **the lease's
  terms once** ("The lease (enforced, for every repository)": repos, committer emails and
  name, signing key, rate, on violation), then **one block per repository** ("Repository
  <name> (enforced)": its template, operations, branches, force push, counts, expected
  paths).
- The enforced terms (id, templates, expiry, repos, operations, branches, force push,
  emails, expected paths with their count, limits, on violation) are repeated in a summary
  of one row each right before the prompt (a list too long for its row is cut, `… (see
  above)`): no amount of agent text can push what gets signed off the screen. A term that
  differs by repository reads `api: …; web: …` on its row, and the counts are the totals over
  the repositories (each repository's are in its block). A terminal narrower than 80 columns
  wraps rows again: approve from one at least that wide.
- `writ sign --yes` (sign without asking) needs a named ticket: it never signs whichever
  ticket happens to be the only one waiting.
- It signs exactly the canonical bytes it displayed (fetched from the daemon, then decoded and
  re-encoded locally to check they match).

### What `writ sign` shows beside the ticket

- **A renewal** (`renews`): which renewal of the work it is, the time every lease of the chain
  ran so far, what the renewed lease used of its counts and its state, the chain's original
  ticket as it was signed (its title, task and plan behind the gutter, its repos, branches and
  end), and the changes from the renewed lease's terms.
- **The estimate**: the agent's, phase by phase, beside the time the lease asks for
  ("35m in all (coding 20m, checks 5m, ci 10m); the lease asks 2h").
- **The other active leases from the ticket's source** (the daemon's record of where each
  ticket came from, never the agent's claim): 10 of them (`MAX_OTHERS`) with their id, time
  left, repos, branches and operations, `OVERLAP` on those with a repo in common and branch
  patterns that meet, and how many more. Overlapping leases come first: one is never the
  lease left out. Display only: `max_active_per_source` is what limits
  them.

All of it comes before the enforced terms, which stay last, right above the prompt.

`writ report <lease>` prints a lease's activity report ([closing](../flows.md#6b-closing-a-ticket)),
the same the agent got from `writ close`.

## Admin changes

After `writd init`, the policy (repo registry and templates), `approvers` and `readers` are
versions in force in the daemon's state (`writ-store`'s `authority` tables), bound to the
keystore by a MAC over their head (`writ_crypto::authority`, keyed by a sealed secret, checked
at unseal). They change only by:

- **`writ admin apply <target> <file>`**: `writ` fetches the version in force (`writ admin
  show`), shows what changes line by line (every line cleaned of what a terminal would act
  on), and signs a `writ-admin/2` document (`{daemon, target, version, previous, text}`: the
  daemon's SSH host key fingerprint, the number and the digest of the version it replaces, the
  new text, at most 100 KiB without control characters but newlines and tabs). The service
  checks the document and the approver's signature, that it names this daemon, and that
  `version` and `previous` are still the version in force: a change made meanwhile, a replay
  (versions only grow, so a change applies once, even when a later change brings the text
  back to what it replaced) and a change signed for another daemon are refused. The daemon
  checks the new text as a start would (it parses; an approver and a reader remain; no key is
  both; a template's signing key is held; a changed repo's mirror opens); then the `admin`
  line is written, the version and its head recorded under the MAC, and the change swapped in
  at once: the service's policy and approver keys, the gateway's readers (checked again at
  each SSH command and HTTPS request, so a removed reader is turned away on a live
  connection), the mirrors (`Mirrors::with_registry`: unchanged repos keep their mirror and
  its lock). The file `writd.yaml` names is written back. One change at a time.
- **Removing an approver takes back what it granted**: a change of `approvers` revokes, once
  in force, every active lease signed by a key it no longer holds, as the daemon revokes on a
  violation (the certificate barred first, a `revoke` line each naming the removed approver
  and the version, the lease's sessions dropped). `writ admin apply` lists the leases revoked.
  They are listed under the change's lock, before anything is written: a list the store can't
  give refuses the change (fail closed), rather than leaving them running.
  A policy that declares a signing key or an `ssh` upstream credential the keystore lacks
  makes the daemon create it before the checks (as its `keys.<id>` declares it, sealed to the
  keystore's recipient with its `.pub`, handed to the running signer through
  [`Signer::add_key`](signer.md#signer-interface)); the reply (`AdminApplied.created`) and
  the `admin` line give the id and public key of each key new to the signers, and `writ admin
  apply` prints them to register on the remotes. A key made for a change that then fails
  stays in the keystore and is loaded, not made again, by the next change that names it
  (and printed then).
- **`writd recover`** on the host, with the passphrase ([recovery](../operators/recovery.md)).

A file edited on the host is never applied: at the next start it is set aside
(`<file>.unapplied-<time>`, an `admin` line, done) and the text in force written back. A
version altered in the state without the keystore's key keeps the daemon sealed. The whole
state put back from an older copy is a restored backup: it carries a valid MAC.

## Reading the policy entry by entry

`writ admin repo|template|key|host list` and `show <name>` (M6.2) read the policy in force
with the reader key: `writ admin show policy`'s text, parsed by `writ` only to show it (with
the lowest `min_ttl` any daemon takes, so a policy in force always reads), each entry as the
canonical layout writes it (`PolicyConfig::entry_yaml`). Keys add `writ admin keys` (`GET
/v1/keys`, `KeysShown`): every declared key with its public half and fingerprint from the
signer that holds it (the agent keys' or the upstream one's), an OpenPGP key's fingerprint
and certificate as certified for the policy in force, a token only as added or not (never its
value or its digest), and what uses each. `key show <id> --public` prints the public half
alone (an OpenPGP key's certificate), for a pipe. A sealed daemon refuses these reads as it
refuses every other; like `writ admin show`, they write no audit line (they grant nothing and
reveal only public halves). Everything the daemon sends is shown escaped.

## Changing the policy field by field

`writ admin <noun> set <name> <field>=<value>…` and `remove <name>` (M6.2) build the new
policy text from the version in force, in Writ's canonical layout (`writ_core::config::edit`:
the entry's fields edited on a tree of the policy, read back whole with the daemon's checks,
then written by `PolicyConfig::to_yaml`), and sign it as `writ admin apply` does (the diff on
the trusted display, one `writ-admin/2` naming the version it replaces, so a change made in
between is refused). `field=value` replaces (a list by its comma-separated values; `field=`
empties it), `field+=value` and `field-=value` add one value to a list and take one from it
(one already listed, or not listed, is refused), `field!` unsets an optional field. What a
key is (`use`, `kind`, `format`, `algorithm`, `backend`) never changes: refused, naming `key
rotate`. The first such change of a hand-written policy writes it in the canonical layout
(its comments go), and says so. `remove` is refused while something uses the entry (a
template a repo names, a key a repo or a template uses, a host a repo needs), naming what; a
repo's removal lists the active leases that reach it; a key's asks for its id to be typed
again (a mistyped one sends nothing), since the change deletes it for good
([removing a key](signer.md#formats-algorithms-and-hashes)). Without a terminal, `remove`
refuses unless `--yes` answers its questions; the signature is asked for all the same. What
`writ` refuses here is a convenience: the daemon checks the text as it checks any change.

## The guided flows

`writ admin <noun> add <name> [<field>=<value>…]` asks each field in order, with its bounds and
default (`writ_core::config::edit::fields`), the ones given not asked, and only those the
entry needs (a template's branches with `commit_sign` or `push`, its committer emails and
signing key with `commit_sign`; a key's fields for its use and kind; a repo's `notes_ref`
with `ticket_link: notes`). Enter keeps what the prompt shows, `!` leaves an optional field
out, `none` empties a list. `edit <name>` asks the same, Enter keeping each current value
(what a key is is never asked: it doesn't change). A repo's credential is one the policy
declares for its URL's kind, or a new key declared in the same change (its id, and an SSH
key's algorithm; a token's host is the URL's). `template add --from <template>` starts from
another template's values. After the change, what to do next is said: a new key's public
half to register (a deploy key with write access), a token to add with `writ admin token`.
Without a terminal `add` asks nothing and refuses unless every required field is given,
naming the missing ones; `edit` refuses (`set` changes fields without one).

`writ admin key rotate <id> [--name <new>]` declares a new key like the old one (`<id>-2`, the
next number after a trailing one, or the name given), one signed change, its public half
printed to register; once it is registered (Enter), switches every repo and template that
used the old key to it, a second signed change (a signing key's leases then stop fitting
their template and are amended: the old public key stays registered for the commits it
signed); then offers to remove the old key. Without a terminal, `--yes` answers the question
between the two changes, and the old key stays declared, unused.

## The daemon's checks

Two operations reach out from the daemon at an approver's request (M6.2), each bounded in
number (10 a minute, daemon-wide) and logged.

**The host key scan** (`writ admin host add <host>` with no `keys=`, `writ admin host rescan
<host>`, and a guided `repo add` on a host with no pin) runs only on an approver's signature:
`writ` asks the daemon for a nonce (`writ admin scan-nonce`, `GET /v1/scan`: 16 bytes, used
once, for 5 minutes, at most 16 outstanding), signs a `writ-scan/1` document naming the daemon
(its host key's fingerprint), the host, the port and the nonce in the `writ-approval`
namespace, and sends it (`writ admin scan`, `POST /v1/scan`). A reader key alone can't make
the daemon reach a host, so the scan can't probe the daemon's network. The daemon checks the
document strictly, the signature against `approvers`, the daemon and the nonce (refused
`scan`, or `signature`), then makes one SSH handshake per key algorithm Writ verifies
(Ed25519, ECDSA P-256 and P-384) with its own SSH library (russh, `writ_mirror::scan`), each
asking for that algorithm alone, dropped once the host proved it holds the key and before any
authentication, within `mirrors.scan_timeout` (30 s by default). The keys come back with their
fingerprints, never pinned by the scan: `writ` shows them and asks whether they are the ones
the remote publishes, and only then signs a second change pinning them. A host offering only
RSA or P-521 keys answers none: its keys are given as `keys=` instead. The scan needs a
terminal, where the approver compares the keys; without one `host add` takes `keys=`.

`host rescan` is for a host whose keys changed (or to see whether they did): each key read is
shown against the pin (pinned, new), each pinned key no longer offered said as going, a pinned
RSA or P-521 key kept as it is (a scan can't read it; `host set <host> keys-=…` removes it);
once confirmed, one signed change replaces the pin. Nothing changes when the pin already holds
what the host offers.

**The upstream check** (`writ admin repo check <repo>`, `writ admin check <repo>`, `POST
/v1/repos/<repo>/check`, with a reader key) reaches only a repo the policy in force names,
with its credential, through the daemon's own git and the mirror's bounds, the mirror held
throughout: read access (`ls-remote`), the mirror synced (its object format the policy's), and
write access (`push --dry-run` of the mirror's branches onto upstream's: receive-pack answers,
nothing is sent). It stops at the first step that fails; what upstream says comes back
cleaned and bounded. A guided `repo add` runs it once Enter says the new credential is
registered on the remote; without a terminal it says the command to run.

## `writ admin token`

The `https://` upstreams' tokens and the notifiers' sealed tokens (`token.sealed`) reach the
keystore from the Mac, never in clear on the daemon host's disk.
`writ admin token <id> [--yes]`:

1. reads the keystore's public recipient from `writ info` (over the pinned channel, so it is
   the daemon's), and the digest of the token file in force (`writ admin token <id>` asks
   `GET /v1/tokens/<id>`: the digest, or none; never the token);
2. reads the token (no echo; one line of stdin when it isn't a terminal), encrypts it to the
   recipient (age, armored), and wipes its copies;
3. signs a `writ-token/2` document `{daemon, id, previous, sealed}` with the approval key:
   `daemon` the daemon's SSH host key fingerprint, `previous` the digest of the
   `tokens/<id>.age` it replaces (`none` for a first one), `sealed` the armored ciphertext (at
   most 8 KiB);
4. sends the document and its SSHSIG (`POST /v1/tokens`).

The service checks the daemon is open, the document decodes strictly and names this daemon,
the signer is an approver in force, and `previous` is still the file in force (a replay, or a
token changed meanwhile, is refused: each file is encrypted afresh, so its digest never comes
back; only `none` could, were a token file removed by hand on the host). The daemon checks the id is a token the policy declares (`kind: token`) or a sealed
notifier uses, opens the ciphertext with the keystore's identity (kept open after unseal) and
checks it is a token; then the `admin` line is written (the id, both digests, the approver:
never the token), `tokens/<id>.age` written (the old one replaced), and the token used at
once: the mirrors of the repos that use it reopen (`Mirrors::with_tokens`), the notifier with
that token starts or takes it. The development keystore refuses it (its tokens are files the
operator writes, `<keys>/tokens/<id>`).

An `https://` repo whose token isn't in the keystore yet doesn't stop the unseal: its mirror
is served, and its syncs and pushes are refused with "add it with `writ admin token <id>`".
A sealed notifier without its token stays off, with a warning at unseal.

Routes: `GET /v1/admin/<target>`, `POST /v1/admin` (SSH: `writ admin show <target>`,
`writ admin apply`); `GET /v1/tokens/<id>`, `POST /v1/tokens` (SSH: `writ admin token show
<id>`, `writ admin token apply`); `GET /v1/keys` (SSH: `writ admin keys`).

## `writ unseal`

A sealed daemon ([Flows § 7](../flows.md#7-daemon-startup-sealed)) answers only `writ info`
and `writ unseal`. `writ unseal [--approval-url] [--key] [--agent]` reads the boot to unseal
from `writ info` (the daemon's host key fingerprint, this start's nonce), asks for the
keystore's passphrase (one line of stdin when it isn't a terminal), signs the `writ-unseal/1`
document `{daemon, nonce}` with the approval key, and sends the three over the pinned
channel. A signature is good for one start of one daemon: replayed after a restart, or sent to
another daemon, it is refused. The passphrase travels in the request body only, is wiped once
read on both sides, and is never logged; a wrong one is refused after the signature was
checked. Both halves are needed: the passphrase alone, or the signature alone, opens nothing.

## Reaching the daemon

The approval API has two transports, each enabled or disabled in `writd.yaml`
(`transports.approvals.ssh`, `transports.approvals.https`; not both disabled), with the same
commands, bodies and replies ([Q29](../decisions.md)):

- **SSH** on its own listener (port 2223 in detached mode): `writ` pins the daemon's host key
  in `~/.writ/known_hosts` and connects as user `writ` with its **reader key**.
- **HTTPS** (port 8443): TLS 1.3 with the daemon's self-signed certificate, pinned by its
  SHA-256 fingerprint in `~/.writ/tls_pins` (`writd tls-fingerprint` prints it; no
  certificate authority is trusted), and a client certificate made from the reader key
  (mutual TLS). Routes: `GET /v1/info`, `GET /v1/tickets[?all=true]`,
  `GET /v1/tickets/<id>`, `POST /v1/tickets/<id>/approve`, `…/refuse`, `…/revoke`,
  `POST /v1/proofs`; JSON
  bodies, replies in the `{"ok"}` / `{"error"}` envelope (HTTP 200, or 422 when the
  command failed, 404 for an unknown route). Each request runs on its own task, to its end
  even when the client goes away (Ctrl-C during `writ unseal` or `writ admin apply`): a
  change is never left half applied, only its reply is lost (SSH commands run so already).

`writ` picks the transport from `WRIT_APPROVAL_URL` (`ssh://…`, `unix:…` or `https://…`).

**Only readers reach the API.** The reader key is an Ed25519 client key `writ reader`
generates on the approver's machine (`~/.writ/reader`, 0600) and prints as a line for the
daemon's `readers` file (`<name> ssh-ed25519 …`). It is never the approval key: Secretive's
key is only ever used through `ssh-keygen -Y sign` (hard rule 8). Without it, anyone who
reached the listener could read every ticket (task, plan, repos, leases). The connection
still grants nothing: approvals (and, with `decisions: signed`, refusals and revocations)
are SSHSIGs the approval service verifies. `writ ls --all` returns the 200 most recent
tickets. Commands: `writ info`, `writ ls [--all]`, `writ show <id>`, `writ approve <id>`,
`writ refuse <id>`, `writ revoke <id>`, `writ prove` (`writ_proto::Command`). Signatures are made with
`ssh-keygen -Y sign -U -n writ-approval -f <approval key .pub>` against the approver's agent
socket (`WRIT_APPROVAL_AGENT`, else `SSH_AUTH_SOCK`): only the dedicated approval key is used,
`-U` makes ssh-keygen sign with the agent only (never a private key file beside the `.pub`),
and ssh-keygen runs by its absolute path (`/usr/bin/ssh-keygen`, or `WRIT_SSH_KEYGEN`) with a
clean environment, never found through `PATH`. Text from the daemon or from ssh-keygen is
escaped like agent text before it reaches the terminal.

## Refusing and revoking

`writ sign` can also **refuse with feedback** (or `writ refuse <id> -m …`). A refusal can't
grant anything. Whether it needs a signature is the daemon's `decisions` setting:

- `signed` (default): an SSHSIG over the canonical `writ-refusal/1` document (ticket id and
  feedback), one Touch ID. Revocations the same, over `writ-revocation/1`.
- `open`: any reader may refuse or revoke without a signature; a signature that is given is
  still checked. The daemon records who signed a refusal: an unsigned one reaches the agent
  labeled as such (`writ wait` says the feedback may not be the approver's words), and its
  feedback enters the revision as `[not signed by an approver] …`. A residual risk (denial of service only,
  [threat model](../threat-model.md#residual-risks-v1)).

The feedback goes back to the agent and is shown next to its next revision, labeled as
recorded by the daemon. `writ revoke` on a pending ticket withdraws it.

## Proving a signing key to a remote

A remote shows a commit as **verified** when its signing key is registered on the account and
the committer email is one of the account's ([M4.1](../history/m4.1-real-end-to-end-scenarios.md)).
`writd signing-keys <writd.yaml>` prints each agent signing key, to add on the account as a
**signing** key. GitHub asks for nothing more. Forgejo and Gitea ask for a **proof**: a
challenge (a 64-hex token, shown in the web UI only) signed with the key, in namespace
`gitea`. The key never leaves the daemon, which signs commits only through the policy, so the
proof goes through it, and is an **approval**, like a ticket ([Q35](../decisions.md)):

```sh
echo -n '<token>' | writ prove-key <key id> --namespace gitea    # in place of ssh-keygen -Y sign -n gitea
```

1. On the approver's machine, `writ prove-key` reads the remote's message on stdin (exactly as
   given, no newline added or removed, 1 to 4 KiB of UTF-8) and shows the key, the namespace
   and the message on stderr, escaped like agent text (newlines and hidden characters as
   `\u{…}`). It asks on the terminal (`/dev/tty`: stdin holds the message), or signs at once
   with `--yes`.
2. The approval key signs the canonical `writ-proof/1` document (`{"kind":"writ-proof/1",
   "key":…,"namespace":…,"message":…}`, namespace `writ-approval`): one Touch ID. Its own
   `kind` keeps a proof from ever passing for a ticket approval, a refusal or a revocation,
   and any of them from passing for a proof.
3. The approval API (`writ prove`, `POST /v1/proofs`, SSH or HTTPS: a reader key reaches it,
   and gets nothing without the approver's signature, whatever `decisions` says) reads the
   document strictly (canonical bytes only), checks the namespace (never `git`, which would
   make commit signatures outside the policy and the ledger, nor `writ-approval` or anything
   starting with `writ`, in any case), the message's size, the key (one a template signs
   commits with: never an upstream credential, the CA or the host key) and the approver's
   signature over exactly those bytes.
4. The daemon signs the message through the `Signer` (outside the state lock, like a commit),
   writes one `prove` audit line (the key, the namespace, the message's SHA-256, the approver;
   never the message), and only then returns the armored signature, which `writ prove-key`
   checks against the key's public half and prints alone on stdout, to paste in the remote's
   form.

**An OpenPGP key** (`format: openpgp`) proves itself the way Forgejo's and Gitea's GPG key
check asks: the account's challenge (`/user/gpg_key_token`) signed as an OpenPGP detached
signature, the key's certificate (`writd signing-keys`) added with it. The proof goes
through the same approval; the namespace is still named and checked, but an OpenPGP
signature carries none, so a message that starts like a git commit or tag (`tree `,
`object `) is refused: it could pass as a commit signature. `writ prove-key` prints the
armored OpenPGP signature as is (it doesn't verify OpenPGP itself: the remote does).

A replayed proof only repeats itself: the same key signs the same message in the same
namespace. Nothing on the daemon host is needed, and it works the same with the sealed
keystore (M5).

## Narrowing

`writ sign` can **narrow** the ticket before signing (interactive, or flags such as
`--ttl 2h`, `--drop-repo`). The signature covers the narrowed ticket; the daemon checks it
only narrows what was submitted (strict subset, [Q26](../decisions.md)) and returns the final
lease to the agent. No dedicated app needed in v1.

The whole exchange is [Flows § 1](../flows.md#1-ticket-submit-review-sign-or-refuse).

`writ sign` prints the ticket with every agent-written field behind a `│` gutter, control,
bidi and invisible characters shown as `\u{…}`, then the changes since the previous revision
(or from the lease terms an amendment replaces), then what the narrowing flags changed, and
asks `[y]es / [n]o / [r]efuse`. Narrowing flags: `--ttl`, `--drop-repo`, `--drop-op`,
`--branch`, `--drop-email`, `--max-signatures`, `--max-pushes`, `--max-ops-per-minute`,
`--max-push-size`, `--no-force-push`, `--revoke-on-violation`; each can only narrow.

The flags on a repository's terms (`--drop-op`, `--branch`, `--max-signatures`,
`--max-pushes`, `--max-push-size`) take `<repo>:<value>` for one repository, or the value
alone for every one (repeatable; no registry name, branch pattern, operation or size holds
a `:`):

- `--drop-op web:push` drops push in `web`; `--drop-op push` wherever the ticket asks for it
  (refused if it asks for it nowhere).
- `--branch api:agent/x` replaces `api`'s branches with those named for it; `--branch
  agent/x` replaces the branches of every repository no `--branch` names, among those that
  have branches (a fetch-only repository has none to narrow, and giving it one would widen).
- `--max-pushes api:2` lowers `api`'s count, refused above the ticket's; `--max-pushes 2`
  caps every repository's at 2, never raising one, never refused.
- A repository the ticket doesn't name is refused (`--branch dotfiles:…: the ticket doesn't
  name repo dotfiles`); `--drop-repo` leaving no repository is refused (refuse the ticket
  instead).

The lease-wide flags (`--ttl`, `--drop-repo`, `--drop-email`, `--max-ops-per-minute`,
`--no-force-push` for every repository, `--revoke-on-violation`) take no repository. Each
repository's template, and the signing key, never change.
