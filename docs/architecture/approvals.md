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
- **The one grant with no approval** (M7.9.7): a fetch-only ticket that names an
  `unsigned_fetch` template for each of its repositories is granted when submitted, never
  pending, so never shown to `writ sign` or the popup and never notified. Its approval is the
  signed policy change that made the template and named it in the repo
  ([lease model](../lease-model.md#granted-with-no-signature-m797)). Approving one is refused
  (it isn't pending), and so is any signature over such a ticket. Removing an approver revokes
  the leases that approver signed; an unsigned lease has none, and ends when its template stops
  allowing it.

## `writ sign`: the trusted display

Secretive's Touch ID prompt doesn't show the ticket. `writ sign` must print the full ticket
(task, plan, repos, ops, branches, limits, templates, diff vs the previous revision) before
triggering the signature; it is the trusted display
([threat model, boundary 4](../threat-model.md#4-approvals-approver-signatures)).

- The ticket text is agent-written and possibly prompt-injected. Before printing it, `writ
  sign` neutralizes terminal control sequences and other invisible characters so an agent
  can't hide or overwrite part of the ticket on screen. Warnings (e.g. an expected path
  outside the repository's terms) are printed by `writ sign` itself, never taken from the ticket.
- The display is bounded in both directions. Every row fits 78 columns (a non-ASCII
  character counted as two), so an 80-column terminal never wraps one: a longer line is cut
  into rows by `writ sign`, between words (only a word longer than a row is cut inside, so
  an id or a name never reads as two), each continuation behind the gutter, so a row the
  terminal made can't start with agent text that reads like one of `writ sign`'s
  (`  repos  …`). Each agent field shows at most 40 rows (runs of blank lines collapsed),
  then how many more there are and the command that shows everything (`writ sign <id>
  --full`). An enforced term is never cut: the expected paths are shown whole, under their
  repository's enforced terms, one quoted item per line (the ticket's bounds keep them
  displayable: 100 paths, 16 KiB, per repository; the review after M7.6, `U-1`: the agent
  chose which paths fell past row 40). Lists are quoted so two different lists never read
  the same.
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
- Every field of the ticket is displayed: `display::ticket` and `display::summary` destructure
  the ticket's types with no `..`, and a test changes each leaf of a ticket's canonical JSON
  in turn and checks the display changes
  (`every_leaf_of_a_ticket_changes_what_writ_sign_shows`): a field added later can't be
  signed unseen.
- The diff sections ("Changes since revision …", "from the terms in force of lease …", "of
  lease …, renewed", "Narrowed by you") list the agent's words first, each side cut at 40
  rows like a field unless `--full`, and the enforced terms last, nearest the prompt, never
  cut. A term that is a set (repos, committer emails, operations, branches, expected paths)
  is shown as its items removed (`-`) and added (`+`), each whole, then how many stay
  (`(41 kept)`), never as both whole lists (M7.9.5); over several repositories, or one
  swapped for another, a per-repository term changes once per repository whose value differs,
  under its name (`operations (web)`, `max pushes (web)`). The ticket's lists are
  sets, so neither an order nor a repetition is a term to show
  (`a_set_change_shows_only_the_items_it_removes_and_adds`,
  `over_several_repositories_each_change_names_its_repository`).

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
  patterns that meet, `no signature (unsigned_fetch)` on a lease granted with none, and how
  many more. Overlapping leases come first: one is never the
  lease left out. Display only: `max_active_per_source` is what limits
  them.

All of it comes before the enforced terms, which stay last, right above the prompt.

`writ report <lease>` prints a lease's activity report ([closing](../flows.md#6b-closing-a-ticket)),
the same the agent got from `writ close`. Its agent text and warnings show 40 rows each, then
how many more and `writ report <lease> --full`, which shows them all (`writ close --full`
for the agent: a lease closes once, so its cut report names `writ report`).

## Admin changes

After `writd init`, the policy (repo registry and templates), `approvers` and `readers` are
versions in force in the daemon's state (`writ-store`'s `authority` tables), bound to the
keystore by a MAC over their head (`writ_crypto::authority`, keyed by a sealed secret, checked
at unseal). They change only by:

- **`writ admin apply <target> <file>`**: `writ` fetches the version in force (`writ admin
  show`), shows what changes line by line (two lines of context, each run of changes under
  the lines that enclose it, `@@ templates: / feature:`; every line cleaned of what a
  terminal would act on and cut to the display's width; the lines both texts share at their
  start and end set aside, and a change still past 4,000,000 compared cells refused, to be
  split, never shown as the whole new text), and signs a `writ-admin/2` document (`{daemon, target, version, previous, text}`: the
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

`writ admin repo|template|key|host|proxy list` and `show <name>` (M6.2; `proxy` M7.2) read the policy in force
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
signing key with `commit_sign`; a key's fields for its use and kind, and its `backend` once
the daemon has more than one, offered with the algorithms each makes (M7.5: the reply to
`writ admin key list` names them, `backends`; a new credential a guided `repo add` declares
is asked its backend too), asked before the algorithm, which is then offered among the ones
that backend makes (its first one the default when it makes no `ed25519` key) and asked
again when the backend doesn't make it; a repo's `notes_ref` with `ticket_link: notes`). Enter keeps what the prompt shows, `!` leaves an optional field
out, `none` empties a list. `edit <name>` asks the same, Enter keeping each current value
(what a key is is never asked: it doesn't change). A repo's credential is one the policy
declares for its URL's kind, or a new key declared in the same change (its id, and an SSH
key's backend then its algorithm; a token's host is the URL's). `template add --from <template>` starts from
another template's values. After the change, what to do next is said: a new key's public
half to register (a deploy key with write access), a token to add with `writ admin token`.
A guided `repo add` whose templates let no unsigned fetch asks last whether agents may fetch
the repo with no signature (M7.9.7, no by default): a yes adds the policy's `unsigned_fetch`
template to the repo, or makes one (`fetch_unsigned`, or the next free name: fetch only,
`max_ttl: 15m`) in the same change, which names it.
Without a terminal `add` asks nothing and refuses unless every required field is given,
naming the missing ones; `edit` refuses (`set` changes fields without one).

`writ admin key rotate <id> [--backend <name>] [--name <new>]` declares a new key like the old
one, on the backend named (`software`, `se-cryptokit`; the old one's by default: a key never
changes backend, so moving one is a rotation; `writ` refuses a backend the daemon doesn't
list, or one that doesn't make the key's algorithm, before the signature is asked for) (`<id>-2`, the
next number after a trailing one, or the name given), one signed change, its public half
printed to register; once it is registered (Enter), switches every repo, proxy and template
that used the old key to it, a second signed change (a signing key's leases then stop fitting
their template and are amended: the old public key stays registered for the commits it
signed); then, once nothing uses the old key, offers to remove it, or says what still uses
it. `--yes` answers the question between the two changes, on a terminal or not, and the old
key stays declared, unused.

## The daemon's checks

Two operations reach out from the daemon at an approver's request (M6.2), each bounded in
number (10 a minute, daemon-wide) and logged.

**The host key scan** (`writ admin host add <host>` with no `keys=`, `writ admin host rescan
<host>`, and a guided `repo add` on a host with no pin) runs only on an approver's signature:
`writ` asks the daemon for a nonce (`writ admin scan-nonce`, `GET /v1/scan`: 16 bytes, used
once, for 5 minutes, at most 16 outstanding), signs a `writ-scan/1` document naming the daemon
(its host key's fingerprint), the host, the port, the nonce and, for a host behind a proxy of
the policy (M7.2, `proxy=<name>` or `--proxy`), that proxy, in the `writ-approval`
namespace, and sends it (`writ admin scan`, `POST /v1/scan`). A reader key alone can't make
the daemon reach a host, so the scan can't probe the daemon's network. The daemon checks the
document strictly, the signature against `approvers`, the daemon and the nonce (refused
`scan`, or `signature`), writes the scan's `scan` line (allowed, `<host>:<port>: scanning`,
with the approver) before it connects out, refusing the scan when the log can't take it (the
review after M7.6: no line, no connection), then makes one SSH handshake per key algorithm Writ verifies, each connection opened
through the named proxy when there is one ([gateway](gateway.md#through-a-proxy)) and refused
when the policy in force declares no such proxy or lacks its password,
(Ed25519, ECDSA P-256 and P-384) with its own SSH library (russh, `writ_mirror::scan`), each
asking for that algorithm alone, dropped once the host proved it holds the key and before any
authentication, within `mirrors.scan_timeout` (30 s by default). The keys come back with their
fingerprints, never pinned by the scan: `writ` shows them and asks whether they are the ones
the remote publishes, and only then signs a second change pinning them. A host offering only
RSA or P-521 keys answers none: its keys are given as `keys=` instead. The scan needs a
terminal, where the approver compares the keys; without one `host add` takes `keys=`.
Before a scan `host add` or `repo add` makes, when no `proxy=<name>` was given and the policy
in force declares proxies, `writ` asks which one the scan goes through (Enter: none, the host
reached directly); in `repo add` the answer is the repo's `proxy`, not asked again. A direct
scan that fails says how to go through a proxy: the ones in force to give as `proxy=<name>`
(`--proxy <name>` for `host rescan`), or, when there is none, `writ admin proxy add` first
(the daemon only dials a proxy the policy in force declares, so one can't be declared in the
same change as the scan through it).

`host rescan` is for a host whose keys changed (or to see whether they did): each key read is
shown against the pin (pinned, new), each pinned key no longer offered said as going, a pinned
RSA or P-521 key kept as it is (a scan can't read it; `host set <host> keys-=…` removes it);
once confirmed, one signed change replaces the pin. Nothing changes when the pin already holds
what the host offers.

**The upstream check** (`writ admin repo check <repo>`, `writ admin check <repo>`, `POST
/v1/repos/<repo>/check`, with a reader key) reaches only a repo the policy in force names,
with its credential, through the daemon's own git and the mirror's bounds, the mirror held
throughout: read access (`ls-remote`), the mirror synced (its object format the policy's), and
write access (a `push --dry-run` deleting a ref no remote holds: receive-pack answers, nothing
is sent, an empty repository passing too). It stops at the first step that fails; what upstream says comes back
cleaned and bounded. A guided `repo add` runs it once Enter says the new credential is
registered on the remote; without a terminal it says the command to run. While it runs,
`writ` asks the mirror's sync status every 2 s on the same connection (a second channel) and
shows the sync running, if one is: on a terminal one line rewritten in place, cut to 78
columns; otherwise a line a minute. A daemon that can't say (an older one) shows nothing.

**The sync status** (`writ admin repo status [<repo>]`, `writ admin status [<repo>]`,
`GET /v1/repos/status`, `GET /v1/repos/<repo>/status`, with a reader key): each registered
repo, or the one named, with the sync running (waiting for a slot or fetching, first or not,
for how long and its limit, the bytes downloaded of `mirrors.max_fetch`, git's phase and
counts) and how the last one ended since the daemon started
([gateway](gateway.md#repo-mirrors)). A read from memory, like `writ admin show`: no
audit line. Each repo's status in rows of at most 78 columns (a long one wraps, so its
progress is never cut away); its text (a failure's reason) cleaned.

## `writ admin token`

The `https://` upstreams' tokens and the notifiers' sealed tokens (`token.sealed`) reach the
keystore from the Mac, never in clear on the daemon host's disk.
`writ admin token <id> [--yes]`:

1. reads the keystore's public recipient from `writ info` (over the pinned channel, so it is
   the daemon's), and what is in force for the id (`writ admin token <id>` asks
   `GET /v1/tokens/<id>`): its change count (how many token changes of it the daemon
   applied) and the digest of its token file, or none; never the token;
2. reads the token (no echo; one line of stdin when it isn't a terminal), encrypts it to the
   recipient (age, armored), and wipes its copies;
3. signs a `writ-token/3` document `{daemon, id, version, previous, sealed}` with the
   approval key: `daemon` the daemon's SSH host key fingerprint, `version` the id's change
   count, `previous` the digest of the `tokens/<id>.age` it replaces (`none` for a first
   one), `sealed` the armored ciphertext (at most 8 KiB);
4. sends the document and its SSHSIG (`POST /v1/tokens`).

The service checks the daemon is open, the document decodes strictly, the signer is an
approver in force, and the document names this daemon. The daemon checks the id is a token
the policy declares (`kind: token`) or a sealed notifier uses, opens the ciphertext with the
keystore's identity (kept open after unseal; the keystore's state held, so a rotation of the
data key waits) and checks it is a token. Then, under the service's state lock: `version`
must be the id's change count and `previous` the file in force (a replay, or a token changed
meanwhile, is refused), the `admin` line is written (the id, the count it makes, both
digests, the approver: never the token), the count bumped in the state, `tokens/<id>.age`
written (the old one replaced) with the token sealed again by the daemon to the recipients in
force (a token a client sealed to recipients read before a rotation is never stored readable
by one taken out), and the token used at once: the mirrors of the repos that use
it reopen (`Mirrors::with_tokens`), the notifier with that token starts or takes it. The
count only grows and is kept by the id (ASCII lowercase) even when the id leaves the policy
and its file is deleted with it: a digest of content can come back (`none`, once the file is
gone), a count can't, so a change applies once (the review after M7.6, A-6; `writ-token/2`,
which had no count, is refused). The development keystore refuses it (its tokens are files
the operator writes, `<keys>/tokens/<id>`).

An `https://` repo whose token isn't in the keystore yet doesn't stop the unseal: its mirror
is served, and its syncs and pushes are refused with "add it with `writ admin token <id>`".
A sealed notifier without its token stays off, with a warning at unseal.

Routes: `GET /v1/admin/<target>`, `POST /v1/admin` (SSH: `writ admin show <target>`,
`writ admin apply`); `GET /v1/tokens/<id>`, `POST /v1/tokens` (SSH: `writ admin token show
<id>`, `writ admin token apply`); `GET /v1/keys` (SSH: `writ admin keys`).

## `writ admin tls rotate`

The HTTPS approval API's key and its self-signed certificate (`tls-01` in the boot tier) are
replaced by an approver's signed change, on a running, unsealed daemon (M7.5): `writ admin
tls rotate [--backend <name>]`. The same command moves the key between backends (`software`,
`se-cryptokit` on a Mac) and rotates it on its own.

- `writ` asks `tls show` (`GET /v1/tls`, `TlsShown`): the daemon's host key fingerprint, the
  certificate in force, its key's backend and the daemon's backends. A backend it doesn't
  list, or one that makes no P-256 key, is refused before the signature is asked for.
- The approver signs `writ-tls/1` (`{daemon, replaces, backend}`) in the `writ-approval`
  namespace; `writ` sends it (`tls rotate`, `POST /v1/tls`, `TlsRequest`). The service decodes
  it strictly, checks the signature against `approvers` and the daemon (refused `tls` or
  `signature`); one admin change at a time.
- The daemon refuses it unless `replaces` is the certificate in force (so the same document
  sent again rotates nothing), then counts it against the rotations' rate (five a minute
  daemon-wide, shared with the CA's: a replay, refused before, takes no rotation's place),
  makes the new key on the backend (software: generated; a
  device: `create_key` on a helper signer of its own), signs its certificate through it, and
  writes the key, its public half (a device's) and the certificate beside the old ones as
  `.new`, the certificate last. It builds the new identity from them (a failure drops them and
  keeps the old), renames each over the old one, then puts it in force: every handshake from
  then on gets the new certificate, the connections open keep theirs (the reply goes back
  over the old one). A start finding a `.new` certificate finishes the renames; `.new` files
  without one are dropped. One `admin` line (`TLS key rotated: certificate <old> replaced by
  <new>, its key on backend <name>`, or `not rotated` with the reason), and the notifiers told.
- **The pin:** over HTTPS, `writ` replaces the line for this daemon in `tls_pins` (only the
  line that names it with the old pin, the file written whole then renamed), says so, and
  connects again with the new pin; over SSH it prints the line to pin. Every other approver's
  machine is refused until it re-pins, from that line or `writd tls-fingerprint` on the host.
  The old certificate vouches for the new one in the reply: after a suspected copy of the
  boot tier, re-pin from the host instead ([threat model](../threat-model.md#residual-risks-v1)).
- `writd init --tls-backend <name>` makes the first key on that backend (the installer asks
  it on a Mac).

## `writ admin ca rotate`

The SSH certificate authority's key, which signs each lease's certificate, is replaced by an
approver's signed change on a running, unsealed daemon (M7.6): `writ admin ca rotate
[--backend <name>]`, which moves it between backends (`software`, `se-cryptokit` on a Mac) or
rotates it on its own. `writ admin ca show` (`GET /v1/ca`, `CaShown`) gives the CA in force,
its backend, the CAs it replaced still trusted, and the daemon's backends.

- The approver signs `writ-ca/1` (`{daemon, replaces, backend}`, `replaces` the CA key's
  fingerprint) in the `writ-approval` namespace (`ca rotate`, `POST /v1/ca`, `CaRequest`).
  The service decodes it strictly, checks the signature against `approvers` and the daemon
  (refused `ca` or `signature`); one admin change at a time.
- The daemon refuses it unless `replaces` is the CA in force (a replay rotates nothing, and,
  refused before the rotations' rate counts it, takes no rotation's place: five a minute,
  shared with the TLS key's) and a backend it has, and refuses a software backend while `unseal: auto` is in force (the next
  start would refuse itself; the review after M7.6, D-2). It makes the new key (software:
  Ed25519, generated; a device: P-256, by the device), builds its signer (a key its device
  refuses: nothing written), stages `ca.age`, `ca.pub` and `ca.backend` beside the old as
  `.new`, writes its `admin` line (`SSH CA rotated: <old> replaced by <new>, its key on backend
  <name>`; refused when the log can't take it, nothing in force changed: S-2), then moves the
  key in, the point of no return, and the two others after it. A start finishing a cut
  rotation moves the public half and the marker after the key, its own line in the audit log
  then; one cut before the key moved is dropped. A failure after the point of no return is
  answered as a rotation and noted "rotated, but …", never "not rotated" (D-4). At each
  unseal the marker must be the backend of the key opened (`auto-unseal` reads it while
  sealed), or the unseal is refused, naming it.
- **The old CA stays trusted until the last lease it certified ends**: the latest `expires_at`
  of the active leases, read once the new CA is in force (the review after M7.6, D-3: a grant
  whose certificate the old CA signed meanwhile is signed again by the new one before its
  lease is recorded), capped at the longest template's `max_ttl` from now (S-9); none active:
  not kept. Every retired CA is kept in `ca-retired.pub`, each with its deadline (at most 16,
  each within a year; a record past either is refused at read, naming the line): the gateway
  takes a certificate signed by the CA in force, or by a retired one before its deadline, and
  no other. New leases (renewals too) are certified by the new CA; an amendment keeps its
  lease's certificate. Agents notice nothing.
- A refusal is one `admin` line, `not rotated` with the reason.
- `writd init --ca-backend <name>` makes the first CA key on that backend (the installer asks
  it on a Mac).

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

## `writ migrate`

After an upgrade that changed the policy's format (M7.9.6), the policy in force is of an
older format, which the daemon never reads: it starts and unseals as before, then refuses every
request but `writ info`, `writ unseal` and the migration with `migration_owed` ("every request
is refused until an approver signs its migration with `writ migrate`"), agents and lease
holders included, each refusal logged (coalesced per source, as a sealed daemon's). `writ
unseal` says that one is owed. To unseal and to check the migration, the daemon holds the older
text read through its rewrite (`writ_core::config::migrate::baseline`: what the rewrite can't
carry over dropped); only its keys, recipients and `unseal` serve, since nothing else runs.

`writ migrate [--file <policy>] [--yes] [--approval-url] [--key] [--agent]` asks the daemon for
the migration (`MigrationShown`: the formats, the policy in force, and the daemon's rewrite of it
in the current format, canonical, or the reasons there is none, each naming its key). The text
in force is checked as `writ admin apply` checks it (the daemon the connection authenticated,
the policy, the text its digest names); the rewrite, or `--file`'s text (needed when there is
no rewrite: a `push_modes` without `gateway`), is shown as the change of the policy it is, line
by line, cleaned, then signed on yes as the policy's `writ-admin/2` naming the version in force:
one approval, the daemon's checks of any admin change (the current format only: an older text
is refused). In force, the daemon serves again (the leases granted before included) and logs a
`migrate` line beside the `admin` one. Declined (exit 6), nothing changes; it can be run again at
any time. With nothing owed it says so and signs nothing. While one is owed, no other admin change
is taken.

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
  `GET /v1/tickets/watch[?since=<cursor>]`, `GET /v1/tickets/<id>`,
  `POST /v1/tickets/<id>/approve`, `…/refuse`, `…/revoke`, `POST /v1/proofs`, and the admin
  routes (`writ_proto::Command::http_route`); JSON
  bodies, replies in the `{"ok"}` / `{"error"}` envelope (HTTP 200, or 422 when the
  command failed, 404 for an unknown route). Each request runs on its own task, to its end
  even when the client goes away (Ctrl-C during `writ unseal` or `writ admin apply`): a
  change is never left half applied, only its reply is lost (SSH commands run so already).
  A watch is the exception: it changes nothing, so it runs in the connection's own future
  and ends with its client.

**The watch** (M7.8, for the [approval popup](clients.md#the-approval-popup-m78)): `writ watch [<cursor>]` over SSH,
`GET /v1/tickets/watch[?since=<cursor>]` over HTTPS. Its reply is the tickets waiting for a
signature, in id order, and their **cursor**, the SHA-256 of their ids one per line (64
lowercase hex characters; anything else is no command). It answers at once when the caller
names no cursor or one that isn't the current one (a stale one, another daemon's), else as
soon as the waiting tickets change (a submission, a signature, a refusal, a withdrawal, an
expiry, which it sweeps every 30 s while it waits) or after 240 s (`WATCH_LIMIT`, well under
the listeners' 10 minutes of inactivity) with the same ones; the client asks again with the
cursor it got. At most 16 watches are held at once, all readers together
(`limits::MAX_WATCHES`); one more is refused at once (`too many watches at once (at most
16)`) and logged as a `command` denial, coalesced per source like the other denials a flood
could repeat. An allowed watch is a read: like `writ ls`, it writes no line. Over SSH a
watch ends with its channel or its connection; over HTTPS with its client. A sealed daemon
refuses it like any other read.

`writ` picks the transport from `WRIT_APPROVAL_URL` (`ssh://…`, `unix:…` or `https://…`).

**What `writ` checks before it signs** (the review after M7.6, L-1). In local mode the pins,
the reader key and the settings are files of the user every agent runs as, so an agent can
point `writ` at a relay of its own that reaches the daemon with the reader key: `writ`
names in a signed document only what its connection authenticated or what it computed
itself, never a reply's word for it.
- **The daemon:** over SSH, the daemon a reply names (`daemon` in `AdminShown`, `TokenShown`,
  `TlsShown`, `CaShown`, `ScanNonce`, and the sealed boot `writ unseal` reads) must be the
  fingerprint of the host key the connection checked against its pin
  (`writ_crypto::keys::fingerprint`, the function the daemon names itself with); any other is
  refused before anything is shown, asked (a passphrase, a token) or signed. Over HTTPS the
  connection authenticates the TLS certificate, never the host key the daemon names itself
  by: the name can't be checked there (a gap,
  [security.md's known gaps](../security.md#known-gaps)); what names the certificate (`writ
  admin tls rotate`'s `replaces`) must be the pinned one.
- **A text and its digest:** the file in force an admin change replaces must hash to the
  digest its reply names (and be the file asked for), whichever command built the change
  (`writ admin apply`, `set`, `add`, `remove`, the guided flows, `key rotate`, `auto-unseal`);
  a CA's fingerprint must be its public key's; a scan's fingerprints are computed by `writ`
  from the keys it pins, for the host asked (U-7).
- **`writ sign`:** the ticket shown as the one a ticket follows (the refused one it revises,
  the terms in force of the lease it amends or renews) must be the one it names, and a
  renewal's original the root of a chain. The source's other leases are the daemon's
  context, shown as it sends them: nothing a client can check.

What a relay that answers in its own name can still do (its host key pinned, its replies
naming itself) is the threat model's residual risk for local mode: it receives what is sent
to it, never a document another daemon takes.

**Only readers reach the API.** The reader key is an Ed25519 client key `writ reader`
generates on the approver's machine (`~/.writ/reader`, 0600) and prints as a line for the
daemon's `readers` file (`<name> ssh-ed25519 …`). It is never the approval key: Secretive's
key is only ever used through `ssh-keygen -Y sign` (hard rule 8). Without it, anyone who
reached the listener could read every ticket (task, plan, repos, leases). The connection
still grants nothing: approvals (and, with `decisions: signed`, refusals and revocations)
are SSHSIGs the approval service verifies. `writ ls --all` returns the 200 most recent
tickets. Commands: `writ info`, `writ ls [--all]`, `writ watch [<cursor>]`, `writ show <id>`, `writ approve <id>`,
`writ refuse <id>`, `writ revoke <id>`, `writ prove` (`writ_proto::Command`). Signatures are made with
`ssh-keygen -Y sign -U -n writ-approval -f <approval key .pub>` against the approver's agent
socket (`WRIT_APPROVAL_AGENT`, else `SSH_AUTH_SOCK`), the bytes to sign on its standard input
and the signature read from its standard output (never a file, which a Ctrl-C at the Touch
ID prompt would leave behind: only the key's public half goes through a private temporary
directory): only the dedicated approval key is used,
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
