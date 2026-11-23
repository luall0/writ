# Clients

Everything outside the daemon is **untrusted** ([design principle 1](../product.md#design-principles)):
clients make the workflow pleasant, the daemon makes it safe.

## Client list

| Client | Role |
|---|---|
| `writ` CLI | `policy` (what a ticket for each repo named may ask, from the daemon: templates, branches, committer emails, signing key id, limits, protected refs, the ticket link; for several, whether one ticket can cover them), `request` (`--dry-run`: the daemon's checks, nothing submitted), `wait`, `sign`, `refuse`, `close` (the lease ended with a summary, its activity report printed and recorded in the timings file), `report` (a lease's report, for the approver), `mark` (the end of a phase, the agent's), `timings` (the timings file's limits), `check` (a ticket file or the timings file, checked as written, nothing sent), `ls`, `revoke`, `prove-key` (an agent signing key's [proof for a remote](approvals.md#proving-a-signing-key-to-a-remote)), `unseal`, `admin show` and `admin apply` (the policy, approvers or readers in force, and [signed changes](approvals.md#admin-changes) of them), `admin repo|template|key|host|proxy list` and `show` (the policy in force [entry by entry](approvals.md#reading-the-policy-entry-by-entry), a key's public half with `--public`), `admin token` (an upstream's or a notifier's token, [encrypted on the Mac](approvals.md#writ-admin-token)), `reader`, `init` (wires a repo: [repo setup](#repo-setup-on-an-agent-host); with no repo named, a folder of repositories: [workspaces](#workspaces); `--list` and `--undo --all`: [the host's list](#the-hosts-list-of-wired-repositories)), `skill update` (`--all`: in every one on that list), `git` and `exec` (git, or a program, with that wiring; `git` finds the repository behind git's global options, `exec -C <dir>` runs in one), `run` (an agent harness as the root of its session: [binding a lease to its session](#binding-a-lease-to-its-session)) |
| Agent skill (`skill/writ/SKILL.md`, built into `writ`, installed by `writ init`; at a workspace root, `skill/writ-workspace/SKILL.md` instead: [workspaces](#workspaces)) | Teaches the agent the ticket workflow, at the start of any task that changes files and before any edit: read what the repo allows (`writ policy`) and the timings file, think through the scope (a branch of its own within the template's patterns, never the default or a protected one; `push` unless told not to) and estimate it, write a ticket (task, plan, repos, branches, estimate, limits), check it (`writ check`, then `writ request --dry-run`) and submit it with `writ request`, wait for my decision, then work with `WRIT_SESSION` set; on refusal, revise using my feedback; on an out-of-ticket denial, submit an amendment; out of time or counts, a renewal; after the final push (not a push mid-task), `writ close` with a summary, then a note in the timings file if something explains the figures. Each new request in a conversation goes through the skill again: a small follow-up to a running lease's work stays under it (amended if it needs more), a different task gets its own ticket after the running lease is closed, and any request after a close is a new ticket; after a close, `WRIT_SESSION` is unset. Everything the agent writes in a ticket is shown to me as-is and never trusted by the policy engine. [The skill and its installer](#the-agent-skill) |
| `writ-sign` | `gpg.ssh.program` shim: `-Y sign` → daemon (the gateway's `writ-sign git <repo>` command for the repo in `writ.repo`, reached at `writ.url` with the SSH command git uses: `GIT_SSH_COMMAND`, then `core.sshCommand`, never a plain `ssh`), with the first parent commit and the trees the daemon needs to see which paths the commit touches ([Gateway](gateway.md#signing)); everything else (`-Y verify`, `find-principals`) → real `ssh-keygen`. Also `gpg.openpgp.program` for a lease whose key is OpenPGP: `--status-fd=2 -bsau <key>` → daemon (`writ-sign openpgp <repo>`, the object on stdin, the armored signature on stdout, `[GNUPG:] SIG_CREATED` on stderr; no GnuPG home, keyring or agent used), `--verify` → the real `gpg` (`WRIT_GPG`, an absolute path, `/usr/bin/gpg` by default), anything else refused |
| Session agent (not built yet: [backlog](../backlog/non-exportable-session-keys.md); on when the host has the hardware) | Holds the session key so it can't be copied: a dedicated ssh-agent backed by the Secure Enclave, a TPM or a YubiKey |
| Harness integration | Omega Code requests a lease when an agent session starts and wires the repo's git config |
| Approvers | v1: `writ sign` + Secretive, and on the Mac the [approval popup](#the-approval-popup-m78) (`writ-popup` over `writ sign --ui`). Later: own Mac SE app, iPhone app |

Code: `crates/writ-cli` (`writ`), `crates/writ-sign` (`writ-sign`), `skill/writ/` and
`skill/writ-workspace/` (the skills). The approver side of the CLI is described in [Approvals](approvals.md).

`writ` reads its settings from flags or environment variables, and the two endpoints also from
`<home>/config` when neither gives them (`writ_cli::settings`: `url`, `approval_url`; read strictly,
an agent can write it): `WRIT_URL` (agents' listener,
`ssh://host:port` or `unix:<path>`), `WRIT_APPROVAL_URL` (approval listener: `https://host:port`, `ssh://host:port` or `unix:<path>`),
`WRIT_APPROVAL_KEY` (the approval key's public half, default `~/.writ/approver.pub`),
`WRIT_APPROVAL_AGENT` (its agent socket, default `SSH_AUTH_SOCK`), `WRIT_HOME` (default
`~/.writ`), `WRIT_KNOWN_HOSTS` (default `~/.writ/known_hosts`, where the daemon's host key
is pinned; `writd host-key` prints it), `WRIT_TLS_PINS` (default `~/.writ/tls_pins`, lines
`[host]:port SHA256:…` pinning the HTTPS certificate; `writd tls-fingerprint` prints it) and
`WRIT_READER` (default `~/.writ/reader`: the key the approval API lets in; `writ reader
[<name>]` makes it on first use and prints the line for the daemon's `readers` file; before
`writ` signs anything a reply named, it checks the reply against what the connection
authenticated: [what `writ` checks](approvals.md#reaching-the-daemon)),
`WRIT_SESSION` (the lease an agent works under: [the session](#which-session-a-command-uses)),
`WRIT_RUN_PID` (set by `writ run`: [the session binding](#binding-a-lease-to-its-session)), and
`WRIT_SSH_KEYGEN` (the ssh-keygen `writ sign` runs, an absolute path; default
`/usr/bin/ssh-keygen`, never looked up in `PATH`). It never reads `~/.ssh` or uses the user's ssh-agent
for connections: it would offer personal keys to the daemon. Exit statuses: 0 done, 1 error,
3 rejected by policy, 4 refused, 5 expired or withdrawn, 6 not signed (the approver answered
no to a "Sign …?" question: `writ sign`, `writ prove-key`, every `writ admin` change, a
scan's keys found not matching; every such question takes `y` or `yes`, in any case, and
nothing else, the end of the input included).

**The questions** (`writ-cli`'s `prompt` module, M7.9.5): on a terminal (stdin and stderr
both, `TERM` not `dumb`), every question `writ` asks is a widget drawn by `inquire`: a select
moved with the arrow keys and filtered by typing (a field whose values are few and known: a
key's use, kind, format, backend, algorithm, hash; a repo's credential, proxy, ticket link,
notes ref, object format; a template's signing key and paths check; every flag), a
multi-select (a template's operations, a repo's templates, the agents `writ
init` installs the skill for), text checked as it is typed (a count, a registry name), a
confirm, a pause. Each gives the answer the plain prompt gave (Enter keeps, `!` leaves an
optional field out, `none` empties a list), so the guided flows' logic is one; a select's
fixed options are the ones the field's own help names (a test). Colour unless `NO_COLOR` is
set. Everything drawn is cleaned first, a scanned host key or a name from the policy alike.
Without a terminal the plain line prompts answer as before (scripts, the variables, the
integration tests). `writ prompt select|text|confirm` asks one such question for a script
(the installer's frame, per question: `--question`, `--hint`, `--default`, the options),
its answer on stdout, Esc or a no exiting 6; refused without a terminal. Passphrases, the recovery key and tokens are never asked there:
`writ_crypto::passphrase` reads them, echo off, into memory it wipes.

Denial reasons from the daemon reach the agent: `writ-sign` prints them on stderr (escaped,
like any text from elsewhere) before exiting 1, and git shows them; git shows the gateway's
rejection message after a push. When ssh itself fails (the gateway refuses an expired, revoked
or unknown certificate during authentication, where SSH can't say why), `writ-sign` reads the
session certificate named in the SSH command and says whether there is no lease, an expired
one, or one the daemon refused: a convenience, the daemon decided already.

### The daemon's version

Every reply names the daemon's version first (`{"version": "0.2.0", "ok": …}`, M7.9.8), on
every listener: `writ_proto::decode_versioned` reads it before the rest. It must be
`MAJOR.MINOR.PATCH`, 32 bytes at most, or the reply is unreadable. `writ` compares it with its
own (`writ-cli`'s `version` module): when they differ, or the daemon names none (a `writd`
before 0.2.0), it says so once per process on stderr, `install the same version of both`. A
hint only (hard rule 1): the reply is read as any, and the daemon decides. A reply that
doesn't parse names both versions in its error, since the messages refuse fields they don't
know and a version apart is the likely reason. `writ --version`, `writd --version` and
`writ-sign --version` print the binary's version; `writ-sign` reads no envelope (the gateway
sends it the signature itself).

### Shell completion

`writ` completes in bash, zsh and fish (M7.9.9) through clap_complete's dynamic engine
(`writ-cli`'s `complete` module): each TAB runs `WRIT_COMPLETE=<shell> writ -- <words>`, which
answers and exits before anything else runs (`complete::answer`, the first thing `main`
does). It answers from a copy of the clap tree with the commands hidden from `--help` left
out (`writ prompt`: clap would still offer one typed far enough to match it alone), each
argument naming something the daemon holds given a source of values by its command's path
(`complete::source_of`): the waiting tickets (`sign`, `refuse`, `wait`) and the running
leases (`revoke`, `report`, `close`, `wait --lease`, `init --lease`) from `writ ls`, scoped
as it is in a repository ([what `writ ls` shows](#what-writ-ls-shows-in-a-repository)), the names
of each section of the policy in force for `writ admin …`, `writ policy`, `writ init` and
`writ sign --drop-repo`, the key backends for `--backend` of `admin key|tls|ca rotate` (the
read `writ admin key list` makes), and the fields of `set` and `add` from
`writ_core::config::edit::fields`. A fixed set of words (`complete::Words`) needs no daemon:
the files of `admin show|apply`, the phases of `mark`, the agents of `init --agents`, the
operations of `sign --drop-op`, each read from the list its argument's parser reads
(`AdminTarget::ALL`, `Phase::ALL`, `Agent::ALL`, `Operation::ALL`), so a word offered is one
the parser takes. These see what is typed: an agent after the ones typed and a comma, an
operation after `<repo>:` (fish and zsh: bash splits a word at `:`, as clap's registration
leaves `COMP_WORDBREAKS` as it is), the typed part reaching the shell only as plain as any
value. A read is the one its command already makes with the
reader key, within one deadline (`complete::DEADLINE`, 1 s, from the connection to the last
byte), on a runtime of its own dropped after it; no file is written and nothing is kept. The
endpoints and files are the flags' variables or the defaults: a TAB has no parsed flags.

Any failure offers no value and says nothing (the version hint quieted too: fish shows
stderr): completion never prompts, never asks for the approval key, never pins a host key.
What reaches the shell is bounded (`MAX_VALUES` values of at most `MAX_VALUE` bytes, of
characters a shell inserts as they are; descriptions stripped of hidden characters and cut to
`MAX_HELP`), and a ticket's description is the daemon's facts (`pending · feature · 1 repo`),
never its title. `writ completions <shell>` prints the registration, naming this `writ` by its
absolute path (an earlier `writ` on `PATH` never answers); zsh's also completes when the file
is `_writ` on `fpath`.

## The approval popup (M7.8)

A ticket waiting for my signature comes up in a window in front of every app, full-screen
ones too, with the whole ticket and two buttons, **Sign** and **Decline**. Two programs:

- **`writ sign --ui`** (`writ_cli::approver::ui`) is the approval client. It holds a
  [watch](approvals.md#reaching-the-daemon) on the daemon, keeps the queue of waiting tickets
  (in id order: the oldest first), fetches the one to show with `writ sign`'s own checks
  (`fetch_reviewed`), builds its display with `writ sign`'s own code (the very text `writ sign
  <id> --full` prints above its question, and the same as a structure of sections and tagged
  rows, written by the same calls: `display::Out`), and signs with `writ sign`'s signer
  (`ssh-keygen -Y sign` through the approval agent, which asks its own confirmation). Nothing of that
  exists anywhere else.
- **`writ-popup`** (Swift: SwiftUI in an AppKit `NSPanel`; `crates/writ-cli/macos/`) only shows what `writ` sends and
  says what was clicked ([decision log](../decisions.md), 2026-11-14: before any richer UI,
  or one on another platform, the approval client is linked into the app instead).

They talk one JSON object per line each way, on `writ`'s stdout and stdin:

| From `writ` (`type`) | What it carries | The window |
|---|---|---|
| `show` | `id`, `kind` (`ticket`, `revision`, `amendment`, `renewal`), `title`, `repos`, `expires_at`, `display` (the terminal's text), `doc` (the same as sections of tagged rows, below), `key` (the approval key's path), `waiting` (every ticket waiting, the one shown among them, oldest first: `id`, `kind`, `title`, `repos`, `skipped`) | shows the ticket; the list beside it, the one shown highlighted |
| `queue` | `waiting` | the list changed |
| `gone` | `id` | the ticket shown stopped waiting (signed or refused elsewhere, withdrawn, expired): its window closes |
| `done` | `id`, `message` | what an answer did (`Signed: lease … is active.`) |
| `failed` | `id` (or `null`), `message` | an answer that signed nothing, a ticket that couldn't be shown, a signature that failed (Touch ID cancelled: the ticket is shown again) |
| `idle` | | nothing waits: the window goes |
| `status` | `message` | the daemon lost or refused the watch: tried again after 1 s, then up to 30 s |
| `reached` | | the daemon answered a watch again after a `status`: that message goes (`the_popup_is_told_when_the_daemon_is_reached_again`) |

| From the app (`answer`) | |
|---|---|
| `sign` | `id`: the ticket shown, signed as shown |
| `refuse` | `id`, `feedback` (may be empty: the agent then reads *Declined in the approval popup, with no feedback.*), signed under `decisions: signed` like `writ refuse` |
| `skip` | `id`: the window closed; the ticket stays waiting, put aside by this run (`writ sign` in a terminal reaches it) |
| `pick` | `id`: a ticket of the list clicked: fetched and checked like any other and shown, one put aside coming back; one not waiting refused (`failed`), the one shown staying |

**The structure** (`doc`, `writ_cli::display::doc`): `sections`, each with a `kind` (`ticket`,
`who`, `lease`, `repository`, `agent`, `feedback`, `renewal`, `changes`, `others`, `signing`),
its `title` and its `rows`; a row has an optional `label`, a `value` (cleaned, one or several
lines: the agent's text whole, as its lines, not cut into the terminal's rows), a `tag`:
`enforced`, `agent`, `context`, `added`, `removed`, `agent_added`, `agent_removed`,
`warning`, and for a term that is a list (repos, committer emails, operations, branches,
expected paths; and the agent's plan, step by step, M7.9.5) its `items`, each cleaned as the value shows it, which `writ` splits so the
app never splits a value (none for a per-repository term over several repositories, whose
value names each); for a row that shows a time, its `at` (RFC 3339, UTC), so the app says
how far it is ("in 2h") beside the clock time without reading the value (M7.9.5); and for the
expected paths, their `tree`: nodes with a `name` (a folder's ends with `/`, a folder holding
only one folder and nothing else merged with it: `writ-integration/tests/`), a `kind`
(`folder`, `file`, `pattern` for a leaf with a glob character, `everything` for `**`), the
`paths` under it and its `children`, built by `writ` from the items alone so every path is
the names on its way down, nothing added, dropped or reordered
(`the_path_tree_gives_back_every_path_exactly`). In a `changes` section, a term that is a
set (repos, committer emails, operations, branches, expected paths) is a row per item
removed (`removed`) and added (`added`), then a `context` row saying how many stay; any other
term, a row per side. Over several repositories, a per-repository term's rows carry the
`repo` they are in, and each `repository` section its `repo` name, so the window places
each change in its repository's card without reading a title or a value. The terminal's text and the structure are written by the same calls, so they say
the same (`the_structure_says_what_the_text_says`); agent text only ever lands in a row
tagged as the agent's, or quoted inside an enforced value (the caller's executable), or as
recorded feedback (`agent_text_is_only_ever_in_the_agent_s_rows`). The app styles each kind
and tag and reads nothing out of a value: it never parses the text.

**The window** (redesigned in M7.9.5, as the user validated it on mockups). Two panes, and a
rail when more than one ticket waits.
- **The rail** (only then), on the left, 58 points wide: the count, then a badge per ticket
  waiting, oldest first, coloured and marked by its kind, the one shown ringed, one put aside
  dimmed; hovering one shows its kind, title and repositories; a click picks it.
- **The centre: what is signed.** A header (the kind, the lease an amendment or a renewal
  touches, the title quoted and said to be the agent's, the time left counted live with the
  clock time beside it); for an amendment, a revision or a renewal, what changes first (each
  set's items removed and added, whole, then how many stay; a value's before → after); then
  every enforced term as a tile, chosen by `writ`'s labels (the `signing` section, the lease's
  signing key, violation rule and rate, each repository's largest push), none folded away,
  in balanced rows that fill the width, every tile as tall as the tallest;
  the expected paths as a file tree from the rows' `tree` (a Tree / List switch, a filter,
  scrolling past 320 points once clicked, so the wheel over it scrolls the window until then,
  a fade and a label saying there is more below; every path whole). Over several repositories, the lease's own
  terms in one strip (commits as, signing key, rate, on violation), then one card per
  repository with its terms and its own path tree; an amendment's cards marked CHANGES where
  its changes are, the others folded to a line; who asks, in a line; the feedback and a
  renewal's chain; the source's other leases, folded unless one overlaps (orange); **Details**,
  folded: the `ticket`, `who`, `lease` and `repository` sections, times shown as how far and
  the clock time, and **Copy as text** (the terminal's text).
- **The right pane: the agent's words.** Every row tagged as the agent's, from every section,
  in `writ`'s order (task, plan, estimate, the origin hint, an amendment's task before and
  after), marked untrusted, scrolling on its own: text of any length never moves what is
  signed. The title is the header's, not repeated.
- **The footer**, always in sight: what happened last (Touch ID awaited, signed, refused, a
  failure), the approval key, **Decline…** (a feedback field, then **Refuse**) and **Sign**.
  No button takes the keyboard's focus or is the default, and each is greyed for a second
  after a ticket shows.

Every text `writ` sends is cleaned of control and hidden characters, as for the terminal.
An answer naming another ticket than the one shown, a line that isn't an answer (unknown
fields included), one past 64 KiB (dropped to its end, never held whole) or one sent while
the daemon is out of reach signs nothing and is said. Narrowing stays in the terminal: `--ui`
takes no ticket, no narrowing flag, no `--yes` or `--full`. Admin changes and unseals never
come to the popup: the watch lists tickets only. The end of the app's output ends `writ sign
--ui` (exit 0).

The tickets that arrive together are all listed: the window shows the oldest, and the list
beside it every ticket waiting, each with its title, repositories and kind; a click shows
another one (`pick`); once the one shown is decided or gone, the oldest left comes up, with no
window to reopen.

## Repo setup on an agent host

`writ init <repo>` wires the repository it runs in, in one of two modes. Both use the same
settings (`writ_cli::wiring::settings`), and what `writ init` did is recorded in
`<git common dir>/writ/config`: never in the working tree, so it can't be committed.

**Wrapper mode (the default)**: nothing in the repo's git config changes. The agent runs every
git command through `writ git …` (commit, rebase, cherry-pick, `commit --amend`, fetch, push,
log…), or a program that runs git through `writ exec -- <program>`; the settings below reach
git through the environment (`GIT_CONFIG_COUNT`, git ≥ 2.31, and `GIT_SSH_COMMAND`), for that
process and what git runs (`writ-sign`, `ssh`, hooks), and so for every git that process
starts, in any repository: `writ-sign` refuses a commit made in a repository other than
`writ.gitdir` before sending anything, so it can't reach the daemon labeled with the wired
repo; the other repository's SSH remotes still get the session's key (and fail on the daemon's
pinned host key). The operator's own `git`, in the same
clone and working tree, keeps the operator's keys, email and remotes; a plain `git push writ`
finds no such remote. Commits a command rewrites (a rebase) are signed again, one signature
each from `max_signatures`. In a linked worktree (`git worktree add`) the record is in the
git directory every worktree of the repository shares: `writ git` works under the wiring in
each of them, and plain git in none.

**Whole repo** (`writ init <repo> --whole-repo`): the same settings written in the repo's
config, for a clone dedicated to an agent (a VM, a container); plain `git` is then the agent's
git. The values they replace are recorded first. Refused in a linked worktree: its config is
the one every worktree of the repository reads, the operator's checkout included (wrapper
mode, or a clone of its own).

Everything `writ init` can refuse is checked before anything is written: the remotes (below),
a linked worktree, the session, every `SKILL.md` it would write (one that isn't Writ's, or
can't be read) and the timings path, the `AGENTS.md`/`CLAUDE.md` it would add to. Then the
record is written first, whole (renamed into place), the repository added to `<home>/repos`
at once, and each thing done recorded as it is done (a folder or a skill before it is made, a
line once added): an init that fails part way says so, and `--undo` then takes back what it
did.

`writ init --undo` takes either back exactly: the record removed, and in whole-repo mode every
key restored as it was; a line it added (an exclude line, the pointer) comes out byte for
byte, with the line break it added before it and in the file's own line endings (`\r\n` or
`\n`), and a file it made for it goes once empty. Good practice for the operator (their own keys, guardrails in the
agent's configuration): the [operators' good practice](../operators/good-practice.md).

```ini
# The settings, as --whole-repo writes them (writ init omega-code); <home> is WRIT_HOME
[remote "writ"]
    url = ssh://git@writ.home:2222/omega-code.git
    fetch = +refs/heads/*:refs/remotes/writ/*
[writ]
    url = ssh://git@writ.home:2222      # where writ-sign sends commits to sign
    repo = omega-code                   # the repo they are for (a registry name)
    gitdir = /path/to/omega/.git        # its git common dir: writ-sign signs nothing made elsewhere
    session = <home>/sessions/current   # the session: its lease's format, checked against WRIT_SESSION
[gpg]
    format = ssh
[gpg "ssh"]
    program = /path/to/writ-sign        # next to `writ`, or `writ-sign` in PATH
[user]
    signingkey = <home>/sessions/current/signing_key.pub   # <home>/sessions/<lease> when pinned
    email = user+agent@example.org      # --email, or the lease's when it allows one
    name = Writ agent                   # the lease's committer_name, when its template sets one
# A lease whose key signs in OpenPGP (its session holds signing_key.asc): instead,
#   gpg.format = openpgp, gpg.openpgp.program = /path/to/writ-sign,
#   user.signingkey = <the certificate's fingerprint>
[commit]
    gpgSign = true
[tag]
    gpgSign = false                     # tags are never signed by the daemon
[core]
    sshCommand = ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none -i '<home>/sessions/current/key' -o 'CertificateFile=<home>/sessions/current/key-cert.pub' -o 'UserKnownHostsFile=<home>/known_hosts' -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes
[url "ssh://git@writ.home:2222/omega-code.git"]
    insteadOf = git@github.com:user/omega-code.git   # the clone's origin URL when wired
    pushInsteadOf = git@github.com:user/omega-code.git   # over any push rule of the user's
```

`writ git` finds the repository a command works in as git does (`writ_cli::gitopts`): git's
global options before the command are read in order (`-C`, `-c`, `--config-env`, `--git-dir`,
`--work-tree`, `--bare`, `--namespace`, `-p`/`-P`, the pathspec and lock flags…), each with
its value taken as git takes it (`-C` and `-c` only as the next argument, `--git-dir` either
way), and git resolves the repository from the ones that say which (`git -C … --git-dir …
--work-tree … --bare rev-parse --git-common-dir`, in this process's environment: `GIT_DIR`
counts as it will for the command). An option git doesn't take before a command, or one
missing its value, is refused with its reason, git never run: never skipped, so the wiring
loaded is always the one of the repository git works in. The options that print and exit
(`--version`, `--help`, `--exec-path` alone, `--list-cmds`) run git with no wiring. `writ
exec -C <dir> -- <program>` runs the program in `<dir>` under that repository's wiring: one
repository per process. A wiring that reaches another repository anyway (a program running
git elsewhere) is refused by `writ-sign`, as above.

Paths are absolute and quoted for `sh`, and point at one session's directory, also named by
`writ.session` ([which session](#which-session-a-command-uses)): `<home>/sessions/current`
unless the repo is pinned (`writ init --lease`) or `WRIT_SESSION` is set. In wrapper mode they
are computed once per command from `WRIT_HOME`, and the email is the session's lease's unless
`--email` was given, and the name (`user.name`) the lease's `committer_name` when it has one
(the daemon refuses a commit under any other name; in a whole-repo clone, like the email, the
one of the lease current at `writ init`); `writ init` computes them once per run (its record for `--undo`, the
config it writes and its summary come from the same values) and reads the values it replaces
with `git config --get-all -z`, so a value over several lines is put back whole. Each commit
needs a `Writ: <lease>` trailer when the repo's `ticket_link` is `trailer`
(`git commit --trailer "Writ: wrt_…"`); `writ init` prints the lease's. A local daemon
(`unix:<path>`, absolute) is reached as `ssh://git@writ-local`: the SSH command adds
`-o HostKeyAlias=writ-local` (the alias its host key is pinned under) and
`-o ProxyCommand=/usr/bin/nc -U <path>`, the path quoted for the shell ssh runs it with,
the whole option for git's; the record keeps the socket (`writ.socket`). `writ-sign` needs
nothing more: it uses git's SSH command and `writ.url`'s host.

### Workspaces

Some people keep several repositories in one folder and start one agent at the folder.
`writ init` there, with no repo named, makes the folder a **workspace** (`writ_cli::workspace`):

- **Its repositories**: the folders right under it that are a repository's top (`.git` there,
  and `git rev-parse --show-toplevel` naming the folder), sorted; a hidden folder, a link
  (named), a name with a control character or not UTF-8 (named), and a submodule of the
  folder's own repository (named: submodules aren't wired yet) are not, nor a worktree of a
  repository already found (named: one git directory, one record; the repository's own
  checkout is kept before its linked worktrees). At most 256. The
  folder's own repository, when it is one (a meta-repository ignoring its children), is a
  member only when named (`--repo .=<name>`).
- **Their registry names**: `--repo <dir>=<name>` (repeatable; `<dir>=-` leaves one out;
  `-` is never a registry name), else asked on a terminal with a default (the `origin` URL's
  last part without `.git`, else the folder's name; Enter takes it, `-` leaves it out).
  Without a terminal, a repository nobody named is refused, naming each with its default,
  before anything is written; so is a `--repo` folder that isn't one of them, a folder named
  twice, two repositories under one name, a repository already wired, and a folder already a
  workspace.
- **Each repository wired as `writ init <repo>` wires it** (the same `wiring::settings`, its
  own `<git common dir>/writ/config`, either mode, `--email` and `--lease` for all), with
  `writ.workspace` naming the folder, and no skill of its own.
- **The `writ-workspace` skill** at the folder (the agents' folders as for a repository,
  `--global` and `--skill-dir` too), listing the repositories and their registry names: one
  ticket with a block for every repository the task touches, `writ policy <repo>…` for them
  all (each block fits a template of its own; one signing key and the strictest template's
  time per lease, or one lease per repository; the trailer is per repository),
  `writ git -C <dir> …` for every git command, `writ exec -C <dir> -- …` for a program,
  `writ mark` and `writ close` at the folder. `--agents-md` adds its own pointer line.
- **The record**, `<folder>/.writ-workspace` (git config format): `writ.mode`, `writ.lease`,
  `member.<dir>.repo` for each repository (written before the repository is wired, so a run
  stopped half way is taken back), and the `skill.*` entries. When the folder is a
  repository, `/.writ-workspace` and the skill's folder go in its `.git/info/exclude`.

At the folder, `writ git` and `writ exec` (when it is no wired repository) and `writ policy`
(with no repo named) list the repositories; `writ mark` uses the workspace's pinned lease;
`writ close` records the run in the workspace's timings file, in the section named by the
lease's repositories, sorted and joined with ` + ` (`api + web`; one repository's is its
own), from the folder or from any of its repositories.

`writ init --undo` at the folder takes each repository back whose own record names this
folder (one that doesn't is named and left), then the skill, the exclude lines, the pointer
lines and the record: every repository's config and the folder as before, the timings file
aside. In one of its repositories, `--undo` refuses and names the folder. The record is in
the working folder, the agent's to write too: it is read bounded (a regular file, never a
link, 64 KiB, at most 256 repositories, each a plain folder name right under the folder or
`.`), and an undo removes only a `SKILL.md` in a `writ/` or `writ-workspace/` folder that
still carries Writ's mark, only folders `writ init` made on the way to one (when empty), and
the pointer line only from an `AGENTS.md` or `CLAUDE.md` (a repository's own undo holds to
the same). A program that runs git across several repositories at once, and submodules, are
in the [backlog](../backlog/README.md).

### Binding a lease to its session

`writ run -- <program> [args…]` (`writ_cli::run`) starts an agent harness as its child, the
root of its session, and stays until it ends. The daemon takes as a session's root only a
direct child of the installed `writ` (`session_launcher`, by its kernel-attested path; the
review after M7.6, C-1), so the harness is `writ run`'s own child: `writ run` starts itself
with `WRIT_RUN_PID=starting`, and that child puts its own pid in `WRIT_RUN_PID` and becomes
the harness (`exec`: the pid is kept). What `writ exec` runs is a child of `writ` too, and
may be a root as well: the lease then lives in that subtree and ends with it.
SIGTERM and SIGHUP are passed on to the harness. SIGINT and SIGQUIT already reach the whole
foreground group from the terminal, so they are not passed on again. Its exit status is the
harness's, or 128 and the signal that ended it.

Under it, `writ request` adds `caller: { descends_from: { pid } }` to a ticket that names no
caller (after a leading `---`). The daemon completes the binding from the kernel's chain of
the submission ([lease model](../lease-model.md#the-complete-ticket)) and refuses a pid the
submission doesn't descend from, or one whose parent isn't the session launcher (pid 1, a
terminal, a shell, `writ run` itself: `session`, telling the agent to use `writ run`). When the harness quits, `writ run` exits and the session
watcher revokes the lease. A `WRIT_RUN_PID` that isn't a pid is refused. A ticket that names
its own caller is sent as written (the daemon still checks it).

### The host's list of wired repositories

`writ init` adds each repository top or workspace root it wires to `<home>/repos`
(`writ_cli::repos`), one `repo <path>` or `workspace <path>` a line, and `writ init --undo`
removes it. It is an index: what each one is comes from its own record. `writ init --list`
prints it checked, `writ init --undo --all` and `writ skill update --all` run the undo or the
update in each entry as they would there, naming one that fails and going on (exit 1 then).
The file is the user's, so an agent can write it: it is read as untrusted input (bounds and
checks in the [security inventory](../security.md#untrusted-inputs)), and an entry is used
only if it names a place that holds `writ init`'s own record of that kind. The uninstall asks
these commands, as the user, never as root.

### Which session a command uses

`writ git`, `writ exec`, `writ init`, `writ mark` and `writ-sign` work under one session,
chosen in this order:

1. `WRIT_SESSION=<lease>`, which `writ request` prints with each grant;
2. the lease the repo is pinned to (`writ init --lease <id>`, kept in the record as
   `writ.lease`; a whole-repo clone gets that session's paths);
3. `<home>/sessions/current`, the latest grant.

A session named by the first two must be on this host, not ended (its `ended` file: closed,
or renewed by another lease) and not past its end, or the command is refused with the reason:
never replaced by `current` (`wiring::choose_session`). `writ init` takes the session the same
way (a whole-repo clone gets that session's paths, `current`'s otherwise) and refuses
`--lease` and `WRIT_SESSION` naming two leases. `writ git` and `writ exec` resolve `current`
once, to the lease it points at: every setting of one command names that session, however a
grant moves `current` while it runs. One command uses one session: with
`WRIT_SESSION` set, `writ-sign` refuses a commit when the settings git gave it name another
session (`writ.session`: a whole-repo clone pinned elsewhere, or `current` pointing at another
lease). `writ request` warns when the grant moves `current` while another lease of the same
home still runs. A client check, never a boundary: the daemon decides by the certificate.

`writ-sign` asks the daemon for the format of the session's lease (`signing_key.asc` in the
session: OpenPGP; otherwise SSH), whichever way git called it (`gpg.ssh.program` or
`gpg.openpgp.program`), and answers in git's way for that call; git stores either in the
commit's signature header. So a whole-repo clone follows its lease when the next lease's key
signs in another format, with no change to its config. Settings without `writ.session` (a
wiring from before M6) ask in git's way, and the daemon refuses the other format
(`signature_format`).

### What `writ ls` shows in a repository

Agents run `writ ls` to see where they stand, and some then tried a lease they saw there:
another repository's (refused by its scope), or another session's on the same repository
(which its scope would let through, unless it is bound with `writ run`). So in a repository
`writ init` wired, or at a workspace root, `writ ls` shows only what concerns it
(`writ_cli::scope`):

- **Which repositories:** the wired repository's registry name (its record), or the
  workspace's members at its root. Elsewhere, or with `--global`, everything shows, as before.
  A ticket or lease is in scope when one of its repositories is.
- **Which lease is yours:** the session the repository's commands use
  ([which session a command uses](#which-session-a-command-uses): `WRIT_SESSION`, then the
  pinned lease, then `current`), marked `yours`, with its amendments. A session that can't be
  used (ended, unknown here) makes no lease yours: the list then hides more, never less.
- **Shown with their ids:** your lease, the waiting tickets that start a lease (an agent
  follows its own request by its id, and a waiting ticket grants nothing), and with `--all`
  the ended ones.
- **Counted, never named:** every other active lease in scope, and every waiting amendment
  of one (its line would name the lease). One line says how many there are, and that
  `writ ls --global` lists them.
- **A header** names the scope, so a short list is never a puzzle.

Running leases offered by [shell completion](#shell-completion) (`revoke`, `report`, `close`,
`wait --lease`, `init --lease`) follow the same scope.

A nudge, never a boundary (hard rule 1): any agent can type `--global`, and the reader key
it uses is readable by every program of the user. What keeps a lease to its holder is the
daemon: its scope, and the session binding of `writ run`
([binding a lease to its session](#binding-a-lease-to-its-session)). A wiring record that
can't be read makes `writ ls` refuse with the reason (the record is the agent's to write):
`--global` still lists everything.

### Fetching with no lease

Before it plans, an agent fetches: to see whether upstream moved, or to start from a clean
tree (M7.9.7). `writ git fetch` and `writ git pull` with no lease named or running
(`WRIT_SESSION` unset, the repo pinned to no lease, `current` pointing at no lease still
running) ask for one themselves, when one of the repository's templates has
`unsigned_fetch` on (`writ policy`'s reply carries each template's, and `writ policy` shows it
as `fetch alone: no signature …`); the first one it lists (the policy's order, by name):

1. a throwaway key, and a fetch-only ticket `writ` writes (`template: <it>`, `operations:
   [fetch]`, its title and task fixed, the template's `unsigned_fetch` as its time; bound to
   the session under `writ run`, as `writ request` binds one), submitted and granted with no
   signature ([lease model](../lease-model.md#granted-with-no-signature-m797)), always with a
   file key (the backlog's [hardware session keys](../backlog/non-exportable-session-keys.md)
   would be for the leases a human signs);
2. its session written (`sessions/<lease>/`: the key, the certificate, `lease.json`), never
   pointed at by `current`, and git run under it (the wrapper's settings and SSH command for
   that session; in a whole-repo clone, the SSH command over the clone's), one line on
   stderr naming the lease and its template;
3. once git returns, whatever its exit, the lease closed with a fixed summary (no report
   printed, no run in the timings file) and its session removed; a close that fails says so,
   and the lease ends by itself at its `unsigned_fetch` time. The command exits with git's
   code.

No such template, or the daemon refusing the ticket: git runs as before (the daemon refuses
a fetch with no lease), or the refusal is printed with its reasons (exit 3). A lease named
but ended, or one without `fetch`, is never replaced (`writ git` never moves a running agent
to another identity). A `pull` that would make a merge commit fails at its signature: the
lease has no `commit_sign` (the skill says `--ff-only`). A convenience: the daemon decides
the grant, as for any ticket.

### What the agent reads before it asks

Before it writes a ticket, the agent asks the daemon what a ticket for its repos may ask:
`writ policy [<repo>…]` (the repos named, or the wired repository's) runs `writ policy <repo>`
on the agents' listener as user `writ`, once per repo, each with a throwaway key (no lease
exists yet), and prints each reply (`writ_proto::RepoPolicy`): each template that allows the
repo (operations, branch patterns, committer emails, committer name, its signing key's id,
force push, `max_ttl` and the counts, `paths_check`, `require_expected_paths`,
`max_renewals`), the repo's protected refs and `ticket_link`, and the daemon's `min_ttl`,
`renew_grace` and `max_active_per_source`. Only that repo: never its upstream, its
credential, a signing key itself (its id only: agents get the public key with each grant),
another repo or what a template allows elsewhere. A repo not in the registry is refused
(exit 3). For several repos, a **Together:** section says whether one ticket can cover them,
as the daemon fits one: for each signing key a template names, the repos with a template of
that key may sign under it and the others only without `commit_sign`, with the strictest TTL
and rate of those templates; a repo no template allows can't be named at all. Otherwise, one
lease per repo. Then `writ request --dry-run <file>` sends the
ticket for every check a submission gets (`writ request --dry-run` on the wire: the rates,
the waiting tickets, `max_active_per_source`, the templates, the lease it amends, renews or
revises) and the daemon stores nothing and tells nobody; the reply is the ticket it would
build (`Checked`), printed as each repo's template and terms (`The daemon would accept this
ticket, until <time> if submitted now: api (template backend): fetch, commit_sign, push on
agent/x; web (template read-only): fetch.`), the template the daemon chose when the ticket
named none. The grant line has the same shape (`Lease <id> granted until <time>: …`). The key is the one the real submission would use (a revision's, an
amendment's or a renewal's session key), and nothing is written on the host. Both count
against the [submission rates](../operators/writd-yaml.md) and write an audit line (`policy`,
`dry_run`). Reads, never grants: every ticket is checked again when it is submitted and when
it is signed.

Before any lease, `writ init` says the committer email will be the lease's (and that
`writ policy` lists the ones a ticket may ask for), rather than suggesting `--email`: an email
given there overrides the lease's for every commit, and one the lease doesn't allow makes
every signature refused.

### The agent skill

`writ init` installs `skill/writ/SKILL.md` (built into `writ` with `include_str!`, so the
skill always matches the CLI) as `<folder>/writ/SKILL.md` in each skills folder of the
agents it is asked for (`writ_cli::skill`), in as few folders as possible:

| Agent (`--agents`) | In the repo | `--global` |
|---|---|---|
| Claude Code (`claude`) | `.claude/skills` | `~/.claude/skills` |
| Codex, Gemini CLI, GitHub Copilot, Amp (`agents`) | `.agents/skills` | `~/.agents/skills` |
| OpenCode (`opencode`), only without the two above, which it reads too | `.opencode/skills` | `~/.config/opencode/skills` |
| Cursor (`cursor`) | `.cursor/skills` | `~/.cursor/skills` |

- On a terminal, `writ init` asks, the agents it detects (`.claude/`, `CLAUDE.md`,
  `.agents/`, `.codex/`, `AGENTS.md`, `.opencode/`, `opencode.json`, `.cursor/`, and their
  folders in the home) pre-selected; `--agents` or `--skill-dir <folder>` answer for it.
  Without a terminal and without them it fails before wiring anything.
- In the repo, each `writ/` folder installed is added to `.git/info/exclude`: never committed,
  never against `expected_paths`.
- A `SKILL.md` that isn't Writ's (no `Written by writ init` mark) is never written over; one
  that is is refreshed.
- `--agents-md` appends one line pointing at the skill to `AGENTS.md` and `CLAUDE.md` (a new
  `AGENTS.md` when the repo has neither); otherwise the summary prints the line. It names
  fetch and pull, before any task (M7.9.7: agents fetched with plain `git` before planning,
  outside the skill, through the operator's own remote). A line an earlier version added is
  replaced in place by today's (`skill::replace_line`, its line break kept), and `--undo`
  takes either back.
- The skill starts with **fetching before planning** (step 0, M7.9.7): `writ git fetch` and
  `writ git pull --ff-only` with no ticket, which a repository whose template has
  `unsigned_fetch` on serves under a lease granted with no signature
  ([fetching with no lease](#fetching-with-no-lease)), the work itself still under a ticket
  the human signs, even under the same template; its description asks the agent to load it
  before any git command, not only before a task that changes files.
- What `writ init` creates and adds is recorded (`skill.created`, `skill.createddir`,
  `skill.exclude`, `skill.agentsmd`…), and `--undo` takes exactly that back: the skill files
  that are still Writ's, and the folders made for them once empty. `timings.md` stays. A
  `SKILL.md` it rewrote (Writ's already: a global skill another repository's `writ init`
  made) is recorded too (`skill.written`): `--undo` leaves it in the repository; outside it
  (a global skill, shared by every repository wired with `--global`), it removes a skill file
  it created or wrote only once no other entry of `<home>/repos` records it, and says which
  one still does. `--global` is refused at a workspace: its skill lists that folder's
  repositories.
- `writ skill update`, after upgrading `writ`: in the repository (or at the workspace's root)
  it runs in, every `SKILL.md` the record names (`skill.created`, `skill.written`) rewritten
  from the skill built into this `writ`, its timings file and a workspace's repositories
  filled in again, each said `updated` or `up to date`. The record is the agent's to write
  too: only a regular file named `SKILL.md` in a `writ/` (`writ-workspace/`) folder, with
  Writ's mark, is written; anything else is kept and said (`skill::update`). In a
  workspace's repository it is refused, naming the root. Every wired repository at once
  (`--all`) comes in M7 with `~/.writ/repos`.
- At a [workspace](#workspaces) root, the `writ-workspace` skill instead (`writ-workspace/`
  in the same folders), with the workspace's repositories listed.

`timings.md`, beside the first `SKILL.md` (which names its path), is what the agent learns
about sizing tickets (`writ_cli::timings`). Front matter holds its limits (`max_lines`,
`max_bytes`, `keep_runs`, `max_notes`; `writ timings` changes them within their bounds). Per
repository: a `summary:` line adding up every run (`key=value`, minutes), an `averages:` line
regenerated from it, the last runs in full (`runs:`, one line each from the activity report:
time used against granted, the estimate against the phases, the counts, the agent's marks),
and the agent's notes (`notes:`). `writ close` appends a run and compacts with fixed rules:
the last `keep_runs` runs and `max_notes` notes (the same note once) per repository; then,
while over `max_lines` or `max_bytes`, the oldest run of the repository with the most, then
the oldest note, then the least recently updated repository, the text's size counted once and
kept up to date (never rendered again per thing dropped). The file is untrusted: read only as
a regular file (never a FIFO) of at most 1 MiB, in one pass that keeps at most 200
repositories and 50 runs and notes each (the latest), what doesn't parse is rewritten, every
line is cut to 400 characters, and `writ check` names every line `writ close` would drop or
rewrite. `writ check` takes a file for a timings file when its front matter names a limit
(`max_lines:`…) or it is the one the wiring here records: a ticket may start with YAML's
`---` too.

The SSH command never reaches the user's own SSH setup: no `~/.ssh/config` (`-F /dev/null`), no
other key and no agent (`IdentitiesOnly`, `IdentityAgent=none`: Secretive's keys are never
offered), no prompt (`BatchMode`), and only the daemon's pinned host key (`known_hosts`, no
global file). `writ-sign` uses the same command (`GIT_SSH_COMMAND`, then `core.sshCommand`)
and refuses to sign when neither is set: it never falls back to a plain `ssh`.

Agents never get a git remote pointing at the real upstream (GitHub, Codeberg, Forgejo…)
with credentials. `writ init` also writes the [URL rewrite](gateway.md#url-rewrite) of the
clone's `origin` so it keeps working (in wrapper mode, passed the same way: `writ git push
origin` goes through the daemon, the operator's `git push origin` doesn't; in whole-repo mode,
every push to `origin` in that clone does, and `writ init` says so). For that to hold,
`writ init` refuses, naming the command that fixes each: an `origin` with a push URL of its
own (`remote.origin.pushurl`, in any of git's config files) or several URLs (git pushes to
each); an `origin` URL holding a credential (any user in an `http(s)://` URL, a password in
another: copied into the record and the settings, printed, and used by plain git past the
daemon; what `writ init` prints shows it as `<redacted>`); in wrapper mode, a `writ` remote of
the user's (the daemon's URL would be added to it); in whole-repo mode, a `writ` remote with a
push URL or set outside the repo's own config. A remote changed after `writ init` isn't seen.

## The recovery key (M7.6)

`writ recovery new` prints a fresh age X25519 key and its recipient, saving nothing (the
operator writes it down; best on an offline machine). `writ recovery check` reads the key (no
echo, or one line of stdin), asks the daemon for its recovery recipient and challenge
(`RecoveryShow`, a reader key), and opens the challenge locally: the key's recipient must be
the daemon's, and the challenge must open to what its digest names. Nothing secret is sent.
`writ admin token` seals a token to what `writ info` names (`token_recipients`: the hardware
recipients and the recovery recipient on a hardware keystore), else to the keystore's
recipient.
