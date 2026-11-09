# Clients

Everything outside the daemon is **untrusted** ([design principle 1](../product.md#design-principles)):
clients make the workflow pleasant, the daemon makes it safe.

## Client list

| Client | Role |
|---|---|
| `writ` CLI | `policy` (what a ticket for each repo named may ask, from the daemon: templates, branches, committer emails, signing key id, limits, protected refs, the ticket link; for several, whether one ticket can cover them), `request` (`--dry-run`: the daemon's checks, nothing submitted), `wait`, `sign`, `refuse`, `close` (the lease ended with a summary, its activity report printed and recorded in the timings file), `report` (a lease's report, for the approver), `mark` (the end of a phase, the agent's), `timings` (the timings file's limits), `check` (a ticket file or the timings file, checked as written, nothing sent), `ls`, `revoke`, `prove-key` (an agent signing key's [proof for a remote](approvals.md#proving-a-signing-key-to-a-remote)), `unseal`, `admin show` and `admin apply` (the policy, approvers or readers in force, and [signed changes](approvals.md#admin-changes) of them), `admin repo|template|key|host list` and `show` (the policy in force [entry by entry](approvals.md#reading-the-policy-entry-by-entry), a key's public half with `--public`), `admin token` (an upstream's or a notifier's token, [encrypted on the Mac](approvals.md#writ-admin-token)), `reader`, `init` (wires a repo: [repo setup](#repo-setup-on-an-agent-host); with no repo named, a folder of repositories: [workspaces](#workspaces); `--list` and `--undo --all`: [the host's list](#the-hosts-list-of-wired-repositories)), `skill update` (`--all`: in every one on that list), `git` and `exec` (git, or a program, with that wiring; `git` finds the repository behind git's global options, `exec -C <dir>` runs in one), `run` (an agent harness as the root of its session: [binding a lease to its session](#binding-a-lease-to-its-session)) |
| Agent skill (`skill/writ/SKILL.md`, built into `writ`, installed by `writ init`; at a workspace root, `skill/writ-workspace/SKILL.md` instead: [workspaces](#workspaces)) | Teaches the agent the ticket workflow, at the start of any task that changes files and before any edit: read what the repo allows (`writ policy`) and the timings file, think through the scope (a branch of its own within the template's patterns, never the default or a protected one; `push` unless told not to) and estimate it, write a ticket (task, plan, repos, branches, estimate, limits), check it (`writ check`, then `writ request --dry-run`) and submit it with `writ request`, wait for my decision, then work with `WRIT_SESSION` set; on refusal, revise using my feedback; on an out-of-ticket denial, submit an amendment; out of time or counts, a renewal; when done, `writ close` with a summary, then a note in the timings file if something explains the figures. Everything the agent writes in a ticket is shown to me as-is and never trusted by the policy engine. [The skill and its installer](#the-agent-skill) |
| `writ-sign` | `gpg.ssh.program` shim: `-Y sign` → daemon (the gateway's `writ-sign git <repo>` command for the repo in `writ.repo`, reached at `writ.url` with the SSH command git uses: `GIT_SSH_COMMAND`, then `core.sshCommand`, never a plain `ssh`), with the first parent commit and the trees the daemon needs to see which paths the commit touches ([Gateway](gateway.md#signing)); everything else (`-Y verify`, `find-principals`) → real `ssh-keygen`. Also `gpg.openpgp.program` for a lease whose key is OpenPGP: `--status-fd=2 -bsau <key>` → daemon (`writ-sign openpgp <repo>`, the object on stdin, the armored signature on stdout, `[GNUPG:] SIG_CREATED` on stderr; no GnuPG home, keyring or agent used), `--verify` → the real `gpg` (`WRIT_GPG`, an absolute path, `/usr/bin/gpg` by default), anything else refused |
| Session agent ([M8.5](../roadmap.md#m85--non-exportable-session-keys), on when the host has the hardware) | Holds the session key so it can't be copied: a dedicated ssh-agent backed by the Secure Enclave, a TPM or a YubiKey |
| Harness integration | Omega Code requests a lease when an agent session starts and wires the repo's git config |
| Approvers | v1: `writ sign` + Secretive. Later: own Mac SE app, iPhone app |

Code: `crates/writ-cli` (`writ`), `crates/writ-sign` (`writ-sign`), `skill/writ/` and
`skill/writ-workspace/` (the skills). The approver side of the CLI is described in [Approvals](approvals.md).

`writ` reads its settings from flags or environment variables: `WRIT_URL` (agents' listener,
`ssh://host:port` or `unix:<path>`), `WRIT_APPROVAL_URL` (approval listener: `https://host:port`, `ssh://host:port` or `unix:<path>`),
`WRIT_APPROVAL_KEY` (the approval key's public half, default `~/.writ/approver.pub`),
`WRIT_APPROVAL_AGENT` (its agent socket, default `SSH_AUTH_SOCK`), `WRIT_HOME` (default
`~/.writ`), `WRIT_KNOWN_HOSTS` (default `~/.writ/known_hosts`, where the daemon's host key
is pinned; `writd host-key` prints it), `WRIT_TLS_PINS` (default `~/.writ/tls_pins`, lines
`[host]:port SHA256:…` pinning the HTTPS certificate; `writd tls-fingerprint` prints it) and
`WRIT_READER` (default `~/.writ/reader`: the key the approval API lets in; `writ reader
[<name>]` makes it on first use and prints the line for the daemon's `readers` file),
`WRIT_SESSION` (the lease an agent works under: [the session](#which-session-a-command-uses)),
`WRIT_RUN_PID` (set by `writ run`: [the session binding](#binding-a-lease-to-its-session)), and
`WRIT_SSH_KEYGEN` (the ssh-keygen `writ sign` runs, an absolute path; default
`/usr/bin/ssh-keygen`, never looked up in `PATH`). It never reads `~/.ssh` or uses the user's ssh-agent
for connections: it would offer personal keys to the daemon. Exit statuses: 0 done, 1 error,
3 rejected by policy, 4 refused, 5 expired or withdrawn, 6 not signed (`writ sign` or `writ
prove-key` answered no).

Denial reasons from the daemon reach the agent: `writ-sign` prints them on stderr (escaped,
like any text from elsewhere) before exiting 1, and git shows them; git shows the gateway's
rejection message after a push. When ssh itself fails (the gateway refuses an expired, revoked
or unknown certificate during authentication, where SSH can't say why), `writ-sign` reads the
session certificate named in the SSH command and says whether there is no lease, an expired
one, or one the daemon refused: a convenience, the daemon decided already.

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
each from `max_signatures`.

**Whole repo** (`writ init <repo> --whole-repo`): the same settings written in the repo's
config, for a clone dedicated to an agent (a VM, a container); plain `git` is then the agent's
git. The values they replace are recorded first.

`writ init --undo` takes either back exactly: the record removed, and in whole-repo mode every
key restored as it was. Good practice for the operator (their own keys, guardrails in the
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
  folder's own repository (named: submodules aren't wired yet) are not. At most 256. The
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

`writ run -- <program> [args…]` (`writ_cli::run`) starts an agent harness as its child and
stays as the root of its session. It sets `WRIT_RUN_PID` to its own pid for the harness.
SIGTERM and SIGHUP are passed on to the harness. SIGINT and SIGQUIT already reach the whole
foreground group from the terminal, so they are not passed on again. Its exit status is the
harness's, or 128 and the signal that ended it.

Under it, `writ request` adds `caller: { descends_from: { pid } }` to a ticket that names no
caller (after a leading `---`). The daemon completes the binding from the kernel's chain of
the submission ([lease model](../lease-model.md#the-complete-ticket)) and refuses a pid the
submission doesn't descend from. When the harness quits, `writ run` exits and the session
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
never replaced by `current` (`wiring::choose_session`). One command uses one session: with
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
  `AGENTS.md` when the repo has neither); otherwise the summary prints the line.
- What `writ init` creates and adds is recorded (`skill.created`, `skill.createddir`,
  `skill.exclude`, `skill.agentsmd`…), and `--undo` takes exactly that back: the skill files
  that are still Writ's, and the folders made for them once empty. `timings.md` stays. A
  `SKILL.md` it rewrote (Writ's already: a global skill another repository's `writ init`
  made) is recorded too (`skill.written`), never removed by `--undo`.
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
the oldest note, then the least recently updated repository. The file is untrusted: what
doesn't parse is rewritten, every line is cut to 400 characters, and `writ check` names every
line `writ close` would drop or rewrite.

The SSH command never reaches the user's own SSH setup: no `~/.ssh/config` (`-F /dev/null`), no
other key and no agent (`IdentitiesOnly`, `IdentityAgent=none`: Secretive's keys are never
offered), no prompt (`BatchMode`), and only the daemon's pinned host key (`known_hosts`, no
global file). `writ-sign` uses the same command (`GIT_SSH_COMMAND`, then `core.sshCommand`)
and refuses to sign when neither is set: it never falls back to a plain `ssh`.

Agents never get a git remote pointing at the real upstream (GitHub, Codeberg, Forgejo…)
with credentials. `writ init` also writes the [URL rewrite](gateway.md#url-rewrite) of the
clone's `origin` so it keeps working (in wrapper mode, passed the same way: `writ git push
origin` goes through the daemon, the operator's `git push origin` doesn't; in whole-repo mode,
every push to `origin` in that clone does, and `writ init` says so).
