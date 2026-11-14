# Client settings: `writ` and `writ-sign`

What `writ` reads, on an agent host and on your machine. Nothing here grants anything: the
daemon checks everything again. The clients never read `~/.ssh` and never use your own
ssh-agent to connect (it would offer your personal keys to the daemon).

## `writ`: flags and environment

Each setting is a flag or an environment variable; the flag wins. `writ <command> --help`
lists them.

| Flag | Variable | Default | What it is |
|---|---|---|---|
| `--home` | `WRIT_HOME` | `~/.writ` | Writ's directory on this host: sessions, pins, the reader key |
| `--known-hosts` | `WRIT_KNOWN_HOSTS` | `<home>/known_hosts` | The daemon's pinned SSH host key ([setup, step 7](setup.md#on-the-daemon-host)) |
| `--tls-pins` | `WRIT_TLS_PINS` | `<home>/tls_pins` | The daemon's pinned TLS certificate, for an `https://` approval URL |
| `--reader` | `WRIT_READER` | `<home>/reader` | Your reader key. `writ reader <name>` creates it and prints the line for the daemon's `readers` |
| `--url` | `WRIT_URL` | none | The agents' listener: `ssh://host:port`, or `unix:<path>` for a daemon on this Mac (local mode). Used by `request`, `wait`, `close`, `policy`, `init` |
| `--approval-url` | `WRIT_APPROVAL_URL` | none | The approval listener, `https://host:port`, `ssh://host:port`, or `unix:<path>` for a daemon on this Mac (local mode). Used by `ls`, `sign`, `refuse`, `revoke`, `report`, `prove-key`, `unseal`, `recovery check` and every `admin` command |
| none | `WRIT_SESSION` | none | The lease an agent works under: `writ git`, `writ exec`, `writ close`, `writ mark` and `writ-sign` use its session, whatever `current` points at. Set it to the line `writ request` prints. A lease this host doesn't have, or that ended, is refused, never replaced by `current`. [Several agents](#several-agents-on-one-host) |
| `--key` | `WRIT_APPROVAL_KEY` | `<home>/approver.pub` | Your approval key's **public** half (a private key file is refused) |
| `--agent` | `WRIT_APPROVAL_AGENT` | `$SSH_AUTH_SOCK` | The ssh-agent holding your approval key: Secretive's socket |
| none | `WRIT_RUN_PID` | none | Set by `writ run` for the agent it starts: `writ request` binds each ticket to that session. Not yours to set. [Binding a lease to its session](#binding-a-lease-to-its-session-local-mode) |
| none | `WRIT_SSH_KEYGEN` | `/usr/bin/ssh-keygen` | The `ssh-keygen` that signs your approvals: an absolute path, OpenSSH 8.9 or newer. Never looked up in `PATH`, where anything could sit first and change what gets signed |
| none | `WRIT_GPG` | `/usr/bin/gpg` | `writ-sign`: the `gpg` it hands git's OpenPGP `--verify` calls to, an absolute path. It never runs gpg to sign: the key is the daemon's |

### The settings file

`<home>/config` gives the two endpoints when no flag or variable does. `make install` writes
it for a daemon on this Mac. A flag or a variable still wins.

```text
url = unix:/Library/Application Support/Writ/run/agents.sock
approval_url = unix:/Library/Application Support/Writ/run/approvals.sock
```

| Setting | What it is |
|---|---|
| `url` | The agents' listener, as `--url` takes it |
| `approval_url` | The approval listener, as `--approval-url` takes it |

One `key = value` a line. Blank lines and lines starting with `#` are skipped. Anything else
(an unknown key, a key twice, a control character, a file over 16 KiB or a link in its
place) makes `writ` refuse the file and name the line. An agent can write this file too. It
can only change where `writ` connects, never which daemon it trusts: that is the host key in
`known_hosts`.

Every command and its arguments: [clients](../architecture/clients.md). `writ sign`'s
narrowing flags: [approvals](../architecture/approvals.md).

Approve from a terminal at least 80 columns wide. `writ sign` keeps every row within that
width, so the terminal never wraps one; a narrower terminal would wrap rows again, and a
wrapped row loses the `│` mark that shows text the agent wrote.

`writ sign` shows at most 40 rows of each thing the agent wrote (its title, task and plan),
then how many more there are and the command that shows them all (`writ sign <id> --full`).
What the lease enforces is always shown whole, the expected paths included. A report works
the same way: `writ report <id> --full`, or `writ close --full` for the agent.

Every "Sign …?" question signs only on `y` or `yes`. Answer anything else and nothing is
signed: `writ` then exits with status 6, whatever the command, so a script can tell a change
you declined from one that was applied.

## Files

| Path | Where | What it is |
|---|---|---|
| `<home>/known_hosts` | Both | The daemon's host key: `[<daemon>]:2222 <key>` on agent hosts, `[<daemon>]:2223 <key>` on your machine. A plain file, yours (or root's) and writable by nobody else, or `writ` refuses it |
| `<home>/tls_pins` | Your machine | The daemon's TLS certificate: `[<daemon>]:8443 SHA256:…`. A plain file, yours (or root's) and writable by nobody else, or `writ` refuses it |
| `<home>/approver.pub` | Your machine | Your approval key's public half |
| `<home>/reader` | Your machine | Your reader key, mode 0600 |
| `<home>/sessions/<lease>/` | Agent host | One per ticket: its session key, its certificate once signed, the lease's terms, and the agent signing key's public half (`signing_key.pub`, for `git verify-commit`), and for an OpenPGP key its certificate (`signing_key.asc`: import it into a GnuPG home to verify). `ended` once it was closed or renewed; `marks`, the agent's `writ mark` lines |
| `<home>/sessions/current` | Agent host | A link to the latest granted session: what wired repos use when neither `WRIT_SESSION` nor a pinned lease says otherwise |
| `<skills folder>/writ/SKILL.md`, `timings.md` | Agent host | The agent skill `writ init` installs, and beside the first one what the agent learns about sizing tickets. [The skill](#the-agent-skill) |
| `<home>/config` | Both | The daemon's endpoints, when no flag or variable gives them. [The settings file](#the-settings-file) |
| `<home>/repos` | Agent host | The repositories and folders `writ init` wired on this host, one a line. `writ init --list` shows them, `writ init --undo --all` takes them all back, `writ skill update --all` updates the skill in each. An agent can write this file too, so each line is checked before anything is done with it. [Every wired repository at once](#every-wired-repository-at-once) |
| `<folder>/.writ-workspace`, `<skills folder>/writ-workspace/SKILL.md` | Agent host | A folder of repositories wired at once: what `writ init` did there, and the skill for an agent at that folder. [A folder of repositories](#a-folder-of-repositories) |

## `writ init` and `writ-sign`

`writ init <repo>` writes the git settings a wired repo needs: in the environment of
`writ git` and `writ exec` (wrapper mode), or in the repo's config (`--whole-repo`). It
records them in `<git common dir>/writ/config`. Never set them by hand: `writ init --undo`
removes exactly what `writ init` wrote.

`writ-sign` (git's `gpg.ssh.program`) reads only those settings: `writ.url`, `writ.repo`,
`writ.gitdir`, `writ.session`, and the SSH command git uses. Each one:
[repo setup on an agent host](../architecture/clients.md#repo-setup-on-an-agent-host).

`writ init`'s flags:

- **`--whole-repo`** writes the settings in the repo's config, for a clone dedicated to an
  agent.
- **`--email`** is the committer email (default: the lease's, when it allows one). The name
  is the lease's when its template sets `committer_name`: `writ git` sets git's `user.name`
  to it, whatever your own git says.
- **`--lease`** pins the repo to a lease: its session, never `current` (`WRIT_SESSION` still
  comes first).
- **`--agents`** says who gets the skill, without asking: `claude`, `agents`, `opencode`,
  `cursor`, comma-separated, or `none`.
- **`--skill-dir`** also installs the skill in that folder (`<folder>/writ/SKILL.md`).
- **`--global`** installs the skill in your own folders (`~/.claude/skills`…) instead of the
  repo's.
- **`--agents-md`** adds a line pointing at the skill to `AGENTS.md` and `CLAUDE.md`.
- **`--repo <dir>=<name>`**, in a folder of repositories only: the registry name of the
  repository in `<dir>`, or `-` to leave it out. Give it once per repository.
- **`--undo`** takes back what `writ init` did. The timings file stays.

## A folder of repositories

Some people keep several repositories in one folder and start one agent at the folder, which
works on all of them. Run `writ init` in that folder without a repo name. It finds the
repositories one level down and wires each one, as `writ init <repo>` would in it.

- Each repository needs its name in the daemon's registry. By default it is the last part of
  its `origin` URL, without `.git`, or else its folder's name. On a terminal, `writ init`
  shows that default for each repository: press Enter to keep it, type another name, or `-`
  to leave the repository out. Without a terminal, give `--repo <dir>=<name>` for every
  repository (`--repo vendor=-` leaves one out); otherwise nothing is wired.
- When the folder is a git repository itself, it is left out unless you name it:
  `--repo .=<name>`. Its submodules are never wired.
- Folders whose names start with `.`, links and plain folders are not wired. Links are named
  in the summary.
- The skill goes in the folder only: the `writ-workspace` skill. It tells the agent to give
  every repository its task changes a block in one ticket (`writ policy <repo>…` says
  whether one ticket can cover them, else one lease per repository), and to run git as
  `writ git -C <dir> …`. A program that runs git runs in one repository at a time:
  `writ exec -C <dir> -- <program>`.
- In the folder, `writ git` and `writ policy` list the repositories. `writ close` there
  records the run in the folder's timings file, under the repositories the lease named
  (`api + web`).
- `writ init` records the workspace in `<folder>/.writ-workspace`. Run `writ init --undo` in
  the folder to take every repository back, and the folder too. In one of the repositories,
  `--undo` refuses and names the folder. The timings file stays.
- `--whole-repo`, `--email`, `--lease` and the skill's flags apply to every repository.

## Every wired repository at once

`writ init` adds each repository or folder it wires to `<home>/repos`, and `writ init --undo`
takes it off. Three commands use that list:

```sh
writ init --list              # what writ init wired here
writ skill update --all       # after upgrading writ: the skill rewritten in each
writ init --undo --all        # each one taken back, as writ init --undo there would
```

Each line is checked first. It must be a full path to a repository or folder that still
holds `writ init`'s own record of it, with no link, no `..` and no odd character. A line that
isn't is skipped and shown. A file larger than 256 KiB is refused whole. A repository wired
before M7 isn't on the list: run `writ init` in it again to add it.

## Several agents on one host

Each `writ request` that is granted moves `<home>/sessions/current`. Two agents sharing a home
would follow it and swap leases. Give each agent its own lease:

- `writ request` prints `export WRIT_SESSION=<lease>`: run the agent with it. It warns when it
  moves `current` while another lease of the home still runs.
- Or pin a clone to a lease with `writ init --lease <lease>`.
- Or give each agent its own home (`WRIT_HOME`), or its own OS user: see
  [good practice](good-practice.md#more-isolation).

## Binding a lease to its session (local mode)

With a daemon on this Mac, start the agent through `writ run` (here Claude Code):

```text
writ run -- claude
```

Each ticket the agent then asks for is bound to that session. Its lease is refused to any
program the session didn't start, and it is revoked when the agent quits. The agent writes
nothing more in its ticket. `writ request` adds the binding, and `writ sign` shows you which
process the lease is bound to. The daemon binds a lease only to a program `writ run` started,
never to your shell or terminal. A template with `require_session` refuses a ticket asked
for outside `writ run`.

`writ run` exits with the agent's status. A Ctrl-C reaches the agent as usual.

## The approval popup on the Mac

With a daemon on this Mac, `make install` starts the approval popup at each login (unless you
answered `no`). When an agent's ticket waits for your signature, a window comes up in front of
every app, full-screen ones too:

- It shows the whole ticket, as `writ sign <id> --full` would in a terminal, laid out: what
  you sign first, then what the agent wrote, in a box of its own (the agent's words, never
  acted on), then any change since the ticket it follows (removed in red, added in green),
  then the details, folded: click a section's header to open it. Paths, branches and
  operations show one by one. **Copy as text** copies it as a terminal
  shows it.
- **Sign** signs it with your approval key: Secretive asks for Touch ID, as in a terminal.
- **Decline** asks for a reason for the agent (you may leave it empty), then **Refuse** signs
  the refusal.
- Both buttons stay greyed for a second after the window comes up, and no key presses them:
  a click or a Return meant for another app does nothing.
- Several tickets at once: the list on the left shows every one, with its title and
  repositories, and the window shows the oldest. Click another to look at it first. When you
  have decided, the oldest left comes up.
- Closing the window decides nothing: the ticket keeps waiting, and the popup doesn't show it
  again until it restarts. Sign it in a terminal with `writ sign <id>`, where you can also
  narrow it. The popup never narrows.

The window goes by itself when the ticket stops waiting (you signed it in a terminal, the
agent withdrew it, it expired). The popup never shows an admin change or an unseal: those stay
in the terminal.

It runs `writ sign --ui` with your settings, and two of them come from its LaunchAgent
(`~/Library/LaunchAgents/dev.writ.popup.plist`): `WRIT_HOME`, and `WRIT_APPROVAL_AGENT`, the
agent socket you gave at the install. To stop it until the next login, or start it again:

```text
launchctl bootout gui/$(id -u)/dev.writ.popup
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.writ.popup.plist
```

An agent running as you can stop the popup too, or draw a window that looks like it. Touch
ID is what matters: touch it only for a signature you started from a window or a terminal
you trust ([threat model](../threat-model.md#residual-risks-v1)).

## The agent skill

`writ init` installs the skill where each agent looks for it. On a terminal it asks which
agents, with the ones it detects marked; `--agents` or `--skill-dir` answer for it. Without a
terminal and without them, it refuses and wires nothing.

| Agent | Folder in the repo | With `--global` |
|---|---|---|
| Claude Code | `.claude/skills` | `~/.claude/skills` |
| Codex, Gemini CLI, GitHub Copilot, Amp (`agents`) | `.agents/skills` | `~/.agents/skills` |
| OpenCode | `.opencode/skills`, only when neither of the two above is picked: it reads them too | `~/.config/opencode/skills` |
| Cursor | `.cursor/skills` | `~/.cursor/skills` |

- In the repo, each `writ/` folder installed goes in `.git/info/exclude`: never committed.
- `SKILL.md` is Writ's: a new `writ init` replaces it. A `SKILL.md` that isn't Writ's is never
  written over.
- After upgrading `writ`, run `writ skill update` in each wired repository (at the folder,
  for a folder of repositories): it rewrites the skill files `writ init` put there with this
  `writ`'s skill, and says which changed. One you replaced with your own is left alone.
- The skill has the agent start each task that changes files, before any edit, with
  `writ policy` (what a ticket for the repo may ask: run it yourself to see what your agents
  see) and the ticket, checked with `writ request --dry-run` before it is submitted.
- `timings.md` beside the first one is what the agent learns. `writ close` records each run in
  it and keeps it within its limits; `writ timings` changes them; `writ check timings.md`
  says what `writ close` would drop or rewrite. `writ init --undo` keeps it.
