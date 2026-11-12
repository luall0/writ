# M7 — Local mode on the Mac

The macOS implementations plugged into an unchanged core: the Unix socket transport, the
process chain attestor and the kqueue session watcher; leases bound to an agent session by
`writ run` and revoked when it ends, the binding completed by the daemon from the kernel, and
required by a template that says so; a daemon isolated from my user under its own role user,
started by launchd; one installer with a setup to pick (`local` first) and an uninstall as
easy, which offers to take Writ out of the repositories it wired
([deployment](../architecture/deployment.md#local-mac),
[platform](../architecture/platform.md#the-macos-process-chain-and-session-watcher),
[the operator's page](../operators/install.md)). The forks settled with the user at its start
(the decision log's 2026-11-09 M7 row), and one more while building (the client's settings
file).

**Status:** done (2026-11-12). `make ci` passes (912 tests, `shellcheck` included); `make e2e`
passes (33 scenarios). All run on macOS; CI runs the same on Linux. The real install on the
Mac (the acceptance items a fake root can't prove) moved to
[M7.7](../roadmap.md#m77--local-mode-checked-on-the-mac), at the user's request: they will
run it once M7.5 and M7.6 are in place, the setup that fits their workflow.

## What was planned

- Unix socket `Transport` (portable Unix, in `writ-platform`).
- `writ-platform-macos`: process chain `CallerAttestor` (executable path and code signature,
  pid + pidversion), kqueue `SessionWatcher`; the full chain in the audit log.
- Leases bound to a session (`caller.descends_from`), revoked when its root process exits.
- **`writ run -- <harness> [args…]`, the session launcher** (settled with the user): an
  agent can't read its own process's pidversion, so without it no real lease would be bound.
  `writ run` starts the harness as its child, exports its own pid (`WRIT_RUN_PID`), passes
  signals on and exits with the harness's status. Under it, `writ request` writes
  `caller: { descends_from: { pid } }` in the ticket, and **the daemon completes the
  binding from the kernel**: the executable, generation and code identity of that pid as the
  submitter's attested chain has them, refusing a pid that isn't in that chain (or a
  submission with no chain, over TCP). The harness quits, `writ run` exits, the lease is
  revoked. Its end-to-end scenario shows a bound lease refused over TCP; the binding itself
  is proved by the integration tests on the Unix socket (local mode joins `make e2e` in
  M7.1).
- **A template can require a bound session** (`require_session: true`, settled with the
  user): the daemon refuses an unbound ticket at submission with its own code, and a
  narrowing can't drop the binding. The local preset's starting templates set it; a detached
  daemon never does (a bound lease is denied everything over TCP). Its rows in the operator
  reference and the configuration coverage, both sides tested.
- **A daemon isolated from my user**: a LaunchDaemon running as a dedicated role user
  `_writd` (uid below 500, no shell, hidden), its binary root-owned, its keys and state in a
  `0700` directory. **The sockets** (agents' and approvals') live in
  `/Library/Application Support/Writ/run/`, `_writd:_writ` `0750`, my user added to a `_writ`
  group: other accounts on the Mac can't connect, and the daemon's files stay out of my
  user's reach. The directory persists across reboots (`/var/run` is wiped at boot and only
  root creates directories there), so the daemon replaces a stale socket at start. **The
  daemon's log** (launchd's `StandardErrorPath`) is `/Library/Logs/Writ/writd.log`,
  `_writd:_writ` `0640`: readable without sudo (agents already see every lease of my user in
  `~/.writ/sessions`); the audit log and state stay in the `0700` directory.
- **One installer, a setup to pick**: `make install` runs the installer (`deploy/install.sh`),
  which asks which setup to install, listing only the ones this build offers on this OS
  (`SETUP=<name>` answers without asking; an unknown or unavailable one is refused with the
  list). M7 brings `local` on macOS; [M7.1](../history/m7.1-local-mode-on-linux.md) adds `local` on Linux,
  and [M8](../roadmap.md#m8--detached-deployment) `detached` and `client`. Every setup shares one frame:
  the dry run, the manifest, the upgrade, the uninstall; each setup is its own steps, and
  adding one changes no other. The installer runs as my user and asks `sudo` only for the
  steps that need root. **POSIX sh** (settled with the user): the frame in
  `deploy/install.sh`, one file per setup (`deploy/setups/local-macos.sh`), shellcheck in
  `make check`; `make test` runs install, upgrade and uninstall against a fake root (a
  prefix, with `dscl`, `launchctl`, `sudo` and `codesign` stubbed on `PATH`), checking the
  manifest, the dry run and the tree left behind against a listing taken before. The real
  install on the Mac is a [manual check](../guides/manual-checks.md).
- **The `local` setup on the Mac, in one command**, from the release builds, starting from the
  spike's `plan-b/` install script: the `_writd` role user and the `_writ` group, my user in
  it; `writd`, `writ` and `writ-sign` in `/opt/writ/bin` (settled with the user), ad-hoc
  signed with the hardened runtime, root-owned with every directory on the way (the
  installer refuses one my user can write: an agent swapping `writd` would run as `_writd`
  at its next start), on my `PATH` through `/etc/paths.d/writ`; the daemon's `0700` directory with a `writd.yaml`
  from the local preset and a starting policy with no repo (repos, keys and templates are then
  added with [`writ admin`](m6.2-managing-the-daemon-from-the-cli.md)); the sockets' directory and the log; the LaunchDaemon's plist, root-owned,
  loaded; `writd init` run as `_writd` (the keystore's passphrase asked on the terminal, never
  stored or passed as an argument); my approval public key (`APPROVER=<.pub>`) in
  `approvers`; for my user, `~/.writ/` with the daemon's host key pinned and the endpoints
  set. It ends by printing what is left: `writ unseal`, then `writ init` in a repo.
  `DRY_RUN=1` lists every change first and makes none. Run again, it upgrades: new binaries,
  the daemon restarted in order (the SIGTERM below), the keystore, state, configuration and
  pins kept. A step that fails stops the install and says what was done so far, which
  `make uninstall` takes back.
- **`writ init` keeps the list of the repos it wires**, in `~/.writ/repos` (each repo's path
  and wiring mode, whole-repo or wrapper, and a workspace root with its children), and
  `writ init --undo` takes a repo off it, for the uninstall and for `writ skill update --all`.
  **`writ init --list`** prints the list as checked (a path that isn't a wired repo, a
  relative path, a link, control characters or an oversized file skipped and named, escaped)
  and **`writ init --undo --all`** undoes every repo on it: the hostile list is read once, in
  Rust, never by the installer's shell (settled with the user). A repo wired before M7 isn't on it until
  `writ init` runs in it again. The list is my user's file, so an agent can write it too: an
  untrusted input, with its row in the [security inventory](../security.md), its bounds and a
  hostile-input test.
- **`writ skill update --all`**: after an upgrade (`make install` upgrades the binaries), the
  skill rewritten in every repo and workspace on `~/.writ/repos`, each as
  [`writ skill update`](m6.2-managing-the-daemon-from-the-cli.md#follow-up-writ-skill-update)
  does it there (each one still holding `writ init`'s record; one that doesn't, or a
  workspace's repository, skipped and named). `make install` ends by naming the command
  when it upgraded `writ`.
- **An uninstall as easy**: `make uninstall` takes the Mac back to how it was before. It reads
  the manifest the install wrote (root-owned) as it went, so it knows the setup and removes
  only what was made: the daemon stopped in order and its LaunchDaemon unloaded; every file,
  directory and the role user removed; nothing it didn't make, nothing outside it. The
  daemon's data (keystore, state, ledger, audit log) is kept unless `PURGE=1`, which names
  what it deletes and asks to confirm on the terminal, and a later `make install` picks it up
  again (the role user made with the same uid). `DRY_RUN=1` as for the install.
- **The uninstall asks whether to take Writ out of the repos already set up too**: it lists
  the repos on `~/.writ/repos` with `writ init --list` (each checked to still hold
  `writ init`'s record; one that doesn't is named and skipped) and asks on the terminal. Yes:
  `writ init --undo --all`, as my user, never as root, before the binaries go, and a repo it can't take back is named with
  why. No: they stay wired and are named, and the question says so before: once `writ` is
  gone, only a new install takes them back. With no terminal it asks nothing and refuses
  unless `REPOS=undo` or `REPOS=keep` answers.
- **`writd recover` checks the daemon is stopped** (left open by M5, found by the
  [M5.6 review](m5.6-review-after-m5.5.md), L17): today it assumes it,
  and two writers would only refuse each other's versions. Settled with the user: `writd run`
  holds an exclusive `flock` on `<state>/writd.lock` for its whole life, its pid written in
  it for the message (the kernel releases the lock when the process ends, so a crash leaves
  none stale), and `writd recover` tries it without waiting and refuses while it is held:
  `writd (pid N) holds <path>`.
- **SIGTERM is an orderly stop** (found by the [M5.6 review](m5.6-review-after-m5.5.md), L16):
  `writd run` stops cleanly on Ctrl-C only (SIGINT); launchd stops a daemon with SIGTERM, which
  kills it at once today (no `stopping` line, an upstream push cut mid-way). `writd run` waits
  on both signals and stops the same way for each, through the platform's signal seam if the
  wait differs by OS (hard rule 4).
- **The recovery guide's macOS commands**: `docs/operators/recovery.md`'s placeholders (the
  LaunchDaemon's label, the daemon's directory and its `writd.yaml`) filled with what
  `make install` makes, and run for real as a manual check.

## What was done

Nine commits on `main`, each passing `make ci` (and `make e2e` when a binary changed):

1. `549c789`: the plan, with the eight forks the user settled (the launcher in M7,
   `require_session`, POSIX sh tested against a fake root, the hostile list read only by
   `writ`, a `flock` for `writd recover`, `/opt/writ/bin`, the sockets through a `_writ`
   group, the log readable by it).
2. **SIGTERM an orderly stop; `writd recover` refused while the daemon runs** (`8ba9e79`).
   SIGINT and SIGTERM taken before anything starts and handled alike: `stopping` with the
   signal, the listeners closed, a lease holder's new git operation or signature refused, those
   in flight waited for (a push answered to its agent), then the upstream operations left (the
   notes), each wait at most `mirrors.timeout` and 5 s. `writd run` holds an exclusive `flock`
   on `<state>/writd.lock`, its pid in it; `writd recover` and a second `writd run` refused
   while it is held. The first test showed the daemon leaving before the agent's push got its
   answer, hence the gateway's own count of operations in flight.
3. **The Unix socket transport** (`bd823f3`): `writ_platform::transport::unix`, a directory
   others can't write, the socket `0660`, only a stale socket replaced; the peer read at accept
   by a `PeerReader` picked per OS; a Unix listener under the network attestor refused at
   start.
4. **The macOS process chain attestor and kqueue watcher** (`ed3e434`): the caller from its
   socket's audit token; each ancestor linked by the unique id its child records for its
   parent (`proc_uniqidentifierinfo`, private ABI checked by the tests against the public
   facts it repeats), the chain ending where the link breaks; code identity only from a valid
   signature, cached per pid and generation; one kqueue thread, a watch per pid shared by the
   leases of a session, a failing kqueue firing every watch.
5. **The binding completed by the daemon, and `require_session`** (`61f914d`): the ticket's
   `caller` a pid only, completed from the submission's kernel chain; a pid outside it, or no
   chain, refused with the `session` code; a template's `require_session` refusing an unbound
   ticket.
6. **`writ run` and git over a local endpoint** (`8c1cc82`): the harness started as the
   session's root, SIGTERM and SIGHUP passed on, its status passed back; `writ request`
   binding under it; a `unix:` endpoint wired as `ssh://git@writ-local` through `nc -U`.
7. **The host's list of wired repositories** (`35cff15`): `<home>/repos`, an index read as
   untrusted input; `writ init --list`, `--undo --all`, `writ skill update --all`.
8. **The client's settings file** (`a851992`): `<home>/config` (`url`, `approval_url`),
   decided with the user so a machine set up by `make install` needs nothing exported.
9. **The installer** (`92aa388`): the frame (`deploy/install.sh`, `frame.sh`), the `local`
   setup (`deploy/setups/local-macos.sh`), `make install` and `make uninstall`, tested against
   a fake root; `shellcheck` in `make check`.

## Decisions

In the [decision log](../decisions.md): the 2026-11-09 rows for M7 (the forks settled at its
start; the orderly stop waiting for whole git operations; the macOS process chain; the
binding completed by the daemon; `writ run` and git over a local endpoint; the list as an
index of roots; the client's settings file; the installer), and the 2026-11-12 row moving the
real install's check to M7.7.

## The security checklist, for M7

1. **Inputs:** three new untrusted inputs, each in the
   [inventory](../security.md#untrusted-inputs) with its bounds and hostile tests: the list of
   wired repositories (`<home>/repos`), the client's settings file (`<home>/config`), the
   installer's manifest (read as root by the uninstall). The ticket's `caller` became a pid
   only, everything else about the process taken from the kernel. The lock file's pid read
   bounded.
2. **Authority:** a binding names only a process the submission runs under; a template can
   require one and the approver can't drop it; who reaches the sockets is decided by their
   directory (a `_writ` group), refused when others could write it; the daemon's files out of
   my user's reach, its binaries root's, every directory on the way checked.
3. **Fail closed:** a caller gone or of another generation refused; a broken parent link ends
   the chain (a bound lease past it refused, never matched elsewhere); a failing kqueue revokes
   every bound lease; once stopping, new operations refused; a file or manifest that can't be
   trusted refused whole; an uninstall question unanswered changes nothing.
4. **Audit:** each connection's chain in its audit lines; the refusals while stopping, and
   those of a binding, each a denial line.
5. **Revocation:** a bound lease revoked when its session's root ends, tested end to end with
   the real daemon (a shell, then `writ run`).
6. **Secrets:** none new; the keystore's passphrase typed into `writd init` only;
   `writd recover` refuses before asking it.
7. **Display:** the completed binding reaches `writ sign` through its escaping; every path and
   line the lists and the settings file skip shown escaped, once.
8. **Dependencies:** `core-foundation-sys` 0.8 (already in the tree, `link` only), more of
   `libc`'s calls in `writ-platform-macos`'s one `unsafe` module; `shellcheck` (a developer
   tool).
9. **Guarantees:** a lease bound to a session refuses a caller outside its process tree and
   every TCP caller, and ends with the session; a push in flight runs to its end at a stop.
10. **Threat model:** boundary 1 says how a binding is made and that `require_session` keeps an
    injected agent from dropping it; boundary 6 (the daemon vs my user) is what the installer
    sets up.

## Acceptance

- [x] **The graft test:** no change in `writ-core`, `writ-store`, `writ-git`, `writ-gateway`,
      `writ-approval` or the clients, beyond bug fixes and the changes settled at M7's start
      (`writ init`'s list of wired repos and its `--list` and `--undo --all`, `writ run` and
      the binding it asks for, the daemon completing a caller from the submitter's chain,
      `require_session`, the client's settings file `<home>/config`); only new
      implementations, `writd`'s wiring and config, and the installer.
      *`writ-store` and `writ-git` untouched. `writ-core`: the pid-only `caller` and its
      completion (`fit::submit`, `Submission::chain`), `require_session`. `writ-approval`: the
      chain passed to `fit::submit`, the binding's refusal code, `require_session` in the
      policy view. `writ-gateway`: the orderly stop's count of operations (`Gateway::stop`,
      a bug fix of M5.6's L16) and the test gateway on the real Unix transport. The clients:
      the list, `writ run`, the binding, the settings file, the `unix:` wiring. Everything else
      is in `writ-platform`, `writ-platform-macos`, `writd`'s wiring, `writ-mirror`'s in-flight
      count (the orderly stop) and `deploy/`.*
- [x] The macOS implementations pass the same contract suites as the portable ones.
      *`writ-platform-macos/tests/local_mode.rs`: the attestor, the watcher and the Unix
      transport with the audit token's peer through `writ_platform::contract`'s suites, with
      real processes, eight runs in a row.*
- [x] The same agent workflow as M6 works against the local daemon with no client change
      beyond the endpoint.
      *`the_agent_workflow_runs_under_writ_run_against_the_local_daemon`: under `writ run`,
      `writ request`, `writ init`, a commit signed by the daemon through `writ-sign` over the
      socket, a push landing upstream; the endpoint from the client's settings or `WRIT_URL`.*
- [x] A lease bound to a session refuses a caller outside that process tree, whatever its
      process name or arguments, and refuses every TCP caller.
      *`a_lease_bound_to_its_session_serves_inside_it_only_and_ends_with_it` (inside served;
      outside and over TCP refused, code `caller`); a caller under another `argv[0]`
      (`exec -a`) named by its executable: `the_caller_is_its_executable_whatever_it_calls_itself`;
      an orphan never placed in the session it left.*
- [x] Quitting the session's root process revokes the lease.
      *The same test (a shell as the root) and the `writ run` workflow test: the `revoke` line,
      the certificate refused after.*
- [x] Under `writ run`, `writ request` gives a lease bound to the `writ run` process, its
      executable, generation and code identity filled by the daemon from the kernel; a pid
      outside the submitter's chain, or a submission with no chain, is refused with its
      code; quitting the harness revokes the lease.
      *`the_agent_workflow_runs_under_writ_run_against_the_local_daemon` (the binding shown to
      the approver with `writ run`'s pid and signature), `a_binding_is_completed_from_the_kernel_s_chain_and_nothing_else`
      (a pid outside the chain, no chain: `session`), scenario 20 (over TCP, end to end).*
- [x] A template with `require_session: true` refuses an unbound ticket with its code and
      takes a bound one; a narrowing can't drop the binding; without the key, an unbound
      ticket is taken.
      *`a_template_requiring_a_session_takes_only_a_bound_ticket`, `a_narrowing_can_t_drop_the_binding`
      (service); with the real daemon, the unbound ticket refused in
      `a_lease_bound_to_its_session_serves_inside_it_only_and_ends_with_it`.*
- [x] The installer's fake-root test passes in `make test` (install, dry run, upgrade,
      uninstall, a failed install taken back), and shellcheck in `make check`.
      *`crates/writ-integration/tests/installer.rs`, four tests; `tool/shellcheck.sh` in
      `make check`.*
- [ ] On a Mac without Writ, `make install` (the `local` setup picked at its question, then
      with `SETUP=local`) then `writ unseal` gives a working local daemon with nothing else
      done by hand; `DRY_RUN=1` lists exactly what the install then makes; a second
      `make install` upgrades the binaries and keeps the keystore, state and pins; a
      `SETUP` this OS doesn't offer is refused with the list.
      *Against the fake root: every part of it (`the_dry_run_lists_every_change_and_makes_none_and_a_setup_is_picked_from_the_offered`,
      `an_install_upgrades_and_uninstalls_leaving_the_mac_as_before`). For real on the Mac:
      [M7.7](../roadmap.md#m77--local-mode-checked-on-the-mac).*
- [ ] `make uninstall` leaves the Mac as before the install (the role user, the
      LaunchDaemon, the binaries, the directories and `~/.writ/`'s pins gone, checked
      against a listing taken before), the daemon's data kept unless `PURGE=1` is
      confirmed; after an install stopped half way, it takes back what was made.
      *Against the fake root, compared with a listing taken before (the users and groups
      too), `PURGE=1` confirmed on a terminal, a failed install taken back. For real: M7.7.*
- [x] The repos question: answered yes, every repo on the list (wrapper, whole-repo, a
      workspace) is back exactly as before its `writ init`, undone as my user; answered no,
      none is touched and each is named; with no terminal and no `REPOS`, the uninstall
      refuses before changing anything. A hostile `~/.writ/repos` (a path that isn't a
      wired repo, a relative path, a link, control characters, an oversized file)
      never makes it touch anything `writ init` didn't wire, and what it skips is named,
      escaped.
      *`the_list_of_wired_repositories_is_read_as_untrusted_and_undoes_only_what_writ_init_wired`
      (a workspace and a repository beside seven hostile lines, an oversized file);
      `an_install_upgrades_and_uninstalls_leaving_the_mac_as_before` (no `REPOS` refused,
      `REPOS=undo` taking a repository back as before); a whole-repo clone's undo is
      `writ init --undo`'s own (`a_dedicated_clone_is_wired_whole_and_undone_exactly`), which
      `--all` runs.*
- [x] `writ skill update --all` rewrites the skill in every repo and workspace on the list
      (wrapper, whole-repo, a workspace root), each said as `writ skill update` says it, and
      the same hostile list makes it write nothing but Writ's own skill files at their
      recorded paths, what it skips named, escaped.
      *The same list test (a workspace root and a repository, the hostile lines skipped, a
      clone never wired untouched); scenario 21 end to end.*
- [ ] My user (so any agent) can't read the daemon's keystore or attach to the daemon
      (`cat` and `lldb -p` refused), and the daemon starts again after a reboot.
      *Needs the real install: M7.7.*
- [x] `launchctl stop` (SIGTERM) stops the daemon as Ctrl-C does: the `stopping` line, the
      listeners closed, an upstream operation in flight allowed its deadline.
      *`sigterm_stops_in_order_and_lets_an_upstream_push_in_flight_finish` and
      `sigint_stops_the_same_way` with the real binary (`kill -TERM`); through launchd
      itself: M7.7.*
- [x] `writd recover` refuses while the daemon runs, naming why, and works once it is
      stopped (both sides tested, a crashed daemon's leftover not
      blocking it); the recovery guide's macOS steps run as written.
      *`recover_is_refused_while_the_daemon_runs_and_a_crashed_one_leaves_no_lock` (and a
      second `writd run` refused); the recovery guide's macOS steps filled in with what
      `make install` makes, run as written in M7.7.*
