# End-to-end scenarios

`make e2e` runs Writ the way people run it: the real Linux binaries in their own containers,
a real Forgejo as the remote, the operator's setup done with the operator guide's own
commands, and agents and an approver using `writ` and git as the docs tell them to. It
exists because the in-process harnesses take shortcuts a person never takes (absolute paths,
keys made in-process, files written in another order): M4's GitHub check found two bugs that
way, on paths only a real operator takes ([M4.1](history/m4.1-real-end-to-end-scenarios.md)).
The next such bug fails the pipeline, not a person.

**The rule** ([AGENTS.md](../AGENTS.md#hard-rules), rule 18): every command and every flag
of `writ`, `writd` and `writ-sign` is used for real by at least one scenario. A new command
or flag comes with its scenario in the same change; the [coverage registry](#coverage-every-command-and-flag)
says which, and `make check` and `make test` fail when one is missing.

## Running it

```sh
make e2e                        # every scenario (about 3.5 minutes once the images are cached)
make e2e ARGS=wrapper_mode      # the scenarios whose name holds a filter (libtest's filter)
WRIT_E2E_KEEP=1 make e2e        # keep the stack afterwards, to look at it (the command to remove it is printed)
```

It needs Docker with compose, and make: everything else (the Rust toolchain included) runs in
containers, and nothing touches your own git, SSH or remotes. It starts from nothing (a
compose project of its own, `writ-e2e-<pid>`) and removes everything it made (containers,
network, volumes, images) whatever happens, and the layers it left in Docker's build cache
(the binaries' copies built from that tree and the steps on top of them, matched by
patterns of `e2e/Dockerfile`'s steps: `BUILD_CACHE_STEPS` in `tool/e2e.sh`). Only the cargo caches stay (the registry and a
`target/` pruned to the last build by `tool/target-cache.py`, as `make test` does), so a
second run compiles incrementally. Docker Desktop's own GC caps none of this unless told to:
its default `builder.gc.defaultKeepStorage` is the space it *keeps*, not a maximum; set
`defaultMaxUsedSpace` in Settings → Docker Engine for a cap. CI runs it as a job of its own on every push (`.github/workflows/ci.yml`,
job `e2e`); it is not part of `make ci`, and the pre-push hook doesn't wait for it.

The expiry scenario waits for an unsigned ticket to expire: the end-to-end daemon's `min_ttl`
is `30s` (`e2e/config/writd.yaml`; `5m` by default), so it waits about 30 seconds, and a ticket
under it is refused naming it. A run takes about as long as its longest other scenario.

## The stack

| Container | Image (`e2e/Dockerfile` target) | Who's there | Reached as |
|---|---|---|---|
| `forgejo` | `codeberg.org/forgejo/forgejo:13.0.5`, pinned by digest | the remote: an admin account `writ` (email `agent@writ.invalid`) owning one repository per scenario | `http://forgejo:3000` (API, web forms), `ssh://git@forgejo` (the daemon's upstream); also named `forgejo-added` (the repo the setup adds with `writ admin`), `forgejo-scan` and `forgejo-new` (the host key scan, scenario 23), pinned by no one at the start |
| `forgejo-https` | `tls-front`: Debian 13, socat and a throwaway self-signed certificate made at build time | Forgejo over HTTPS: TLS in front of `forgejo:3000` | `https://forgejo-https:3443` (the `https` repo's upstream) |
| `forgejo-https-system` | `tls-front` again (`TLS_NAME`), with its own certificate, which the setup adds to the `writd` container's system store, never to `mirrors.ca_certs` | Forgejo over HTTPS, a second front | `https://forgejo-https-system:3443` (the `https-system` repo's upstream: refused) |
| `writd` | `writd`: Debian 13, git 2.47, OpenSSH 10.0, the real `writd` | the operator, user `writ`, in `/home/writ` (`writd.yaml`, `policy.yaml`, `approvers`, `readers`, `data/`, `writd.log`) | `writd:2222` (agents), `writd:2223` (approval API, SSH), `writd:8443` (approval API, HTTPS) |
| `agent` | `agent`: the same base, `writ` and `writ-sign` | user `agent`: one directory and `WRIT_HOME` per scenario's agent (`~/agents/<name>`), and the operator's own git (`user.name Operator`); user `approver`: the approver's machine (`~/.writ`, a throwaway ssh-agent holding the approval key, standing in for Secretive) | `docker exec` |
| `local` | `local`: the same base, `writd`, `writ` and `writ-sign`, OpenBSD's `nc`, `strace` and `gdb`; given `SYS_PTRACE` | local mode on Linux, one machine (scenario 24): the system user `writd` (the daemon, started as its systemd unit starts it, with `setpriv`), the `writ` group, user `dev` in it (the agent and the approver); `/etc/writ/writd.yaml`, `/var/lib/writ`, the sockets in `/run/writ`, the log in `/var/log/writd.log` | `docker exec` |
| `runner` | `runner`: the scenarios' test binary and the Docker client | the scenarios, driving the others through the Docker socket and Forgejo's API | started by `make e2e` |

- **The images** are built from the repository by `e2e/Dockerfile`: a builder stage on the
  pinned Rust image (`rust:1.99.1-slim-trixie`, the toolchain `rust-toolchain.toml` pins)
  builds the binaries as they ship (`-p writd -p writ-cli -p writ-sign --locked`, debug
  builds, without the development keystore: the daemon runs on the sealed keystore, as an
  operator's does) and the scenarios' test binary, then each target copies what its host
  needs. A test image, decided with the user: M8's deploy image builds on it.
- **No port is published**: everything talks on the project's network, by name. Fixed ports
  inside it are fine (nothing else binds there).
- **The configuration** the operator installs is `e2e/config/writd.yaml` and
  `e2e/config/policy.yaml`: relative paths, the operator's `submissions` and `max_pending`
  raised (every agent submits from one container, one source address), `fresh_for: 0s` (every
  fetch and push asks Forgejo first), one repository per scenario with its own upstream
  credential (a remote takes a deploy key on one repository only; `https`'s is a token), the
  HTTPS front's certificate as `mirrors.ca_certs`, the template `feature` for them all and
  `verified` with its own signing key.

## How a run goes

1. `tool/e2e.sh` builds the images, starts `forgejo`, `writd` (idle: its entrypoint,
   `e2e/writd-start.sh`, waits for the operator) and `agent`, then runs the runner.
2. The first scenario to need the stack runs **the operator setup** (`crates/writ-e2e/src/setup.rs`),
   once, from nothing, in the order of the [operator setup](operators/setup.md):
   the daemon's files; `writ reader` on the approver's machine, its line in `readers`; the
   approval key in its agent, its line in `approvers`; `writd init` (the passphrase on
   stdin); `writd upstream-keys`, each key added on its repository as a deploy key; the
   HTTPS front's certificate as `upstream_ca.pem`; Forgejo's host key scanned, compared with
   the one Forgejo publishes, pinned; `writd signing-keys`; `writd host-key` and `writd
   tls-fingerprint`, pinned on the clients; `writd run writd.yaml`, from the daemon's
   directory, sealed; `writ unseal`; the `https` repo's token (made on the account for
   repositories) added with `writ admin token`. A scenario that restarts the daemon unseals it
   again. Every command
   the guide shows runs exactly as written there ([below](#commands-the-docs-show)). A setup
   that fails fails every scenario with its reason.
3. The scenarios run side by side ([`Stack::shared`]), each with its own agent and its own
   repository. Those that stop, restart or change a container ([`Stack::exclusive`]: Forgejo
   stopped, its host key changed, the daemon restarted, the concurrency storm) wait for the
   others, hold the stack alone, and leave it working.
4. `tool/e2e.sh` removes everything; on a failure it prints the end of the daemon's log
   first.

## Scenarios

One module per scenario in `crates/writ-e2e/tests/scenarios/`, each on its own repository
(checked by `tool/check-e2e.py`: every module is listed here, and every row is a module).

| # | Module | Repo | What it proves | Stack |
|---|---|---|---|---|
| 1 | `operator_setup` | `setup` | The setup from nothing, as the guide gives it: the approvers and readers, `writd init`, the print commands with no passphrase, `writ unseal`, the `https` token through `writ admin token`, the daemon on a relative path from its directory, every mirror's hook at an absolute path, a protected push refused and an allowed one landing | shared |
| 2 | `ticket_lifecycle` | `lifecycle` | Rejected, requested and waited for, listed, signed over SSH and HTTPS, refused (flag and prompt) and revised, `n` and withdrawn, `--full`, an amendment with `--lease`, revoked; a ticket under the daemon's `min_ttl` refused naming it, one at it left unsigned and expiring; every client setting as a flag | shared |
| 2b | `narrowing` | `narrowing` | Every narrowing flag of `writ sign`, the agent told, the lease holding to each (a push past the count, a dropped operation revoking the lease) | shared |
| 3 | `wrapper_mode` | `demo` | The GitHub manual check's steps 5-7 verbatim: `writ init`, fetch, signed commit, push, verification through `writ-sign`, `writ exec`, upstream moved (clean rebase), the refused pushes; the operator's plain git untouched | shared |
| 4 | `whole_repo` | `whole` | `writ init --whole-repo --email --url`, plain git as the agent's, a second wiring refused, `--undo` exact | shared |
| 5 | `push_denials` | `denials` | Every push denial (protected ref, branch, force push, deletion, unsigned, unsigned parent, another lease's, over `max_push_size`, a tree with a non-standard mode, case, fetch without `fetch`), Forgejo and the mirror unchanged | shared |
| 6 | `upstream_moved` | `moved` | Upstream moved with a conflict: refused, fetch, rebase, resolved, signed again, pushed | shared |
| 7 | `remote_protection` | `protection` | Forgejo's own branch protection: its reason relayed, the mirror unchanged | shared |
| 8 | `verified_commits` | `verified` | Unverified, then registered (`writd signing-keys`), then proven (`writ prove-key` through Forgejo's form, on a terminal and with `--yes`): verified | shared |
| 9 | `revocation_and_expiry` | `inflight` | A session in flight dropped on revocation and on expiry; the certificate refused afterwards | shared |
| 10 | `restart` | `restart` | The daemon's container restarted (sealed, then unsealed) keeps leases, mirrors and ledger | alone |
| 11 | `hostile_upstream` | `hostile` | Forgejo stopped, its host key changed, its deploy key removed: refused with the reason, working again once restored | alone |
| 12 | `concurrency` | `busy` | Eight agents on one daemon at once (tickets submitted and signed in parallel, each pushing its rounds) while a writer changes Forgejo directly; consistent end state whatever the interleaving | alone |
| 13 | `https_upstream` | `https`, `https-system` | An HTTPS upstream with a token (Forgejo behind its TLS front, the certificate in `mirrors.ca_certs`): fetch, push, a protected ref refused; the token sealed in its keystore file, in clear nowhere (not in the daemon's files, the log, the mirrors, the audit log or on the agent's side); a second front whose certificate the system store trusts (plain git reaches it) refused by the daemon, which trusts `mirrors.ca_certs` alone | shared |
| 14 | `notes` | `notes` | `ticket_link: notes` under heavy concurrency: eight agents pushing at once while a person writes notes on the same `refs/notes/commits` with plain git; every agent commit gets exactly its lease's note on Forgejo (API and commit page), the person's notes kept, the commits untouched, each lease's notes counted once, the mirror's notes ref Forgejo's, an agent's notes push refused (`ref`), the guide's commands to read them | alone |
| 15 | `notes_reconcile` | `backfill` | The notes reconcile at start: a repo with pushed commits switched to `ticket_link: notes` (a signed admin change, `writ admin apply policy`) and the daemon restarted; both pushed commits' notes on Forgejo (API and page) from the ledger, none for a commit signed and never pushed (until its push), the policy put back | alone |
| 16 | `sealed_keystore` | — | `writd init` as the operator runs it: the keys directory at rest reveals no key (one age file per secret to the recipient, the identity to the passphrase, only public halves in clear), the boot tier holds the host and TLS keys alone, the commands that print a key read the public halves with no passphrase; a key declared afterwards made by the policy `writd recover` puts in force (RSA 3072, sealed, printed, logged, made once); declarations its backend or format refuse stopped with their reason, nothing put in force; a second `writd init` and a short passphrase refused, nothing left behind; `--tls-backend` (a backend the daemon lacks refused, `software` given); a second daemon started sealed and hardened (`writd init` too: no warning with the compose file's unlimited `memlock`; the daemon's `/proc` entries owned by root while it runs as `writ`, its memory unreadable, its core limit 0, its memory locked, each step in its log): every request refused until `writ unseal` (a wrong passphrase over HTTPS refused, then over SSH unsealed), each logged; unsealed without its `https://` repo's token (said in the log), the token then added with `writ admin token` (sealed on the daemon's host, never there in clear, an unused id refused); `writ admin show` and `apply` (a second approval key, written back to the daemon's file), `writd recover` with the daemon stopped (a wrong passphrase refused, the right one putting the first approvers back), unsealed again; then the HTTPS approval API's TLS key rotated live (M7.5: `writ admin tls rotate` over HTTPS, the approver's pin replaced and checked, the old one refused; `--backend se-cryptokit` refused before any signature; over SSH with `--backend software`, the line to pin printed and re-pinned from `writd tls-fingerprint`; two `admin` lines); `writd init --ca-backend` the same way (M7.6: a backend the daemon lacks refused, `software` given) | shared |
| 17 | `hardening_limits` | — | `writd init`, which hardens itself as `writd run` does, under the two conditions the compose file doesn't give the daemon: as `writ` under a 64 KiB lock limit (many hosts' default), the memory lock not applied and said once on stderr with its fix (`ulimit -l unlimited`), the other steps applied, the keystore made all the same (a warning, never a refusal); as root, every step applied. With scenario 16 (unlimited, as `writ`), the three conditions M5 checked by hand in a Linux container | shared |
| 18 | `openpgp_commits` | `openpgp` | A template signing with an OpenPGP key (`format: openpgp`, its user id in the policy): the lease's certificate is the one `writd signing-keys` prints; `writ init` wires git for gpg (`writ-sign` as `gpg.openpgp.program`, the fingerprint as `user.signingkey`); commits sign with a hostile GnuPG home and agent in the environment (never used); the agent verifies them through `writ-sign --verify` (the real gpg, `WRIT_GPG`); unverified on Forgejo until the key is added with Forgejo's GPG challenge signed through `writ prove-key` (OpenPGP), then verified; an SSH signature under the lease denied (`signature_format`) | shared |
| 19 | `protocol_versions` | `protocols` | Every protocol version a client asks for, served in v0 with no difference an agent notices: clones and fetches with git's default, v2, v1 and v0 asked (the same refs), `ls-remote` with v2 asked, a shallow clone deepened, a `--filter=blob:none` clone made whole, a reachable non-tip commit fetched by its id, a commit no ref reaches (its branch deleted on Forgejo after the mirror synced) refused by its id with v2 asked (`not our ref`, exit 128), a push after a v2 fetch | shared |
| 20 | `sessions_and_renewals` | `sessions` | A lease's whole life with M6: a ticket file checked (`writ check`) with an estimate; what the repo allows read from the daemon (`writ policy`, by name and in the wired clone; only that repo shown, an unknown one refused) and the ticket checked by it without being submitted (`writ request --dry-run`: on `main` rejected with its reason, then accepted, nothing stored, its `dry_run` line); a clone pinned to the lease with the skill for several agents (`writ init --lease --agents --skill-dir --agents-md`), excluded from git; a phase marked; a renewal reviewed with the original ticket and the chain, the pinned lease then refused and the renewal (`WRIT_SESSION`) pushing what the renewed lease signed; `writ close` (`--full`: a summary of 45 lines whole) and its report recorded in the timings file; the timings file checked and its limits changed; the approver's `writ report` (cut at 40 rows, naming `writ report <id> --full`, then whole with it); `writ skill update` (an older skill rewritten, the current one left, one replaced by hand kept); `--global` (its skill updated from the repository); everything undone, the timings kept; `writ run`: the harness's status passed on, the session's pid given to it, a ticket under it bound to the session and refused over TCP (`writ_run_binds_its_tickets_to_its_session_and_passes_the_harness_s_status_on`) | shared |
| 21 | `workspaces` | `ws-api`, `ws-web` | A folder of two clones wired at once (`writ init` with no repo named): without a terminal, every repository's registry name required (`--repo <dir>=<name>`), nothing wired before; the `writ-workspace` skill at the folder only; `writ git` at the folder listing the repositories; one lease for both, each repository's policy read by name; a commit in each through `writ git -C`, both pushed by `origin` (Forgejo, the mirrors, two signatures and two pushes in the audit log); `writ exec -C`; `writ skill update` at the folder (the repositories listed again) and refused in one repository; a phase marked and the lease closed at the folder, the run recorded under `ws-api + ws-web`; `--undo` in one repository refused; the host's list of what writ init wired (`writ init --list`, `writ skill update --all`), and `writ init --undo --all` taking every repository and the folder back (the timings kept), the list then empty | shared |
| 22 | `per_repository` | `pr-api`, `pr-web` | Per-repository tickets (M6.1.5): `writ policy` for both repositories, its "Together:" line; a repository two templates fit rejected until its block names one; repositories signing with different keys rejected naming each template and key; one ticket under two templates granted with one signature, each repository's template in the lease; each repository held to its own part (a path outside pr-web's `expected_paths` refused at signing, `paths`; pr-api's branch refused in pr-web, `ref`; pr-web's one push, then `limit` while pr-api still pushes; Forgejo and the audit log); the same work as one lease per repository, each repository's commands under its own `WRIT_SESSION`, the other lease's repository refused (`repo`); every lease closed | shared |
| 23 | `daemon_management` | `setup` | Managing the daemon from the approver's machine (M6.2): `writ admin repo\|template\|key\|host list` and `show` with the reader key, every entry as the policy writes it, a missing one refused with its reason; each key's public half from the daemon's signers, the one the operator registered (`--public`), an OpenPGP key's fingerprint and certificate, a token only as added (never its value, no public half); Forgejo's pin with the fingerprint the setup compared; each through `--approval-url` too (shared). Then, alone: `set` on each noun in every syntax (the first one writing the policy in Writ's layout, said), refusals naming the field (a fixed field, a field the noun lacks, what the policy refuses) with nothing sent; `remove` refused while something uses it, a key's id typed again on a terminal (a mistyped one sends nothing), the key's files deleted once the change applies and its public half in the `admin` line, a template, a host and a repo removed; the policy put back as it was (the removed key made again, new). Then step by step on a terminal: `add` and `edit` on each noun (each field asked with its bounds and default or its current value, only the fields the entry needs, Enter keeping it), `template add --from`, a repo added with a new RSA credential declared in the same change, `key rotate` through both its changes and the removal it offers (and named with `--yes` without a terminal; `--backend software`, and `--backend se-cryptokit` refused before any signature on a daemon without it, as `writ admin key list` names its backends), `--yes` asking nothing but the fields; the policy put back. Then the daemon's checks: Forgejo scanned under another name (`writ admin host add` with no keys, on a terminal, the proxy to scan through asked first and answered none; refused without one) on the approver's signature, its key the one the setup compared, pinned once confirmed; `host rescan` finding the pin current, then a stale pin replaced (Forgejo's key shown as new); each scan an `allowed` `scan` line before it connects out and a `done` one with what it read, both with the approver; `repo check` reading, syncing and writing with nothing pushed, a repo not in the registry refused; `repo status` for every repo and for the one checked (its last sync ended within the check, refs moved), a repo not in the registry refused; a guided `repo add` on a host with no pin scanning it in the same change (the proxy asked before the scan) and checking the repo once Enter says its credential is registered (one that isn't failing at reading); the policy put back; each `edit --yes` a real change applied with no question, the exit code read; the daily operations page (`sealing.md`) run as written, its policy commands entry by entry (`repo add` and `edit` on a terminal, `template set`, `key remove` with its id typed) and the approvers as a whole file through `$EDITOR`, put back | shared, then alone |
| 24 | `local_mode` | `local` | Local mode on Linux in the `local` container, laid out as `make install` does it: the daemon as `writd` started as its systemd unit starts it (`setpriv`, the ambient `CAP_SYS_PTRACE`), every capability dropped once started and its process reader (`writd proc-reader`) holding `CAP_SYS_PTRACE` alone (read in `/proc/<pid>/status`); `dev` refused the daemon's directory, keystore and memory, and `strace -p` and `gdb -p` on the daemon and its reader; `writ unseal` over the approvals socket; the M6 workflow under `writ run` (the ticket bound by the daemon to `/usr/local/bin/writ`'s pid, no code identity shown, a commit signed, pushed to Forgejo, the push's chain in its audit line read across users); the same lease refused outside the session (`caller`); revoked when the session ends; SIGTERM an orderly stop (`stopping`) that ends the reader too | shared |
| 25 | `upstream_proxies` | `behind-socks`, `behind-http` | Upstreams behind a proxy (M7.2): Forgejo on a network the daemon isn't on, under names it can't resolve, reached through real proxies each asking for a password (microsocks, SOCKS5, for the ssh repository; tinyproxy, HTTP CONNECT, for the HTTPS one), the passwords added with `writ admin token`: fetch, signed commit, push, a protected ref refused, each on Forgejo and in the mirror; each proxy's log showing the tunnels it opened by name; the passwords in clear nowhere on the daemon's host, the agents' side or the audit log. Then, alone: `writ admin proxy list` and `show` (through `--approval-url` too), `add` with every field given, `set`, `edit` on a terminal (the credential not asked without a user), `remove` refused while a repo is behind the proxy; the repo moved behind a proxy that wants a password it isn't given (refused with the proxy's reason), then reached directly (its name resolves nowhere: refused, no fallback), then back (reached); `host rescan` through the proxy the host's repos share and through `--proxy`, a new name pinned with `host add <host> proxy=<name>` (scanned through it, logged with the proxy); another with no proxy named, the proxy asked before the scan: answered none, the direct scan failing with how to go through one; then a guided `repo add` on that host, the proxy asked before the scan (a name not in force asked again), scanned through it, the answer the repo's own proxy (not asked again), the repo checked through it; the policy put back | shared, then alone |
| 26 | `keystore_recipients` | — | The keystore's recipients (M7.6) on the passphrase keystore: a recovery key made on the approver's machine with `writ recovery new` (in no file), declared with `writ admin recipient add`, listed and shown (through `--approval-url` too), checked with `writ recovery check` (the right key opens the daemon's challenge; another is named by its recipient), replaced with `set` (the old key refused), edited on a terminal, removed (the check then says there is none); a hardware recipient refused by name, the daemon having no Secure Enclave; the policy put back; then `writ admin ca show` and `writ admin ca rotate` (every flag), live, the other scenarios' leases working on, a backend the daemon lacks refused; `writ admin auto-unseal status` (what is missing), `on` refused with it, `off`; `recipient edit` with every flag a real change applied with no question; the daily operations page's recovery steps run as written (`writ recovery new`, `recipient add`, `writ recovery check`) | alone |
| 27 | `approval_popup` | — | The approval popup's side of `writ` (M7.8): `writ sign --ui` driven as `writ-popup` drives it, one JSON line each way; two tickets at once, the oldest shown with the other stacked behind it, its display the very text `writ sign --full` prints; an answer naming the ticket behind refused with nothing signed; the first signed (the agent's lease, one `grant` line), the second refused with feedback the agent reads; a ticket withdrawn while shown closing its window; the end of the app's input ending the command | alone |

Every scenario checks, where it applies: **what the agent reads** (the exit code and the
words, never just "it failed"), **the audit line** (event, result, code), **Forgejo's state**
through its API (where a push landed, or proof that a refused one didn't), and **the mirror**
(its refs, and that a refused commit never reached it).

## Coverage: every command and flag

Each row is a command or a flag as its binary defines it (by its long name, or its short one
when it has none: `writ exec -C`), and the scenarios (test functions) that use it for real. A flag given through its environment variable (`WRIT_HOME` for
`--home`) counts: it is the same setting; `every_client_setting_works_as_a_flag` also gives
each one as a flag. Checked: `writ`'s rows against its command-line definition
(`writ-cli`'s `every_command_and_flag_is_in_the_end_to_end_registry`), `writd`'s against its
command table (`every_writd_command_is_in_the_end_to_end_registry`), every named test against
the scenarios (`tool/check-e2e.py`).

| Feature | Scenarios |
|---|---|
| `writ --home` | `every_client_setting_works_as_a_flag` |
| `writ --known-hosts` | `every_client_setting_works_as_a_flag` |
| `writ --tls-pins` | `every_client_setting_works_as_a_flag` |
| `writ --reader` | `every_client_setting_works_as_a_flag` |
| `writ request` | `tickets_are_requested_signed_refused_revised_amended_and_revoked` |
| `writ request -` (ticket on stdin) | `tickets_are_requested_signed_refused_revised_amended_and_revoked` |
| `writ request --no-wait` | `tickets_are_requested_signed_refused_revised_amended_and_revoked`, `many_agents_and_a_busy_remote_share_one_daemon` |
| `writ request --url` | `every_client_setting_works_as_a_flag` |
| `writ request --dry-run` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ policy` | `a_lease_is_renewed_closed_and_learned_from`, `one_ticket_holds_each_repository_to_its_own_template` (several repositories) |
| `writ policy --url` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ wait` | `tickets_are_requested_signed_refused_revised_amended_and_revoked`, `a_ticket_left_unsigned_expires` |
| `writ wait --lease` | `tickets_are_requested_signed_refused_revised_amended_and_revoked` |
| `writ wait --url` | `every_client_setting_works_as_a_flag` |
| `writ init` | `an_agent_works_through_writ_git_beside_the_operator_s_own_git` |
| `writ init --whole-repo` | `a_dedicated_clone_is_wired_whole_and_undone_exactly` |
| `writ init --email` | `a_dedicated_clone_is_wired_whole_and_undone_exactly` |
| `writ init --undo` | `a_dedicated_clone_is_wired_whole_and_undone_exactly`, `one_agent_at_a_workspace_root_works_on_two_repositories_under_one_lease` |
| `writ init --all` | `one_agent_at_a_workspace_root_works_on_two_repositories_under_one_lease` |
| `writ init --list` | `one_agent_at_a_workspace_root_works_on_two_repositories_under_one_lease` |
| `writ init --url` | `a_dedicated_clone_is_wired_whole_and_undone_exactly` |
| `writ init --lease` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ init --agents` | `a_lease_is_renewed_closed_and_learned_from`, `an_agent_works_through_writ_git_beside_the_operator_s_own_git` |
| `writ init --skill-dir` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ init --global` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ init --agents-md` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ init --repo` | `one_agent_at_a_workspace_root_works_on_two_repositories_under_one_lease` |
| `writ skill update` | `a_lease_is_renewed_closed_and_learned_from`, `one_agent_at_a_workspace_root_works_on_two_repositories_under_one_lease` |
| `writ skill update --all` | `one_agent_at_a_workspace_root_works_on_two_repositories_under_one_lease` |
| `writ close` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ close --full` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ close --summary` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ close --url` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ check` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ mark` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ timings` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ timings --max-lines` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ timings --max-bytes` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ timings --keep-runs` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ timings --max-notes` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ report` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ report --approval-url` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ report --full` | `a_lease_is_renewed_closed_and_learned_from` |
| `writ git` | `an_agent_works_through_writ_git_beside_the_operator_s_own_git`, `every_push_denial_leaves_forgejo_and_the_mirror_unchanged`, `one_agent_at_a_workspace_root_works_on_two_repositories_under_one_lease` |
| `writ exec` | `an_agent_works_through_writ_git_beside_the_operator_s_own_git` |
| `writ exec -C` | `one_agent_at_a_workspace_root_works_on_two_repositories_under_one_lease` |
| `writ run` | `writ_run_binds_its_tickets_to_its_session_and_passes_the_harness_s_status_on` |
| `writ reader` | `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says` |
| `writ ls` | `tickets_are_requested_signed_refused_revised_amended_and_revoked`, `a_restarted_daemon_keeps_leases_mirrors_and_ledger` |
| `writ ls --all` | `tickets_are_requested_signed_refused_revised_amended_and_revoked` |
| `writ ls --approval-url` | `every_client_setting_works_as_a_flag` |
| `writ sign` (the prompt: `y`, `n`, `r`) | `tickets_are_requested_signed_refused_revised_amended_and_revoked` |
| `writ sign --yes` | `tickets_are_requested_signed_refused_revised_amended_and_revoked`, `many_agents_and_a_busy_remote_share_one_daemon` |
| `writ sign --full` | `tickets_are_requested_signed_refused_revised_amended_and_revoked`, `the_popup_shows_what_waits_in_order_and_signs_or_refuses_on_its_answer` |
| `writ sign --ui` | `the_popup_shows_what_waits_in_order_and_signs_or_refuses_on_its_answer` |
| `writ sign --ttl` | `the_approver_narrows_every_term_and_the_lease_holds_to_them`, `revocation_and_expiry_drop_sessions_in_flight_and_refuse_the_certificate` |
| `writ sign --drop-repo` | `the_approver_narrows_every_term_and_the_lease_holds_to_them` |
| `writ sign --drop-op` | `the_approver_narrows_every_term_and_the_lease_holds_to_them` |
| `writ sign --branch` | `the_approver_narrows_every_term_and_the_lease_holds_to_them` |
| `writ sign --drop-email` | `the_approver_narrows_every_term_and_the_lease_holds_to_them` |
| `writ sign --max-signatures` | `the_approver_narrows_every_term_and_the_lease_holds_to_them` |
| `writ sign --max-pushes` | `the_approver_narrows_every_term_and_the_lease_holds_to_them` |
| `writ sign --max-ops-per-minute` | `the_approver_narrows_every_term_and_the_lease_holds_to_them` |
| `writ sign --max-push-size` | `the_approver_narrows_every_term_and_the_lease_holds_to_them` |
| `writ sign --no-force-push` | `the_approver_narrows_every_term_and_the_lease_holds_to_them` |
| `writ sign --revoke-on-violation` | `the_approver_narrows_every_term_and_the_lease_holds_to_them` |
| `writ sign --approval-url` | `every_client_setting_works_as_a_flag` |
| `writ sign --key` | `every_client_setting_works_as_a_flag` |
| `writ sign --agent` | `every_client_setting_works_as_a_flag` |
| `writ refuse` | `tickets_are_requested_signed_refused_revised_amended_and_revoked` |
| `writ refuse --message` | `tickets_are_requested_signed_refused_revised_amended_and_revoked`, `every_client_setting_works_as_a_flag` |
| `writ refuse --approval-url` | `every_client_setting_works_as_a_flag` |
| `writ refuse --key` | `every_client_setting_works_as_a_flag` |
| `writ refuse --agent` | `every_client_setting_works_as_a_flag` |
| `writ revoke` | `tickets_are_requested_signed_refused_revised_amended_and_revoked`, `revocation_and_expiry_drop_sessions_in_flight_and_refuse_the_certificate` |
| `writ revoke --approval-url` | `every_client_setting_works_as_a_flag` |
| `writ revoke --key` | `every_client_setting_works_as_a_flag` |
| `writ revoke --agent` | `every_client_setting_works_as_a_flag` |
| `writ unseal` | `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says`, `a_restarted_daemon_keeps_leases_mirrors_and_ledger`, `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ unseal --approval-url` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ unseal --key` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ unseal --agent` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin show` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin show --approval-url` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin apply` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin apply --yes` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin apply --approval-url` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin apply --key` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin apply --agent` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin tls rotate` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin tls rotate --backend` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin tls rotate --yes` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin tls rotate --approval-url` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin tls rotate --key` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin tls rotate --agent` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin token` | `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says`, `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin token --yes` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin token --approval-url` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin token --key` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin token --agent` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin repo list` | `the_policy_in_force_is_read_entry_by_entry_from_the_approver_s_machine` |
| `writ admin repo list --approval-url` | `the_policy_in_force_is_read_entry_by_entry_from_the_approver_s_machine` |
| `writ admin repo show` | `the_policy_in_force_is_read_entry_by_entry_from_the_approver_s_machine` |
| `writ admin repo show --approval-url` | `the_policy_in_force_is_read_entry_by_entry_from_the_approver_s_machine` |
| `writ admin template list` | `the_policy_in_force_is_read_entry_by_entry_from_the_approver_s_machine` |
| `writ admin template list --approval-url` | `the_policy_in_force_is_read_entry_by_entry_from_the_approver_s_machine` |
| `writ admin template show` | `the_policy_in_force_is_read_entry_by_entry_from_the_approver_s_machine` |
| `writ admin template show --approval-url` | `the_policy_in_force_is_read_entry_by_entry_from_the_approver_s_machine` |
| `writ admin key list` | `the_policy_in_force_is_read_entry_by_entry_from_the_approver_s_machine` |
| `writ admin key list --approval-url` | `the_policy_in_force_is_read_entry_by_entry_from_the_approver_s_machine` |
| `writ admin key show` | `the_policy_in_force_is_read_entry_by_entry_from_the_approver_s_machine` |
| `writ admin key show --approval-url` | `the_policy_in_force_is_read_entry_by_entry_from_the_approver_s_machine` |
| `writ admin key show --public` | `the_policy_in_force_is_read_entry_by_entry_from_the_approver_s_machine` |
| `writ admin repo add` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin repo add --yes` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin repo add --approval-url` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin repo add --key` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin repo add --agent` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin repo edit` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin repo edit --yes` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin repo edit --approval-url` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin repo edit --key` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin repo edit --agent` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin template add` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin template add --yes` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin template add --approval-url` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin template add --key` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin template add --agent` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin template edit` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin template edit --yes` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin template edit --approval-url` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin template edit --key` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin template edit --agent` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin key add` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin key add --yes` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin key add --approval-url` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin key add --key` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin key add --agent` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin key edit` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin key edit --yes` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin key edit --approval-url` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin key edit --key` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin key edit --agent` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin host add` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin host add --yes` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin host add --approval-url` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin host add --key` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin host add --agent` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin host edit` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin host edit --yes` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin host edit --approval-url` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin host edit --key` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin host edit --agent` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin host rescan` | `a_host_is_scanned_from_the_daemon_rescanned_and_a_repo_checked_against_forgejo` |
| `writ admin host rescan --yes` | `a_host_is_scanned_from_the_daemon_rescanned_and_a_repo_checked_against_forgejo` |
| `writ admin host rescan --approval-url` | `a_host_is_scanned_from_the_daemon_rescanned_and_a_repo_checked_against_forgejo` |
| `writ admin host rescan --key` | `a_host_is_scanned_from_the_daemon_rescanned_and_a_repo_checked_against_forgejo` |
| `writ admin host rescan --agent` | `a_host_is_scanned_from_the_daemon_rescanned_and_a_repo_checked_against_forgejo` |
| `writ admin host rescan --proxy` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin repo check` | `a_host_is_scanned_from_the_daemon_rescanned_and_a_repo_checked_against_forgejo` |
| `writ admin repo check --approval-url` | `a_host_is_scanned_from_the_daemon_rescanned_and_a_repo_checked_against_forgejo` |
| `writ admin repo status` | `a_host_is_scanned_from_the_daemon_rescanned_and_a_repo_checked_against_forgejo` |
| `writ admin repo status --approval-url` | `a_host_is_scanned_from_the_daemon_rescanned_and_a_repo_checked_against_forgejo` |
| `writ admin template add --from` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin key rotate` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin key rotate --name` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin key rotate --backend` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin key rotate --yes` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin key rotate --approval-url` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin key rotate --key` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin key rotate --agent` | `entries_are_added_edited_and_a_key_rotated_step_by_step_on_a_terminal` |
| `writ admin repo set` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin repo set --yes` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin repo set --approval-url` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin repo set --key` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin repo set --agent` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin repo remove` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin repo remove --yes` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin repo remove --approval-url` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin repo remove --key` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin repo remove --agent` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin template set` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin template set --yes` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin template set --approval-url` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin template set --key` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin template set --agent` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin template remove` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin template remove --yes` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin template remove --approval-url` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin template remove --key` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin template remove --agent` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin key set` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin key set --yes` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin key set --approval-url` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin key set --key` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin key set --agent` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin key remove` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin key remove --yes` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin key remove --approval-url` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin key remove --key` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin key remove --agent` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin host set` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin host set --yes` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin host set --approval-url` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin host set --key` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin host set --agent` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin host remove` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin host remove --yes` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin host remove --approval-url` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin host remove --key` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin host remove --agent` | `the_policy_is_changed_field_by_field_and_entries_removed_from_the_approver_s_machine` |
| `writ admin proxy list` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy list --approval-url` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy show` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy show --approval-url` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy add` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy add --yes` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy add --approval-url` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy add --key` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy add --agent` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy edit` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy edit --yes` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy edit --approval-url` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy edit --key` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy edit --agent` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy set` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy set --yes` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy set --approval-url` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy set --key` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy set --agent` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy remove` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy remove --yes` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy remove --approval-url` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy remove --key` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ admin proxy remove --agent` | `proxies_are_managed_from_the_approver_s_machine_and_hosts_behind_them_scanned_through_them` |
| `writ recovery new` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ recovery check` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ recovery check --approval-url` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient list` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient list --approval-url` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient show` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient show --approval-url` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient add` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient add --yes` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient add --approval-url` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient add --key` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient add --agent` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient edit` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient edit --yes` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient edit --approval-url` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient edit --key` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient edit --agent` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient set` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient set --yes` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient set --approval-url` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient set --key` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient set --agent` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient remove` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient remove --yes` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient remove --approval-url` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient remove --key` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin recipient remove --agent` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin ca show` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin ca show --approval-url` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin ca rotate` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin ca rotate --backend` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin ca rotate --yes` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin ca rotate --approval-url` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin ca rotate --key` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin ca rotate --agent` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin auto-unseal status` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin auto-unseal status --approval-url` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin auto-unseal on` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin auto-unseal on --yes` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin auto-unseal on --approval-url` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin auto-unseal on --key` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin auto-unseal on --agent` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin auto-unseal off` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin auto-unseal off --yes` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin auto-unseal off --approval-url` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin auto-unseal off --key` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin auto-unseal off --agent` | `the_recovery_key_is_made_declared_checked_and_replaced_from_the_approver_s_machine` |
| `writ admin host list` | `the_policy_in_force_is_read_entry_by_entry_from_the_approver_s_machine` |
| `writ admin host list --approval-url` | `the_policy_in_force_is_read_entry_by_entry_from_the_approver_s_machine` |
| `writ admin host show` | `the_policy_in_force_is_read_entry_by_entry_from_the_approver_s_machine` |
| `writ admin host show --approval-url` | `the_policy_in_force_is_read_entry_by_entry_from_the_approver_s_machine` |
| `writ prove-key` (the prompt, on a terminal: `y`, `n`) | `commits_are_verified_once_the_signing_key_is_registered_and_proven` |
| `writ prove-key --namespace` | `commits_are_verified_once_the_signing_key_is_registered_and_proven`, `an_openpgp_key_is_proven_on_forgejo_and_its_commits_show_verified` |
| `writ prove-key --yes` | `commits_are_verified_once_the_signing_key_is_registered_and_proven`, `every_client_setting_works_as_a_flag` |
| `writ prove-key --approval-url` | `every_client_setting_works_as_a_flag` |
| `writ prove-key --key` | `every_client_setting_works_as_a_flag` |
| `writ prove-key --agent` | `every_client_setting_works_as_a_flag` |
| `writd run` | `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says`, `a_restarted_daemon_keeps_leases_mirrors_and_ledger`, `local_mode_on_linux_binds_a_lease_to_its_session_and_keeps_the_daemon_out_of_reach` (local mode, Linux) |
| `writd init` | `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says`, `writd_init_makes_a_sealed_keystore_that_reveals_no_key_at_rest`, `a_low_lock_limit_is_a_warning_with_its_fix_and_root_is_hardened_too` |
| `writd init --tls-backend` | `writd_init_makes_a_sealed_keystore_that_reveals_no_key_at_rest` |
| `writd init --ca-backend` | `writd_init_makes_a_sealed_keystore_that_reveals_no_key_at_rest` |
| `writd recover` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writd host-key` | `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says` |
| `writd tls-fingerprint` | `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says` |
| `writd upstream-keys` | `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says`, `a_stopped_a_changed_and_a_closed_upstream_are_refused_with_their_reasons` |
| `writd signing-keys` | `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says`, `commits_are_verified_once_the_signing_key_is_registered_and_proven` |
| `writd hook pre-receive` (every push) | `every_push_denial_leaves_forgejo_and_the_mirror_unchanged`, `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says` |
| `writd upstream-ssh` (every sync and upstream push) | `a_stopped_a_changed_and_a_closed_upstream_are_refused_with_their_reasons`, `many_agents_and_a_busy_remote_share_one_daemon` |
| `writd upstream-credential` (every sync and upstream push of an `https://` upstream) | `a_repo_behind_https_is_fetched_and_pushed_with_a_token_nobody_else_sees` |
| `writd upstream-tunnel` (every sync and upstream push of an `ssh://` upstream behind a proxy) | `repos_behind_a_socks5_and_an_http_proxy_are_reached_through_them_alone` |
| `writd proc-reader` (started by `writd run` on Linux with `CAP_SYS_PTRACE`) | `local_mode_on_linux_binds_a_lease_to_its_session_and_keeps_the_daemon_out_of_reach` |
| `writ-sign -Y sign` (every commit under the wiring) | `an_agent_works_through_writ_git_beside_the_operator_s_own_git`, `a_dedicated_clone_is_wired_whole_and_undone_exactly` |
| `writ-sign -Y verify` (handed to `ssh-keygen`) | `an_agent_works_through_writ_git_beside_the_operator_s_own_git` |
| `writ-sign --status-fd=2 -bsau` (every commit under an OpenPGP lease) | `an_openpgp_key_is_proven_on_forgejo_and_its_commits_show_verified` |
| `writ-sign --verify` (handed to `gpg`) | `an_openpgp_key_is_proven_on_forgejo_and_its_commits_show_verified` |

## Commands the docs show

The commands the operator guide and the manual checks show are the ones the pipeline runs.
The test files run each command through `doc_step`, `doc_step_fails` or `doc_step_detached`
(`writ_e2e::setup`), with the doc's text as a string literal, exactly (placeholders such as
`<host>`, `<name>` or `<lease id>` filled in at run time, a trailing `# comment` ignored).

**Operator pages are listed here, whole, and carry no marker** (people read them): every
command line of every `sh` block on the page is run by one of the files its row names.
A block that isn't run doesn't belong on such a page as `sh` (a `yaml` or `text` block is
not checked).

| Page | Run by |
|---|---|
| [Setup](operators/setup.md) | `crates/writ-e2e/src/setup.rs`, `crates/writ-e2e/tests/scenarios/notes.rs` |
| [Clients](operators/clients.md) | `crates/writ-e2e/tests/scenarios/workspaces.rs` |
| [Hardening](operators/hardening.md) | `crates/writ-e2e/tests/scenarios/local_mode.rs` |
| [Good practice](operators/good-practice.md) | `crates/writ-e2e/tests/scenarios/wrapper_mode.rs` |
| [Sealing](operators/sealing.md) | `crates/writ-e2e/src/setup.rs`, `crates/writ-e2e/tests/scenarios/daemon_management.rs`, `crates/writ-e2e/tests/scenarios/keystore_recipients.rs` |
| [Recovery](operators/recovery.md) | owed by M8 (the detached deployment it shows) |
| [Install](operators/install.md) | owed by M7.9 (the real install, run by hand) |

`make check` refuses an operator page that shows an `sh` block and has no row here, run
whole or owed by a milestone still to come (`tool/check-e2e.py`).

**Developer guides, where only some blocks are run**, mark each run block with the file that
runs it, on the line before:

````markdown
<!-- e2e: crates/writ-e2e/tests/scenarios/wrapper_mode.rs -->
```sh
writ git fetch origin
```
````

Today: the [GitHub manual check](guides/manual-checks.md#a-throwaway-github-repo-m4)'s agent
steps (`wrapper_mode.rs`).

`tool/check-e2e.py` checks both ways: every command a listed page or a marked block shows
is run by its file, and every `doc_step…` literal is shown by a page or a block for its
file. So a step changed in the docs is changed in the pipeline, and the other way round. A
marker on an operator page is refused.

## Rules for a scenario

The [hardened-test rules](testing.md#hardened-tests) hold here too:

- **No sleep and assert.** Wait for a signal (a process's exit, `writ wait` returning, a log
  line) or a bounded poll through `docker::eventually` for what gives none (a container's
  service coming up), with a `// poll:` comment. Every command is bounded (`docker::TIMEOUT`,
  3 minutes): a hang fails its scenario, not the pipeline.
- **Exact outcomes.** An exit code is asserted exactly (`agent::expect(&out, 1, …)`), a
  denial by its words and its audit `code`; never a bare "it failed".
- **The allowed case beside each refusal**, so the refusal is the check's doing and not a
  broken fixture.
- **What holds whatever the interleaving.** Scenarios run side by side and the daemon is
  shared: assert about your own lease, repository and agent (`Stack::audited(lease, …)`,
  `Stack::mirror_ref(repo, …)`), never "the last line of the log" or global counts. A
  concurrency scenario asserts invariants (every branch where its agent says, the mirror
  equal to Forgejo), never an order.
- **Leave the stack working.** A scenario that stops, changes or restarts a container holds
  the stack alone (`Stack::exclusive`) and restores what it changed before it ends.
- **Through what people use.** The binaries, git, ssh, Forgejo's API and web forms, the
  daemon's files as the operator reads them. No in-process shortcut: that is the integration
  level's job (`crates/writ-integration`).

## Adding a scenario

When a milestone adds behavior a person or an agent reaches through a binary, or a bug is
found on a path no scenario takes:

1. **Pick or add a scenario.** If the behavior extends an existing scenario's story (another
   denial: `push_denials`), add to it. Otherwise add a module
   `crates/writ-e2e/tests/scenarios/<name>.rs` (named for what it proves, snake case), its
   `mod <name>;` in `main.rs`, and a row in the [scenarios table](#scenarios). Its `//!`
   header says what it proves.
2. **Give it its own repository** if it pushes or fetches: a line in
   `e2e/config/policy.yaml` (`upstream: ssh://git@forgejo/writ/<repo>.git`, a credential
   `upstream-<repo>` of its own) and the repo in the `feature` template (or a template of its
   own if it needs another signing key or limits), and the repo in `operator_setup`'s
   `REPOS`. The setup creates it on Forgejo with its deploy key; nothing else to do.
3. **Write the test**: `#[test]` and `#[ignore = "end to end: make e2e"]` (the pipeline runs
   ignored tests only, `make test` compiles them); `Stack::shared()` unless it stops,
   restarts or changes a container (`Stack::exclusive()`); its own agent,
   `stack.agent("<name>")` (a name no other scenario uses); a lease with `agent.lease(&stack,
   &ticket(…))`, or `wired(&stack, &agent, "<repo>")` for a lease and a wired clone. Check
   the four things: what the agent reads, the audit line, Forgejo, the mirror.
4. **Register what it covers**: a new command or flag gets a row in the
   [coverage registry](#coverage-every-command-and-flag) naming the test; an existing row
   may name it too.
5. **Doc-linked commands**: when the scenario runs commands a guide shows, run each line
   through `doc_step` with the same text, and link the two
   ([commands the docs show](#commands-the-docs-show)): an operator page gets the file in its
   row of the table, a developer guide a `<!-- e2e: <the scenario's file> -->` marker before
   the block.
6. **Run it**: `make e2e ARGS=<name>` while writing it, then `make e2e` once before the
   commit (it runs beside the others). `make check` runs `tool/check-e2e.py`.

## Adding a command or a flag

A new `writ` subcommand or flag, a new `writd` command (a row of `COMMANDS` in
`crates/writd/src/main.rs`), a new `writ-sign` mode: in the same change, a scenario that uses
it (above) and its row in the registry. Without the row, `make test` fails
(`every_command_and_flag_is_in_the_end_to_end_registry`,
`every_writd_command_is_in_the_end_to_end_registry`); without the scenario, `make check`
does (`tool/check-e2e.py`).

## When it fails

- The failing assertion prints the command, its exit code, its stdout and stderr; `make e2e`
  prints the end of the daemon's log after a failure.
- `WRIT_E2E_KEEP=1 make e2e ARGS=<name>` keeps the stack: `docker exec -it -u writ
  writ-e2e-<pid>-writd-1 sh` (the daemon's files, `writd.log`, `data/audit.jsonl`, the mirrors
  in `data/repos/`), `docker exec -it -u agent writ-e2e-<pid>-agent-1 sh` (`~/agents/<name>`),
  Forgejo's logs with `docker logs writ-e2e-<pid>-forgejo-1`. Remove it with the command
  printed at the end.
- A setup failure fails every scenario with the same reason: fix that first.

## What it doesn't do

- **Touch ID and the approver's real agent** (Secretive): the throwaway ssh-agent stands in
  for it; the real one is the [manual checks](guides/manual-checks.md)' job.
- **GitHub**: a hosted remote with a real account stays a [manual check](guides/manual-checks.md#a-throwaway-github-repo-m4);
  its agent steps are the same commands `wrapper_mode` runs.
- **Local mode** (M7, the Mac's Unix socket and process chain): the pipeline is detached
  mode on Linux.
