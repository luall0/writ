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
make e2e                        # every scenario (about 8 minutes once the images are cached)
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

The longest scenario waits for an unsigned ticket to expire (a ticket asks for at least 5
minutes): the others run beside it, so a run never takes less than about 5 minutes.

## The stack

| Container | Image (`e2e/Dockerfile` target) | Who's there | Reached as |
|---|---|---|---|
| `forgejo` | `codeberg.org/forgejo/forgejo:13.0.5`, pinned by digest | the remote: an admin account `writ` (email `agent@writ.invalid`) owning one repository per scenario | `http://forgejo:3000` (API, web forms), `ssh://git@forgejo` (the daemon's upstream) |
| `forgejo-https` | `tls-front`: Debian 13, socat and a throwaway self-signed certificate made at build time | Forgejo over HTTPS: TLS in front of `forgejo:3000` | `https://forgejo-https:3443` (the `https` repo's upstream) |
| `forgejo-https-system` | `tls-front` again (`TLS_NAME`), with its own certificate, which the setup adds to the `writd` container's system store, never to `mirrors.ca_certs` | Forgejo over HTTPS, a second front | `https://forgejo-https-system:3443` (the `https-system` repo's upstream: refused) |
| `writd` | `writd`: Debian 13, git 2.47, OpenSSH 10.0, the real `writd` | the operator, user `writ`, in `/home/writ` (`writd.yaml`, `policy.yaml`, `approvers`, `readers`, `data/`, `writd.log`) | `writd:2222` (agents), `writd:2223` (approval API, SSH), `writd:8443` (approval API, HTTPS) |
| `agent` | `agent`: the same base, `writ` and `writ-sign` | user `agent`: one directory and `WRIT_HOME` per scenario's agent (`~/agents/<name>`), and the operator's own git (`user.name Operator`); user `approver`: the approver's machine (`~/.writ`, a throwaway ssh-agent holding the approval key, standing in for Secretive) | `docker exec` |
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
| 2 | `ticket_lifecycle` | `lifecycle` | Rejected, requested and waited for, listed, signed over SSH and HTTPS, refused (flag and prompt) and revised, `n` and withdrawn, `--full`, an amendment with `--lease`, revoked; an unsigned ticket expiring; every client setting as a flag | shared |
| 2b | `narrowing` | `narrowing` | Every narrowing flag of `writ sign`, the agent told, the lease holding to each (a push past the count, a dropped operation revoking the lease) | shared |
| 3 | `wrapper_mode` | `demo` | The GitHub manual check's steps 5-7 verbatim: `writ init`, fetch, signed commit, push, verification through `writ-sign`, `writ exec`, upstream moved (clean rebase), the refused pushes; the operator's plain git untouched | shared |
| 4 | `whole_repo` | `whole` | `writ init --whole-repo --email --url`, plain git as the agent's, a second wiring refused, `--undo` exact | shared |
| 5 | `push_denials` | `denials` | Every push denial (protected ref, branch, force push, deletion, unsigned, unsigned parent, another lease's, over `max_push_size`, case, fetch without `fetch`), Forgejo and the mirror unchanged | shared |
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
| 16 | `sealed_keystore` | — | `writd init` as the operator runs it: the keys directory at rest reveals no key (one age file per secret to the recipient, the identity to the passphrase, only public halves in clear), the boot tier holds the host and TLS keys alone, the commands that print a key read the public halves with no passphrase; a second `writd init` and a short passphrase refused, nothing left behind; a second daemon started sealed and hardened (`writd init` too: no warning with the compose file's unlimited `memlock`; the daemon's `/proc` entries owned by root while it runs as `writ`, its memory unreadable, its core limit 0, its memory locked, each step in its log): every request refused until `writ unseal` (a wrong passphrase over HTTPS refused, then over SSH unsealed), each logged; unsealed without its `https://` repo's token (said in the log), the token then added with `writ admin token` (sealed on the daemon's host, never there in clear, an unused id refused); `writ admin show` and `apply` (a second approval key, written back to the daemon's file), `writd recover` with the daemon stopped (a wrong passphrase refused, the right one putting the first approvers back), unsealed again | shared |
| 17 | `hardening_limits` | — | `writd init`, which hardens itself as `writd run` does, under the two conditions the compose file doesn't give the daemon: as `writ` under a 64 KiB lock limit (many hosts' default), the memory lock not applied and said once on stderr with its fix (`ulimit -l unlimited`), the other steps applied, the keystore made all the same (a warning, never a refusal); as root, every step applied. With scenario 16 (unlimited, as `writ`), the three conditions M5 checked by hand in a Linux container | shared |

Every scenario checks, where it applies: **what the agent reads** (the exit code and the
words, never just "it failed"), **the audit line** (event, result, code), **Forgejo's state**
through its API (where a push landed, or proof that a refused one didn't), and **the mirror**
(its refs, and that a refused commit never reached it).

## Coverage: every command and flag

Each row is a command or a flag as its binary defines it, and the scenarios (test functions)
that use it for real. A flag given through its environment variable (`WRIT_HOME` for
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
| `writ wait` | `tickets_are_requested_signed_refused_revised_amended_and_revoked`, `a_ticket_left_unsigned_expires` |
| `writ wait --lease` | `tickets_are_requested_signed_refused_revised_amended_and_revoked` |
| `writ wait --url` | `every_client_setting_works_as_a_flag` |
| `writ init` | `an_agent_works_through_writ_git_beside_the_operator_s_own_git` |
| `writ init --whole-repo` | `a_dedicated_clone_is_wired_whole_and_undone_exactly` |
| `writ init --email` | `a_dedicated_clone_is_wired_whole_and_undone_exactly` |
| `writ init --undo` | `a_dedicated_clone_is_wired_whole_and_undone_exactly` |
| `writ init --url` | `a_dedicated_clone_is_wired_whole_and_undone_exactly` |
| `writ git` | `an_agent_works_through_writ_git_beside_the_operator_s_own_git`, `every_push_denial_leaves_forgejo_and_the_mirror_unchanged` |
| `writ exec` | `an_agent_works_through_writ_git_beside_the_operator_s_own_git` |
| `writ reader` | `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says` |
| `writ ls` | `tickets_are_requested_signed_refused_revised_amended_and_revoked`, `a_restarted_daemon_keeps_leases_mirrors_and_ledger` |
| `writ ls --all` | `tickets_are_requested_signed_refused_revised_amended_and_revoked` |
| `writ ls --approval-url` | `every_client_setting_works_as_a_flag` |
| `writ sign` (the prompt: `y`, `n`, `r`) | `tickets_are_requested_signed_refused_revised_amended_and_revoked` |
| `writ sign --yes` | `tickets_are_requested_signed_refused_revised_amended_and_revoked`, `many_agents_and_a_busy_remote_share_one_daemon` |
| `writ sign --full` | `tickets_are_requested_signed_refused_revised_amended_and_revoked` |
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
| `writ admin token` | `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says`, `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin token --yes` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin token --approval-url` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin token --key` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ admin token --agent` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writ prove-key` (the prompt, on a terminal: `y`, `n`) | `commits_are_verified_once_the_signing_key_is_registered_and_proven` |
| `writ prove-key --namespace` | `commits_are_verified_once_the_signing_key_is_registered_and_proven` |
| `writ prove-key --yes` | `commits_are_verified_once_the_signing_key_is_registered_and_proven`, `every_client_setting_works_as_a_flag` |
| `writ prove-key --approval-url` | `every_client_setting_works_as_a_flag` |
| `writ prove-key --key` | `every_client_setting_works_as_a_flag` |
| `writ prove-key --agent` | `every_client_setting_works_as_a_flag` |
| `writd run` | `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says`, `a_restarted_daemon_keeps_leases_mirrors_and_ledger` |
| `writd init` | `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says`, `writd_init_makes_a_sealed_keystore_that_reveals_no_key_at_rest`, `a_low_lock_limit_is_a_warning_with_its_fix_and_root_is_hardened_too` |
| `writd recover` | `a_sealed_daemon_serves_nothing_until_writ_unseal` |
| `writd host-key` | `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says` |
| `writd tls-fingerprint` | `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says` |
| `writd upstream-keys` | `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says`, `a_stopped_a_changed_and_a_closed_upstream_are_refused_with_their_reasons` |
| `writd signing-keys` | `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says`, `commits_are_verified_once_the_signing_key_is_registered_and_proven` |
| `writd hook pre-receive` (every push) | `every_push_denial_leaves_forgejo_and_the_mirror_unchanged`, `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says` |
| `writd upstream-ssh` (every sync and upstream push) | `a_stopped_a_changed_and_a_closed_upstream_are_refused_with_their_reasons`, `many_agents_and_a_busy_remote_share_one_daemon` |
| `writd upstream-credential` (every sync and upstream push of an `https://` upstream) | `a_repo_behind_https_is_fetched_and_pushed_with_a_token_nobody_else_sees` |
| `writ-sign -Y sign` (every commit under the wiring) | `an_agent_works_through_writ_git_beside_the_operator_s_own_git`, `a_dedicated_clone_is_wired_whole_and_undone_exactly` |
| `writ-sign -Y verify` (handed to `ssh-keygen`) | `an_agent_works_through_writ_git_beside_the_operator_s_own_git` |

## Commands the docs show

The commands the operator guide and the manual checks show are the ones the pipeline runs.
A fenced block right after a marker comment names the file that runs it:

````markdown
<!-- e2e: crates/writ-e2e/src/setup.rs -->
```sh
writd upstream-keys writd.yaml
```
````

and that file runs each of its lines through `doc_step`, `doc_step_fails` or
`doc_step_detached` (`writ_e2e::setup`), with the line's text as a string literal, exactly
(placeholders such as `<host>`, `<name>` or `<lease id>` filled in at run time, a trailing
`# comment` ignored). `tool/check-e2e.py` checks both ways: every command line of a marked
block is run by that file, and every `doc_step…` literal is a line of a block marked for its
file. So a step changed in the docs is changed in the pipeline, and the other way round.
Today: the operator guide's [setup](operators/setup.md) (`setup.rs`)
and the [GitHub manual check](guides/manual-checks.md#a-throwaway-github-repo-m4)'s agent
steps (`wrapper_mode.rs`).

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
5. **Doc-linked commands**: when the scenario runs commands a guide shows, put a
   `<!-- e2e: <the scenario's file> -->` marker before the guide's block and run each line
   through `doc_step` with the same text.
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
