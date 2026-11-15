# Security conventions

How every change keeps Writ secure. [AGENTS.md](../AGENTS.md) holds the hard rules; the
[threat model](threat-model.md) says what Writ defends and what it doesn't; this page is the
working rulebook between them: the patterns every change follows, each with **why** and
**how it is checked**. Written at the [M2.6 security checkup](history/m2.6-security-checkup.md).

Writ is a security tool: a convention here is not a style. A change that can't follow one
changes this page in the same change, with a row in the [decision log](decisions.md) and, if
it weakens a guarantee or adds a residual risk, the [threat model](threat-model.md) and the
user's go-ahead (hard rule 12).

## How it is enforced

| Check | What it enforces | Where |
|---|---|---|
| `make ci` | Everything below, as one target: GitHub Actions runs it on Linux for every push to `main` and every pull request; on the Mac, the `pre-push` hook (`make hooks`) allows only a tree it passed on (`make push`) | `Makefile`, `.github/workflows/ci.yml`, `tool/git-hooks/pre-push`, `tool/ci-stamp.sh`, `tool/install-hooks.sh` |
| clippy (`-D warnings`) | No `unwrap`/`expect`/`panic!`, unchecked indexing, slicing or truncating casts outside tests; no unchecked arithmetic in `writ-core`, `writ-crypto`, `writ-proto`, `writ-git`, `writ-mirror`, `writ-gateway`; no `unsafe` outside its dedicated modules, and every `unsafe` block with its `SAFETY` comment (`undocumented_unsafe_blocks`) | `Cargo.toml` `[workspace.lints]`, each crate's `lib.rs` |
| `tool/check-rules.py` | A file's test module ends it, found however its attributes are spelled and closed with comments, strings and characters left out (so nothing escapes the rules below; a `#[cfg(test)]` helper is test code to its end only; one that never closes refused); no bare `is_err()`/`!success()`/`assert_ne!(…code(), Some(0))` in tests (an assert read whole), no unmarked sleep in tests (`thread::sleep`, an imported `sleep`, `sleep_until`), no test `git` reading the user's config, no `if let Ok(… .lock())` that skips work, no relative program path in production code (a literal or a `const` holding one), no unexplained `#[allow]` or `#[expect]` (or `cfg_attr` of one) of a denied lint or `unsafe_code`, no cfg on the OS (`target_os`, `unix`, `windows`, `target_family`, `target_vendor`, `target_env`, in `cfg`, `cfg!` or `cfg_attr`) outside the platform code, no prints or stdio writes in libraries; each binary's global allocator the wiping one; every crate on the workspace lints, the six arithmetic denies kept, every crate with a `main.rs` a listed binary; the toolchain pinned the same in its three places | `make check` |
| `tool/check-deps.py` | Clients never depend on daemon crates (hard rule 1) | `make check` |
| `tool/check-features.py` | No `testing`, `dev-keystore` or `system-allocator` feature in a shipped binary's graph (checks itself on the test crate) | `make check` |
| `tool/check-guarantees.py` | Every guarantee names tests that exist and aren't ignored, or a milestone still to come; every test the [untrusted-input inventory](#untrusted-inputs) names exists | `make check` |
| `cargo deny` | Advisories, yanked crates, sources, banned crates, licenses | `deny.toml`, `make check` |
| Review | Everything a script can't see: the checklist below | every change |

## The security checklist

Every milestone's history page answers these, one line each, and every change that touches
one of them answers it in its commit message. "Not touched" is a valid answer; silence isn't.

1. **Inputs.** Does it add or change an untrusted input (a field, a command, a file, a
   header)? It is in the [inventory](#untrusted-inputs), with its size, time and count
   bounds (in bytes as well as in count, including what is built from it, and in CPU for
   what is matched under a lock), its parser, and a hostile-input test; costly work on it
   comes after the cheapest authorization check. A format another program also reads (a git
   tree, a protocol) is read as that program reads it, or what it reads differently is
   refused ([parsed as git parses](#untrusted-inputs)).
2. **Authority.** Does it add a way to grant, widen or read? It goes through an approver
   signature (grants), a reader key (reads), or a template (scope), never a flag or a client
   check (hard rules 1, 5). A signed document that changes state names what it applies to
   once and only there: the daemon, and the version it replaces by a number that only grows
   (a digest of content can come back). A check whose type stands for its result has
   private fields: only the check makes one. A client names in a signed document only what
   it authenticated (the daemon: the host key its connection checked) or computed itself
   (a text's digest, a key's fingerprint), never a reply's word for it.
3. **Fail closed.** Every error, unknown value, poisoned lock and missing fact denies;
   fallbacks go toward deny ([details](#fail-closed-in-practice)).
4. **Audit.** Every allow, deny, grant, refusal, revocation and admin change writes its line;
   grants first, reductions never blocked ([details](#grants-reductions-and-the-audit-log)).
5. **Revocation.** Does it hold a decision anywhere (memory, a token, a session)? A
   revocation reaches it, and it is rebuilt from the store at startup. A revocation decided
   while handling a request bars the certificate before the lock is released.
6. **Secrets.** No key, token or passphrase in an error, a log, a reply, `Debug`, or a file
   others can read; zeroized, in buffers sized up front (a `Vec` or `String` growing by
   itself leaves a copy each time: the wiping allocator zeroes it when freed, but Writ's own
   secrets don't rely on it); moved, never copied; written whole (a temporary
   file, synced, linked or renamed into place); redacted in every form it can come back in,
   after the text is cleaned ([details](#secrets)).
7. **Display.** Does agent or daemon text reach a terminal or a notification? It is escaped,
   bounded in rows and in width (the terminal must never wrap it), and never mistaken for
   Writ's own words ([details](#what-people-see)).
8. **Dependencies.** A new crate or feature follows [the dependency rules](#dependencies).
9. **Guarantees.** A guarantee touched has its tests in the registry, trying to break it.
   A request that changes state runs to its end once started (never dropped with its
   client's connection); one that waits for a client ends with it.
10. **Threat model.** A new trust boundary, residual risk or weaker guarantee is written in
    the threat model in the same change, with the user's go-ahead.

## Untrusted inputs

Everything here comes from someone the daemon doesn't trust (an agent, a network peer, a
reader with `decisions: open`). Each has a bound, a strict parser, and a hostile-input test.

- **Parsed as its other readers parse it.** Where git (or ssh, or a remote) also reads an
  input, the daemon reads it the same way, or refuses what they would read differently: a
  tree entry mode git reads as a directory (`40755`) was read as a file, and hid a subtree
  from the path check (the review after M5.5, S1). A setting that holds in one protocol
  version only pins that version (upload-pack speaks v0: in v2, git ignores
  `allow*SHA1InWant`).
- **Bound bytes, not only counts.** A limit on how many things also needs one on how big each
  is, and on what the daemon builds from them: the touched-paths walk was bounded in entries,
  paths and depth, yet one long directory name over many files made it hold the name once per
  file (the M3 review's F1). Count the bytes of what is built (`MAX_PATH_LEN`,
  `MAX_PATH_BYTES`), not only the input's.
- **Costly work after the cheapest authorization.** Decoding, hashing or walking a large
  input waits until the caller is known to be allowed to ask at all (`Service::may_sign`
  before a sign request is read); the decision itself still checks everything again where it
  is made.
- **A violation is a choice, malformed input is not.** What the policy forbids (a tag, another
  repo, a committer outside the lease) is a violation and may revoke a lease; bytes that don't
  parse, or aren't the kind of object asked for, are `invalid` and never revoke one.

| Input | From | Bounds | Parsed by |
|---|---|---|---|
| TCP connection | anyone who reaches a listener | `allow` ranges (required on agents' TCP), 256 per listener, 16 per source (an IPv6 /64; on a Unix socket, per caller process by pid and generation, test `on_a_unix_socket_each_caller_process_gets_its_own_share`), 20 s from the accept to be authenticated (SSH handshake and authentication together, or the TLS handshake), 10 s for an HTTPS request's headers, 10 min idle, 4 channels per SSH connection and one command per channel (each refusal logged); denials logged once per source and minute, 60 lines a minute in all, each line counting the source's own apart from those the budget held back (`a_line_counts_its_source_s_denials_apart_from_the_others`) | `writ_core::net`, `writ-gateway/src/limits.rs` |
| SSH handshake and auth | the same | listed algorithms only, publickey only, 6 attempts, certificate checks (CA, type, validity, principal, no critical option, deny list) | russh with `preferred_algorithms`, `writ_crypto::ca` |
| SSH exec line and env | authenticated peers | exact command grammar, repo names validated, every `env` request refused and nothing of it kept (`GIT_PROTOCOL` included: `upload-pack` speaks protocol v0, where `uploadpack.allow*SHA1InWant` hold; test `a_fetch_by_id_gets_only_what_refs_reach_whatever_the_protocol_asked`), 4 channels per connection | `writ_proto::Command`, `writ-gateway/src/command.rs` |
| Request bodies (SSH stdin, HTTPS) | agents, readers | 256 KiB (`MAX_BODY`), 30 s | `writ_proto` envelope, `deny_unknown_fields` |
| The approval popup's answers (`writ sign --ui`'s stdin, M7.8; client-side) | the app (`writ-popup`), or any process of the approver's user that runs `writ sign --ui` (an agent in local mode: it gets nothing a terminal's `writ sign` wouldn't give it, and every signature still asks the approval key) | one JSON object per line, at most 64 KiB (`MAX_ANSWER`: a longer line dropped to its end, never held whole), UTF-8; `answer` one of `sign`, `refuse`, `skip`, `pick`, its `id` a ticket id, `feedback` only on `refuse`, nothing else (`deny_unknown_fields`); acted on only when it names the ticket shown (a `pick` only for a ticket waiting, fetched and checked like any), else nothing signed and said; read on a thread of its own, 16 lines queued; what serde says of a bad line cleaned before it is sent back (`answers_are_read_strictly`, `a_line_is_read_up_to_its_bound_and_dropped_past_it`, `the_popup_signs_refuses_and_follows_what_waits_over_ssh`) | `writ_cli::approver::ui` |
| A watch (`writ watch [<cursor>]`, `GET /v1/tickets/watch[?since=<cursor>]`, M7.8) | readers | the cursor 64 lowercase hex characters or none, nothing else on the line or in the query (`a_watch_answers_on_a_change_over_ssh_and_over_https`, `command_lines_round_trip`); at most 16 held at once, all readers together, past it refused and logged as a `command` denial, coalesced per source; each held at most 240 s (`WATCH_LIMIT`), ended with its SSH channel, its connection or its HTTPS client (`watches_past_the_cap_are_refused_and_logged_and_each_ends_with_its_client`); the store read on a blocking thread; nothing changed, no line when allowed | `writ_proto::Command::parse`, `from_http`, `writ-gateway/src/api.rs` (`watch`), `Service::watch` |
| Ticket YAML | agents | the body bound, one document, no anchors/aliases/merge keys, depth 32, 50,000 nodes, strict booleans; text bounds (title 200 one line, task 4,000 / 100 lines, plan 50 × 500 one line, 16 repositories (`repos`, at least one), per repository 100 paths of 1,024 bytes and 50 branches, 16 KiB of paths in all, 16 wildcards each, `caller` a pid only (everything else about the process from the kernel's chain of the submission, a pid outside it refused, the executable within 1,024 bytes and UTF-8), each phase of `estimate` at most 30 days); the layout before `writ-ticket/3` refused, naming each key's new place; `amends` and `renews` never both, each a lease of the same session (to another, it doesn't exist), a renewal checked against its lease (`fit::check_renewal`: state, `renew_grace`, each repository's template, subject, scope per repository, the strictest `max_renewals`) at submission and again at signing; `ttl` ≥ `min_ttl` (5 min by default, 10 s at the lowest); 2 pending per session key, 10 submissions/min per address and 60/min from all sources (defaults; the operator sets both, 1-1,000 and 1-10,000: `submissions`), `max_pending` in all | `writ_core::yaml`, `fit` |
| A dry run's ticket (`writ request --dry-run`) | agents (any key the listener lets in) | the ticket YAML's bounds and every check a submission gets, in the same code (`Service::admit`); nothing stored, no notification; counted against the submission rates like a submission; one `dry_run` line (denials coalesced like a submission's) | `Service::dry_run`; tests `a_dry_run_checks_like_a_submission_and_stores_nothing`, `a_dry_run_is_refused_where_a_submission_would_be` |
| A policy read (`writ policy <repo>`, once per repo named) | agents (any key the listener lets in) | the exec line's bound; the repo a registry name (`RepoName`: `[A-Za-z0-9._-]`, 1 to 100 characters, no path); counted against the submission rates; the reply holds only that repo's protected refs, ticket link and templates (each template's signing key by its id, never the key; never its upstream, its credential, another repo); a repo not in the registry refused and logged | `writ_proto::Command::parse`, `Service::repo_policy`; tests `command_lines_round_trip`, `writ_policy_shows_one_repo_and_nothing_else_of_the_policy`, `policy_reads_and_dry_runs_count_against_the_submission_rate` |
| A closing summary (`writ close`) | lease holders, with their session key (any key the agents' listener lets in can ask) | the body bound; counted against the submission rates like a submission (over them, refused and coalesced like one); only the lease's own session (to another, it doesn't exist, and the denial names no lease: the id is the caller's choice); one summary per lease (once it has one, a `close` gets the report as `writ report` gives it, the summary as first written, and writes no line); 4,000 characters, 100 lines, not blank (`RefusalCode::Summary`); kept as agent text, shown escaped, never acted on; the report built from it reads the audit log without the state lock, at most 100,000 lines of the chain, each line at most 512 KiB | `Service::close`, `writ_store::read_lines`; tests `closing_ends_the_lease_and_reports_what_it_did`, `closes_count_against_the_submission_rates_and_a_flood_of_unknown_ids_is_bounded` |
| `writ git`'s arguments, `writ exec -C` (client-side, on the agent host) | the agent | git's global options read in git's order and forms (`-C` and `-c` only with the next argument, the `=` forms only for the options git takes them for); an option git doesn't take before a command, a missing value or a non-UTF-8 option refused with its reason, git never run; the repository resolved by git itself from `-C`, `--git-dir`, `--work-tree`, `--bare` and the environment; its reason escaped; a convenience: `writ-sign` refuses a commit made outside the wired repository, the daemon checks every request | `writ_cli::gitopts`; tests `what_git_would_refuse_or_read_otherwise_is_refused_with_its_reason`, `every_global_option_is_read_and_only_the_locating_ones_kept` |
| The installer's manifest (`install.manifest`, M7), read as root by the uninstall | the installer (as root) | trusted only as a regular file, root-owned (the test root's owner under `WRIT_INSTALL_ROOT`), that neither group nor others can write; each line's path acted on only if it is one of the setup's own (`setup_owns`: `/opt/writ`, `/etc/paths.d/writ`, the plist, `/var/db/writ`, Writ's directories under `/Library`, your `~/.writ`), anything else named and left as it is; the uninstall asks every question (`REPOS`, `PURGE`) before it changes anything | `deploy/frame.sh`; tests `an_install_upgrades_and_uninstalls_leaving_the_mac_as_before` (a group-writable manifest refused), `the_uninstall_takes_back_only_the_installer_s_own_paths` |
| The client's settings file (`<home>/config`, M7; client-side) | the user, the installer, the agent (the user's file) | a regular file, never a link, at most 16 KiB, UTF-8; `key = value` lines, `#` comments; only `url` and `approval_url`, each once, a value of 1 to 4,096 bytes; no control or hidden character; anything else refuses the whole file, naming the line (escaped once, by `writ`'s error output); flags and variables win over it; what it can change is where `writ` connects, never whom it trusts (the pinned host key and TLS pins decide) | `writ_cli::settings`; tests `the_endpoints_are_read_each_once`, `anything_else_refuses_the_file_naming_the_line`, `a_file_that_can_t_be_trusted_is_not_read`, `the_client_settings_file_gives_the_endpoints_and_flags_still_win` |
| The list of what `writ init` wired (`<home>/repos`, M7; client-side) | the agent (the user's file), the operator | a regular file, never a link, at most 256 KiB (larger: refused whole, nothing done), UTF-8; at most 4,096 lines used; each `repo <path>` or `workspace <path>`, the path absolute and normalized (no `.`, `..`, `//` or trailing `/`), at most 4,096 bytes, no control or hidden character, a directory there and not a link, holding `writ init`'s own record of that kind (a repository on its own, not a workspace's); anything else skipped and named, escaped; acted on only through `writ init --undo` and `writ skill update` as they run in that place; written whole (a private temporary file renamed) | `writ_cli::repos`; tests `an_entry_is_a_known_kind_and_a_clean_absolute_path`, `an_oversized_file_is_refused_whole_and_a_link_too`, `a_line_that_names_nothing_wired_is_skipped_and_named_escaped`, `the_list_of_wired_repositories_is_read_as_untrusted_and_undoes_only_what_writ_init_wired` |
| A workspace record (`<folder>/.writ-workspace`), a repository's record (`<git common dir>/writ/config`), `--repo` answers, and the `skill.*` entries of any wiring record (client-side, on the agent host) | the agent (the folder is its working folder), the operator | a regular file, never a link, at most 64 KiB (opened without following a link or blocking on a FIFO, then read whole and handed to `git config -f -` on its stdin, so git reads what was checked); at most 256 repositories, each `.` or a plain folder name (no `/`, not hidden, no control character, at most 255 bytes) once, its registry name a `RepoName`; `--repo` the same, `-` to leave one out; an undo takes back only a repository whose own record names this folder, removes only a regular `SKILL.md` in a `writ/` or `writ-workspace/` folder that still carries Writ's mark, only empty folders on the way to one, the pointer line only from `AGENTS.md`/`CLAUDE.md`, exclude lines only from the repository's own `.git/info/exclude`; everything shown escaped; never sent to the daemon | `writ_cli::workspace`, `writ_cli::skill`; tests `a_hostile_record_is_refused_whole`, `a_record_that_is_a_link_or_too_large_is_not_read`, `repo_answers_are_read_strictly`, `a_repository_folder_is_one_plain_name_right_under_the_root`, `undo_removes_only_writ_s_own_skill_files_and_the_empty_folders_it_made`, `a_record_is_read_bounded_whatever_is_in_its_place`, `a_record_in_a_hostile_place_is_refused_never_waited_on` |
| The timings file, `writ check`'s file, a session's `marks` (client-side, on the agent host) | the agent | the timings file a regular file (opened without blocking: a FIFO refused), at most 1 MiB, parsed in one pass keeping at most 200 repositories (the latest) and 50 runs and 50 notes each (the latest); compacting counts the text's size once and keeps it up to date (never rendered per thing dropped); `writ check`'s file at most 256 KiB, a timings file only when its front matter names a limit or it is the one the wiring records; `marks` a regular file, at most 256 KiB and 10,000 lines; only what parses is kept, each line cut to 400 characters, control characters replaced; limits within their bounds or the defaults; never sent to the daemon | `writ_cli::timings`, `writ_cli::close`; tests `hostile_or_broken_files_are_read_within_bounds`, `a_hostile_file_is_capped_while_it_is_read_and_compacted_in_one_pass`, `a_timings_file_that_is_a_fifo_or_a_directory_is_not_read`, `marks_are_read_bounded_and_never_from_a_fifo`, `a_ticket_starting_with_yaml_s_marker_is_checked_as_a_ticket` |
| Canonical tickets and decisions | approver clients | decode then re-encode to the same bytes | `writ_core::canonical` |
| SSHSIGs | approver clients | namespace, keys compared whole, accepted key types, `sk-` user presence | `writ_crypto::sshsig`, `allowed_signers` |
| Proofs (`writ prove`) | readers, with an approver's signature | the body bound; the `writ-proof/1` document decoded strictly (canonical bytes); the namespace 1-64 of `[A-Za-z0-9._@-]`, never `git` nor `writ…` in any case; the message 1 to 4,096 bytes of UTF-8; the key one a template signs commits with; for an OpenPGP key, never a message that starts like a git commit or tag (`tree `, `object `); the approver's SSHSIG over exactly those bytes, required whatever `decisions` says; through the signer's queue (`Busy`, `Timeout`) | `writ_core::signed::Proof`, `writ_core::names::ProofNamespace`, `Service::prove` |
| TLS client certificates | HTTPS peers | TLS 1.3, a reader's Ed25519 key, handshake signature checked; no session resumption (no session stored, no ticket), so every handshake checks the certificate (`the_approval_api_never_resumes_a_session`) | `writ_crypto::tls::ReaderVerifier` |
| Pre-receive input | git, on an agent's push | 1 MiB (the hook reads at most one byte more from git, `the_hook_reads_at_most_one_byte_past_the_daemon_s_bound`), cut-short refused, a token, a quarantine path (believed only as a directory, not a link, right under the mirror's `objects` with git's prefix), 1 to 1,000 lines each an exact update; the lease's ref rules on them (`policy::check_push_refs`, `decide_push`'s ref loop) before the mirror is held or any git runs for them (`the_ref_rules_are_checked_before_anything_is_read`); each `old` the ref's value in the mirror, or refused (`an_update_whose_old_id_is_not_the_ref_s_is_refused`) | `writ-gateway/src/hook`, `writ_mirror::quarantine` |
| Pushed objects | agents | `fsckObjects` (with `.git`, `.`, `..`, empty, absolute names, null ids, non-standard and zero-padded modes at error level), `receive.maxInputSize` = the repo's `max_push_size` in the lease (the smaller of it and its template's); the ref commands before the pack at most 1 MiB (pkt-lines up to the first flush) and the push at most `max_push_size` and that in all, git killed and the push refused with its reason past either (`ref_commands_past_their_bound_are_refused_before_git_holds_them`, `a_push_s_commands_are_bounded_up_to_their_flush_and_never_the_pack`); a fetch's negotiation at most 16 MiB; every git operation at most an hour in all (`a_stopped_process_is_killed_and_its_reason_returned`); read only after `may_push`; new commits those no branch or tag of the mirror reaches (a commit only its notes ref reaches is new, `a_commit_only_the_mirror_s_notes_reach_is_checked_like_a_new_one`); new commits at most the lease's `max_signatures` (10,000 in all); each commit's paths from at most 16 MiB of objects, in the bounded walk; every read within 120 s | git, configured by `writ_mirror::git`; `writ_mirror::quarantine`; `writ_git::paths` |
| Sign requests (`writ-sign git <repo>`, `writ-sign openpgp <repo>`) | lease holders | the exec line's grammar (`git` or `openpgp`, a registry name; a format that isn't the lease's key's denied, `signature_format`, before a slot is taken); the body read only for a lease that is active, allows `commit_sign` and names the repo; the `writ-sign/1` body: 16 MiB (`MAX_SIGN_INPUT`) within 60 s, at most 100,000 evidence objects, sizes in plain decimal, nothing after the last object; at most 16 sign requests held by the daemon at once, all lease holders together, and the operator's share per lease (`sign_requests.per_lease`, 4 by default, 1-16), from the body read to the answer (refused at once past either); at most 16 signatures waiting for the signer (`Busy` past it), 10 s each (`Timeout`), each with its slot taken first; what is signed held at most four times while a request runs (the body read, an OpenPGP ECDSA or RSA key's preimage of it, sized up front, the signer queue's copy, a helper's one request frame), so 16 requests hold at most 1 GiB, each copy wiped when freed (the review after M7.6, K-5) | `writ_proto::sign::SignInput`, `writ-gateway/src/exec/sign.rs` |
| The commit to sign | lease holders | only the layout git writes (`tree`, `parent`s, `author` and `committer` as `name <email> time zone`, `encoding`, `mergetag`), no signature already in it, 100 parents; trailers found as git finds them (git's whitespace only: space, tab, newline, carriage return, `trailers_are_git_s`); the author's and the committer's emails both compared exactly with the lease's `committer_emails`, and their names (bytes before ` <`; not UTF-8 is none, never guessed) with its `committer_name` when it has one | `writ_git::commit`, `writ_git::trailers` |
| Evidence objects (the first parent commit, trees) | lease holders | read only by the id computed from their bytes (SHA-1 with collision detection, or SHA-256); trees parsed strictly (no empty, `.`, `..` or `/` name, no name twice, no `.git` as any filesystem reads it, no mode but the five git writes, `100644`, `100755`, `120000`, `40000`, `160000`, since git reads `40755` or `040000` as a directory: a commit with either is refused whatever `paths_check` says, test `a_directory_with_a_non_standard_mode_cannot_hide_its_files`); the walk visits at most 1,000,000 entries, lists 100,000 paths, follows 256 levels, builds no path over 4,096 bytes and at most 64 MiB of paths in all; a parsed tree holds its names borrowed and each entry in a fixed 56 bytes (`tree::ENTRY_BYTES`) of one vector sized from the content, at most twice its bytes (an entry takes at least 28), two trees at a time, so a walk over 16 MiB of evidence holds at most about 32 MiB of entries and 16 bytes a name to compare them (`a_parsed_tree_costs_at_most_twice_its_bytes`); `.git` as `git fsck` reads it (`a_dot_git_name_is_refused_wherever_git_fsck_sees_one`) | `writ_git::paths`, `writ_git::tree` |
| Caller facts | the kernel, via the attestor | never what the client claims; attested off the async threads; a caller that can't be attested turned away, except on an approval listener's Unix socket, taken without a chain (`a_broken_process_reader_never_shuts_the_approver_out_and_slots_are_per_process`) | `CallerAttestor` implementations |
| Config and authority files | the operator | owner, mode, no link, regular file, 1 MiB | `writ_platform::fs::read_authority` |
| Upstream host keys (the policy's `upstream_hosts`, M6.2) | an approver (a signed policy) | 256 hosts, 16 keys each, 8 KiB a key; each host a plain name or `[host]:port` (no wildcard, negation, hashed name or marker; port 22 unbracketed), each key `<type> <base64>` with no comment and no DSA type, decoded whole before the policy is in force; written by the daemon for ssh in its own form | `writ_core::config::hosts`, `writ_mirror::known_hosts` |
| Key declarations (the policy's `keys`, M6.2) | an approver (a signed policy) | each field checked against its use and kind, names from fixed lists (`use`, `kind`, `format`, `algorithm`, `hash`), a backend name of 1 to 32 characters, a token's host a plain name of at most 253, 1 to 16 user ids; every combination checked against its backend, never adjusted | `writ_core::config::keys`, `writd`'s `declared` |
| What upstream sends on a sync (refs, objects, its errors) | the remote (semi-trusted: compromised, or behind a hostile network) | the pinned host key (`ssh://`), or a certificate from the trusted CAs and no redirect (`https://`); `mirrors.max_fetch` bytes per operation, every git of it together (the operation's proxy, for `ssh://` as for `https://`; the relay bounds each git too: `the_byte_cap_holds_for_an_operation_s_gits_together`) and `mirrors.timeout` (process group killed); `fsck` with `.git`, `.`, `..`, empty, absolute names, null ids, non-standard and zero-padded modes at error level; branches and tags only, all or none; the registry's object format; the token (and its Basic form) taken out of the text as git prints it (split at each line break, git's `remote: ` prefixes and hidden characters gone) before any cut, the whole text withheld if a part of 8 characters still shows (`a_token_split_cut_or_broken_up_by_git_s_formatting_is_never_shown`); error text cut to 2,000 characters, hidden characters dropped; an agent told only the repo and what failed, never upstream's address, words, proxy or credential (a refused push: the refused refs and the remote's own words), the whole text in the audit line and the log (`an_agent_is_told_nothing_of_upstream_s_address_or_words`) | git, configured by `writ_mirror::git`; `writ_mirror::relay`; `writ_mirror::proxy` |
| Upstream's notes ref (`ticket_link: notes`), and what it says of a notes push | the remote (semi-trusted) | fetched only when the daemon's notes push is refused as behind it (`fetch first`, `non-fast-forward` on that ref, from git's porcelain output): that one ref, forced into the mirror's, with a sync's checks and bounds (`fsck`, `mirrors.max_fetch`, `mirrors.timeout`, a failed fetch's partial pack removed); one retry, then a refusal; its notes merged with `union` (kept as written, never interpreted); its words cut and cleaned like a sync's | `writ_mirror` `mirror/notes.rs`; test `a_malformed_notes_ref_upstream_never_lands_and_the_notes_push_fails` |
| The upstream agent socket | processes of the daemon's user (a private directory) | one key, 4 connections, 4 signatures, 256 KiB messages, 30 s each, 16 requests a connection; anything but "list keys" and "sign with that key" fails | `writ_mirror::agent` |
| An HTTPS upstream's token file (`<keys>/tokens/<id>`) | the operator | a secret file (`read_secret`: owner, 0600, no link), 4 KiB; the token 1 to 1,024 printable ASCII characters, no space or newline, surrounding whitespace trimmed; missing or malformed stops the daemon, the error never holding it | `writ_mirror::credential::UpstreamToken`, `writd/src/keystore.rs` |
| Upstream CA certificates (`mirrors.ca_certs`) | the operator | an authority file (1 MiB); 1 to 1,000 PEM certificates, each a trust anchor webpki reads, no other block; rewritten by the daemon for git | `writ_crypto::tls::check_ca_certs` |
| The upstream credential socket | processes of the daemon's user (a private directory): the daemon's helper | 8 connections, 4 answers holding the token, a 4 KiB request within 30 s; answered only for `protocol=https` and the registry's host and port, each named once; anything else closed without a word | `writ_mirror::credential` |
| The upstream proxy (SOCKS5) | the daemon's git, and ssh's tunnel behind a proxy (`writd upstream-tunnel`) (a private directory) | `CONNECT` without authentication only; the registry's host and port only (by name, case aside, or the address the URL names); 16 connections, git's request within 30 s, then upstream reached within 15 s (behind a proxy: within its `connect_timeout`, up to 5 min, and no shorter deadline: `a_dial_gets_its_proxy_s_whole_timeout_and_git_s_exchange_its_own_deadline`); every `ssh://` operation through it too, directly or not; what upstream sends counted against `mirrors.max_fetch` across every tunnel, all ended past it | `writ_mirror::proxy` |
| A proxy's answers (`proxies.<name>`, M7.2: SOCKS5 replies, an HTTP CONNECT answer's head) | the proxy (no more trusted than the network) | within the proxy's `connect_timeout` (1 s to 5 min); SOCKS5 read field by field (version, the method offered and nothing else, RFC 1929's status, the reply's status, an address of a known type and length, read whole so what follows is upstream's); HTTP read byte by byte to the head's end, at most 8 KiB, `HTTP/1.0` or `HTTP/1.1` and three digits, only `200` opens the tunnel (`407`: the credential refused or needed); what it says cleaned and cut, the password and its Basic form taken out | `writ_mirror::dial` (`every_bad_socks5_answer_is_refused_with_its_reason`, `every_bad_http_answer_is_refused_with_its_reason`, `an_endless_head_is_cut_at_8_kib_on_both_sides`, `no_message_holds_the_password`) |
| A proxy's URL (`proxies.<name>.url`) | an approver (a signed policy) | `socks5://` or `http://` only, `[user@]host:port`: printable ASCII, no quote, a plain host name or address (at most 253), an explicit port 1-65535, the user of `[A-Za-z0-9._~-]` (at most 255), no password, path, query or fragment | `writ_core::config::ProxyUrl` |
| `writd upstream-tunnel`'s arguments | ssh's `ProxyCommand`, written by the daemon | an absolute socket path, a plain host (at most 255), a port 1-65535; its paths never hold what a shell or ssh's `%` tokens read | `writ_mirror::tunnel`, `writ_mirror::upstream` |
| An HTTPS upstream's URL (`upstream`) | the operator (the registry) | `https://[user@]host[:port]/path`: printable ASCII, no quote, a plain host name or address, port 1-65535, the user of `[A-Za-z0-9._~-]`, no password, query or fragment; never `http://` | `writ_mirror::upstream::HttpsUrl` |
| The sealed keystore's files (`keystore.sealed`: the secrets' age files, their public halves, the recipient, the boot tier) | whoever can write the daemon's keys directory or boot tier | a secret (age file, boot key) is a secret file (`read_secret`: owner, 0600, no link), 64 KiB, an age file encrypted to a recipient (one encrypted to a passphrase refused), opened only by the keystore's identities; a public half or the TLS certificate is an authority file, and each public half must be its key's when the key is opened (one replaced is refused, naming both files); a key the policy names that the keystore lacks is refused by name | `writd/src/keystore/sealed.rs` (`SecretFiles`); tests `a_replaced_or_foreign_file_is_refused_by_name`, `a_declared_key_the_keystore_lacks_or_holds_otherwise_is_said` |
| A passphrase typed (`writd init`) | the operator's terminal, or one line of stdin | read a byte at a time into memory wiped on drop, at most 1,024 bytes before its line's end; a new one 12 characters or more, UTF-8, no control character; never printed, never in an error | `writ_crypto::passphrase`; tests `a_new_passphrase_is_bounded_on_both_sides`, `a_line_ends_at_its_newline_and_is_bounded` |
| The unseal request (`writ unseal`: the passphrase, the `writ-unseal/1` document, its SSHSIG) | readers (the approval listeners) | the body bound (256 KiB); answered only while sealed; one at a time (another is refused at once); the document decoded strictly (canonical bytes), naming this daemon's host key and this boot's nonce (32 lowercase hex); the approver's SSHSIG over exactly those bytes checked before the passphrase is tried (scrypt runs only for an approver); the body wiped once read; the passphrase never in a reply, a log or an audit line | `writ_core::signed::Unseal`, `Service::check_unseal`, `writ-gateway/src/api.rs`; tests `an_unseal_needs_an_approver_signature_over_this_daemon_and_this_boot`, `unsealing_needs_both_the_passphrase_and_an_approver_signature` |
| An admin change (`writ admin apply`: the `writ-admin/2` document, its SSHSIG) | readers, with an approver's signature | the body bound (256 KiB); the daemon open; the document decoded strictly (canonical bytes), the text at most 100 KiB of UTF-8 without control characters but newlines and tabs, `daemon` this daemon's host key fingerprint, `version` a number, `previous` 64 lowercase hex; the approver's SSHSIG over exactly those bytes; `version` and `previous` the version in force, checked again under the lock (a replay, even after the text came back to what it replaced, a change for another daemon, or one made meanwhile refused); a change of `approvers` revokes the leases a removed key signed; the text parsed and checked like a start (YAML bounds, `allowed_signers`, `readers`, one key one purpose, the template's keys held, a changed repo's mirror opened); one change at a time | `writ_core::signed::Admin`, `Service::check_admin`, `writd`'s `daemon::Opener::apply_admin`; tests `an_unsigned_wrongly_signed_or_stale_change_is_refused_and_logged`, `a_change_replayed_after_the_text_came_back_never_applies_again`, `removing_an_approver_revokes_the_leases_it_signed`, `a_signed_change_applies_at_once_and_is_written_back_to_its_file` |
| A token change (`writ admin token`: the `writ-token/3` document, its SSHSIG) | readers, with an approver's signature | the body bound (256 KiB); the daemon open, its keystore sealed (the development keystore refuses it); the document decoded strictly (canonical bytes; `writ-token/2` refused), `id` a key id an `https://` repo or a sealed notifier uses, `daemon` this daemon's host key fingerprint, `version` a number, `previous` 64 lowercase hex or `none`, `sealed` an armored age file of at most 8 KiB encrypted to a recipient (never a passphrase); the approver's SSHSIG over exactly those bytes; the ciphertext opened by the keystore's identity and parsed as a token (`UpstreamToken`, `BotToken` bounds) before anything is written; then under the state lock `version` the id's change count (a number that only grows, kept by the id even once it leaves the policy: the review after M7.6, A-6) and `previous` the token file in force (a replay, even once the file was deleted with its key, or a change made meanwhile refused), the line, the count bumped, the file written: the token sealed again by the daemon to the keystore's recipients in force, never the file as sent (a client's stale recipients never stored, the review after M7.6); the token never in a reply, a log or an audit line | `writ_core::signed::Token`, `Service::check_token`, `Service::commit_token`, `writd`'s `daemon::Opener::apply_token`; tests `an_unsigned_wrongly_signed_or_malformed_token_is_refused_and_logged`, `a_signed_token_against_the_file_in_force_is_logged_and_a_replay_is_stale`, `a_token_replayed_once_its_file_was_deleted_is_refused_by_its_count`, `a_token_change_is_counted_and_written_only_after_its_line`, `a_token_s_change_count_only_grows_and_survives_a_reopen`, `a_token_sealed_to_a_recipient_taken_out_is_stored_without_it`, `a_token_added_from_the_mac_is_used_at_once_and_never_in_clear_on_disk` |
| The authority versions in the state (`leases.db`'s `authority` tables) | whoever can write the daemon's state | each text checked against its digest when read; at a sealed start only read and refused from (a policy that doesn't parse stops the start), never acted on: the head checked against the keystore's MAC as soon as the unseal opens the authority key, before anything is written or made from the policy (an `unseal: auto` read there lets the devices unwrap the identity, nothing more), and again by the service; a version altered, replaced or swapped refused, nothing written, the daemon sealed; a sealed daemon without versions refuses to start | `writ_store`'s `store/authority.rs`, `keystore::open`, `InForce::check_mac`, `Service::unseal`; tests `a_text_changed_under_its_digest_or_a_missing_version_is_corrupt`, `versions_whose_mac_is_not_the_keystore_s_keep_the_daemon_sealed`, `a_policy_altered_at_rest_is_refused_at_unseal_before_anything_is_written`, `on_the_mac_an_unseal_auto_altered_at_rest_opens_nothing_and_writes_nothing` |
| A file given to `writd recover` | the operator on the host | an authority file (owner, mode, no link, 1 MiB); the keystore's passphrase or its recovery key first (one line typed, read like a passphrase: an age secret key opens the recovery file `identity.recovery.age` only, anything else is a passphrase and refused on a keystore the hardware opens, each named; M7.6); checked like an admin change with the two others in force, and every question asked (trusting versions altered at rest, a new passphrase), before the keystore is touched (the review after M7.6, S-6) | `writd`'s `recover.rs`, `authority::prepare_recover`; tests `a_version_altered_at_rest_keeps_the_daemon_sealed_and_writd_recover_needs_the_passphrase`, `writd_recover_answered_no_changes_nothing_even_for_a_policy_dropping_a_recipient` |
| A rotation of the data key's files (`rotation/` and its record `rotation/commit`, `rotation-owed`, M7.7) | the daemon's own (whoever can write the keys directory: Q38, M8) | read before anything else at a sealed start, an unseal and `writd recover`, from the record alone (never the policy); `rotation` a directory (a link or a file refused by name); staging with no record removed; the record an authority file (owner, mode, no link, 1 MiB), its header `writ-rotation/1`, then `put <file> sha256:<64 hex>` and `remove <file>` lines, each file once, at least one put, every file one of the keystore's own (a fixed list of names, `signing/`, `upstream/`, `tokens/` `<id>.age`, `recipients/<id>.pub` or `.blob`: never a path out of the keys directory); each staged file read bounded (64 KiB secret, 0600; or an authority file) and moved only when its digest is the record's, one in place checked by its digest; `rotation-owed` an authority file, its header, 1 to 64 reasons of at most 512 characters, no control character; anything else refuses the start naming the file | `writd` `keystore::rotation`; tests `a_record_reads_back_and_anything_else_is_refused_by_why`, `only_the_keystore_s_own_files_are_a_rotation_s_and_each_has_its_mode`, `a_rotation_record_or_staging_not_writd_s_refuses_the_start_by_name` |

| The device keys owed to the daemon (`to-make.json` in the keys directory, written by `writd init` and `writd recover`) | the daemon's own (whoever can write the keys directory: Q38, M8) | read at each sealed start, before anything else reads a key; an authority file (owner, mode, no link, 1 MiB) of strict JSON, unknown fields refused: `kind` `writ-to-make/1`, at most one CA and one TLS entry and 1,000 keys, each id a `KeyId` named once, its role `signing` or `upstream`, its declaration read like the policy's (`keys.<id>`) and on a backend the daemon has that is a device (an owed software key refused), an OpenPGP key's user ids bounded like the policy's; the policy in force is never read for it (S-1); a key whose files are there is taken as made, never made again; anything else stops the start, naming the file and the entry | `writd/src/keystore/to_make.rs`; tests `a_to_make_file_out_of_bounds_or_hostile_stops_the_start`, `what_is_owed_is_read_written_whole_and_added_to`, `on_the_mac_writd_init_leaves_each_device_key_to_the_daemon_s_first_start`, `on_the_mac_writd_recover_leaves_a_device_key_to_the_daemon_s_next_start` |
| A TLS key rotation (`writ admin tls rotate`: the `writ-tls/1` document, its SSHSIG; M7.5) | readers, with an approver's signature | the body bound (256 KiB); the daemon open; the document decoded strictly (canonical bytes), naming this daemon, the certificate it replaces (`SHA256:` and 43 base64 characters, the one in force or refused: a replay rotates nothing) and a backend (`BackendName`; one the daemon has, making P-256 keys); the signature by a key in `approvers`; 5 rotations a minute, counted once it names the certificate in force (a replay takes none); one admin change at a time | `writ_approval` `service/tls.rs`, `writd` `daemon::Opener::rotate`; tests `a_replayed_stale_foreign_or_unsigned_rotation_is_refused_and_logged`, `a_tls_rotation_is_pinned_strict_and_names_the_certificate_it_replaces`, `a_replayed_rotation_takes_no_place_in_the_rate_which_holds_on_both_sides` |
| The daemon's new certificate, in a rotation's reply (`TlsRotated`, M7.5) | the daemon, over a connection its old certificate authenticated | a fingerprint read strictly (`CertFingerprint`); `writ` replaces only the line pinning this daemon to the old one, in a pins file it checked like for a connection, written whole then renamed, and connects again with the new pin before saying it is done | `writ-cli` `https::repin`, `approver::admin::tls_rotate`; test `the_tls_key_is_rotated_live_the_client_repinned_and_the_old_pin_refused` |
| A scan request (`writ admin scan`: the `writ-scan/1` document, its SSHSIG) | readers, with an approver's signature | the body bound (256 KiB); the daemon open; the document decoded strictly (canonical bytes), naming this daemon, a host name of at most 253 characters (`HostName`), a port 1-65535, a nonce the daemon handed out (16 outstanding, 5 minutes, used once), and optionally a proxy (`ProxyName`; one the policy in force declares, with its password in the keystore, else refused before anything is reached); the signature by a key in `approvers`; 10 scans a minute; its line written before the daemon connects out, the scan refused without it | `writ_approval` `service/scan.rs`; tests `a_scan_runs_only_on_an_approver_s_signature_over_this_daemon_and_a_fresh_nonce`, `nonces_and_scans_are_bounded`, `a_scan_s_line_comes_before_the_daemon_connects_out_and_none_refuses_it`, `a_host_behind_a_proxy_is_scanned_through_it_on_the_approver_s_signature` |
| What a scanned host sends (its key exchange, its host key) | any host an approver names (untrusted) | one handshake per algorithm (Ed25519, P-256, P-384), each asking that one alone, within `mirrors.scan_timeout`; the key parsed by russh and kept only once the host proved it holds it (the exchange's signature), at most 3; dropped before authentication; errors cleaned; shown with fingerprints, never pinned | `writ_mirror::scan`; test `a_host_is_scanned_on_a_signature_pinned_once_compared_and_a_repo_checked` |
| What upstream says on a check (`writ admin repo check`) | the remote (semi-trusted) | a repo the registry names only; the sync's bounds (`mirrors.timeout`, or `mirrors.first_sync_timeout` for an empty mirror's sync, its output caps, the pinned host); a push `--dry-run` sends nothing; what it says cleaned (control characters out) and cut, in the output and the `check` line; 10 checks a minute | `writ_mirror` `mirror/check.rs`; test `a_host_is_scanned_on_a_signature_pinned_once_compared_and_a_repo_checked` (a hostile message, a flood) |
| git's progress on a sync (`fetch --progress`: its stderr as it comes; the counts of `Receiving objects` from the pack upstream sends, and its `remote:` phases) | the remote (semi-trusted) | read in 64 KiB reads, cut at each `\r` and `\n`, a part of at most 256 bytes looked at (a longer one is no progress); a progress part only a phase from a fixed list (git's two, upstream's three after `remote: `), then `<n>% (<done>/<total>)` in ASCII digits only, each count a `u64` (an overflow: not progress), the percent computed by Writ from the counts, `done` shown at most `total`; a progress part kept out of the 64 KiB of stderr a failure is classified from, any other kept as before; only Writ's words and the numbers reach the status, never git's text; only shown, never enforced (`hostile_progress_never_reaches_the_status_but_as_numbers`) | `writ_mirror::progress` |
| A sync status read (`writ admin repo status [<repo>]`, `GET /v1/repos/status`, `GET /v1/repos/<repo>/status`) | readers | the exec line's grammar and the route's; the repo a registry name (`RepoName`) or none, one the registry doesn't name refused (`unknown repo`); answered from memory, under the status's own lock (never the mirror's), one entry per registered repo; a failure as the check says it (cleaned, at most 2,000 characters), cleaned again by `writ` and shown in rows of at most 78 columns; a read, like `writ admin show`: no audit line | `writ_mirror` `mirror/status.rs`; tests `an_empty_mirror_s_sync_has_the_first_sync_limit_and_a_synced_one_the_other`, `a_host_is_scanned_on_a_signature_pinned_once_compared_and_a_repo_checked` |
| What macOS says of a caller and its ancestors (M7: the audit token, `proc_pidinfo`, `proc_pidpath`, the Security framework's code signature; a process's signing id and team id are the agent's own choice when it signs its program ad hoc) | the agent (its processes), the kernel | the caller's pid and generation from the audit token taken at connect, never what the client says; each parent the one the kernel records for its child (its unique id), a parent gone or a pid reused ending the chain there, a process changed between two reads not vouched for; at most 64 processes a chain (`MAX_CHAIN`); the executable as `proc_pidpath` names it (`PROC_PIDPATHINFO_MAXSIZE`), never the name or arguments; a code identity kept only for a valid signature, the signing id at most 255 characters and the team id at most 64, no hidden character (else none), at most 1,024 identities cached; shown escaped, compared exactly | `writ_platform_macos::attest`, `sys::process`, `sys::codesign`; tests `identities_past_the_bounds_are_left_out`, `the_chain_goes_from_the_caller_to_launchd_each_with_its_generation`, `the_caller_is_its_executable_whatever_it_calls_itself`, `an_orphan_s_chain_never_runs_through_the_session_it_left` |
| What `/proc` says of a caller and its ancestors (Linux, M7.1: `stat`, the executable and namespace links; `comm`, inside `stat`, is the process's own choice) | the agent (its processes' names), the kernel | each file read at most 64 KiB; `stat`'s fields read after the last `)`, numbers parsed strictly, anything else unreadable; an executable path at most 4,096 bytes (`PATH_MAX`), the kernel's ` (deleted)` taken off and said as `unbindable`; namespace links parsed as `<kind>:[<inode>]` only; every read of a process inside one pidfd's life (a process gone, or one whose pid was reused, never read for it); a parent that started after its child is not its parent; at most 64 processes a chain; name and arguments never read | `writ_platform_linux::procfs`, `attest`; tests `stat_is_read_after_the_process_s_own_name`, `a_namespace_link_is_its_kind_and_inode`, `a_parent_reused_or_gone_ends_the_chain_there`, `a_chain_holds_at_most_its_bound`, `the_caller_is_its_executable_whatever_it_calls_itself` |
| The process reader's answers (`writd proc-reader`, Linux, M7.1) | the daemon's own helper (trusted, but a process of its own: checked like an input; confined by its seccomp filter to its socket, `readlink`, its memory and its exit) | one request, one answer, each within 5 s; a known tag only; the links only (executable, namespaces), the rest read by the daemon itself inside the pidfd it holds; an executable at most 4,096 bytes and a reason at most 512 bytes, said before their bytes and refused past them; the deleted flag 0 or 1; an answer that doesn't fit its request, a late or a broken one ends the reader's use for good (every Unix caller of the agents' listener refused, logged once; the approval listeners take theirs without a chain), never retried | `writ_platform_linux::helper`; tests `a_broken_answer_ends_the_process_reader_for_good`, `a_process_reader_that_doesn_t_answer_in_time_is_not_used_again`, `a_process_reader_that_doesn_t_say_ready_is_refused_at_start` |
| The Secure Enclave helper's answers (`writ-se`, macOS, M7.5) | the daemon's own helper (trusted, but a process of its own that calls CryptoKit, which may crash on a corrupted blob: checked like an input) | `writ-se/1`: one request at a time, its write and its answer within one deadline (written by a thread of its own: a helper that stops reading is killed at the deadline, `a_helper_that_never_reads_a_large_request_costs_one_deadline`), each answer and its fields in buffers wiped when dropped, and wiped by the helper once written; an answer at most 64 KiB, said before its bytes and refused past it; a status 0 or 1 only, exactly the operation's fields, each length within the frame; a refusal one code of at most 64 bytes of `[a-z0-9-]`; a public point 65 bytes, uncompressed, on P-256, and the key's own (at start against the public half the daemon kept; a key just made signs a probe first); every signature 64 bytes and verified with the key's public half before it leaves. **No blob reaches it unframed:** the stored bytes are the blob behind `writ-se-blob/1` and a SHA-256 over the header, the key's public point and the blob, checked against the kept public half before the helper is asked (a corrupted blob can panic the Secure Enclave's firmware, and the Mac with it). **Its key agreement (M7.6):** a key-agreement key's blob framed under its own header (`writ-se-agreement/1`, so a signing blob never passes for one, nor the other way round) and checked the same way; its point 65 bytes, uncompressed, on P-256, and the key's (answered at load, then proven by a probe agreement with a fresh ephemeral point, computed back from the point); a peer point checked on the curve before it is sent; a shared secret exactly 32 bytes (a wrong one only fails to open its stanza). A helper that dies, stays silent, or answers wrong is killed and the job refused (its error logged, nothing of the helper's text sent to a client); the next job starts a new one. Started by absolute path (a relative one refused), with an empty environment, its stderr discarded; requests at most 16 MiB of data | `writ_signer::helper`, `writ_signer::helper::agreement`; tests in `crates/writ-signer/tests/helper.rs`, `crates/writ-signer/tests/agreement.rs` (`every_way_a_helper_fails_to_sign_is_refused_and_the_next_job_served`, `a_framed_blob_the_helper_refuses_or_reads_as_another_key_is_unusable`, `a_helper_that_dies_on_a_blob_at_start_costs_that_key_alone`, `stored_bytes_not_framed_for_the_key_never_reach_the_helper`, `a_key_the_helper_makes_must_prove_its_point`) |
| A `piv-p256` stanza in a keystore file (M7.6: a secret wrapped to a hardware key-agreement key) | whoever can write the keys directory (the daemon's user, a restored volume: the recipients are public, so anyone can make one, Q38) | read before any device sees its point: exactly two arguments, a tag of 4 bytes of unpadded base64, an ephemeral key of 33 bytes, compressed (`0x02`/`0x03`) and on P-256 (never the identity), a body of exactly 32 bytes; a stanza whose tag isn't the key's is never tried; the file key opens only under ChaCha20-Poly1305 with the HKDF key, a body that doesn't is refused; a shared secret other than 32 bytes refused; the recipient text bech32 (not bech32m) of 33 bytes under its own prefix | `writ_crypto::piv_p256` (`a_malformed_stanza_is_refused_by_name_before_any_ecdh`, `a_damaged_body_or_a_wrong_shared_secret_never_opens`, `a_recipient_text_that_is_not_one_is_refused`) |
| The daemon's recovery challenge (`writ recovery check`, M7.6; client-side) | the daemon, over the pinned channel | standard base64 decoded strictly; an age file opened only by the key typed, whose recipient must be the one the daemon names (checked first); at most 64 bytes read from it; its SHA-256 compared with the digest; every refusal names why, never the key | `writ_crypto::recovery` (`a_new_key_checks_against_its_own_challenge_and_no_other`) |
| A recipient's files (`recipients/<name>.pub`, `.blob`, M7.6; the recovery marker `identity.recovery.pub`, moved out of `recipients/` in M7.7) | the daemon's own (whoever could replace a `.pub` would choose what every later secret is wrapped to) | read as authority files (the daemon's user's, no link), bounded; a `.pub` a recipient line and a backend line only (one naming no backend refused: only the marker had none, and it moved); a blob read as a secret (0600) and framed for its point, checked before the helper sees it, the key's point proven by a probe agreement; the set held compared with the policy's at every unseal | `keystore::recipients`; `on_the_mac_a_hardware_recipient_takes_the_keystore_live_and_unwraps_the_token_per_use` |
| The approval API's replies that `writ` signs from (`AdminShown`, `MigrationShown`'s policy in force and rewrite, `TokenShown`, `TlsShown`, `CaShown`, `ScanNonce`, `Scanned`, `writ info`'s sealed boot, `Shown`) | the daemon, or whatever answers in its place (in local mode the pins are files of the user agents run as) | each reply 8 MiB, decoded strictly; over SSH the daemon it names must be the host key the connection checked (`Authenticated::check_daemon`), over HTTPS the certificate it names the pinned one; an admin text must hash to its digest and be the file asked for; a CA's fingerprint its key's; a scan's fingerprints computed from its keys, for the host asked; a ticket shown as the one followed the one named; all checked before anything is shown, asked or signed | `writ-cli` `client::Authenticated`, `approver::admin::in_force`, `approver::guided::checked_scan`, `approver::follows`; tests `a_reply_naming_another_daemon_than_the_one_authenticated_is_refused`, `a_file_in_force_is_checked_against_the_connection_the_target_and_its_digest`, `a_scan_is_shown_by_fingerprints_of_the_keys_pinned_for_the_host_asked`, `a_ticket_shown_as_the_one_followed_must_be_the_one_named`, `a_relay_that_shows_another_text_under_the_daemon_s_digest_gets_nothing_signed`, `a_relay_with_its_own_host_key_is_not_the_daemon_its_replies_name` |
| An SSH CA rotation (`writ admin ca rotate`: the `writ-ca/1` document, its SSHSIG; M7.6) | readers, with an approver's signature | the body bound (256 KiB); the daemon open; the document decoded strictly (canonical bytes), naming this daemon, the CA it replaces (its key's fingerprint, the one in force or refused: a replay rotates nothing) and a backend (one the daemon has); the signature by a key in `approvers`; the rotations' rate (5 a minute, shared with the TLS key's, counted once it names the CA in force: a replay takes none); one admin change at a time; the retired CAs' record the daemon's own (an authority file, bounded, at most 16, each a time and a public key) | `writ_approval` `service/ca.rs`, `writd` `keystore::ca`; tests `a_replayed_stale_foreign_or_unsigned_ca_rotation_is_refused_and_logged`, `a_ca_rotation_is_pinned_strict_and_names_the_ca_it_replaces`, `a_replayed_rotation_takes_no_place_in_the_rate_which_holds_on_both_sides` |
| The clone's remotes, read by `writ init` (`remote.origin.*`, `remote.writ.*`, from every git config file; client-side) | the agent (a clone's `.git/config` is its to write), the operator | refused before anything is written, naming the command that fixes each: several `origin` URLs, an `origin` push URL, a credential in the `origin` URL (any user in `http(s)://`, a password in another `scheme://`), in wrapper mode any `writ` remote, in whole-repo mode a `writ` remote with a push URL or set outside the repository's own config; a credential shown as `<redacted>` in everything `writ init` prints; a convenience, the daemon checks every push | `writ_cli::init::check_remotes`, `writ_cli::wiring::has_credential`; tests `everything_that_can_refuse_refuses_before_anything_is_written`, `a_credential_in_a_url_is_found_and_never_shown`, `a_push_rule_of_the_user_s_never_takes_origin_past_the_daemon` |

A new input is added here in the same change.

## Fail closed in practice

- **No fallback toward allow.** `unwrap_or(0)`, `unwrap_or_default()`, `map_or(true, …)` and
  friends are allowed only when the fallback denies (an empty list, `true` meaning
  "revoked"). A conversion that can't fail in practice still fails the request if it does
  (`map_err(internal)?`), never a default value.
- **A poisoned lock** either fails the request (state), or is recovered with
  `PoisonError::into_inner` when the work is a reduction of privilege (dropping sessions,
  forgetting a push). `if let Ok(lock)` that skips work needs a `// poisoned: <why>` comment
  showing that skipping is the safe side (checked).
- **Missing facts deny**: no process chain, no source address where a list is set, an
  unknown key type, an unreadable row.
- **Accept loops never end on one connection's error**: every listener (each transport,
  and the gateway's own hook socket) accepts through `writ_platform::transport::accept_retrying`,
  which retries transient errors (out of descriptors, a reset before the accept); only a
  broken listener stops it.
- **The deny list is checked at every decision point** (connection, each command, the
  pre-receive hook), not only at connection.

## Grants, reductions and the audit log

- **Grants and allows are logged first** (`Service::logged`): no line, no grant.
- **Reductions of privilege never wait for the log** (`Service::reduced`): revocation,
  withdrawal, expiry, exhaustion and an ended session are applied either way; the
  certificate goes on the deny list first, before anything that can fail, and a revocation
  decided while handling a request (a violation) bars it before the state lock is released,
  so no other request of the lease gets in between; the line is written first when
  possible, otherwise kept in memory (bounded) and written once the log can take it.
- **Denials before authentication are coalesced** per source and minute, with a global budget
  of 60 lines a minute, and a count: every denial is counted, and a flood from many sources
  can't fill the disk either.
- **Every text in a line is bounded**: each text field (reason, committer, code, refs,
  warnings, process chain) is cut to 2,048 characters with `…` when the line is written
  (`writ_store::MAX_FIELD_CHARS`), whoever built the event, and the policy shows an agent's
  value (a committer email, a path) cut to 256 characters in a denial or a warning, so no
  request makes a large line.
- **Submissions refused over a rate are coalesced** per burst, per source and for all
  sources together: the first refusal has its line, the others are counted, and the count
  is written when that rate next lets one through or when its minute ends (the sweep), so a
  source that goes quiet still has every refusal counted. The table of sources is bounded
  (4,096): when it is full, the window quiet the longest is dropped, its count written
  first.
- **A lease holder's denials are coalesced** past 60 lines a minute per lease
  ([Q34](decisions.md)): still denied, counted, and the count written as one line per kind
  when the minute is over. **So are its allowed connections** (`connect`, a certificate
  accepted), past 60 a minute on their own budget (M4): a lease holder looping `ssh` can't grow
  the log without bound, and each command it then runs still has its line (fetch, push and
  sign are bounded by the lease's rate). Grants, the other allowed lines and reductions of
  privilege are never held back.
- **A per-source limit counts sources by group** (`writ_core::net::source_group`): an IPv6
  host holds a whole /64 and would otherwise be 2^64 sources.
- **Every refusal is a line**, wherever it happens: a refused TLS handshake, a plain key for a
  user that takes a certificate, a source not allowed, as much as a lease decision.
- **The audit log is plain data**: no field can hold a secret, hidden characters are
  escaped, a failed write never glues lines together, the file is `0600`.
- **The daemon's own log stays bounded**: what any peer can trigger is logged at `debug`
  (the audit line is the record), and an audit-log outage is reported once, not per line;
  a lasting accept failure is reported once per accept, when its pause reaches a second.

## Revocation and enforcement state

- **Anything that enforces a lease and lives in memory is rebuilt from the store at
  startup**: the deny list, the session watches (a session that can't be watched revokes
  its lease).
- **A decision made earlier is checked again when it takes effect**: the pre-receive hook
  re-authorizes the lease; a revoked lease's pushes in progress are forgotten; a signature
  made outside the state lock leaves only if its lease is still the same, active, unexpired,
  its certificate not on the deny list, and the decision holds against the policy in force,
  all of it but the count and the rate its slot answered (`policy::recheck_sign`, in
  `Service::sign`'s last phase: a template's `paths_check` or a repo's `ticket_link`
  tightened meanwhile discards it); a push decided is in flight until upstream answered, and
  its lease isn't marked used up meanwhile (`InFlightPush`, the review after M7.6, A-3).
- **Nothing slow runs under the state lock, nor under any lock an admin change takes** (a
  device, the network, a subprocess), so a revocation never waits behind one; a value read
  under a lock for a slow call is copied out first (`match lock().get(..)` holds the guard
  for the whole arm); what the first phase reserved is never given back. Work under the
  lock is bounded by the input (the path match by the ticket's bounds). A lease's certificate
  is signed in three phases like a commit (the review after M7.6, A-2): decided under the
  lock, signed without it (the CA may be a device), decided again under the lock before the
  lease is recorded.
- **A lock that serializes leases is held by the work, never by a peer, and waited on with a
  deadline**: a push's mirror is released when `receive-pack` exits, not when the client has
  read its output, at once when the push is refused, and 10 s after the hook's yes at the
  latest; what a holder does under it is bounded in time (an upstream operation,
  `LOCAL_WORK_DEADLINE` for all its local work together: a sync's repack, the reading of a
  push; `writ admin repo check` takes it for each step apart; the sync status is kept
  beside it, under its own lock, so reading it never waits for a sync); a caller waits for
  it at most that long, then is refused (`the mirror is busy`).
- **An amendment keeps the lease's whole subject** (session key and bound process).

## Files that grant authority, and secrets

- **Authority files** (`writd.yaml`, the policy, `approvers`, `readers`, `mirrors.ca_certs`)
  are read with
  `read_authority`: no link followed, never blocking (a FIFO), a regular file of the
  daemon's user, writable by nobody else.
- **Secrets** (bot token, wrapped key, keystore keys, upstream tokens) are read with
  `read_secret`: the same,
  readable by nobody else, bounded, zeroized.
- **Created files** are private from creation (`0600`, `create_new`, directories `0700` with
  `DirBuilder::mode`), never through a link, never overwritten.

## Secrets

- A secret has its own type, zeroized on drop, with a redacting `Debug` (hard rule 3).
- A secret never enters an error, a log line, a reply, the audit log or a notification; a
  library error that might hold one is replaced by a short word. Tests scan for them
  (`looks_secret`, `errors_and_debug_never_contain_the_token`).
- Key material moves into the library that needs it; no other copy is kept, and the copies
  made on the way (a PKCS#8 encoding, rcgen's key pair) are wiped on every path. What a
  library frees is zeroed by the wiping allocator, `writ_alloc::Wiping`, the global allocator
  of `writd`, `writ` and `writ-sign` (on in every build, [M5.7](history/m5.7-memory-wiped-on-free.md));
  what a library keeps alive (ring's key, a copy while its call runs) is a residual risk in
  the threat model.
- A token travels in clear only to this machine (Telegram's `http` base: loopback only), and
  never through a proxy named in the environment (`proxy(None)`, tested in a child process
  with every proxy variable set). An upstream token goes only over TLS the daemon's git
  verified, to the registry's host, through the daemon's own proxy (no `http://`, no
  redirect), and reaches git only through its credential helper's pipes (never a command
  line, environment, URL or file).
- No `log` → `tracing` bridge: libraries such as ureq log URLs that hold tokens
  (`cargo deny` bans the bridges).

## What people see

- **Agent and daemon text is escaped** before any terminal: `display::clean`/`clean_lines`
  turn every hidden character into a visible `\u{…}`, and `writ-sign` does the same to what
  the daemon and ssh say (a denial lists the commit's paths, which can hold anything). The hidden set is generated from
  Unicode categories (`tool/gen-hidden-chars.py`), never written by hand.
- **The trusted display is bounded** in rows (40 per agent field unless `--full`, then how
  many more and the command that shows them; an enforced term, the expected paths included,
  never cut; the diff sections the same, the enforced changes last) and in width (every row 78 columns at most, a non-ASCII character
  counted as two; a longer line cut by the display, between words, each continuation
  behind the gutter, never left to the terminal to wrap), and **ends on the enforced terms**, one row each,
  right above the prompt. Lists are quoted so two different lists never read the same. A
  new line of the display that holds agent text goes through `display::cut` or `block`. Every
  field of a ticket is shown: the display destructures its types (no `..`), and a test changes
  each leaf of a ticket's JSON and checks the display changes. An admin change's diff names
  each hunk's section and entry, cuts its rows to the width, and refuses a change too large to
  compare rather than show it otherwise.
- **Every "Sign …?" takes the same answers** (`y` or `yes`, any case; anything else signs
  nothing) and an answered no exits 6 on every command.
- **The bytes to sign never touch the disk:** `ssh-keygen -Y sign` reads them on stdin and
  writes the signature on stdout, so a Ctrl-C at the Touch ID prompt leaves no ticket or
  policy text behind.
- **Enforced identities are ASCII** (committer emails), so look-alikes and invisibles can't
  pass for another.
- **No agent text leaves the network** in a notification, and nothing in a notification
  grants anything.
- **Unsigned words are labeled**: feedback from a refusal nobody signed reaches the agent and
  the revision marked as such.
- **A confirmation flag needs an explicit target** (`writ sign --yes <id>`, `writ prove-key
  <key id> --namespace <ns> --yes`).
- **A remote's message is shown whole and escaped** before a proof is signed (`writ
  prove-key`: newlines and hidden characters as `\u{…}`, its length in bytes), since what is
  signed is exactly those bytes.

## Library defaults are never the decision

What a library or a build feature happens to accept is not a policy. Each is stated in code,
with a test:

- YAML: `writ_core::yaml::options` (no anchors, aliases, merge keys, includes or variable
  interpolation; strict booleans; bounded).
- SSH: `preferred_algorithms` in the gateway (no compression, modern kex, AEAD, Ed25519 and
  P-256 keys).
- TLS: 1.3 only, ring, pinned server certificate, reader client certificates, no session
  resumption (`the_approval_api_never_resumes_a_session`).
- Key types: approvers (`APPROVER_KEY_TYPES`), readers (Ed25519), session keys (Ed25519,
  P-256); `sk-` approvals need user presence.
- Certificates: critical options refused.
- git: one builder for every git the daemon runs (`writ_mirror::git::command`): a clean
  environment, no system or global config, no transport but the one an upstream operation
  allows (`git_reaches_nothing_but_the_one_transport_allowed`), the gateway's own hooks or
  none, `fsckObjects` everywhere, packs kept whole, a size cap on pushes and on
  syncs (`the_daemon_user_s_config_and_environment_never_reach_git`).
- ssh to upstream: `-F /dev/null` and every option stated (`writ_mirror::upstream`), the
  operator's pinned host keys only; the paths in its options hold no whitespace, `%` or `$`
  (ssh splits and expands them there), refused at start with the reason.
- HTTPS to upstream: every setting git relies on stated (`writ_mirror::git::HTTPS_HARDENING`:
  certificate verified, no redirect, no header, cookie, prompt or other credential helper),
  the operator's CAs or the system's, never both (with `mirrors.ca_certs`, git also gets an
  empty CA directory: curl built with a default one, Debian's, keeps trusting it when only
  the file is named), an empty `HOME` (no `.netrc`), the daemon's proxy.
- Git objects an agent sends: ids computed here (SHA-1 with collision detection, never a plain
  SHA-1), only the commit layout git writes, trailers found as git finds them (checked
  against `git interpret-trailers`, `trailers_are_git_s`), and refused at least where git's
  own validators refuse them (`.git` tree entries as `verify_path` reads them), and read as
  git reads them or not at all (a tree entry's mode: git takes a directory from the type
  bits, so only the modes git writes are read, `only_the_modes_git_writes_are_read`).
- **A tool's own checks at the severity we need**: an external validator's warning is not a
  refusal. `git fsck` only warns on a `.git` tree entry (`hasDotgit`); a transfer's `fsck`
  (`receive.fsckObjects`, `fetch.fsckObjects`) runs strict and refuses it (git 2.54), but
  that is git's default, not Writ's decision: every git the daemon runs sets `hasDotgit`
  (and `hasDot`, `hasDotdot`, `emptyName`, `fullPathname`, `nullSha1`, `badFilemode`,
  `zeroPaddedFilemode`) to `error`, for
  pushes and syncs alike (`malformed_objects_never_land`,
  `malformed_or_dangerous_objects_from_upstream_never_land`). Each check Writ relies on is
  set to an error explicitly, with a test.

## Subprocesses

- **Paths handed to git are absolute**: git resolves a relative one from wherever it runs (a
  relative `core.hooksPath` is looked up inside the repository, finds no hook, and the push
  goes through unchecked). `writd.yaml`'s paths are made absolute when it is read, and the
  gateway and the mirrors refuse relative directories.
- **By absolute path**, or a `// PATH: <why>` comment saying why `PATH` is trusted there
  (the agent host's own tools) (checked). The daemon's git and ssh are configured absolute
  paths (`mirrors.git`, `mirrors.ssh`), checked at startup to be executable files; what git
  itself starts (`sh` for an ssh command or a credential helper) comes from the daemon's
  `PATH`, trusted with its host.
- **Bounded in time, as a group**: a subprocess that talks to the network (a sync, an
  upstream push) runs in its own process group, killed whole past its deadline or when its
  caller gives up (`writ_mirror::process`).
- **A clean environment** (`env_clear`, then only what is needed).
- **No argument can start with `-`** where a value is user-chosen (hosts, users, URLs).
- **The strictest flags**: `ssh-keygen -Y sign -U` (agent only), `git upload-pack --strict`.

## Cryptography

- Approvals and admin changes are SSHSIGs (namespace `writ-approval`) over canonical bytes by
  a key in `approvers` (hard rule 5); keys are compared whole, never by fingerprint.
- One key, one purpose: the approval key signs, the reader key opens the approval API, the
  session key identifies a lease, the CA key issues certificates. Never reuse one for
  another; the daemon refuses to start with a key listed both in `approvers` and `readers`.
- Randomness comes from the OS and fails rather than falls back.
- Certificate validity is the lease's; serials are random and unique; a time that doesn't
  fit fails the grant.

## Code

- **No panic on hostile input**: no `unwrap`/`expect`/`panic!`, no unchecked index, slice or
  truncating cast outside tests (clippy); `.get()`, `split_at_checked`, `strip_prefix`
  instead. An `#[allow]` says why it can't fail, on the line above (checked).
- **No unchecked arithmetic** in the crates that parse untrusted bytes and compute limits
  (`writ-core`, `writ-crypto`, `writ-proto`, `writ-git`, `writ-mirror`, `writ-gateway`):
  `checked_*` or `saturating_*`. Release builds keep overflow checks.
- **No `unsafe`** (`unsafe_code = "deny"`); safe wrappers (`rustix`) for system calls. The
  exceptions are dedicated modules, each `unsafe` block with its `SAFETY` comment:
  `writ-platform-macos`'s `sys` (what `rustix` doesn't wrap: `debug`, `kqueue`, `process` and
  `codesign`, the last the Security framework), `writ-platform-linux`'s `sys`
  (`getsockopt(SO_PEERPIDFD)` and `prctl(PR_SET_SECCOMP)`), and `writ-alloc`'s `wipe` (the
  wiping allocator) and, in tests only, `testing`.
- **Parse, don't validate**: untrusted strings become validated newtypes at the edge.
- **Compare security values exactly**: never `Path ==` (it normalizes), never a fingerprint
  where the whole key is at hand, case-insensitively where a file system folds case (refs;
  repo names, which name mirrors, are unique ignoring case).

## Dependencies

- A new crate needs a row in [stack.md](stack.md) ("Decided", with the reason), the fewest
  features it needs (`default-features = false` when possible), and `cargo deny` passing.
- Prefer a crate already in the tree; prefer ring/rustls for cryptography; never `openssl`,
  `native-tls`, `rsa` or a `log` bridge (`deny.toml`).
- An advisory is never ignored silently: `deny.toml` lists each accepted one with its reason,
  and the decision log has its row.
- `Cargo.lock` is committed and every build is `--locked`; the toolchain is pinned.
- No third-party GitHub Action: CI runs `make ci` with git and the runner's tools.
- How to upgrade anything, and what to do when an advisory appears:
  [dependency upgrades](guides/dependency-upgrades.md).

## Tests

The hardened-test rules are in [testing.md](testing.md#hardened-tests). For security:

- **Every denial asserts its exact code or variant** (`DenyCode`, `RefusalCode`,
  `LifecycleError`…), or an exit status's exact code. `// any error: <why>` marks the rare
  opaque failure (checked).
- **Every limit is tested on both sides**, at the limit and one past it.
- **Hostile input is tried** wherever input is untrusted: escapes, bidi, tag characters,
  look-alikes, path-like names, cut-short and oversized input, a link or a FIFO in place of
  a file.
- **Refusals are proven to be the check's doing**: the allowed case runs next to the denial.
- **No test depends on time passing**: signals, `FakeClock`, paused tokio time; a poll says
  what it waits for (`// poll:`, checked).

## Guarantees and their tests

The [threat model's guarantees](threat-model.md#what-writ-guarantees) table is the registry:
each guarantee names the tests that try to break it, checked by `tool/check-guarantees.py`. A
new guarantee, or a change to one, updates the table and its tests in the same change. A
guarantee that a later milestone brings says so (`planned: M<n>`) and is the only kind
allowed without a test.

## Known gaps

What this page doesn't cover yet, with the milestone that does: agents sharing a Writ home (M6's `WRIT_SESSION` keeps them on their own leases but
doesn't keep one out of another's session files; M7's session binding does, in local mode, for an agent run under `writ run`, and `require_session` makes it the rule), the daemon's name in a reply over HTTPS (the connection authenticates the TLS certificate, the daemon names itself by its SSH host key: no milestone yet; a binding of the certificate signed by the host key would close it, the review after M7.6, L-1), macOS-only code tested only by
`make ci` on the Mac, which the pre-push hook requires (CI is Linux). The [residual risks](threat-model.md#residual-risks-v1) list
the rest.
