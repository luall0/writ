# Decisions

Every design decision, with its date and why. New decisions get a row at the end of the log
in the same change that implements them; questions to settle go under
[Open questions](#open-questions). Ideas for later are in the [backlog](backlog/README.md).

## Decision log

| Date | ID | Decision | Why |
|---|---|---|---|
| 2026-10-31 | Q1 | Design against **sloppy** and **prompt-injected** agents. Malware on an agent host is bounded by the lease; the daemon host is trusted in v1. | The agent is the realistic risk. |
| 2026-10-31 | Q2 | **Coexist with Secretive.** Secretive keeps my personal keys; Writ owns only agent keys. | Bounds the worst case of any approval to the agent keys. |
| 2026-10-31 | Q3 | **Dedicated agent signing key, commits under my name**, with a **distinct committer email** (e.g. `user+agent@…`). | Verified and attributable to me, while agent commits stay filterable and the key revocable on its own. The key and email must be registered/verified on each forge account where Verified status matters. |
| 2026-10-31 | Q6 | **Deny + notify** for any out-of-lease request. | Fail closed. |
| 2026-10-31 | — | **Forge-agnostic.** No reliance on GitHub rulesets or any forge-specific protection. | I use GitHub, Gitea, Forgejo and others. |
| 2026-10-31 | — | **The daemon is the agents' git remote (gateway) and the only thing that pushes upstream.** | Repo, destination ref and pushed content become strong checks, forge-agnostic. |
| 2026-10-31 | — | **Sign at commit time, verify at push time** via a ledger of commits signed per lease. | Commit hashes never change; only lease-signed commits reach upstream. |
| 2026-10-31 | Q15 | **Two deployment modes, one protocol:** detached (Linux, Docker, agents anywhere) and local (native on the Mac). | One place of trust for all agents, with a local fallback. |
| 2026-10-31 | — | **Signer-agnostic keys.** `Signer` interface; v1 software keys; later YubiKey PIV, TPM, Secure Enclave; generic ssh-agent backend possible where its socket is out of the agents' reach. | Start simple, move to hardware without redesign. |
| 2026-10-31 | Q12 | **Personal use** for now. | Not tied to client work. |
| 2026-10-31 | Q17 | **Sealed start.** Software keys live in an encrypted keystore; v1 unseal = keystore passphrase + approver signature via `writ unseal`. Hardware recipients (age plugins for SE / YubiKey) later, plus a recovery recipient. | Keys encrypted at rest; a stolen volume is useless. |
| 2026-10-31 | Q8 | **Active leases persist** across restarts (SQLite) and are reloaded after unsealing. | Container restarts are routine; sealing already gates them. |
| 2026-10-31 | Q20 | **Signer-agnostic approvals:** an approval is an SSHSIG (namespace `writ-approval`) from any key in the daemon's `approvers` file. v1: `writ sign` on the Mac signing with a **dedicated Secretive key** (Touch ID). Later: own Mac SE app, iPhone app; a YubiKey FIDO2 key as backup approver. | Start with what I already use; replacing Secretive later is just adding a key. |
| 2026-10-31 | Q18 | **Upstream credentials: SSH keys on my own forge accounts**, one per purpose/forge, each labeled with a `+alias` of my email. | Simple to set up everywhere. Trade-off: forges can't scope personal SSH keys per repo, so these keys have account-wide access and the daemon's repo registry is the only per-repo boundary. The `+alias` is a label for auth keys; it only matters to forges for signing keys (committer email). |
| 2026-10-31 | — | **Borrowed from secrets-dispatcher:** process chain checks in local mode (executable path only, name/args advisory), JSON audit log with the process chain, and a reversible `writ try`. | Proven ideas, cheap to adopt. |
| 2026-10-31 | Q22 | **Push mode configured per repo** in the registry: `gateway` (default, full checks), `proxy` (daemon relays the SSH stream, checks repo and refs, no mirror), `direct_ssh` (lent agent socket, host checks only). `direct_ssh` requires a repo-scoped deploy key unless `allow_account_wide: true`, and is flagged in the approval prompt. | Lets each repo pick its trade-off. Over direct SSH the repo path is hidden from the agent socket, so only the forge can scope it. |
| 2026-10-31 | Q23 | **`proxy` mode checks the ledger too.** The daemon buffers the incoming pack, indexes it in a temporary quarantine (`git index-pack`), walks the new commits, and checks each one against the ledger before relaying anything upstream. | Gives `proxy` the same commit guarantee as `gateway`, without keeping a mirror. Costs some latency and temporary disk on large pushes; `max_push_size` bounds it. |
| 2026-10-31 | Q9 | **Rust core** for the daemon and CLI (Linux container + native Mac). Swift only for the later Secure Enclave signer/approver app. | One codebase for both modes; mature SSH crates. |
| 2026-10-31 | Q16 | **SSH + daemon-issued certificates** for everything between agents and the daemon: git, signing, lease commands. | One channel; git speaks SSH natively; certificate expiry = lease expiry. |
| 2026-10-31 | Q21 | Detached daemon reachable from **LAN + VPN only**. | Nothing exposed to the internet; agents still work away from home. |
| 2026-10-31 | Q4 | **Upstream over SSH and HTTPS tokens**, chosen per repo by the `upstream` URL. Tokens live in the sealed keystore. | Covers setups where only HTTPS works. Bonus: GitHub fine-grained tokens can be limited to selected repos. |
| 2026-10-31 | Q10 | **Ticket workflow via CLI + agent skill.** I start an agent for a specific feature or fix; the skill makes it think through the scope first and submit a **ticket** (task, plan, repos, branches, limits) with `writ request`. I sign it (it becomes the lease) or refuse it with feedback, and the agent revises. Amendments for scope changes; `writ close` with a summary at the end. Omega Code plugin is a future improvement. | Agents work end to end on an agreed scope, without prompting me for each commit. The ticket text is agent-written: shown to me, never trusted by the policy engine. |
| 2026-10-31 | Q14 | **Every ticket must fit a template.** Templates (admin-approved) set the maximum scope; tickets outside every template are rejected before reaching me. | The agent writes its own ticket; a hard cap that doesn't depend on my attention at approval time is the right defense. |
| 2026-10-31 | Q11 | **No tag signing in v1.** | Releases stay a human act; `refs/tags/*` protected in the registry. |
| 2026-10-31 | Q19 | Mirrors synced **on demand + periodically**; no webhooks. | Works on every forge and fits LAN + VPN only. |
| 2026-10-31 | Q24 | **Path check configurable per template:** `paths_check: off \| warn \| deny` (default `warn`). A ticket without `expected_paths` skips the check unless the template requires them. | Useful guardrail, but some tasks don't map well to paths; each template decides. |
| 2026-10-31 | Q25 | **Ticket link configurable per repo:** `ticket_link: trailer \| notes \| ledger_only`. `trailer` = `Writ:` line required and checked; `notes` = git note, message untouched; `ledger_only` = nothing on the forge. The daemon never strips a trailer: that would change the commit hash and break the signature. | Some repos' commit conventions don't allow extra trailers. The ledger keeps commit → ticket traceability in every mode. |
| 2026-10-31 | Q26 | **Narrowing at signing time**, already in v1 through `writ sign` (interactive or flags like `--ttl 2h`, `--drop-repo`). Secretive signs the narrowed ticket; the daemon checks it is a strict subset of what the agent submitted and returns the final lease to the agent. | Saves a refusal round-trip; can never widen. Needs no dedicated app: the CLI is already the trusted display. |
| 2026-10-31 | — | **Name: Writ.** CLI `writ`, daemon `writd`, shim `writ-sign`, commit trailer `Writ: wrt_…`, approval namespace `writ-approval`. Agent requests are still called tickets; a signed ticket is a writ. | A writ is a written order under seal authorizing action within stated limits: exactly a signed ticket. "Leash" was dropped because StrongDM already ships an AI-agent policy tool named Leash. |
| 2026-10-31 | Q7/Q13 | Approvals are always cryptographic signatures; a notification click alone is never an approval. Notifications via ntfy first. | Keeps approvals strong whatever the channel. |
| 2026-10-31 | Q30 | **Platform-agnostic core, modes as configuration.** Everything OS-, hardware- or deployment-specific sits behind an interface (`Signer`, `Transport`, `CallerAttestor`, `SessionWatcher`, `KeystoreUnlock`, `Notifier`) with implementations picked at startup; the policy sees only `CallerFacts`, and missing facts deny. macOS-only code lives in `writ-platform-macos`. Local mode moves to M7, before detached (M8). | Mac features (process chain, Secure Enclave, launchd) plug in without touching the policy, the gateway or the clients, and a Linux local mode can come the same way. The daemon already runs natively on the Mac during development. |

## Open questions

To settle before (or while) building the milestone named in each row.

| ID | Question | Needed by |
|---|---|---|
| Q27 | Does v1 local mode need the **Secure Enclave signer backend**, or does it first ship with the software signer (SE as a follow-up)? The SE backend needs a code-signed native component. | [M7](roadmap.md#m7--local-mode-on-the-mac) |
| Q28 | Confirm the **proposed crates** in [Stack](stack.md) (async runtime, SQLite access, keystore, CLI parsing), each checked against what it must support (e.g. `ssh-key` verifying Secretive's ECDSA P-256 SSHSIGs, `russh` certificate auth). | [M0](roadmap.md#m0--protocol-spike-gono-go) |
| Q29 | **Transport of the approval API** (port 8443): how `writ sign` / `writ unseal` authenticate the daemon (pinned TLS certificate, or the gateway's SSH host key reused) and which channel carries the passphrase. | [M2](roadmap.md#m2--ticket-flow-request-sign-refuse-revoke) |

