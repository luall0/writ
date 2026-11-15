//! Scenario 16, sealed keystore: `writd init` in the daemon's container, as the operator runs
//! it beside a `writd.yaml` with `keystore.sealed`, the passphrase on stdin. The keys directory
//! at rest reveals no key (every secret its own age file, only public halves in clear); the
//! boot tier holds the host and TLS keys alone; the commands that print a key read the public
//! halves with no passphrase, and print what `writd init` printed; a second `writd init`, and
//! a short passphrase, are refused and leave nothing behind. Then a second daemon on its own
//! ports, started sealed: every request refused with "daemon sealed" until the approver runs
//! `writ unseal` (a wrong passphrase refused first, over HTTPS; the right one over SSH), and
//! hardened before it read anything (not dumpable, no core, its memory locked).

use std::time::Duration;

use writ_e2e::Stack;
use writ_e2e::agent::expect;
use writ_e2e::docker::eventually;
use writ_e2e::setup::{DAEMON, POLICY_YAML, WRITD_YAML};

/// The end-to-end `writd.yaml` with a sealed keystore in `keys/` and its boot tier in `boot/`.
fn sealed_yaml() -> String {
    let dev = WRITD_YAML
        .lines()
        .find(|l| l.starts_with("keystore:"))
        .expect("the end-to-end config names its keystore");
    WRITD_YAML.replace(dev, "keystore: { sealed: { dir: keys, boot: boot } }")
}

/// `policy` with one more key declared, `declaration` (`<id>: { … }`), at the top of its
/// `keys:` section. Refuses a `policy` it doesn't change.
fn declare(policy: &str, declaration: &str) -> String {
    let declared = policy.replacen("\nkeys:\n", &format!("\nkeys:\n  {declaration}\n"), 1);
    assert_ne!(declared, policy, "{declaration} not declared");
    declared
}

/// The value after `label` on the line of `out` that starts with it.
fn printed<'a>(out: &'a str, label: &str) -> &'a str {
    out.lines()
        .find_map(|l| l.strip_prefix(label))
        .unwrap_or_else(|| panic!("no {label:?} line in:\n{out}"))
}

#[test]
#[ignore = "end to end: make e2e"]
fn writd_init_makes_a_sealed_keystore_that_reveals_no_key_at_rest() {
    let stack = Stack::shared();
    let home = &stack.operator;
    // The approvers and readers first: `writd init` records the three files in force.
    home.ok(
        "mkdir -p sealed-init sealed-short sealed-tls sealed-ca && cp approvers readers sealed-init/ && \
             cp approvers readers sealed-short/ && cp approvers readers sealed-tls/ && \
             cp approvers readers sealed-ca/",
    );
    let dir = home.with(&format!("{}/sealed-init", home.dir), None);
    dir.write("writd.yaml", &sealed_yaml(), "0644");
    dir.write("policy.yaml", POLICY_YAML, "0644");

    let out = dir.run_with("writd init writd.yaml", b"an end-to-end passphrase\n");
    expect(&out, 0, "writd init");
    let made = writ_e2e::stdout(&out);
    assert!(made.starts_with("keystore made: /"), "{made}");
    let recipient = printed(&made, "recipient: ");
    assert!(recipient.starts_with("age1"), "{made}");
    let host = printed(&made, "host key: ");
    assert!(host.starts_with("ssh-ed25519 "), "{made}");

    // At rest: no private key in clear, every secret an age file to the recipient (the
    // identity to the passphrase), private; the public halves and the recipient readable.
    assert_eq!(dir.ok("grep -rl 'PRIVATE KEY' keys || true"), "");
    assert_eq!(
        dir.ok("head -c 22 keys/identity.age"),
        "age-encryption.org/v1\n"
    );
    assert_eq!(dir.ok("grep -c '^-> scrypt ' keys/identity.age"), "1\n");
    let secrets = dir.ok("find keys -name '*.age' ! -name identity.age | sort");
    assert!(secrets.lines().any(|l| l == "keys/ca.age"), "{secrets}");
    assert!(
        secrets.lines().any(|l| l.starts_with("keys/signing/")),
        "{secrets}"
    );
    assert!(
        secrets.lines().any(|l| l.starts_with("keys/upstream/")),
        "{secrets}"
    );
    for secret in secrets.lines() {
        assert_eq!(
            dir.ok(&format!("grep -c '^-> X25519 ' {secret}")),
            "1\n",
            "{secret}"
        );
        assert_eq!(dir.ok(&format!("stat -c %a {secret}")), "600\n", "{secret}");
    }
    assert_eq!(dir.ok("cat keys/recipient"), format!("{recipient}\n"));
    assert_eq!(dir.ok("stat -c %a keys boot"), "700\n700\n");
    // The boot tier: the keys a sealed daemon authenticates itself with, and only those.
    assert_eq!(dir.ok("ls boot"), "host\ntls-01\ntls-01.crt\n");
    // The TLS key is an OpenSSH P-256 key for the daemon's signer: no PEM key file anywhere.
    let tls_key = dir.ok("ssh-keygen -l -f boot/tls-01");
    assert!(
        tls_key.starts_with("256 SHA256:") && tls_key.trim_end().ends_with("(ECDSA)"),
        "{tls_key}"
    );
    assert_eq!(dir.ok("find keys boot -name '*.pem'"), "");
    assert_eq!(dir.ok("grep -c CERTIFICATE boot/tls-01.crt"), "2\n");
    assert_eq!(dir.ok("stat -c %a boot/host boot/tls-01"), "600\n600\n");
    // No token is ever made: the https repo's comes from the approver (M5).
    assert_eq!(dir.ok("find keys -path '*token*'"), "");

    // The commands that print a key need no passphrase (stdin closed) and print what
    // `writd init` printed.
    assert_eq!(dir.ok("writd host-key writd.yaml").trim(), host);
    assert_eq!(
        dir.ok("writd tls-fingerprint writd.yaml").trim(),
        printed(&made, "TLS fingerprint: ")
    );
    let signing = dir.ok("writd signing-keys writd.yaml");
    // An OpenPGP key's certificate follows its line.
    for line in signing.lines().filter(|l| l.contains(" (templates: ")) {
        let (id, rest) = line.split_once(' ').unwrap();
        assert_eq!(
            printed(&made, &format!("signing key {id}: ")),
            rest,
            "{made}"
        );
    }
    let upstream = dir.ok("writd upstream-keys writd.yaml");
    assert!(!upstream.is_empty());
    for line in upstream.lines() {
        let (id, rest) = line.split_once(' ').unwrap();
        assert_eq!(
            printed(&made, &format!("upstream key {id}: ")),
            rest,
            "{made}"
        );
    }

    // A key declared after `writd init`, in a policy `writd recover` puts in force on the
    // host (with the passphrase): made, sealed to the recipient, its public half printed,
    // logged; made once.
    let declared = declare(
        POLICY_YAML,
        "agent-e2e-rsa: { use: signing, format: ssh, algorithm: rsa3072 }",
    );
    dir.write("declared.yaml", &declared, "0644");
    let recovered = dir.run_with(
        "writd recover writd.yaml policy declared.yaml",
        b"an end-to-end passphrase\n",
    );
    let (created, _) = expect(&recovered, 0, "a policy recovered on the host");
    let rsa = printed(
        &created,
        "New signing key agent-e2e-rsa (register it on the remote): ",
    );
    assert!(rsa.starts_with("ssh-rsa AAAA"), "{created}");
    assert_eq!(
        dir.ok("head -c 22 keys/signing/agent-e2e-rsa.age"),
        "age-encryption.org/v1\n"
    );
    assert_eq!(dir.ok("grep -rl 'PRIVATE KEY' keys || true"), "");
    assert_eq!(
        dir.ok("ssh-keygen -l -f keys/signing/agent-e2e-rsa.pub")
            .split(' ')
            .next(),
        Some("3072")
    );
    assert_eq!(
        dir.ok("grep -c '\"event\":\"key\"' data/audit.jsonl"),
        "1\n"
    );
    let again = dir.run_with(
        "writd recover writd.yaml policy declared.yaml",
        b"an end-to-end passphrase\n",
    );
    let (again, _) = expect(&again, 0, "the same policy recovered again");
    assert!(!again.contains("New "), "made twice: {again}");
    assert_eq!(
        dir.ok("grep -c '\"event\":\"key\"' data/audit.jsonl"),
        "1\n"
    );

    // A declaration its backend can't sign with, or one the format doesn't take: refused with
    // the reason, never adjusted, nothing put in force.
    for (declaration, reason) in [
        (
            "    format: openpgp\n    algorithm: p256\n    hash: sha512\n",
            "keys.agent-e2e-pgp: openpgp signs p256 keys with sha256, not sha512",
        ),
        (
            "    format: openpgp\n    algorithm: rsa2048\n",
            "RSA keys are 3072 or 4096 bits",
        ),
    ] {
        let refused =
            declared.replace("    format: openpgp\n    algorithm: ed25519\n", declaration);
        assert_ne!(refused, declared);
        dir.ok("rm -f refused.yaml");
        dir.write("refused.yaml", &refused, "0644");
        let (_, why) = expect(
            &dir.run_with(
                "writd recover writd.yaml policy refused.yaml",
                b"an end-to-end passphrase\n",
            ),
            1,
            "a declaration refused",
        );
        assert!(why.contains(reason), "{why}");
    }

    // Made once: a second `writd init` is refused, the keystore untouched.
    let before = dir.ok("sha256sum keys/identity.age boot/host");
    let again = dir.run_with("writd init writd.yaml", b"another end-to-end passphrase\n");
    let (_, why) = expect(&again, 1, "a second writd init");
    assert!(
        why.trim_end()
            .ends_with("is not empty: a keystore is made once, into empty directories"),
        "{why}"
    );
    assert_eq!(dir.ok("sha256sum keys/identity.age boot/host"), before);

    // A passphrase under twelve characters: refused before anything is written.
    let short = home.with(&format!("{}/sealed-short", home.dir), None);
    short.write("writd.yaml", &sealed_yaml(), "0644");
    short.write("policy.yaml", POLICY_YAML, "0644");
    let out = short.run_with("writd init writd.yaml", b"too short\n");
    let (_, why) = expect(&out, 1, "a short passphrase");
    assert_eq!(
        why.trim_end(),
        "writd: the passphrase is 9 characters: at least 12 are needed"
    );
    assert_eq!(
        short.ok("ls"),
        "approvers\npolicy.yaml\nreaders\nwritd.yaml\n"
    );

    // The TLS key's backend at `writd init` (M7.5, the installer's way to the Secure Enclave on
    // a Mac): one this Linux daemon lacks refused before anything is asked; `software` given.
    let chosen = home.with(&format!("{}/sealed-tls", home.dir), None);
    chosen.write("writd.yaml", &sealed_yaml(), "0644");
    chosen.write("policy.yaml", POLICY_YAML, "0644");
    let out = chosen.run_with(
        "writd init writd.yaml --tls-backend se-cryptokit",
        b"an end-to-end passphrase\n",
    );
    let (_, why) = expect(&out, 1, "a TLS backend the daemon lacks");
    assert_eq!(
        why.trim_end(),
        "writd: --tls-backend se-cryptokit: this daemon has no such backend (it has: software)"
    );
    let out = chosen.run_with(
        "writd init writd.yaml --tls-backend software",
        b"an end-to-end passphrase\n",
    );
    let (said, _) = expect(&out, 0, "writd init --tls-backend software");
    assert!(said.contains("TLS fingerprint: SHA256:"), "{said}");

    // The SSH CA's backend at `writd init` (M7.6, for auto-unseal on a Mac): likewise.
    let ca = home.with(&format!("{}/sealed-ca", home.dir), None);
    ca.write("writd.yaml", &sealed_yaml(), "0644");
    ca.write("policy.yaml", POLICY_YAML, "0644");
    let out = ca.run_with(
        "writd init writd.yaml --ca-backend se-cryptokit",
        b"an end-to-end passphrase\n",
    );
    let (_, why) = expect(&out, 1, "a CA backend the daemon lacks");
    assert_eq!(
        why.trim_end(),
        "writd: --ca-backend se-cryptokit: this daemon has no such backend (it has: software)"
    );
    let out = ca.run_with(
        "writd init writd.yaml --tls-backend software --ca-backend software",
        b"an end-to-end passphrase\n",
    );
    let (said, _) = expect(&out, 0, "writd init --ca-backend software");
    assert!(said.contains("keystore made:"), "{said}");
    assert!(ca.ok("cat keys/ca.pub").starts_with("ssh-ed25519 "));
}

/// The second daemon's policy: an `ssh://` repo, and an `https://` one whose token only an
/// approver adds (`writ admin token`); one template.
const SEALED_POLICY: &str = r#"format: 2
keys:
  agent-sealed: { use: signing, format: ssh, algorithm: ed25519 }
  upstream-sealed: { use: upstream, kind: ssh, algorithm: ed25519 }
  token-sealed: { use: upstream, kind: token, host: forgejo-https }
upstream_hosts:
  forgejo: ["FORGEJO"]
repos:
  setup: { upstream: "ssh://git@forgejo/writ/setup.git", upstream_credential: upstream-sealed, templates: [feature] }
  https: { upstream: "https://forgejo-https:3443/writ/https.git", upstream_credential: token-sealed, templates: [] }
templates:
  feature:
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    committer_emails: ["agent@writ.invalid"]
    signing_key: agent-sealed
    max_ttl: 1h
    max_signatures: 10
    max_pushes: 10
    max_ops_per_minute: 10
    max_push_size: 1MB
"#;

#[test]
#[ignore = "end to end: make e2e"]
fn a_sealed_daemon_serves_nothing_until_writ_unseal() {
    let stack = Stack::shared();
    let home = &stack.operator;
    home.ok("mkdir -p sealed-run && cp approvers readers upstream_ca.pem sealed-run/");
    let dir = home.with(&format!("{}/sealed-run", home.dir), None);
    // Its own ports, beside the stack's daemon.
    let yaml = sealed_yaml()
        .replace("0.0.0.0:2222", "0.0.0.0:3222")
        .replace("0.0.0.0:2223", "0.0.0.0:3223")
        .replace("0.0.0.0:8443", "0.0.0.0:9443");
    dir.write("writd.yaml", &yaml, "0644");
    // Forgejo's host key, as the setup pinned it (compared with the one it publishes).
    let policy = SEALED_POLICY.replace("FORGEJO", &stack.report.published_upstream);
    dir.write("policy.yaml", &policy, "0644");
    let passphrase = "the sealed run's passphrase";
    let (_, warned) = expect(
        &dir.run_with(
            "writd init writd.yaml",
            format!("{passphrase}\n").as_bytes(),
        ),
        0,
        "init",
    );
    // `writd init` hardens itself too: with the compose file's unlimited lock limit, nothing
    // to warn about.
    assert!(!warned.contains("not applied"), "{warned}");
    let host_key = dir.ok("writd host-key writd.yaml").trim().to_owned();
    let pin = dir.ok("writd tls-fingerprint writd.yaml").trim().to_owned();
    dir.ok("nohup writd run writd.yaml > writd.log 2>&1 & echo $! > writd.pid");
    eventually("the sealed daemon started", Duration::from_secs(30), || {
        dir.run("grep -q 'sealed=true' writd.log").status.success()
    });

    // Hardened before it read anything (docs/operators/hardening.md): not dumpable (its /proc
    // entries owned by root while it runs as `writ`, its memory unreadable to `writ`), no core
    // dump, its memory locked (the compose file's unlimited `memlock`); each step in its log.
    let pid = dir.ok("cat writd.pid").trim().to_owned();
    assert_eq!(dir.ok("id -un"), "writ\n");
    assert_eq!(dir.ok(&format!("stat -c %U /proc/{pid}/status")), "root\n");
    let mem = dir.run(&format!("head -c1 /proc/{pid}/mem"));
    let (_, why) = expect(&mem, 1, "reading the daemon's memory");
    assert!(why.contains("Permission denied"), "{why}");
    let core = dir.ok(&format!("grep 'Max core file size' /proc/{pid}/limits"));
    let limits: Vec<&str> = core.split_whitespace().collect();
    assert_eq!(limits.get(4..6), Some(&["0", "0"][..]), "{core}");
    let locked = dir.ok(&format!("grep VmLck /proc/{pid}/status"));
    let kb: u64 = locked
        .split_whitespace()
        .nth(1)
        .and_then(|n| n.parse().ok())
        .unwrap_or_default();
    assert!(kb > 0, "{locked}");
    let log = dir.read("writd.log");
    for step in ["no core dumps", "no debugger", "memory locked"] {
        assert!(
            log.contains(&format!("process hardening applied step={step}")),
            "{step}: {log}"
        );
    }
    assert!(!log.contains("not applied"), "{log}");

    // The approver pins it, and uses every flag of `writ unseal`.
    let approver = &stack.approver;
    approver.ok("mkdir -m 700 -p .writ-sealed");
    approver.write(
        ".writ-sealed/known_hosts",
        &format!("[{DAEMON}]:3223 {host_key}\n"),
        "0644",
    );
    approver.write(
        ".writ-sealed/tls_pins",
        &format!("[{DAEMON}]:9443 {pin}\n"),
        "0644",
    );
    let writ =
        "writ --known-hosts $HOME/.writ-sealed/known_hosts --tls-pins $HOME/.writ-sealed/tls_pins";
    let ssh = format!("ssh://{DAEMON}:3223");
    let https = format!("https://{DAEMON}:9443");
    let signer = "--key $HOME/.writ/approver.pub --agent $HOME/agent.sock";

    let out = approver.run(&format!("{writ} ls --approval-url {ssh}"));
    let (_, why) = expect(&out, 1, "ls while sealed");
    assert!(
        why.contains("daemon sealed: an approver unseals it with `writ unseal`"),
        "{why}"
    );

    let out = approver.run_with(
        &format!("{writ} unseal --approval-url {https} {signer}"),
        b"not the passphrase\n",
    );
    let (said, why) = expect(&out, 1, "a wrong passphrase");
    assert!(said.contains("is sealed (start "), "{said}");
    assert!(why.contains("wrong passphrase"), "{why}");

    let out = approver.run_with(
        &format!("{writ} unseal --approval-url {ssh} {signer}"),
        format!("{passphrase}\n").as_bytes(),
    );
    let (said, _) = expect(&out, 0, "writ unseal");
    assert!(said.contains("Unsealed (signed by SHA256:"), "{said}");
    let out = approver.run(&format!("{writ} ls --approval-url {https}"));
    expect(&out, 0, "ls once unsealed");
    // Unsealed without the `https` repo's token: said in the log, the command to run named.
    assert!(
        dir.read("writd.log").contains("no token yet"),
        "{}",
        dir.read("writd.log")
    );

    // The token, added from the approver's machine (every flag of `writ admin token`): read
    // on stdin, encrypted there, sealed on the daemon's host, never in clear there.
    let token = stack.report.https_token.as_str();
    let out = approver.run_with(
        &format!("{writ} admin token token-sealed --yes --approval-url {https} {signer}"),
        format!("{token}\n").as_bytes(),
    );
    let (said, _) = expect(&out, 0, "writ admin token");
    assert!(said.contains("it replaces no token."), "{said}");
    assert!(
        said.contains("Token token-sealed in force (file sha256 "),
        "{said}"
    );
    assert_eq!(
        dir.ok("grep -c '^-> X25519 ' keys/tokens/token-sealed.age"),
        "1\n"
    );
    assert_eq!(dir.ok("stat -c %a keys/tokens/token-sealed.age"), "600\n");
    assert_eq!(
        dir.ok(&format!("grep -rlF -e '{token}' . || true")),
        "",
        "the token in clear on the daemon's host"
    );
    // An id the policy doesn't use: refused.
    let out = approver.run_with(
        &format!("{writ} admin token token-other --yes --approval-url {ssh} {signer}"),
        format!("{token}\n").as_bytes(),
    );
    let (_, why) = expect(&out, 1, "writ admin token for an unused id");
    assert!(
        why.contains("the policy in force declares no token token-other"),
        "{why}"
    );

    // In its audit log: the sealed start, the refusals, the unseal.
    let audit = dir.read("data/audit.jsonl");
    let lines: Vec<serde_json::Value> = audit
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let count = |event: &str, result: &str| {
        lines
            .iter()
            .filter(|l| l["event"] == event && l["result"] == result)
            .count()
    };
    assert_eq!(count("seal", "done"), 1, "{audit}");
    assert_eq!(count("unseal", "denied"), 1, "{audit}");
    assert_eq!(count("unseal", "allowed"), 1, "{audit}");
    assert!(count("command", "denied") >= 1, "{audit}");
    assert!(!audit.contains(passphrase));
    assert!(
        audit.contains("token token-sealed: version 1 (sha256 ") && !audit.contains(token),
        "{audit}"
    );

    // Admin changes: the approvers in force shown, a second approval key added (every flag
    // of `writ admin show` and `apply`), written back to the daemon's file at once.
    let out = approver.run(&format!(
        "{writ} admin show approvers --approval-url {https}"
    ));
    let (in_force, header) = expect(&out, 0, "writ admin show");
    assert!(
        header.starts_with("approvers: version 1 (sha256 "),
        "{header}"
    );
    assert_eq!(dir.read("approvers"), in_force);
    approver.ok("rm -f .writ-sealed/second* && \
         ssh-keygen -q -t ed25519 -N '' -C second -f .writ-sealed/second && \
         SSH_AUTH_SOCK=$HOME/agent.sock ssh-add -q .writ-sealed/second && rm .writ-sealed/second");
    let second = approver.read(".writ-sealed/second.pub");
    let both = format!("{in_force}second {}\n", second.trim());
    approver.write(".writ-sealed/approvers", &both, "0644");
    let out = approver.run(&format!(
        "{writ} admin apply approvers .writ-sealed/approvers --yes --approval-url {ssh} {signer}"
    ));
    let (said, _) = expect(&out, 0, "writ admin apply");
    // The key on the next row: a diff row fits the display (the review after M7.6, U-6).
    assert!(said.contains("+ second ssh-ed25519\n+│ AAAA"), "{said}");
    assert!(
        said.contains("Applied: approvers is version 2 (sha256 "),
        "{said}"
    );
    assert_eq!(dir.read("approvers"), both);

    // `writd recover`, the daemon stopped: the first approvers put back with the passphrase.
    dir.ok(
        "kill $(cat writd.pid) && while kill -0 $(cat writd.pid) 2>/dev/null; do sleep 0.1; done",
    );
    dir.write("recovered-approvers", &in_force, "0644");
    let out = dir.run_with(
        "writd recover writd.yaml approvers recovered-approvers",
        b"not the passphrase\n",
    );
    let (_, why) = expect(&out, 1, "recover with a wrong passphrase");
    assert!(why.contains("wrong passphrase"), "{why}");
    assert_eq!(dir.read("approvers"), both, "nothing changed");
    let out = dir.run_with(
        "writd recover writd.yaml approvers recovered-approvers",
        format!("{passphrase}\n").as_bytes(),
    );
    let (said, _) = expect(&out, 0, "writd recover");
    assert!(
        said.contains("approvers: version 3 in force (recovered on the host)"),
        "{said}"
    );
    assert_eq!(dir.read("approvers"), in_force);
    let audit = dir.read("data/audit.jsonl");
    assert!(audit.contains("recovered on the host"), "{audit}");
    dir.ok("nohup writd run writd.yaml > writd.log 2>&1 & echo $! > writd.pid");
    eventually(
        "the sealed daemon started again",
        Duration::from_secs(30),
        || {
            dir.run("test $(grep -c 'sealed=true' writd.log) -ge 1")
                .status
                .success()
        },
    );
    let out = approver.run_with(
        &format!("{writ} unseal --approval-url {ssh} {signer}"),
        format!("{passphrase}\n").as_bytes(),
    );
    expect(&out, 0, "unseal after recovery");

    // An older policy in force (M7.9.6), as a writd before format 2 leaves one: put in force
    // with `writd recover`, the daemon stopped. Started again and unsealed, it refuses every
    // request until `writ migrate` signs a format 2 policy.
    let current = dir.read("policy.yaml");
    let older = current.replacen("format: 2\n", "", 1).replacen(
        "templates: [feature] }",
        "templates: [feature], push_modes: [gateway] }",
        1,
    );
    assert!(older.len() > current.len(), "{older}");
    dir.ok(
        "kill $(cat writd.pid) && while kill -0 $(cat writd.pid) 2>/dev/null; do sleep 0.1; done",
    );
    dir.write("older-policy.yaml", &older, "0644");
    let out = dir.run_with(
        "writd recover writd.yaml policy older-policy.yaml",
        format!("{passphrase}\n").as_bytes(),
    );
    expect(&out, 0, "writd recover an older policy");
    // What the next start will do, asked before it (M7.9.6), the state left as it is.
    let before = dir.ok("sha256sum data/leases.db");
    let out = dir.run("writd check-upgrade writd.yaml");
    let (said, _) = expect(&out, 0, "writd check-upgrade");
    assert!(
        said.contains("The state: version 12, this writd's: nothing to migrate.")
            && said.contains("The policy in force: format 1; this writd reads format 2.")
            && said.contains("The daemon's rewrite is ready")
            && said.ends_with("Nothing blocks the upgrade.\n"),
        "{said}"
    );
    assert_eq!(
        dir.ok("sha256sum data/leases.db"),
        before,
        "the state changed"
    );
    dir.ok("nohup writd run writd.yaml > writd.log 2>&1 & echo $! > writd.pid");
    eventually(
        "the sealed daemon started on an older policy",
        Duration::from_secs(30),
        || {
            dir.run("test $(grep -c 'sealed=true' writd.log) -ge 1")
                .status
                .success()
        },
    );
    let out = approver.run_with(
        &format!("{writ} unseal --approval-url {ssh} {signer}"),
        format!("{passphrase}\n").as_bytes(),
    );
    let (said, _) = expect(&out, 0, "unseal with an older policy in force");
    assert!(
        said.contains(
            "The policy in force is format 1; this daemon reads format 2: every request is \
             refused until you sign its migration with writ migrate."
        ),
        "{said}"
    );
    let out = approver.run(&format!("{writ} ls --approval-url {ssh}"));
    let (_, why) = expect(&out, 1, "ls while a migration is owed");
    assert!(
        why.contains(
            "every request is refused until an approver signs its migration with `writ migrate`"
        ),
        "{why}"
    );
    // The daemon's rewrite shown, declined: nothing changes.
    let out = approver.run_with(
        &format!("{writ} migrate --approval-url {ssh} {signer}"),
        b"n\n",
    );
    let (said, _) = expect(&out, 6, "writ migrate declined");
    assert!(
        said.contains("rewritten to format 2 by the daemon") && said.contains("Not signed."),
        "{said}"
    );
    expect(
        &approver.run(&format!("{writ} ls --approval-url {ssh}")),
        1,
        "ls still refused",
    );
    // The operator's own text signed instead: the format 2 policy from before.
    approver.write("policy-format-2.yaml", &current, "0600");
    let out = approver.run(&format!(
        "{writ} migrate --file policy-format-2.yaml --yes --approval-url {ssh} {signer}"
    ));
    let (said, _) = expect(&out, 0, "writ migrate --file");
    assert!(
        said.contains("replaced by policy-format-2.yaml")
            && said.contains("Applied: policy is version "),
        "{said}"
    );
    approver.ok(&format!("{writ} ls --approval-url {ssh}"));
    let out = approver.run(&format!("{writ} migrate --approval-url {ssh} {signer}"));
    let (said, _) = expect(&out, 0, "writ migrate with nothing owed");
    assert!(said.contains("Nothing to migrate"), "{said}");
    let audit = dir.read("data/audit.jsonl");
    assert!(
        audit.contains("\"event\":\"migrate\",\"result\":\"allowed\""),
        "{audit}"
    );
    assert_eq!(dir.read("policy.yaml"), current, "the file written back");

    // The HTTPS approval API's TLS key rotated live, from the approver's machine (M7.5): over
    // HTTPS the approver's pin replaced, the old one refused from then on.
    approver.ok("cp $HOME/.writ-sealed/tls_pins $HOME/.writ-sealed/tls_pins.old");
    let out = approver.run(&format!(
        "{writ} admin tls rotate --yes --approval-url {https} {signer}"
    ));
    let (said, _) = expect(&out, 0, "writ admin tls rotate over HTTPS");
    assert!(
        said.contains("TLS key rotated: certificate SHA256:"),
        "{said}"
    );
    assert!(
        said.contains("(key on software), replacing SHA256:"),
        "{said}"
    );
    assert!(
        said.contains("Checked: the daemon answers with the new certificate."),
        "{said}"
    );
    let rotated = dir.ok("writd tls-fingerprint writd.yaml");
    assert!(
        approver
            .read(".writ-sealed/tls_pins")
            .contains(&format!("[{DAEMON}]:9443 {}", rotated.trim())),
        "the approver's pin replaced"
    );
    let out = approver.run(&format!(
        "writ --known-hosts $HOME/.writ-sealed/known_hosts --tls-pins \
         $HOME/.writ-sealed/tls_pins.old ls --approval-url {https}"
    ));
    let (_, why) = expect(&out, 1, "the old pin");
    assert!(
        why.contains("the daemon's certificate doesn't match the pinned fingerprint"),
        "{why}"
    );
    // A backend this Linux daemon lacks: refused before any signature.
    let out = approver.run(&format!(
        "{writ} admin tls rotate --backend se-cryptokit --yes --approval-url {ssh} {signer}"
    ));
    let (_, why) = expect(&out, 1, "a backend the daemon lacks");
    assert!(
        why.contains("the daemon has no backend se-cryptokit (it has: software)"),
        "{why}"
    );
    // Over SSH, with --backend: the line to pin printed; the approver re-pins from the host's
    // `writd tls-fingerprint`, as the guide says.
    let out = approver.run(&format!(
        "{writ} admin tls rotate --backend software --yes --approval-url {ssh} {signer}"
    ));
    let (said, _) = expect(&out, 0, "writ admin tls rotate over SSH");
    assert!(
        said.contains("Pin it wherever you reach the daemon over HTTPS"),
        "{said}"
    );
    let again = dir.ok("writd tls-fingerprint writd.yaml");
    assert_ne!(again.trim(), rotated.trim());
    approver.write(
        ".writ-sealed/tls_pins",
        &format!("[{DAEMON}]:9443 {}\n", again.trim()),
        "0644",
    );
    expect(
        &approver.run(&format!("{writ} ls --approval-url {https}")),
        0,
        "re-pinned",
    );
    let audit = dir.read("data/audit.jsonl");
    assert_eq!(
        audit.matches("TLS key rotated: certificate").count(),
        2,
        "{audit}"
    );
    dir.ok("kill $(cat writd.pid)");
}
