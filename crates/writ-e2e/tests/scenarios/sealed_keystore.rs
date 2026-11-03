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

/// `yaml` with one more signing key declared, `declaration` (`<id>: { … }`), right under its
/// `signing_keys:` line (which may carry a comment). Refuses a `yaml` it doesn't change.
fn declare(yaml: &str, declaration: &str) -> String {
    let line = yaml
        .lines()
        .find(|l| l.starts_with("signing_keys:"))
        .expect("the end-to-end config declares its signing keys");
    let declared = yaml.replacen(
        &format!("{line}\n"),
        &format!("{line}\n  {declaration}\n"),
        1,
    );
    assert_ne!(declared, yaml, "{declaration} not declared");
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
        "mkdir -p sealed-init sealed-short && cp approvers readers sealed-init/ && \
             cp approvers readers sealed-short/",
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

    // A key declared after `writd init`, made by `writd keys create` with no passphrase:
    // sealed to the recipient, its public half printed, logged; made once.
    let declared = declare(
        &sealed_yaml(),
        "agent-e2e-rsa: { format: ssh, algorithm: rsa3072 }",
    );
    dir.ok("rm writd.yaml");
    dir.write("writd.yaml", &declared, "0644");
    let created = dir.ok("writd keys create writd.yaml agent-e2e-rsa");
    assert!(
        created.starts_with("agent-e2e-rsa ssh-rsa AAAA")
            && created.trim_end().ends_with("(templates: )"),
        "{created}"
    );
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
    let again = dir.run_with("writd keys create writd.yaml agent-e2e-rsa", b"");
    let (_, why) = expect(&again, 1, "a key made twice");
    assert!(why.contains("is in the keystore already"), "{why}");

    // A declaration its backend can't sign with, or one the format doesn't take: the
    // commands refuse it with the reason, never adjusting it.
    for (declaration, reason) in [
        (
            "agent-e2e-pgp: { format: openpgp, algorithm: p256, hash: sha512 }",
            "signing_keys.agent-e2e-pgp: openpgp signs p256 keys with sha256, not sha512",
        ),
        (
            "agent-e2e-pgp: { format: openpgp, algorithm: rsa2048 }",
            "RSA keys are 3072 or 4096 bits",
        ),
    ] {
        let refused = declared.replace(
            "agent-e2e-pgp: { format: openpgp, algorithm: ed25519 }",
            declaration,
        );
        assert_ne!(refused, declared);
        dir.ok("rm writd.yaml");
        dir.write("writd.yaml", &refused, "0644");
        let (_, why) = expect(
            &dir.run("writd signing-keys writd.yaml"),
            1,
            "a declaration refused",
        );
        assert!(why.contains(reason), "{why}");
    }
    dir.ok("rm writd.yaml");
    dir.write("writd.yaml", &declared, "0644");

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
}

/// The second daemon's policy: an `ssh://` repo, and an `https://` one whose token only an
/// approver adds (`writ admin token`); one template.
const SEALED_POLICY: &str = r#"repos:
  setup: { upstream: "ssh://git@forgejo/writ/setup.git", upstream_credential: upstream-sealed }
  https: { upstream: "https://forgejo-https:3443/writ/https.git", upstream_credential: token-sealed }
templates:
  feature:
    repos: [setup]
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
    home.ok("mkdir -p sealed-run && cp approvers readers upstream_known_hosts upstream_ca.pem sealed-run/");
    let dir = home.with(&format!("{}/sealed-run", home.dir), None);
    // Its own ports, beside the stack's daemon.
    let yaml = declare(
        &sealed_yaml(),
        "agent-sealed: { format: ssh, algorithm: ed25519 }",
    )
    .replace("0.0.0.0:2222", "0.0.0.0:3222")
    .replace("0.0.0.0:2223", "0.0.0.0:3223")
    .replace("0.0.0.0:8443", "0.0.0.0:9443");
    dir.write("writd.yaml", &yaml, "0644");
    dir.write("policy.yaml", SEALED_POLICY, "0644");
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
        why.contains("no https:// repo of the policy in force names it"),
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
        audit.contains("token token-sealed: sha256 ") && !audit.contains(token),
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
    assert!(said.contains("+ second ssh-ed25519 "), "{said}");
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
    dir.ok("kill $(cat writd.pid)");
}
