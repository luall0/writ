//! Scenario 16, sealed keystore: `writd init` in the daemon's container, as the operator runs
//! it beside a `writd.yaml` with `keystore.sealed`, the passphrase on stdin. The keys directory
//! at rest reveals no key (every secret its own age file, only public halves in clear); the
//! boot tier holds the host and TLS keys alone; the commands that print a key read the public
//! halves with no passphrase, and print what `writd init` printed; a second `writd init`, and
//! a short passphrase, are refused and leave nothing behind.

use writ_e2e::Stack;
use writ_e2e::agent::expect;
use writ_e2e::setup::{POLICY_YAML, WRITD_YAML};

/// The end-to-end `writd.yaml` with a sealed keystore in `keys/` and its boot tier in `boot/`.
fn sealed_yaml() -> String {
    let dev = WRITD_YAML
        .lines()
        .find(|l| l.starts_with("keystore:"))
        .expect("the end-to-end config names its keystore");
    WRITD_YAML.replace(dev, "keystore: { sealed: { dir: keys, boot: boot } }")
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
    home.ok("mkdir -p sealed-init sealed-short");
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
    assert_eq!(dir.ok("ls boot"), "host\ntls-cert.pem\ntls-key.pem\n");
    assert_eq!(
        dir.ok("stat -c %a boot/host boot/tls-key.pem"),
        "600\n600\n"
    );
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
    for line in signing.lines() {
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
    assert_eq!(short.ok("ls"), "policy.yaml\nwritd.yaml\n");
}
