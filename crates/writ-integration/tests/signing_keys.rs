//! Declared keys (the policy's `keys`, M6.2; M5.5 for the combinations), with the real
//! binaries: every combination the daemon can't sign with stops it at start with its reason,
//! a key held as something else than declared stops it too, the keys `writd.yaml` held before
//! M6.2 are refused naming the policy, and every algorithm and hash signs commits the real
//! `git` (`ssh-keygen`) verifies.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::fs;

use writ_crypto::algorithm::{Hash, KeyAlgorithm};
use writ_integration::daemon::{Approvals, Daemon};
use writ_integration::gateway::GitGateway;
use writ_integration::{stderr, stdout};

const POLICY: &str = r#"
keys:
  agent-01:
    use: signing
    format: ssh
    algorithm: ed25519
  upstream-01:
    use: upstream
    kind: ssh
    algorithm: ed25519
upstream_hosts:
  remote.invalid:
    - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
    templates: [feature]
templates:
  feature:
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    committer_emails: ["agent@writ"]
    signing_key: agent-01
    max_ttl: 2h
    max_signatures: 5
    max_pushes: 5
    max_ops_per_minute: 60
    max_push_size: 10MB
"#;

/// `POLICY`'s declaration of `agent-01`.
const AGENT_01: &str = "  agent-01:\n    use: signing\n    format: ssh\n    algorithm: ed25519\n";

/// `POLICY` with `agent-01` declared as `declaration` (a flow mapping's inside).
fn declaring(declaration: &str) -> String {
    assert!(POLICY.contains(AGENT_01));
    POLICY.replace(AGENT_01, &format!("  agent-01: {{ {declaration} }}\n"))
}

/// The last line `writd` printed: its error.
fn last(error: &str) -> &str {
    error.lines().last().unwrap_or_default()
}

#[test]
fn each_refused_key_declaration_stops_the_start_with_its_reason() {
    for (policy, expected) in [
        // Algorithm × hash: SSH's SSHSIG takes sha256 or sha512.
        (
            declaring("use: signing, format: ssh, algorithm: p384, hash: sha384"),
            "keys.agent-01: ssh signs p384 keys with sha256, sha512, not sha384",
        ),
        // RSA 2048: no name to declare it with, and the reason said.
        (
            declaring("use: signing, format: ssh, algorithm: rsa2048"),
            "\"rsa2048\" is not a key algorithm (RSA keys are 3072 or 4096 bits)",
        ),
        // A backend this build doesn't have.
        (
            declaring("use: signing, format: ssh, algorithm: p256, backend: se-cryptokit"),
            "keys.agent-01.backend: this daemon has no backend se-cryptokit (it has: software)",
        ),
        // OpenPGP P-256 takes SHA-256 only.
        (
            declaring(
                "use: signing, format: openpgp, algorithm: p256, hash: sha512, uids: \
                 [\"<agent@writ>\"]",
            ),
            "keys.agent-01: openpgp signs p256 keys with sha256, not sha512",
        ),
        // An OpenPGP key whose user ids don't cover a committer email of its templates.
        (
            declaring("use: signing, format: openpgp, algorithm: ed25519"),
            "templates.feature.committer_emails: agent@writ has no user id in \
             keys.agent-01.uids (the OpenPGP key would sign commits a remote shows as \
             unverified)",
        ),
        // A template naming a key nobody declared.
        (
            POLICY.replace(AGENT_01, ""),
            "templates.feature.signing_key: agent-01 is not declared in keys",
        ),
        // An upstream credential of the wrong kind for its URL, and one of no algorithm.
        (
            POLICY.replace(
                "    kind: ssh\n    algorithm: ed25519\n",
                "    kind: token\n    host: remote.invalid\n",
            ),
            "repos.demo.upstream_credential: keys.upstream-01 is a token (kind: token): an \
             ssh:// upstream needs kind: ssh",
        ),
        (
            POLICY.replace("    kind: ssh\n    algorithm: ed25519\n", "    kind: ssh\n"),
            "keys.upstream-01.algorithm: required for an ssh credential",
        ),
    ] {
        let error = Daemon::refused_policy(POLICY, &policy);
        assert!(
            last(&error).starts_with("writd: the policy in force: ")
                && last(&error).contains(expected),
            "{expected}: {error}"
        );
    }
}

#[test]
fn the_keys_writd_yaml_held_are_refused_naming_the_policy() {
    for (edit, expected) in [
        (
            "signing_keys:\n  agent-01: { format: ssh, algorithm: ed25519 }\n",
            "signing_keys: moved to the policy in M6.2: declare each key under the policy's \
             keys.<id>",
        ),
        (
            "mirrors: { known_hosts: upstream_known_hosts }\n",
            "mirrors.known_hosts: moved to the policy in M6.2: the upstream host keys are its \
             upstream_hosts",
        ),
    ] {
        let error = Daemon::refused(POLICY, |yaml| {
            format!("{}{edit}", yaml.replace("mirrors: { fresh_for: 0s }\n", ""))
        });
        assert!(last(&error).contains(expected), "{expected}: {error}");
    }
}

#[test]
fn a_key_held_otherwise_than_declared_is_refused_by_recover_and_stops_the_start() {
    let mut daemon = Daemon::start(POLICY, Approvals::Ssh);
    daemon.stop();
    // agent-01 and upstream-01 were made Ed25519 at the first start: a policy declaring them
    // otherwise is refused by `writd recover` (the development keystore needs no passphrase),
    // nothing put in force.
    let text = fs::read_to_string(daemon.root().join("policy.yaml")).unwrap();
    for (from, to, expected) in [
        (
            AGENT_01,
            "  agent-01: { use: signing, format: ssh, algorithm: p256 }\n",
            "writd: signing key agent-01: declared p256 but the keystore holds a ed25519 key (a \
             key never changes algorithm: declare it as it is, or give the new one another id)",
        ),
        (
            "    kind: ssh\n    algorithm: ed25519\n",
            "    kind: ssh\n    algorithm: rsa3072\n",
            "writd: upstream credential upstream-01: declared rsa3072 but the keystore holds a \
             ed25519 key (a key never changes algorithm: declare it as it is, or give the new \
             one another id)",
        ),
    ] {
        assert!(text.contains(from), "{text}");
        fs::write(
            daemon.root().join("other-policy.yaml"),
            text.replace(from, to),
        )
        .unwrap();
        let out = daemon.writd_with(
            &["recover", "writd.yaml", "policy", "other-policy.yaml"],
            "",
        );
        assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
        assert_eq!(last(&stderr(&out)), expected);
        assert_eq!(
            fs::read_to_string(daemon.root().join("policy.yaml")).unwrap(),
            text
        );
    }
    // The key file replaced in the keystore by another algorithm's: the start refuses it.
    let path = daemon.root().join("s/keys/signing/agent-01");
    let other = writ_crypto::keypair::KeyPair::generate(KeyAlgorithm::P256).unwrap();
    let encoded =
        writ_crypto::keyfile::encode_secret(&other, writ_crypto::keyfile::KeyMeta::SSH).unwrap();
    fs::write(&path, encoded.as_bytes()).unwrap();
    let out = daemon.writd_with(&["run", "writd.yaml"], "");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(
        last(&stderr(&out)),
        "writd: signing key agent-01: declared ed25519 but the keystore holds a p256 key (a key \
         never changes algorithm: declare it as it is, or give the new one another id)"
    );
}

#[test]
fn every_algorithm_and_hash_signs_commits_git_verifies() {
    for (algorithm, hash) in [
        (KeyAlgorithm::Ed25519, Hash::Sha256),
        (KeyAlgorithm::P256, Hash::Sha512),
        (KeyAlgorithm::P384, Hash::Sha256),
        (KeyAlgorithm::Rsa3072, Hash::Sha256),
        (KeyAlgorithm::Rsa4096, Hash::Sha512),
    ] {
        let gw = GitGateway::start_signing(algorithm, hash);
        gw.seed_repo();
        let work = gw.clone("work");
        gw.wire_signing(&work);
        let id = gw.commit_signed(&work, "feature", "x\n");
        let out = gw.git(&work, &["verify-commit", "HEAD"]);
        assert!(out.status.success(), "{algorithm} {hash}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("Good \"git\" signature for agent@writ"),
            "{algorithm} {hash}: {}",
            stderr(&out)
        );
        let ledger = gw.ledger(&gw.lease);
        assert_eq!(ledger.len(), 1, "{algorithm} {hash}");
        assert_eq!(ledger[0].commit.as_str(), id);
        // The SSHSIG's own hash is the one declared.
        let raw = gw.git_ok(&work, &["cat-file", "commit", "HEAD"]);
        let armored: String = raw
            .lines()
            .skip_while(|l| !l.starts_with("gpgsig "))
            .map(|l| l.trim_start_matches("gpgsig ").trim())
            .take_while(|l| !l.is_empty())
            .take_while(|l| !l.starts_with("-----END"))
            .chain(["-----END SSH SIGNATURE-----"])
            .collect::<Vec<_>>()
            .join("\n");
        let sig = writ_crypto::ssh_key::SshSig::from_pem(&armored).unwrap();
        assert_eq!(sig.hash_alg().as_str(), hash.name(), "{algorithm}");
    }
}

/// A policy whose template signs with the harness's OpenPGP key, certified for its committer.
const OPENPGP_POLICY: &str = r#"
keys:
  agent-pgp:
    use: signing
    format: openpgp
    algorithm: ed25519
    uids: ["Agent <agent@writ>"]
  upstream-01:
    use: upstream
    kind: ssh
    algorithm: ed25519
upstream_hosts:
  remote.invalid:
    - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
    templates: [feature]
templates:
  feature:
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    committer_emails: ["agent@writ"]
    signing_key: agent-pgp
    max_ttl: 2h
    max_signatures: 5
    max_pushes: 5
    max_ops_per_minute: 60
    max_push_size: 10MB
"#;

#[test]
fn an_openpgp_key_s_certificate_is_printed_and_imports_into_gpg_with_its_user_ids() {
    let daemon = Daemon::start(OPENPGP_POLICY, Approvals::Ssh);
    let printed = daemon.print("signing-keys");
    let (line, certificate) = printed.split_once('\n').unwrap();
    // `agent-pgp openpgp <fingerprint> (ed25519) (templates: feature)`.
    let fields: Vec<&str> = line.split(' ').collect();
    assert_eq!(fields[..2], ["agent-pgp", "openpgp"], "{line}");
    let fingerprint = fields[2];
    assert_eq!(fingerprint.len(), 40, "{line}");
    assert!(line.ends_with(" (ed25519) (templates: feature)"), "{line}");
    assert!(certificate.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    // Imported into a throwaway GNUPGHOME: the key, with its user id.
    let home = daemon.root().join("gnupg");
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    fs::write(daemon.root().join("cert.asc"), format!("{certificate}\n")).unwrap();
    let gpg = |args: &[&str]| {
        std::process::Command::new("gpg")
            .args(["--batch", "--no-tty", "--homedir"])
            .arg(&home)
            .args(args)
            .output()
            .unwrap()
    };
    let out = gpg(&["--import", daemon.root().join("cert.asc").to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    let listed = stdout(&gpg(&["--with-colons", "--list-keys", fingerprint]));
    assert!(listed.contains("Agent <agent@writ>"), "{listed}");
}
