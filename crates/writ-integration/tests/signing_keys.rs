//! Declared signing keys (`writd.yaml`'s `signing_keys`, M5.5), with the real binaries: every
//! combination the daemon can't sign with stops it at start with its reason, a key held as
//! something else than declared stops it too, `writd keys create` makes a declared key once
//! and logs it, and every algorithm and hash signs commits the real `git` (`ssh-keygen`)
//! verifies.

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
use writ_integration::daemon::{Approvals, Daemon, SIGNING_KEYS};
use writ_integration::gateway::GitGateway;
use writ_integration::{audit_events, stderr, stdout};

const POLICY: &str = r#"
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
templates:
  feature:
    repos: [demo]
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

/// The harness's declaration of `agent-01`.
const AGENT_01: &str = "agent-01: { format: ssh, algorithm: ed25519 }";

/// The last line `writd` printed: its error.
fn last(error: &str) -> &str {
    error.lines().last().unwrap_or_default()
}

#[test]
fn each_refused_signing_key_declaration_stops_the_start_with_its_reason() {
    assert!(SIGNING_KEYS.contains(AGENT_01), "{SIGNING_KEYS}");
    // Algorithm × hash: SSH's SSHSIG takes sha256 or sha512.
    let error = Daemon::refused(POLICY, |yaml| {
        yaml.replace(
            AGENT_01,
            "agent-01: { format: ssh, algorithm: p384, hash: sha384 }",
        )
    });
    assert_eq!(
        last(&error),
        "writd: signing_keys.agent-01: ssh signs p384 keys with sha256, sha512, not sha384"
    );
    // RSA 2048: no name to declare it with, and the reason said.
    let error = Daemon::refused(POLICY, |yaml| {
        yaml.replace(AGENT_01, "agent-01: { format: ssh, algorithm: rsa2048 }")
    });
    assert!(
        last(&error).contains("signing_keys.agent-01.algorithm")
            && last(&error).contains("RSA keys are 3072 or 4096 bits"),
        "{error}"
    );
    // A backend this build doesn't have.
    let error = Daemon::refused(POLICY, |yaml| {
        yaml.replace(
            AGENT_01,
            "agent-01: { format: ssh, algorithm: p256, backend: se-cryptokit }",
        )
    });
    assert!(
        last(&error).contains("signing_keys.agent-01.backend")
            && last(&error).contains("se-cryptokit"),
        "{error}"
    );
    // OpenPGP P-256 takes SHA-256 only.
    let error = Daemon::refused(POLICY, |yaml| {
        yaml.replace(
            AGENT_01,
            "agent-01: { format: openpgp, algorithm: p256, hash: sha512 }",
        )
    });
    assert_eq!(
        last(&error),
        "writd: signing_keys.agent-01: openpgp signs p256 keys with sha256, not sha512"
    );
    // An OpenPGP key whose user ids don't cover a committer email of its templates.
    let error = Daemon::refused(POLICY, |yaml| {
        yaml.replace(AGENT_01, "agent-01: { format: openpgp, algorithm: ed25519 }")
    });
    assert_eq!(
        last(&error),
        "writd: policy: templates.feature.committer_emails: agent@writ has no user id in \
         signing_keys.agent-01.uids (the OpenPGP key would sign commits a remote shows as \
         unverified)"
    );
    // A template naming a key nobody declared.
    let error = Daemon::refused(POLICY, |yaml| yaml.replace(&format!("  {AGENT_01}\n"), ""));
    assert_eq!(
        last(&error),
        "writd: policy: templates.feature.signing_key: agent-01 is not declared in \
         writd.yaml's signing_keys"
    );
}

#[test]
fn a_key_held_otherwise_than_declared_stops_the_start_and_keys_create_makes_a_declared_one() {
    let mut daemon = Daemon::start(POLICY, Approvals::Ssh);
    daemon.stop();
    let yaml_path = daemon.root().join("writd.yaml");
    let yaml = fs::read_to_string(&yaml_path).unwrap();
    // agent-01 was made Ed25519 on first start: declared P-256 now, it is refused.
    fs::write(
        &yaml_path,
        yaml.replace(AGENT_01, "agent-01: { format: ssh, algorithm: p256 }"),
    )
    .unwrap();
    let out = daemon.writd_with(&["run", "writd.yaml"], "");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(
        last(&stderr(&out)),
        "writd: signing key agent-01: declared p256 but the keystore holds a ed25519 key (a \
         key never changes algorithm: declare it as it is, or give the new one another id)"
    );

    // A new declared key: made once by `writd keys create`, logged, printed to register.
    let declared = yaml.replace(
        "signing_keys:\n",
        "signing_keys:\n  agent-rsa: { format: ssh, algorithm: rsa3072, hash: sha256 }\n",
    );
    fs::write(&yaml_path, &declared).unwrap();
    let out = daemon.writd_with(&["keys", "create", "writd.yaml", "agent-rsa"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    let printed = stdout(&out);
    assert!(
        printed.starts_with("agent-rsa ssh-rsa AAAA")
            && printed.trim_end().ends_with("(templates: )"),
        "{printed}"
    );
    let lines = audit_events(&daemon.audit(), "key", "allowed");
    assert_eq!(lines.len(), 1, "{}", daemon.audit());
    assert_eq!(lines[0]["key"], "agent-rsa");
    assert_eq!(
        lines[0]["reason"],
        "ssh rsa3072 key made by writd keys create"
    );
    let again = daemon.writd_with(&["keys", "create", "writd.yaml", "agent-rsa"], "");
    assert_eq!(again.status.code(), Some(1));
    assert!(
        stderr(&again).contains("signing key agent-rsa is in the keystore already"),
        "{}",
        stderr(&again)
    );
    assert_eq!(audit_events(&daemon.audit(), "key", "allowed").len(), 1);
    // An undeclared id: nothing made.
    let undeclared = daemon.writd_with(&["keys", "create", "writd.yaml", "agent-99"], "");
    assert_eq!(undeclared.status.code(), Some(1));
    assert_eq!(
        last(&stderr(&undeclared)),
        "writd: signing key agent-99 is not declared in writd.yaml's signing_keys"
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
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
templates:
  feature:
    repos: [demo]
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    committer_emails: ["agent@writ"]
    signing_key: agent-pgp
    max_ttl: 2h
    max_signatures: 5
    max_pushes: 5
    max_ops_per_minute: 60
    max_push_size: 10MB
signing_keys:
  agent-pgp:
    uids: ["Agent <agent@writ>"]
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
