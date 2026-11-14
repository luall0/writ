//! The SSH CA behind the `Signer` (M7.6) with the real `writd`, `writ`, `git` and `ssh`: `writd
//! init --ca-backend` refuses a backend the daemon lacks; on the Mac, against the fake
//! `writ-se` (no test blob ever reaches the real Secure Enclave), the CA made on the device as
//! a P-256 key, its blob in the keystore and no private key, signing each lease's certificate,
//! which the gateway takes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice
)]

use std::fs;
use std::process::{Command, Output};

use writ_integration::binaries::bin;
use writ_integration::daemon::{Approvals, Daemon, PASSPHRASE, ssh_options};
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
    max_signatures: 40
    max_pushes: 20
    max_ops_per_minute: 100
    max_push_size: 10MB
"#;

const TICKET: &str = "repos:\n  demo:\n    operations: [fetch]\n    branches: [\"agent/x\"]\n\
                      ticket:\n  title: \"CA\"\n  task: CA\nlimits:\n  ttl: 30m\n";

fn ls_remote(daemon: &Daemon, lease: &str) -> Output {
    let ssh = format!(
        "ssh {}",
        ssh_options(&daemon.root().join("known_hosts"), &daemon.session(lease)).join(" ")
    );
    Command::new("git")
        .args([
            "ls-remote",
            &format!("ssh://git@127.0.0.1:{}/demo.git", daemon.agents_port),
        ])
        .env("GIT_SSH_COMMAND", ssh)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("HOME", daemon.root().join("home"))
        .output()
        .unwrap()
}

#[test]
fn writd_init_refuses_a_ca_backend_it_lacks() {
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    let have = if std::env::consts::OS == "macos" {
        "software, se-cryptokit"
    } else {
        "software"
    };
    let out = Command::new(bin("writd"))
        .arg("init")
        .arg(daemon.root().join("writd.yaml"))
        .args(["--ca-backend", "yubikey"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(
        stderr(&out).lines().last(),
        Some(
            format!(
                "writd: --ca-backend yubikey: this daemon has no such backend (it has: {have})"
            )
            .as_str()
        ),
        "{}",
        stderr(&out)
    );
}

#[test]
fn on_the_mac_the_ca_writd_init_owes_is_made_on_the_device_and_signs_each_certificate() {
    if !writ_integration::on_the_mac("this test") {
        return;
    }
    let helper = bin("writ-fake-se");
    let daemon = Daemon::start_sealed_init(
        POLICY,
        Approvals::Ssh,
        &["--ca-backend", "se-cryptokit"],
        |yaml| {
            format!(
                "{yaml}signers:\n  se_cryptokit:\n    helper: {}\n",
                helper.display()
            )
        },
    );
    let keys = daemon.root().join("s/keys");
    let public = fs::read_to_string(keys.join("ca.pub")).unwrap();
    assert!(public.starts_with("ecdsa-sha2-nistp256 "), "{public}");
    let out = daemon.unseal();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    // A lease's certificate, signed by the device's CA: the gateway, which trusts only its own
    // CA, takes it.
    let request = daemon.request("ca", TICKET);
    let out = daemon.run(&["sign", &request.id, "--yes"], "");
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}\n{}",
        stderr(&out),
        daemon.log()
    );
    let (status, _, err) = request.finish();
    assert_eq!(status.code(), Some(0), "{err}");
    let lease = daemon.lease("ca", TICKET);
    let out = ls_remote(&daemon, &lease);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
}

/// The policy of [`on_the_mac_device_keys_made_elsewhere_are_named_and_each_rotation_mends_one`]:
/// its signing key on the device too.
const POLICY_SE: &str = r#"
keys:
  agent-01:
    use: signing
    format: ssh
    algorithm: p256
    backend: se-cryptokit
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
    max_signatures: 40
    max_pushes: 20
    max_ops_per_minute: 100
    max_push_size: 10MB
"#;

/// Found on the first real install (2026-11-14): device keys made where the daemon doesn't
/// run (`writd init` through `sudo -u _writd`) opened under the LaunchDaemon but never signed,
/// and the first approval failed as an internal error. The fake helper binds each key to the
/// context it was made in (read from a file by its wrapper): the keys are made in one, the
/// daemon restarted in another. The TLS key is named at start (the daemon running), the CA and
/// the signing key at unseal, each with the command that replaces it; an approval is refused
/// naming `writ admin ca rotate`, and each rotation, made by the running daemon, mends its key.
#[test]
fn on_the_mac_device_keys_made_elsewhere_are_named_and_each_rotation_mends_one() {
    if !writ_integration::on_the_mac("this test") {
        return;
    }
    let outside = tempfile::tempdir().unwrap();
    let context = outside.path().join("context");
    fs::write(&context, "first").unwrap();
    let wrapper = outside.path().join("writ-se");
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nexec {} --context \"$(cat {})\" \"$@\"\n",
            bin("writ-fake-se").display(),
            context.display()
        ),
    )
    .unwrap();
    fs::set_permissions(
        &wrapper,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let mut daemon = Daemon::start_sealed_init(
        POLICY_SE,
        Approvals::Ssh,
        &[
            "--ca-backend",
            "se-cryptokit",
            "--tls-backend",
            "se-cryptokit",
        ],
        |yaml| {
            format!(
                "{yaml}signers:\n  se_cryptokit:\n    helper: {}\n",
                wrapper.display()
            )
        },
    );
    // Where they were made, every key signs: a lease is granted.
    let out = daemon.unseal();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let request = daemon.request("before", TICKET);
    let out = daemon.run(&["sign", &request.id, "--yes"], "");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(request.finish().0.code(), Some(0));

    // Elsewhere: the device refuses every one of them.
    fs::write(&context, "second").unwrap();
    daemon.restart();
    let tls = "the TLS key is unusable: on backend se-cryptokit, refused at start (it does not \
               sign: the helper refused: sign-failed): writ admin tls rotate --backend \
               se-cryptokit replaces it, every HTTPS handshake refused until then";
    assert!(daemon.log().contains(tls), "{}", daemon.log());
    let out = daemon.unseal();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let notes = [
        tls,
        "the CA key is unusable: refused at unseal (it does not sign: the helper refused: \
         sign-failed); writ admin ca rotate --backend se-cryptokit replaces it, every grant \
         refused until then",
        "key agent-01 is unusable: refused at unseal (it does not sign: the helper refused: \
         sign-failed); writ admin key rotate agent-01 replaces it",
    ];
    let audit = daemon.audit();
    for said in notes {
        assert_eq!(audit.matches(said).count(), 1, "{said}\n{audit}");
    }
    // An approval is refused by name, never as an internal error; the ticket stays pending.
    let request = daemon.request("after", TICKET);
    let out = daemon.run(&["sign", &request.id, "--yes"], "");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains(
            "the daemon's CA key is unusable: refused at unseal (it does not sign: the helper \
             refused: sign-failed): writ admin ca rotate --backend se-cryptokit replaces it"
        ),
        "{}",
        stderr(&out)
    );
    assert!(!stderr(&out).contains("internal error"), "{}", stderr(&out));

    // Each rotation, made by the running daemon, gives a key that signs here.
    for rotate in [
        &[
            "admin",
            "ca",
            "rotate",
            "--backend",
            "se-cryptokit",
            "--yes",
        ][..],
        &[
            "admin",
            "tls",
            "rotate",
            "--backend",
            "se-cryptokit",
            "--yes",
        ],
        &[
            "admin",
            "key",
            "rotate",
            "agent-01",
            "--backend",
            "se-cryptokit",
            "--yes",
        ],
        // The rotated key stays declared until it is removed (nothing uses it now).
        &["admin", "key", "remove", "agent-01", "--yes"],
    ] {
        let out = daemon.run(rotate, "");
        assert_eq!(out.status.code(), Some(0), "{rotate:?}: {}", stderr(&out));
    }
    let out = daemon.run(&["sign", &request.id, "--yes"], "");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(request.finish().0.code(), Some(0));
    // A restart here: nothing is said unusable again.
    daemon.restart();
    let out = daemon.unseal();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let audit = daemon.audit();
    for said in notes {
        assert_eq!(audit.matches(said).count(), 1, "{said}\n{audit}");
    }
}

/// Found on the first real install (2026-11-14): the keys `writd init` made on the device,
/// run by hand, never signed for the daemon. The fake helper's wrapper binds each key to the
/// command that made it (`writd init` or `writd run`, read from its parent): `writd init`
/// owes the TLS key, the CA and the signing key (said, and refused by the commands that print
/// them; `writd host-key` still works), the first start makes each, in the audit log, and
/// they sign: a lease granted over HTTPS (the TLS key), its certificate (the CA).
#[test]
fn on_the_mac_writd_init_leaves_each_device_key_to_the_daemon_s_first_start() {
    if !writ_integration::on_the_mac("this test") {
        return;
    }
    let outside = tempfile::tempdir().unwrap();
    let wrapper = outside.path().join("writ-se");
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\ncase \"$(/bin/ps -o args= -p $PPID)\" in\n  *\" init \"*) c=init ;;\n  \
             *) c=run ;;\nesac\nexec {} --context \"$c\" \"$@\"\n",
            bin("writ-fake-se").display()
        ),
    )
    .unwrap();
    fs::set_permissions(
        &wrapper,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let flags = [
        "--ca-backend",
        "se-cryptokit",
        "--tls-backend",
        "se-cryptokit",
    ];
    let mut daemon = Daemon::start_sealed_init(POLICY_SE, Approvals::Https, &flags, |yaml| {
        format!(
            "{yaml}signers:\n  se_cryptokit:\n    helper: {}\n",
            wrapper.display()
        )
    });
    // A keystore made again by hand, so what `writd init` leaves is seen before any start.
    daemon.stop();
    let root = daemon.root().to_owned();
    for dir in ["s/keys", "s/boot"] {
        fs::remove_dir_all(root.join(dir)).unwrap();
        fs::create_dir(root.join(dir)).unwrap();
    }
    fs::remove_file(root.join("s/leases.db")).unwrap();
    let mut args = vec!["init", "writd.yaml"];
    args.extend(flags);
    let out = daemon.writd_with(&args, &format!("{PASSPHRASE}\n"));
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let said = stdout(&out);
    for line in [
        "TLS key: on se-cryptokit, owed: the daemon makes it at its first start (writd \
         tls-fingerprint prints it then)",
        "CA key: on se-cryptokit, owed: the daemon makes it at its first start (its log says so)",
        "signing key agent-01: on se-cryptokit, owed: the daemon makes it at its first start \
         (writd signing-keys prints it then)",
    ] {
        assert!(said.lines().any(|l| l == line), "{line}\n{said}");
    }
    assert!(!said.contains("TLS fingerprint:"), "{said}");
    for file in ["ca.age", "signing/agent-01.age"] {
        assert!(!root.join("s/keys").join(file).exists(), "{file}");
    }
    assert!(!root.join("s/boot/tls-01").exists());
    // Before the first start: the host key prints, what is owed is refused by name.
    let host = daemon.writd_with(&["host-key", "writd.yaml"], "");
    assert_eq!(host.status.code(), Some(0), "{}", stderr(&host));
    let owed = " is owed to the daemon: it makes it at its first start (a key on a device is \
                made only by the running daemon); start it once, then run this again";
    for (command, what) in [
        ("tls-fingerprint", "the TLS key"),
        ("signing-keys", "signing key agent-01"),
    ] {
        let out = daemon.writd_with(&[command, "writd.yaml"], "");
        assert_eq!(out.status.code(), Some(1), "{command}: {}", stdout(&out));
        assert_eq!(
            stderr(&out).trim_end(),
            format!("writd: {what}{owed}"),
            "{command}"
        );
    }
    let upstream = daemon.writd_with(&["upstream-keys", "writd.yaml"], "");
    assert_eq!(upstream.status.code(), Some(0), "{}", stderr(&upstream));

    // The first start makes each one, as `writd run`: in the audit log, the file gone. (The
    // audit log outlived the keystore made again: only what follows counts.)
    let before = daemon.audit().len();
    daemon.restart();
    assert!(!root.join("s/keys/to-make.json").exists());
    let audit = daemon.audit()[before..].to_owned();
    for made in [
        "the CA's key made on se-cryptokit at the daemon's start",
        "the TLS key made on se-cryptokit at the daemon's start",
        "signing key agent-01 made on se-cryptokit at the daemon's start",
    ] {
        assert_eq!(audit.matches(made).count(), 1, "{made}\n{audit}");
    }
    let fingerprint = daemon.writd_with(&["tls-fingerprint", "writd.yaml"], "");
    assert_eq!(
        fingerprint.status.code(),
        Some(0),
        "{}",
        stderr(&fingerprint)
    );
    let keys = daemon.writd_with(&["signing-keys", "writd.yaml"], "");
    assert!(
        stdout(&keys).starts_with("agent-01 ecdsa-sha2-nistp256 "),
        "{}",
        stdout(&keys)
    );
    // They sign for the daemon: nothing unusable at unseal, a lease granted over HTTPS.
    let out = daemon.unseal();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let request = daemon.request("owed", TICKET);
    let out = daemon.run(&["sign", &request.id, "--yes"], "");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(request.finish().0.code(), Some(0));
    assert!(
        !daemon.audit()[before..].contains("is unusable"),
        "{}",
        daemon.audit()
    );
    // A restart makes nothing again.
    daemon.restart();
    assert_eq!(
        daemon.audit()[before..]
            .matches("at the daemon's start (owed by a command run by hand)")
            .count(),
        3,
        "{}",
        daemon.audit()
    );
}

/// `writd recover`, run by hand like `writd init`, never makes a key on a device either: a
/// recovered policy declaring one leaves it owed (said, in the audit log, refused by `writd
/// signing-keys`), and the next start makes it, signing for the daemon at unseal.
#[test]
fn on_the_mac_writd_recover_leaves_a_device_key_to_the_daemon_s_next_start() {
    if !writ_integration::on_the_mac("this test") {
        return;
    }
    let outside = tempfile::tempdir().unwrap();
    let wrapper = outside.path().join("writ-se");
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\ncase \"$(/bin/ps -o args= -p $PPID)\" in\n  *\" run \"*) c=run ;;\n  \
             *) c=by-hand ;;\nesac\nexec {} --context \"$c\" \"$@\"\n",
            bin("writ-fake-se").display()
        ),
    )
    .unwrap();
    fs::set_permissions(
        &wrapper,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let mut daemon = Daemon::start_sealed_init(
        POLICY_SE,
        Approvals::Ssh,
        &["--ca-backend", "se-cryptokit"],
        |yaml| {
            format!(
                "{yaml}signers:\n  se_cryptokit:\n    helper: {}\n",
                wrapper.display()
            )
        },
    );
    daemon.stop();
    let root = daemon.root().to_owned();
    let in_force = fs::read_to_string(root.join("policy.yaml")).unwrap();
    let recovered = in_force.replacen(
        "keys:\n",
        "keys:\n  agent-02:\n    use: signing\n    format: ssh\n    algorithm: p256\n    \
         backend: se-cryptokit\n",
        1,
    );
    assert_ne!(recovered, in_force);
    let file = root.join("recovered-policy.yaml");
    fs::write(&file, &recovered).unwrap();
    let out = daemon.writd_with(
        &["recover", "writd.yaml", "policy", file.to_str().unwrap()],
        &format!("{PASSPHRASE}\n"),
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );
    let owed = "signing key agent-02 on se-cryptokit: owed by writd recover, the daemon makes it \
                at its next start";
    assert!(
        stdout(&out)
            .lines()
            .any(|l| l == format!("{owed} (writd signing-keys or upstream-keys prints it then)")),
        "{}",
        stdout(&out)
    );
    assert_eq!(
        daemon.audit().matches(owed).count(),
        1,
        "{}",
        daemon.audit()
    );
    assert!(!root.join("s/keys/signing/agent-02.age").exists());
    let keys = daemon.writd_with(&["signing-keys", "writd.yaml"], "");
    assert_eq!(keys.status.code(), Some(1), "{}", stdout(&keys));
    assert!(
        stdout(&keys).starts_with("agent-01 ecdsa-sha2-nistp256 "),
        "the keys made are printed first: {}",
        stdout(&keys)
    );
    assert!(
        stderr(&keys).starts_with("writd: signing key agent-02 is owed to the daemon"),
        "{}",
        stderr(&keys)
    );

    // The next start makes it, as `writd run`: it signs for the daemon.
    daemon.restart();
    assert!(!root.join("s/keys/to-make.json").exists());
    assert_eq!(
        daemon
            .audit()
            .matches("signing key agent-02 made on se-cryptokit at the daemon's start")
            .count(),
        1,
        "{}",
        daemon.audit()
    );
    let out = daemon.unseal();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        !daemon.audit().contains("is unusable"),
        "{}",
        daemon.audit()
    );
    assert!(
        daemon
            .print("signing-keys")
            .contains("agent-02 ecdsa-sha2-nistp256 ")
    );
}
