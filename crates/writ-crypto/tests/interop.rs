//! SSHSIG and certificates against the real OpenSSH tools, in both directions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use writ_crypto::ca::{CertificateAuthority, CertificateError, CertificateRequest};
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{LineEnding, PrivateKey, PublicKey};
use writ_crypto::{Error, ca, sshsig};

const MSG: &[u8] =
    b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor A <a@b> 0 +0000\n\nmsg\n";

fn write_private_key(dir: &Path, name: &str, key: &PrivateKey) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn ssh_keygen(dir: &Path) -> Command {
    let mut cmd = Command::new("ssh-keygen");
    cmd.current_dir(dir).env_remove("SSH_AUTH_SOCK");
    cmd
}

#[test]
fn rust_signatures_verify_with_ssh_keygen() {
    for kind in [KeyKind::Ed25519, KeyKind::P256] {
        let dir = tempfile::tempdir().unwrap();
        let key = generate(kind).unwrap();
        let armored = sshsig::sign(&key, "git", MSG).unwrap();
        fs::write(dir.path().join("msg.sig"), &armored).unwrap();
        fs::write(
            dir.path().join("allowed_signers"),
            format!("agent@writ {}\n", key.public_key().to_openssh().unwrap()),
        )
        .unwrap();

        let mut child = ssh_keygen(dir.path())
            .args(["-Y", "verify", "-f", "allowed_signers", "-I", "agent@writ"])
            .args(["-n", "git", "-s", "msg.sig"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child.stdin.take().unwrap().write_all(MSG).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{kind:?}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

#[test]
fn ssh_keygen_signatures_verify_in_rust() {
    for kind in [KeyKind::Ed25519, KeyKind::P256] {
        let dir = tempfile::tempdir().unwrap();
        let key = generate(kind).unwrap();
        write_private_key(dir.path(), "approver", &key);
        fs::write(dir.path().join("ticket"), MSG).unwrap();
        let status = ssh_keygen(dir.path())
            .args([
                "-q",
                "-Y",
                "sign",
                "-n",
                "writ-approval",
                "-f",
                "approver",
                "ticket",
            ])
            .status()
            .unwrap();
        assert!(status.success());
        let armored = fs::read_to_string(dir.path().join("ticket.sig")).unwrap();
        let allowed = vec![key.public_key().clone()];

        let signer = sshsig::verify(&allowed, "writ-approval", MSG, &armored).unwrap();
        assert_eq!(signer, key.public_key());

        assert!(matches!(
            sshsig::verify(&allowed, "git", MSG, &armored),
            Err(Error::Namespace { .. })
        ));
        assert!(matches!(
            sshsig::verify(&allowed, "writ-approval", b"other bytes", &armored),
            Err(Error::BadSignature)
        ));
        let stranger = vec![generate(kind).unwrap().public_key().clone()];
        assert!(matches!(
            sshsig::verify(&stranger, "writ-approval", MSG, &armored),
            Err(Error::UnknownSigner(_))
        ));
    }
}

/// Signs a message with `ssh-keygen -Y sign` through an ssh-agent, the way approvers sign:
/// the private key stays in the agent, `ssh-keygen` only gets the public key.
fn sign_through_agent(socket: &Path, key: &PublicKey, namespace: &str, msg: &[u8]) -> String {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("key.pub"), key.to_openssh().unwrap()).unwrap();
    fs::write(dir.path().join("message"), msg).unwrap();
    let out = ssh_keygen(dir.path())
        .env("SSH_AUTH_SOCK", socket)
        .args([
            "-q", "-Y", "sign", "-n", namespace, "-f", "key.pub", "message",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "signing through the agent failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    fs::read_to_string(dir.path().join("message.sig")).unwrap()
}

/// What any approval key must satisfy, whatever agent holds it.
fn agent_signature_verifies(socket: &Path, key: &PublicKey) {
    let msg = format!(
        "writ test ticket {}\n",
        writ_crypto::keys::random_hex(16).unwrap()
    );
    let armored = sign_through_agent(socket, key, "writ-approval", msg.as_bytes());
    let allowed = vec![key.clone()];

    sshsig::verify(&allowed, "writ-approval", msg.as_bytes(), &armored).unwrap();
    assert!(matches!(
        sshsig::verify(&allowed, "git", msg.as_bytes(), &armored),
        Err(Error::Namespace { .. })
    ));
    assert!(matches!(
        sshsig::verify(&allowed, "writ-approval", b"other bytes", &armored),
        Err(Error::BadSignature)
    ));
}

/// A throwaway `ssh-agent`, never the user's.
struct TestAgent {
    child: std::process::Child,
    socket: PathBuf,
    dir: tempfile::TempDir,
}

impl TestAgent {
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let child = Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&socket)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        // Built before waiting, so a timeout still stops the agent (on drop).
        let agent = Self { child, socket, dir };
        for _ in 0..100 {
            if agent.socket.exists() {
                return agent;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("ssh-agent did not start");
    }

    fn add(&self, key: &PrivateKey) {
        let path = write_private_key(self.dir.path(), "key", key);
        let status = Command::new("ssh-add")
            .arg("-q")
            .arg(&path)
            .env("SSH_AUTH_SOCK", &self.socket)
            .status()
            .unwrap();
        assert!(status.success());
        fs::remove_file(path).unwrap();
    }
}

impl Drop for TestAgent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn agent_held_keys_sign_approvals_rust_verifies() {
    let agent = TestAgent::start();
    for kind in [KeyKind::Ed25519, KeyKind::P256] {
        let key = generate(kind).unwrap();
        agent.add(&key);
        agent_signature_verifies(&agent.socket, key.public_key());
    }
}

/// Opt-in: the same check with a key held by your own agent (Secure Enclave, YubiKey…),
/// which may ask for Touch ID or a touch. Signs a fresh random message; nothing is kept.
///
/// `make test-agent KEY=<public key .pub>` (uses `SSH_AUTH_SOCK`, or `AGENT=<socket>`).
#[test]
#[ignore = "needs your ssh-agent: make test-agent KEY=<public key .pub>"]
fn your_agent_key_signs_approvals_rust_verifies() {
    let path = std::env::var_os("WRIT_TEST_AGENT_KEY")
        .expect("set WRIT_TEST_AGENT_KEY to the public key (.pub) of a key in your agent");
    let socket = std::env::var_os("SSH_AUTH_SOCK").expect("set SSH_AUTH_SOCK to your agent");
    let key = PublicKey::from_openssh(fs::read_to_string(path).unwrap().trim()).unwrap();
    agent_signature_verifies(Path::new(&socket), &key);
}

#[test]
fn certificates_are_issued_and_checked() {
    let authority = CertificateAuthority::new(generate(KeyKind::Ed25519).unwrap());
    let session = generate(KeyKind::Ed25519).unwrap();
    let issue = |serial, valid_after, valid_before| {
        authority
            .issue(&CertificateRequest {
                subject: session.public_key(),
                serial,
                key_id: "wrt_test",
                principals: &["git"],
                valid_after,
                valid_before,
            })
            .unwrap()
    };
    let trusted = [authority.fingerprint()];
    let revoked: HashSet<u64> = [7].into_iter().collect();
    let check = |cert, user, now| {
        ca::validate_user_certificate(cert, &trusted, |s| revoked.contains(&s), user, now)
    };

    let cert = issue(1, 1000, 2000);
    assert_eq!(cert.key_id(), "wrt_test");
    assert_eq!(check(&cert, "git", 1500), Ok(()));
    assert_eq!(check(&cert, "git", 999), Err(CertificateError::NotYetValid));
    assert_eq!(check(&cert, "git", 2000), Err(CertificateError::Expired));
    assert_eq!(
        check(&cert, "root", 1500),
        Err(CertificateError::WrongPrincipal("root".into()))
    );
    let revoked_cert = issue(7, 1000, 2000);
    assert_eq!(
        check(&revoked_cert, "git", 1500),
        Err(CertificateError::Revoked(7))
    );

    let other = CertificateAuthority::new(generate(KeyKind::Ed25519).unwrap());
    let foreign = other
        .issue(&CertificateRequest {
            subject: session.public_key(),
            serial: 1,
            key_id: "wrt_test",
            principals: &["git"],
            valid_after: 1000,
            valid_before: 2000,
        })
        .unwrap();
    assert!(matches!(
        check(&foreign, "git", 1500),
        Err(CertificateError::UnknownAuthority(_))
    ));
}

#[test]
fn ssh_keygen_reads_issued_certificates() {
    let dir = tempfile::tempdir().unwrap();
    let authority = CertificateAuthority::new(generate(KeyKind::Ed25519).unwrap());
    let session = generate(KeyKind::P256).unwrap();
    let cert = authority
        .issue(&CertificateRequest {
            subject: session.public_key(),
            serial: 1842,
            key_id: "wrt_01JD8X",
            principals: &["git"],
            valid_after: 0,
            valid_before: u64::MAX,
        })
        .unwrap();
    fs::write(dir.path().join("key-cert.pub"), cert.to_openssh().unwrap()).unwrap();
    let out = ssh_keygen(dir.path())
        .args(["-L", "-f", "key-cert.pub"])
        .output()
        .unwrap();
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{listing}");
    assert!(listing.contains("Serial: 1842"), "{listing}");
    assert!(listing.contains("Key ID: \"wrt_01JD8X\""), "{listing}");
}
