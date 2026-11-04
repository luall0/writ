//! The software backend: the `Signer` contract (alone and behind a `QueuedSigner`), keys it
//! refuses, and nothing of a key in its `Debug` or its errors.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use writ_core::names::KeyId;
use writ_crypto::algorithm::{Hash, KeyAlgorithm, SignerHash};
use writ_crypto::keypair::{KeyPair, RawSignature};
use writ_crypto::keys::{KeyKind, generate};
use writ_signer::contract::{add_key_contract, queued_signer_contract, signer_contract};
use writ_signer::queue::{QueueConfig, QueuedSigner};
use writ_signer::software::SoftwareSigner;
use writ_signer::testing::{FailingSigner, keypair, software_signer};
use writ_signer::{Signer, SignerError, sshsig};

fn id(text: &str) -> KeyId {
    text.parse().unwrap()
}

#[test]
fn the_software_backend_passes_the_contract() {
    signer_contract(&software_signer(&["agent-01"], KeyKind::Ed25519));
    signer_contract(&software_signer(&["agent-p256"], KeyKind::P256));
    // One key of every algorithm the backend declares: each pair signs and verifies.
    let pairs = writ_signer::software::pairs();
    let mut algorithms: Vec<KeyAlgorithm> = pairs.iter().map(|(a, _)| *a).collect();
    algorithms.dedup();
    let mixed = SoftwareSigner::new(
        algorithms
            .iter()
            .map(|a| (id(a.name()), KeyPair::generate(*a).unwrap())),
    )
    .unwrap();
    signer_contract(&mixed);
    assert_eq!(mixed.capabilities().pairs, pairs);
    for expected in [
        (KeyAlgorithm::Ed25519, None),
        (KeyAlgorithm::P256, Some(Hash::Sha256)),
        (KeyAlgorithm::P384, Some(Hash::Sha384)),
    ] {
        assert!(pairs.contains(&expected), "{expected:?}");
    }
    assert!(mixed.capabilities().exportable);
    assert!(!mixed.capabilities().needs_touch);
    assert!(mixed.capabilities().takes_keys);
    add_key_contract(&mixed);
    // A backend that holds no key yet takes one too.
    let empty = SoftwareSigner::empty();
    add_key_contract(&empty);
    assert_eq!(empty.list_keys().unwrap().len(), 1);
}

#[test]
fn the_software_backend_passes_the_contract_behind_a_queue() {
    queued_signer_contract(software_signer(&["agent-01"], KeyKind::Ed25519));
    queued_signer_contract(software_signer(&["agent-p256", "other"], KeyKind::P256));
}

#[test]
fn the_failing_signer_passes_the_contract_until_it_fails() {
    let signer = FailingSigner::new(software_signer(&["agent-01"], KeyKind::Ed25519));
    signer_contract(&signer);
    signer.set_failing(true);
    assert!(matches!(
        sshsig(&signer, &id("agent-01"), "git", Hash::Sha512, b"x"),
        Err(SignerError::Failed(k)) if k == id("agent-01")
    ));
}

#[test]
fn keys_it_refuses() {
    let key = generate(KeyKind::Ed25519).unwrap();
    let pair = || KeyPair::from_ssh(key.clone()).unwrap();
    assert!(matches!(
        SoftwareSigner::new([(id("a"), pair()), (id("a"), pair())]),
        Err(SignerError::DuplicateKey(k)) if k == id("a")
    ));
    // A security key: its private half is a handle on a device, never a software key.
    use writ_crypto::ssh_key::{private, public};
    let inner = key.key_data().ed25519().unwrap().public;
    let sk =
        private::SkEd25519::new(public::SkEd25519::new(inner, "ssh:"), 0x01, [7u8; 32]).unwrap();
    let sk =
        writ_crypto::ssh_key::PrivateKey::new(private::KeypairData::SkEd25519(sk), "").unwrap();
    assert_eq!(
        KeyPair::from_ssh(sk).unwrap_err().to_string(),
        "not supported: a sk-ssh-ed25519@openssh.com key"
    );
    // Added while it runs: an id held already is refused, nothing new listed.
    let signer = SoftwareSigner::new([(id("a"), pair())]).unwrap();
    assert!(matches!(
        signer.add_key(id("a"), keypair(KeyKind::P256)),
        Err(SignerError::DuplicateKey(k)) if k == id("a")
    ));
    assert_eq!(signer.list_keys().unwrap().len(), 1);
    assert_eq!(
        writ_signer::public_key(&signer, &id("a")).unwrap(),
        *key.public_key(),
        "the key held is kept"
    );
    // A pair the key doesn't sign with: refused by name, never signed otherwise.
    let refused = signer
        .sign(&id("a"), b"data", Some(Hash::Sha512))
        .unwrap_err();
    assert_eq!(
        refused.to_string(),
        "key a: ed25519 with sha512 is not supported by this backend"
    );
}

/// A backend that makes its own keys (a stand-in for a device): it takes none from outside.
struct MakesItsOwn(SoftwareSigner);

impl Signer for MakesItsOwn {
    fn list_keys(&self) -> Result<Vec<writ_signer::KeyInfo>, SignerError> {
        self.0.list_keys()
    }

    fn sign(&self, id: &KeyId, data: &[u8], hash: SignerHash) -> Result<RawSignature, SignerError> {
        self.0.sign(id, data, hash)
    }

    fn capabilities(&self) -> writ_signer::Capabilities {
        writ_signer::Capabilities {
            takes_keys: false,
            exportable: false,
            ..self.0.capabilities()
        }
    }
}

#[test]
fn a_backend_that_takes_no_key_says_so_alone_and_behind_a_queue() {
    let own = || MakesItsOwn(software_signer(&["agent-01"], KeyKind::P256));
    signer_contract(&own());
    add_key_contract(&own());
    queued_signer_contract(own());
}

#[test]
fn no_key_in_debug_or_errors() {
    let key = keypair(KeyKind::Ed25519);
    let pem = key.to_pem().unwrap();
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let signer = SoftwareSigner::new([(id("agent-01"), key)]).unwrap();
    let debug = format!("{signer:?}");
    assert_eq!(debug, r#"SoftwareSigner { keys: [KeyId("agent-01")] }"#);
    let queued = QueuedSigner::new(
        SoftwareSigner::new([(id("agent-02"), keypair(KeyKind::Ed25519))]).unwrap(),
        QueueConfig {
            name: "writ-sign-test".to_owned(),
            capacity: 1,
            deadline: std::time::Duration::from_secs(60),
        },
    )
    .unwrap();
    assert_eq!(
        format!("{queued:?}"),
        r#"QueuedSigner { keys: [KeyId("agent-02")], deadline: 60s, .. }"#
    );
    let error = signer
        .sign(&id("other"), b"x", None)
        .unwrap_err()
        .to_string();
    assert_eq!(error, "the signer has no key other");
    for text in [&debug, &error] {
        assert!(!text.contains(&body[..20]), "{text}");
    }
}

/// A backend whose every signature panics (a device library that falls over).
struct Panicking(SoftwareSigner);

impl Signer for Panicking {
    fn list_keys(&self) -> Result<Vec<writ_signer::KeyInfo>, SignerError> {
        self.0.list_keys()
    }

    fn sign(&self, _: &KeyId, _: &[u8], _: SignerHash) -> Result<RawSignature, SignerError> {
        panic!("the device fell over");
    }

    fn capabilities(&self) -> writ_signer::Capabilities {
        self.0.capabilities()
    }
}

/// What a test subscriber wrote.
#[derive(Clone, Default)]
struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_backend_that_panics_signs_nothing_more_and_says_so_once() {
    let log = Captured::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let key = id("agent-01");
    tracing::subscriber::with_default(subscriber, || {
        let queued = QueuedSigner::new(
            Panicking(software_signer(&["agent-01"], KeyKind::Ed25519)),
            QueueConfig {
                name: "writ-sign-test".to_owned(),
                capacity: 4,
                deadline: std::time::Duration::from_secs(60),
            },
        )
        .unwrap();
        // Answered at once, not at the deadline: the worker said so before it stopped.
        assert!(matches!(
            queued.sign(&key, b"first", None),
            Err(SignerError::Unavailable)
        ));
        // Never trusted again, without another try.
        for _ in 0..3 {
            assert!(matches!(
                queued.sign(&key, b"again", None),
                Err(SignerError::Unavailable)
            ));
        }
        // What doesn't go through the backend still answers.
        assert_eq!(queued.list_keys().unwrap().len(), 1);
    });
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("the signer backend panicked"))
        .collect();
    assert_eq!(lines.len(), 1, "{text}");
    assert!(lines[0].contains("ERROR"), "{}", lines[0]);
    assert!(
        lines[0].contains("queue=\"writ-sign-test\""),
        "{}",
        lines[0]
    );
    assert!(lines[0].contains("key=agent-01"), "{}", lines[0]);
}

/// Every SSHSIG the software backend makes, for each algorithm and message hash SSH takes,
/// verifies with the real `ssh-keygen -Y verify` (OpenSSH's own reading of the format: an RSA
/// key signs as `rsa-sha2-256` or `rsa-sha2-512`), and fails it for other bytes. A throwaway
/// directory only: never the user's `~/.ssh`.
#[test]
fn every_algorithm_s_sshsig_verifies_with_ssh_keygen() {
    use writ_crypto::algorithm::SignatureFormat;
    let dir = tempfile::tempdir().unwrap();
    for algorithm in KeyAlgorithm::ALL {
        let signer =
            SoftwareSigner::new([(id("k"), KeyPair::generate(algorithm).unwrap())]).unwrap();
        let public = writ_signer::public_key(&signer, &id("k")).unwrap();
        let allowed = dir.path().join("allowed_signers");
        std::fs::write(
            &allowed,
            format!("agent@writ.invalid {}\n", public.to_openssh().unwrap()),
        )
        .unwrap();
        for &hash in writ_crypto::algorithm::hashes(SignatureFormat::Ssh, algorithm) {
            let msg = format!("signed with {algorithm} and {hash}\n");
            let armored = sshsig(&signer, &id("k"), "git", hash, msg.as_bytes()).unwrap();
            let sig = dir.path().join("sig");
            std::fs::write(&sig, &armored).unwrap();
            for (bytes, valid) in [(msg.as_str(), true), ("other bytes\n", false)] {
                let mut child = std::process::Command::new("ssh-keygen")
                    .args([
                        "-Y",
                        "verify",
                        "-n",
                        "git",
                        "-I",
                        "agent@writ.invalid",
                        "-f",
                    ])
                    .arg(&allowed)
                    .arg("-s")
                    .arg(&sig)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap();
                std::io::Write::write_all(child.stdin.as_mut().unwrap(), bytes.as_bytes()).unwrap();
                let out = child.wait_with_output().unwrap();
                assert_eq!(
                    out.status.success(),
                    valid,
                    "{algorithm} {hash} over {bytes:?}: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }
}

/// What `gpg` prints on its status descriptor, run in a throwaway `GNUPGHOME` (never the
/// user's own `~/.gnupg`, no agent of theirs: `--batch`, and the home made here).
fn gpg(home: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new("gpg")
        .args(["--batch", "--no-tty", "--homedir"])
        .arg(home)
        .args(args)
        .env_remove("GPG_AGENT_INFO")
        .output()
        .unwrap()
}

/// Every algorithm's OpenPGP certificate imports into the real `gpg` with its user ids, and
/// its detached signatures with each hash the format allows verify (`VALIDSIG` with its
/// fingerprint), only over the bytes signed.
#[test]
fn every_algorithm_s_openpgp_signature_verifies_with_gpg() {
    use writ_crypto::algorithm::SignatureFormat;
    use writ_signer::{openpgp_certificate, openpgp_key, openpgp_signature};
    let created = 1_762_128_000;
    for algorithm in KeyAlgorithm::ALL {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("gnupg");
        std::fs::create_dir(&home).unwrap();
        std::fs::set_permissions(&home, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        let signer =
            SoftwareSigner::new([(id("k"), KeyPair::generate(algorithm).unwrap())]).unwrap();
        let hashes = writ_crypto::algorithm::hashes(SignatureFormat::Openpgp, algorithm);
        let strongest = *hashes.last().unwrap();
        let uids = ["Agent <agent@writ.invalid>", "<bot@writ.invalid>"];
        let cert = openpgp_certificate(&signer, &id("k"), created, strongest, &uids).unwrap();
        // The same key, time and user ids: the same certificate.
        assert_eq!(
            openpgp_certificate(&signer, &id("k"), created, strongest, &uids).unwrap(),
            cert,
            "{algorithm}"
        );
        let fingerprint = openpgp_key(&signer, &id("k"), created)
            .unwrap()
            .fingerprint_hex();
        std::fs::write(dir.path().join("cert.asc"), &cert).unwrap();
        let out = gpg(
            &home,
            &["--import", dir.path().join("cert.asc").to_str().unwrap()],
        );
        assert!(
            out.status.success(),
            "{algorithm}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let listed = gpg(&home, &["--with-colons", "--list-keys", &fingerprint]);
        let listed = String::from_utf8_lossy(&listed.stdout).into_owned();
        for uid in uids {
            assert!(listed.contains(uid), "{algorithm}: {uid} in {listed}");
        }
        // Valid user ids: their self-signatures checked (`u` or `-` validity, never `i`).
        assert!(
            !listed
                .lines()
                .any(|l| l.starts_with("uid:i:") || l.starts_with("uid:r:")),
            "{algorithm}: {listed}"
        );
        for &hash in hashes {
            let data =
                format!("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\n{algorithm} {hash}\n");
            let armored = openpgp_signature(
                &signer,
                &id("k"),
                created,
                hash,
                data.as_bytes(),
                created + 60,
            )
            .unwrap();
            assert!(armored.starts_with("-----BEGIN PGP SIGNATURE-----\n\n"));
            std::fs::write(dir.path().join("sig.asc"), &armored).unwrap();
            std::fs::write(dir.path().join("data"), &data).unwrap();
            std::fs::write(dir.path().join("other"), "other bytes\n").unwrap();
            for (file, valid) in [("data", true), ("other", false)] {
                let out = gpg(
                    &home,
                    &[
                        "--status-fd",
                        "1",
                        "--verify",
                        dir.path().join("sig.asc").to_str().unwrap(),
                        dir.path().join(file).to_str().unwrap(),
                    ],
                );
                let status = String::from_utf8_lossy(&out.stdout).into_owned();
                assert_eq!(
                    status.contains(&format!("[GNUPG:] VALIDSIG {fingerprint} ")),
                    valid,
                    "{algorithm} {hash} over {file}: {status}{}",
                    String::from_utf8_lossy(&out.stderr)
                );
                if !valid {
                    assert!(status.contains("[GNUPG:] BADSIG "), "{status}");
                }
            }
        }
    }
}

/// A backend that signs with another hash than the one asked for (a broken or lying device).
struct OtherHash(SoftwareSigner);

impl Signer for OtherHash {
    fn list_keys(&self) -> Result<Vec<writ_signer::KeyInfo>, SignerError> {
        self.0.list_keys()
    }
    fn sign(&self, id: &KeyId, data: &[u8], hash: SignerHash) -> Result<RawSignature, SignerError> {
        let other = match hash {
            Some(Hash::Sha512) => Some(Hash::Sha256),
            _ => Some(Hash::Sha512),
        };
        self.0.sign(id, data, other)
    }
    fn capabilities(&self) -> writ_signer::Capabilities {
        self.0.capabilities()
    }
}

/// The review after M5.5 (L8): the SSHSIG was assembled from whatever the backend answered,
/// as long as it encoded: one signing with another hash than asked made a signature its
/// SSHSIG mislabels. It is refused, as an OpenPGP one is.
#[test]
fn a_backend_answering_with_another_hash_makes_no_sshsig() {
    let honest =
        SoftwareSigner::new([(id("k"), KeyPair::generate(KeyAlgorithm::Rsa3072).unwrap())])
            .unwrap();
    assert!(sshsig(&honest, &id("k"), "git", Hash::Sha512, b"x").is_ok());
    let lying = OtherHash(honest);
    match sshsig(&lying, &id("k"), "git", Hash::Sha512, b"x") {
        Err(SignerError::Failed(key)) => assert_eq!(key, id("k")),
        other => panic!("expected Failed, got {other:?}"),
    }
}
