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
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::LineEnding;
use writ_signer::contract::{add_key_contract, queued_signer_contract, signer_contract};
use writ_signer::queue::{QueueConfig, QueuedSigner};
use writ_signer::software::SoftwareSigner;
use writ_signer::testing::{FailingSigner, software_signer};
use writ_signer::{Signer, SignerError, sshsig};

fn id(text: &str) -> KeyId {
    text.parse().unwrap()
}

#[test]
fn the_software_backend_passes_the_contract() {
    signer_contract(&software_signer(&["agent-01"], KeyKind::Ed25519));
    signer_contract(&software_signer(&["agent-p256"], KeyKind::P256));
    let mixed = SoftwareSigner::new([
        (id("a"), generate(KeyKind::Ed25519).unwrap()),
        (id("b"), generate(KeyKind::P256).unwrap()),
    ])
    .unwrap();
    signer_contract(&mixed);
    assert_eq!(mixed.capabilities().algorithms.len(), 2);
    assert!(mixed.capabilities().exportable);
    assert!(!mixed.capabilities().needs_touch);
    assert!(mixed.capabilities().takes_keys);
    add_key_contract(&mixed);
    // A backend that holds no key yet takes one too.
    let empty = SoftwareSigner::new([]).unwrap();
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
        sshsig(&signer, &id("agent-01"), "git", b"x"),
        Err(SignerError::Failed(k)) if k == id("agent-01")
    ));
}

#[test]
fn keys_it_refuses() {
    let key = generate(KeyKind::Ed25519).unwrap();
    assert!(matches!(
        SoftwareSigner::new([(id("a"), key.clone()), (id("a"), key.clone())]),
        Err(SignerError::DuplicateKey(k)) if k == id("a")
    ));
    // A security key: its private half is a handle on a device, never a software key.
    use writ_crypto::ssh_key::{private, public};
    let inner = key.key_data().ed25519().unwrap().public;
    let sk =
        private::SkEd25519::new(public::SkEd25519::new(inner, "ssh:"), 0x01, [7u8; 32]).unwrap();
    let sk =
        writ_crypto::ssh_key::PrivateKey::new(private::KeypairData::SkEd25519(sk), "").unwrap();
    assert!(matches!(
        SoftwareSigner::new([(id("sk"), sk.clone())]),
        Err(SignerError::Unsupported { id: k, algorithm }) if k == id("sk")
            && algorithm == "sk-ssh-ed25519@openssh.com"
    ));
    // Added while it runs: the same refusals, and nothing new listed.
    let signer = SoftwareSigner::new([(id("a"), key.clone())]).unwrap();
    assert!(matches!(
        signer.add_key(id("sk"), sk),
        Err(SignerError::Unsupported { id: k, .. }) if k == id("sk")
    ));
    assert!(matches!(
        signer.add_key(id("a"), generate(KeyKind::P256).unwrap()),
        Err(SignerError::DuplicateKey(k)) if k == id("a")
    ));
    assert_eq!(signer.list_keys().unwrap().len(), 1);
    assert_eq!(
        writ_signer::public_key(&signer, &id("a")).unwrap(),
        *key.public_key(),
        "the key held is kept"
    );
}

/// A backend that makes its own keys (a stand-in for a device): it takes none from outside.
struct MakesItsOwn(SoftwareSigner);

impl Signer for MakesItsOwn {
    fn list_keys(&self) -> Result<Vec<writ_signer::KeyInfo>, SignerError> {
        self.0.list_keys()
    }

    fn sign(
        &self,
        id: &KeyId,
        data: &[u8],
    ) -> Result<writ_crypto::ssh_key::Signature, SignerError> {
        self.0.sign(id, data)
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
    let key = generate(KeyKind::Ed25519).unwrap();
    let pem = key.to_openssh(LineEnding::LF).unwrap();
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let signer = SoftwareSigner::new([(id("agent-01"), key)]).unwrap();
    let debug = format!("{signer:?}");
    assert_eq!(debug, r#"SoftwareSigner { keys: [KeyId("agent-01")] }"#);
    let queued = QueuedSigner::new(
        SoftwareSigner::new([(id("agent-02"), generate(KeyKind::Ed25519).unwrap())]).unwrap(),
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
    let error = signer.sign(&id("other"), b"x").unwrap_err().to_string();
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

    fn sign(&self, _: &KeyId, _: &[u8]) -> Result<writ_crypto::ssh_key::Signature, SignerError> {
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
            queued.sign(&key, b"first"),
            Err(SignerError::Unavailable)
        ));
        // Never trusted again, without another try.
        for _ in 0..3 {
            assert!(matches!(
                queued.sign(&key, b"again"),
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
