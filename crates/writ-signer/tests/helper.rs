//! The helper signer against a fake `writ-se` (`writ-fake-se`): the whole `Signer` contract,
//! alone and behind a queue; the startup check; and every way a helper may fail or lie, each
//! refused with its exact error, the next job served by a new helper.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use writ_core::names::KeyId;
use writ_crypto::algorithm::{Hash, KeyAlgorithm};
use writ_crypto::ssh_key::PublicKey;
use writ_signer::contract::{
    add_key_contract, create_key_contract, queued_signer_contract, signer_contract,
};
use writ_signer::helper::{HelperConfig, HelperError, HelperSigner, Load, MAX_DATA, check};
use writ_signer::{Signer, SignerError, Stored};

const FAKE: &str = env!("CARGO_BIN_EXE_writ-fake-se");

fn id(text: &str) -> KeyId {
    text.parse().unwrap()
}

/// The fake helper with `args`; `deadline` how long it may stay silent.
fn config(args: &[&str], deadline: Duration) -> HelperConfig {
    HelperConfig {
        backend: "se-test".to_owned(),
        program: PathBuf::from(FAKE),
        args: args.iter().map(OsString::from).collect(),
        deadline,
    }
}

/// Long enough for any answer of a working helper: what ends a wait is the answer.
const PATIENT: Duration = Duration::from_secs(60);

/// The deadline of the tests whose subject is a helper that never answers: what ends that
/// wait. The working helper's requests run under it too (a signer has one deadline), so it is
/// far past one of their round trips on a warm binary ([`warmed`]), and the test's outcome
/// is the silent helper's, never the working one's speed (the review after M7.6, T-7).
const SHORT: Duration = Duration::from_secs(1);

/// Runs the fake once and waits for its end (it reads its stdin to EOF, then exits): the
/// first start of a freshly built binary (a Mac scanning it) never falls under [`SHORT`].
fn warmed() {
    let status = std::process::Command::new(FAKE)
        .stdin(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "{status:?}");
}

fn signer(args: &[&str]) -> HelperSigner {
    HelperSigner::new(config(args, PATIENT), []).unwrap()
}

/// What the fake stores for a key, and its public half, made by a well-behaved helper.
fn made(ids: &[&str]) -> Vec<Load> {
    let maker = signer(&[]);
    ids.iter()
        .map(|k| {
            let created = maker.create_key(id(k), KeyAlgorithm::P256).unwrap();
            Load {
                id: id(k),
                stored: created.stored,
                public: created.info.public_key,
            }
        })
        .collect()
}

fn rebuild(stored: Vec<(KeyId, Stored, PublicKey)>) -> Box<dyn Signer> {
    let loads = stored
        .into_iter()
        .map(|(id, stored, public)| Load { id, stored, public });
    Box::new(HelperSigner::new(config(&[], PATIENT), loads).unwrap())
}

#[test]
fn the_helper_signer_passes_the_contract_alone_and_behind_a_queue() {
    let held = HelperSigner::new(config(&[], PATIENT), made(&["se-01", "se-02"])).unwrap();
    assert!(held.refused().is_empty());
    signer_contract(&held);
    let capabilities = held.capabilities();
    assert!(capabilities.makes_keys && !capabilities.takes_keys && !capabilities.exportable);
    assert_eq!(
        capabilities.pairs,
        [(KeyAlgorithm::P256, Some(Hash::Sha256))]
    );
    add_key_contract(&held);
    create_key_contract(&held, Some(&rebuild));
    create_key_contract(&signer(&[]), Some(&rebuild));
    queued_signer_contract(HelperSigner::new(config(&[], PATIENT), made(&["se-01"])).unwrap());
}

#[test]
fn the_startup_check_says_whether_the_helper_runs_and_has_its_device() {
    check(&config(&[], PATIENT)).unwrap();
    assert_eq!(
        check(&config(&["--no-enclave"], PATIENT)),
        Err(HelperError::Refused("no-secure-enclave".to_owned()))
    );
    let missing = HelperConfig {
        program: PathBuf::from("/nonexistent/writ-se"),
        ..config(&[], PATIENT)
    };
    assert!(matches!(check(&missing), Err(HelperError::Spawn(_))));
    let relative = HelperConfig {
        program: PathBuf::from("writ-se"),
        ..config(&[], PATIENT)
    };
    assert_eq!(
        check(&relative),
        Err(HelperError::Spawn("its path is not absolute".to_owned()))
    );
    assert_eq!(
        check(&config(&["--fault", "hello:crash"], PATIENT)),
        Err(HelperError::Died)
    );
    assert_eq!(
        check(&config(&["--fault", "hello:oversize"], PATIENT)),
        Err(HelperError::Oversized)
    );
}

/// The error a signature gets from a helper with `fault` on `sign`.
fn sign_with_fault(fault: &str, deadline: Duration) -> SignerError {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("once");
    let fault = format!("sign:{fault}");
    let args = [
        "--fault",
        &fault,
        "--from",
        "2",
        "--once",
        marker.to_str().unwrap(),
    ];
    let held = HelperSigner::new(config(&args, deadline), made(&["k"])).unwrap();
    assert_eq!(held.refused(), []);
    // `public` and the probe answered right when the key was loaded, by the first helper:
    // its fault is armed for the next `sign`.
    let error = held
        .sign(&id("k"), b"data", Some(Hash::Sha256))
        .unwrap_err();
    if fault == "sign:refuse" {
        // Its own refusal: the same helper is kept, so it refuses again.
        assert!(matches!(
            held.sign(&id("k"), b"data", Some(Hash::Sha256)),
            Err(SignerError::Failed(_))
        ));
        return error;
    }
    // The helper that failed was ended; the next one (no fault: the marker is there) signs.
    let signature = held
        .sign(&id("k"), b"data", Some(Hash::Sha256))
        .unwrap_or_else(|e| panic!("{fault}: {e:?}"));
    let public = writ_signer::public_key(&held, &id("k")).unwrap();
    writ_crypto::keypair::verify(&public, b"data", &signature).unwrap();
    error
}

#[test]
fn every_way_a_helper_fails_to_sign_is_refused_and_the_next_job_served() {
    for fault in [
        "crash",
        "oversize",
        "bad-signature",
        "bad-point",
        "dirty-code",
        "extra-field",
        "unknown-status",
    ] {
        let error = sign_with_fault(fault, PATIENT);
        assert!(
            matches!(&error, SignerError::Failed(k) if k == &id("k")),
            "{fault}: {error:?}"
        );
    }
    // Its own refusal: the job refused, the same helper kept.
    assert!(matches!(
        sign_with_fault("refuse", PATIENT),
        SignerError::Failed(k) if k == id("k")
    ));
    // Silent: past its deadline, a timeout (the deadline is what's tested: it ends the wait).
    warmed();
    assert!(matches!(
        sign_with_fault("silent", SHORT),
        SignerError::Timeout(k) if k == id("k")
    ));
}

/// The review after M7.6 (K-2): the request was written with no deadline, so a helper that
/// stopped reading its stdin held the caller (and the helper's lock) for good once the
/// request was larger than the pipe's buffer. One deadline now covers the write and the
/// answer: the job times out, the helper is killed, the next job is served.
#[test]
fn a_helper_that_never_reads_a_large_request_costs_one_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("once");
    let args = [
        "--fault",
        "sign:no-read",
        "--from",
        "2",
        "--once",
        marker.to_str().unwrap(),
    ];
    warmed();
    let held = HelperSigner::new(config(&args, SHORT), made(&["k"])).unwrap();
    // Far past a pipe's buffer (64 KiB on macOS and Linux): the write itself blocks.
    let data = vec![b'x'; 1 << 20];
    assert!(matches!(
        held.sign(&id("k"), &data, Some(Hash::Sha256)),
        Err(SignerError::Timeout(k)) if k == id("k")
    ));
    // That helper was killed; a new one (the marker is there: no fault) signs the same data.
    let signature = held.sign(&id("k"), &data, Some(Hash::Sha256)).unwrap();
    let public = writ_signer::public_key(&held, &id("k")).unwrap();
    writ_crypto::keypair::verify(&public, &data, &signature).unwrap();
}

/// The review after M7.6 (K-8): a helper that answered another key's point when the signer
/// was built stayed running for the next key. It is ended: the next key's check runs on a new
/// one (with `--once`, one without the fault), and is held usable.
#[test]
fn a_helper_that_answers_another_key_s_point_is_not_kept() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("once");
    let args = [
        "--fault",
        "public:other-key",
        "--once",
        marker.to_str().unwrap(),
    ];
    let held = HelperSigner::new(config(&args, PATIENT), made(&["a", "b"])).unwrap();
    assert_eq!(
        held.refused(),
        [(
            id("a"),
            "the helper answers another key for its blob".to_owned()
        )]
    );
    held.sign(&id("b"), b"data", Some(Hash::Sha256)).unwrap();
}

/// Stored bytes that aren't the frame made for the key, each with why it is refused.
fn tampered(good: &Load, other: &Load) -> Vec<(&'static str, Vec<u8>, &'static str)> {
    let bytes = good.stored.as_bytes();
    let frame_len = b"writ-se-blob/1\n".len();
    let flip = |at: usize| {
        let mut b = bytes.to_vec();
        b[at] ^= 0x5a;
        b
    };
    let digest = "its stored bytes don't match their digest (corrupted, or another key's)";
    vec![
        ("flipped-blob", flip(bytes.len() - 7), digest),
        ("flipped-digest", flip(frame_len + 3), digest),
        (
            "flipped-header",
            flip(2),
            "its stored bytes are not a writ-se-blob/1 frame",
        ),
        ("cut-blob", bytes[..bytes.len() - 1].to_vec(), digest),
        (
            "cut-digest",
            bytes[..frame_len + 31].to_vec(),
            "its stored bytes are cut",
        ),
        (
            "no-blob",
            bytes[..frame_len + 32].to_vec(),
            "its stored blob's length is out of bounds",
        ),
        (
            "empty",
            Vec::new(),
            "its stored bytes are not a writ-se-blob/1 frame",
        ),
        // The bare blob, as the helper made it: never sent without its frame.
        (
            "bare",
            bytes[frame_len + 32..].to_vec(),
            "its stored bytes are not a writ-se-blob/1 frame",
        ),
        // Another key's frame, whole and well-formed, under this key's public half.
        ("other-key", other.stored.as_bytes().to_vec(), digest),
    ]
}

#[test]
fn stored_bytes_not_framed_for_the_key_never_reach_the_helper() {
    let made = made(&["good", "other"]);
    let cases = tampered(&made[0], &made[1]);
    let public = made[0].public.clone();
    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().join("requests");
    let mut loads: Vec<Load> = cases
        .iter()
        .map(|(name, bytes, _)| Load {
            id: id(name),
            stored: Stored::new(bytes.clone()),
            public: public.clone(),
        })
        .collect();
    loads.extend(made);
    let args = ["--record", record.to_str().unwrap()];
    let held = HelperSigner::new(config(&args, PATIENT), loads).unwrap();
    // The helper was asked for the two good keys' points and their probes, and nothing else.
    let requests = std::fs::read_to_string(&record).unwrap();
    let ops: Vec<&str> = requests
        .lines()
        .map(|l| l.split(' ').next().unwrap())
        .collect();
    assert_eq!(ops, ["public", "sign", "public", "sign"], "{requests}");
    let mut expected: Vec<(KeyId, String)> = cases
        .iter()
        .map(|(name, _, why)| (id(name), (*why).to_owned()))
        .collect();
    expected.sort();
    let mut refused = held.refused().to_vec();
    refused.sort();
    assert_eq!(refused, expected);
    for (name, _, _) in &cases {
        let error = held
            .sign(&id(name), b"data", Some(Hash::Sha256))
            .unwrap_err();
        assert!(matches!(&error, SignerError::Unusable(k) if k == &id(name)));
        assert!(
            error.to_string().contains("writ admin key rotate"),
            "{error}"
        );
    }
    // Listed all the same, from the public half kept; the good keys sign.
    assert_eq!(held.list_keys().unwrap().len(), cases.len() + 2);
    held.sign(&id("good"), b"data", Some(Hash::Sha256)).unwrap();
    held.sign(&id("other"), b"data", Some(Hash::Sha256))
        .unwrap();
    let asked = std::fs::read_to_string(&record).unwrap().lines().count();
    assert_eq!(asked, 6, "two points and probes, then two signatures");
    // A public half kept that isn't P-256: refused before the helper too.
    let ed25519 = writ_crypto::keypair::KeyPair::generate(KeyAlgorithm::Ed25519)
        .unwrap()
        .public_key();
    let good = made_one("k");
    let held = HelperSigner::new(
        config(&args, PATIENT),
        [Load {
            id: id("k"),
            stored: good.stored,
            public: ed25519,
        }],
    )
    .unwrap();
    assert_eq!(
        held.refused(),
        [(
            id("k"),
            "the public half kept for it is not a P-256 key".to_owned()
        )]
    );
    assert_eq!(
        std::fs::read_to_string(&record).unwrap().lines().count(),
        asked,
        "nothing more asked"
    );
}

fn made_one(name: &str) -> Load {
    made(&[name]).pop().unwrap()
}

#[test]
fn a_framed_blob_the_helper_refuses_or_reads_as_another_key_is_unusable() {
    for (fault, why) in [
        ("public:refuse", "the helper refused: refused-on-demand"),
        (
            "public:other-key",
            "the helper answers another key for its blob",
        ),
        (
            "public:bad-point",
            "the helper's answer is malformed: not a point on P-256",
        ),
    ] {
        let held =
            HelperSigner::new(config(&["--fault", fault], PATIENT), [made_one("k")]).unwrap();
        assert_eq!(held.refused(), [(id("k"), why.to_owned())], "{fault}");
    }
}

/// Found on the first real install (2026-11-14): a key made outside the LaunchDaemon opened
/// there (its point answered) but its device refused every signature, which showed only at
/// the first approval. Each key now signs a probe when its signer is built: one that can't is
/// unusable from the start, said with why, and refuses every signature by name.
#[test]
fn a_key_its_device_won_t_sign_with_is_unusable_from_the_start() {
    for (fault, why) in [
        (
            "refuse",
            "it does not sign: the helper refused: refused-on-demand",
        ),
        (
            "bad-signature",
            "it does not sign: a signature that doesn't verify",
        ),
        ("bad-point", "it does not sign: not a P-256 signature"),
        ("crash", "it does not sign: the helper died"),
        (
            "extra-field",
            "it does not sign: the helper's answer is malformed: not the fields the operation \
             answers",
        ),
        (
            "dirty-code",
            "it does not sign: the helper's answer is malformed: a refusal that isn't one code",
        ),
    ] {
        let fault = format!("sign:{fault}");
        let held =
            HelperSigner::new(config(&["--fault", &fault], PATIENT), [made_one("k")]).unwrap();
        assert_eq!(held.refused(), [(id("k"), why.to_owned())], "{fault}");
        let error = held
            .sign(&id("k"), b"data", Some(Hash::Sha256))
            .unwrap_err();
        assert!(
            matches!(&error, SignerError::Unusable(k) if k == &id("k")),
            "{fault}: {error:?}"
        );
        // Listed all the same, from the public half kept.
        assert_eq!(held.list_keys().unwrap().len(), 1, "{fault}");
    }
    // The real install's case: a key made by a helper in one context (`writd init` run by
    // hand) is refused by the device in another (the LaunchDaemon), its point still answered.
    let maker = HelperSigner::new(config(&["--context", "by-hand"], PATIENT), []).unwrap();
    let created = maker.create_key(id("ca"), KeyAlgorithm::P256).unwrap();
    let load = || Load {
        id: id("ca"),
        stored: Stored::new(created.stored.as_bytes().to_vec()),
        public: created.info.public_key.clone(),
    };
    let elsewhere = HelperSigner::new(config(&["--context", "daemon"], PATIENT), [load()]).unwrap();
    assert_eq!(
        elsewhere.refused(),
        [(
            id("ca"),
            "it does not sign: the helper refused: sign-failed".to_owned()
        )]
    );
    assert!(matches!(
        elsewhere.sign(&id("ca"), b"data", Some(Hash::Sha256)),
        Err(SignerError::Unusable(k)) if k == id("ca")
    ));
    // Where it was made, it signs.
    let there = HelperSigner::new(config(&["--context", "by-hand"], PATIENT), [load()]).unwrap();
    assert_eq!(there.refused(), []);
    let signature = there.sign(&id("ca"), b"data", Some(Hash::Sha256)).unwrap();
    writ_crypto::keypair::verify(&created.info.public_key, b"data", &signature).unwrap();
}

/// A helper whose probe answer lies is ended like one that answers another key's point: the
/// next key's check runs on a new helper (with `--once`, one without the fault), and signs.
#[test]
fn a_helper_that_lies_on_a_probe_is_not_kept() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("once");
    let args = [
        "--fault",
        "sign:bad-signature",
        "--once",
        marker.to_str().unwrap(),
    ];
    let held = HelperSigner::new(config(&args, PATIENT), made(&["a", "b"])).unwrap();
    assert_eq!(
        held.refused(),
        [(
            id("a"),
            "it does not sign: a signature that doesn't verify".to_owned()
        )]
    );
    let signature = held.sign(&id("b"), b"data", Some(Hash::Sha256)).unwrap();
    let public = writ_signer::public_key(&held, &id("b")).unwrap();
    writ_crypto::keypair::verify(&public, b"data", &signature).unwrap();
}

#[test]
fn a_helper_that_dies_on_a_blob_at_start_costs_that_key_alone() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("once");
    let args = [
        "--fault",
        "public:crash",
        "--once",
        marker.to_str().unwrap(),
    ];
    let held = HelperSigner::new(config(&args, PATIENT), made(&["first", "second"])).unwrap();
    assert_eq!(
        held.refused(),
        [(id("first"), "the helper died".to_owned())]
    );
    held.sign(&id("second"), b"data", Some(Hash::Sha256))
        .unwrap();
    for fault in ["bad-point", "other-key"] {
        let fault = format!("public:{fault}");
        let held = HelperSigner::new(config(&["--fault", &fault], PATIENT), made(&["k"])).unwrap();
        assert_eq!(held.refused().len(), 1, "{fault}");
    }
}

#[test]
fn a_key_the_helper_makes_must_prove_its_point() {
    for fault in ["bad-point", "other-key", "crash", "refuse", "extra-field"] {
        let fault = format!("create:{fault}");
        let held = signer(&["--fault", &fault]);
        let error = held.create_key(id("k"), KeyAlgorithm::P256).unwrap_err();
        assert!(
            matches!(&error, SignerError::Failed(k) if k == &id("k")),
            "{fault}: {error:?}"
        );
        assert!(
            held.list_keys().unwrap().is_empty(),
            "{fault}: nothing kept"
        );
    }
    // An algorithm it doesn't make: refused before the helper is asked.
    assert!(matches!(
        signer(&["--fault", "create:crash"]).create_key(id("k"), KeyAlgorithm::Ed25519),
        Err(SignerError::Unsupported { id: k, .. }) if k == id("k")
    ));
}

#[test]
fn what_it_does_not_sign_is_refused_by_name() {
    let held = HelperSigner::new(config(&[], PATIENT), made(&["k"])).unwrap();
    assert!(matches!(
        held.sign(&id("k"), &vec![0; MAX_DATA + 1], Some(Hash::Sha256)),
        Err(SignerError::Unsupported { id: k, .. }) if k == id("k")
    ));
    held.sign(&id("k"), &vec![0; MAX_DATA], Some(Hash::Sha256))
        .unwrap();
    assert!(matches!(
        held.sign(&id("k"), b"x", Some(Hash::Sha512)),
        Err(SignerError::Unsupported { id: k, .. }) if k == id("k")
    ));
    let missing = HelperConfig {
        program: PathBuf::from("/nonexistent/writ-se"),
        ..config(&[], PATIENT)
    };
    let gone = HelperSigner::new(missing, []).unwrap();
    assert!(matches!(
        gone.create_key(id("k"), KeyAlgorithm::P256),
        Err(SignerError::Unavailable)
    ));
}

#[test]
fn nothing_it_stores_is_printed() {
    let held = HelperSigner::new(config(&[], PATIENT), made(&["k"])).unwrap();
    let debug = format!("{held:?}");
    assert!(
        debug.starts_with(r#"HelperSigner { backend: "se-test", keys: [KeyId("k")]"#),
        "{debug}"
    );
    assert!(!debug.contains("fake-se"), "{debug}");
}
