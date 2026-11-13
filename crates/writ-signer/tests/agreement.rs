//! The helper's key agreement (M7.6) against a fake `writ-se` (`writ-fake-se`): the unwrap
//! contract through `writ-platform`'s `piv-p256` way; a key made and loaded, its point proven
//! by a probe agreement; and every way a helper may fail or lie, each refused with its exact
//! error, the next agreement served. Stored bytes not framed for the key never reach it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use writ_crypto::piv_p256::{P256Recipient, SHARED_BYTES, UNCOMPRESSED_BYTES};
use writ_platform::unlock::piv::{KeyAgreement, PivUnwrap};
use writ_signer::Stored;
use writ_signer::helper::agreement::HelperAgreement;
use writ_signer::helper::{HelperConfig, HelperError};

const FAKE: &str = env!("CARGO_BIN_EXE_writ-fake-se");
const PATIENT: Duration = Duration::from_secs(60);

fn config(args: &[&str], deadline: Duration) -> HelperConfig {
    HelperConfig {
        backend: "se-test".to_owned(),
        program: PathBuf::from(FAKE),
        args: args.iter().map(OsString::from).collect(),
        deadline,
    }
}

/// The helper's agreement as the device `writd` wires into the way.
struct Device(HelperAgreement);

impl KeyAgreement for Device {
    fn agree(
        &self,
        peer: &[u8; UNCOMPRESSED_BYTES],
    ) -> writ_platform::Result<zeroize::Zeroizing<[u8; SHARED_BYTES]>> {
        self.0
            .agree(peer)
            .map_err(|e| writ_platform::PlatformError::Unlock(e.to_string()))
    }
}

fn way(name: &str, agreement: HelperAgreement) -> PivUnwrap {
    let recipient = P256Recipient::from_sec1(agreement.point(), "age1se").unwrap();
    PivUnwrap::new(name, recipient, Arc::new(Device(agreement)))
}

#[test]
fn the_helper_s_key_agreement_passes_the_unwrap_contract() {
    let (agreement, _) = HelperAgreement::create(&config(&[], PATIENT)).unwrap();
    let way = way("se-01", agreement);
    let (other, _) = HelperAgreement::create(&config(&[], PATIENT)).unwrap();
    let other = self::way("se-02", other);
    let fake = writ_platform::testing::FakeUnwrap::new("fake", [1; 16]).recipient();
    writ_platform::contract::keystore_unwrap(
        &way,
        way.recipient(),
        &[other.recipient(), &fake],
        &[&other],
        true,
        &[],
    );
}

#[test]
fn a_key_made_is_loaded_again_from_what_the_daemon_kept() {
    let (made_now, made) = HelperAgreement::create(&config(&[], PATIENT)).unwrap();
    assert_eq!(made_now.point(), &made.point);
    let loaded = HelperAgreement::load(&config(&[], PATIENT), &made.stored, &made.point).unwrap();
    let peer = HelperAgreement::create(&config(&[], PATIENT))
        .unwrap()
        .1
        .point;
    assert_eq!(
        *loaded.agree(&peer).unwrap(),
        *made_now.agree(&peer).unwrap(),
        "the same key, from its stored bytes"
    );
}

/// Every way the stored bytes can be wrong is refused before the helper sees them (the fake
/// records each request it gets).
#[test]
fn stored_bytes_not_framed_for_the_key_never_reach_the_helper() {
    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().join("requests");
    let made = HelperAgreement::create(&config(&[], PATIENT)).unwrap().1;
    let other = HelperAgreement::create(&config(&[], PATIENT)).unwrap().1;
    let bytes = made.stored.as_bytes().to_vec();
    let mut flipped = bytes.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    let signing_frame = [b"writ-se-blob/1\n".as_slice(), &bytes[20..]].concat();
    let cases: Vec<(&str, Vec<u8>, &[u8; 65], &str)> = vec![
        (
            "a byte of the blob flipped",
            flipped,
            &made.point,
            "its stored bytes don't match their digest (corrupted, or another key's)",
        ),
        (
            "cut in its digest",
            bytes[..30].to_vec(),
            &made.point,
            "its stored bytes are cut",
        ),
        (
            "the bare blob",
            bytes[52..].to_vec(),
            &made.point,
            "its stored bytes are not a writ-se-agreement/1 frame",
        ),
        (
            "a signing key's frame",
            signing_frame,
            &made.point,
            "its stored bytes are not a writ-se-agreement/1 frame",
        ),
        (
            "another key's point",
            bytes.clone(),
            &other.point,
            "its stored bytes don't match their digest (corrupted, or another key's)",
        ),
    ];
    let args = ["--record", record.to_str().unwrap()];
    for (what, stored, point, expected) in cases {
        let refused = HelperAgreement::load(&config(&args, PATIENT), &Stored::new(stored), point);
        assert_eq!(refused.map(|_| ()).unwrap_err(), expected, "{what}");
    }
    assert!(!record.exists(), "no request reached the helper");
    // A point that isn't one: refused before anything else.
    let mut off = made.point;
    off[64] ^= 1;
    assert_eq!(
        HelperAgreement::load(&config(&args, PATIENT), &made.stored, &off)
            .map(|_| ())
            .unwrap_err(),
        "the helper's answer is malformed: not a point on P-256"
    );
    assert!(!record.exists());
}

#[test]
fn every_way_a_helper_fails_or_lies_is_refused_with_its_error() {
    let dir = tempfile::tempdir().unwrap();
    let made = HelperAgreement::create(&config(&[], PATIENT)).unwrap().1;
    let malformed = |why: &'static str| Err(HelperError::Malformed(why).to_string());
    // Loading: the point answered, and the probe.
    let load_cases: Vec<(&str, Duration, Result<(), String>)> = vec![
        (
            "public-agreement:bad-point",
            PATIENT,
            malformed("not a point on P-256"),
        ),
        (
            "public-agreement:other-key",
            PATIENT,
            Err("the helper answers another key for its blob".to_owned()),
        ),
        (
            "public-agreement:refuse",
            PATIENT,
            Err("the helper refused: refused-on-demand".to_owned()),
        ),
        (
            "public-agreement:crash",
            PATIENT,
            Err(HelperError::Died.to_string()),
        ),
        (
            "public-agreement:silent",
            Duration::from_millis(300),
            Err(HelperError::Silent.to_string()),
        ),
        (
            "agree:other-secret",
            PATIENT,
            malformed("a shared secret its point doesn't give (another key's)"),
        ),
        (
            "agree:short-secret",
            PATIENT,
            malformed("a shared secret of another length"),
        ),
        (
            "agree:extra-field",
            PATIENT,
            malformed("not the fields the operation answers"),
        ),
        (
            "agree:dirty-code",
            PATIENT,
            malformed("a refusal that isn't one code"),
        ),
        (
            "agree:unknown-status",
            PATIENT,
            malformed("an unknown status"),
        ),
        (
            "agree:oversize",
            PATIENT,
            Err(HelperError::Oversized.to_string()),
        ),
    ];
    for (fault, deadline, expected) in load_cases {
        let got = HelperAgreement::load(
            &config(&["--fault", fault], deadline),
            &made.stored,
            &made.point,
        )
        .map(|_| ());
        assert_eq!(got, expected, "{fault}");
    }
    // Making: the point answered, then the probe.
    let create_cases: Vec<(&str, HelperError)> = vec![
        (
            "create-agreement:bad-point",
            HelperError::Malformed("not a point on P-256"),
        ),
        (
            "create-agreement:other-key",
            HelperError::Malformed("a shared secret its point doesn't give (another key's)"),
        ),
        (
            "create-agreement:refuse",
            HelperError::Refused("refused-on-demand".to_owned()),
        ),
    ];
    for (fault, expected) in create_cases {
        let got = HelperAgreement::create(&config(&["--fault", fault], PATIENT)).map(|_| ());
        assert_eq!(got.unwrap_err(), expected, "{fault}");
    }
    // A helper that crashes on one agreement: that one refused, the next served by a new one.
    let marker = dir.path().join("once");
    let args = ["--fault", "agree:crash", "--once", marker.to_str().unwrap()];
    // The probe at load is the faulty agreement the first time (the fault fired, exactly
    // once: the review after M7.6, T-7); the next load's helper (the marker there) answers.
    let first = HelperAgreement::load(&config(&args, PATIENT), &made.stored, &made.point);
    assert_eq!(first.err(), Some(HelperError::Died.to_string()));
    assert!(marker.exists(), "the faulty helper ran");
    let loaded = HelperAgreement::load(&config(&args, PATIENT), &made.stored, &made.point).unwrap();
    let peer = HelperAgreement::create(&config(&[], PATIENT))
        .unwrap()
        .1
        .point;
    assert!(loaded.agree(&peer).is_ok());
    // A peer that isn't a point on the curve is refused here, never sent.
    let mut off = peer;
    off[64] ^= 1;
    assert_eq!(
        loaded.agree(&off).unwrap_err(),
        HelperError::Malformed("the peer is not an uncompressed point on P-256")
    );
}
