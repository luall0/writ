//! The `piv-p256` stanza (M7.6) against age-plugin-yubikey's own code, both ways, and every
//! way a hostile or damaged stanza is refused before a device would see it.
//!
//! The vectors were made by age-plugin-yubikey 0.5.0's `format.rs` (its `wrap_file_key`,
//! unchanged, the crate checked against the crates.io index) for the software key `SCALAR`:
//! its recipient line, then the stanza's tag, ephemeral key and body for two file keys. The
//! other way, a stanza this crate wrapped (`OURS`) was opened by the plugin's `from_stanza`
//! and its unwrap's HKDF and AEAD, with a software ECDH in the YubiKey's place, to `OURS_KEY`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use age::secrecy::ExposeSecret;
use age_core::format::{FileKey, Stanza};
use base64ct::{Base64Unpadded, Encoding};
use writ_crypto::piv_p256::software::SoftwareKey;
use writ_crypto::piv_p256::{Line, P256Recipient, PivError, STANZA_TAG};

const SCALAR: [u8; 32] = [
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93,
    0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
];
const RECIPIENT: &str = "age1yubikey1qds0a496y4df6vwfv84hf334d45vqjdcjgakr7nvue5kytnq720mvw34n6v";
const TAG: &str = "pGgHKw";
/// (ephemeral key, body, file key), from the plugin's wrap.
const THEIRS: [(&str, &str, [u8; 16]); 2] = [
    (
        "A76CPO14u0ikinTvSu+pUad5lKU+1AV/ZmP1Yjqj12TT",
        "qP2W0yldPzXv2El3XwWW5ufQevp6AhKMtV3ex/KE8Ik",
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    ),
    (
        "ArjwgXmPNoae3e/8RdLGPcMZv8PID7gVvEBRu7/PMxSv",
        "+/gv6eikCdXfwJKzwn8C4iLM05od/nyTNiF75E+bWTE",
        [
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00,
        ],
    ),
];

fn key() -> SoftwareKey {
    SoftwareKey::from_scalar(&SCALAR, "age1yubikey").unwrap()
}

fn stanza(args: &[&str], body: Vec<u8>) -> Stanza {
    Stanza {
        tag: STANZA_TAG.to_owned(),
        args: args.iter().map(|a| (*a).to_owned()).collect(),
        body,
    }
}

fn theirs(i: usize) -> Stanza {
    let (epk, body, _) = THEIRS[i];
    stanza(&[TAG, epk], Base64Unpadded::decode_vec(body).unwrap())
}

fn file_key(bytes: [u8; 16]) -> FileKey {
    FileKey::new(Box::new(bytes))
}

#[test]
fn the_recipient_and_its_tag_are_the_plugin_s() {
    let key = key();
    assert_eq!(key.recipient().to_string(), RECIPIENT);
    assert_eq!(Base64Unpadded::encode_string(&key.recipient().tag()), TAG);
    // Read back from its text, the same recipient; under another prefix, refused.
    assert_eq!(
        &P256Recipient::parse(RECIPIENT, "age1yubikey").unwrap(),
        key.recipient()
    );
    assert_eq!(
        P256Recipient::parse(RECIPIENT, "age1se"),
        Err(PivError::Recipient("another kind of recipient"))
    );
    // The Secure Enclave's prints the same point as age-plugin-se does.
    let se = SoftwareKey::from_scalar(&SCALAR, "age1se").unwrap();
    assert!(se.recipient().to_string().starts_with("age1se1"));
    assert_eq!(se.recipient().compressed(), key.recipient().compressed());
}

#[test]
fn a_stanza_the_plugin_wrapped_opens_to_its_file_key() {
    let key = key();
    for (i, (_, _, expected)) in THEIRS.iter().enumerate() {
        let opened = key.unwrap(&theirs(i)).unwrap().unwrap();
        assert_eq!(opened.expose_secret(), expected, "vector {i}");
    }
}

/// What this crate wraps, the plugin opened (the module's doc says how): this stanza, for
/// `OURS_KEY`.
const OURS: (&str, &str) = (
    "AsfFfB2QZokxjcwVcmXDvVgSQUcBO8bgDuf57RslIShq",
    "5RfAMHzn5avpAjomGAxnMVM7rzVVYWTDN5sD8Yz/VNU",
);
const OURS_KEY: [u8; 16] = [0x42; 16];

#[test]
fn a_stanza_this_crate_wraps_has_the_plugin_s_shape_and_opens_both_ways() {
    let key = key();
    // Ours, recorded once and opened by the plugin's code: still opens here.
    let recorded = stanza(&[TAG, OURS.0], Base64Unpadded::decode_vec(OURS.1).unwrap());
    assert_eq!(
        key.unwrap(&recorded).unwrap().unwrap().expose_secret(),
        &OURS_KEY
    );
    // A fresh wrap: the plugin's layout (two arguments, the tag, a compressed point, 32
    // bytes), a new ephemeral key each time, and it opens.
    let first = key.recipient().wrap(&file_key(OURS_KEY)).unwrap();
    let second = key.recipient().wrap(&file_key(OURS_KEY)).unwrap();
    for wrapped in [&first, &second] {
        assert_eq!(wrapped.tag, "piv-p256");
        assert_eq!(wrapped.args.len(), 2);
        assert_eq!(wrapped.args[0], TAG);
        let epk = Base64Unpadded::decode_vec(&wrapped.args[1]).unwrap();
        assert_eq!(epk.len(), 33);
        assert!(matches!(epk[0], 0x02 | 0x03));
        assert_eq!(wrapped.body.len(), 32);
        assert_eq!(
            key.unwrap(wrapped).unwrap().unwrap().expose_secret(),
            &OURS_KEY
        );
    }
    assert_ne!(first.args[1], second.args[1], "an ephemeral key per wrap");
}

#[test]
fn through_age_a_file_to_the_recipient_and_another_opens_with_the_key() {
    use std::io::{Read, Write};
    struct Way(SoftwareKey);
    impl age::Identity for Way {
        fn unwrap_stanza(&self, s: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
            self.0
                .unwrap(s)
                .map(|r| r.map_err(|_| age::DecryptError::KeyDecryptionFailed))
        }
    }
    let way = Way(key());
    let other = age::x25519::Identity::generate().to_public();
    let recipients: [&dyn age::Recipient; 2] = [&other, way.0.recipient()];
    let encryptor = age::Encryptor::with_recipients(recipients.into_iter()).unwrap();
    let mut sealed = Vec::new();
    let mut writer = encryptor.wrap_output(&mut sealed).unwrap();
    writer.write_all(b"a token").unwrap();
    writer.finish().unwrap();
    let mut reader = age::Decryptor::new_buffered(&sealed[..])
        .unwrap()
        .decrypt(std::iter::once(&way as &dyn age::Identity))
        .unwrap();
    let mut plain = Vec::new();
    reader.read_to_end(&mut plain).unwrap();
    assert_eq!(plain, b"a token");
}

#[test]
fn another_kind_of_stanza_is_not_this_one_s() {
    let mut other = theirs(0);
    other.tag = "X25519".to_owned();
    assert!(Line::parse(&other).is_none());
    // Another recipient's tag: well made, not this key's to try.
    let line = Line::parse(&theirs(0)).unwrap().unwrap();
    let another = SoftwareKey::from_scalar(&[7; 32], "age1yubikey").unwrap();
    assert!(!line.is_for(another.recipient()));
    assert!(another.unwrap(&theirs(0)).is_none());
}

#[test]
fn a_malformed_stanza_is_refused_by_name_before_any_ecdh() {
    let (epk, body, _) = THEIRS[0];
    let body = Base64Unpadded::decode_vec(body).unwrap();
    let epk_bytes = Base64Unpadded::decode_vec(epk).unwrap();
    let point = |bytes: &[u8]| Base64Unpadded::encode_string(bytes);
    let mut uncompressed = vec![0x04];
    uncompressed.extend_from_slice(&[0x11; 64]);
    let mut off_curve = epk_bytes.clone();
    off_curve[1..].fill(0xff);
    let mut bad_prefix = epk_bytes.clone();
    bad_prefix[0] = 0x05;
    let cases: Vec<(&str, Stanza, PivError)> = vec![
        (
            "no argument",
            stanza(&[], body.clone()),
            PivError::Arguments(0),
        ),
        (
            "one argument",
            stanza(&[TAG], body.clone()),
            PivError::Arguments(1),
        ),
        (
            "three arguments",
            stanza(&[TAG, epk, "x"], body.clone()),
            PivError::Arguments(3),
        ),
        (
            "a tag not base64",
            stanza(&["!!!!!!", epk], body.clone()),
            PivError::Tag,
        ),
        (
            "a tag of 3 bytes",
            stanza(&["pGgH", epk], body.clone()),
            PivError::Tag,
        ),
        (
            "a tag of 5 bytes",
            stanza(&["pGgHKwAA", epk], body.clone()),
            PivError::Tag,
        ),
        (
            "a key not base64",
            stanza(&[TAG, "@@@@"], body.clone()),
            PivError::Point,
        ),
        (
            "a key of 32 bytes",
            stanza(&[TAG, &point(&epk_bytes[..32])], body.clone()),
            PivError::Point,
        ),
        (
            "an uncompressed key",
            stanza(&[TAG, &point(&uncompressed)], body.clone()),
            PivError::Point,
        ),
        (
            "the identity (a 0x00 key)",
            stanza(&[TAG, &point(&[0u8; 33])], body.clone()),
            PivError::Point,
        ),
        (
            "a key off the curve",
            stanza(&[TAG, &point(&off_curve)], body.clone()),
            PivError::Point,
        ),
        (
            "a key with another prefix",
            stanza(&[TAG, &point(&bad_prefix)], body.clone()),
            PivError::Point,
        ),
        (
            "a body of 31 bytes",
            stanza(&[TAG, epk], body[..31].to_vec()),
            PivError::Body(31),
        ),
        (
            "a body of 33 bytes",
            stanza(&[TAG, epk], [body.clone(), vec![0]].concat()),
            PivError::Body(33),
        ),
        (
            "an empty body",
            stanza(&[TAG, epk], Vec::new()),
            PivError::Body(0),
        ),
    ];
    for (what, bad, expected) in cases {
        assert_eq!(Line::parse(&bad), Some(Err(expected)), "{what}");
    }
}

#[test]
fn a_damaged_body_or_a_wrong_shared_secret_never_opens() {
    let key = key();
    let line = Line::parse(&theirs(0)).unwrap().unwrap();
    let right = key.agree(&line);
    assert!(line.unwrap(key.recipient(), &right).is_ok());
    // Every byte of the body flipped in turn: refused, never another file key.
    let (epk, body, _) = THEIRS[0];
    let body = Base64Unpadded::decode_vec(body).unwrap();
    for i in 0..body.len() {
        let mut changed = body.clone();
        changed[i] ^= 0x01;
        let line = Line::parse(&stanza(&[TAG, epk], changed)).unwrap().unwrap();
        assert_eq!(
            line.unwrap(key.recipient(), &right).map(|_| ()),
            Err(PivError::Open),
            "byte {i}"
        );
    }
    // A shared secret off by one bit, or of another length (a device answering wrong).
    let mut wrong = right;
    wrong[0] ^= 0x01;
    assert_eq!(
        line.unwrap(key.recipient(), &wrong).map(|_| ()),
        Err(PivError::Open)
    );
    for len in [0, 31, 33, 64] {
        assert_eq!(
            line.unwrap(key.recipient(), &vec![0; len]).map(|_| ()),
            Err(PivError::Shared),
            "{len} bytes"
        );
    }
    // The device is handed the point uncompressed, on the curve.
    let peer = line.peer_point();
    assert_eq!(peer[0], 0x04);
    assert!(P256Recipient::from_sec1(&peer, "age1se").is_ok());
}

#[test]
fn a_recipient_text_that_is_not_one_is_refused() {
    for (text, why) in [
        ("", "not bech32"),
        ("age1yubikey1", "not bech32"),
        ("age1yubikey1qqqqqqqq", "not bech32"),
        ("age1yubikey1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "not bech32"),
    ] {
        assert_eq!(
            P256Recipient::parse(text, "age1yubikey"),
            Err(PivError::Recipient(why)),
            "{text:?}"
        );
    }
    // Well-formed bech32 of the wrong length, or of 33 bytes that aren't a point.
    use bech32::ToBase32;
    let short = bech32::encode(
        "age1yubikey",
        [2u8; 32].to_base32(),
        bech32::Variant::Bech32,
    )
    .unwrap();
    assert_eq!(
        P256Recipient::parse(&short, "age1yubikey"),
        Err(PivError::Recipient("not a compressed point"))
    );
    let mut not_point = [0xffu8; 33];
    not_point[0] = 0x02;
    let text = bech32::encode(
        "age1yubikey",
        not_point.to_base32(),
        bech32::Variant::Bech32,
    )
    .unwrap();
    assert_eq!(
        P256Recipient::parse(&text, "age1yubikey"),
        Err(PivError::Recipient("not a point on the curve"))
    );
    let bech32m = bech32::encode(
        "age1yubikey",
        key().recipient().compressed().to_base32(),
        bech32::Variant::Bech32m,
    )
    .unwrap();
    assert_eq!(
        P256Recipient::parse(&bech32m, "age1yubikey"),
        Err(PivError::Recipient("another kind of recipient"))
    );
}
