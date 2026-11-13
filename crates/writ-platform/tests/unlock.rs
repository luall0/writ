//! Every way into the keystore, real and fake, through the unwrap contract, the passphrase
//! file's own guarantees, and how a file opens when several ways are given.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::path::Path;

use writ_platform::contract;
use writ_platform::testing::{FakeAgreement, FakeUnwrap};
use writ_platform::unlock::passphrase::{self, PassphraseUnwrap};
use writ_platform::unlock::x25519::X25519Unwrap;
use writ_platform::unlock::{OpenError, PassphraseFile};
use writ_platform::{DataKey, KeystoreUnwrap, Passphrase, PlatformError};

const PASSPHRASE: &str = "correct horse battery staple";
const KEY: [u8; 32] = [
    0x5a, 0x01, 0xfe, 0x33, 0x90, 0x12, 0x7c, 0x44, 0xab, 0xcd, 0x00, 0x11, 0x22, 0x99, 0x88, 0x77,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7, 0x08,
];
/// A low scrypt work factor so the tests run fast.
const LOG_N: u8 = 4;

fn passphrase(text: &str) -> Passphrase {
    Passphrase::new(text.to_owned())
}

fn enroll(path: &Path) {
    passphrase::enroll_with_work_factor(
        path,
        &passphrase(PASSPHRASE),
        &DataKey::from_bytes(KEY),
        LOG_N,
    )
    .unwrap()
}

/// The data key at `path`, opened with the passphrase `text`.
fn unlock(path: &Path, text: &str) -> writ_platform::Result<DataKey> {
    writ_platform::unlock::data_key(path, &[&PassphraseUnwrap::new(&passphrase(text))])
}

fn unlock_error(path: &Path, text: &str) -> String {
    match unlock(path, text) {
        Ok(_) => panic!("must not unlock"),
        Err(e) => {
            assert!(matches!(e, PlatformError::Unlock(_)), "{e:?}");
            e.to_string()
        }
    }
}

/// Wraps arbitrary plaintext the way `enroll` does, to build bad files.
fn wrap_raw(path: &Path, plaintext: &[u8]) {
    let mut recipient =
        age::scrypt::Recipient::new(age::secrecy::SecretString::from(PASSPHRASE.to_owned()));
    recipient.set_work_factor(LOG_N);
    let wrapped = age::encrypt(&recipient, plaintext).unwrap();
    write_private(path, &wrapped);
}

/// Writes a file only its owner can read, as the daemon requires of a wrapped key.
fn write_private(path: &Path, contents: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn the_passphrase_passes_the_contract() {
    contract::keystore_unwrap_passphrase(PASSPHRASE, LOG_N);
}

#[test]
fn an_x25519_identity_passes_the_contract() {
    let identity = DataKey::from_bytes(KEY).identity().unwrap();
    let way = X25519Unwrap::new("recovery", identity);
    let other = age::x25519::Identity::generate();
    let fake = FakeUnwrap::new("se-01", [7; 16]).recipient();
    let wrong = X25519Unwrap::new("keystore", other.clone());
    contract::keystore_unwrap(
        &way,
        &way.recipient(),
        &[&other.to_public(), &fake],
        &[&wrong],
        true,
        &[],
    );
}

#[test]
fn the_fake_passes_the_contract() {
    let way = FakeUnwrap::new("se-01", [7; 16]);
    let other = FakeUnwrap::new("se-02", [9; 16]);
    let x25519 = age::x25519::Identity::generate().to_public();
    contract::keystore_unwrap(
        &way,
        &way.recipient(),
        &[&other.recipient(), &x25519],
        &[&other],
        true,
        &[],
    );
}

#[test]
fn enroll_with_the_default_work_factor_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data-key.age");
    passphrase::enroll(&path, &passphrase(PASSPHRASE), &DataKey::from_bytes(KEY)).unwrap();
    assert_eq!(unlock(&path, PASSPHRASE).unwrap().as_bytes(), &KEY);
}

#[test]
fn enroll_refuses_to_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data-key.age");
    std::fs::write(&path, b"precious").unwrap();
    let result = passphrase::enroll_with_work_factor(
        &path,
        &passphrase(PASSPHRASE),
        &DataKey::from_bytes(KEY),
        LOG_N,
    );
    assert!(
        matches!(result, Err(PlatformError::Config(_))),
        "{result:?}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"precious");

    // Nor its own earlier enrollment.
    let path = dir.path().join("enrolled.age");
    enroll(&path);
    let before = std::fs::read(&path).unwrap();
    let again = passphrase::enroll_with_work_factor(
        &path,
        &passphrase("another"),
        &DataKey::from_bytes([1; 32]),
        LOG_N,
    );
    assert!(
        matches!(
            again,
            Err(PlatformError::Unlock(_))
                | Err(PlatformError::Io(_))
                | Err(PlatformError::Config(_))
        ),
        "{again:?}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), before, "never overwritten");
}

#[cfg(unix)]
#[test]
fn the_wrapped_key_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data-key.age");
    enroll(&path);
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn the_wrapped_key_file_holds_neither_the_key_nor_the_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data-key.age");
    enroll(&path);
    let bytes = std::fs::read(&path).unwrap();
    assert!(bytes.starts_with(b"age-encryption.org/v1\n"));
    assert!(!bytes.windows(32).any(|w| w == KEY));
    assert!(
        !bytes
            .windows(PASSPHRASE.len())
            .any(|w| w == PASSPHRASE.as_bytes())
    );
}

#[test]
fn a_wrong_passphrase_or_no_way_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data-key.age");
    enroll(&path);
    let error = unlock_error(&path, "Correct horse battery staple");
    assert_eq!(error, "cannot unlock the keystore: wrong passphrase");
    let none = writ_platform::unlock::data_key(&path, &[]);
    match none {
        Err(PlatformError::Unlock(why)) => {
            assert_eq!(why, format!("{}: nothing given unwraps it", path.display()));
        }
        other => panic!("{other:?}"),
    }
    // An identity is no way into a passphrase file.
    let identity = X25519Unwrap::new("recovery", age::x25519::Identity::generate());
    let error = writ_platform::unlock::data_key(&path, &[&identity]).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "cannot unlock the keystore: {}: nothing given unwraps it",
            path.display()
        )
    );
}

#[test]
fn a_missing_file_fails_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    unlock_error(&dir.path().join("absent.age"), PASSPHRASE);
}

#[test]
fn a_truncated_or_corrupted_file_fails_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let good = dir.path().join("data-key.age");
    enroll(&good);
    let bytes = std::fs::read(&good).unwrap();

    let mut variants: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("garbage", b"not an age file at all\n".to_vec()),
        ("header only", bytes[..bytes.len() / 2].to_vec()),
        ("last byte cut", bytes[..bytes.len() - 1].to_vec()),
        (
            "trailing garbage",
            [bytes.clone(), b"extra".to_vec()].concat(),
        ),
    ];
    for offset in [bytes.len() - 1, bytes.len() - 20, 30] {
        let mut flipped = bytes.clone();
        flipped[offset] ^= 0x40;
        variants.push(("one flipped byte", flipped));
    }

    for (i, (what, contents)) in variants.into_iter().enumerate() {
        let path = dir.path().join(format!("bad-{i}.age"));
        write_private(&path, &contents);
        let error = unlock_error(&path, PASSPHRASE);
        assert!(!error.contains(PASSPHRASE), "{what}: {error}");
    }
}

#[test]
fn a_wrapped_key_of_the_wrong_length_fails() {
    let dir = tempfile::tempdir().unwrap();
    for len in [0usize, 16, 31, 33, 64] {
        let path = dir.path().join(format!("len-{len}.age"));
        wrap_raw(&path, &vec![7u8; len]);
        let error = unlock_error(&path, PASSPHRASE);
        assert!(error.contains("32-byte"), "{len}: {error}");
    }
    // The same plaintext path works for exactly 32 bytes.
    let path = dir.path().join("len-32.age");
    wrap_raw(&path, &KEY);
    let key = unlock(&path, PASSPHRASE).unwrap();
    assert_eq!(key.as_bytes(), &KEY);
}

#[test]
fn a_huge_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("huge.age");
    write_private(&path, &vec![b'a'; 200 * 1024]);
    let error = unlock_error(&path, PASSPHRASE);
    assert!(error.contains("is larger than"), "{error}");
}

#[test]
fn a_wrapped_key_others_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data-key.age");
    enroll(&path);
    assert!(unlock(&path, PASSPHRASE).is_ok());
    // A copy others can read allows an offline attack on the passphrase.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = unlock_error(&path, PASSPHRASE);
    assert!(
        error.contains("accessible by group or others (mode 644)"),
        "{error}"
    );
}

#[test]
fn an_invalid_work_factor_is_a_config_error() {
    let dir = tempfile::tempdir().unwrap();
    for log_n in [0u8, 64, 200] {
        let result = passphrase::enroll_with_work_factor(
            dir.path().join(format!("wf-{log_n}.age")),
            &passphrase(PASSPHRASE),
            &DataKey::from_bytes(KEY),
            log_n,
        );
        assert!(matches!(result, Err(PlatformError::Config(_))), "{log_n}");
    }
}

#[test]
fn generated_data_keys_are_random() {
    let a = DataKey::generate().unwrap();
    let b = DataKey::generate().unwrap();
    assert_ne!(a.as_bytes(), b.as_bytes());
    assert_ne!(a.as_bytes(), &[0u8; 32]);
    assert_eq!(format!("{a:?}"), "DataKey(<redacted>)");
}

#[test]
fn a_data_key_is_one_age_identity_whose_recipient_opens_only_with_it() {
    use std::io::{Read, Write};
    let key = DataKey::from_bytes(KEY);
    // The same bytes, the same identity: what the passphrase unwraps is the keystore's.
    assert_eq!(
        key.recipient().unwrap().to_string(),
        DataKey::from_bytes(KEY).recipient().unwrap().to_string()
    );
    let recipient = key.recipient().unwrap();
    assert!(recipient.to_string().starts_with("age1"), "{recipient}");
    let other = DataKey::from_bytes([9; 32]);
    assert_ne!(
        other.recipient().unwrap().to_string(),
        recipient.to_string()
    );

    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .unwrap();
    let mut sealed = Vec::new();
    let mut writer = encryptor.wrap_output(&mut sealed).unwrap();
    writer.write_all(b"a secret").unwrap();
    writer.finish().unwrap();

    let open = |key: &DataKey| -> Option<Vec<u8>> {
        let identity = key.identity().unwrap();
        let decryptor = age::Decryptor::new_buffered(&sealed[..]).unwrap();
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .ok()?;
        let mut plain = Vec::new();
        reader.read_to_end(&mut plain).unwrap();
        Some(plain)
    };
    assert_eq!(open(&key).as_deref(), Some(&b"a secret"[..]));
    assert_eq!(open(&other), None, "another key opens nothing");
}

/// A file encrypted to several ways opens through whichever is given; a way that fails
/// doesn't stop the next, and its failure is the error when nothing opens.
#[test]
fn a_file_opens_by_any_of_its_ways_and_a_failing_one_does_not_stop_the_next() {
    use std::io::Write;
    let device = FakeUnwrap::new("se-01", [7; 16]);
    let recovery = X25519Unwrap::new("recovery", age::x25519::Identity::generate());
    let recipients: [&dyn age::Recipient; 2] = [&device.recipient(), &recovery.recipient()];
    let encryptor = age::Encryptor::with_recipients(recipients.into_iter()).unwrap();
    let mut sealed = Vec::new();
    let mut writer = encryptor.wrap_output(&mut sealed).unwrap();
    writer.write_all(b"a token").unwrap();
    writer.finish().unwrap();
    let open = |ways: &[&dyn KeystoreUnwrap]| {
        writ_platform::unlock::open(&sealed, ways, PassphraseFile::Refused, 1024)
    };

    assert_eq!(open(&[&device]).unwrap().as_slice(), b"a token");
    assert_eq!(open(&[&recovery]).unwrap().as_slice(), b"a token");
    assert_eq!(device.uses(), 1);

    device.refuse();
    // The device refuses: the recovery identity after it still opens the file.
    assert_eq!(open(&[&device, &recovery]).unwrap().as_slice(), b"a token");
    // Alone, the device's refusal is the error, with its name.
    match open(&[&device]) {
        Err(OpenError::Way { way, reason }) => {
            assert_eq!(way, "se-01");
            assert_eq!(
                reason.to_string(),
                "cannot unlock the keystore: the fake device refuses"
            );
        }
        other => panic!("{other:?}"),
    }
    // A way with no stanza in the file: nothing opens it.
    let other = FakeUnwrap::new("se-02", [7; 16]);
    assert!(matches!(open(&[&other]), Err(OpenError::NoWay)));
    // Past the bound, never parsed.
    assert!(matches!(
        writ_platform::unlock::open(&sealed, &[&recovery], PassphraseFile::Refused, 16),
        Err(OpenError::TooLarge(16))
    ));
    assert!(matches!(
        writ_platform::unlock::open(b"garbage", &[&recovery], PassphraseFile::Refused, 1024),
        Err(OpenError::NotAge)
    ));
}

#[test]
fn a_passphrase_file_opens_only_where_one_is_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data-key.age");
    enroll(&path);
    let sealed = std::fs::read(&path).unwrap();
    let way = PassphraseUnwrap::new(&passphrase(PASSPHRASE));
    assert!(matches!(
        writ_platform::unlock::open(&sealed, &[&way], PassphraseFile::Refused, 64 * 1024),
        Err(OpenError::Passphrase)
    ));
    assert_eq!(
        writ_platform::unlock::open(&sealed, &[&way], PassphraseFile::Allowed, 64 * 1024)
            .unwrap()
            .as_slice(),
        KEY
    );
}

#[test]
fn a_hardware_recipient_passes_the_contract() {
    let device = FakeAgreement::new([0x21; 32]).unwrap();
    let way = device.way("se-01");
    let other = FakeAgreement::new([0x22; 32]).unwrap();
    let x25519 = age::x25519::Identity::generate().to_public();
    let wrong = other.way("se-02");
    contract::keystore_unwrap(
        &way,
        &device.recipient(),
        &[&other.recipient(), &x25519],
        &[&wrong],
        true,
        &[],
    );
}

/// A `piv-p256` stanza is read before the device is asked: another recipient's, or a
/// malformed one, never reaches it; a device that refuses fails the way with its reason.
#[test]
fn the_device_sees_only_its_own_well_made_stanzas() {
    let device = FakeAgreement::new([0x21; 32]).unwrap();
    let way = device.way("se-01");
    let theirs = FakeAgreement::new([0x22; 32]).unwrap();
    let file_key = writ_platform::unlock::FileKey::new(Box::new([5; 16]));
    let for_them = theirs.recipient().wrap(&file_key).unwrap();
    assert!(
        way.unwrap(std::slice::from_ref(&for_them))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        device.uses(),
        0,
        "another recipient's stanza never reaches the device"
    );

    let mut malformed = device.recipient().wrap(&file_key).unwrap();
    malformed.args.truncate(1);
    let Err(error) = way.unwrap(std::slice::from_ref(&malformed)) else {
        panic!("a malformed stanza must be refused");
    };
    assert_eq!(
        error.to_string(),
        "cannot unlock the keystore: a piv-p256 stanza takes 2 arguments, not 1"
    );
    assert_eq!(
        device.uses(),
        0,
        "a malformed stanza never reaches the device"
    );

    let mine = device.recipient().wrap(&file_key).unwrap();
    let Ok(Some(opened)) = way.unwrap(&[for_them, mine]) else {
        panic!("its own stanza opens, after another's");
    };
    assert_eq!(age::secrecy::ExposeSecret::expose_secret(&opened), &[5; 16]);
    assert_eq!(device.uses(), 1);

    device.refuse();
    let mine = device.recipient().wrap(&file_key).unwrap();
    let Err(error) = way.unwrap(&[mine]) else {
        panic!("a refusing device opens nothing");
    };
    assert_eq!(
        error.to_string(),
        "cannot unlock the keystore: the fake device refuses"
    );
}
