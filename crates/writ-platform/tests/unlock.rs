//! Every keystore unlock, real and fake, through the unlock contract, and the passphrase
//! file's own guarantees.

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
use writ_platform::testing::FakeUnlock;
use writ_platform::unlock::passphrase::PassphraseUnlock;
use writ_platform::{DataKey, KeystoreUnlock, Passphrase, PlatformError, UnsealRequest};

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

fn request(text: &str) -> UnsealRequest {
    UnsealRequest::with_passphrase(passphrase(text))
}

fn enroll(path: &Path) -> PassphraseUnlock {
    PassphraseUnlock::enroll_with_work_factor(
        path,
        &passphrase(PASSPHRASE),
        &DataKey::from_bytes(KEY),
        LOG_N,
    )
    .unwrap()
}

fn unlock_error(unlock: &PassphraseUnlock, text: &str) -> String {
    match unlock.unlock(&request(text)) {
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
fn passphrase_unlock_passes_the_contract() {
    let dir = tempfile::tempdir().unwrap();
    let unlock = enroll(&dir.path().join("data-key.age"));
    contract::keystore_unlock_passphrase(&unlock, PASSPHRASE, &KEY);
}

#[test]
fn passphrase_unlock_reopened_from_its_path_passes_the_contract() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data-key.age");
    enroll(&path);
    contract::keystore_unlock_passphrase(&PassphraseUnlock::new(&path), PASSPHRASE, &KEY);
}

#[test]
fn fake_unlock_passes_the_contract() {
    contract::keystore_unlock_passphrase(&FakeUnlock::new(PASSPHRASE, KEY), PASSPHRASE, &KEY);
}

#[test]
fn enroll_with_the_default_work_factor_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data-key.age");
    let unlock =
        PassphraseUnlock::enroll(&path, &passphrase(PASSPHRASE), &DataKey::from_bytes(KEY))
            .unwrap();
    assert_eq!(
        unlock.unlock(&request(PASSPHRASE)).unwrap().as_bytes(),
        &KEY
    );
}

#[test]
fn enroll_refuses_to_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data-key.age");
    std::fs::write(&path, b"precious").unwrap();
    let result = PassphraseUnlock::enroll_with_work_factor(
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
    let again = PassphraseUnlock::enroll_with_work_factor(
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
fn a_wrong_or_missing_passphrase_fails() {
    let dir = tempfile::tempdir().unwrap();
    let unlock = enroll(&dir.path().join("data-key.age"));
    let error = unlock_error(&unlock, "Correct horse battery staple");
    assert!(error.contains("wrong passphrase"), "{error}");
    let missing = unlock.unlock(&UnsealRequest::default());
    match missing {
        Err(PlatformError::Unlock(why)) => assert_eq!(why, "a passphrase is required"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_missing_file_fails_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let unlock = PassphraseUnlock::new(dir.path().join("absent.age"));
    unlock_error(&unlock, PASSPHRASE);
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
        let unlock = PassphraseUnlock::new(&path);
        let error = unlock_error(&unlock, PASSPHRASE);
        assert!(!error.contains(PASSPHRASE), "{what}: {error}");
    }
}

#[test]
fn a_wrapped_key_of_the_wrong_length_fails() {
    let dir = tempfile::tempdir().unwrap();
    for len in [0usize, 16, 31, 33, 64] {
        let path = dir.path().join(format!("len-{len}.age"));
        wrap_raw(&path, &vec![7u8; len]);
        let error = unlock_error(&PassphraseUnlock::new(&path), PASSPHRASE);
        assert!(error.contains("32-byte"), "{len}: {error}");
    }
    // The same plaintext path works for exactly 32 bytes.
    let path = dir.path().join("len-32.age");
    wrap_raw(&path, &KEY);
    let key = PassphraseUnlock::new(&path)
        .unlock(&request(PASSPHRASE))
        .unwrap();
    assert_eq!(key.as_bytes(), &KEY);
}

#[test]
fn a_huge_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("huge.age");
    write_private(&path, &vec![b'a'; 200 * 1024]);
    let error = unlock_error(&PassphraseUnlock::new(&path), PASSPHRASE);
    assert!(error.contains("is larger than"), "{error}");
}

#[test]
fn a_wrapped_key_others_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data-key.age");
    let unlock = enroll(&path);
    assert!(unlock.unlock(&request(PASSPHRASE)).is_ok());
    // A copy others can read allows an offline attack on the passphrase.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = unlock_error(&unlock, PASSPHRASE);
    assert!(
        error.contains("accessible by group or others (mode 644)"),
        "{error}"
    );
}

#[test]
fn an_invalid_work_factor_is_a_config_error() {
    let dir = tempfile::tempdir().unwrap();
    for log_n in [0u8, 64, 200] {
        let result = PassphraseUnlock::enroll_with_work_factor(
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
