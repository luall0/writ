//! The authority versions and their head: recorded in one transaction, each version following
//! the one in force, read back with every text checked against its digest; a head naming a
//! missing version, or a text changed under its digest, is corrupt.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use writ_core::authority::{AdminTarget, TextDigest};
use writ_core::units::Timestamp;
use writ_store::{AuthorityHead, AuthorityHow, AuthorityVersion, Store, StoreError};

fn version(target: AdminTarget, n: u64, text: &str, how: AuthorityHow) -> AuthorityVersion {
    AuthorityVersion {
        target,
        version: n,
        text: text.to_owned(),
        digest: TextDigest::of(text),
        how,
        document: None,
        signature: None,
        approver: None,
        applied_at: Timestamp::from_unix(1_800_000_000).unwrap(),
    }
}

fn head(policy: u64, approvers: u64, readers: u64) -> AuthorityHead {
    AuthorityHead {
        versions: BTreeMap::from([
            (AdminTarget::Policy, policy),
            (AdminTarget::Approvers, approvers),
            (AdminTarget::Readers, readers),
        ]),
        mac: format!("mac-{policy}-{approvers}-{readers}"),
    }
}

fn first(store: &Store) {
    store
        .record_authority(
            &[
                version(AdminTarget::Policy, 1, "repos: {}\n", AuthorityHow::Init),
                version(
                    AdminTarget::Approvers,
                    1,
                    "me ssh-ed25519 A\n",
                    AuthorityHow::Init,
                ),
                version(
                    AdminTarget::Readers,
                    1,
                    "mac ssh-ed25519 B\n",
                    AuthorityHow::Init,
                ),
            ],
            &head(1, 1, 1),
        )
        .unwrap();
}

#[test]
fn versions_follow_each_other_and_the_head_puts_them_in_force() {
    let store = Store::open_in_memory().unwrap();
    assert_eq!(store.authority_in_force().unwrap(), None);
    first(&store);
    let (in_force, files) = store.authority_in_force().unwrap().unwrap();
    assert_eq!(in_force, head(1, 1, 1));
    assert_eq!(files[&AdminTarget::Approvers].text, "me ssh-ed25519 A\n");

    let mut second = version(
        AdminTarget::Approvers,
        2,
        "me ssh-ed25519 C\n",
        AuthorityHow::Admin,
    );
    second.approver = Some(
        "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
            .parse()
            .unwrap(),
    );
    second.document = Some("{}".into());
    store
        .record_authority(&[second.clone()], &head(1, 2, 1))
        .unwrap();
    let (in_force, files) = store.authority_in_force().unwrap().unwrap();
    assert_eq!(in_force.versions[&AdminTarget::Approvers], 2);
    assert_eq!(files[&AdminTarget::Approvers], second);
    // The earlier version is kept.
    let earlier = store
        .authority_version(AdminTarget::Approvers, 1)
        .unwrap()
        .unwrap();
    assert_eq!(earlier.how, AuthorityHow::Init);

    // A version that doesn't follow (skipped, or repeated): refused, nothing changed.
    for n in [2, 4] {
        let error = store
            .record_authority(
                &[version(
                    AdminTarget::Approvers,
                    n,
                    "x\n",
                    AuthorityHow::Admin,
                )],
                &head(1, n, 1),
            )
            .unwrap_err();
        assert!(
            matches!(&error, StoreError::Corrupt { why, .. } if why == &format!("version {n} does not follow the one in force")),
            "{error}"
        );
    }
    assert_eq!(
        store.authority_in_force().unwrap().unwrap().0,
        head(1, 2, 1)
    );
}

#[test]
fn a_text_changed_under_its_digest_or_a_missing_version_is_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leases.db");
    let store = Store::open(&path).unwrap();
    first(&store);
    drop(store);
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE authority SET text = 'eve ssh-ed25519 E\n' WHERE target = 'approvers'",
        [],
    )
    .unwrap();
    drop(conn);
    let store = Store::open(&path).unwrap();
    match store.authority_in_force() {
        Err(StoreError::Corrupt { id, why }) => {
            assert_eq!(id, "authority approvers 1");
            assert_eq!(why, "its text is not the one its digest names");
        }
        other => panic!("expected a corrupt record, got {other:?}"),
    }
    drop(store);
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute("UPDATE authority_head SET readers = 9", [])
        .unwrap();
    conn.execute("DELETE FROM authority WHERE target = 'approvers'", [])
        .unwrap();
    drop(conn);
    let store = Store::open(&path).unwrap();
    match store.authority_in_force() {
        Err(StoreError::Corrupt { why, .. }) => assert_eq!(why, "approvers version 1 is missing"),
        other => panic!("expected a corrupt record, got {other:?}"),
    }
}
