//! The host key scan's decision (M6.2): only an approver's signed `writ-scan/1` naming this
//! daemon and a nonce it handed out (used once, for a few minutes), within the scans' rate;
//! every refusal logged with its code. And the upstream check's: only a repo in the registry,
//! within the checks' rate.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::sync::Arc;

use writ_approval::testing::{TestService, TestServiceBuilder};
use writ_approval::{
    MAX_CHECKS_A_MINUTE, MAX_NONCES, MAX_SCANS_A_MINUTE, NONCE_SECONDS, RefusalCode, ServiceError,
};
use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::lease::APPROVAL_NAMESPACE;
use writ_core::signed::{BootNonce, Scan};
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::PrivateKey;
use writ_crypto::sshsig;
use writ_platform::testing::FakeClock;
use writ_proto::ScanRequest;

const POLICY: &str = include_str!("../../writ-core/tests/fixtures/policy.yaml");

fn facts() -> CallerFacts {
    CallerFacts {
        source_addr: Some("192.0.2.9".parse().unwrap()),
        process_chain: None,
    }
}

fn signed(signer: &PrivateKey, scan: &Scan) -> ScanRequest {
    let document = scan.canonical_bytes().unwrap();
    ScanRequest {
        signature: sshsig::sign(signer, APPROVAL_NAMESPACE, &document).unwrap(),
        document: String::from_utf8(document).unwrap(),
    }
}

/// A scan of forgejo.home:2222 with a nonce this service handed out.
fn scan(h: &TestService) -> Scan {
    let nonce = h.service.scan_nonce().unwrap();
    assert_eq!(&nonce.daemon, h.service.daemon());
    Scan::new(
        nonce.daemon,
        "forgejo.home".to_owned().try_into().unwrap(),
        2222,
        nonce.nonce,
    )
}

fn refused<T: std::fmt::Debug>(result: Result<T, ServiceError>, code: RefusalCode) -> String {
    match result {
        Err(error) => {
            assert_eq!(error.code(), Some(code), "{error}");
            error.to_string()
        }
        Ok(value) => panic!("expected a refusal ({code:?}), got {value:?}"),
    }
}

/// The `scan` lines with `result`.
fn scan_lines(h: &TestService, result: &str) -> Vec<serde_json::Value> {
    h.audit()
        .into_iter()
        .filter(|l| l["event"] == "scan" && l["result"] == result)
        .collect()
}

#[test]
fn a_scan_runs_only_on_an_approver_s_signature_over_this_daemon_and_a_fresh_nonce() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock::at_unix(1_800_000_000));
    let h = TestServiceBuilder::new(POLICY)
        .clock(clock.clone())
        .build(dir.path());

    // Signed by an approver, this daemon, a nonce it handed out: taken, the nonce used.
    let good = scan(&h);
    let request = signed(&h.approver, &good);
    let checked = h.service.check_scan(&request, &facts()).unwrap();
    assert_eq!(checked.scan(), &good);
    assert_eq!(checked.approver().as_str().len(), 50);
    // The same document again (a replay): the nonce is used.
    let why = refused(h.service.check_scan(&request, &facts()), RefusalCode::Scan);
    assert!(
        why.contains("the scan's nonce is unknown, used or expired"),
        "{why}"
    );

    // A key that isn't an approver's (a reader key alone signs nothing that counts).
    let stranger = generate(KeyKind::Ed25519).unwrap();
    let why = refused(
        h.service
            .check_scan(&signed(&stranger, &scan(&h)), &facts()),
        RefusalCode::Signature,
    );
    assert!(why.contains("which is not in approvers"), "{why}");
    // No signature over the bytes sent (another document signed).
    let mut swapped = signed(&h.approver, &scan(&h));
    swapped.document = String::from_utf8(scan(&h).canonical_bytes().unwrap()).unwrap();
    refused(
        h.service.check_scan(&swapped, &facts()),
        RefusalCode::Signature,
    );
    // Another daemon's document.
    let mut other = scan(&h);
    other.daemon = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
        .parse()
        .unwrap();
    let why = refused(
        h.service.check_scan(&signed(&h.approver, &other), &facts()),
        RefusalCode::Scan,
    );
    assert!(why.contains("the scan names daemon SHA256:47DEQ"), "{why}");
    // A nonce it never handed out.
    let mut made_up = scan(&h);
    made_up.nonce = BootNonce::from_bytes([9; 16]);
    refused(
        h.service
            .check_scan(&signed(&h.approver, &made_up), &facts()),
        RefusalCode::Scan,
    );
    // Not a writ-scan/1 at all.
    let not_one = ScanRequest {
        document: "{\"kind\":\"writ-unseal/1\"}".to_owned(),
        signature: "x".to_owned(),
    };
    let why = refused(h.service.check_scan(&not_one, &facts()), RefusalCode::Scan);
    assert!(why.starts_with("not a writ-scan/1 document"), "{why}");
    // An expired nonce: past NONCE_SECONDS, refused; just within, taken.
    let late = scan(&h);
    clock.advance(u64::try_from(NONCE_SECONDS).unwrap());
    refused(
        h.service.check_scan(&signed(&h.approver, &late), &facts()),
        RefusalCode::Scan,
    );
    let in_time = scan(&h);
    clock.advance(u64::try_from(NONCE_SECONDS).unwrap() - 1);
    h.service
        .check_scan(&signed(&h.approver, &in_time), &facts())
        .unwrap();
    // Every refusal is a `scan` line, denied.
    assert_eq!(scan_lines(&h, "denied").len(), 7, "{:?}", h.audit());
}

/// The review after M7.6 (T-11): the nonce cap on its other side: with [`MAX_NONCES`] out,
/// the oldest still counts; one more evicts it.
#[test]
fn the_oldest_nonce_stays_while_at_most_max_nonces_are_out() {
    let dir = tempfile::tempdir().unwrap();
    let h = TestServiceBuilder::new(POLICY).build(dir.path());
    let oldest = scan(&h);
    for _ in 0..MAX_NONCES - 1 {
        scan(&h);
    }
    h.service
        .check_scan(&signed(&h.approver, &oldest), &facts())
        .unwrap();
    // One past: the oldest of those out now goes.
    let next = scan(&h);
    for _ in 0..MAX_NONCES {
        scan(&h);
    }
    let why = refused(
        h.service.check_scan(&signed(&h.approver, &next), &facts()),
        RefusalCode::Scan,
    );
    assert!(
        why.contains("the scan's nonce is unknown, used or expired"),
        "{why}"
    );
}

#[test]
fn nonces_and_scans_are_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock::at_unix(1_800_000_000));
    let h = TestServiceBuilder::new(POLICY)
        .clock(clock.clone())
        .build(dir.path());
    // Past MAX_NONCES handed out, the oldest goes.
    let first = scan(&h);
    for _ in 0..MAX_NONCES {
        scan(&h);
    }
    refused(
        h.service.check_scan(&signed(&h.approver, &first), &facts()),
        RefusalCode::Scan,
    );
    // MAX_SCANS_A_MINUTE a minute: one more refused, taken again a minute later.
    for _ in 0..MAX_SCANS_A_MINUTE - 1 {
        h.service
            .check_scan(&signed(&h.approver, &scan(&h)), &facts())
            .unwrap();
    }
    // The nonce of `first` was refused before the rate counted it: one left.
    h.service
        .check_scan(&signed(&h.approver, &scan(&h)), &facts())
        .unwrap();
    let why = refused(
        h.service
            .check_scan(&signed(&h.approver, &scan(&h)), &facts()),
        RefusalCode::Scan,
    );
    assert!(why.contains("scans a minute"), "{why}");
    clock.advance(60);
    h.service
        .check_scan(&signed(&h.approver, &scan(&h)), &facts())
        .unwrap();
}

/// The review after M7.6 (A-5's remainder): a scan's line was written after the daemon had
/// connected out, best effort. It is written first now, naming the target and the approver,
/// and a log that can't take it refuses the scan (no line, no connection out); what the scan
/// read is its own line after.
#[test]
fn a_scan_s_line_comes_before_the_daemon_connects_out_and_none_refuses_it() {
    let dir = tempfile::tempdir().unwrap();
    let h = TestServiceBuilder::new(POLICY).build(dir.path());
    let checked = h
        .service
        .check_scan(&signed(&h.approver, &scan(&h)), &facts())
        .unwrap();
    h.audit_breaker.set_broken(true);
    let error = h.service.scan_starting(&checked, &facts()).unwrap_err();
    assert!(matches!(error, ServiceError::AuditLog(_)), "{error:?}");
    h.audit_breaker.set_broken(false);
    assert!(scan_lines(&h, "allowed").is_empty(), "nothing written");
    h.service.scan_starting(&checked, &facts()).unwrap();
    let started = scan_lines(&h, "allowed");
    assert_eq!(started.len(), 1);
    assert_eq!(started[0]["reason"], "forgejo.home:2222: scanning");
    assert_eq!(started[0]["approver"], checked.approver().as_str());
    h.service.scan_logged(
        &checked,
        Ok(&["SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU".to_owned()]),
        &facts(),
    );
    let done = scan_lines(&h, "done");
    assert_eq!(done.len(), 1);
    assert_eq!(
        done[0]["reason"],
        "forgejo.home:2222: SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
    );
}

#[test]
fn a_check_reaches_only_a_registered_repo_within_its_rate() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock::at_unix(1_800_000_000));
    let h = TestServiceBuilder::new(POLICY)
        .clock(clock.clone())
        .build(dir.path());
    let repo = "omega-code".parse().unwrap();
    refused(
        h.service
            .check_allowed(&"nowhere".parse().unwrap(), &facts()),
        RefusalCode::UnknownRepo,
    );
    for _ in 0..MAX_CHECKS_A_MINUTE {
        h.service.check_allowed(&repo, &facts()).unwrap();
    }
    refused(h.service.check_allowed(&repo, &facts()), RefusalCode::Check);
    clock.advance(60);
    h.service.check_allowed(&repo, &facts()).unwrap();
    let denied: Vec<_> = h
        .audit()
        .into_iter()
        .filter(|l| l["event"] == "check" && l["result"] == "denied")
        .collect();
    assert_eq!(denied.len(), 2, "{denied:?}");
}
