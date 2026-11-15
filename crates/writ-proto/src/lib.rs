//! Messages between clients and the daemon.
//!
//! Everything travels over the daemon's SSH protocol (Q16 in `docs/decisions.md`): a
//! client opens a session channel, runs one command (an SSH exec request), writes a body on
//! stdin, and reads one JSON reply on stdout. The exit status is 0 when the command did what
//! was asked, 1 otherwise; on failure the daemon also writes `writ: <reason>` on stderr, for
//! people using plain `ssh`.
//!
//! | Listener | Authenticated as | Commands |
//! |---|---|---|
//! | agents | a session certificate | git, `writ-sign git <repo>` (gateway, body: [`sign::SignInput`]) |
//! | agents | a plain session key | [`Command::Request`], [`Command::DryRun`], [`Command::Policy`], [`Command::Wait`], [`Command::Close`] |
//! | approvals | a reader key | [`Command::Info`], [`Command::List`], [`Command::Show`], [`Command::Watch`], [`Command::Report`], [`Command::Approve`], [`Command::Refuse`], [`Command::Revoke`], [`Command::Prove`], [`Command::Unseal`], [`Command::AdminShow`], [`Command::AdminApply`], [`Command::TokenShow`], [`Command::TokenApply`], [`Command::RecoveryShow`], [`Command::AdminKeys`], [`Command::ScanNonce`], [`Command::Scan`], [`Command::RepoCheck`], [`Command::RepoStatus`], [`Command::TlsShow`], [`Command::TlsRotate`], [`Command::CaShow`], [`Command::CaRotate`], [`Command::AutoUnsealShow`], [`Command::MigrationShow`] |
//!
//! While the daemon is sealed, it answers only [`Command::Info`] (which then names the boot
//! to unseal) and [`Command::Unseal`]; every other request fails with "daemon sealed". While a
//! migration of the policy is owed (M7.9.6), it answers only those two, [`Command::MigrationShow`]
//! and a policy's [`Command::AdminApply`]; every other request fails with its refusal.
//!
//! Replies are wrapped in an envelope naming the daemon's version, `{"version": …, "ok": …}` or
//! `{"version": …, "error": {"message": …, "reasons": […]}}` ([`encode_reply`],
//! [`decode_versioned`]; M7.9.8). Tickets travel as their canonical bytes in a string,
//! so a client can decode them strictly (`Ticket::from_canonical`) and sign exactly them.

// This crate parses untrusted input and computes limits: every arithmetic operation is
// checked, saturating, or allowed with the reason it can't overflow.
#![deny(clippy::arithmetic_side_effects)]

mod command;
mod envelope;
mod messages;
pub mod sign;

pub use command::Command;
pub use envelope::{
    ApiError, FIRST_NAMED_VERSION, Reply, VERSION, decode_body, decode_reply, decode_versioned,
    encode_body, encode_reply, is_version,
};
pub use messages::{
    Ack, AdminApplied, AdminRequest, AdminShown, ApproveRequest, AutoUnsealShown, BackendShown,
    CaRequest, CaRotated, CaShown, ChainLink, CheckStep, Checked, CloseRequest, Count, CreatedKey,
    Decision, Decisions, DenialCount, Info, KeyRole, KeyShown, KeysShown, Listing, MigrationOwed,
    MigrationShown, OpenpgpShown, OtherLease, Others, PassphraseText, Phases, Previous,
    ProveRequest, Proved, RecoveryShown, RefuseRequest, Relation, RemovedKey, Renewal, RepoPolicy,
    Report, ReportCommit, ReportPush, RetiredCa, RevokeRequest, ScanNonce, ScanRequest, Scanned,
    ScannedKey, SealedBoot, Shown, Submitted, Summary, SyncEnded, SyncPhase, SyncProgress,
    SyncResult, SyncRunning, SyncStatus, SyncStatuses, TemplateView, TlsRequest, TlsRotated,
    TlsShown, TokenApplied, TokenRequest, TokenShown, UnsealRequest, UnsealWay, Unsealed,
    UpstreamChecked, Watched,
};

/// The largest body a command reads on stdin (a ticket file, an approval).
pub const MAX_BODY: usize = 256 * 1024;

/// The SSH user of lease holders, who connect with a session certificate issued for it
/// (`ssh://git@host`).
pub const LEASE_USER: &str = "git";

/// The SSH user of clients with a plain key: ticket submission (the session key) and the
/// approval API (a reader key).
pub const CLIENT_USER: &str = "writ";

#[cfg(test)]
mod tests {
    use writ_core::names::TicketId;

    use super::*;

    #[test]
    fn command_lines_round_trip() {
        let id = TicketId::from_parts(1_800_000_000_000, [7; 10]);
        for command in [
            Command::Request,
            Command::DryRun,
            Command::Policy {
                repo: "omega-code".parse().unwrap(),
            },
            Command::Wait { id: id.clone() },
            Command::Close { id: id.clone() },
            Command::Report { id: id.clone() },
            Command::Info,
            Command::List { all: false },
            Command::List { all: true },
            Command::Show { id: id.clone() },
            Command::Approve { id: id.clone() },
            Command::Refuse { id: id.clone() },
            Command::Revoke { id },
            Command::Prove,
            Command::Unseal,
            Command::AdminShow {
                target: writ_core::authority::AdminTarget::Readers,
            },
            Command::AdminApply,
            Command::TokenShow {
                id: "token-01".parse().unwrap(),
            },
            Command::TokenApply,
            Command::AdminKeys,
            Command::ScanNonce,
            Command::Scan,
            Command::RepoCheck {
                repo: "omega-code".parse().unwrap(),
            },
            Command::RepoStatus { repo: None },
            Command::RepoStatus {
                repo: Some("omega-code".parse().unwrap()),
            },
            // A repo named like the route's word for every repo is still that repo.
            Command::RepoStatus {
                repo: Some("status".parse().unwrap()),
            },
            // The six M7.x added (the review after M7.6, P-4).
            Command::RecoveryShow,
            Command::TlsShow,
            Command::TlsRotate,
            Command::CaShow,
            Command::CaRotate,
            Command::AutoUnsealShow,
            // M7.8.
            Command::Watch { since: None },
            Command::Watch {
                since: Some(writ_core::authority::TextDigest::of("wrt_x")),
            },
            // M7.9.6.
            Command::MigrationShow,
        ] {
            assert_eq!(Command::parse(&command.line()), Some(command));
        }
        for line in [
            "",
            "writ",
            "writ request now",
            "writ request --dry-run now",
            "writ request --dry",
            "writ policy",
            "writ policy ../x",
            "writ policy demo extra",
            "writ policy demo --all",
            "writ wait",
            "writ wait wrt_nope",
            "writ close",
            "writ close wrt_nope",
            "writ report",
            "writ ls -a",
            "writ ls --all extra",
            "writ  ls",
            "writ sign wrt_01JD8X0000000000000000000",
            "writ prove agent-01",
            "writ prove-key",
            "writ unseal now",
            "writ migration now",
            "writ migrate",
            "writ admin",
            "writ admin show",
            "writ admin show templates",
            "writ admin show policy extra",
            "writ admin apply policy",
            "writ admin token",
            "writ admin token token-01",
            "writ admin token show",
            "writ admin token show ../x",
            "writ admin token show token-01 extra",
            "writ admin token apply token-01",
            "writ admin token apply extra more",
            "writ admin token remove token-01",
            "writ admin keys extra",
            "writ admin keys --public",
            "writ admin scan extra",
            "writ admin check",
            "writ admin check ../x",
            "writ admin check demo extra",
            // A watch's cursor is 64 lowercase hex characters, and only one.
            "writ watch extra",
            "writ watch 0",
            &format!("writ watch {}", "A".repeat(64)),
            &format!("writ watch {}", "a".repeat(63)),
            &format!("writ watch {}", "a".repeat(65)),
            &format!("writ watch {} {}", "a".repeat(64), "a".repeat(64)),
            &format!("writ watch  {}", "a".repeat(64)),
            "git-upload-pack 'x'",
        ] {
            assert_eq!(Command::parse(line), None, "{line:?}");
        }
    }

    #[test]
    fn http_routes_round_trip_and_agent_commands_have_none() {
        let id = TicketId::from_parts(1_800_000_000_000, [7; 10]);
        for command in [
            Command::Info,
            Command::List { all: false },
            Command::List { all: true },
            Command::Show { id: id.clone() },
            Command::Report { id: id.clone() },
            Command::Approve { id: id.clone() },
            Command::Refuse { id: id.clone() },
            Command::Revoke { id: id.clone() },
            Command::Prove,
            Command::Unseal,
            Command::AdminShow {
                target: writ_core::authority::AdminTarget::Policy,
            },
            Command::AdminApply,
            Command::TokenShow {
                id: "token-01".parse().unwrap(),
            },
            Command::TokenApply,
            Command::AdminKeys,
            Command::ScanNonce,
            Command::Scan,
            Command::RepoCheck {
                repo: "omega-code".parse().unwrap(),
            },
            Command::RepoStatus { repo: None },
            Command::RepoStatus {
                repo: Some("omega-code".parse().unwrap()),
            },
            // A repo named like the route's word for every repo is still that repo.
            Command::RepoStatus {
                repo: Some("status".parse().unwrap()),
            },
            // The six M7.x added (the review after M7.6, P-4).
            Command::RecoveryShow,
            Command::TlsShow,
            Command::TlsRotate,
            Command::CaShow,
            Command::CaRotate,
            Command::AutoUnsealShow,
            Command::Watch { since: None },
            Command::Watch {
                since: Some(writ_core::authority::TextDigest::of("wrt_x")),
            },
            Command::MigrationShow,
        ] {
            let (method, path) = command.http_route().unwrap();
            assert_eq!(Command::from_http(method, &path), Some(command));
        }
        // Every approval command is one by name, never by falling outside the agent ones.
        for command in [
            Command::RecoveryShow,
            Command::TlsShow,
            Command::TlsRotate,
            Command::CaShow,
            Command::CaRotate,
            Command::AutoUnsealShow,
            Command::Watch { since: None },
            Command::MigrationShow,
        ] {
            assert!(command.is_approval() && !command.is_agent(), "{command:?}");
        }
        assert_eq!(Command::Request.http_route(), None);
        assert_eq!(Command::DryRun.http_route(), None);
        let policy = Command::Policy {
            repo: "demo".parse().unwrap(),
        };
        assert_eq!(policy.http_route(), None);
        assert!(!policy.is_approval() && Command::DryRun.is_agent());
        assert_eq!(Command::Wait { id: id.clone() }.http_route(), None);
        assert_eq!(Command::Close { id: id.clone() }.http_route(), None);
        for (method, path) in [
            ("POST", "/v1/info"),
            ("GET", "/v1/tickets?all=1"),
            ("GET", "/v1/tickets?all=true&x=1"),
            ("GET", "/v1/tickets/wrt_nope"),
            ("GET", &format!("/v1/tickets/{id}/approve")),
            ("POST", &format!("/v1/tickets/{id}/report")),
            ("POST", &format!("/v1/tickets/{id}/close")),
            ("POST", &format!("/v1/tickets/{id}/sign")),
            ("POST", "/v1/request"),
            ("GET", "/v1/policy/demo"),
            ("GET", "/v1/proofs"),
            ("POST", "/v1/proofs/x"),
            ("POST", "/v1/proofs?key=agent-01"),
            ("GET", "/v1/unseal"),
            ("POST", "/v1/unseal/x"),
            ("GET", "/v1/admin"),
            ("GET", "/v1/admin/templates"),
            ("POST", "/v1/admin/policy"),
            ("GET", "/v1/admin/policy/x"),
            ("GET", "/v1/tokens"),
            ("GET", "/v1/tokens/..%2Fx"),
            ("GET", "/v1/tokens/token-01/x"),
            ("POST", "/v1/tokens/token-01"),
            ("GET", "/v1/tokens/token-01?show=1"),
            ("GET", "/v2/info"),
            ("GET", "/v1/info/"),
            ("GET", "v1/info"),
            ("POST", "/v1/tickets/watch"),
            ("GET", "/v1/tickets/watch/"),
            ("GET", "/v1/tickets/watch?since="),
            ("GET", "/v1/tickets/watch?since=xyz"),
            (
                "GET",
                &format!("/v1/tickets/watch?since={}", "A".repeat(64)),
            ),
            (
                "GET",
                &format!("/v1/tickets/watch?cursor={}", "a".repeat(64)),
            ),
            (
                "GET",
                &format!("/v1/tickets/watch?since={}&x=1", "a".repeat(64)),
            ),
            (
                "GET",
                &format!("/v1/tickets/watch?since={}", "a".repeat(65)),
            ),
        ] {
            assert_eq!(Command::from_http(method, path), None, "{method} {path}");
        }
    }

    #[test]
    fn replies_round_trip_and_errors_are_typed() {
        let ok: Result<Info, ApiError> = Ok(Info {
            decisions: Decisions::Open,
            sealed: None,
            recipient: None,
            token_recipients: Vec::new(),
            unseal: None,
            rotation_owed: Vec::new(),
            migration: None,
        });
        let bytes = encode_reply(&ok);
        assert_eq!(
            bytes,
            format!("{{\"version\":\"{VERSION}\",\"ok\":{{\"decisions\":\"open\"}}}}\n").as_bytes()
        );
        assert_eq!(decode_reply::<Info>(&bytes), ok);

        let err: Result<Info, ApiError> = Err(ApiError::with_reasons("rejected", vec!["a".into()]));
        assert_eq!(decode_reply::<Info>(&encode_reply(&err)), err);
        for bad in [&b"not json"[..], br#"{"ok":{"decisions":"open"},"x":1}"#] {
            let error = decode_reply::<Info>(bad).unwrap_err();
            assert!(error.message.starts_with("unreadable reply"), "{error:?}");
        }

        let decision = Decision::Refused {
            feedback: "no".into(),
            signed_by: None,
        };
        let bytes = encode_reply(&Ok::<_, ApiError>(decision.clone()));
        assert_eq!(
            bytes,
            format!(
                "{{\"version\":\"{VERSION}\",\"ok\":{{\"status\":\"refused\",\"feedback\":\"no\",\"signed_by\":null}}}}\n"
            )
            .as_bytes()
        );
        assert_eq!(decode_reply::<Decision>(&bytes), Ok(decision));
    }

    /// M7.9.8: every reply names the daemon's version, read before the rest; a reply with
    /// none (a daemon before 0.2.0) is read as before; a version that isn't one makes the
    /// reply unreadable; a reply that doesn't parse names both versions when they differ.
    #[test]
    fn a_reply_names_the_daemon_s_version_and_an_unreadable_one_names_both() {
        assert!(is_version(VERSION), "{VERSION}");
        let open = r#""ok":{"decisions":"open"}"#;
        let info = |text: String| decode_versioned::<Info>(text.as_bytes());
        // This build's, and another's: read, the version kept.
        let ours = info(format!(r#"{{"version":"{VERSION}",{open}}}"#));
        assert_eq!(ours.version.as_deref(), Some(VERSION));
        assert!(ours.readable && ours.result.is_ok(), "{ours:?}");
        let theirs = info(format!(r#"{{"version":"9.10.11",{open}}}"#));
        assert_eq!(theirs.version.as_deref(), Some("9.10.11"));
        assert!(theirs.result.is_ok(), "{theirs:?}");
        // An error reply names it too.
        let error = info(r#"{"version":"9.10.11","error":{"message":"no"}}"#.to_owned());
        assert_eq!(error.version.as_deref(), Some("9.10.11"));
        assert_eq!(error.result, Err(ApiError::new("no")));
        assert!(error.readable);
        // None: a daemon before the first version that names itself, read as before.
        let before = info(format!("{{{open}}}"));
        assert_eq!(before.version, None);
        assert!(before.result.is_ok(), "{before:?}");

        // A version that isn't one: the reply is unreadable, whatever else it holds.
        let long = format!("{}.0.0", "1".repeat(29));
        assert!(
            is_version(&format!("{}.0.0", "1".repeat(28))),
            "32 bytes is the bound"
        );
        for bad in [
            r#""v0.1.0""#,
            r#""0.1""#,
            r#""0.1.0.0""#,
            r#""01.0.0""#,
            r#""0.1.0-rc.1""#,
            r#""0..1""#,
            r#""""#,
            r#"1"#,
            r#"null"#,
            r#"["0.1.0"]"#,
            &format!(r#""{long}""#),
        ] {
            let read = info(format!(r#"{{"version":{bad},{open}}}"#));
            assert_eq!(read.version, None, "{bad}");
            assert!(!read.readable, "{bad}");
            assert_eq!(
                read.result,
                Err(ApiError::new(
                    "unreadable reply from the daemon: its version is not MAJOR.MINOR.PATCH"
                )),
                "{bad}"
            );
        }

        // A payload that doesn't parse: as before from this build's version; both named
        // from another's, or from one that names none.
        let changed = r#""ok":{"decisions":"open","new":1}"#;
        let same = info(format!(r#"{{"version":"{VERSION}",{changed}}}"#));
        let message = same.result.unwrap_err().message;
        assert!(
            message.starts_with("unreadable reply from the daemon: unknown field `new`"),
            "{message}"
        );
        let other = info(format!(r#"{{"version":"9.10.11",{changed}}}"#));
        assert!(!other.readable);
        assert_eq!(other.version.as_deref(), Some("9.10.11"));
        let message = other.result.unwrap_err().message;
        assert!(
            message.starts_with(&format!(
                "unreadable reply from writd 9.10.11, and this writ is {VERSION}: install the \
                 same version of both (the changelog's Upgrading): unknown field `new`"
            )),
            "{message}"
        );
        let unnamed = info(format!("{{{changed}}}"));
        let message = unnamed.result.unwrap_err().message;
        assert!(
            message.starts_with(&format!(
                "unreadable reply from a daemon that names no version (a writd before 0.2.0), \
                 and this writ is {VERSION}: install the same version of both (the changelog's \
                 Upgrading): unknown field `new`"
            )),
            "{message}"
        );
        // Any other field beside the version is refused as before, and so are a second
        // variant and none at all: the envelope is one of `ok` and `error`, exactly.
        for bad in [
            format!(r#"{{"version":"{VERSION}",{open},"x":1}}"#),
            format!(r#"{{"version":"{VERSION}",{open},"error":{{"message":"no"}}}}"#),
            format!(r#"{{"version":"{VERSION}"}}"#),
        ] {
            let read = info(bad.clone());
            assert!(!read.readable, "{bad}");
            assert_eq!(
                read.result,
                Err(ApiError::new(
                    "unreadable reply from the daemon: invalid value: map, expected map with a \
                     single key"
                )),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_passphrase_on_the_wire_is_never_printed() {
        let request = UnsealRequest {
            passphrase: PassphraseText::new("correct horse battery staple".to_owned()),
            unseal: "{}".to_owned(),
            signature: "sig".to_owned(),
        };
        let shown = format!("{request:?}");
        assert!(!shown.contains("horse"), "{shown}");
        let bytes = encode_body(&request).unwrap();
        let back: UnsealRequest = decode_body(&bytes).unwrap();
        assert_eq!(back.passphrase.expose(), "correct horse battery staple");
        // A sealed boot in `info`, absent once open.
        let info = Info {
            decisions: Decisions::Signed,
            sealed: Some(SealedBoot {
                daemon: "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
                    .parse()
                    .unwrap(),
                nonce: writ_core::signed::BootNonce::from_bytes([1; 16]),
            }),
            recipient: Some(
                "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p".to_owned(),
            ),
            token_recipients: vec!["age1se1example".to_owned()],
            unseal: Some(crate::UnsealWay::Hardware),
            rotation_owed: vec!["the recovery recipient age1example replaced".to_owned()],
            migration: Some(crate::MigrationOwed { from: 1, to: 2 }),
        };
        let bytes = encode_reply(&Ok::<_, ApiError>(info.clone()));
        assert_eq!(decode_reply::<Info>(&bytes), Ok(info));
        let open = encode_reply(&Ok::<_, ApiError>(Info {
            decisions: Decisions::Signed,
            sealed: None,
            recipient: None,
            token_recipients: Vec::new(),
            unseal: None,
            rotation_owed: Vec::new(),
            migration: None,
        }));
        assert_eq!(
            open,
            format!("{{\"version\":\"{VERSION}\",\"ok\":{{\"decisions\":\"signed\"}}}}\n")
                .as_bytes()
        );
        // The rotation owed (the review after M7.6, S-8) on the wire, under its name.
        let bytes = String::from_utf8(bytes).unwrap();
        assert!(
            bytes.contains("\"rotation_owed\":[\"the recovery recipient age1example replaced\"]"),
            "{bytes}"
        );
        // The migration owed (M7.9.6) too; none, left out (above).
        assert!(
            bytes.contains("\"migration\":{\"from\":1,\"to\":2}"),
            "{bytes}"
        );
    }

    #[test]
    fn what_a_change_did_to_the_keystore_round_trips_and_is_left_out_when_nothing() {
        let applied = AdminApplied {
            target: writ_core::authority::AdminTarget::Policy,
            version: 3,
            digest: writ_core::authority::TextDigest::of("policy"),
            signed_by: "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
                .parse()
                .unwrap(),
            created: Vec::new(),
            revoked: Vec::new(),
            removed: Vec::new(),
            keystore: vec!["the keystore's data key rotated (x)".to_owned()],
        };
        let bytes = encode_reply(&Ok::<_, ApiError>(applied.clone()));
        let text = String::from_utf8_lossy(&bytes).into_owned();
        assert!(
            text.contains("\"keystore\":[\"the keystore's data key rotated (x)\"]"),
            "{text}"
        );
        assert_eq!(decode_reply::<AdminApplied>(&bytes), Ok(applied.clone()));
        let none = encode_reply(&Ok::<_, ApiError>(AdminApplied {
            keystore: Vec::new(),
            ..applied
        }));
        assert!(!String::from_utf8_lossy(&none).contains("keystore"));
    }

    /// The review after M7.6 (A-6): a token's change count travels in both replies, and a
    /// reply without it (the format before) is unreadable, never read as count 0.
    #[test]
    fn a_token_s_change_count_round_trips_and_is_required() {
        let daemon: writ_core::names::KeyFingerprint =
            "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
                .parse()
                .unwrap();
        let shown = TokenShown {
            daemon: daemon.clone(),
            id: "token-01".parse().unwrap(),
            version: 4,
            previous: writ_core::authority::PreviousToken::None,
        };
        let bytes = encode_reply(&Ok::<_, ApiError>(shown.clone()));
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.contains(r#""version":4,"previous":"none""#), "{text}");
        assert_eq!(decode_reply::<TokenShown>(&bytes), Ok(shown));
        let without = text.replace(r#""version":4,"#, "");
        let error = decode_reply::<TokenShown>(without.as_bytes()).unwrap_err();
        assert!(
            error.message.contains("missing field `version`"),
            "{error:?}"
        );

        let applied = TokenApplied {
            id: "token-01".parse().unwrap(),
            version: 5,
            digest: writ_core::authority::TextDigest::of_bytes(b"file"),
            replaced: writ_core::authority::PreviousToken::None,
            signed_by: daemon,
        };
        let bytes = encode_reply(&Ok::<_, ApiError>(applied.clone()));
        assert_eq!(decode_reply::<TokenApplied>(&bytes), Ok(applied));
    }
}
