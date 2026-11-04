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
//! | agents | a plain session key | [`Command::Request`], [`Command::Wait`], [`Command::Close`] |
//! | approvals | a reader key | [`Command::Info`], [`Command::List`], [`Command::Show`], [`Command::Report`], [`Command::Approve`], [`Command::Refuse`], [`Command::Revoke`], [`Command::Prove`], [`Command::Unseal`], [`Command::AdminShow`], [`Command::AdminApply`], [`Command::TokenShow`], [`Command::TokenApply`] |
//!
//! While the daemon is sealed, it answers only [`Command::Info`] (which then names the boot
//! to unseal) and [`Command::Unseal`]; every other request fails with "daemon sealed".
//!
//! Replies are wrapped in an envelope, `{"ok": …}` or `{"error": {"message": …, "reasons": […]}}`
//! ([`encode_reply`], [`decode_reply`]). Tickets travel as their canonical bytes in a string,
//! so a client can decode them strictly (`Ticket::from_canonical`) and sign exactly them.

// This crate parses untrusted input and computes limits: every arithmetic operation is
// checked, saturating, or allowed with the reason it can't overflow.
#![deny(clippy::arithmetic_side_effects)]

mod command;
mod envelope;
mod messages;
pub mod sign;

pub use command::Command;
pub use envelope::{ApiError, decode_body, decode_reply, encode_body, encode_reply};
pub use messages::{
    Ack, AdminApplied, AdminRequest, AdminShown, ApproveRequest, ChainLink, CloseRequest, Count,
    CreatedKey, Decision, Decisions, DenialCount, Info, KeyRole, Listing, OtherLease, Others,
    PassphraseText, Phases, Previous, ProveRequest, Proved, RefuseRequest, Relation, Renewal,
    Report, ReportCommit, ReportPush, RevokeRequest, SealedBoot, Shown, Submitted, Summary,
    TokenApplied, TokenRequest, TokenShown, UnsealRequest, Unsealed,
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
        ] {
            assert_eq!(Command::parse(&command.line()), Some(command));
        }
        for line in [
            "",
            "writ",
            "writ request now",
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
        ] {
            let (method, path) = command.http_route().unwrap();
            assert_eq!(Command::from_http(method, &path), Some(command));
        }
        assert_eq!(Command::Request.http_route(), None);
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
        });
        let bytes = encode_reply(&ok);
        assert_eq!(bytes, b"{\"ok\":{\"decisions\":\"open\"}}\n");
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
            b"{\"ok\":{\"status\":\"refused\",\"feedback\":\"no\",\"signed_by\":null}}\n"
        );
        assert_eq!(decode_reply::<Decision>(&bytes), Ok(decision));
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
        };
        let bytes = encode_reply(&Ok::<_, ApiError>(info.clone()));
        assert_eq!(decode_reply::<Info>(&bytes), Ok(info));
        let open = encode_reply(&Ok::<_, ApiError>(Info {
            decisions: Decisions::Signed,
            sealed: None,
            recipient: None,
        }));
        assert_eq!(open, b"{\"ok\":{\"decisions\":\"signed\"}}\n");
    }
}
