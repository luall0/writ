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
//! | agents | a session certificate | git, `writ-sign git` (gateway) |
//! | agents | a plain session key | [`Command::Request`], [`Command::Wait`] |
//! | approvals | any key | [`Command::Info`], [`Command::List`], [`Command::Show`], [`Command::Approve`], [`Command::Refuse`], [`Command::Revoke`] |
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

pub use command::Command;
pub use envelope::{ApiError, decode_body, decode_reply, encode_body, encode_reply};
pub use messages::{
    Ack, ApproveRequest, Decision, Decisions, Info, Listing, Previous, RefuseRequest, Relation,
    RevokeRequest, Shown, Submitted, Summary,
};

/// The largest body a command reads on stdin (a ticket file, an approval).
pub const MAX_BODY: usize = 256 * 1024;

/// The SSH user of lease holders, who connect with a session certificate issued for it
/// (`ssh://git@host`).
pub const LEASE_USER: &str = "git";

/// The SSH user of clients with a plain key: ticket submission (the session key) and the
/// approval API (any key).
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
            Command::Info,
            Command::List { all: false },
            Command::List { all: true },
            Command::Show { id: id.clone() },
            Command::Approve { id: id.clone() },
            Command::Refuse { id: id.clone() },
            Command::Revoke { id },
        ] {
            assert_eq!(Command::parse(&command.line()), Some(command));
        }
        for line in [
            "",
            "writ",
            "writ request now",
            "writ wait",
            "writ wait wrt_nope",
            "writ ls -a",
            "writ ls --all extra",
            "writ  ls",
            "writ sign wrt_01JD8X0000000000000000000",
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
            Command::Approve { id: id.clone() },
            Command::Refuse { id: id.clone() },
            Command::Revoke { id: id.clone() },
        ] {
            let (method, path) = command.http_route().unwrap();
            assert_eq!(Command::from_http(method, &path), Some(command));
        }
        assert_eq!(Command::Request.http_route(), None);
        assert_eq!(Command::Wait { id: id.clone() }.http_route(), None);
        for (method, path) in [
            ("POST", "/v1/info"),
            ("GET", "/v1/tickets?all=1"),
            ("GET", "/v1/tickets?all=true&x=1"),
            ("GET", "/v1/tickets/wrt_nope"),
            ("GET", &format!("/v1/tickets/{id}/approve")),
            ("POST", &format!("/v1/tickets/{id}/sign")),
            ("POST", "/v1/request"),
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
        });
        let bytes = encode_reply(&ok);
        assert_eq!(bytes, b"{\"ok\":{\"decisions\":\"open\"}}\n");
        assert_eq!(decode_reply::<Info>(&bytes), ok);

        let err: Result<Info, ApiError> = Err(ApiError::with_reasons("rejected", vec!["a".into()]));
        assert_eq!(decode_reply::<Info>(&encode_reply(&err)), err);
        assert!(decode_reply::<Info>(b"not json").is_err());
        assert!(decode_reply::<Info>(br#"{"ok":{"decisions":"open"},"x":1}"#).is_err());

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
}
