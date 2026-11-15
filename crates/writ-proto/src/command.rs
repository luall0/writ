//! The commands: an SSH exec line (`writ approve <id>`) or, for the approval API, an HTTPS
//! route (`POST /v1/tickets/<id>/approve`).

use writ_core::authority::{AdminTarget, TextDigest};
use writ_core::names::{KeyId, RepoName, TicketId};

/// A command run over the daemon's SSH protocol (the exec line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `writ request`: submit the ticket file on stdin; the connection's key is the session
    /// key. Reply: [`Submitted`].
    Request,
    /// `writ request --dry-run`: every check a submission gets, on the ticket file on stdin,
    /// and nothing stored or sent to the approver. Reply: [`Checked`].
    DryRun,
    /// `writ policy <repo>`: what a ticket for one repo may ask, from the policy in force.
    /// Reply: [`RepoPolicy`].
    Policy { repo: RepoName },
    /// `writ wait <id>`: wait until the ticket is decided. Reply: [`Decision`].
    Wait { id: TicketId },
    /// `writ close <lease>`: end the lease with a summary ([`CloseRequest`] on stdin), the
    /// connection's key being its session key. Reply: [`Report`].
    Close { id: TicketId },
    /// `writ info`: how this daemon takes decisions. Reply: [`Info`].
    Info,
    /// `writ ls [--all]`: pending tickets and active leases, or every ticket. Reply: [`Listing`].
    List { all: bool },
    /// `writ show <id>`: a ticket's canonical bytes and the revision it follows. Reply: [`Shown`].
    Show { id: TicketId },
    /// `writ watch [<cursor>]` (M7.8): the tickets waiting for a signature, given as soon as
    /// they aren't the ones `since` names (the cursor of an earlier reply; none: at once), or
    /// after a bounded time with the same ones. Reply: [`Watched`].
    Watch { since: Option<TextDigest> },
    /// `writ report <lease>`: a lease's activity report. Reply: [`Report`].
    Report { id: TicketId },
    /// `writ approve <id>`: an approval ([`ApproveRequest`] on stdin). Reply: [`Ack`].
    Approve { id: TicketId },
    /// `writ refuse <id>`: a refusal ([`RefuseRequest`] on stdin). Reply: [`Ack`].
    Refuse { id: TicketId },
    /// `writ revoke <id>`: revoke a lease or withdraw a pending ticket ([`RevokeRequest`] on
    /// stdin). Reply: [`Ack`].
    Revoke { id: TicketId },
    /// `writ prove`: an agent signing key signs a remote's message, with an approver's
    /// signature over the `writ-proof/1` document ([`ProveRequest`] on stdin). Reply:
    /// [`Proved`].
    Prove,
    /// `writ unseal`: the keystore's passphrase and an approver's signature over this boot's
    /// `writ-unseal/1` document ([`UnsealRequest`] on stdin). Reply: [`Unsealed`]. The only
    /// command, with `info`, a sealed daemon answers.
    Unseal,
    /// `writ admin show <target>`: the version in force of the policy, `approvers` or
    /// `readers`. Reply: [`AdminShown`].
    AdminShow { target: AdminTarget },
    /// `writ admin apply`: an approver's signed `writ-admin/2` change ([`AdminRequest`] on
    /// stdin). Reply: [`AdminApplied`].
    AdminApply,
    /// `writ admin token <id>`, first step: the token file in force for the credential `id`
    /// (its digest, never the token). Reply: [`TokenShown`].
    TokenShow { id: KeyId },
    /// `writ admin token <id>`: an approver's signed `writ-token/3` ([`TokenRequest`] on
    /// stdin). Reply: [`TokenApplied`].
    TokenApply,
    /// `writ recovery check` (M7.6): the keystore's recovery recipient and its challenge, to
    /// open on the approver's machine. Reply: [`RecoveryShown`].
    RecoveryShow,
    /// `writ admin key list|show`: every key the policy in force declares, each with its
    /// public half (or, for a token, whether it was added) and what uses it. Reply:
    /// [`KeysShown`].
    AdminKeys,
    /// `writ admin host add`, first step: a one-use nonce for a `writ-scan/1`. Reply:
    /// [`ScanNonce`].
    ScanNonce,
    /// `writ admin host add`: an approver's signed `writ-scan/1` ([`ScanRequest`] on stdin):
    /// the host's keys read, never pinned. Reply: [`Scanned`].
    Scan,
    /// `writ admin repo check <repo>`: the repo's upstream reached with its credential, read
    /// and write access proven with nothing pushed, the mirror synced. Reply:
    /// [`UpstreamChecked`].
    RepoCheck { repo: RepoName },
    /// `writ admin repo status [<repo>]`: each registered repo's sync status (the sync
    /// running, how the last one ended), or the named one's. Reply: [`SyncStatuses`].
    RepoStatus { repo: Option<RepoName> },
    /// `writ admin tls rotate`, first step: the HTTPS approval API's certificate in force
    /// (its fingerprint and backend) and the daemon a `writ-tls/1` names. Reply:
    /// [`TlsShown`].
    TlsShow,
    /// `writ admin tls rotate`: an approver's signed `writ-tls/1` ([`TlsRequest`] on stdin):
    /// a new key and certificate, in force at once. Reply: [`TlsRotated`].
    TlsRotate,
    /// `writ admin ca show` (M7.6): the SSH CA in force, and the one it replaced while still
    /// trusted. Reply: [`CaShown`].
    CaShow,
    /// `writ admin ca rotate`: an approver's signed `writ-ca/1` ([`CaRequest`] on stdin): a
    /// new CA key, in force at once. Reply: [`CaRotated`].
    CaRotate,
    /// `writ admin auto-unseal status|on|off` (M7.6): how the daemon unseals at start, and what
    /// keeps it from opening itself. Reply: [`AutoUnsealShown`].
    AutoUnsealShow,
    /// `writ migrate` (M7.9.6): the migration the policy in force owes, its text in force and
    /// the daemon's rewrite of it, or that none is owed. Reply: [`MigrationShown`].
    MigrationShow,
}

impl Command {
    /// Parses an exec line. Anything else is `None`.
    pub fn parse(line: &str) -> Option<Self> {
        let mut words = line.split(' ');
        if words.next()? != "writ" {
            return None;
        }
        let verb = words.next()?;
        if verb == "admin" {
            let what = words.next()?;
            let arg = words.next();
            if what == "recovery" {
                return match (arg, words.next()) {
                    (Some("show"), None) => Some(Self::RecoveryShow),
                    _ => None,
                };
            }
            if what == "token" {
                let third = words.next();
                if words.next().is_some() {
                    return None;
                }
                return match (arg?, third) {
                    ("show", Some(id)) => Some(Self::TokenShow {
                        id: id.parse().ok()?,
                    }),
                    ("apply", None) => Some(Self::TokenApply),
                    _ => None,
                };
            }
            if words.next().is_some() {
                return None;
            }
            return match (what, arg) {
                ("show", Some(target)) => Some(Self::AdminShow {
                    target: target.parse().ok()?,
                }),
                ("apply", None) => Some(Self::AdminApply),
                ("keys", None) => Some(Self::AdminKeys),
                ("scan", None) => Some(Self::Scan),
                ("scan-nonce", None) => Some(Self::ScanNonce),
                ("check", Some(repo)) => Some(Self::RepoCheck {
                    repo: repo.parse().ok()?,
                }),
                ("status", None) => Some(Self::RepoStatus { repo: None }),
                ("status", Some(repo)) => Some(Self::RepoStatus {
                    repo: Some(repo.parse().ok()?),
                }),
                ("tls", Some("show")) => Some(Self::TlsShow),
                ("tls", Some("rotate")) => Some(Self::TlsRotate),
                ("ca", Some("show")) => Some(Self::CaShow),
                ("ca", Some("rotate")) => Some(Self::CaRotate),
                ("auto-unseal", Some("show")) => Some(Self::AutoUnsealShow),
                _ => None,
            };
        }
        let arg = words.next();
        if words.next().is_some() {
            return None;
        }
        let id = || arg?.parse::<TicketId>().ok();
        match (verb, arg) {
            ("request", None) => Some(Self::Request),
            ("request", Some("--dry-run")) => Some(Self::DryRun),
            ("policy", Some(repo)) => Some(Self::Policy {
                repo: repo.parse().ok()?,
            }),
            ("wait", Some(_)) => Some(Self::Wait { id: id()? }),
            ("close", Some(_)) => Some(Self::Close { id: id()? }),
            ("report", Some(_)) => Some(Self::Report { id: id()? }),
            ("info", None) => Some(Self::Info),
            ("ls", None) => Some(Self::List { all: false }),
            ("ls", Some("--all")) => Some(Self::List { all: true }),
            ("show", Some(_)) => Some(Self::Show { id: id()? }),
            ("watch", None) => Some(Self::Watch { since: None }),
            ("watch", Some(cursor)) => Some(Self::Watch {
                since: Some(TextDigest::try_from(cursor.to_owned()).ok()?),
            }),
            ("approve", Some(_)) => Some(Self::Approve { id: id()? }),
            ("refuse", Some(_)) => Some(Self::Refuse { id: id()? }),
            ("revoke", Some(_)) => Some(Self::Revoke { id: id()? }),
            ("prove", None) => Some(Self::Prove),
            ("unseal", None) => Some(Self::Unseal),
            ("migration", None) => Some(Self::MigrationShow),
            _ => None,
        }
    }

    /// The exec line.
    pub fn line(&self) -> String {
        match self {
            Self::Request => "writ request".to_owned(),
            Self::DryRun => "writ request --dry-run".to_owned(),
            Self::Policy { repo } => format!("writ policy {repo}"),
            Self::Wait { id } => format!("writ wait {id}"),
            Self::Close { id } => format!("writ close {id}"),
            Self::Report { id } => format!("writ report {id}"),
            Self::Info => "writ info".to_owned(),
            Self::List { all: false } => "writ ls".to_owned(),
            Self::List { all: true } => "writ ls --all".to_owned(),
            Self::Show { id } => format!("writ show {id}"),
            Self::Watch { since: None } => "writ watch".to_owned(),
            Self::Watch {
                since: Some(cursor),
            } => format!("writ watch {cursor}"),
            Self::Approve { id } => format!("writ approve {id}"),
            Self::Refuse { id } => format!("writ refuse {id}"),
            Self::Revoke { id } => format!("writ revoke {id}"),
            Self::Prove => "writ prove".to_owned(),
            Self::Unseal => "writ unseal".to_owned(),
            Self::AdminShow { target } => format!("writ admin show {target}"),
            Self::AdminApply => "writ admin apply".to_owned(),
            Self::TokenShow { id } => format!("writ admin token show {id}"),
            Self::TokenApply => "writ admin token apply".to_owned(),
            Self::RecoveryShow => "writ admin recovery show".to_owned(),
            Self::AdminKeys => "writ admin keys".to_owned(),
            Self::ScanNonce => "writ admin scan-nonce".to_owned(),
            Self::Scan => "writ admin scan".to_owned(),
            Self::RepoCheck { repo } => format!("writ admin check {repo}"),
            Self::RepoStatus { repo: None } => "writ admin status".to_owned(),
            Self::RepoStatus { repo: Some(repo) } => format!("writ admin status {repo}"),
            Self::TlsShow => "writ admin tls show".to_owned(),
            Self::TlsRotate => "writ admin tls rotate".to_owned(),
            Self::CaShow => "writ admin ca show".to_owned(),
            Self::CaRotate => "writ admin ca rotate".to_owned(),
            Self::AutoUnsealShow => "writ admin auto-unseal show".to_owned(),
            Self::MigrationShow => "writ migration".to_owned(),
        }
    }

    /// Whether this command is served on the approval listener (the others on the agents').
    pub fn is_approval(&self) -> bool {
        !self.is_agent()
    }

    /// Whether this command is served on the agents' listener, to a plain key.
    pub fn is_agent(&self) -> bool {
        matches!(
            self,
            Self::Request
                | Self::DryRun
                | Self::Policy { .. }
                | Self::Wait { .. }
                | Self::Close { .. }
        )
    }

    /// The HTTPS route of an approval command: method and path (with its query). Agent
    /// commands have none: they only exist over SSH.
    ///
    /// | Command | Route |
    /// |---|---|
    /// | info | `GET /v1/info` |
    /// | ls, ls --all | `GET /v1/tickets`, `GET /v1/tickets?all=true` |
    /// | show | `GET /v1/tickets/<id>` |
    /// | watch | `GET /v1/tickets/watch`, `GET /v1/tickets/watch?since=<cursor>` |
    /// | report | `GET /v1/tickets/<id>/report` |
    /// | approve, refuse, revoke | `POST /v1/tickets/<id>/approve` (`refuse`, `revoke`) |
    /// | prove | `POST /v1/proofs` |
    /// | unseal | `POST /v1/unseal` |
    /// | admin show, admin apply | `GET /v1/admin/<target>`, `POST /v1/admin` |
    /// | admin token (show, apply) | `GET /v1/tokens/<id>`, `POST /v1/tokens` |
    /// | admin keys | `GET /v1/keys` |
    /// | admin scan-nonce, admin scan | `GET /v1/scan`, `POST /v1/scan` |
    /// | admin check | `POST /v1/repos/<repo>/check` |
    /// | admin status | `GET /v1/repos/status`, `GET /v1/repos/<repo>/status` |
    /// | admin tls (show, rotate) | `GET /v1/tls`, `POST /v1/tls` |
    /// | recovery check | `GET /v1/recovery` |
    /// | admin ca (show, rotate) | `GET /v1/ca`, `POST /v1/ca` |
    /// | admin auto-unseal | `GET /v1/auto-unseal` |
    /// | migrate | `GET /v1/migration` |
    pub fn http_route(&self) -> Option<(&'static str, String)> {
        match self {
            Self::Request
            | Self::DryRun
            | Self::Policy { .. }
            | Self::Wait { .. }
            | Self::Close { .. } => None,
            Self::Info => Some(("GET", "/v1/info".to_owned())),
            Self::List { all: false } => Some(("GET", "/v1/tickets".to_owned())),
            Self::List { all: true } => Some(("GET", "/v1/tickets?all=true".to_owned())),
            Self::Show { id } => Some(("GET", format!("/v1/tickets/{id}"))),
            Self::Watch { since: None } => Some(("GET", "/v1/tickets/watch".to_owned())),
            Self::Watch {
                since: Some(cursor),
            } => Some(("GET", format!("/v1/tickets/watch?since={cursor}"))),
            Self::Report { id } => Some(("GET", format!("/v1/tickets/{id}/report"))),
            Self::Approve { id } => Some(("POST", format!("/v1/tickets/{id}/approve"))),
            Self::Refuse { id } => Some(("POST", format!("/v1/tickets/{id}/refuse"))),
            Self::Revoke { id } => Some(("POST", format!("/v1/tickets/{id}/revoke"))),
            Self::Prove => Some(("POST", "/v1/proofs".to_owned())),
            Self::Unseal => Some(("POST", "/v1/unseal".to_owned())),
            Self::AdminShow { target } => Some(("GET", format!("/v1/admin/{target}"))),
            Self::AdminApply => Some(("POST", "/v1/admin".to_owned())),
            Self::TokenShow { id } => Some(("GET", format!("/v1/tokens/{id}"))),
            Self::TokenApply => Some(("POST", "/v1/tokens".to_owned())),
            Self::RecoveryShow => Some(("GET", "/v1/recovery".to_owned())),
            Self::AdminKeys => Some(("GET", "/v1/keys".to_owned())),
            Self::ScanNonce => Some(("GET", "/v1/scan".to_owned())),
            Self::Scan => Some(("POST", "/v1/scan".to_owned())),
            Self::RepoCheck { repo } => Some(("POST", format!("/v1/repos/{repo}/check"))),
            Self::RepoStatus { repo: None } => Some(("GET", "/v1/repos/status".to_owned())),
            Self::RepoStatus { repo: Some(repo) } => {
                Some(("GET", format!("/v1/repos/{repo}/status")))
            }
            Self::TlsShow => Some(("GET", "/v1/tls".to_owned())),
            Self::TlsRotate => Some(("POST", "/v1/tls".to_owned())),
            Self::CaShow => Some(("GET", "/v1/ca".to_owned())),
            Self::CaRotate => Some(("POST", "/v1/ca".to_owned())),
            Self::AutoUnsealShow => Some(("GET", "/v1/auto-unseal".to_owned())),
            Self::MigrationShow => Some(("GET", "/v1/migration".to_owned())),
        }
    }

    /// Parses an HTTPS request line (method, path with its query) into an approval command.
    /// Anything else, an unknown query parameter included, is `None`.
    pub fn from_http(method: &str, path_and_query: &str) -> Option<Self> {
        let (path, query) = match path_and_query.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (path_and_query, None),
        };
        let parts: Vec<&str> = path.strip_prefix("/v1/")?.split('/').collect();
        let id = |text: &str| text.parse::<TicketId>().ok();
        let command = match (method, parts.as_slice(), query) {
            ("GET", ["info"], None) => Self::Info,
            ("GET", ["tickets"], None) => Self::List { all: false },
            ("GET", ["tickets"], Some("all=true")) => Self::List { all: true },
            // Before `tickets/<id>`: `watch` is no ticket id, and never parses as one.
            ("GET", ["tickets", "watch"], None) => Self::Watch { since: None },
            ("GET", ["tickets", "watch"], Some(query)) => Self::Watch {
                since: Some(TextDigest::try_from(query.strip_prefix("since=")?.to_owned()).ok()?),
            },
            ("GET", ["tickets", t], None) => Self::Show { id: id(t)? },
            ("GET", ["tickets", t, "report"], None) => Self::Report { id: id(t)? },
            ("POST", ["tickets", t, "approve"], None) => Self::Approve { id: id(t)? },
            ("POST", ["tickets", t, "refuse"], None) => Self::Refuse { id: id(t)? },
            ("POST", ["tickets", t, "revoke"], None) => Self::Revoke { id: id(t)? },
            ("POST", ["proofs"], None) => Self::Prove,
            ("POST", ["unseal"], None) => Self::Unseal,
            ("GET", ["admin", target], None) => Self::AdminShow {
                target: target.parse().ok()?,
            },
            ("POST", ["admin"], None) => Self::AdminApply,
            ("GET", ["tokens", id], None) => Self::TokenShow {
                id: id.parse().ok()?,
            },
            ("POST", ["tokens"], None) => Self::TokenApply,
            ("GET", ["recovery"], None) => Self::RecoveryShow,
            ("GET", ["keys"], None) => Self::AdminKeys,
            ("GET", ["scan"], None) => Self::ScanNonce,
            ("POST", ["scan"], None) => Self::Scan,
            ("POST", ["repos", repo, "check"], None) => Self::RepoCheck {
                repo: repo.parse().ok()?,
            },
            ("GET", ["repos", "status"], None) => Self::RepoStatus { repo: None },
            ("GET", ["repos", repo, "status"], None) => Self::RepoStatus {
                repo: Some(repo.parse().ok()?),
            },
            ("GET", ["tls"], None) => Self::TlsShow,
            ("POST", ["tls"], None) => Self::TlsRotate,
            ("GET", ["ca"], None) => Self::CaShow,
            ("POST", ["ca"], None) => Self::CaRotate,
            ("GET", ["auto-unseal"], None) => Self::AutoUnsealShow,
            ("GET", ["migration"], None) => Self::MigrationShow,
            _ => return None,
        };
        Some(command)
    }
}
