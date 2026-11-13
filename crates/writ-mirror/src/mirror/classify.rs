//! What a failed sync or upstream push says, read as one of [`MirrorError`]'s causes, and
//! upstream's words made safe to show (cut, cleaned, the token taken out).

use super::access::Access;
use super::{MirrorGuard, Reach};
use crate::git::Transport;
use crate::{MirrorError, relay, shown};

impl MirrorGuard {
    /// The error the stderr of a failed sync or upstream push (`what`) names. Upstream can
    /// print anything there: at worst it changes which failure is reported, never whether the
    /// operation failed.
    pub(super) fn classify(
        &self,
        access: &Access,
        stderr: &[u8],
        what: &'static str,
    ) -> MirrorError {
        let text = String::from_utf8_lossy(stderr);
        let repo = self.repo.name.clone();
        if access.too_large() || text.contains(relay::TOO_LARGE) {
            MirrorError::TooLarge {
                repo,
                max: self.shared.config.max_fetch_bytes,
            }
        } else if let Some(failure) = access.dial_failure() {
            // git only says the daemon's proxy failed (every operation goes through it): the
            // dialer says why, through the repo's proxy or directly (upstream's host named:
            // the audit line's, never the agent's).
            match failure {
                crate::dial::DialError::Proxy { .. } => MirrorError::Proxy { repo, failure },
                crate::dial::DialError::Direct(why) => MirrorError::Upstream {
                    repo,
                    upstream: self.repo.reach.url().to_owned(),
                    why: format!("cannot reach it: {why}"),
                },
            }
        } else if text.contains("Host key verification failed") {
            MirrorError::HostKey { repo }
        } else if access.transport == Transport::Https && is_certificate_failure(&text) {
            MirrorError::Certificate {
                repo,
                why: self.clean(access, stderr),
            }
        } else if text.contains("mismatched algorithms") {
            MirrorError::ObjectFormat {
                repo,
                expected: self.repo.format.as_str().to_owned(),
            }
        } else {
            MirrorError::Git {
                repo,
                what,
                stderr: self.clean(access, stderr),
            }
        }
    }

    /// A text from git or upstream made safe for an error ([`shown`]), the token taken out:
    /// upstream receives it, and a hostile one could print it back, to the audit log and an
    /// agent's terminal. Taken out once the hidden characters went, so one hidden inside the
    /// token (`ghp_ab\u{200B}cd…`) can't rebuild it once stripped (the review after M5.5,
    /// S9); its Basic-auth form (`base64(user:token)`) too; a text still holding a long part
    /// of either is withheld ([`redacted`]). The token is the one `access` unwrapped for this
    /// operation.
    pub(super) fn clean(&self, access: &Access, text: &[u8]) -> String {
        match (&self.repo.reach, &access.token) {
            (Reach::Https { url, .. }, Some(token)) => redacted(
                text,
                token.expose(),
                url.user().unwrap_or(crate::credential::DEFAULT_USER),
            ),
            (Reach::Https { .. } | Reach::Ssh { .. }, _) => shown(text),
        }
    }
}

/// What curl says when an HTTPS upstream's certificate doesn't verify, by TLS backend: OpenSSL
/// (`SSL certificate problem: …`, `no alternative certificate subject name matches …`),
/// GnuTLS, older and newer (`server certificate verification failed. CAfile: …`,
/// `server verification failed: certificate signer not trusted. (CAfile: …)`), the name
/// checks (`SSL: certificate subject name (…) does not match target host name …`), and
/// Secure Transport (`… certificate verify failed`).
const CERTIFICATE_FAILURES: [&str; 6] = [
    "SSL certificate problem",
    "server certificate verification failed",
    "server verification failed",
    "no alternative certificate subject name",
    "does not match target host name",
    "certificate verify failed",
];

/// Whether git's stderr says the server's certificate didn't verify.
fn is_certificate_failure(stderr: &str) -> bool {
    CERTIFICATE_FAILURES.iter().any(|m| stderr.contains(m))
}

/// How long a part of a secret's form gives it away: a text still holding a part this long
/// once every whole form is taken out is withheld whole.
const LEAKED_PART: usize = 8;

/// What is shown in place of a text that still held a long part of the secret.
pub(crate) const WITHHELD: &str = "<upstream's words withheld: they held part of the credential>";

/// `text` made safe like [`shown`], with every form of `token` (sent as `user`) taken out, on
/// the text as git prints it (the review after M7.6, M-1): split at every `\r` and `\n` (git
/// prefixes each piece of a remote's message with `remote: ` and pads it with spaces), each
/// piece's hidden characters dropped, then each whole form replaced, before any cut. Then the
/// pieces are read as one canonical text (git's prefixes, whitespace and the breaks between
/// pieces gone): if a part of a form [`LEAKED_PART`] long still shows there (the token split
/// across lines, cut by a bound, broken by a character), the whole text is [`WITHHELD`].
pub(crate) fn redacted(text: &[u8], token: &str, user: &str) -> String {
    let forms = token_forms(token, user);
    let lossy = zeroize::Zeroizing::new(String::from_utf8_lossy(text).into_owned());
    let mut pieces: Vec<zeroize::Zeroizing<String>> = Vec::new();
    for piece in lossy.split(['\r', '\n']) {
        let mut piece = zeroize::Zeroizing::new(writ_core::text::strip(
            piece,
            writ_core::text::Newlines::Drop,
            usize::MAX,
        ));
        for form in &forms {
            if piece.contains(form.as_str()) {
                piece = zeroize::Zeroizing::new(piece.replace(form.as_str(), "<redacted>"));
            }
        }
        if !piece.trim().is_empty() {
            pieces.push(piece);
        }
    }
    let mut canonical = zeroize::Zeroizing::new(String::with_capacity(lossy.len()));
    for piece in &pieces {
        let mut rest = piece.trim();
        while let Some(after) = rest.strip_prefix("remote:") {
            rest = after.trim_start();
        }
        canonical.extend(rest.chars().filter(|c| !c.is_whitespace()));
    }
    if forms.iter().any(|form| holds_part(&canonical, form)) {
        return WITHHELD.to_owned();
    }
    let lines: Vec<&str> = pieces.iter().map(|piece| piece.trim()).collect();
    writ_core::text::shown(&lines.join("; "), crate::MAX_SHOWN)
}

/// Whether `text` holds a part of `form` [`LEAKED_PART`] long (all of it, when shorter).
fn holds_part(text: &str, form: &str) -> bool {
    let (text, form) = (text.as_bytes(), form.as_bytes());
    let length = form.len().min(LEAKED_PART);
    if length == 0 {
        return false;
    }
    let parts: std::collections::HashSet<&[u8]> = form.windows(length).collect();
    text.windows(length).any(|window| parts.contains(window))
}

/// The forms a token can come back in: as it is, and as git's Basic authorization sends it
/// (`base64(user:token)`). Wiped when dropped: each is the secret.
fn token_forms(token: &str, user: &str) -> [zeroize::Zeroizing<String>; 2] {
    use base64ct::Encoding as _;
    // Sized up front: a growing buffer would leave copies of the token behind.
    let mut pair = zeroize::Zeroizing::new(String::with_capacity(
        user.len().saturating_add(1).saturating_add(token.len()),
    ));
    pair.push_str(user);
    pair.push(':');
    pair.push_str(token);
    [
        zeroize::Zeroizing::new(token.to_owned()),
        zeroize::Zeroizing::new(base64ct::Base64::encode_string(pair.as_bytes())),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The review after M5.5 (S9): the token was taken out before the hidden characters went,
    /// so one hidden inside it came back whole once stripped; its Basic-auth form wasn't.
    #[test]
    fn a_hostile_upstream_can_t_print_the_token_back_in_any_form() {
        use base64ct::Encoding as _;
        let token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
        let basic = base64ct::Base64::encode_string(format!("writ:{token}").as_bytes());
        for echo in [
            format!("remote: {token}"),
            "remote: ghp_0123\u{200b}456789abcdefghijklmnopqrstuvwxyz".to_owned(),
            "remote: ghp_01\x1b23456789abcdefghijklmnopqrstuvwxyz".to_owned(),
            "remote: ghp_0123456789\rabcdefghijklmnopqrstuvwxyz".to_owned(),
            format!("remote: \u{202e}{token}"),
            format!("remote: Authorization: Basic {basic}"),
        ] {
            let shown = redacted(echo.as_bytes(), token, "writ");
            assert!(!shown.contains(token), "{echo:?} -> {shown:?}");
            assert!(!shown.contains(&basic), "{echo:?} -> {shown:?}");
            // Taken out, or (split by the `\r`, M-1) the whole text withheld.
            assert!(
                shown.contains("<redacted>") || shown == WITHHELD,
                "{echo:?} -> {shown:?}"
            );
            assert!(!holds_part(&shown, token), "{echo:?} -> {shown:?}");
        }
        // Another user's Basic form is another string: the one sent is the one taken out.
        let theirs = base64ct::Base64::encode_string(format!("x-token-auth:{token}").as_bytes());
        assert!(
            !redacted(format!("Basic {theirs}").as_bytes(), token, "x-token-auth")
                .contains(&theirs)
        );
    }

    /// The review after M7.6 (M-1): the token was taken out of the raw text and of the text
    /// once cut, so a token split by a line break (and git's `remote: ` before the second
    /// half), or cut by either bound, came through in readable parts. Each text below is what
    /// git prints on its stderr for a remote's message (sideband 2): every piece, ended by its
    /// `\r` or `\n`, behind `remote: ` and padded with eight spaces (git's `sideband.c` when
    /// stderr isn't a terminal, the daemon's case).
    #[test]
    fn a_token_split_cut_or_broken_up_by_git_s_formatting_is_never_shown() {
        use base64ct::Encoding as _;
        const PAD: &str = "        ";
        let token = "tok-0123456789abcdefghijklmnopqrstuvwxyz";
        let basic = base64ct::Base64::encode_string(format!("writ:{token}").as_bytes());
        let withheld = |text: &[u8]| {
            let shown = redacted(text, token, "writ");
            assert_eq!(shown, WITHHELD, "{:?}", String::from_utf8_lossy(text));
        };
        // Split by `\r` (git's own prefix in the middle) and by `\n`.
        withheld(
            format!("remote: tok-0123456789{PAD}\rremote: abcdefghijklmnopqrstuvwxyz{PAD}\n")
                .as_bytes(),
        );
        withheld(
            format!("remote: tok-0123456789abcdefghij{PAD}\nremote: klmnopqrstuvwxyz{PAD}\n")
                .as_bytes(),
        );
        // The Basic form split the same way.
        let (head, tail) = basic.split_at(20);
        withheld(format!("remote: {head}{PAD}\nremote: {tail}{PAD}\n").as_bytes());
        // Each half behind its own prefix, more than one prefix, hidden characters around.
        withheld(format!("remote: remote: tok-0123\u{200b}456789{PAD}\n\x1b[2Kremote: abcdefghijklmnopqrstuvwxyz{PAD}\n").as_bytes());
        // Cut by the raw stderr bound (64 KiB, the space before it empty lines): the token's
        // last characters never came.
        let mut cut = vec![b'\n'; crate::process::MAX_STDERR - 40];
        cut.extend_from_slice(b"remote: tok-0123456789abcdefghijklmnopqrstu");
        withheld(&cut);
        // A part of the token on its own: withheld at 8 characters, shown at 7 (the limit on
        // both sides), whatever comes around it.
        withheld(b"remote: 89abcdef is what you sent\n");
        assert_eq!(
            redacted(b"remote: 89abcde is what you sent\n", token, "writ"),
            "remote: 89abcde is what you sent"
        );
        // Whole on a line: taken out, the rest kept; before the 2,000-character cut, so the cut
        // never leaves part of it.
        let long = format!(
            "remote: {}{token}{PAD}\n",
            "x".repeat(crate::MAX_SHOWN - 20)
        );
        let shown = redacted(long.as_bytes(), token, "writ");
        assert!(shown.ends_with("x<redacted>"), "{shown}");
        assert_eq!(
            redacted(
                format!("remote: you sent {token}{PAD}\nfatal: unable to access upstream\n")
                    .as_bytes(),
                token,
                "writ"
            ),
            "remote: you sent <redacted>; fatal: unable to access upstream"
        );
        // Words without it are shown as they were.
        assert_eq!(
            redacted(
                format!("remote: Repository not found.{PAD}\nfatal: could not read\n").as_bytes(),
                token,
                "writ"
            ),
            "remote: Repository not found.; fatal: could not read"
        );
    }

    #[test]
    fn every_tls_backend_s_certificate_failure_is_recognized() {
        // As curl prints them through git, each backend and version (the GnuTLS ones from
        // Debian 13's git 2.47, the image `make e2e` and the deployment run).
        for stderr in [
            "fatal: unable to access 'https://h/r.git/': SSL certificate problem: self-signed certificate",
            "fatal: unable to access 'https://h/r.git/': server certificate verification failed. CAfile: /x.pem CRLfile: none",
            "fatal: unable to access 'https://h/r.git/': server verification failed: certificate signer not trusted. (CAfile: /x.pem CRLfile: none)",
            "fatal: unable to access 'https://h/r.git/': no alternative certificate subject name matches target host name 'h'",
            "fatal: unable to access 'https://h/r.git/': SSL: certificate subject name (other) does not match target host name 'h'",
            "fatal: unable to access 'https://h/r.git/': error:0A000086:SSL routines::certificate verify failed",
        ] {
            assert!(is_certificate_failure(stderr), "{stderr}");
        }
        for stderr in [
            "fatal: unable to access 'https://h/r.git/': Failed to connect to h port 443",
            "fatal: Authentication failed for 'https://h/r.git/'",
            "remote: Repository not found.",
        ] {
            assert!(!is_certificate_failure(stderr), "{stderr}");
        }
    }
}
