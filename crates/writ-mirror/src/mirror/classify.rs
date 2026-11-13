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
        } else if let Some(failure @ crate::dial::DialError::Proxy { .. }) = access.dial_failure() {
            // git only says the proxy failed: the dialer says why.
            MirrorError::Proxy { repo, failure }
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
    /// agent's terminal. Taken out before and after the hidden characters go, so one hidden
    /// inside the token (`ghp_ab\u{200B}cd…`) can't rebuild it once stripped (the review
    /// after M5.5, S9); its Basic-auth form (`base64(user:token)`) too.
    /// The token is the one `access` unwrapped for this operation.
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

/// `text` [`shown`], with every form of `token` (sent as `user`) taken out, before and after
/// its hidden characters go.
pub(crate) fn redacted(text: &[u8], token: &str, user: &str) -> String {
    let forms = token_forms(token, user);
    let redact = |text: &str| {
        forms
            .iter()
            .fold(text.to_owned(), |t, f| t.replace(f.as_str(), "<redacted>"))
    };
    let once = redact(&String::from_utf8_lossy(text));
    redact(&shown(once.as_bytes()))
}

/// The forms a token can come back in: as it is, and as git's Basic authorization sends it
/// (`base64(user:token)`). Wiped when dropped: each is the secret.
fn token_forms(token: &str, user: &str) -> [zeroize::Zeroizing<String>; 2] {
    use base64ct::Encoding as _;
    let pair = zeroize::Zeroizing::new(format!("{user}:{token}"));
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
            assert!(shown.contains("<redacted>"), "{echo:?} -> {shown:?}");
        }
        // Another user's Basic form is another string: the one sent is the one taken out.
        let theirs = base64ct::Base64::encode_string(format!("x-token-auth:{token}").as_bytes());
        assert!(
            !redacted(format!("Basic {theirs}").as_bytes(), token, "x-token-auth")
                .contains(&theirs)
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
