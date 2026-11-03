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
        } else if text.contains("Host key verification failed") {
            MirrorError::HostKey { repo }
        } else if access.transport == Transport::Https && is_certificate_failure(&text) {
            MirrorError::Certificate {
                repo,
                why: self.clean(stderr),
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
                stderr: self.clean(stderr),
            }
        }
    }

    /// A text from git or upstream made safe for an error ([`shown`]), the token taken out
    /// first: upstream receives it, and a hostile one could print it back, to the audit log
    /// and an agent's terminal.
    pub(super) fn clean(&self, text: &[u8]) -> String {
        match &self.repo.reach {
            Reach::Https {
                token: Some(token), ..
            } => {
                let text = String::from_utf8_lossy(text).replace(token.expose(), "<redacted>");
                shown(text.as_bytes())
            }
            Reach::Https { token: None, .. } | Reach::Ssh { .. } => shown(text),
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

#[cfg(test)]
mod tests {
    use super::*;

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
