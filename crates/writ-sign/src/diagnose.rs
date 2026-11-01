//! Why the daemon may have turned the session away, when ssh itself failed (exit 255): the
//! gateway refuses an expired, revoked or unknown certificate during authentication, where
//! SSH has no way to say why. The session certificate named in the SSH command (`writ init`
//! writes `-o CertificateFile=…`) says whether there is a lease at all and when it ends.
//!
//! A convenience for the agent, never a decision: the daemon decided already.

use std::path::{Path, PathBuf};

use writ_core::units::Timestamp;
use writ_crypto::ssh_key::Certificate;

/// A sentence for the agent, if the certificate explains the refusal.
pub fn explain(ssh_command: &str, now: u64) -> Option<String> {
    let path = certificate_file(ssh_command)?;
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Some(format!(
            "no lease: there is no session certificate at {} (request a lease with `writ request`)",
            path.display()
        ));
    };
    let certificate = Certificate::from_openssh(text.trim()).ok()?;
    let lease = certificate.key_id();
    if now >= certificate.valid_before() {
        let when = i64::try_from(certificate.valid_before())
            .ok()
            .and_then(|t| Timestamp::from_unix(t).ok())
            .map_or_else(|| "its end".to_owned(), |t| t.to_string());
        return Some(format!(
            "lease {lease} expired at {when}: request a new lease (or an amendment before it ends)"
        ));
    }
    Some(format!(
        "the daemon refused the session certificate of lease {lease}: the lease is revoked, \
         closed or used up, or the daemon doesn't know it"
    ))
}

/// The `CertificateFile` of an SSH command line (`-o CertificateFile=<path>`, quoted or not).
fn certificate_file(command: &str) -> Option<PathBuf> {
    let words = split(command);
    let value = words.iter().find_map(|w| {
        let (key, value) = w.split_once('=')?;
        key.eq_ignore_ascii_case("CertificateFile").then_some(value)
    })?;
    Some(match value.strip_prefix("~/") {
        Some(rest) => Path::new(&std::env::var_os("HOME")?).join(rest),
        None => PathBuf::from(value),
    })
}

/// Splits a command line as `sh` would for plain words: single quotes, double quotes, and
/// backslashes outside single quotes.
fn split(command: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word: Option<String> = None;
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\n' => {
                if let Some(w) = word.take() {
                    words.push(w);
                }
            }
            '\'' => {
                let w = word.get_or_insert_with(String::new);
                w.extend(chars.by_ref().take_while(|&c| c != '\''));
            }
            '"' => {
                let w = word.get_or_insert_with(String::new);
                while let Some(c) = chars.next() {
                    match c {
                        '"' => break,
                        '\\' => w.extend(chars.next()),
                        c => w.push(c),
                    }
                }
            }
            '\\' => word.get_or_insert_with(String::new).extend(chars.next()),
            c => word.get_or_insert_with(String::new).push(c),
        }
    }
    words.extend(word);
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_certificate_file() {
        assert_eq!(
            certificate_file("ssh -F /dev/null -o CertificateFile=/a/key-cert.pub -i /a/key"),
            Some(PathBuf::from("/a/key-cert.pub"))
        );
        assert_eq!(
            certificate_file("ssh -o 'CertificateFile=/a b/it'\\''s/cert'"),
            Some(PathBuf::from("/a b/it's/cert"))
        );
        assert_eq!(
            certificate_file(r#"ssh -o "certificatefile=/x/\"y\"""#),
            Some(PathBuf::from("/x/\"y\""))
        );
        assert_eq!(certificate_file("ssh -i /a/key"), None);
    }

    #[test]
    fn no_certificate_means_no_lease() {
        let dir = std::env::temp_dir().join("writ-sign-no-such-dir/key-cert.pub");
        let text = explain(&format!("ssh -o CertificateFile={}", dir.display()), 0).unwrap();
        assert!(
            text.starts_with("no lease: there is no session certificate at"),
            "{text}"
        );
    }
}
