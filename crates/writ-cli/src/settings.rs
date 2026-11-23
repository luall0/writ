//! The client's settings file, `<home>/config` (M7): the daemon's endpoints when no flag or
//! environment variable gives them, so a machine set up once (`make install` writes it for
//! local mode; a `client` setup would for a detached daemon) needs nothing exported. Flags and
//! environment variables still win.
//!
//! ```text
//! # Written by the installer.
//! url = unix:/Library/Application Support/Writ/run/agents.sock
//! approval_url = unix:/Library/Application Support/Writ/run/approvals.sock
//! ```
//!
//! An agent can write it (it is the user's file), so it is read strictly (its words reach
//! the terminal through `writ`'s escaping of every error): a regular file of
//! at most [`MAX_BYTES`], UTF-8, `key = value` lines (blank lines and `#` comments aside),
//! only the keys below, each once, no control or hidden character. Anything else refuses the
//! file, naming the line. What it can change is where `writ` connects, never whom it trusts:
//! the daemon is still the one pinned in `known_hosts`.

use std::io::Read as _;
use std::path::Path;

use anyhow::{Context, bail};

/// The file, in Writ's home.
pub const FILE: &str = "config";
/// The largest file read.
pub const MAX_BYTES: u64 = 16 * 1024;
/// The longest value.
pub const MAX_VALUE: usize = 4096;

/// What the file sets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    /// The agents' listener (`WRIT_URL`).
    pub url: Option<String>,
    /// The approval listener (`WRIT_APPROVAL_URL`).
    pub approval_url: Option<String>,
}

/// The settings in `home`: none when there is no file; refused when it can't be read as one.
pub fn load(home: &Path) -> anyhow::Result<Settings> {
    let path = home.join(FILE);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Settings::default()),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    if !metadata.is_file() {
        bail!(
            "{} is not a regular file (a link?): not read",
            path.display()
        );
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .and_then(|f| f.take(MAX_BYTES.saturating_add(1)).read_to_end(&mut bytes))
        .with_context(|| format!("cannot read {}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_BYTES {
        bail!(
            "{} is larger than {MAX_BYTES} bytes: not read",
            path.display()
        );
    }
    let text = String::from_utf8(bytes)
        .with_context(|| format!("{} is not UTF-8: not read", path.display()))?;
    parse(&text).map_err(|why| anyhow::anyhow!("{}: {why}", path.display()))
}

/// The settings `text` gives, or why it gives none (the line named).
fn parse(text: &str) -> Result<Settings, String> {
    let mut settings = Settings::default();
    for (n, line) in text.lines().enumerate() {
        let number = n.saturating_add(1);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Shown as written: `writ` escapes every error it prints, once.
        let shown = line;
        if line
            .chars()
            .any(|c| c.is_control() || writ_core::text::is_hidden_char(c))
        {
            return Err(format!(
                "line {number}: a control or hidden character ({shown})"
            ));
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {number}: not `key = value` ({shown})"));
        };
        let (key, value) = (key.trim(), value.trim());
        if value.is_empty() || value.len() > MAX_VALUE {
            return Err(format!(
                "line {number}: {key} needs a value of at most {MAX_VALUE} bytes"
            ));
        }
        let slot = match key {
            "url" => &mut settings.url,
            "approval_url" => &mut settings.approval_url,
            _ => {
                return Err(format!(
                    "line {number}: unknown setting {key} (url, approval_url)"
                ));
            }
        };
        if slot.is_some() {
            return Err(format!("line {number}: {key} is set twice"));
        }
        *slot = Some(value.to_owned());
    }
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_endpoints_are_read_each_once() {
        let text = "# Written by the installer.\n\nurl = unix:/Library/App Support/agents.sock\n\
                    approval_url=unix:/run/approvals.sock\n";
        assert_eq!(
            parse(text),
            Ok(Settings {
                url: Some("unix:/Library/App Support/agents.sock".to_owned()),
                approval_url: Some("unix:/run/approvals.sock".to_owned()),
            })
        );
        assert_eq!(parse(""), Ok(Settings::default()));
    }

    #[test]
    fn anything_else_refuses_the_file_naming_the_line() {
        for (text, why) in [
            ("url = a\nurl = b\n", "line 2: url is set twice"),
            (
                "home = /tmp\n",
                "line 1: unknown setting home (url, approval_url)",
            ),
            ("url\n", "line 1: not `key = value` (url)"),
            ("url =\n", "line 1: url needs a value of at most 4096 bytes"),
            (
                "url = a\u{1b}[2Jb\n",
                "line 1: a control or hidden character (url = a\u{1b}[2Jb)",
            ),
            (
                "url = a\u{202e}b\n",
                "line 1: a control or hidden character (url = a\u{202e}b)",
            ),
        ] {
            assert_eq!(parse(text), Err(why.to_owned()), "{text:?}");
        }
        let at = format!("url = {}", "a".repeat(MAX_VALUE));
        assert!(parse(&at).is_ok());
        let past = format!("url = {}", "a".repeat(MAX_VALUE + 1));
        assert_eq!(
            parse(&past),
            Err("line 1: url needs a value of at most 4096 bytes".to_owned())
        );
    }

    #[test]
    fn a_file_that_can_t_be_trusted_is_not_read() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(load(home.path()).unwrap(), Settings::default());
        let path = home.path().join(FILE);
        std::fs::write(&path, format!("url = a\n#{}", "x".repeat(16 * 1024))).unwrap();
        let error = crate::error_of(load(home.path()));
        assert!(
            error.ends_with("is larger than 16384 bytes: not read"),
            "{error}"
        );
        std::fs::remove_file(&path).unwrap();
        let elsewhere = home.path().join("elsewhere");
        std::fs::write(&elsewhere, "url = ssh://elsewhere:2222\n").unwrap();
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
        let error = crate::error_of(load(home.path()));
        assert!(
            error.ends_with("is not a regular file (a link?): not read"),
            "{error}"
        );
    }
}
