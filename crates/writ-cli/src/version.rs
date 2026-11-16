//! The daemon's version against this `writ`'s (M7.9.8): a hint on stderr, never a check
//! (hard rule 1: the daemon decides). Every reply names the daemon's version
//! ([`writ_proto::decode_versioned`]); a reply that can't be read already names both.

use std::sync::atomic::{AtomicBool, Ordering};

use writ_proto::{FIRST_NAMED_VERSION, VERSION};

/// Whether this process has said it already: once is enough.
static SAID: AtomicBool = AtomicBool::new(false);

/// Says nothing from now on: a TAB's process (M7.9.9) writes nothing to the terminal.
pub fn quiet() {
    SAID.store(true, Ordering::Relaxed);
}

/// What to say when the daemon's version, as its reply names it, isn't this `writ`'s: `None`
/// when they are the same. The version was checked to be digits and dots when it was read.
pub fn mismatch(theirs: Option<&str>) -> Option<String> {
    match theirs {
        Some(theirs) if theirs == VERSION => None,
        Some(theirs) => Some(format!(
            "writ: this writ is {VERSION} and writd is {theirs}: install the same version of \
             both (the changelog's Upgrading)"
        )),
        None => Some(format!(
            "writ: this writ is {VERSION} and the daemon names no version (a writd before \
             {FIRST_NAMED_VERSION}): install the same version of both (the changelog's Upgrading)"
        )),
    }
}

/// Reads a reply, and says once per process when the daemon's version isn't this `writ`'s.
pub fn read<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, writ_proto::ApiError> {
    let reply = writ_proto::decode_versioned(bytes);
    if reply.readable
        && let Some(hint) = mismatch(reply.version.as_deref())
        && !SAID.swap(true, Ordering::Relaxed)
    {
        eprintln!("{hint}");
    }
    reply.result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_another_version_or_none_is_said() {
        assert_eq!(mismatch(Some(VERSION)), None);
        assert_eq!(
            mismatch(Some("9.10.11")),
            Some(format!(
                "writ: this writ is {VERSION} and writd is 9.10.11: install the same version of \
                 both (the changelog's Upgrading)"
            ))
        );
        assert_eq!(
            mismatch(None),
            Some(format!(
                "writ: this writ is {VERSION} and the daemon names no version (a writd before \
                 0.2.0): install the same version of both (the changelog's Upgrading)"
            ))
        );
        // A version a patch apart is another version.
        let parts: Vec<u64> = VERSION.split('.').map(|p| p.parse().unwrap()).collect();
        let next = format!("{}.{}.{}", parts[0], parts[1], parts[2] + 1);
        assert!(mismatch(Some(&next)).is_some());
    }

    #[test]
    fn a_reply_is_read_as_before_whatever_the_daemon_s_version() {
        // The hint is a hint: the reply's result is the same with any version named.
        let ok = r#""ok":{"decisions":"open"}"#;
        for version in [
            format!(r#""version":"{VERSION}","#),
            r#""version":"9.10.11","#.to_owned(),
            String::new(),
        ] {
            let read = read::<writ_proto::Info>(format!("{{{version}{ok}}}").as_bytes());
            assert!(read.is_ok(), "{version}: {read:?}");
        }
    }
}
