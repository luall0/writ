//! A passphrase a person types: its bounds, and reading it without echo from the terminal, or
//! as one line on stdin when stdin isn't a terminal (a script, a test, a pipe from a password
//! manager). Used by `writd init` and `writd recover-approvers` on the daemon host and by
//! `writ unseal` on the approver's machine.
//!
//! The text is read one byte at a time straight from the file descriptor, so no buffer keeps a
//! copy, into memory wiped on drop. It is never printed.

use std::os::fd::AsFd;

use zeroize::Zeroizing;

/// The fewest characters a new passphrase may have. It guards every secret of the keystore
/// against whoever copies the keys directory, behind age's scrypt.
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// The longest passphrase read, in bytes.
pub const MAX_PASSPHRASE_BYTES: usize = 1024;

/// A passphrase that can't be taken, or couldn't be read. Never holds the text.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PassphraseError {
    #[error("the passphrase is {0} characters: at least {MIN_PASSPHRASE_CHARS} are needed")]
    TooShort(usize),
    #[error("the passphrase is longer than {MAX_PASSPHRASE_BYTES} bytes")]
    TooLong,
    #[error("the passphrase holds a control character")]
    Control,
    #[error("the passphrase is not UTF-8")]
    NotUtf8,
    #[error("the two passphrases differ")]
    Mismatch,
    #[error("no passphrase: the input ended first")]
    NoInput,
    #[error("cannot read the passphrase: {0}")]
    Io(String),
}

/// Whether `text` may be a keystore passphrase: [`MIN_PASSPHRASE_CHARS`] characters or more,
/// at most [`MAX_PASSPHRASE_BYTES`] bytes, no control character.
pub fn check(text: &str) -> Result<(), PassphraseError> {
    if text.len() > MAX_PASSPHRASE_BYTES {
        return Err(PassphraseError::TooLong);
    }
    if text.chars().any(char::is_control) {
        return Err(PassphraseError::Control);
    }
    let chars = text.chars().count();
    if chars < MIN_PASSPHRASE_CHARS {
        return Err(PassphraseError::TooShort(chars));
    }
    Ok(())
}

/// Reads a passphrase: on a terminal, after `prompt` on stderr with the echo off, and, with
/// `confirm`, a second time after that prompt (they must match); otherwise one line of stdin
/// (no prompt, no confirmation). The line's end (`\n`, `\r\n`) is not part of it. Its bounds
/// are checked when `new` (a passphrase being chosen); an existing one is checked only for
/// length, so a wrong one is refused by the keystore, not here.
pub fn read(
    prompt: &str,
    confirm: Option<&str>,
    new: bool,
) -> Result<Zeroizing<String>, PassphraseError> {
    let stdin = std::io::stdin();
    let terminal = rustix::termios::isatty(stdin.as_fd());
    let first = if terminal {
        read_hidden(prompt)?
    } else {
        read_line(stdin.as_fd())?
    };
    if new {
        check(&first)?;
    } else if first.len() > MAX_PASSPHRASE_BYTES {
        return Err(PassphraseError::TooLong);
    }
    if let (true, Some(confirm)) = (terminal, confirm) {
        let second = read_hidden(confirm)?;
        if *second != *first {
            return Err(PassphraseError::Mismatch);
        }
    }
    Ok(first)
}

/// The terminal's settings, put back when dropped (also on an error or a panic).
struct EchoOff<Fd: AsFd> {
    fd: Fd,
    saved: rustix::termios::Termios,
}

impl<Fd: AsFd> Drop for EchoOff<Fd> {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(
            &self.fd,
            rustix::termios::OptionalActions::Now,
            &self.saved,
        );
    }
}

fn io(e: impl std::fmt::Display) -> PassphraseError {
    PassphraseError::Io(e.to_string())
}

/// One line from the terminal on stdin, echo off, after `prompt` on stderr.
fn read_hidden(prompt: &str) -> Result<Zeroizing<String>, PassphraseError> {
    use std::io::Write;
    let stdin = std::io::stdin();
    let saved = rustix::termios::tcgetattr(stdin.as_fd()).map_err(io)?;
    let mut quiet = saved.clone();
    quiet.local_modes.remove(rustix::termios::LocalModes::ECHO);
    let guard = EchoOff {
        fd: stdin.as_fd(),
        saved,
    };
    rustix::termios::tcsetattr(stdin.as_fd(), rustix::termios::OptionalActions::Now, &quiet)
        .map_err(io)?;
    let mut stderr = std::io::stderr();
    let _ = write!(stderr, "{prompt}");
    let _ = stderr.flush();
    let line = read_line(stdin.as_fd());
    drop(guard);
    let _ = writeln!(stderr);
    line
}

/// One line from `fd`, a byte at a time (no buffer keeps a copy), at most
/// [`MAX_PASSPHRASE_BYTES`] bytes before its end.
fn read_line(fd: impl AsFd) -> Result<Zeroizing<String>, PassphraseError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PASSPHRASE_BYTES.saturating_add(2)));
    let mut byte = [0u8; 1];
    let ended = loop {
        match rustix::io::read(&fd, &mut byte) {
            Ok(0) => break bytes.is_empty(),
            Ok(_) if byte == *b"\n" => break false,
            Ok(_) => {
                if bytes.len() > MAX_PASSPHRASE_BYTES {
                    return Err(PassphraseError::TooLong);
                }
                bytes.push(byte[0]);
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(io(e)),
        }
    };
    if ended {
        return Err(PassphraseError::NoInput);
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| PassphraseError::NotUtf8)?;
    Ok(Zeroizing::new(text.to_owned()))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn a_new_passphrase_is_bounded_on_both_sides() {
        let shortest = "a".repeat(MIN_PASSPHRASE_CHARS);
        assert_eq!(check(&shortest), Ok(()));
        assert_eq!(
            check(&"a".repeat(MIN_PASSPHRASE_CHARS - 1)),
            Err(PassphraseError::TooShort(MIN_PASSPHRASE_CHARS - 1))
        );
        // Characters, not bytes: twelve accented letters are enough.
        assert_eq!(check(&"é".repeat(MIN_PASSPHRASE_CHARS)), Ok(()));
        assert_eq!(check(&"a".repeat(MAX_PASSPHRASE_BYTES)), Ok(()));
        assert_eq!(
            check(&"a".repeat(MAX_PASSPHRASE_BYTES + 1)),
            Err(PassphraseError::TooLong)
        );
        for control in [
            "correct horse\tbattery",
            "correct horse\nbattery",
            "\u{1b}[2Jcorrect horse",
        ] {
            assert_eq!(check(control), Err(PassphraseError::Control), "{control:?}");
        }
    }

    fn line(input: &[u8]) -> Result<Zeroizing<String>, PassphraseError> {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(input).unwrap();
        std::io::Seek::rewind(&mut file).unwrap();
        read_line(&file)
    }

    #[test]
    fn a_line_ends_at_its_newline_and_is_bounded() {
        assert_eq!(
            line(b"correct horse\nnext").unwrap().as_str(),
            "correct horse"
        );
        assert_eq!(
            line(b"correct horse\r\n").unwrap().as_str(),
            "correct horse"
        );
        assert_eq!(line(b"no newline").unwrap().as_str(), "no newline");
        assert_eq!(line(b"").unwrap_err(), PassphraseError::NoInput);
        assert_eq!(line(b"\n").unwrap().as_str(), "");
        assert_eq!(line(b"\xff\xfe\n").unwrap_err(), PassphraseError::NotUtf8);
        let longest = "a".repeat(MAX_PASSPHRASE_BYTES + 1);
        assert_eq!(
            line(longest.as_bytes()).unwrap().len(),
            MAX_PASSPHRASE_BYTES + 1
        );
        let longer = "a".repeat(MAX_PASSPHRASE_BYTES + 2);
        assert_eq!(
            line(longer.as_bytes()).unwrap_err(),
            PassphraseError::TooLong
        );
    }

    #[test]
    fn errors_never_hold_the_text() {
        for error in [
            check("short pass").unwrap_err(),
            check(&"secret".repeat(200)).unwrap_err(),
            check("secret\u{7}passphrase").unwrap_err(),
        ] {
            let text = format!("{error} {error:?}");
            assert!(
                !text.contains("secret") && !text.contains("short pass"),
                "{text}"
            );
        }
    }
}
