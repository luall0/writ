//! The trailers of a commit message (`Writ: wrt_…`), found the way git finds them
//! (`trailer.c`, as `git interpret-trailers --parse --no-divider` reads a message): the last
//! paragraph, not the title, made only of trailers, or of at least a quarter of trailers with
//! one git itself writes (`Signed-off-by: `, `(cherry picked from commit `). Lines starting
//! with `#` are skipped; a line starting with a space or a tab continues the trailer above.
//!
//! Agent-written text: read here, never trusted beyond what the policy compares exactly.

/// One trailer: its key as written (trimmed), its value with continuation lines unfolded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trailer {
    pub key: String,
    pub value: String,
}

/// Trailers git writes itself: they let a block hold other lines too.
const GIT_GENERATED: [&[u8]; 2] = [b"Signed-off-by: ", b"(cherry picked from commit "];

/// git's default `core.commentChar`.
const COMMENT: u8 = b'#';

/// Every trailer of `message`, in order.
pub fn parse(message: &[u8]) -> Vec<Trailer> {
    let lines: Vec<&[u8]> = split_lines(message);
    let Some(start) = block_start(&lines) else {
        return Vec::new();
    };
    let mut trailers: Vec<Trailer> = Vec::new();
    let mut last_is_trailer = false;
    for line in lines.iter().skip(start) {
        if line.first() == Some(&COMMENT) {
            continue;
        }
        if line.first().copied().is_some_and(is_git_space) {
            if let (true, Some(last)) = (last_is_trailer, trailers.last_mut()) {
                let more = String::from_utf8_lossy(trim(line)).into_owned();
                if !more.is_empty() {
                    last.value.push(' ');
                    last.value.push_str(&more);
                }
            }
            continue;
        }
        last_is_trailer = false;
        if is_blank(line) {
            continue;
        }
        if let Some(position) = separator(line).filter(|&p| p >= 1) {
            let (key, value) = line.split_at_checked(position).unwrap_or((line, b""));
            let value = value.get(1..).unwrap_or_default();
            trailers.push(Trailer {
                key: String::from_utf8_lossy(trim(key)).into_owned(),
                value: String::from_utf8_lossy(trim(value)).into_owned(),
            });
            last_is_trailer = true;
        }
    }
    trailers
}

/// The message's lines, without their newlines; trailing blank lines dropped.
fn split_lines(message: &[u8]) -> Vec<&[u8]> {
    let mut lines: Vec<&[u8]> = message.split(|&b| b == b'\n').collect();
    while lines.last().is_some_and(|l| is_blank(l)) {
        lines.pop();
    }
    lines
}

/// git's `isspace` (its own `sane_ctype`): space, tab, newline and carriage return only. Rust's
/// `is_ascii_whitespace` adds the form feed, where git sees text (the review after M7.6, G-3: a
/// `\f` line split a block git reads whole, and hid a second `Writ:` trailer).
fn is_git_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// `bytes` without git's whitespace at either end (`strbuf_trim`).
fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&b| !is_git_space(b))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|&b| !is_git_space(b))
        .map_or(start, |last| last.saturating_add(1));
    bytes.get(start..end).unwrap_or_default()
}

fn is_blank(line: &[u8]) -> bool {
    line.iter().copied().all(is_git_space)
}

/// The index of the first line of the trailer block, if the message has one (git's
/// `find_trailer_block_start`).
fn block_start(lines: &[&[u8]]) -> Option<usize> {
    // The first paragraph is the title and can't hold trailers.
    let end_of_title = lines.iter().position(|l| is_blank(l))?;
    let (mut trailer_lines, mut non_trailer, mut continuations) = (0usize, 0usize, 0usize);
    let mut recognized = false;
    let mut only_spaces = true;
    for index in (end_of_title..lines.len()).rev() {
        let line = lines.get(index)?;
        if line.first() == Some(&COMMENT) {
            non_trailer = non_trailer.saturating_add(continuations);
            continuations = 0;
            continue;
        }
        if is_blank(line) {
            if only_spaces {
                continue;
            }
            non_trailer = non_trailer.saturating_add(continuations);
            let block = (recognized && trailer_lines.saturating_mul(3) >= non_trailer)
                || (trailer_lines > 0 && non_trailer == 0);
            return block.then_some(index.saturating_add(1));
        }
        only_spaces = false;
        if GIT_GENERATED.iter().any(|prefix| line.starts_with(prefix)) {
            trailer_lines = trailer_lines.saturating_add(1);
            continuations = 0;
            recognized = true;
            continue;
        }
        let starts_with_space = line.first().copied().is_some_and(is_git_space);
        if separator(line).is_some_and(|p| p >= 1) && !starts_with_space {
            trailer_lines = trailer_lines.saturating_add(1);
            continuations = 0;
        } else if starts_with_space {
            continuations = continuations.saturating_add(1);
        } else {
            non_trailer = non_trailer.saturating_add(1).saturating_add(continuations);
            continuations = 0;
        }
    }
    None
}

/// Where the `:` separator of a trailer line is: after a token of letters, digits and `-`,
/// and maybe whitespace (git's `find_separator`).
fn separator(line: &[u8]) -> Option<usize> {
    let mut whitespace = false;
    for (index, &b) in line.iter().enumerate() {
        if b == b':' {
            return Some(index);
        }
        if !whitespace && (b.is_ascii_alphanumeric() || b == b'-') {
            continue;
        }
        if index != 0 && (b == b' ' || b == b'\t') {
            whitespace = true;
            continue;
        }
        return None;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(message: &str) -> Vec<(String, String)> {
        parse(message.as_bytes())
            .into_iter()
            .map(|t| (t.key, t.value))
            .collect()
    }

    fn one(key: &str, value: &str) -> Vec<(String, String)> {
        vec![(key.to_owned(), value.to_owned())]
    }

    #[test]
    fn the_last_paragraph_of_trailers() {
        assert_eq!(pairs("Subject\n\nWrit: wrt_A\n"), one("Writ", "wrt_A"));
        assert_eq!(
            pairs("Subject\n\nBody.\n\nWrit: wrt_A\nCo-authored-by: X <x@y>\n\n\n"),
            vec![
                ("Writ".into(), "wrt_A".into()),
                ("Co-authored-by".into(), "X <x@y>".into())
            ]
        );
        // A space before the separator, and a continuation line.
        assert_eq!(pairs("S\n\nWrit : wrt_A\n"), one("Writ", "wrt_A"));
        assert_eq!(
            pairs("S\n\nWrit: wrt_A\n  more\n"),
            one("Writ", "wrt_A more")
        );
    }

    #[test]
    fn not_trailers() {
        for message in [
            // The title alone is never a trailer block.
            "Writ: wrt_A\n",
            "Writ: wrt_A\nWrit: wrt_B\n",
            // A body line among them, without a git-generated trailer.
            "S\n\nSome text\nWrit: wrt_A\n",
            // Not the last paragraph.
            "S\n\nWrit: wrt_A\n\nThanks.\n",
            // No token, or a space first.
            "S\n\n: wrt_A\n",
            "S\n\n Writ: wrt_A\n",
            "S\n\nWr it: wrt_A x\nmore text\n",
            "",
        ] {
            assert_eq!(pairs(message), vec![], "{message:?}");
        }
    }

    /// The review after M7.6, G-3: a form feed is text to git, never a blank line nor
    /// whitespace to trim.
    #[test]
    fn whitespace_is_git_s_set() {
        assert_eq!(
            pairs("S\n\nSigned-off-by: A <a@x>\nWrit: wrt_OTHER\n\x0c\nWrit: wrt_A\n"),
            vec![
                ("Signed-off-by".into(), "A <a@x>".into()),
                ("Writ".into(), "wrt_OTHER".into()),
                ("Writ".into(), "wrt_A".into())
            ]
        );
        assert_eq!(pairs("S\n\nBody\n\x0c\nWrit: wrt_A\n"), vec![]);
        assert_eq!(pairs("S\n\nWrit: wrt_A\n\x0c\n"), vec![]);
        assert_eq!(pairs("S\n\nWrit: wrt_A\x0c\n"), one("Writ", "wrt_A\x0c"));
        assert_eq!(pairs("S\n\nWrit: wrt_A\r\n"), one("Writ", "wrt_A"));
    }

    #[test]
    fn a_git_generated_trailer_lets_other_lines_in() {
        assert_eq!(
            pairs("S\n\nBody line\nSigned-off-by: A <a@x>\nWrit: wrt_A\n"),
            vec![
                ("Signed-off-by".into(), "A <a@x>".into()),
                ("Writ".into(), "wrt_A".into())
            ]
        );
        // Past a quarter of other lines, even with one, it's no block.
        assert_eq!(
            pairs("S\n\none\ntwo\nthree\nfour\nSigned-off-by: A <a@x>\n"),
            vec![]
        );
        // Comments are skipped.
        assert_eq!(
            pairs("S\n\nWrit: wrt_A\n# a comment\n"),
            one("Writ", "wrt_A")
        );
    }
}
