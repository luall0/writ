//! Agent-written text made safe to show: the one list of characters that must never reach a
//! terminal or a notification as they are (hard rule 6).
//!
//! Every place that shows agent text uses [`is_hidden_char`]: `writ sign` escapes these
//! characters visibly, notifications drop them ([`strip`]).

mod hidden;

/// Whether `c` could move the cursor, recolor, hide or reorder text, or render as nothing:
/// controls (C0, DEL, C1, newlines included), format characters (bidi controls, zero-width
/// characters, tags), private-use and unassigned code points, line and paragraph separators,
/// and every default-ignorable character (variation selectors, fillers). The table is
/// generated from Unicode ([`hidden`], `tool/gen-hidden-chars.py`), never written by hand.
pub fn is_hidden_char(c: char) -> bool {
    let code = u32::from(c);
    hidden::HIDDEN
        .binary_search_by(|&(lo, hi)| {
            if hi < code {
                std::cmp::Ordering::Less
            } else if lo > code {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Whether a newline is kept by [`strip`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Newlines {
    Keep,
    Drop,
}

/// `text` without its hidden characters ([`is_hidden_char`]), `\n` kept if asked, at most
/// `max_chars` characters long.
pub fn strip(text: &str, newlines: Newlines, max_chars: usize) -> String {
    text.chars()
        .filter(|&c| (newlines == Newlines::Keep && c == '\n') || !is_hidden_char(c))
        .take(max_chars)
        .collect()
}

/// `text` cut to `max_chars` characters, with `…` when something was cut: for text from
/// elsewhere (an agent, a peer) that goes in a message or a log line.
pub fn shown(text: &str, max_chars: usize) -> String {
    let mut chars = text.chars();
    let mut out: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shown_cuts_on_both_sides() {
        assert_eq!(shown("abc", 3), "abc");
        assert_eq!(shown("abcd", 3), "abc…");
        assert_eq!(shown("éèê€", 2), "éè…");
        assert_eq!(shown("", 0), "");
        assert_eq!(shown("a", 0), "…");
    }

    #[test]
    fn hides_every_character_that_can_disguise_text() {
        let hidden = [
            '\0', '\t', '\n', '\r', '\u{1b}', '\u{7f}', '\u{80}', '\u{9b}', '\u{9f}', '\u{061C}',
            '\u{180E}', '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}', '\u{2028}',
            '\u{2029}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2060}',
            '\u{2061}', '\u{2062}', '\u{2063}', '\u{2064}', '\u{2066}', '\u{2067}', '\u{2068}',
            '\u{2069}', '\u{FEFF}',
        ];
        for c in hidden {
            assert!(is_hidden_char(c), "{:?} must be hidden", c);
        }
        // The neighbours of each range stay visible.
        for c in [
            ' ', 'a', '~', '\u{a0}', '\u{061B}', '\u{180A}', '\u{200A}', '\u{2010}', '\u{2027}',
            '\u{202F}', '\u{205F}', '\u{FEFC}', '\u{FF01}', 'é', '中', '🙂', '\u{3000}',
        ] {
            assert!(!is_hidden_char(c), "{:?} must stay visible", c);
        }
    }

    #[test]
    fn invisible_characters_found_by_the_review_are_hidden() {
        for c in [
            '\u{00AD}',   // soft hyphen
            '\u{034F}',   // combining grapheme joiner
            '\u{0600}',   // Arabic number sign (format)
            '\u{115F}',   // Hangul choseong filler
            '\u{3164}',   // Hangul filler
            '\u{180B}',   // Mongolian free variation selector
            '\u{206A}',   // inhibit symmetric swapping (deprecated format)
            '\u{206F}',   // nominal digit shapes
            '\u{FE00}',   // variation selector 1
            '\u{FE0F}',   // variation selector 16
            '\u{FFF9}',   // interlinear annotation anchor
            '\u{FFFB}',   // interlinear annotation terminator
            '\u{1D173}',  // musical symbol begin beam
            '\u{E0001}',  // language tag
            '\u{E0041}',  // tag Latin capital A: "ASCII smuggling"
            '\u{E007F}',  // cancel tag
            '\u{E0100}',  // variation selector 17
            '\u{E000}',   // private use
            '\u{F8FF}',   // private use (the Apple logo on a Mac)
            '\u{10FFFF}', // a noncharacter, unassigned
            '\u{2065}',   // unassigned, in the middle of the bidi controls
        ] {
            assert!(is_hidden_char(c), "{:?} must be hidden", c);
        }
    }

    #[test]
    fn the_generated_table_is_sorted_and_disjoint() {
        let mut last: Option<u32> = None;
        for &(lo, hi) in hidden::HIDDEN {
            assert!(lo <= hi, "{lo:x}..{hi:x}");
            if let Some(last) = last {
                assert!(
                    lo > last + 1,
                    "{lo:x} touches or overlaps the previous range"
                );
            }
            last = Some(hi);
        }
        // Every control is in it: the derivation includes what char::is_control knows.
        for code in 0..=0x10FFFFu32 {
            if let Some(c) = char::from_u32(code)
                && c.is_control()
            {
                assert!(is_hidden_char(c), "{c:?}");
            }
        }
    }

    #[test]
    fn strip_drops_hidden_characters_and_caps_the_length() {
        let text = "a\u{1b}[31mb\u{202E}c\nd\u{200B}e";
        assert_eq!(strip(text, Newlines::Drop, 100), "a[31mbcde");
        assert_eq!(strip(text, Newlines::Keep, 100), "a[31mbc\nde");
        assert_eq!(strip(text, Newlines::Keep, 3), "a[3");
        assert_eq!(strip("", Newlines::Keep, 3), "");
        assert_eq!(
            strip("héllo", Newlines::Drop, 2),
            "hé",
            "counted in characters"
        );
        assert_eq!(strip("abc", Newlines::Drop, 0), "");
    }
}
