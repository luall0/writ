//! Agent-written text made safe to show: the one list of characters that must never reach a
//! terminal or a notification as they are (hard rule 6).
//!
//! Every place that shows agent text uses [`is_hidden_char`]: `writ sign` escapes these
//! characters visibly, notifications drop them ([`strip`]).

/// Whether `c` could move the cursor, recolor, hide or reorder text: control characters (C0,
/// DEL, C1, newlines included), bidi controls, invisible format characters and line
/// separators.
pub fn is_hidden_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'                  // Arabic letter mark
            | '\u{180E}'                // Mongolian vowel separator
            | '\u{200B}'..='\u{200F}'   // zero-width spaces and joiners, LRM, RLM
            | '\u{2028}'..='\u{2029}'   // line and paragraph separators
            | '\u{202A}'..='\u{202E}'   // bidi embeddings and overrides
            | '\u{2060}'..='\u{2064}'   // word joiner and invisible operators
            | '\u{2066}'..='\u{2069}'   // bidi isolates
            | '\u{FEFF}' // zero-width no-break space (BOM)
        )
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

#[cfg(test)]
mod tests {
    use super::*;

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
            ' ', 'a', '~', '\u{a0}', '\u{061B}', '\u{180D}', '\u{200A}', '\u{2010}', '\u{2027}',
            '\u{202F}', '\u{205F}', '\u{2065}', '\u{206A}', '\u{FEFE}', '\u{FF00}', 'é', '中',
            '🙂',
        ] {
            assert!(!is_hidden_char(c), "{:?} must stay visible", c);
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
