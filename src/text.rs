//! Text that came from a repository or a server.
//!
//! An attacker chooses these bytes. A file name can contain terminal escape
//! sequences that clear the screen, print a fake verdict or write to the
//! clipboard, so this text must never reach the terminal unescaped.

use std::fmt;

/// The most we keep of any single untrusted value.
const MAX_STORED_BYTES: usize = 4096;
/// The most we show of one value, so a long name can't bury the results.
const MAX_SHOWN_CHARS: usize = 200;

/// Text from an untrusted source. Displaying it always escapes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Untrusted(String);

impl Untrusted {
    pub fn from_bytes(raw: &[u8]) -> Self {
        let kept = &raw[..raw.len().min(MAX_STORED_BYTES)];
        Self(String::from_utf8_lossy(kept).into_owned())
    }

    /// The original text, for matching. Never print this.
    pub fn raw(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Untrusted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&escape(&self.0))
    }
}

/// Makes text safe to print.
///
/// Control characters, invisible characters and text direction overrides become
/// visible escapes such as `\u{1b}`. Backslashes are escaped too, so a name
/// can't imitate an escape. Ordinary text in any language stays readable.
pub fn escape(text: &str) -> String {
    let mut shown = String::new();
    let mut chars = text.chars();

    for ch in chars.by_ref().take(MAX_SHOWN_CHARS) {
        match ch {
            '\'' | '"' => shown.push(ch),
            _ => shown.extend(ch.escape_debug()),
        }
    }
    if chars.next().is_some() {
        shown.push_str("...(truncated)");
    }
    shown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_characters_that_control_a_terminal_or_hide_text() {
        for ch in [
            '\x1b',
            '\x07',
            '\0',
            '\n',
            '\r',
            '\t',
            '\x08',
            '\x7f',
            '\u{85}',
            '\u{9b}',
            '\u{ad}',
            '\u{61c}',
            '\u{200b}',
            '\u{200c}',
            '\u{200d}',
            '\u{200e}',
            '\u{200f}',
            '\u{2028}',
            '\u{2029}',
            '\u{202a}',
            '\u{202e}',
            '\u{2060}',
            '\u{2066}',
            '\u{2069}',
            '\u{feff}',
            '\u{e0001}',
            '\u{e0041}',
        ] {
            let shown = escape(&format!("a{ch}b"));
            assert!(shown.is_ascii(), "{ch:?} was not escaped: {shown}");
            assert!(shown.starts_with('a') && shown.ends_with('b'), "{shown}");
            assert!(shown.contains('\\'), "{ch:?} was not escaped: {shown}");
        }
    }

    #[test]
    fn a_fake_verdict_stays_on_one_visible_line() {
        let shown = escape("x\x1b[2J\x1b[H\nverdict: CLEAN");
        assert_eq!(shown, "x\\u{1b}[2J\\u{1b}[H\\nverdict: CLEAN");
    }

    #[test]
    fn a_name_cannot_imitate_an_escape() {
        assert_eq!(escape(r"a\u{1b}b"), r"a\\u{1b}b");
    }

    #[test]
    fn leaves_ordinary_text_readable() {
        for text in ["src/main.rs", "日本語/文件.js", "it's \"fine\".txt"] {
            assert_eq!(escape(text), text);
        }
    }

    #[test]
    fn limits_how_much_is_shown() {
        let shown = escape(&"a".repeat(MAX_SHOWN_CHARS + 1));
        assert_eq!(shown.len(), MAX_SHOWN_CHARS + "...(truncated)".len());

        let exact = "a".repeat(MAX_SHOWN_CHARS);
        assert_eq!(escape(&exact), exact);
    }

    #[test]
    fn limits_how_much_is_stored_without_splitting_characters_unsafely() {
        let long = "é".repeat(MAX_STORED_BYTES);
        let stored = Untrusted::from_bytes(long.as_bytes());
        assert!(stored.raw().len() <= MAX_STORED_BYTES + 3);
    }

    #[test]
    fn invalid_utf8_does_not_panic() {
        let stored = Untrusted::from_bytes(b"a\xff\xfeb");
        assert_eq!(stored.raw(), "a\u{fffd}\u{fffd}b");
    }

    #[test]
    fn displaying_untrusted_text_escapes_it_but_matching_sees_the_original() {
        let name = Untrusted::from_bytes(b"x\x1b[2Jy");
        assert_eq!(name.to_string(), "x\\u{1b}[2Jy");
        assert_eq!(name.raw(), "x\x1b[2Jy");
    }
}
