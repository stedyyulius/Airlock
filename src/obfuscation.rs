//! Finds code written so that people can't read it, or can't see it at all.
//!
//! Attackers often leave a normal looking file and hide the real code in it:
//! scrambled by an obfuscator, pushed hundreds of spaces past the edge of the
//! screen, or written in characters that don't display. The checks here look for
//! those marks, not for any one piece of malware.
//!
//! Minifiers also make code unreadable, but honest minified code doesn't look
//! like this. Minified libraries get a note, and only a file that shouldn't be
//! minified, such as a config file, gets a warning.

use crate::git::RepoFile;
use crate::network::{FileClass, classify, is_binary, is_test_path};
use crate::report::{At, Kind, Report};
use crate::text::Untrusted;
use regex::bytes::Regex;
use std::sync::LazyLock;

/// Few people's editors show this many columns before wrapping or scrolling.
const OFF_SCREEN_GAP: usize = 120;
/// Generated code can be deeply indented, so a gap at the start needs to be wider
/// than one in the middle of a line before it stops looking like indentation.
const OFF_SCREEN_INDENT: usize = 300;
const OFF_SCREEN_BLANK_LINES: usize = 200;
/// Names like `_0x3b486b` can appear by chance in a dump or a test, a few times.
const MIN_SCRAMBLED_NAMES: usize = 8;
/// How many obfuscator-style tokens must share one line.
const MIN_OBFUSCATED_TOKENS: usize = 12;
const LONG_LINE_BYTES: usize = 1000;
/// How much of a file has to be on long lines for it to count as minified.
const MINIFIED_PERCENT: usize = 80;
/// How many code words a long line needs before it counts as code, not data.
const MIN_CODE_WORDS: usize = 5;
const MAX_SNIPPET_BYTES: usize = 160;

/// Fingerprints left by obfuscators, each with a description for the report.
/// None of these appear in code that people write or that minifiers produce.
const FINGERPRINTS: [(&str, &str); 9] = [
    (
        r#"(?i-u)\[['"]push['"]\]\s*\(\s*[\w$]+\[['"]shift['"]\]"#,
        "rotates a hidden table of strings, which javascript-obfuscator does",
    ),
    (
        r"(?-u)while\s*\(\s*!!\[\]\s*\)",
        "uses while(!![]), a mark of javascript-obfuscator",
    ),
    (
        r"(?i-u)parseInt\(\s*[\w$]+\(\s*0x[0-9a-f]+[^)]{0,40}\)\s*\)\s*/\s*0x",
        "checks a hidden table of strings, which javascript-obfuscator does",
    ),
    (
        r"(?-u)eval\(function\(p,a,c,k,e,[rd]\)",
        "unpacks itself and runs the result, using a known JavaScript packer",
    ),
    (
        r"(?-u)\[\]\[\(!\[\]\+\[\]\)",
        "is written only in symbols, which JSFuck does",
    ),
    (
        r"(?-u)\$=~\[\];\$=\{___:\+\+\$",
        "is written only in symbols, which jjencode does",
    ),
    (
        r"(?-u)__pyarmor__|pyarmor_runtime|__armor_enter__",
        "is encrypted with PyArmor, so its code can't be read",
    ),
    (
        r#"(?i-u)\bdebu['"]\s*\+\s*['"]gger\b"#,
        "builds the word debugger to stop people inspecting it",
    ),
    (
        r#"(?-u)\[\s*['"](?:ev|eva|e)['"]\s*\+\s*['"](?:al|l|val)['"]\s*\]"#,
        "builds the word eval out of pieces so a search can't find it",
    ),
];

/// Ways around anything watching normal calls. Test suites for runtimes use these
/// honestly, so in tests they're listed as a warning.
const ROUTES_AROUND: [(&str, &str); 2] = [
    (
        r#"(?-u)\bprocess\.binding\s*\(\s*['"](?:spawn_sync|process_wrap|tcp_wrap|pipe_wrap)['"]|\bprocess\.mainModule\.require\b|\bmodule\.constructor\._load\b"#,
        "reaches into Node's internals, a way around anything watching normal calls",
    ),
    (
        r#"(?-u)\b__builtins__\b[^\n]{0,40}['"](?:exec|eval|__import__)['"]|\bglobals\(\)\s*\[\s*['"]__builtins__['"]\s*\]"#,
        "reaches into Python's built-ins, a way to hide a call to eval or exec",
    ),
];
/// Node's own modules that can't run anything, reach the network or read files, so
/// building one of these names out of pieces can't be hiding much. Anything else
/// built this way counts, including packages Airlock has never heard of.
const HARMLESS_MODULES: [&str; 7] = [
    "url",
    "path",
    "util",
    "events",
    "assert",
    "querystring",
    "string_decoder",
];

static COMPILED_ROUTES_AROUND: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    ROUTES_AROUND
        .iter()
        .map(|(pattern, what)| (compile(pattern), *what))
        .collect()
});
/// `require('child_' + 'process')`, and whether more follows after the last piece.
static MODULE_IN_PIECES: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r#"(?-u)\b(?:require|import)\s*\(\s*((?:['"`][\w:./-]{0,30}['"`]\s*\+\s*)+['"`][\w:./-]{0,30}['"`])\s*(\+)?"#,
    )
});
static QUOTED_PIECE: LazyLock<Regex> = LazyLock::new(|| compile(r#"(?-u)['"`]([\w:./-]*)['"`]"#));

static COMPILED_FINGERPRINTS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    FINGERPRINTS
        .iter()
        .map(|(pattern, what)| (compile(pattern), *what))
        .collect()
});

/// Names picked by obfuscators. The `l` and `I` names look identical on screen.
static SCRAMBLED_NAME: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?-u)_0x[0-9a-fA-F]{3,}|\b__Ox[0-9a-f]{4,}\b|\b_\$_[0-9a-f]{4}\b"));
static CONFUSING_NAME: LazyLock<Regex> = LazyLock::new(|| compile(r"(?-u)\b[lI]{8,}\b"));
/// Minifiers shorten numbers and write `a.push`, while obfuscators write
/// `a(0xd0)`, `a[0x3]`, `!0x0` and `a['push'](`.
static OBFUSCATED_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r#"(?i-u)[\w$]\(\s*0x[0-9a-f]+\s*\)|\[0x[0-9a-f]+\]|!0x[01]\b|\[['"](?:push|shift|length|from|replace|split|join|slice|charCodeAt|toString|indexOf|concat|map|call|apply)['"]\]"#,
    )
});
static CODE_WORD: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?-u)\b(?:function|return|require|import|const|var|let|def|class|eval|exec|fetch|await|if|for|while|try|catch)\b|=>",
    )
});
/// Enough to tell code from a table of text or data.
static LOOKS_LIKE_CODE: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?i-u)[=({;]|\b(?:require|import|const|var|let|function|eval|exec|fetch|curl|wget|atob|def|class|system|buffer|powershell|bash|sh|python|node)\b",
    )
});
static LOOKS_LIKE_RUNNING_CODE: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?i-u)\b(?:require|import|eval|exec|fetch|atob|system|powershell)\s*\(|\b(?:curl|wget)\s|child_process",
    )
});
/// Markup has attributes everywhere, so it needs something that really runs.
static LOOKS_LIKE_SCRIPT: LazyLock<Regex> = LazyLock::new(|| {
    compile(r"(?i-u)<script|\b(?:eval|fetch|require|atob|document\.write|xmlhttprequest)\s*\(")
});

/// Text direction overrides can make code display in a different order than it
/// runs, known as Trojan Source.
static DIRECTION_OVERRIDE: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?-u)\xE2\x80[\xAA-\xAE]|\xE2\x81[\xA6-\xA9]"));
/// Korean filler characters look like nothing at all, and can be variable names.
static INVISIBLE_NAME: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?-u)\xE3\x85\xA4|\xE1\x85[\x9F\xA0]|\xEF\xBE\xA0"));
/// Long runs of characters that never display. Whole programs and hidden prompts
/// for AI tools have been carried this way. Tags hold one byte each, and so do
/// variation selectors. Emoji use one selector at a time, never a run, and the
/// longest honest use of tags is the six in the flag of England.
static INVISIBLE_RUN: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?-u)(?:\xF3\xA0[\x80-\x87][\x80-\xBF]|\xEF\xB8[\x80-\x8F]){8,}|(?:\xE2\x80[\x8B-\x8D]|\xE2\x81[\xA0-\xA4]|\xC2\xAD){8,}",
    )
});
/// Raw terminal codes in source can hide or overwrite text when a file is printed
/// with `cat`, such as moving back over a line or setting text to invisible.
static TERMINAL_TRICK: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?-u)\x1b\[(?:8m|\d*[AK]|2J|H|\d+;\d+H)"));

fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).expect("patterns are constants covered by tests")
}

/// Formats where long lines and wide gaps are normal, and which don't run.
const DATA_EXTENSIONS: [&str; 16] = [
    "csv", "tsv", "txt", "log", "sql", "dat", "map", "svg", "xml", "po", "pot", "strings", "xlf",
    "snap", "lock", "ndjson",
];
const MARKUP_EXTENSIONS: [&str; 4] = ["html", "htm", "vue", "svelte"];
/// Low-level code is full of hex numbers, in tables and in calls.
const NATIVE_EXTENSIONS: [&str; 17] = [
    "c", "h", "cc", "cpp", "cxx", "hpp", "hh", "inc", "rs", "go", "java", "kt", "swift", "cs", "s",
    "asm", "py",
];
/// Programming languages, where characters that hide text have no honest use.
/// Other files, such as Illustrator documents, only look like text at the start.
const CODE_EXTENSIONS: [&str; 44] = [
    "js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx", "vue", "svelte", "py", "rb", "php", "sh",
    "bash", "zsh", "fish", "ps1", "psm1", "bat", "cmd", "pl", "pm", "lua", "go", "rs", "java",
    "kt", "kts", "swift", "c", "h", "cc", "cpp", "cxx", "hpp", "cs", "scala", "sol", "dart", "ex",
    "exs", "gradle", "groovy",
];
/// Where people expect a line of code to be readable.
const SCRIPT_EXTENSIONS: [&str; 16] = [
    "js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx", "py", "rb", "php", "sh", "bash", "ps1",
    "pl", "lua",
];
/// Places minified code is normally kept, so it isn't surprising to find it.
const MINIFIED_FOLDERS: [&str; 14] = [
    "dist/",
    "build/",
    "out/",
    "vendor/",
    "vendors/",
    "third_party/",
    "third-party/",
    "public/",
    "static/",
    "assets/",
    "lib/",
    "libs/",
    "bower_components/",
    ".yarn/",
];
const MINIFIED_NAME_MARKS: [&str; 7] = [
    ".min.", "-min.", ".bundle.", "-bundle.", ".prod.", ".umd.", ".packed.",
];

/// Records anything in a file written to stop people reading it.
pub fn scan(file: &RepoFile, report: &mut Report) {
    if is_binary(&file.contents) || classify(file.path.raw()) == FileClass::Lockfile {
        return;
    }
    scan_invisible_text(file, report);

    if classify(file.path.raw()) != FileClass::Code {
        return;
    }
    let extension = extension_of(file.path.raw());
    if extension == "map" {
        return;
    }

    scan_fingerprints(file, report);
    scan_scrambled_names(file, report);
    if !DATA_EXTENSIONS.contains(&extension.as_str()) {
        scan_layout(file, &extension, report);
    }
}

fn extension_of(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.rsplit_once('.')
        .map_or(String::new(), |(_, extension)| {
            extension.to_ascii_lowercase()
        })
}

/// The line a byte offset falls on, counting from 1.
fn line_at(contents: &[u8], offset: usize) -> u64 {
    contents[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count() as u64
        + 1
}

fn add_disguised(file: &RepoFile, kind: Kind, subject: &str, line: u64, report: &mut Report) {
    report.add(
        kind,
        "",
        subject,
        Some(At {
            path: &file.path,
            line: Some(line),
        }),
    );
    report.mark_disguised(file.path.raw());
}

fn scan_fingerprints(file: &RepoFile, report: &mut Report) {
    let contents = file.contents.as_slice();
    for (pattern, what) in COMPILED_FINGERPRINTS.iter() {
        if let Some(found) = pattern.find(contents) {
            let line = line_at(contents, found.start());
            add_disguised(file, Kind::ObfuscatedCode, what, line, report);
        }
    }
    for (pattern, what) in COMPILED_ROUTES_AROUND.iter() {
        if let Some(found) = pattern.find(contents) {
            let line = line_at(contents, found.start());
            if is_test_path(file.path.raw()) {
                let at = Some(At {
                    path: &file.path,
                    line: Some(line),
                });
                report.add(Kind::InternalsInTests, "", what, at);
            } else {
                add_disguised(file, Kind::ObfuscatedCode, what, line, report);
            }
        }
    }
    scan_modules_in_pieces(file, report);
}

/// Puts a split-up module name back together to see what it really is.
fn scan_modules_in_pieces(file: &RepoFile, report: &mut Report) {
    let contents = file.contents.as_slice();

    for captures in MODULE_IN_PIECES.captures_iter(contents) {
        let Some(pieces) = captures.get(1) else {
            continue;
        };
        let name: Vec<u8> = QUOTED_PIECE
            .captures_iter(pieces.as_bytes())
            .filter_map(|piece| piece.get(1))
            .flat_map(|piece| piece.as_bytes().iter().copied())
            .collect();
        let name = name.strip_prefix(b"node:").unwrap_or(&name);

        // A path to the project's own file, as in `require('./locale/' + 'en')`.
        let is_local_file = matches!(name.first(), Some(b'.' | b'/'));
        // With more to come, the final name can't be known.
        let is_complete = captures.get(2).is_none();
        let is_harmless = is_complete
            && HARMLESS_MODULES
                .iter()
                .any(|module| module.as_bytes() == name);

        if !is_local_file && !is_harmless {
            let what = "builds a module's name out of pieces so a search can't find it";
            let line = line_at(contents, pieces.start());
            if is_test_path(file.path.raw()) {
                let at = Some(At {
                    path: &file.path,
                    line: Some(line),
                });
                report.add(Kind::InternalsInTests, "", what, at);
            } else {
                add_disguised(file, Kind::ObfuscatedCode, what, line, report);
            }
            return;
        }
    }
}

fn scan_scrambled_names(file: &RepoFile, report: &mut Report) {
    let contents = file.contents.as_slice();

    for (pattern, minimum) in [
        (&*SCRAMBLED_NAME, MIN_SCRAMBLED_NAMES),
        // Plenty of honest names are long, so this needs many to count.
        (&*CONFUSING_NAME, MIN_SCRAMBLED_NAMES * 3),
    ] {
        let mut matches = pattern.find_iter(contents);
        let Some(first) = matches.next() else {
            continue;
        };
        let count = matches.count() + 1;
        if count >= minimum {
            let name = Untrusted::from_bytes(first.as_bytes());
            let subject = format!("{count} scrambled names such as {}", name.raw());
            let line = line_at(contents, first.start());
            add_disguised(file, Kind::ObfuscatedCode, &subject, line, report);
        }
    }
}

/// Measures every line, because how the file is laid out is the trick here.
fn scan_layout(file: &RepoFile, extension: &str, report: &mut Report) {
    let is_native = NATIVE_EXTENSIONS.contains(&extension);
    let contents = file.contents.as_slice();
    // Tests of how code handles odd layouts are full of odd layouts, so these
    // need to show something that really runs.
    let hint: &Regex = if MARKUP_EXTENSIONS.contains(&extension) {
        &LOOKS_LIKE_SCRIPT
    } else if is_test_path(file.path.raw()) {
        &LOOKS_LIKE_RUNNING_CODE
    } else {
        &LOOKS_LIKE_CODE
    };

    let mut number = 0_u64;
    let mut blank_lines = 0_usize;
    let mut seen_content = false;
    let mut long_line_bytes = 0;
    let mut coded_long_line = None;
    let mut found_gap = false;

    for line in contents.split(|byte| *byte == b'\n') {
        number += 1;

        if line.trim_ascii().is_empty() {
            blank_lines += 1;
            continue;
        }
        if seen_content
            && blank_lines >= OFF_SCREEN_BLANK_LINES
            && !found_gap
            && is_visible_code(line.trim_ascii_start(), hint)
        {
            let what = format!("after {blank_lines} blank lines: {}", snippet(line));
            add_disguised(file, Kind::OffScreenCode, &what, number, report);
            found_gap = true;
        }
        blank_lines = 0;
        seen_content = true;

        if line.len() >= OFF_SCREEN_GAP && !found_gap {
            if let Some((gap, rest)) = off_screen_part(line, hint) {
                let what = format!("after {gap} blank characters: {}", snippet(rest));
                add_disguised(file, Kind::OffScreenCode, &what, number, report);
                found_gap = true;
            }
        }

        if line.len() >= LONG_LINE_BYTES / 4 && !is_native {
            let tokens = OBFUSCATED_TOKEN.find_iter(line).count();
            if tokens >= MIN_OBFUSCATED_TOKENS {
                let what = "written with hex numbers and quoted method names, as obfuscators do";
                add_disguised(file, Kind::ObfuscatedCode, what, number, report);
            }
        }

        if line.len() >= LONG_LINE_BYTES {
            long_line_bytes += line.len();
            if coded_long_line.is_none() && CODE_WORD.find_iter(line).count() >= MIN_CODE_WORDS {
                coded_long_line = Some((number, line.len()));
            }
        }
    }

    if SCRIPT_EXTENSIONS.contains(&extension) {
        report_long_lines(file, long_line_bytes, coded_long_line, report);
    }
}

/// Whether text past a gap is code, and not just a comment someone lined up.
fn is_visible_code(text: &[u8], hint: &Regex) -> bool {
    let is_comment = [&b"//"[..], b"#", b"/*", b"*", b"--", b"<!--", b"%"]
        .iter()
        .any(|mark| text.starts_with(mark));
    !is_comment && hint.is_match(text)
}

/// Finds code separated from the visible part of a line by a wide gap.
fn off_screen_part<'a>(line: &'a [u8], hint: &Regex) -> Option<(usize, &'a [u8])> {
    let mut at = 0;
    while at < line.len() {
        if !matches!(line[at], b' ' | b'\t') {
            at += 1;
            continue;
        }
        let start = at;
        while at < line.len() && matches!(line[at], b' ' | b'\t') {
            at += 1;
        }
        let gap = at - start;
        let minimum = if start == 0 {
            OFF_SCREEN_INDENT
        } else {
            OFF_SCREEN_GAP
        };
        if gap < minimum || at == line.len() {
            continue;
        }

        let rest = &line[at..];
        if is_visible_code(rest, hint) {
            return Some((gap, rest));
        }
    }
    None
}

fn snippet(line: &[u8]) -> String {
    let kept = &line[..line.len().min(MAX_SNIPPET_BYTES)];
    Untrusted::from_bytes(kept.trim_ascii()).raw().to_string()
}

fn report_long_lines(
    file: &RepoFile,
    long_line_bytes: usize,
    coded_long_line: Option<(u64, usize)>,
    report: &mut Report,
) {
    // Long lines with no code words are data, such as a picture or a table.
    if long_line_bytes == 0 || coded_long_line.is_none() {
        return;
    }
    let path = file.path.raw();
    let is_minified = long_line_bytes * 100 >= file.contents.len() * MINIFIED_PERCENT;

    if is_minified {
        if is_usual_place_for_minified_code(path) {
            report.add(Kind::MinifiedCode, "", path, None);
        } else {
            let detail = format!(
                "{} bytes in a file named like source code",
                file.contents.len()
            );
            report.add_detail(Kind::LongCodeLine, path, &detail);
            report.mark_disguised(path);
        }
    } else if is_usual_place_for_minified_code(path) {
        report.add(Kind::MinifiedCode, "", path, None);
    } else if let Some((line, length)) = coded_long_line {
        let what = format!("a line of {length} characters among normal ones");
        report.add(
            Kind::LongCodeLine,
            "",
            &what,
            Some(At {
                path: &file.path,
                line: Some(line),
            }),
        );
        report.mark_disguised(path);
    }
}

fn is_usual_place_for_minified_code(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);

    is_test_path(path)
        || MINIFIED_NAME_MARKS.iter().any(|mark| name.contains(mark))
        || MINIFIED_FOLDERS
            .iter()
            .any(|folder| lower.starts_with(folder) || lower.contains(&format!("/{folder}")))
}

fn scan_invisible_text(file: &RepoFile, report: &mut Report) {
    let contents = file.contents.as_slice();
    let path = file.path.raw();
    let is_code =
        classify(path) == FileClass::Code && CODE_EXTENSIONS.contains(&extension_of(path).as_str());

    if let Some(found) = INVISIBLE_RUN.find(contents) {
        let hidden = decode_invisible(found.as_bytes());
        let what = if hidden.is_empty() {
            format!("{} bytes of characters that don't display", found.len())
        } else {
            format!("characters that don't display, spelling out: {hidden}")
        };
        let line = line_at(contents, found.start());
        add_disguised(file, Kind::InvisibleText, &what, line, report);
    }

    // Right-to-left text and translations use these honestly, but code has no need.
    if is_code {
        // Bundled libraries handle text in every language, and nobody reviews them
        // line by line anyway, so there's nothing for these to fool.
        let kind = if is_usual_place_for_minified_code(path) {
            Kind::UnusualCharacters
        } else {
            Kind::InvisibleText
        };
        if let Some(found) = DIRECTION_OVERRIDE.find(contents) {
            if !is_in_character_table(contents, found.start(), found.end()) {
                let what = "text direction overrides, so the code may not run as it reads";
                let line = line_at(contents, found.start());
                add_invisible(file, kind, what, line, report);
            }
        }
        let blank_name = INVISIBLE_NAME
            .find_iter(contents)
            .find(|found| !is_in_character_table(contents, found.start(), found.end()));
        if let Some(found) = blank_name {
            let what = "a blank-looking character that can be used as a variable name";
            let line = line_at(contents, found.start());
            add_invisible(file, kind, what, line, report);
        }
        // Bundled tools use these to draw progress bars.
        if let Some(found) = TERMINAL_TRICK.find(contents) {
            let what = "terminal codes that can hide text when this file is printed";
            let line = line_at(contents, found.start());
            add_invisible(file, Kind::UnusualCharacters, what, line, report);
        }
        scan_lookalike_letters(file, report);
    }
}

fn add_invisible(file: &RepoFile, kind: Kind, what: &str, line: u64, report: &mut Report) {
    if kind == Kind::InvisibleText {
        add_disguised(file, kind, what, line, report);
    } else {
        report.add(
            kind,
            "",
            what,
            Some(At {
                path: &file.path,
                line: Some(line),
            }),
        );
    }
}

/// Text-handling libraries contain tables of every odd character, side by side or
/// as ranges like `a-b`. A trick has to sit among ordinary code to do anything.
fn is_in_character_table(contents: &[u8], start: usize, end: usize) -> bool {
    let before = start.checked_sub(1).map(|at| contents[at]);
    let after = contents.get(end).copied();
    let is_table_neighbor =
        |byte: Option<u8>| byte.is_some_and(|byte| byte >= 0x80 || byte == b'-');

    is_table_neighbor(before) || is_table_neighbor(after)
}

/// Reads what a run of invisible characters encodes, if it encodes readable text.
/// A tag character holds one ASCII letter, and a variation selector holds one byte.
fn decode_invisible(run: &[u8]) -> String {
    let text = String::from_utf8_lossy(run);
    let mut bytes = Vec::new();

    for ch in text.chars() {
        let code = ch as u32;
        match code {
            0xE0000..=0xE007F => bytes.push((code - 0xE0000) as u8),
            0xFE00..=0xFE0F => bytes.push((code - 0xFE00) as u8),
            0xE0100..=0xE01EF => bytes.push((code - 0xE0100 + 16) as u8),
            _ => return String::new(),
        }
    }
    let is_readable = bytes
        .iter()
        .all(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace());
    if is_readable {
        snippet(&bytes)
    } else {
        String::new()
    }
}

/// Letters from other alphabets that look just like Latin ones. A name mixing
/// them with Latin letters is either a typing accident or an imitation.
fn is_lookalike_letter(ch: char) -> bool {
    matches!(
        ch,
        'а' | 'е'
            | 'о'
            | 'р'
            | 'с'
            | 'у'
            | 'х'
            | 'і'
            | 'ј'
            | 'ѕ'
            | 'һ'
            | 'А'
            | 'В'
            | 'Е'
            | 'К'
            | 'М'
            | 'Н'
            | 'О'
            | 'Р'
            | 'С'
            | 'Т'
            | 'Х'
            | 'Ι'
            | 'Ο'
            | 'Α'
            | 'Β'
            | 'Ε'
            | 'Κ'
            | 'Ν'
            | 'Τ'
            | 'Χ'
            | 'ο'
            | 'ν'
            | 'ι'
    )
}

fn scan_lookalike_letters(file: &RepoFile, report: &mut Report) {
    if file.contents.is_ascii() {
        return;
    }
    let text = String::from_utf8_lossy(&file.contents);

    for (index, line) in text.lines().enumerate() {
        if line.is_ascii() {
            continue;
        }
        for token in line.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$')) {
            let has_latin = token.chars().any(|c| c.is_ascii_alphabetic());
            let mut others = token.chars().filter(|c| !c.is_ascii());
            let first_other = others.next();
            let all_lookalikes =
                first_other.is_some_and(is_lookalike_letter) && others.all(is_lookalike_letter);

            if has_latin && all_lookalikes {
                let shown: String = token
                    .chars()
                    .map(|c| {
                        if c.is_ascii() {
                            c.to_string()
                        } else {
                            c.escape_unicode().to_string()
                        }
                    })
                    .collect();
                report.add(
                    Kind::LookalikeLetters,
                    "",
                    &shown,
                    Some(At {
                        path: &file.path,
                        line: Some(index as u64 + 1),
                    }),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_text(path: &str, contents: &[u8]) -> Report {
        let file = RepoFile {
            path: Untrusted::from_bytes(path.as_bytes()),
            contents: contents.to_vec(),
        };
        let mut report = Report::new();
        scan(&file, &mut report);
        report
    }

    fn count(report: &Report, kind: Kind) -> usize {
        report.listed(kind).len()
    }

    /// Code shaped like a real obfuscator's output, doing nothing at all.
    fn obfuscator_line() -> String {
        let mut line = String::from(
            "const aR=F;(function(aD,aE){const aQ=F,aF=aD();while(!![]){try{const aG=parseInt(aQ(0xd0))/0x1+-parseInt(aQ(0xd2))/0x2;if(aG===aE)break;else aF['push'](aF['shift']());}catch(aH){aF['push'](aF['shift']());}}}(D,0xac73e));",
        );
        for number in 0..30 {
            line.push_str(&format!("x(0x{number:x});"));
        }
        line
    }

    #[test]
    fn finds_names_chosen_by_an_obfuscator() {
        let text = "var _0x3b486b=1;".repeat(MIN_SCRAMBLED_NAMES);
        let report = scan_text("next.config.js", text.as_bytes());

        assert_eq!(
            report.listed(Kind::ObfuscatedCode),
            [(
                format!("{MIN_SCRAMBLED_NAMES} scrambled names such as _0x3b486b"),
                1
            )]
        );
        assert!(report.is_disguised("next.config.js"));
    }

    #[test]
    fn a_few_names_of_that_shape_are_not_enough() {
        let report = scan_text("dump.js", b"sub_0x401000 sub_0x401100 loc_0x401200\n");

        assert_eq!(count(&report, Kind::ObfuscatedCode), 0);
    }

    #[test]
    fn finds_an_obfuscator_that_does_not_use_those_names() {
        let report = scan_text("server/routes/a.js", obfuscator_line().as_bytes());

        let subjects: Vec<String> = report
            .listed(Kind::ObfuscatedCode)
            .into_iter()
            .map(|(subject, _)| subject)
            .collect();
        assert!(subjects.iter().any(|s| s.contains("while(!![])")));
        assert!(subjects.iter().any(|s| s.contains("hidden table")));
        assert!(subjects.iter().any(|s| s.contains("hex numbers")));
    }

    #[test]
    fn finds_other_known_packers() {
        for text in [
            "eval(function(p,a,c,k,e,d){return p})",
            "[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]]",
            "$=~[];$={___:++$,$$$$:(![]+\"\")[$]}",
            "from pytransform import pyarmor_runtime\npyarmor_runtime()",
            "a['constructor']('debu' + 'gger')",
        ] {
            let report = scan_text("a.js", text.as_bytes());

            assert_eq!(count(&report, Kind::ObfuscatedCode), 1, "{text}");
        }
    }

    #[test]
    fn finds_names_built_out_of_pieces_and_routes_around_normal_calls() {
        for text in [
            "const c = require('child_' + 'process');",
            "global['ev' + 'al'](x)",
            "process.binding('spawn_sync')",
            "process.mainModule.require('fs')",
            "module.constructor._load('fs')",
            "__builtins__.__dict__['exec'](x)",
            "globals()['__builtins__']",
        ] {
            let report = scan_text("a.js", text.as_bytes());

            assert_eq!(count(&report, Kind::ObfuscatedCode), 1, "{text}");
        }
    }

    #[test]
    fn module_names_in_pieces_are_read_before_judging_them() {
        for text in [
            "require('chi' + 'ld_pro' + 'cess')",
            "require('node:' + 'child_process')",
            "require(`child_` + `process`)",
            "import('child_' + 'process')",
            "require('f' + 's')",
            "require('ax' + 'ios')",
            // A package nobody has heard of could be anything.
            "require('some-pack' + 'age')",
            // The rest of the name could be anything too.
            "require('u' + 'rl' + suffix)",
            "require('chi' + 'ld_' + rest)",
        ] {
            let report = scan_text("a.js", text.as_bytes());

            assert_eq!(count(&report, Kind::ObfuscatedCode), 1, "{text}");
        }
        for text in [
            "require('u' + 'rl').pathToFileURL(p).href",
            "require('node:' + 'url')",
            "require('pa' + 'th')",
            "require('./locale/' + 'en')",
            "require('./locale/' + 'en' + name)",
        ] {
            let report = scan_text("a.js", text.as_bytes());

            assert_eq!(count(&report, Kind::ObfuscatedCode), 0, "{text}");
        }
    }

    #[test]
    fn a_module_name_in_pieces_is_only_a_warning_in_tests() {
        let text = b"await import('some-' + 'module')";
        let report = scan_text("tests/specs/run/a.out", text);

        assert_eq!(count(&report, Kind::InternalsInTests), 1);
        assert_eq!(count(&report, Kind::ObfuscatedCode), 0);
    }

    #[test]
    fn reaching_into_internals_is_only_a_warning_in_tests() {
        for text in [
            "process.binding('tcp_wrap')",
            "process.mainModule.require('fs')",
        ] {
            let test = scan_text("tests/unit/a.ts", text.as_bytes());
            assert_eq!(count(&test, Kind::InternalsInTests), 1, "{text}");
            assert_eq!(count(&test, Kind::ObfuscatedCode), 0, "{text}");

            let code = scan_text("src/a.ts", text.as_bytes());
            assert_eq!(count(&code, Kind::ObfuscatedCode), 1, "{text}");
            assert_eq!(count(&code, Kind::InternalsInTests), 0, "{text}");
        }
    }

    #[test]
    fn building_a_path_to_require_is_fine() {
        for text in [
            "require('./locale/' + name)",
            "require(base + '/index.js')",
            "process.binding('fs')",
        ] {
            let report = scan_text("a.js", text.as_bytes());

            assert_eq!(count(&report, Kind::ObfuscatedCode), 0, "{text}");
        }
    }

    #[test]
    fn minified_code_is_not_called_obfuscated() {
        let minified = "function a(b,c){return b.push(c),b.length}var d=a([],1);".repeat(200);

        for path in ["dist/app.min.js", "src/app.js"] {
            let report = scan_text(path, minified.as_bytes());

            assert_eq!(count(&report, Kind::ObfuscatedCode), 0, "{path}");
            assert_eq!(count(&report, Kind::OffScreenCode), 0, "{path}");
        }
    }

    #[test]
    fn low_level_code_can_be_full_of_hex() {
        let table = "REG(0x10), ".repeat(100);

        for path in ["driver.c", "table.h", "tables.rs"] {
            let report = scan_text(path, table.as_bytes());

            assert_eq!(count(&report, Kind::ObfuscatedCode), 0, "{path}");
        }
    }

    #[test]
    fn finds_code_pushed_off_the_edge_of_the_screen() {
        let gap = " ".repeat(908);
        let text = format!("module.exports = router;{gap}const a=require('fs');\n");
        let report = scan_text("server/routes/a.js", text.as_bytes());

        assert_eq!(
            report.listed(Kind::OffScreenCode),
            [(
                "after 908 blank characters: const a=require('fs');".to_string(),
                1
            )]
        );
        assert!(report.is_disguised("server/routes/a.js"));
    }

    #[test]
    fn finds_code_pushed_off_with_tabs_and_gives_the_right_line() {
        let gap = "\t".repeat(OFF_SCREEN_GAP);
        let text = format!("one\ntwo\nx = 1;{gap}eval(y)\n");
        let report = scan_text("a.py", text.as_bytes());

        let (subject, _) = &report.listed(Kind::OffScreenCode)[0];
        assert_eq!(report.first_line(Kind::OffScreenCode, subject), Some(3));
    }

    #[test]
    fn finds_code_pushed_far_below_the_visible_part_of_a_file() {
        let blanks = "\n".repeat(OFF_SCREEN_BLANK_LINES + 1);
        let text = format!("module.exports = a;{blanks}require('child_process')\n");
        let report = scan_text("a.js", text.as_bytes());

        assert_eq!(count(&report, Kind::OffScreenCode), 1);
    }

    #[test]
    fn honest_layout_is_not_off_screen_code() {
        let wide = " ".repeat(OFF_SCREEN_GAP + 10);
        for (path, text) in [
            // Lining up a comment.
            ("a.js", format!("let a = 1;{wide}// the first\n")),
            ("a.py", format!("a = 1{wide}# the first\n")),
            // Trailing spaces.
            ("a.js", format!("let a = 1;{wide}\n")),
            // Plain columns of data.
            ("a.js", format!("name{wide}value\n")),
            ("data.csv", format!("a = 1;{wide}eval(b)\n")),
            ("data.txt", format!("a = 1;{wide}eval(b)\n")),
            // Deep indentation.
            ("gen.js", format!("{wide}x = 1;\n")),
            // Markup is indented heavily, and only a script matters.
            ("a.html", format!("<p>a</p>{wide}<p class=\"b\">c</p>\n")),
        ] {
            let report = scan_text(path, text.as_bytes());

            assert_eq!(count(&report, Kind::OffScreenCode), 0, "{path}: {text}");
        }
    }

    #[test]
    fn a_script_pushed_off_screen_in_markup_is_found() {
        let wide = " ".repeat(OFF_SCREEN_GAP + 10);
        let text = format!("<p>a</p>{wide}<script>go()</script>\n");

        assert_eq!(
            count(&scan_text("a.html", text.as_bytes()), Kind::OffScreenCode),
            1
        );
    }

    #[test]
    fn minified_code_in_the_usual_places_gets_a_note() {
        let minified = "function a(b){return b}".repeat(100);

        for path in [
            "dist/app.js",
            "static/js/app.js",
            "vendor/lib.js",
            "src/jquery.min.js",
        ] {
            let report = scan_text(path, minified.as_bytes());

            assert_eq!(count(&report, Kind::MinifiedCode), 1, "{path}");
            assert_eq!(count(&report, Kind::LongCodeLine), 0, "{path}");
        }
    }

    #[test]
    fn minified_code_named_like_source_gets_a_warning() {
        let minified = "function a(b){return b}".repeat(100);
        let report = scan_text("next.config.js", minified.as_bytes());

        assert_eq!(count(&report, Kind::LongCodeLine), 1);
        assert!(report.is_disguised("next.config.js"));
    }

    #[test]
    fn one_huge_line_of_code_among_normal_ones_gets_a_warning() {
        let huge = "function a(b){return b}".repeat(100);
        let normal = "const x = 1;\n".repeat(400);
        let text = format!("{normal}{huge}\n");
        let report = scan_text("server/a.js", text.as_bytes());

        let (subject, _) = &report.listed(Kind::LongCodeLine)[0];
        assert!(subject.contains("2300 characters"), "{subject}");
        assert_eq!(report.first_line(Kind::LongCodeLine, subject), Some(401));
    }

    #[test]
    fn long_lines_of_data_are_fine() {
        let data = format!("const a = \"{}\";\n", "x".repeat(LONG_LINE_BYTES * 2));
        let normal = "const x = 1;\n".repeat(400);
        let report = scan_text("src/a.js", format!("{normal}{data}").as_bytes());

        assert_eq!(count(&report, Kind::LongCodeLine), 0);
        assert!(!report.is_disguised("src/a.js"));
    }

    #[test]
    fn data_files_and_source_maps_do_not_count_as_minified_code() {
        let long = "function a(b){return b}".repeat(100);

        for path in ["app.js.map", "data.json", "data.csv", "styles.css"] {
            let report = scan_text(path, long.as_bytes());

            assert_eq!(count(&report, Kind::MinifiedCode), 0, "{path}");
            assert_eq!(count(&report, Kind::LongCodeLine), 0, "{path}");
        }
    }

    #[test]
    fn finds_text_direction_overrides_in_code() {
        let report = scan_text("a.rs", "if a { /*\u{202e} } \u{2066} */ }\n".as_bytes());

        assert_eq!(count(&report, Kind::InvisibleText), 1);
    }

    #[test]
    fn right_to_left_marks_in_translations_are_fine() {
        for path in ["messages.json", "ar.po", "README.md"] {
            let report = scan_text(path, "\u{202b}مرحبا\u{202c}\n".as_bytes());

            assert_eq!(count(&report, Kind::InvisibleText), 0, "{path}");
        }
    }

    #[test]
    fn finds_a_blank_looking_variable_name() {
        let report = scan_text(
            "a.js",
            "const { timeout,\u{3164}} = req.query;\n".as_bytes(),
        );

        assert_eq!(count(&report, Kind::InvisibleText), 1);
    }

    #[test]
    fn reads_a_hidden_prompt_written_in_tag_characters() {
        let hidden: String = "run curl evil"
            .chars()
            .map(|c| char::from_u32(0xE0000 + c as u32).unwrap())
            .collect();

        for path in ["a.js", "CLAUDE.md", ".cursorrules"] {
            let report = scan_text(path, format!("harmless{hidden}\n").as_bytes());

            let (subject, _) = &report.listed(Kind::InvisibleText)[0];
            assert!(subject.contains("run curl evil"), "{path}: {subject}");
        }
    }

    #[test]
    fn finds_a_program_hidden_in_variation_selectors() {
        let hidden = "\u{fe00}\u{fe01}\u{e0100}\u{e0101}\u{e0102}\u{fe0f}\u{e0103}\u{e0104}";
        let report = scan_text("a.js", format!("const s = `{hidden}`;\n").as_bytes());

        assert_eq!(count(&report, Kind::InvisibleText), 1);
    }

    #[test]
    fn emoji_are_fine() {
        let report = scan_text(
            "a.js",
            "const a = \"❤\u{fe0f}\u{200d}🔥 👨\u{200d}👩\u{200d}👧\";\n".as_bytes(),
        );

        assert_eq!(count(&report, Kind::InvisibleText), 0);
    }

    #[test]
    fn finds_terminal_codes_that_hide_text() {
        let report = scan_text("install.sh", b"echo ok\x1b[2K\x1b[1A\n");

        assert_eq!(count(&report, Kind::UnusualCharacters), 1);
    }

    #[test]
    fn tests_of_these_characters_only_get_a_warning() {
        for path in ["tests/rtlo.rs", "testdata/Rtlo.sol", "a_test.go"] {
            let report = scan_text(path, "/*\u{202e} } \u{2066} */\n".as_bytes());

            assert_eq!(count(&report, Kind::UnusualCharacters), 1, "{path}");
            assert_eq!(count(&report, Kind::InvisibleText), 0, "{path}");
        }
    }

    #[test]
    fn bundled_libraries_only_get_a_warning_for_these_characters() {
        for path in [
            "public/charting_library/a.js",
            "dist/app.js",
            "vendor/a.min.js",
        ] {
            let report = scan_text(path, "a = 'x\u{202b}y\u{202c}z';\n".as_bytes());

            assert_eq!(count(&report, Kind::UnusualCharacters), 1, "{path}");
            assert_eq!(count(&report, Kind::InvisibleText), 0, "{path}");
        }
    }

    #[test]
    fn tables_of_odd_characters_are_fine() {
        for text in [
            // Ranges in a regular expression.
            "const r = /[\u{3164}-\u{318e}\u{202a}-\u{202e}]/;",
            "const r = \"\u{ffa0}\u{ffa1}\u{ffa2}\";",
        ] {
            let report = scan_text("xregexp.js", text.as_bytes());

            assert_eq!(count(&report, Kind::InvisibleText), 0, "{text}");
        }
    }

    #[test]
    fn flags_made_from_tag_characters_are_fine() {
        let england = "\u{1f3f4}\u{e0067}\u{e0062}\u{e0065}\u{e006e}\u{e0067}\u{e007f}";
        let report = scan_text("emoji.js", format!("a = '{england}';\n").as_bytes());

        assert_eq!(count(&report, Kind::InvisibleText), 0);
    }

    #[test]
    fn documents_that_only_look_like_text_are_not_searched_for_these() {
        let report = scan_text("logo.ai", "%PDF \u{3164} \u{202e}\n".as_bytes());

        assert_eq!(count(&report, Kind::InvisibleText), 0);
    }

    #[test]
    fn a_comment_far_below_is_not_hidden_code() {
        let blanks = "\n".repeat(OFF_SCREEN_BLANK_LINES + 1);
        let text = format!("a = 1;{blanks}//// the end\n");

        assert_eq!(
            count(&scan_text("a.js", text.as_bytes()), Kind::OffScreenCode),
            0
        );
    }

    #[test]
    fn a_wide_gap_in_a_test_needs_something_that_really_runs() {
        let wide = " ".repeat(OFF_SCREEN_GAP + 10);
        let harmless = format!("a = 1;{wide}hello '>;\n");
        let hidden = format!("a = 1;{wide}require('fs')\n");

        assert_eq!(
            count(
                &scan_text("test/a.js", harmless.as_bytes()),
                Kind::OffScreenCode
            ),
            0
        );
        assert_eq!(
            count(
                &scan_text("test/a.js", hidden.as_bytes()),
                Kind::OffScreenCode
            ),
            1
        );
    }

    #[test]
    fn minified_tests_only_get_a_note() {
        let minified = "function a(b){return b}".repeat(100);
        let report = scan_text("test/fixtures/a.js", minified.as_bytes());

        assert_eq!(count(&report, Kind::MinifiedCode), 1);
        assert_eq!(count(&report, Kind::LongCodeLine), 0);
    }

    #[test]
    fn long_lines_of_pictures_and_tables_are_not_code() {
        for text in [
            format!(
                "const a = <svg><path d=\"{}\"/></svg>;",
                "M1 2L3 4".repeat(200)
            ),
            format!("export const a = '{}';", "ab12".repeat(500)),
        ] {
            let report = scan_text("src/logo.tsx", text.as_bytes());

            assert_eq!(count(&report, Kind::LongCodeLine), 0);
        }
    }

    #[test]
    fn finds_names_mixing_in_lookalike_letters() {
        // The first letter is Cyrillic.
        let report = scan_text("a.js", "const \u{0430}dmin = 1;\n".as_bytes());

        assert_eq!(
            report.listed(Kind::LookalikeLetters),
            [("\\u{430}dmin".to_string(), 1)]
        );
    }

    #[test]
    fn words_in_other_languages_are_fine() {
        for line in ["// Привет world", "const имя = 'Wi-Fi';", "x = 'Ключ1'"] {
            let report = scan_text("a.js", line.as_bytes());

            assert_eq!(count(&report, Kind::LookalikeLetters), 0, "{line}");
        }
    }

    #[test]
    fn hostile_bytes_do_not_panic() {
        for contents in [
            &b"\xff\xfe\xfd"[..],
            b"\xF3\xA0",
            b"\xF3\xA0\x80\x80\xF3\xA0\x80\x80\xF3\xA0\x80\x80\xF3\xA0\x80",
            b"",
            b"\n\n\n",
        ] {
            scan_text("a.js", contents);
        }
        scan_text("a.js", " ".repeat(1024 * 1024).as_bytes());
        scan_text("a.js", "\n".repeat(1024 * 1024).as_bytes());
    }
}
