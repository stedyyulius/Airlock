//! Finds packages that don't come from the normal registry, and packages whose
//! names imitate popular ones.
//!
//! A malware database only knows about packages in a registry. A dependency that
//! points straight at a web address or a git repository can't be looked up at all,
//! and whatever is at that address can change whenever its owner likes. Attackers
//! use this to install code that no registry or scanner ever sees, even from a
//! lockfile where nobody would think to look.

use crate::git::RepoFile;
use crate::lookalike;
use crate::network::{host_of, is_binary, is_local, is_test_path};
use crate::report::{At, Kind, Report};
use crate::text::Untrusted;
use regex::bytes::Regex;
use serde_json::{Map, Value};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

/// The official registries, including where they keep their files.
const NORMAL_HOSTS: [&str; 18] = [
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "pypi.org",
    "pypi.python.org",
    "files.pythonhosted.org",
    "crates.io",
    "index.crates.io",
    "static.crates.io",
    "rubygems.org",
    "index.rubygems.org",
    "packagist.org",
    "repo.packagist.org",
    "services.gradle.org",
    "downloads.gradle.org",
    "repo.maven.apache.org",
    "repo1.maven.org",
    "api.nuget.org",
    "proxy.golang.org",
];
const CRATES_INDEX: &str = "github.com/rust-lang/crates.io-index";
const NPM_FIELDS: [&str; 4] = [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];
const NPM_OVERRIDE_FIELDS: [&str; 2] = ["overrides", "resolutions"];
const REMOTE_PREFIXES: [&str; 9] = [
    "http:",
    "https:",
    "git+",
    "git:",
    "git@",
    "ssh:",
    "github:",
    "gitlab:",
    "bitbucket:",
];

fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).expect("patterns are constants covered by tests")
}

static NPM_LOCK_RESOLVED: LazyLock<Regex> =
    LazyLock::new(|| compile(r#"(?m-u)^\s*resolved\s+"([^"\n]+)""#));
static YARN_BERRY_RESOLUTION: LazyLock<Regex> = LazyLock::new(|| {
    compile(r#"(?m-u)^\s*resolution:\s*"[^"@\n]*@?[^"@\n]*@((?:https?:|git[+:@]|ssh:)[^"\n]+)""#)
});
static PNPM_LOCATION: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?-u)\b(?:tarball|repo):\s*([^\s,}]+)"));
static NPMRC_REGISTRY: LazyLock<Regex> =
    LazyLock::new(|| compile(r#"(?m-u)^\s*(?:@[^:\n]+:)?registry\s*=\s*"?([^"\s]+)"#));
static YARNRC_REGISTRY: LazyLock<Regex> =
    LazyLock::new(|| compile(r#"(?m-u)^\s*(?:registry\s+"|npmRegistryServer:\s*["']?)([^"'\s]+)"#));
static BUNFIG_REGISTRY: LazyLock<Regex> =
    LazyLock::new(|| compile(r#"(?m-u)^\s*registry\s*=\s*"([^"\n]+)""#));
static REQUIREMENT_OPTION: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?m-u)^\s*(?:--index-url|--extra-index-url|--find-links|--trusted-host|-i|-f)[\s=]+(\S+)",
    )
});
static REQUIREMENT_LINK: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?m-u)^\s*(?:-e\s+|--editable[\s=]+|[A-Za-z0-9._-]+(?:\[[^\]]*\])?\s*@\s*)?((?:git\+|https?://)\S+)",
    )
});
static TOML_URL: LazyLock<Regex> =
    LazyLock::new(|| compile(r#"(?m-u)^\s*(?:url|git)\s*=\s*"([^"\n]+)""#));
static PYPROJECT_LOCATION: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r#"(?m-u)^\s*(?:url|git|index-url|extra-index-url)\s*=\s*"([^"\n]+)"|\bgit\s*=\s*"([^"\n]+)"|"[A-Za-z0-9._-]+\s*@\s*((?:https?://|git\+)[^"\n]+)""#,
    )
});
static UV_SOURCE: LazyLock<Regex> =
    LazyLock::new(|| compile(r#"(?m-u)^source\s*=\s*\{\s*(?:git|url|registry)\s*=\s*"([^"\n]+)""#));
static CARGO_LOCK_SOURCE: LazyLock<Regex> =
    LazyLock::new(|| compile(r##"(?m-u)^source\s*=\s*"(?:registry\+|sparse\+)?([^"#?\n]+)"##));
static CARGO_TOML_GIT: LazyLock<Regex> =
    LazyLock::new(|| compile(r#"(?-u)\bgit\s*=\s*"([^"\n]+)""#));
static GEMFILE_LOCATION: LazyLock<Regex> = LazyLock::new(|| {
    compile(r#"(?m-u)^\s*source\s+["']([^"'\n]+)["']|\bgit:\s*["']([^"'\n]+)["']"#)
});
static GEMFILE_LOCK_REMOTE: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?m-u)^\s*remote:\s*(\S+)"));
static NUGET_SOURCE: LazyLock<Regex> =
    LazyLock::new(|| compile(r#"(?i-u)<add\b[^>\n]*\bvalue="(https?://[^"\n]+)""#));
static WRAPPER_DISTRIBUTION: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?m-u)^\s*distributionUrl\s*=\s*(\S+)"));
static REQUIREMENT_NAME: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?m-u)^([A-Za-z0-9][A-Za-z0-9._-]*)"));

/// Records unusual package sources and imitated names in a file.
pub fn scan(file: &RepoFile, report: &mut Report) {
    if is_binary(&file.contents) {
        return;
    }
    let path = file.path.raw().replace('\\', "/");
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);

    match name {
        "package.json" => scan_package_json(file, report),
        "package-lock.json" | "npm-shrinkwrap.json" => scan_npm_lock(file, report),
        "yarn.lock" => {
            add_locations(file, &NPM_LOCK_RESOLVED, "a locked package", report);
            add_locations(file, &YARN_BERRY_RESOLUTION, "a locked package", report);
        }
        "pnpm-lock.yaml" => add_locations(file, &PNPM_LOCATION, "a locked package", report),
        ".npmrc" => add_locations(file, &NPMRC_REGISTRY, "npm package registry", report),
        ".yarnrc" | ".yarnrc.yml" => {
            add_locations(file, &YARNRC_REGISTRY, "yarn package registry", report);
        }
        "bunfig.toml" => add_locations(file, &BUNFIG_REGISTRY, "bun package registry", report),
        "pipfile" => add_locations(file, &TOML_URL, "a Python package source", report),
        "pyproject.toml" => {
            add_locations(file, &PYPROJECT_LOCATION, "a Python package source", report);
        }
        "poetry.lock" => add_locations(file, &TOML_URL, "a locked package", report),
        "uv.lock" => add_locations(file, &UV_SOURCE, "a locked package", report),
        "cargo.lock" => add_locations(file, &CARGO_LOCK_SOURCE, "a locked crate", report),
        "cargo.toml" => add_locations(file, &CARGO_TOML_GIT, "a crate from git", report),
        "go.mod" => scan_go_mod(file, report),
        "composer.json" => scan_composer_json(file, report),
        "gemfile" => add_locations(file, &GEMFILE_LOCATION, "a Ruby gem source", report),
        "gemfile.lock" => add_locations(file, &GEMFILE_LOCK_REMOTE, "a locked gem", report),
        "nuget.config" => add_locations(file, &NUGET_SOURCE, "a NuGet package source", report),
        "gradle-wrapper.properties" | "maven-wrapper.properties" => {
            add_locations(file, &WRAPPER_DISTRIBUTION, "the build tool itself", report);
        }
        name if name.starts_with("requirements") && name.ends_with(".txt") => {
            scan_requirements(file, report);
        }
        _ => {}
    }
}

/// Decides how a package address should be reported, if at all.
fn kind_of_address(address: &str) -> Option<(Kind, String)> {
    let address = address.trim();
    let address = address.replace("\\:", ":");
    let address = address.strip_prefix("git+").unwrap_or(&address);

    if address.contains(CRATES_INDEX) {
        return None;
    }
    let (scheme, url) = if let Some((scheme, _)) = address.split_once("://") {
        (scheme.to_ascii_lowercase(), address.to_string())
    } else if let Some(rest) = address.strip_prefix("git@") {
        // The `git@github.com:owner/repo` form.
        let (host, path) = rest.split_once(':')?;
        ("ssh".to_string(), format!("ssh://git@{host}/{path}"))
    } else {
        return None;
    };
    let host = host_of(&url)?;
    // Someone's own computer can't be used to attack them from outside.
    if NORMAL_HOSTS.contains(&host.as_str()) || is_local(&host) {
        return None;
    }

    let is_ip = host.parse::<Ipv4Addr>().is_ok()
        || host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .is_some_and(|host| host.parse::<Ipv6Addr>().is_ok());
    // Anyone on the network can swap what comes back over these.
    let is_unencrypted = matches!(scheme.as_str(), "http" | "git" | "ftp");
    let kind = if is_ip || is_unencrypted {
        Kind::UnsafePackageSource
    } else {
        Kind::UnusualPackageSource
    };
    Some((kind, host))
}

fn add_address(file: &RepoFile, what: &str, address: &str, line: Option<u64>, report: &mut Report) {
    if let Some((kind, host)) = kind_of_address(address) {
        // Tests of how package managers handle addresses use every odd kind.
        let kind = if is_test_path(file.path.raw()) {
            Kind::UnusualPackageSource
        } else {
            kind
        };
        let address = Untrusted::from_bytes(address.trim().as_bytes());
        report.add(
            kind,
            &host,
            &format!("{what}: {}", address.raw()),
            Some(At {
                path: &file.path,
                line,
            }),
        );
    }
}

fn line_at(contents: &[u8], offset: usize) -> u64 {
    contents[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count() as u64
        + 1
}

fn line_of(contents: &[u8], needle: &str) -> Option<u64> {
    let needle = needle.as_bytes();
    if needle.is_empty() {
        return None;
    }
    let offset = contents
        .windows(needle.len())
        .position(|window| window == needle)?;
    Some(line_at(contents, offset))
}

/// Runs a pattern whose capture groups each hold an address, one per match.
fn add_locations(file: &RepoFile, pattern: &Regex, what: &str, report: &mut Report) {
    let contents = file.contents.as_slice();
    for captures in pattern.captures_iter(contents) {
        let Some(found) = captures.iter().skip(1).flatten().next() else {
            continue;
        };
        let address = String::from_utf8_lossy(found.as_bytes());
        add_address(
            file,
            what,
            &address,
            Some(line_at(contents, found.start())),
            report,
        );
    }
}

/// What a dependency's version field really points at, if not the registry.
fn npm_spec_address(spec: &str) -> Option<String> {
    let spec = spec.trim();
    if let Some(rest) = spec.strip_prefix("github:") {
        return Some(format!("https://github.com/{rest}"));
    }
    if let Some(rest) = spec.strip_prefix("gitlab:") {
        return Some(format!("https://gitlab.com/{rest}"));
    }
    if let Some(rest) = spec.strip_prefix("bitbucket:") {
        return Some(format!("https://bitbucket.org/{rest}"));
    }
    if REMOTE_PREFIXES
        .iter()
        .any(|prefix| spec.starts_with(prefix))
    {
        return Some(spec.to_string());
    }
    // `owner/repo` means that repository on GitHub.
    let is_shorthand = !spec.starts_with(['@', '.', '/', '~', '^', '>', '<', '='])
        && !spec.contains(':')
        && !spec.contains(' ')
        && spec.split('#').next().is_some_and(|repo| {
            repo.split('/').count() == 2 && repo.split('/').all(|part| !part.is_empty())
        });
    is_shorthand.then(|| format!("https://github.com/{spec}"))
}

fn scan_package_json(file: &RepoFile, report: &mut Report) {
    let Ok(root) = serde_json::from_slice::<Value>(&file.contents) else {
        return;
    };
    let contents = file.contents.as_slice();

    for field in NPM_FIELDS {
        let Some(dependencies) = root.get(field).and_then(Value::as_object) else {
            continue;
        };
        for (name, spec) in dependencies {
            let spec = spec.as_str().unwrap_or("");
            let line = line_of(contents, &format!("\"{name}\""));
            if let Some(address) = npm_spec_address(spec) {
                add_address(file, name, &address, line, report);
            }
            add_if_imitated(file, "npm", name, line, report);
        }
    }
    for field in NPM_OVERRIDE_FIELDS {
        if let Some(overrides) = root.get(field).and_then(Value::as_object) {
            scan_npm_overrides(file, overrides, report);
        }
    }
    if let Some(overrides) = root.pointer("/pnpm/overrides").and_then(Value::as_object) {
        scan_npm_overrides(file, overrides, report);
    }
}

/// These can swap any package in the whole tree for something else. The JSON
/// parser limits how deep files can go, which bounds this recursion.
fn scan_npm_overrides(file: &RepoFile, overrides: &Map<String, Value>, report: &mut Report) {
    for (name, value) in overrides {
        match value {
            Value::String(spec) => {
                if let Some(address) = npm_spec_address(spec) {
                    let line = line_of(&file.contents, &format!("\"{name}\""));
                    let what = format!("{name}, replacing whatever would be installed");
                    add_address(file, &what, &address, line, report);
                }
            }
            Value::Object(nested) => scan_npm_overrides(file, nested, report),
            _ => {}
        }
    }
}

fn add_if_imitated(
    file: &RepoFile,
    ecosystem: &str,
    name: &str,
    line: Option<u64>,
    report: &mut Report,
) {
    if let Some(popular) = lookalike::imitated(ecosystem, name) {
        let name = Untrusted::from_bytes(name.as_bytes());
        report.add(
            Kind::LookalikePackage,
            "",
            &format!("{} ({ecosystem}) looks like {popular}", name.raw()),
            Some(At {
                path: &file.path,
                line,
            }),
        );
    }
}

fn scan_npm_lock(file: &RepoFile, report: &mut Report) {
    let Ok(root) = serde_json::from_slice::<Value>(&file.contents) else {
        return;
    };
    if let Some(packages) = root.get("packages").and_then(Value::as_object) {
        for (key, package) in packages {
            let name = key
                .rsplit_once("node_modules/")
                .map_or(key.as_str(), |(_, name)| name);
            check_locked_package(file, name, package, report);
        }
    }
    if let Some(dependencies) = root.get("dependencies").and_then(Value::as_object) {
        scan_old_npm_lock(file, dependencies, report);
    }
}

/// Older lockfiles nest packages inside each other. The JSON parser limits how
/// deep files can go, which bounds this recursion.
fn scan_old_npm_lock(file: &RepoFile, dependencies: &Map<String, Value>, report: &mut Report) {
    for (name, package) in dependencies {
        check_locked_package(file, name, package, report);
        if let Some(nested) = package.get("dependencies").and_then(Value::as_object) {
            scan_old_npm_lock(file, nested, report);
        }
    }
}

fn check_locked_package(file: &RepoFile, name: &str, package: &Value, report: &mut Report) {
    if package.get("link").and_then(Value::as_bool) == Some(true) {
        return;
    }
    if let Some(resolved) = package.get("resolved").and_then(Value::as_str) {
        if kind_of_address(resolved).is_some() {
            let line = line_of(&file.contents, resolved);
            add_address(file, name, resolved, line, report);
        }
    }
}

fn scan_requirements(file: &RepoFile, report: &mut Report) {
    let contents = file.contents.as_slice();

    for captures in REQUIREMENT_OPTION.captures_iter(contents) {
        let Some(found) = captures.get(1) else {
            continue;
        };
        let value = String::from_utf8_lossy(found.as_bytes());
        // A bare host name, as `--trusted-host` takes, turns off its certificate.
        let address = if value.contains("://") {
            value.into_owned()
        } else {
            format!("https://{value}")
        };
        add_address(
            file,
            "a Python package source",
            &address,
            Some(line_at(contents, found.start())),
            report,
        );
    }
    for captures in REQUIREMENT_LINK.captures_iter(contents) {
        let Some(found) = captures.get(1) else {
            continue;
        };
        let address = String::from_utf8_lossy(found.as_bytes());
        add_address(
            file,
            "a Python package",
            &address,
            Some(line_at(contents, found.start())),
            report,
        );
    }
    for captures in REQUIREMENT_NAME.captures_iter(contents) {
        let Some(found) = captures.get(1) else {
            continue;
        };
        let name = String::from_utf8_lossy(found.as_bytes());
        add_if_imitated(
            file,
            "PyPI",
            &name,
            Some(line_at(contents, found.start())),
            report,
        );
    }
}

/// `replace` swaps one Go module for another, and local paths are the honest and
/// common case.
fn scan_go_mod(file: &RepoFile, report: &mut Report) {
    let text = String::from_utf8_lossy(&file.contents);
    let mut in_block = false;

    for (index, line) in text.lines().enumerate() {
        let line = line.split("//").next().unwrap_or("").trim();
        let rule = if in_block {
            if line == ")" {
                in_block = false;
                continue;
            }
            line
        } else if line == "replace (" {
            in_block = true;
            continue;
        } else if let Some(rest) = line.strip_prefix("replace ") {
            rest
        } else {
            continue;
        };

        let Some((old, new)) = rule.split_once("=>") else {
            continue;
        };
        let new = new.trim();
        if new.starts_with('.') || new.starts_with('/') || new.is_empty() {
            continue;
        }
        let old = old.split_whitespace().next().unwrap_or("");
        let module = new.split_whitespace().next().unwrap_or("");
        let host = module.split('/').next().unwrap_or(module);
        let subject = Untrusted::from_bytes(format!("{old} replaced by {new}").as_bytes());
        report.add(
            Kind::UnusualPackageSource,
            host,
            subject.raw(),
            Some(At {
                path: &file.path,
                line: Some(index as u64 + 1),
            }),
        );
    }
}

fn scan_composer_json(file: &RepoFile, report: &mut Report) {
    let Ok(root) = serde_json::from_slice::<Value>(&file.contents) else {
        return;
    };
    let repositories: Vec<&Value> = match root.get("repositories") {
        Some(Value::Array(list)) => list.iter().collect(),
        Some(Value::Object(map)) => map.values().collect(),
        _ => return,
    };

    for repository in repositories {
        if let Some(url) = repository.get("url").and_then(Value::as_str) {
            let line = line_of(&file.contents, url);
            add_address(file, "a PHP package source", url, line, report);
        }
    }
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

    fn unusual(report: &Report) -> Vec<String> {
        report
            .listed(Kind::UnusualPackageSource)
            .into_iter()
            .map(|(subject, _)| subject)
            .collect()
    }

    fn unsafe_ones(report: &Report) -> Vec<String> {
        report
            .listed(Kind::UnsafePackageSource)
            .into_iter()
            .map(|(subject, _)| subject)
            .collect()
    }

    #[test]
    fn finds_npm_dependencies_that_skip_the_registry() {
        let report = scan_text(
            "package.json",
            r#"{"dependencies":{
                "a":"1.2.3",
                "b":"^2.0.0",
                "c":"https://cdn.acme.net/c.tgz",
                "d":"github:evil/d",
                "e":"evil/e#main",
                "f":"git+ssh://git@gitlab.com/evil/f.git",
                "g":"file:../g",
                "h":"workspace:*",
                "i":"npm:real@1.0.0",
                "j":"latest",
                "k":"link:./k",
                "l":"catalog:"
            }}"#,
        );

        assert_eq!(
            unusual(&report),
            [
                "c: https://cdn.acme.net/c.tgz",
                "d: https://github.com/evil/d",
                "e: https://github.com/evil/e#main",
                "f: git+ssh://git@gitlab.com/evil/f.git",
            ]
        );
        assert_eq!(
            report
                .group_of(Kind::UnusualPackageSource, "c: https://cdn.acme.net/c.tgz")
                .as_deref(),
            Some("cdn.acme.net")
        );
    }

    #[test]
    fn dependencies_over_an_unencrypted_connection_or_a_raw_address_are_dangerous() {
        for spec in [
            "http://packages.acme.net/x.tgz",
            "https://95.164.17.24/x.tgz",
            "git://acme.net/x.git",
        ] {
            let text = format!("{{\"dependencies\":{{\"x\":\"{spec}\"}}}}");
            let report = scan_text("package.json", &text);

            assert_eq!(unsafe_ones(&report), [format!("x: {spec}")], "{spec}");
        }
    }

    #[test]
    fn a_registry_on_this_computer_is_fine() {
        let text = r#"{"dependencies":{"x":"http://localhost:4260/x.tgz"}}"#;

        assert!(unsafe_ones(&scan_text("package.json", text)).is_empty());
        assert!(unusual(&scan_text("package.json", text)).is_empty());
    }

    #[test]
    fn odd_addresses_in_tests_are_only_a_warning() {
        let text = r#"{"dependencies":{"x":"git://acme.net/x.git"}}"#;
        let report = scan_text("test/cases/package.json", text);

        assert!(unsafe_ones(&report).is_empty());
        assert_eq!(unusual(&report).len(), 1);
    }

    #[test]
    fn finds_overrides_that_swap_a_package_for_something_else() {
        let report = scan_text(
            "package.json",
            r#"{"overrides":{"a":"https://evil.net/a.tgz","b":{"c":"https://evil.net/c.tgz"},"d":"1.0.0"},
                "resolutions":{"e":"github:evil/e"},
                "pnpm":{"overrides":{"f":"https://evil.net/f.tgz"}}}"#,
        );

        assert_eq!(unusual(&report).len(), 4);
    }

    #[test]
    fn finds_a_lockfile_pointing_somewhere_unexpected() {
        let report = scan_text(
            "package-lock.json",
            r#"{"packages":{
                "":{"name":"app"},
                "node_modules/ok":{"version":"1.0.0","resolved":"https://registry.npmjs.org/ok/-/ok-1.0.0.tgz"},
                "node_modules/lodash":{"version":"4.17.21","resolved":"https://evil.net/lodash.tgz"},
                "node_modules/a/node_modules/b":{"version":"1.0.0","resolved":"http://evil.net/b.tgz"},
                "node_modules/local":{"resolved":"packages/local","link":true}
            },
            "dependencies":{"c":{"version":"1.0.0","resolved":"https://evil.net/c.tgz",
                "dependencies":{"d":{"resolved":"https://evil.net/d.tgz"}}}}}"#,
        );

        assert_eq!(
            unusual(&report),
            [
                "c: https://evil.net/c.tgz",
                "d: https://evil.net/d.tgz",
                "lodash: https://evil.net/lodash.tgz"
            ]
        );
        assert_eq!(unsafe_ones(&report), ["b: http://evil.net/b.tgz"]);
    }

    #[test]
    fn finds_other_lockfiles_pointing_somewhere_unexpected() {
        for (path, text) in [
            (
                "yarn.lock",
                "a@1:\n  version \"1\"\n  resolved \"https://registry.yarnpkg.com/a.tgz\"\nb@1:\n  version \"1\"\n  resolved \"https://evil.net/b.tgz\"\n",
            ),
            (
                "yarn.lock",
                "\"b@https://evil.net/b.tgz\":\n  version: 1.0.0\n  resolution: \"b@https://evil.net/b.tgz\"\n",
            ),
            (
                "pnpm-lock.yaml",
                "packages:\n  b@1.0.0:\n    resolution: {tarball: https://evil.net/b.tgz}\n",
            ),
            (
                "uv.lock",
                "[[package]]\nname = \"b\"\nsource = { url = \"https://evil.net/b.tgz\" }\n",
            ),
            (
                "poetry.lock",
                "[package.source]\ntype = \"url\"\nurl = \"https://evil.net/b.tgz\"\n",
            ),
            (
                "Cargo.lock",
                "[[package]]\nname = \"b\"\nsource = \"git+https://evil.net/b.git#abc\"\n",
            ),
            ("Gemfile.lock", "GIT\n  remote: https://evil.net/b.git\n"),
        ] {
            let report = scan_text(path, text);

            assert_eq!(
                report.listed(Kind::UnusualPackageSource).len(),
                1,
                "{path}: {:?}",
                unusual(&report)
            );
        }
    }

    #[test]
    fn the_official_registries_are_fine() {
        for (path, text) in [
            (
                "Cargo.lock",
                "source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
            ),
            (
                "uv.lock",
                "source = { registry = \"https://pypi.org/simple\" }\n",
            ),
            ("Gemfile", "source \"https://rubygems.org\"\n"),
            ("Pipfile", "[[source]]\nurl = \"https://pypi.org/simple\"\n"),
            (".npmrc", "registry=https://registry.npmjs.org/\n"),
            (
                "gradle-wrapper.properties",
                "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.zip\n",
            ),
            (
                "nuget.config",
                "<add key=\"nuget\" value=\"https://api.nuget.org/v3/index.json\" />",
            ),
        ] {
            let report = scan_text(path, text);

            assert!(
                unusual(&report).is_empty(),
                "{path}: {:?}",
                unusual(&report)
            );
            assert!(unsafe_ones(&report).is_empty(), "{path}");
        }
    }

    #[test]
    fn finds_settings_pointing_at_another_registry() {
        for (path, text) in [
            (".npmrc", "registry=https://evil.net/\n"),
            (".npmrc", "@acme:registry=https://evil.net/\n"),
            (".yarnrc", "registry \"https://evil.net/\"\n"),
            (".yarnrc.yml", "npmRegistryServer: \"https://evil.net/\"\n"),
            ("bunfig.toml", "registry = \"https://evil.net/\"\n"),
            ("Pipfile", "[[source]]\nurl = \"https://evil.net/simple\"\n"),
            (
                "pyproject.toml",
                "[[tool.uv.index]]\nurl = \"https://evil.net/simple\"\n",
            ),
            ("Gemfile", "source \"https://evil.net\"\n"),
            (
                "nuget.config",
                "<add key=\"a\" value=\"https://evil.net/v3\" />",
            ),
            (
                "gradle-wrapper.properties",
                "distributionUrl=https\\://evil.net/gradle.zip\n",
            ),
            (
                "composer.json",
                r#"{"repositories":[{"type":"vcs","url":"https://evil.net/x"},{"type":"path","url":"../x"}]}"#,
            ),
        ] {
            let report = scan_text(path, text);

            assert_eq!(unusual(&report).len(), 1, "{path}");
        }
    }

    #[test]
    fn finds_python_requirements_that_skip_the_registry() {
        let report = scan_text(
            "requirements.txt",
            "flask==2.0\n--extra-index-url https://evil.net/simple\n--trusted-host evil.net\nrequests @ https://evil.net/r.whl\ngit+https://evil.net/x.git\n-e git+https://evil.net/y.git\n# https://evil.net/comment\n",
        );

        assert_eq!(unusual(&report).len(), 5, "{:?}", unusual(&report));
    }

    #[test]
    fn finds_python_projects_that_skip_the_registry() {
        let report = scan_text(
            "pyproject.toml",
            "[project]\ndependencies = [\"a @ https://evil.net/a.whl\"]\n[tool.poetry.dependencies]\nb = { git = \"https://evil.net/b.git\" }\n",
        );

        assert_eq!(unusual(&report).len(), 2, "{:?}", unusual(&report));
    }

    #[test]
    fn finds_crates_and_gems_from_git() {
        assert_eq!(
            unusual(&scan_text(
                "Cargo.toml",
                "[dependencies]\na = { git = \"https://github.com/evil/a\" }\nb = \"1\"\n"
            ))
            .len(),
            1
        );
        assert_eq!(
            unusual(&scan_text(
                "Gemfile",
                "gem 'a', git: 'https://evil.net/a.git'\n"
            ))
            .len(),
            1
        );
    }

    #[test]
    fn finds_go_modules_replaced_by_other_modules() {
        let report = scan_text(
            "go.mod",
            "module a\nreplace github.com/x/y => github.com/evil/y v1.0.0\nreplace (\n\tgithub.com/z => ../z\n\tgithub.com/w v1.0.0 => evil.net/w v1.0.0 // why\n)\n",
        );

        assert_eq!(
            unusual(&report),
            [
                "github.com/w replaced by evil.net/w v1.0.0",
                "github.com/x/y replaced by github.com/evil/y v1.0.0",
            ]
        );
    }

    #[test]
    fn finds_names_imitating_popular_packages() {
        let report = scan_text(
            "package.json",
            "{\n  \"dependencies\": {\n    \"axois\": \"1.0.0\",\n    \"axios\": \"1.0.0\"\n  }\n}",
        );

        assert_eq!(
            report.listed(Kind::LookalikePackage),
            [("axois (npm) looks like axios".to_string(), 1)]
        );
        assert_eq!(
            report.first_line(Kind::LookalikePackage, "axois (npm) looks like axios"),
            Some(3)
        );

        let report = scan_text("requirements.txt", "reqeusts==2.0\nflask\n");

        assert_eq!(
            report.listed(Kind::LookalikePackage),
            [("reqeusts (PyPI) looks like requests".to_string(), 1)]
        );
    }

    #[test]
    fn files_that_cannot_be_read_are_left_to_other_checks() {
        for path in ["package.json", "package-lock.json", "composer.json"] {
            let report = scan_text(path, "{ not json");

            assert!(unusual(&report).is_empty(), "{path}");
        }
    }

    #[test]
    fn hostile_addresses_do_not_panic() {
        for spec in [
            "git@",
            "git@:",
            "http://",
            "https://[",
            "git+",
            "ssh://@",
            "github:",
            "/",
            "a/b/c/d",
            "\\u0000",
        ] {
            let text = format!("{{\"dependencies\":{{\"x\":\"{spec}\"}}}}");
            scan_text("package.json", &text);
        }
    }
}
