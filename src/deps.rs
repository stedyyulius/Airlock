//! Finds the packages a repository depends on, and checks them against OSV.
//!
//! The malware in many repositories isn't in the repository at all. It's one
//! dependency among thousands, fetched when someone runs `npm install`, so no
//! amount of reading the repo's own code will find it.
//!
//! Formats are read as text where a full parser would be a large dependency, and
//! every parser accepts anything: a malformed file gets reported, never trusted.

use crate::git::RepoFile;
use crate::network::LineCounter;
use crate::osv::{self, Advisory};
use crate::report::{At, Kind, Report};
use crate::text::Untrusted;
use regex::bytes::Regex;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;

const MAX_PACKAGES: usize = 100_000;
const MAX_LOCATIONS: usize = 5;
const MAX_NAME_BYTES: usize = 300;
const MAX_IDS_SHOWN: usize = 3;
const MAX_VERSIONS_SHOWN: usize = 6;
const MAX_ADVISORIES_READ: usize = 4000;
/// npm replaces packages it removes, often malware, with an empty one of this
/// version. It holds no code, but anything depending on one is worth a look.
const PLACEHOLDER_NOTE: &str =
    "npm's empty placeholder for a removed package, so probably harmless, but check why it's here";
/// Dependencies written like these don't come from the registry, so looking them
/// up by name would find a stranger's package that happens to share the name.
const NOT_FROM_REGISTRY: [&str; 13] = [
    "file:",
    "link:",
    "workspace:",
    "portal:",
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
const NPM_DEPENDENCY_FIELDS: [&str; 4] = [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

static JSON_KEY: LazyLock<Regex> = LazyLock::new(|| compile(r#"(?-u)"([^"\\\n]{1,300})"\s*:"#));
static BUN_ENTRY: LazyLock<Regex> =
    LazyLock::new(|| compile(r#"(?-u)\[\s*"(@?[^"@\s]+)@(\d[^"]*)""#));
static REQUIREMENT: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?-u)^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(===?|>=|<=|~=|!=|>|<)?\s*([^,;\s]*)",
    )
});

fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).expect("patterns are constants covered by tests")
}

/// One package at one version. With no version, it's unknown what would be
/// installed, so only malware counts, and bugs that may not apply are ignored.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Package {
    pub ecosystem: &'static str,
    pub name: String,
    pub version: Option<String>,
}

impl Package {
    fn describe(&self) -> String {
        match &self.version {
            Some(version) => format!("{} {version} ({})", self.name, self.ecosystem),
            None => format!("{} ({})", self.name, self.ecosystem),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    name: String,
    version: Option<String>,
    line: Option<u64>,
}

type Parser = fn(&str) -> Result<Vec<Entry>, String>;

/// A file, and the line in it where something was seen.
type Place = (Untrusted, Option<u64>);

#[derive(Default)]
struct Seen {
    count: u64,
    locations: Vec<Place>,
}

/// Every package found so far.
#[derive(Default)]
pub struct Dependencies {
    found: BTreeMap<Package, Seen>,
    /// Which folders pin which packages to an exact version. A loose version in
    /// `package.json` says nothing if the lockfile beside it pins the real one.
    pinned_in: HashSet<(String, &'static str, String)>,
    over_limit: u64,
}

fn folder_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(folder, _)| folder)
}

impl Dependencies {
    /// Reads a file's packages, if it's a kind of file that lists them.
    pub fn scan(&mut self, file: &RepoFile, report: &mut Report) {
        let lower = file.path.raw().to_ascii_lowercase().replace('\\', "/");
        let name = lower.rsplit('/').next().unwrap_or(&lower);
        let Some((ecosystem, parser)) = parser_for(name) else {
            return;
        };

        let text = String::from_utf8_lossy(&file.contents);
        match parser(text.trim_start_matches('\u{feff}')) {
            Ok(entries) => {
                for entry in entries {
                    self.add(ecosystem, entry, &file.path);
                }
            }
            Err(reason) => report.add_detail(
                Kind::DependencyNotChecked,
                file.path.raw(),
                &format!("could not read this file: {reason}"),
            ),
        }
    }

    fn add(&mut self, ecosystem: &'static str, entry: Entry, path: &Untrusted) {
        if entry.name.is_empty() || entry.name.len() > MAX_NAME_BYTES {
            return;
        }
        if entry.version.is_some() {
            self.pinned_in.insert((
                folder_of(path.raw()).to_string(),
                ecosystem,
                entry.name.clone(),
            ));
        }
        let package = Package {
            ecosystem,
            name: entry.name,
            version: entry.version,
        };
        if !self.found.contains_key(&package) && self.found.len() >= MAX_PACKAGES {
            self.over_limit += 1;
            return;
        }

        let seen = self.found.entry(package).or_default();
        seen.count += 1;
        if seen.locations.len() < MAX_LOCATIONS {
            seen.locations.push((path.clone(), entry.line));
        }
    }

    pub fn len(&self) -> usize {
        self.found.len()
    }

    /// Looks up every package and reports the results. Returns how many packages
    /// were checked. Anything that couldn't be checked gets reported as such.
    pub fn check_all(self, report: &mut Report) -> usize {
        if self.over_limit > 0 {
            report.add_detail(
                Kind::DependencyNotChecked,
                &format!("{} more packages", self.over_limit),
                "this repository lists more packages than Airlock checks",
            );
        }

        let packages: Vec<(&Package, Vec<&Place>)> = self
            .found
            .iter()
            .filter_map(|(package, seen)| {
                let places = self.places_to_report(package, seen);
                (!places.is_empty()).then_some((package, places))
            })
            .collect();
        if packages.is_empty() {
            return 0;
        }

        let lookups: Vec<&Package> = packages.iter().map(|(package, _)| *package).collect();
        let outcome = osv::check(&lookups);
        let checked = outcome.ids.len();

        let wanted = advisories_to_read(&lookups, &outcome.ids);
        let advisories = osv::read_advisories(&wanted);
        let unread = wanted.len().saturating_sub(advisories.len());

        for ((package, places), ids) in packages.iter().zip(&outcome.ids) {
            let Some((kind, subject)) = classify_package(package, ids, &advisories) else {
                continue;
            };
            for (path, line) in places.iter().copied() {
                report.add(kind, "", &subject, Some(At { path, line: *line }));
            }
            let seen = &self.found[*package];
            for _ in 0..seen.count.saturating_sub(seen.locations.len() as u64) {
                report.add(kind, "", &subject, None);
            }
        }

        if let Some(failure) = &outcome.failure {
            report.add_detail(
                Kind::DependencyNotChecked,
                &format!("{} packages", packages.len() - checked),
                &format!("could not check these against OSV: {failure}"),
            );
        }
        if outcome.partly_listed > 0 {
            report.add_detail(
                Kind::DependencyNotChecked,
                &format!("{} packages", outcome.partly_listed),
                "OSV listed only some of their advisories",
            );
        }
        if unread > 0 {
            report.add_detail(
                Kind::DependencyNotChecked,
                &format!("{unread} advisories"),
                "could not read these, so some listed as bugs could really be malware",
            );
        }
        checked
    }

    /// Where a package should be reported. A package with no exact version is
    /// skipped in folders that pin it, because the pinned entry gets checked.
    fn places_to_report<'a>(&self, package: &Package, seen: &'a Seen) -> Vec<&'a Place> {
        seen.locations
            .iter()
            .filter(|(path, _)| {
                package.version.is_some()
                    || !self.pinned_in.contains(&(
                        folder_of(path.raw()).to_string(),
                        package.ecosystem,
                        package.name.clone(),
                    ))
            })
            .collect()
    }
}

/// Chooses which advisories to read in full, most useful first in case there
/// are too many. An ID alone can't say whether a package is hijacked or entirely
/// malware, and some older malware has an ordinary-looking ID.
fn advisories_to_read(packages: &[&Package], ids: &[Vec<String>]) -> Vec<String> {
    let mut malware_without_version = BTreeSet::new();
    let mut with_version = BTreeSet::new();
    let mut others = BTreeSet::new();

    for (package, ids) in packages.iter().zip(ids) {
        for id in ids {
            let looks_malicious = osv::is_malware(id, None);
            match (package.version.is_some(), looks_malicious) {
                (false, true) => malware_without_version.insert(id.clone()),
                // Already known to be malware at this exact version.
                (true, true) => false,
                (true, false) => with_version.insert(id.clone()),
                (false, false) => others.insert(id.clone()),
            };
        }
    }

    malware_without_version
        .into_iter()
        .chain(with_version)
        .chain(others)
        .take(MAX_ADVISORIES_READ)
        .collect()
}

/// Decides what a package's advisories mean.
///
/// An exact version only gets an advisory if that version is affected, so any
/// malware advisory is a direct hit. Without a version the question is whether
/// the package is malware through and through, which is a danger, or an honest
/// package that had some releases hijacked, which is a warning. Treating those
/// the same would flag every project using a popular package that was once hit.
fn classify_package(
    package: &Package,
    ids: &[String],
    advisories: &HashMap<String, Advisory>,
) -> Option<(Kind, String)> {
    let malware: Vec<&String> = ids
        .iter()
        .filter(|id| osv::is_malware(id, advisories.get(id.as_str())))
        .collect();
    let join = |ids: &[&String]| {
        ids.iter()
            .map(|id| id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };

    if package.version.is_some() {
        if !malware.is_empty() {
            let is_placeholder = package.ecosystem == "npm"
                && package
                    .version
                    .as_deref()
                    .is_some_and(|version| version.ends_with("-security"));
            let note = if is_placeholder {
                format!(", {PLACEHOLDER_NOTE}")
            } else {
                String::new()
            };
            let subject = format!("{}: {}{note}", package.describe(), join(&malware));
            return Some((Kind::KnownMalicious, subject));
        }
        if ids.is_empty() {
            return None;
        }
        let shown = ids[..ids.len().min(MAX_IDS_SHOWN)].join(", ");
        let rest = ids.len().saturating_sub(MAX_IDS_SHOWN);
        let more = if rest > 0 {
            format!(" and {rest} more")
        } else {
            String::new()
        };
        let subject = format!("{}: {shown}{more}", package.describe());
        return Some((Kind::KnownVulnerable, subject));
    }

    if malware.is_empty() {
        return None;
    }

    // If an advisory couldn't be read, assume the worst.
    let entirely_malware: Vec<&String> = malware
        .iter()
        .copied()
        .filter(|id| {
            advisories
                .get(id.as_str())
                .is_none_or(|advisory| advisory.covers_every_version_of(package))
        })
        .collect();
    if !entirely_malware.is_empty() {
        let subject = format!("{}: {}", package.describe(), join(&entirely_malware));
        return Some((Kind::KnownMalicious, subject));
    }

    let mut versions: Vec<String> = malware
        .iter()
        .filter_map(|id| advisories.get(id.as_str()))
        .flat_map(|advisory| advisory.listed_versions_of(package))
        .collect();
    versions.sort();
    versions.dedup();
    let rest = versions.len().saturating_sub(MAX_VERSIONS_SHOWN);
    versions.truncate(MAX_VERSIONS_SHOWN);
    let affected = if versions.is_empty() {
        "some versions".to_string()
    } else if rest > 0 {
        format!("{} and {rest} more", versions.join(", "))
    } else {
        versions.join(", ")
    };
    let subject = format!(
        "{}: {} affected {affected}",
        package.describe(),
        join(&malware)
    );
    Some((Kind::HadMaliciousReleases, subject))
}

fn parser_for(name: &str) -> Option<(&'static str, Parser)> {
    Some(match name {
        "package-lock.json" | "npm-shrinkwrap.json" => ("npm", parse_npm_lock),
        "package.json" => ("npm", parse_package_json),
        "yarn.lock" => ("npm", parse_yarn_lock),
        "pnpm-lock.yaml" => ("npm", parse_pnpm_lock),
        "bun.lock" => ("npm", parse_bun_lock),
        "cargo.lock" => ("crates.io", parse_cargo_lock),
        "uv.lock" => ("PyPI", parse_uv_lock),
        "poetry.lock" => ("PyPI", parse_poetry_lock),
        "pipfile.lock" => ("PyPI", parse_pipfile_lock),
        "go.sum" => ("Go", parse_go_sum),
        "go.mod" => ("Go", parse_go_mod),
        "composer.lock" => ("Packagist", parse_composer_lock),
        "gemfile.lock" => ("RubyGems", parse_gemfile_lock),
        name if name.starts_with("requirements") && name.ends_with(".txt") => {
            ("PyPI", parse_requirements)
        }
        _ => return None,
    })
}

fn parse_json(text: &str) -> Result<Value, String> {
    serde_json::from_str(text).map_err(|error| error.to_string())
}

/// Finds the line each JSON key first appears on. One pass over the file, because
/// searching for each package separately could take minutes on a hostile file.
fn key_lines(text: &str) -> HashMap<&str, u64> {
    let bytes = text.as_bytes();
    let mut lines = LineCounter::new(bytes, false);
    let mut found = HashMap::new();

    for captures in JSON_KEY.captures_iter(bytes) {
        let Some(key) = captures.get(1) else {
            continue;
        };
        let Some(line) = lines.line_at(key.start()) else {
            continue;
        };
        if let Ok(key) = std::str::from_utf8(key.as_bytes()) {
            found.entry(key).or_insert(line);
        }
    }
    found
}

/// A version only if it pins one exact release. Ranges like `^1.2.0` don't say
/// what would be installed.
fn exact_version(spec: &str) -> Option<String> {
    let spec = spec.trim();
    // Removed packages only ever have this one version, so a range still means it.
    let spec = if spec.ends_with("-security") {
        spec.trim_start_matches(['^', '~'])
    } else {
        spec
    };
    let spec = spec.strip_prefix('=').unwrap_or(spec);
    let spec = spec.strip_prefix('v').unwrap_or(spec);

    let is_exact = spec.starts_with(|c: char| c.is_ascii_digit())
        && spec
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_'))
        && !spec.to_ascii_lowercase().split('.').any(|part| part == "x");
    is_exact.then(|| spec.to_string())
}

/// Splits `name@1.2.3`, allowing for a scope as in `@scope/name@1.2.3`.
fn split_name_and_version(text: &str) -> Option<(&str, &str)> {
    let at = text.get(1..)?.rfind('@')? + 1;
    Some((&text[..at], &text[at + 1..]))
}

/// Whether a dependency written this way comes from the registry. Anything else
/// gets reported by the check for unusual package sources.
fn is_from_registry(spec: &str) -> bool {
    let spec = spec.trim();
    let is_github_shorthand =
        spec.contains('/') && !spec.starts_with(['@', '.', '/', '~']) && !spec.contains(':');

    !is_github_shorthand
        && !NOT_FROM_REGISTRY
            .iter()
            .any(|prefix| spec.starts_with(prefix))
}

/// Handles npm aliases, where `"nice-name": "npm:real-package@1.0.0"` really
/// installs `real-package`. Attackers can use this to pick an innocent name.
fn npm_entry(name: &str, spec: &str, line: Option<u64>) -> Entry {
    let aliased = spec
        .strip_prefix("npm:")
        .map(|target| split_name_and_version(target).unwrap_or((target, "")));
    let (name, spec) = aliased.unwrap_or((name, spec));

    Entry {
        name: name.to_string(),
        version: exact_version(spec),
        line,
    }
}

fn parse_npm_lock(text: &str) -> Result<Vec<Entry>, String> {
    let root = parse_json(text)?;
    let lines = key_lines(text);
    let mut entries = Vec::new();

    if let Some(packages) = root.get("packages").and_then(Value::as_object) {
        for (key, package) in packages {
            // Other keys are the project's own folders.
            let Some((_, name)) = key.rsplit_once("node_modules/") else {
                continue;
            };
            if package.get("link").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let name = package.get("name").and_then(Value::as_str).unwrap_or(name);
            let version = package.get("version").and_then(Value::as_str).unwrap_or("");
            if is_from_registry(version) {
                entries.push(npm_entry(name, version, lines.get(key.as_str()).copied()));
            }
        }
    }
    if let Some(dependencies) = root.get("dependencies").and_then(Value::as_object) {
        collect_old_npm_lock(dependencies, &lines, &mut entries);
    }
    Ok(entries)
}

/// Older lockfiles nest packages inside each other. The JSON parser limits how
/// deep files can go, which bounds this recursion.
fn collect_old_npm_lock(
    dependencies: &Map<String, Value>,
    lines: &HashMap<&str, u64>,
    entries: &mut Vec<Entry>,
) {
    for (name, package) in dependencies {
        let version = package.get("version").and_then(Value::as_str).unwrap_or("");
        if is_from_registry(version) {
            entries.push(npm_entry(name, version, lines.get(name.as_str()).copied()));
        }

        if let Some(nested) = package.get("dependencies").and_then(Value::as_object) {
            collect_old_npm_lock(nested, lines, entries);
        }
    }
}

fn parse_package_json(text: &str) -> Result<Vec<Entry>, String> {
    let root = parse_json(text)?;
    let lines = key_lines(text);
    let mut entries = Vec::new();

    for field in NPM_DEPENDENCY_FIELDS {
        let Some(dependencies) = root.get(field).and_then(Value::as_object) else {
            continue;
        };
        for (name, spec) in dependencies {
            let spec = spec.as_str().unwrap_or("");
            if is_from_registry(spec) {
                entries.push(npm_entry(name, spec, lines.get(name.as_str()).copied()));
            }
        }
    }
    Ok(entries)
}

fn parse_yarn_lock(text: &str) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    let mut current: Option<(String, u64)> = None;

    for (index, line) in text.lines().enumerate() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(char::is_whitespace) {
            current = line
                .trim_end()
                .strip_suffix(':')
                .and_then(yarn_package_name)
                .map(|name| (name, index as u64 + 1));
            continue;
        }

        // Exactly two spaces: deeper lines list this package's own dependencies,
        // and one of those could be named `version`.
        let is_field = line.starts_with("  ") && !line.starts_with("   ");
        if let (true, Some(rest)) = (is_field, line.trim_start().strip_prefix("version")) {
            if let Some((name, at)) = current.take() {
                let version = rest.trim_start_matches([':', ' ']).trim_matches('"');
                entries.push(Entry {
                    name,
                    version: exact_version(version),
                    line: Some(at),
                });
            }
        }
    }
    Ok(entries)
}

fn yarn_package_name(header: &str) -> Option<String> {
    let first = header.split(',').next()?.trim().trim_matches('"');
    if first.starts_with("__metadata") {
        return None;
    }
    let (name, version) = split_name_and_version(first)?;
    is_from_registry(version.strip_prefix("npm:").unwrap_or(version)).then(|| name.to_string())
}

fn parse_pnpm_lock(text: &str) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    let mut in_packages = false;

    for (index, line) in text.lines().enumerate() {
        if !line.starts_with(' ') && !line.trim().is_empty() {
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        if !in_packages || !line.starts_with("  ") || line.starts_with("   ") {
            continue;
        }
        let Some(key) = line.trim().strip_suffix(':') else {
            continue;
        };
        let key = key.trim_matches(['\'', '"']);
        let key = key.strip_prefix('/').unwrap_or(key);
        // Peer dependencies follow in brackets, as in `a@1.0.0(b@2.0.0)`.
        let key = key.split('(').next().unwrap_or(key);

        let parts = split_name_and_version(key).or_else(|| key.rsplit_once('/'));
        if let Some((name, version)) = parts {
            entries.push(Entry {
                name: name.to_string(),
                version: exact_version(version),
                line: Some(index as u64 + 1),
            });
        }
    }
    Ok(entries)
}

fn parse_bun_lock(text: &str) -> Result<Vec<Entry>, String> {
    let bytes = text.as_bytes();
    let mut lines = LineCounter::new(bytes, false);
    let mut entries = Vec::new();

    for captures in BUN_ENTRY.captures_iter(bytes) {
        let (Some(name), Some(version)) = (captures.get(1), captures.get(2)) else {
            continue;
        };
        entries.push(Entry {
            name: String::from_utf8_lossy(name.as_bytes()).into_owned(),
            version: exact_version(&String::from_utf8_lossy(version.as_bytes())),
            line: lines.line_at(name.start()),
        });
    }
    Ok(entries)
}

/// Reads the `[[package]]` tables that Cargo, uv and Poetry all write.
fn parse_package_tables(text: &str, requires_registry: bool) -> Vec<Entry> {
    #[derive(Default)]
    struct Table {
        name: Option<String>,
        version: Option<String>,
        line: u64,
        from_registry: bool,
    }

    let mut entries = Vec::new();
    let mut table: Option<Table> = None;
    let mut flush = |table: Option<Table>| {
        let Some(table) = table else {
            return;
        };
        if requires_registry && !table.from_registry {
            return;
        }
        if let Some(name) = table.name {
            entries.push(Entry {
                name,
                version: table.version.as_deref().and_then(exact_version),
                line: Some(table.line),
            });
        }
    };

    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line == "[[package]]" {
            flush(table.take());
            table = Some(Table {
                line: index as u64 + 1,
                ..Table::default()
            });
        } else if line.starts_with('[') {
            // Sub-tables have their own `name` and `version` keys.
            flush(table.take());
        } else if let Some(current) = table.as_mut() {
            if let Some(value) = toml_string(line, "name") {
                current.name = Some(value);
            } else if let Some(value) = toml_string(line, "version") {
                current.version = Some(value);
            } else if line.starts_with("source") && line.contains("registry") {
                current.from_registry = true;
            }
        }
    }
    flush(table);
    entries
}

fn toml_string(line: &str, key: &str) -> Option<String> {
    let value = line
        .strip_prefix(key)?
        .trim_start()
        .strip_prefix('=')?
        .trim();
    Some(value.strip_prefix('"')?.strip_suffix('"')?.to_string())
}

/// The project's own crates have no `source`, and looking them up could match
/// an unrelated public crate with the same name.
fn parse_cargo_lock(text: &str) -> Result<Vec<Entry>, String> {
    Ok(parse_package_tables(text, true))
}

fn parse_uv_lock(text: &str) -> Result<Vec<Entry>, String> {
    Ok(parse_package_tables(text, true))
}

fn parse_poetry_lock(text: &str) -> Result<Vec<Entry>, String> {
    Ok(parse_package_tables(text, false))
}

fn parse_pipfile_lock(text: &str) -> Result<Vec<Entry>, String> {
    let root = parse_json(text)?;
    let lines = key_lines(text);
    let mut entries = Vec::new();

    for section in ["default", "develop"] {
        let Some(packages) = root.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (name, package) in packages {
            let version = package.get("version").and_then(Value::as_str).unwrap_or("");
            entries.push(Entry {
                name: normalize_python_name(name),
                version: version.strip_prefix("==").and_then(exact_version),
                line: lines.get(name.as_str()).copied(),
            });
        }
    }
    Ok(entries)
}

/// Python treats `My_Package`, `my-package` and `my.package` as the same name.
fn normalize_python_name(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    for piece in name
        .split(['-', '_', '.'])
        .filter(|piece| !piece.is_empty())
    {
        if !normalized.is_empty() {
            normalized.push('-');
        }
        normalized.push_str(&piece.to_ascii_lowercase());
    }
    normalized
}

fn parse_requirements(text: &str) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();

    for (index, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        // Options, other files, and direct links. Links appear in the address list.
        if line.is_empty() || line.starts_with('-') || line.contains("://") {
            continue;
        }
        let Some(captures) = REQUIREMENT.captures(line.as_bytes()) else {
            continue;
        };
        let Some(name) = captures.get(1) else {
            continue;
        };
        let operator = captures.get(2).map(|found| found.as_bytes());
        let version = captures
            .get(3)
            .filter(|_| matches!(operator, Some(b"==" | b"===")))
            .map(|found| String::from_utf8_lossy(found.as_bytes()).into_owned());

        entries.push(Entry {
            name: normalize_python_name(&String::from_utf8_lossy(name.as_bytes())),
            version: version.as_deref().and_then(exact_version),
            line: Some(index as u64 + 1),
        });
    }
    Ok(entries)
}

/// OSV writes Go versions without the leading `v`.
fn go_entry(module: &str, version: &str, line: u64) -> Entry {
    let version = version.strip_suffix("+incompatible").unwrap_or(version);
    Entry {
        name: module.to_string(),
        version: exact_version(version),
        line: Some(line),
    }
}

fn parse_go_sum(text: &str) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();

    for (index, line) in text.lines().enumerate() {
        let mut fields = line.split_whitespace();
        if let (Some(module), Some(version)) = (fields.next(), fields.next()) {
            let version = version.strip_suffix("/go.mod").unwrap_or(version);
            entries.push(go_entry(module, version, index as u64 + 1));
        }
    }
    Ok(entries)
}

fn parse_go_mod(text: &str) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    let mut in_block = false;

    for (index, line) in text.lines().enumerate() {
        let line = line.split("//").next().unwrap_or("").trim();
        let requirement = if in_block {
            if line == ")" {
                in_block = false;
                continue;
            }
            line
        } else if line == "require (" {
            in_block = true;
            continue;
        } else if let Some(rest) = line.strip_prefix("require ") {
            rest
        } else {
            continue;
        };

        let mut fields = requirement.split_whitespace();
        if let (Some(module), Some(version)) = (fields.next(), fields.next()) {
            entries.push(go_entry(module, version, index as u64 + 1));
        }
    }
    Ok(entries)
}

fn parse_composer_lock(text: &str) -> Result<Vec<Entry>, String> {
    let root = parse_json(text)?;
    let mut entries = Vec::new();

    for section in ["packages", "packages-dev"] {
        let Some(packages) = root.get(section).and_then(Value::as_array) else {
            continue;
        };
        for package in packages {
            let Some(name) = package.get("name").and_then(Value::as_str) else {
                continue;
            };
            let version = package.get("version").and_then(Value::as_str).unwrap_or("");
            entries.push(Entry {
                name: name.to_string(),
                version: exact_version(version),
                line: None,
            });
        }
    }
    Ok(entries)
}

fn parse_gemfile_lock(text: &str) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    let mut in_gems = false;

    for (index, line) in text.lines().enumerate() {
        if !line.starts_with(' ') && !line.trim().is_empty() {
            in_gems = line.trim_end() == "GEM";
            continue;
        }
        // Exactly four spaces: deeper lines are each gem's own requirements.
        if !in_gems || !line.starts_with("    ") || line.starts_with("     ") {
            continue;
        }
        let Some((name, rest)) = line.trim().split_once(" (") else {
            continue;
        };
        let version = rest.trim_end_matches(')');
        // Platform builds look like `1.2.3-x86_64-linux`.
        let version = version.split('-').next().unwrap_or(version);
        entries.push(Entry {
            name: name.to_string(),
            version: exact_version(version),
            line: Some(index as u64 + 1),
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summarize(entries: &[Entry]) -> Vec<(String, Option<String>)> {
        entries
            .iter()
            .map(|entry| (entry.name.clone(), entry.version.clone()))
            .collect()
    }

    fn pinned(name: &str, version: &str) -> (String, Option<String>) {
        (name.to_string(), Some(version.to_string()))
    }

    fn unpinned(name: &str) -> (String, Option<String>) {
        (name.to_string(), None)
    }

    fn scan_file(deps: &mut Dependencies, report: &mut Report, path: &str, contents: &str) {
        deps.scan(
            &RepoFile {
                path: Untrusted::from_bytes(path.as_bytes()),
                contents: contents.as_bytes().to_vec(),
            },
            report,
        );
    }

    #[test]
    fn reads_a_modern_npm_lockfile_including_the_malicious_case_that_started_this() {
        let text = r#"{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "packages/local": { "version": "9.9.9" },
    "node_modules/local": { "resolved": "packages/local", "link": true },
    "node_modules/cdn-icon-fetcher": { "version": "1.2.2" },
    "node_modules/a/node_modules/@scope/b": { "version": "2.0.0" },
    "node_modules/nice-name": { "name": "real-name", "version": "3.0.0" }
  }
}"#;

        let entries = parse_npm_lock(text).unwrap();
        let mut found = summarize(&entries);
        found.sort();

        assert_eq!(
            found,
            [
                pinned("@scope/b", "2.0.0"),
                pinned("cdn-icon-fetcher", "1.2.2"),
                pinned("real-name", "3.0.0"),
            ]
        );
        let malicious = entries
            .iter()
            .find(|entry| entry.name == "cdn-icon-fetcher")
            .unwrap();
        assert_eq!(malicious.line, Some(8));
    }

    #[test]
    fn reads_an_old_nested_npm_lockfile() {
        let text = r#"{"dependencies":{
            "a":{"version":"1.0.0","dependencies":{"b":{"version":"2.0.0"}}},
            "c":{"version":"https://evil.example/c.tgz"},
            "d":{"version":"npm:real@4.0.0"}
        }}"#;

        let mut found = summarize(&parse_npm_lock(text).unwrap());
        found.sort();

        assert_eq!(
            found,
            [
                pinned("a", "1.0.0"),
                pinned("b", "2.0.0"),
                pinned("real", "4.0.0"),
            ]
        );
    }

    #[test]
    fn reads_package_json_with_and_without_exact_versions() {
        let text = r#"{
            "dependencies": {"a": "1.2.3", "b": "^1.0.0", "c": "npm:real@2.0.0"},
            "devDependencies": {"d": "=3.0.0", "e": "latest"},
            "optionalDependencies": {"f": "github:evil/f"},
            "peerDependencies": {"g": ">=1"},
            "bundledDependencies": ["h"]
        }"#;

        let mut found = summarize(&parse_package_json(text).unwrap());
        found.sort();

        assert_eq!(
            found,
            [
                pinned("a", "1.2.3"),
                unpinned("b"),
                pinned("d", "3.0.0"),
                unpinned("e"),
                unpinned("g"),
                pinned("real", "2.0.0"),
            ]
        );
    }

    #[test]
    fn dependencies_that_do_not_come_from_the_registry_are_not_looked_up_by_name() {
        let text = r#"{"dependencies":{
            "a":"file:../a",
            "b":"workspace:*",
            "c":"link:./c",
            "d":"github:acme/d",
            "e":"acme/e",
            "f":"https://acme.net/f.tgz",
            "g":"git+ssh://git@acme.net/g.git",
            "h":"^1.0.0",
            "i":"@scope/i@1.0.0"
        }}"#;

        assert_eq!(
            summarize(&parse_package_json(text).unwrap()),
            [unpinned("h"), unpinned("i")]
        );
    }

    #[test]
    fn local_packages_in_a_yarn_lockfile_are_not_looked_up_by_name() {
        let text = r#""eslint-plugin-react-internal@link:./scripts/eslint-rules":
  version "0.0.0"

"local@workspace:packages/local":
  version: 0.0.0

"real@npm:^1.0.0":
  version: 1.0.0
"#;

        assert_eq!(
            summarize(&parse_yarn_lock(text).unwrap()),
            [pinned("real", "1.0.0")]
        );
    }

    #[test]
    fn a_removed_packages_placeholder_counts_as_its_exact_version_with_a_note() {
        let package = Package {
            ecosystem: "npm",
            name: "fs".to_string(),
            version: exact_version("^0.0.1-security"),
        };
        let ids = vec!["MAL-2025-21003".to_string()];

        let (kind, subject) = classify_package(&package, &ids, &HashMap::new()).unwrap();

        assert_eq!(kind, Kind::KnownMalicious);
        assert!(subject.starts_with("fs 0.0.1-security (npm): MAL-2025-21003, npm's empty"));
    }

    #[test]
    fn reads_both_yarn_lockfile_formats() {
        let classic = r#"# yarn lockfile v1

"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.1.0":
  version "7.22.13"
  dependencies:
    version "^1.0.0"

lodash@^4.0.0:
  version "4.17.21"
"#;
        let berry = r#"__metadata:
  version: 8

"lodash@npm:^4.0.0":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
"#;

        let entries = parse_yarn_lock(classic).unwrap();
        assert_eq!(
            summarize(&entries),
            [
                pinned("@babel/code-frame", "7.22.13"),
                pinned("lodash", "4.17.21")
            ]
        );
        assert_eq!(entries[1].line, Some(8));
        assert_eq!(
            summarize(&parse_yarn_lock(berry).unwrap()),
            [pinned("lodash", "4.17.21")]
        );
    }

    #[test]
    fn reads_every_pnpm_lockfile_format() {
        let text = r#"lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      ignored: 1.0.0

packages:

  /old/1.0.0:
    resolution: {integrity: x}

  /@scope/older/2.0.0:
    dev: false

  /newer@3.0.0(peer@1.0.0):
    dev: false

  '@scope/newest@4.0.0':
    resolution: {integrity: x}

  plain@5.0.0:
    resolution: {integrity: x}

snapshots:

  not-this@6.0.0: {}
"#;

        assert_eq!(
            summarize(&parse_pnpm_lock(text).unwrap()),
            [
                pinned("old", "1.0.0"),
                pinned("@scope/older", "2.0.0"),
                pinned("newer", "3.0.0"),
                pinned("@scope/newest", "4.0.0"),
                pinned("plain", "5.0.0"),
            ]
        );
    }

    #[test]
    fn reads_bun_lockfiles() {
        let text = r#"{
  "packages": {
    "a": ["a@1.0.0", "", {}, "sha512-x"],
    "@s/b": ["@s/b@2.0.0", "", {}, "sha512-y"],
  }
}"#;

        assert_eq!(
            summarize(&parse_bun_lock(text).unwrap()),
            [pinned("a", "1.0.0"), pinned("@s/b", "2.0.0")]
        );
    }

    #[test]
    fn reads_cargo_lockfiles_and_skips_the_projects_own_crates() {
        let text = r#"version = 4

[[package]]
name = "airlock"
version = "0.1.0"
dependencies = ["tar"]

[[package]]
name = "tar"
version = "0.4.46"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[metadata]
name = "not-a-package"
"#;

        let entries = parse_cargo_lock(text).unwrap();

        assert_eq!(summarize(&entries), [pinned("tar", "0.4.46")]);
        assert_eq!(entries[0].line, Some(8));
    }

    #[test]
    fn reads_uv_and_poetry_lockfiles() {
        let uv = r#"[[package]]
name = "my-project"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }
"#;
        let poetry = r#"[[package]]
name = "flask"
version = "3.0.0"
description = "A framework"

[package.dependencies]
name = "not-this"
version = "9.9.9"

[[package]]
name = "click"
version = "8.1.7"
"#;

        assert_eq!(
            summarize(&parse_uv_lock(uv).unwrap()),
            [pinned("requests", "2.32.3")]
        );
        assert_eq!(
            summarize(&parse_poetry_lock(poetry).unwrap()),
            [pinned("flask", "3.0.0"), pinned("click", "8.1.7")]
        );
    }

    #[test]
    fn reads_pipfile_lockfiles() {
        let text = r#"{
            "default": {"Flask_Thing": {"version": "==3.0.0"}},
            "develop": {"pytest": {"version": "==8.0.0"}, "odd": {"git": "x"}}
        }"#;

        let mut found = summarize(&parse_pipfile_lock(text).unwrap());
        found.sort();

        assert_eq!(
            found,
            [
                pinned("flask-thing", "3.0.0"),
                unpinned("odd"),
                pinned("pytest", "8.0.0"),
            ]
        );
    }

    #[test]
    fn reads_requirements_files() {
        let text = "# comment
requests==2.32.3
flask>=2.0
Django_Thing[extra]==4.0  # inline comment
plain
-r other.txt
--index-url https://evil.example/simple
https://evil.example/x.tar.gz
numpy==1.*
";

        assert_eq!(
            summarize(&parse_requirements(text).unwrap()),
            [
                pinned("requests", "2.32.3"),
                unpinned("flask"),
                pinned("django-thing", "4.0"),
                unpinned("plain"),
                unpinned("numpy"),
            ]
        );
    }

    #[test]
    fn reads_go_files() {
        let sum = "github.com/a/b v1.2.3 h1:abc=\n\
                   github.com/a/b v1.2.3/go.mod h1:def=\n\
                   github.com/c/d v2.0.0+incompatible h1:ghi=\n";
        let module = "module x\n\ngo 1.21\n\nrequire github.com/a/b v1.2.3\n\n\
                      require (\n\tgithub.com/c/d v0.1.0 // indirect\n)\n";

        let mut found = summarize(&parse_go_sum(sum).unwrap());
        found.dedup();
        assert_eq!(
            found,
            [
                pinned("github.com/a/b", "1.2.3"),
                pinned("github.com/c/d", "2.0.0")
            ]
        );
        assert_eq!(
            summarize(&parse_go_mod(module).unwrap()),
            [
                pinned("github.com/a/b", "1.2.3"),
                pinned("github.com/c/d", "0.1.0")
            ]
        );
    }

    #[test]
    fn reads_composer_lockfiles() {
        let text = r#"{
            "packages": [{"name": "a/b", "version": "v1.2.3"}],
            "packages-dev": [{"name": "c/d", "version": "dev-main"}, {"version": "1.0"}]
        }"#;

        assert_eq!(
            summarize(&parse_composer_lock(text).unwrap()),
            [pinned("a/b", "1.2.3"), unpinned("c/d")]
        );
    }

    #[test]
    fn reads_gemfile_lockfiles() {
        let text = "GEM
  remote: https://rubygems.org/
  specs:
    rack (3.0.0)
    nokogiri (1.16.0-x86_64-linux)
      racc (~> 1.4)

PLATFORMS
  ruby

DEPENDENCIES
  rack
";

        assert_eq!(
            summarize(&parse_gemfile_lock(text).unwrap()),
            [pinned("rack", "3.0.0"), pinned("nokogiri", "1.16.0")]
        );
    }

    #[test]
    fn recognizes_exact_versions() {
        for (spec, expected) in [
            ("1.2.3", Some("1.2.3")),
            ("=1.2.3", Some("1.2.3")),
            ("v1.2.3", Some("1.2.3")),
            ("1.2.3-beta.1", Some("1.2.3-beta.1")),
            ("^1.2.3", None),
            ("~1.2.3", None),
            (">=1.0.0", None),
            ("1.x", None),
            ("1.2.X", None),
            ("1.2.*", None),
            ("latest", None),
            ("", None),
            ("github:a/b", None),
            ("1.0.0 || 2.0.0", None),
        ] {
            assert_eq!(exact_version(spec).as_deref(), expected, "spec: {spec:?}");
        }
    }

    #[test]
    fn only_reads_files_that_list_packages() {
        for name in [
            "readme.md",
            "my-package.json",
            "cargo.toml",
            "requirement.txt",
        ] {
            assert!(parser_for(name).is_none(), "{name}");
        }
        for name in [
            "package-lock.json",
            "package.json",
            "requirements.txt",
            "requirements-dev.txt",
        ] {
            assert!(parser_for(name).is_some(), "{name}");
        }
    }

    #[test]
    fn matches_file_names_whatever_their_case_and_folder() {
        let mut deps = Dependencies::default();
        let mut report = Report::new();

        scan_file(
            &mut deps,
            &mut report,
            "a/b/PACKAGE.JSON",
            r#"{"dependencies":{"x":"1.0.0"}}"#,
        );

        assert_eq!(deps.len(), 1);
    }

    #[test]
    fn counts_the_same_package_once_and_remembers_where_it_was_seen() {
        let mut deps = Dependencies::default();
        let mut report = Report::new();
        let lock = r#"{"dependencies":{"x":{"version":"1.0.0"}}}"#;

        scan_file(&mut deps, &mut report, "a/package-lock.json", lock);
        scan_file(&mut deps, &mut report, "b/package-lock.json", lock);

        assert_eq!(deps.len(), 1);
        let seen = deps.found.values().next().unwrap();
        assert_eq!(seen.count, 2);
        assert_eq!(seen.locations.len(), 2);
    }

    #[test]
    fn says_when_a_dependency_file_cannot_be_read() {
        let mut deps = Dependencies::default();
        let mut report = Report::new();

        scan_file(&mut deps, &mut report, "package-lock.json", "{ not json");

        assert_eq!(deps.len(), 0);
        assert!(
            report
                .detail_of(Kind::DependencyNotChecked, "package-lock.json")
                .unwrap()
                .starts_with("could not read this file")
        );
    }

    #[test]
    fn hostile_files_do_not_panic_or_overflow() {
        let deep = format!("{}1{}", "[".repeat(100_000), "]".repeat(100_000));
        let deep_lock = format!(
            r#"{{"dependencies":{}"x"{}}}"#,
            r#"{"a":{"version":"1","dependencies":"#.repeat(5000),
            "}}".repeat(5000)
        );
        for parser in [
            parse_npm_lock,
            parse_package_json,
            parse_yarn_lock,
            parse_pnpm_lock,
            parse_bun_lock,
            parse_cargo_lock,
            parse_uv_lock,
            parse_poetry_lock,
            parse_pipfile_lock,
            parse_requirements,
            parse_go_sum,
            parse_go_mod,
            parse_composer_lock,
            parse_gemfile_lock,
        ] {
            for text in [
                "",
                "\u{feff}",
                "é:",
                "@:",
                "@",
                "  é",
                "[[package]]",
                "[[package]]\nname = \"é",
                "{}",
                "null",
                r#"{"packages":{"node_modules/":1},"dependencies":{"a":1}}"#,
                &deep,
                &deep_lock,
            ] {
                let _ = parser(text);
            }
        }
    }

    #[test]
    fn long_names_are_ignored_and_too_many_packages_are_counted() {
        let mut deps = Dependencies::default();
        let path = Untrusted::from_bytes(b"a");
        let entry = |name: String| Entry {
            name,
            version: None,
            line: None,
        };

        deps.add("npm", entry("x".repeat(MAX_NAME_BYTES + 1)), &path);
        assert_eq!(deps.len(), 0);

        for number in 0..MAX_PACKAGES + 3 {
            deps.add("npm", entry(format!("p{number}")), &path);
        }
        assert_eq!(deps.len(), MAX_PACKAGES);
        assert_eq!(deps.over_limit, 3);
    }

    fn package(version: Option<&str>) -> Package {
        Package {
            ecosystem: "npm",
            name: "p".to_string(),
            version: version.map(str::to_string),
        }
    }

    fn ids(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|id| id.to_string()).collect()
    }

    fn advisories(list: &[(&str, &str)]) -> HashMap<String, Advisory> {
        list.iter()
            .map(|(id, json)| {
                let advisory = crate::osv::parse_advisory_for_tests(json.as_bytes());
                (id.to_string(), advisory)
            })
            .collect()
    }

    const ENTIRELY_MALWARE: &str = r#"{"affected":[{"package":{"ecosystem":"npm","name":"p"},
        "ranges":[{"events":[{"introduced":"0"}]}]}]}"#;
    const HIJACKED_RELEASES: &str = r#"{"affected":[{"package":{"ecosystem":"npm","name":"p"},
        "versions":["1.14.1","0.30.4"]}]}"#;
    const PLANTED_CODE: &str = r#"{"database_specific":{"cwe_ids":["CWE-506"]},
        "affected":[{"package":{"ecosystem":"npm","name":"p"},"versions":["3.3.6"]}]}"#;
    const ORDINARY_BUG: &str = r#"{"database_specific":{"cwe_ids":["CWE-79"]},
        "affected":[{"package":{"ecosystem":"npm","name":"p"},
        "ranges":[{"events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}"#;

    #[test]
    fn an_exact_version_with_a_malware_advisory_is_known_malicious() {
        let found = classify_package(
            &package(Some("1.2.2")),
            &ids(&["GHSA-a", "MAL-2025-1"]),
            &HashMap::new(),
        );

        assert_eq!(
            found,
            Some((
                Kind::KnownMalicious,
                "p 1.2.2 (npm): MAL-2025-1".to_string()
            ))
        );
    }

    #[test]
    fn an_older_attack_under_an_ordinary_id_is_known_malicious() {
        let found = classify_package(
            &package(Some("3.3.6")),
            &ids(&["GHSA-old"]),
            &advisories(&[("GHSA-old", PLANTED_CODE)]),
        );

        assert_eq!(
            found,
            Some((Kind::KnownMalicious, "p 3.3.6 (npm): GHSA-old".to_string()))
        );
    }

    #[test]
    fn no_exact_version_of_a_package_that_is_entirely_malware_is_known_malicious() {
        let found = classify_package(
            &package(None),
            &ids(&["MAL-1"]),
            &advisories(&[("MAL-1", ENTIRELY_MALWARE)]),
        );

        assert_eq!(
            found,
            Some((Kind::KnownMalicious, "p (npm): MAL-1".to_string()))
        );
    }

    // The false alarm this guards against: axios with a version range was called
    // malware, because two of its releases were once hijacked.
    #[test]
    fn no_exact_version_of_a_hijacked_package_is_a_warning_naming_the_bad_versions() {
        let found = classify_package(
            &package(None),
            &ids(&["MAL-2", "GHSA-bug"]),
            &advisories(&[("MAL-2", HIJACKED_RELEASES), ("GHSA-bug", ORDINARY_BUG)]),
        );

        assert_eq!(
            found,
            Some((
                Kind::HadMaliciousReleases,
                "p (npm): MAL-2 affected 0.30.4, 1.14.1".to_string()
            ))
        );
    }

    #[test]
    fn a_safe_exact_version_of_a_hijacked_package_is_not_flagged() {
        // OSV returns nothing for versions an advisory doesn't affect.
        assert_eq!(
            classify_package(&package(Some("1.6.0")), &[], &HashMap::new()),
            None
        );
    }

    #[test]
    fn assumes_the_worst_when_a_malware_advisory_cannot_be_read() {
        let found = classify_package(&package(None), &ids(&["MAL-3"]), &HashMap::new());

        assert_eq!(
            found,
            Some((Kind::KnownMalicious, "p (npm): MAL-3".to_string()))
        );
    }

    #[test]
    fn ordinary_bugs_at_an_exact_version_are_listed_briefly() {
        let bugs: Vec<String> = (1..=5).map(|n| format!("GHSA-{n}")).collect();

        let found = classify_package(&package(Some("1.0.0")), &bugs, &HashMap::new());

        assert_eq!(
            found,
            Some((
                Kind::KnownVulnerable,
                "p 1.0.0 (npm): GHSA-1, GHSA-2, GHSA-3 and 2 more".to_string()
            ))
        );
    }

    #[test]
    fn bugs_are_ignored_without_a_version_because_they_may_not_apply() {
        let found = classify_package(
            &package(None),
            &ids(&["GHSA-bug"]),
            &advisories(&[("GHSA-bug", ORDINARY_BUG)]),
        );

        assert_eq!(found, None);
    }

    #[test]
    fn a_clean_package_reports_nothing() {
        assert_eq!(
            classify_package(&package(Some("1.0.0")), &[], &HashMap::new()),
            None
        );
        assert_eq!(classify_package(&package(None), &[], &HashMap::new()), None);
    }

    #[test]
    fn reads_the_advisories_that_can_change_the_answer_first() {
        let loose = package(None);
        let exact = package(Some("1.0.0"));

        let wanted = advisories_to_read(
            &[&loose, &exact],
            &[ids(&["GHSA-z", "MAL-1"]), ids(&["GHSA-a", "MAL-2"])],
        );

        // MAL-2 is already a direct hit, so it doesn't need reading.
        assert_eq!(wanted, ["MAL-1", "GHSA-a", "GHSA-z"]);
    }

    #[test]
    fn a_loose_version_is_skipped_where_a_lockfile_pins_that_package() {
        let mut deps = Dependencies::default();
        let mut report = Report::new();
        let manifest = r#"{"dependencies":{"x":"^1.0.0"}}"#;
        let lock = r#"{"dependencies":{"x":{"version":"1.6.0"}}}"#;

        scan_file(&mut deps, &mut report, "a/package.json", manifest);
        scan_file(&mut deps, &mut report, "a/package-lock.json", lock);
        scan_file(&mut deps, &mut report, "b/package.json", manifest);

        let loose = Package {
            ecosystem: "npm",
            name: "x".to_string(),
            version: None,
        };
        let places = deps.places_to_report(&loose, &deps.found[&loose]);
        let paths: Vec<&str> = places.iter().map(|(path, _)| path.raw()).collect();

        assert_eq!(paths, ["b/package.json"]);
    }

    #[test]
    fn finds_the_folder_of_a_path() {
        assert_eq!(folder_of("a/b/package.json"), "a/b");
        assert_eq!(folder_of("package.json"), "");
    }
}
