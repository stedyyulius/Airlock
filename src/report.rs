//! Everything a scan finds, listed for the user to judge.
//!
//! Being listed doesn't mean something is malicious. Nothing is filtered out
//! for looking harmless, because that decision belongs to the user. Every check
//! reports through `Report::add`, so new checks get the same treatment.

use crate::text::{Untrusted, escape};
use std::collections::BTreeMap;
use std::fmt;

/// How many places are named per finding. All of them are still counted.
const MAX_LOCATIONS: usize = 5;
/// A hostile repo could contain millions of unique addresses. Past this limit
/// items are counted and the report says it is incomplete.
const MAX_REPORT_BYTES: usize = 128 * 1024 * 1024;
const ENTRY_OVERHEAD_BYTES: usize = 128;

const LIMITS: &str = "
Limits of this list
  Only addresses written as plain text can be listed. Encoded, split up or
  downloaded addresses will not appear.
  A downloaded archive can leave out files that git clone would give you.
  Being listed doesn't mean something is malicious, and not being listed
  doesn't mean it is safe.

This is a list for you to review, not a safety verdict.
";

/// The sections of a report, in printing order.
///
/// The most important section prints last, right above the summary. A long
/// list of harmless links can then never push it off the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    DocumentationAddress,
    LockfileAddress,
    MentionedAddress,
    LocalAddress,
    NotRead,
    OpaqueFile,
    IpAddress,
    CallWithoutAddress,
    NetworkCall,
}

impl Kind {
    const ALL: [Self; 9] = [
        Self::DocumentationAddress,
        Self::LockfileAddress,
        Self::MentionedAddress,
        Self::LocalAddress,
        Self::NotRead,
        Self::OpaqueFile,
        Self::IpAddress,
        Self::CallWithoutAddress,
        Self::NetworkCall,
    ];

    fn title(self) -> &'static str {
        match self {
            Self::DocumentationAddress => "Addresses in documentation",
            Self::LockfileAddress => "Addresses in lockfiles",
            Self::MentionedAddress => "Other addresses in code and config",
            Self::LocalAddress => "Local, private and reserved addresses",
            Self::NotRead => "Entries Airlock did not read",
            Self::OpaqueFile => "Files Airlock cannot read inside",
            Self::IpAddress => "IP addresses (some may be version numbers)",
            Self::CallWithoutAddress => "Network calls with no visible address",
            Self::NetworkCall => "Network calls to these addresses",
        }
    }

    fn is_address(self) -> bool {
        matches!(
            self,
            Self::DocumentationAddress
                | Self::LockfileAddress
                | Self::MentionedAddress
                | Self::LocalAddress
                | Self::IpAddress
                | Self::NetworkCall
        )
    }
}

/// Where something was found.
pub struct At<'a> {
    pub path: &'a Untrusted,
    /// Absent for binary files, where line numbers mean nothing.
    pub line: Option<u64>,
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
    locations: Vec<(Untrusted, Option<u64>)>,
}

/// Everything found so far.
pub struct Report {
    entries: BTreeMap<Key, Entry>,
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

    /// Records findings that had to be dropped before reaching the report.
    pub fn note_not_listed(&mut self, count: u64) {
        self.not_listed += count;
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut counts: BTreeMap<Kind, u64> = BTreeMap::new();
        for key in self.entries.keys() {
            *counts.entry(key.kind).or_default() += 1;
        }

        let mut section = None;
        let mut group = None;
        for (key, entry) in &self.entries {
            if section != Some(key.kind) {
                writeln!(f, "\n{} ({})", key.kind.title(), counts[&key.kind])?;
                section = Some(key.kind);
                group = None;
            }
            if !key.group.is_empty() && group != Some(key.group.as_str()) {
                writeln!(f, "  {}", show_group(key))?;
                group = Some(key.group.as_str());
            }
            writeln!(f, "    {}", show_subject(key))?;

            for (path, line) in &entry.locations {
                match line {
                    Some(line) => writeln!(f, "      {path}:{line}")?,
                    None => writeln!(f, "      {path}")?,
                }
            }
            let named = entry.locations.len() as u64;
            if named > 0 && entry.count > named {
                writeln!(f, "      ...and {} more places", entry.count - named)?;
            }
        }

        writeln!(f, "\nSummary")?;
        for kind in Kind::ALL.iter().rev() {
            let count = counts.get(kind).copied().unwrap_or(0);
            writeln!(f, "  {}: {count}", kind.title())?;
        }
        if self.not_listed > 0 {
            writeln!(
                f,
                "\nThis list is incomplete: {} more items were found but not listed.",
                self.not_listed
            )?;
        }
        f.write_str(LIMITS)
    }
}

fn show_group(key: &Key) -> String {
    if !key.kind.is_address() {
        return escape(&key.group);
    }
    let shown = escape(&defang(&key.group));
    // These can imitate a familiar name letter for letter.
    if key.group.is_ascii() {
        shown
    } else {
        format!("{shown} (contains non-ASCII characters, check for look-alikes)")
    }
}

fn show_subject(key: &Key) -> String {
    if key.kind.is_address() {
        escape(&defang(&key.subject))
    } else {
        escape(&key.subject)
    }
}

/// Rewrites an address so a terminal won't turn it into a clickable link. A
/// report about suspicious addresses must not make them one click away.
fn defang(address: &str) -> String {
    match address.split_once("://") {
        Some((scheme, rest)) => {
            let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            let (authority, tail) = rest.split_at(end);
            format!(
                "{scheme}[://]{}{}",
                authority.replace('.', "[.]"),
                tail.replace("://", "[://]")
            )
        }
        None => address.replace('.', "[.]"),
    }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(name: &str) -> Untrusted {
        Untrusted::from_bytes(name.as_bytes())
    }

    fn at(path: &Untrusted, line: u64) -> Option<At<'_>> {
        Some(At {
            path,
            line: Some(line),
        })
    }

    #[test]
    fn lists_every_finding_however_many_there_are() {
        let file = path("a.js");
        let mut report = Report::new();
        for number in 0..500 {
            let url = format!("https://host{number}.example/x");
            report.add(Kind::MentionedAddress, "", &url, at(&file, number));
        }

        let shown = report.to_string();

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

        let shown = report.to_string();

        assert!(shown.contains("a.js:5"));
        assert!(!shown.contains("a.js:6"));
        assert!(shown.contains("...and 3 more places"));
        assert_eq!(
            report.listed(Kind::NetworkCall),
            [("https://a.example".to_string(), 8)]
        );
    }

    #[test]
    fn the_same_address_in_a_more_serious_place_is_not_hidden_by_a_harmless_one() {
        let readme = path("README.md");
        let script = path("install.js");
        let mut report = Report::new();
        let url = "https://evil.example/x";
        report.add(Kind::DocumentationAddress, "", url, at(&readme, 1));
        report.add(Kind::NetworkCall, "", url, at(&script, 9));

        let shown = report.to_string();

        assert!(shown.contains("README.md:1"));
        assert!(shown.contains("install.js:9"));
    }

    #[test]
    fn the_most_important_section_prints_last_above_the_summary() {
        let file = path("a.js");
        let mut report = Report::new();
        report.add(
            Kind::DocumentationAddress,
            "",
            "https://d.example",
            at(&file, 1),
        );
        report.add(Kind::NetworkCall, "", "https://c.example", at(&file, 2));

        let shown = report.to_string();
        let docs = shown.find("Addresses in documentation (1)").unwrap();
        let calls = shown.find("Network calls to these addresses (1)").unwrap();
        let summary = shown.find("\nSummary").unwrap();

        assert!(docs < calls && calls < summary);
    }

    #[test]
    fn the_summary_names_every_section_even_when_empty() {
        let shown = Report::new().to_string();

        for kind in Kind::ALL {
            assert!(shown.contains(&format!("{}: 0", kind.title())), "{kind:?}");
        }
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

        let shown = report.to_string();

        assert!(shown.contains("https[://]evil[.]example/a.b?next=https[://]other.example/"));
        assert!(shown.contains("evil[.]example"));
        assert!(shown.contains("1[.]1[.]1[.]1"));
        assert!(!shown.contains("://evil"));
        assert!(!shown.contains("https://"));
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
        report.add(Kind::NotRead, "", "link\x1b[2J: not a regular file", None);

        let shown = report.to_string();

        assert!(!shown.contains('\x1b') && !shown.contains('\x07'));
        assert!(!shown.lines().any(|line| line.starts_with("verdict")));
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

        assert!(report.to_string().contains("look-alikes"));
    }

    #[test]
    fn says_when_it_is_incomplete_instead_of_silently_dropping_items() {
        let file = path("a.js");
        let mut report = Report::with_budget(1000);
        for number in 0..100 {
            let url = format!("https://host{number}.example/x");
            report.add(Kind::MentionedAddress, "", &url, at(&file, 1));
        }

        let shown = report.to_string();

        assert!(report.not_listed > 0);
        assert!(shown.contains("This list is incomplete"));
        assert!(report.retained_bytes <= 1000);
    }

    #[test]
    fn entries_dropped_before_reaching_the_report_are_mentioned() {
        let mut report = Report::new();
        report.note_not_listed(7);

        assert!(report.to_string().contains("7 more items"));
    }

    #[test]
    fn always_states_that_this_is_not_a_verdict() {
        let shown = Report::new().to_string();

        assert!(shown.contains("not a safety verdict"));
        assert!(shown.contains("Only addresses written as plain text"));
    }
}
