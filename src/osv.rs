//! Asks the public OSV database whether packages have known problems.
//!
//! This sends package names and versions, and nothing else from the repository.

use crate::deps::Package;
use crate::fetch;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::thread;
use std::time::{Duration, Instant};

const BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
/// The most OSV accepts in one request.
const BATCH_SIZE: usize = 1000;
const MAX_RESPONSE_BYTES: u64 = 128 * 1024 * 1024;
const ATTEMPTS: u32 = 4;
const RETRY_DELAY: Duration = Duration::from_secs(2);
const TOTAL_TIME_ALLOWED: Duration = Duration::from_secs(180);

const ADVISORY_URL: &str = "https://api.osv.dev/v1/vulns/";
const MAX_ADVISORY_BYTES: u64 = 8 * 1024 * 1024;
const ADVISORY_WORKERS: usize = 8;
const ADVISORY_TIME_ALLOWED: Duration = Duration::from_secs(60);
const MALICIOUS_ID_PREFIX: &str = "MAL-";
/// The weakness types that mean deliberately planted code. Older attacks such as
/// `event-stream` only appear this way, under an ordinary-looking advisory.
const MALWARE_WEAKNESSES: [&str; 7] = [
    "CWE-506", "CWE-507", "CWE-508", "CWE-509", "CWE-510", "CWE-511", "CWE-512",
];

/// What one advisory says, as far as it matters here.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Advisory {
    has_malware_weakness: bool,
    affected: Vec<Affected>,
}

#[derive(Debug, PartialEq, Eq)]
struct Affected {
    ecosystem: String,
    name: String,
    versions: Vec<String>,
    covers_every_version: bool,
}

impl Advisory {
    fn entries_for<'a>(&'a self, package: &'a Package) -> impl Iterator<Item = &'a Affected> {
        self.affected.iter().filter(|affected| {
            affected.name == package.name && affected.ecosystem == package.ecosystem
        })
    }

    /// Whether the package itself is malware, as opposed to an honest package
    /// that had some releases hijacked.
    pub fn covers_every_version_of(&self, package: &Package) -> bool {
        self.entries_for(package)
            .any(|affected| affected.covers_every_version)
    }

    /// The specific versions this advisory names.
    pub fn listed_versions_of(&self, package: &Package) -> Vec<String> {
        self.entries_for(package)
            .flat_map(|affected| affected.versions.iter().cloned())
            .collect()
    }
}

/// Whether an advisory means malware. `advisory` is its details, if available.
pub fn is_malware(id: &str, advisory: Option<&Advisory>) -> bool {
    id.starts_with(MALICIOUS_ID_PREFIX)
        || advisory.is_some_and(|advisory| advisory.has_malware_weakness)
}

/// Reads the details of many advisories at once. Ones that can't be read are
/// left out, and the caller decides what that means.
pub fn read_advisories(ids: &[String]) -> HashMap<String, Advisory> {
    let started = Instant::now();
    let chunk_size = ids.len().div_ceil(ADVISORY_WORKERS).max(1);

    thread::scope(|scope| {
        let workers: Vec<_> = ids
            .chunks(chunk_size)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .filter(|_| started.elapsed() < ADVISORY_TIME_ALLOWED)
                        .filter_map(|id| Some((id.clone(), read_advisory(id)?)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();

        workers
            .into_iter()
            .flat_map(|worker| worker.join().unwrap_or_default())
            .collect()
    })
}

fn read_advisory(id: &str) -> Option<Advisory> {
    let is_safe_id = id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !is_safe_id {
        return None;
    }

    let url = format!("{ADVISORY_URL}{id}");
    for attempt in 1..=ATTEMPTS {
        if attempt > 1 {
            thread::sleep(RETRY_DELAY);
        }
        match fetch::get(&url, MAX_ADVISORY_BYTES) {
            Ok(response) => return parse_advisory(&response),
            Err(error) if error.is_temporary() => {}
            Err(_) => return None,
        }
    }
    None
}

#[cfg(test)]
pub fn parse_advisory_for_tests(response: &[u8]) -> Advisory {
    parse_advisory(response).expect("test advisories are valid")
}

fn parse_advisory(response: &[u8]) -> Option<Advisory> {
    let root: Value = serde_json::from_slice(response).ok()?;

    let has_malware_weakness = root
        .pointer("/database_specific/cwe_ids")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|weakness| MALWARE_WEAKNESSES.contains(&weakness));

    let affected = root
        .get("affected")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(parse_affected)
        .collect();

    Some(Advisory {
        has_malware_weakness,
        affected,
    })
}

fn parse_affected(entry: &Value) -> Option<Affected> {
    let package = entry.get("package")?;
    let versions = entry
        .get("versions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    let covers_every_version = entry
        .get("ranges")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(range_covers_everything);

    Some(Affected {
        ecosystem: package.get("ecosystem")?.as_str()?.to_string(),
        name: package.get("name")?.as_str()?.to_string(),
        versions,
        covers_every_version,
    })
}

/// A range that starts at version 0 and never ends.
fn range_covers_everything(range: &Value) -> bool {
    let Some(events) = range.get("events").and_then(Value::as_array) else {
        return false;
    };
    let starts_at_zero = events
        .iter()
        .any(|event| event.get("introduced").and_then(Value::as_str) == Some("0"));
    let ever_ends = events.iter().any(|event| {
        event.get("fixed").is_some()
            || event.get("last_affected").is_some()
            || event.get("limit").is_some()
    });
    starts_at_zero && !ever_ends
}

/// What OSV said. `ids[n]` lists the advisories for package `n`. It can be
/// shorter than the package list, and then `failure` says why it stopped.
#[derive(Debug, Default)]
pub struct Outcome {
    pub ids: Vec<Vec<String>>,
    /// Packages with more advisories than OSV returned in one answer.
    pub partly_listed: usize,
    pub failure: Option<String>,
}

/// Looks up every package, in batches.
pub fn check(packages: &[&Package]) -> Outcome {
    let started = Instant::now();
    let mut outcome = Outcome::default();

    for batch in packages.chunks(BATCH_SIZE) {
        match query_with_retries(batch, started) {
            Ok(answer) => {
                outcome.ids.extend(answer.ids);
                outcome.partly_listed += answer.partly_listed;
            }
            Err(reason) => {
                outcome.failure = Some(reason);
                break;
            }
        }
    }
    outcome
}

struct Answer {
    ids: Vec<Vec<String>>,
    partly_listed: usize,
}

fn query_with_retries(batch: &[&Package], started: Instant) -> Result<Answer, String> {
    let body = request_body(batch);
    let mut last_error = String::new();

    for attempt in 1..=ATTEMPTS {
        if started.elapsed() > TOTAL_TIME_ALLOWED {
            return Err("the lookup took too long".to_string());
        }
        if attempt > 1 {
            thread::sleep(RETRY_DELAY);
        }

        let headers = [("Content-Type", "application/json")];
        match fetch::post(BATCH_URL, &headers, &body, MAX_RESPONSE_BYTES) {
            Ok(response) => {
                return parse_response(&response, batch.len())
                    .ok_or_else(|| "OSV sent an unreadable answer".to_string());
            }
            Err(error) if error.is_temporary() => last_error = error.to_string(),
            Err(error) => return Err(error.to_string()),
        }
    }
    Err(last_error)
}

fn request_body(batch: &[&Package]) -> Vec<u8> {
    let queries: Vec<Value> = batch
        .iter()
        .map(|package| {
            let mut query = json!({
                "package": { "name": package.name, "ecosystem": package.ecosystem }
            });
            if let Some(version) = &package.version {
                query["version"] = json!(version);
            }
            query
        })
        .collect();

    json!({ "queries": queries }).to_string().into_bytes()
}

/// Reads an answer, which must hold exactly one result per package asked about.
/// Anything else could quietly attach advisories to the wrong package.
fn parse_response(response: &[u8], expected: usize) -> Option<Answer> {
    let root: Value = serde_json::from_slice(response).ok()?;
    let results = root.get("results")?.as_array()?;
    if results.len() != expected {
        return None;
    }

    let mut ids = Vec::with_capacity(expected);
    let mut partly_listed = 0;
    for result in results {
        let advisories = result.get("vulns").and_then(Value::as_array);
        ids.push(
            advisories
                .into_iter()
                .flatten()
                .filter_map(|advisory| advisory.get("id")?.as_str().map(str::to_string))
                .collect(),
        );
        if result.get("next_page_token").is_some() {
            partly_listed += 1;
        }
    }
    Some(Answer { ids, partly_listed })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(name: &str, version: Option<&str>) -> Package {
        Package {
            ecosystem: "npm",
            name: name.to_string(),
            version: version.map(str::to_string),
        }
    }

    #[test]
    fn builds_a_request_with_and_without_versions() {
        let pinned = package("a", Some("1.2.3"));
        let unpinned = package("b", None);

        let body = request_body(&[&pinned, &unpinned]);
        let parsed: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            parsed,
            json!({"queries": [
                {"package": {"name": "a", "ecosystem": "npm"}, "version": "1.2.3"},
                {"package": {"name": "b", "ecosystem": "npm"}},
            ]})
        );
    }

    #[test]
    fn hostile_package_names_stay_inside_their_json_string() {
        let hostile = package("a\",\"version\":\"9\"}},{\"package\":{\"name\":\"b", None);

        let body = request_body(&[&hostile]);
        let parsed: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(parsed["queries"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["queries"][0]["package"]["name"], hostile.name);
    }

    #[test]
    fn reads_advisories_in_the_order_they_were_asked_for() {
        let response = br#"{"results":[
            {"vulns":[{"id":"MAL-2025-2655","modified":"2025-03-25T00:00:00Z"}]},
            {},
            {"vulns":[{"id":"GHSA-a"},{"id":"GHSA-b"}]}
        ]}"#;

        let answer = parse_response(response, 3).unwrap();

        assert_eq!(answer.ids[0], ["MAL-2025-2655"]);
        assert!(answer.ids[1].is_empty());
        assert_eq!(answer.ids[2], ["GHSA-a", "GHSA-b"]);
        assert_eq!(answer.partly_listed, 0);
    }

    #[test]
    fn notices_when_a_package_has_more_advisories_than_were_returned() {
        let response = br#"{"results":[{"vulns":[{"id":"A"}],"next_page_token":"x"}]}"#;

        assert_eq!(parse_response(response, 1).unwrap().partly_listed, 1);
    }

    #[test]
    fn refuses_an_answer_that_does_not_match_the_question() {
        for response in [
            &br#"{"results":[{}]}"#[..],
            br#"{"results":[{},{},{}]}"#,
            br#"{"results":"nope"}"#,
            br#"{}"#,
            b"<html>error</html>",
            b"",
        ] {
            assert!(parse_response(response, 2).is_none(), "{response:?}");
        }
    }

    #[test]
    fn a_package_that_is_entirely_malware_covers_every_version() {
        // Shape taken from the real advisory MAL-2025-2655.
        let advisory = parse_advisory(
            br#"{"id":"MAL-2025-2655","affected":[{
                "package":{"ecosystem":"npm","name":"cdn-icon-fetcher"},
                "ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]
            }]}"#,
        )
        .unwrap();

        assert!(advisory.covers_every_version_of(&package("cdn-icon-fetcher", None)));
        assert!(is_malware("MAL-2025-2655", Some(&advisory)));
    }

    #[test]
    fn hijacked_releases_of_an_honest_package_do_not_cover_every_version() {
        // Shape taken from the real advisory MAL-2026-2307.
        let advisory = parse_advisory(
            br#"{"id":"MAL-2026-2307","affected":[{
                "package":{"ecosystem":"npm","name":"axios"},
                "versions":["0.30.4","1.14.1"]
            }]}"#,
        )
        .unwrap();
        let axios = package("axios", None);

        assert!(!advisory.covers_every_version_of(&axios));
        assert_eq!(advisory.listed_versions_of(&axios), ["0.30.4", "1.14.1"]);
    }

    #[test]
    fn recognizes_older_attacks_filed_under_ordinary_advisories() {
        // Shape taken from the real advisory GHSA-mh6f-8j2x-4483, event-stream.
        let advisory = parse_advisory(
            br#"{"id":"GHSA-mh6f-8j2x-4483",
                "database_specific":{"cwe_ids":["CWE-506"]},
                "affected":[
                  {"package":{"ecosystem":"npm","name":"event-stream"},"versions":["3.3.6"],
                   "ranges":[{"events":[{"introduced":"3.3.6"},{"fixed":"4.0.0"}]}]},
                  {"package":{"ecosystem":"npm","name":"flatmap-stream"},
                   "ranges":[{"events":[{"introduced":"0"}]}]}
                ]}"#,
        )
        .unwrap();

        assert!(is_malware("GHSA-mh6f-8j2x-4483", Some(&advisory)));
        assert!(!advisory.covers_every_version_of(&package("event-stream", None)));
        assert!(advisory.covers_every_version_of(&package("flatmap-stream", None)));
    }

    #[test]
    fn an_ordinary_bug_is_not_malware() {
        // Shape taken from the real advisory GHSA-29mw-wpgm-hmr9, lodash.
        let advisory = parse_advisory(
            br#"{"id":"GHSA-29mw-wpgm-hmr9",
                "database_specific":{"cwe_ids":["CWE-1333","CWE-400"]},
                "affected":[{"package":{"ecosystem":"npm","name":"lodash"},
                   "ranges":[{"events":[{"introduced":"4.0.0"},{"fixed":"4.17.21"}]}]}]}"#,
        )
        .unwrap();

        assert!(!is_malware("GHSA-29mw-wpgm-hmr9", Some(&advisory)));
        assert!(!is_malware("GHSA-29mw-wpgm-hmr9", None));
        assert!(!advisory.covers_every_version_of(&package("lodash", None)));
    }

    #[test]
    fn a_range_with_an_end_does_not_cover_everything() {
        for (range, expected) in [
            (json!({"events":[{"introduced":"0"}]}), true),
            (
                json!({"events":[{"introduced":"0"},{"fixed":"1.0"}]}),
                false,
            ),
            (
                json!({"events":[{"introduced":"0"},{"last_affected":"1.0"}]}),
                false,
            ),
            (json!({"events":[{"introduced":"1.0"}]}), false),
            (json!({"events":[]}), false),
            (json!({}), false),
        ] {
            assert_eq!(range_covers_everything(&range), expected, "{range}");
        }
    }

    #[test]
    fn matches_advisories_to_the_right_ecosystem_and_name() {
        let advisory = parse_advisory(
            br#"{"affected":[{"package":{"ecosystem":"PyPI","name":"x"},
                 "ranges":[{"events":[{"introduced":"0"}]}]}]}"#,
        )
        .unwrap();

        assert!(!advisory.covers_every_version_of(&package("x", None)));
    }

    #[test]
    fn an_unreadable_advisory_is_refused_and_odd_ids_are_never_requested() {
        assert!(parse_advisory(b"<html>").is_none());
        assert!(read_advisory("../../secret").is_none());
    }

    // These reach the real OSV service, sending only package names and advisory
    // IDs. No package is ever downloaded. Run with: cargo test -- --ignored
    #[test]
    #[ignore = "needs internet access"]
    fn the_real_service_flags_a_known_malicious_package() {
        let malicious = package("cdn-icon-fetcher", Some("1.2.2"));

        let outcome = check(&[&malicious]);

        assert_eq!(outcome.failure, None);
        assert!(
            outcome.ids[0].iter().any(|id| id.starts_with("MAL-")),
            "{:?}",
            outcome.ids
        );
    }

    #[test]
    #[ignore = "needs internet access"]
    fn the_real_service_tells_malware_from_hijacks_and_bugs() {
        let advisories = read_advisories(&[
            "MAL-2025-2655".to_string(),
            "MAL-2026-2307".to_string(),
            "GHSA-mh6f-8j2x-4483".to_string(),
            "GHSA-29mw-wpgm-hmr9".to_string(),
        ]);

        assert!(
            advisories["MAL-2025-2655"].covers_every_version_of(&package("cdn-icon-fetcher", None))
        );
        assert!(!advisories["MAL-2026-2307"].covers_every_version_of(&package("axios", None)));
        assert!(is_malware(
            "GHSA-mh6f-8j2x-4483",
            advisories.get("GHSA-mh6f-8j2x-4483")
        ));
        assert!(!is_malware(
            "GHSA-29mw-wpgm-hmr9",
            advisories.get("GHSA-29mw-wpgm-hmr9")
        ));
    }
}
