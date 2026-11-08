//! Works out which branch or tag a pasted folder link means.
//!
//! In `.../tree/feature/x/src`, the branch could be `feature` or `feature/x`, and
//! the URL alone can't say which. So this asks the repository, using the same
//! git protocol that `git clone` starts with. It only lists names and commits,
//! and it works without logging in on all three hosts.

use crate::archive::is_commit_id;
use crate::fetch::{self, FetchError};
use crate::source::Source;
use std::fmt;

/// Enough for any real answer, because only the names we ask about come back.
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
/// Branch names are short, and this bounds the size of the question.
const MAX_SEGMENTS_TRIED: usize = 16;

/// What a branch or folder link refers to.
#[derive(Debug, PartialEq, Eq)]
pub struct Resolved {
    pub commit: String,
    /// The branch or tag name, as the link gave it.
    pub reference: String,
    /// What `reference` is: a branch, a tag or a commit.
    pub reference_kind: &'static str,
    /// The folder or file inside the repository, if the link named one.
    pub folder: Option<String>,
}

/// Why a branch or folder link couldn't be resolved.
#[derive(Debug)]
pub enum RefError {
    NotFound(String),
    Malformed,
    Fetch(FetchError),
}

impl fmt::Display for RefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(view) => write!(f, "no branch or tag matches this link: {view}"),
            Self::Malformed => write!(f, "the host sent an unreadable list of branches"),
            Self::Fetch(error) => write!(f, "could not list branches: {error}"),
        }
    }
}

impl std::error::Error for RefError {}

/// Finds the commit and folder that a link's `view` text refers to.
pub fn resolve(source: &Source, view: &str) -> Result<Resolved, RefError> {
    let segments: Vec<&str> = view.split('/').collect();

    if is_commit_id(segments[0]) {
        return Ok(Resolved {
            commit: segments[0].to_string(),
            reference: segments[0].to_string(),
            reference_kind: "commit",
            folder: folder_after(&segments, 1),
        });
    }

    let response = fetch::post(
        &format!("{}/git-upload-pack", source.git_url()),
        &[
            ("Content-Type", "application/x-git-upload-pack-request"),
            ("Accept", "application/x-git-upload-pack-result"),
            ("Git-Protocol", "version=2"),
        ],
        request_body(&segments).as_bytes(),
        MAX_RESPONSE_BYTES,
    )
    .map_err(RefError::Fetch)?;

    let refs = parse_refs(&response).ok_or(RefError::Malformed)?;
    choose(&segments, &refs).ok_or_else(|| RefError::NotFound(view.to_string()))
}

fn folder_after(segments: &[&str], used: usize) -> Option<String> {
    (segments.len() > used).then(|| segments[used..].join("/"))
}

fn packet(text: &str) -> String {
    format!("{:04x}{text}", text.len() + 4)
}

/// Asks about every way the link could split into a name and a folder.
fn request_body(segments: &[&str]) -> String {
    let mut body = packet("command=ls-refs\n");
    body.push_str("0001");
    body.push_str(&packet("peel\n"));

    for used in 1..=segments.len().min(MAX_SEGMENTS_TRIED) {
        let name = segments[..used].join("/");
        // A space would make this line mean something else, and git names
        // can't contain one anyway.
        if name.contains(char::is_whitespace) {
            break;
        }
        body.push_str(&packet(&format!("ref-prefix refs/heads/{name}\n")));
        body.push_str(&packet(&format!("ref-prefix refs/tags/{name}\n")));
    }
    body.push_str("0000");
    body
}

#[derive(Debug, PartialEq, Eq)]
struct Ref {
    name: String,
    commit: String,
}

/// Reads the answer, a series of lines that each start with their length.
fn parse_refs(response: &[u8]) -> Option<Vec<Ref>> {
    let mut refs = Vec::new();
    let mut rest = response;

    while !rest.is_empty() {
        let length = std::str::from_utf8(rest.get(..4)?).ok()?;
        let length = usize::from_str_radix(length, 16).ok()?;

        // 0000 to 0002 are markers with no content.
        if length <= 2 {
            rest = &rest[4..];
            continue;
        }
        if length < 4 {
            return None;
        }
        let line = std::str::from_utf8(rest.get(4..length)?).ok()?.trim_end();
        rest = &rest[length..];

        let mut fields = line.split(' ');
        let commit = fields.next()?;
        if !is_commit_id(commit) {
            return None;
        }
        let name = fields.next()?;
        // An annotated tag points at a tag object, and this names its commit.
        let peeled = fields.find_map(|field| field.strip_prefix("peeled:"));

        refs.push(Ref {
            name: name.to_string(),
            commit: peeled.unwrap_or(commit).to_string(),
        });
    }
    Some(refs)
}

/// Picks the longest name that exactly matches a real branch or tag. Git can't
/// have both `feature` and `feature/x` as branches, so branches can't conflict,
/// and a wrong guess finds no files at the folder path and stops the scan.
fn choose(segments: &[&str], refs: &[Ref]) -> Option<Resolved> {
    let find = |name: &str| refs.iter().find(|candidate| candidate.name == name);

    for used in (1..=segments.len().min(MAX_SEGMENTS_TRIED)).rev() {
        let name = segments[..used].join("/");
        let branch = find(&format!("refs/heads/{name}")).map(|found| (found, "branch"));
        let tag = find(&format!("refs/tags/{name}")).map(|found| (found, "tag"));

        if let Some((found, reference_kind)) = branch.or(tag) {
            return Some(Resolved {
                commit: found.commit.clone(),
                reference: name,
                reference_kind,
                folder: folder_after(segments, used),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT_A: &str = "7bff443b45b93efecfeae1779404d12a20f4c225";
    const COMMIT_B: &str = "9ed43f6507f1214b165fcb79f88e5e503f4a3539";

    fn reference(name: &str, commit: &str) -> Ref {
        Ref {
            name: name.to_string(),
            commit: commit.to_string(),
        }
    }

    fn segments(view: &str) -> Vec<&str> {
        view.split('/').collect()
    }

    #[test]
    fn asks_about_each_possible_branch_name() {
        let body = request_body(&["feature", "x", "src"]);

        assert!(body.starts_with("0014command=ls-refs\n0001"));
        assert!(body.ends_with("0000"));
        for prefix in [
            "ref-prefix refs/heads/feature\n",
            "ref-prefix refs/tags/feature\n",
            "ref-prefix refs/heads/feature/x\n",
            "ref-prefix refs/heads/feature/x/src\n",
        ] {
            assert!(body.contains(prefix), "missing: {prefix}");
        }
    }

    #[test]
    fn names_with_spaces_cannot_add_lines_to_the_request() {
        let body = request_body(&["main", "my folder", "x"]);

        assert!(body.contains("refs/heads/main\n"));
        assert!(!body.contains("my folder"));
    }

    #[test]
    fn reads_a_real_answer() {
        // Captured from a real server.
        let response = format!(
            "003f{COMMIT_A} refs/heads/master\n\
             003f{COMMIT_B} refs/tags/v1.40.0\n\
             0000"
        );

        assert_eq!(
            parse_refs(response.as_bytes()).unwrap(),
            [
                reference("refs/heads/master", COMMIT_A),
                reference("refs/tags/v1.40.0", COMMIT_B)
            ]
        );
    }

    #[test]
    fn uses_the_commit_behind_an_annotated_tag() {
        let line = format!("{COMMIT_A} refs/tags/v1 peeled:{COMMIT_B}\n");
        let response = format!("{:04x}{line}0000", line.len() + 4);

        assert_eq!(
            parse_refs(response.as_bytes()).unwrap(),
            [reference("refs/tags/v1", COMMIT_B)]
        );
    }

    #[test]
    fn refuses_answers_it_cannot_read() {
        for response in [
            &b"zzzz"[..],
            b"00",
            b"0003",
            b"0100short",
            b"0010not-a-commit\n",
            b"\xff\xff\xff\xff",
        ] {
            assert_eq!(parse_refs(response), None, "{response:?}");
        }
    }

    #[test]
    fn an_empty_answer_means_nothing_matched() {
        let refs = parse_refs(b"0000").unwrap();

        assert_eq!(choose(&segments("nope/src"), &refs), None);
    }

    #[test]
    fn splits_a_link_into_branch_and_folder() {
        let refs = [reference("refs/heads/main", COMMIT_A)];

        assert_eq!(
            choose(&segments("main/erc20-token-dapp"), &refs),
            Some(Resolved {
                commit: COMMIT_A.to_string(),
                reference: "main".to_string(),
                reference_kind: "branch",
                folder: Some("erc20-token-dapp".to_string()),
            })
        );
    }

    #[test]
    fn handles_a_branch_name_containing_a_slash() {
        let refs = [reference("refs/heads/feature/x", COMMIT_A)];

        assert_eq!(
            choose(&segments("feature/x/src/a"), &refs),
            Some(Resolved {
                commit: COMMIT_A.to_string(),
                reference: "feature/x".to_string(),
                reference_kind: "branch",
                folder: Some("src/a".to_string()),
            })
        );
    }

    #[test]
    fn a_link_to_a_branch_has_no_folder() {
        let refs = [reference("refs/heads/main", COMMIT_A)];

        assert_eq!(choose(&segments("main"), &refs).unwrap().folder, None);
    }

    #[test]
    fn prefers_a_branch_over_a_tag_with_the_same_name() {
        let refs = [
            reference("refs/tags/v1", COMMIT_B),
            reference("refs/heads/v1", COMMIT_A),
        ];

        assert_eq!(choose(&segments("v1"), &refs).unwrap().commit, COMMIT_A);
    }

    #[test]
    fn says_when_a_link_means_a_tag() {
        let refs = [reference("refs/tags/v1.40.0", COMMIT_B)];

        assert_eq!(
            choose(&segments("v1.40.0"), &refs).unwrap().reference_kind,
            "tag"
        );
    }

    #[test]
    fn similar_names_do_not_count_as_a_match() {
        let refs = [reference("refs/heads/main2", COMMIT_A)];

        assert_eq!(choose(&segments("main/src"), &refs), None);
    }
}
