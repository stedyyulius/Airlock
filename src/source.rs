//! Turns a pasted repository URL into what Airlock should download.
//!
//! The input is untrusted, so parsing is strict: anything we don't fully
//! understand is an error. Silently scanning the wrong code and reporting it
//! as clean would be worse than refusing.

use std::fmt;

/// A repository Airlock knows how to download.
#[derive(Debug, PartialEq, Eq)]
pub enum Source {
    GitHub {
        owner: String,
        repo: String,
    },
    GitLab {
        /// One group, or nested groups joined by `/`.
        namespace: String,
        project: String,
    },
    Bitbucket {
        workspace: String,
        repo: String,
    },
}

/// What a pasted URL asks Airlock to scan.
#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    pub source: Source,
    /// For a branch or folder link, the decoded text after the page marker, such
    /// as `main/src` in `.../tree/main/src`. Which part is the branch is worked
    /// out later, because branch names can contain slashes.
    pub view: Option<String>,
}

/// Why a pasted URL was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum SourceError {
    UnsupportedScheme,
    CredentialsInUrl,
    UnsupportedHost(String),
    InvalidPath(String),
    InvalidName(String),
}

// The first two variants carry no text on purpose: the URL they reject may
// contain a password or access token, and error messages end up in logs.
impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedScheme => write!(f, "only https URLs are supported"),
            Self::CredentialsInUrl => write!(
                f,
                "URLs with a username, password or token are not supported, \
                 use https://host/owner/repo"
            ),
            Self::UnsupportedHost(host) => write!(
                f,
                "unsupported host: {host}, Airlock supports github.com, gitlab.com and bitbucket.org"
            ),
            Self::InvalidPath(path) => {
                write!(
                    f,
                    "expected a link to a repository, branch or folder, got: {path}"
                )
            }
            Self::InvalidName(name) => write!(f, "invalid owner or repo name: {name}"),
        }
    }
}

impl std::error::Error for SourceError {}

impl Target {
    /// Parses a repository, branch or folder URL from GitHub, GitLab or
    /// Bitbucket, such as `https://github.com/owner/repo/tree/main/src`.
    pub fn parse(input: &str) -> Result<Self, SourceError> {
        let trimmed = input.trim();
        let without_scheme = trimmed.strip_prefix("https://").unwrap_or(trimmed);
        if without_scheme.contains("://") {
            return Err(SourceError::UnsupportedScheme);
        }

        // Drop any ?query or #fragment: they don't identify the repo.
        let end = without_scheme
            .find(['?', '#'])
            .unwrap_or(without_scheme.len());
        let location = &without_scheme[..end];
        let (host, path) = location.split_once('/').unwrap_or((location, ""));

        if host.contains('@') {
            return Err(SourceError::CredentialsInUrl);
        }

        // The host must match exactly, so lookalikes such as
        // github.com.evil.com are rejected.
        match host.to_ascii_lowercase().as_str() {
            "github.com" | "www.github.com" => parse_github(path),
            "gitlab.com" | "www.gitlab.com" => parse_gitlab(path),
            "bitbucket.org" | "www.bitbucket.org" => parse_bitbucket(path),
            other => Err(SourceError::UnsupportedHost(other.to_string())),
        }
    }
}

impl Source {
    /// The repository's name as people write it, such as `github.com/owner/repo`.
    pub fn name(&self) -> String {
        match self {
            Self::GitHub { owner, repo } => format!("github.com/{owner}/{repo}"),
            Self::GitLab { namespace, project } => format!("gitlab.com/{namespace}/{project}"),
            Self::Bitbucket { workspace, repo } => format!("bitbucket.org/{workspace}/{repo}"),
        }
    }

    /// The URL that git itself would talk to.
    pub fn git_url(&self) -> String {
        format!("https://{}.git", self.name())
    }
}

fn split_path(path: &str) -> Vec<&str> {
    path.trim_end_matches('/').split('/').collect()
}

fn parse_github(path: &str) -> Result<Target, SourceError> {
    let segments = split_path(path);
    let (owner, repo, view) = match segments.as_slice() {
        [owner, repo] => (*owner, *repo, None),
        [owner, repo, "tree" | "blob", rest @ ..] if !rest.is_empty() => {
            (*owner, *repo, Some(parse_view(rest, path)?))
        }
        _ => return Err(SourceError::InvalidPath(path.to_string())),
    };
    let (owner, repo) = validate_owner_and_repo(owner, repo)?;
    Ok(Target {
        source: Source::GitHub { owner, repo },
        view,
    })
}

fn parse_bitbucket(path: &str) -> Result<Target, SourceError> {
    let segments = split_path(path);
    let (workspace, repo, view) = match segments.as_slice() {
        [workspace, repo] => (*workspace, *repo, None),
        [workspace, repo, "src", rest @ ..] if !rest.is_empty() => {
            (*workspace, *repo, Some(parse_view(rest, path)?))
        }
        _ => return Err(SourceError::InvalidPath(path.to_string())),
    };
    let (workspace, repo) = validate_owner_and_repo(workspace, repo)?;
    Ok(Target {
        source: Source::Bitbucket { workspace, repo },
        view,
    })
}

/// GitLab projects can sit inside nested groups, as in `group/subgroup/project`.
/// Its other pages follow a `-` segment, as in `group/project/-/tree/dev`.
fn parse_gitlab(path: &str) -> Result<Target, SourceError> {
    let segments = split_path(path);
    let (repo_part, view) = match segments.iter().position(|segment| *segment == "-") {
        None => (segments.as_slice(), None),
        Some(dash) => match &segments[dash + 1..] {
            ["tree" | "blob", rest @ ..] if !rest.is_empty() => {
                (&segments[..dash], Some(parse_view(rest, path)?))
            }
            _ => return Err(SourceError::InvalidPath(path.to_string())),
        },
    };

    let [groups @ .., project] = repo_part else {
        return Err(SourceError::InvalidPath(path.to_string()));
    };
    if groups.is_empty() {
        return Err(SourceError::InvalidPath(path.to_string()));
    }
    let project = project.strip_suffix(".git").unwrap_or(project);

    for name in groups.iter().copied().chain([project]) {
        if !is_valid_name(name) {
            return Err(SourceError::InvalidName(name.to_string()));
        }
    }
    Ok(Target {
        source: Source::GitLab {
            namespace: groups.join("/"),
            project: project.to_string(),
        },
        view,
    })
}

fn validate_owner_and_repo(owner: &str, repo: &str) -> Result<(String, String), SourceError> {
    let repo = repo.strip_suffix(".git").unwrap_or(repo);

    for name in [owner, repo] {
        if !is_valid_name(name) {
            return Err(SourceError::InvalidName(name.to_string()));
        }
    }
    Ok((owner.to_string(), repo.to_string()))
}

/// These names end up inside a download URL, so only allow safe characters.
fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Decodes the branch and folder part of a link and checks each piece of it.
/// This text only ever selects files by name inside the repository and is never
/// used as a real path, but anything odd is still refused.
fn parse_view(segments: &[&str], path: &str) -> Result<String, SourceError> {
    let invalid = || SourceError::InvalidPath(path.to_string());
    let view = percent_decode(&segments.join("/")).ok_or_else(invalid)?;

    let is_valid = view.split('/').all(|piece| {
        !piece.is_empty()
            && piece != "."
            && piece != ".."
            && !piece.contains(|c: char| c.is_control() || c == '\\')
    });
    if is_valid { Ok(view) } else { Err(invalid()) }
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;

    while at < bytes.len() {
        if bytes[at] == b'%' {
            let digits = std::str::from_utf8(bytes.get(at + 1..at + 3)?).ok()?;
            decoded.push(u8::from_str_radix(digits, 16).ok()?);
            at += 3;
        } else {
            decoded.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn github(owner: &str, repo: &str) -> Source {
        Source::GitHub {
            owner: owner.to_string(),
            repo: repo.to_string(),
        }
    }

    fn gitlab(namespace: &str, project: &str) -> Source {
        Source::GitLab {
            namespace: namespace.to_string(),
            project: project.to_string(),
        }
    }

    fn bitbucket(workspace: &str, repo: &str) -> Source {
        Source::Bitbucket {
            workspace: workspace.to_string(),
            repo: repo.to_string(),
        }
    }

    fn whole(source: Source) -> Target {
        Target { source, view: None }
    }

    fn viewing(source: Source, view: &str) -> Target {
        Target {
            source,
            view: Some(view.to_string()),
        }
    }

    #[test]
    fn parses_common_github_url_forms() {
        let expected = || Ok(whole(github("foundry-rs", "foundry")));

        for url in [
            "https://github.com/foundry-rs/foundry",
            "https://github.com/foundry-rs/foundry/",
            "https://github.com/foundry-rs/foundry.git",
            "https://www.github.com/foundry-rs/foundry",
            "https://GitHub.com/foundry-rs/foundry",
            "github.com/foundry-rs/foundry",
            "  https://github.com/foundry-rs/foundry\n",
            "https://github.com/foundry-rs/foundry?tab=readme-ov-file",
            "https://github.com/foundry-rs/foundry#installation",
        ] {
            assert_eq!(Target::parse(url), expected(), "input: {url:?}");
        }
    }

    #[test]
    fn parses_common_gitlab_url_forms() {
        let expected = || Ok(whole(gitlab("gitlab-org", "cli")));

        for url in [
            "https://gitlab.com/gitlab-org/cli",
            "https://gitlab.com/gitlab-org/cli/",
            "https://gitlab.com/gitlab-org/cli.git",
            "https://www.gitlab.com/gitlab-org/cli",
            "https://GitLab.com/gitlab-org/cli",
            "gitlab.com/gitlab-org/cli",
            "https://gitlab.com/gitlab-org/cli?tab=readme",
            "https://gitlab.com/gitlab-org/cli#install",
        ] {
            assert_eq!(Target::parse(url), expected(), "input: {url:?}");
        }
    }

    #[test]
    fn parses_gitlab_projects_inside_nested_groups() {
        assert_eq!(
            Target::parse("https://gitlab.com/gitlab-org/api/client-go"),
            Ok(whole(gitlab("gitlab-org/api", "client-go")))
        );
        assert_eq!(
            Target::parse("https://gitlab.com/a/b/c/d/project.git"),
            Ok(whole(gitlab("a/b/c/d", "project")))
        );
    }

    #[test]
    fn parses_common_bitbucket_url_forms() {
        let expected = || Ok(whole(bitbucket("atlassian", "aws-s3-deploy")));

        for url in [
            "https://bitbucket.org/atlassian/aws-s3-deploy",
            "https://bitbucket.org/atlassian/aws-s3-deploy/",
            "https://bitbucket.org/atlassian/aws-s3-deploy.git",
            "https://www.bitbucket.org/atlassian/aws-s3-deploy",
            "https://Bitbucket.org/atlassian/aws-s3-deploy",
            "bitbucket.org/atlassian/aws-s3-deploy",
            "https://bitbucket.org/atlassian/aws-s3-deploy?x=1",
        ] {
            assert_eq!(Target::parse(url), expected(), "input: {url:?}");
        }
    }

    #[test]
    fn parses_branch_and_folder_links_on_every_host() {
        for (url, target) in [
            (
                "https://github.com/o/r/tree/main",
                viewing(github("o", "r"), "main"),
            ),
            (
                "https://github.com/o/r/tree/main/erc20-token-dapp",
                viewing(github("o", "r"), "main/erc20-token-dapp"),
            ),
            (
                "https://github.com/o/r/tree/feature/x/src/",
                viewing(github("o", "r"), "feature/x/src"),
            ),
            (
                "https://github.com/o/r/blob/main/src/a.js",
                viewing(github("o", "r"), "main/src/a.js"),
            ),
            (
                "https://gitlab.com/g/p/-/tree/main/src?ref_type=heads",
                viewing(gitlab("g", "p"), "main/src"),
            ),
            (
                "https://gitlab.com/g/s/p/-/blob/main/a.js",
                viewing(gitlab("g/s", "p"), "main/a.js"),
            ),
            (
                "https://bitbucket.org/w/r/src/master/src/",
                viewing(bitbucket("w", "r"), "master/src"),
            ),
            (
                "https://github.com/o/r/tree/main/my%20folder",
                viewing(github("o", "r"), "main/my folder"),
            ),
        ] {
            assert_eq!(Target::parse(url), Ok(target), "input: {url:?}");
        }
    }

    #[test]
    fn rejects_folder_links_that_try_to_climb_or_hide_characters() {
        for url in [
            "https://github.com/o/r/tree/main/../secret",
            "https://github.com/o/r/tree/main/%2e%2e/secret",
            "https://github.com/o/r/tree/main/.",
            "https://github.com/o/r/tree/main//src",
            "https://github.com/o/r/tree/main/a%0Ab",
            "https://github.com/o/r/tree/main/a%5Cb",
            "https://github.com/o/r/tree/main/%ff",
            "https://github.com/o/r/tree/main/%zz",
            "https://github.com/o/r/tree/main/%2",
            "https://gitlab.com/g/p/-/tree/main/../x",
            "https://bitbucket.org/w/r/src/main/../x",
        ] {
            assert!(
                matches!(Target::parse(url), Err(SourceError::InvalidPath(_))),
                "input: {url:?}"
            );
        }
    }

    #[test]
    fn builds_names_and_git_urls() {
        assert_eq!(github("o", "r").name(), "github.com/o/r");
        assert_eq!(gitlab("g/s", "p").git_url(), "https://gitlab.com/g/s/p.git");
        assert_eq!(
            bitbucket("w", "r").git_url(),
            "https://bitbucket.org/w/r.git"
        );
    }

    #[test]
    fn rejects_hosts_that_only_look_like_a_supported_one() {
        for url in [
            "https://github.com.evil.com/owner/repo",
            "https://evilgithub.com/owner/repo",
            // The first letter is a Cyrillic look-alike.
            "https://\u{0261}ithub.com/owner/repo",
            "https://gitlab.com.evil.example/owner/repo",
            "https://evilgitlab.com/owner/repo",
            "https://gitlab.example.com/owner/repo",
            "https://bitbucket.org.evil.example/owner/repo",
            "https://evilbitbucket.org/owner/repo",
            "https://bitbucket.com/owner/repo",
        ] {
            assert!(
                matches!(Target::parse(url), Err(SourceError::UnsupportedHost(_))),
                "input: {url:?}"
            );
        }
    }

    #[test]
    fn rejects_credentials_without_repeating_them() {
        for url in [
            "https://user:ghp_secret@github.com/owner/repo",
            "https://ghp_secret@github.com/owner/repo",
            "https://ghp_secret@github.com",
            "https://github.com@ghp_secret.example/owner/repo",
            "http://user:ghp_secret@github.com/owner/repo",
            "ghp_secret@github.com:owner/repo.git",
            "https://user:ghp_secret@gitlab.com/owner/repo",
            "ghp_secret@gitlab.com:owner/repo.git",
            "https://user:ghp_secret@bitbucket.org/owner/repo",
            "ghp_secret@bitbucket.org:owner/repo.git",
        ] {
            let error = Target::parse(url).unwrap_err();

            assert!(
                !error.to_string().contains("ghp_secret"),
                "input: {url:?}, error: {error}"
            );
        }
    }

    #[test]
    fn rejects_other_schemes() {
        for url in [
            "http://github.com/owner/repo",
            "ssh://git@github.com/owner/repo",
            "file:///etc/passwd",
        ] {
            assert!(
                matches!(Target::parse(url), Err(SourceError::UnsupportedScheme)),
                "input: {url:?}"
            );
        }
    }

    #[test]
    fn rejects_pages_that_are_not_a_repository_branch_or_folder() {
        for url in [
            "https://github.com",
            "https://github.com/owner",
            "https://github.com/owner/repo/tree",
            "https://github.com/owner/repo/issues",
            "https://github.com/owner/repo/pull/12",
            "https://gitlab.com",
            "https://gitlab.com/owner",
            "https://gitlab.com/group/project/-",
            "https://gitlab.com/group/project/-/tree",
            "https://gitlab.com/group/project/-/merge_requests",
            "https://gitlab.com/-/tree/main",
            "https://bitbucket.org",
            "https://bitbucket.org/workspace",
            "https://bitbucket.org/workspace/repo/src",
            "https://bitbucket.org/workspace/repo/commits",
        ] {
            assert!(
                matches!(Target::parse(url), Err(SourceError::InvalidPath(_))),
                "input: {url:?}"
            );
        }
    }

    #[test]
    fn rejects_names_that_could_alter_the_download_url() {
        for url in [
            "https://github.com/../repo",
            "https://github.com/owner/..",
            "https://github.com/owner/.git",
            "https://github.com/owner/re%2Fpo",
            "https://github.com/ow ner/repo",
            "https://gitlab.com/../repo",
            "https://gitlab.com/group/../repo",
            "https://gitlab.com/group/..",
            "https://gitlab.com//repo",
            "https://gitlab.com/group/re%2Fpo",
            "https://gitlab.com/group/.git",
            "https://bitbucket.org/../repo",
            "https://bitbucket.org/workspace/..",
            "https://bitbucket.org/workspace/re%2Fpo",
        ] {
            assert!(
                matches!(Target::parse(url), Err(SourceError::InvalidName(_))),
                "input: {url:?}"
            );
        }
    }

    #[test]
    fn says_which_hosts_are_supported() {
        let error = Target::parse("https://example.com/owner/repo").unwrap_err();

        assert!(error.to_string().contains("gitlab.com"));
        assert!(error.to_string().contains("bitbucket.org"));
    }
}
