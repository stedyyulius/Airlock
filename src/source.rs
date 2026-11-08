//! Turns a pasted repository URL into the archive URL Airlock downloads.
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
                write!(f, "expected a path like owner/repo, got: {path}")
            }
            Self::InvalidName(name) => write!(f, "invalid owner or repo name: {name}"),
        }
    }
}

impl std::error::Error for SourceError {}

impl Source {
    /// Parses a repository URL from GitHub, GitLab or Bitbucket, such as
    /// `https://github.com/owner/repo`.
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
            "github.com" | "www.github.com" => {
                let (owner, repo) = parse_owner_repo(path)?;
                Ok(Self::GitHub { owner, repo })
            }
            "gitlab.com" | "www.gitlab.com" => {
                let (namespace, project) = parse_gitlab_path(path)?;
                Ok(Self::GitLab { namespace, project })
            }
            "bitbucket.org" | "www.bitbucket.org" => {
                let (workspace, repo) = parse_owner_repo(path)?;
                Ok(Self::Bitbucket { workspace, repo })
            }
            other => Err(SourceError::UnsupportedHost(other.to_string())),
        }
    }

    /// The URL of a tarball containing the repository's default branch.
    pub fn archive_url(&self) -> String {
        match self {
            Self::GitHub { owner, repo } => {
                format!("https://codeload.github.com/{owner}/{repo}/tar.gz/HEAD")
            }
            Self::GitLab { namespace, project } => format!(
                "https://gitlab.com/{namespace}/{project}/-/archive/HEAD/{project}-HEAD.tar.gz"
            ),
            Self::Bitbucket { workspace, repo } => {
                format!("https://bitbucket.org/{workspace}/{repo}/get/HEAD.tar.gz")
            }
        }
    }
}

/// Splits `owner/repo` and validates both names.
///
/// Extra segments such as `owner/repo/tree/dev` are rejected rather than
/// ignored: otherwise we would scan the default branch while the user believes
/// we scanned `dev`.
fn parse_owner_repo(path: &str) -> Result<(String, String), SourceError> {
    let segments: Vec<&str> = path.trim_end_matches('/').split('/').collect();
    let [owner, repo] = segments.as_slice() else {
        return Err(SourceError::InvalidPath(path.to_string()));
    };
    let repo = repo.strip_suffix(".git").unwrap_or(repo);

    for name in [*owner, repo] {
        if !is_valid_name(name) {
            return Err(SourceError::InvalidName(name.to_string()));
        }
    }
    Ok((owner.to_string(), repo.to_string()))
}

/// Splits a GitLab path into its groups and project. A project can sit inside
/// nested groups, as in `group/subgroup/project`.
///
/// GitLab's other pages contain a `-` segment, as in `group/project/-/tree/dev`.
/// They are rejected for the same reason as `owner/repo/tree/dev`.
fn parse_gitlab_path(path: &str) -> Result<(String, String), SourceError> {
    let segments: Vec<&str> = path.trim_end_matches('/').split('/').collect();
    let [groups @ .., project] = segments.as_slice() else {
        return Err(SourceError::InvalidPath(path.to_string()));
    };
    if groups.is_empty() || segments.contains(&"-") {
        return Err(SourceError::InvalidPath(path.to_string()));
    }
    let project = project.strip_suffix(".git").unwrap_or(project);

    for name in groups.iter().copied().chain([project]) {
        if !is_valid_name(name) {
            return Err(SourceError::InvalidName(name.to_string()));
        }
    }
    Ok((groups.join("/"), project.to_string()))
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

    #[test]
    fn parses_common_github_url_forms() {
        let expected = || Ok(github("foundry-rs", "foundry"));

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
            assert_eq!(Source::parse(url), expected(), "input: {url:?}");
        }
    }

    #[test]
    fn builds_github_archive_url() {
        assert_eq!(
            github("foundry-rs", "foundry").archive_url(),
            "https://codeload.github.com/foundry-rs/foundry/tar.gz/HEAD"
        );
    }

    #[test]
    fn parses_common_gitlab_url_forms() {
        let expected = || Ok(gitlab("gitlab-org", "cli"));

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
            assert_eq!(Source::parse(url), expected(), "input: {url:?}");
        }
    }

    #[test]
    fn parses_gitlab_projects_inside_nested_groups() {
        assert_eq!(
            Source::parse("https://gitlab.com/gitlab-org/api/client-go"),
            Ok(gitlab("gitlab-org/api", "client-go"))
        );
        assert_eq!(
            Source::parse("https://gitlab.com/a/b/c/d/project.git"),
            Ok(gitlab("a/b/c/d", "project"))
        );
    }

    #[test]
    fn parses_common_bitbucket_url_forms() {
        let expected = || Ok(bitbucket("atlassian", "aws-s3-deploy"));

        for url in [
            "https://bitbucket.org/atlassian/aws-s3-deploy",
            "https://bitbucket.org/atlassian/aws-s3-deploy/",
            "https://bitbucket.org/atlassian/aws-s3-deploy.git",
            "https://www.bitbucket.org/atlassian/aws-s3-deploy",
            "https://Bitbucket.org/atlassian/aws-s3-deploy",
            "bitbucket.org/atlassian/aws-s3-deploy",
            "https://bitbucket.org/atlassian/aws-s3-deploy?x=1",
        ] {
            assert_eq!(Source::parse(url), expected(), "input: {url:?}");
        }
    }

    #[test]
    fn builds_gitlab_archive_url() {
        assert_eq!(
            gitlab("gitlab-org/api", "client-go").archive_url(),
            "https://gitlab.com/gitlab-org/api/client-go/-/archive/HEAD/client-go-HEAD.tar.gz"
        );
    }

    #[test]
    fn builds_bitbucket_archive_url() {
        assert_eq!(
            bitbucket("atlassian", "aws-s3-deploy").archive_url(),
            "https://bitbucket.org/atlassian/aws-s3-deploy/get/HEAD.tar.gz"
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
                matches!(Source::parse(url), Err(SourceError::UnsupportedHost(_))),
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
            let error = Source::parse(url).unwrap_err();

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
                matches!(Source::parse(url), Err(SourceError::UnsupportedScheme)),
                "input: {url:?}"
            );
        }
    }

    #[test]
    fn rejects_paths_that_are_not_exactly_owner_and_repo() {
        for url in [
            "https://github.com",
            "https://github.com/owner",
            "https://github.com/owner/repo/tree/dev",
            "https://github.com/owner/repo/blob/main/src/main.rs",
            "https://gitlab.com",
            "https://gitlab.com/owner",
            "https://gitlab.com/group/project/-/tree/dev",
            "https://gitlab.com/group/sub/project/-/blob/main/a.rs",
            "https://gitlab.com/group/project/-",
            "https://bitbucket.org",
            "https://bitbucket.org/workspace",
            "https://bitbucket.org/workspace/repo/src/dev/",
            "https://bitbucket.org/workspace/repo/commits",
        ] {
            assert!(
                matches!(Source::parse(url), Err(SourceError::InvalidPath(_))),
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
                matches!(Source::parse(url), Err(SourceError::InvalidName(_))),
                "input: {url:?}"
            );
        }
    }

    #[test]
    fn says_which_hosts_are_supported() {
        let error = Source::parse("https://example.com/owner/repo").unwrap_err();

        assert!(error.to_string().contains("gitlab.com"));
        assert!(error.to_string().contains("bitbucket.org"));
    }
}
