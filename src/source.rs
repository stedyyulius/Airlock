//! Turns a pasted repository URL into the archive URL Airlock downloads.
//!
//! The input is untrusted, so parsing is strict: anything we don't fully
//! understand is an error. Silently scanning the wrong code and reporting it
//! as clean would be worse than refusing.

use std::fmt;

/// A repository Airlock knows how to download.
#[derive(Debug, PartialEq, Eq)]
pub enum Source {
    GitHub { owner: String, repo: String },
}

/// Why a pasted URL was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum SourceError {
    UnsupportedScheme(String),
    UnsupportedHost(String),
    InvalidPath(String),
    InvalidName(String),
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedScheme(url) => write!(f, "only https URLs are supported: {url}"),
            Self::UnsupportedHost(host) => write!(f, "unsupported host: {host}"),
            Self::InvalidPath(path) => {
                write!(f, "expected a path like owner/repo, got: {path}")
            }
            Self::InvalidName(name) => write!(f, "invalid owner or repo name: {name}"),
        }
    }
}

impl std::error::Error for SourceError {}

impl Source {
    /// Parses a URL such as `https://github.com/owner/repo`.
    pub fn parse(input: &str) -> Result<Self, SourceError> {
        let trimmed = input.trim();
        let without_scheme = trimmed.strip_prefix("https://").unwrap_or(trimmed);
        if without_scheme.contains("://") {
            return Err(SourceError::UnsupportedScheme(trimmed.to_string()));
        }

        // Drop any ?query or #fragment: they don't identify the repo.
        let end = without_scheme
            .find(['?', '#'])
            .unwrap_or(without_scheme.len());
        let location = &without_scheme[..end];

        let (host, path) = location
            .split_once('/')
            .ok_or_else(|| SourceError::InvalidPath(location.to_string()))?;

        // The host must match exactly, so lookalikes such as
        // github.com.evil.com and github.com@evil.com are rejected.
        match host.to_ascii_lowercase().as_str() {
            "github.com" | "www.github.com" => {
                let (owner, repo) = parse_owner_repo(path)?;
                Ok(Self::GitHub { owner, repo })
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
    fn rejects_hosts_that_only_look_like_github() {
        for url in [
            "https://github.com.evil.com/owner/repo",
            "https://github.com@evil.com/owner/repo",
            "https://evilgithub.com/owner/repo",
            "https://gitlab.com/owner/repo",
        ] {
            assert!(
                matches!(Source::parse(url), Err(SourceError::UnsupportedHost(_))),
                "input: {url:?}"
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
                matches!(Source::parse(url), Err(SourceError::UnsupportedScheme(_))),
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
        ] {
            assert!(
                matches!(Source::parse(url), Err(SourceError::InvalidName(_))),
                "input: {url:?}"
            );
        }
    }
}
