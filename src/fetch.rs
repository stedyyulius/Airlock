//! Talks to the outside world over HTTPS.

use std::fmt;
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(300);
const HTTP_OK: u16 = 200;
const USER_AGENT: &str = concat!("airlock/", env!("CARGO_PKG_VERSION"));

/// Why a request failed.
#[derive(Debug)]
pub enum FetchError {
    NotFound,
    /// GitLab answers this way for a repository that is private or missing,
    /// sending the visitor to its sign-in page.
    Redirected,
    Status(u16),
    Network(ureq::Error),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "repository not found (it may be private)"),
            Self::Redirected => write!(
                f,
                "the host sent a redirect instead of the archive, so the repository \
                 may be private, renamed or missing"
            ),
            Self::Status(code) => write!(f, "server returned HTTP {code}"),
            Self::Network(error) => write!(f, "download failed: {error}"),
        }
    }
}

impl std::error::Error for FetchError {}

/// Hosts answer these requests directly, so redirects are not followed. A
/// response can't send us to another host, including services on the user's
/// own network.
fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_global(Some(TOTAL_TIMEOUT))
        .user_agent(USER_AGENT)
        .build()
        .into()
}

/// Starts a download and returns a reader over the response body.
///
/// The body is not read here: whoever consumes it applies the size limits.
pub fn open_archive(url: &str) -> Result<ureq::BodyReader<'static>, FetchError> {
    let response = check_status(agent().get(url).call())?;
    Ok(response.into_body().into_reader())
}

/// Sends `body` and returns the response, which may be at most `limit` bytes.
pub fn post(
    url: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    limit: u64,
) -> Result<Vec<u8>, FetchError> {
    let mut request = agent().post(url);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }

    let mut response = check_status(request.send(body))?;
    response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(FetchError::Network)
}

fn check_status(
    result: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<ureq::http::Response<ureq::Body>, FetchError> {
    match result {
        Ok(response) if response.status() == HTTP_OK => Ok(response),
        Ok(response) if response.status().is_redirection() => Err(FetchError::Redirected),
        Ok(response) => Err(FetchError::Status(response.status().as_u16())),
        Err(ureq::Error::StatusCode(404)) => Err(FetchError::NotFound),
        Err(ureq::Error::StatusCode(code)) => Err(FetchError::Status(code)),
        Err(error) => Err(FetchError::Network(error)),
    }
}
