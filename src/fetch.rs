//! Opens a repository archive for streaming over HTTPS.

use std::fmt;
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(300);
const HTTP_OK: u16 = 200;
const USER_AGENT: &str = concat!("airlock/", env!("CARGO_PKG_VERSION"));

/// Why an archive could not be opened.
#[derive(Debug)]
pub enum FetchError {
    NotFound,
    Status(u16),
    Network(ureq::Error),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "repository not found (it may be private)"),
            Self::Status(code) => write!(f, "server returned HTTP {code}"),
            Self::Network(error) => write!(f, "download failed: {error}"),
        }
    }
}

impl std::error::Error for FetchError {}

/// Starts a download and returns a reader over the response body.
///
/// Archives are served directly, so redirects are not followed. A response can't
/// send us to another host, including services on the user's own network.
/// The body is not read here: whoever consumes it applies the size limits.
pub fn open_archive(url: &str) -> Result<ureq::BodyReader<'static>, FetchError> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_global(Some(TOTAL_TIMEOUT))
        .user_agent(USER_AGENT)
        .build()
        .into();

    match agent.get(url).call() {
        Ok(response) if response.status() == HTTP_OK => Ok(response.into_body().into_reader()),
        Ok(response) => Err(FetchError::Status(response.status().as_u16())),
        Err(ureq::Error::StatusCode(404)) => Err(FetchError::NotFound),
        Err(ureq::Error::StatusCode(code)) => Err(FetchError::Status(code)),
        Err(error) => Err(FetchError::Network(error)),
    }
}
