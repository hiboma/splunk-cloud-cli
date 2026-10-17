//! Shared endpoint validation and redirect-free authenticated transport.
use crate::error::{Result, SplunkError};
use reqwest::{Method, RequestBuilder, Url};

/// A canonical service origin, with no embedded credentials or URL suffix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint(String);

impl Endpoint {
    pub fn parse(value: &str) -> Result<Self> {
        let invalid = || {
            SplunkError::Config(
            "base_url must be an HTTPS origin, or HTTP on localhost, 127.0.0.1 or [::1], without credentials, path, query or fragment".into(),
        )
        };
        // Reject parser normalization of whitespace and backslashes explicitly.
        if value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
        {
            return Err(invalid());
        }
        let url = Url::parse(value).map_err(|_| invalid())?;
        let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(invalid());
        }
        // Empty userinfo and dot paths can disappear during URL parsing.
        let authority_and_path = value.split_once("://").ok_or_else(invalid)?.1;
        let (authority, path) = authority_and_path
            .split_once('/')
            .unwrap_or((authority_and_path, ""));
        if authority.contains('@') || !path.is_empty() {
            return Err(invalid());
        }
        Ok(Self(url.origin().ascii_serialization()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn origin(&self) -> String {
        self.0.clone()
    }
}

/// Credential-bearing requests must never follow a redirect (CWE-200).
/// The inner client is private so callers cannot inject a weaker policy.
#[derive(Clone)]
pub struct HttpClient(reqwest::Client);

impl HttpClient {
    pub fn new() -> Result<Self> {
        Ok(Self(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .user_agent(concat!("splunk-cloud-cli/", env!("CARGO_PKG_VERSION")))
                .build()?,
        ))
    }

    pub fn request(&self, method: Method, url: &str) -> RequestBuilder {
        self.0.request(method, url)
    }

    pub fn post(&self, url: &str) -> RequestBuilder {
        self.request(Method::POST, url)
    }

    pub fn get(&self, url: &str) -> RequestBuilder {
        self.request(Method::GET, url)
    }
}
