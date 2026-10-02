// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The `HttpClient` seam between [`super::GitHubAppClient`] and whatever
//! actually opens a socket. Tests exercise the real HTTP code path
//! (headers, status, body) against a loopback fake GitHub server --
//! `wiremock`-style, just hand-rolled, since nothing in this crate's
//! dependency tree needs TLS and a loopback test server never speaks
//! TLS anyway.
//!
//! [`UreqClient`] has **no `tls` feature enabled** (see the crate's
//! `Cargo.toml`): it can reach `http://` only. Production wiring to the
//! real `https://api.github.com` needs a TLS-capable transport supplied
//! by whatever binary links this crate for deployment (D-B3.11
//! follow-up) -- most simply, `loom-cli` depending on `ureq` itself with
//! its `tls` feature on, since that binary is built and run only where a
//! real C toolchain exists (CI, the release image), never in this
//! agent's sandbox.

use std::io::Read;

pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpError(pub String);

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// What [`super::GitHubAppClient`] needs from an HTTP client: three verbs,
/// a bearer token, and a JSON body in/out. No cookies, no redirects, no
/// retries -- those policies belong to the caller (D-B3.11's token cache
/// already owns retry-on-expiry).
pub trait HttpClient: Send + Sync {
    fn post(&self, url: &str, bearer: &str, body: &[u8]) -> Result<HttpResponse, HttpError>;
    fn get(&self, url: &str, bearer: &str) -> Result<HttpResponse, HttpError>;
}

/// The `ureq`-backed transport (no TLS feature -- see module docs).
pub struct UreqClient {
    agent: ureq::Agent,
}

impl Default for UreqClient {
    fn default() -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(10))
                .build(),
        }
    }
}

fn to_response(resp: ureq::Response) -> Result<HttpResponse, HttpError> {
    let status = resp.status();
    let mut body = Vec::new();
    resp.into_reader()
        .read_to_end(&mut body)
        .map_err(|e| HttpError(e.to_string()))?;
    Ok(HttpResponse { status, body })
}

/// `ureq` treats any non-2xx as `Err(Error::Status(..))`; GitHub's error
/// bodies (rate limit, bad credentials, validation failures) are exactly
/// what callers need to see, so unwrap that case back into an ordinary
/// response instead of an opaque transport error.
fn unwrap_status_errors(
    result: Result<ureq::Response, ureq::Error>,
) -> Result<HttpResponse, HttpError> {
    match result {
        Ok(resp) => to_response(resp),
        Err(ureq::Error::Status(_, resp)) => to_response(resp),
        Err(ureq::Error::Transport(t)) => Err(HttpError(t.to_string())),
    }
}

impl HttpClient for UreqClient {
    fn post(&self, url: &str, bearer: &str, body: &[u8]) -> Result<HttpResponse, HttpError> {
        let result = self
            .agent
            .post(url)
            .set("Authorization", &format!("Bearer {bearer}"))
            .set("Accept", "application/vnd.github+json")
            .set("X-GitHub-Api-Version", "2022-11-28")
            .set("Content-Type", "application/json")
            .send_bytes(body);
        unwrap_status_errors(result)
    }

    fn get(&self, url: &str, bearer: &str) -> Result<HttpResponse, HttpError> {
        let result = self
            .agent
            .get(url)
            .set("Authorization", &format!("Bearer {bearer}"))
            .set("Accept", "application/vnd.github+json")
            .set("X-GitHub-Api-Version", "2022-11-28")
            .call();
        unwrap_status_errors(result)
    }
}
