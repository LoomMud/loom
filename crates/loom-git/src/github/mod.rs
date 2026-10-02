// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The GitHub App client (D-B3.9/D-B3.11, P2-B3.3): mints an RS256 App
//! JWT, exchanges it for a short-lived installation token, and caches
//! that token in memory until 5 minutes before it expires. This is the
//! `TokenProvider` B3.2's `GitWorker` calls for every push/fetch (and,
//! once wired, for `propose`'s PR open/comment calls).
//!
//! This is a *dedicated* App (`loom-warp-propose`): never the OBI-43
//! reviewer App, never a shared PAT (D-B3.9). The driver process that
//! configures a [`GitHubAppClient`] is the only thing that ever holds
//! this App's private key, read once from a mounted secret file
//! (`/run/secrets/warp_app.pem`) and kept in memory only -- see
//! `GitHubAppClient::from_pem_file`.

pub mod jwt;
pub mod transport;

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use rsa::RsaPrivateKey;
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub use transport::{HttpClient, HttpError, HttpResponse, UreqClient};

use crate::worker::TokenProvider;

/// Refresh 5 minutes before expiry (D-B3.11/design §2 D-B3.11: "caches
/// until 5 min before expiry").
const REFRESH_SKEW: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone)]
struct CachedToken {
    token: String,
    expires_at: SystemTime,
}

#[derive(Deserialize)]
struct AccessTokenResponse {
    token: String,
    expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitHubAppError {
    BadKey(String),
    /// Non-2xx response from GitHub: status plus a body snippet (never
    /// the key or the minted JWT -- those are not in this error at all).
    Api {
        status: u16,
        body: String,
    },
    Transport(String),
    /// The response body wasn't the JSON shape GitHub documents.
    BadResponse(String),
}

impl std::fmt::Display for GitHubAppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitHubAppError::BadKey(e) => write!(f, "bad GitHub App private key: {e}"),
            GitHubAppError::Api { status, body } => {
                write!(f, "GitHub API error {status}: {body}")
            }
            GitHubAppError::Transport(e) => write!(f, "GitHub API transport error: {e}"),
            GitHubAppError::BadResponse(e) => write!(f, "unexpected GitHub API response: {e}"),
        }
    }
}

/// Clamp any error body logged/returned to callers -- GitHub error
/// payloads are normally small, but nothing says a misconfigured proxy
/// couldn't hand back megabytes of HTML.
const MAX_ERROR_BODY: usize = 2048;

fn truncate_body(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    if text.len() > MAX_ERROR_BODY {
        format!(
            "{}... ({} bytes total)",
            &text[..MAX_ERROR_BODY],
            text.len()
        )
    } else {
        text.into_owned()
    }
}

pub struct GitHubAppClient<C: HttpClient = UreqClient> {
    app_id: String,
    installation_id: String,
    private_key: RsaPrivateKey,
    /// `https://api.github.com` in production; a loopback fake server in
    /// tests.
    api_base: String,
    transport: C,
    cache: Mutex<Option<CachedToken>>,
    now: fn() -> SystemTime,
}

impl GitHubAppClient<UreqClient> {
    /// Reads the PEM from `path` (e.g. `/run/secrets/warp_app.pem`,
    /// D-B3.11) once at construction. The key never touches the VFS or
    /// any other persistence after this.
    pub fn from_pem_file(
        app_id: impl Into<String>,
        installation_id: impl Into<String>,
        pem_path: &std::path::Path,
    ) -> Result<Self, GitHubAppError> {
        let pem = std::fs::read_to_string(pem_path)
            .map_err(|e| GitHubAppError::BadKey(format!("reading {pem_path:?}: {e}")))?;
        Self::new(app_id, installation_id, &pem, UreqClient::default())
    }
}

impl<C: HttpClient> GitHubAppClient<C> {
    pub fn new(
        app_id: impl Into<String>,
        installation_id: impl Into<String>,
        private_key_pem: &str,
        transport: C,
    ) -> Result<Self, GitHubAppError> {
        let private_key = jwt::load_private_key(private_key_pem)
            .map_err(|e| GitHubAppError::BadKey(e.to_string()))?;
        Ok(Self {
            app_id: app_id.into(),
            installation_id: installation_id.into(),
            private_key,
            api_base: "https://api.github.com".to_string(),
            transport,
            cache: Mutex::new(None),
            now: SystemTime::now,
        })
    }

    /// Test/staging seam: point at a loopback fake GitHub server instead
    /// of `https://api.github.com`.
    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Self {
        self.api_base = api_base.into();
        self
    }

    #[cfg(test)]
    fn with_clock(mut self, now: fn() -> SystemTime) -> Self {
        self.now = now;
        self
    }

    /// Mints and exchanges a fresh installation token, unconditionally
    /// (bypasses the cache). `token()` is the cached, refresh-aware path
    /// callers (and `TokenProvider::token`) should use instead.
    fn mint_installation_token(&self) -> Result<CachedToken, GitHubAppError> {
        let app_jwt = jwt::mint(&self.app_id, &self.private_key, (self.now)())
            .map_err(|e| GitHubAppError::BadKey(e.to_string()))?;
        let url = format!(
            "{}/app/installations/{}/access_tokens",
            self.api_base, self.installation_id
        );
        let resp = self
            .transport
            .post(&url, &app_jwt, b"{}")
            .map_err(|e| GitHubAppError::Transport(e.0))?;
        if !(200..300).contains(&resp.status) {
            return Err(GitHubAppError::Api {
                status: resp.status,
                body: truncate_body(&resp.body),
            });
        }
        let parsed: AccessTokenResponse = serde_json::from_slice(&resp.body)
            .map_err(|e| GitHubAppError::BadResponse(e.to_string()))?;
        let expires_at = OffsetDateTime::parse(&parsed.expires_at, &Rfc3339)
            .map_err(|e| GitHubAppError::BadResponse(format!("expires_at: {e}")))?;
        Ok(CachedToken {
            token: parsed.token,
            expires_at: SystemTime::UNIX_EPOCH
                + Duration::from_secs(expires_at.unix_timestamp().max(0) as u64),
        })
    }

    /// The cached, refresh-aware installation token. Safe to call on
    /// every push/fetch/propose attempt -- it only hits the network when
    /// there is no cached token or it is within 5 minutes of expiry
    /// (D-B3.11).
    pub fn installation_token(&self) -> Result<String, GitHubAppError> {
        let now = (self.now)();
        {
            let guard = self.cache.lock().expect("GitHubAppClient cache poisoned");
            if let Some(cached) = guard.as_ref()
                && cached
                    .expires_at
                    .duration_since(now)
                    .map(|remaining| remaining > REFRESH_SKEW)
                    .unwrap_or(false)
            {
                return Ok(cached.token.clone());
            }
        }
        let fresh = self.mint_installation_token()?;
        let token = fresh.token.clone();
        *self.cache.lock().expect("GitHubAppClient cache poisoned") = Some(fresh);
        Ok(token)
    }

    pub fn api_base(&self) -> &str {
        &self.api_base
    }
}

impl<C: HttpClient> TokenProvider for GitHubAppClient<C> {
    fn token(&self) -> Result<String, String> {
        self.installation_token().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_pem() -> String {
        use rsa::pkcs8::EncodePrivateKey;
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        key.to_pkcs8_pem(Default::default()).unwrap().to_string()
    }

    /// A tiny fake GitHub `/app/installations/.../access_tokens` server:
    /// one TCP accept loop, canned JSON responses driven by a closure so
    /// each test controls status/body/expiry without a real mock-server
    /// dependency.
    struct FakeGitHub {
        addr: String,
        requests: std::sync::Arc<AtomicUsize>,
    }

    fn spawn_fake_github(
        mut respond: impl FnMut(usize, &str) -> (u16, String) + Send + 'static,
    ) -> FakeGitHub {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let requests = std::sync::Arc::new(AtomicUsize::new(0));
        let requests_clone = requests.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut buf = [0u8; 8192];
                let n = match stream.read(&mut buf) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("")
                    .to_string();
                let call_index = requests_clone.fetch_add(1, Ordering::SeqCst);
                let (status, body) = respond(call_index, &path);
                let status_text = match status {
                    201 => "Created",
                    401 => "Unauthorized",
                    403 => "Forbidden",
                    _ => "OK",
                };
                let resp = format!(
                    "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(body.as_bytes());
            }
        });
        FakeGitHub { addr, requests }
    }

    fn client(server: &FakeGitHub) -> GitHubAppClient<UreqClient> {
        GitHubAppClient::new("123", "456", &test_pem(), UreqClient::default())
            .unwrap()
            .with_api_base(format!("http://{}", server.addr))
    }

    #[test]
    fn mints_and_caches_token() {
        let server = spawn_fake_github(|_, _| {
            (
                201,
                r#"{"token":"ghs_abc","expires_at":"2099-01-01T00:00:00Z"}"#.to_string(),
            )
        });
        let app = client(&server);
        let t1 = app.installation_token().unwrap();
        let t2 = app.installation_token().unwrap();
        assert_eq!(t1, "ghs_abc");
        assert_eq!(t2, "ghs_abc");
        // Second call used the cache: only one HTTP round trip.
        assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn token_provider_impl_delegates_to_installation_token() {
        let server = spawn_fake_github(|_, _| {
            (
                201,
                r#"{"token":"ghs_xyz","expires_at":"2099-01-01T00:00:00Z"}"#.to_string(),
            )
        });
        let app = client(&server);
        let provider: &dyn TokenProvider = &app;
        assert_eq!(provider.token().unwrap(), "ghs_xyz");
    }

    #[test]
    fn refreshes_within_five_minutes_of_expiry() {
        // First response expires in 4 minutes (inside the 5-minute
        // refresh skew), second response is far in the future.
        let server = spawn_fake_github(|call, _| {
            if call == 0 {
                (
                    201,
                    r#"{"token":"ghs_soon","expires_at":"2099-01-01T00:04:00Z"}"#.to_string(),
                )
            } else {
                (
                    201,
                    r#"{"token":"ghs_fresh","expires_at":"2099-02-01T00:00:00Z"}"#.to_string(),
                )
            }
        });
        // Freeze "now" to just before the fake expiry so the test does
        // not depend on wall-clock time.
        fn fixed_now() -> SystemTime {
            SystemTime::UNIX_EPOCH
                + Duration::from_secs(
                    OffsetDateTime::parse("2099-01-01T00:00:00Z", &Rfc3339)
                        .unwrap()
                        .unix_timestamp() as u64,
                )
        }
        let app = client(&server).with_clock(fixed_now);
        let t1 = app.installation_token().unwrap();
        assert_eq!(t1, "ghs_soon");
        // Still "now" (4 min < 5 min skew left): must remint, not reuse.
        let t2 = app.installation_token().unwrap();
        assert_eq!(t2, "ghs_fresh");
        assert_eq!(server.requests.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn does_not_refresh_when_well_within_expiry() {
        fn fixed_now() -> SystemTime {
            SystemTime::UNIX_EPOCH
                + Duration::from_secs(
                    OffsetDateTime::parse("2099-01-01T00:00:00Z", &Rfc3339)
                        .unwrap()
                        .unix_timestamp() as u64,
                )
        }
        let server = spawn_fake_github(|_, _| {
            (
                201,
                // Expires in one hour: well outside the 5-minute skew.
                r#"{"token":"ghs_hour","expires_at":"2099-01-01T01:00:00Z"}"#.to_string(),
            )
        });
        let app = client(&server).with_clock(fixed_now);
        for _ in 0..5 {
            assert_eq!(app.installation_token().unwrap(), "ghs_hour");
        }
        assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn non_2xx_is_a_clear_error_not_a_panic() {
        let server =
            spawn_fake_github(|_, _| (401, r#"{"message":"Bad credentials"}"#.to_string()));
        let app = client(&server);
        let err = app.installation_token().unwrap_err();
        match err {
            GitHubAppError::Api { status, body } => {
                assert_eq!(status, 401);
                assert!(body.contains("Bad credentials"));
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[test]
    fn unparseable_body_is_a_clear_error() {
        let server = spawn_fake_github(|_, _| (201, "not json".to_string()));
        let app = client(&server);
        assert!(matches!(
            app.installation_token().unwrap_err(),
            GitHubAppError::BadResponse(_)
        ));
    }

    #[test]
    fn request_carries_bearer_jwt_and_github_headers() {
        let seen_auth = std::sync::Arc::new(Mutex::new(String::new()));
        let seen_auth_clone = seen_auth.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            for line in req.lines() {
                if let Some(v) = line.strip_prefix("Authorization: ") {
                    *seen_auth_clone.lock().unwrap() = v.trim().to_string();
                }
            }
            let body = r#"{"token":"ghs_ok","expires_at":"2099-01-01T00:00:00Z"}"#;
            let resp = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(resp.as_bytes()).unwrap();
            stream.write_all(body.as_bytes()).unwrap();
        });
        let app = GitHubAppClient::new("99", "11", &test_pem(), UreqClient::default())
            .unwrap()
            .with_api_base(format!("http://{addr}"));
        app.installation_token().unwrap();
        let auth = seen_auth.lock().unwrap().clone();
        assert!(auth.starts_with("Bearer "));
        // Three JWT segments after "Bearer ".
        assert_eq!(auth.trim_start_matches("Bearer ").split('.').count(), 3);
    }

    #[test]
    fn bad_pem_is_rejected_at_construction() {
        let err = match GitHubAppClient::new("1", "2", "garbage", UreqClient::default()) {
            Err(e) => e,
            Ok(_) => panic!("expected a bad-key error"),
        };
        assert!(matches!(err, GitHubAppError::BadKey(_)));
    }
}
