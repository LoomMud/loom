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

pub mod issues;
pub mod jwt;
pub mod pulls;
pub mod tls_transport;
pub mod transport;

/// The fake HTTP **reader**: how a fake reads one complete request and how it
/// answers one (OBI-350).
#[cfg(test)]
pub(crate) mod fake_http;
/// The fake HTTP **server**: who reads and answers, one connection per thread,
/// and no accepted connection left unanswered (OBI-351).
#[cfg(test)]
pub(crate) mod fake_server;

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use ring::signature::RsaKeyPair;
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub use tls_transport::RustlsHttpClient;
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

pub(super) fn truncate_body(body: &[u8]) -> String {
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

pub struct GitHubAppClient<C: HttpClient = RustlsHttpClient> {
    app_id: String,
    installation_id: String,
    private_key: RsaKeyPair,
    /// `https://api.github.com` in production; a loopback fake server in
    /// tests.
    api_base: String,
    transport: C,
    cache: Mutex<Option<CachedToken>>,
    now: fn() -> SystemTime,
}

impl GitHubAppClient<RustlsHttpClient> {
    /// Reads the PEM from `path` (e.g. `/run/secrets/warp_app.pem`,
    /// D-B3.11) once at construction. The key never touches the VFS or
    /// any other persistence after this. Uses [`RustlsHttpClient`] (TLS,
    /// OBI-215) to actually reach `https://api.github.com` -- this is
    /// the production constructor, not the test seam.
    pub fn from_pem_file(
        app_id: impl Into<String>,
        installation_id: impl Into<String>,
        pem_path: &std::path::Path,
    ) -> Result<Self, GitHubAppError> {
        let pem = std::fs::read_to_string(pem_path)
            .map_err(|e| GitHubAppError::BadKey(format!("reading {pem_path:?}: {e}")))?;
        Self::new(app_id, installation_id, &pem, RustlsHttpClient::default())
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

    pub(super) fn transport(&self) -> &C {
        &self.transport
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
    use std::net::TcpStream;
    use std::sync::Arc;
    use std::sync::mpsc;

    // Shared throwaway test fixture (see `jwt`'s test module docs): not a
    // real GitHub App key, just something `load_private_key` accepts.
    fn test_pem() -> String {
        include_str!("testdata/test_key.pkcs8.pem").to_string()
    }

    /// The test's fake GitHub: `fake_server`'s per-connection fake, answering
    /// whatever this test said it would.
    ///
    /// OBI-351 retired the hand-rolled accept loop that lived here. It served
    /// one connection at a time and, when a read failed, answered that
    /// connection with *nothing* (`Err(_) => continue`): the client's socket
    /// closed, `ureq` reported an io error, `GitHubAppClient` mapped any io
    /// error to [`GitHubAppError::Transport`], and a test about *response
    /// parsing* went red as if parsing were broken. The wrapper stays because
    /// these tests assert on the harness's own record of what it served.
    struct FakeGitHub {
        server: fake_server::FakeHttpServer,
    }

    impl FakeGitHub {
        fn addr(&self) -> &str {
            self.server.addr()
        }

        /// The full text of every request the fake served, in the order it
        /// served them -- headers *and* body, because each was read by
        /// [`fake_http::read_request`].
        fn served_requests(&self) -> Vec<String> {
            self.server.served_requests()
        }

        /// How many requests reached the handler. Replaces the counter this
        /// module used to keep by hand, which its serial accept loop could only
        /// ever fill one connection at a time.
        fn request_count(&self) -> usize {
            self.server.request_count()
        }

        /// Connections the fake accepted and could not serve as GitHub
        /// requests, each with the reason. Always empty in a healthy run.
        fn dropped_connections(&self) -> Vec<fake_server::DropRecord> {
            self.server.dropped_connections()
        }

        /// Assert the fake answered every connection it accepted. A test that
        /// fails here found a harness bug; one that fails anywhere else found a
        /// product one.
        fn assert_healthy(&self) {
            self.server.assert_healthy();
        }
    }

    /// Spawn a fake whose `respond` decides each answer from the call number
    /// and the request path.
    fn spawn_fake_github(
        respond: impl Fn(usize, &str) -> (u16, String) + Send + Sync + 'static,
    ) -> FakeGitHub {
        FakeGitHub {
            server: fake_server::FakeHttpServer::spawn(
                move |call: usize, request: fake_http::FakeRequest| respond(call, &request.path),
            ),
        }
    }

    fn client(server: &FakeGitHub) -> GitHubAppClient<UreqClient> {
        // The fake is real HTTP/1.1, so every header parse, body read and JSON
        // decode below is the *production* code path. The transport gets the
        // harness budget rather than the product's 10 s: the fake has already
        // been proven to answer (the readiness barrier in
        // `fake_server::FakeHttpServer::spawn`), so what is left of the budget
        // is for the call under test, not for waiting the harness into
        // existence (OBI-351).
        GitHubAppClient::new("123", "456", &test_pem(), fake_server::test_transport())
            .unwrap()
            .with_api_base(format!("http://{}", server.addr()))
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
        assert_eq!(server.request_count(), 1);
        server.assert_healthy();
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
        assert_eq!(server.request_count(), 2);
        server.assert_healthy();
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
        assert_eq!(server.request_count(), 1);
        server.assert_healthy();
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
        let err = app.installation_token().unwrap_err();
        // Loud on purpose, and the harness is part of the report. This used to
        // be `assert!(matches!(...))`, which swallowed *whatever* came back --
        // so when the old serial fake dropped the connection, the run said
        // "not a BadResponse" about a test that had proved the parser worked,
        // and the actual `Transport` error was never shown (OBI-351).
        match err {
            // The body was unparseable and the status was 2xx: the only way to
            // this variant is a response the fake really did send.
            GitHubAppError::BadResponse(message) => {
                assert!(!message.is_empty(), "a parse failure always says why");
            }
            other => panic!(
                "expected BadResponse for an unparseable 201 body, got {other:?}; the fake served \
                 {:?} and dropped {:?}",
                server.served_requests(),
                server.dropped_connections()
            ),
        }
        assert_eq!(
            server.request_count(),
            1,
            "the request under test must have reached the fake"
        );
        server.assert_healthy();
    }

    /// The product-level form of the OBI-351 flake: two connections open
    /// against one fake, and the one the client measures must be answered no
    /// matter what the other is doing.
    ///
    /// Under the old serial accept loop the parked connection held the whole
    /// fake, so the client's POST either waited out its absolute 10 s budget or
    /// was closed without an answer -- both of which `GitHubAppClient` reports
    /// as `Transport`. Nothing here sleeps against a timeout: the test waits for
    /// the fake to *report* that it is holding the first connection, then asks
    /// the client a question it can only answer if connections are served
    /// concurrently.
    #[test]
    fn an_installation_token_is_minted_while_another_connection_is_held() {
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let gate = Arc::new(fake_server::Gate::default());
        let held_by_handler = gate.clone();
        let server = spawn_fake_github(move |call, path| {
            if path == "/held" {
                let _ = entered_tx.send(());
                held_by_handler.wait_for_open();
                return (204, String::new());
            }
            let _ = (call,);
            (
                201,
                r#"{"token":"ghs_concurrent","expires_at":"2099-01-01T00:00:00Z"}"#.to_string(),
            )
        });
        let app = client(&server);

        let mut parked = TcpStream::connect(server.addr()).unwrap();
        parked
            .set_read_timeout(Some(fake_server::CLIENT_PATIENCE))
            .unwrap();
        parked
            .write_all(fake_server::get_request("/held").as_bytes())
            .unwrap();
        parked.flush().unwrap();
        entered_rx
            .recv_timeout(fake_server::HOLD_RENDEZVOUS)
            .expect("the fake never started serving the connection it accepted");

        // The measured call, while that connection is still parked.
        let token = app
            .installation_token()
            .expect("a held connection must not stop the fake from answering");
        assert_eq!(token, "ghs_concurrent");

        gate.open();
        let mut held_response = String::new();
        parked.read_to_string(&mut held_response).unwrap();
        assert!(
            held_response.contains("204"),
            "the held connection should get its answer on release: {held_response:?}"
        );
        assert_eq!(
            server.request_count(),
            2,
            "the client's mint and the parked request are two served requests"
        );
        server.assert_healthy();
    }

    /// Deterministic reproduction of the CI-only `unparseable_body` flake
    /// (OBI-350): a POST whose headers and body leave the client as two
    /// TCP segments must be served as **one** request.
    ///
    /// A fake that does a single `read()` per connection sees only the
    /// first segment, answers from it, and leaves the body unread in its
    /// own receive queue. Unread data at close time is what makes the
    /// kernel answer the client's FIN with a RST -- `ureq` surfaces that
    /// as an io error, and `GitHubAppClient` maps any io error to
    /// [`GitHubAppError::Transport`], which is why the flake reported a
    /// connection failure for a test that was only ever trying to prove a
    /// *payload* failure. Reading the complete request before answering
    /// is what retires that class.
    #[test]
    fn fake_serves_a_request_that_arrives_in_two_segments() {
        let server = spawn_fake_github(|_, _| {
            (
                201,
                r#"{"token":"ghs_segmented","expires_at":"2099-01-01T00:00:00Z"}"#.to_string(),
            )
        });
        let mut stream = TcpStream::connect(server.addr()).unwrap();
        // `TCP_NODELAY` keeps the two writes in two segments (no Nagle
        // coalescing), and the read bound means a fake that never finishes
        // the exchange fails the assertions below instead of hanging CI.
        stream.set_nodelay(true).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        const HEADERS: &str = "POST /app/installations/456/access_tokens HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Authorization: Bearer header.segment.body\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 2\r\n\
             \r\n";
        stream.write_all(HEADERS.as_bytes()).unwrap();
        stream.flush().unwrap();
        // Let the fake take the first segment. With the read-once fake
        // this is exactly the moment it answered and stopped reading.
        std::thread::sleep(Duration::from_millis(150));
        let body_written = stream.write_all(b"{}");

        let mut response = String::new();
        let response_read = stream.read_to_string(&mut response);

        // 1. The fake must have served the *whole* request, body included.
        let served = server.served_requests();
        assert_eq!(
            served.len(),
            1,
            "the fake should have served exactly one request"
        );
        assert!(
            served[0].ends_with("\r\n\r\n{}"),
            "the fake served a truncated request (the body was lost): {:?}",
            served[0]
        );
        // 2. ... and the client must have got a clean response, not a
        //    reset: that is the `Transport` error the flake showed up as.
        body_written.expect("the second segment must not land on a closing socket");
        response_read.expect("reading the full response must not fail");
        assert!(
            response.contains("201 Created"),
            "response was {response:?}"
        );
        assert!(
            response.contains(r#""token":"ghs_segmented""#),
            "response was {response:?}"
        );
        server.assert_healthy();
    }

    #[test]
    fn request_carries_bearer_jwt_and_github_headers() {
        let server = spawn_fake_github(|_, _| {
            (
                201,
                r#"{"token":"ghs_ok","expires_at":"2099-01-01T00:00:00Z"}"#.to_string(),
            )
        });
        let app = GitHubAppClient::new("99", "11", &test_pem(), fake_server::test_transport())
            .unwrap()
            .with_api_base(format!("http://{}", server.addr()));
        app.installation_token().unwrap();

        // The shared fake records the request it served, so this test gets
        // the whole exchange -- headers *and* body -- instead of whatever
        // one `read()` happened to return.
        let served = server.served_requests();
        assert_eq!(served.len(), 1, "expected one served request");
        let request = &served[0];
        let header = |name: &str| {
            request.lines().skip(1).find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.trim()
                    .eq_ignore_ascii_case(name)
                    .then(|| value.trim().to_string())
            })
        };

        assert_eq!(
            request.lines().next().unwrap_or(""),
            "POST /app/installations/11/access_tokens HTTP/1.1"
        );
        let auth = header("Authorization").expect("no Authorization header");
        assert!(auth.starts_with("Bearer "));
        // Three JWT segments after "Bearer ".
        assert_eq!(auth.trim_start_matches("Bearer ").split('.').count(), 3);
        // The GitHub API headers `UreqClient::post` is named for.
        assert_eq!(
            header("Accept").as_deref(),
            Some("application/vnd.github+json")
        );
        assert_eq!(
            header("X-GitHub-Api-Version").as_deref(),
            Some("2022-11-28")
        );
        assert_eq!(header("Content-Type").as_deref(), Some("application/json"));
        // And the body the mint posts. A fake that lost it to a truncated
        // read (OBI-350) would show up here as an empty body.
        assert_eq!(request.split_once("\r\n\r\n").unwrap().1, "{}");
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
