// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `loom`'s axum HTTP server (§8/§9). Owner: Legolas.
//!
//! Routes:
//! - `/ws` (OBI-39): a browser session gets the same seam as telnet
//!   (`loom_net::NetEvent`/`NetCommand`).
//! - `/lsp` (OBI-180, `lsp.rs`): the production WebSocket bridge to
//!   `loom-lsp`'s protocol core, gated by an Origin allowlist and a
//!   D-TM4 single-use ticket from `POST /api/v1/ws-ticket` (M-LSP-1/
//!   M-LSP-4).
//! - `/healthz` (OBI-28/OBI-115): liveness -- "is the process up at
//!   all". Always `200 OK` once the axum server itself is serving
//!   requests; never consults readiness or any backend.
//! - `/readyz` (OBI-28/OBI-115): readiness -- `200 OK` once
//!   `HttpState`'s [`loom_obs::Readiness`] has been flipped by the world
//!   thread (mudlib compiled, DB backend reachable), `503` before that.
//! - `/metrics` (OBI-28/OBI-115): renders `HttpState`'s
//!   [`loom_obs::PrometheusMetrics`] as Prometheus text exposition
//!   format.
//! - fallback (OBI-158): when `HttpState`'s `web_root` is set, serves the
//!   built `web-client/` (`index.html` and its `dist/` bundle) as the
//!   router fallback -- explicit routes above always win, so this can
//!   never shadow `/ws`, `/healthz`, `/readyz`, or `/metrics`. With no
//!   `web_root` (the default -- see `LOOM_WEB_ROOT` in `loom-cli`), the
//!   fallback is a plain `404`, matching pre-OBI-158 behaviour for tests
//!   and local runs that don't set it.

use std::path::PathBuf;

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{WebSocket, WebSocketUpgrade};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use loom_obs::{PrometheusMetrics, Readiness};
use tokio::sync::mpsc;
use tower_http::services::ServeDir;
// `ServeFileSystemResponseBody` is `ServeDir`'s response body type, reached
// through `services::fs` (only `ServeDir`/`ServeFile` are re-exported from
// `services` itself).
use tower_http::services::fs::ServeFileSystemResponseBody;
use tracing::debug;

mod admin;
pub mod admin_query;
pub mod auth;
mod client_ip;
pub mod files;
mod handlers;
mod lsp;
pub mod webhook;

pub use handlers::auth_router;

/// Shared state for `loom-http`'s routes.
#[derive(Clone)]
pub struct HttpState {
    ws_accept_tx: mpsc::Sender<WebSocket>,
    readiness: Readiness,
    metrics: PrometheusMetrics,
    web_root: Option<PathBuf>,
    auth: Option<auth::AuthService>,
    github: Option<std::sync::Arc<dyn auth::GithubIdentityProvider>>,
    /// The (non-secret) half of the GitHub OAuth app config (OBI-201):
    /// client id + exact redirect URI, which `/auth/github/start` needs
    /// to build the authorize URL. `Some` iff [`Self::with_github`] was
    /// called.
    github_login: Option<auth::GithubLoginConfig>,
    /// M-AUTH-6: the exact `Origin` values `/auth/refresh` and
    /// `/auth/logout` accept (no CORS for anything else). Empty by
    /// default, which refuses every cookie-bearing request -- an
    /// operator who wants those routes reachable from a browser must set
    /// `LOOM_STAFF_ORIGINS` themselves (see `loom-cli`).
    staff_origins: Vec<String>,
    github_webhook: Option<webhook::GithubWebhookConfig>,
    file_op_tx: Option<files::FileOpSender>,
    write_rate_limiter: files::WriteRateLimiter,
    world_query: Option<std::sync::Arc<dyn admin_query::WorldAdminQuery>>,
    /// M-LSP-4's session caps for `/lsp` (OBI-180) -- always present
    /// (unlike `file_op_tx`'s `Option`), since an empty limiter still
    /// correctly allows sessions right up to the cap; the route itself
    /// answers `503` before ever touching this if no file-op channel is
    /// wired.
    lsp_sessions: lsp::SessionLimiter,
    /// Test-only override for `/lsp`'s timing constants (idle timeout,
    /// ping interval, first-frame timeout, revocation-recheck interval)
    /// -- `None` uses the real spec values (M-LSP-1/M-LSP-4). Set via
    /// [`Self::with_lsp_tuning_for_test`], never by `loom-cli`.
    lsp_tuning: lsp::LspTuning,
}

impl HttpState {
    pub fn new(
        ws_accept_tx: mpsc::Sender<WebSocket>,
        readiness: Readiness,
        metrics: PrometheusMetrics,
    ) -> Self {
        Self {
            ws_accept_tx,
            readiness,
            metrics,
            web_root: None,
            auth: None,
            github: None,
            github_login: None,
            staff_origins: Vec::new(),
            github_webhook: None,
            file_op_tx: None,
            write_rate_limiter: files::new_write_rate_limiter(),
            world_query: None,
            lsp_sessions: lsp::SessionLimiter::default(),
            lsp_tuning: lsp::LspTuning::default(),
        }
    }

    /// Serve the built web client (index.html + dist/) from `root` as the
    /// router fallback (OBI-158). Unset by default -- see `LOOM_WEB_ROOT`.
    pub fn with_web_root(mut self, root: PathBuf) -> Self {
        self.web_root = Some(root);
        self
    }

    /// Mount `/auth/*` (OBI-174): staff login, refresh, logout, TOTP
    /// enrolment/verification. Unset by default -- `loom-cli` only calls
    /// this when Postgres (`LOOM_DATABASE_URL`) and a JWT secret
    /// (`LOOM_JWT_KEY_FILE`) are both configured.
    pub fn with_auth(mut self, auth: auth::AuthService) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Mount `/auth/github/*` (OBI-174/OBI-201, optional): the real
    /// authorization-code + PKCE flow. Unset by default; requires
    /// [`Self::with_auth`] to also be set, since GitHub login still goes
    /// through the same `AuthService`. `login_config` is the non-secret
    /// half (client id + exact redirect URI) `/auth/github/start` needs
    /// to build the authorize URL.
    pub fn with_github(
        mut self,
        github: std::sync::Arc<dyn auth::GithubIdentityProvider>,
        login_config: auth::GithubLoginConfig,
    ) -> Self {
        self.github = Some(github);
        self.github_login = Some(login_config);
        self
    }

    /// Set the staff-origin allowlist (OBI-198, M-AUTH-6): the exact
    /// `Origin` values `/auth/refresh` and `/auth/logout` accept. Unset
    /// (empty) by default, which refuses both routes outright -- see
    /// `LOOM_STAFF_ORIGINS` in `loom-cli`.
    pub fn with_staff_origins(mut self, origins: Vec<String>) -> Self {
        self.staff_origins = origins;
        self
    }

    /// `Some` iff [`Self::with_auth`] was called -- shared by `handlers.rs`
    /// and `admin.rs` (OBI-185) for bearer-token extraction.
    pub(crate) fn auth_service(&self) -> Option<&auth::AuthService> {
        self.auth.as_ref()
    }

    /// Mount `POST /api/v1/hooks/github` (OBI-212, D-B3.12). Unset by
    /// default -- answers `503` until `loom-cli` configures a webhook
    /// secret and wires a `GitWorkerHandle`.
    pub fn with_github_webhook(mut self, config: webhook::GithubWebhookConfig) -> Self {
        self.github_webhook = Some(config);
        self
    }

    /// Mount `GET /api/v1/files/content` (OBI-180 M-FS-1). Unset by
    /// default -- answers `503` until `loom-cli` wires the world-thread
    /// file-op channel (see `files::file_op_channel`).
    pub fn with_file_ops(mut self, file_op_tx: files::FileOpSender) -> Self {
        self.file_op_tx = Some(file_op_tx);
        self
    }

    /// Wire the `who`/object-browser routes (OBI-234, P2-O2) to a real
    /// world-thread query channel. Unset by default -- those routes
    /// answer `503` (`AdminError::WorldUnavailable`) until `loom-cli`
    /// configures the world-side receiver (see `admin_query`'s module
    /// doc for the channel contract) and calls this.
    pub fn with_world_query(
        mut self,
        world_query: std::sync::Arc<dyn admin_query::WorldAdminQuery>,
    ) -> Self {
        self.world_query = Some(world_query);
        self
    }

    /// `Some` iff [`Self::with_world_query`] was called -- `admin.rs`'s
    /// `who`/`objects`/`objects/:path/vars` handlers.
    pub(crate) fn world_query(&self) -> Option<&dyn admin_query::WorldAdminQuery> {
        self.world_query.as_deref()
    }

    /// `lsp.rs`'s own accessors: `/lsp` reuses the M-FS-1 file-op channel
    /// and the M-AUTH-6 staff-origin allowlist exactly as `files.rs`/
    /// `handlers.rs` do, plus its own always-present session limiter.
    pub(crate) fn file_op_tx(&self) -> Option<&files::FileOpSender> {
        self.file_op_tx.as_ref()
    }

    pub(crate) fn staff_origins(&self) -> &[String] {
        &self.staff_origins
    }

    pub(crate) fn lsp_sessions(&self) -> &lsp::SessionLimiter {
        &self.lsp_sessions
    }

    pub(crate) fn lsp_tuning(&self) -> &lsp::LspTuning {
        &self.lsp_tuning
    }

    /// Shrink `/lsp`'s timing constants for a fast, deterministic test
    /// (idle timeout/ping interval/revocation-recheck interval all
    /// default to tens of seconds, far too slow for a test to wait out
    /// in real wall-clock time). Test-only -- `loom-cli` never calls
    /// this, so every real `/lsp` connection gets the spec's actual
    /// M-LSP-4 values.
    #[cfg(test)]
    pub(crate) fn with_lsp_tuning_for_test(mut self, tuning: lsp::LspTuning) -> Self {
        self.lsp_tuning = tuning;
        self
    }
}

/// The static bundle's response CSP (OBI-180 M-IDE-1, threat model v2
/// §5), sent by loom-http as a header so `frame-ancestors` actually
/// applies (it is ignored in `<meta>` per the CSP spec; `report-uri`
/// and `sandbox` are the other header-only directives).
///
/// This is the threat model's policy *verbatim*. Two directives look
/// looser than they need to be and are not optional:
///
/// * `style-src 'unsafe-inline'` -- Monaco injects inline `<style>` and
///   `style=` attributes for every measured text block; without it the
///   editor renders wrong. It is the one exception the threat model
///   grants explicitly ("'unsafe-inline' styles are only for Monaco").
///   Pages that don't need it tighten it back in their own `<meta>`
///   (`index.html`, `admin.html`), since a document bound by both a
///   header and a meta must satisfy *both*.
/// * `worker-src 'self' blob:` -- Monaco's language/ editor workers are
///   started from a same-origin blob URL. `blob:` is scoped to workers
///   only; scripts stay `'self'`.
///
/// `script-src 'self'` with no `'unsafe-inline'`/`'unsafe-eval'` is the
/// point of the whole policy: it is only safe to send because no served
/// file contains an inline script any more (OBI-180 moved
/// `index.html`'s bootstrap into `loom.css` + `dist/main.js`; the
/// `check-static-csp.mjs` gate in `npm run lint` keeps that true, per
/// O3-T6's "a CI-enforced test that no served static file contains an
/// inline script"). `connect-src 'self'` is deliberate and the one line
/// that could break a deployment: it means **same-origin `/ws` only**
/// (the player's `ws://`/`wss://` to this host's own port is covered --
/// CSP3 'self' matches the same host through the ws/wss upgrade), so a
/// future client connecting to a separate telnet or WS host must widen
/// this with an explicit host list rather than a wildcard.
const STATIC_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; worker-src 'self' blob:; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// The rest of M-IDE-1's static-bundle header set, as `(name, value)`
/// pairs so the policy stays one reviewable list. Values are all
/// literals, hence `from_static`.
///
/// * `X-Frame-Options: DENY` -- header-only fallback for UAs that
///   predate `frame-ancestors`.
/// * `X-Content-Type-Options: nosniff` -- a served `.txt`/`.js` is never
///   sniffed into something the CSP would then have to protect against.
/// * `Referrer-Policy: no-referrer` -- an admin/IDE URL *is* a domain
///   path (`/builders/<u>/<area>/...`, M-IDE-1/T-IDE-2), so it must not
///   leak to a third party through the Referer of a sub-resource.
/// * `Cross-Origin-Opener-Policy: same-origin` -- isolates this
///   document's browsing group, so a window opened by another origin
///   can't hold a handle on the staff session's window (M-IDE-1).
const STATIC_SECURITY_HEADERS: [(&str, &str); 4] = [
    ("x-frame-options", "DENY"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("cross-origin-opener-policy", "same-origin"),
];

/// Stamp [`STATIC_CSP`] + [`STATIC_SECURITY_HEADERS`] onto a response
/// from the static-file service (OBI-180/M-IDE-1). Applied by
/// [`app`]'s fallback chain, so it covers every path the file service
/// answers -- including a 404 for a missing file, which is harmless and
/// cheaper than path-sniffing -- and deliberately not on `/ws`,
/// `/metrics` or the API routes, which set their own per-response
/// headers (a file body served by `/api/v1/files/content` carries a
/// `sandbox; default-src 'none'` CSP of its own, M-FS-4). Only headers
/// change; the body and status pass through.
fn with_static_security_headers(
    mut response: axum::response::Response<ServeFileSystemResponseBody>,
) -> axum::response::Response<ServeFileSystemResponseBody> {
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(STATIC_CSP),
    );
    for (name, value) in STATIC_SECURITY_HEADERS {
        headers.insert(
            header::HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    response
}

pub fn app(state: HttpState) -> Router {
    let web_root = state.web_root.clone();
    let router = Router::new()
        .route("/ws", get(ws_handler))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .merge(handlers::auth_router())
        .merge(admin::admin_router())
        .merge(webhook::webhook_router())
        .merge(files::files_router())
        .merge(lsp::lsp_router())
        .with_state(state);
    match web_root {
        Some(root) => {
            // The qualified `ServiceExt` call is load-bearing, not ceremony:
            // `ServeDir` serves *any* request body, and `map_response` adds a
            // second free type parameter for the response, so the plain
            // method-call form leaves the request body ambiguous and the crate
            // does not compile (E0283). Naming the request here says exactly
            // what the router's fallback will send -- `axum::extract::Request`
            // -- and lets the response type be inferred from
            // [`with_static_security_headers`]'s signature.
            let static_files =
                <ServeDir as tower::ServiceExt<axum::extract::Request>>::map_response(
                    ServeDir::new(root),
                    with_static_security_headers,
                );
            router.fallback_service(static_files)
        }
        None => router,
    }
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<HttpState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| async move {
        if state.ws_accept_tx.send(socket).await.is_err() {
            debug!("dropped websocket upgrade: net server is not accepting connections");
        }
    })
}

async fn healthz() -> impl IntoResponse {
    StatusCode::OK
}

async fn readyz(State(state): State<HttpState>) -> impl IntoResponse {
    if state.readiness.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn metrics(State(state): State<HttpState>) -> impl IntoResponse {
    state.metrics.render()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;

    use futures_util::{SinkExt, StreamExt};
    use http_body_util::BodyExt;
    use loom_net::{NetCommand, NetConfig, NetEvent};
    use serde_json::json;
    use tokio::net::TcpListener as TokioTcpListener;
    use tokio_tungstenite::tungstenite::Message as ClientMessage;
    use tower::ServiceExt;

    async fn spawn_test_server() -> (
        SocketAddr,
        mpsc::Sender<NetCommand>,
        mpsc::Receiver<NetEvent>,
        tokio::sync::watch::Sender<bool>,
    ) {
        let http_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();

        let (ws_accept_tx, ws_accept_rx) = mpsc::channel(16);
        let state = HttpState::new(
            ws_accept_tx,
            Readiness::new(),
            PrometheusMetrics::new_unregistered(),
        );
        let app = app(state);
        tokio::spawn(async move {
            axum::serve(http_listener, app).await.unwrap();
        });

        // A bound-but-unused telnet listener: `run_server_with_ws` still
        // wants one, but nothing in these tests dials it.
        let telnet_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();

        let (event_tx, event_rx) = mpsc::channel(256);
        let (command_tx, command_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        tokio::spawn(loom_net::run_server_with_ws(
            telnet_listener,
            NetConfig::default(),
            event_tx,
            command_rx,
            shutdown_rx,
            ws_accept_rx,
        ));

        (http_addr, command_tx, event_rx, shutdown_tx)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ws_line_round_trips_through_net_event_and_command() {
        let (addr, command_tx, mut event_rx, _shutdown_tx) = spawn_test_server().await;

        let url = format!("ws://{addr}/ws");
        let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();

        ws.send(ClientMessage::Text(
            json!({"type": "line", "text": "look"}).to_string().into(),
        ))
        .await
        .unwrap();

        let conn_id = loop {
            match event_rx.recv().await.unwrap() {
                NetEvent::Connected(id) => {
                    let _ = id;
                }
                NetEvent::Line(id, text) => {
                    assert_eq!(text, "look");
                    break id;
                }
                other => panic!("unexpected event: {other:?}"),
            }
        };

        command_tx
            .send(NetCommand::Send(conn_id, "A Room\n".to_string()))
            .await
            .unwrap();

        let reply = ws.next().await.unwrap().unwrap();
        let ClientMessage::Text(text) = reply else {
            panic!("expected a text frame, got {reply:?}");
        };
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["type"], "line");
        assert_eq!(parsed["text"], "A Room\n");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ws_gmcp_round_trips_as_json() {
        let (addr, command_tx, mut event_rx, _shutdown_tx) = spawn_test_server().await;

        let url = format!("ws://{addr}/ws");
        let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();

        ws.send(ClientMessage::Text(
            json!({"type": "gmcp", "package": "Core.Hello", "payload": {"client": "web", "version": "1"}})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();

        let conn_id = loop {
            match event_rx.recv().await.unwrap() {
                NetEvent::Connected(id) => {
                    let _ = id;
                }
                NetEvent::Gmcp(id, msg) => {
                    assert_eq!(
                        msg,
                        loom_net::GmcpMessage::CoreHello {
                            client: "web".to_string(),
                            version: "1".to_string(),
                        }
                    );
                    break id;
                }
                other => panic!("unexpected event: {other:?}"),
            }
        };

        command_tx
            .send(NetCommand::SendGmcp(
                conn_id,
                "Char.Vitals".to_string(),
                json!({"hp": 10}),
            ))
            .await
            .unwrap();

        let reply = ws.next().await.unwrap().unwrap();
        let ClientMessage::Text(text) = reply else {
            panic!("expected a text frame, got {reply:?}");
        };
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["type"], "gmcp");
        assert_eq!(parsed["package"], "Char.Vitals");
        assert_eq!(parsed["payload"]["hp"], 10);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_ws_reader_is_dropped_without_affecting_a_fast_one() {
        let http_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();
        let (ws_accept_tx, ws_accept_rx) = mpsc::channel(16);
        let state = HttpState::new(
            ws_accept_tx,
            Readiness::new(),
            PrometheusMetrics::new_unregistered(),
        );
        let app = app(state);
        tokio::spawn(async move {
            axum::serve(http_listener, app).await.unwrap();
        });

        let telnet_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(256);
        let (command_tx, command_rx) = mpsc::channel(256);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(loom_net::run_server_with_ws(
            telnet_listener,
            NetConfig {
                output_queue_depth: 1,
                ..NetConfig::default()
            },
            event_tx,
            command_rx,
            shutdown_rx,
            ws_accept_rx,
        ));

        let url = format!("ws://{http_addr}/ws");
        let (mut slow, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        let (mut fast, _) = tokio_tungstenite::connect_async(&url).await.unwrap();

        slow.send(ClientMessage::Text(
            json!({"type": "line", "text": "slow"}).to_string().into(),
        ))
        .await
        .unwrap();
        fast.send(ClientMessage::Text(
            json!({"type": "line", "text": "fast"}).to_string().into(),
        ))
        .await
        .unwrap();

        let mut slow_conn = None;
        let mut saw_slow_disconnect = false;
        let mut replied_fast = false;

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while !(saw_slow_disconnect && replied_fast) {
            let event = tokio::time::timeout_at(deadline, event_rx.recv())
                .await
                .expect("timed out waiting for slow disconnect / fast reply")
                .expect("event channel closed");
            match event {
                NetEvent::Connected(_) => {}
                NetEvent::Line(id, line) => {
                    if line == "slow" {
                        slow_conn = Some(id);
                        for i in 0..200 {
                            let _ = command_tx
                                .send(NetCommand::Send(id, format!("spam-{i}\n")))
                                .await;
                        }
                    } else if line == "fast" {
                        let _ = command_tx
                            .send(NetCommand::Send(id, "ok\n".to_string()))
                            .await;
                        replied_fast = true;
                    }
                }
                NetEvent::Disconnected(id) => {
                    if Some(id) == slow_conn {
                        saw_slow_disconnect = true;
                    }
                }
                other => panic!("unexpected event: {other:?}"),
            }
        }

        assert!(saw_slow_disconnect, "slow WS client was never dropped");

        // The fast client keeps getting served: read frames until we see
        // the "ok" reply (there may be a stray earlier frame in flight).
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let msg = tokio::time::timeout_at(deadline, fast.next())
                .await
                .expect("timed out waiting for fast client reply")
                .expect("fast client stream ended")
                .unwrap();
            let ClientMessage::Text(text) = msg else {
                continue;
            };
            let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
            if parsed["type"] == "line" && parsed["text"] == "ok\n" {
                break;
            }
        }

        // Draining the slow socket eventually surfaces the server-initiated
        // close (or the read simply erroring once the TCP connection is
        // torn down) -- either way confirms it was actually dropped, not
        // just stalled.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), slow.next()).await;
    }

    /// Copyover, old-process side (OBI-184/OBI-227 review): a WebSocket
    /// session has no raw-fd story, so `loom_net::ws`'s `Reclaim` handler
    /// must answer `None` *and* actually end the session -- not leave a
    /// zombie task that the registry no longer routes commands to but
    /// that keeps reading the client's frames and emitting `NetEvent`s
    /// for a `conn_id` nothing tracks anymore. Drives a real
    /// `axum`-upgraded WS connection (not a bare `TcpStream`, unlike
    /// `loom-net`'s own reclaim test) through `run_server_full`'s
    /// `reclaim_rx` directly, since `run_server_with_ws` doesn't expose
    /// it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ws_reclaim_answers_none_and_ends_the_session() {
        let http_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();
        let (ws_accept_tx, ws_accept_rx) = mpsc::channel(16);
        let state = HttpState::new(
            ws_accept_tx,
            Readiness::new(),
            PrometheusMetrics::new_unregistered(),
        );
        let app = app(state);
        tokio::spawn(async move {
            axum::serve(http_listener, app).await.unwrap();
        });

        let telnet_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(256);
        let (_command_tx, command_rx) = mpsc::channel(256);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (_adopt_tx, adopt_rx) = mpsc::channel(1);
        let (reclaim_tx, reclaim_rx) = mpsc::channel(4);
        tokio::spawn(loom_net::run_server_full(
            telnet_listener,
            NetConfig::default(),
            event_tx,
            command_rx,
            shutdown_rx,
            ws_accept_rx,
            adopt_rx,
            reclaim_rx,
        ));

        let url = format!("ws://{http_addr}/ws");
        let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();

        ws.send(ClientMessage::Text(
            json!({"type": "line", "text": "hi"}).to_string().into(),
        ))
        .await
        .unwrap();

        let conn_id = loop {
            match event_rx.recv().await.unwrap() {
                NetEvent::Connected(_) => {}
                NetEvent::Line(id, text) => {
                    assert_eq!(text, "hi");
                    break id;
                }
                other => panic!("unexpected event: {other:?}"),
            }
        };

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        reclaim_tx.send((conn_id, reply_tx)).await.unwrap();
        let reclaimed = tokio::time::timeout(std::time::Duration::from_secs(5), reply_rx)
            .await
            .expect("WS reclaim must answer promptly, not hang")
            .expect("reclaim reply channel dropped");
        assert!(
            reclaimed.is_none(),
            "a WS connection has no raw fd to hand off -- reclaim must answer None"
        );

        // Not a zombie: the session actually ends -- the client sees its
        // socket close, and the registry still reports a real disconnect
        // (so a bound object's `net_dead()` still runs; this session does
        // not survive the copyover).
        let closed = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
            .await
            .expect("client should observe the server closing the socket");
        assert!(
            matches!(closed, Some(Ok(ClientMessage::Close(_))) | None),
            "expected the server to close the WS session after an unsupported reclaim, got {closed:?}"
        );

        let disconnect_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let event = tokio::time::timeout_at(disconnect_deadline, event_rx.recv())
                .await
                .expect("timed out waiting for the post-reclaim Disconnected event")
                .expect("event channel closed");
            if let NetEvent::Disconnected(id) = event {
                assert_eq!(id, conn_id);
                break;
            }
        }
    }

    async fn spawn_health_test_server() -> Router {
        let (ws_accept_tx, _ws_accept_rx) = mpsc::channel(16);
        let readiness = Readiness::new();
        let state = HttpState::new(
            ws_accept_tx,
            readiness,
            PrometheusMetrics::new_unregistered(),
        );
        app(state)
    }

    #[tokio::test]
    async fn healthz_is_always_ok() {
        let app = spawn_health_test_server().await;
        let request = axum::http::Request::builder()
            .uri("/healthz")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_reflects_readiness_gate() {
        let (ws_accept_tx, _ws_accept_rx) = mpsc::channel(16);
        let readiness = Readiness::new();
        let state = HttpState::new(
            ws_accept_tx,
            readiness.clone(),
            PrometheusMetrics::new_unregistered(),
        );
        let app = app(state);

        let request = axum::http::Request::builder()
            .uri("/readyz")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        readiness.set_ready();
        let request = axum::http::Request::builder()
            .uri("/readyz")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_renders_prometheus_text() {
        let app = spawn_health_test_server().await;
        let request = axum::http::Request::builder()
            .uri("/metrics")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // An empty recorder still renders valid (if empty) exposition
        // text -- just check the route wires through to `render()`
        // without error.
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _ = String::from_utf8(body.to_vec()).unwrap();
    }

    #[tokio::test]
    async fn root_is_404_without_a_web_root() {
        let app = spawn_health_test_server().await;
        let request = axum::http::Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        // No `LOOM_WEB_ROOT` set (`HttpState::new`'s default): unchanged
        // pre-OBI-158 behaviour for tests and local runs.
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn root_serves_index_html_with_a_web_root_set() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<html>loom</html>").unwrap();
        std::fs::create_dir(dir.path().join("dist")).unwrap();
        std::fs::write(dir.path().join("dist").join("app.js"), "export {};").unwrap();

        let (ws_accept_tx, _ws_accept_rx) = mpsc::channel(16);
        let state = HttpState::new(
            ws_accept_tx,
            Readiness::new(),
            PrometheusMetrics::new_unregistered(),
        )
        .with_web_root(dir.path().to_path_buf());
        let app = app(state);

        let request = axum::http::Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "<html>loom</html>".as_bytes());

        // A path inside the served tree (the built JS bundle) also comes
        // through the fallback, not just `/` itself.
        let request = axum::http::Request::builder()
            .uri("/dist/app.js")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Explicit routes still win over the fallback.
        let request = axum::http::Request::builder()
            .uri("/healthz")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn static_fallback_carries_the_m_ide_1_csp_and_header_set() {
        // OBI-294/OBI-180 M-IDE-1: `frame-ancestors` (and `report-uri`/
        // `sandbox`) are no-ops when delivered only via
        // `<meta http-equiv="Content-Security-Policy">` -- they take
        // effect as a response header alone. So the static fallback sends
        // the whole M-IDE-1 policy as headers, for every path under the
        // served tree -- not just the staff pages -- and each page's
        // `<meta>` stays as the belt-and-braces copy for whatever loom
        // -http is not in front of (a proxy serving the bundle directly).
        // Two policies on one document are both enforced, so a tighter
        // `<meta>` can only narrow what the header allows, never widen it.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<html>loom</html>").unwrap();
        std::fs::write(
            dir.path().join("admin.html"),
            "<html><!-- meta CSP lives here too --></html>",
        )
        .unwrap();

        let (ws_accept_tx, _ws_accept_rx) = mpsc::channel(16);
        let state = HttpState::new(
            ws_accept_tx,
            Readiness::new(),
            PrometheusMetrics::new_unregistered(),
        )
        .with_web_root(dir.path().to_path_buf());
        let app = app(state);

        for path in ["/", "/admin.html"] {
            let request = axum::http::Request::builder()
                .uri(path)
                .body(axum::body::Body::empty())
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "path: {path}");
            let csp = response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap_or_else(|| panic!("missing CSP header on {path}"))
                .to_str()
                .unwrap();
            assert_eq!(csp, STATIC_CSP, "path: {path}");
            assert!(
                csp.contains("frame-ancestors 'none'"),
                "frame-ancestors must ride in the header, not only the meta: {path}"
            );
            let xfo = response
                .headers()
                .get(header::HeaderName::from_static("x-frame-options"))
                .unwrap_or_else(|| panic!("missing X-Frame-Options header on {path}"))
                .to_str()
                .unwrap();
            assert_eq!(xfo, "DENY");
        }

        // Explicit (non-fallback) routes are untouched by the static-file
        // header stamping -- it only wraps the `ServeDir` fallback
        // service. `/healthz` must not pick up a document CSP.
        let request = axum::http::Request::builder()
            .uri("/healthz")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .is_none()
        );
    }

    /// A `script-src 'self'` with an escape hatch is the same as no
    /// script-src at all for a page that renders builder-authored text
    /// (M-IDE-2/T-IDE-1: a stored `<script>`-shaped string is only
    /// dangerous if the policy lets inline or remote script in). Pin the
    /// exact directive rather than grepping for substrings that could
    /// appear in another directive's source list.
    #[test]
    fn static_csp_grants_no_script_escape_hatch() {
        let script_src = csp_directive(STATIC_CSP, "script-src");
        assert_eq!(script_src, "'self'", "script-src must stay 'self' only");
        for forbidden in [
            "unsafe-inline",
            "unsafe-eval",
            "blob:",
            "data:",
            "*",
            "http",
        ] {
            assert!(
                !script_src.contains(forbidden),
                "script-src carries {forbidden:?}: {script_src}"
            );
        }
        // `default-src` is the fallback for every directive the policy
        // does not name, so it must not be looser than script-src either.
        assert_eq!(csp_directive(STATIC_CSP, "default-src"), "'self'");
        assert_eq!(csp_directive(STATIC_CSP, "object-src"), "'none'");
        assert_eq!(csp_directive(STATIC_CSP, "base-uri"), "'none'");
        assert_eq!(csp_directive(STATIC_CSP, "form-action"), "'self'");
    }

    /// The two `style-src`/`worker-src` exceptions are documented in
    /// `STATIC_CSP` as Monaco-only. Pin them so a future "tighten
    /// everything" change can't silently drop them (Monaco renders wrong
    /// without inline styles and starts its workers from a blob URL), and
    /// so the exceptions cannot spread to `script-src`.
    #[test]
    fn static_csp_keeps_the_monaco_exceptions_scoped_to_monaco() {
        assert_eq!(
            csp_directive(STATIC_CSP, "style-src"),
            "'self' 'unsafe-inline'"
        );
        assert_eq!(csp_directive(STATIC_CSP, "worker-src"), "'self' blob:");
        // `blob:` belongs to workers only: if it ever reached the script
        // or fetch directives, a same-origin blob could carry code. The
        // admin pages' `<meta>` is where the `style-src` exception is
        // narrowed back to `'self'` for pages that don't mount Monaco.
        for directive in ["script-src", "connect-src", "default-src"] {
            assert!(
                !csp_directive(STATIC_CSP, directive).contains("blob:"),
                "{directive} must not allow blob:"
            );
        }
    }

    /// `connect-src 'self'` is the directive that decides whether the
    /// player client can reach the driver at all: the WS is same-origin
    /// (`/ws`, `/lsp`), which CSP3's `ws`/`wss` upgrade matching covers,
    /// but a split client host would not be covered and would need an
    /// explicit host list here -- never a wildcard. Pinned so the
    /// constraint is visible at the point someone tries to widen it.
    #[test]
    fn static_csp_connect_src_is_same_origin_only() {
        assert_eq!(csp_directive(STATIC_CSP, "connect-src"), "'self'");
        assert!(
            !STATIC_CSP.contains("connect-src *") && !STATIC_CSP.contains("wss://*"),
            "a wildcard connect-src would let a compromised staff page exfiltrate to any host"
        );
    }

    #[tokio::test]
    async fn static_fallback_sends_nosniff_referrer_policy_and_coop() {
        // M-IDE-1's remaining three headers. `Referrer-Policy` matters
        // because the *path itself* is a domain path (T-IDE-2), and
        // `nosniff` because `/api/v1/files/content` serves raw builder
        // text -- the same reasoning as M-FS-4's per-response headers.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<html>loom</html>").unwrap();
        std::fs::write(dir.path().join("admin.html"), "<html>admin</html>").unwrap();
        std::fs::create_dir(dir.path().join("dist")).unwrap();
        std::fs::write(dir.path().join("dist/app.js"), "export {};\n").unwrap();
        let app = app_with_static_root(dir.path());

        for path in ["/", "/admin.html", "/dist/app.js", "/nope.html"] {
            let request = axum::http::Request::builder()
                .uri(path)
                .body(axum::body::Body::empty())
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            for (name, expected) in STATIC_SECURITY_HEADERS {
                let value = response
                    .headers()
                    .get(header::HeaderName::from_static(name))
                    .unwrap_or_else(|| panic!("missing {name} header on {path}"))
                    .to_str()
                    .unwrap();
                assert_eq!(value, expected, "{name} on {path}");
            }
            assert!(
                response
                    .headers()
                    .get(header::CONTENT_SECURITY_POLICY)
                    .is_some(),
                "missing CSP header on {path}"
            );
        }
    }

    /// The sources of one CSP directive, or `"<absent>"`. Matching is on
    /// the whole directive token (splitting on `;` and then on the first
    /// space) rather than `contains`, so `script-src` assertions can't be
    /// satisfied by `worker-src`'s or `style-src`'s source list.
    fn csp_directive(policy: &str, directive: &str) -> String {
        policy
            .split(';')
            .map(str::trim)
            .find_map(|part| {
                let (name, rest) = part.split_once(char::is_whitespace)?;
                (name == directive).then(|| rest.trim().to_owned())
            })
            .unwrap_or_else(|| format!("<{directive} absent>"))
    }

    /// `app` with a `web_root` pointing at `root` (the static-file path
    /// needs one; every other route is left at its default).
    fn app_with_static_root(root: &std::path::Path) -> Router {
        let (ws_accept_tx, _ws_accept_rx) = mpsc::channel(16);
        let state = HttpState::new(
            ws_accept_tx,
            Readiness::new(),
            PrometheusMetrics::new_unregistered(),
        )
        .with_web_root(root.to_path_buf());
        app(state)
    }
}
