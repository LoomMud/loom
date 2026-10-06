// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `loom`'s axum HTTP server (§8/§9). Owner: Legolas.
//!
//! Routes:
//! - `/ws` (OBI-39): a browser session gets the same seam as telnet
//!   (`loom_net::NetEvent`/`NetCommand`).
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
use tower::ServiceBuilder;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::debug;

mod admin;
pub mod admin_query;
pub mod auth;
mod client_ip;
pub mod files;
mod handlers;
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
    github_webhook: Option<webhook::GithubWebhookConfig>,
    file_op_tx: Option<files::FileOpSender>,
    write_rate_limiter: files::WriteRateLimiter,
    compile_in_flight: files::CompileInFlight,
    world_query: Option<std::sync::Arc<dyn admin_query::WorldAdminQuery>>,
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
            github_webhook: None,
            file_op_tx: None,
            write_rate_limiter: files::new_write_rate_limiter(),
            compile_in_flight: files::new_compile_in_flight(),
            world_query: None,
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

    /// Mount `/auth/github/callback` (OBI-174, optional). Unset by
    /// default; requires [`Self::with_auth`] to also be set, since GitHub
    /// login still goes through the same `AuthService`.
    pub fn with_github(mut self, github: std::sync::Arc<dyn auth::GithubIdentityProvider>) -> Self {
        self.github = Some(github);
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
}

/// M-IDE-1/M-IDE-2 (OBI-179 threat model) for the static web client
/// (`web-client/admin.html` and friends, OBI-294): `admin.html` already
/// carries this via a `<meta http-equiv="Content-Security-Policy">` tag,
/// but `frame-ancestors` (and `sandbox`/`report-uri`) are no-ops when
/// delivered that way per the CSP spec -- they only take effect as an
/// actual response header. A header and a `<meta>` tag can coexist
/// (browsers enforce the intersection), so the header carries *only*
/// the header-only directive: it wraps every file under the web root,
/// including the player client (`index.html`), which uses an inline
/// `<style>` and inline module `<script>` that admin.html's
/// `script-src 'self'; style-src 'self'` would block. Page-specific
/// policy stays in each page's `<meta>` tag. `X-Frame-Options: DENY`
/// rides along as a header-only fallback for UAs that predate
/// `frame-ancestors`.
const STATIC_CSP: &str = "frame-ancestors 'none'";

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
        .with_state(state);
    match web_root {
        Some(root) => {
            let static_files = ServiceBuilder::new()
                .layer(SetResponseHeaderLayer::overriding(
                    header::CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static(STATIC_CSP),
                ))
                .layer(SetResponseHeaderLayer::overriding(
                    header::HeaderName::from_static("x-frame-options"),
                    HeaderValue::from_static("DENY"),
                ))
                .service(ServeDir::new(root));
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
    async fn static_fallback_carries_frame_ancestors_as_a_header_not_only_meta() {
        // OBI-294: `admin.html`'s `frame-ancestors 'none'` is a no-op
        // when delivered only via `<meta http-equiv="Content-Security-
        // Policy">` (ignored by the CSP spec for that directive). The
        // static fallback must also carry it as a real response header
        // for every path under the served tree -- not just `admin.html`
        // -- plus `X-Frame-Options: DENY` as a header-only fallback for
        // older UAs.
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
            assert_eq!(csp, "frame-ancestors 'none'", "path: {path}");
            // Must not constrain script/style: index.html relies on an
            // inline <style> and inline module <script>.
            assert!(!csp.contains("script-src") && !csp.contains("default-src"));
            let xfo = response
                .headers()
                .get(header::HeaderName::from_static("x-frame-options"))
                .unwrap_or_else(|| panic!("missing X-Frame-Options header on {path}"))
                .to_str()
                .unwrap();
            assert_eq!(xfo, "DENY");
        }

        // Explicit (non-fallback) routes are untouched by the static-file
        // CSP layer -- it only wraps the `ServeDir` fallback service.
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
}
