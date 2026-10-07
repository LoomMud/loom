// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `GET /lsp` (OBI-180, M-LSP-1/M-LSP-4): the production WebSocket
//! bridge to `loom-lsp`'s protocol core ([`loom_lsp::server::
//! run_with_workspace`]), gated by auth this crate owns rather than by
//! `loom-lsp` itself (see `loom_lsp::ws`'s module doc: that crate's own
//! `--ws` bridge is a local/dev tool with no auth of its own, and
//! explicitly calls this module "OBI-180's job").
//!
//! - **M-LSP-1**: `Origin` must be on `HttpState`'s staff-origin
//!   allowlist (the same list M-AUTH-6 uses). The first WS frame must be
//!   `{"auth":"<ticket>"}`, a D-TM4 single-use ticket from `POST
//!   /api/v1/ws-ticket`, within 5s or the socket is closed. The session
//!   is then bound to the ticket's `sub`; a background task re-reads the
//!   uid's tier every [`REVOCATION_RECHECK_INTERVAL`] and closes the
//!   socket the moment it drops below the builder floor or the uid's
//!   `staff` row disappears (a demotion/removal "takes effect on the
//!   next [check]", same wording as D-TM3 -- the WS equivalent of
//!   D-TM3's per-request re-read, since there is no per-request moment
//!   on an idle LSP session to hang that check off). **Known gap**: a
//!   token-family revocation (M-AUTH-5, e.g. a staff member's refresh
//!   session being revoked without a tier change) is not observed by an
//!   already-open `/lsp` session, since `StaffDirectory` has no
//!   `sid`-keyed "is this family still live" query today -- only a tier
//!   drop or uid removal closes an open session. Tracked as a follow-up;
//!   the 30s ticket TTL plus this recheck bounds the exposure.
//! - **M-LSP-4**: `max_message_size` 4 MiB / `max_frame_size` 1 MiB,
//!   <= 2 sessions per uid, <= 32 total, 60s idle timeout. (Document/
//!   request-level limits -- max open documents, the 5s per-request
//!   deadline, the bounded worker pool -- are `loom_lsp::server::run`'s
//!   job, unchanged by this module.)
//! - **M-LSP-2/M-LSP-3** (`loom-lsp`'s job, OBI-168): this module's only
//!   contribution is the [`loom_lsp::file_provider::ReadAuthorizer`] that
//!   gates every read through the same M-FS-1 world-thread channel
//!   `files.rs` uses, with guard set exactly `{uid}` -- no new VFS path,
//!   no HTTP-side ACL (D-TM5).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::get;
use lsp_server::{Connection, Message as LspMessage};
use serde::Deserialize;

use crate::HttpState;
use crate::files::{FileOpKind, FileOpSender, FileOpValue, request_file_op};

/// Spec M-LSP-4: "WS `max_message_size` 4 MiB and `max_frame_size` 1 MiB".
const MAX_WS_MESSAGE_BYTES: usize = 4 << 20;
const MAX_WS_FRAME_BYTES: usize = 1 << 20;
/// Spec M-LSP-4: "<= 2 sessions per uid".
const MAX_SESSIONS_PER_UID: usize = 2;
/// Spec M-LSP-4: "<= 32 sessions total".
const MAX_SESSIONS_TOTAL: usize = 32;
/// Spec M-LSP-4: "a 60 s idle ping/pong timeout".
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// D-TM4: the first frame must carry the ticket "within 5 s or be closed".
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(5);
/// M-LSP-1's demotion/removal recheck cadence (see module doc's "known
/// gap" note) -- frequent enough that a demoted builder loses LSP access
/// well inside one work session, cheap enough (one directory read) not
/// to matter at this rate.
const REVOCATION_RECHECK_INTERVAL: Duration = Duration::from_secs(15);
/// D-TM3/scopes_for_tier: tier 0 has no `"builder"` scope at all.
const MIN_LSP_TIER: i16 = 1;

/// M-LSP-4's session caps, shared across every `/lsp` connection via
/// [`HttpState`]. Cheap enough to be an always-present field (unlike
/// `file_op_tx`'s `Option`): with no file-op channel wired the route
/// still answers `503` before ever touching this.
#[derive(Clone, Default)]
pub struct SessionLimiter {
    total: Arc<AtomicUsize>,
    per_uid: Arc<Mutex<HashMap<String, usize>>>,
}

/// Released automatically when the session ends (including on an error
/// return or a panic unwind), so a cap is never leaked by a forgotten
/// decrement on an early-return path.
struct SessionGuard {
    uid: String,
    limiter: SessionLimiter,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.limiter.total.fetch_sub(1, Ordering::SeqCst);
        let mut per_uid = self.limiter.per_uid.lock().unwrap();
        if let Some(count) = per_uid.get_mut(&self.uid) {
            *count -= 1;
            if *count == 0 {
                per_uid.remove(&self.uid);
            }
        }
    }
}

impl SessionLimiter {
    fn try_acquire(&self, uid: &str) -> Option<SessionGuard> {
        // Reserve the total slot first; release it immediately if the
        // per-uid cap is what actually refuses, so the two checks can't
        // leave the total counter stuck above the real session count.
        if self.total.fetch_add(1, Ordering::SeqCst) >= MAX_SESSIONS_TOTAL {
            self.total.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        let mut per_uid = self.per_uid.lock().unwrap();
        let count = per_uid.entry(uid.to_string()).or_insert(0);
        if *count >= MAX_SESSIONS_PER_UID {
            drop(per_uid);
            self.total.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        *count += 1;
        Some(SessionGuard {
            uid: uid.to_string(),
            limiter: self.clone(),
        })
    }
}

/// [`loom_lsp::file_provider::ReadAuthorizer`]/[`loom_lsp::file_provider::
/// FileProvider`] backed by the M-FS-1 world-thread channel (D-TM5: no
/// HTTP-side ACL, the same `valid_read` the files API uses, guard set
/// exactly `{uid}`). `path` arrives already normalised by `loom-lsp`'s
/// own VFS resolver (M-LSP-3, `loom_lsp::file_provider`'s module doc);
/// this only appends the on-disk `.wf` suffix the file-op channel's
/// `read_file` efun expects (same convention `files.rs`'s own
/// `LocalDirectoryProvider` equivalent uses).
struct WorldReadProvider {
    file_op_tx: FileOpSender,
    uid: String,
}

impl WorldReadProvider {
    /// Blocks the calling thread for up to 10s (M-FS-5) -- callers must
    /// be one of `loom-lsp`'s own bounded blocking-pool threads (spec
    /// M-LSP-4), never an async task.
    fn read_through_channel(&self, path: &str) -> Result<String, String> {
        let file_path = format!("{path}.wf");
        match request_file_op(&self.file_op_tx, &self.uid, &file_path, FileOpKind::Read) {
            Ok(FileOpValue::Str(contents)) => Ok(contents),
            // M-FS-3: a denial must look exactly like "does not exist" --
            // `Null` (readable, absent), `Refused` (denied), and a
            // channel/timeout failure are deliberately not distinguished
            // here. `Internal`/other `FileOpValue` variants also fall
            // through to this one "missing" answer.
            _ => Err("No such file or directory".to_string()),
        }
    }
}

impl loom_lsp::file_provider::FileProvider for WorldReadProvider {
    fn read(&self, path: &str) -> Result<String, String> {
        self.read_through_channel(path)
    }

    fn can_read(&self, path: &str) -> bool {
        self.read_through_channel(path).is_ok()
    }
}

pub fn lsp_router() -> Router<HttpState> {
    Router::new().route("/lsp", get(lsp_handler))
}

/// `GET /lsp` (M-LSP-1): Origin-gated WS upgrade, ticket-authenticated
/// in the first frame, session-capped and idle-timed-out per M-LSP-4.
async fn lsp_handler(
    ws: WebSocketUpgrade,
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(auth) = state.auth_service() else {
        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(file_op_tx) = state.file_op_tx().cloned() else {
        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    };

    // M-LSP-1: Origin must be on the same staff-origin allowlist
    // M-AUTH-6 uses (`LOOM_STAFF_ORIGINS`). Browsers always send
    // `Origin` on a cross-origin (and same-site) WS handshake and cannot
    // be made to omit or spoof it from page script, unlike a header a
    // `fetch` call could set -- so, unlike `staff_csrf_guard_passes`,
    // there is no second custom-header check to pair it with here (a
    // browser WebSocket client cannot set arbitrary handshake headers at
    // all, so requiring one would only break real clients).
    let origin_ok = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|origin| {
            state
                .staff_origins()
                .iter()
                .any(|allowed| allowed == origin)
        });
    if !origin_ok {
        return axum::http::StatusCode::FORBIDDEN.into_response();
    }

    let auth = auth.clone();
    ws.max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_FRAME_BYTES)
        .on_upgrade(move |socket| async move {
            run_session(socket, state, auth, file_op_tx).await;
        })
        .into_response()
}

async fn run_session(
    mut socket: WebSocket,
    state: HttpState,
    auth: crate::auth::AuthService,
    file_op_tx: FileOpSender,
) {
    // D-TM4: "must send `{"auth":ticket}` within 5 s or be closed."
    #[derive(Deserialize)]
    struct AuthFrame {
        auth: String,
    }
    let Ok(Some(Ok(frame))) = tokio::time::timeout(FIRST_FRAME_TIMEOUT, socket.recv()).await else {
        let _ = socket.send(WsMessage::Close(None)).await;
        return;
    };
    let text = match frame {
        WsMessage::Text(t) => t,
        _ => {
            let _ = socket.send(WsMessage::Close(None)).await;
            return;
        }
    };
    let Ok(auth_frame) = serde_json::from_str::<AuthFrame>(&text) else {
        let _ = socket.send(WsMessage::Close(None)).await;
        return;
    };
    let Ok(identity) = auth.redeem_ws_ticket(&auth_frame.auth) else {
        let _ = socket.send(WsMessage::Close(None)).await;
        return;
    };
    let uid = identity.sub;

    // M-LSP-1: refuse a uid that is below the builder floor (or has no
    // `staff` row at all) before ever starting a session, not just on
    // the periodic recheck below.
    match auth.current_tier(&uid).await {
        Ok(Some(tier)) if tier >= MIN_LSP_TIER => {}
        _ => {
            let _ = socket.send(WsMessage::Close(None)).await;
            return;
        }
    }

    // M-LSP-4: session caps, checked only now (after the ticket is
    // already proven valid) so an unauthenticated connection attempt can
    // never itself be used to exhaust the cap.
    let Some(_guard) = state.lsp_sessions().try_acquire(&uid) else {
        let _ = socket.send(WsMessage::Close(None)).await;
        return;
    };

    let (server_conn, bridge_conn) = Connection::memory();
    let workspace = loom_lsp::workspace::Workspace::new_vfs(Arc::new(WorldReadProvider {
        file_op_tx,
        uid: uid.clone(),
    }));
    let _server_task = tokio::task::spawn_blocking(move || {
        loom_lsp::server::run_with_workspace(server_conn, workspace)
    });

    // Server -> client: `bridge_conn.receiver.recv()` blocks
    // synchronously, so (mirroring `loom_lsp::ws`'s own bridge) that side
    // runs on one dedicated OS thread for the whole session's lifetime
    // and forwards into this async-friendly channel -- not a fresh
    // `spawn_blocking` per message, which would leave an orphaned
    // blocked thread behind every time `tokio::select!` picked the other
    // branch first.
    let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<LspMessage>();
    let receiver = bridge_conn.receiver.clone();
    std::thread::spawn(move || {
        for msg in &receiver {
            if out_tx.send(msg).is_err() {
                break;
            }
        }
    });

    // M-LSP-1: close the socket the next time this fires after a
    // demotion/removal (see module doc's "known gap" note on what this
    // does not cover).
    let mut recheck = tokio::time::interval(REVOCATION_RECHECK_INTERVAL);
    recheck.tick().await; // first tick fires immediately; skip it

    let sender = bridge_conn.sender.clone();
    loop {
        tokio::select! {
            frame = tokio::time::timeout(IDLE_TIMEOUT, socket.recv()) => {
                let Ok(Some(Ok(frame))) = frame else { break; };
                match frame {
                    WsMessage::Text(text) => {
                        let Ok(msg) = serde_json::from_str::<LspMessage>(&text) else { continue; };
                        if sender.send(msg).is_err() { break; }
                    }
                    WsMessage::Close(_) => break,
                    _ => {}
                }
            }
            outgoing = out_rx.recv() => {
                let Some(msg) = outgoing else { break; };
                let Ok(text) = message_to_text(&msg) else { continue; };
                if socket.send(WsMessage::Text(text.into())).await.is_err() { break; }
            }
            _ = recheck.tick() => {
                // A directory error (transient Postgres outage) does not
                // close the session -- only a confirmed demotion/removal
                // does (see `current_tier`'s doc).
                if let Ok(tier) = auth.current_tier(&uid).await
                    && !matches!(tier, Some(t) if t >= MIN_LSP_TIER)
                {
                    break;
                }
            }
        }
    }
    let _ = socket.send(WsMessage::Close(None)).await;
}

fn message_to_text(msg: &LspMessage) -> serde_json::Result<String> {
    #[derive(serde::Serialize)]
    struct JsonRpc<'a> {
        jsonrpc: &'static str,
        #[serde(flatten)]
        msg: &'a LspMessage,
    }
    serde_json::to_string(&JsonRpc {
        jsonrpc: "2.0",
        msg,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};

    #[test]
    fn session_limiter_enforces_per_uid_cap() {
        let limiter = SessionLimiter::default();
        let _a = limiter.try_acquire("alice").unwrap();
        let _b = limiter.try_acquire("alice").unwrap();
        assert!(limiter.try_acquire("alice").is_none());
        // A different uid is unaffected.
        assert!(limiter.try_acquire("bob").is_some());
    }

    #[test]
    fn session_limiter_releases_on_drop() {
        let limiter = SessionLimiter::default();
        {
            let _a = limiter.try_acquire("alice").unwrap();
            let _b = limiter.try_acquire("alice").unwrap();
        }
        assert!(limiter.try_acquire("alice").is_some());
    }

    #[test]
    fn session_limiter_enforces_total_cap() {
        let limiter = SessionLimiter::default();
        let mut guards = Vec::new();
        for i in 0..MAX_SESSIONS_TOTAL {
            guards.push(limiter.try_acquire(&format!("uid-{i}")).unwrap());
        }
        assert!(limiter.try_acquire("one-more").is_none());
    }

    // -- HTTP-wire tests: real axum server + a real WS client -----------

    use crate::app;
    use crate::auth::jwt::JwtKeys;
    use crate::auth::tests::FakeDirectory;
    use crate::auth::{AccessClaims, AuthService};
    use crate::files::{FileOpValue, file_op_channel};
    use crate::{HttpState, files};

    const STAFF_ORIGIN: &str = "https://build.loommud.test";

    fn keys() -> JwtKeys {
        JwtKeys::single(
            [7u8; 32],
            "test-kid",
            "https://build.loommud.test/",
            "loom-staff",
        )
    }

    fn claims_for(uid: &str, keys: &JwtKeys, sid: &str) -> AccessClaims {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        AccessClaims {
            sub: uid.to_string(),
            tier: 1,
            scopes: vec!["builder".to_string()],
            iss: keys.issuer().to_string(),
            aud: keys.audience().to_string(),
            iat: now,
            nbf: now,
            exp: now + 300,
            sid: sid.to_string(),
            amr: vec!["pwd".to_string()],
            mfa_at: None,
        }
    }

    /// A world-thread stand-in (M-FS-1): answers every `Read` with
    /// `Null` ( readable, nothing written yet) unless `content` names
    /// the exact file path, in which case it answers that content once.
    fn spawn_fake_world(content: Option<(&'static str, &'static str)>) -> files::FileOpSender {
        let (file_op_tx, file_op_rx) = file_op_channel();
        std::thread::spawn(move || {
            while let Ok(req) = file_op_rx.recv() {
                let reply = match (&req.kind, content) {
                    (files::FileOpKind::Read, Some((path, text))) if req.path == path => {
                        FileOpValue::Str(text.to_string())
                    }
                    _ => FileOpValue::Null,
                };
                req.respond(Ok(reply));
            }
        });
        file_op_tx
    }

    async fn spawn_lsp_server(
        content: Option<(&'static str, &'static str)>,
    ) -> (std::net::SocketAddr, AuthService, FakeDirectory) {
        let (ws_accept_tx, _ws_accept_rx) = tokio::sync::mpsc::channel(1);
        let directory = FakeDirectory::new();
        directory.add_staff("frodo", "hunter2", 1);
        let auth = AuthService::new(std::sync::Arc::new(directory.clone()), keys());
        let state = HttpState::new(
            ws_accept_tx,
            loom_obs::Readiness::new(),
            loom_obs::PrometheusMetrics::new_unregistered(),
        )
        .with_auth(auth.clone())
        .with_staff_origins(vec![STAFF_ORIGIN.to_string()])
        .with_file_ops(spawn_fake_world(content));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app(state)).await.unwrap();
        });
        (addr, auth, directory)
    }

    fn ws_request(addr: std::net::SocketAddr, origin: Option<&str>) -> axum::http::Request<()> {
        let mut builder = axum::http::Request::builder()
            .uri(format!("ws://{addr}/lsp"))
            .header("Host", addr.to_string())
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            );
        if let Some(origin) = origin {
            builder = builder.header("Origin", origin);
        }
        builder.body(()).unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_disallowed_origin_is_refused_before_any_upgrade() {
        let (addr, _auth, _directory) = spawn_lsp_server(None).await;
        let err = tokio_tungstenite::connect_async(ws_request(addr, Some("https://evil.example")))
            .await
            .unwrap_err();
        match err {
            tokio_tungstenite::tungstenite::Error::Http(response) => {
                assert_eq!(response.status(), 403);
            }
            other => panic!("expected an HTTP 403, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_first_frame_ticket_closes_the_socket() {
        let (addr, _auth, _directory) = spawn_lsp_server(None).await;
        let (mut ws, _) = tokio_tungstenite::connect_async(ws_request(addr, Some(STAFF_ORIGIN)))
            .await
            .unwrap();
        // Say nothing; the server must close within FIRST_FRAME_TIMEOUT.
        let next = tokio::time::timeout(Duration::from_secs(10), ws.next()).await;
        match next {
            Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)))) | Ok(None) => {}
            other => panic!("expected the server to close the socket, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_ticket_can_only_authenticate_one_session() {
        let (addr, auth, _directory) = spawn_lsp_server(None).await;
        let claims = claims_for("frodo", &keys(), "sid-1");
        let ticket = auth.issue_ws_ticket(&claims).unwrap();

        let (mut first, _) = tokio_tungstenite::connect_async(ws_request(addr, Some(STAFF_ORIGIN)))
            .await
            .unwrap();
        first
            .send(tokio_tungstenite::tungstenite::Message::Text(
                serde_json::json!({ "auth": ticket }).to_string().into(),
            ))
            .await
            .unwrap();

        let (mut second, _) =
            tokio_tungstenite::connect_async(ws_request(addr, Some(STAFF_ORIGIN)))
                .await
                .unwrap();
        second
            .send(tokio_tungstenite::tungstenite::Message::Text(
                serde_json::json!({ "auth": ticket }).to_string().into(),
            ))
            .await
            .unwrap();
        let next = tokio::time::timeout(Duration::from_secs(10), second.next()).await;
        match next {
            Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)))) | Ok(None) => {}
            other => {
                panic!("expected the second (replayed-ticket) session to be closed, got {other:?}")
            }
        }
        // First session is unaffected by the replay against its own ticket.
        first
            .send(tokio_tungstenite::tungstenite::Message::Text(
                serde_json::json!({
                    "id": 1,
                    "method": "shutdown",
                    "params": null,
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_valid_ticket_bridges_a_real_initialize_round_trip() {
        let (addr, auth, _directory) = spawn_lsp_server(None).await;
        let claims = claims_for("frodo", &keys(), "sid-1");
        let ticket = auth.issue_ws_ticket(&claims).unwrap();

        let (mut ws, _) = tokio_tungstenite::connect_async(ws_request(addr, Some(STAFF_ORIGIN)))
            .await
            .unwrap();
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            serde_json::json!({ "auth": ticket }).to_string().into(),
        ))
        .await
        .unwrap();
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            serde_json::json!({
                "id": 1,
                "method": "initialize",
                "params": { "capabilities": {} },
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

        let reply = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("timed out waiting for the initialize response")
            .expect("socket closed before answering")
            .expect("a WS error");
        let tokio_tungstenite::tungstenite::Message::Text(text) = reply else {
            panic!("expected a text frame");
        };
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["id"], 1);
        assert!(parsed["result"]["capabilities"].is_object());
    }
}
