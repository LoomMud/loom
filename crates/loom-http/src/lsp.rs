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
//!   is then bound to the ticket's `sub`+`sid`; a background task
//!   re-reads the uid's tier *and* the ticket's token-family liveness
//!   (`StaffDirectory::session_family_live`, CTO review of PR #122
//!   must-fix 2) every [`LspTuning::revocation_recheck_interval`] and
//!   closes the socket the moment either one fails -- a demotion/
//!   removal, or an M-AUTH-5 session-family revocation (logout,
//!   `refresh_token_revoke_all`) with no tier change at all. This
//!   recheck cadence (accepted by the CTO review as the right tradeoff
//!   for an idle LSP session with no per-request moment to hang a check
//!   off, same reasoning D-TM3 gives for its own per-request re-read) is
//!   the bound on how stale either check can be; the spec text in
//!   `docs/threat-model-phase2.md` describes it under M-LSP-1.
//! - **M-LSP-4**: `max_message_size` 4 MiB / `max_frame_size` 1 MiB,
//!   <= 2 sessions per uid, <= 32 total, and a genuine 60s idle timeout:
//!   the deadline is a single fixed instant reset only when a real
//!   inbound WS frame arrives (CTO review of PR #122 must-fix 1 -- an
//!   earlier cut rebuilt `tokio::time::timeout(IDLE_TIMEOUT, ..)` fresh
//!   on every `select!` pass, so the periodic revocation-recheck tick
//!   alone kept re-arming a brand new 60s window and the timeout could
//!   never actually fire, leaking a half-open socket's session-cap slot
//!   forever). The server also sends a WS `Ping` every
//!   [`LspTuning::ping_interval`] (well under the idle timeout) so a
//!   client that stopped reading/writing but left the TCP connection up
//!   is still detected once its automatic `Pong` stops arriving.
//!   (Document/request-level limits -- max open documents, the 5s
//!   per-request deadline, the bounded worker pool -- are
//!   `loom_lsp::server::run`'s job, unchanged by this module.)
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
/// D-TM3/scopes_for_tier: tier 0 has no `"builder"` scope at all.
const MIN_LSP_TIER: i16 = 1;

/// `/lsp`'s timing constants (CTO review of PR #122, must-fix 1):
/// overridable only in tests ([`crate::HttpState::
/// with_lsp_tuning_for_test`]), since the real spec values (tens of
/// seconds each) are far too slow for a test to wait out in real
/// wall-clock time, and there is otherwise no production knob for any
/// of these -- `loom-cli` never calls the test-only setter, so every
/// real `/lsp` connection gets [`Self::default`] below.
#[derive(Clone, Copy, Debug)]
pub struct LspTuning {
    /// Spec M-LSP-4: "a 60 s idle ping/pong timeout" -- reset only on a
    /// real inbound WS frame (CTO review must-fix 1; see module doc).
    pub idle_timeout: Duration,
    /// How often the server sends a WS `Ping` so a client that stopped
    /// responding (but left the TCP connection itself up) is detected
    /// once its automatic `Pong` replies stop arriving -- well under
    /// `idle_timeout` so a truly dead peer is caught before the idle
    /// timeout would have fired anyway.
    pub ping_interval: Duration,
    /// D-TM4: the first frame must carry the ticket "within 5 s or be
    /// closed".
    pub first_frame_timeout: Duration,
    /// M-LSP-1's demotion/removal/session-revocation recheck cadence --
    /// frequent enough that a demoted/revoked builder loses LSP access
    /// well inside one work session, cheap enough (one directory read
    /// each) not to matter at this rate.
    pub revocation_recheck_interval: Duration,
}

impl Default for LspTuning {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(60),
            ping_interval: Duration::from_secs(20),
            first_frame_timeout: Duration::from_secs(5),
            revocation_recheck_interval: Duration::from_secs(15),
        }
    }
}

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
    /// CTO review of PR #122, should-fix: `can_read` immediately
    /// followed by `read` for the same path (the common pattern --
    /// opening a document, or `GatedProvider`-style callers) used to
    /// cost two full `read_file` round trips (10s M-FS-5 budget each)
    /// for one logical operation, since `can_read` has no lighter-weight
    /// "exists" query to call instead -- it fetched and discarded the
    /// whole content just to answer a bool. A single-slot cache keyed by
    /// the last path asked about is enough to collapse that common
    /// back-to-back pair into one round trip without adding a new
    /// file-op kind; it never serves a *different* path's stale answer
    /// (the key is checked every call), and a cache miss just falls back
    /// to a fresh round trip, so this is a pure latency optimisation,
    /// never a correctness-affecting one.
    cache: Mutex<Option<(String, Result<String, String>)>>,
}

impl WorldReadProvider {
    fn new(file_op_tx: FileOpSender, uid: String) -> Self {
        Self {
            file_op_tx,
            uid,
            cache: Mutex::new(None),
        }
    }

    /// Blocks the calling thread for up to 10s (M-FS-5) -- callers must
    /// be one of `loom-lsp`'s own bounded blocking-pool threads (spec
    /// M-LSP-4), never an async task.
    fn read_through_channel(&self, path: &str) -> Result<String, String> {
        if let Some((cached_path, cached)) = self.cache.lock().unwrap().as_ref()
            && cached_path == path
        {
            return cached.clone();
        }
        let file_path = format!("{path}.wf");
        let result =
            match request_file_op(&self.file_op_tx, &self.uid, &file_path, FileOpKind::Read) {
                Ok(FileOpValue::Str(contents)) => Ok(contents),
                // M-FS-3: a denial must look exactly like "does not exist" --
                // `Null` (readable, absent), `Refused` (denied), and a
                // channel/timeout failure are deliberately not distinguished
                // here. `Internal`/other `FileOpValue` variants also fall
                // through to this one "missing" answer.
                _ => Err("No such file or directory".to_string()),
            };
        *self.cache.lock().unwrap() = Some((path.to_string(), result.clone()));
        result
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
    let tuning = *state.lsp_tuning();
    ws.max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_FRAME_BYTES)
        .on_upgrade(move |socket| async move {
            run_session(socket, state, auth, file_op_tx, tuning).await;
        })
        .into_response()
}

/// `true` iff `uid`/`sid` still passes both M-LSP-1 checks: a live tier
/// at or above [`MIN_LSP_TIER`], *and* `sid`'s token family not revoked
/// (CTO review of PR #122, must-fix 2 -- a tier check alone misses an
/// M-AUTH-5 logout/revocation that never touched the uid's tier). A
/// directory error on either check is treated as "still OK" here, not a
/// revocation -- see `AuthService::current_tier`/`session_family_live`'s
/// own docs on why a transient outage must not look like a confirmed
/// revocation to a periodic recheck.
async fn still_authorized(auth: &crate::auth::AuthService, uid: &str, sid: &str) -> bool {
    let tier_live = match auth.current_tier(uid).await {
        Ok(tier) => matches!(tier, Some(t) if t >= MIN_LSP_TIER),
        Err(_) => true,
    };
    if !tier_live {
        return false;
    }
    auth.session_family_live(sid).await.unwrap_or(true)
}

async fn run_session(
    mut socket: WebSocket,
    state: HttpState,
    auth: crate::auth::AuthService,
    file_op_tx: FileOpSender,
    tuning: LspTuning,
) {
    // D-TM4: "must send `{"auth":ticket}` within 5 s or be closed."
    #[derive(Deserialize)]
    struct AuthFrame {
        auth: String,
    }
    let Ok(Some(Ok(frame))) = tokio::time::timeout(tuning.first_frame_timeout, socket.recv()).await
    else {
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
    let sid = identity.sid;

    // M-LSP-1: refuse a uid/sid that already fails either check (tier
    // floor, or a revoked token family) before ever starting a session,
    // not just on the periodic recheck below.
    if !still_authorized(&auth, &uid, &sid).await {
        let _ = socket.send(WsMessage::Close(None)).await;
        return;
    }

    // M-LSP-4: session caps, checked only now (after the ticket is
    // already proven valid) so an unauthenticated connection attempt can
    // never itself be used to exhaust the cap.
    let Some(_guard) = state.lsp_sessions().try_acquire(&uid) else {
        let _ = socket.send(WsMessage::Close(None)).await;
        return;
    };

    let (server_conn, bridge_conn) = Connection::memory();
    let workspace = loom_lsp::workspace::Workspace::new_vfs(Arc::new(WorldReadProvider::new(
        file_op_tx,
        uid.clone(),
    )));
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
    //
    // Bounded (CTO review of PR #122, should-fix), not unbounded: an
    // unbounded channel lets a client that stops reading its socket (but
    // keeps the LSP server busy producing notifications/diagnostics)
    // grow this queue without limit, the same backpressure concern every
    // other bounded channel in this codebase (`FILE_OP_QUEUE_DEPTH`,
    // `AUDIT_DROP_WARN_INTERVAL`'s sink, ...) exists to avoid. The
    // producer thread blocks on `blocking_send` once the bound fills --
    // it is a dedicated OS thread for exactly this session, so blocking
    // it costs nothing else; a session whose client never reads just
    // stalls that one session's outbound delivery, never the world
    // thread or any other session.
    const OUTBOUND_QUEUE_DEPTH: usize = 256;
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<LspMessage>(OUTBOUND_QUEUE_DEPTH);
    let receiver = bridge_conn.receiver.clone();
    std::thread::spawn(move || {
        for msg in &receiver {
            if out_tx.blocking_send(msg).is_err() {
                break;
            }
        }
    });

    // M-LSP-1: close the socket the next time this fires after a
    // demotion/removal/revocation (see `still_authorized`).
    let mut recheck = tokio::time::interval(tuning.revocation_recheck_interval);
    recheck.tick().await; // first tick fires immediately; skip it

    // M-LSP-4: a genuine idle timeout (CTO review of PR #122, must-fix
    // 1) -- one fixed deadline, reset only when a real inbound WS frame
    // arrives (`idle_deadline = Instant::now() + tuning.idle_timeout`),
    // never rebuilt from "now" on every `select!` pass the way a fresh
    // `tokio::time::timeout(..)` per iteration would (that was the bug:
    // the periodic revocation-recheck tick alone kept re-arming a new
    // 60s window, so the timeout could never fire). A separate `Ping`
    // timer (not reset by anything) catches a client that stopped
    // responding but left the TCP connection itself open.
    let mut idle_deadline = tokio::time::Instant::now() + tuning.idle_timeout;
    let mut ping_interval = tokio::time::interval(tuning.ping_interval);
    ping_interval.tick().await; // first tick fires immediately; skip it

    let sender = bridge_conn.sender.clone();
    loop {
        tokio::select! {
            frame = tokio::time::timeout_at(idle_deadline, socket.recv()) => {
                let Ok(Some(Ok(frame))) = frame else { break; };
                // Any real inbound frame -- including the `Pong` a client
                // sends automatically in response to our `Ping` below --
                // is activity: push the deadline back out.
                idle_deadline = tokio::time::Instant::now() + tuning.idle_timeout;
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
            _ = ping_interval.tick() => {
                if socket.send(WsMessage::Ping(Vec::new().into())).await.is_err() { break; }
            }
            _ = recheck.tick() => {
                if !still_authorized(&auth, &uid, &sid).await {
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

    /// CTO review of PR #122, should-fix: `can_read` immediately
    /// followed by `read` on the same path must reuse the cached round
    /// trip, not make a second one -- the common back-to-back pattern
    /// `GatedProvider`/`server.rs`'s callers use.
    #[test]
    fn can_read_then_read_on_the_same_path_only_makes_one_round_trip() {
        use loom_lsp::file_provider::FileProvider;
        let (file_op_tx, file_op_rx) = file_op_channel();
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let calls_in_thread = calls.clone();
        std::thread::spawn(move || {
            while let Ok(req) = file_op_rx.recv() {
                calls_in_thread.fetch_add(1, Ordering::SeqCst);
                req.respond(Ok(FileOpValue::Str("int x;".to_string())));
            }
        });
        let provider = WorldReadProvider::new(file_op_tx, "frodo".to_string());
        assert!(provider.can_read("/builders/frodo/a"));
        assert_eq!(provider.read("/builders/frodo/a").as_deref(), Ok("int x;"));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "can_read followed by read on the same path must not re-fetch"
        );

        // A different path still gets its own fresh round trip.
        assert!(provider.can_read("/builders/frodo/b"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

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

    // -- Idle-deadline arithmetic (CTO review of PR #122, must-fix 1) --
    //
    // `run_session`'s real idle timeout is driven by a live socket and a
    // real revocation-recheck timer, which is awkward to drive
    // deterministically; these two tests isolate the exact arithmetic
    // bug instead (a fixed deadline that is reset only on real activity,
    // not rebuilt from "now" by every `select!` pass) using a paused
    // clock, so they run instantly and can't flake on timing.

    /// The bug this guards against: an earlier cut built a fresh
    /// `tokio::time::timeout(IDLE_TIMEOUT, ..)` *inside* the `select!`
    /// on every single pass, which computes its own deadline as
    /// `Instant::now() + IDLE_TIMEOUT` at that moment -- so as long as
    /// `select!` picked *any* branch (the unrelated revocation-recheck
    /// tick, here standing in for that) at least once every
    /// `IDLE_TIMEOUT`, the "timeout" could never actually elapse. A
    /// single fixed deadline, reset only by real inbound activity (which
    /// this test never supplies), must still fire.
    #[tokio::test(start_paused = true)]
    async fn idle_deadline_fires_even_though_an_unrelated_timer_keeps_ticking() {
        let idle_timeout = Duration::from_secs(60);
        let idle_deadline = tokio::time::Instant::now() + idle_timeout;
        let mut other_ticks = tokio::time::interval(Duration::from_secs(1));
        other_ticks.tick().await; // first tick fires immediately; skip it

        let mut idle_fired = false;
        for _ in 0..120 {
            tokio::select! {
                _ = tokio::time::sleep_until(idle_deadline) => {
                    idle_fired = true;
                    break;
                }
                _ = other_ticks.tick() => {
                    // Unrelated activity -- must NOT push the deadline
                    // out, unlike the old per-pass `timeout(..)` bug.
                }
            }
        }
        assert!(
            idle_fired,
            "a fixed deadline must still elapse even though another timer in the same \
             select! loop keeps firing"
        );
    }

    /// The flip side: real activity (the only thing that's supposed to
    /// reset the deadline) does push it back out.
    #[tokio::test(start_paused = true)]
    async fn idle_deadline_only_resets_on_explicit_activity() {
        let idle_timeout = Duration::from_secs(60);
        let would_have_elapsed_without_reset = tokio::time::Instant::now() + idle_timeout;

        tokio::time::advance(Duration::from_secs(50)).await;
        // Simulate an inbound frame arriving just before the old
        // deadline would have elapsed -- the only thing that's allowed
        // to push the deadline out.
        let idle_deadline = tokio::time::Instant::now() + idle_timeout;

        tokio::time::advance(Duration::from_secs(50)).await;
        assert!(
            tokio::time::Instant::now() >= would_have_elapsed_without_reset,
            "sanity: 100s must be past the original (un-reset) 60s deadline"
        );
        assert!(
            tokio::time::Instant::now() < idle_deadline,
            "activity at t=50s must push a 60s deadline out past t=100s"
        );
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
        spawn_lsp_server_with_tuning(content, LspTuning::default()).await
    }

    /// Same as [`spawn_lsp_server`], but with `/lsp`'s timing constants
    /// shrunk so a test can wait out a real idle timeout/ping interval/
    /// revocation recheck without a multi-second real sleep (CTO review
    /// of PR #122, must-fix 1/2 -- these need a test that proves the
    /// behaviour over real wall-clock time, not just the paused-clock
    /// unit tests above that prove the deadline arithmetic in isolation).
    async fn spawn_lsp_server_with_tuning(
        content: Option<(&'static str, &'static str)>,
        tuning: LspTuning,
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
        .with_file_ops(spawn_fake_world(content))
        .with_lsp_tuning_for_test(tuning);
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
        let (addr, auth, directory) = spawn_lsp_server(None).await;
        directory.seed_live_session_for_test("frodo", "sid-1");
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
        let (addr, auth, directory) = spawn_lsp_server(None).await;
        directory.seed_live_session_for_test("frodo", "sid-1");
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

    // -- Real end-to-end timing tests (CTO review of PR #122) ----------
    //
    // These use `with_lsp_tuning_for_test` to shrink the idle timeout/
    // ping interval/revocation-recheck interval to tens of
    // milliseconds, so they can wait out the real behaviour over real
    // (if brief) wall-clock time, deliberately with the recheck tick
    // firing *faster* than the idle timeout -- reproducing the exact
    // shape of the must-fix-1 bug (a fast unrelated timer in the same
    // loop must not stop the idle timeout from firing).

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn idle_timeout_fires_even_with_a_much_faster_recheck_tick() {
        let (addr, auth, directory) = spawn_lsp_server_with_tuning(
            None,
            LspTuning {
                idle_timeout: Duration::from_millis(300),
                ping_interval: Duration::from_secs(10), // out of the way
                first_frame_timeout: Duration::from_secs(5),
                revocation_recheck_interval: Duration::from_millis(20),
            },
        )
        .await;
        directory.seed_live_session_for_test("frodo", "sid-1");
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

        // Send nothing else. The 20ms recheck tick fires ~15 times
        // before the 300ms idle timeout should; the old per-pass
        // `timeout(..)` bug would have let every one of those ticks
        // re-arm a fresh window, so this would never close.
        let next = tokio::time::timeout(Duration::from_secs(5), ws.next()).await;
        match next {
            Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)))) | Ok(None) => {}
            other => panic!("expected the idle timeout to close the socket, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_server_sends_periodic_pings() {
        let (addr, auth, directory) = spawn_lsp_server_with_tuning(
            None,
            LspTuning {
                idle_timeout: Duration::from_secs(10),
                ping_interval: Duration::from_millis(50),
                first_frame_timeout: Duration::from_secs(5),
                revocation_recheck_interval: Duration::from_secs(10),
            },
        )
        .await;
        directory.seed_live_session_for_test("frodo", "sid-1");
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

        let next = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timed out waiting for a Ping")
            .expect("socket closed before any Ping arrived")
            .expect("a WS error");
        assert!(
            matches!(next, tokio_tungstenite::tungstenite::Message::Ping(_)),
            "expected a Ping frame, got {next:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revoked_session_family_closes_an_open_session_on_the_next_recheck() {
        let (addr, auth, directory) = spawn_lsp_server_with_tuning(
            None,
            LspTuning {
                idle_timeout: Duration::from_secs(10),
                ping_interval: Duration::from_secs(10),
                first_frame_timeout: Duration::from_secs(5),
                revocation_recheck_interval: Duration::from_millis(50),
            },
        )
        .await;
        directory.seed_live_session_for_test("frodo", "sid-1");
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
        // Prove the session is actually up first (same round trip as
        // `a_valid_ticket_bridges_a_real_initialize_round_trip`), so a
        // close below can only be the revocation recheck, not a session
        // that never started.
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
        let reply = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timed out waiting for the initialize response")
            .expect("socket closed before answering")
            .expect("a WS error");
        assert!(matches!(
            reply,
            tokio_tungstenite::tungstenite::Message::Text(_)
        ));

        // M-AUTH-5: revoke the token family -- no tier change at all.
        directory.revoke_session_family_for_test("sid-1");

        let next = tokio::time::timeout(Duration::from_secs(5), ws.next()).await;
        match next {
            Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)))) | Ok(None) => {}
            other => {
                panic!("expected the revoked session family to close the socket, got {other:?}")
            }
        }
    }
}
