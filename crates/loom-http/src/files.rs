// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `/api/v1/files/*` (OBI-180): read-through to `World::call_file_efun`
//! (M-FS-1), without `loom-http` ever depending on `loom-vm` directly.
//!
//! ## Why the channel types live here, not in `loom-cli`
//!
//! `loom-cli` is a binary crate (the composition root): it depends on
//! both `loom-vm` (for `World`) and `loom-http` (for [`HttpState`]), but
//! nothing can depend back on a binary crate, so a channel type that
//! both the axum handlers below *and* `loom-cli`'s world-thread drain
//! loop need to share has to live in a crate both of them see --
//! `loom-http`, the same way [`crate::webhook::GithubWebhookConfig`] is
//! defined here and constructed by `loom-cli`. [`FileOpRequest`]/
//! [`FileOpValue`] intentionally hold no `loom_vm` type (`args`/the
//! reply are plain `String`s) so this module adds no new dependency
//! edge; the `loom_vm::Value` <-> [`FileOpValue`] conversion stays in
//! `loom-cli`, right next to the `World::call_file_efun` call that
//! produces the `Value` in the first place.
//!
//! ## What this module does *not* do yet
//!
//! Listings (M-FS-3's "filtered by `valid_read`") and `compile_object`
//! are a later slice -- `FileOpValue`'s doc already notes
//! `compile_object`'s diagnostics-list result needs a richer shape than
//! `Null`/`Bool`/`Str`. `PUT`'s M-FS-5 "one in-flight compile per uid"
//! clause is also deferred to that slice (there is no compile to
//! serialize yet).

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::HttpState;
use crate::handlers::bearer_uid;

/// Bound on in-flight `/api/v1/files/*` file-op requests queued for the
/// world thread (M-FS-5): past this many outstanding requests,
/// [`FileOpSender::try_send`] fails immediately and the handler answers
/// `503` instead of queueing.
pub const FILE_OP_QUEUE_DEPTH: usize = 64;

/// M-FS-5's "10 s timeout": how long [`request_file_op`] blocks its own
/// (dedicated, non-async -- see that function's doc) thread waiting for
/// the world thread to answer, before giving up.
pub const FILE_OP_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// A `read_file`/`write_file` result, far enough from `loom_vm::Value`
/// (which holds `Rc`s and so is not `Send`) to cross the file-op reply
/// channel into an async HTTP handler's thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileOpValue {
    Null,
    Bool(bool),
    Str(String),
}

/// One file operation requested by an `/api/v1/files/*` HTTP handler
/// (M-FS-1), to be run on the world thread with guard set exactly
/// `{uid}` via `World::call_file_efun`. `efun` is `"read_file"` or
/// `"write_file"`; `args` are the efun's string arguments in order
/// (`[path]` for a read, `[path, text]` for a write). The reply channel
/// is a fresh one-shot `std::sync::mpsc` per request.
pub struct FileOpRequest {
    pub uid: String,
    pub efun: &'static str,
    pub args: Vec<String>,
    reply: std::sync::mpsc::Sender<Result<FileOpValue, String>>,
}

impl FileOpRequest {
    /// The world-thread side's only way to answer a request -- consumes
    /// `self` so a drain loop can't accidentally reply twice or forget
    /// to. A dropped (never-called) `respond` surfaces to the waiting
    /// HTTP-side thread as a `recv` error, not a hang (see
    /// [`request_file_op`]'s doc).
    pub fn respond(self, result: Result<FileOpValue, String>) {
        let _ = self.reply.send(result);
    }
}

/// The world thread's half of the file-op channel; `loom-cli`'s
/// `spawn_world_thread` drains the matching [`Receiver<FileOpRequest>`].
pub type FileOpSender = SyncSender<FileOpRequest>;

/// Construct the bounded file-op channel (M-FS-5's queue depth). Kept as
/// a function (rather than letting callers pick their own depth) so
/// `FILE_OP_QUEUE_DEPTH` is the one place the bound is defined.
pub fn file_op_channel() -> (FileOpSender, Receiver<FileOpRequest>) {
    std::sync::mpsc::sync_channel(FILE_OP_QUEUE_DEPTH)
}

/// Ask the world thread to run `efun(args)` with guard set exactly
/// `{uid}` (`World::call_file_efun`, M-FS-1), blocking this call's own
/// thread until it answers or [`FILE_OP_REQUEST_TIMEOUT`] elapses
/// (M-FS-5).
///
/// **Never call this from an async task directly** -- it blocks a real
/// OS thread for up to 10s. Callers in this module always wrap it in
/// `tokio::task::spawn_blocking`.
pub fn request_file_op(
    file_op_tx: &FileOpSender,
    uid: &str,
    efun: &'static str,
    args: Vec<String>,
) -> Result<FileOpValue, String> {
    let (reply_tx, reply_rx) = std::sync::mpsc::channel();
    match file_op_tx.try_send(FileOpRequest {
        uid: uid.to_string(),
        efun,
        args,
        reply: reply_tx,
    }) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => return Err("file-op queue is full".to_string()),
        Err(TrySendError::Disconnected(_)) => {
            return Err("the world thread is gone".to_string());
        }
    }
    reply_rx
        .recv_timeout(FILE_OP_REQUEST_TIMEOUT)
        .map_err(|err| format!("world thread did not answer the file-op request: {err}"))?
}

#[derive(Debug, Deserialize)]
pub struct ReadFileQuery {
    path: String,
}

/// 1 MiB request body cap (M-FS-5). Enforced by axum's
/// [`DefaultBodyLimit`] layer (rejects an oversized body before fully
/// buffering it, not just after) on the `PUT` route only -- the `GET`
/// route has no request body to limit.
const MAX_WRITE_BODY_BYTES: usize = 1024 * 1024;

pub fn files_router() -> Router<HttpState> {
    Router::new().route(
        "/api/v1/files/content",
        get(read_file)
            .put(write_file)
            .route_layer(DefaultBodyLimit::max(MAX_WRITE_BODY_BYTES)),
    )
}

/// `GET /api/v1/files/content?path=/builders/<u>/...` (M-FS-1).
///
/// - `401` with no/invalid bearer token.
/// - `404` for a path `valid_read` refuses *or* that doesn't exist --
///   deliberately the same status for both (M-FS-3): a 403 would tell an
///   unauthorised caller a path exists.
/// - `503` on a full queue or a world thread that didn't answer in time
///   (M-FS-5), never a hang.
/// - `200` with `Content-Type: text/plain; charset=utf-8`,
///   `X-Content-Type-Options: nosniff`, a sandboxed `Content-Security-
///   Policy`, and `Content-Disposition: attachment` (M-FS-4) -- the MIME
///   type is never derived from the path's extension.
async fn read_file(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<ReadFileQuery>,
) -> impl IntoResponse {
    let Some(uid) = bearer_uid(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(file_op_tx) = state.file_op_tx.clone() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let path = query.path;
    let result = tokio::task::spawn_blocking(move || {
        request_file_op(&file_op_tx, &uid, "read_file", vec![path])
    })
    .await;
    match result {
        Ok(Ok(FileOpValue::Str(contents))) => file_response(contents),
        Ok(Ok(FileOpValue::Null)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Ok(FileOpValue::Bool(_))) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(_join_err) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

/// M-FS-4's exact response shape for a successful read: `text/plain`,
/// `nosniff`, a sandboxed CSP, and `attachment` disposition so a
/// browser navigating here directly never renders the body as HTML.
fn file_response(contents: String) -> axum::response::Response {
    let mut response = (StatusCode::OK, contents).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment"),
    );
    response
}

/// A strong `ETag` over a file's exact byte contents (M-FS-6):
/// `sha256(contents)`, hex-encoded, quoted per RFC 9110 S8.8.3. Cheap
/// enough to recompute on every `PUT` (one hash over at most
/// [`MAX_WRITE_BODY_BYTES`]) rather than caching -- the world thread is
/// the only place the real content lives, and this is never on the hot
/// per-tick path.
fn etag_for(contents: &str) -> String {
    let digest = Sha256::digest(contents.as_bytes());
    format!("\"{}\"", hex_encode(&digest))
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Bound on distinct uids tracked by [`write_rate_limiter`] (OBI-204
/// hygiene, same shape as `auth::ratelimit`'s caps): past this many
/// tracked buckets, the oldest-touched ones are evicted rather than
/// letting an unbounded number of distinct uids grow the map forever.
/// Staff uid counts are nowhere near this in practice.
const MAX_TRACKED_WRITE_UIDS: usize = 10_000;

/// Per-uid write token bucket (M-FS-5's "per-uid write rate limit"):
/// `CAPACITY` burst, refilling at one token per `REFILL_INTERVAL`. First
/// cut for Phase 2 -- numbers are a starting point, not yet tuned
/// against real builder workflows; revisit with the CTO once there's
/// usage data, the same caveat `scopes_for_tier` carries.
const WRITE_BUCKET_CAPACITY: f64 = 20.0;
const WRITE_BUCKET_REFILL_INTERVAL: Duration = Duration::from_secs(2);

struct WriteBucket {
    tokens: f64,
    last_refill: Instant,
}

fn write_rate_limiter() -> &'static Mutex<HashMap<String, WriteBucket>> {
    static LIMITER: OnceLock<Mutex<HashMap<String, WriteBucket>>> = OnceLock::new();
    LIMITER.get_or_init(|| Mutex::new(HashMap::new()))
}

/// `true` if `uid` may write now (and consumes one token if so); `false`
/// if its bucket is empty (M-FS-5 -- caller answers `429`).
fn check_write_rate_limit(uid: &str) -> bool {
    let mut map = write_rate_limiter()
        .lock()
        .expect("write rate limiter mutex poisoned");
    if map.len() >= MAX_TRACKED_WRITE_UIDS && !map.contains_key(uid) {
        // OBI-204-style hard cap: evict the single oldest-touched entry
        // to make room rather than growing without bound. A full sweep
        // (like `auth::ratelimit`'s) is overkill here -- write buckets
        // have no lockout state to expire, just tokens that passively
        // refill, so one eviction per over-cap insert keeps the map
        // bounded without a separate sweep pass.
        if let Some(oldest) = map
            .iter()
            .min_by_key(|(_, b)| b.last_refill)
            .map(|(k, _)| k.clone())
        {
            map.remove(&oldest);
        }
    }
    let now = Instant::now();
    let bucket = map.entry(uid.to_string()).or_insert_with(|| WriteBucket {
        tokens: WRITE_BUCKET_CAPACITY,
        last_refill: now,
    });
    let elapsed = now.saturating_duration_since(bucket.last_refill);
    let refilled = elapsed.as_secs_f64() / WRITE_BUCKET_REFILL_INTERVAL.as_secs_f64();
    bucket.tokens = (bucket.tokens + refilled).min(WRITE_BUCKET_CAPACITY);
    bucket.last_refill = now;
    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        true
    } else {
        false
    }
}

#[derive(Debug, Deserialize)]
pub struct WriteFileQuery {
    path: String,
}

/// `PUT /api/v1/files/content?path=...` (M-FS-1/M-FS-6/M-FS-7).
///
/// Preconditions are mandatory, not optional (M-FS-6): exactly one of
/// `If-Match: "<etag>"` (update an existing file whose current contents
/// hash to that etag) or `If-None-Match: *` (create a file that must not
/// already exist) is required on every request, so a save can never
/// silently clobber a concurrent edit.
///
/// - `401` no/invalid bearer token.
/// - `400` body isn't valid UTF-8, or neither/both precondition headers
///   given, or `If-None-Match` is present but isn't exactly `*`.
/// - `413` body over [`MAX_WRITE_BODY_BYTES`] (enforced twice: axum's
///   `DefaultBodyLimit` layer on the route, and a belt-and-suspenders
///   check here).
/// - `429` the uid's write rate limit is exhausted (M-FS-5).
/// - `412` a precondition failed: `If-Match` doesn't match the file's
///   current `ETag`, or `If-None-Match: *` was sent but the file already
///   exists.
/// - `404` the path doesn't authorize for this uid (M-FS-3, same
///   not-found-shaped refusal as `GET`) -- checked by attempting the
///   write itself, never a separate ACL.
/// - `503` no file-op channel wired, a full queue, or a world-thread
///   timeout (M-FS-5).
/// - `204` success. The write itself (`World::call_file_efun` ->
///   `write_file`) is already audited with the real actor uid by the
///   existing `write_file` efun path (M-FS-7) -- this handler adds no
///   second audit trail.
async fn write_file(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<WriteFileQuery>,
    body: Bytes,
) -> impl IntoResponse {
    let Some(uid) = bearer_uid(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if body.len() > MAX_WRITE_BODY_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let Ok(text) = String::from_utf8(body.to_vec()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    let if_match = header_str(&headers, header::IF_MATCH);
    let if_none_match_is_star = header_str(&headers, header::IF_NONE_MATCH).as_deref() == Some("*");
    let if_none_match_present = headers.contains_key(header::IF_NONE_MATCH);
    if if_none_match_present && !if_none_match_is_star {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if if_match.is_none() && !if_none_match_is_star {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if if_match.is_some() && if_none_match_is_star {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let Some(file_op_tx) = state.file_op_tx.clone() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if !check_write_rate_limit(&uid) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let path = query.path;
    let current = {
        let file_op_tx = file_op_tx.clone();
        let path = path.clone();
        let uid = uid.clone();
        tokio::task::spawn_blocking(move || {
            request_file_op(&file_op_tx, &uid, "read_file", vec![path])
        })
        .await
    };
    match current {
        Ok(Ok(FileOpValue::Str(existing))) => {
            // The file exists: `If-None-Match: *` must refuse (M-FS-6),
            // `If-Match` must match its current `ETag`.
            if if_none_match_is_star {
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
            if if_match.as_deref() != Some(etag_for(&existing).as_str()) {
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
        }
        Ok(Ok(FileOpValue::Null)) => {
            // The file doesn't exist: `If-Match` can never match (M-FS-6).
            if if_match.is_some() {
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
        }
        Ok(Ok(FileOpValue::Bool(_))) => return StatusCode::NOT_FOUND.into_response(),
        // A refused/failed read for this path -- can't resolve the
        // precondition either way. Fall through to the real write
        // attempt below, whose own authorization decision is the one
        // that actually matters; if that refuses too, it maps to the
        // same `404` as `GET` (M-FS-3).
        Ok(Err(_)) | Err(_) => {}
    }

    let result = tokio::task::spawn_blocking(move || {
        request_file_op(&file_op_tx, &uid, "write_file", vec![path, text])
    })
    .await;
    match result {
        Ok(Ok(FileOpValue::Bool(true))) => StatusCode::NO_CONTENT.into_response(),
        // `write_file` returns `false` for an over-quota write (OBI-137
        // S1), not an authorization refusal -- a distinct status from
        // `404` so a builder can tell "no" from "not allowed".
        Ok(Ok(FileOpValue::Bool(false))) => StatusCode::INSUFFICIENT_STORAGE.into_response(),
        Ok(Ok(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Ok(Err(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(_join_err) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> Option<String> {
    headers.get(name)?.to_str().ok().map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `request_file_op` round-trips through a fake "world thread" that
    /// just echoes the request back -- proves the channel plumbing
    /// itself (queueing, the per-request reply channel) without needing
    /// a real `World`/mudlib boot.
    #[test]
    fn round_trips_through_a_fake_world_thread() {
        let (file_op_tx, file_op_rx) = file_op_channel();
        let worker = std::thread::spawn(move || {
            let req = file_op_rx.recv().expect("a request should arrive");
            assert_eq!(req.efun, "read_file");
            assert_eq!(req.args, vec!["/builders/glorfindel/a.wf".to_string()]);
            let uid = req.uid.clone();
            req.respond(Ok(FileOpValue::Str(format!("hello, {uid}"))));
        });
        let result = request_file_op(
            &file_op_tx,
            "glorfindel",
            "read_file",
            vec!["/builders/glorfindel/a.wf".to_string()],
        );
        worker.join().expect("worker thread");
        assert_eq!(
            result,
            Ok(FileOpValue::Str("hello, glorfindel".to_string()))
        );
    }

    /// If `respond` is never called (e.g. the world thread panicked),
    /// the reply channel just drops -- `request_file_op` must surface
    /// that as an error promptly, not hang.
    #[test]
    fn a_request_never_answered_is_an_error_not_a_hang() {
        let (file_op_tx, file_op_rx) = file_op_channel();
        let worker = std::thread::spawn(move || {
            let req = file_op_rx.recv().expect("a request should arrive");
            drop(req); // never responds
        });
        let result = request_file_op(
            &file_op_tx,
            "glorfindel",
            "read_file",
            vec!["/builders/glorfindel/a.wf".to_string()],
        );
        worker.join().expect("worker thread");
        assert!(result.is_err(), "{result:?}");
    }

    /// Past `FILE_OP_QUEUE_DEPTH` outstanding requests, `try_send` must
    /// fail immediately (M-FS-5's "503 on backpressure") rather than
    /// block the caller.
    #[test]
    fn a_full_queue_fails_fast_instead_of_blocking() {
        let (file_op_tx, _file_op_rx) = std::sync::mpsc::sync_channel::<FileOpRequest>(1);
        let (reply_tx, _reply_rx) = std::sync::mpsc::channel();
        file_op_tx
            .try_send(FileOpRequest {
                uid: "glorfindel".to_string(),
                efun: "read_file",
                args: vec![],
                reply: reply_tx,
            })
            .expect("fill the one slot");
        let (reply_tx2, _reply_rx2) = std::sync::mpsc::channel();
        let err = file_op_tx
            .try_send(FileOpRequest {
                uid: "glorfindel".to_string(),
                efun: "read_file",
                args: vec![],
                reply: reply_tx2,
            })
            .unwrap_err();
        assert!(matches!(err, TrySendError::Full(_)));
    }

    // -----------------------------------------------------------------
    // HTTP wire tests: drive the real `GET /api/v1/files/content` route
    // (axum router + `HttpState`), not just the channel helpers above.
    // -----------------------------------------------------------------
    mod http_wire {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        use super::*;
        use crate::auth::{
            AccessClaims, AuditEvent, DirectoryError, JwtKeys, RefreshRecord, RefreshRotation,
            StaffAuthRecord, StaffAuthStatus, StaffDirectory,
        };
        use crate::{HttpState, app};

        /// `verify_access_token` (the only directory-free path these
        /// tests exercise) never touches the directory, so this fake
        /// only needs to exist, not do anything.
        struct UnusedDirectory;

        #[async_trait::async_trait]
        impl StaffDirectory for UnusedDirectory {
            async fn staff_login(
                &self,
                _username: &str,
                _password: &str,
            ) -> Result<Option<StaffAuthRecord>, DirectoryError> {
                unimplemented!("not exercised by these tests")
            }
            async fn auth_status_for(
                &self,
                _uid: &str,
            ) -> Result<Option<StaffAuthStatus>, DirectoryError> {
                unimplemented!("not exercised by these tests")
            }
            async fn resolve_uid(&self, _username: &str) -> Result<Option<String>, DirectoryError> {
                unimplemented!("not exercised by these tests")
            }
            async fn totp_enroll(
                &self,
                _uid: &str,
                _secret_base32: &str,
            ) -> Result<(), DirectoryError> {
                unimplemented!("not exercised by these tests")
            }
            async fn totp_confirm(&self, _uid: &str) -> Result<(), DirectoryError> {
                unimplemented!("not exercised by these tests")
            }
            async fn totp_secret_for(&self, _uid: &str) -> Result<Option<String>, DirectoryError> {
                unimplemented!("not exercised by these tests")
            }
            async fn totp_consume_step(
                &self,
                _uid: &str,
                _step: u64,
            ) -> Result<bool, DirectoryError> {
                unimplemented!("not exercised by these tests")
            }
            async fn refresh_token_insert(
                &self,
                _uid: &str,
                _token_hash: &str,
                _expires_at: time::OffsetDateTime,
                _sid: &str,
                _amr: &[String],
                _mfa_at: Option<time::OffsetDateTime>,
            ) -> Result<(), DirectoryError> {
                unimplemented!("not exercised by these tests")
            }
            async fn refresh_token_lookup(
                &self,
                _token_hash: &str,
            ) -> Result<Option<RefreshRecord>, DirectoryError> {
                unimplemented!("not exercised by these tests")
            }
            async fn refresh_token_rotate(
                &self,
                _token_hash: &str,
            ) -> Result<RefreshRotation, DirectoryError> {
                unimplemented!("not exercised by these tests")
            }
            async fn refresh_token_revoke(&self, _token_hash: &str) -> Result<(), DirectoryError> {
                unimplemented!("not exercised by these tests")
            }
            async fn refresh_token_revoke_all(&self, _uid: &str) -> Result<(), DirectoryError> {
                unimplemented!("not exercised by these tests")
            }
            async fn github_lookup(
                &self,
                _github_id: i64,
            ) -> Result<Option<String>, DirectoryError> {
                unimplemented!("not exercised by these tests")
            }
            async fn record_audit(&self, _event: AuditEvent) -> Result<(), DirectoryError> {
                unimplemented!("not exercised by these tests")
            }
        }

        fn keys() -> JwtKeys {
            JwtKeys::single(
                [7u8; 32],
                "test-kid",
                "https://build.loommud.test/",
                "loom-staff",
            )
        }

        fn bearer_for(uid: &str, keys: &JwtKeys) -> String {
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let claims = AccessClaims {
                sub: uid.to_string(),
                tier: 1,
                scopes: vec!["builder".to_string()],
                iss: keys.issuer().to_string(),
                aud: keys.audience().to_string(),
                iat: now,
                nbf: now,
                exp: now + 300,
                sid: "test-sid".to_string(),
                amr: vec!["pwd".to_string()],
                mfa_at: None,
            };
            keys.encode(&claims).expect("encode a test token")
        }

        fn test_state(file_op_tx: Option<FileOpSender>) -> (HttpState, JwtKeys) {
            let (ws_accept_tx, _ws_accept_rx) = tokio::sync::mpsc::channel(1);
            let keys = keys();
            let mut state = HttpState::new(
                ws_accept_tx,
                loom_obs::Readiness::new(),
                loom_obs::PrometheusMetrics::new_unregistered(),
            )
            .with_auth(crate::auth::AuthService::new(
                std::sync::Arc::new(UnusedDirectory),
                keys.clone(),
            ));
            if let Some(tx) = file_op_tx {
                state = state.with_file_ops(tx);
            }
            (state, keys)
        }

        #[tokio::test]
        async fn no_bearer_token_is_401() {
            let (state, _keys) = test_state(None);
            let response = app(state)
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/files/content?path=/builders/frodo/a.wf")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn no_file_op_channel_wired_is_503() {
            let (state, keys) = test_state(None);
            let token = bearer_for("frodo", &keys);
            let response = app(state)
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/files/content?path=/builders/frodo/a.wf")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }

        #[tokio::test]
        async fn a_readable_file_is_200_with_m_fs_4_headers() {
            let (file_op_tx, file_op_rx) = file_op_channel();
            std::thread::spawn(move || {
                let req = file_op_rx.recv().expect("a request should arrive");
                assert_eq!(req.uid, "frodo");
                assert_eq!(req.efun, "read_file");
                req.respond(Ok(FileOpValue::Str("int x;".to_string())));
            });
            let (state, keys) = test_state(Some(file_op_tx));
            let token = bearer_for("frodo", &keys);
            let response = app(state)
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/files/content?path=/builders/frodo/a.wf")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let headers = response.headers().clone();
            assert_eq!(
                headers.get(header::CONTENT_TYPE).unwrap(),
                "text/plain; charset=utf-8"
            );
            assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
            assert_eq!(
                headers.get(header::CONTENT_SECURITY_POLICY).unwrap(),
                "sandbox"
            );
            assert_eq!(
                headers.get(header::CONTENT_DISPOSITION).unwrap(),
                "attachment"
            );
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], b"int x;");
        }

        /// M-FS-3: a refused path (the fake world thread answers `Err`,
        /// standing in for `valid_read` refusing it) is `404`, exactly
        /// like a path that doesn't exist -- never `403`.
        #[tokio::test]
        async fn a_refused_path_is_404_not_403() {
            let (file_op_tx, file_op_rx) = file_op_channel();
            std::thread::spawn(move || {
                let req = file_op_rx.recv().expect("a request should arrive");
                req.respond(Err("valid_read refused /secure/master.wf".to_string()));
            });
            let (state, keys) = test_state(Some(file_op_tx));
            let token = bearer_for("frodo", &keys);
            let response = app(state)
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/files/content?path=/secure/master.wf")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        /// A path that authorizes fine but doesn't exist (`read_file`
        /// returns `Null`) is also `404` -- same status as a refusal,
        /// never distinguishable from the outside (M-FS-3).
        #[tokio::test]
        async fn a_missing_file_is_404() {
            let (file_op_tx, file_op_rx) = file_op_channel();
            std::thread::spawn(move || {
                let req = file_op_rx.recv().expect("a request should arrive");
                req.respond(Ok(FileOpValue::Null));
            });
            let (state, keys) = test_state(Some(file_op_tx));
            let token = bearer_for("frodo", &keys);
            let response = app(state)
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/files/content?path=/builders/frodo/missing.wf")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        // -------------------------------------------------------------
        // PUT /api/v1/files/content (M-FS-1/M-FS-6/M-FS-7)
        // -------------------------------------------------------------

        fn put_request(uid_path: &str, token: &str, body: &'static str) -> Request<Body> {
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/files/content?path={uid_path}"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(body))
                .unwrap()
        }

        #[tokio::test]
        async fn create_with_if_none_match_star_succeeds_when_the_file_is_absent() {
            let (file_op_tx, file_op_rx) = file_op_channel();
            std::thread::spawn(move || {
                let read = file_op_rx.recv().expect("read request");
                assert_eq!(read.efun, "read_file");
                read.respond(Ok(FileOpValue::Null));
                let write = file_op_rx.recv().expect("write request");
                assert_eq!(write.efun, "write_file");
                assert_eq!(write.args[1], "int x;");
                write.respond(Ok(FileOpValue::Bool(true)));
            });
            let (state, keys) = test_state(Some(file_op_tx));
            let token = bearer_for("pippin", &keys);
            let mut request = put_request("/builders/pippin/new.wf", &token, "int x;");
            request
                .headers_mut()
                .insert("if-none-match", HeaderValue::from_static("*"));
            let response = app(state).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }

        #[tokio::test]
        async fn create_with_if_none_match_star_is_412_when_the_file_already_exists() {
            let (file_op_tx, file_op_rx) = file_op_channel();
            std::thread::spawn(move || {
                let read = file_op_rx.recv().expect("read request");
                read.respond(Ok(FileOpValue::Str("already here".to_string())));
                // No write should ever be requested.
            });
            let (state, keys) = test_state(Some(file_op_tx));
            let token = bearer_for("merry", &keys);
            let mut request = put_request("/builders/merry/exists.wf", &token, "int x;");
            request
                .headers_mut()
                .insert("if-none-match", HeaderValue::from_static("*"));
            let response = app(state).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
        }

        #[tokio::test]
        async fn update_with_a_matching_if_match_succeeds() {
            let (file_op_tx, file_op_rx) = file_op_channel();
            std::thread::spawn(move || {
                let read = file_op_rx.recv().expect("read request");
                read.respond(Ok(FileOpValue::Str("old contents".to_string())));
                let write = file_op_rx.recv().expect("write request");
                write.respond(Ok(FileOpValue::Bool(true)));
            });
            let (state, keys) = test_state(Some(file_op_tx));
            let token = bearer_for("sam", &keys);
            let etag = etag_for("old contents");
            let mut request = put_request("/builders/sam/a.wf", &token, "new contents");
            request
                .headers_mut()
                .insert("if-match", HeaderValue::from_str(&etag).unwrap());
            let response = app(state).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }

        #[tokio::test]
        async fn update_with_a_stale_if_match_is_412() {
            let (file_op_tx, file_op_rx) = file_op_channel();
            std::thread::spawn(move || {
                let read = file_op_rx.recv().expect("read request");
                read.respond(Ok(FileOpValue::Str("current contents".to_string())));
            });
            let (state, keys) = test_state(Some(file_op_tx));
            let token = bearer_for("rosie", &keys);
            let mut request = put_request("/builders/rosie/a.wf", &token, "new contents");
            request.headers_mut().insert(
                "if-match",
                HeaderValue::from_static(
                    "\"0000000000000000000000000000000000000000000000000000000000000000\"",
                ),
            );
            let response = app(state).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
        }

        #[tokio::test]
        async fn missing_precondition_headers_is_400() {
            let (state, keys) = test_state(None);
            let token = bearer_for("bilbo", &keys);
            let request = put_request("/builders/bilbo/a.wf", &token, "text");
            let response = app(state).oneshot(request).await.unwrap();
            // No file-op channel wired either, but the precondition check
            // runs before any channel use, so this is 400, not 503.
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn a_body_over_the_cap_is_413() {
            let (file_op_tx, _file_op_rx) = file_op_channel();
            let (state, keys) = test_state(Some(file_op_tx));
            let token = bearer_for("farmer-maggot", &keys);
            let oversized = vec![b'x'; MAX_WRITE_BODY_BYTES + 1];
            let mut request = Request::builder()
                .method("PUT")
                .uri("/api/v1/files/content?path=/builders/farmer-maggot/a.wf")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(oversized))
                .unwrap();
            request
                .headers_mut()
                .insert("if-none-match", HeaderValue::from_static("*"));
            let response = app(state).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        }

        #[tokio::test]
        async fn no_bearer_token_is_401_for_put_too() {
            let (state, _keys) = test_state(None);
            let response = app(state)
                .oneshot(put_request(
                    "/builders/frodo/a.wf",
                    "not-a-real-token",
                    "text",
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }
}
