// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `/api/v1/files/*` (OBI-180): read-through to `World::call_file_efun`/
//! `World::call_file_write_if_match` (M-FS-1), without `loom-http` ever
//! depending on `loom-vm` directly.
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
//! [`FileOpValue`]/[`FilePrecondition`] intentionally hold no `loom_vm`
//! type (paths/text are plain `String`s) so this module adds no new
//! dependency edge; the `loom_vm` conversions (`Value` <-> [`FileOpValue`]
//! for a read, `FileCasOutcome` <-> [`FileOpValue`] for a write,
//! [`FilePrecondition`] <-> `loom_vm::world::FileMatchPrecondition`) stay
//! in `loom-cli`, right next to the `World` calls that produce/consume
//! them.
//!
//! ## Why `PUT` is one round trip through the channel, not two
//!
//! An earlier cut of this module sent a `read_file` request to compute
//! the current `ETag`, then -- as a *separate* channel round trip -- a
//! `write_file` request. The world thread drains the channel one request
//! at a time, so another `PUT`, or LPC code calling `write_file` directly,
//! could land between those two round trips and invalidate the
//! precondition this handler had just checked (a lost update, exactly
//! what M-FS-6 exists to prevent; CTO review on this PR, must-fix 1).
//! [`FileOpKind::WriteIfMatch`] sends the precondition down in the *same*
//! request as the new text, so `loom_vm::World::call_file_write_if_match`
//! can do the read, the compare, and the write inside one atomic
//! world-thread `exec` call -- nothing can interleave inside that.
//!
//! ## What this module does *not* do yet
//!
//! Listings (M-FS-3's "filtered by `valid_read`") and `compile_object`
//! are a later slice -- [`FileOpValue`] would need a richer shape for
//! `compile_object`'s diagnostics list. M-FS-5's "one in-flight compile
//! per uid" clause is also deferred to that slice (there is no compile to
//! serialize yet).
//!
//! ## API notes (CTO re-review on OBI-180, `4e65f1a`; record in client docs)
//!
//! - **`PUT` needs read permission too.** CAS reads the current `ETag`
//!   before it writes, so a uid with `valid_write` but no `valid_read`
//!   on a path gets `404` on `PUT`, same as a plain `GET` would. That is
//!   the correct fail-closed behaviour (M-FS-3), not a bug -- clients
//!   should not assume write access alone is enough to `PUT`.
//! - **A `503` doesn't mean the write didn't land.** A timeout after the
//!   request was already enqueued can still commit on the world-thread
//!   side; the client just never saw the `200`. CAS makes a retry safe:
//!   replaying the same `If-Match` after a `503` gets `412` (not a lost
//!   update) if the first attempt actually committed. Clients should
//!   re-`GET` for the current `ETag` on a `412` that follows a `503`,
//!   rather than assuming the retry itself failed.
//! - **`Refused` also covers I/O errors, not just permission denials.**
//!   A `fileio` error (and tick exhaustion) maps to the same
//!   [`FileOpError::Refused`] as a `valid_read`/`valid_write` denial, and
//!   both come back as the same `404` (M-FS-3: a refusal must look
//!   exactly like "not found", so it can't be used to probe which files
//!   exist). If callers ever need to tell an I/O failure apart from a
//!   permission denial, that needs a new `Internal` variant mapped to
//!   `500` and logged server-side only -- today they are indistinguishable
//!   on the wire by design.

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use serde::{Deserialize, Serialize};
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

/// A `read_file`/CAS-`write_file` result, far enough from `loom_vm`
/// types (`Value` holds `Rc`s and so is not `Send`) to cross the file-op
/// reply channel into an async HTTP handler's thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileOpValue {
    /// `read_file` found nothing at this path.
    Null,
    /// `read_file`'s contents.
    Str(String),
    /// [`FileOpKind::WriteIfMatch`]'s precondition held and the write
    /// happened.
    Written,
    /// [`FileOpKind::WriteIfMatch`]'s precondition held but `write_file`
    /// itself refused for disk quota (OBI-137 S1), not authorization.
    QuotaExceeded,
    /// [`FileOpKind::WriteIfMatch`]'s precondition did not hold (stale
    /// `If-Match`, or `If-None-Match: *` against an existing file).
    PreconditionFailed,
    /// [`FileOpKind::List`]'s directory listing, filtered by
    /// `valid_read` (M-FS-3). Distinct from `Null` (a readable directory
    /// can legitimately be empty) -- an unreadable or missing directory
    /// is a [`FileOpError::Refused`] from `World::list_dir`'s `None`,
    /// mapped the same place `read_file`'s own `Null` is. `truncated` is
    /// `World::MAX_LIST_ENTRIES`-truncation (CTO review on PR #117,
    /// should-fix 1), carried through to the JSON response body.
    Entries { names: Vec<String>, truncated: bool },
    /// [`FileOpKind::Compile`] ran `compile_object` and it succeeded
    /// (spec §7.2 step 6.4: per-object migration warnings, if any, are
    /// not fatal and are not surfaced here -- OBI-34 tracks a real
    /// builder-facing channel for those; this is only the top-level
    /// compile-failed/compile-succeeded distinction).
    CompileOk,
    /// [`FileOpKind::Compile`] ran `compile_object` and the compiler
    /// produced diagnostics (parse/semantic errors) -- not a driver
    /// refusal, so unlike [`FileOpError::Refused`] this is reported to
    /// the client verbatim (M-IDE's "see a diagnostic, fix it" flow
    /// needs the real compiler message).
    CompileFailed(String),
}

/// Which `World` entry point a [`FileOpRequest`] resolves to.
#[derive(Debug, Clone)]
pub enum FileOpKind {
    /// `World::call_file_efun(uid, "read_file", ..)`.
    Read,
    /// `World::call_file_write_if_match(uid, path, precondition, text,
    /// ..)` -- one atomic round trip, see this module's doc for why.
    WriteIfMatch {
        precondition: FilePrecondition,
        text: String,
    },
    /// `World::list_dir(uid, path, ..)` (M-FS-3).
    List,
    /// `World::call_file_efun(uid, "compile_object", ..)` (M-FS-5's "one
    /// in-flight compile per uid, newest save wins" -- enforced by
    /// [`CompileInFlight`] at the HTTP layer, not here).
    Compile,
}

/// Mirrors `loom_vm::world::FileMatchPrecondition` without depending on
/// `loom-vm` (see this module's doc). `loom-cli`'s drain loop converts
/// one into the other right before calling `World`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilePrecondition {
    /// `If-Match: "<etag>"`, already unquoted.
    IfMatch(String),
    /// `If-None-Match: *`.
    IfNoneMatchStar,
}

/// Why a [`FileOpRequest`] didn't get an answer, or got a refusal,
/// distinguished so handlers can tell M-FS-5's backpressure/timeout
/// (`503`) apart from M-FS-3's authorization/not-found refusal (`404`)
/// -- both used to collapse into the same untyped `String` error (CTO
/// review must-fix 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileOpError {
    /// [`FileOpSender::try_send`] found the queue full (M-FS-5 "503 on
    /// backpressure").
    Busy,
    /// The world thread didn't answer within [`FILE_OP_REQUEST_TIMEOUT`]
    /// (M-FS-5 "10 s timeout").
    Timeout,
    /// The world thread's receiver is gone (shutting down).
    Closed,
    /// The world thread ran the request and refused it: `valid_read`/
    /// `valid_write` said no, a reserved principal, or (for `GET`/`PUT`
    /// on `/api/v1/files/content`, which fail closed through `authorize`)
    /// an I/O error. Carries the message for logging only -- HTTP
    /// handlers never echo it to the client (M-FS-3: a refusal looks
    /// exactly like "not found").
    Refused(String),
    /// A `valid_read`/`valid_write` apply itself threw or exhausted its
    /// tick budget, or an unexpected `fileio` I/O error distinct from
    /// the normal "missing" case -- currently only `World::list_dir`
    /// produces this (`loom_vm::world::ListDirError::Internal`). Mapped
    /// to `503`, the same split `loom_http::admin_query::
    /// WorldQueryError::Internal` already draws for the admin endpoints
    /// (OBI-279): a `valid_read` that can't produce a real decision must
    /// never look like a (possibly truncated) successful listing or a
    /// plain `Refused`.
    Internal(String),
}

/// One file operation requested by an `/api/v1/files/*` HTTP handler
/// (M-FS-1). The reply channel is a fresh one-shot `std::sync::mpsc` per
/// request.
pub struct FileOpRequest {
    pub uid: String,
    pub path: String,
    pub kind: FileOpKind,
    reply: std::sync::mpsc::Sender<Result<FileOpValue, FileOpError>>,
}

impl FileOpRequest {
    /// The world-thread side's only way to answer a request -- consumes
    /// `self` so a drain loop can't accidentally reply twice or forget
    /// to. A dropped (never-called) `respond` surfaces to the waiting
    /// HTTP-side thread as a `recv` error, mapped to [`FileOpError::
    /// Timeout`] (see [`request_file_op`]'s doc) rather than a hang.
    pub fn respond(self, result: Result<FileOpValue, FileOpError>) {
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

/// Ask the world thread to run `kind` against `path` with guard set
/// exactly `{uid}` (M-FS-1), blocking this call's own thread until it
/// answers or [`FILE_OP_REQUEST_TIMEOUT`] elapses (M-FS-5).
///
/// **Never call this from an async task directly** -- it blocks a real
/// OS thread for up to 10s. Callers in this module always wrap it in
/// `tokio::task::spawn_blocking`.
pub fn request_file_op(
    file_op_tx: &FileOpSender,
    uid: &str,
    path: &str,
    kind: FileOpKind,
) -> Result<FileOpValue, FileOpError> {
    let (reply_tx, reply_rx) = std::sync::mpsc::channel();
    match file_op_tx.try_send(FileOpRequest {
        uid: uid.to_string(),
        path: path.to_string(),
        kind,
        reply: reply_tx,
    }) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => return Err(FileOpError::Busy),
        Err(TrySendError::Disconnected(_)) => return Err(FileOpError::Closed),
    }
    reply_rx
        .recv_timeout(FILE_OP_REQUEST_TIMEOUT)
        .unwrap_or(Err(FileOpError::Timeout))
}

/// Maps backpressure/timeout/shutdown to `503` and a world-thread refusal
/// to `404` (CTO review must-fix 3) -- the one place both `GET` and `PUT`
/// make that decision, so they can't drift apart.
fn status_for_file_op_error(err: &FileOpError) -> StatusCode {
    match err {
        FileOpError::Busy
        | FileOpError::Timeout
        | FileOpError::Closed
        | FileOpError::Internal(_) => StatusCode::SERVICE_UNAVAILABLE,
        FileOpError::Refused(_) => StatusCode::NOT_FOUND,
    }
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
    Router::new()
        .route(
            "/api/v1/files/content",
            get(read_file)
                .put(write_file)
                .route_layer(DefaultBodyLimit::max(MAX_WRITE_BODY_BYTES)),
        )
        .route("/api/v1/files/list", get(list_dir))
        .route("/api/v1/files/compile", axum::routing::post(compile_object))
}

/// `GET /api/v1/files/content?path=/builders/<u>/...` (M-FS-1).
///
/// - `401` with no/invalid bearer token.
/// - `404` for a path `valid_read` refuses *or* that doesn't exist --
///   deliberately the same status for both (M-FS-3): a 403 would tell an
///   unauthorised caller a path exists.
/// - `503` on a full queue, a world thread that didn't answer in time,
///   or no file-op channel wired at all (M-FS-5), never a hang.
/// - `200` with `Content-Type: text/plain; charset=utf-8`,
///   `X-Content-Type-Options: nosniff`, a sandboxed `Content-Security-
///   Policy`, `Content-Disposition: attachment`, and an `ETag` (M-FS-4/
///   M-FS-6 -- a client needs this to build a later `If-Match`) -- the
///   MIME type is never derived from the path's extension.
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
        request_file_op(&file_op_tx, &uid, &path, FileOpKind::Read)
    })
    .await;
    match result {
        Ok(Ok(FileOpValue::Str(contents))) => file_response(contents),
        Ok(Ok(FileOpValue::Null)) => StatusCode::NOT_FOUND.into_response(),
        // `read_file` never produces these -- a driver bug, not a
        // client-facing distinction.
        Ok(Ok(
            FileOpValue::Written
            | FileOpValue::QuotaExceeded
            | FileOpValue::PreconditionFailed
            | FileOpValue::Entries { .. }
            | FileOpValue::CompileOk
            | FileOpValue::CompileFailed(_),
        )) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Ok(Err(err)) => status_for_file_op_error(&err).into_response(),
        Err(_join_err) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

/// M-FS-4's exact response shape for a successful read: `text/plain`,
/// `nosniff`, a sandboxed CSP with `default-src 'none'` (CTO review
/// must-fix 5), `attachment` disposition so a browser navigating here
/// directly never renders the body as HTML, and an `ETag` (CTO review
/// must-fix 4) so a later `PUT` can build `If-Match` without re-hashing
/// bytes the client already has another way.
fn file_response(contents: String) -> axum::response::Response {
    let etag = etag_for(&contents);
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
        HeaderValue::from_static("sandbox; default-src 'none'"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment"),
    );
    if let Ok(value) = HeaderValue::from_str(&etag) {
        headers.insert(header::ETAG, value);
    }
    response
}

/// A strong `ETag` over a file's exact byte contents (M-FS-6):
/// `sha256(contents)`, hex-encoded, quoted per RFC 9110 S8.8.3.
/// Deliberately duplicated in `loom_vm::world::file_etag_hex` rather than
/// shared across the crate boundary -- see this module's top doc for why
/// `loom-http` stays `loom-vm`-free. Both sides must still agree
/// byte-for-byte; a unit test on each side pins the same fixture string
/// to the same digest.
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

/// Bound on distinct uids tracked by a [`WriteRateLimiter`] (OBI-204
/// hygiene, same shape as `auth::ratelimit`'s caps): past this many
/// tracked buckets, the oldest-touched ones are evicted rather than
/// letting an unbounded number of distinct uids grow the map forever.
/// Staff uid counts are nowhere near this in practice.
const MAX_TRACKED_WRITE_UIDS: usize = 10_000;

/// Per-uid write token bucket (M-FS-5's "per-uid write rate limit"):
/// `WRITE_BUCKET_CAPACITY` burst, refilling at one token per
/// `WRITE_BUCKET_REFILL_INTERVAL`. First cut for Phase 2 -- numbers are a
/// starting point, not yet tuned against real builder workflows; revisit
/// with the CTO once there's usage data, the same caveat
/// `scopes_for_tier` carries.
const WRITE_BUCKET_CAPACITY: f64 = 20.0;
const WRITE_BUCKET_REFILL_INTERVAL: Duration = Duration::from_secs(2);

pub(crate) struct WriteBucket {
    tokens: f64,
    last_refill: Instant,
}

/// Per-[`HttpState`] write-rate-limiter state (CTO review non-blocking
/// item: this used to be a process-global `static`, which meant every
/// `HttpState` in the same process -- notably every test -- shared one
/// set of buckets). `HttpState::new` creates a fresh, empty one via
/// [`new_write_rate_limiter`]; `Arc` so `HttpState`'s `#[derive(Clone)]`
/// (one clone per request, axum's usual `State` extraction) shares the
/// same buckets rather than resetting them per clone.
pub(crate) type WriteRateLimiter = Arc<Mutex<HashMap<String, WriteBucket>>>;

/// A fresh, empty rate-limiter state for [`HttpState::new`].
pub(crate) fn new_write_rate_limiter() -> WriteRateLimiter {
    Arc::new(Mutex::new(HashMap::new()))
}

/// `true` if `uid` may write now (and consumes one token if so); `false`
/// if its bucket is empty (M-FS-5 -- caller answers `429`).
fn check_write_rate_limit(limiter: &WriteRateLimiter, uid: &str) -> bool {
    let mut map = limiter.lock().expect("write rate limiter mutex poisoned");
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
/// already exist) is required on every request. The whole read-compare-
/// write happens as **one** atomic world-thread operation (see this
/// module's top doc) -- there is no window between checking the
/// precondition and acting on it.
///
/// - `401` no/invalid bearer token.
/// - `400` body isn't valid UTF-8, or neither/both precondition headers
///   given, or `If-None-Match` is present but isn't exactly `*`.
/// - `413` body over [`MAX_WRITE_BODY_BYTES`] (enforced twice: axum's
///   `DefaultBodyLimit` layer on the route, and a belt-and-suspenders
///   check here).
/// - `429` the uid's write rate limit is exhausted (M-FS-5).
/// - `412` the precondition didn't hold: `If-Match` didn't match the
///   file's current `ETag`, or `If-None-Match: *` was sent but the file
///   already exists.
/// - `404` the path doesn't authorize for this uid, or the read half of
///   the CAS failed for any other reason (M-FS-3, same not-found-shaped
///   refusal as `GET` -- never a fail-open fall-through to an
///   unconditional write).
/// - `503` no file-op channel wired, a full queue, or a world-thread
///   timeout (M-FS-5).
/// - `204` success. The write itself is already audited with the real
///   actor uid by the existing `write_file` efun path (M-FS-7) -- this
///   handler adds no second audit trail.
/// - `507` the precondition held but `write_file` itself refused for
///   disk quota (OBI-137 S1), not authorization -- distinct from `404`
///   so a builder can tell "no" from "not allowed".
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
    let precondition = if if_none_match_is_star {
        FilePrecondition::IfNoneMatchStar
    } else {
        FilePrecondition::IfMatch(
            if_match
                .expect("checked above: exactly one of if_match/if_none_match_is_star is set")
                .trim_matches('"')
                .to_string(),
        )
    };

    let Some(file_op_tx) = state.file_op_tx.clone() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if !check_write_rate_limit(&state.write_rate_limiter, &uid) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let path = query.path;
    let result = tokio::task::spawn_blocking(move || {
        request_file_op(
            &file_op_tx,
            &uid,
            &path,
            FileOpKind::WriteIfMatch { precondition, text },
        )
    })
    .await;
    match result {
        Ok(Ok(FileOpValue::Written)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(FileOpValue::QuotaExceeded)) => StatusCode::INSUFFICIENT_STORAGE.into_response(),
        Ok(Ok(FileOpValue::PreconditionFailed)) => StatusCode::PRECONDITION_FAILED.into_response(),
        // A CAS write never produces these -- a driver bug, not a
        // client-facing distinction.
        Ok(Ok(
            FileOpValue::Null
            | FileOpValue::Str(_)
            | FileOpValue::Entries { .. }
            | FileOpValue::CompileOk
            | FileOpValue::CompileFailed(_),
        )) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Ok(Err(err)) => status_for_file_op_error(&err).into_response(),
        Err(_join_err) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> Option<String> {
    headers.get(name)?.to_str().ok().map(|s| s.to_string())
}

#[derive(Debug, Deserialize)]
pub struct ListDirQuery {
    path: String,
}

#[derive(Debug, Serialize)]
struct ListDirResponse {
    entries: Vec<String>,
    /// `true` if the real directory had more than `World::
    /// MAX_LIST_ENTRIES` entries (CTO review on PR #117, should-fix 1):
    /// `entries` is the sorted-by-name prefix, never silently a
    /// different (e.g. random) subset.
    truncated: bool,
}

/// `GET /api/v1/files/list?path=/builders/<u>/...` (M-FS-3).
///
/// - `401` with no/invalid bearer token.
/// - `404` for a directory `valid_read` refuses on the directory itself
///   *or* that doesn't exist -- same status for both, same reasoning as
///   `GET /api/v1/files/content`'s `404` (M-FS-3: a 403 would tell an
///   unauthorised caller the directory exists).
/// - `503` on a full queue, a world thread that didn't answer in time,
///   or no file-op channel wired at all (M-FS-5).
/// - `200` with a JSON `{"entries": [...], "truncated": bool}` body --
///   `World::list_dir` has already dropped any individual entry
///   `valid_read` refuses, so every name in the response is one this
///   uid may also `GET`; `truncated` is `true` if the real directory had
///   more than `World::MAX_LIST_ENTRIES` entries. `Content-Type:
///   application/json`, `nosniff`, and the same sandboxed CSP as a file
///   read (M-FS-4).
async fn list_dir(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<ListDirQuery>,
) -> impl IntoResponse {
    let Some(uid) = bearer_uid(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(file_op_tx) = state.file_op_tx.clone() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let path = query.path;
    let result = tokio::task::spawn_blocking(move || {
        request_file_op(&file_op_tx, &uid, &path, FileOpKind::List)
    })
    .await;
    match result {
        Ok(Ok(FileOpValue::Entries { names, truncated })) => list_dir_response(names, truncated),
        // `World::list_dir` reports a refused/missing directory as a
        // `FileOpError::Refused` (loom-cli's drain loop maps its `None`
        // there), not an `Ok` -- these never happen, but are not a
        // client-facing distinction if the driver side ever changes.
        Ok(Ok(
            FileOpValue::Null
            | FileOpValue::Str(_)
            | FileOpValue::Written
            | FileOpValue::QuotaExceeded
            | FileOpValue::PreconditionFailed
            | FileOpValue::CompileOk
            | FileOpValue::CompileFailed(_),
        )) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Ok(Err(err)) => status_for_file_op_error(&err).into_response(),
        Err(_join_err) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

/// M-FS-4's response shape for a listing: JSON, `nosniff`, the same
/// sandboxed CSP as a file read. No `Content-Disposition: attachment` --
/// that header is specifically for `GET /api/v1/files/content`'s raw
/// file bodies (M-FS-4 names it for "raw bodies"), not a JSON API
/// response, which axum's `Json` already sends as `application/json`,
/// never sniffable as HTML regardless.
fn list_dir_response(entries: Vec<String>, truncated: bool) -> axum::response::Response {
    let mut response = (
        StatusCode::OK,
        axum::Json(ListDirResponse { entries, truncated }),
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox; default-src 'none'"),
    );
    response
}

/// Per-[`HttpState`] generation counter for M-FS-5's "one in-flight
/// compile per uid (newest save wins)": each uid has one counter, bumped
/// every time a compile request for that uid starts. A request only
/// gets to answer the client if its own token is still the latest one
/// recorded for that uid by the time the compile finishes -- a request
/// superseded by a newer one for the same uid (the common case: a
/// builder saves again before the first compile returns) answers `409`
/// instead of a possibly-stale result, so the client never has to guess
/// which of two overlapping responses is the current one. This does not
/// cancel the superseded compile's world-thread work (there is no
/// cancellation hook into a `World::exec` already running) -- it only
/// suppresses that response, same bounded scope as the rest of this
/// slice.
pub(crate) type CompileInFlight = Arc<Mutex<HashMap<String, u64>>>;

/// Bound on distinct uids tracked by a [`CompileInFlight`] map, same
/// reasoning and cap as [`MAX_TRACKED_WRITE_UIDS`].
const MAX_TRACKED_COMPILE_UIDS: usize = 10_000;

/// A fresh, empty compile-in-flight tracker for [`HttpState::new`].
pub(crate) fn new_compile_in_flight() -> CompileInFlight {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Claim the next generation token for `uid`, evicting an arbitrary
/// tracked uid first if the map is at [`MAX_TRACKED_COMPILE_UIDS`] and
/// `uid` isn't already tracked (same bounded-map shape as
/// [`check_write_rate_limit`]).
fn claim_compile_token(tracker: &CompileInFlight, uid: &str) -> u64 {
    let mut map = tracker.lock().expect("compile-in-flight mutex poisoned");
    if map.len() >= MAX_TRACKED_COMPILE_UIDS
        && !map.contains_key(uid)
        && let Some(oldest) = map.keys().next().cloned()
    {
        map.remove(&oldest);
    }
    let entry = map.entry(uid.to_string()).or_insert(0);
    *entry += 1;
    *entry
}

/// `true` if `token` is still the latest one claimed for `uid` -- i.e.
/// this request was not superseded by a newer compile for the same uid
/// while it was running.
fn compile_token_is_current(tracker: &CompileInFlight, uid: &str, token: u64) -> bool {
    let map = tracker.lock().expect("compile-in-flight mutex poisoned");
    map.get(uid) == Some(&token)
}

#[derive(Debug, Deserialize)]
pub struct CompileQuery {
    path: String,
}

#[derive(Debug, Serialize)]
struct CompileResponse {
    ok: bool,
    /// Present (non-empty) only when `ok` is `false`: the compiler's own
    /// diagnostics text, verbatim (M-IDE "see a diagnostic, fix it").
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostics: Option<String>,
}

fn compile_response(ok: bool, diagnostics: Option<String>) -> axum::response::Response {
    let mut response = (
        StatusCode::OK,
        axum::Json(CompileResponse { ok, diagnostics }),
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox; default-src 'none'"),
    );
    response
}

/// `POST /api/v1/files/compile?path=...` (M-FS-1/M-FS-5/M-FS-7):
/// `World::call_file_efun(uid, "compile_object", [path], ..)`, going
/// through the exact same `authorize()` (`Privilege::P1`,
/// `Operation::Compile`) and audit path a `compile_object()` LPC call
/// gets -- this handler adds no second permission check.
///
/// - `401` no/invalid bearer token.
/// - `429` the uid's write rate limit is exhausted -- compiling is
///   shared with [`check_write_rate_limit`]'s bucket (M-FS-5): a compile
///   is at least as expensive as a write, and in practice always follows
///   one.
/// - `409` this request was superseded by a newer `/compile` call for
///   the same uid before it got to answer (M-FS-5 "one in-flight compile
///   per uid, newest save wins") -- the client should trust the newer
///   request's response instead.
/// - `404` `path` doesn't authorize (`Privilege::P1`'s `valid_write`-
///   style confinement) for this uid, same not-found-shaped refusal as
///   `GET`/`PUT` (M-FS-3).
/// - `503` no file-op channel wired, a full queue, or a world-thread
///   timeout (M-FS-5).
/// - `200` `{"ok": true}` on a clean compile, or `{"ok": false,
///   "diagnostics": "..."}` when the compiler produced diagnostics --
///   deliberately still `200`, not a `4xx`/`5xx`: the HTTP request
///   itself succeeded, the *compile* just found errors, the same
///   distinction a `200` `GET` makes for a file that happens to contain
///   broken LPC.
async fn compile_object(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<CompileQuery>,
) -> impl IntoResponse {
    let Some(uid) = bearer_uid(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(file_op_tx) = state.file_op_tx.clone() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if !check_write_rate_limit(&state.write_rate_limiter, &uid) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let token = claim_compile_token(&state.compile_in_flight, &uid);
    let path = query.path;
    let compile_uid = uid.clone();
    let result = tokio::task::spawn_blocking(move || {
        request_file_op(&file_op_tx, &compile_uid, &path, FileOpKind::Compile)
    })
    .await;
    if !compile_token_is_current(&state.compile_in_flight, &uid, token) {
        return StatusCode::CONFLICT.into_response();
    }
    match result {
        Ok(Ok(FileOpValue::CompileOk)) => compile_response(true, None),
        Ok(Ok(FileOpValue::CompileFailed(diagnostics))) => {
            compile_response(false, Some(diagnostics))
        }
        // `compile_object` never produces these -- a driver bug, not a
        // client-facing distinction.
        Ok(Ok(
            FileOpValue::Null
            | FileOpValue::Str(_)
            | FileOpValue::Written
            | FileOpValue::QuotaExceeded
            | FileOpValue::PreconditionFailed
            | FileOpValue::Entries { .. },
        )) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Ok(Err(err)) => status_for_file_op_error(&err).into_response(),
        Err(_join_err) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
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
            assert!(matches!(req.kind, FileOpKind::Read));
            assert_eq!(req.path, "/builders/glorfindel/a.wf");
            let uid = req.uid.clone();
            req.respond(Ok(FileOpValue::Str(format!("hello, {uid}"))));
        });
        let result = request_file_op(
            &file_op_tx,
            "glorfindel",
            "/builders/glorfindel/a.wf",
            FileOpKind::Read,
        );
        worker.join().expect("worker thread");
        assert_eq!(
            result,
            Ok(FileOpValue::Str("hello, glorfindel".to_string()))
        );
    }

    /// If `respond` is never called (e.g. the world thread panicked),
    /// the reply channel just drops -- `request_file_op` must surface
    /// that promptly as [`FileOpError::Timeout`], not hang.
    #[test]
    fn a_request_never_answered_is_a_timeout_not_a_hang() {
        let (file_op_tx, file_op_rx) = file_op_channel();
        let worker = std::thread::spawn(move || {
            let req = file_op_rx.recv().expect("a request should arrive");
            drop(req); // never responds
        });
        let result = request_file_op(
            &file_op_tx,
            "glorfindel",
            "/builders/glorfindel/a.wf",
            FileOpKind::Read,
        );
        worker.join().expect("worker thread");
        assert_eq!(result, Err(FileOpError::Timeout));
    }

    /// Past `FILE_OP_QUEUE_DEPTH` outstanding requests, `try_send` must
    /// fail immediately with [`FileOpError::Busy`] (M-FS-5's "503 on
    /// backpressure") rather than block the caller.
    #[test]
    fn a_full_queue_fails_fast_instead_of_blocking() {
        let (file_op_tx, _file_op_rx) = std::sync::mpsc::sync_channel::<FileOpRequest>(1);
        let (reply_tx, _reply_rx) = std::sync::mpsc::channel();
        file_op_tx
            .try_send(FileOpRequest {
                uid: "glorfindel".to_string(),
                path: "/builders/glorfindel/a.wf".to_string(),
                kind: FileOpKind::Read,
                reply: reply_tx,
            })
            .expect("fill the one slot");
        let (reply_tx2, _reply_rx2) = std::sync::mpsc::channel();
        let err = file_op_tx
            .try_send(FileOpRequest {
                uid: "glorfindel".to_string(),
                path: "/builders/glorfindel/a.wf".to_string(),
                kind: FileOpKind::Read,
                reply: reply_tx2,
            })
            .unwrap_err();
        assert!(matches!(err, TrySendError::Full(_)));
    }

    /// Pins `etag_for` to the exact same digest
    /// `loom_vm::world::file_etag_hex`'s own test pins for the same
    /// fixture string (plus this side's quoting) -- see that test's doc
    /// for why they must agree byte-for-byte.
    #[test]
    fn etag_for_is_pinned_against_the_loom_vm_fixture() {
        assert_eq!(
            etag_for("int x;"),
            "\"e13e332bd08e13cbe2aee094e130ed23878b3b554be5b9a665a83e63caa987ae\""
        );
    }

    #[test]
    fn status_mapping_matches_m_fs_5_and_m_fs_3() {
        assert_eq!(
            status_for_file_op_error(&FileOpError::Busy),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status_for_file_op_error(&FileOpError::Timeout),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status_for_file_op_error(&FileOpError::Closed),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status_for_file_op_error(&FileOpError::Refused("no".to_string())),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status_for_file_op_error(&FileOpError::Internal("apply threw".to_string())),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    // -----------------------------------------------------------------
    // HTTP wire tests: drive the real routes (axum router + `HttpState`),
    // not just the channel helpers above.
    // -----------------------------------------------------------------
    mod http_wire {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        use super::*;
        use crate::auth::{
            AccessClaims, AuditEvent, DirectoryError, JwtKeys, RefreshRecord, SessionRotateOutcome,
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
            async fn session_revoke_family_by_token(
                &self,
                _token_hash: &str,
            ) -> Result<(), DirectoryError> {
                unimplemented!("not exercised by these tests")
            }
            async fn session_rotate(
                &self,
                _old_token_hash: &str,
                _new_token_hash: &str,
                _idle_cutoff: time::OffsetDateTime,
            ) -> Result<SessionRotateOutcome, DirectoryError> {
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
            async fn admin_set_tier(
                &self,
                _actor: &str,
                _target_uid: &str,
                _new_tier: i16,
                _reason: &str,
            ) -> Result<(), crate::auth::AdminDirectoryError> {
                unimplemented!("not exercised by these tests")
            }
            async fn admin_audit_recent(
                &self,
                _limit: i64,
                _before_id: Option<i64>,
            ) -> Result<Vec<crate::auth::AdminAuditEntry>, crate::auth::AdminDirectoryError>
            {
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
        async fn a_readable_file_is_200_with_m_fs_4_and_m_fs_6_headers() {
            let (file_op_tx, file_op_rx) = file_op_channel();
            std::thread::spawn(move || {
                let req = file_op_rx.recv().expect("a request should arrive");
                assert_eq!(req.uid, "frodo");
                assert!(matches!(req.kind, FileOpKind::Read));
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
                "sandbox; default-src 'none'"
            );
            assert_eq!(
                headers.get(header::CONTENT_DISPOSITION).unwrap(),
                "attachment"
            );
            assert_eq!(
                headers.get(header::ETAG).unwrap(),
                etag_for("int x;").as_str()
            );
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], b"int x;");
        }

        /// M-FS-3: a refused path (the fake world thread answers
        /// `Refused`, standing in for `valid_read` refusing it) is
        /// `404`, exactly like a path that doesn't exist -- never `403`.
        #[tokio::test]
        async fn a_refused_path_is_404_not_403() {
            let (file_op_tx, file_op_rx) = file_op_channel();
            std::thread::spawn(move || {
                let req = file_op_rx.recv().expect("a request should arrive");
                req.respond(Err(FileOpError::Refused(
                    "valid_read refused /secure/master.wf".to_string(),
                )));
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

        /// CTO review must-fix 3: backpressure must be `503`, never
        /// `404` -- a wire test for the status mapping unit-tested above.
        #[tokio::test]
        async fn a_busy_queue_is_503_not_404() {
            let (file_op_tx, file_op_rx) = file_op_channel();
            std::thread::spawn(move || {
                let req = file_op_rx.recv().expect("a request should arrive");
                req.respond(Err(FileOpError::Busy));
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
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
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
                let req = file_op_rx.recv().expect("a request should arrive");
                assert_eq!(req.path, "/builders/pippin/new.wf");
                match &req.kind {
                    FileOpKind::WriteIfMatch { precondition, text } => {
                        assert_eq!(precondition, &FilePrecondition::IfNoneMatchStar);
                        assert_eq!(text, "int x;");
                    }
                    FileOpKind::Read | FileOpKind::List | FileOpKind::Compile => {
                        panic!("expected a write")
                    }
                }
                req.respond(Ok(FileOpValue::Written));
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
                let req = file_op_rx.recv().expect("a request should arrive");
                req.respond(Ok(FileOpValue::PreconditionFailed));
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
                let req = file_op_rx.recv().expect("a request should arrive");
                match &req.kind {
                    FileOpKind::WriteIfMatch { precondition, .. } => {
                        assert_eq!(
                            precondition,
                            &FilePrecondition::IfMatch(
                                etag_for("old contents").trim_matches('"').to_string()
                            )
                        );
                    }
                    FileOpKind::Read | FileOpKind::List | FileOpKind::Compile => {
                        panic!("expected a write")
                    }
                }
                req.respond(Ok(FileOpValue::Written));
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
                let req = file_op_rx.recv().expect("a request should arrive");
                req.respond(Ok(FileOpValue::PreconditionFailed));
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

        /// CTO review must-fix 2: a failed CAS read (refused, timed out,
        /// or any other world-thread error) must never fall through to a
        /// write -- it's a single atomic request now, so there is no
        /// separate "write anyway" code path left to fall through to.
        #[tokio::test]
        async fn a_refused_cas_is_404_and_never_a_fallthrough_write() {
            let (file_op_tx, file_op_rx) = file_op_channel();
            std::thread::spawn(move || {
                let req = file_op_rx.recv().expect("a request should arrive");
                // Exactly one request ever arrives -- there is no second
                // "write anyway" request to drain.
                req.respond(Err(FileOpError::Refused(
                    "valid_write refused /secure/x.wf".to_string(),
                )));
            });
            let (state, keys) = test_state(Some(file_op_tx));
            let token = bearer_for("glorfindel", &keys);
            let mut request = put_request("/secure/x.wf", &token, "pwned");
            request
                .headers_mut()
                .insert("if-none-match", HeaderValue::from_static("*"));
            let response = app(state).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
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

        /// Each `HttpState` gets its own write-rate-limiter buckets (CTO
        /// review non-blocking item: this used to be one process-global
        /// `static` every `HttpState` -- including every test -- shared).
        /// A bucket exhausted on one `HttpState` must not affect another.
        #[tokio::test]
        async fn write_rate_limiter_is_per_http_state_not_global() {
            let (file_op_tx, file_op_rx) = file_op_channel();
            std::thread::spawn(move || {
                while let Ok(req) = file_op_rx.recv() {
                    req.respond(Ok(FileOpValue::Written));
                }
            });
            let (state_a, keys) = test_state(Some(file_op_tx));
            let token = bearer_for("exhaust-me", &keys);
            // Exhaust state_a's bucket for this uid.
            for _ in 0..(WRITE_BUCKET_CAPACITY as usize) {
                let mut request = put_request("/builders/exhaust-me/a.wf", &token, "x");
                request
                    .headers_mut()
                    .insert("if-none-match", HeaderValue::from_static("*"));
                let response = app(state_a.clone()).oneshot(request).await.unwrap();
                assert_eq!(response.status(), StatusCode::NO_CONTENT);
            }
            let mut request = put_request("/builders/exhaust-me/a.wf", &token, "x");
            request
                .headers_mut()
                .insert("if-none-match", HeaderValue::from_static("*"));
            let response = app(state_a.clone()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

            // A fresh HttpState (same uid) must not inherit that
            // exhaustion.
            let (state_b, _keys_b) = test_state(None);
            let (file_op_tx_b, file_op_rx_b) = file_op_channel();
            std::thread::spawn(move || {
                let req = file_op_rx_b.recv().expect("a request should arrive");
                req.respond(Ok(FileOpValue::Written));
            });
            let state_b = state_b.with_file_ops(file_op_tx_b);
            let mut request = put_request("/builders/exhaust-me/a.wf", &token, "x");
            request
                .headers_mut()
                .insert("if-none-match", HeaderValue::from_static("*"));
            let response = app(state_b).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }

        // -------------------------------------------------------------
        // GET /api/v1/files/list (M-FS-3)
        // -------------------------------------------------------------

        #[tokio::test]
        async fn listing_a_readable_directory_is_200_with_json_entries() {
            let (file_op_tx, file_op_rx) = file_op_channel();
            std::thread::spawn(move || {
                let req = file_op_rx.recv().expect("a request should arrive");
                assert_eq!(req.path, "/builders/frodo");
                assert!(matches!(req.kind, FileOpKind::List));
                req.respond(Ok(FileOpValue::Entries {
                    names: vec!["a.wf".to_string(), "b.wf".to_string()],
                    truncated: false,
                }));
            });
            let (state, keys) = test_state(Some(file_op_tx));
            let token = bearer_for("frodo", &keys);
            let response = app(state)
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/files/list?path=/builders/frodo")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let headers = response.headers().clone();
            assert_eq!(
                headers.get(header::CONTENT_SECURITY_POLICY).unwrap(),
                "sandbox; default-src 'none'"
            );
            assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["entries"], serde_json::json!(["a.wf", "b.wf"]));
            assert_eq!(json["truncated"], serde_json::json!(false));
        }

        /// M-FS-3: a refused or missing directory is `404`, same status
        /// as `GET /api/v1/files/content`'s refusal case -- never `403`.
        #[tokio::test]
        async fn listing_a_refused_directory_is_404_not_403() {
            let (file_op_tx, file_op_rx) = file_op_channel();
            std::thread::spawn(move || {
                let req = file_op_rx.recv().expect("a request should arrive");
                req.respond(Err(FileOpError::Refused(
                    "get_dir refused or the directory does not exist".to_string(),
                )));
            });
            let (state, keys) = test_state(Some(file_op_tx));
            let token = bearer_for("frodo", &keys);
            let response = app(state)
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/files/list?path=/secure")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn listing_with_no_bearer_token_is_401() {
            let (state, _keys) = test_state(None);
            let response = app(state)
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/files/list?path=/builders/frodo")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn listing_with_no_file_op_channel_wired_is_503() {
            let (state, keys) = test_state(None);
            let token = bearer_for("frodo", &keys);
            let response = app(state)
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/files/list?path=/builders/frodo")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }

        #[tokio::test]
        async fn listing_a_truncated_directory_carries_truncated_true() {
            let (file_op_tx, file_op_rx) = file_op_channel();
            std::thread::spawn(move || {
                let req = file_op_rx.recv().expect("a request should arrive");
                req.respond(Ok(FileOpValue::Entries {
                    names: vec!["a.wf".to_string()],
                    truncated: true,
                }));
            });
            let (state, keys) = test_state(Some(file_op_tx));
            let token = bearer_for("frodo", &keys);
            let response = app(state)
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/files/list?path=/builders/frodo")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["truncated"], serde_json::json!(true));
        }

        // -------------------------------------------------------------
        // POST /api/v1/files/compile (M-FS-5 "one in-flight compile per
        // uid, newest save wins")
        // -------------------------------------------------------------

        #[tokio::test]
        async fn a_clean_compile_is_200_ok_true() {
            let (file_op_tx, file_op_rx) = file_op_channel();
            std::thread::spawn(move || {
                let req = file_op_rx.recv().expect("a request should arrive");
                assert_eq!(req.path, "/builders/frodo/a.wf");
                assert!(matches!(req.kind, FileOpKind::Compile));
                req.respond(Ok(FileOpValue::CompileOk));
            });
            let (state, keys) = test_state(Some(file_op_tx));
            let token = bearer_for("frodo", &keys);
            let response = app(state)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/files/compile?path=/builders/frodo/a.wf")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["ok"], serde_json::json!(true));
            assert!(json.get("diagnostics").is_none());
        }

        #[tokio::test]
        async fn a_failed_compile_is_200_ok_false_with_diagnostics() {
            let (file_op_tx, file_op_rx) = file_op_channel();
            std::thread::spawn(move || {
                let req = file_op_rx.recv().expect("a request should arrive");
                req.respond(Ok(FileOpValue::CompileFailed(
                    "a.wf:3: expected ';'".to_string(),
                )));
            });
            let (state, keys) = test_state(Some(file_op_tx));
            let token = bearer_for("frodo", &keys);
            let response = app(state)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/files/compile?path=/builders/frodo/a.wf")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["ok"], serde_json::json!(false));
            assert_eq!(
                json["diagnostics"],
                serde_json::json!("a.wf:3: expected ';'")
            );
        }

        #[tokio::test]
        async fn a_refused_compile_path_is_404_not_403() {
            let (file_op_tx, file_op_rx) = file_op_channel();
            std::thread::spawn(move || {
                let req = file_op_rx.recv().expect("a request should arrive");
                req.respond(Err(FileOpError::Refused("valid_write refused".to_string())));
            });
            let (state, keys) = test_state(Some(file_op_tx));
            let token = bearer_for("frodo", &keys);
            let response = app(state)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/files/compile?path=/secure/evil.wf")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn no_bearer_token_is_401_for_compile_too() {
            let (state, _keys) = test_state(None);
            let response = app(state)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/files/compile?path=/builders/frodo/a.wf")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn no_file_op_channel_wired_is_503_for_compile() {
            let (state, keys) = test_state(None);
            let token = bearer_for("frodo", &keys);
            let response = app(state)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/files/compile?path=/builders/frodo/a.wf")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }

        #[tokio::test]
        async fn a_full_queue_is_503_for_compile() {
            let (file_op_tx, _file_op_rx) = std::sync::mpsc::sync_channel::<FileOpRequest>(0);
            // A zero-capacity channel with nothing ever receiving: the
            // very first `try_send` finds it full (no rendezvous
            // partner), same shape as `a_busy_queue_is_503_not_404`.
            let (state, keys) = test_state(Some(file_op_tx));
            let token = bearer_for("frodo", &keys);
            let response = app(state)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/files/compile?path=/builders/frodo/a.wf")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }

        /// M-FS-5 "one in-flight compile per uid, newest save wins": if
        /// another compile for the same uid claims a newer token while
        /// this request is still waiting on the world thread, this
        /// request must answer `409` instead of its (now-stale) result,
        /// even though the world thread itself answered successfully.
        #[tokio::test]
        async fn a_superseded_compile_is_409_even_on_a_successful_world_thread_answer() {
            let (file_op_tx, file_op_rx) = file_op_channel();
            let (state, keys) = test_state(Some(file_op_tx));
            let token = bearer_for("frodo", &keys);
            let tracker = state.compile_in_flight.clone();
            std::thread::spawn(move || {
                let req = file_op_rx.recv().expect("a request should arrive");
                // Simulate a second, newer `/compile` request for the same
                // uid claiming its token while this one is still in
                // flight -- this request's own token (claimed before this
                // closure ran) is now stale.
                claim_compile_token(&tracker, "frodo");
                req.respond(Ok(FileOpValue::CompileOk));
            });
            let response = app(state)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/files/compile?path=/builders/frodo/a.wf")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CONFLICT);
        }
    }
}
