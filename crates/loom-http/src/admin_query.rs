// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The world-thread query channel for the admin `who`/object-browser
//! routes (OBI-234, P2-O2).
//!
//! `loom-http` runs on the tokio runtime; the live connection table and
//! object/variable state it needs to answer `/api/v1/admin/who`,
//! `/api/v1/admin/objects`, and `/api/v1/admin/objects/:path/vars` live on
//! the dedicated `loom-world` OS thread (`World`, owned by `loom-vm`), and
//! `valid_read`/`/secure` filtering requires calling into the master
//! object, which only that thread may do. This module defines the
//! *contract* for crossing that boundary -- never the World side of it.
//!
//! ## Shape: request/oneshot-reply over a bounded channel
//!
//! [`WorldQueryRequest`] is the wire type a `loom-cli`-owned adapter sends
//! on a `tokio::sync::mpsc::Sender<WorldQueryRequest>` whose receiving end
//! is drained by the world thread's own event loop -- the same shape as
//! `loom-persist`'s `DbRequest`/`DbEvent`, but request-direction-reversed
//! (HTTP calls into the world, not the world calling into Postgres) and
//! answered with a `tokio::sync::oneshot` per request instead of a shared
//! event stream, since each admin HTTP request wants exactly one answer
//! and nothing else is listening for it.
//!
//! **This module never blocks the world thread.** [`ChannelWorldQuery`]
//! (the `loom-http`-side, i.e. HTTP-request-side of the channel) only ever
//! `try_send`s -- a full channel (the world thread behind on draining it)
//! is [`WorldQueryError::Busy`] immediately, never an `await` that would
//! pile up concurrent HTTP requests into an unbounded queue. The
//! world-thread side (`loom-vm`/`loom-cli`, OBI-234 follow-up, see the
//! child issue filed against Gimli) is expected to mirror
//! `spawn_world_thread`'s `drain_db_events`: drain every pending
//! `WorldQueryRequest` with `try_recv` once per event-loop iteration
//! (never `blocking_recv`, never awaiting a full queue), answer each with
//! its own tick-budgeted `valid_read`/`valid_*` apply (the existing
//! `security::APPLY_TICKS`/`MISS_CHARGE` budget already bounds that part),
//! and send the reply on the included `oneshot::Sender` -- which is
//! instant and can't block either, since a oneshot send never waits for a
//! receiver.
//!
//! ## Bound and backpressure (OBI-234 acceptance: "document the channel's
//! bound and backpressure behavior")
//!
//! - **Bound**: [`ADMIN_QUERY_QUEUE_DEPTH`] (32) -- `loom-cli` passes this
//!   to the `mpsc::channel` constructor when it wires the real
//!   implementation, same pattern as `WS_ACCEPT_QUEUE_DEPTH`/
//!   `DB_QUEUE_DEPTH` in `loom-cli::main`.
//! - **Backpressure**: a full channel never blocks the sending HTTP
//!   task -- `try_send` fails immediately, mapped to
//!   [`WorldQueryError::Busy`], which the HTTP layer turns into `503`. A
//!   world thread that is behind (a long recompile, a slow tick) sheds
//!   admin-query load first; it never accumulates an unbounded backlog of
//!   outstanding admin requests, and it never stalls player-visible
//!   ticks waiting on an admin query.
//! - **Timeout**: [`ADMIN_QUERY_TIMEOUT`] (2s) bounds how long an HTTP
//!   request waits for a reply once it *is* queued, so a world thread that
//!   accepted the request but is wedged (vs. merely busy) still returns a
//!   bounded-time `503` rather than hanging the HTTP connection
//!   indefinitely.

use std::time::Duration;

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::sync::{mpsc, oneshot};

/// Channel depth `loom-cli` should use for the real
/// [`WorldQueryRequest`] channel (see the module doc's "Bound" section).
pub const ADMIN_QUERY_QUEUE_DEPTH: usize = 32;

/// How long [`ChannelWorldQuery`] waits for a reply once a request is
/// queued, before giving up with [`WorldQueryError::Timeout`] (see the
/// module doc's "Timeout" section).
pub const ADMIN_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// A connected session, as reported by `who` (M-ADM-3: never an email or
/// an IP address -- those fields don't exist on this type at all, so
/// there is no field to forget to scrub).
#[derive(Debug, Clone, PartialEq)]
pub struct WhoEntry {
    /// The net layer's connection id (`loom_net`/`World::live_connections`).
    pub conn_id: u64,
    /// The bound player/staff account uid, if the connection has logged
    /// in (`None` for a connection still at a login/creation prompt).
    pub account: Option<String>,
    pub connected_at: OffsetDateTime,
    pub idle_secs: i64,
}

/// One object in the `/api/v1/admin/objects` listing -- already filtered
/// by `valid_read` on the world side; `loom-http` never re-derives or
/// relaxes that filter (design note: "do not invent a parallel rule
/// set").
#[derive(Debug, Clone, PartialEq)]
pub struct ObjectSummary {
    pub path: String,
    pub euid: String,
}

/// One inspected variable, `object_vars`'s per-field answer. `value` is a
/// world-side-rendered display string (the exact rendering -- struct
/// fields, mapping keys, closures -- is `loom-vm` territory); `loom-http`
/// never introspects it beyond passing it through to JSON.
#[derive(Debug, Clone, PartialEq)]
pub struct VarEntry {
    pub name: String,
    pub value: String,
}

/// The answer to an `object_vars` query.
#[derive(Debug, Clone, PartialEq)]
pub struct ObjectVars {
    pub path: String,
    pub vars: Vec<VarEntry>,
}

/// One group from `GET /api/v1/admin/errors` (OBI-235) -- the HTTP-side
/// mirror of [`crate::errors` in `loom-vm`]'s `ErrorRecord`/the `errors`
/// efun's per-row shape (`loom-http` doesn't depend on `loom-vm`
/// directly, so this is its own copy of the same fields, not a type
/// alias). `message` is already capped/redacted and `line`/`function`
/// already the innermost-frame attribution (M-ERR-1) by the time this
/// crosses the channel -- `loom-http` never reinterprets any of it.
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorGroup {
    pub program: String,
    pub function: String,
    /// `None` = no line attribution available (see `loom-vm`'s
    /// `ErrorRecord::line` doc: `0` there maps to `None` here).
    pub line: Option<u32>,
    /// Already `"<redacted>"` if `redacted` is `true` and the caller's
    /// tier is below 5 (M-ERR-1) -- the world side applies that rule
    /// before replying, same as the `errors` efun does for in-world
    /// callers.
    pub message: String,
    pub redacted: bool,
    pub count: u64,
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    pub sample_trace: Vec<String>,
}

/// Why a [`WorldAdminQuery`] call didn't return data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorldQueryError {
    /// The request channel was full -- the world thread is behind
    /// draining it. Never a reason to block; the caller gets this back
    /// immediately (`try_send` failed).
    Busy,
    /// The request was queued, but no reply arrived within
    /// [`ADMIN_QUERY_TIMEOUT`] (world thread wedged, not merely busy).
    Timeout,
    /// The channel (or its reply half) is closed -- no world thread is
    /// running (e.g. not wired at all, or the process is shutting down).
    Closed,
    /// `object_vars` for a path that doesn't name a live object.
    NotFound,
    /// OBI-279 (CTO review, PR #102, non-blocking note 1): the request
    /// was answered, but the world side's own `valid_read` gate failed
    /// to produce a real decision (a tick-budget or other runtime
    /// failure inside the master's `valid_read`, see `loom_vm::World::
    /// admin_list_objects`/`admin_object_vars`/`admin_errors`'s doc
    /// comments) -- distinct from an empty/`NotFound` result, which
    /// means the gate *ran* and said no. Carries the world-side error
    /// message for operator-facing logs; never rendered to the HTTP
    /// response body (same "never a different error shape" rule
    /// `NotFound` already follows for `object_vars`).
    Internal(String),
}

/// What `loom-http`'s admin routes need from the world thread. Defined
/// here (the consumer) rather than in `loom-vm` (the eventual
/// implementer) so the HTTP layer, its tier/audit gating, and its tests
/// can all be built and merged against this trait before the
/// `loom-vm`/`loom-cli` side exists -- see the module doc for the
/// channel contract the real implementation is expected to honor.
#[async_trait]
pub trait WorldAdminQuery: Send + Sync {
    /// `GET /api/v1/admin/who`: every live connection, newest `connect`
    /// first or any other stable order -- `loom-http` doesn't sort.
    async fn who(&self) -> Result<Vec<WhoEntry>, WorldQueryError>;

    /// `GET /api/v1/admin/objects`: every live object the caller
    /// (`euid`, `tier` -- already past the T3 floor by the time this is
    /// called) passes `valid_read` for. An empty `Vec` (not an error) is
    /// the correct answer for "nothing readable".
    async fn list_objects(
        &self,
        euid: &str,
        tier: i16,
    ) -> Result<Vec<ObjectSummary>, WorldQueryError>;

    /// `GET /api/v1/admin/objects/:path/vars`: `path`'s variables, if
    /// `euid`/`tier` (already past the T4 floor, and the T5 `/secure`
    /// floor if `path` is under `/secure/`, by the time this is called)
    /// pass `valid_read` for it. [`WorldQueryError::NotFound`] for a path
    /// that isn't a live object; a `valid_read` refusal inside the world
    /// is also surfaced as `NotFound` (never a different error shape) so
    /// the HTTP layer can't be used to distinguish "doesn't exist" from
    /// "exists but you can't see it".
    async fn object_vars(
        &self,
        euid: &str,
        tier: i16,
        path: &str,
    ) -> Result<ObjectVars, WorldQueryError>;

    /// `GET /api/v1/admin/errors` (OBI-235): every error-inbox group
    /// `euid`/`tier` (already past the T3 floor by the time this is
    /// called) passes `valid_read` for on the group's `program`,
    /// optionally narrowed to `program_prefix` (same semantics as the
    /// `errors` efun's own `filter` argument) -- same "world side is the
    /// real filter" shape as `list_objects`. An empty `Vec` (not an
    /// error) is the correct answer for "nothing readable".
    async fn errors(
        &self,
        euid: &str,
        tier: i16,
        program_prefix: Option<&str>,
    ) -> Result<Vec<ErrorGroup>, WorldQueryError>;
}

/// The wire request [`ChannelWorldQuery`] sends; the world-thread-side
/// receiver (OBI-234 follow-up) answers each by sending exactly once on
/// its `reply` half.
pub enum WorldQueryRequest {
    Who {
        reply: oneshot::Sender<Result<Vec<WhoEntry>, WorldQueryError>>,
    },
    ListObjects {
        euid: String,
        tier: i16,
        reply: oneshot::Sender<Result<Vec<ObjectSummary>, WorldQueryError>>,
    },
    ObjectVars {
        euid: String,
        tier: i16,
        path: String,
        reply: oneshot::Sender<Result<ObjectVars, WorldQueryError>>,
    },
    Errors {
        euid: String,
        tier: i16,
        program_prefix: Option<String>,
        reply: oneshot::Sender<Result<Vec<ErrorGroup>, WorldQueryError>>,
    },
}

/// [`WorldAdminQuery`] wired to a [`WorldQueryRequest`] channel (the
/// production path once `loom-cli` spawns the world-thread-side
/// receiver): every method `try_send`s its request (never blocks on a
/// full channel -- [`WorldQueryError::Busy`] instead) and then waits up
/// to [`ADMIN_QUERY_TIMEOUT`] for the reply.
#[derive(Clone)]
pub struct ChannelWorldQuery {
    request_tx: mpsc::Sender<WorldQueryRequest>,
}

impl ChannelWorldQuery {
    pub fn new(request_tx: mpsc::Sender<WorldQueryRequest>) -> Self {
        Self { request_tx }
    }

    async fn roundtrip<T>(
        &self,
        request: WorldQueryRequest,
        reply_rx: oneshot::Receiver<Result<T, WorldQueryError>>,
    ) -> Result<T, WorldQueryError> {
        self.request_tx.try_send(request).map_err(|err| match err {
            mpsc::error::TrySendError::Full(_) => WorldQueryError::Busy,
            mpsc::error::TrySendError::Closed(_) => WorldQueryError::Closed,
        })?;
        match tokio::time::timeout(ADMIN_QUERY_TIMEOUT, reply_rx).await {
            Ok(Ok(result)) => result,
            // The reply sender was dropped without answering (world
            // thread gone / adapter task died mid-flight).
            Ok(Err(_)) => Err(WorldQueryError::Closed),
            Err(_) => Err(WorldQueryError::Timeout),
        }
    }
}

#[async_trait]
impl WorldAdminQuery for ChannelWorldQuery {
    async fn who(&self) -> Result<Vec<WhoEntry>, WorldQueryError> {
        let (reply, reply_rx) = oneshot::channel();
        self.roundtrip(WorldQueryRequest::Who { reply }, reply_rx)
            .await
    }

    async fn list_objects(
        &self,
        euid: &str,
        tier: i16,
    ) -> Result<Vec<ObjectSummary>, WorldQueryError> {
        let (reply, reply_rx) = oneshot::channel();
        self.roundtrip(
            WorldQueryRequest::ListObjects {
                euid: euid.to_string(),
                tier,
                reply,
            },
            reply_rx,
        )
        .await
    }

    async fn object_vars(
        &self,
        euid: &str,
        tier: i16,
        path: &str,
    ) -> Result<ObjectVars, WorldQueryError> {
        let (reply, reply_rx) = oneshot::channel();
        self.roundtrip(
            WorldQueryRequest::ObjectVars {
                euid: euid.to_string(),
                tier,
                path: path.to_string(),
                reply,
            },
            reply_rx,
        )
        .await
    }

    async fn errors(
        &self,
        euid: &str,
        tier: i16,
        program_prefix: Option<&str>,
    ) -> Result<Vec<ErrorGroup>, WorldQueryError> {
        let (reply, reply_rx) = oneshot::channel();
        self.roundtrip(
            WorldQueryRequest::Errors {
                euid: euid.to_string(),
                tier,
                program_prefix: program_prefix.map(|s| s.to_string()),
                reply,
            },
            reply_rx,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake "world thread": drains exactly one request and answers it,
    /// standing in for the real `loom-cli`/`loom-vm` receiver loop this
    /// module's doc comment specifies.
    fn spawn_fake_world(mut request_rx: mpsc::Receiver<WorldQueryRequest>) {
        tokio::spawn(async move {
            if let Some(WorldQueryRequest::Who { reply }) = request_rx.recv().await {
                let _ = reply.send(Ok(vec![WhoEntry {
                    conn_id: 1,
                    account: Some("lead".to_string()),
                    connected_at: OffsetDateTime::now_utc(),
                    idle_secs: 0,
                }]));
            }
        });
    }

    #[tokio::test]
    async fn round_trip_succeeds() {
        let (tx, rx) = mpsc::channel(ADMIN_QUERY_QUEUE_DEPTH);
        spawn_fake_world(rx);
        let client = ChannelWorldQuery::new(tx);
        let who = client.who().await.unwrap();
        assert_eq!(who.len(), 1);
        assert_eq!(who[0].account.as_deref(), Some("lead"));
    }

    #[tokio::test]
    async fn full_channel_is_busy_not_blocking() {
        // Depth 1, nothing draining it: the first send fills the queue,
        // the second must fail immediately (`Busy`), never hang.
        let (tx, _rx) = mpsc::channel(1);
        let client = ChannelWorldQuery::new(tx.clone());
        let (reply, _reply_rx) = oneshot::channel();
        tx.try_send(WorldQueryRequest::Who { reply }).unwrap();
        let err = tokio::time::timeout(Duration::from_millis(200), client.who())
            .await
            .expect("must not hang waiting on a full channel")
            .unwrap_err();
        assert_eq!(err, WorldQueryError::Busy);
    }

    #[tokio::test]
    async fn no_reply_times_out() {
        let (tx, mut rx) = mpsc::channel(ADMIN_QUERY_QUEUE_DEPTH);
        // Accept the request but never answer it, and never drop it
        // either (dropping the request would drop its `reply` oneshot
        // sender, which would resolve the receiver immediately with
        // `Closed` instead of exercising a real timeout) -- simulates a
        // wedged world thread, distinct from both a full channel and a
        // closed one.
        tokio::spawn(async move {
            let request = rx.recv().await;
            std::mem::forget(request);
        });
        let client = ChannelWorldQuery::new(tx);
        let err = client.who().await.unwrap_err();
        assert_eq!(err, WorldQueryError::Timeout);
    }

    #[tokio::test]
    async fn closed_channel_is_closed_not_busy() {
        let (tx, rx) = mpsc::channel::<WorldQueryRequest>(ADMIN_QUERY_QUEUE_DEPTH);
        drop(rx);
        let client = ChannelWorldQuery::new(tx);
        let err = client.who().await.unwrap_err();
        assert_eq!(err, WorldQueryError::Closed);
    }
}
