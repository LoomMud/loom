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
//! Only `GET` (`read_file`) is wired below. `PUT` (`write_file` +
//! `If-Match`/`If-None-Match`, M-FS-6/M-FS-7), listings (M-FS-3), and
//! `compile_object` are a later slice -- `FileOpValue`'s doc already
//! notes `compile_object`'s diagnostics-list result needs a richer
//! shape than `Null`/`Bool`/`Str`.

use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::time::Duration;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use serde::Deserialize;

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

pub fn files_router() -> Router<HttpState> {
    Router::new().route("/api/v1/files/content", get(read_file))
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
    }
}
