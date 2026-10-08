// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `/api/v1/admin/*` routes (OBI-185, P2-O2): role management and the
//! audit view slice of the staff admin UI. Mounted unconditionally by
//! [`crate::app`], same "optional, `503` if unconfigured" shape as
//! `/auth/*` (`handlers.rs`) -- both go through the same [`HttpState::auth`].
//!
//! ## M-ADM-1: the actor is always the token's `sub`
//!
//! [`AdminSetTierRequest`] has no `actor` field. `#[serde(deny_unknown_fields)]`
//! means any unrecognized field in the body -- `actor` included -- is a
//! `400`, not a silently ignored extra key a client might assume does
//! something. The actor passed to [`crate::auth::AuthService::admin_set_tier`]
//! is always `claims.sub`, read from the verified bearer token.
//!
//! ## M-ADM-2: tier floor + step-up, enforced by [`AuthService`]
//!
//! This module only extracts and forwards; the tier (>= 3) and step-up
//! (`mfa_at` within 5 minutes) checks, and the real security boundary
//! (the `roles_set_tier` SQL function), all live in
//! [`crate::auth::AuthService`] -- see that module's doc comments.
//!
//! ## M-ADM-4: every admin endpoint is audited
//!
//! Both routes go through `AuthService` methods that call `audit()`
//! themselves (allow and deny alike), so there's no handler-side step
//! here that could forget to record one.

use axum::Json;
use axum::Router;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};

use crate::HttpState;
use crate::auth::{AccessClaims, AdminError};
use crate::client_ip::client_ip;

pub fn admin_router() -> Router<HttpState> {
    Router::new()
        .route("/api/v1/admin/roles/tier", post(set_tier))
        .route("/api/v1/admin/audit", get(audit_recent))
        .route("/api/v1/admin/who", get(who))
        .route("/api/v1/admin/objects", get(list_objects))
        .route("/api/v1/admin/objects/{*rest}", get(object_vars))
        .route("/api/v1/admin/errors", get(errors))
        .route("/api/v1/admin/broadcast", post(broadcast))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminSetTierRequest {
    target_uid: String,
    new_tier: i16,
    reason: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

fn error_response(code: StatusCode, error: &'static str) -> (StatusCode, Json<ErrorResponse>) {
    (
        code,
        Json(ErrorResponse {
            error,
            detail: None,
        }),
    )
}

fn admin_error_response(error: AdminError) -> (StatusCode, Json<ErrorResponse>) {
    match error {
        AdminError::Forbidden => error_response(StatusCode::FORBIDDEN, "forbidden"),
        AdminError::StepUpRequired => error_response(StatusCode::FORBIDDEN, "step_up_required"),
        AdminError::BadRequest => error_response(StatusCode::BAD_REQUEST, "bad_request"),
        AdminError::Rejected(detail) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "rejected",
                detail: Some(detail),
            }),
        ),
        AdminError::DirectoryUnavailable => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
        AdminError::WorldUnavailable => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
        AdminError::NotFound => error_response(StatusCode::NOT_FOUND, "not_found"),
        AdminError::BodyTooLarge => error_response(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large"),
    }
}

/// Extract and verify the bearer access token's full claims (tier,
/// `mfa_at`, `sub`) -- unlike `handlers.rs`'s `bearer_uid`, admin routes
/// need more than just the uid to enforce M-ADM-2 at the edge.
fn bearer_claims(headers: &HeaderMap, state: &HttpState) -> Option<AccessClaims> {
    let auth = state.auth_service()?;
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let token = value.strip_prefix("Bearer ")?;
    auth.verify_access_token(token).ok()
}

fn auth_context(
    headers: &HeaderMap,
    peer: Option<std::net::SocketAddr>,
) -> crate::auth::AuthContext {
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(256).collect::<String>());
    crate::auth::AuthContext::new(client_ip(headers, peer), user_agent)
}

async fn set_tier(
    State(state): State<HttpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let Some(auth) = state.auth_service() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable").into_response();
    };
    let Some(claims) = bearer_claims(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    // M-ADM-1: `deny_unknown_fields` rejects a body `actor` field (or any
    // other field this struct doesn't know about) as a 400, not a
    // silently-ignored extra key.
    let request: AdminSetTierRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "bad_request").into_response(),
    };

    let ctx = auth_context(&headers, Some(peer));
    match auth
        .admin_set_tier(
            &claims,
            &ctx,
            &request.target_uid,
            request.new_tier,
            &request.reason,
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => admin_error_response(error).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    before_id: Option<i64>,
}

#[derive(Debug, Serialize)]
struct AuditEntryResponse {
    id: i64,
    at: String,
    kind: String,
    caller: Option<String>,
    effective_principal: Option<String>,
    apply: Option<String>,
    class: Option<i16>,
    argument: Option<String>,
    guard_set: Vec<String>,
    verdict: String,
    detail: Option<String>,
}

impl From<crate::auth::AdminAuditEntry> for AuditEntryResponse {
    fn from(entry: crate::auth::AdminAuditEntry) -> Self {
        AuditEntryResponse {
            id: entry.id,
            at: entry
                .at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            kind: entry.kind,
            caller: entry.caller,
            effective_principal: entry.effective_principal,
            apply: entry.apply,
            class: entry.class,
            argument: entry.argument,
            guard_set: entry.guard_set,
            verdict: entry.verdict,
            detail: entry.detail,
        }
    }
}

async fn audit_recent(
    State(state): State<HttpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> impl IntoResponse {
    let Some(auth) = state.auth_service() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable").into_response();
    };
    let Some(claims) = bearer_claims(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let ctx = auth_context(&headers, Some(peer));
    let limit = query.limit.unwrap_or(50);
    match auth
        .admin_audit_recent(&claims, &ctx, limit, query.before_id)
        .await
    {
        Ok(rows) => {
            let rows: Vec<AuditEntryResponse> = rows.into_iter().map(Into::into).collect();
            (StatusCode::OK, Json(rows)).into_response()
        }
        Err(error) => admin_error_response(error).into_response(),
    }
}

/// `GET /api/v1/admin/who` response row (M-ADM-3: no email, no IP --
/// those fields simply don't exist on [`crate::admin_query::WhoEntry`],
/// so there's nothing here for serde to serialize even by accident).
#[derive(Debug, Serialize)]
struct WhoEntryResponse {
    conn_id: u64,
    account: Option<String>,
    connected_at: String,
    idle_secs: i64,
}

impl From<crate::admin_query::WhoEntry> for WhoEntryResponse {
    fn from(entry: crate::admin_query::WhoEntry) -> Self {
        WhoEntryResponse {
            conn_id: entry.conn_id,
            account: entry.account,
            connected_at: entry
                .connected_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            idle_secs: entry.idle_secs,
        }
    }
}

async fn who(
    State(state): State<HttpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(auth) = state.auth_service() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable").into_response();
    };
    let Some(claims) = bearer_claims(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(query) = state.world_query() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable").into_response();
    };
    let ctx = auth_context(&headers, Some(peer));
    match auth.admin_who(&claims, &ctx, query).await {
        Ok(rows) => {
            let rows: Vec<WhoEntryResponse> = rows.into_iter().map(Into::into).collect();
            (StatusCode::OK, Json(rows)).into_response()
        }
        Err(error) => admin_error_response(error).into_response(),
    }
}

#[derive(Debug, Serialize)]
struct ObjectSummaryResponse {
    path: String,
    euid: String,
}

impl From<crate::admin_query::ObjectSummary> for ObjectSummaryResponse {
    fn from(entry: crate::admin_query::ObjectSummary) -> Self {
        ObjectSummaryResponse {
            path: entry.path,
            euid: entry.euid,
        }
    }
}

async fn list_objects(
    State(state): State<HttpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(auth) = state.auth_service() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable").into_response();
    };
    let Some(claims) = bearer_claims(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(query) = state.world_query() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable").into_response();
    };
    let ctx = auth_context(&headers, Some(peer));
    match auth.admin_list_objects(&claims, &ctx, query).await {
        Ok(rows) => {
            let rows: Vec<ObjectSummaryResponse> = rows.into_iter().map(Into::into).collect();
            (StatusCode::OK, Json(rows)).into_response()
        }
        Err(error) => admin_error_response(error).into_response(),
    }
}

/// `GET /api/v1/admin/objects/:path/vars`, mounted as the
/// `/api/v1/admin/objects/{*rest}` wildcard (axum has no way to express
/// a static suffix after a variable-length path segment): `rest` is
/// everything after `/api/v1/admin/objects/`, and this handler is the
/// one place that peels the `/vars` suffix back off to recover the
/// object path -- e.g. a request for `/std/room`'s variables is
/// `GET /api/v1/admin/objects/std/room/vars`, `rest` is `"std/room/vars"`,
/// and the object path passed to [`crate::auth::AuthService::
/// admin_object_vars`] is `"/std/room"`. A `rest` that doesn't end in
/// `/vars` is a plain `404` -- there is no other route under this
/// prefix.
async fn object_vars(
    State(state): State<HttpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    axum::extract::Path(rest): axum::extract::Path<String>,
) -> impl IntoResponse {
    let Some(object_path) = rest.strip_suffix("/vars").map(|p| format!("/{p}")) else {
        return error_response(StatusCode::NOT_FOUND, "not_found").into_response();
    };
    let Some(auth) = state.auth_service() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable").into_response();
    };
    let Some(claims) = bearer_claims(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(query) = state.world_query() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable").into_response();
    };
    let ctx = auth_context(&headers, Some(peer));
    match auth
        .admin_object_vars(&claims, &ctx, query, &object_path)
        .await
    {
        Ok(vars) => (StatusCode::OK, Json(ObjectVarsResponse::from(vars))).into_response(),
        Err(error) => admin_error_response(error).into_response(),
    }
}

#[derive(Debug, Serialize)]
struct VarEntryResponse {
    name: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct ObjectVarsResponse {
    path: String,
    vars: Vec<VarEntryResponse>,
}

impl From<crate::admin_query::ObjectVars> for ObjectVarsResponse {
    fn from(entry: crate::admin_query::ObjectVars) -> Self {
        ObjectVarsResponse {
            path: entry.path,
            vars: entry
                .vars
                .into_iter()
                .map(|v| VarEntryResponse {
                    name: v.name,
                    value: v.value,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ErrorsQuery {
    #[serde(default)]
    program_prefix: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorGroupResponse {
    program: String,
    function: String,
    line: Option<u32>,
    message: String,
    redacted: bool,
    count: u64,
    first_seen_unix_ms: u64,
    last_seen_unix_ms: u64,
    sample_trace: Vec<String>,
}

impl From<crate::admin_query::ErrorGroup> for ErrorGroupResponse {
    fn from(entry: crate::admin_query::ErrorGroup) -> Self {
        ErrorGroupResponse {
            program: entry.program,
            function: entry.function,
            line: entry.line,
            message: entry.message,
            redacted: entry.redacted,
            count: entry.count,
            first_seen_unix_ms: entry.first_seen_unix_ms,
            last_seen_unix_ms: entry.last_seen_unix_ms,
            sample_trace: entry.sample_trace,
        }
    }
}

/// `GET /api/v1/admin/errors` (OBI-235, P2-O2): the HTTP wiring for the
/// grouped runtime-error inbox `loom-vm` built for the `errors` efun
/// (OBI-169) -- T3+ (same floor as object listing, [`crate::auth::
/// ERROR_INBOX_MIN_TIER`]), filtered/redacted entirely on the world
/// side (`query.errors`), audited allow and deny alike (M-ADM-4).
async fn errors(
    State(state): State<HttpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(query_params): Query<ErrorsQuery>,
) -> impl IntoResponse {
    let Some(auth) = state.auth_service() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable").into_response();
    };
    let Some(claims) = bearer_claims(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(query) = state.world_query() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable").into_response();
    };
    let ctx = auth_context(&headers, Some(peer));
    match auth
        .admin_errors(&claims, &ctx, query, query_params.program_prefix.as_deref())
        .await
    {
        Ok(rows) => {
            let rows: Vec<ErrorGroupResponse> = rows.into_iter().map(Into::into).collect();
            (StatusCode::OK, Json(rows)).into_response()
        }
        Err(error) => admin_error_response(error).into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminBroadcastRequest {
    text: String,
}

#[derive(Debug, Serialize)]
struct BroadcastResponse {
    recipients: usize,
}

/// `POST /api/v1/admin/broadcast` (OBI-233, M-ADM-2/4/5): a server-wide
/// staff message, delivered through the normal mudlib output path --
/// `crate::admin_query::WorldAdminQuery::broadcast`, routed through the
/// world thread to interactive sessions only (CTO review, OBI-233),
/// never a direct write to `loom-net`'s connection table. Tier/step-up
/// checks, the size cap, sanitization, and the driver-fixed
/// `[Broadcast] ` prefix all live in `AuthService::admin_broadcast` --
/// this handler only extracts the body and forwards it. `state.auth` or
/// `state.world_query()` unset both answer `503`, same "optional, not
/// wired" shape as every other admin/auth route. On success, the
/// response body reports how many interactive sessions received it --
/// `0` is a normal (not an error) answer when nobody is logged in.
async fn broadcast(
    State(state): State<HttpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let Some(auth) = state.auth_service() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable").into_response();
    };
    let Some(claims) = bearer_claims(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(query) = state.world_query() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable").into_response();
    };

    let request: AdminBroadcastRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "bad_request").into_response(),
    };

    let ctx = auth_context(&headers, Some(peer));
    match auth
        .admin_broadcast(&claims, &ctx, query, &request.text)
        .await
    {
        Ok(recipients) => (StatusCode::OK, Json(BroadcastResponse { recipients })).into_response(),
        Err(error) => admin_error_response(error).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::Request;
    use axum::http::StatusCode;
    use axum::http::header::AUTHORIZATION;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::auth::{AuthService, JwtKeys, StaffDirectory, jwt};
    use crate::{HttpState, app};

    // A minimal in-memory `StaffDirectory` sufficient to drive these HTTP
    // wire-level tests -- `auth::tests` already covers `AuthService`'s
    // own logic in depth; these only prove the handler plumbing (body
    // parsing, status codes, bearer extraction). `audits` captures every
    // `record_audit` call (OBI-234: "every object/variable access is
    // audited") so tests can assert on it directly, not just infer it
    // from the response.
    #[derive(Default, Clone)]
    struct Dir {
        audits: std::sync::Arc<std::sync::Mutex<Vec<crate::auth::AuditEvent>>>,
    }

    #[async_trait::async_trait]
    impl StaffDirectory for Dir {
        async fn staff_login(
            &self,
            _username: &str,
            _password: &str,
        ) -> Result<Option<crate::auth::StaffAuthRecord>, crate::auth::DirectoryError> {
            Ok(None)
        }
        async fn auth_status_for(
            &self,
            uid: &str,
        ) -> Result<Option<crate::auth::StaffAuthStatus>, crate::auth::DirectoryError> {
            Ok(Some(crate::auth::StaffAuthStatus {
                tier: if uid == "lead" { 3 } else { 1 },
                totp_secret: None,
                totp_confirmed: false,
            }))
        }
        async fn resolve_uid(
            &self,
            _username: &str,
        ) -> Result<Option<String>, crate::auth::DirectoryError> {
            Ok(None)
        }
        async fn totp_enroll(
            &self,
            _uid: &str,
            _secret_base32: &str,
        ) -> Result<(), crate::auth::DirectoryError> {
            Ok(())
        }
        async fn totp_confirm(&self, _uid: &str) -> Result<(), crate::auth::DirectoryError> {
            Ok(())
        }
        async fn totp_secret_for(
            &self,
            _uid: &str,
        ) -> Result<Option<String>, crate::auth::DirectoryError> {
            Ok(None)
        }
        async fn totp_consume_step(
            &self,
            _uid: &str,
            _step: u64,
        ) -> Result<bool, crate::auth::DirectoryError> {
            Ok(true)
        }
        async fn refresh_token_insert(
            &self,
            _uid: &str,
            _token_hash: &str,
            _expires_at: time::OffsetDateTime,
            _sid: &str,
            _amr: &[String],
            _mfa_at: Option<time::OffsetDateTime>,
        ) -> Result<(), crate::auth::DirectoryError> {
            Ok(())
        }
        async fn refresh_token_lookup(
            &self,
            _token_hash: &str,
        ) -> Result<Option<crate::auth::RefreshRecord>, crate::auth::DirectoryError> {
            Ok(None)
        }
        async fn session_revoke_family_by_token(
            &self,
            _token_hash: &str,
        ) -> Result<(), crate::auth::DirectoryError> {
            Ok(())
        }
        async fn session_family_live(
            &self,
            _sid: &str,
        ) -> Result<bool, crate::auth::DirectoryError> {
            Ok(true)
        }
        async fn session_rotate(
            &self,
            _old_token_hash: &str,
            _new_token_hash: &str,
            _idle_cutoff: time::OffsetDateTime,
        ) -> Result<crate::auth::SessionRotateOutcome, crate::auth::DirectoryError> {
            Ok(crate::auth::SessionRotateOutcome::Invalid)
        }
        async fn refresh_token_revoke(
            &self,
            _token_hash: &str,
        ) -> Result<(), crate::auth::DirectoryError> {
            Ok(())
        }
        async fn refresh_token_revoke_all(
            &self,
            _uid: &str,
        ) -> Result<(), crate::auth::DirectoryError> {
            Ok(())
        }
        async fn github_lookup(
            &self,
            _github_id: i64,
        ) -> Result<Option<String>, crate::auth::DirectoryError> {
            Ok(None)
        }
        async fn record_audit(
            &self,
            event: crate::auth::AuditEvent,
        ) -> Result<(), crate::auth::DirectoryError> {
            self.audits.lock().unwrap().push(event);
            Ok(())
        }
        async fn admin_set_tier(
            &self,
            actor: &str,
            target_uid: &str,
            new_tier: i16,
            _reason: &str,
        ) -> Result<(), crate::auth::AdminDirectoryError> {
            if actor == target_uid {
                return Err(crate::auth::AdminDirectoryError::Rejected(
                    "self-promotion is not permitted".to_string(),
                ));
            }
            let _ = new_tier;
            Ok(())
        }
        async fn admin_audit_recent(
            &self,
            _limit: i64,
            _before_id: Option<i64>,
        ) -> Result<Vec<crate::auth::AdminAuditEntry>, crate::auth::AdminDirectoryError> {
            Ok(Vec::new())
        }
    }

    /// A minimal [`crate::admin_query::WorldAdminQuery`] fake: `who`
    /// returns one fixed session (never an email/IP field -- the type
    /// has none to put one in); `list_objects` plays the part of
    /// `valid_read`'s filtering (everyone sees `/std/room`, only `lead`
    /// also sees `/secure/master`), so the routing/gating tests below
    /// can tell "reached the world query and got a real filtered answer"
    /// apart from "never got that far".
    struct FakeWorldQuery {
        broadcasts: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        /// When set, [`FakeWorldQuery::broadcast`] answers with this error
        /// instead of the fixed `Ok(2)` -- OBI-233 (CTO review, third pass,
        /// optional item 1): the delivery-failure audit path (`outcome=\`
        /// unknown`/`not_delivered`) is only reachable through a world side
        /// that actually fails.
        broadcast_error:
            Option<std::sync::Arc<dyn Fn() -> crate::admin_query::WorldQueryError + Send + Sync>>,
    }

    impl Default for FakeWorldQuery {
        fn default() -> Self {
            FakeWorldQuery {
                broadcasts: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                broadcast_error: None,
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::admin_query::WorldAdminQuery for FakeWorldQuery {
        async fn who(
            &self,
        ) -> Result<Vec<crate::admin_query::WhoEntry>, crate::admin_query::WorldQueryError>
        {
            Ok(vec![crate::admin_query::WhoEntry {
                conn_id: 1,
                account: Some("apprentice".to_string()),
                connected_at: time::OffsetDateTime::now_utc(),
                idle_secs: 5,
            }])
        }

        async fn list_objects(
            &self,
            euid: &str,
            _tier: i16,
        ) -> Result<Vec<crate::admin_query::ObjectSummary>, crate::admin_query::WorldQueryError>
        {
            let all = vec![
                crate::admin_query::ObjectSummary {
                    path: "/std/room".to_string(),
                    euid: "root".to_string(),
                },
                crate::admin_query::ObjectSummary {
                    path: "/secure/master".to_string(),
                    euid: "root".to_string(),
                },
            ];
            Ok(all
                .into_iter()
                .filter(|o| euid == "lead" || !o.path.starts_with("/secure/"))
                .collect())
        }

        async fn object_vars(
            &self,
            _euid: &str,
            _tier: i16,
            path: &str,
        ) -> Result<crate::admin_query::ObjectVars, crate::admin_query::WorldQueryError> {
            Ok(crate::admin_query::ObjectVars {
                path: path.to_string(),
                vars: vec![crate::admin_query::VarEntry {
                    name: "hp".to_string(),
                    value: "100".to_string(),
                }],
            })
        }

        async fn errors(
            &self,
            euid: &str,
            _tier: i16,
            program_prefix: Option<&str>,
        ) -> Result<Vec<crate::admin_query::ErrorGroup>, crate::admin_query::WorldQueryError>
        {
            let all = vec![
                crate::admin_query::ErrorGroup {
                    program: "/d/shire/calc.wf".to_string(),
                    function: "calc".to_string(),
                    line: Some(42),
                    message: "division by zero".to_string(),
                    redacted: false,
                    count: 3,
                    first_seen_unix_ms: 1_000,
                    last_seen_unix_ms: 2_000,
                    sample_trace: vec!["in calc()".to_string()],
                },
                crate::admin_query::ErrorGroup {
                    program: "/secure/master".to_string(),
                    function: "boot".to_string(),
                    line: None,
                    message: if euid == "lead" {
                        "real secret detail".to_string()
                    } else {
                        "<redacted>".to_string()
                    },
                    redacted: true,
                    count: 1,
                    first_seen_unix_ms: 500,
                    last_seen_unix_ms: 500,
                    sample_trace: vec![],
                },
            ];
            Ok(all
                .into_iter()
                .filter(|e| euid == "lead" || !e.program.starts_with("/secure/"))
                .filter(|e| program_prefix.is_none_or(|p| e.program.starts_with(p)))
                .collect())
        }

        /// Captures the exact text [`crate::auth::AuthService::
        /// admin_broadcast`] handed it (already sanitized and prefixed)
        /// so tests can assert on it, and returns a fixed fake recipient
        /// count (`2`) -- standing in for "the world thread fanned it out
        /// to every interactive session". When `broadcast_error` is set it
        /// still captures the text (the world side *did* receive the
        /// request), but answers with that error.
        async fn broadcast(
            &self,
            text: &str,
        ) -> Result<usize, crate::admin_query::WorldQueryError> {
            self.broadcasts.lock().unwrap().push(text.to_string());
            match &self.broadcast_error {
                Some(make_err) => Err(make_err()),
                None => Ok(2),
            }
        }
    }

    fn test_app() -> (axum::Router, AuthService, Dir) {
        let keys = JwtKeys::single(
            [7u8; 32],
            "test-kid",
            "https://build.loommud.com/",
            jwt::AUDIENCE,
        );
        let dir = Dir::default();
        let auth = AuthService::new(std::sync::Arc::new(dir.clone()), keys);
        let (ws_accept_tx, _ws_accept_rx) = tokio::sync::mpsc::channel(1);
        let state = HttpState::new(
            ws_accept_tx,
            loom_obs::Readiness::new(),
            loom_obs::PrometheusMetrics::new_unregistered(),
        )
        .with_auth(auth.clone())
        .with_world_query(std::sync::Arc::new(FakeWorldQuery::default()));
        (app(state), auth, dir)
    }

    /// Same as [`test_app`], but also returns the [`Dir`] (so tests can
    /// read the `admin.broadcast` audit rows, M-ADM-4) and a handle onto
    /// the exact strings [`FakeWorldQuery::broadcast`] was called with --
    /// the broadcast route's delivery side, which `test_app`'s shared
    /// `FakeWorldQuery` already answers (so the `200`/`recipients` wire
    /// shape is identical), but these tests also need to inspect what
    /// was actually "delivered".
    fn test_app_with_broadcast_capture() -> (
        axum::Router,
        AuthService,
        Dir,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        test_app_with_broadcast_failing(None)
    }

    /// [`test_app_with_broadcast_capture`], but with the world side's
    /// `broadcast` answering `Err(make_err())` instead of `Ok(2)` -- the
    /// delivery-failure path (CTO review, OBI-233 third pass, optional
    /// item 1: a request that was already queued to a world thread that
    /// then went silent must be audited as an *unknown* outcome, not as a
    /// clean "did not deliver").
    fn test_app_with_broadcast_failing(
        make_err: Option<
            std::sync::Arc<dyn Fn() -> crate::admin_query::WorldQueryError + Send + Sync>,
        >,
    ) -> (
        axum::Router,
        AuthService,
        Dir,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        let keys = JwtKeys::single(
            [7u8; 32],
            "test-kid",
            "https://build.loommud.com/",
            jwt::AUDIENCE,
        );
        let dir = Dir::default();
        let auth = AuthService::new(std::sync::Arc::new(dir.clone()), keys);
        let (ws_accept_tx, _ws_accept_rx) = tokio::sync::mpsc::channel(1);
        let query = FakeWorldQuery {
            broadcasts: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            broadcast_error: make_err,
        };
        let broadcasts = query.broadcasts.clone();
        let state = HttpState::new(
            ws_accept_tx,
            loom_obs::Readiness::new(),
            loom_obs::PrometheusMetrics::new_unregistered(),
        )
        .with_auth(auth.clone())
        .with_world_query(std::sync::Arc::new(query));
        (app(state), auth, dir, broadcasts)
    }

    /// Same as [`test_app`], but with [`HttpState::with_world_query`]
    /// deliberately left unset -- proves the broadcast route's (and
    /// every world-query route's) `503` "not wired" path.
    fn test_app_without_world_query() -> (axum::Router, AuthService) {
        let keys = JwtKeys::single(
            [7u8; 32],
            "test-kid",
            "https://build.loommud.com/",
            jwt::AUDIENCE,
        );
        let auth = AuthService::new(std::sync::Arc::new(Dir::default()), keys);
        let (ws_accept_tx, _ws_accept_rx) = tokio::sync::mpsc::channel(1);
        let state = HttpState::new(
            ws_accept_tx,
            loom_obs::Readiness::new(),
            loom_obs::PrometheusMetrics::new_unregistered(),
        )
        .with_auth(auth.clone());
        (app(state), auth)
    }

    async fn access_token(auth: &AuthService, sub: &str, tier: i16, mfa_at: Option<i64>) -> String {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let claims = crate::auth::AccessClaims {
            sub: sub.to_string(),
            tier,
            scopes: crate::auth::scopes_for_tier(tier),
            iss: "https://build.loommud.com/".to_string(),
            aud: jwt::AUDIENCE.to_string(),
            iat: now,
            nbf: now,
            exp: now + 600,
            sid: "sid".to_string(),
            amr: vec!["pwd".to_string(), "otp".to_string()],
            mfa_at,
        };
        auth.sign_for_test(&claims)
    }

    /// `axum::serve(...).into_make_service_with_connect_info` is what
    /// inserts the `ConnectInfo` extension in production; a direct
    /// `oneshot` call bypasses that service wrapper, so every test here
    /// inserts it the same way (same pattern as `auth::tests::http_wire`).
    fn with_peer(mut request: Request<axum::body::Body>) -> Request<axum::body::Body> {
        let peer: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
        request
    }

    #[tokio::test]
    async fn roles_tier_with_an_actor_field_in_the_body_is_400() {
        let (app, auth, _dir) = test_app();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, "lead", 3, Some(now)).await;

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/roles/tier")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({
                    "actor": "lead",
                    "target_uid": "someone",
                    "new_tier": 2,
                    "reason": "sneaky"
                })
                .to_string(),
            ))
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn roles_tier_without_bearer_is_401() {
        let (app, _auth, _dir) = test_app();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/roles/tier")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"target_uid": "x", "new_tier": 2, "reason": "r"}).to_string(),
            ))
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn roles_tier_below_tier_3_is_forbidden() {
        let (app, auth, _dir) = test_app();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, "builder", 2, Some(now)).await;
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/roles/tier")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"target_uid": "x", "new_tier": 2, "reason": "r"}).to_string(),
            ))
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn roles_tier_succeeds_for_t3_with_step_up() {
        let (app, auth, _dir) = test_app();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, "lead", 3, Some(now)).await;
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/roles/tier")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"target_uid": "apprentice", "new_tier": 2, "reason": "promo"})
                    .to_string(),
            ))
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn audit_view_requires_tier_3() {
        let (app, auth, _dir) = test_app();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, "builder", 2, Some(now)).await;
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/audit")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn audit_view_succeeds_for_t3() {
        let (app, auth, _dir) = test_app();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, "lead", 3, Some(now)).await;
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/audit")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    }

    /// M-ADM-3: `who`'s response shape never carries an email or an IP,
    /// whatever the caller's tier -- asserted directly on the parsed JSON
    /// keys, not just by trusting the Rust type.
    #[tokio::test]
    async fn who_response_never_includes_email_or_ip() {
        let (app, auth, dir) = test_app();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, "builder", 2, Some(now)).await;
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/who")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let rows: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(rows.len(), 1);
        let keys: Vec<&str> = rows[0]
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        assert!(!keys.contains(&"email"));
        assert!(!keys.contains(&"ip"));
        assert!(keys.contains(&"account"));
        assert!(keys.contains(&"connected_at"));
        assert!(keys.contains(&"idle_secs"));

        // M-ADM-4: audited.
        let audits = dir.audits.lock().unwrap();
        assert!(
            audits
                .iter()
                .any(|e| e.kind == "admin.who" && e.verdict == "allow")
        );
    }

    #[tokio::test]
    async fn who_without_bearer_is_401() {
        let (app, _auth, _dir) = test_app();
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/who")
            .body(axum::body::Body::empty())
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn who_below_tier_2_is_forbidden() {
        let (app, auth, dir) = test_app();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, "apprentice", 1, Some(now)).await;
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/who")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let audits = dir.audits.lock().unwrap();
        assert!(
            audits
                .iter()
                .any(|e| e.kind == "admin.who" && e.verdict == "deny")
        );
    }

    #[tokio::test]
    async fn objects_list_below_tier_3_is_forbidden() {
        let (app, auth, dir) = test_app();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, "builder", 2, Some(now)).await;
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/objects")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let audits = dir.audits.lock().unwrap();
        assert!(
            audits
                .iter()
                .any(|e| e.kind == "admin.objects.list" && e.verdict == "deny")
        );
    }

    #[tokio::test]
    async fn objects_list_at_tier_3_is_filtered_by_valid_read() {
        let (app, auth, dir) = test_app();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        // A T3 caller who isn't `lead`: `FakeWorldQuery::list_objects`
        // (standing in for `valid_read`) hides `/secure/master` from
        // anyone but `lead` -- proves the HTTP layer passes the real
        // `euid` through and doesn't re-filter or widen the result.
        let token = access_token(&auth, "domainlead", 3, Some(now)).await;
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/objects")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let rows: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["path"], "/std/room");
        let audits = dir.audits.lock().unwrap();
        assert!(
            audits
                .iter()
                .any(|e| e.kind == "admin.objects.list" && e.verdict == "allow")
        );
    }

    #[tokio::test]
    async fn objects_list_at_tier_3_for_lead_sees_secure_too() {
        let (app, auth, _dir) = test_app();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, "lead", 3, Some(now)).await;
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/objects")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let rows: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[tokio::test]
    async fn object_vars_below_tier_4_is_forbidden() {
        let (app, auth, dir) = test_app();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, "domainlead", 3, Some(now)).await;
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/objects/std/room/vars")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let audits = dir.audits.lock().unwrap();
        assert!(
            audits
                .iter()
                .any(|e| e.kind == "admin.objects.vars" && e.verdict == "deny")
        );
    }

    #[tokio::test]
    async fn object_vars_at_tier_4_succeeds_for_non_secure_path() {
        let (app, auth, dir) = test_app();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, "wizard", 4, Some(now)).await;
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/objects/std/room/vars")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["path"], "/std/room");
        assert_eq!(payload["vars"][0]["name"], "hp");
        let audits = dir.audits.lock().unwrap();
        assert!(
            audits
                .iter()
                .any(|e| e.kind == "admin.objects.vars" && e.verdict == "allow")
        );
    }

    #[tokio::test]
    async fn object_vars_for_secure_path_below_tier_5_is_forbidden() {
        let (app, auth, dir) = test_app();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        // T4 passes the plain object-vars floor but not the stricter
        // `/secure/` one.
        let token = access_token(&auth, "wizard", 4, Some(now)).await;
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/objects/secure/master/vars")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let audits = dir.audits.lock().unwrap();
        assert!(
            audits
                .iter()
                .any(|e| e.kind == "admin.objects.vars" && e.verdict == "deny")
        );
    }

    #[tokio::test]
    async fn object_vars_for_secure_path_at_tier_5_succeeds() {
        let (app, auth, _dir) = test_app();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, "lead", 5, Some(now)).await;
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/objects/secure/master/vars")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["path"], "/secure/master");
    }

    #[tokio::test]
    async fn object_vars_without_world_query_wired_is_503() {
        // Same shape as `/auth/*`'s "optional, 503 if unconfigured" rule
        // (`lib.rs` module doc): no `with_world_query` call at all.
        let keys = JwtKeys::single(
            [7u8; 32],
            "test-kid",
            "https://build.loommud.com/",
            jwt::AUDIENCE,
        );
        let auth = AuthService::new(std::sync::Arc::new(Dir::default()), keys);
        let (ws_accept_tx, _ws_accept_rx) = tokio::sync::mpsc::channel(1);
        let state = HttpState::new(
            ws_accept_tx,
            loom_obs::Readiness::new(),
            loom_obs::PrometheusMetrics::new_unregistered(),
        )
        .with_auth(auth.clone());
        let app = app(state);
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, "lead", 5, Some(now)).await;
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/objects/secure/master/vars")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn errors_below_tier_3_is_forbidden() {
        let (app, auth, dir) = test_app();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, "builder", 2, Some(now)).await;
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/errors")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let audits = dir.audits.lock().unwrap();
        assert!(
            audits
                .iter()
                .any(|e| e.kind == "admin.errors" && e.verdict == "deny")
        );
    }

    #[tokio::test]
    async fn errors_at_tier_3_is_filtered_and_redacted_by_world_query() {
        let (app, auth, dir) = test_app();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        // `domainlead` is T3 but not `lead`: `FakeWorldQuery::errors`
        // hides `/secure/master`'s group entirely for non-`lead` callers
        // -- proves the HTTP layer passes the real `euid` through and
        // doesn't widen the result.
        let token = access_token(&auth, "domainlead", 3, Some(now)).await;
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/errors")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let rows: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["program"], "/d/shire/calc.wf");
        assert_eq!(rows[0]["count"], 3);
        let audits = dir.audits.lock().unwrap();
        assert!(
            audits
                .iter()
                .any(|e| e.kind == "admin.errors" && e.verdict == "allow")
        );
    }

    #[tokio::test]
    async fn errors_at_tier_3_for_lead_sees_the_redacted_secure_group_too() {
        let (app, auth, _dir) = test_app();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, "lead", 3, Some(now)).await;
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/errors")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let rows: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter()
                .any(|r| r["program"] == "/secure/master" && r["redacted"] == true)
        );
    }

    #[tokio::test]
    async fn errors_program_prefix_query_param_is_forwarded() {
        let (app, auth, _dir) = test_app();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, "domainlead", 3, Some(now)).await;
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/errors?program_prefix=/d/shire")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let request = with_peer(request);
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let rows: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(rows.len(), 1);

        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/errors?program_prefix=/nowhere")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let rows: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(rows.len(), 0);
    }

    #[tokio::test]
    async fn errors_without_bearer_is_401() {
        let (app, _auth, _dir) = test_app();
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/errors")
            .body(axum::body::Body::empty())
            .unwrap();
        let request = with_peer(request);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    fn broadcast_request(token: &str, text: &str) -> Request<axum::body::Body> {
        with_peer(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/broadcast")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"text": text}).to_string(),
                ))
                .unwrap(),
        )
    }

    /// The `sub` the broadcast tests below mint their token for, and the
    /// actor `broadcast_audit` asserts the row carries (M-ADM-1: always the
    /// token's `sub`, never anything the body could say).
    const BROADCAST_ACTOR: &str = "root";

    /// M-ADM-4: the single `admin.broadcast` audit row an attempt must have
    /// produced, as `(verdict, detail)`. Asserts *exactly one* row -- not
    /// `any(...)` -- so an outcome that audits twice, or not at all, fails
    /// the test rather than passing on a stray sibling row.
    fn broadcast_audit(dir: &Dir) -> (String, String) {
        let rows: Vec<crate::auth::AuditEvent> = {
            let audits = dir.audits.lock().unwrap();
            audits
                .iter()
                .filter(|e| e.kind == "admin.broadcast")
                .cloned()
                .collect()
        };
        assert_eq!(
            rows.len(),
            1,
            "expected exactly one `admin.broadcast` audit row, got {}",
            rows.len()
        );
        let row = &rows[0];
        assert_eq!(
            row.uid.as_deref(),
            Some(BROADCAST_ACTOR),
            "M-ADM-4: the audited actor is the token's `sub`"
        );
        assert!(
            row.ip.is_some(),
            "M-ADM-4: the audit row carries the request's IP"
        );
        (
            row.verdict.to_string(),
            row.detail.clone().unwrap_or_default(),
        )
    }

    /// The `reason=<token>` inside a deny `detail`, or `""` when the row
    /// carries none (the `allow` row has no reason to give).
    fn audit_reason(detail: &str) -> String {
        detail
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix("reason="))
            .unwrap_or_default()
            .to_string()
    }

    /// The `text=<delivered>` part of an `admin.broadcast` `detail` --
    /// everything after the first ` text=` token, so M-IDE-2 can be checked
    /// against exactly what went to sessions.
    fn audit_delivered_text(detail: &str) -> String {
        detail
            .split_once(" text=")
            .map(|(_, rest)| rest.to_string())
            .unwrap_or_default()
    }

    /// The audit shape every deny path shares: exactly one `admin.broadcast`
    /// row, verdict `deny`, carrying `reason=<expected_reason>`.
    fn assert_denied_audit(dir: &Dir, expected_reason: &str) {
        let (verdict, detail) = broadcast_audit(dir);
        assert_eq!(verdict, "deny", "detail was {detail:?}");
        assert_eq!(audit_reason(&detail), expected_reason);
    }

    #[tokio::test]
    async fn broadcast_is_503_when_world_query_is_not_wired() {
        let (app, auth) = test_app_without_world_query();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, BROADCAST_ACTOR, 5, Some(now)).await;
        let response = app
            .oneshot(broadcast_request(&token, "server restart in 5m"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn broadcast_without_bearer_is_401() {
        let (app, _auth, _dir, _broadcasts) = test_app_with_broadcast_capture();
        let request = with_peer(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/broadcast")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"text": "hi"}).to_string(),
                ))
                .unwrap(),
        );
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// M-ADM-2 + M-ADM-4: a T3 caller (enough for a role change, not for
    /// broadcast) is refused *and* the refusal is on the audit trail with
    /// `reason=forbidden` -- nothing reaches the world side at all.
    #[tokio::test]
    async fn broadcast_below_tier_4_is_forbidden_and_audited() {
        let (app, auth, dir, broadcasts) = test_app_with_broadcast_capture();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, "lead", 3, Some(now)).await;
        let response = app
            .oneshot(broadcast_request(&token, "server restart"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        {
            // The actor here is `lead`, not `BROADCAST_ACTOR`, so check the
            // row directly instead of through `broadcast_audit`.
            let audits = dir.audits.lock().unwrap();
            let rows: Vec<&crate::auth::AuditEvent> = audits
                .iter()
                .filter(|e| e.kind == "admin.broadcast")
                .collect();
            assert_eq!(rows.len(), 1, "expected exactly one audit row");
            assert_eq!(rows[0].verdict, "deny");
            assert_eq!(rows[0].uid.as_deref(), Some("lead"));
            assert!(rows[0].ip.is_some());
            assert_eq!(
                audit_reason(rows[0].detail.as_deref().unwrap_or("")),
                "forbidden"
            );
        }
        assert!(
            broadcasts.lock().unwrap().is_empty(),
            "a forbidden broadcast must never reach the world side"
        );
    }

    /// M-ADM-2 + M-ADM-4: high enough tier but no fresh `mfa_at` is refused
    /// with `reason=step_up_required`, audited, and never delivered.
    #[tokio::test]
    async fn broadcast_at_tier_4_without_step_up_is_forbidden_and_audited() {
        let (app, auth, dir, broadcasts) = test_app_with_broadcast_capture();
        // `mfa_at: None` -- never stepped up.
        let token = access_token(&auth, BROADCAST_ACTOR, 4, None).await;
        let response = app
            .oneshot(broadcast_request(&token, "server restart"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_denied_audit(&dir, "step_up_required");
        assert!(
            broadcasts.lock().unwrap().is_empty(),
            "a step-up refusal must never reach the world side"
        );
    }

    /// M-ADM-5 + M-ADM-4: an over-1 KiB body is rejected (not truncated),
    /// audited as `reason=body_too_large`, and never delivered.
    #[tokio::test]
    async fn broadcast_with_a_body_over_1kib_is_rejected_and_audited() {
        let (app, auth, dir, broadcasts) = test_app_with_broadcast_capture();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, BROADCAST_ACTOR, 5, Some(now)).await;
        let oversized = "a".repeat(1025);
        let response = app
            .oneshot(broadcast_request(&token, &oversized))
            .await
            .unwrap();
        assert!(
            response.status() == StatusCode::PAYLOAD_TOO_LARGE
                || response.status() == StatusCode::BAD_REQUEST,
            "expected 413 or 400, got {}",
            response.status()
        );
        let (verdict, detail) = broadcast_audit(&dir);
        assert_eq!(verdict, "deny");
        assert_eq!(audit_reason(&detail), "body_too_large");
        assert!(
            detail.contains("bytes=1025"),
            "the row should say how big the body was: {detail:?}"
        );
        assert!(
            !detail.contains("text="),
            "an oversized body must not be recorded verbatim: {detail:?}"
        );
        assert!(
            broadcasts.lock().unwrap().is_empty(),
            "an oversized body must never reach the world side, even truncated"
        );
    }

    /// A body that sanitizes down to nothing is a 400 with
    /// `reason=empty_after_sanitizing`, audited, and never delivered as a
    /// blank line (CTO review, first pass, non-blocking 3).
    #[tokio::test]
    async fn broadcast_that_sanitizes_to_nothing_is_400_and_audited() {
        let (app, auth, dir, broadcasts) = test_app_with_broadcast_capture();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, BROADCAST_ACTOR, 5, Some(now)).await;
        // Entirely control characters: sanitizes down to the empty string.
        let response = app
            .oneshot(broadcast_request(&token, "\x07\x1b\x01"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_denied_audit(&dir, "empty_after_sanitizing");
        assert!(
            broadcasts.lock().unwrap().is_empty(),
            "a blank broadcast must never reach the world side"
        );
    }

    /// M-ADM-4 + M-IDE-2 + CTO review (first pass, must-fix 1): the `allow`
    /// row records the *exact* string delivered to sessions -- sanitized,
    /// `[Broadcast] `-prefixed, one trailing `\n` -- plus the real recipient
    /// count, and never the raw input.
    #[tokio::test]
    async fn broadcast_succeeds_for_t4_with_step_up_and_reaches_world_query() {
        let (app, auth, dir, broadcasts) = test_app_with_broadcast_capture();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, BROADCAST_ACTOR, 4, Some(now)).await;
        let response = app
            .oneshot(broadcast_request(&token, "server restart in 5m\x07"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["recipients"], 2);

        let delivered = broadcasts.lock().unwrap().clone();
        assert_eq!(delivered, vec!["[Broadcast] server restart in 5m\n"]);

        let (verdict, detail) = broadcast_audit(&dir);
        assert_eq!(verdict, "allow");
        assert_eq!(audit_reason(&detail), "", "an allow row carries no reason");
        assert!(
            detail.contains("recipients=2"),
            "the row records how many sessions got it: {detail:?}"
        );
        // M-IDE-2: audited text == delivered text, byte for byte, control
        // character stripped -- one string, never two derivations.
        assert_eq!(
            audit_delivered_text(&detail),
            delivered[0],
            "the audited detail must be exactly what was delivered"
        );
        assert!(
            !detail.contains('\u{7}'),
            "raw control bytes must not be stored"
        );
    }

    /// A multi-line body gets the prefix on *every* line (CTO review, second
    /// pass), and the sanitizer strips bidi/zero-width characters, the
    /// line/paragraph separators and `U+061C` (CTO review, third pass,
    /// optional 2) in addition to C0/C1 controls.
    #[tokio::test]
    async fn broadcast_prefixes_every_line_and_strips_bidi_and_zero_width() {
        let (app, auth, dir, broadcasts) = test_app_with_broadcast_capture();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, BROADCAST_ACTOR, 4, Some(now)).await;
        let text =
            "line one\u{202E}\nline\u{200B} two\u{FEFF}\nthree\u{2028}\u{2029}\u{061C}four\u{2066}";
        let response = app.oneshot(broadcast_request(&token, text)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let delivered = broadcasts.lock().unwrap().clone();
        assert_eq!(
            delivered,
            vec!["[Broadcast] line one\n[Broadcast] line two\n[Broadcast] threefour\n"]
        );

        // Every line of a multi-line broadcast keeps its prefix, so nothing
        // can be delivered as an unattributed continuation line.
        let delivered_text = &delivered[0];
        assert!(delivered_text.starts_with("[Broadcast] "));
        for line in delivered_text.trim_end_matches('\n').split('\n') {
            assert!(
                line.starts_with("[Broadcast] "),
                "line {line:?} lost its attribution"
            );
        }

        let (verdict, detail) = broadcast_audit(&dir);
        assert_eq!(verdict, "allow");
        assert_eq!(audit_delivered_text(&detail), delivered_text.as_str());
    }

    #[tokio::test]
    async fn broadcast_with_an_unknown_field_is_400() {
        let (app, auth, dir, _broadcasts) = test_app_with_broadcast_capture();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, BROADCAST_ACTOR, 5, Some(now)).await;
        let request = with_peer(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/broadcast")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"text": "hi", "actor": "root"}).to_string(),
                ))
                .unwrap(),
        );
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        // Deliberate, and matching `admin_set_tier`: a body that never
        // parsed is a 400 from the handler, before `AuthService` ever sees
        // it, so there is no `admin.broadcast` row for it.
        let audits = dir.audits.lock().unwrap();
        assert!(
            !audits.iter().any(|e| e.kind == "admin.broadcast"),
            "a body that failed to parse must not produce an allow/deny row"
        );
    }

    /// CTO review (OBI-233, first pass, must-fix 2) and (third pass,
    /// optional 1): a delivery that the world side *refused outright*
    /// (`Busy`: the request never left `loom-http`) is a `503`, audited as a
    /// deny with `outcome=not_delivered` -- never a `204` an operator could
    /// misread as "sent".
    #[tokio::test]
    async fn broadcast_reports_503_and_audits_not_delivered_when_the_world_is_busy() {
        let (app, auth, dir, _broadcasts) =
            test_app_with_broadcast_failing(Some(std::sync::Arc::new(|| {
                crate::admin_query::WorldQueryError::Busy
            })));
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, BROADCAST_ACTOR, 4, Some(now)).await;
        let response = app
            .oneshot(broadcast_request(&token, "server restart in 5m"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let (verdict, detail) = broadcast_audit(&dir);
        assert_eq!(verdict, "deny");
        assert_eq!(audit_reason(&detail), "Busy");
        assert!(
            detail.contains("outcome=not_delivered"),
            "a `try_send` that failed never left the process: {detail:?}"
        );
    }

    /// CTO review (OBI-233, third pass, optional 1): a `Timeout` means the
    /// request *was* queued to the world thread and no reply came back, so
    /// the broadcast may well have gone out. The audit row must say the
    /// outcome is unknown, not imply it definitely wasn't delivered.
    #[tokio::test]
    async fn broadcast_audits_an_unknown_outcome_when_the_world_times_out() {
        let (app, auth, dir, broadcasts) =
            test_app_with_broadcast_failing(Some(std::sync::Arc::new(|| {
                crate::admin_query::WorldQueryError::Timeout
            })));
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = access_token(&auth, BROADCAST_ACTOR, 4, Some(now)).await;
        let response = app
            .oneshot(broadcast_request(&token, "server restart in 5m"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let (verdict, detail) = broadcast_audit(&dir);
        assert_eq!(verdict, "deny");
        assert_eq!(audit_reason(&detail), "Timeout");
        assert!(
            detail.contains("outcome=unknown"),
            "a queued-but-unanswered request may have been delivered: {detail:?}"
        );
        // The request really did reach the channel, which is *why* the
        // outcome is unknowable from here.
        assert_eq!(broadcasts.lock().unwrap().len(), 1);
    }
}
