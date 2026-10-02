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
    // parsing, status codes, bearer extraction).
    #[derive(Default, Clone)]
    struct Dir;

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
        async fn refresh_token_rotate(
            &self,
            _token_hash: &str,
        ) -> Result<crate::auth::RefreshRotation, crate::auth::DirectoryError> {
            Ok(crate::auth::RefreshRotation::NotFound)
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
            _event: crate::auth::AuditEvent,
        ) -> Result<(), crate::auth::DirectoryError> {
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

    fn test_app() -> (axum::Router, AuthService) {
        let keys = JwtKeys::single(
            [7u8; 32],
            "test-kid",
            "https://build.loommud.com/",
            jwt::AUDIENCE,
        );
        let auth = AuthService::new(std::sync::Arc::new(Dir), keys);
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
        let (app, auth) = test_app();
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
        let (app, _auth) = test_app();
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
        let (app, auth) = test_app();
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
        let (app, auth) = test_app();
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
        let (app, auth) = test_app();
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
        let (app, auth) = test_app();
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
}
