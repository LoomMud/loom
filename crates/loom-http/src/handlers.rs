// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `/auth/*` HTTP routes (OBI-174, hardened per OBI-199/OBI-200). Mounted
//! unconditionally by [`app`] but every handler checks `HttpState`'s
//! `auth`/`github` fields and answers `503` if the relevant service isn't
//! configured -- same "optional, absent by default" shape as `web_root`
//! (OBI-158).

use axum::Json;
use axum::Router;
use axum::extract::ConnectInfo;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use serde::{Deserialize, Serialize};

use crate::HttpState;
use crate::auth::{
    ACCESS_AUDIENCE, AccessClaims, AuthContext, AuthError, GithubAuthError, TokenPair,
};
use crate::client_ip::client_ip;

pub fn auth_router() -> Router<HttpState> {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/totp/enroll", post(totp_enroll))
        .route("/auth/totp/verify", post(totp_verify))
        .route("/auth/mfa/step-up", post(mfa_step_up))
        .route("/auth/github/callback", post(github_callback))
        .route("/auth/admin/totp-reset", post(admin_totp_reset))
        .route("/auth/admin/github/link", post(admin_github_link))
        .route("/auth/admin/github/unlink", post(admin_github_unlink))
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    totp_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
struct GithubCallbackRequest {
    code: String,
}

#[derive(Debug, Deserialize)]
struct TotpEnrollRequest {
    password: String,
    /// Required when re-enrolling over an already-confirmed secret (a
    /// TOTP reset); ignored/unused for a brand new T3+ bootstrap
    /// enrolment, which has no existing secret to prove possession of.
    existing_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TotpVerifyRequest {
    code: String,
}

#[derive(Debug, Deserialize)]
struct StepUpRequest {
    code: String,
}

#[derive(Debug, Deserialize)]
struct AdminTotpResetRequest {
    uid: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct AdminGithubLinkRequest {
    uid: String,
    github_id: i64,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct AdminGithubUnlinkRequest {
    uid: String,
    reason: String,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    access_expires_at: i64,
    refresh_expires_at: i64,
}

impl From<TokenPair> for TokenResponse {
    fn from(pair: TokenPair) -> Self {
        TokenResponse {
            access_token: pair.access_token,
            refresh_token: pair.refresh_token,
            access_expires_at: pair.access_expires_at.unix_timestamp(),
            refresh_expires_at: pair.refresh_expires_at.unix_timestamp(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: &'static str,
    /// Only set for [`AuthError::EnrolmentRequired`]: the narrow
    /// bootstrap credential the client uses on `/auth/totp/enroll`
    /// instead of a normal access token, since this account has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    enrol_token: Option<String>,
}

fn auth_error_response(error: AuthError) -> (StatusCode, Json<ErrorResponse>) {
    let (status, code, enrol_token) = match error {
        AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials", None),
        AuthError::TotpRequired => (StatusCode::FORBIDDEN, "totp_required", None),
        AuthError::TotpInvalid => (StatusCode::FORBIDDEN, "totp_invalid", None),
        AuthError::EnrolmentRequired(token) => {
            (StatusCode::FORBIDDEN, "enrolment_required", Some(token))
        }
        AuthError::StepUpRequired => (StatusCode::FORBIDDEN, "step_up_required", None),
        AuthError::InvalidRefreshToken => (StatusCode::UNAUTHORIZED, "invalid_refresh_token", None),
        AuthError::DirectoryUnavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable", None),
        AuthError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", None),
    };
    (
        status,
        Json(ErrorResponse {
            error: code,
            enrol_token,
        }),
    )
}

fn unavailable() -> axum::response::Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse {
            error: "unavailable",
            enrol_token: None,
        }),
    )
        .into_response()
}

/// Build the [`AuthContext`] (client IP + user agent) an auth call needs
/// for rate limiting and audit (OBI-200). `peer` is the TCP connection's
/// address (see [`crate::client_ip::client_ip`]'s doc comment on why XFF
/// is trusted unconditionally here).
fn auth_context(headers: &HeaderMap, peer: Option<std::net::SocketAddr>) -> AuthContext {
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(256).collect::<String>());
    AuthContext::new(client_ip(headers, peer), user_agent)
}

/// Extract and verify the bearer access token's claims, whatever its
/// `aud`. Handlers that need a *full* session (not the narrow enrolment
/// credential) must additionally check `claims.aud == ACCESS_AUDIENCE`
/// (or use [`bearer_access_claims`]) -- this function alone only proves
/// "a validly signed, unexpired token for this `sub`".
fn bearer_claims(headers: &HeaderMap, state: &HttpState) -> Option<AccessClaims> {
    let auth = state.auth.as_ref()?;
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let token = value.strip_prefix("Bearer ")?;
    auth.verify_access_token(token).ok()
}

/// Same as [`bearer_claims`] but refuses an enrolment-only token --
/// callers that are not `/auth/totp/*` must never accept one (even though
/// its empty `tier`/`scopes` already make it useless for anything
/// scope-gated, this is the explicit, auditable check).
fn bearer_access_claims(headers: &HeaderMap, state: &HttpState) -> Option<AccessClaims> {
    let claims = bearer_claims(headers, state)?;
    (claims.aud == ACCESS_AUDIENCE).then_some(claims)
}

async fn login(
    State(state): State<HttpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> impl IntoResponse {
    let Some(auth) = state.auth.as_ref() else {
        return unavailable();
    };
    let ctx = auth_context(&headers, Some(peer));
    match auth
        .login(
            &request.username,
            &request.password,
            request.totp_code.as_deref(),
            &ctx,
        )
        .await
    {
        Ok(pair) => (StatusCode::OK, Json(TokenResponse::from(pair))).into_response(),
        Err(error) => auth_error_response(error).into_response(),
    }
}

async fn refresh(
    State(state): State<HttpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<RefreshRequest>,
) -> impl IntoResponse {
    let Some(auth) = state.auth.as_ref() else {
        return unavailable();
    };
    let ctx = auth_context(&headers, Some(peer));
    match auth.refresh(&request.refresh_token, &ctx).await {
        Ok(pair) => (StatusCode::OK, Json(TokenResponse::from(pair))).into_response(),
        Err(error) => auth_error_response(error).into_response(),
    }
}

async fn logout(
    State(state): State<HttpState>,
    Json(request): Json<RefreshRequest>,
) -> impl IntoResponse {
    let Some(auth) = state.auth.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match auth.logout(&request.refresh_token).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => auth_error_response(error).into_response(),
    }
}

/// (Re-)enrol TOTP (OBI-199, M-AUTH-8). Accepts *either* a normal access
/// token (self re-enrolment/reset, step-up-gated when a confirmed secret
/// already exists) or the narrow T3+ bootstrap enrolment token (first
/// enrolment only) -- see [`bearer_claims`].
async fn totp_enroll(
    State(state): State<HttpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<TotpEnrollRequest>,
) -> impl IntoResponse {
    let Some(claims) = bearer_claims(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // Safe to unwrap: `bearer_claims` only returns `Some` when
    // `state.auth` is `Some`.
    let auth = state.auth.as_ref().unwrap();
    let ctx = auth_context(&headers, Some(peer));
    match auth
        .totp_enroll(
            &claims.sub,
            &request.password,
            request.existing_code.as_deref(),
            &ctx,
        )
        .await
    {
        Ok(enrollment) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "secret_base32": enrollment.secret_base32,
                "otpauth_url": enrollment.otpauth_url,
            })),
        )
            .into_response(),
        Err(error) => auth_error_response(error).into_response(),
    }
}

/// Confirm a just-enrolled secret. Same `aud`-agnostic bearer acceptance
/// as [`totp_enroll`] -- this is the step that actually activates the
/// T3+ bootstrap account, so it must also work with the enrolment-only
/// token.
async fn totp_verify(
    State(state): State<HttpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<TotpVerifyRequest>,
) -> impl IntoResponse {
    let Some(claims) = bearer_claims(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let auth = state.auth.as_ref().unwrap();
    let ctx = auth_context(&headers, Some(peer));
    match auth.totp_confirm(&claims.sub, &request.code, &ctx).await {
        Ok(recovery_codes) => (
            StatusCode::OK,
            Json(serde_json::json!({ "recovery_codes": recovery_codes })),
        )
            .into_response(),
        Err(error) => auth_error_response(error).into_response(),
    }
}

/// Step-up re-verification (design threat-model-phase2.md \u00a76.1 M-ADM-2:
/// "the UI re-prompts for TOTP"): re-proves the second factor for an
/// already-authenticated session, refreshing `mfa_at` so a subsequent
/// step-up-gated call (admin TOTP reset, GitHub link/unlink) succeeds.
/// Requires a full access token -- the bootstrap enrolment token has
/// nothing to step up from.
async fn mfa_step_up(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<StepUpRequest>,
) -> impl IntoResponse {
    let Some(claims) = bearer_access_claims(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let auth = state.auth.as_ref().unwrap();
    match auth.step_up(&claims.sub, &request.code).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => auth_error_response(error).into_response(),
    }
}

async fn github_callback(
    State(state): State<HttpState>,
    Json(request): Json<GithubCallbackRequest>,
) -> impl IntoResponse {
    let (Some(auth), Some(github)) = (state.auth.as_ref(), state.github.as_ref()) else {
        return unavailable();
    };
    let user = match github.exchange_code(&request.code).await {
        Ok(user) => user,
        Err(GithubAuthError::InvalidCode) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_code",
                    enrol_token: None,
                }),
            )
                .into_response();
        }
        Err(GithubAuthError::Unavailable) => {
            return unavailable();
        }
    };
    match auth.github_login(user.id).await {
        Ok(pair) => (StatusCode::OK, Json(TokenResponse::from(pair))).into_response(),
        Err(error) => auth_error_response(error).into_response(),
    }
}

/// Admin (T4+) TOTP reset for a *different* uid (OBI-199, M-ADM-2: "TOTP
/// reset ... admin"). Step-up-gated on the actor's own `mfa_at`; scope
/// (T4+) is enforced in SQL (`auth_totp_admin_reset`) -- this handler
/// only requires *a* valid full session, same shape as every other
/// privileged write in this module until scope-gating lands (see the
/// OBI-174 PR caveat).
async fn admin_totp_reset(
    State(state): State<HttpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<AdminTotpResetRequest>,
) -> impl IntoResponse {
    let Some(claims) = bearer_access_claims(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let auth = state.auth.as_ref().unwrap();
    let ctx = auth_context(&headers, Some(peer));
    match auth
        .totp_admin_reset(&claims.sub, &request.uid, &request.reason, &ctx)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => auth_error_response(error).into_response(),
    }
}

/// Admin (T4+) GitHub link, step-up-gated (OBI-199, M-AUTH-7/M-ADM-2).
async fn admin_github_link(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<AdminGithubLinkRequest>,
) -> impl IntoResponse {
    let Some(claims) = bearer_access_claims(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let auth = state.auth.as_ref().unwrap();
    match auth
        .github_link(
            &claims.sub,
            &request.uid,
            request.github_id,
            &request.reason,
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => auth_error_response(error).into_response(),
    }
}

/// Admin (T4+) GitHub unlink, step-up-gated (OBI-199).
async fn admin_github_unlink(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<AdminGithubUnlinkRequest>,
) -> impl IntoResponse {
    let Some(claims) = bearer_access_claims(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let auth = state.auth.as_ref().unwrap();
    match auth
        .github_unlink(&claims.sub, &request.uid, &request.reason)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => auth_error_response(error).into_response(),
    }
}
