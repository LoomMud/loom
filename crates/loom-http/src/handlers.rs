// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `/auth/*` HTTP routes (OBI-174). Mounted unconditionally by [`app`] but
//! every handler checks `HttpState`'s `auth`/`github` fields and answers
//! `503` if the relevant service isn't configured -- same "optional,
//! absent by default" shape as `web_root` (OBI-158).

use axum::Json;
use axum::Router;
use axum::extract::ConnectInfo;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use serde::{Deserialize, Serialize};

use crate::HttpState;
use crate::auth::{AuthContext, AuthError, GithubAuthError, TokenPair};
use crate::client_ip::client_ip;

pub fn auth_router() -> Router<HttpState> {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/totp/enroll", post(totp_enroll))
        .route("/auth/totp/verify", post(totp_verify))
        .route("/auth/github/callback", post(github_callback))
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
struct TotpVerifyRequest {
    code: String,
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
}

fn auth_error_response(error: AuthError) -> (StatusCode, Json<ErrorResponse>) {
    let (status, code) = match error {
        AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
        AuthError::TotpRequired => (StatusCode::FORBIDDEN, "totp_required"),
        AuthError::TotpInvalid => (StatusCode::FORBIDDEN, "totp_invalid"),
        AuthError::InvalidRefreshToken => (StatusCode::UNAUTHORIZED, "invalid_refresh_token"),
        AuthError::DirectoryUnavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        AuthError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
    };
    (status, Json(ErrorResponse { error: code }))
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

/// Extract `sub` from a bearer access token in `Authorization: Bearer ...`.
/// `None` for a missing header or a token that fails verification --
/// callers answer `401` either way; they never need to distinguish.
fn bearer_uid(headers: &HeaderMap, state: &HttpState) -> Option<String> {
    let auth = state.auth.as_ref()?;
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let token = value.strip_prefix("Bearer ")?;
    auth.verify_access_token(token)
        .ok()
        .map(|claims| claims.sub)
}

async fn login(
    State(state): State<HttpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> impl IntoResponse {
    let Some(auth) = state.auth.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "unavailable",
            }),
        )
            .into_response();
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
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "unavailable",
            }),
        )
            .into_response();
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

async fn totp_enroll(
    State(state): State<HttpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(uid) = bearer_uid(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // Safe to unwrap: `bearer_uid` only returns `Some` when `state.auth`
    // is `Some`.
    let auth = state.auth.as_ref().unwrap();
    let ctx = auth_context(&headers, Some(peer));
    match auth.totp_enroll(&uid, &ctx).await {
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

async fn totp_verify(
    State(state): State<HttpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<TotpVerifyRequest>,
) -> impl IntoResponse {
    let Some(uid) = bearer_uid(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let auth = state.auth.as_ref().unwrap();
    let ctx = auth_context(&headers, Some(peer));
    match auth.totp_confirm(&uid, &request.code, &ctx).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => auth_error_response(error).into_response(),
    }
}

async fn github_callback(
    State(state): State<HttpState>,
    Json(request): Json<GithubCallbackRequest>,
) -> impl IntoResponse {
    let (Some(auth), Some(github)) = (state.auth.as_ref(), state.github.as_ref()) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "unavailable",
            }),
        )
            .into_response();
    };
    let user = match github.exchange_code(&request.code).await {
        Ok(user) => user,
        Err(GithubAuthError::InvalidCode) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_code",
                }),
            )
                .into_response();
        }
        Err(GithubAuthError::Unavailable) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "unavailable",
                }),
            )
                .into_response();
        }
    };
    match auth.github_login(user.id).await {
        Ok(pair) => (StatusCode::OK, Json(TokenResponse::from(pair))).into_response(),
        Err(error) => auth_error_response(error).into_response(),
    }
}
