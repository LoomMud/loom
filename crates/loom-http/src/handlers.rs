// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `/auth/*` HTTP routes (OBI-174, OBI-198). Mounted unconditionally by
//! [`app`] but every handler checks `HttpState`'s `auth`/`github` fields
//! and answers `503` if the relevant service isn't configured -- same
//! "optional, absent by default" shape as `web_root` (OBI-158).
//!
//! `/auth/refresh` and `/auth/logout` (OBI-198, D-TM2/M-AUTH-5/M-AUTH-6):
//! the refresh token travels only as an HttpOnly `__Host-loom_rt` cookie,
//! never in a JSON request or response body, and both routes refuse
//! outright unless `Origin` is on `HttpState`'s staff-origin allowlist
//! *and* the request carries `X-Loom-Auth: 1` -- see
//! `crate::auth::staff_csrf_guard_passes`. This service never sends an
//! `Access-Control-Allow-*` header for any route.

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
struct GithubCallbackRequest {
    code: String,
    #[serde(default)]
    totp_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TotpVerifyRequest {
    code: String,
}

/// The access token plus its expiry (design §9/D-TM2, OBI-198): the
/// refresh token itself never appears here any more -- it only ever
/// travels as the `__Host-loom_rt` cookie, never in a JSON body a script
/// could read.
#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    access_expires_at: i64,
}

impl From<&TokenPair> for TokenResponse {
    fn from(pair: &TokenPair) -> Self {
        TokenResponse {
            access_token: pair.access_token.clone(),
            access_expires_at: pair.access_expires_at.unix_timestamp(),
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
        AuthError::TotpAlreadyEnrolled => (StatusCode::CONFLICT, "totp_already_enrolled"),
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
pub(crate) fn bearer_uid(headers: &HeaderMap, state: &HttpState) -> Option<String> {
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

/// Build the `200 OK` response for a successful login/refresh: the JSON
/// body (access token only) plus the `Set-Cookie` header carrying the
/// rotated refresh token (OBI-198, D-TM2).
fn token_response(pair: &TokenPair) -> axum::response::Response {
    let max_age = (pair.refresh_expires_at - time::OffsetDateTime::now_utc())
        .whole_seconds()
        .max(0);
    let mut response = (StatusCode::OK, Json(TokenResponse::from(pair))).into_response();
    response.headers_mut().insert(
        crate::auth::set_cookie_name(),
        crate::auth::set_cookie_header(&pair.refresh_token, max_age),
    );
    response
}

/// M-AUTH-6: require `Origin` ∈ the staff-origin allowlist and
/// `X-Loom-Auth: 1` before touching the cookie at all -- a request that
/// fails this never even reaches the refresh-token cookie extraction
/// below.
fn csrf_guard_response(headers: &HeaderMap, state: &HttpState) -> Option<axum::response::Response> {
    if crate::auth::staff_csrf_guard_passes(headers, &state.staff_origins) {
        None
    } else {
        Some(
            (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "origin_not_allowed",
                }),
            )
                .into_response(),
        )
    }
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
        Ok(pair) => token_response(&pair),
        Err(error) => auth_error_response(error).into_response(),
    }
}

async fn refresh(
    State(state): State<HttpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(rejection) = csrf_guard_response(&headers, &state) {
        return rejection;
    }
    let Some(auth) = state.auth.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "unavailable",
            }),
        )
            .into_response();
    };
    let Some(refresh_token) = crate::auth::refresh_token_from_cookies(&headers) else {
        return auth_error_response(AuthError::InvalidRefreshToken).into_response();
    };
    let ctx = auth_context(&headers, Some(peer));
    match auth.refresh(&refresh_token, &ctx).await {
        Ok(pair) => token_response(&pair),
        Err(error) => {
            // Should-fix (OBI-198 re-review): a dead/reused/expired
            // refresh also clears the cookie, so the browser stops
            // sending a token that will never work again.
            let mut response = auth_error_response(error).into_response();
            response.headers_mut().insert(
                crate::auth::set_cookie_name(),
                crate::auth::clear_cookie_header(),
            );
            response
        }
    }
}

async fn logout(State(state): State<HttpState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(rejection) = csrf_guard_response(&headers, &state) {
        return rejection;
    }
    let Some(auth) = state.auth.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(refresh_token) = crate::auth::refresh_token_from_cookies(&headers) else {
        // No cookie presented: nothing to revoke, but still clear
        // whatever the client has (idempotent logout).
        let mut response = StatusCode::NO_CONTENT.into_response();
        response.headers_mut().insert(
            crate::auth::set_cookie_name(),
            crate::auth::clear_cookie_header(),
        );
        return response;
    };
    match auth.logout(&refresh_token).await {
        Ok(()) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            response.headers_mut().insert(
                crate::auth::set_cookie_name(),
                crate::auth::clear_cookie_header(),
            );
            response
        }
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
    match auth
        .github_login(user.id, request.totp_code.as_deref())
        .await
    {
        Ok(pair) => token_response(&pair),
        Err(error) => auth_error_response(error).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use http_body_util::BodyExt;
    use tokio::sync::mpsc;
    use tower::ServiceExt;

    use crate::auth::tests::{FakeDirectory, test_service};

    const STAFF_ORIGIN: &str = "https://staff.loom.example";

    async fn app_with_auth() -> (Router, FakeDirectory) {
        let directory = FakeDirectory::new();
        directory.add_staff("frodo", "ringbearer", 1);
        let service = test_service(directory.clone());

        let (ws_accept_tx, _ws_accept_rx) = mpsc::channel(16);
        let state = crate::HttpState::new(
            ws_accept_tx,
            loom_obs::Readiness::new(),
            loom_obs::PrometheusMetrics::new_unregistered(),
        )
        .with_auth(service)
        .with_staff_origins(vec![STAFF_ORIGIN.to_string()]);
        (crate::app(state), directory)
    }

    fn with_peer(mut request: axum::http::Request<Body>) -> axum::http::Request<Body> {
        let peer: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
        request
    }

    async fn login_and_get_cookie(app: &Router) -> String {
        let request = with_peer(
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"username": "frodo", "password": "ringbearer"}).to_string(),
                ))
                .unwrap(),
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let set_cookie = response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .expect("login sets the refresh cookie")
            .to_str()
            .unwrap()
            .to_string();
        assert!(set_cookie.starts_with("__Host-loom_rt="));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("Secure"));
        assert!(set_cookie.contains("SameSite=Strict"));
        assert!(set_cookie.contains("Path=/"));

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json.get("refresh_token").is_none(),
            "refresh token must never appear in the JSON body"
        );

        let value = set_cookie
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("__Host-loom_rt=")
            .unwrap();
        format!("__Host-loom_rt={value}")
    }

    /// Acceptance: "refresh without the header rejected".
    #[tokio::test]
    async fn refresh_without_x_loom_auth_header_is_rejected() {
        let (app, _directory) = app_with_auth().await;
        let cookie = login_and_get_cookie(&app).await;

        let request = with_peer(
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/refresh")
                .header("origin", STAFF_ORIGIN)
                .header("cookie", &cookie)
                // deliberately no X-Loom-Auth header
                .body(Body::empty())
                .unwrap(),
        );
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Acceptance: "cross-origin refresh rejected".
    #[tokio::test]
    async fn refresh_from_a_disallowed_origin_is_rejected() {
        let (app, _directory) = app_with_auth().await;
        let cookie = login_and_get_cookie(&app).await;

        let request = with_peer(
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/refresh")
                .header("origin", "https://evil.example")
                .header("x-loom-auth", "1")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Missing Origin entirely is rejected the same way.
        let request = with_peer(
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/refresh")
                .header("x-loom-auth", "1")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        );
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// A same-origin, correctly-headered refresh succeeds, rotates the
    /// cookie, and never puts the refresh token in the JSON body.
    #[tokio::test]
    async fn refresh_with_origin_and_header_succeeds_and_rotates_the_cookie() {
        let (app, _directory) = app_with_auth().await;
        let cookie = login_and_get_cookie(&app).await;

        let request = with_peer(
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/refresh")
                .header("origin", STAFF_ORIGIN)
                .header("x-loom-auth", "1")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let set_cookie = response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .expect("refresh rotates the cookie")
            .to_str()
            .unwrap()
            .to_string();
        assert!(set_cookie.starts_with("__Host-loom_rt="));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("refresh_token").is_none());
        assert!(json.get("access_token").is_some());

        // The old cookie is now revoked (rotated out): replaying it fails
        // and clears the cookie client-side.
        let request = with_peer(
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/refresh")
                .header("origin", STAFF_ORIGIN)
                .header("x-loom-auth", "1")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        );
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let set_cookie = response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .expect("a failed refresh clears the cookie too")
            .to_str()
            .unwrap();
        assert!(set_cookie.contains("Max-Age=0"));
    }

    /// Acceptance: logout also requires Origin + X-Loom-Auth, and clears
    /// the cookie on success.
    #[tokio::test]
    async fn logout_requires_origin_and_header_and_clears_the_cookie() {
        let (app, _directory) = app_with_auth().await;
        let cookie = login_and_get_cookie(&app).await;

        // Cross-origin logout rejected the same way as refresh.
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/auth/logout")
            .header("origin", "https://evil.example")
            .header("x-loom-auth", "1")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/auth/logout")
            .header("origin", STAFF_ORIGIN)
            .header("x-loom-auth", "1")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let set_cookie = response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.contains("Max-Age=0"));

        // The logged-out session is now dead.
        let request = with_peer(
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/refresh")
                .header("origin", STAFF_ORIGIN)
                .header("x-loom-auth", "1")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        );
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// No CORS headers at all -- M-AUTH-6: "No CORS for any other
    /// origin (no Access-Control-Allow-Origin at all)".
    #[tokio::test]
    async fn no_cors_headers_are_ever_sent() {
        let (app, _directory) = app_with_auth().await;
        let cookie = login_and_get_cookie(&app).await;

        let request = with_peer(
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/refresh")
                .header("origin", STAFF_ORIGIN)
                .header("x-loom-auth", "1")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        );
        let response = app.oneshot(request).await.unwrap();
        assert!(
            response
                .headers()
                .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
    }
}
