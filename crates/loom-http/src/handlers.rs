// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `/auth/*` HTTP routes (OBI-174). Mounted unconditionally by [`app`] but
//! every handler checks `HttpState`'s `auth`/`github` fields and answers
//! `503` if the relevant service isn't configured -- same "optional,
//! absent by default" shape as `web_root` (OBI-158).

use axum::Json;
use axum::Router;
use axum::extract::ConnectInfo;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::HttpState;
use crate::auth::{
    AuthContext, AuthError, GithubAuthError, OAUTH_STATE_PURPOSE, OAuthStateClaims, TokenPair,
    generate_pkce, generate_state,
};
use crate::client_ip::client_ip;

/// The `__Host-` state cookie (OBI-201, M-AUTH-7): `__Host-` requires
/// `Secure`, no `Domain` attribute, and `Path=/`, all of which
/// [`state_cookie_header`] sets -- that prefix is what stops a
/// network/subdomain attacker from ever setting their own cookie by this
/// name that our server would accept.
const GITHUB_STATE_COOKIE: &str = "__Host-github_oauth_state";
const GITHUB_STATE_TTL_SECS: i64 = 10 * 60;

pub fn auth_router() -> Router<HttpState> {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/totp/enroll", post(totp_enroll))
        .route("/auth/totp/verify", post(totp_verify))
        .route("/auth/github/start", get(github_start))
        .route("/auth/github/callback", get(github_callback))
        .route("/auth/github/totp", post(github_totp))
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
    #[serde(default)]
    totp_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LogoutRequest {
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
struct GithubCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    /// Set instead of `code`/`state` if the user denied the GitHub
    /// authorization prompt, or GitHub itself refused the request.
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GithubTotpRequest {
    pending_token: String,
    totp_code: String,
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
        AuthError::TotpAlreadyEnrolled => (StatusCode::CONFLICT, "totp_already_enrolled"),
        AuthError::InvalidRefreshToken => (StatusCode::UNAUTHORIZED, "invalid_refresh_token"),
        AuthError::DirectoryUnavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        AuthError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
        AuthError::InvalidPendingToken => (StatusCode::UNAUTHORIZED, "invalid_pending_token"),
        AuthError::InvalidOAuthState => (StatusCode::UNAUTHORIZED, "invalid_oauth_state"),
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
    match auth
        .refresh(&request.refresh_token, request.totp_code.as_deref(), &ctx)
        .await
    {
        Ok(pair) => (StatusCode::OK, Json(TokenResponse::from(pair))).into_response(),
        Err(error) => auth_error_response(error).into_response(),
    }
}

async fn logout(
    State(state): State<HttpState>,
    Json(request): Json<LogoutRequest>,
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

async fn github_start(State(state): State<HttpState>) -> impl IntoResponse {
    let (Some(auth), Some(login)) = (state.auth.as_ref(), state.github_login.as_ref()) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "unavailable",
            }),
        )
            .into_response();
    };

    let pkce = generate_pkce();
    let csrf_state = generate_state();
    let issued_at = OffsetDateTime::now_utc();
    let claims = OAuthStateClaims {
        state: csrf_state.clone(),
        verifier: pkce.verifier,
        purpose: OAUTH_STATE_PURPOSE.to_string(),
        iat: issued_at.unix_timestamp(),
        exp: issued_at.unix_timestamp() + GITHUB_STATE_TTL_SECS,
    };
    let cookie_value = match auth.sign_oauth_state(&claims) {
        Ok(value) => value,
        Err(error) => return auth_error_response(error).into_response(),
    };

    // No `scope` parameter (should-fix from the OBI-195/OBI-201 review):
    // GitHub's default (no-scope) OAuth app grant already returns the
    // numeric id from `GET /user`, which is all `LiveGithubProvider`
    // reads -- `read:user` would only ask for more than this flow uses.
    let authorize_url = format!(
        "{base}?client_id={client_id}&redirect_uri={redirect_uri}&state={state}&code_challenge={challenge}&code_challenge_method=S256&allow_signup=false",
        base = login.authorize_url,
        client_id = percent_encode(&login.client_id),
        redirect_uri = percent_encode(&login.redirect_uri),
        state = percent_encode(&csrf_state),
        challenge = percent_encode(&pkce.challenge),
    );

    let mut response = Redirect::to(&authorize_url).into_response();
    set_cookie(
        response.headers_mut(),
        &state_cookie_header(&cookie_value, GITHUB_STATE_TTL_SECS),
    );
    response
}

async fn github_callback(
    State(state): State<HttpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<GithubCallbackQuery>,
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
    let ctx = auth_context(&headers, Some(peer));

    // Every response path below clears the state cookie (one-time use)
    // and sets `Cache-Control: no-store` -- this response can carry a
    // token pair or a pending token, neither of which a cache or browser
    // history should ever retain (OBI-195/OBI-201 review, must-fix #2).
    let respond = |status: StatusCode, body: serde_json::Value| {
        let mut response = (status, Json(body)).into_response();
        let response_headers = response.headers_mut();
        set_cookie(response_headers, &clear_cookie_header());
        response_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    };

    if let Some(provider_error) = query.error.as_deref() {
        // Truncated (should-fix from the OBI-195/OBI-201 review): this is
        // GitHub's `error` query parameter, attacker-influenced, and
        // logs must not become an unbounded write amplifier.
        let truncated: String = provider_error.chars().take(64).collect();
        tracing::debug!(error = %truncated, "github oauth: provider-side error");
        return respond(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"error": "invalid_code"}),
        );
    }
    let (Some(code), Some(returned_state)) = (query.code.as_deref(), query.state.as_deref()) else {
        return respond(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"error": "missing_code_or_state"}),
        );
    };

    let Some(cookie_value) = read_cookie(&headers, GITHUB_STATE_COOKIE) else {
        return respond(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"error": "invalid_oauth_state"}),
        );
    };
    let oauth_state = match auth.verify_oauth_state(&cookie_value) {
        Ok(claims) => claims,
        Err(_) => {
            return respond(
                StatusCode::UNAUTHORIZED,
                serde_json::json!({"error": "invalid_oauth_state"}),
            );
        }
    };
    // Constant-time-ness doesn't matter here the way it does for the HMAC
    // check above: `state` is high-entropy and known to the legitimate
    // browser via its own (HttpOnly) cookie, not a secret an attacker is
    // trying to brute force character-by-character over the network.
    if oauth_state.state != returned_state {
        return respond(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"error": "invalid_oauth_state"}),
        );
    }

    let user = match github.exchange_code(code, &oauth_state.verifier).await {
        Ok(user) => user,
        Err(GithubAuthError::InvalidCode) => {
            return respond(
                StatusCode::UNAUTHORIZED,
                serde_json::json!({"error": "invalid_code"}),
            );
        }
        Err(GithubAuthError::Unavailable) => {
            return respond(
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({"error": "unavailable"}),
            );
        }
    };

    // M-AUTH-7 ("GitHub counts as the password factor only"): this
    // already runs through the same rate limiter + audit trail as
    // password login (OBI-206) -- see `AuthService::github_login`.
    match auth.github_login(user.id, None, &ctx).await {
        Ok(pair) => respond(
            StatusCode::OK,
            serde_json::json!({
                "access_token": pair.access_token,
                "refresh_token": pair.refresh_token,
                "access_expires_at": pair.access_expires_at.unix_timestamp(),
                "refresh_expires_at": pair.refresh_expires_at.unix_timestamp(),
            }),
        ),
        Err(AuthError::TotpRequired) => {
            // GitHub counts as the password factor only (M-AUTH-7): a T3+
            // uid still needs a TOTP code, which this redirect has no
            // room to carry. The client exchanges this pending token plus
            // a code via `/auth/github/totp` instead of redoing the OAuth
            // dance (the authorization code is already spent).
            match auth.issue_github_pending(user.id) {
                Ok(pending_token) => respond(
                    StatusCode::FORBIDDEN,
                    serde_json::json!({
                        "error": "totp_required",
                        "pending_token": pending_token,
                    }),
                ),
                Err(error) => {
                    let (status, Json(body)) = auth_error_response(error);
                    respond(status, serde_json::to_value(body).unwrap())
                }
            }
        }
        Err(error) => {
            let (status, Json(body)) = auth_error_response(error);
            respond(status, serde_json::to_value(body).unwrap())
        }
    }
}

async fn github_totp(
    State(state): State<HttpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<GithubTotpRequest>,
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
    let mut response = match auth
        .github_login_with_pending(&request.pending_token, Some(&request.totp_code), &ctx)
        .await
    {
        Ok(pair) => (StatusCode::OK, Json(TokenResponse::from(pair))).into_response(),
        Err(error) => auth_error_response(error).into_response(),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// A `__Host-` cookie (OBI-201, M-AUTH-7): the `__Host-` prefix itself
/// requires `Secure`, no `Domain` attribute, and `Path=/`, which is what
/// stops a co-tenant subdomain or a plain-HTTP MITM from ever being able
/// to set a cookie by this name that our server would accept.
fn state_cookie_header(value: &str, max_age_secs: i64) -> String {
    format!(
        "{GITHUB_STATE_COOKIE}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}"
    )
}

fn clear_cookie_header() -> String {
    format!("{GITHUB_STATE_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

fn set_cookie(headers: &mut HeaderMap, value: &str) {
    if let Ok(header_value) = HeaderValue::from_str(value) {
        headers.insert(header::SET_COOKIE, header_value);
    }
}

/// Read a single cookie by name out of the `Cookie` request header.
fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|part| {
        let part = part.trim();
        part.strip_prefix(name)?
            .strip_prefix('=')
            .map(str::to_string)
    })
}

/// Percent-encode a query-string value (RFC 3986 unreserved set kept
/// literal, everything else `%XX`). Good enough for the handful of
/// values this module ever puts in a query string -- it doesn't need to
/// handle an arbitrary request body.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::{
        AuditEvent, AuthService, DirectoryError, GithubIdentityProvider, GithubLoginConfig,
        GithubUser, JwtKeys, RefreshRecord, RefreshRotation, StaffAuthRecord, StaffAuthStatus,
        StaffDirectory,
    };
    use crate::{HttpState, app};
    use loom_obs::{PrometheusMetrics, Readiness};
    use tokio::sync::mpsc;

    /// A fake [`GithubIdentityProvider`] scoped to this test module -- one
    /// fixed code -> id mapping, no network.
    struct FakeProvider {
        code: String,
        github_id: i64,
    }

    #[async_trait::async_trait]
    impl GithubIdentityProvider for FakeProvider {
        async fn exchange_code(
            &self,
            code: &str,
            _code_verifier: &str,
        ) -> Result<GithubUser, GithubAuthError> {
            if code == self.code {
                Ok(GithubUser { id: self.github_id })
            } else {
                Err(GithubAuthError::InvalidCode)
            }
        }
    }

    fn test_state(directory: FakeGithubDirectory, github_code: &str, github_id: i64) -> HttpState {
        let (ws_accept_tx, _ws_accept_rx) = mpsc::channel(16);
        let keys = JwtKeys::from_secret(b"handler-test-secret-at-least-32b");
        let auth = AuthService::new(Arc::new(directory), keys);
        let provider = Arc::new(FakeProvider {
            code: github_code.to_string(),
            github_id,
        });
        let login_config = GithubLoginConfig::new(
            "test-client-id".to_string(),
            "https://staff.example/cb".to_string(),
        );
        HttpState::new(
            ws_accept_tx,
            Readiness::new(),
            PrometheusMetrics::new_unregistered(),
        )
        .with_auth(auth)
        .with_github(provider, login_config)
    }

    fn cookie_from(headers: &HeaderMap) -> String {
        headers
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    fn with_peer(mut request: Request<Body>) -> Request<Body> {
        let peer: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
        request
    }

    #[tokio::test]
    async fn github_start_redirects_with_pkce_and_sets_the_state_cookie_and_no_scope() {
        let state = test_state(FakeGithubDirectory::default(), "unused", 1);
        let router = app(state);

        let request = with_peer(
            Request::builder()
                .uri("/auth/github/start")
                .body(Body::empty())
                .unwrap(),
        );
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let location = response
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.starts_with("https://github.com/login/oauth/authorize?"));
        assert!(location.contains("code_challenge_method=S256"));
        assert!(location.contains("client_id=test-client-id"));
        // Should-fix (OBI-195/OBI-201 review): no `scope` parameter.
        assert!(!location.contains("scope="));

        let cookie = cookie_from(response.headers());
        assert!(cookie.starts_with("__Host-github_oauth_state="));
    }

    #[tokio::test]
    async fn github_callback_end_to_end_with_a_linked_user_no_totp() {
        let directory = FakeGithubDirectory::default();
        directory.link("samwise", 1, 42);
        let state = test_state(directory, "good-code", 42);
        let router = app(state.clone());

        let start_request = with_peer(
            Request::builder()
                .uri("/auth/github/start")
                .body(Body::empty())
                .unwrap(),
        );
        let start_response = router.clone().oneshot(start_request).await.unwrap();
        let location = start_response
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let cookie = cookie_from(start_response.headers());
        let csrf_state = location
            .split("state=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();

        let callback_request = with_peer(
            Request::builder()
                .uri(format!(
                    "/auth/github/callback?code=good-code&state={csrf_state}"
                ))
                .header(axum::http::header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        );
        let callback_response = router.oneshot(callback_request).await.unwrap();
        assert_eq!(callback_response.status(), StatusCode::OK);
        let cleared = callback_response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cleared.contains("Max-Age=0"));
        assert_eq!(
            callback_response
                .headers()
                .get(header::CACHE_CONTROL)
                .unwrap(),
            "no-store"
        );

        let body = callback_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("access_token").is_some());
    }

    #[tokio::test]
    async fn github_callback_with_a_wrong_state_is_refused() {
        let directory = FakeGithubDirectory::default();
        directory.link("samwise", 1, 42);
        let state = test_state(directory, "good-code", 42);
        let router = app(state);

        let start_request = with_peer(
            Request::builder()
                .uri("/auth/github/start")
                .body(Body::empty())
                .unwrap(),
        );
        let start_response = router.clone().oneshot(start_request).await.unwrap();
        let cookie = cookie_from(start_response.headers());

        let callback_request = with_peer(
            Request::builder()
                .uri("/auth/github/callback?code=good-code&state=not-the-real-state")
                .header(axum::http::header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        );
        let callback_response = router.oneshot(callback_request).await.unwrap();
        assert_eq!(callback_response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn github_callback_without_the_state_cookie_is_refused() {
        let directory = FakeGithubDirectory::default();
        directory.link("samwise", 1, 42);
        let state = test_state(directory, "good-code", 42);
        let router = app(state);

        let callback_request = with_peer(
            Request::builder()
                .uri("/auth/github/callback?code=good-code&state=whatever")
                .body(Body::empty())
                .unwrap(),
        );
        let callback_response = router.oneshot(callback_request).await.unwrap();
        assert_eq!(callback_response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn github_callback_for_a_t3_uid_then_github_totp_completes_login() {
        let directory = FakeGithubDirectory::default();
        directory.link("gandalf", 3, 99);
        let state = test_state(directory.clone(), "good-code", 99);
        let auth = state.auth.clone().unwrap();
        let router = app(state);

        let enrollment = auth.totp_enroll("gandalf", &test_ctx()).await.unwrap();
        directory.confirm_totp_for_test("gandalf");
        let totp = crate::auth::totp_for_secret(&enrollment.secret_base32, "gandalf").unwrap();

        let start_request = with_peer(
            Request::builder()
                .uri("/auth/github/start")
                .body(Body::empty())
                .unwrap(),
        );
        let start_response = router.clone().oneshot(start_request).await.unwrap();
        let location = start_response
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let cookie = cookie_from(start_response.headers());
        let csrf_state = location
            .split("state=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();

        let callback_request = with_peer(
            Request::builder()
                .uri(format!(
                    "/auth/github/callback?code=good-code&state={csrf_state}"
                ))
                .header(axum::http::header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        );
        let callback_response = router.clone().oneshot(callback_request).await.unwrap();
        assert_eq!(callback_response.status(), StatusCode::FORBIDDEN);
        let body = callback_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "totp_required");
        let pending_token = json["pending_token"].as_str().unwrap().to_string();

        let fresh_code = totp.generate_current().to_string();
        let totp_request = with_peer(
            Request::builder()
                .method("POST")
                .uri("/auth/github/totp")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "pending_token": pending_token,
                        "totp_code": fresh_code,
                    })
                    .to_string(),
                ))
                .unwrap(),
        );
        let totp_response = router.oneshot(totp_request).await.unwrap();
        assert_eq!(totp_response.status(), StatusCode::OK);
        assert_eq!(
            totp_response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }

    fn test_ctx() -> AuthContext {
        AuthContext::default()
    }

    /// A minimal [`StaffDirectory`] for handler-level tests -- this
    /// module only needs tier + TOTP + GitHub-link state, not the full
    /// refresh-token/rate-limit bookkeeping `auth::tests::FakeDirectory`
    /// (not `pub`) covers.
    #[derive(Default, Clone)]
    pub struct FakeGithubDirectory {
        inner: Arc<Mutex<Inner>>,
    }

    #[derive(Default)]
    struct Inner {
        staff: HashMap<String, (i16, Option<String>, bool, Option<u64>)>,
        github_links: HashMap<i64, String>,
        refresh_tokens:
            HashMap<String, (String, time::OffsetDateTime, Option<time::OffsetDateTime>)>,
    }

    impl FakeGithubDirectory {
        fn link(&self, uid: &str, tier: i16, github_id: i64) {
            let mut inner = self.inner.lock().unwrap();
            inner
                .staff
                .insert(uid.to_string(), (tier, None, false, None));
            inner.github_links.insert(github_id, uid.to_string());
        }

        fn confirm_totp_for_test(&self, uid: &str) {
            self.inner.lock().unwrap().staff.get_mut(uid).unwrap().2 = true;
        }
    }

    #[async_trait::async_trait]
    impl StaffDirectory for FakeGithubDirectory {
        async fn staff_login(
            &self,
            _username: &str,
            _password: &str,
        ) -> Result<Option<StaffAuthRecord>, DirectoryError> {
            Ok(None)
        }

        async fn auth_status_for(
            &self,
            uid: &str,
        ) -> Result<Option<StaffAuthStatus>, DirectoryError> {
            Ok(self
                .inner
                .lock()
                .unwrap()
                .staff
                .get(uid)
                .map(|(tier, secret, confirmed, _)| StaffAuthStatus {
                    tier: *tier,
                    totp_secret: secret.clone(),
                    totp_confirmed: *confirmed,
                }))
        }

        async fn totp_enroll(&self, uid: &str, secret_base32: &str) -> Result<(), DirectoryError> {
            let mut inner = self.inner.lock().unwrap();
            let entry = inner.staff.get_mut(uid).ok_or(DirectoryError)?;
            entry.1 = Some(secret_base32.to_string());
            entry.2 = false;
            entry.3 = None;
            Ok(())
        }

        async fn totp_confirm(&self, uid: &str) -> Result<(), DirectoryError> {
            let mut inner = self.inner.lock().unwrap();
            let entry = inner.staff.get_mut(uid).ok_or(DirectoryError)?;
            if entry.1.is_none() {
                return Err(DirectoryError);
            }
            entry.2 = true;
            Ok(())
        }

        async fn totp_secret_for(&self, uid: &str) -> Result<Option<String>, DirectoryError> {
            Ok(self
                .inner
                .lock()
                .unwrap()
                .staff
                .get(uid)
                .and_then(|(_, secret, _, _)| secret.clone()))
        }

        async fn totp_consume_step(&self, uid: &str, step: u64) -> Result<bool, DirectoryError> {
            let mut inner = self.inner.lock().unwrap();
            let entry = inner.staff.get_mut(uid).ok_or(DirectoryError)?;
            if entry.3.is_some_and(|last| step <= last) {
                return Ok(false);
            }
            entry.3 = Some(step);
            Ok(true)
        }

        async fn refresh_token_insert(
            &self,
            uid: &str,
            token_hash: &str,
            expires_at: time::OffsetDateTime,
        ) -> Result<(), DirectoryError> {
            self.inner
                .lock()
                .unwrap()
                .refresh_tokens
                .insert(token_hash.to_string(), (uid.to_string(), expires_at, None));
            Ok(())
        }

        async fn refresh_token_lookup(
            &self,
            token_hash: &str,
        ) -> Result<Option<RefreshRecord>, DirectoryError> {
            Ok(self
                .inner
                .lock()
                .unwrap()
                .refresh_tokens
                .get(token_hash)
                .map(|(uid, expires_at, revoked_at)| RefreshRecord {
                    staff_uid: uid.clone(),
                    expires_at: *expires_at,
                    revoked_at: *revoked_at,
                }))
        }

        async fn refresh_token_rotate(
            &self,
            token_hash: &str,
        ) -> Result<RefreshRotation, DirectoryError> {
            let mut inner = self.inner.lock().unwrap();
            let Some(entry) = inner.refresh_tokens.get_mut(token_hash) else {
                return Ok(RefreshRotation::NotFound);
            };
            if entry.2.is_some() {
                return Ok(RefreshRotation::Reused {
                    staff_uid: entry.0.clone(),
                });
            }
            if entry.1 <= time::OffsetDateTime::now_utc() {
                return Ok(RefreshRotation::Expired);
            }
            entry.2 = Some(time::OffsetDateTime::now_utc());
            Ok(RefreshRotation::Rotated {
                staff_uid: entry.0.clone(),
            })
        }

        async fn refresh_token_revoke(&self, token_hash: &str) -> Result<(), DirectoryError> {
            if let Some(entry) = self
                .inner
                .lock()
                .unwrap()
                .refresh_tokens
                .get_mut(token_hash)
            {
                entry.2 = Some(time::OffsetDateTime::now_utc());
            }
            Ok(())
        }

        async fn refresh_token_revoke_all(&self, uid: &str) -> Result<(), DirectoryError> {
            let mut inner = self.inner.lock().unwrap();
            for (token_uid, _, revoked_at) in inner.refresh_tokens.values_mut() {
                if token_uid == uid {
                    *revoked_at = Some(time::OffsetDateTime::now_utc());
                }
            }
            Ok(())
        }

        async fn github_lookup(&self, github_id: i64) -> Result<Option<String>, DirectoryError> {
            Ok(self
                .inner
                .lock()
                .unwrap()
                .github_links
                .get(&github_id)
                .cloned())
        }

        async fn record_audit(&self, _event: AuditEvent) -> Result<(), DirectoryError> {
            Ok(())
        }
    }
}
