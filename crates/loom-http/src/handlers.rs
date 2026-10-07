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
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};

use crate::HttpState;
use crate::auth::{
    AuthContext, AuthError, GithubAuthError, TokenPair, generate_pkce, generate_state,
};
use crate::client_ip::client_ip;

/// The `__Host-` state cookie (OBI-201, M-AUTH-7): the `__Host-` prefix
/// itself requires `Secure`, no `Domain` attribute, and `Path=/`, which
/// is what stops a co-tenant subdomain or a plain-HTTP MITM from ever
/// being able to set a cookie by this name that our server would accept.
const GITHUB_STATE_COOKIE: &str = "__Host-github_oauth_state";
const GITHUB_STATE_TTL_SECS: i64 = 10 * 60;

/// The `__Host-` GitHub-login TOTP-pending-token cookie (OBI-201 review
/// must-fix #2): path-scoped to `/auth/github/totp`, the only route that
/// ever reads it, rather than the whole origin -- it carries a bearer
/// credential for *finishing* a login, not a session, so it has no
/// business being sent anywhere else.
const GITHUB_PENDING_COOKIE: &str = "__Host-github_pending";
const GITHUB_PENDING_COOKIE_PATH: &str = "/auth/github/totp";
const GITHUB_PENDING_TTL_SECS: i64 = 5 * 60;

/// Where a successful `/auth/github/callback` redirects the browser
/// (OBI-201 review must-fix #2: a top-level GET navigation must never
/// carry a token pair as a JSON response body). The SPA is expected to
/// call `/auth/refresh` on load -- the `__Host-loom_rt` cookie this
/// redirect just set is all it needs to mint an access token.
const GITHUB_LOGIN_SUCCESS_REDIRECT: &str = "/";
/// Where a `totp_required` outcome redirects the browser instead: the
/// pending-token cookie travels with it (scoped to
/// [`GITHUB_PENDING_COOKIE_PATH`]), and the SPA's TOTP page posts it plus
/// a code to `/auth/github/totp`.
const GITHUB_TOTP_REDIRECT: &str = "/login/totp";

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
struct GithubCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    /// Set instead of `code`/`state` if the user denied the GitHub
    /// authorization prompt, or GitHub itself refused the request.
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GithubTotpRequest {
    totp_code: String,
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
    let cookie_value = match auth.sign_oauth_state(&csrf_state, &pkce.verifier) {
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
    // and sets `Cache-Control: no-store` -- regardless of whether this
    // response is a JSON error, a `303` to the app (success), or a `303`
    // to the TOTP page (pending) -- none of which a cache or browser
    // history should ever retain (OBI-195/OBI-201 review, must-fix #2).
    let clear_state = |mut response: axum::response::Response| {
        let response_headers = response.headers_mut();
        set_cookie(response_headers, &clear_state_cookie_header());
        response_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    };
    let error_json = |status: StatusCode, body: serde_json::Value| {
        clear_state((status, Json(body)).into_response())
    };

    if let Some(provider_error) = query.error.as_deref() {
        // Truncated (should-fix from the OBI-195/OBI-201 review): this is
        // GitHub's `error` query parameter, attacker-influenced, and
        // logs must not become an unbounded write amplifier.
        let truncated: String = provider_error.chars().take(64).collect();
        tracing::debug!(error = %truncated, "github oauth: provider-side error");
        return error_json(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"error": "invalid_code"}),
        );
    }
    let (Some(code), Some(returned_state)) = (query.code.as_deref(), query.state.as_deref()) else {
        return error_json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"error": "missing_code_or_state"}),
        );
    };

    let Some(cookie_value) = read_cookie(&headers, GITHUB_STATE_COOKIE) else {
        return error_json(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"error": "invalid_oauth_state"}),
        );
    };
    let oauth_state = match auth.verify_oauth_state(&cookie_value) {
        Ok(claims) => claims,
        Err(_) => {
            return error_json(
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
        return error_json(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"error": "invalid_oauth_state"}),
        );
    }

    let user = match github.exchange_code(code, &oauth_state.verifier).await {
        Ok(user) => user,
        Err(GithubAuthError::InvalidCode) => {
            return error_json(
                StatusCode::UNAUTHORIZED,
                serde_json::json!({"error": "invalid_code"}),
            );
        }
        Err(GithubAuthError::Unavailable) => {
            return error_json(
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({"error": "unavailable"}),
            );
        }
    };

    // M-AUTH-7 ("GitHub counts as the password factor only"): this
    // already runs through the same rate limiter + audit trail as
    // password login (OBI-206) -- see `AuthService::github_login`.
    match auth.github_login(user.id, None, &ctx).await {
        Ok(pair) => {
            // Success: deliver via the same cookie-only session-family
            // path `/auth/login` uses (OBI-201 review must-fix #2) -- a
            // `303` to the app, never a JSON body with a token pair on a
            // top-level navigation. The SPA calls `/auth/refresh` on load
            // to mint an access token from the cookie this just set.
            let mut response =
                clear_state(Redirect::to(GITHUB_LOGIN_SUCCESS_REDIRECT).into_response());
            let max_age = (pair.refresh_expires_at - time::OffsetDateTime::now_utc())
                .whole_seconds()
                .max(0);
            response.headers_mut().append(
                crate::auth::set_cookie_name(),
                crate::auth::set_cookie_header(&pair.refresh_token, max_age),
            );
            response
        }
        Err(AuthError::TotpRequired) => {
            // GitHub counts as the password factor only (M-AUTH-7): a T3+
            // uid still needs a TOTP code, which this redirect has no
            // room to carry. The pending token travels in its own
            // path-scoped `__Host-` cookie (OBI-201 review must-fix #2),
            // never the JSON body or a query parameter -- the client
            // posts it (implicitly, via the cookie) plus a code to
            // `/auth/github/totp` instead of redoing the OAuth dance
            // (the authorization code is already spent).
            match auth.issue_github_pending(user.id) {
                Ok(pending_token) => {
                    let mut response =
                        clear_state(Redirect::to(GITHUB_TOTP_REDIRECT).into_response());
                    set_cookie(
                        response.headers_mut(),
                        &pending_cookie_header(&pending_token, GITHUB_PENDING_TTL_SECS),
                    );
                    response
                }
                Err(error) => {
                    let (status, Json(body)) = auth_error_response(error);
                    error_json(status, serde_json::to_value(body).unwrap())
                }
            }
        }
        Err(error) => {
            let (status, Json(body)) = auth_error_response(error);
            error_json(status, serde_json::to_value(body).unwrap())
        }
    }
}

async fn github_totp(
    State(state): State<HttpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<GithubTotpRequest>,
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
    // One-time use (same discipline as the OAuth-state cookie): cleared
    // on every response path below, success or failure.
    let clear_pending = |mut response: axum::response::Response| {
        let response_headers = response.headers_mut();
        set_cookie(response_headers, &clear_pending_cookie_header());
        response_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    };
    let Some(pending_token) = read_cookie(&headers, GITHUB_PENDING_COOKIE) else {
        return clear_pending(auth_error_response(AuthError::InvalidPendingToken).into_response());
    };
    let ctx = auth_context(&headers, Some(peer));
    match auth
        .github_login_with_pending(&pending_token, Some(&request.totp_code), &ctx)
        .await
    {
        Ok(pair) => clear_pending(token_response(&pair)),
        Err(error) => clear_pending(auth_error_response(error).into_response()),
    }
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

fn clear_state_cookie_header() -> String {
    format!("{GITHUB_STATE_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

/// The GitHub-login TOTP-pending-token cookie (OBI-201 review must-fix
/// #2): `Path`-scoped to [`GITHUB_PENDING_COOKIE_PATH`], not `/`, so it
/// is never sent anywhere but the one route that redeems it.
fn pending_cookie_header(value: &str, max_age_secs: i64) -> String {
    format!(
        "{GITHUB_PENDING_COOKIE}={value}; Path={GITHUB_PENDING_COOKIE_PATH}; Secure; HttpOnly; SameSite=Strict; Max-Age={max_age_secs}"
    )
}

fn clear_pending_cookie_header() -> String {
    format!(
        "{GITHUB_PENDING_COOKIE}=; Path={GITHUB_PENDING_COOKIE_PATH}; Secure; HttpOnly; SameSite=Strict; Max-Age=0"
    )
}

fn set_cookie(headers: &mut HeaderMap, value: &str) {
    if let Ok(header_value) = HeaderValue::from_str(value) {
        // `append`, not `insert`: a response can carry more than one
        // `Set-Cookie` header (e.g. the success path below clears the
        // OAuth-state cookie *and* sets the refresh cookie) -- `insert`
        // would silently replace one with the other.
        headers.append(header::SET_COOKIE, header_value);
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
    use super::*;

    use std::sync::Arc;

    use axum::body::Body;
    use http_body_util::BodyExt;
    use tokio::sync::mpsc;
    use tower::ServiceExt;

    use crate::auth::tests::{FakeDirectory, FakeGithubProvider, test_service};
    use crate::auth::{AuthContext, GithubIdentityProvider, GithubLoginConfig};

    const STAFF_ORIGIN: &str = "https://staff.loom.example";
    const GITHUB_REDIRECT_URI: &str = "https://staff.loom.example/auth/github/callback";

    async fn app_with_github(github_code: &str, github_id: i64) -> (Router, FakeDirectory) {
        let directory = FakeDirectory::new();
        directory.add_staff("samwise", "unused-password", 1);
        directory.link_github(github_id, "samwise");
        let service = test_service(directory.clone());
        let provider: Arc<dyn GithubIdentityProvider> =
            Arc::new(FakeGithubProvider::new().with_code(github_code, github_id));
        let login_config = GithubLoginConfig::new(
            "test-client-id".to_string(),
            GITHUB_REDIRECT_URI.to_string(),
        );
        let (ws_accept_tx, _ws_accept_rx) = mpsc::channel(16);
        let state = crate::HttpState::new(
            ws_accept_tx,
            loom_obs::Readiness::new(),
            loom_obs::PrometheusMetrics::new_unregistered(),
        )
        .with_auth(service)
        .with_github(provider, login_config)
        .with_staff_origins(vec![STAFF_ORIGIN.to_string()]);
        (crate::app(state), directory)
    }

    /// Like [`app_with_github`], but the linked uid is T3+ with a
    /// confirmed TOTP secret (returned as base32, so the test can compute
    /// real codes against it) -- for exercising the `totp_required` /
    /// pending-token path. The enrolling service is throwaway: it shares
    /// the same [`FakeDirectory`] (an `Arc<Mutex<..>>` under the hood) as
    /// the one wired into the returned app, and the deterministic test
    /// keyset ([`test_service`]) means tokens minted by one are valid
    /// JwtKeys for the other.
    async fn app_with_github_t3(github_code: &str, github_id: i64) -> (Router, String) {
        let directory = FakeDirectory::new();
        directory.add_staff("elrond", "unused-password", 3);
        directory.link_github(github_id, "elrond");

        let enroll_service = test_service(directory.clone());
        let enrollment = enroll_service
            .totp_enroll("elrond", &AuthContext::default())
            .await
            .unwrap();
        directory.confirm_totp_for_test("elrond");

        let service = test_service(directory.clone());
        let provider: Arc<dyn GithubIdentityProvider> =
            Arc::new(FakeGithubProvider::new().with_code(github_code, github_id));
        let login_config = GithubLoginConfig::new(
            "test-client-id".to_string(),
            GITHUB_REDIRECT_URI.to_string(),
        );
        let (ws_accept_tx, _ws_accept_rx) = mpsc::channel(16);
        let state = crate::HttpState::new(
            ws_accept_tx,
            loom_obs::Readiness::new(),
            loom_obs::PrometheusMetrics::new_unregistered(),
        )
        .with_auth(service)
        .with_github(provider, login_config)
        .with_staff_origins(vec![STAFF_ORIGIN.to_string()]);
        (crate::app(state), enrollment.secret_base32)
    }

    fn with_peer(mut request: axum::http::Request<Body>) -> axum::http::Request<Body> {
        let peer: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
        request
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

    /// Like [`cookie_from`], but scans every `Set-Cookie` header value
    /// for the one whose name matches `name=` -- needed once a response
    /// carries more than one (e.g. the GitHub callback clears the
    /// OAuth-state cookie *and* sets the refresh cookie, or the pending
    /// cookie, in the same response).
    /// The full `Set-Cookie` header value whose name matches `name=`
    /// (not truncated to `name=value` -- for attribute assertions; use
    /// [`cookie_header_for`] to get a reusable `Cookie` request-header
    /// value instead). Scans every `Set-Cookie` value, since a response
    /// can carry more than one (e.g. the GitHub callback clears the
    /// OAuth-state cookie *and* sets the refresh cookie in the same
    /// response).
    fn cookie_named(headers: &HeaderMap, name: &str) -> String {
        let prefix = format!("{name}=");
        headers
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|value| {
                let value = value.to_str().ok()?;
                value.starts_with(&prefix).then(|| value.to_string())
            })
            .unwrap_or_else(|| panic!("no Set-Cookie header named {name:?}"))
    }

    /// [`cookie_named`], truncated to `name=value` -- what a real browser
    /// would actually send back in a `Cookie` request header (no
    /// `Path`/`Secure`/etc attributes).
    fn cookie_header_for(headers: &HeaderMap, name: &str) -> String {
        cookie_named(headers, name)
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    /// Extract one query-string parameter's raw (not percent-decoded --
    /// every value this module ever puts in a query string is already in
    /// the unreserved set) value out of a URL.
    fn query_param(url: &str, key: &str) -> Option<String> {
        let query = url.split('?').nth(1)?;
        query.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == key).then(|| v.to_string())
        })
    }

    /// Acceptance: PKCE S256 challenge + CSRF state in the authorize URL,
    /// the `__Host-` state cookie with the right attributes, and no
    /// `scope` parameter (should-fix from the OBI-195/OBI-201 review).
    #[tokio::test]
    async fn github_start_redirects_with_pkce_and_sets_the_state_cookie_and_no_scope() {
        let (app, _directory) = app_with_github("the-code", 7).await;
        let request = axum::http::Request::builder()
            .uri("/auth/github/start")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("code_challenge="));
        assert!(location.contains("code_challenge_method=S256"));
        assert!(location.contains("state="));
        assert!(location.contains("client_id=test-client-id"));
        assert!(!location.contains("scope="));

        let set_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.starts_with("__Host-github_oauth_state="));
        assert!(set_cookie.contains("Secure"));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("SameSite=Lax"));
        assert!(set_cookie.contains("Path=/"));
    }

    /// A linked, sub-T3 uid's callback succeeds: the refresh cookie is
    /// set (OBI-198's cookie-only session path, not a JSON token pair),
    /// the browser is `303`-redirected to the app -- never a JSON body
    /// with tokens on a top-level navigation (OBI-201 review must-fix) --
    /// and the response never caches.
    #[tokio::test]
    async fn github_callback_success_sets_the_refresh_cookie_and_redirects_to_the_app() {
        let (app, _directory) = app_with_github("the-code", 7).await;

        let start_request = axum::http::Request::builder()
            .uri("/auth/github/start")
            .body(Body::empty())
            .unwrap();
        let start_response = app.clone().oneshot(start_request).await.unwrap();
        let location = start_response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let state_cookie = cookie_from(start_response.headers());
        let state_value = query_param(&location, "state").unwrap();

        let callback_request = with_peer(
            axum::http::Request::builder()
                .uri(format!(
                    "/auth/github/callback?code=the-code&state={state_value}"
                ))
                .header("cookie", &state_cookie)
                .body(Body::empty())
                .unwrap(),
        );
        let response = app.oneshot(callback_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            GITHUB_LOGIN_SUCCESS_REDIRECT
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let set_cookie = cookie_named(response.headers(), "__Host-loom_rt");
        assert!(set_cookie.starts_with("__Host-loom_rt="));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("Secure"));
    }

    /// A `state` that doesn't match the signed cookie's (a forged or
    /// stale callback) is refused outright, before GitHub's token
    /// endpoint is ever called.
    #[tokio::test]
    async fn github_callback_with_a_mismatched_state_is_refused() {
        let (app, _directory) = app_with_github("the-code", 7).await;

        let start_request = axum::http::Request::builder()
            .uri("/auth/github/start")
            .body(Body::empty())
            .unwrap();
        let start_response = app.clone().oneshot(start_request).await.unwrap();
        let state_cookie = cookie_from(start_response.headers());

        let callback_request = with_peer(
            axum::http::Request::builder()
                .uri("/auth/github/callback?code=the-code&state=not-the-right-state")
                .header("cookie", &state_cookie)
                .body(Body::empty())
                .unwrap(),
        );
        let response = app.oneshot(callback_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// A callback with no state cookie at all (missing/expired) is
    /// refused, not treated as an unauthenticated success.
    #[tokio::test]
    async fn github_callback_with_no_state_cookie_is_refused() {
        let (app, _directory) = app_with_github("the-code", 7).await;
        let callback_request = with_peer(
            axum::http::Request::builder()
                .uri("/auth/github/callback?code=the-code&state=whatever")
                .body(Body::empty())
                .unwrap(),
        );
        let response = app.oneshot(callback_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// M-AUTH-7 end to end: a T3+ linked uid's callback stops at
    /// `totp_required`, redirecting to the TOTP page with the pending
    /// token in its own path-scoped cookie (OBI-201 review must-fix),
    /// which `/auth/github/totp` -- CSRF-guarded the same as `/auth/
    /// refresh` (OBI-201 review must-fix) -- redeems to finish the login.
    #[tokio::test]
    async fn github_callback_totp_required_then_github_totp_completes_the_login() {
        let (app, secret_base32) = app_with_github_t3("the-code", 99).await;

        let start_request = axum::http::Request::builder()
            .uri("/auth/github/start")
            .body(Body::empty())
            .unwrap();
        let start_response = app.clone().oneshot(start_request).await.unwrap();
        let location = start_response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let state_cookie = cookie_from(start_response.headers());
        let state_value = query_param(&location, "state").unwrap();

        let callback_request = with_peer(
            axum::http::Request::builder()
                .uri(format!(
                    "/auth/github/callback?code=the-code&state={state_value}"
                ))
                .header("cookie", &state_cookie)
                .body(Body::empty())
                .unwrap(),
        );
        let response = app.clone().oneshot(callback_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            GITHUB_TOTP_REDIRECT
        );
        let pending_cookie = cookie_header_for(response.headers(), "__Host-github_pending");
        assert!(pending_cookie.starts_with("__Host-github_pending="));

        // Without Origin + X-Loom-Auth, /auth/github/totp refuses outright
        // (OBI-201 review must-fix: same CSRF guard as /auth/refresh).
        let code = crate::auth::totp_for_secret(&secret_base32, "elrond")
            .unwrap()
            .generate_current()
            .to_string();
        let unguarded_request = with_peer(
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/github/totp")
                .header("content-type", "application/json")
                .header("cookie", &pending_cookie)
                .body(Body::from(
                    serde_json::json!({"totp_code": code}).to_string(),
                ))
                .unwrap(),
        );
        let response = app.clone().oneshot(unguarded_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let totp_request = with_peer(
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/github/totp")
                .header("origin", STAFF_ORIGIN)
                .header("x-loom-auth", "1")
                .header("content-type", "application/json")
                .header("cookie", &pending_cookie)
                .body(Body::from(
                    serde_json::json!({"totp_code": code}).to_string(),
                ))
                .unwrap(),
        );
        let response = app.oneshot(totp_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let set_cookie = cookie_named(response.headers(), "__Host-loom_rt");
        assert!(set_cookie.starts_with("__Host-loom_rt="));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("access_token").is_some());
    }

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
