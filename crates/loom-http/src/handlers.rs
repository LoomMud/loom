// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `/auth/*` HTTP routes (OBI-174, OBI-198, OBI-201). Mounted
//! unconditionally by [`app`] but every handler checks `HttpState`'s
//! `auth`/`github` fields and answers `503` if the relevant service
//! isn't configured -- same "optional, absent by default" shape as
//! `web_root` (OBI-158).
//!
//! `/auth/refresh` and `/auth/logout` (OBI-198, D-TM2/M-AUTH-5/M-AUTH-6):
//! the refresh token travels only as an HttpOnly `__Host-loom_rt` cookie,
//! never in a JSON request or response body, and both routes refuse
//! outright unless `Origin` is on `HttpState`'s staff-origin allowlist
//! *and* the request carries `X-Loom-Auth: 1` -- see
//! `crate::auth::staff_csrf_guard_passes`. This service never sends an
//! `Access-Control-Allow-*` header for any route.
//!
//! `/auth/github/*` (OBI-201, M-AUTH-7, CTO review on PR #78): the whole
//! flow follows the same cookie-session model as password login, not a
//! separate JSON-token shape --
//!
//! - `GET /auth/github/start`: redirects to GitHub's authorize endpoint
//!   with a PKCE S256 challenge, after setting a short-lived `__Host-`
//!   state cookie (`state` + PKCE verifier, signed -- see
//!   `crate::auth::AuthService::sign_oauth_state`).
//! - `GET /auth/github/callback`: verifies that cookie, exchanges the
//!   code, and -- on success -- sets the **same** `__Host-loom_rt`
//!   refresh cookie `/auth/login` does (via
//!   [`crate::auth::set_cookie_header`]) and `303`s back to the staff
//!   app, rather than returning a JSON access/refresh token pair (the
//!   must-fix from that review: a JSON token body here would be
//!   incompatible with OBI-198's cookie-only session model). A T3+ uid
//!   that still needs a TOTP code gets a distinct, short-TTL **cookie**
//!   (`__Host-github_pending`) instead of a JSON `pending_token` --
//!   `/auth/github/totp` reads it back off the request, never out of a
//!   body a script would have to hold onto.
//! - `POST /auth/github/totp`: redeems that pending cookie plus a fresh
//!   TOTP code, the same way `/auth/login`'s second attempt would,
//!   setting the refresh cookie on success. Guarded by the same
//!   Origin + `X-Loom-Auth` CSRF check as `/auth/refresh`/`/auth/logout`
//!   (defense in depth: it reads one cookie and, on success, sets
//!   another).

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

/// The `__Host-` state cookie (OBI-201, M-AUTH-7): the `__Host-` prefix
/// requires `Secure`, no `Domain` attribute, and `Path=/`, which is what
/// stops a co-tenant subdomain or a plain-HTTP MITM from ever setting a
/// cookie by this name that our server would accept.
const GITHUB_STATE_COOKIE: &str = "__Host-github_oauth_state";
const GITHUB_STATE_TTL_SECS: i64 = 10 * 60;
/// The pending-TOTP cookie (OBI-201, must-fix from the PR #78 CTO
/// review): a T3+ GitHub login that still needs a code gets this instead
/// of a JSON `pending_token` -- `/auth/github/totp` reads it straight off
/// the request, so a script never has to hold the credential at all.
const GITHUB_PENDING_COOKIE: &str = "__Host-github_pending";
const GITHUB_PENDING_TTL_SECS: i64 = 5 * 60;
/// Where `/auth/github/callback` sends the browser after a successful
/// login (OBI-201): the staff SPA's own root, served by this same origin
/// (`HttpState::with_web_root`, OBI-158) -- there is no separate "staff
/// app" origin to redirect to. The SPA's bootstrap already has to call
/// `POST /auth/refresh` on load to mint a fresh access token from
/// whatever refresh cookie it finds, so it needs no token on this URL.
const GITHUB_LOGIN_REDIRECT: &str = "/";
/// Where `/auth/github/callback` sends the browser when a T3+ uid still
/// needs a TOTP code: the same SPA root, plus a query marker the client
/// watches for to prompt for a code and `POST` it to
/// `/auth/github/totp` (the `__Host-github_pending` cookie travels with
/// that request automatically; there is nothing to carry in the URL).
const GITHUB_PENDING_REDIRECT: &str = "/?github_totp_pending=1";

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
        .route("/api/v1/ws-ticket", post(ws_ticket))
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    totp_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TotpVerifyRequest {
    code: String,
}

#[derive(Debug, Deserialize)]
struct GithubTotpRequest {
    totp_code: String,
}

#[derive(Debug, Deserialize)]
struct GithubCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    /// Set instead of `code`/`state` if the user denied the GitHub
    /// authorization prompt, or GitHub itself refused the request.
    error: Option<String>,
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
        AuthError::InvalidWsTicket => (StatusCode::UNAUTHORIZED, "invalid_ws_ticket"),
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
    bearer_claims(headers, state).map(|claims| claims.sub)
}

/// As [`bearer_uid`], but the full [`crate::auth::AccessClaims`] --
/// `/api/v1/ws-ticket` (D-TM4) needs `sid` too, not just `sub`.
pub(crate) fn bearer_claims(
    headers: &HeaderMap,
    state: &HttpState,
) -> Option<crate::auth::AccessClaims> {
    let auth = state.auth.as_ref()?;
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let token = value.strip_prefix("Bearer ")?;
    auth.verify_access_token(token).ok()
}

/// `POST /api/v1/ws-ticket` (D-TM4, OBI-180): Bearer-authenticated, mints
/// a single-use 30s ticket for `/lsp`'s first WS frame. `401` with no
/// `Authorization` header or an invalid/expired access token -- same
/// shape as every other bearer-gated route here.
pub(crate) async fn ws_ticket(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(claims) = bearer_claims(&headers, &state) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // Safe to unwrap: `bearer_claims` only returns `Some` when
    // `state.auth` is `Some`.
    let auth = state.auth.as_ref().unwrap();
    match auth.issue_ws_ticket(&claims) {
        Ok(ticket) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ticket": ticket, "expires_in": 30 })),
        )
            .into_response(),
        Err(error) => auth_error_response(error).into_response(),
    }
}

/// Build the `200 OK` response for a successful login/refresh/GitHub-totp
/// completion: the JSON body (access token only) plus the `Set-Cookie`
/// header carrying the rotated refresh token (OBI-198, D-TM2). Uses
/// `append`, not `insert` -- a GitHub-login response may also need to
/// clear the pending-TOTP cookie in the same response (two distinct
/// `Set-Cookie` headers).
fn token_response(pair: &TokenPair) -> axum::response::Response {
    let max_age = (pair.refresh_expires_at - time::OffsetDateTime::now_utc())
        .whole_seconds()
        .max(0);
    let mut response = (StatusCode::OK, Json(TokenResponse::from(pair))).into_response();
    response.headers_mut().append(
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

    // No `scope` parameter: GitHub's default (no-scope) OAuth app grant
    // already returns the numeric id from `GET /user`, which is all
    // `LiveGithubProvider` reads -- `read:user` would only ask for more
    // than this flow uses.
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
        &build_cookie(GITHUB_STATE_COOKIE, &cookie_value, GITHUB_STATE_TTL_SECS),
    );
    response
}

/// `GET /auth/github/callback` (OBI-201, M-AUTH-7, CTO review on PR #78
/// must-fix 1): on success, sets the **same** `__Host-loom_rt` refresh
/// cookie `/auth/login` does and `303`s to the staff app -- never a JSON
/// access/refresh token body, which would be incompatible with OBI-198's
/// cookie-only session model. A T3+ uid that still needs a TOTP code gets
/// a `__Host-github_pending` cookie (not a JSON `pending_token`) and is
/// redirected to a page that prompts for one and `POST`s it to
/// `/auth/github/totp`.
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
    // and sets `Cache-Control: no-store`.
    let respond_error = |status: StatusCode, error: &'static str| {
        let mut response = (status, Json(ErrorResponse { error })).into_response();
        let response_headers = response.headers_mut();
        set_cookie(response_headers, &clear_cookie(GITHUB_STATE_COOKIE));
        response_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    };

    if let Some(provider_error) = query.error.as_deref() {
        // Truncated: this is GitHub's `error` query parameter,
        // attacker-influenced, and logs must not become an unbounded
        // write amplifier.
        let truncated: String = provider_error.chars().take(64).collect();
        tracing::debug!(error = %truncated, "github oauth: provider-side error");
        return respond_error(StatusCode::UNAUTHORIZED, "invalid_code");
    }
    let (Some(code), Some(returned_state)) = (query.code.as_deref(), query.state.as_deref()) else {
        return respond_error(StatusCode::BAD_REQUEST, "missing_code_or_state");
    };

    let Some(cookie_value) = read_cookie(&headers, GITHUB_STATE_COOKIE) else {
        return respond_error(StatusCode::UNAUTHORIZED, "invalid_oauth_state");
    };
    let oauth_state = match auth.verify_oauth_state(&cookie_value) {
        Ok(claims) => claims,
        Err(_) => return respond_error(StatusCode::UNAUTHORIZED, "invalid_oauth_state"),
    };
    // Constant-time-ness doesn't matter here the way it does for an HMAC
    // check: `state` is high-entropy and known to the legitimate browser
    // via its own (HttpOnly) cookie, not a secret an attacker is trying
    // to brute force character-by-character over the network.
    if oauth_state.state != returned_state {
        return respond_error(StatusCode::UNAUTHORIZED, "invalid_oauth_state");
    }

    let user = match github.exchange_code(code, &oauth_state.verifier).await {
        Ok(user) => user,
        Err(GithubAuthError::InvalidCode) => {
            return respond_error(StatusCode::UNAUTHORIZED, "invalid_code");
        }
        Err(GithubAuthError::Unavailable) => {
            return respond_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
        }
    };

    // M-AUTH-7 ("GitHub counts as the password factor only"): this
    // already runs through the same rate limiter + audit trail as
    // password login (OBI-206) -- see `AuthService::github_login`.
    match auth.github_login(user.id, None, &ctx).await {
        Ok(pair) => {
            let max_age = (pair.refresh_expires_at - OffsetDateTime::now_utc())
                .whole_seconds()
                .max(0);
            let mut response = Redirect::to(GITHUB_LOGIN_REDIRECT).into_response();
            let response_headers = response.headers_mut();
            response_headers.append(
                crate::auth::set_cookie_name(),
                crate::auth::set_cookie_header(&pair.refresh_token, max_age),
            );
            set_cookie(response_headers, &clear_cookie(GITHUB_STATE_COOKIE));
            response_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(AuthError::TotpRequired) => {
            // GitHub counts as the password factor only (M-AUTH-7): a T3+
            // uid still needs a TOTP code, which this redirect has no
            // room to carry. The browser gets a short-TTL cookie instead
            // of a JSON `pending_token` (CTO review, must-fix): the
            // authorization code is already spent, so the client
            // exchanges this cookie plus a code via `/auth/github/totp`
            // rather than redoing the OAuth dance.
            match auth.issue_github_pending(user.id) {
                Ok(pending_token) => {
                    let mut response = Redirect::to(GITHUB_PENDING_REDIRECT).into_response();
                    let response_headers = response.headers_mut();
                    response_headers.append(
                        header::SET_COOKIE,
                        HeaderValue::from_str(&build_cookie(
                            GITHUB_PENDING_COOKIE,
                            &pending_token,
                            GITHUB_PENDING_TTL_SECS,
                        ))
                        .expect("cookie header value is ASCII-safe by construction"),
                    );
                    set_cookie(response_headers, &clear_cookie(GITHUB_STATE_COOKIE));
                    response_headers
                        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
                    response
                }
                Err(error) => {
                    let (status, Json(body)) = auth_error_response(error);
                    respond_error(status, body.error)
                }
            }
        }
        Err(error) => {
            let (status, Json(body)) = auth_error_response(error);
            respond_error(status, body.error)
        }
    }
}

/// `POST /auth/github/totp` (OBI-201): redeems the `__Host-github_pending`
/// cookie plus a fresh TOTP code. Guarded by the same Origin +
/// `X-Loom-Auth` CSRF check `/auth/refresh`/`/auth/logout` use (defense
/// in depth -- it reads one cookie and, on success, sets another). On
/// success this responds exactly like `/auth/login`: the access token in
/// the JSON body, the refresh token only as the `__Host-loom_rt` cookie.
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
    let Some(pending_token) = read_cookie(&headers, GITHUB_PENDING_COOKIE) else {
        return auth_error_response(AuthError::InvalidPendingToken).into_response();
    };
    let ctx = auth_context(&headers, Some(peer));
    match auth
        .github_login_with_pending(&pending_token, Some(&request.totp_code), &ctx)
        .await
    {
        Ok(pair) => {
            let mut response = token_response(&pair);
            let response_headers = response.headers_mut();
            set_cookie(response_headers, &clear_cookie(GITHUB_PENDING_COOKIE));
            response_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(error) => {
            let mut response = auth_error_response(error).into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
    }
}

/// A `__Host-` cookie (OBI-201, M-AUTH-7): the `__Host-` prefix itself
/// requires `Secure`, no `Domain` attribute, and `Path=/`, which is what
/// stops a co-tenant subdomain or a plain-HTTP MITM from ever being able
/// to set a cookie by this name that our server would accept.
fn build_cookie(name: &str, value: &str, max_age_secs: i64) -> String {
    format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}")
}

fn clear_cookie(name: &str) -> String {
    format!("{name}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

/// Append (never replace) a `Set-Cookie` header -- a GitHub-login
/// response can carry more than one (e.g. clearing the state cookie
/// while setting the refresh cookie), and browsers treat repeated
/// `Set-Cookie` headers as independent cookies, not an overwrite.
fn set_cookie(headers: &mut HeaderMap, value: &str) {
    if let Ok(header_value) = HeaderValue::from_str(value) {
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

    // -- OBI-201: GitHub login, cookie-session model --------------------

    /// A fake [`GithubIdentityProvider`] scoped to this test module -- one
    /// fixed code -> id mapping, no network.
    struct FakeProvider {
        code: String,
        github_id: i64,
    }

    #[async_trait::async_trait]
    impl crate::auth::GithubIdentityProvider for FakeProvider {
        async fn exchange_code(
            &self,
            code: &str,
            _code_verifier: &str,
        ) -> Result<crate::auth::GithubUser, GithubAuthError> {
            if code == self.code {
                Ok(crate::auth::GithubUser { id: self.github_id })
            } else {
                Err(GithubAuthError::InvalidCode)
            }
        }
    }

    async fn app_with_github(
        directory: FakeDirectory,
        github_code: &str,
        github_id: i64,
    ) -> Router {
        let service = test_service(directory);
        let (ws_accept_tx, _ws_accept_rx) = mpsc::channel(16);
        let provider = std::sync::Arc::new(FakeProvider {
            code: github_code.to_string(),
            github_id,
        });
        let login_config = crate::auth::GithubLoginConfig::new(
            "test-client-id".to_string(),
            "https://staff.example/cb".to_string(),
        );
        let state = crate::HttpState::new(
            ws_accept_tx,
            loom_obs::Readiness::new(),
            loom_obs::PrometheusMetrics::new_unregistered(),
        )
        .with_auth(service)
        .with_github(provider, login_config)
        .with_staff_origins(vec![STAFF_ORIGIN.to_string()]);
        crate::app(state)
    }

    /// Every `Set-Cookie` header value on a response (there can be more
    /// than one -- see [`set_cookie`]'s doc comment).
    fn set_cookie_values(headers: &HeaderMap) -> Vec<String> {
        headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    fn find_cookie<'a>(values: &'a [String], name: &str) -> Option<&'a str> {
        values.iter().map(String::as_str).find(|v| {
            v.split(';')
                .next()
                .is_some_and(|first| first.starts_with(&format!("{name}=")))
        })
    }

    #[tokio::test]
    async fn github_start_redirects_with_pkce_and_sets_the_state_cookie_and_no_scope() {
        let app = app_with_github(FakeDirectory::new(), "unused", 1).await;

        let request = with_peer(
            axum::http::Request::builder()
                .uri("/auth/github/start")
                .body(Body::empty())
                .unwrap(),
        );
        let response = app.oneshot(request).await.unwrap();
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
        assert!(!location.contains("scope="));

        let cookies = set_cookie_values(response.headers());
        assert!(find_cookie(&cookies, GITHUB_STATE_COOKIE).is_some());
    }

    #[tokio::test]
    async fn github_callback_end_to_end_with_a_linked_user_sets_the_session_cookie_and_redirects() {
        let directory = FakeDirectory::new();
        directory.add_staff("samwise", "unused-password", 1);
        directory.link_github(42, "samwise");
        let app = app_with_github(directory, "good-code", 42).await;

        let start_request = with_peer(
            axum::http::Request::builder()
                .uri("/auth/github/start")
                .body(Body::empty())
                .unwrap(),
        );
        let start_response = app.clone().oneshot(start_request).await.unwrap();
        let location = start_response
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let cookies = set_cookie_values(start_response.headers());
        let state_cookie = find_cookie(&cookies, GITHUB_STATE_COOKIE).unwrap();
        let state_cookie = state_cookie.split(';').next().unwrap().to_string();
        let csrf_state = location
            .split("state=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();

        let callback_request = with_peer(
            axum::http::Request::builder()
                .uri(format!(
                    "/auth/github/callback?code=good-code&state={csrf_state}"
                ))
                .header(axum::http::header::COOKIE, state_cookie)
                .body(Body::empty())
                .unwrap(),
        );
        let callback_response = app.oneshot(callback_request).await.unwrap();
        assert_eq!(callback_response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            callback_response
                .headers()
                .get(axum::http::header::LOCATION)
                .unwrap(),
            GITHUB_LOGIN_REDIRECT
        );
        let cookies = set_cookie_values(callback_response.headers());
        let refresh_cookie = find_cookie(&cookies, crate::auth::REFRESH_COOKIE_NAME)
            .expect("github login sets the session refresh cookie, not a JSON token body");
        assert!(refresh_cookie.contains("HttpOnly"));
        assert!(refresh_cookie.contains("Secure"));
        let cleared_state = find_cookie(&cookies, GITHUB_STATE_COOKIE).unwrap();
        assert!(cleared_state.contains("Max-Age=0"));
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
        // Must-fix (PR #78 CTO review): no JSON access/refresh token body
        // on this response at all -- the body is empty (a redirect).
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn github_callback_with_a_wrong_state_is_refused() {
        let directory = FakeDirectory::new();
        directory.add_staff("samwise", "unused-password", 1);
        directory.link_github(42, "samwise");
        let app = app_with_github(directory, "good-code", 42).await;

        let start_request = with_peer(
            axum::http::Request::builder()
                .uri("/auth/github/start")
                .body(Body::empty())
                .unwrap(),
        );
        let start_response = app.clone().oneshot(start_request).await.unwrap();
        let cookies = set_cookie_values(start_response.headers());
        let state_cookie = find_cookie(&cookies, GITHUB_STATE_COOKIE)
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();

        let callback_request = with_peer(
            axum::http::Request::builder()
                .uri("/auth/github/callback?code=good-code&state=not-the-real-state")
                .header(axum::http::header::COOKIE, state_cookie)
                .body(Body::empty())
                .unwrap(),
        );
        let callback_response = app.oneshot(callback_request).await.unwrap();
        assert_eq!(callback_response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn github_callback_without_the_state_cookie_is_refused() {
        let directory = FakeDirectory::new();
        directory.add_staff("samwise", "unused-password", 1);
        directory.link_github(42, "samwise");
        let app = app_with_github(directory, "good-code", 42).await;

        let callback_request = with_peer(
            axum::http::Request::builder()
                .uri("/auth/github/callback?code=good-code&state=whatever")
                .body(Body::empty())
                .unwrap(),
        );
        let callback_response = app.oneshot(callback_request).await.unwrap();
        assert_eq!(callback_response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Acceptance (OBI-201, M-AUTH-7): a T3 GitHub login without TOTP gets
    /// redirected with a pending cookie, not a hard failure and not a
    /// JSON `pending_token` -- `/auth/github/totp` reads that cookie back
    /// (CSRF-guarded the same as `/auth/refresh`) and, with a correct
    /// code, completes the session exactly like `/auth/login` would.
    #[tokio::test]
    async fn github_callback_for_a_t3_uid_sets_a_pending_cookie_then_github_totp_completes_login() {
        let directory = FakeDirectory::new();
        directory.add_staff("gandalf", "unused-password", 3);
        directory.link_github(99, "gandalf");
        let app = app_with_github(directory.clone(), "good-code", 99).await;

        let service = test_service(directory.clone());
        let enrollment = service
            .totp_enroll("gandalf", &crate::auth::AuthContext::default())
            .await
            .unwrap();
        directory.confirm_totp_for_test("gandalf");
        let totp = crate::auth::totp_for_secret(&enrollment.secret_base32, "gandalf").unwrap();

        let start_request = with_peer(
            axum::http::Request::builder()
                .uri("/auth/github/start")
                .body(Body::empty())
                .unwrap(),
        );
        let start_response = app.clone().oneshot(start_request).await.unwrap();
        let location = start_response
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let cookies = set_cookie_values(start_response.headers());
        let state_cookie = find_cookie(&cookies, GITHUB_STATE_COOKIE)
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let csrf_state = location
            .split("state=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();

        let callback_request = with_peer(
            axum::http::Request::builder()
                .uri(format!(
                    "/auth/github/callback?code=good-code&state={csrf_state}"
                ))
                .header(axum::http::header::COOKIE, state_cookie)
                .body(Body::empty())
                .unwrap(),
        );
        let callback_response = app.clone().oneshot(callback_request).await.unwrap();
        assert_eq!(callback_response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            callback_response
                .headers()
                .get(axum::http::header::LOCATION)
                .unwrap(),
            GITHUB_PENDING_REDIRECT
        );
        let cookies = set_cookie_values(callback_response.headers());
        let pending_cookie = find_cookie(&cookies, GITHUB_PENDING_COOKIE)
            .expect("totp-required github login sets a pending cookie, not a JSON body token")
            .split(';')
            .next()
            .unwrap()
            .to_string();
        assert!(find_cookie(&cookies, crate::auth::REFRESH_COOKIE_NAME).is_none());

        let fresh_code = totp.generate_current().to_string();
        let totp_request = with_peer(
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/github/totp")
                .header("origin", STAFF_ORIGIN)
                .header("x-loom-auth", "1")
                .header(axum::http::header::COOKIE, pending_cookie)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "totp_code": fresh_code }).to_string(),
                ))
                .unwrap(),
        );
        let totp_response = app.oneshot(totp_request).await.unwrap();
        assert_eq!(totp_response.status(), StatusCode::OK);
        assert_eq!(
            totp_response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let cookies = set_cookie_values(totp_response.headers());
        assert!(find_cookie(&cookies, crate::auth::REFRESH_COOKIE_NAME).is_some());
    }

    /// `/auth/github/totp` is CSRF-guarded like `/auth/refresh`/`/auth/logout`.
    #[tokio::test]
    async fn github_totp_without_x_loom_auth_header_is_rejected() {
        let directory = FakeDirectory::new();
        directory.add_staff("gandalf", "unused-password", 1);
        directory.link_github(99, "gandalf");
        let app = app_with_github(directory, "good-code", 99).await;

        let request = with_peer(
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/github/totp")
                .header("origin", STAFF_ORIGIN)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "totp_code": "000000" }).to_string(),
                ))
                .unwrap(),
        );
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
