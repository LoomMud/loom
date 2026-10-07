// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The GitHub side of staff GitHub login (OBI-174/OBI-201, M-AUTH-7):
//! authorization-code flow with **PKCE (S256)** and a `state` bound to a
//! short-lived `__Host-` cookie, an exact redirect URI, and an identity
//! key that is the **numeric GitHub user id only** (never the login or
//! email -- GitHub logins can be renamed, the id cannot).
//!
//! GitHub's OAuth app flow does not actually issue an OIDC `id_token`;
//! the equivalent in practice is exchanging the authorization code (plus
//! the PKCE verifier) for an access token, then calling GitHub's REST
//! `/user` endpoint for that numeric id.
//!
//! [`GithubIdentityProvider`] abstracts that exchange so
//! [`crate::auth::AuthService::github_login`] and its tests never need a
//! live GitHub app/network: tests use a fake
//! ([`fake::FakeGithubProvider`]). [`LiveGithubProvider`] is the
//! network-backed implementation, wired in by `loom-cli` only when
//! `LOOM_GITHUB_CLIENT_ID`/`LOOM_GITHUB_CLIENT_SECRET`/
//! `LOOM_GITHUB_REDIRECT_URI` are all configured -- same "absent by
//! default" shape as `LOOM_JWT_SECRET`/`LOOM_WEB_ROOT`. The redirect-flow
//! plumbing itself (the `/auth/github/start`/`/auth/github/callback`
//! handlers, PKCE verifier + `state` generation, and the `__Host-` cookie
//! that binds them) lives in `crate::handlers` and
//! [`OAuthStateClaims`]/[`generate_pkce`]/[`generate_state`] below --
//! deliberately plain functions/types with no axum dependency, so they're
//! unit-testable without spinning up a router.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GithubUser {
    pub id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GithubAuthError {
    /// The authorization code (or PKCE verifier) was rejected, expired,
    /// or already used.
    InvalidCode,
    /// The network/API call itself failed, or returned something this
    /// client couldn't parse.
    Unavailable,
}

#[async_trait::async_trait]
pub trait GithubIdentityProvider: Send + Sync {
    /// Exchange an OAuth authorization code -- plus the PKCE verifier
    /// that matches the `code_challenge` sent in the authorize request --
    /// for the GitHub user it belongs to. Implementations must not
    /// themselves decide whether that user is linked to a staff uid --
    /// that is `github_identities`' job, done by
    /// [`crate::auth::AuthService::github_login`] after this returns.
    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<GithubUser, GithubAuthError>;
}

/// A PKCE (RFC 7636) verifier/challenge pair, S256 only (GitHub supports
/// `plain` too, but there is no reason to ever use it: S256 is strictly
/// stronger and the derivation costs nothing).
#[derive(Debug, Clone)]
pub struct PkcePair {
    /// 32 bytes of CSPRNG output, base64url-no-pad -- within RFC 7636's
    /// required 43-128 char range (43 chars for 32 bytes).
    pub verifier: String,
    /// `BASE64URL(SHA256(verifier))`.
    pub challenge: String,
}

/// Generate a fresh PKCE verifier/challenge pair for one authorization
/// request. Never reused across requests.
pub fn generate_pkce() -> PkcePair {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    PkcePair {
        verifier,
        challenge,
    }
}

/// Generate a fresh CSRF `state` value for one authorization request:
/// 32 bytes of CSPRNG output, base64url-no-pad.
pub fn generate_state() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The only valid [`OAuthStateClaims::purpose`] value. Checked on
/// decode as a belt-and-suspenders check -- [`OAUTH_STATE_AUDIENCE`] is
/// the real cross-type guard (OBI-201 review must-fix).
pub const OAUTH_STATE_PURPOSE: &str = "github_oauth_state";

/// [`OAuthStateClaims`]'s pinned `aud` (OBI-201 review must-fix):
/// distinct from [`crate::auth::AUDIENCE`] (access tokens) and from
/// [`crate::auth::claims::GITHUB_PENDING_AUDIENCE`] (the GitHub-login
/// TOTP-pending token), so [`crate::auth::jwt::JwtKeys::decode_claims`]
/// refuses a cross-type token outright, not just via the `purpose`
/// field.
pub const OAUTH_STATE_AUDIENCE: &str = "loom-oauth-state";

/// What the `__Host-` state cookie carries (OBI-201, M-AUTH-7): the
/// `state` value GitHub must echo back, and the PKCE verifier that
/// matches the `code_challenge` sent in the authorize request. Signed
/// (via [`crate::auth::JwtKeys::encode_claims`]) rather than opaque +
/// server-side-stored, since the driver already has a signing key and
/// this keeps the OAuth flow stateless (no extra table, no cleanup job
/// for abandoned flows). The cookie is `HttpOnly`/`Secure` so the
/// verifier never reaches page JS; it is still sent to GitHub, in the
/// clear, as part of the (server-to-server, TLS) token exchange, which is
/// exactly what PKCE expects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthStateClaims {
    pub state: String,
    pub verifier: String,
    pub purpose: String,
    pub iss: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
}

/// Configuration for [`LiveGithubProvider`]. `token_url`/`user_url` are
/// overridable so tests can point them at a local mock server instead of
/// `github.com`/`api.github.com`; `loom-cli` never overrides them.
#[derive(Debug, Clone)]
pub struct GithubOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    /// Must exactly match what the authorize request sent and what's
    /// registered on the GitHub OAuth app -- GitHub refuses a mismatch
    /// (M-AUTH-7: "exact redirect URI").
    pub redirect_uri: String,
    pub token_url: String,
    pub user_url: String,
}

impl GithubOAuthConfig {
    /// The real `github.com`/`api.github.com` endpoints.
    pub fn new(client_id: String, client_secret: String, redirect_uri: String) -> Self {
        Self {
            client_id,
            client_secret,
            redirect_uri,
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            user_url: "https://api.github.com/user".to_string(),
        }
    }
}

/// The (non-secret) half of [`GithubOAuthConfig`] the `/auth/github/start`
/// redirect handler needs to build the authorize URL -- kept separate
/// from the client secret so `HttpState` can hand it to a handler (and,
/// in logs/traces, be seen) without the secret ever being reachable the
/// same way.
#[derive(Debug, Clone)]
pub struct GithubLoginConfig {
    pub client_id: String,
    /// Must exactly match [`GithubOAuthConfig::redirect_uri`] and the
    /// GitHub OAuth app's registered callback URL.
    pub redirect_uri: String,
    pub authorize_url: String,
}

impl GithubLoginConfig {
    pub fn new(client_id: String, redirect_uri: String) -> Self {
        Self {
            client_id,
            redirect_uri,
            authorize_url: "https://github.com/login/oauth/authorize".to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum TokenResponse {
    Ok {
        access_token: String,
    },
    #[allow(dead_code)]
    Err {
        error: String,
    },
}

#[derive(Debug, Deserialize)]
struct GithubUserResponse {
    id: i64,
}

/// The network-backed [`GithubIdentityProvider`] (OBI-201): exchanges a
/// code + PKCE verifier for a GitHub access token, then resolves that to
/// a numeric user id via `GET /user`. Never retains the GitHub access
/// token past this call -- it is a bearer credential for GitHub's API,
/// not something this driver has any use for afterwards, and keeping it
/// around would just be one more secret to leak.
pub struct LiveGithubProvider {
    client: reqwest::Client,
    config: GithubOAuthConfig,
}

impl LiveGithubProvider {
    pub fn new(config: GithubOAuthConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("reqwest client with only a timeout always builds");
        Self { client, config }
    }
}

#[async_trait::async_trait]
impl GithubIdentityProvider for LiveGithubProvider {
    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<GithubUser, GithubAuthError> {
        let token_response = self
            .client
            .post(&self.config.token_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[
                ("client_id", self.config.client_id.as_str()),
                ("client_secret", self.config.client_secret.as_str()),
                ("code", code),
                ("redirect_uri", self.config.redirect_uri.as_str()),
                ("code_verifier", code_verifier),
            ])
            .send()
            .await
            .map_err(|_| GithubAuthError::Unavailable)?;

        if !token_response.status().is_success() {
            return Err(GithubAuthError::Unavailable);
        }

        let token: TokenResponse = token_response
            .json()
            .await
            .map_err(|_| GithubAuthError::Unavailable)?;
        let access_token = match token {
            TokenResponse::Ok { access_token } => access_token,
            // GitHub answers a bad/expired/already-used code or a PKCE
            // verifier mismatch with `200 {"error": "..."}`, not a non-2xx
            // status -- this is the branch that catches that.
            TokenResponse::Err { .. } => return Err(GithubAuthError::InvalidCode),
        };

        let user_response = self
            .client
            .get(&self.config.user_url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {access_token}"),
            )
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            // GitHub's API refuses requests with no User-Agent.
            .header(reqwest::header::USER_AGENT, "loom-driver")
            .send()
            .await
            .map_err(|_| GithubAuthError::Unavailable)?;

        if !user_response.status().is_success() {
            return Err(GithubAuthError::Unavailable);
        }

        let user: GithubUserResponse = user_response
            .json()
            .await
            .map_err(|_| GithubAuthError::Unavailable)?;
        Ok(GithubUser { id: user.id })
    }
}

#[cfg(test)]
pub mod fake {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A fake [`GithubIdentityProvider`] for tests: maps a fixed set of
    /// authorization codes to GitHub user ids, with no network involved.
    /// Ignores `code_verifier` -- PKCE verification against the
    /// `code_challenge` GitHub received is GitHub's job, not something a
    /// unit test of [`crate::auth::AuthService`] needs to re-prove.
    #[derive(Default)]
    pub struct FakeGithubProvider {
        codes: Mutex<HashMap<String, i64>>,
    }

    impl FakeGithubProvider {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn with_code(self, code: &str, github_id: i64) -> Self {
            self.codes
                .lock()
                .unwrap()
                .insert(code.to_string(), github_id);
            self
        }
    }

    #[async_trait::async_trait]
    impl GithubIdentityProvider for FakeGithubProvider {
        async fn exchange_code(
            &self,
            code: &str,
            _code_verifier: &str,
        ) -> Result<GithubUser, GithubAuthError> {
            match self.codes.lock().unwrap().get(code) {
                Some(&id) => Ok(GithubUser { id }),
                None => Err(GithubAuthError::InvalidCode),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_the_sha256_of_the_verifier() {
        let pair = generate_pkce();
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(pair.verifier.as_bytes()));
        assert_eq!(pair.challenge, expected);
        // RFC 7636 requires 43-128 chars; 32 random bytes base64url-no-pad
        // is 43.
        assert_eq!(pair.verifier.len(), 43);
    }

    #[test]
    fn pkce_pairs_and_states_are_not_reused() {
        let a = generate_pkce();
        let b = generate_pkce();
        assert_ne!(a.verifier, b.verifier);
        assert_ne!(a.challenge, b.challenge);
        assert_ne!(generate_state(), generate_state());
    }
}
