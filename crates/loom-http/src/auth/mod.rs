// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Staff web auth (OBI-174, design §9/D-P2.5): JWT access + refresh tokens,
//! TOTP enrolment/verification (mandatory for T3+), and an optional
//! GitHub-login path that only ever authenticates an *already-linked*
//! staff uid.
//!
//! ## The tier always comes from Postgres
//!
//! [`StaffDirectory::auth_status_for`] is the *only* source of truth for a
//! staff uid's tier. [`AuthService::issue_tokens`] -- the single place
//! shared by the password, refresh, and GitHub login paths -- calls it
//! fresh every time: an access token's `tier`/`scopes` claims are a
//! snapshot taken at issue time, never a value the client (or an upstream
//! IdP) can set, and a promotion or demotion always takes effect at the
//! access token's next refresh, which can be forced by revoking the
//! caller's refresh tokens (see
//! [`StaffDirectory::refresh_token_revoke_all`]). A uid with *no* `staff`
//! row at all (e.g. removed staff) is refused outright rather than minting
//! a tier-0 token (OBI-195 review fix 5).
//!
//! ## TOTP is mandatory for T3+, at issue *and* refresh
//!
//! [`AuthService::issue_tokens`] refuses a tier-3-or-above staff member's
//! session with [`AuthError::TotpRequired`] unless their TOTP secret is
//! both enrolled *and* confirmed (see `staff.totp_confirmed_at` in
//! migration 0003), and refuses with [`AuthError::TotpInvalid`] unless
//! `totp_code` verifies -- for every path that reaches it: password login,
//! refresh, and GitHub login alike (OBI-195 review fix 2: the first cut of
//! this PR only gated the password path, which meant a T3+ uid promoted
//! after an earlier, sub-T3 login could keep refreshing T3+ tokens
//! forever, and GitHub login skipped the gate entirely). There is no
//! bypass: a T3+ row with no confirmed secret cannot get a session, only
//! enrol one (via [`AuthService::totp_enroll`]/[`AuthService::totp_confirm`],
//! which themselves require a password login having already succeeded up
//! to the TOTP gate -- see `handlers.rs`). Every accepted code also
//! consumes its RFC 6238 time-step via
//! [`StaffDirectory::totp_consume_step`], so the same code can never be
//! replayed even within the skew window (OBI-195 review fix 4).
//!
//! Requiring a fresh `totp_code` on every refresh call for a T3+ uid is a
//! deliberate stopgap, not a final UX: it closes the immediate gap: the
//! richer step-up/`mfa_at` design from the OBI-179 threat model (skip the
//! code if the session authenticated with one recently) is tracked as a
//! follow-up (OBI-197/OBI-198), not blocking this PR.
//!
//! ## GitHub login never creates staff
//!
//! [`AuthService::github_login`] looks up the numeric GitHub user id in
//! `github_identities` (populated only by an arch/root through
//! `Persist::github_link`, T4+). An unlinked id is refused outright --
//! this module has no code path that inserts a `staff` row.
//!
//! ## Rate limiting, lockout, and audit (OBI-200)
//!
//! [`AuthService::login`]/[`AuthService::totp_confirm`] share one
//! [`RateLimiter`] (see that module's docs for the exact numbers): a
//! wrong password or wrong TOTP code counts as a failure toward both a
//! per-account lockout and a per-IP token bucket, and a locked account
//! gets exactly the same response as a wrong password. Every login,
//! refresh-reuse, and TOTP enrol/reset is appended to `audit_log` via
//! [`StaffDirectory::record_audit`] (M-AUTH-9); see
//! `docs/threat-model-phase2.md` §6.1 (M-AUTH-1, M-AUTH-2, M-AUTH-9).

mod claims;
mod directory;
mod github;
mod jwt;
pub mod ratelimit;
mod totp;

pub use claims::{AccessClaims, GITHUB_PENDING_PURPOSE, GithubPendingClaims, scopes_for_tier};
pub use directory::{
    AuditEvent, DirectoryError, RefreshRecord, RefreshRotation, StaffAuthRecord, StaffAuthStatus,
    StaffDirectory,
};
pub use github::{
    GithubAuthError, GithubIdentityProvider, GithubLoginConfig, GithubOAuthConfig, GithubUser,
    LiveGithubProvider, OAUTH_STATE_PURPOSE, OAuthStateClaims, PkcePair, generate_pkce,
    generate_state,
};
pub use jwt::{Expires, JwtKeys, TokenPair};
pub use ratelimit::{RateLimitDecision, RateLimiter};
pub use totp::{
    TotpEnrollment, generate_totp_secret, totp_for_secret, totp_step_for_code, verify_totp_code,
};

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tracing::warn;

/// Everything a login/refresh/TOTP attempt carries about *who's asking*,
/// for the rate limiter (M-AUTH-1) and the audit trail (M-AUTH-9) --
/// never for an authorization decision (that's still `sub`/tier, read
/// fresh from the directory). `ip` is `None` only in tests or if
/// `loom-http`'s client-IP resolution ([`crate::client_ip`]) truly has
/// nothing to fall back to.
#[derive(Debug, Clone, Default)]
pub struct AuthContext {
    pub ip: Option<IpAddr>,
    pub user_agent: Option<String>,
}

impl AuthContext {
    pub fn new(ip: Option<IpAddr>, user_agent: Option<String>) -> Self {
        Self { ip, user_agent }
    }
}

/// Access tokens are short-lived: a promotion/demotion or a TOTP
/// requirement change is at most this stale before a refresh picks it up.
pub const ACCESS_TOKEN_TTL: Duration = Duration::from_secs(10 * 60);
/// Refresh tokens are long-lived but revocable and rotated on every use.
pub const REFRESH_TOKEN_TTL: Duration = Duration::from_secs(14 * 24 * 60 * 60);
/// Tiers at or above this one must have a confirmed TOTP secret to obtain a
/// session (design §9/D-P2.5: "mandatory for T3+").
pub const MANDATORY_TOTP_TIER: i16 = 3;
/// A GitHub-login-pending-TOTP token (OBI-201) is a narrow, single-use
/// credential: it only ever proves "GitHub's authorization-code exchange
/// already resolved to this numeric github_id", not "this uid is signed
/// in". Kept short so a leaked one (log, referrer, browser history on a
/// JSON response) is cheap to wait out.
pub const GITHUB_PENDING_TTL: Duration = Duration::from_secs(5 * 60);
/// How long a GitHub OAuth `state`/PKCE-verifier cookie is good for
/// (OBI-201, M-AUTH-7) -- long enough for a human to authorize on GitHub,
/// short enough that a captured cookie isn't useful for long.
pub const OAUTH_STATE_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// Bad username/password, or (for GitHub) an unlinked identity, or a
    /// uid with no `staff` row at all (removed staff -- OBI-195 review
    /// fix 5).
    InvalidCredentials,
    /// Correct password, but the account needs a TOTP code and none (or an
    /// incorrect one) was supplied.
    TotpRequired,
    /// Correct password and tier is below the mandatory-TOTP floor, but the
    /// account somehow has no *confirmed* TOTP secret even though one was
    /// supplied/expected -- surfaced separately from `TotpRequired` so
    /// callers can tell "you didn't send a code" apart from "your code was
    /// wrong" (this also covers a replayed/already-consumed step: RFC
    /// 6238-valid but refused, OBI-195 review fix 4).
    TotpInvalid,
    /// `totp_enroll` refused: the uid already has a *confirmed* secret.
    /// Overwriting one from nothing but a bearer token would let a stolen
    /// access token downgrade a T3+ account's second factor (OBI-195
    /// review fix 3) -- a real reset needs a dedicated, step-up-gated flow
    /// (tracked as a follow-up, OBI-199).
    TotpAlreadyEnrolled,
    /// The refresh token is unknown, expired, or already revoked.
    InvalidRefreshToken,
    /// The backing directory (Postgres) failed.
    DirectoryUnavailable,
    /// The per-IP token bucket is empty (M-AUTH-1). Distinct from
    /// [`AuthError::InvalidCredentials`] -- unlike an account lockout,
    /// which must look exactly like a wrong password, an IP-level
    /// throttle is not account-specific and doesn't leak anything about
    /// a particular username.
    RateLimited,
    /// The GitHub-login-pending-TOTP token is unknown, expired, malformed,
    /// or was issued for a different purpose (OBI-201).
    InvalidPendingToken,
    /// The OAuth `state` cookie is missing, expired, malformed, signed for
    /// a different purpose, or doesn't match the `state` GitHub echoed
    /// back (OBI-201, M-AUTH-7).
    InvalidOAuthState,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AuthError::InvalidCredentials => "invalid credentials",
            AuthError::TotpRequired => "totp code required",
            AuthError::TotpInvalid => "totp code invalid",
            AuthError::TotpAlreadyEnrolled => "totp already enrolled",
            AuthError::InvalidRefreshToken => "invalid refresh token",
            AuthError::DirectoryUnavailable => "directory unavailable",
            AuthError::RateLimited => "rate limited",
            AuthError::InvalidPendingToken => "invalid pending token",
            AuthError::InvalidOAuthState => "invalid oauth state",
        };
        f.write_str(s)
    }
}

impl std::error::Error for AuthError {}

impl From<DirectoryError> for AuthError {
    fn from(_: DirectoryError) -> Self {
        AuthError::DirectoryUnavailable
    }
}

/// Everything [`AuthService::login`]/[`AuthService::refresh`]/
/// [`AuthService::github_login`] need: the staff directory, the JWT
/// signing keys, the TTLs (fixed to the module constants above, exposed as
/// fields only so tests can shrink them), and the rate limiter (OBI-200).
#[derive(Clone)]
pub struct AuthService {
    directory: Arc<dyn StaffDirectory>,
    keys: JwtKeys,
    access_ttl: Duration,
    refresh_ttl: Duration,
    rate_limiter: Arc<RateLimiter>,
}

impl AuthService {
    pub fn new(directory: Arc<dyn StaffDirectory>, keys: JwtKeys) -> Self {
        Self {
            directory,
            keys,
            access_ttl: ACCESS_TOKEN_TTL,
            refresh_ttl: REFRESH_TOKEN_TTL,
            rate_limiter: Arc::new(RateLimiter::new()),
        }
    }

    /// Shrink the TTLs for a deterministic test (e.g. a 1-nanosecond-ish
    /// access TTL to exercise expiry without sleeping real minutes).
    #[cfg(test)]
    pub fn with_ttls(mut self, access_ttl: Duration, refresh_ttl: Duration) -> Self {
        self.access_ttl = access_ttl;
        self.refresh_ttl = refresh_ttl;
        self
    }

    /// Swap in a rate limiter with shrunk windows for a deterministic
    /// test (OBI-200).
    #[cfg(test)]
    pub fn with_rate_limiter(mut self, rate_limiter: RateLimiter) -> Self {
        self.rate_limiter = Arc::new(rate_limiter);
        self
    }

    /// Username/password login (design §9). Refuses with
    /// [`AuthError::TotpRequired`]/[`AuthError::TotpInvalid`] for a T3+
    /// staff member unless `totp_code` verifies against their confirmed
    /// secret -- enforced inside [`Self::issue_tokens`], the single gate
    /// shared by every login method (OBI-195 review fix 2).
    ///
    /// Rate limiting (OBI-200, M-AUTH-1): checked *before* any
    /// credential work. A throttled IP gets [`AuthError::RateLimited`]. A
    /// locked account gets exactly [`AuthError::InvalidCredentials`] --
    /// the same response as a wrong password, so a client can never tell
    /// "this account is locked" from "that password is wrong" (which
    /// would otherwise leak account existence/activity). A wrong
    /// password or a wrong TOTP code both count as a failure toward the
    /// account lockout; a *missing* TOTP code does not (it isn't a
    /// guess). Every outcome is audited (M-AUTH-9).
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        totp_code: Option<&str>,
        ctx: &AuthContext,
    ) -> Result<TokenPair, AuthError> {
        match self.rate_limiter.check(username, ctx.ip) {
            RateLimitDecision::IpThrottled => {
                self.audit(
                    "auth.login.fail",
                    None,
                    ctx,
                    "deny",
                    Some("ip_rate_limited".to_string()),
                )
                .await;
                return Err(AuthError::RateLimited);
            }
            RateLimitDecision::AccountLocked => {
                self.audit(
                    "auth.login.fail",
                    None,
                    ctx,
                    "deny",
                    Some("account_locked".to_string()),
                )
                .await;
                return Err(AuthError::InvalidCredentials);
            }
            RateLimitDecision::Allowed => {}
        }

        let record = match self.directory.staff_login(username, password).await {
            Ok(Some(record)) => record,
            Ok(None) => {
                self.rate_limiter.record_failure(username);
                self.audit(
                    "auth.login.fail",
                    None,
                    ctx,
                    "deny",
                    Some("invalid_credentials".to_string()),
                )
                .await;
                return Err(AuthError::InvalidCredentials);
            }
            Err(err) => return Err(err.into()),
        };

        // The TOTP gate and token mint both happen inside `issue_tokens`,
        // which re-reads tier/TOTP state fresh rather than reusing
        // `record` -- one enforcement point for every login method
        // (OBI-195 review fix 2), and a login never trusts a `staff_login`
        // row that could in principle be a moment stale.
        match self.issue_tokens(&record.uid, totp_code).await {
            Ok(pair) => {
                self.rate_limiter.record_success(username);
                self.audit(
                    "auth.login.ok",
                    Some(record.uid.clone()),
                    ctx,
                    "allow",
                    None,
                )
                .await;
                Ok(pair)
            }
            Err(err) => {
                if err == AuthError::TotpInvalid {
                    self.rate_limiter.record_failure(username);
                }
                self.audit(
                    "auth.login.fail",
                    Some(record.uid.clone()),
                    ctx,
                    "deny",
                    Some(totp_gate_detail(&err).to_string()),
                )
                .await;
                Err(err)
            }
        }
    }

    /// GitHub login (design §9, M-AUTH-7): `github_id` is the numeric id
    /// the caller already obtained from the real OAuth2 + PKCE exchange
    /// (see [`GithubIdentityProvider`]/`crate::handlers`) -- this function
    /// never talks to GitHub itself, it only resolves the link. An
    /// unlinked id is always refused; this never creates a staff row.
    ///
    /// `totp_code` is required for a T3+ uid exactly like the password
    /// path (OBI-195 review fix 2): linking a GitHub identity to a T3+ uid
    /// is itself a T4+ action (`auth_github_link`), but that only vouches
    /// for the *link*, not for a second factor on *this* login -- a GitHub
    /// account takeover must not bypass the mandatory-TOTP floor just
    /// because an arch linked it once.
    ///
    /// Shares the password path's rate limiter and audit trail (OBI-206:
    /// GitHub login previously bypassed both, so a compromised GitHub
    /// account -- or a stolen/forged authorization code -- could brute
    /// force TOTP codes through repeated callbacks with no lockout and no
    /// record). The limiter key is `github:{github_id}` rather than a
    /// uid: the id is known before the link is resolved, so a flood of
    /// bogus/unlinked ids is throttled too, not just guesses against a
    /// linked account.
    pub async fn github_login(
        &self,
        github_id: i64,
        totp_code: Option<&str>,
        ctx: &AuthContext,
    ) -> Result<TokenPair, AuthError> {
        let rate_limit_key = format!("github:{github_id}");
        match self.rate_limiter.check(&rate_limit_key, ctx.ip) {
            RateLimitDecision::IpThrottled => {
                self.audit(
                    "auth.login.fail",
                    None,
                    ctx,
                    "deny",
                    Some("ip_rate_limited".to_string()),
                )
                .await;
                return Err(AuthError::RateLimited);
            }
            RateLimitDecision::AccountLocked => {
                self.audit(
                    "auth.login.fail",
                    None,
                    ctx,
                    "deny",
                    Some("account_locked".to_string()),
                )
                .await;
                return Err(AuthError::InvalidCredentials);
            }
            RateLimitDecision::Allowed => {}
        }

        let uid = match self.directory.github_lookup(github_id).await {
            Ok(Some(uid)) => uid,
            Ok(None) => {
                self.rate_limiter.record_failure(&rate_limit_key);
                self.audit(
                    "auth.login.fail",
                    None,
                    ctx,
                    "deny",
                    Some("github_unlinked".to_string()),
                )
                .await;
                return Err(AuthError::InvalidCredentials);
            }
            Err(err) => return Err(err.into()),
        };

        match self.issue_tokens(&uid, totp_code).await {
            Ok(pair) => {
                self.rate_limiter.record_success(&rate_limit_key);
                self.audit("auth.login.ok", Some(uid.clone()), ctx, "allow", None)
                    .await;
                Ok(pair)
            }
            Err(err) => {
                if err == AuthError::TotpInvalid {
                    self.rate_limiter.record_failure(&rate_limit_key);
                }
                self.audit(
                    "auth.login.fail",
                    Some(uid.clone()),
                    ctx,
                    "deny",
                    Some(totp_gate_detail(&err).to_string()),
                )
                .await;
                Err(err)
            }
        }
    }

    /// Mint a short-lived, single-purpose token asserting "GitHub's
    /// authorization-code exchange already resolved to this numeric
    /// `github_id`" (OBI-201), for the callback handler to hand back when
    /// [`Self::github_login`] refuses with [`AuthError::TotpRequired`]:
    /// the authorization code is single-use and already spent by that
    /// point, so the client can't just redo the OAuth dance with a
    /// `totp_code` attached -- it redeems this token instead, via
    /// [`Self::github_login_with_pending`].
    pub fn issue_github_pending(&self, github_id: i64) -> Result<String, AuthError> {
        let issued_at = now();
        let claims = GithubPendingClaims {
            github_id,
            purpose: GITHUB_PENDING_PURPOSE.to_string(),
            iat: issued_at.unix_timestamp(),
            exp: (issued_at + GITHUB_PENDING_TTL).unix_timestamp(),
        };
        self.keys
            .encode_claims(&claims)
            .map_err(|_| AuthError::DirectoryUnavailable)
    }

    /// Redeem a [`Self::issue_github_pending`] token plus a TOTP code,
    /// completing a GitHub login that stopped at the TOTP gate. Resolves
    /// the link fresh (same as [`Self::github_login`] would), rather than
    /// trusting a uid baked into the pending token, so a link revoked in
    /// the interim is honoured.
    pub async fn github_login_with_pending(
        &self,
        pending_token: &str,
        totp_code: Option<&str>,
        ctx: &AuthContext,
    ) -> Result<TokenPair, AuthError> {
        let claims: GithubPendingClaims = self
            .keys
            .decode_claims(pending_token)
            .map_err(|_| AuthError::InvalidPendingToken)?;
        if claims.purpose != GITHUB_PENDING_PURPOSE {
            return Err(AuthError::InvalidPendingToken);
        }
        self.github_login(claims.github_id, totp_code, ctx).await
    }

    /// Sign an [`OAuthStateClaims`] bundle for the `__Host-` state cookie
    /// (OBI-201, M-AUTH-7). Used by `crate::handlers::github_start`.
    pub fn sign_oauth_state(&self, claims: &OAuthStateClaims) -> Result<String, AuthError> {
        self.keys
            .encode_claims(claims)
            .map_err(|_| AuthError::DirectoryUnavailable)
    }

    /// Verify and decode the `__Host-` state cookie (OBI-201, M-AUTH-7).
    /// Refuses an expired cookie, a bad signature, or one signed for a
    /// different purpose -- used by `crate::handlers::github_callback`
    /// before it trusts anything in the cookie (the PKCE verifier
    /// especially).
    pub fn verify_oauth_state(&self, cookie_value: &str) -> Result<OAuthStateClaims, AuthError> {
        let claims: OAuthStateClaims = self
            .keys
            .decode_claims(cookie_value)
            .map_err(|_| AuthError::InvalidOAuthState)?;
        if claims.purpose != OAUTH_STATE_PURPOSE {
            return Err(AuthError::InvalidOAuthState);
        }
        Ok(claims)
    }

    /// Rotate a refresh token: the presented token must be unexpired and
    /// unrevoked, else [`AuthError::InvalidRefreshToken`]. On success the
    /// old token is revoked and a new (access, refresh) pair is issued,
    /// with `tier`/`scopes` -- and the TOTP gate -- read fresh from
    /// Postgres, never carried over from whatever the old access token
    /// claimed (OBI-195 review fix 2: a T3+ uid must keep proving TOTP at
    /// refresh, not just at the original login).
    ///
    /// The rotation itself is a single atomic `UPDATE ... RETURNING` (see
    /// [`RefreshRotation`], OBI-195 review fix 1): two concurrent
    /// presentations of the same bearer token can never both see "not yet
    /// revoked" and both succeed. A `Reused` outcome -- replay of a
    /// rotated-out or logged-out token, i.e. a stolen refresh token --
    /// revokes every other outstanding token for that uid, not just the
    /// one presented, since by definition one of the two parties holding
    /// it is not the legitimate session, and is audited as
    /// `auth.refresh.reuse` (M-AUTH-9).
    pub async fn refresh(
        &self,
        refresh_token: &str,
        totp_code: Option<&str>,
        ctx: &AuthContext,
    ) -> Result<TokenPair, AuthError> {
        let token_hash = hash_token(refresh_token);
        match self.directory.refresh_token_rotate(&token_hash).await? {
            RefreshRotation::Rotated { staff_uid } => {
                self.issue_tokens(&staff_uid, totp_code).await
            }
            RefreshRotation::Reused { staff_uid } => {
                self.directory.refresh_token_revoke_all(&staff_uid).await?;
                self.audit("auth.refresh.reuse", Some(staff_uid), ctx, "deny", None)
                    .await;
                Err(AuthError::InvalidRefreshToken)
            }
            RefreshRotation::Expired | RefreshRotation::NotFound => {
                Err(AuthError::InvalidRefreshToken)
            }
        }
    }

    /// Revoke a single refresh token (logout).
    pub async fn logout(&self, refresh_token: &str) -> Result<(), AuthError> {
        let token_hash = hash_token(refresh_token);
        self.directory.refresh_token_revoke(&token_hash).await?;
        Ok(())
    }

    /// Generate and store a fresh TOTP secret for `uid` (self-service --
    /// the directory re-checks actor == uid in SQL). Returns the
    /// enrolment payload (base32 secret + `otpauth://` URL) once; the
    /// caller must show it to the user now, since only its hash-adjacent
    /// state (not the plaintext) is ever returned again. Audited as
    /// `auth.totp.enrol` the first time `uid` gets a secret, or
    /// `auth.totp.reset` if one already existed (M-AUTH-9).
    ///
    /// Refuses with [`AuthError::TotpAlreadyEnrolled`] if `uid` already has
    /// a *confirmed* secret (OBI-195 review fix 3) -- the SQL function
    /// backing [`StaffDirectory::totp_enroll`] re-checks this too (D-27.2
    /// pattern), this is the fast/typed path so the HTTP layer can answer
    /// `409` instead of a generic `503`. A real reset of a *confirmed*
    /// secret needs a dedicated, step-up-gated flow (OBI-199 follow-up).
    pub async fn totp_enroll(
        &self,
        uid: &str,
        ctx: &AuthContext,
    ) -> Result<totp::TotpEnrollment, AuthError> {
        let status = self
            .directory
            .auth_status_for(uid)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;
        if status.totp_confirmed {
            return Err(AuthError::TotpAlreadyEnrolled);
        }
        let had_prior_secret = status.totp_secret.is_some();
        let enrollment = totp::generate_totp_secret(uid);
        self.directory
            .totp_enroll(uid, &enrollment.secret_base32)
            .await?;
        let kind = if had_prior_secret {
            "auth.totp.reset"
        } else {
            "auth.totp.enrol"
        };
        self.audit(kind, Some(uid.to_string()), ctx, "allow", None)
            .await;
        Ok(enrollment)
    }

    /// Verify `code` against `uid`'s just-enrolled (or previously
    /// enrolled) secret and, on success, mark it confirmed -- the gate
    /// [`Self::issue_tokens`] checks for T3+ staff. Like every other TOTP
    /// check in this service, the matched step is consumed atomically
    /// (OBI-195 review fix 4): confirming with a code does not leave that
    /// code valid for a subsequent login. TOTP attempts share the login
    /// rate limiter (M-AUTH-1): a wrong code counts as a failure against
    /// both the per-account and per-IP limits.
    pub async fn totp_confirm(
        &self,
        uid: &str,
        code: &str,
        ctx: &AuthContext,
    ) -> Result<(), AuthError> {
        match self.rate_limiter.check(uid, ctx.ip) {
            RateLimitDecision::IpThrottled => return Err(AuthError::RateLimited),
            RateLimitDecision::AccountLocked => return Err(AuthError::TotpInvalid),
            RateLimitDecision::Allowed => {}
        }

        let secret = self
            .directory
            .totp_secret_for(uid)
            .await?
            .ok_or(AuthError::TotpInvalid)?;
        match self.verify_and_consume_totp(uid, &secret, code).await {
            Ok(()) => {
                self.directory.totp_confirm(uid).await?;
                self.rate_limiter.record_success(uid);
                Ok(())
            }
            Err(err) => {
                self.rate_limiter.record_failure(uid);
                Err(err)
            }
        }
    }

    /// Verify an access token's signature/expiry and return its claims.
    /// Does **not** re-read the tier from Postgres -- callers that need a
    /// guaranteed-current tier (any privileged write) must still check
    /// against the directory directly; this is for cheap, read-mostly
    /// authorization at the edge.
    pub fn verify_access_token(&self, token: &str) -> Result<AccessClaims, AuthError> {
        self.keys
            .decode(token)
            .map_err(|_| AuthError::InvalidRefreshToken)
    }

    /// Issue a fresh (access, refresh) pair for `uid`, reading its tier and
    /// TOTP state from Postgres right now and enforcing the mandatory-TOTP
    /// gate against them. Shared by the password, GitHub, and refresh
    /// paths so there is exactly one place that turns a tier into scopes,
    /// enforces TOTP, and mints tokens (OBI-195 review fix 2).
    async fn issue_tokens(
        &self,
        uid: &str,
        totp_code: Option<&str>,
    ) -> Result<TokenPair, AuthError> {
        let Some(status) = self.directory.auth_status_for(uid).await? else {
            // No `staff` row at all (OBI-195 review fix 5): removed staff,
            // or any uid that otherwise reached this point without one.
            // The old `tier_of`-based design defaulted this to tier 0 and
            // minted a token anyway; refuse outright instead, and drop any
            // sessions this uid might still hold.
            self.directory.refresh_token_revoke_all(uid).await?;
            return Err(AuthError::InvalidCredentials);
        };

        self.enforce_totp_gate(
            uid,
            status.tier,
            status.totp_secret.as_deref(),
            status.totp_confirmed,
            totp_code,
        )
        .await?;

        let tier = status.tier;
        let scopes = scopes_for_tier(tier);
        let issued_at = now();
        let access_expires_at = issued_at + self.access_ttl;
        let claims = AccessClaims {
            sub: uid.to_string(),
            tier,
            scopes,
            iat: issued_at.unix_timestamp(),
            exp: access_expires_at.unix_timestamp(),
        };
        let access_token = self
            .keys
            .encode(&claims)
            .map_err(|_| AuthError::DirectoryUnavailable)?;

        let refresh_token = generate_refresh_token();
        let refresh_expires_at = issued_at + self.refresh_ttl;
        self.directory
            .refresh_token_insert(uid, &hash_token(&refresh_token), refresh_expires_at)
            .await?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            access_expires_at,
            refresh_expires_at,
        })
    }

    /// The mandatory-TOTP gate (design §9/D-P2.5: "mandatory for T3+"),
    /// enforced identically for every path that reaches
    /// [`Self::issue_tokens`] (OBI-195 review fix 2).
    async fn enforce_totp_gate(
        &self,
        uid: &str,
        tier: i16,
        totp_secret: Option<&str>,
        totp_confirmed: bool,
        totp_code: Option<&str>,
    ) -> Result<(), AuthError> {
        if tier < MANDATORY_TOTP_TIER {
            return Ok(());
        }

        let Some(secret) = totp_secret.filter(|_| totp_confirmed) else {
            // T3+ with no confirmed secret: refused outright, not just
            // "code required" -- there is no code that would satisfy this.
            return Err(AuthError::TotpRequired);
        };

        let Some(code) = totp_code else {
            return Err(AuthError::TotpRequired);
        };

        self.verify_and_consume_totp(uid, secret, code).await
    }

    /// Verify `code` against `secret` and, only if it matches, atomically
    /// consume the RFC 6238 step it matched (OBI-195 review fix 4) so the
    /// same code can never be accepted twice -- whether replayed by an
    /// attacker or resubmitted by a confused client.
    async fn verify_and_consume_totp(
        &self,
        uid: &str,
        secret: &str,
        code: &str,
    ) -> Result<(), AuthError> {
        let Some(step) = totp::totp_step_for_code(secret, code) else {
            return Err(AuthError::TotpInvalid);
        };
        if self.directory.totp_consume_step(uid, step).await? {
            Ok(())
        } else {
            // RFC 6238-valid, but this step was already used.
            Err(AuthError::TotpInvalid)
        }
    }

    /// Append one audit row (M-AUTH-9), logging and swallowing any
    /// directory failure -- see [`StaffDirectory::record_audit`]'s doc
    /// comment for why this never propagates.
    async fn audit(
        &self,
        kind: &'static str,
        uid: Option<String>,
        ctx: &AuthContext,
        verdict: &'static str,
        detail: Option<String>,
    ) {
        let event = AuditEvent {
            kind,
            uid,
            ip: ctx.ip,
            user_agent: ctx.user_agent.clone(),
            verdict,
            detail,
        };
        if let Err(err) = self.directory.record_audit(event).await {
            warn!(?err, kind, "failed to record auth audit event");
        }
    }
}

/// A short, non-sensitive label for why a login's TOTP/tier gate refused
/// it, for the `auth.login.fail` audit row's `detail`.
fn totp_gate_detail(error: &AuthError) -> &'static str {
    match error {
        AuthError::TotpRequired => "totp_required",
        AuthError::TotpInvalid => "totp_invalid",
        AuthError::InvalidCredentials => "staff_row_missing",
        _ => "totp_gate_failed",
    }
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// A cryptographically random, URL-safe-ish opaque refresh token (32 bytes
/// of CSPRNG output, hex-encoded). Only its SHA-256 hash is ever persisted.
fn generate_refresh_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests;
