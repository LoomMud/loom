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
//! shared by the password, refresh, and GitHub login paths -- is always
//! fed a status read fresh just beforehand: an access token's
//! `tier`/`scopes` claims are a snapshot taken at issue time, never a
//! value the client (or an upstream IdP) can set, and a promotion or
//! demotion always takes effect at the access token's next refresh,
//! which can be forced by revoking the caller's refresh tokens (see
//! [`StaffDirectory::refresh_token_revoke_all`]). A uid with *no* `staff`
//! row at all (e.g. removed staff) is refused outright rather than minting
//! a tier-0 token (OBI-195 review fix 5).
//!
//! ## TOTP is mandatory for T3+, at issue and at refresh
//!
//! [`AuthService::login`]/[`AuthService::github_login`] refuse a
//! tier-3-or-above staff member's session with [`AuthError::TotpRequired`]
//! unless their TOTP secret is both enrolled *and* confirmed (see
//! `staff.totp_confirmed_at` in migration 0003) and a correct `totp_code`
//! is supplied (OBI-195 review fix 2: the first cut of this PR only gated
//! the password path, which meant a T3+ uid promoted after an earlier,
//! sub-T3 login could keep refreshing T3+ tokens forever, and GitHub login
//! skipped the gate entirely). There is no bypass: a T3+ row with no
//! confirmed secret cannot get a session, only enrol one (via
//! [`AuthService::totp_enroll`]/[`AuthService::totp_confirm`], which
//! themselves require a password login having already succeeded up to the
//! TOTP gate -- see `handlers.rs`). Every accepted code also consumes its
//! RFC 6238 time-step via [`StaffDirectory::totp_consume_step`], so the
//! same code can never be replayed even within the skew window (OBI-195
//! review fix 4).
//!
//! [`AuthService::refresh`] enforces the *same* mandatory-TOTP floor, but
//! against state rather than a fresh code (OBI-197/OBI-198 follow-up to
//! OBI-195 review fix 2): a cookie-only refresh cannot carry a TOTP code,
//! and step-up freshness is `mfa_at`'s job (M-ADM-2), not every refresh's.
//! A refresh for a T3+ uid is refused if there is no staff row, if TOTP
//! isn't confirmed, or if the token family's `amr` (fixed at login, never
//! recomputed by a refresh -- see [`Self::issue_tokens`]) doesn't contain
//! `"otp"`; any of those refusals revokes the whole family.
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
pub mod jwt;
pub mod ratelimit;
mod totp;

pub use claims::{AccessClaims, scopes_for_tier};
pub use directory::{
    AuditEvent, DirectoryError, RefreshRecord, RefreshRotation, StaffAuthRecord, StaffAuthStatus,
    StaffDirectory,
};
pub use github::{GithubAuthError, GithubIdentityProvider, GithubUser};
pub use jwt::{AUDIENCE, JwtKeys, TokenPair};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// Bad username/password, or (for GitHub) an unlinked identity, or a
    /// uid with no `staff` row at all (removed staff -- OBI-195 review
    /// fix 5).
    InvalidCredentials,
    /// Correct password, but the account needs a TOTP code and none (or an
    /// incorrect one) was supplied -- or, on refresh, the account's tier
    /// now requires TOTP and the session family never completed it.
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
    /// secret -- the only path, together with [`Self::github_login`],
    /// that gates on a *code*; [`Self::refresh`] gates on state instead
    /// (see the module docs).
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

        // Re-read tier/TOTP state fresh rather than trusting `record`,
        // which could in principle be a moment stale, and so that a
        // removed staff row (OBI-195 review fix 5) is refused here too.
        let status = match self.require_staff_status(&record.uid).await {
            Ok(status) => status,
            Err(err) => {
                self.audit(
                    "auth.login.fail",
                    Some(record.uid.clone()),
                    ctx,
                    "deny",
                    Some(totp_gate_detail(&err).to_string()),
                )
                .await;
                return Err(err);
            }
        };

        let totp_verified = match self
            .enforce_totp_gate_with_code(
                &record.uid,
                status.tier,
                status.totp_secret.as_deref(),
                status.totp_confirmed,
                totp_code,
            )
            .await
        {
            Ok(verified) => verified,
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
                return Err(err);
            }
        };
        let (amr, mfa_at) = if totp_verified {
            (vec!["pwd".to_string(), "otp".to_string()], Some(now()))
        } else {
            (vec!["pwd".to_string()], None)
        };

        self.rate_limiter.record_success(username);
        let pair = self
            .issue_tokens(&record.uid, status.tier, generate_sid(), amr, mfa_at)
            .await?;
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

    /// GitHub login (design §9): `github_id` is the numeric id the caller
    /// already obtained by exchanging an OAuth code and calling GitHub's
    /// `/user` endpoint (see [`GithubIdentityProvider`]) -- this function
    /// never talks to GitHub itself, it only resolves the link. An
    /// unlinked id is always refused; this never creates a staff row.
    ///
    /// `totp_code` is required for a T3+ uid exactly like the password
    /// path (OBI-195 review fix 2): linking a GitHub identity to a T3+ uid
    /// is itself a T4+ action (`auth_github_link`), but that only vouches
    /// for the *link*, not for a second factor on *this* login -- a GitHub
    /// account takeover must not bypass the mandatory-TOTP floor just
    /// because an arch linked it once.
    pub async fn github_login(
        &self,
        github_id: i64,
        totp_code: Option<&str>,
    ) -> Result<TokenPair, AuthError> {
        let uid = self
            .directory
            .github_lookup(github_id)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;
        let status = self.require_staff_status(&uid).await?;
        let totp_verified = self
            .enforce_totp_gate_with_code(
                &uid,
                status.tier,
                status.totp_secret.as_deref(),
                status.totp_confirmed,
                totp_code,
            )
            .await?;
        let (amr, mfa_at) = if totp_verified {
            (vec!["github".to_string(), "otp".to_string()], Some(now()))
        } else {
            (vec!["github".to_string()], None)
        };
        self.issue_tokens(&uid, status.tier, generate_sid(), amr, mfa_at)
            .await
    }

    /// Rotate a refresh token: the presented token must be unexpired and
    /// unrevoked, else [`AuthError::InvalidRefreshToken`]. On success the
    /// old token is revoked and a new (access, refresh) pair is issued in
    /// the *same session family* -- `sid`/`amr`/`mfa_at` are carried
    /// forward unchanged from the row the presented token rotated out of
    /// (OBI-203: `sid` stays the token-family id M-AUTH-5 reuse detection
    /// and family revocation are keyed off, and `amr`/`mfa_at` still
    /// describe the *original* login's authentication context, so the
    /// M-ADM-2 step-up freshness window is measured from the real
    /// authentication event, never reset by a later refresh) -- while
    /// `tier`/`scopes` are read fresh from Postgres, never carried over
    /// from whatever the old access token claimed.
    ///
    /// The mandatory-TOTP floor is enforced here too (OBI-195 review fix
    /// 2), but against *state*, not a fresh code (OBI-197/OBI-198
    /// follow-up): a cookie-only refresh has nowhere to carry a TOTP code,
    /// and the family's `amr` already records whether its login completed
    /// one. A refresh for a tier at or above [`MANDATORY_TOTP_TIER`] is
    /// refused -- revoking the whole family -- if there is no staff row,
    /// if TOTP isn't confirmed, or if `amr` doesn't contain `"otp"` (e.g.
    /// a T2 login later promoted to T3, which never had the chance to
    /// prove TOTP in the first place).
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
        ctx: &AuthContext,
    ) -> Result<TokenPair, AuthError> {
        let token_hash = hash_token(refresh_token);
        match self.directory.refresh_token_rotate(&token_hash).await? {
            RefreshRotation::Rotated {
                staff_uid,
                sid,
                amr,
                mfa_at,
            } => {
                let status = match self.require_staff_status(&staff_uid).await {
                    Ok(status) => status,
                    Err(err) => return Err(err),
                };
                if let Err(err) = self.enforce_totp_gate_for_refresh(status.tier, &amr) {
                    self.directory.refresh_token_revoke_all(&staff_uid).await?;
                    return Err(err);
                }
                self.issue_tokens(&staff_uid, status.tier, sid, amr, mfa_at)
                    .await
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
    /// [`Self::login`]/[`Self::github_login`] check for T3+ staff. Like
    /// every other TOTP check in this service, the matched step is
    /// consumed atomically (OBI-195 review fix 4): confirming with a code
    /// does not leave that code valid for a subsequent login. TOTP
    /// attempts share the login rate limiter (M-AUTH-1): a wrong code
    /// counts as a failure against both the per-account and per-IP
    /// limits.
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

    /// Read `uid`'s fresh tier/TOTP status, refusing outright (and
    /// dropping any sessions it might still hold) if it has no `staff`
    /// row at all (OBI-195 review fix 5): the old `tier_of`-based design
    /// defaulted a missing row to tier 0 and minted a token anyway.
    async fn require_staff_status(&self, uid: &str) -> Result<StaffAuthStatus, AuthError> {
        let Some(status) = self.directory.auth_status_for(uid).await? else {
            self.directory.refresh_token_revoke_all(uid).await?;
            return Err(AuthError::InvalidCredentials);
        };
        Ok(status)
    }

    /// Issue a fresh (access, refresh) pair for `uid` at `tier` (read
    /// fresh from Postgres by the caller just beforehand -- see
    /// [`Self::require_staff_status`]). Shared by the password, GitHub,
    /// and refresh paths so there is exactly one place that turns a tier
    /// into scopes and mints tokens. `sid` is the token-family id (fresh
    /// at login via [`generate_sid`]; carried forward unchanged on
    /// refresh -- see [`Self::refresh`]), and `amr`/`mfa_at` describe
    /// *the family's original* authentication context (D-TM3: identity,
    /// never authority).
    async fn issue_tokens(
        &self,
        uid: &str,
        tier: i16,
        sid: String,
        amr: Vec<String>,
        mfa_at: Option<OffsetDateTime>,
    ) -> Result<TokenPair, AuthError> {
        let scopes = scopes_for_tier(tier);
        let issued_at = now();
        let access_expires_at = issued_at + self.access_ttl;
        let claims = AccessClaims {
            sub: uid.to_string(),
            tier,
            scopes,
            iss: self.keys.issuer().to_string(),
            aud: self.keys.audience().to_string(),
            iat: issued_at.unix_timestamp(),
            nbf: issued_at.unix_timestamp(),
            exp: access_expires_at.unix_timestamp(),
            sid: sid.clone(),
            amr: amr.clone(),
            mfa_at: mfa_at.map(|t| t.unix_timestamp()),
        };
        let access_token = self
            .keys
            .encode(&claims)
            .map_err(|_| AuthError::DirectoryUnavailable)?;

        let refresh_token = generate_refresh_token();
        let refresh_expires_at = issued_at + self.refresh_ttl;
        self.directory
            .refresh_token_insert(
                uid,
                &hash_token(&refresh_token),
                refresh_expires_at,
                &sid,
                &amr,
                mfa_at,
            )
            .await?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            access_expires_at,
            refresh_expires_at,
        })
    }

    /// The mandatory-TOTP gate for [`Self::login`]/[`Self::github_login`]
    /// (design §9/D-P2.5: "mandatory for T3+"), enforced identically for
    /// both. Returns whether a TOTP code was presented and verified, so
    /// callers can set `amr`/`mfa_at` accordingly (M-AUTH-3's "record
    /// `amr` and `mfa_at`"). `Ok(false)` covers both "TOTP isn't mandatory
    /// for this uid and none was supplied" and -- deliberately -- is never
    /// reached for a mandatory-TOTP uid without a verified code, since
    /// those return `Err` instead.
    async fn enforce_totp_gate_with_code(
        &self,
        uid: &str,
        tier: i16,
        totp_secret: Option<&str>,
        totp_confirmed: bool,
        totp_code: Option<&str>,
    ) -> Result<bool, AuthError> {
        if tier < MANDATORY_TOTP_TIER {
            return Ok(false);
        }

        let Some(secret) = totp_secret.filter(|_| totp_confirmed) else {
            // T3+ with no confirmed secret: refused outright, not just
            // "code required" -- there is no code that would satisfy this.
            return Err(AuthError::TotpRequired);
        };

        let Some(code) = totp_code else {
            return Err(AuthError::TotpRequired);
        };

        self.verify_and_consume_totp(uid, secret, code).await?;
        Ok(true)
    }

    /// The mandatory-TOTP gate for [`Self::refresh`]: unlike the code-based
    /// gate above, this checks *state* -- tier, confirmation, and whether
    /// the session family's `amr` already contains `"otp"` -- since a
    /// cookie-only refresh has no code to present (see the module docs).
    fn enforce_totp_gate_for_refresh(&self, tier: i16, amr: &[String]) -> Result<(), AuthError> {
        if tier < MANDATORY_TOTP_TIER {
            return Ok(());
        }
        if !amr.iter().any(|m| m == "otp") {
            return Err(AuthError::TotpRequired);
        }
        Ok(())
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

/// A fresh token-family id (M-AUTH-4's `sid` claim): identity only, never
/// looked up or revoked by itself (M-AUTH-5's revocation is keyed off the
/// refresh token's hash) -- it exists so audit/log correlation
/// (M-AUTH-9) can tie an access token back to the session that minted it
/// without logging the token itself.
fn generate_sid() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    hex_encode(&bytes)
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
