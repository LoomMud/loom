// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Staff web auth (OBI-174, design §9/D-P2.5): JWT access + refresh tokens,
//! TOTP enrolment/verification (mandatory for T3+), and an optional
//! GitHub-login path that only ever authenticates an *already-linked*
//! staff uid.
//!
//! ## The tier always comes from Postgres
//!
//! [`StaffDirectory::tier_of`] is the *only* source of truth for a staff
//! uid's tier. [`issue_tokens`] (both the password and GitHub login paths)
//! and [`refresh`] both call it fresh -- an access token's `tier`/`scopes`
//! claims are a snapshot taken at issue time, never a value the client (or
//! an upstream IdP) can set, and a promotion or demotion always takes
//! effect at the access token's next refresh, which can be forced by
//! revoking the caller's refresh tokens (see
//! [`StaffDirectory::refresh_token_revoke_all`]).
//!
//! ## TOTP is mandatory for T3+
//!
//! [`login`] refuses a tier-3-or-above staff member's password with
//! [`AuthError::TotpRequired`]/[`AuthError::EnrolmentRequired`] unless
//! their TOTP secret is both enrolled *and* confirmed (see
//! `staff.totp_confirmed_at` in migration 0003). There is no bypass: a
//! T3+ row with no confirmed secret cannot get a session, only enrol one
//! (via [`totp_enroll`]/[`totp_confirm`]) -- see "T3+ bootstrap
//! enrolment" below for how it reaches that endpoint in the first place.
//!
//! ## GitHub login never creates staff
//!
//! [`github_login`] looks up the numeric GitHub user id in
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
//!
//! ## TOTP at rest, recovery codes, step-up, and T3+ bootstrap (OBI-199)
//!
//! `staff.totp_secret_enc` is an XChaCha20-Poly1305 ciphertext blob
//! ([`crypto::TotpCipher`]), never a plaintext secret past this module's
//! own decrypt step (M-AUTH-8). Confirming a secret for the first time
//! issues [`RECOVERY_CODE_COUNT`] single-use recovery codes, which
//! [`login`] accepts as an alternate second factor. (Re-)enrolling always
//! requires the password again, and -- for a *reset* of an
//! already-confirmed secret specifically -- a valid code against the
//! current secret plus a fresh step-up ([`require_step_up`]).
//! [`AuthService::github_link`]/[`github_unlink`]/[`totp_admin_reset`]
//! are all step-up-gated the same way (M-ADM-2). A T3+ account with *no*
//! TOTP ever enrolled gets [`AuthError::EnrolmentRequired`] from
//! [`login`] instead of a dead-end refusal: a narrowly-scoped,
//! short-lived token (`aud: loom-staff-enrol`) usable only on
//! `/auth/totp/enroll`/`/auth/totp/verify`, since this account cannot
//! obtain an ordinary access token.

mod claims;
mod crypto;
mod directory;
mod github;
mod jwt;
pub mod ratelimit;
mod totp;

pub use claims::{ACCESS_AUDIENCE, AccessClaims, ENROL_AUDIENCE, scopes_for_tier};
pub use crypto::TotpCipher;
pub use directory::{AuditEvent, DirectoryError, RefreshRecord, StaffAuthRecord, StaffDirectory};
pub use github::{GithubAuthError, GithubIdentityProvider, GithubUser};
pub use jwt::{JwtKeys, TokenPair};
pub use ratelimit::{RateLimitDecision, RateLimiter};
pub use totp::{TotpEnrollment, generate_totp_secret, totp_for_secret, verify_totp_code};

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
/// The T3+ bootstrap enrolment-only credential (OBI-199, M-AUTH-3): usable
/// only on `/auth/totp/enroll`/`/auth/totp/verify`, nothing else.
pub const ENROL_TOKEN_TTL: Duration = Duration::from_secs(5 * 60);
/// Tiers at or above this one must have a confirmed TOTP secret to obtain a
/// session (design §9/D-P2.5: "mandatory for T3+").
pub const MANDATORY_TOTP_TIER: i16 = 3;
/// Step-up window (design threat-model-phase2.md §6.1 M-ADM-2): a
/// sensitive action (TOTP reset, GitHub link/unlink) needs `mfa_at` no
/// older than this.
pub const STEP_UP_WINDOW: Duration = Duration::from_secs(5 * 60);
/// How many single-use recovery codes are issued whenever a TOTP secret is
/// confirmed (M-AUTH-8: "Issue 10 single-use recovery codes").
pub const RECOVERY_CODE_COUNT: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// Bad username/password, or (for GitHub) an unlinked identity.
    InvalidCredentials,
    /// Correct password, but the account needs a TOTP code and none (or an
    /// incorrect one) was supplied.
    TotpRequired,
    /// Correct password and tier is below the mandatory-TOTP floor, but the
    /// account somehow has no *confirmed* TOTP secret even though one was
    /// supplied/expected -- surfaced separately from `TotpRequired` so
    /// callers can tell "you didn't send a code" apart from "your code was
    /// wrong".
    TotpInvalid,
    /// Correct password, tier >= [`MANDATORY_TOTP_TIER`], and *no* TOTP
    /// secret has ever been enrolled (not even unconfirmed): there is no
    /// code this caller could supply. Carries a narrowly-scoped,
    /// short-lived enrolment-only token (OBI-199) so the client can reach
    /// `/auth/totp/enroll` without an ordinary access token, which this
    /// account cannot obtain yet.
    EnrolmentRequired(String),
    /// A step-up-gated action (TOTP reset, GitHub link/unlink, ...) was
    /// attempted without a fresh (`mfa_at` within [`STEP_UP_WINDOW`])
    /// second-factor verification.
    StepUpRequired,
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
            AuthError::EnrolmentRequired(_) => "totp enrolment required",
            AuthError::StepUpRequired => "step-up verification required",
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

/// Everything [`login`]/[`refresh`]/[`github_login`] need: the staff
/// directory, the JWT signing keys, the TOTP-at-rest cipher, the rate
/// limiter, and the TTLs (fixed to the module constants above, exposed as
/// fields only so tests can shrink/replace them).
#[derive(Clone)]
pub struct AuthService {
    directory: Arc<dyn StaffDirectory>,
    keys: JwtKeys,
    totp_cipher: TotpCipher,
    access_ttl: Duration,
    refresh_ttl: Duration,
    rate_limiter: Arc<RateLimiter>,
}

impl AuthService {
    pub fn new(directory: Arc<dyn StaffDirectory>, keys: JwtKeys, totp_cipher: TotpCipher) -> Self {
        Self {
            directory,
            keys,
            totp_cipher,
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
    /// secret or against one of their unused recovery codes. A T3+ staff
    /// member with *no* TOTP ever enrolled gets
    /// [`AuthError::EnrolmentRequired`] instead, carrying a narrow
    /// bootstrap token for `/auth/totp/enroll` (OBI-199).
    ///
    /// Rate limiting (OBI-200, M-AUTH-1): checked *before* any
    /// credential work. A throttled IP gets [`AuthError::RateLimited`]. A
    /// locked account gets exactly [`AuthError::InvalidCredentials`] --
    /// the same response as a wrong password, so a client can never tell
    /// "this account is locked" from "that password is wrong" (which
    /// would otherwise leak account existence/activity). A wrong
    /// password or a wrong TOTP code both count as a failure toward the
    /// account lockout; a *missing* TOTP code or an enrolment bootstrap
    /// does not (neither is a guess). Every outcome is audited (M-AUTH-9).
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

        if let Err(err) = self.enforce_totp_gate(&record, totp_code).await {
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

        self.rate_limiter.record_success(username);
        let pair = self.issue_tokens(&record.uid).await?;
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
    /// TOTP is intentionally *not* re-checked here: linking a GitHub
    /// identity to a T3+ uid is itself a T4+, step-up-gated action
    /// (`auth_github_link`), so by the time a link exists an arch has
    /// already vouched for the account, and the mandatory-TOTP gate was
    /// already enforced the first time that uid logged in with a
    /// password. Revisiting this if GitHub login becomes the *primary*
    /// path for T3+ accounts is tracked in the OBI-174 PR description.
    pub async fn github_login(&self, github_id: i64) -> Result<TokenPair, AuthError> {
        let uid = self
            .directory
            .github_lookup(github_id)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;
        self.issue_tokens(&uid).await
    }

    /// Rotate a refresh token: the presented token must be unexpired and
    /// unrevoked, else [`AuthError::InvalidRefreshToken`]. On success the
    /// old token is revoked and a new (access, refresh) pair is issued,
    /// with `tier`/`scopes` read fresh from Postgres -- never carried over
    /// from whatever the old access token claimed.
    ///
    /// Presenting an *already-revoked* token (replay of a rotated-out
    /// token, i.e. a stolen refresh token) revokes every other outstanding
    /// token for that uid, not just the one presented, since by
    /// definition one of the two parties holding it is not the legitimate
    /// session. That replay is audited as `auth.refresh.reuse` (M-AUTH-9).
    pub async fn refresh(
        &self,
        refresh_token: &str,
        ctx: &AuthContext,
    ) -> Result<TokenPair, AuthError> {
        let token_hash = hash_token(refresh_token);
        let record = self
            .directory
            .refresh_token_lookup(&token_hash)
            .await?
            .ok_or(AuthError::InvalidRefreshToken)?;

        if record.revoked_at.is_some() {
            self.directory
                .refresh_token_revoke_all(&record.staff_uid)
                .await?;
            self.audit(
                "auth.refresh.reuse",
                Some(record.staff_uid.clone()),
                ctx,
                "deny",
                None,
            )
            .await;
            return Err(AuthError::InvalidRefreshToken);
        }
        if record.expires_at <= now() {
            return Err(AuthError::InvalidRefreshToken);
        }

        self.directory.refresh_token_revoke(&token_hash).await?;
        self.issue_tokens(&record.staff_uid).await
    }

    /// Revoke a single refresh token (logout).
    pub async fn logout(&self, refresh_token: &str) -> Result<(), AuthError> {
        let token_hash = hash_token(refresh_token);
        self.directory.refresh_token_revoke(&token_hash).await?;
        Ok(())
    }

    /// (Re-)enrol `uid`'s TOTP secret (OBI-199, M-AUTH-8: "Enrolment
    /// requires the password again plus one valid code before
    /// activation."). `password` must re-verify (password re-entry).
    ///
    /// If `uid` already has a *confirmed* secret, this is a reset, not a
    /// first enrolment: it additionally requires `existing_code` to verify
    /// against the *current* secret (proof the caller still controls the
    /// device being replaced) and a fresh step-up (`mfa_at` within
    /// [`STEP_UP_WINDOW`]) -- see [`Self::step_up`]. A first enrolment
    /// (no confirmed secret yet) requires neither, since there is nothing
    /// to prove continued possession of, and no prior MFA session to step
    /// up from -- that is exactly the T3+ bootstrap case this module's
    /// enrolment-only token exists for.
    ///
    /// Returns the enrolment payload (base32 secret + `otpauth://` URL)
    /// once; the caller must show it to the user now, since only its
    /// encrypted-at-rest state (never the plaintext) is ever retrievable
    /// again. Recovery codes are **not** issued here -- they are
    /// generated once the new secret is actually confirmed, by
    /// [`Self::totp_confirm`]. Audited as `auth.totp.enrol` for a first
    /// enrolment or `auth.totp.reset` for a reset (M-AUTH-9).
    pub async fn totp_enroll(
        &self,
        uid: &str,
        password: &str,
        existing_code: Option<&str>,
        ctx: &AuthContext,
    ) -> Result<totp::TotpEnrollment, AuthError> {
        if !self.directory.verify_password(uid, password).await? {
            return Err(AuthError::InvalidCredentials);
        }

        let is_reset = self.directory.totp_confirmed_for(uid).await?;
        if is_reset {
            self.require_step_up(uid).await?;
            let current_secret = self.current_confirmed_secret(uid).await?;
            let Some(code) = existing_code else {
                return Err(AuthError::TotpRequired);
            };
            match current_secret {
                Some(secret) if verify_totp_code(&secret, code) => {}
                _ => return Err(AuthError::TotpInvalid),
            }
        }

        let enrollment = totp::generate_totp_secret(uid);
        let ciphertext = self.totp_cipher.encrypt(uid, &enrollment.secret_base32);
        self.directory.totp_enroll(uid, &ciphertext).await?;
        let kind = if is_reset {
            "auth.totp.reset"
        } else {
            "auth.totp.enrol"
        };
        self.audit(kind, Some(uid.to_string()), ctx, "allow", None)
            .await;
        Ok(enrollment)
    }

    /// An admin (T4+, step-up-gated) clearing a *different* uid's TOTP
    /// enrolment entirely -- lost-device recovery (OBI-199, M-ADM-2:
    /// "TOTP reset ... (self and admin)"). `actor` must have its own
    /// fresh `mfa_at`; the directory re-checks this in SQL regardless.
    /// Audited as `auth.totp.reset` (M-AUTH-9).
    pub async fn totp_admin_reset(
        &self,
        actor: &str,
        uid: &str,
        reason: &str,
        ctx: &AuthContext,
    ) -> Result<(), AuthError> {
        self.require_step_up(actor).await?;
        self.directory.totp_admin_reset(actor, uid, reason).await?;
        self.audit(
            "auth.totp.reset",
            Some(uid.to_string()),
            ctx,
            "allow",
            Some(format!("admin reset by {actor}: {reason}")),
        )
        .await;
        Ok(())
    }

    /// Verify `code` against `uid`'s just-enrolled (or previously
    /// enrolled) secret and, on success, mark it confirmed and (if this is
    /// the first time this secret is confirmed) issue
    /// [`RECOVERY_CODE_COUNT`] single-use recovery codes -- the gate
    /// [`Self::login`] checks for T3+ staff. Also touches `mfa_at`: a
    /// successful confirmation is itself a fresh second-factor proof.
    /// TOTP attempts share the login rate limiter (M-AUTH-1): a wrong
    /// code counts as a failure against both the per-account and per-IP
    /// limits.
    pub async fn totp_confirm(
        &self,
        uid: &str,
        code: &str,
        ctx: &AuthContext,
    ) -> Result<Vec<String>, AuthError> {
        match self.rate_limiter.check(uid, ctx.ip) {
            RateLimitDecision::IpThrottled => return Err(AuthError::RateLimited),
            RateLimitDecision::AccountLocked => return Err(AuthError::TotpInvalid),
            RateLimitDecision::Allowed => {}
        }

        let ciphertext = self
            .directory
            .totp_secret_for(uid)
            .await?
            .ok_or(AuthError::TotpInvalid)?;
        let secret = self
            .totp_cipher
            .decrypt(uid, &ciphertext)
            .ok_or(AuthError::TotpInvalid)?;
        if !verify_totp_code(&secret, code) {
            self.rate_limiter.record_failure(uid);
            return Err(AuthError::TotpInvalid);
        }
        self.rate_limiter.record_success(uid);

        self.directory.totp_confirm(uid).await?;
        self.directory.mfa_touch(uid).await?;

        let (codes, hashes) = generate_recovery_codes();
        self.directory.recovery_codes_store(uid, &hashes).await?;
        Ok(codes)
    }

    /// Re-verify a TOTP or recovery code for an already-authenticated
    /// session (bearer token already presented and checked by the
    /// caller), refreshing `mfa_at` -- the "UI re-prompts for TOTP" step-up
    /// flow (design threat-model-phase2.md §6.1 M-ADM-2) that a client
    /// drives right before a step-up-gated action (TOTP reset, GitHub
    /// link/unlink, a role change).
    pub async fn step_up(&self, uid: &str, code: &str) -> Result<(), AuthError> {
        if self.verify_totp_or_recovery_code(uid, code).await? {
            self.directory.mfa_touch(uid).await?;
            Ok(())
        } else {
            Err(AuthError::TotpInvalid)
        }
    }

    /// Link a GitHub numeric user id to `uid` (T4+, step-up-gated:
    /// OBI-199, M-AUTH-7/M-ADM-2). `actor` must have its own fresh
    /// `mfa_at`; the directory re-checks tier and freshness in SQL
    /// regardless of this app-layer check. Auditing (`auth.github.link`)
    /// happens inside `loom-persist`'s `github_link` (OBI-200).
    pub async fn github_link(
        &self,
        actor: &str,
        uid: &str,
        github_id: i64,
        reason: &str,
    ) -> Result<(), AuthError> {
        self.require_step_up(actor).await?;
        self.directory
            .github_link(actor, uid, github_id, reason)
            .await?;
        Ok(())
    }

    /// Unlink `uid`'s GitHub identity (T4+, step-up-gated: OBI-199).
    /// Auditing (`auth.github.unlink`) happens inside `loom-persist`'s
    /// `github_unlink` (OBI-200).
    pub async fn github_unlink(
        &self,
        actor: &str,
        uid: &str,
        reason: &str,
    ) -> Result<(), AuthError> {
        self.require_step_up(actor).await?;
        self.directory.github_unlink(actor, uid, reason).await?;
        Ok(())
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

    /// Issue a fresh (access, refresh) pair for `uid`, reading its tier
    /// from Postgres right now. Shared by the password, GitHub, and
    /// refresh paths so there is exactly one place that turns a tier into
    /// scopes and mints tokens.
    async fn issue_tokens(&self, uid: &str) -> Result<TokenPair, AuthError> {
        let tier = self.directory.tier_of(uid).await?;
        let scopes = scopes_for_tier(tier);
        let issued_at = now();
        let access_expires_at = issued_at + self.access_ttl;
        let claims = AccessClaims {
            sub: uid.to_string(),
            aud: ACCESS_AUDIENCE.to_string(),
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

    async fn enforce_totp_gate(
        &self,
        record: &StaffAuthRecord,
        totp_code: Option<&str>,
    ) -> Result<(), AuthError> {
        if record.tier < MANDATORY_TOTP_TIER {
            return Ok(());
        }

        if !record.totp_confirmed || record.totp_secret_enc.is_none() {
            // T3+ with no confirmed secret: refused outright, not just
            // "code required" -- there is no code that would satisfy
            // this. Issue the narrow bootstrap enrolment token instead
            // (OBI-199) so the client can reach `/auth/totp/enroll`.
            let token = self.issue_enrolment_token(&record.uid)?;
            return Err(AuthError::EnrolmentRequired(token));
        }

        let Some(code) = totp_code else {
            return Err(AuthError::TotpRequired);
        };

        if self.verify_totp_or_recovery_code(&record.uid, code).await? {
            self.directory.mfa_touch(&record.uid).await?;
            Ok(())
        } else {
            Err(AuthError::TotpInvalid)
        }
    }

    /// Verify `code` against `uid`'s confirmed secret, falling back to an
    /// unused recovery code (consumed atomically) if the TOTP check fails.
    /// Used by both login and the explicit step-up re-verification.
    async fn verify_totp_or_recovery_code(&self, uid: &str, code: &str) -> Result<bool, AuthError> {
        if let Some(secret) = self.current_confirmed_secret(uid).await?
            && verify_totp_code(&secret, code)
        {
            return Ok(true);
        }
        Ok(self
            .directory
            .recovery_code_consume(uid, &hash_token(code))
            .await?)
    }

    /// `uid`'s current secret, decrypted. `None` for no secret or a
    /// ciphertext that fails to decrypt (wrong key/corrupt row -- treated
    /// the same as "no secret"). Callers that must distinguish a
    /// confirmed secret from a pending one (e.g. [`Self::totp_enroll`]'s
    /// reset check) call [`StaffDirectory::totp_confirmed_for`] first.
    async fn current_confirmed_secret(&self, uid: &str) -> Result<Option<String>, AuthError> {
        let Some(ciphertext) = self.directory.totp_secret_for(uid).await? else {
            return Ok(None);
        };
        Ok(self.totp_cipher.decrypt(uid, &ciphertext))
    }

    /// Require `uid`'s own `mfa_at` to be fresh (OBI-199, M-ADM-2); the
    /// directory/SQL layer re-checks this independently for every
    /// step-up-gated write, this is just the app-layer check that lets us
    /// return a distinct, friendly [`AuthError::StepUpRequired`] instead of
    /// a bare directory failure.
    async fn require_step_up(&self, uid: &str) -> Result<(), AuthError> {
        let mfa_at = self.directory.mfa_at_of(uid).await?;
        match mfa_at {
            Some(at) if now() - at <= time::Duration::try_from(STEP_UP_WINDOW).unwrap() => Ok(()),
            _ => Err(AuthError::StepUpRequired),
        }
    }

    /// Mint the T3+ bootstrap enrolment-only credential (OBI-199): `aud` =
    /// [`ENROL_AUDIENCE`], `tier`/`scopes` empty, TTL
    /// [`ENROL_TOKEN_TTL`] (~5 min). Usable only on `/auth/totp/enroll`
    /// and `/auth/totp/verify` -- see `claims::AccessClaims::is_enrolment_only`
    /// and the handlers that check it.
    fn issue_enrolment_token(&self, uid: &str) -> Result<String, AuthError> {
        let issued_at = now();
        let claims = AccessClaims {
            sub: uid.to_string(),
            aud: ENROL_AUDIENCE.to_string(),
            tier: 0,
            scopes: Vec::new(),
            iat: issued_at.unix_timestamp(),
            exp: (issued_at + ENROL_TOKEN_TTL).unix_timestamp(),
        };
        self.keys
            .encode(&claims)
            .map_err(|_| AuthError::DirectoryUnavailable)
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

/// A short, non-sensitive label for why `enforce_totp_gate` refused a
/// login, for the `auth.login.fail` audit row's `detail`.
fn totp_gate_detail(error: &AuthError) -> &'static str {
    match error {
        AuthError::TotpRequired => "totp_required",
        AuthError::TotpInvalid => "totp_invalid",
        AuthError::EnrolmentRequired(_) => "enrolment_required",
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

/// Generate [`RECOVERY_CODE_COUNT`] fresh single-use recovery codes
/// (M-AUTH-8): each one is 10 random bytes, hex-encoded and grouped for
/// readability -- plenty of entropy for a code a human copies down once
/// and uses at most once. Returns the plaintext codes (shown to the user
/// exactly once) alongside their SHA-256 hashes (the only form ever
/// persisted, same treatment as a refresh token).
fn generate_recovery_codes() -> (Vec<String>, Vec<String>) {
    let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut hashes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let mut bytes = [0u8; 10];
        rand::rng().fill_bytes(&mut bytes);
        let hex = hex_encode(&bytes);
        let code = format!("{}-{}", &hex[0..10], &hex[10..20]);
        hashes.push(hash_token(&code));
        codes.push(code);
    }
    (codes, hashes)
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
