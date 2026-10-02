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
//! [`AuthError::TotpRequired`] unless their TOTP secret is both enrolled
//! *and* confirmed (see `staff.totp_confirmed_at` in migration 0003). There
//! is no bypass: a T3+ row with no confirmed secret cannot get a session,
//! only enrol one (via [`totp_enroll`]/[`totp_confirm`], which themselves
//! require a password login having already succeeded up to the TOTP gate --
//! see `handlers.rs`).
//!
//! ## GitHub login never creates staff
//!
//! [`github_login`] looks up the numeric GitHub user id in
//! `github_identities` (populated only by an arch/root through
//! `Persist::github_link`, T4+). An unlinked id is refused outright --
//! this module has no code path that inserts a `staff` row.

mod claims;
mod directory;
mod github;
mod jwt;
mod totp;

pub use claims::{AccessClaims, scopes_for_tier};
pub use directory::{DirectoryError, RefreshRecord, StaffAuthRecord, StaffDirectory};
pub use github::{GithubAuthError, GithubIdentityProvider, GithubUser};
pub use jwt::{JwtKeys, TokenPair};
pub use totp::{TotpEnrollment, generate_totp_secret, totp_for_secret, verify_totp_code};

use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

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
    /// The refresh token is unknown, expired, or already revoked.
    InvalidRefreshToken,
    /// The backing directory (Postgres) failed.
    DirectoryUnavailable,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AuthError::InvalidCredentials => "invalid credentials",
            AuthError::TotpRequired => "totp code required",
            AuthError::TotpInvalid => "totp code invalid",
            AuthError::InvalidRefreshToken => "invalid refresh token",
            AuthError::DirectoryUnavailable => "directory unavailable",
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
/// directory, the JWT signing keys, and the TTLs (fixed to the module
/// constants above, exposed as fields only so tests can shrink them).
#[derive(Clone)]
pub struct AuthService {
    directory: Arc<dyn StaffDirectory>,
    keys: JwtKeys,
    access_ttl: Duration,
    refresh_ttl: Duration,
}

impl AuthService {
    pub fn new(directory: Arc<dyn StaffDirectory>, keys: JwtKeys) -> Self {
        Self {
            directory,
            keys,
            access_ttl: ACCESS_TOKEN_TTL,
            refresh_ttl: REFRESH_TOKEN_TTL,
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

    /// Username/password login (design §9). Refuses with
    /// [`AuthError::TotpRequired`]/[`AuthError::TotpInvalid`] for a T3+
    /// staff member unless `totp_code` verifies against their confirmed
    /// secret.
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        totp_code: Option<&str>,
    ) -> Result<TokenPair, AuthError> {
        let record = self
            .directory
            .staff_login(username, password)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        self.enforce_totp_gate(&record, totp_code)?;
        self.issue_tokens(&record.uid).await
    }

    /// GitHub login (design §9): `github_id` is the numeric id the caller
    /// already obtained by exchanging an OAuth code and calling GitHub's
    /// `/user` endpoint (see [`GithubIdentityProvider`]) -- this function
    /// never talks to GitHub itself, it only resolves the link. An
    /// unlinked id is always refused; this never creates a staff row.
    ///
    /// TOTP is intentionally *not* re-checked here: linking a GitHub
    /// identity to a T3+ uid is itself a T4+ action (`auth_github_link`),
    /// so by the time a link exists an arch has already vouched for the
    /// account, and the mandatory-TOTP gate was already enforced the first
    /// time that uid logged in with a password. Revisiting this if GitHub
    /// login becomes the *primary* path for T3+ accounts is tracked in the
    /// OBI-174 PR description.
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
    /// session.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenPair, AuthError> {
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

    /// Generate and store a fresh TOTP secret for `uid` (self-service --
    /// the directory re-checks actor == uid in SQL). Returns the
    /// enrolment payload (base32 secret + `otpauth://` URL) once; the
    /// caller must show it to the user now, since only its hash-adjacent
    /// state (not the plaintext) is ever returned again.
    pub async fn totp_enroll(&self, uid: &str) -> Result<totp::TotpEnrollment, AuthError> {
        let enrollment = totp::generate_totp_secret(uid);
        self.directory
            .totp_enroll(uid, &enrollment.secret_base32)
            .await?;
        Ok(enrollment)
    }

    /// Verify `code` against `uid`'s just-enrolled (or previously
    /// enrolled) secret and, on success, mark it confirmed -- the gate
    /// [`Self::login`] checks for T3+ staff.
    pub async fn totp_confirm(&self, uid: &str, code: &str) -> Result<(), AuthError> {
        let secret = self
            .directory
            .totp_secret_for(uid)
            .await?
            .ok_or(AuthError::TotpInvalid)?;
        if totp::verify_totp_code(&secret, code) {
            self.directory.totp_confirm(uid).await?;
            Ok(())
        } else {
            Err(AuthError::TotpInvalid)
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

    fn enforce_totp_gate(
        &self,
        record: &StaffAuthRecord,
        totp_code: Option<&str>,
    ) -> Result<(), AuthError> {
        if record.tier < MANDATORY_TOTP_TIER {
            return Ok(());
        }

        let Some(secret) = record
            .totp_secret
            .as_deref()
            .filter(|_| record.totp_confirmed)
        else {
            // T3+ with no confirmed secret: refused outright, not just
            // "code required" -- there is no code that would satisfy this.
            return Err(AuthError::TotpRequired);
        };

        let Some(code) = totp_code else {
            return Err(AuthError::TotpRequired);
        };

        if verify_totp_code(secret, code) {
            Ok(())
        } else {
            Err(AuthError::TotpInvalid)
        }
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
