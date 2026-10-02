// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The [`StaffDirectory`] trait: everything the auth layer needs from
//! persistence, abstracted so `loom-http`'s auth tests run against an
//! in-memory fake instead of a live Postgres (OBI-174). The production
//! implementation is `impl StaffDirectory for loom_persist::Persist` at
//! the bottom of this file.

use std::net::IpAddr;

use time::OffsetDateTime;

/// One `audit_log` row for an auth event (OBI-200, M-AUTH-9): `kind` is
/// one of `auth.login.ok`, `auth.login.fail`, `auth.refresh.reuse`,
/// `auth.totp.enrol`, `auth.totp.reset`, `auth.github.link`,
/// `auth.github.unlink`. `uid` is `None` only for a login attempt against
/// a username that never resolved to a staff row (so there is no uid to
/// attribute it to); the attempted username still lands in `detail`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub kind: &'static str,
    pub uid: Option<String>,
    pub ip: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub verdict: &'static str,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaffAuthRecord {
    pub uid: String,
    pub tier: i16,
    pub totp_secret: Option<String>,
    pub totp_confirmed: bool,
}

/// Fresh tier + TOTP enrolment state for a uid, re-read from Postgres at
/// every token issue/refresh/GitHub login (OBI-174) -- deliberately *not*
/// the same shape as [`StaffAuthRecord`] even though the fields overlap,
/// because this one is `Option`-wrapped at the call site
/// ([`StaffDirectory::auth_status_for`]): `None` means "no `staff` row",
/// which [`crate::auth::AuthService`] must refuse outright (OBI-195 review
/// fix 5) rather than fall back to a tier-0 token the way the old
/// `tier_of`-returns-0-for-missing-rows design did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaffAuthStatus {
    pub tier: i16,
    pub totp_secret: Option<String>,
    pub totp_confirmed: bool,
}

/// The outcome of atomically rotating a refresh token (OBI-195 review fix
/// 1): lookup-then-revoke used to be two statements, so two concurrent
/// requests presenting the same refresh token could both see "not yet
/// revoked" and both succeed, defeating reuse detection. A single
/// `UPDATE ... WHERE revoked_at IS NULL AND expires_at > NOW() RETURNING`
/// means at most one caller ever observes [`RefreshRotation::Rotated`] for
/// a given token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshRotation {
    /// This caller won the race (or there was no race): the old token is
    /// now revoked and a new pair should be issued for `staff_uid`, in the
    /// same token family -- `sid`/`amr`/`mfa_at` are the values carried
    /// forward from the row that was just rotated out (OBI-203).
    Rotated {
        staff_uid: String,
        sid: String,
        amr: Vec<String>,
        mfa_at: Option<OffsetDateTime>,
    },
    /// The token exists but was already revoked -- either rotated out by
    /// an earlier, legitimate `refresh` call, or explicitly logged out.
    /// Either way, a *second* presentation of it is either a lost race
    /// (benign, the caller should have used the new token) or a replayed
    /// stolen token (malicious) -- this service cannot tell those apart,
    /// so it treats every reuse as the latter and the caller must revoke
    /// the whole session family.
    Reused { staff_uid: String },
    /// The token exists, was never revoked, but its `expires_at` has
    /// passed -- plain expiry, not a reuse signal, so the caller refuses
    /// without killing other sessions.
    Expired,
    /// No row matches this hash at all.
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshRecord {
    pub staff_uid: String,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    /// The token-family id (OBI-203, M-AUTH-5): set at login, carried
    /// forward unchanged on every rotation of this family.
    pub sid: String,
    /// The authentication methods the *login* that started this family
    /// used -- carried forward unchanged across rotation.
    pub amr: Vec<String>,
    /// The most recent MFA completion at the time this family's login
    /// happened, if any -- carried forward unchanged across rotation (the
    /// M-ADM-2 step-up freshness window is always measured from this, not
    /// reset by a later refresh).
    pub mfa_at: Option<OffsetDateTime>,
}

/// Opaque directory failure: callers only ever see
/// [`crate::auth::AuthError::DirectoryUnavailable`] once this crosses the
/// `auth` module boundary (see `impl From<DirectoryError> for AuthError`),
/// so nothing here needs to carry a message a client could see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryError;

#[async_trait::async_trait]
pub trait StaffDirectory: Send + Sync {
    async fn staff_login(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<StaffAuthRecord>, DirectoryError>;

    /// Fresh tier + TOTP state for `uid`, `None` if it has no `staff` row
    /// (OBI-195 review fix 5). Always a fresh read; never cached by this
    /// trait's implementations. Replaces the old `tier_of`, which
    /// defaulted a missing row to tier 0 instead of refusing outright.
    async fn auth_status_for(&self, uid: &str) -> Result<Option<StaffAuthStatus>, DirectoryError>;

    /// Resolve `username` to its staff uid with no password check at all
    /// (OBI-204) -- used only to pick a rate-limiter key before the
    /// password is verified. `None` for a username that doesn't exist or
    /// isn't staff.
    async fn resolve_uid(&self, username: &str) -> Result<Option<String>, DirectoryError>;

    async fn totp_enroll(&self, uid: &str, secret_base32: &str) -> Result<(), DirectoryError>;
    async fn totp_confirm(&self, uid: &str) -> Result<(), DirectoryError>;
    /// The uid's currently enrolled secret, confirmed or not -- used by
    /// the TOTP-verify step, which needs to check a user-submitted code
    /// against the secret [`Self::totp_enroll`] just stored.
    async fn totp_secret_for(&self, uid: &str) -> Result<Option<String>, DirectoryError>;
    /// Anti-replay (OBI-195 review fix 4): atomically accept `step` only
    /// if it is strictly greater than the last step ever accepted for
    /// `uid`, recording it if so. `false` means the step was already used
    /// (same code submitted twice, or two requests racing on the same
    /// step) -- a code that is RFC 6238-valid but must still be refused.
    async fn totp_consume_step(&self, uid: &str, step: u64) -> Result<bool, DirectoryError>;

    async fn refresh_token_insert(
        &self,
        uid: &str,
        token_hash: &str,
        expires_at: OffsetDateTime,
        sid: &str,
        amr: &[String],
        mfa_at: Option<OffsetDateTime>,
    ) -> Result<(), DirectoryError>;
    async fn refresh_token_lookup(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshRecord>, DirectoryError>;
    /// Atomically rotate a refresh token (OBI-195 review fix 1): see
    /// [`RefreshRotation`]. Used by the hot `refresh` path instead of a
    /// separate lookup + revoke.
    async fn refresh_token_rotate(
        &self,
        token_hash: &str,
    ) -> Result<RefreshRotation, DirectoryError>;
    async fn refresh_token_revoke(&self, token_hash: &str) -> Result<(), DirectoryError>;
    async fn refresh_token_revoke_all(&self, uid: &str) -> Result<(), DirectoryError>;

    /// `None` means unlinked: GitHub login must refuse, never create staff.
    async fn github_lookup(&self, github_id: i64) -> Result<Option<String>, DirectoryError>;

    /// Append one `audit_log` row (OBI-200, M-AUTH-9). Best-effort from
    /// the caller's point of view -- a failure here must never stop a
    /// login/refresh/enrol from completing (losing an audit row is bad;
    /// refusing a legitimate staff member because Postgres hiccuped on an
    /// `INSERT` would be worse), so [`crate::auth::AuthService`] logs and
    /// swallows any `Err` from this instead of propagating it.
    async fn record_audit(&self, event: AuditEvent) -> Result<(), DirectoryError>;
}

#[async_trait::async_trait]
impl StaffDirectory for loom_persist::Persist {
    async fn staff_login(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<StaffAuthRecord>, DirectoryError> {
        let record = self
            .staff_login(username, password)
            .await
            .map_err(|_| DirectoryError)?;
        Ok(record.map(|r| StaffAuthRecord {
            uid: r.uid,
            tier: r.tier,
            totp_secret: r.totp_secret,
            totp_confirmed: r.totp_confirmed,
        }))
    }

    async fn auth_status_for(&self, uid: &str) -> Result<Option<StaffAuthStatus>, DirectoryError> {
        let status = loom_persist::Persist::staff_auth_status(self, uid)
            .await
            .map_err(|_| DirectoryError)?;
        Ok(status.map(|s| StaffAuthStatus {
            tier: s.tier,
            totp_secret: s.totp_secret,
            totp_confirmed: s.totp_confirmed,
        }))
    }

    async fn resolve_uid(&self, username: &str) -> Result<Option<String>, DirectoryError> {
        loom_persist::Persist::staff_uid_for_username(self, username)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn totp_consume_step(&self, uid: &str, step: u64) -> Result<bool, DirectoryError> {
        // `step` is a Unix-time-derived 30s counter; it will not reach
        // `i64::MAX` before the heat death of the universe, so this cast
        // never truncates in practice.
        loom_persist::Persist::totp_consume_step(self, uid, step as i64)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn refresh_token_rotate(
        &self,
        token_hash: &str,
    ) -> Result<RefreshRotation, DirectoryError> {
        let outcome = loom_persist::Persist::refresh_token_rotate(self, token_hash)
            .await
            .map_err(|_| DirectoryError)?;
        Ok(match outcome {
            loom_persist::RefreshTokenRotation::Rotated {
                staff_uid,
                sid,
                amr,
                mfa_at,
            } => RefreshRotation::Rotated {
                staff_uid,
                sid,
                amr,
                mfa_at,
            },
            loom_persist::RefreshTokenRotation::Reused { staff_uid } => {
                RefreshRotation::Reused { staff_uid }
            }
            loom_persist::RefreshTokenRotation::Expired => RefreshRotation::Expired,
            loom_persist::RefreshTokenRotation::NotFound => RefreshRotation::NotFound,
        })
    }

    async fn totp_enroll(&self, uid: &str, secret_base32: &str) -> Result<(), DirectoryError> {
        loom_persist::Persist::totp_enroll(self, uid, secret_base32)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn totp_confirm(&self, uid: &str) -> Result<(), DirectoryError> {
        loom_persist::Persist::totp_confirm(self, uid)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn totp_secret_for(&self, uid: &str) -> Result<Option<String>, DirectoryError> {
        loom_persist::Persist::totp_secret_for(self, uid)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn refresh_token_insert(
        &self,
        uid: &str,
        token_hash: &str,
        expires_at: OffsetDateTime,
        sid: &str,
        amr: &[String],
        mfa_at: Option<OffsetDateTime>,
    ) -> Result<(), DirectoryError> {
        loom_persist::Persist::refresh_token_insert(
            self, uid, token_hash, expires_at, sid, amr, mfa_at,
        )
        .await
        .map(|_| ())
        .map_err(|_| DirectoryError)
    }

    async fn refresh_token_lookup(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshRecord>, DirectoryError> {
        let record = loom_persist::Persist::refresh_token_lookup(self, token_hash)
            .await
            .map_err(|_| DirectoryError)?;
        Ok(record.map(|r| RefreshRecord {
            staff_uid: r.staff_uid,
            expires_at: r.expires_at,
            revoked_at: r.revoked_at,
            sid: r.sid,
            amr: r.amr,
            mfa_at: r.mfa_at,
        }))
    }

    async fn refresh_token_revoke(&self, token_hash: &str) -> Result<(), DirectoryError> {
        loom_persist::Persist::refresh_token_revoke(self, token_hash)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn refresh_token_revoke_all(&self, uid: &str) -> Result<(), DirectoryError> {
        loom_persist::Persist::refresh_token_revoke_all(self, uid)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn github_lookup(&self, github_id: i64) -> Result<Option<String>, DirectoryError> {
        loom_persist::Persist::github_lookup(self, github_id)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn record_audit(&self, event: AuditEvent) -> Result<(), DirectoryError> {
        let detail = serde_json::json!({
            "ip": event.ip.map(|ip| ip.to_string()),
            "user_agent": event.user_agent,
            "detail": event.detail,
        })
        .to_string();
        let row = loom_persist::AuditRow {
            at: time::OffsetDateTime::now_utc(),
            kind: event.kind.to_string(),
            caller: event.uid,
            effective_principal: None,
            apply: None,
            class: None,
            argument: None,
            guard_set: Vec::new(),
            verdict: event.verdict.to_string(),
            detail: Some(detail),
        };
        loom_persist::Persist::insert_audit_batch(self, std::slice::from_ref(&row))
            .await
            .map_err(|_| DirectoryError)
    }
}
