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

/// Mirrors `loom_persist::SessionRotateOutcome` (OBI-198) -- kept as a
/// separate type so `loom-http`'s `auth` module never has to depend on
/// `loom_persist` types directly outside this file's `impl StaffDirectory
/// for loom_persist::Persist`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRotateOutcome {
    Rotated {
        staff_uid: String,
        sid: String,
        amr: Vec<String>,
        mfa_at: Option<OffsetDateTime>,
        expires_at: OffsetDateTime,
    },
    Reused {
        staff_uid: String,
    },
    Invalid,
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

    /// The *current* tier for `uid` (0 if it has no `staff` row). Always a
    /// fresh read; never cached by this trait's implementations.
    async fn tier_of(&self, uid: &str) -> Result<i16, DirectoryError>;

    async fn totp_enroll(&self, uid: &str, secret_base32: &str) -> Result<(), DirectoryError>;
    async fn totp_confirm(&self, uid: &str) -> Result<(), DirectoryError>;
    /// The uid's currently enrolled secret, confirmed or not -- used by
    /// the TOTP-verify step, which needs to check a user-submitted code
    /// against the secret [`Self::totp_enroll`] just stored.
    async fn totp_secret_for(&self, uid: &str) -> Result<Option<String>, DirectoryError>;

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
    async fn refresh_token_revoke(&self, token_hash: &str) -> Result<(), DirectoryError>;
    async fn refresh_token_revoke_all(&self, uid: &str) -> Result<(), DirectoryError>;

    /// Revoke every unrevoked session sharing `token_hash`'s family
    /// (OBI-198: logout revokes the family).
    async fn session_revoke_family_by_token(&self, token_hash: &str) -> Result<(), DirectoryError>;

    /// Atomically rotate the session for `old_token_hash` to
    /// `new_token_hash` (OBI-198 re-review, must-fix 1/2) -- see
    /// `loom_persist::Persist::session_rotate`.
    async fn session_rotate(
        &self,
        old_token_hash: &str,
        new_token_hash: &str,
        idle_cutoff: OffsetDateTime,
    ) -> Result<SessionRotateOutcome, DirectoryError>;

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

    async fn tier_of(&self, uid: &str) -> Result<i16, DirectoryError> {
        loom_persist::Persist::tier_of(self, uid)
            .await
            .map_err(|_| DirectoryError)
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

    async fn session_revoke_family_by_token(&self, token_hash: &str) -> Result<(), DirectoryError> {
        loom_persist::Persist::session_revoke_family_by_token(self, token_hash)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn session_rotate(
        &self,
        old_token_hash: &str,
        new_token_hash: &str,
        idle_cutoff: OffsetDateTime,
    ) -> Result<SessionRotateOutcome, DirectoryError> {
        let outcome = loom_persist::Persist::session_rotate(
            self,
            old_token_hash,
            new_token_hash,
            idle_cutoff,
        )
        .await
        .map_err(|_| DirectoryError)?;
        Ok(match outcome {
            loom_persist::SessionRotateOutcome::Rotated {
                staff_uid,
                sid,
                amr,
                mfa_at,
                expires_at,
            } => SessionRotateOutcome::Rotated {
                staff_uid,
                sid,
                amr,
                mfa_at,
                expires_at,
            },
            loom_persist::SessionRotateOutcome::Reused { staff_uid } => {
                SessionRotateOutcome::Reused { staff_uid }
            }
            loom_persist::SessionRotateOutcome::Invalid => SessionRotateOutcome::Invalid,
        })
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
