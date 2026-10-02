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
    /// XChaCha20-Poly1305 ciphertext blob (OBI-199, M-AUTH-8) -- never a
    /// plaintext secret past `loom-http`'s own decrypt step.
    pub totp_secret_enc: Option<Vec<u8>>,
    pub totp_confirmed: bool,
    /// Last successful second-factor verification (OBI-199): step-up-gated
    /// actions require this to be no more than 5 minutes old.
    pub mfa_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshRecord {
    pub staff_uid: String,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
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

    /// Verify `uid`'s account password directly (OBI-199: the password
    /// re-entry step for TOTP (re-)enrolment, where the caller already
    /// has a bearer-authenticated `uid` rather than a username).
    async fn verify_password(&self, uid: &str, password: &str) -> Result<bool, DirectoryError>;

    /// The *current* tier for `uid` (0 if it has no `staff` row). Always a
    /// fresh read; never cached by this trait's implementations.
    async fn tier_of(&self, uid: &str) -> Result<i16, DirectoryError>;

    async fn totp_enroll(&self, uid: &str, secret_ciphertext: &[u8]) -> Result<(), DirectoryError>;
    async fn totp_confirm(&self, uid: &str) -> Result<(), DirectoryError>;
    /// The uid's currently enrolled secret ciphertext, confirmed or not --
    /// used by the TOTP-verify step, which needs to decrypt and check a
    /// user-submitted code against the secret [`Self::totp_enroll`] just
    /// stored.
    async fn totp_secret_for(&self, uid: &str) -> Result<Option<Vec<u8>>, DirectoryError>;
    /// Whether `uid` has a *confirmed* TOTP secret right now, distinct
    /// from merely having a pending/unconfirmed one (OBI-199).
    async fn totp_confirmed_for(&self, uid: &str) -> Result<bool, DirectoryError>;
    /// An admin (T4+, step-up-gated) clearing a *different* uid's TOTP
    /// enrolment entirely (lost-device recovery). The target's next login
    /// goes through the T3+ bootstrap enrolment path again.
    async fn totp_admin_reset(
        &self,
        actor: &str,
        uid: &str,
        reason: &str,
    ) -> Result<(), DirectoryError>;

    /// Touch `uid`'s `mfa_at` to now (self-service): called right after a
    /// login or step-up re-verification accepts a TOTP/recovery code.
    async fn mfa_touch(&self, uid: &str) -> Result<(), DirectoryError>;
    /// `uid`'s current `mfa_at`, for an app-layer step-up freshness check.
    async fn mfa_at_of(&self, uid: &str) -> Result<Option<OffsetDateTime>, DirectoryError>;

    /// Replace `uid`'s full set of recovery-code hashes (self-service).
    async fn recovery_codes_store(
        &self,
        uid: &str,
        code_hashes: &[String],
    ) -> Result<(), DirectoryError>;
    /// Atomically claim a single-use recovery code by its SHA-256 hash.
    /// `true` iff this call is the one that claimed it.
    async fn recovery_code_consume(
        &self,
        uid: &str,
        code_hash: &str,
    ) -> Result<bool, DirectoryError>;

    async fn refresh_token_insert(
        &self,
        uid: &str,
        token_hash: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), DirectoryError>;
    async fn refresh_token_lookup(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshRecord>, DirectoryError>;
    async fn refresh_token_revoke(&self, token_hash: &str) -> Result<(), DirectoryError>;
    async fn refresh_token_revoke_all(&self, uid: &str) -> Result<(), DirectoryError>;

    /// `None` means unlinked: GitHub login must refuse, never create staff.
    async fn github_lookup(&self, github_id: i64) -> Result<Option<String>, DirectoryError>;
    /// Link a GitHub numeric user id to `uid` (T4+, step-up-gated).
    async fn github_link(
        &self,
        actor: &str,
        uid: &str,
        github_id: i64,
        reason: &str,
    ) -> Result<(), DirectoryError>;
    /// Unlink `uid`'s GitHub identity (T4+, step-up-gated).
    async fn github_unlink(
        &self,
        actor: &str,
        uid: &str,
        reason: &str,
    ) -> Result<(), DirectoryError>;

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
            totp_secret_enc: r.totp_secret_enc,
            totp_confirmed: r.totp_confirmed,
            mfa_at: r.mfa_at,
        }))
    }

    async fn verify_password(&self, uid: &str, password: &str) -> Result<bool, DirectoryError> {
        loom_persist::Persist::verify_password_for_uid(self, uid, password)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn tier_of(&self, uid: &str) -> Result<i16, DirectoryError> {
        loom_persist::Persist::tier_of(self, uid)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn totp_enroll(&self, uid: &str, secret_ciphertext: &[u8]) -> Result<(), DirectoryError> {
        loom_persist::Persist::totp_enroll(self, uid, secret_ciphertext)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn totp_confirm(&self, uid: &str) -> Result<(), DirectoryError> {
        loom_persist::Persist::totp_confirm(self, uid)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn totp_secret_for(&self, uid: &str) -> Result<Option<Vec<u8>>, DirectoryError> {
        loom_persist::Persist::totp_secret_for(self, uid)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn totp_confirmed_for(&self, uid: &str) -> Result<bool, DirectoryError> {
        loom_persist::Persist::totp_confirmed_for(self, uid)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn totp_admin_reset(
        &self,
        actor: &str,
        uid: &str,
        reason: &str,
    ) -> Result<(), DirectoryError> {
        loom_persist::Persist::totp_admin_reset(self, actor, uid, reason)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn mfa_touch(&self, uid: &str) -> Result<(), DirectoryError> {
        loom_persist::Persist::mfa_touch(self, uid)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn mfa_at_of(&self, uid: &str) -> Result<Option<OffsetDateTime>, DirectoryError> {
        loom_persist::Persist::mfa_at_of(self, uid)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn recovery_codes_store(
        &self,
        uid: &str,
        code_hashes: &[String],
    ) -> Result<(), DirectoryError> {
        loom_persist::Persist::recovery_codes_store(self, uid, code_hashes)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn recovery_code_consume(
        &self,
        uid: &str,
        code_hash: &str,
    ) -> Result<bool, DirectoryError> {
        loom_persist::Persist::recovery_code_consume(self, uid, code_hash)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn refresh_token_insert(
        &self,
        uid: &str,
        token_hash: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), DirectoryError> {
        loom_persist::Persist::refresh_token_insert(self, uid, token_hash, expires_at)
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

    async fn github_link(
        &self,
        actor: &str,
        uid: &str,
        github_id: i64,
        reason: &str,
    ) -> Result<(), DirectoryError> {
        loom_persist::Persist::github_link(self, actor, uid, github_id, reason)
            .await
            .map_err(|_| DirectoryError)
    }

    async fn github_unlink(
        &self,
        actor: &str,
        uid: &str,
        reason: &str,
    ) -> Result<(), DirectoryError> {
        loom_persist::Persist::github_unlink(self, actor, uid, reason)
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
