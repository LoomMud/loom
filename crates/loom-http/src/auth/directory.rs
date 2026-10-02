// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The [`StaffDirectory`] trait: everything the auth layer needs from
//! persistence, abstracted so `loom-http`'s auth tests run against an
//! in-memory fake instead of a live Postgres (OBI-174). The production
//! implementation is `impl StaffDirectory for loom_persist::Persist` at
//! the bottom of this file.

use time::OffsetDateTime;

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
    ) -> Result<(), DirectoryError>;
    async fn refresh_token_lookup(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshRecord>, DirectoryError>;
    async fn refresh_token_revoke(&self, token_hash: &str) -> Result<(), DirectoryError>;
    async fn refresh_token_revoke_all(&self, uid: &str) -> Result<(), DirectoryError>;

    /// `None` means unlinked: GitHub login must refuse, never create staff.
    async fn github_lookup(&self, github_id: i64) -> Result<Option<String>, DirectoryError>;
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
}
