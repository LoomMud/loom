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
/// revoked" and both succeed, defeating reuse detection. Superseded by
/// [`SessionRotateOutcome`]/`session_rotate` (OBI-198, OBI-216): that path
/// is strictly more atomic, since it also carries `sid`/`amr`/`mfa_at`/
/// `expires_at` forward in the same statement and takes the owning
/// staff row's lock.

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

/// A failure from one of the admin (OBI-185) directory calls.
///
/// Unlike [`DirectoryError`], this one distinguishes "the
/// `security definer` function itself refused the call" (a real policy
/// decision -- self-promotion, actor tier too low, tier out of Phase-1
/// range, etc, M-ADM-1) from "the database connection failed" -- the
/// former is a `4xx` the admin UI should show the staff member, the
/// latter is a `503`. `Rejected`'s message is always the SQL function's
/// own `RAISE EXCEPTION` text, which is policy prose (same kind of thing
/// as the comment next to the `RAISE`), never a credential or a row's
/// contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminDirectoryError {
    Unavailable,
    Rejected(String),
}

/// One row read back from `audit_log` for the admin audit view (OBI-185,
/// M-ADM-4). Mirrors [`loom_persist::AuditLogEntry`] at the `loom-http`
/// boundary, same pattern as [`AuditEvent`]/[`loom_persist::AuditRow`] on
/// the write side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminAuditEntry {
    pub id: i64,
    pub at: OffsetDateTime,
    pub kind: String,
    pub caller: Option<String>,
    pub effective_principal: Option<String>,
    pub apply: Option<String>,
    pub class: Option<i16>,
    pub argument: Option<String>,
    pub guard_set: Vec<String>,
    pub verdict: String,
    pub detail: Option<String>,
}

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

    /// Admin role-tier change (OBI-185, M-ADM-1): goes through
    /// `roles_set_tier` and nothing else. `actor` MUST be the token's
    /// `sub`, never a caller-supplied value -- enforced by
    /// [`crate::auth::AuthService::admin_set_tier`], which is the only
    /// caller of this method. A SQL-level refusal (wrong actor tier,
    /// self-promotion, tier outside the Phase-1 1-3 range, ...) comes
    /// back as [`AdminDirectoryError::Rejected`], distinct from a plain
    /// connection failure, so the HTTP layer can answer a `4xx` instead
    /// of a `503`.
    async fn admin_set_tier(
        &self,
        actor: &str,
        target_uid: &str,
        new_tier: i16,
        reason: &str,
    ) -> Result<(), AdminDirectoryError>;

    /// Read back the most recent `audit_log` rows for the admin audit
    /// view (OBI-185, M-ADM-4), newest first.
    async fn admin_audit_recent(
        &self,
        limit: i64,
        before_id: Option<i64>,
    ) -> Result<Vec<AdminAuditEntry>, AdminDirectoryError>;
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

    async fn admin_set_tier(
        &self,
        actor: &str,
        target_uid: &str,
        new_tier: i16,
        reason: &str,
    ) -> Result<(), AdminDirectoryError> {
        loom_persist::Persist::roles_set_tier(self, actor, target_uid, new_tier, reason)
            .await
            .map_err(|err| AdminDirectoryError::Rejected(err.to_string()))
    }

    async fn admin_audit_recent(
        &self,
        limit: i64,
        before_id: Option<i64>,
    ) -> Result<Vec<AdminAuditEntry>, AdminDirectoryError> {
        loom_persist::Persist::audit_log_recent(self, limit, before_id)
            .await
            .map(|rows| {
                rows.into_iter()
                    .map(|row| AdminAuditEntry {
                        id: row.id,
                        at: row.at,
                        kind: row.kind,
                        caller: row.caller,
                        effective_principal: row.effective_principal,
                        apply: row.apply,
                        class: row.class,
                        argument: row.argument,
                        guard_set: row.guard_set,
                        verdict: row.verdict,
                        detail: row.detail,
                    })
                    .collect()
            })
            .map_err(|_| AdminDirectoryError::Unavailable)
    }
}
