// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Postgres-backed persistence for accounts, roles, and object state.
//!
//! Password hashes use Argon2id (`m=19MiB, t=2, p=1`) to balance interactive
//! login latency with offline cracking resistance for Phase 1.
//!
//! ## Two logins (D-27.4)
//!
//! Migrations run through [`run_migrations`] against `LOOM_DB_MIGRATE_URL`,
//! which must authenticate as `loom_owner` -- the login that owns every
//! table and `security definer` function. [`Persist::connect`] is the
//! world-runtime login (`loom_app`), which is not an owner and has no
//! insert/update/delete on the role tables; see `migrations/0001_init.sql`
//! for the exact grants.
//!
//! ## Roles are security-definer only (design §5.11.3)
//!
//! The role-management functions on [`Persist`] (`roles_set_tier`,
//! `roles_set_member`, `roles_grant`, `roles_revoke_grant`) all take an
//! `actor` argument. **`actor` must be the effective principal computed by
//! the driver's stack-based least-privilege check (OBI-35), never a string
//! taken from mudlib/Weft code.** Each call re-runs the §5.11.2
//! promotion-rights check inside the database, in the same transaction as
//! the write, so even a compromised `/secure/roles` object cannot escalate
//! past what the actor's *recorded* tier allows -- but that check is only as
//! trustworthy as the `actor` the driver passes in.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use serde_json::Value;
use sqlx::QueryBuilder;
use sqlx::postgres::{PgListener, PgPool, PgPoolOptions};
use std::collections::HashMap;
use std::sync::Mutex;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tracing::warn;
use uuid::Uuid;

const ARGON_M_COST_KIB: u32 = 19 * 1024;
const ARGON_T_COST: u32 = 2;
const ARGON_P_COST: u32 = 1;
/// Never a real credential -- only ever hashed once (at [`Persist::from_pool`])
/// and verified against for its CPU cost (OBI-200, M-AUTH-2).
const DUMMY_PASSWORD: &str = "loom-dummy-verify-constant-time-padding";

pub type Result<T> = std::result::Result<T, PersistError>;

#[derive(Debug, Error)]
pub enum PersistError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("password hash error: {0}")]
    PasswordHash(String),
    #[error("invalid argon2 parameters")]
    ArgonParams,
    /// OBI-151: `assert_not_control_plane_db` rejected a connection string
    /// that looks like Paperclip's control-plane DB.
    #[error("{0}")]
    ControlPlaneDbRejected(String),
}

#[derive(Debug, Clone)]
pub struct Persist {
    pool: PgPool,
    argon2: Argon2<'static>,
    /// A precomputed Argon2id hash of a fixed, never-used password,
    /// verified against on every lookup of an unknown account/staff
    /// username (OBI-200, M-AUTH-2). Running a real Argon2 verify against
    /// *some* hash for a nonexistent user spends the same CPU time a real
    /// user's wrong-password attempt would, so response timing never
    /// reveals whether a username exists.
    dummy_password_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub id: Uuid,
    pub username: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ObjectState {
    pub object_path: String,
    pub key: String,
    pub program_path: String,
    pub program_version: i64,
    pub schema_hash: String,
    pub state: Value,
}

/// A named grant kind (design §5.11.2 / §5.11.3 `grants` table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantKind {
    Efun,
    DbQuery,
    Path,
}

impl GrantKind {
    fn as_sql(self) -> &'static str {
        match self {
            GrantKind::Efun => "efun",
            GrantKind::DbQuery => "db_query",
            GrantKind::Path => "path",
        }
    }

    /// Parse the wire-format string a [`DbRequest::RolesGrant`]/
    /// [`DbRequest::RolesRevokeGrant`] carries (the same strings
    /// `RolesSnapshot`'s `kind` field and the SQL functions use).
    /// `None` for anything else -- the DB worker answers `"invalid_kind"`
    /// rather than ever sending an unrecognised string to Postgres.
    fn parse(s: &str) -> Option<GrantKind> {
        match s {
            "efun" => Some(GrantKind::Efun),
            "db_query" => Some(GrantKind::DbQuery),
            "path" => Some(GrantKind::Path),
            _ => None,
        }
    }
}

/// Plain-data rows loaded by [`Persist::load_roles_snapshot`]. Deliberately
/// has no `loom-vm` dependency: `loom-vm` builds its own `RolesSnapshot`
/// from these rows (OBI-120/S2b).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaffRow {
    pub uid: String,
    pub account_id: Uuid,
    pub tier: i16,
    pub totp_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRow {
    pub name: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainMemberRow {
    pub domain: String,
    pub uid: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierPolicyRow {
    pub tier: i16,
    pub max_ticks_exec: Option<i32>,
    pub max_mem_exec_mb: Option<i32>,
    pub tick_share_per_min: Option<i64>,
    pub max_objects: Option<i32>,
    pub max_heartbeats: Option<i32>,
    pub max_callouts_obj: Option<i32>,
    pub max_callouts_uid: Option<i32>,
    pub disk_quota_mb: Option<i32>,
    pub efun_classes: Vec<i16>,
}

/// A staff row resolved by username/password for the web auth layer
/// (OBI-174, design §9/D-P2.5): the staff uid, its current tier, and
/// whatever TOTP state it has (both read fresh from Postgres -- the tier
/// here is never cached past the single query that produced it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaffAuthRecord {
    pub uid: String,
    pub account_id: Uuid,
    pub tier: i16,
    pub totp_secret: Option<String>,
    pub totp_confirmed: bool,
}

/// A `refresh_tokens` row (OBI-174, `sid`/`amr`/`mfa_at` added OBI-203).
/// Only ever looked up by [`Persist::refresh_token_lookup`]'s SHA-256 hash
/// of the bearer token -- the plaintext token itself is never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshTokenRecord {
    pub id: Uuid,
    pub staff_uid: String,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    /// The token-family id established at login and carried forward on
    /// every rotation of this family (OBI-203, M-AUTH-5): the key reuse
    /// detection and family revocation are keyed off.
    pub sid: String,
    /// The authentication methods that produced the *login* that started
    /// this family -- carried forward unchanged across rotation (OBI-203).
    pub amr: Vec<String>,
    /// The most recent MFA completion at the time this family's login
    /// happened, if any -- carried forward unchanged across rotation so
    /// the M-ADM-2 step-up freshness window is measured from the original
    /// authentication, not reset by every refresh.
    pub mfa_at: Option<OffsetDateTime>,
}

/// The outcome of [`Persist::session_rotate`] (OBI-198 re-review,
/// must-fix 1 and 2): a single atomic consume-and-insert, so two
/// concurrent rotations of the same token can never both win, and the
/// new row always inherits the consumed row's `expires_at`/`sid`/`amr`/
/// `mfa_at` rather than recomputing any of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRotateOutcome {
    /// The old token was unrevoked, within its absolute expiry, and
    /// within its idle window: it is now revoked and a fresh row exists
    /// under `new_token_hash`, same family (`sid`), same `amr`/`mfa_at`,
    /// same `expires_at`.
    Rotated {
        staff_uid: String,
        sid: String,
        amr: Vec<String>,
        mfa_at: Option<OffsetDateTime>,
        expires_at: OffsetDateTime,
    },
    /// The old token was already revoked (a rotated-out or previously-
    /// revoked token replayed) -- this is what a stolen refresh token
    /// looks like, so the whole family (every row sharing its `sid`) is
    /// now revoked too.
    Reused { staff_uid: String },
    /// Unknown token hash, or a known one past its absolute/idle expiry
    /// (not revoked, just stale -- no family-wide response needed).
    Invalid,
}

/// A row from the `active_grants` view (already excludes expired grants).
#[derive(Debug, Clone, PartialEq)]
pub struct GrantRow {
    pub uid: String,
    pub kind: String,
    pub target: String,
    pub granted_by: String,
    pub expires_at: OffsetDateTime,
}

/// The full roles snapshot (design §1/D-S2.1): staff, domains, domain
/// membership, tier policy, and every currently-unexpired grant, plus the
/// earliest grant expiry so the driver can arm a refresh timer for it.
#[derive(Debug, Clone, PartialEq)]
pub struct RolesRows {
    pub staff: Vec<StaffRow>,
    pub domains: Vec<DomainRow>,
    pub domain_members: Vec<DomainMemberRow>,
    pub tier_policy: Vec<TierPolicyRow>,
    pub active_grants: Vec<GrantRow>,
    pub earliest_grant_expiry: Option<OffsetDateTime>,
}

/// One row for [`Persist::insert_audit_batch`] (design §5/D-S2.5): the
/// Postgres sink for the driver's in-memory audit ring.
#[derive(Debug, Clone)]
pub struct AuditRow {
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

#[derive(Debug)]
pub enum DbRequest {
    Sleep {
        correlation_id: u64,
        duration_ms: u64,
    },
    /// `account_create()` (spec, OBI-85): create a new account. Answered
    /// with [`DbEvent::AccountResult`] (`detail` is the new account's uuid
    /// on success, or `"exists"`/`"unavailable"` on failure -- the driver
    /// validates `name`/`password` shape itself before ever building one of
    /// these, so `"invalid"` never comes from here).
    CreateAccount {
        correlation_id: u64,
        username: String,
        password: Password,
    },
    /// `account_login()`: verify a login. Answered with
    /// [`DbEvent::AccountResult`] (`detail` is the account's uuid on
    /// success, or `"bad_credentials"`/`"unavailable"` on failure).
    VerifyLogin {
        correlation_id: u64,
        username: String,
        password: Password,
    },
    /// `roles_set_tier()` (OBI-36 D-S2.2/OBI-123): `actor` is the
    /// driver-computed actor-rule euid (see module docs), never a Weft
    /// string. Answered with [`DbEvent::RolesResult`] (`detail` is
    /// `"ok"` on success, else the Postgres function's `RAISE EXCEPTION`
    /// message, or `"invalid_tier"`/`"unavailable"`).
    RolesSetTier {
        correlation_id: u64,
        actor: String,
        target: String,
        tier: i64,
        reason: String,
    },
    /// `roles_set_member()`. `role` is `"member"`, `"lead"`, or `"none"`
    /// to remove the membership (the SQL function's own convention, so no
    /// conversion happens here).
    RolesSetMember {
        correlation_id: u64,
        actor: String,
        domain: String,
        target: String,
        role: String,
        reason: String,
    },
    /// `roles_grant()`. `expires_at` is Unix seconds; `None` answers
    /// `"expires_at_required"` without a round trip (the SQL column is
    /// `NOT NULL`).
    RolesGrant {
        correlation_id: u64,
        actor: String,
        target: String,
        kind: String,
        what: String,
        expires_at: Option<i64>,
        reason: String,
    },
    /// `roles_revoke_grant()`.
    RolesRevokeGrant {
        correlation_id: u64,
        actor: String,
        target: String,
        kind: String,
        what: String,
        reason: String,
    },
    /// `roles_propose_tier()`: `detail` is the new proposal's id (as a
    /// decimal string) on success.
    RolesProposeTier {
        correlation_id: u64,
        actor: String,
        target: String,
        tier: i64,
        reason: String,
    },
    /// `roles_approve_proposal()`.
    RolesApprove {
        correlation_id: u64,
        actor: String,
        proposal_id: i64,
    },
}

#[derive(Debug)]
pub enum DbEvent {
    SleepDone {
        correlation_id: u64,
    },
    QueryFailed {
        correlation_id: u64,
        message: String,
    },
    /// The answer to a [`DbRequest::CreateAccount`]/[`DbRequest::VerifyLogin`].
    AccountResult {
        correlation_id: u64,
        ok: bool,
        detail: String,
    },
    /// The answer to any `DbRequest::Roles*` request (OBI-123).
    RolesResult {
        correlation_id: u64,
        ok: bool,
        detail: String,
    },
}

/// A password in transit to/from the DB worker. The only way to read the
/// contents back out is [`Password::expose`] -- everything else
/// (`Debug`, and therefore anything that formats a [`DbRequest`] whole,
/// including tracing/log/error-report call sites and any future field
/// added to `DbRequest`) redacts it, per spec ("the password must never
/// appear in tracing spans, logs, the privilege `AuditEntry`, error
/// reports, or `Debug` output of `DbRequest`").
pub struct Password(String);

impl Password {
    pub fn new(s: impl Into<String>) -> Password {
        Password(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

/// Reject connection strings that look like they point at Paperclip's
/// control-plane Postgres instead of a disposable/dedicated one (OBI-151).
///
/// Agent shells export `DATABASE_URL` for Paperclip's own control-plane DB
/// (see OBI-150); nothing in loom/warp may ever open a connection to it.
/// This is a defense-in-depth belt, not the primary guardrail -- the
/// primary guardrail is that test/dev entrypoints must not read the
/// ambient `DATABASE_URL` at all (see `LOOM_TEST_DATABASE_URL`,
/// `LOOM_TEST_DB_MIGRATE_URL`, `LOOM_SMOKE_DATABASE_URL` and
/// `scripts/with-disposable-postgres.sh`). This check only catches the
/// two concrete shapes the control-plane DSN is known to take; it is not a
/// general allow-list and must not be treated as one.
pub fn assert_not_control_plane_db(url: &str) -> std::result::Result<(), String> {
    // Deliberately not pulling in a URL-parsing crate for this: a crude
    // split is enough to pull the host:port and database name out of a
    // `postgres://user:pass@host:port/dbname?query` DSN.
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let after_at = after_scheme.rsplit('@').next().unwrap_or(after_scheme);
    let mut path_split = after_at.splitn(2, '/');
    let host_port = path_split.next().unwrap_or("");
    let db_name = path_split
        .next()
        .unwrap_or("")
        .split(['?', '#'])
        .next()
        .unwrap_or("");

    if host_port.eq_ignore_ascii_case("postgres:5432") {
        return Err(format!(
            "refusing to connect to {host_port:?}: this looks like Paperclip's \
             control-plane Postgres host, not a disposable/dedicated loom DB \
             (OBI-151/OBI-150). Use scripts/with-disposable-postgres.sh, or point \
             LOOM_TEST_DATABASE_URL/LOOM_TEST_DB_MIGRATE_URL/LOOM_SMOKE_DATABASE_URL \
             at a DB you own instead."
        ));
    }
    if db_name.eq_ignore_ascii_case("paperclip") {
        return Err(format!(
            "refusing to connect to database {db_name:?}: this looks like Paperclip's \
             control-plane database, not a disposable/dedicated loom DB \
             (OBI-151/OBI-150). Use scripts/with-disposable-postgres.sh, or point \
             LOOM_TEST_DATABASE_URL/LOOM_TEST_DB_MIGRATE_URL/LOOM_SMOKE_DATABASE_URL \
             at a DB you own instead."
        ));
    }
    Ok(())
}

#[cfg(test)]
mod control_plane_guard_tests {
    use super::assert_not_control_plane_db;

    #[test]
    fn rejects_control_plane_host() {
        let err =
            assert_not_control_plane_db("postgres://paperclip:secret@postgres:5432/paperclip")
                .unwrap_err();
        assert!(err.contains("postgres:5432"));
    }

    #[test]
    fn rejects_control_plane_db_name_on_other_host() {
        let err =
            assert_not_control_plane_db("postgres://x:y@localhost:55432/paperclip").unwrap_err();
        assert!(err.contains("paperclip"));
    }

    #[test]
    fn allows_disposable_db() {
        assert_not_control_plane_db("postgres://loom_app:pw@127.0.0.1:55432/loom").unwrap();
    }

    #[test]
    fn allows_query_string_and_no_path() {
        assert_not_control_plane_db("postgres://loom_app:pw@127.0.0.1:55432/loom?sslmode=disable")
            .unwrap();
        assert_not_control_plane_db("postgres://loom_app:pw@127.0.0.1:55432").unwrap();
    }
}

/// Run schema migrations against `migrate_database_url`.
///
/// This must authenticate as `loom_owner` (see `LOOM_DB_MIGRATE_URL`), the
/// login that owns every table and function. It is deliberately a free
/// function taking its own connection string, not a method on [`Persist`],
/// so the world-runtime pool (`loom_app`, which is not an owner) is never
/// used to run migrations (D-27.4 finding: "ownership makes the REVOKEs
/// moot").
pub async fn run_migrations(migrate_database_url: &str) -> Result<()> {
    assert_not_control_plane_db(migrate_database_url)
        .map_err(PersistError::ControlPlaneDbRejected)?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(migrate_database_url)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    pool.close().await;
    Ok(())
}

impl Persist {
    /// Connect the world-runtime pool. `database_url` should authenticate as
    /// `loom_app`, which owns nothing and cannot write the role tables
    /// directly (D-27.4).
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self> {
        assert_not_control_plane_db(database_url).map_err(PersistError::ControlPlaneDbRejected)?;
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(database_url)
            .await?;
        Self::from_pool(pool)
    }

    pub fn from_pool(pool: PgPool) -> Result<Self> {
        let params = Params::new(ARGON_M_COST_KIB, ARGON_T_COST, ARGON_P_COST, None)
            .map_err(|_| PersistError::ArgonParams)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let dummy_password_hash = {
            let salt = SaltString::generate(&mut OsRng);
            argon2
                .hash_password(DUMMY_PASSWORD.as_bytes(), &salt)
                .map_err(|e| PersistError::PasswordHash(e.to_string()))?
                .to_string()
        };
        Ok(Self {
            pool,
            argon2,
            dummy_password_hash,
        })
    }

    /// Run a real Argon2id verify against the fixed dummy hash so a
    /// lookup miss (unknown account/staff username) costs the same CPU
    /// time as a wrong-password attempt against a real one (OBI-200,
    /// M-AUTH-2). The result is always discarded -- this exists purely
    /// for its timing, never its outcome.
    fn dummy_verify(&self, password: &str) {
        let parsed = PasswordHash::new(&self.dummy_password_hash)
            .expect("the dummy hash computed in from_pool is always a valid PHC string");
        let _ = self.argon2.verify_password(password.as_bytes(), &parsed);
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn create_account(&self, username: &str, password: &str) -> Result<Account> {
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = self
            .argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|error| PersistError::PasswordHash(error.to_string()))?
            .to_string();

        let row = sqlx::query!(
            "INSERT INTO accounts (username, password_hash)
             VALUES ($1, $2)
             RETURNING id, username",
            username,
            password_hash,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(Account {
            id: row.id,
            username: row.username,
        })
    }

    pub async fn verify_login(&self, username: &str, password: &str) -> Result<Option<Account>> {
        let row = sqlx::query!(
            "SELECT id, username, password_hash
             FROM accounts
             WHERE username = $1",
            username,
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            // OBI-200, M-AUTH-2: dummy verify so timing doesn't reveal that
            // this username doesn't exist.
            self.dummy_verify(password);
            return Ok(None);
        };

        let parsed = PasswordHash::new(&row.password_hash)
            .map_err(|error| PersistError::PasswordHash(error.to_string()))?;
        if self
            .argon2
            .verify_password(password.as_bytes(), &parsed)
            .is_err()
        {
            return Ok(None);
        }

        Ok(Some(Account {
            id: row.id,
            username: row.username,
        }))
    }

    /// Resolve a staff login by account username/password (OBI-174): joins
    /// `accounts` to `staff` by `account_id` (never by `uid = username` --
    /// see `roles_resolve_account`'s doc comment on why those can diverge),
    /// verifies the Argon2id hash the same way [`Persist::verify_login`]
    /// does, and returns `None` for either a bad password or an account
    /// that has no `staff` row (a player, not staff).
    pub async fn staff_login(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<StaffAuthRecord>> {
        let row = sqlx::query(
            "SELECT a.id as account_id, a.password_hash, s.uid, s.tier, s.totp_secret, \
                    s.totp_confirmed_at
             FROM accounts a
             JOIN staff s ON s.account_id = a.id
             WHERE a.username = $1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            // OBI-200, M-AUTH-2: dummy verify so timing doesn't reveal that
            // this username doesn't exist (or isn't staff).
            self.dummy_verify(password);
            return Ok(None);
        };
        use sqlx::Row;
        let password_hash: String = row.try_get("password_hash")?;

        let parsed = PasswordHash::new(&password_hash)
            .map_err(|error| PersistError::PasswordHash(error.to_string()))?;
        if self
            .argon2
            .verify_password(password.as_bytes(), &parsed)
            .is_err()
        {
            return Ok(None);
        }

        Ok(Some(StaffAuthRecord {
            uid: row.try_get("uid")?,
            account_id: row.try_get("account_id")?,
            tier: row.try_get("tier")?,
            totp_secret: row.try_get("totp_secret")?,
            totp_confirmed: row
                .try_get::<Option<OffsetDateTime>, _>("totp_confirmed_at")?
                .is_some(),
        }))
    }

    /// Enrol (or re-enrol) `uid`'s TOTP secret via the `auth_totp_enroll`
    /// security-definer function. Self-service only -- the function itself
    /// re-checks `actor == uid` in SQL. Re-enrolling always clears any
    /// prior confirmation, so [`Persist::staff_login`]'s `totp_confirmed`
    /// never reports true for a secret nobody has proven.
    pub async fn totp_enroll(&self, uid: &str, secret_base32: &str) -> Result<()> {
        sqlx::query("SELECT auth_totp_enroll($1, $2, $3)")
            .bind(uid)
            .bind(uid)
            .bind(secret_base32)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Mark `uid`'s pending TOTP secret confirmed via `auth_totp_confirm`.
    /// Callers must have already verified a code against the pending
    /// secret (loom-http does this before calling); this function only
    /// records that fact.
    pub async fn totp_confirm(&self, uid: &str) -> Result<()> {
        sqlx::query("SELECT auth_totp_confirm($1, $2)")
            .bind(uid)
            .bind(uid)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The uid's currently enrolled TOTP secret (confirmed or not), for
    /// the verify step to check a submitted code against. `loom_app` has
    /// plain `SELECT` on `staff` already (0001_init.sql); no
    /// security-definer wrapper needed for a read.
    pub async fn totp_secret_for(&self, uid: &str) -> Result<Option<String>> {
        use sqlx::Row;
        let row = sqlx::query("SELECT totp_secret FROM staff WHERE uid = $1")
            .bind(uid)
            .fetch_optional(&self.pool)
            .await?;
        Ok(match row {
            Some(row) => row.try_get("totp_secret")?,
            None => None,
        })
    }

    /// Record a newly-issued refresh token. Only `token_hash` (SHA-256 of
    /// the bearer token, computed by loom-http) is ever stored. `sid` is
    /// the token-family id (fresh at login, carried forward on rotation --
    /// see `loom-http`'s `AuthService::issue_tokens`), and `amr`/`mfa_at`
    /// describe the family's *original* authentication context (OBI-203).
    pub async fn refresh_token_insert(
        &self,
        staff_uid: &str,
        token_hash: &str,
        expires_at: OffsetDateTime,
        sid: &str,
        amr: &[String],
        mfa_at: Option<OffsetDateTime>,
    ) -> Result<Uuid> {
        use sqlx::Row;
        let row = sqlx::query(
            "INSERT INTO staff_sessions (staff_uid, token_hash, expires_at, sid, amr, mfa_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id",
        )
        .bind(staff_uid)
        .bind(token_hash)
        .bind(expires_at)
        .bind(sid)
        .bind(amr)
        .bind(mfa_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get("id")?)
    }

    /// Look up a refresh token by the SHA-256 hash of its bearer value.
    /// Callers must check both `expires_at` and `revoked_at` themselves --
    /// this returns whatever row matches the hash, expired or not, so a
    /// caller can tell "expired" apart from "never existed" if it ever
    /// needs to (it currently doesn't, but the distinction costs nothing).
    pub async fn refresh_token_lookup(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshTokenRecord>> {
        use sqlx::Row;
        let row = sqlx::query(
            "SELECT id, staff_uid, expires_at, revoked_at, sid, amr, mfa_at \
             FROM staff_sessions WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        Ok(Some(RefreshTokenRecord {
            id: row.try_get("id")?,
            staff_uid: row.try_get("staff_uid")?,
            expires_at: row.try_get("expires_at")?,
            revoked_at: row.try_get("revoked_at")?,
            sid: row.try_get("sid")?,
            amr: row.try_get("amr")?,
            mfa_at: row.try_get("mfa_at")?,
        }))
    }

    /// Revoke a single refresh token by its bearer-value hash (logout, or
    /// rotating it out after a single use).
    pub async fn refresh_token_revoke(&self, token_hash: &str) -> Result<()> {
        sqlx::query("UPDATE staff_sessions SET revoked_at = NOW() WHERE token_hash = $1 AND revoked_at IS NULL")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Revoke every outstanding refresh token for `uid` (reuse-detection
    /// response: a revoked or expired token being replayed looks like a
    /// stolen refresh token, so the whole session family is killed, not
    /// just the one token).
    pub async fn refresh_token_revoke_all(&self, uid: &str) -> Result<()> {
        sqlx::query("UPDATE staff_sessions SET revoked_at = NOW() WHERE staff_uid = $1 AND revoked_at IS NULL")
            .bind(uid)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Revoke every unrevoked session sharing `token_hash`'s `sid`
    /// (family) -- OBI-198, M-AUTH-5: "logout revokes the family", not
    /// just the one presented token. A no-op (not an error) if
    /// `token_hash` is unknown.
    pub async fn session_revoke_family_by_token(&self, token_hash: &str) -> Result<()> {
        sqlx::query(
            "UPDATE staff_sessions
             SET revoked_at = NOW()
             WHERE revoked_at IS NULL
               AND sid = (SELECT sid FROM staff_sessions WHERE token_hash = $1)",
        )
        .bind(token_hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Atomically rotate the session identified by `old_token_hash` to a
    /// fresh `new_token_hash` (OBI-198 re-review, must-fix 1 and 2):
    ///
    /// - **Must-fix 1 (absolute expiry must not slide):** the new row
    ///   inherits the *consumed* row's `expires_at`, `sid`, `amr`, and
    ///   `mfa_at` verbatim -- nothing here computes a fresh `now() + 14d`,
    ///   so a session's 14-day absolute cap is fixed at login and never
    ///   extended by a later rotation.
    /// - **Must-fix 2 (serialize against revoke-all):** before touching
    ///   any row, this takes `SELECT ... FOR SHARE` on the owning
    ///   `staff` row, in the same transaction as the consume+insert.
    ///   `staff_sessions_revoke_for_uid` (migration 0006) takes
    ///   `FOR UPDATE` on that same row before its revoke `UPDATE` --
    ///   `FOR UPDATE` conflicts with `FOR SHARE`, so whichever side asks
    ///   first completes first and the other sees a fully-committed,
    ///   consistent result (see the migration's doc comment for the two
    ///   orderings). Without this, a tier change/password change/TOTP
    ///   reset/GitHub unlink racing a concurrent refresh could miss the
    ///   newly-inserted row.
    ///
    /// `idle_cutoff` is "now minus the idle TTL": a session whose
    /// `last_used_at` is at or before it is treated as idle-expired, same
    /// as a session past its absolute `expires_at`.
    pub async fn session_rotate(
        &self,
        old_token_hash: &str,
        new_token_hash: &str,
        idle_cutoff: OffsetDateTime,
    ) -> Result<SessionRotateOutcome> {
        use sqlx::Row;
        let mut tx = self.pool.begin().await?;

        let Some(owner_row) =
            sqlx::query("SELECT staff_uid FROM staff_sessions WHERE token_hash = $1")
                .bind(old_token_hash)
                .fetch_optional(&mut *tx)
                .await?
        else {
            tx.commit().await?;
            return Ok(SessionRotateOutcome::Invalid);
        };
        let owner_uid: String = owner_row.try_get("staff_uid")?;

        // Serialize against `staff_sessions_revoke_for_uid`'s `FOR
        // UPDATE` on the same row -- see migration 0006's doc comment.
        // Taken through `staff_sessions_lock_for_rotate` (security
        // definer) since Postgres's row-locking clauses require
        // `UPDATE`/`DELETE` privilege on the table, which `loom_app`
        // never has on `staff` (D-27.4: `SELECT` only). A missing
        // `staff` row (shouldn't happen for a session that was ever
        // legitimately issued, but cheap to tolerate) just means
        // nothing to lock against; proceed.
        sqlx::query("SELECT staff_sessions_lock_for_rotate($1)")
            .bind(&owner_uid)
            .execute(&mut *tx)
            .await?;

        let consumed = sqlx::query(
            "UPDATE staff_sessions
             SET revoked_at = NOW()
             WHERE token_hash = $1
               AND revoked_at IS NULL
               AND expires_at > NOW()
               AND last_used_at > $2
             RETURNING staff_uid, sid, amr, mfa_at, expires_at",
        )
        .bind(old_token_hash)
        .bind(idle_cutoff)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(consumed) = consumed else {
            // Didn't match the guarded UPDATE above -- find out why.
            let existing =
                sqlx::query("SELECT sid, revoked_at FROM staff_sessions WHERE token_hash = $1")
                    .bind(old_token_hash)
                    .fetch_optional(&mut *tx)
                    .await?;
            let Some(existing) = existing else {
                tx.commit().await?;
                return Ok(SessionRotateOutcome::Invalid);
            };
            let revoked_at: Option<OffsetDateTime> = existing.try_get("revoked_at")?;
            if revoked_at.is_none() {
                // Not revoked, but didn't match: past its absolute or
                // idle expiry. Stale, not malicious -- no family-wide
                // response.
                tx.commit().await?;
                return Ok(SessionRotateOutcome::Invalid);
            }
            // Already revoked and presented again: a stolen (rotated-out,
            // or previously logged-out) refresh token. Kill the whole
            // family.
            let sid: String = existing.try_get("sid")?;
            sqlx::query(
                "UPDATE staff_sessions SET revoked_at = NOW() WHERE sid = $1 AND revoked_at IS NULL",
            )
            .bind(&sid)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(SessionRotateOutcome::Reused {
                staff_uid: owner_uid,
            });
        };

        let staff_uid: String = consumed.try_get("staff_uid")?;
        let sid: String = consumed.try_get("sid")?;
        let amr: Vec<String> = consumed.try_get("amr")?;
        let mfa_at: Option<OffsetDateTime> = consumed.try_get("mfa_at")?;
        let expires_at: OffsetDateTime = consumed.try_get("expires_at")?;

        sqlx::query(
            "INSERT INTO staff_sessions (staff_uid, token_hash, expires_at, sid, amr, mfa_at, last_used_at)
             VALUES ($1, $2, $3, $4, $5, $6, NOW())",
        )
        .bind(&staff_uid)
        .bind(new_token_hash)
        .bind(expires_at)
        .bind(&sid)
        .bind(&amr)
        .bind(mfa_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(SessionRotateOutcome::Rotated {
            staff_uid,
            sid,
            amr,
            mfa_at,
            expires_at,
        })
    }

    /// Resolve a numeric GitHub user id to a linked staff uid
    /// (`github_identities`, OBI-174). `None` means unlinked -- GitHub
    /// login must never create a staff row, only ever authenticate as a
    /// uid an arch has already linked via `auth_github_link`.
    pub async fn github_lookup(&self, github_id: i64) -> Result<Option<String>> {
        use sqlx::Row;
        let row = sqlx::query("SELECT staff_uid FROM github_identities WHERE github_id = $1")
            .bind(github_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(match row {
            Some(row) => Some(row.try_get("staff_uid")?),
            None => None,
        })
    }

    /// Link a GitHub numeric user id to an existing staff uid via
    /// `auth_github_link`. `actor` MUST be the driver/app's authenticated
    /// principal (an arch or root, T4+); the function re-checks this in SQL
    /// and never creates a staff row for an unrecognised uid. Audited as
    /// `auth.github.link` (OBI-200, M-AUTH-9).
    pub async fn github_link(
        &self,
        actor: &str,
        uid: &str,
        github_id: i64,
        reason: &str,
    ) -> Result<()> {
        sqlx::query("SELECT auth_github_link($1, $2, $3, $4)")
            .bind(actor)
            .bind(uid)
            .bind(github_id)
            .bind(reason)
            .execute(&self.pool)
            .await?;
        if let Err(err) = self
            .record_auth_audit(
                "auth.github.link",
                Some(actor),
                Some(uid),
                Some(format!("github_id={github_id} reason={reason}")),
            )
            .await
        {
            tracing::warn!(%err, "failed to audit auth.github.link");
        }
        Ok(())
    }

    /// Unlink a staff uid's GitHub identity via `auth_github_unlink`.
    /// Same actor-tier floor as [`Self::github_link`] (T4+). Audited as
    /// `auth.github.unlink` (OBI-200, M-AUTH-9).
    pub async fn github_unlink(&self, actor: &str, uid: &str, reason: &str) -> Result<()> {
        sqlx::query("SELECT auth_github_unlink($1, $2, $3)")
            .bind(actor)
            .bind(uid)
            .bind(reason)
            .execute(&self.pool)
            .await?;
        if let Err(err) = self
            .record_auth_audit(
                "auth.github.unlink",
                Some(actor),
                Some(uid),
                Some(reason.to_string()),
            )
            .await
        {
            tracing::warn!(%err, "failed to audit auth.github.unlink");
        }
        Ok(())
    }

    /// Append one `audit_log` row for an auth event that isn't already
    /// covered by [`Self::insert_audit_batch`]'s callers in `loom-http`
    /// (OBI-200, M-AUTH-9). `verdict` is always `"allow"` here -- the
    /// callers of this helper ([`Self::github_link`]/`github_unlink`)
    /// only run after their SQL function already succeeded.
    async fn record_auth_audit(
        &self,
        kind: &str,
        caller: Option<&str>,
        target: Option<&str>,
        detail: Option<String>,
    ) -> Result<()> {
        let row = AuditRow {
            at: OffsetDateTime::now_utc(),
            kind: kind.to_string(),
            caller: caller.map(|s| s.to_string()),
            effective_principal: target.map(|s| s.to_string()),
            apply: None,
            class: None,
            argument: None,
            guard_set: Vec::new(),
            verdict: "allow".to_string(),
            detail,
        };
        self.insert_audit_batch(&[row]).await
    }

    pub async fn save_object_state(&self, object: &ObjectState) -> Result<()> {
        sqlx::query!(
            "INSERT INTO object_state (
                object_path,
                key,
                program_path,
                program_version,
                schema_hash,
                state_json
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (object_path, key)
            DO UPDATE SET
                program_path = EXCLUDED.program_path,
                program_version = EXCLUDED.program_version,
                schema_hash = EXCLUDED.schema_hash,
                state_json = EXCLUDED.state_json,
                updated_at = NOW()",
            object.object_path,
            object.key,
            object.program_path,
            object.program_version,
            object.schema_hash,
            object.state,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn load_object_state(
        &self,
        object_path: &str,
        key: &str,
    ) -> Result<Option<ObjectState>> {
        let row = sqlx::query!(
            "SELECT object_path, key, program_path, program_version, schema_hash,
                    state_json as \"state_json: serde_json::Value\"
             FROM object_state
             WHERE object_path = $1 AND key = $2",
            object_path,
            key,
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        Ok(Some(ObjectState {
            object_path: row.object_path,
            key: row.key,
            program_path: row.program_path,
            program_version: row.program_version,
            schema_hash: row.schema_hash,
            state: row.state_json,
        }))
    }

    /// Promote/demote `target_uid` to `new_tier` via the `roles_set_tier`
    /// security-definer function.
    ///
    /// `actor` MUST be the driver's effective principal (see module docs),
    /// never a mudlib-supplied string. The database re-checks §5.11.2
    /// promotion rights (T3: T1<->T2 within a led domain; T4: up to T3, no
    /// self-promotion) and writes `role_changes` in the same transaction. It
    /// `RAISE`s (surfaced here as [`PersistError::Db`]) on any denial.
    pub async fn roles_set_tier(
        &self,
        actor: &str,
        target_uid: &str,
        new_tier: i16,
        reason: &str,
    ) -> Result<()> {
        sqlx::query!(
            "SELECT roles_set_tier($1, $2, $3, $4)",
            actor,
            target_uid,
            new_tier,
            reason,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Add, change, or remove `target_uid`'s membership in `domain` via the
    /// `roles_set_member` security-definer function.
    ///
    /// `actor` MUST be the driver's effective principal (see module docs).
    /// `role` is `"member"`, `"lead"`, or `None`/`"none"` to remove the
    /// membership. T3 (domain lead) may only set `"member"` in a domain it
    /// leads; T4+ may also appoint leads.
    pub async fn roles_set_member(
        &self,
        actor: &str,
        domain: &str,
        target_uid: &str,
        role: Option<&str>,
        reason: &str,
    ) -> Result<()> {
        sqlx::query!(
            "SELECT roles_set_member($1, $2, $3, $4, $5)",
            actor,
            domain,
            target_uid,
            role,
            reason,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Grant `uid` a time-boxed, per-uid exception via `roles_grant`.
    ///
    /// `actor` MUST be the driver's effective principal (see module docs).
    /// Requires actor tier >= 4 (arch and above); the actor may not grant to
    /// itself, may only grant to a uid whose recorded tier is strictly below
    /// the actor's own, and `expires_at` must be in the future and no more
    /// than 90 days out. Exceptions never require a tier change.
    pub async fn roles_grant(
        &self,
        actor: &str,
        uid: &str,
        kind: GrantKind,
        target: &str,
        expires_at: OffsetDateTime,
        reason: &str,
    ) -> Result<()> {
        sqlx::query!(
            "SELECT roles_grant($1, $2, $3, $4, $5, $6)",
            actor,
            uid,
            kind.as_sql(),
            target,
            expires_at,
            reason,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Revoke a previously granted exception via `roles_revoke_grant`.
    ///
    /// `actor` MUST be the driver's effective principal (see module docs).
    pub async fn roles_revoke_grant(
        &self,
        actor: &str,
        uid: &str,
        kind: GrantKind,
        target: &str,
        reason: &str,
    ) -> Result<()> {
        sqlx::query!(
            "SELECT roles_revoke_grant($1, $2, $3, $4, $5)",
            actor,
            uid,
            kind.as_sql(),
            target,
            reason,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Read `uid`'s current tier (0 if `uid` has no `staff` row, i.e. it is
    /// a player).
    pub async fn tier_of(&self, uid: &str) -> Result<i16> {
        let row = sqlx::query!("SELECT tier FROM staff WHERE uid = $1", uid)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.tier).unwrap_or(0))
    }

    /// List `uid`'s unexpired grants via the `active_grants` view, ignoring
    /// any grant whose `expires_at` has passed.
    pub async fn active_grants(&self, uid: &str) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query!(
            "SELECT kind as \"kind!\", target as \"target!\"
             FROM active_grants WHERE uid = $1 ORDER BY kind, target",
            uid,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| (r.kind, r.target)).collect())
    }

    /// Load the full roles snapshot (design §1/D-S2.1): plain data, no
    /// `loom-vm` dependency. Called by the DB worker, never the world
    /// thread; the driver swaps the resulting snapshot in with
    /// `World::set_roles_snapshot` (OBI-120/S2b).
    pub async fn load_roles_snapshot(&self) -> Result<RolesRows> {
        let staff = sqlx::query_as!(
            StaffRow,
            "SELECT uid, account_id, tier, totp_required FROM staff ORDER BY uid"
        )
        .fetch_all(&self.pool)
        .await?;

        let domains = sqlx::query_as!(DomainRow, "SELECT name, state FROM domains ORDER BY name")
            .fetch_all(&self.pool)
            .await?;

        let domain_members = sqlx::query_as!(
            DomainMemberRow,
            "SELECT domain, uid, role FROM domain_members ORDER BY domain, uid"
        )
        .fetch_all(&self.pool)
        .await?;

        let tier_policy = sqlx::query_as!(
            TierPolicyRow,
            "SELECT tier, max_ticks_exec, max_mem_exec_mb, tick_share_per_min, max_objects,
                    max_heartbeats, max_callouts_obj, max_callouts_uid, disk_quota_mb,
                    efun_classes
             FROM tier_policy ORDER BY tier"
        )
        .fetch_all(&self.pool)
        .await?;

        let active_grants = sqlx::query_as!(
            GrantRow,
            "SELECT uid as \"uid!\", kind as \"kind!\", target as \"target!\",
                    granted_by as \"granted_by!\", expires_at as \"expires_at!\"
             FROM active_grants ORDER BY uid, kind, target"
        )
        .fetch_all(&self.pool)
        .await?;

        let earliest_grant_expiry = active_grants.iter().map(|g| g.expires_at).min();

        Ok(RolesRows {
            staff,
            domains,
            domain_members,
            tier_policy,
            active_grants,
            earliest_grant_expiry,
        })
    }

    /// `LISTEN roles_changed` (migration 0002's `NOTIFY` triggers on
    /// `staff`, `domains`, `domain_members`, `tier_policy` and `grants`).
    /// Spawns a task that forwards each notification's payload (the
    /// table name that changed) on the returned channel; the driver's DB
    /// worker drains it and triggers a fresh [`Persist::load_roles_snapshot`]
    /// plus `World::set_roles_snapshot`. The task exits when the receiver
    /// is dropped or the listener errors.
    pub async fn listen_roles_changed(&self) -> Result<mpsc::Receiver<String>> {
        let mut listener = PgListener::connect_with(&self.pool).await?;
        listener.listen("roles_changed").await?;

        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(async move {
            loop {
                match listener.recv().await {
                    Ok(notification) => {
                        if tx.send(notification.payload().to_string()).await.is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        warn!("roles_changed listener error: {error}");
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }

    /// Propose a T4/T5 tier change via `roles_propose_tier` (two-root rule,
    /// design §6/D-S2.6). `actor` MUST be the driver's effective principal
    /// (see module docs) and must be a T5 root. Returns the new proposal's
    /// id; a *different* T5 root must call [`Persist::roles_approve_proposal`]
    /// before it takes effect.
    pub async fn roles_propose_tier(
        &self,
        actor: &str,
        target_uid: &str,
        new_tier: i16,
        reason: &str,
    ) -> Result<i64> {
        let id = sqlx::query_scalar!(
            "SELECT roles_propose_tier($1, $2, $3, $4) as \"id!\"",
            actor,
            target_uid,
            new_tier,
            reason,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    /// Approve a pending two-root proposal via `roles_approve_proposal`.
    /// `actor` MUST be the driver's effective principal (see module docs),
    /// a T5 root distinct from both the proposer and the target, and the
    /// proposal must be unexpired and not already applied.
    pub async fn roles_approve_proposal(&self, actor: &str, proposal_id: i64) -> Result<()> {
        sqlx::query!("SELECT roles_approve_proposal($1, $2)", actor, proposal_id,)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Append a batch of audit entries to `audit_log` in one round trip
    /// (design §5/D-S2.5). `loom_app` may only `INSERT` here; the sink is
    /// append-only, matching the driver's in-memory ring semantics.
    pub async fn insert_audit_batch(&self, rows: &[AuditRow]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }

        let mut builder: QueryBuilder<sqlx::Postgres> = QueryBuilder::new(
            "INSERT INTO audit_log (at, kind, caller, effective_principal, apply, class, \
             argument, guard_set, verdict, detail) ",
        );
        builder.push_values(rows, |mut row_builder, row| {
            row_builder
                .push_bind(row.at)
                .push_bind(&row.kind)
                .push_bind(&row.caller)
                .push_bind(&row.effective_principal)
                .push_bind(&row.apply)
                .push_bind(row.class)
                .push_bind(&row.argument)
                .push_bind(&row.guard_set)
                .push_bind(&row.verdict)
                .push_bind(&row.detail);
        });
        builder.build().execute(&self.pool).await?;
        Ok(())
    }
}

/// Detect a unique-constraint violation (Postgres code `23505`) so
/// `account_create` can distinguish "this username already exists" from
/// any other database failure.
fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(
        err.as_database_error().and_then(|d| d.code()),
        Some(code) if code == "23505"
    )
}

/// Spawn the world-facing async DB worker (OBI-33/OBI-85): everything the
/// world thread sends on the returned [`DbRequest`] sender runs off the
/// world thread (Argon2 hashing and any query against `persist`'s pool),
/// and the answer comes back on the returned [`DbEvent`] receiver, which
/// the world thread drains with `try_recv` (never `.await`s it).
pub fn spawn_db_worker(
    persist: Persist,
    queue_depth: usize,
) -> (mpsc::Sender<DbRequest>, mpsc::Receiver<DbEvent>) {
    let (request_tx, mut request_rx) = mpsc::channel::<DbRequest>(queue_depth);
    let (event_tx, event_rx) = mpsc::channel::<DbEvent>(queue_depth);

    tokio::spawn(async move {
        while let Some(request) = request_rx.recv().await {
            let event = match request {
                DbRequest::Sleep {
                    correlation_id,
                    duration_ms,
                } => {
                    let seconds = duration_ms as f64 / 1000.0;
                    let result = sqlx::query("SELECT pg_sleep($1)")
                        .bind(seconds)
                        .execute(persist.pool())
                        .await;
                    match result {
                        Ok(_) => DbEvent::SleepDone { correlation_id },
                        Err(error) => DbEvent::QueryFailed {
                            correlation_id,
                            message: error.to_string(),
                        },
                    }
                }
                DbRequest::CreateAccount {
                    correlation_id,
                    username,
                    password,
                } => {
                    let (ok, detail) =
                        match persist.create_account(&username, password.expose()).await {
                            Ok(account) => (true, account.id.to_string()),
                            Err(PersistError::Db(e)) if is_unique_violation(&e) => {
                                (false, "exists".to_string())
                            }
                            Err(_) => (false, "unavailable".to_string()),
                        };
                    DbEvent::AccountResult {
                        correlation_id,
                        ok,
                        detail,
                    }
                }
                DbRequest::VerifyLogin {
                    correlation_id,
                    username,
                    password,
                } => {
                    let (ok, detail) =
                        match persist.verify_login(&username, password.expose()).await {
                            Ok(Some(account)) => (true, account.id.to_string()),
                            Ok(None) => (false, "bad_credentials".to_string()),
                            Err(_) => (false, "unavailable".to_string()),
                        };
                    DbEvent::AccountResult {
                        correlation_id,
                        ok,
                        detail,
                    }
                }
                DbRequest::RolesSetTier {
                    correlation_id,
                    actor,
                    target,
                    tier,
                    reason,
                } => {
                    let (ok, detail) = match i16::try_from(tier) {
                        Err(_) => (false, "invalid_tier".to_string()),
                        Ok(tier) => {
                            match persist.roles_set_tier(&actor, &target, tier, &reason).await {
                                Ok(()) => (true, "ok".to_string()),
                                Err(e) => (false, roles_error_detail(&e)),
                            }
                        }
                    };
                    DbEvent::RolesResult {
                        correlation_id,
                        ok,
                        detail,
                    }
                }
                DbRequest::RolesSetMember {
                    correlation_id,
                    actor,
                    domain,
                    target,
                    role,
                    reason,
                } => {
                    let (ok, detail) = match persist
                        .roles_set_member(&actor, &domain, &target, Some(&role), &reason)
                        .await
                    {
                        Ok(()) => (true, "ok".to_string()),
                        Err(e) => (false, roles_error_detail(&e)),
                    };
                    DbEvent::RolesResult {
                        correlation_id,
                        ok,
                        detail,
                    }
                }
                DbRequest::RolesGrant {
                    correlation_id,
                    actor,
                    target,
                    kind,
                    what,
                    expires_at,
                    reason,
                } => {
                    let (ok, detail) = match (GrantKind::parse(&kind), expires_at) {
                        (None, _) => (false, "invalid_kind".to_string()),
                        (_, None) => (false, "expires_at_required".to_string()),
                        (Some(kind), Some(secs)) => {
                            match OffsetDateTime::from_unix_timestamp(secs) {
                                Err(_) => (false, "invalid_expires_at".to_string()),
                                Ok(expires_at) => match persist
                                    .roles_grant(&actor, &target, kind, &what, expires_at, &reason)
                                    .await
                                {
                                    Ok(()) => (true, "ok".to_string()),
                                    Err(e) => (false, roles_error_detail(&e)),
                                },
                            }
                        }
                    };
                    DbEvent::RolesResult {
                        correlation_id,
                        ok,
                        detail,
                    }
                }
                DbRequest::RolesRevokeGrant {
                    correlation_id,
                    actor,
                    target,
                    kind,
                    what,
                    reason,
                } => {
                    let (ok, detail) = match GrantKind::parse(&kind) {
                        None => (false, "invalid_kind".to_string()),
                        Some(kind) => match persist
                            .roles_revoke_grant(&actor, &target, kind, &what, &reason)
                            .await
                        {
                            Ok(()) => (true, "ok".to_string()),
                            Err(e) => (false, roles_error_detail(&e)),
                        },
                    };
                    DbEvent::RolesResult {
                        correlation_id,
                        ok,
                        detail,
                    }
                }
                DbRequest::RolesProposeTier {
                    correlation_id,
                    actor,
                    target,
                    tier,
                    reason,
                } => {
                    let (ok, detail) = match i16::try_from(tier) {
                        Err(_) => (false, "invalid_tier".to_string()),
                        Ok(tier) => match persist
                            .roles_propose_tier(&actor, &target, tier, &reason)
                            .await
                        {
                            Ok(id) => (true, id.to_string()),
                            Err(e) => (false, roles_error_detail(&e)),
                        },
                    };
                    DbEvent::RolesResult {
                        correlation_id,
                        ok,
                        detail,
                    }
                }
                DbRequest::RolesApprove {
                    correlation_id,
                    actor,
                    proposal_id,
                } => {
                    let (ok, detail) =
                        match persist.roles_approve_proposal(&actor, proposal_id).await {
                            Ok(()) => (true, "ok".to_string()),
                            Err(e) => (false, roles_error_detail(&e)),
                        };
                    DbEvent::RolesResult {
                        correlation_id,
                        ok,
                        detail,
                    }
                }
            };
            if event_tx.send(event).await.is_err() {
                warn!("db worker exiting: world event receiver dropped");
                break;
            }
        }
    });

    (request_tx, event_rx)
}

/// A denied/failed `roles_*` mutation's detail string: the Postgres
/// function's own `RAISE EXCEPTION` message where there is one (never a
/// secret -- these are all fixed, developer-authored strings, e.g.
/// `"actor does not lead domain shire"`), else `"unavailable"` for any
/// other database failure (connection loss, ...).
fn roles_error_detail(err: &PersistError) -> String {
    match err {
        PersistError::Db(sqlx::Error::Database(db)) => db.message().to_string(),
        _ => "unavailable".to_string(),
    }
}

/// The in-memory dev backend for `account_create`/`account_login` (spec,
/// OBI-85): used when `DATABASE_URL` is unset. Same Argon2 hashing as
/// [`Persist`] (off the calling task via `spawn_blocking`, matching the
/// "never blocks" requirement), but nothing here survives a restart --
/// callers should log a startup warning once, which this function does
/// not do itself (it has no way to know if it is only ever constructed
/// once), so `loom-cli` logs it at the call site instead.
pub fn spawn_dev_account_worker(
    queue_depth: usize,
) -> (mpsc::Sender<DbRequest>, mpsc::Receiver<DbEvent>) {
    let (request_tx, mut request_rx) = mpsc::channel::<DbRequest>(queue_depth);
    let (event_tx, event_rx) = mpsc::channel::<DbEvent>(queue_depth);
    let store: HashMap<String, (Uuid, String)> = HashMap::new();
    let store = std::sync::Arc::new(Mutex::new(store));

    tokio::spawn(async move {
        while let Some(request) = request_rx.recv().await {
            let event = match request {
                DbRequest::Sleep { correlation_id, .. } => DbEvent::QueryFailed {
                    correlation_id,
                    message: "dev account backend does not support Sleep".to_string(),
                },
                DbRequest::CreateAccount {
                    correlation_id,
                    username,
                    password,
                } => {
                    if store.lock().unwrap().contains_key(&username) {
                        DbEvent::AccountResult {
                            correlation_id,
                            ok: false,
                            detail: "exists".to_string(),
                        }
                    } else {
                        let pass = password.expose().to_string();
                        let hash = tokio::task::spawn_blocking(move || dev_hash(&pass)).await;
                        match hash {
                            Ok(Ok(hash)) => {
                                let id = Uuid::new_v4();
                                store.lock().unwrap().insert(username, (id, hash));
                                DbEvent::AccountResult {
                                    correlation_id,
                                    ok: true,
                                    detail: id.to_string(),
                                }
                            }
                            _ => DbEvent::AccountResult {
                                correlation_id,
                                ok: false,
                                detail: "unavailable".to_string(),
                            },
                        }
                    }
                }
                DbRequest::VerifyLogin {
                    correlation_id,
                    username,
                    password,
                } => {
                    let entry = store.lock().unwrap().get(&username).cloned();
                    match entry {
                        None => DbEvent::AccountResult {
                            correlation_id,
                            ok: false,
                            detail: "bad_credentials".to_string(),
                        },
                        Some((id, hash)) => {
                            let pass = password.expose().to_string();
                            let verified =
                                tokio::task::spawn_blocking(move || dev_verify(&pass, &hash)).await;
                            match verified {
                                Ok(true) => DbEvent::AccountResult {
                                    correlation_id,
                                    ok: true,
                                    detail: id.to_string(),
                                },
                                _ => DbEvent::AccountResult {
                                    correlation_id,
                                    ok: false,
                                    detail: "bad_credentials".to_string(),
                                },
                            }
                        }
                    }
                }
                DbRequest::RolesSetTier { correlation_id, .. }
                | DbRequest::RolesSetMember { correlation_id, .. }
                | DbRequest::RolesGrant { correlation_id, .. }
                | DbRequest::RolesRevokeGrant { correlation_id, .. }
                | DbRequest::RolesProposeTier { correlation_id, .. }
                | DbRequest::RolesApprove { correlation_id, .. } => {
                    // No Postgres in dev mode: there is no roles schema to
                    // mutate at all (`LOOM_ROLES_SEED` is read-only), so
                    // every roles mutation is `"unavailable"` here, same as
                    // any other DB outage -- never silently pending.
                    DbEvent::RolesResult {
                        correlation_id,
                        ok: false,
                        detail: "unavailable".to_string(),
                    }
                }
            };
            if event_tx.send(event).await.is_err() {
                warn!("dev account worker exiting: world event receiver dropped");
                break;
            }
        }
    });

    (request_tx, event_rx)
}

fn dev_argon2() -> Argon2<'static> {
    let params = Params::new(ARGON_M_COST_KIB, ARGON_T_COST, ARGON_P_COST, None)
        .expect("static argon2 params are always valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn dev_hash(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    dev_argon2()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| PersistError::PasswordHash(e.to_string()))
}

fn dev_verify(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    dev_argon2()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec (OBI-85): "the password must never appear in ... `Debug`
    /// output of `DbRequest`". Covers both request variants, and checks
    /// the *whole* enum's `Debug`, not just `Password`'s in isolation, so
    /// a future field added directly to `DbRequest` in plain `String`
    /// would have to deliberately avoid this test rather than pass it by
    /// accident.
    #[test]
    fn db_request_debug_output_never_contains_the_password() {
        let secret = "correct horse battery staple";
        let create = DbRequest::CreateAccount {
            correlation_id: 1,
            username: "legolas".to_string(),
            password: Password::new(secret),
        };
        let login = DbRequest::VerifyLogin {
            correlation_id: 2,
            username: "legolas".to_string(),
            password: Password::new(secret),
        };
        for req in [format!("{create:?}"), format!("{login:?}")] {
            assert!(!req.contains(secret), "password leaked into Debug: {req}");
            assert!(
                req.contains("redacted"),
                "expected a redaction marker: {req}"
            );
        }
    }

    #[tokio::test]
    async fn dev_account_worker_create_duplicate_and_wrong_password() {
        let (tx, mut rx) = spawn_dev_account_worker(8);

        tx.send(DbRequest::CreateAccount {
            correlation_id: 1,
            username: "ranger".to_string(),
            password: Password::new("anduril123"),
        })
        .await
        .unwrap();
        let created = rx.recv().await.unwrap();
        let DbEvent::AccountResult {
            correlation_id: 1,
            ok: true,
            detail,
        } = created
        else {
            panic!("expected a successful create, got {created:?}");
        };
        assert!(
            uuid::Uuid::parse_str(&detail).is_ok(),
            "detail should be a uuid: {detail}"
        );

        // Duplicate username.
        tx.send(DbRequest::CreateAccount {
            correlation_id: 2,
            username: "ranger".to_string(),
            password: Password::new("anduril123"),
        })
        .await
        .unwrap();
        let dup = rx.recv().await.unwrap();
        assert!(matches!(
            dup,
            DbEvent::AccountResult { correlation_id: 2, ok: false, ref detail } if detail == "exists"
        ));

        // Wrong password.
        tx.send(DbRequest::VerifyLogin {
            correlation_id: 3,
            username: "ranger".to_string(),
            password: Password::new("wrong-password"),
        })
        .await
        .unwrap();
        let bad = rx.recv().await.unwrap();
        assert!(matches!(
            bad,
            DbEvent::AccountResult { correlation_id: 3, ok: false, ref detail } if detail == "bad_credentials"
        ));

        // Right password.
        tx.send(DbRequest::VerifyLogin {
            correlation_id: 4,
            username: "ranger".to_string(),
            password: Password::new("anduril123"),
        })
        .await
        .unwrap();
        let ok = rx.recv().await.unwrap();
        assert!(matches!(
            ok,
            DbEvent::AccountResult {
                correlation_id: 4,
                ok: true,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn dev_account_worker_unknown_username_is_bad_credentials_not_exists_leak() {
        let (tx, mut rx) = spawn_dev_account_worker(8);
        tx.send(DbRequest::VerifyLogin {
            correlation_id: 1,
            username: "nobody".to_string(),
            password: Password::new("whatever-password"),
        })
        .await
        .unwrap();
        let event = rx.recv().await.unwrap();
        assert!(matches!(
            event,
            DbEvent::AccountResult { ok: false, ref detail, .. } if detail == "bad_credentials"
        ));
    }
}
