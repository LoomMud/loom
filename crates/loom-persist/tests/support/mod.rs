// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared test fixtures for `loom-persist` integration tests.
//!
//! Tests connect on **two** logins, matching production (D-27.4):
//! - `owner_pool()` -- `loom_owner`, used only to run migrations and to seed
//!   fixtures that a real bootstrap process would write directly (T4/T5
//!   staff rows, domains). Production code never uses this login.
//! - `Persist` built from `app_database_url()` -- `loom_app`, the
//!   world-runtime login under test. All `roles_*` calls in these tests go
//!   through this login, so a passing test proves the security-definer
//!   functions work for the login that will actually call them.

use loom_persist::Persist;
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

/// Returns `Some(value)` for `name`, or `None` if unset -- unless
/// `LOOM_REQUIRE_DB=1` is set, in which case a missing required DB variable
/// panics instead of letting the test suite silently skip DB coverage
/// (D-27.7: CI must fail, not skip).
fn required_env(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) => Some(value),
        Err(_) => {
            if std::env::var("LOOM_REQUIRE_DB").as_deref() == Ok("1") {
                panic!(
                    "{name} is required when LOOM_REQUIRE_DB=1; DB integration tests must not \
                     be silently skipped in CI"
                );
            }
            None
        }
    }
}

/// Test fixture bundle, or `None` when no database is configured locally
/// and `LOOM_REQUIRE_DB` isn't set (dev-machine skip path).
pub struct Fixture {
    pub owner: PgPool,
    pub app: Persist,
}

pub async fn setup() -> Option<Fixture> {
    let Some(migrate_url) = required_env("LOOM_DB_MIGRATE_URL") else {
        eprintln!("skipping: LOOM_DB_MIGRATE_URL not set");
        return None;
    };
    let Some(app_url) = required_env("DATABASE_URL") else {
        eprintln!("skipping: DATABASE_URL not set");
        return None;
    };

    loom_persist::run_migrations(&migrate_url)
        .await
        .expect("run migrations as loom_owner");

    let owner = PgPoolOptions::new()
        .max_connections(5)
        .connect(&migrate_url)
        .await
        .expect("connect owner pool");

    let app = Persist::connect(&app_url, 5)
        .await
        .expect("connect loom_app pool");

    Some(Fixture { owner, app })
}

/// Insert an account directly (owner connection) and return its id.
pub async fn seed_account(owner: &PgPool, username: &str) -> Uuid {
    sqlx::query_scalar!(
        "INSERT INTO accounts (username, password_hash) VALUES ($1, 'unused-in-tests')
         RETURNING id",
        username,
    )
    .fetch_one(owner)
    .await
    .expect("seed account")
}

/// Insert a `staff` row directly (owner connection): this is the only way
/// to create T4/T5 accounts in Phase 1, since `roles_set_tier` refuses to
/// set tiers above 3 (D-27.2).
pub async fn seed_staff(owner: &PgPool, uid: &str, account_id: Uuid, tier: i16) {
    sqlx::query!(
        "INSERT INTO staff (uid, account_id, tier) VALUES ($1, $2, $3)",
        uid,
        account_id,
        tier,
    )
    .execute(owner)
    .await
    .expect("seed staff");
}

pub async fn seed_domain(owner: &PgPool, name: &str, state: &str) {
    sqlx::query!(
        "INSERT INTO domains (name, state) VALUES ($1, $2)",
        name,
        state,
    )
    .execute(owner)
    .await
    .expect("seed domain");
}

pub async fn seed_domain_member(owner: &PgPool, domain: &str, uid: &str, role: &str) {
    sqlx::query!(
        "INSERT INTO domain_members (domain, uid, role) VALUES ($1, $2, $3)",
        domain,
        uid,
        role,
    )
    .execute(owner)
    .await
    .expect("seed domain member");
}

pub async fn staff_tier(owner: &PgPool, uid: &str) -> Option<i16> {
    sqlx::query_scalar!("SELECT tier FROM staff WHERE uid = $1", uid)
        .fetch_optional(owner)
        .await
        .expect("query staff tier")
}

pub fn unique_uid(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4())
}
