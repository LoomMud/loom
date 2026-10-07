// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-123 (loom-cli roles wiring, design OBI-36 §8): the DB-worker snapshot
//! loader, `LISTEN roles_changed`, the expiry timer, the `RolesMutations`
//! dispatch (`ChannelRolesMutations`/`run_roles_manager` in `src/main.rs`),
//! and the `audit_log` sink, exercised end to end against a real `loom serve`
//! subprocess and a real Postgres -- same two-login harness as
//! `loom-persist`'s own integration tests (D-27.4).
//!
//! Skips (like every DB-backed test in this workspace, D-27.7) unless
//! `LOOM_TEST_DB_MIGRATE_URL`/`LOOM_TEST_DATABASE_URL` are set, or fails
//! outright if `LOOM_REQUIRE_DB=1` (CI never silently skips DB coverage).
//!
//! OBI-151: these are deliberately *not* `LOOM_DB_MIGRATE_URL`/
//! `DATABASE_URL` -- agent shells export `DATABASE_URL` pointing at
//! Paperclip's own control-plane Postgres (OBI-150), so this harness must
//! never read that variable. Point `LOOM_TEST_DB_MIGRATE_URL`/
//! `LOOM_TEST_DATABASE_URL` at a disposable/dedicated Postgres instead --
//! `scripts/with-disposable-postgres.sh` provisions and tears one down for
//! exactly this purpose. `Persist::connect`/`run_migrations` also hard-fail
//! (OBI-151's belt-and-suspenders check) if the URL still looks like the
//! control-plane DB.
//!
//! OBI-305: the subprocess itself, its ports, its captured output and the
//! telnet transcript reading all come from `loom_testing`. The
//! file-specific part of that harness -- a per-test log *file* plus a
//! `dump_log` that only ran in two places -- is replaced by the shared
//! in-memory tail, which is printed on every panic (`assert_alive`, a dropped
//! connection, a needle timeout) rather than only on early exit.

use std::io::BufReader;
use std::net::TcpStream;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use loom_testing::{
    Reply, Server, Spawn, poll_until_contains, read_one_reply, read_until_contains, send_line,
};
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

/// These tests assert on decisions that arrive asynchronously (a notify-driven
/// snapshot swap, an expiry timer), so every wait is bounded by its own needle
/// timeout and the socket read timeout stays short.
const READ_TIMEOUT: Duration = Duration::from_millis(200);

/// Every process test here boots the same `roles` mudlib against a real
/// Postgres with the same log level; only the ports (which `loom_testing`
/// reserves) and the seeded rows differ.
fn spawn_roles_server(app_url: &str) -> Server {
    let mudlib = loom_testing::fixture(env!("CARGO_MANIFEST_DIR"), "roles");
    Spawn::serve(&mudlib)
        .with_env("DATABASE_URL", app_url)
        .with_log("loom_cli=debug,loom_vm=info,loom_persist=debug")
        .start()
}

/// Every test here spawns a real `loom serve` subprocess and hits the
/// same shared Postgres instance (through its own connection pool *and*
/// through the owner pool this file seeds/asserts with). Running them
/// concurrently (the default `cargo test` behaviour) stacks up to four
/// subprocesses, each with their own DB worker, `LISTEN` connection, and
/// world-tick timer, competing for CPU and DB connections on the same
/// runner -- exactly the kind of contention that turns a generous-looking
/// timeout into a flaky one. Serializing them trades a few extra seconds
/// of wall time for determinism.
fn serialize_db_tests() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn unique_uid(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4()).replace('-', "")
}

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

struct Fixture {
    owner: PgPool,
    /// `loom_app` DSN, handed to the spawned `loom serve` subprocess as
    /// `DATABASE_URL` -- the same login `loom-cli`'s DB worker uses in
    /// production. Sourced from `LOOM_TEST_DATABASE_URL`, not the ambient
    /// `DATABASE_URL` (OBI-151): this value only ever reaches the child
    /// process's own environment, explicitly, never inherited.
    app_url: String,
}

async fn setup() -> Option<Fixture> {
    let migrate_url = required_env("LOOM_TEST_DB_MIGRATE_URL")?;
    let app_url = required_env("LOOM_TEST_DATABASE_URL")?;

    loom_persist::run_migrations(&migrate_url)
        .await
        .expect("run migrations as loom_owner");

    let owner = PgPoolOptions::new()
        .max_connections(5)
        .connect(&migrate_url)
        .await
        .expect("connect owner pool");

    Some(Fixture { owner, app_url })
}

async fn seed_account(owner: &PgPool, username: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO accounts (username, password_hash) VALUES ($1, 'unused-in-tests')
         RETURNING id",
    )
    .bind(username)
    .fetch_one(owner)
    .await
    .expect("seed account")
}

async fn seed_staff(owner: &PgPool, uid: &str, account_id: Uuid, tier: i16) {
    sqlx::query("INSERT INTO staff (uid, account_id, tier) VALUES ($1, $2, $3)")
        .bind(uid)
        .bind(account_id)
        .bind(tier)
        .execute(owner)
        .await
        .expect("seed staff");
}

async fn seed_domain(owner: &PgPool, name: &str) {
    sqlx::query("INSERT INTO domains (name, state) VALUES ($1, 'live') ON CONFLICT DO NOTHING")
        .bind(name)
        .execute(owner)
        .await
        .expect("seed domain");
}

async fn seed_domain_member(owner: &PgPool, domain: &str, uid: &str, role: &str) {
    sqlx::query("INSERT INTO domain_members (domain, uid, role) VALUES ($1, $2, $3)")
        .bind(domain)
        .bind(uid)
        .bind(role)
        .execute(owner)
        .await
        .expect("seed domain member");
}

async fn staff_tier(owner: &PgPool, uid: &str) -> Option<i16> {
    sqlx::query_scalar("SELECT tier FROM staff WHERE uid = $1")
        .bind(uid)
        .fetch_optional(owner)
        .await
        .expect("query staff tier")
}

async fn last_role_change_actor(owner: &PgPool, target_uid: &str) -> Option<String> {
    sqlx::query_scalar("SELECT actor FROM role_changes WHERE uid = $1 ORDER BY id DESC LIMIT 1")
        .bind(target_uid)
        .fetch_optional(owner)
        .await
        .expect("query role_changes")
}

/// Poll `audit_log` for a row matching `kind`/`verdict` whose `argument`
/// contains `needle`, up to `timeout` -- the sink flushes once per world
/// tick (100ms), so this is never instantaneous.
async fn poll_audit_log_row(
    owner: &PgPool,
    kind: &str,
    verdict: &str,
    needle: &str,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let rows: Vec<Option<String>> = sqlx::query_scalar(
            "SELECT argument FROM audit_log WHERE kind = $1 AND verdict = $2 \
             ORDER BY id DESC LIMIT 50",
        )
        .bind(kind)
        .bind(verdict)
        .fetch_all(owner)
        .await
        .expect("query audit_log");
        if rows
            .iter()
            .any(|a| a.as_deref().is_some_and(|a| a.contains(needle)))
        {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Seeds `staff` rows for both `uid` and `granted_by` (the `grants` table's
/// two `REFERENCES staff(uid)` foreign keys) before inserting the grant
/// itself. Tier 1 (the lowest `staff.tier` allows -- the `CHECK (tier
/// BETWEEN 1 AND 5)` constraint; a player with no tier at all has no
/// `staff` row, so 0 is not a valid tier here) for both; nothing here
/// reads either uid's tier.
async fn insert_expiring_grant(owner: &PgPool, uid: &str, granted_by: &str, seconds_from_now: i64) {
    let uid_account = seed_account(owner, uid).await;
    seed_staff(owner, uid, uid_account, 1).await;
    let granter_account = seed_account(owner, granted_by).await;
    seed_staff(owner, granted_by, granter_account, 1).await;

    sqlx::query(
        "INSERT INTO grants (uid, kind, target, granted_by, expires_at)
         VALUES ($1, 'efun', 'write_file', $2, NOW() + make_interval(secs => $3))",
    )
    .bind(uid)
    .bind(granted_by)
    .bind(seconds_from_now as f64)
    .execute(owner)
    .await
    .expect("seed grant");
}

/// AC 1: "A mutation issued from `/secure/roles` through `process_input`
/// reaches SQL with the interactive's euid as the actor, and `roles_result`
/// arrives." A T3 domain lead (`become`'d, i.e. the actor-rule euid) may
/// promote a T1 member of a domain it leads to T2 (`roles_set_tier`'s own
/// rank rule, migration 0001) -- if `role_changes.actor` ends up as
/// anything but the lead's own uid, the driver laundered a Weft-supplied
/// string as the actor instead of the interactive's euid.
#[test]
fn mutation_from_secure_roles_reaches_sql_with_the_interactives_euid_as_actor() {
    let _serialize = serialize_db_tests();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let Some(fx) = rt.block_on(setup()) else {
        eprintln!("skipping: no database configured");
        return;
    };

    let lead_uid = unique_uid("lead");
    let member_uid = unique_uid("member");
    let domain = unique_uid("domain");
    rt.block_on(async {
        let lead_account = seed_account(&fx.owner, &lead_uid).await;
        seed_staff(&fx.owner, &lead_uid, lead_account, 3).await;
        let member_account = seed_account(&fx.owner, &member_uid).await;
        seed_staff(&fx.owner, &member_uid, member_account, 1).await;
        seed_domain(&fx.owner, &domain).await;
        seed_domain_member(&fx.owner, &domain, &lead_uid, "lead").await;
        seed_domain_member(&fx.owner, &domain, &member_uid, "member").await;
    });

    let mut server = spawn_roles_server(&fx.app_url);
    let mut conn = reconnect(&mut server, &[]);

    send_line(&mut conn, &format!("become {lead_uid}"));
    read_until_contains(&mut conn, "ok", Duration::from_secs(2));

    send_line(&mut conn, &format!("settier {member_uid} 2 promotion"));
    let out = poll_until_contains(&mut conn, "req ", Duration::from_secs(2), None);
    assert!(out.contains("req "), "{out}");

    let out = poll_until_contains(&mut conn, "roles_result ", Duration::from_secs(15), None);
    assert!(
        out.contains("roles_result 1 true"),
        "expected the promotion to succeed: {out}"
    );

    rt.block_on(async {
        assert_eq!(
            staff_tier(&fx.owner, &member_uid).await,
            Some(2),
            "roles_set_tier must have actually landed in Postgres"
        );
        assert_eq!(
            last_role_change_actor(&fx.owner, &member_uid)
                .await
                .as_deref(),
            Some(lead_uid.as_str()),
            "role_changes.actor must be the interactive's own euid, never a Weft string"
        );
        assert!(
            poll_audit_log_row(
                &fx.owner,
                "roles_set_tier",
                "allow",
                &format!("{member_uid} tier=2"),
                Duration::from_secs(10),
            )
            .await,
            "audit_log must have an allowed roles_set_tier row naming the operation and target"
        );
    });

    server.assert_alive();
}

/// AC 2: "A `roles_changed` notify swaps the snapshot and flushes the
/// security cache." Mutates `staff` directly through the owner connection
/// (never through a `roles_*` mutation efun, so the *only* thing that can
/// possibly wake the driver up is migration 0002's `NOTIFY roles_changed`
/// trigger on `staff`, not the post-mutation reload pulse in
/// `spawn_world_thread`'s drain loop) and waits for a `writefile` that was
/// denied before the promotion to start succeeding after it, with no
/// server restart.
#[test]
fn a_roles_changed_notify_swaps_the_snapshot_and_flushes_the_security_cache() {
    let _serialize = serialize_db_tests();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let Some(fx) = rt.block_on(setup()) else {
        eprintln!("skipping: no database configured");
        return;
    };

    let uid = unique_uid("bob");
    rt.block_on(async {
        let account = seed_account(&fx.owner, &uid).await;
        seed_staff(&fx.owner, &uid, account, 1).await; // T1: valid_write denies (< 2)
    });

    let mut server = spawn_roles_server(&fx.app_url);
    let mut conn = reconnect(&mut server, &[]);

    send_line(&mut conn, &format!("become {uid}"));
    read_until_contains(&mut conn, "ok", Duration::from_secs(2));

    // Give the boot-time snapshot load a moment to land before asserting
    // the pre-promotion denial (otherwise a `writefile` this early could
    // spuriously "succeed" against the tier-0-for-everyone boot default,
    // which is also < 2 -- so it would still deny, but for the wrong
    // reason; settle first so the test is about the notify, not a race
    // with the very first load).
    send_line(&mut conn, "writefile /roles_demo_notify.txt hi");
    let out = poll_until_contains(&mut conn, "denied", Duration::from_secs(5), None);
    assert!(out.contains("denied"), "T1 must be denied: {out}");

    // Direct owner-connection UPDATE: no `roles_set_tier` call, so no
    // post-mutation pulse -- only `NOTIFY roles_changed` can wake the
    // driver's `run_roles_manager` up for this one.
    rt.block_on(async {
        sqlx::query("UPDATE staff SET tier = 3 WHERE uid = $1")
            .bind(&uid)
            .execute(&fx.owner)
            .await
            .expect("promote bob directly");
    });

    // Re-send the same command: the client must re-issue the request to
    // see a fresh decision; the server does not push updates on its own.
    // Retry it periodically until the notify-driven reload lands and it
    // starts succeeding.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        send_line(&mut conn, "writefile /roles_demo_notify.txt hi");
        let reply = read_one_reply(&mut conn, Duration::from_secs(2));
        match reply {
            Reply::Line(l) if l.trim_end() == "true" => break,
            Reply::Closed => conn = reconnect(&mut server, &[&format!("become {uid}")]),
            Reply::Line(_) | Reply::Timeout => {}
        }
        if Instant::now() > deadline {
            panic!("writefile never started succeeding after the promotion");
        }
    }

    server.assert_alive();
}

/// AC 3: "An expired grant disappears from the snapshot without a
/// restart." No row ever changes at expiry (nothing to `NOTIFY` on), so
/// only the expiry timer (`run_roles_manager`'s `tokio::time::sleep`
/// branch, armed at `RolesRows::earliest_grant_expiry`) can make this
/// happen.
///
/// (CTO review N4: kept the reconnect-on-`Reply::Closed` retry below even
/// after B1's `run_roles_manager` reliability fix -- that fix is about the
/// *server's* reload loop never permanently stopping, not about the
/// occasional "connection closed" this test's own telnet client observed
/// against a real, Postgres-backed server under CI load, which is a
/// separate, still not fully root-caused symptom.)
#[test]
fn an_expired_grant_disappears_from_the_snapshot_without_a_restart() {
    let _serialize = serialize_db_tests();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let Some(fx) = rt.block_on(setup()) else {
        eprintln!("skipping: no database configured");
        return;
    };

    let uid = unique_uid("carol");
    let granter = unique_uid("granter");
    // A generous expiry window (10s): the boot-time snapshot load has to
    // connect, `LISTEN`, and run its first `load_roles_snapshot()` round
    // trip before the grant is visible at all -- give that plenty of
    // slack on a contended CI runner, well before the grant's own expiry.
    const GRANT_TTL_SECS: i64 = 10;
    rt.block_on(async {
        insert_expiring_grant(&fx.owner, &uid, &granter, GRANT_TTL_SECS).await;
    });

    let mut server = spawn_roles_server(&fx.app_url);
    let mut conn = reconnect(&mut server, &[]);

    // Retry (not a single request): the boot-time snapshot load is async,
    // so an immediate `hasgrant` could race a world that has not yet
    // swapped the real snapshot in.
    let query = format!("hasgrant {uid} efun write_file");
    let load_deadline = Instant::now() + Duration::from_secs(8);
    loop {
        send_line(&mut conn, &query);
        let reply = read_one_reply(&mut conn, Duration::from_secs(1));
        match reply {
            Reply::Line(l) if l.trim_end() == "hasgrant true" => break,
            Reply::Closed => conn = reconnect(&mut server, &[]),
            Reply::Line(_) | Reply::Timeout => {}
        }
        if Instant::now() > load_deadline {
            panic!("the unexpired grant was never loaded within the deadline");
        }
    }

    // Poll past the expiry: the earliest-expiry timer must reload on its
    // own, no NOTIFY, no restart.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        send_line(&mut conn, &query);
        let reply = read_one_reply(&mut conn, Duration::from_secs(1));
        match reply {
            Reply::Line(l) if l.trim_end() == "hasgrant false" => break,
            Reply::Closed => conn = reconnect(&mut server, &[]),
            Reply::Line(_) | Reply::Timeout => {}
        }
        if Instant::now() > deadline {
            panic!("grant never expired from the snapshot");
        }
    }

    server.assert_alive();
}

/// AC 4 (second half): "`audit_log` rows are written for a denied P2+
/// check". A T0 (no `staff` row) connection's `writefile` is denied by
/// `valid_write`, which is a P2+ `authorize()` decision, not the roles
/// mutation gate covered by the actor-rule test above.
#[test]
fn audit_log_has_a_row_for_a_denied_p2_plus_check() {
    let _serialize = serialize_db_tests();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let Some(fx) = rt.block_on(setup()) else {
        eprintln!("skipping: no database configured");
        return;
    };

    let mut server = spawn_roles_server(&fx.app_url);
    let mut conn = reconnect(&mut server, &[]);

    let marker = unique_uid("denyfile");
    send_line(&mut conn, &format!("writefile /{marker}.txt hi"));
    let out = poll_until_contains(&mut conn, "denied", Duration::from_secs(5), None);
    assert!(out.contains("denied"), "{out}");

    rt.block_on(async {
        assert!(
            poll_audit_log_row(
                &fx.owner,
                "write_file",
                "deny",
                &marker,
                Duration::from_secs(10)
            )
            .await,
            "expected a denied write_file audit_log row for {marker}"
        );
    });

    server.assert_alive();
}

/// (Re)connect and read past the `Welcome.` banner, then replay `warmup`
/// commands (e.g. `become <uid>`) to restore any per-connection state a
/// reconnect would otherwise lose. Used both for the first connection and to
/// recover from an occasional [`Reply::Closed`].
///
/// `loom_testing` owns the connect-with-retry and the startup negotiation
/// drain; a `serve` subprocess hands its readiness connection to the first
/// session and answers every later one with its own (OBI-305).
fn reconnect(server: &mut Server, warmup: &[&str]) -> BufReader<TcpStream> {
    let mut conn = server.session().into_reader(READ_TIMEOUT);
    read_until_contains(&mut conn, "Welcome.", Duration::from_secs(5));
    for cmd in warmup {
        send_line(&mut conn, cmd);
        read_one_reply(&mut conn, Duration::from_secs(2));
    }
    conn
}
