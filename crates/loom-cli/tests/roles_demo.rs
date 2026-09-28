// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-123 (loom-cli roles wiring, design OBI-36 \u00a78): the DB-worker
//! snapshot loader, `LISTEN roles_changed`, the expiry timer, the
//! `RolesMutations` dispatch (`ChannelRolesMutations`/`run_roles_manager`
//! in `src/main.rs`), and the `audit_log` sink, exercised end to end
//! against a real `loom serve` subprocess and a real Postgres -- same
//! two-login harness as `loom-persist`'s own integration tests (D-27.4).
//!
//! Skips (like every DB-backed test in this workspace, D-27.7) unless
//! `LOOM_DB_MIGRATE_URL`/`DATABASE_URL` are set, or fails outright if
//! `LOOM_REQUIRE_DB=1` (CI never silently skips DB coverage).

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

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
    /// production.
    app_url: String,
}

async fn setup() -> Option<Fixture> {
    let migrate_url = required_env("LOOM_DB_MIGRATE_URL")?;
    let app_url = required_env("DATABASE_URL")?;

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
    sqlx::query("INSERT INTO domains (name, state) VALUES ($1, 'active') ON CONFLICT DO NOTHING")
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

async fn insert_expiring_grant(owner: &PgPool, uid: &str, granted_by: &str, seconds_from_now: i64) {
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

    let mudlib = fixture("roles");
    let port = reserve_local_port();
    let bind = format!("127.0.0.1:{port}");
    let mut server = LoomServer::spawn(&mudlib, &bind, &fx.app_url);

    let stream = connect_with_retry(&bind, Duration::from_secs(5));
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut conn = BufReader::new(stream);
    read_until_contains(&mut conn, "Welcome.", Duration::from_secs(5));

    send_line(&mut conn, &format!("become {lead_uid}"));
    read_until_contains(&mut conn, "ok", Duration::from_secs(2));

    send_line(&mut conn, &format!("settier {member_uid} 2 promotion"));
    let out = poll_until_contains(&mut conn, "req ", Duration::from_secs(2));
    assert!(out.contains("req "), "{out}");

    let out = poll_until_contains(&mut conn, "roles_result ", Duration::from_secs(5));
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
                Duration::from_secs(3),
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

    let mudlib = fixture("roles");
    let port = reserve_local_port();
    let bind = format!("127.0.0.1:{port}");
    let mut server = LoomServer::spawn(&mudlib, &bind, &fx.app_url);

    let stream = connect_with_retry(&bind, Duration::from_secs(5));
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut conn = BufReader::new(stream);
    read_until_contains(&mut conn, "Welcome.", Duration::from_secs(5));

    send_line(&mut conn, &format!("become {uid}"));
    read_until_contains(&mut conn, "ok", Duration::from_secs(2));

    // Give the boot-time snapshot load a moment to land before asserting
    // the pre-promotion denial (otherwise a `writefile` this early could
    // spuriously "succeed" against the tier-0-for-everyone boot default,
    // which is also < 2 -- so it would still deny, but for the wrong
    // reason; settle first so the test is about the notify, not a race
    // with the very first load).
    let out = poll_until_contains(&mut conn, "denied", Duration::from_secs(5));
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

    let out = poll_until_contains(&mut conn, "true", Duration::from_secs(10));
    assert_eq!(out.trim_end(), "true", "{out:?}");

    server.assert_alive();
}

/// AC 3: "An expired grant disappears from the snapshot without a
/// restart." No row ever changes at expiry (nothing to `NOTIFY` on), so
/// only the expiry timer (`run_roles_manager`'s `tokio::time::sleep`
/// branch, armed at `RolesRows::earliest_grant_expiry`) can make this
/// happen.
#[test]
fn an_expired_grant_disappears_from_the_snapshot_without_a_restart() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let Some(fx) = rt.block_on(setup()) else {
        eprintln!("skipping: no database configured");
        return;
    };

    let uid = unique_uid("carol");
    let granter = unique_uid("granter");
    rt.block_on(async {
        seed_account(&fx.owner, &uid).await;
        insert_expiring_grant(&fx.owner, &uid, &granter, 3).await;
    });

    let mudlib = fixture("roles");
    let port = reserve_local_port();
    let bind = format!("127.0.0.1:{port}");
    let mut server = LoomServer::spawn(&mudlib, &bind, &fx.app_url);

    let stream = connect_with_retry(&bind, Duration::from_secs(5));
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut conn = BufReader::new(stream);
    read_until_contains(&mut conn, "Welcome.", Duration::from_secs(5));

    send_line(&mut conn, &format!("hasgrant {uid} efun write_file"));
    let out = poll_until_contains(&mut conn, "hasgrant ", Duration::from_secs(5));
    assert!(
        out.contains("hasgrant true"),
        "the unexpired grant must be loaded: {out}"
    );

    // Poll past the 3s expiry: the earliest-expiry timer must reload on
    // its own, no NOTIFY, no restart.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        send_line(&mut conn, &format!("hasgrant {uid} efun write_file"));
        let out = poll_until_contains(&mut conn, "hasgrant ", Duration::from_secs(5));
        if out.contains("hasgrant false") {
            break;
        }
        if Instant::now() > deadline {
            panic!("grant never expired from the snapshot: {out}");
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
    let rt = tokio::runtime::Runtime::new().unwrap();
    let Some(fx) = rt.block_on(setup()) else {
        eprintln!("skipping: no database configured");
        return;
    };

    let mudlib = fixture("roles");
    let port = reserve_local_port();
    let bind = format!("127.0.0.1:{port}");
    let mut server = LoomServer::spawn(&mudlib, &bind, &fx.app_url);

    let stream = connect_with_retry(&bind, Duration::from_secs(5));
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut conn = BufReader::new(stream);
    read_until_contains(&mut conn, "Welcome.", Duration::from_secs(5));

    let marker = unique_uid("denyfile");
    send_line(&mut conn, &format!("writefile /{marker}.txt hi"));
    let out = poll_until_contains(&mut conn, "denied", Duration::from_secs(5));
    assert!(out.contains("denied"), "{out}");

    rt.block_on(async {
        assert!(
            poll_audit_log_row(
                &fx.owner,
                "write_file",
                "deny",
                &marker,
                Duration::from_secs(5)
            )
            .await,
            "expected a denied write_file audit_log row for {marker}"
        );
    });

    server.assert_alive();
}

fn send_line(reader: &mut BufReader<TcpStream>, line: &str) {
    let stream = reader.get_mut();
    stream
        .write_all(line.as_bytes())
        .unwrap_or_else(|err| panic!("write command `{line}` failed: {err}"));
    stream
        .write_all(b"\n")
        .unwrap_or_else(|err| panic!("write newline for `{line}` failed: {err}"));
    stream
        .flush()
        .unwrap_or_else(|err| panic!("flush command `{line}` failed: {err}"));
}

/// [`read_until_contains`], but re-sends `line`'s command itself every
/// ~100ms while waiting (an idle connection would otherwise never re-poll
/// an async result -- see `accounts_demo.rs`'s copy of this same helper).
fn poll_until_contains(
    reader: &mut BufReader<TcpStream>,
    needle: &str,
    timeout: Duration,
) -> String {
    let deadline = Instant::now() + timeout;
    let mut transcript = String::new();

    loop {
        if transcript.contains(needle) {
            return transcript;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for `{needle}`. Transcript so far:\n{transcript}");
        }

        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => panic!(
                "connection closed while waiting for `{needle}`. Transcript so far:\n{transcript}"
            ),
            Ok(_) => transcript.push_str(&line.replace("\r\n", "\n")),
            Err(err)
                if err.kind() == std::io::ErrorKind::TimedOut
                    || err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => panic!("socket read failed while waiting for `{needle}`: {err}"),
        }
    }
}

fn read_until_contains(
    reader: &mut BufReader<TcpStream>,
    needle: &str,
    timeout: Duration,
) -> String {
    let deadline = Instant::now() + timeout;
    let mut transcript = String::new();

    loop {
        if Instant::now() > deadline {
            panic!("timed out waiting for `{needle}`. Transcript so far:\n{transcript}");
        }

        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => panic!(
                "connection closed while waiting for `{needle}`. Transcript so far:\n{transcript}"
            ),
            Ok(_) => {
                let normalized = line.replace("\r\n", "\n");
                transcript.push_str(&normalized);
                if transcript.contains(needle) {
                    return transcript;
                }
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::TimedOut
                    || err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => panic!("socket read failed while waiting for `{needle}`: {err}"),
        }
    }
}

fn connect_with_retry(addr: &str, timeout: Duration) -> TcpStream {
    let deadline = Instant::now() + timeout;
    loop {
        match TcpStream::connect(addr) {
            Ok(mut stream) => {
                drain_telnet_preamble(&mut stream);
                return stream;
            }
            Err(err) if Instant::now() < deadline => {
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::TimedOut
                ) {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                panic!("failed to connect to {addr}: {err}");
            }
            Err(err) => panic!("failed to connect to {addr} before timeout: {err}"),
        }
    }
}

/// See `accounts_demo.rs`'s copy of this helper: `loom serve` negotiates a
/// fixed 12-byte telnet preamble before any text protocol.
fn drain_telnet_preamble(stream: &mut TcpStream) {
    use std::io::Read;
    let mut preamble = [0_u8; 12];
    stream
        .read_exact(&mut preamble)
        .expect("read telnet negotiation preamble");
}

fn reserve_local_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("read local addr").port()
}

struct LoomServer {
    child: Child,
}

impl LoomServer {
    fn spawn(mudlib: &Path, bind: &str, database_url: &str) -> Self {
        let loom_bin = std::env::var("CARGO_BIN_EXE_loom-cli")
            .or_else(|_| std::env::var("CARGO_BIN_EXE_loom_cli"))
            .expect("cargo binary path for loom-cli");
        let http_port = reserve_local_port();

        let child = Command::new(loom_bin)
            .arg("serve")
            .arg("--mudlib")
            .arg(mudlib)
            .env("LOOM_TELNET_ADDR", bind)
            .env("LOOM_HTTP_ADDR", format!("127.0.0.1:{http_port}"))
            .env("DATABASE_URL", database_url)
            .env("RUST_LOG", "")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn loom serve");

        Self { child }
    }

    fn assert_alive(&mut self) {
        if let Some(status) = self.child.try_wait().expect("poll server process") {
            panic!("loom server exited early with status {status}");
        }
    }
}

impl Drop for LoomServer {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

static N: AtomicU32 = AtomicU32::new(0);

fn scratch(tag: &str) -> PathBuf {
    let n = N.fetch_add(1, Ordering::SeqCst);
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir scratch");
    dir
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("mkdir destination");
    for entry in std::fs::read_dir(from).expect("read fixture directory") {
        let path = entry.expect("fixture entry").path();
        let dest = to.join(path.file_name().expect("fixture filename"));
        if path.is_dir() {
            copy_dir(&path, &dest);
        } else {
            std::fs::copy(&path, &dest).expect("copy fixture file");
        }
    }
}

fn fixture(name: &str) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let dir = scratch(name);
    copy_dir(&src, &dir);
    dir
}
