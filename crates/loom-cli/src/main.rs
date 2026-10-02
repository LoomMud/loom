// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `loom` command-line entry point (`serve`, `check`, ...).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use loom_net::{GmcpMessage, NetCommand, NetConfig, NetEvent};
use loom_persist::{DbEvent, DbRequest, Password, Persist};
use loom_vm::{AccountAuth, Host, RolesMutations, RolesSnapshot, World};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

const EVENT_CHANNEL_CAPACITY: usize = 1024;
const COMMAND_CHANNEL_CAPACITY: usize = 1024;
/// Bound on in-flight `account_create`/`account_login`/`roles_*` mutation
/// requests (spec's bounded-queue engineering lens): past this many
/// outstanding DB/dev-backend requests, [`ChannelAccountAuth`]/
/// [`ChannelRolesMutations`]'s `try_send` starts failing (never blocking
/// the world thread; see their docs), and `World::issue_account_request`/
/// the `roles_*` mutation efuns immediately queue an `"unavailable"`
/// result instead of leaving the request pending forever.
const DB_QUEUE_DEPTH: usize = 256;
/// Bound on audit rows in flight between the world thread and
/// [`run_audit_sink`] (OBI-36 D-S2.5/OBI-123): the world thread's
/// `try_send` drops a batch (with a warning) rather than ever blocking on
/// a slow/stalled Postgres connection -- the in-memory ring is still the
/// source of truth and the batch is only a handful of ticks' worth of
/// entries (see `World::drain_audit_since`'s doc for what a fallen-behind
/// sink loses instead: the ring's own bound, not this queue's).
const AUDIT_QUEUE_DEPTH: usize = 64;

/// World tick granularity (spec r5 N2): `World::tick` (heartbeats,
/// `call_out`s) is driven once per this interval by `serve()`'s timer
/// (OBI-82). `call_out` delays and the heartbeat cadence
/// (`loom_vm::Limits::heartbeat_interval_ticks`) are both counted in world
/// ticks, i.e. multiples of this duration, not wall-clock time directly.
const WORLD_TICK_INTERVAL: Duration = Duration::from_millis(100);

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let _tracing_guard = loom_obs::init_tracing("loom-cli");

    if let Err(err) = run().await {
        error!(error = %err, "loom command failed");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        println!("loom {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    };

    match command.as_str() {
        "serve" => {
            let mudlib = parse_mudlib_arg(args)?;
            serve(mudlib).await
        }
        "check" => {
            let mut root = None;
            let mut dump_hir = false;
            let mut deny_warnings = false;
            for a in args {
                match a.as_str() {
                    "--dump-hir" => dump_hir = true,
                    "--deny-warnings" => deny_warnings = true,
                    _ if root.is_none() => root = Some(PathBuf::from(a)),
                    _ => return Err(format!("unexpected argument: {a}")),
                }
            }
            let Some(root) = root else {
                return Err(
                    "usage: loom check <mudlib-root> [--dump-hir] [--deny-warnings]".to_string(),
                );
            };
            check(root, dump_hir, deny_warnings)
        }
        "disasm" => {
            let args: Vec<String> = args.collect();
            let (Some(root), Some(program)) = (args.first(), args.get(1)) else {
                return Err("usage: loom disasm <mudlib-root> <program-path>".to_string());
            };
            disasm(PathBuf::from(root), program)
        }
        "probe" => {
            let url = args
                .next()
                .ok_or_else(|| "usage: loom probe <url>".to_string())?;
            if args.next().is_some() {
                return Err("usage: loom probe <url>".to_string());
            }
            probe(&url)
        }
        "migrate" => migrate().await,
        other => Err(format!("unknown command: {other}")),
    }
}

/// `loom probe <url>`: a minimal healthcheck client for use as a container
/// `HEALTHCHECK`/Compose healthcheck command. The runtime image is
/// `debian:bookworm-slim` with no `curl`/`wget`/`nc` installed (R6, OBI-42),
/// so Docker Compose needs something already on `PATH` inside the image to
/// probe `loom`'s own liveness/readiness.
///
/// Two URL schemes are supported:
/// - `http://host:port/path` -- opens a TCP connection, sends a bare
///   `GET /path HTTP/1.1` with a `Connection: close` header, and treats any
///   `2xx` status line as success. Intended for the `loom-http` `:8080`
///   `/healthz` and `/readyz` endpoints once that crate exists; today it
///   works against any minimal HTTP responder.
/// - `tcp://host:port` -- a bare TCP connect-and-close check, no HTTP
///   involved. This is the interim healthcheck R6 uses today, since `loom`
///   only listens on the telnet port (`:4000`); it proves the process is
///   accepting connections, not that the world thread is healthy.
///
/// Exits (via the `Result` error path, caught by `main`) non-zero on any
/// connection failure, timeout (5s) or non-2xx status, and prints nothing
/// on success (Docker healthchecks judge by exit code only).
fn probe(url: &str) -> Result<(), String> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(5);

    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("probe: unsupported url (missing scheme): {url}"))?;

    let connect = |host_port: &str| -> Result<TcpStream, String> {
        let mut addrs = host_port
            .to_socket_addrs()
            .map_err(|err| format!("probe: cannot resolve {host_port}: {err}"))?;
        let addr = addrs
            .next()
            .ok_or_else(|| format!("probe: no addresses for {host_port}"))?;
        let stream = TcpStream::connect_timeout(&addr, TIMEOUT)
            .map_err(|err| format!("probe: connect {host_port} failed: {err}"))?;
        stream
            .set_read_timeout(Some(TIMEOUT))
            .map_err(|err| format!("probe: set_read_timeout: {err}"))?;
        stream
            .set_write_timeout(Some(TIMEOUT))
            .map_err(|err| format!("probe: set_write_timeout: {err}"))?;
        Ok(stream)
    };

    match scheme {
        "tcp" => {
            connect(rest)?;
            Ok(())
        }
        "http" => {
            let (host_port, path) = match rest.split_once('/') {
                Some((hp, p)) => (hp, format!("/{p}")),
                None => (rest, "/".to_string()),
            };
            let mut stream = connect(host_port)?;
            let request =
                format!("GET {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
            stream
                .write_all(request.as_bytes())
                .map_err(|err| format!("probe: write failed: {err}"))?;
            let mut response = Vec::new();
            stream
                .read_to_end(&mut response)
                .map_err(|err| format!("probe: read failed: {err}"))?;
            let status_line = response
                .split(|&b| b == b'\n')
                .next()
                .map(|line| String::from_utf8_lossy(line).trim().to_string())
                .unwrap_or_default();
            let status_code = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|code| code.parse::<u16>().ok())
                .ok_or_else(|| format!("probe: unparseable status line: {status_line:?}"))?;
            if (200..300).contains(&status_code) {
                Ok(())
            } else {
                Err(format!("probe: non-2xx status: {status_line}"))
            }
        }
        other => Err(format!("probe: unsupported scheme: {other}")),
    }
}

/// `loom migrate`: run `loom-persist`'s embedded `sqlx` migrations against
/// `LOOM_DB_MIGRATE_URL`, which must authenticate as `loom_owner` -- the
/// login that owns every table and `security definer` function (D-27.4,
/// `loom-persist`'s module docs). Never touches `DATABASE_URL`
/// (`loom_app`, the world-runtime login): that login has no DDL rights and
/// this command doesn't need it. Intended to run once, to completion,
/// before `loom serve` is started against the same database (OBI-130: the
/// staging Compose stack runs this as a separate one-shot step, the same
/// way `mudlib-sync` gates `loom` on `service_completed_successfully`).
async fn migrate() -> Result<(), String> {
    let url = std::env::var("LOOM_DB_MIGRATE_URL").map_err(|_| {
        "LOOM_DB_MIGRATE_URL is not set (must authenticate as loom_owner)".to_string()
    })?;
    loom_persist::run_migrations(&url)
        .await
        .map_err(|err| format!("migration failed: {err}"))?;
    info!("migrations applied");
    Ok(())
}

/// `loom disasm <mudlib-root> <program-path>`: compile one program (and its
/// ancestors) to verified bytecode and print its disassembly (spec §5.8;
/// `crate::` here is `loom_compiler::disasm`). Exits non-zero (without a
/// disassembly) if the program does not check, does not lower yet (a V2
/// gap such as closures), or the assembled bytecode fails verification --
/// that last case is a compiler bug, not a user error, and is reported as
/// such.
fn disasm(root: PathBuf, program: &str) -> Result<(), String> {
    let normalized = loom_compiler::mudlib::normalize_path(program)?;
    let mut session = loom_compiler::Session::new(loom_compiler::FsLoader { root });
    let outcome = session.compile(&normalized);
    let checked = match outcome {
        loom_compiler::Outcome::Ok(c) => c,
        loom_compiler::Outcome::Failed(r) => return Err(format!("{normalized}: has errors:\n{r}")),
        loom_compiler::Outcome::Missing(r) => return Err(format!("{normalized}: {r}")),
    };
    let module =
        loom_compiler::codegen::compile(&checked.hir).map_err(|e| format!("{normalized}: {e}"))?;
    loom_compiler::verify::verify(&module).map_err(|e| {
        format!("{normalized}: compiler bug: assembled bytecode failed verification: {e}")
    })?;
    print!("{}", loom_compiler::disasm::module(&module));
    Ok(())
}

/// `loom check <mudlib-root>`: resolve and type-check every `.wf` file with
/// the Phase 1 compiler front end (`loom-compiler`) without running anything;
/// print diagnostics and fail if there are any. `--dump-hir` prints the
/// typed HIR of every clean program. Lint warnings (`09xx` codes, e.g.
/// D-P1.4 literal setters in `create()`) print but do not fail the check
/// unless `--deny-warnings` is given.
fn check(root: PathBuf, dump_hir: bool, deny_warnings: bool) -> Result<(), String> {
    let report = loom_compiler::check_mudlib(&root)
        .map_err(|err| format!("cannot scan {}: {err}", root.display()))?;
    if dump_hir {
        for c in report.programs.values() {
            println!("{}", loom_compiler::dump::program(&c.hir));
        }
    }
    for w in &report.warnings {
        eprintln!("{w}");
    }
    let errors = report.errors;
    for e in &errors {
        eprintln!("{e}\n");
    }
    if !errors.is_empty() {
        return Err(format!("{} file(s) with errors", errors.len()));
    }
    if deny_warnings && !report.warnings.is_empty() {
        return Err(format!(
            "{} warning(s) (--deny-warnings)",
            report.warnings.len()
        ));
    }
    println!("loom check: {} ok", root.display());
    Ok(())
}

fn parse_mudlib_arg(mut args: impl Iterator<Item = String>) -> Result<PathBuf, String> {
    let mut mudlib: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        if arg == "--mudlib" {
            let Some(path) = args.next() else {
                return Err("--mudlib requires a value".to_string());
            };
            mudlib = Some(PathBuf::from(path));
        } else {
            return Err(format!("unexpected argument: {arg}"));
        }
    }

    mudlib.ok_or_else(|| "missing required --mudlib <path>".to_string())
}

async fn serve(mudlib_root: PathBuf) -> Result<(), String> {
    let bind_addr = loom_net::telnet_addr_from_env();
    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(|err| format!("failed to bind {bind_addr}: {err}"))?;
    let actual_addr = listener
        .local_addr()
        .map_err(|err| format!("failed to read local addr: {err}"))?;

    let http_bind_addr = http_addr_from_env();
    let http_listener = TcpListener::bind(&http_bind_addr)
        .await
        .map_err(|err| format!("failed to bind {http_bind_addr}: {err}"))?;
    let http_actual_addr = http_listener
        .local_addr()
        .map_err(|err| format!("failed to read HTTP local addr: {err}"))?;

    let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let (command_tx, command_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let tick_pending = Arc::new(AtomicBool::new(false));

    let persist = connect_persist().await?;
    let (db_req_tx, db_event_rx) = match &persist {
        Some(p) => loom_persist::spawn_db_worker(p.clone(), DB_QUEUE_DEPTH),
        None => {
            warn!(
                "neither LOOM_SMOKE_DATABASE_URL nor DATABASE_URL is set: accounts and roles \
                 mutations are NOT persisted \
                 (in-memory dev backend); everything here is lost on restart, and every \
                 roles_* mutation efun answers `unavailable`"
            );
            loom_persist::spawn_dev_account_worker(DB_QUEUE_DEPTH)
        }
    };

    // OBI-123: the roles snapshot's three refresh triggers (design OBI-36
    // §1 -- boot, `LISTEN roles_changed`, and the earliest grant expiry)
    // plus a fourth (every completed mutation, OBI-120's own AC) all funnel
    // through one task, `run_roles_manager`, which reloads whenever any of
    // them fires and publishes the result on `roles_snapshot_rx` for the
    // world thread to swap in. `roles_reload_tx` is the world thread's
    // side of the fourth trigger (a pulse after every `roles_result`).
    // Neither channel does anything if `persist` is `None`: without
    // Postgres there is no roles schema to load, and `LOOM_ROLES_SEED` (the
    // dev/CI path) is loaded once, synchronously, inside
    // `spawn_world_thread` instead.
    let (roles_snapshot_tx, roles_snapshot_rx) = watch::channel(None);
    let (roles_reload_tx, roles_reload_rx) = mpsc::channel::<()>(1);
    if let Some(p) = persist.clone() {
        tokio::spawn(run_roles_manager(
            p,
            roles_reload_rx,
            roles_snapshot_tx,
            shutdown_rx.clone(),
        ));
    }

    // OBI-123: batch-write the in-memory audit ring (P2+ decisions,
    // denials, `unguarded`, role mutations, and eventually S2c's quota
    // breaches) to the Postgres `audit_log` sink. The world thread computes
    // the rows (it alone can see `World`'s audit state) and hands them,
    // already-owned, to this task once per world tick; a `None` `persist`
    // means there is nowhere to write them, so nothing is spawned and the
    // world thread's `try_send`s are simply never drained (harmless: nothing
    // reads `audit_rx` back, and the channel is bounded).
    let (audit_tx, audit_rx) = mpsc::channel(AUDIT_QUEUE_DEPTH);
    if let Some(p) = persist.clone() {
        tokio::spawn(run_audit_sink(p, audit_rx, shutdown_rx.clone()));
    }

    let world_handle = spawn_world_thread(
        mudlib_root.clone(),
        event_rx,
        command_tx.clone(),
        db_req_tx,
        db_event_rx,
        tick_pending.clone(),
        roles_snapshot_rx,
        roles_reload_tx,
        audit_tx,
        persist.is_some(),
        persist.is_none(),
    )?;

    info!(bind = %actual_addr, http_bind = %http_actual_addr, mudlib = %mudlib_root.display(), "loom server started");

    // Startup (mudlib compiled, DB backend spawned, both listeners bound)
    // is finished by this point -- everything above returned `Ok` via
    // `?`. Flip readiness now so `/readyz` reports 200 as soon as the
    // HTTP server starts accepting connections, not before.
    let readiness = loom_obs::Readiness::new();
    readiness.set_ready();
    let metrics = loom_obs::PrometheusMetrics::install()
        .expect("metrics recorder installed exactly once per process");

    let (ws_accept_tx, ws_accept_rx) = mpsc::channel(WS_ACCEPT_QUEUE_DEPTH);
    let mut http_state = loom_http::HttpState::new(ws_accept_tx, readiness, metrics);
    if let Some(web_root) = web_root_from_env() {
        http_state = http_state.with_web_root(web_root);
    }
    // OBI-174/OBI-199: `/auth/*` only mounted when Postgres, a JWT
    // secret, and a TOTP-at-rest encryption key are all configured --
    // staff web auth has nothing to authenticate against otherwise (no
    // `staff` table without Postgres), must never sign a token with a
    // guessable default secret, and must never fall back to storing a
    // TOTP secret unencrypted (M-AUTH-8).
    if let (Some(p), Some(secret), Some(totp_key)) = (
        persist.clone(),
        jwt_secret_from_env(),
        totp_enc_key_from_env(),
    ) {
        let directory: std::sync::Arc<dyn loom_http::auth::StaffDirectory> = std::sync::Arc::new(p);
        let keys = loom_http::auth::JwtKeys::from_secret(&secret);
        let totp_cipher = loom_http::auth::TotpCipher::new(&totp_key);
        http_state = http_state.with_auth(loom_http::auth::AuthService::new(
            directory,
            keys,
            totp_cipher,
        ));
    } else {
        tracing::info!(
            "staff web auth (/auth/*) disabled: set LOOM_DATABASE_URL (or DATABASE_URL), \
             LOOM_JWT_SECRET, and LOOM_TOTP_ENC_KEY to enable it"
        );
    }
    let mut http_server = tokio::spawn(async move {
        // Same reason as loom-net's telnet accept: WebSocket frames are
        // small interactive writes, so disable Nagle on every HTTP socket.
        let http_listener = axum::serve::ListenerExt::tap_io(http_listener, |tcp| {
            if let Err(err) = tcp.set_nodelay(true) {
                tracing::debug!(%err, "set_nodelay failed on an HTTP connection");
            }
        });
        axum::serve(
            http_listener,
            loom_http::app(http_state)
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .map_err(|err| format!("HTTP server failed: {err}"))
    });

    let mut server = tokio::spawn(loom_net::run_server_with_ws(
        listener,
        NetConfig {
            mssp_fields: vec![
                ("NAME".to_string(), "ObieMud".to_string()),
                ("CODEBASE".to_string(), "Loom".to_string()),
                ("CRAWL_DELAY".to_string(), "-1".to_string()),
            ],
            ..NetConfig::default()
        },
        event_tx.clone(),
        command_rx,
        shutdown_rx.clone(),
        ws_accept_rx,
    ));
    let mut ticker = tokio::spawn(run_world_tick_timer(
        event_tx,
        shutdown_rx,
        tick_pending,
        WORLD_TICK_INTERVAL,
    ));

    tokio::select! {
        result = &mut server => {
            result
                .map_err(|err| format!("network server task failed: {err}"))?
                .map_err(|err| format!("network server failed: {err}"))?;
        }
        result = &mut http_server => {
            result
                .map_err(|err| format!("HTTP server task failed: {err}"))??;
        }
        _ = shutdown_signal() => {
            info!("shutdown signal received");
            let _ = shutdown_tx.send(true);
        }
    }

    let _ = shutdown_tx.send(true);
    if !server.is_finished() {
        server
            .await
            .map_err(|err| format!("network server task failed: {err}"))?
            .map_err(|err| format!("network server failed: {err}"))?;
    }
    http_server.abort();
    let _ = (&mut http_server).await;
    if !ticker.is_finished() {
        let _ = (&mut ticker).await;
    }
    drop(command_tx);

    world_handle
        .join()
        .map_err(|_| "world thread panicked".to_string())?;

    Ok(())
}

pub const DEFAULT_HTTP_ADDR: &str = "0.0.0.0:4001";

/// Bound on in-flight accepted-but-not-yet-registered WebSocket upgrades
/// between `loom-http`'s `/ws` route and `run_server_with_ws`'s accept
/// loop (spec's bounded-queue engineering lens: nothing here is
/// unbounded).
const WS_ACCEPT_QUEUE_DEPTH: usize = 64;

fn http_addr_from_env() -> String {
    std::env::var("LOOM_HTTP_ADDR").unwrap_or_else(|_| DEFAULT_HTTP_ADDR.to_string())
}

/// The built web client's directory (`index.html` + `dist/`), served by
/// `loom-http`'s router fallback (OBI-158). Unset (the default) keeps
/// `/` a plain `404`, matching pre-OBI-158 behaviour for tests and local
/// runs that don't set it.
fn web_root_from_env() -> Option<PathBuf> {
    std::env::var_os("LOOM_WEB_ROOT").map(PathBuf::from)
}

/// Staff web auth's JWT signing secret (OBI-174, design §9/D-P2.5).
/// `/auth/*` is only mounted when this is set *and* Postgres
/// (`connect_persist`) is configured -- same "absent by default" shape as
/// `LOOM_WEB_ROOT`. There is no insecure default: an operator who wants
/// staff auth must generate and set a real secret (at least 32 bytes of
/// CSPRNG output, e.g. `openssl rand -hex 32`) themselves.
fn jwt_secret_from_env() -> Option<Vec<u8>> {
    std::env::var("LOOM_JWT_SECRET")
        .ok()
        .map(String::into_bytes)
}

/// The TOTP-at-rest encryption key (OBI-199, design threat-model-
/// phase2.md §6.1 M-AUTH-8: "Store the secret encrypted ... under a key
/// from the secret file"). `/auth/*` is only mounted when this is set
/// *and* `LOOM_JWT_SECRET` *and* Postgres are -- there is no fallback to
/// storing a TOTP secret in plaintext. Must be exactly 64 hex characters
/// (32 bytes of CSPRNG output, e.g. `openssl rand -hex 32`); anything
/// else is treated as absent (never silently truncated/padded).
fn totp_enc_key_from_env() -> Option<[u8; 32]> {
    let hex = std::env::var("LOOM_TOTP_ENC_KEY").ok()?;
    let bytes = hex_decode(hex.trim())?;
    bytes.try_into().ok()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// The `serve()` world-tick timer (spec r5 N2, OBI-82): every `interval`
/// (`WORLD_TICK_INTERVAL`, 100 ms, in production; a shorter one in tests),
/// send one `NetEvent::Tick` so the world thread advances `World::tick`. No
/// busy-wait: `tokio::time::interval` parks the task between ticks.
/// `tick_pending` is shared with the world thread (cleared there right
/// after `World::tick` returns, see `spawn_world_thread`): if the world
/// thread is still catching up on the previous tick (a slow callback, GC
/// pause, ...) the flag is still `true` and this loop skips sending
/// another `Tick` for that interval instead of queuing one up -- at most
/// one `Tick` is ever in-flight (queued in `event_tx` or being processed),
/// so a world thread that falls behind coalesces missed ticks instead of
/// racing to drain an unbounded backlog of them once it catches up.
async fn run_world_tick_timer(
    event_tx: mpsc::Sender<NetEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
    tick_pending: Arc<AtomicBool>,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            _ = ticker.tick() => {
                if tick_pending.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok()
                    && event_tx.send(NetEvent::Tick).await.is_err()
                {
                    break;
                }
                // else: either the previous Tick has not been processed yet
                // (coalesce by skipping this one), or the event channel is
                // gone (shutting down).
            }
        }
    }
}

/// Spawn the world thread. The `World` is not `Send` (single-threaded heap,
/// spec §3.3), so it is booted *on* the world thread; boot errors are
/// reported back before we start accepting connections.
/// Connect to Postgres for the account/roles/audit backends (spec OBI-85,
/// design OBI-36 D-S2.1/D-S2.2/D-S2.5). `None` means the in-memory dev
/// backend (`loom-persist::spawn_dev_account_worker`) is used instead:
/// nothing here survives a restart, roles mutations always answer
/// `"unavailable"`, and there is no `audit_log` sink -- what CI (sans the
/// Postgres service) and a bare `cargo run` use.
///
/// OBI-151: local/interactive smoke runs (an agent's shell running `loom
/// serve` directly, not through a real deployment) must opt in explicitly
/// via `LOOM_SMOKE_DATABASE_URL` -- never via the ambient `DATABASE_URL`
/// that agent shells export for Paperclip's own control-plane DB (OBI-150).
/// `DATABASE_URL` is still honoured as a fallback because that is the real
/// production/staging wiring (the container's own env, not an ambient
/// leak), but [`loom_persist::assert_not_control_plane_db`] (called inside
/// `Persist::connect`) hard-fails either way if the resolved URL still
/// looks like the control-plane DB.
async fn connect_persist() -> Result<Option<Persist>, String> {
    let url = match std::env::var("LOOM_SMOKE_DATABASE_URL") {
        Ok(url) => Some(url),
        Err(_) => std::env::var("DATABASE_URL").ok(),
    };
    match url {
        Some(url) => Persist::connect(&url, 5)
            .await
            .map(Some)
            .map_err(|err| format!("failed to connect to Postgres: {err}")),
        None => Ok(None),
    }
}

/// [`AccountAuth`] wired to whichever `DbRequest` sender [`connect_persist`]'s
/// caller chose: `create_account`/`login` never block the world thread (a
/// `try_send` on a bounded channel, `Err` if it is full or the worker task
/// is gone -- the caller then queues an `"unavailable"` result locally
/// instead of leaving the request pending forever, spec/CTO review OBI-85),
/// and the eventual [`DbEvent::AccountResult`] comes back through the
/// `DbEvent` receiver the world thread drains every loop iteration (see
/// `spawn_world_thread`; once `NetEvent::Tick`, OBI-82, lands, `World::tick`
/// already drains it too -- see `World::tick`'s doc comment).
struct ChannelAccountAuth {
    request_tx: mpsc::Sender<DbRequest>,
}

impl AccountAuth for ChannelAccountAuth {
    fn create_account(&mut self, request_id: u64, name: &str, password: &str) -> bool {
        self.request_tx
            .try_send(DbRequest::CreateAccount {
                correlation_id: request_id,
                username: name.to_string(),
                password: Password::new(password),
            })
            .is_ok()
    }

    fn login(&mut self, request_id: u64, name: &str, password: &str) -> bool {
        self.request_tx
            .try_send(DbRequest::VerifyLogin {
                correlation_id: request_id,
                username: name.to_string(),
                password: Password::new(password),
            })
            .is_ok()
    }
}

/// [`RolesMutations`] wired to the same `DbRequest` sender as
/// [`ChannelAccountAuth`] (OBI-123): every method issues its request with a
/// `try_send` and reports `false` (never blocking, never leaving the
/// request pending forever, same rule as `ChannelAccountAuth`) if the
/// channel is full or the worker task is gone. Answers come back as
/// [`DbEvent::RolesResult`], delivered to `World::deliver_roles_result` by
/// `spawn_world_thread`'s drain loop, which also pulses `reload_tx` so
/// [`run_roles_manager`] reloads the snapshot right after (design OBI-36
/// §1: "after every roles mutation completes").
struct ChannelRolesMutations {
    request_tx: mpsc::Sender<DbRequest>,
}

impl RolesMutations for ChannelRolesMutations {
    fn set_tier(
        &mut self,
        request_id: u64,
        actor: &str,
        target: &str,
        tier: i64,
        reason: &str,
    ) -> bool {
        self.request_tx
            .try_send(DbRequest::RolesSetTier {
                correlation_id: request_id,
                actor: actor.to_string(),
                target: target.to_string(),
                tier,
                reason: reason.to_string(),
            })
            .is_ok()
    }

    fn set_member(
        &mut self,
        request_id: u64,
        actor: &str,
        domain: &str,
        target: &str,
        role: &str,
        reason: &str,
    ) -> bool {
        self.request_tx
            .try_send(DbRequest::RolesSetMember {
                correlation_id: request_id,
                actor: actor.to_string(),
                domain: domain.to_string(),
                target: target.to_string(),
                role: role.to_string(),
                reason: reason.to_string(),
            })
            .is_ok()
    }

    fn grant(
        &mut self,
        request_id: u64,
        actor: &str,
        target: &str,
        kind: &str,
        what: &str,
        expires_at: Option<i64>,
        reason: &str,
    ) -> bool {
        self.request_tx
            .try_send(DbRequest::RolesGrant {
                correlation_id: request_id,
                actor: actor.to_string(),
                target: target.to_string(),
                kind: kind.to_string(),
                what: what.to_string(),
                expires_at,
                reason: reason.to_string(),
            })
            .is_ok()
    }

    fn revoke_grant(
        &mut self,
        request_id: u64,
        actor: &str,
        target: &str,
        kind: &str,
        what: &str,
        reason: &str,
    ) -> bool {
        self.request_tx
            .try_send(DbRequest::RolesRevokeGrant {
                correlation_id: request_id,
                actor: actor.to_string(),
                target: target.to_string(),
                kind: kind.to_string(),
                what: what.to_string(),
                reason: reason.to_string(),
            })
            .is_ok()
    }

    fn propose_tier(
        &mut self,
        request_id: u64,
        actor: &str,
        target: &str,
        tier: i64,
        reason: &str,
    ) -> bool {
        self.request_tx
            .try_send(DbRequest::RolesProposeTier {
                correlation_id: request_id,
                actor: actor.to_string(),
                target: target.to_string(),
                tier,
                reason: reason.to_string(),
            })
            .is_ok()
    }

    fn approve(&mut self, request_id: u64, actor: &str, proposal_id: i64) -> bool {
        self.request_tx
            .try_send(DbRequest::RolesApprove {
                correlation_id: request_id,
                actor: actor.to_string(),
                proposal_id,
            })
            .is_ok()
    }
}

/// Build a [`RolesSnapshot`] from `loom-persist`'s plain-data rows
/// (`Persist::load_roles_snapshot`, OBI-119/S2a): the DB-worker loader half
/// of design OBI-36 §1/D-S2.1. `tier_policy`'s `efun_classes` column is not
/// mapped into the per-tier policy map -- it is a list, not a scalar, and
/// has no reader yet (S2c, OBI-121, is the first consumer of any of
/// `tier_policy`'s columns for enforcement; this loader only has to satisfy
/// today's `roles_policy()`/`policy_row()` readers, which are all scalar).
fn build_roles_snapshot(rows: loom_persist::RolesRows) -> RolesSnapshot {
    let staff = rows
        .staff
        .into_iter()
        .map(|r| (r.uid, r.tier.max(0) as u32))
        .collect();

    let mut domain_members: std::collections::HashMap<
        String,
        std::collections::HashMap<String, loom_vm::DomainRole>,
    > = std::collections::HashMap::new();
    for r in rows.domain_members {
        let role = match r.role.as_str() {
            "lead" => loom_vm::DomainRole::Lead,
            "member" => loom_vm::DomainRole::Member,
            other => {
                warn!(domain = %r.domain, uid = %r.uid, role = other, "unrecognised domain_members.role; skipping");
                continue;
            }
        };
        domain_members
            .entry(r.domain)
            .or_default()
            .insert(r.uid, role);
    }

    let tier_policy = rows
        .tier_policy
        .into_iter()
        .map(|r| {
            let mut cols = std::collections::HashMap::new();
            let mut set = |name: &str, v: Option<i32>| {
                if let Some(v) = v {
                    cols.insert(name.to_string(), v as i64);
                }
            };
            set("max_ticks_exec", r.max_ticks_exec);
            set("max_mem_exec_mb", r.max_mem_exec_mb);
            set("max_objects", r.max_objects);
            set("max_heartbeats", r.max_heartbeats);
            set("max_callouts_obj", r.max_callouts_obj);
            set("max_callouts_uid", r.max_callouts_uid);
            set("disk_quota_mb", r.disk_quota_mb);
            if let Some(v) = r.tick_share_per_min {
                cols.insert("tick_share_per_min".to_string(), v);
            }
            (r.tier.max(0) as u32, cols)
        })
        .collect();

    let grants = rows
        .active_grants
        .into_iter()
        .map(|g| loom_vm::Grant {
            uid: g.uid,
            kind: g.kind,
            target: g.target,
            expires_at: Some(g.expires_at.unix_timestamp()),
        })
        .collect();

    RolesSnapshot::new(staff, domain_members, tier_policy, grants)
}

/// Reload trigger for [`run_roles_manager`]'s loop: which of the three
/// design-note refresh sources (plus the fourth, a completed mutation)
/// woke it up. Used only for `debug!` logging; the loop always reloads
/// regardless of which one fired.
#[derive(Debug, Clone, Copy)]
enum RolesReloadTrigger {
    Boot,
    Notify,
    Mutation,
    Expiry,
    LoadFailedRetry,
    /// The `LISTEN roles_changed` connection was lost (e.g. a Postgres
    /// restart) and is being reconnected in the background (CTO review,
    /// OBI-123 B1) -- the mutation and expiry triggers keep working the
    /// whole time, so this is never a reason to stop refreshing.
    ListenerLost,
    /// `LISTEN roles_changed` just reconnected after [`ListenerLost`](Self::ListenerLost).
    ListenerReconnected,
}

/// The next backoff delay after a failed `LISTEN roles_changed`
/// (re)connect attempt: doubles, capped at [`LISTEN_RETRY_MAX`]. A pure
/// function so the backoff schedule itself is unit-testable without a
/// Postgres connection at all (CTO review, OBI-123 B1's "add a test").
const LISTEN_RETRY_MIN: Duration = Duration::from_secs(1);
const LISTEN_RETRY_MAX: Duration = Duration::from_secs(30);

fn next_listen_backoff(current: Duration) -> Duration {
    (current * 2).min(LISTEN_RETRY_MAX)
}

/// [`run_roles_manager`]'s `LISTEN roles_changed` receiver, when it has
/// one. `None` means the connection is down and being reconnected on a
/// backoff timer; `recv_listen` never resolves in that state (`pending()`),
/// so `tokio::select!` simply never picks that branch until it is `Some`
/// again -- the mutation/expiry branches keep firing normally either way.
async fn recv_listen(rx: &mut Option<mpsc::Receiver<String>>) -> Option<String> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// Owns every refresh trigger for the roles snapshot (design OBI-36 §1,
/// wired by OBI-123): boot (the first loop iteration), `LISTEN
/// roles_changed` (`listen_roles_changed`), a pulse on `reload_rx` after
/// every completed `roles_*` mutation (the fourth trigger, from
/// `spawn_world_thread`'s drain loop), and a timer at the earliest
/// `expires_at` among the grants in the snapshot just loaded. Publishes
/// every successful reload on `snapshot_tx`, a [`watch`] channel so the
/// world thread only ever sees the latest snapshot, never a backlog of
/// stale ones.
///
/// **Never permanently stops refreshing except on shutdown** (CTO review,
/// OBI-123 B1): a `LISTEN` failure at boot, or the listener connection
/// dropping later (e.g. a Postgres restart), no longer ends the loop --
/// `RolesSnapshot::has_grant`'s own `expires_at` check (B2) is only
/// defence in depth, not a substitute for actually refreshing, so a
/// snapshot that never reloads again would otherwise fail open forever on
/// every *other* kind of change (a demotion, a revoked grant that hasn't
/// hit its own `expires_at` yet, ...). The boot load always runs, `LISTEN`
/// reconnects on an exponential backoff
/// ([`next_listen_backoff`], capped at [`LISTEN_RETRY_MAX`]) while the
/// mutation and expiry triggers keep working the whole time, and every
/// successful (re)connect forces an immediate reload.
async fn run_roles_manager(
    persist: Persist,
    mut reload_rx: mpsc::Receiver<()>,
    snapshot_tx: watch::Sender<Option<std::sync::Arc<RolesSnapshot>>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut listen_rx = match persist.listen_roles_changed().await {
        Ok(rx) => Some(rx),
        Err(err) => {
            warn!(error = %err, "LISTEN roles_changed failed at boot; retrying in the background -- the boot load and the mutation/expiry triggers are unaffected");
            None
        }
    };
    let mut listen_backoff = LISTEN_RETRY_MIN;

    let mut trigger = RolesReloadTrigger::Boot;
    loop {
        match persist.load_roles_snapshot().await {
            Ok(rows) => {
                debug!(?trigger, "roles snapshot reloaded");
                let earliest = rows.earliest_grant_expiry;
                let snap = build_roles_snapshot(rows);
                if snapshot_tx.send(Some(std::sync::Arc::new(snap))).is_err() {
                    return; // world thread is gone
                }
                let sleep_for = earliest
                    .map(|t| t - OffsetDateTime::now_utc())
                    .map(|d| Duration::from_secs_f64(d.as_seconds_f64().max(0.0)))
                    .unwrap_or(Duration::from_secs(3600));
                tokio::select! {
                    _ = shutdown_rx.changed() => break,
                    payload = recv_listen(&mut listen_rx) => {
                        match payload {
                            Some(table) => {
                                debug!(table = %table, "roles_changed notify");
                                trigger = RolesReloadTrigger::Notify;
                            }
                            None => {
                                warn!("roles_changed LISTEN connection lost; reconnecting in the background");
                                listen_rx = None;
                                listen_backoff = LISTEN_RETRY_MIN;
                                trigger = RolesReloadTrigger::ListenerLost;
                            }
                        }
                    }
                    _ = reload_rx.recv() => trigger = RolesReloadTrigger::Mutation,
                    _ = tokio::time::sleep(sleep_for) => trigger = RolesReloadTrigger::Expiry,
                    _ = tokio::time::sleep(listen_backoff), if listen_rx.is_none() => {
                        match persist.listen_roles_changed().await {
                            Ok(rx) => {
                                listen_rx = Some(rx);
                                listen_backoff = LISTEN_RETRY_MIN;
                                trigger = RolesReloadTrigger::ListenerReconnected;
                            }
                            Err(err) => {
                                warn!(error = %err, backoff = ?listen_backoff, "LISTEN roles_changed reconnect failed; backing off");
                                listen_backoff = next_listen_backoff(listen_backoff);
                            }
                        }
                    }
                }
            }
            Err(err) => {
                error!(error = %err, "load_roles_snapshot failed; retrying in 5s");
                trigger = RolesReloadTrigger::LoadFailedRetry;
                tokio::select! {
                    _ = shutdown_rx.changed() => break,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
            }
        }
    }
}

/// Batch-write the in-memory audit ring to the `audit_log` Postgres sink
/// (design OBI-36 §5/D-S2.5, wired by OBI-123): drains whatever
/// `spawn_world_thread` hands it (already-owned rows, computed on the world
/// thread from `World::drain_audit_since`) and appends each batch in one
/// round trip (`Persist::insert_audit_batch`). A failed batch is logged and
/// dropped -- the audit ring itself is still the source of truth and keeps
/// its own bounded history, so losing one batch to a transient DB error is
/// preferable to blocking the world thread or retrying forever.
async fn run_audit_sink(
    persist: Persist,
    mut audit_rx: mpsc::Receiver<Vec<loom_vm::AuditRow>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            batch = audit_rx.recv() => {
                let Some(batch) = batch else { break };
                let rows: Vec<loom_persist::AuditRow> = batch.into_iter().map(to_persist_audit_row).collect();
                if let Err(err) = persist.insert_audit_batch(&rows).await {
                    warn!(error = %err, dropped = rows.len(), "audit_log insert failed; batch dropped");
                }
            }
        }
    }
}

fn to_persist_audit_row(r: loom_vm::AuditRow) -> loom_persist::AuditRow {
    // CTO review (OBI-123 N2): `at` is the decision's own timestamp
    // (`AuditEntry::push`'s, stamped on the world thread when the
    // decision was made), not `now_utc()` here -- this function can run
    // arbitrarily later than the decision if `run_audit_sink` is behind.
    let at = OffsetDateTime::from_unix_timestamp_nanos(r.at_unix_ms as i128 * 1_000_000)
        .unwrap_or_else(|_| OffsetDateTime::now_utc());
    loom_persist::AuditRow {
        at,
        kind: r.kind.to_string(),
        caller: r.caller,
        effective_principal: r.effective_principal,
        apply: Some(r.apply.to_string()),
        class: Some(r.class),
        argument: Some(r.argument),
        guard_set: r.guard_set,
        verdict: if r.allowed { "allow" } else { "deny" }.to_string(),
        detail: r.detail,
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_world_thread(
    mudlib_root: PathBuf,
    mut event_rx: mpsc::Receiver<NetEvent>,
    command_tx: mpsc::Sender<NetCommand>,
    db_req_tx: mpsc::Sender<DbRequest>,
    mut db_event_rx: mpsc::Receiver<DbEvent>,
    tick_pending: Arc<AtomicBool>,
    mut roles_snapshot_rx: watch::Receiver<Option<std::sync::Arc<RolesSnapshot>>>,
    roles_reload_tx: mpsc::Sender<()>,
    audit_tx: mpsc::Sender<Vec<loom_vm::AuditRow>>,
    has_audit_sink: bool,
    load_roles_seed: bool,
) -> Result<thread::JoinHandle<()>, String> {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let handle = thread::Builder::new()
        .name("loom-world".to_string())
        .spawn(move || {
            let mut world = match World::boot(&mudlib_root) {
                Ok(world) => world,
                Err(err) => {
                    let _ = ready_tx.send(Err(format!("world boot failed: {err}")));
                    return;
                }
            };
            // OBI-123: without Postgres (`persist` was `None`), `LOOM_ROLES_SEED`
            // is the dev/CI path (`crate::roles::load_seed_from_env`'s doc): a
            // set-but-malformed seed is a boot failure, never a silent empty
            // snapshot. With Postgres, the real snapshot arrives asynchronously
            // through `roles_snapshot_rx` shortly after boot (`run_roles_manager`'s
            // first load) -- until then, `World::boot`'s tier-0-for-everyone
            // default is in effect, same as every other `World::boot` caller
            // before OBI-36.
            if load_roles_seed {
                match loom_vm::roles::load_seed_from_env() {
                    None => {}
                    Some(Ok(seed)) => world.set_roles_snapshot(std::sync::Arc::new(seed)),
                    Some(Err(err)) => {
                        let _ = ready_tx.send(Err(format!("LOOM_ROLES_SEED: {err}")));
                        return;
                    }
                }
            }
            let _ = ready_tx.send(Ok(()));
            world.set_account_auth(Box::new(ChannelAccountAuth {
                request_tx: db_req_tx.clone(),
            }));
            world.set_roles_backend(Box::new(ChannelRolesMutations {
                request_tx: db_req_tx,
            }));
            let mut host = NetHost { command_tx };
            let mut audit_cursor: u64 = 0;
            // CTO review (OBI-123 N1): rate-limit the "batch dropped"
            // warning below to at most once per interval -- a full/closed
            // `audit_tx` is expected to fail closed-loop for a while under
            // sustained backpressure, and logging every single tick's drop
            // in that case would itself be a (smaller) flood.
            let mut last_audit_drop_warn: Option<std::time::Instant> = None;
            const AUDIT_DROP_WARN_INTERVAL: Duration = Duration::from_secs(30);

            // OBI-85/OBI-123: drain any `account_create`/`account_login`/
            // `roles_*` result that has come back since the last time we
            // looked, on every loop iteration -- once `NetEvent::Tick`
            // (OBI-82) lands, an idle server will also flush this on every
            // tick, since `World::tick` calls `World::drain_account_results`/
            // `World::drain_roles_results` itself.
            let mut drain_db_events = |world: &mut World, host: &mut NetHost| {
                while let Ok(event) = db_event_rx.try_recv() {
                    match event {
                        DbEvent::AccountResult {
                            correlation_id,
                            ok,
                            detail,
                        } => {
                            world.deliver_account_result(correlation_id, ok, &detail);
                        }
                        DbEvent::RolesResult {
                            correlation_id,
                            ok,
                            detail,
                        } => {
                            world.deliver_roles_result(correlation_id, ok, &detail);
                            // Design OBI-36 §1's fourth refresh trigger: reload
                            // right after a completed mutation. `try_send`:
                            // a reload already pending (channel full) covers
                            // this one too, and `run_roles_manager` may not
                            // even be running (no Postgres) -- either way
                            // this must never block the world thread.
                            let _ = roles_reload_tx.try_send(());
                        }
                        // `DbEvent::SleepDone`/`QueryFailed` are R2's own
                        // diagnostics, not surfaced to the world.
                        DbEvent::SleepDone { .. } | DbEvent::QueryFailed { .. } => {}
                    }
                }
                world.drain_account_results(host);
                world.drain_roles_results(host);
            };

            while let Some(event) = event_rx.blocking_recv() {
                match event {
                    NetEvent::Connected(conn) => world.connect(conn, &mut host),
                    NetEvent::Line(conn, line) => world.input(conn, &line, &mut host),
                    NetEvent::Disconnected(conn) => world.disconnect(conn, &mut host),
                    NetEvent::Tick => {
                        world.tick(&mut host);
                        // Cleared only after `World::tick` returns: the
                        // timer must not queue up a second `Tick` while
                        // this one is still (synchronously) running, so
                        // this is the coalescing boundary, not just a
                        // "received" acknowledgement.
                        tick_pending.store(false, Ordering::Release);

                        // OBI-123 D-S2.5: once per world tick, flush any
                        // audit entries recorded since the last flush.
                        // Skipped entirely when there is no sink at all
                        // (`has_audit_sink` false: no `DATABASE_URL`) --
                        // nothing would ever drain `audit_tx` anyway (CTO
                        // review N1). A full/closed `audit_tx` with a real
                        // sink (the sink task fell behind, or the process
                        // is shutting down) drops this batch, logged at a
                        // rate limit -- the audit ring itself still has it,
                        // up to its own bound.
                        if has_audit_sink {
                            let (rows, cursor) = world.drain_audit_since(audit_cursor);
                            audit_cursor = cursor;
                            if !rows.is_empty() && audit_tx.try_send(rows).is_err() {
                                let now = std::time::Instant::now();
                                if last_audit_drop_warn
                                    .is_none_or(|t| now.duration_since(t) >= AUDIT_DROP_WARN_INTERVAL)
                                {
                                    warn!(
                                        "audit_log batch dropped: run_audit_sink is full or gone \
                                         (further drops suppressed for {AUDIT_DROP_WARN_INTERVAL:?})"
                                    );
                                    last_audit_drop_warn = Some(now);
                                }
                            }
                        }
                    }
                    // NAWS/TTYPE/GMCP hooks into the world (efun-visible
                    // state, `Char.*` driving game logic) are OBI-26
                    // follow-up work; for the alpha the driver just logs
                    // them so the wire protocol and tests are exercised
                    // end to end without a `World`/`Host` seam change.
                    NetEvent::WindowSize(conn, width, height) => {
                        info!(conn, width, height, "NAWS window size");
                    }
                    NetEvent::TerminalType(conn, name) => {
                        info!(conn, %name, "TTYPE terminal type");
                    }
                    NetEvent::Gmcp(conn, msg) => {
                        // `debug!`, module name only: GMCP payloads are
                        // client-controlled JSON that routinely carries
                        // credentials (e.g. `Char.Login {"name":...,
                        // "password":...}`), so logging the payload itself
                        // at `info` would put passwords in logs. This is
                        // one line per client frame either way, which is
                        // debug-log territory, not info-log territory.
                        let module = match &msg {
                            GmcpMessage::CoreHello { .. } => "Core.Hello",
                            GmcpMessage::CoreSupportsSet(_) => "Core.Supports.Set",
                            GmcpMessage::CoreSupportsAdd(_) => "Core.Supports.Add",
                            GmcpMessage::CoreSupportsRemove(_) => "Core.Supports.Remove",
                            GmcpMessage::Package { module, .. } => module.as_str(),
                        };
                        debug!(conn, module, "GMCP message");
                    }
                }
                // OBI-123: the roles snapshot's own swap-in point -- checked
                // every loop iteration (cheap: `watch::Receiver::has_changed`
                // never awaits), so a reload from `run_roles_manager` takes
                // effect on the very next event, not just on a tick.
                if roles_snapshot_rx.has_changed().unwrap_or(false)
                    && let Some(snap) = roles_snapshot_rx.borrow_and_update().clone()
                {
                    world.set_roles_snapshot(snap);
                }
                drain_db_events(&mut world, &mut host);
            }
        })
        .map_err(|err| format!("failed to spawn world thread: {err}"))?;
    ready_rx
        .recv()
        .map_err(|_| "world thread exited during boot".to_string())??;
    Ok(handle)
}

struct NetHost {
    command_tx: mpsc::Sender<NetCommand>,
}

impl Host for NetHost {
    fn send(&mut self, conn: u64, text: &str) {
        let _ = self
            .command_tx
            .blocking_send(NetCommand::Send(conn, text.to_string()));
    }

    fn close(&mut self, conn: u64) {
        let _ = self.command_tx.blocking_send(NetCommand::Close(conn));
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");

        tokio::select! {
            _ = sigint.recv() => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod probe_tests {
    use super::probe;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// `loom probe tcp://host:port` (R6, OBI-42): a bare connect succeeds
    /// against any listener, and fails once nothing is listening on that
    /// port. This is the interim `loom` container healthcheck until
    /// `loom-http` ships a real `/healthz`.
    #[test]
    fn tcp_probe_succeeds_against_a_listener_and_fails_once_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        // Accept (and drop) one connection per probe so the listener
        // backlog doesn't matter.
        let accept_thread = std::thread::spawn(move || {
            let _ = listener.accept();
        });
        assert!(probe(&format!("tcp://{addr}")).is_ok());
        accept_thread.join().expect("accept thread");

        // Nothing is listening on this port now: connect must fail.
        assert!(probe(&format!("tcp://{addr}")).is_err());
    }

    /// `loom probe http://host:port/path` succeeds only on a genuine `2xx`
    /// status line, and fails on a non-2xx response. Exercised against a
    /// hand-rolled one-shot HTTP responder, since `loom-http` does not
    /// exist yet.
    #[test]
    fn http_probe_checks_the_status_line() {
        for (status_line, expect_ok) in [("HTTP/1.1 200 OK", true), ("HTTP/1.1 503 Busy", false)] {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            let body = format!("{status_line}\r\nContent-Length: 0\r\n\r\n");
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                stream.write_all(body.as_bytes()).expect("write response");
            });
            let result = probe(&format!("http://{addr}/healthz"));
            server.join().expect("server thread");
            assert_eq!(result.is_ok(), expect_ok, "status line: {status_line}");
        }
    }

    #[test]
    fn unsupported_scheme_is_an_error() {
        assert!(probe("ftp://127.0.0.1:9").is_err());
    }

    #[test]
    fn missing_scheme_is_an_error() {
        assert!(probe("127.0.0.1:9").is_err());
    }
}

#[cfg(test)]
mod account_auth_tests {
    use super::*;

    /// CTO review (OBI-85): a zero-capacity channel is always full, so
    /// `try_send` always fails and `ChannelAccountAuth` must report that
    /// as `false` (never block, never panic).
    #[test]
    fn zero_capacity_channel_reports_failure_not_a_block() {
        let (tx, _rx) = mpsc::channel(1);
        // Fill the one slot so the next `try_send` is guaranteed to see
        // `Full`, deterministically, instead of racing a zero-capacity
        // channel's exact semantics.
        tx.try_send(DbRequest::Sleep {
            correlation_id: 0,
            duration_ms: 0,
        })
        .expect("fill the one slot");

        let mut auth = ChannelAccountAuth { request_tx: tx };
        assert!(!auth.create_account(1, "legolas", "hunter2pass"));
        assert!(!auth.login(2, "legolas", "hunter2pass"));
    }

    /// A closed channel (the worker task is gone) must also report
    /// failure, not panic.
    #[test]
    fn closed_channel_reports_failure_not_a_panic() {
        let (tx, rx) = mpsc::channel(8);
        drop(rx);

        let mut auth = ChannelAccountAuth { request_tx: tx };
        assert!(!auth.create_account(1, "legolas", "hunter2pass"));
        assert!(!auth.login(2, "legolas", "hunter2pass"));
    }
}

#[cfg(test)]
mod tick_timer_tests {
    use super::*;

    /// A `Tick` fires every interval when something (standing in for the
    /// world thread) clears `tick_pending` promptly, i.e. the timer does
    /// not stall just because it *can* coalesce.
    #[tokio::test(start_paused = true)]
    async fn sends_one_tick_per_interval_when_promptly_cleared() {
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let tick_pending = Arc::new(AtomicBool::new(false));
        let interval = Duration::from_millis(10);

        let handle = tokio::spawn(run_world_tick_timer(
            event_tx,
            shutdown_rx,
            tick_pending.clone(),
            interval,
        ));

        for _ in 0..5 {
            tokio::time::advance(interval).await;
            let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
                .await
                .expect("timed out waiting for Tick")
                .expect("event channel closed");
            assert_eq!(event, NetEvent::Tick);
            // Stand in for the world thread finishing `World::tick`.
            tick_pending.store(false, Ordering::Release);
        }

        handle.abort();
    }

    /// Bounded coalescing (OBI-82 acceptance criterion): if `tick_pending`
    /// is never cleared (the world thread never catches up), letting many
    /// intervals elapse must still leave at most one `Tick` sitting in the
    /// channel -- not one per missed interval.
    #[tokio::test(start_paused = true)]
    async fn falling_behind_never_queues_more_than_one_pending_tick() {
        let (event_tx, mut event_rx) = mpsc::channel(64);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let tick_pending = Arc::new(AtomicBool::new(false));
        let interval = Duration::from_millis(10);

        let handle = tokio::spawn(run_world_tick_timer(
            event_tx,
            shutdown_rx,
            tick_pending.clone(),
            interval,
        ));

        // Let 50 intervals' worth of (virtual) time pass without ever
        // clearing `tick_pending`: an unbounded design would queue up to
        // 50 `Tick`s; a coalescing one sends exactly the first and then
        // skips the rest.
        tokio::time::advance(interval * 50).await;
        tokio::task::yield_now().await;

        let first = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .expect("timed out waiting for the first Tick")
            .expect("event channel closed");
        assert_eq!(first, NetEvent::Tick);

        // Nothing else should be queued behind it.
        assert!(
            event_rx.try_recv().is_err(),
            "a second Tick was queued while the first was still pending: coalescing is not bounded"
        );

        // Now let the (still-pending) world catch up: only after that does
        // the next Tick get sent, and still only one at a time.
        tick_pending.store(false, Ordering::Release);
        tokio::time::advance(interval).await;
        let second = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .expect("timed out waiting for the second Tick")
            .expect("event channel closed");
        assert_eq!(second, NetEvent::Tick);
        assert!(event_rx.try_recv().is_err());

        handle.abort();
    }
}

#[cfg(test)]
mod roles_manager_tests {
    use super::*;

    /// CTO review (OBI-123 B1): the reconnect backoff must actually grow
    /// (never immediately hammer a down Postgres in a tight loop) and
    /// must be bounded (never grow unbounded either). A pure function,
    /// deliberately: the full async reconnect behaviour needs a real
    /// Postgres connection to exercise end to end (covered by
    /// `loom-cli/tests/roles_demo.rs`'s Postgres-backed tests for the
    /// happy path), but the backoff schedule itself does not, and is
    /// exactly the part most likely to have an off-by-one/unbounded-growth
    /// bug.
    #[test]
    fn listen_backoff_doubles_and_caps_at_the_max() {
        let mut backoff = LISTEN_RETRY_MIN;
        assert_eq!(backoff, Duration::from_secs(1));
        backoff = next_listen_backoff(backoff);
        assert_eq!(backoff, Duration::from_secs(2));
        backoff = next_listen_backoff(backoff);
        assert_eq!(backoff, Duration::from_secs(4));
        backoff = next_listen_backoff(backoff);
        assert_eq!(backoff, Duration::from_secs(8));
        backoff = next_listen_backoff(backoff);
        assert_eq!(backoff, Duration::from_secs(16));
        backoff = next_listen_backoff(backoff);
        assert_eq!(backoff, LISTEN_RETRY_MAX, "32s would exceed the 30s cap");
        // Stays capped, does not keep growing past it.
        for _ in 0..5 {
            backoff = next_listen_backoff(backoff);
            assert_eq!(backoff, LISTEN_RETRY_MAX);
        }
    }

    /// `recv_listen` must never resolve while the receiver is `None` --
    /// otherwise a `tokio::select!` arm on it would busy-loop instead of
    /// genuinely waiting for either a real notification or the reconnect
    /// timer.
    #[tokio::test(start_paused = true)]
    async fn recv_listen_never_resolves_with_no_receiver() {
        let mut rx: Option<mpsc::Receiver<String>> = None;
        let raced = tokio::select! {
            _ = recv_listen(&mut rx) => "recv_listen resolved",
            _ = tokio::time::sleep(Duration::from_secs(3600)) => "timer won",
        };
        assert_eq!(raced, "timer won");
    }
}
