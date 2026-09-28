// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `loom` command-line entry point (`serve`, `check`, ...).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use loom_net::{GmcpMessage, NetCommand, NetConfig, NetEvent};
use loom_persist::{DbEvent, DbRequest, Password};
use loom_vm::{AccountAuth, Host, World};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

const EVENT_CHANNEL_CAPACITY: usize = 1024;
const COMMAND_CHANNEL_CAPACITY: usize = 1024;
/// Bound on in-flight `account_create`/`account_login` requests (spec's
/// bounded-queue engineering lens): past this many outstanding DB/dev-
/// backend requests, [`ChannelAccountAuth`]'s `try_send` starts failing
/// (never blocking the world thread; see its doc), and
/// `World::issue_account_request` immediately queues an `"unavailable"`
/// `account_result` instead of leaving the request pending forever.
const ACCOUNT_QUEUE_DEPTH: usize = 256;

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
        other => Err(format!("unknown command: {other}")),
    }
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

    let (account_req_tx, account_event_rx) = spawn_account_backend().await?;

    let world_handle = spawn_world_thread(
        mudlib_root.clone(),
        event_rx,
        command_tx.clone(),
        account_req_tx,
        account_event_rx,
        tick_pending.clone(),
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
    let http_state = loom_http::HttpState::new(ws_accept_tx, readiness, metrics);
    let mut http_server = tokio::spawn(async move {
        axum::serve(http_listener, loom_http::app(http_state))
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
/// Wire up the `account_create`/`account_login` backend (spec, OBI-85):
/// Postgres via `loom-persist`'s R2 DB worker if `DATABASE_URL` is set,
/// else the in-memory dev backend (same Argon2 hashing, nothing survives
/// a restart) -- what CI and the R4 load bot use.
async fn spawn_account_backend()
-> Result<(mpsc::Sender<DbRequest>, mpsc::Receiver<DbEvent>), String> {
    match std::env::var("DATABASE_URL") {
        Ok(url) => {
            let persist = loom_persist::Persist::connect(&url, 5)
                .await
                .map_err(|err| format!("failed to connect DATABASE_URL: {err}"))?;
            Ok(loom_persist::spawn_db_worker(persist, ACCOUNT_QUEUE_DEPTH))
        }
        Err(_) => {
            warn!(
                "DATABASE_URL is not set: accounts are NOT persisted (in-memory dev backend); \
                 every account is lost on restart"
            );
            Ok(loom_persist::spawn_dev_account_worker(ACCOUNT_QUEUE_DEPTH))
        }
    }
}

/// [`AccountAuth`] wired to whichever `DbRequest` sender
/// [`spawn_account_backend`] chose: `create_account`/`login` never block
/// the world thread (a `try_send` on a bounded channel, `Err` if it is
/// full or the worker task is gone -- the caller then queues an
/// `"unavailable"` result locally instead of leaving the request pending
/// forever, spec/CTO review OBI-85), and the eventual
/// [`DbEvent::AccountResult`] comes back through the `DbEvent` receiver
/// the world thread drains every loop iteration (see `spawn_world_thread`;
/// once `NetEvent::Tick`, OBI-82, lands, `World::tick` already drains it
/// too -- see `World::tick`'s doc comment).
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

fn spawn_world_thread(
    mudlib_root: PathBuf,
    mut event_rx: mpsc::Receiver<NetEvent>,
    command_tx: mpsc::Sender<NetCommand>,
    account_req_tx: mpsc::Sender<DbRequest>,
    mut account_event_rx: mpsc::Receiver<DbEvent>,
    tick_pending: Arc<AtomicBool>,
) -> Result<thread::JoinHandle<()>, String> {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let handle = thread::Builder::new()
        .name("loom-world".to_string())
        .spawn(move || {
            let mut world = match World::boot(&mudlib_root) {
                Ok(world) => {
                    let _ = ready_tx.send(Ok(()));
                    world
                }
                Err(err) => {
                    let _ = ready_tx.send(Err(format!("world boot failed: {err}")));
                    return;
                }
            };
            world.set_account_auth(Box::new(ChannelAccountAuth {
                request_tx: account_req_tx,
            }));
            let mut host = NetHost { command_tx };

            // OBI-85: drain any `account_create`/`account_login` result
            // that has come back since the last time we looked, on every
            // loop iteration -- once `NetEvent::Tick` (OBI-82) lands, an
            // idle server will also flush this on every tick, since
            // `World::tick` calls `World::drain_account_results` itself.
            let mut drain_account_events = |world: &mut World, host: &mut NetHost| {
                while let Ok(event) = account_event_rx.try_recv() {
                    if let DbEvent::AccountResult {
                        correlation_id,
                        ok,
                        detail,
                    } = event
                    {
                        world.deliver_account_result(correlation_id, ok, &detail);
                    }
                    // `DbEvent::SleepDone`/`QueryFailed` are R2's own
                    // diagnostics, not surfaced to the world; nothing else
                    // uses this worker yet.
                }
                world.drain_account_results(host);
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
                drain_account_events(&mut world, &mut host);
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
