// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `loom` command-line entry point (`serve`, `check`, ...).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use loom_http::admin_query::{
    ADMIN_QUERY_QUEUE_DEPTH, ChannelWorldQuery, ErrorGroup, ObjectVars, VarEntry, WhoEntry,
    WorldQueryRequest,
};
use loom_net::{AdoptedConn, GmcpMessage, NetCommand, NetConfig, NetEvent, ReclaimRequest};
use loom_persist::{DbEvent, DbRequest, Password, Persist};
use loom_vm::{AccountAuth, Host, RolesMutations, RolesSnapshot, Value, World};
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

/// Bound on `reclaim_tx`/`adopt_tx` (OBI-184 copyover-trigger slice): a
/// copyover deliberately quiesces/drains before reclaiming, so this
/// never needs to carry more than one request at a time in practice --
/// sized the same as `AUDIT_QUEUE_DEPTH` for a comfortable margin rather
/// than tuning it tightly against a workload that doesn't exist yet.
const RECLAIM_QUEUE_DEPTH: usize = 64;

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
            let args = parse_serve_args(args)?;
            serve(args.mudlib, args.save_dir, args.adopt_control_fd).await
        }
        "supervise" => {
            let mudlib = parse_mudlib_arg(args)?;
            supervise(mudlib).await
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
    let module = loom_compiler::codegen::compile(&checked.hir, &checked.src)
        .map_err(|e| format!("{normalized}: {e}"))?;
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

/// `loom serve`'s parsed arguments. `adopt_control_fd` is `loom
/// supervise`'s own internal handoff protocol (OBI-184): an inherited,
/// already-open control-socket fd number this `serve` process should wait
/// on (via [`loom_supervise::fdpass::recv_fds`]) for its listening
/// sockets, instead of binding them itself. Not documented as
/// user-facing CLI surface -- it is only ever passed by `loom supervise`
/// itself, to its own spawned standby child, with an fd number that is
/// meaningless to type by hand.
///
/// `save_dir` (OBI-171) overrides [`loom_vm::World`]'s default
/// player-save root -- a `saves` directory beside the mudlib root; see
/// `World::set_save_root`'s docs for why that default deliberately
/// isn't *inside* the mudlib's own Git-backed working tree.
/// `LOOM_SAVE_DIR` is the same override as an environment variable, for
/// Compose/Flux-style deployments that set env vars rather than args;
/// the flag wins if both are given.
struct ServeArgs {
    mudlib: PathBuf,
    save_dir: Option<PathBuf>,
    adopt_control_fd: Option<std::os::fd::RawFd>,
}

fn parse_serve_args(mut args: impl Iterator<Item = String>) -> Result<ServeArgs, String> {
    let mut mudlib: Option<PathBuf> = None;
    let mut save_dir: Option<PathBuf> = None;
    let mut adopt_control_fd: Option<std::os::fd::RawFd> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mudlib" => {
                let Some(path) = args.next() else {
                    return Err("--mudlib requires a value".to_string());
                };
                mudlib = Some(PathBuf::from(path));
            }
            "--save-dir" => {
                let Some(path) = args.next() else {
                    return Err("--save-dir requires a value".to_string());
                };
                save_dir = Some(PathBuf::from(path));
            }
            "--adopt-control-fd" => {
                let Some(value) = args.next() else {
                    return Err("--adopt-control-fd requires a value".to_string());
                };
                adopt_control_fd =
                    Some(value.parse().map_err(|err| {
                        format!("--adopt-control-fd: not a valid fd number: {err}")
                    })?);
            }
            other => return Err(format!("unexpected argument: {other}")),
        }
    }
    if save_dir.is_none()
        && let Some(env_dir) = std::env::var_os("LOOM_SAVE_DIR")
    {
        save_dir = Some(PathBuf::from(env_dir));
    }

    Ok(ServeArgs {
        mudlib: mudlib.ok_or_else(|| "missing required --mudlib <path>".to_string())?,
        save_dir,
        adopt_control_fd,
    })
}

/// `serve()`'s listening sockets, acquired one of two ways (OBI-184):
/// bound fresh (the historical, still-default path -- `adopt_control_fd`
/// is `None`), or adopted from `loom supervise`'s standby hand-off over
/// an inherited control-socket fd. Both paths return live, non-blocking
/// Tokio listeners ready for `axum::serve`/`loom_net::run_server_with_ws`
/// exactly as before; callers downstream of this function never need to
/// know which path was taken.
///
/// The third return value is the control socket itself, kept alive (not
/// dropped once the handoff handshake finishes) when `adopt_control_fd`
/// is `Some` -- `loom supervise` (OBI-184's control-protocol slice) uses
/// it for messages sent *after* startup, not just the one-shot ready/
/// `SCM_RIGHTS` exchange this function itself performs. `None` in the
/// fresh-bind path: there is no supervisor on the other end of anything
/// to receive further messages from.
async fn acquire_listeners(
    adopt_control_fd: Option<std::os::fd::RawFd>,
) -> Result<
    (
        TcpListener,
        TcpListener,
        Option<std::os::unix::net::UnixStream>,
    ),
    String,
> {
    match adopt_control_fd {
        None => {
            let bind_addr = loom_net::telnet_addr_from_env();
            let listener = TcpListener::bind(&bind_addr)
                .await
                .map_err(|err| format!("failed to bind {bind_addr}: {err}"))?;
            let http_bind_addr = http_addr_from_env();
            let http_listener = TcpListener::bind(&http_bind_addr)
                .await
                .map_err(|err| format!("failed to bind {http_bind_addr}: {err}"))?;
            Ok((listener, http_listener, None))
        }
        Some(fd) => {
            // The handshake with `loom supervise` is a handful of
            // blocking syscalls (one `write`, one `recvmsg`) run via
            // `spawn_blocking` so they cannot stall the async runtime's
            // worker threads -- this is a one-time startup cost, not
            // something steady-state traffic ever waits on.
            let (std_telnet, std_http, control) = tokio::task::spawn_blocking(move || {
                use std::io::Write;
                // SAFETY: `fd` is the number `loom supervise` itself
                // passed down via `--adopt-control-fd`, inherited at
                // `exec` specifically because the supervisor cleared its
                // `FD_CLOEXEC` for that purpose (`spawn_and_handoff`) --
                // nothing else in this freshly-exec'd process has opened
                // or wrapped this fd number yet.
                //
                // `loom-cli` otherwise denies `unsafe_code` workspace-wide;
                // this is the one call site that needs the exception
                // (CTO review, OBI-184/OBI-225: the safety argument above
                // depends on *how this process was invoked*, which only
                // this call site -- not `loom-supervise::listener` itself
                // -- actually knows).
                #[allow(unsafe_code)]
                let mut control =
                    unsafe { loom_supervise::listener::control_stream_from_raw_fd(fd) }
                        .map_err(|err| format!("adopt-control-fd: adopt control socket: {err}"))?;
                // Tell `loom supervise` we're ready to receive the
                // listening sockets ...
                control
                    .write_all(b"R")
                    .map_err(|err| format!("adopt-control-fd: ready signal: {err}"))?;
                // ... then block for its SCM_RIGHTS reply: exactly two
                // fds, telnet first then HTTP -- a fixed, out-of-band-
                // agreed order (see `loom_supervise::fdpass`'s module doc
                // for why there's no self-describing framing on the
                // wire).
                //
                // TODO(OBI-184 abort/fallback slice): neither this call
                // nor the `read_exact` on the supervisor's side
                // (`spawn_and_handoff`) has a timeout, so a standby/
                // supervisor that hangs mid-handshake blocks the other
                // side forever. Acceptable for this slice (no
                // already-running-process copyover to abort out of yet);
                // needs `set_read_timeout` on both ends before this
                // becomes part of a real copyover against a live old
                // process (CTO review, OBI-225).
                let fds = loom_supervise::fdpass::recv_fds(&control)
                    .map_err(|err| format!("adopt-control-fd: recv_fds: {err}"))?;
                let [telnet_fd, http_fd]: [std::os::fd::OwnedFd; 2] =
                    fds.try_into().map_err(|fds: Vec<_>| {
                        format!(
                            "adopt-control-fd: expected 2 fds (telnet, http), got {}",
                            fds.len()
                        )
                    })?;
                let telnet = loom_supervise::listener::adopt_tcp_listener(telnet_fd)
                    .map_err(|err| format!("adopt-control-fd: adopt telnet listener: {err}"))?;
                let http = loom_supervise::listener::adopt_tcp_listener(http_fd)
                    .map_err(|err| format!("adopt-control-fd: adopt HTTP listener: {err}"))?;
                telnet
                    .set_nonblocking(true)
                    .map_err(|err| format!("adopt-control-fd: set_nonblocking (telnet): {err}"))?;
                http.set_nonblocking(true)
                    .map_err(|err| format!("adopt-control-fd: set_nonblocking (http): {err}"))?;
                Ok::<_, String>((telnet, http, control))
            })
            .await
            .map_err(|err| format!("adopt-control-fd: join: {err}"))??;

            let listener = TcpListener::from_std(std_telnet).map_err(|err| {
                format!("adopt-control-fd: tokio TcpListener::from_std (telnet): {err}")
            })?;
            let http_listener = TcpListener::from_std(std_http).map_err(|err| {
                format!("adopt-control-fd: tokio TcpListener::from_std (http): {err}")
            })?;
            Ok((listener, http_listener, Some(control)))
        }
    }
}

/// Runs on its own dedicated `std::thread` (control-socket reads are
/// blocking, and this loop lives for the rest of the process -- not a
/// one-shot `spawn_blocking`): answers `loom supervise`'s post-handoff
/// control messages ([`loom_supervise::control`]) for as long as the
/// control socket stays open.
///
/// **Scope (OBI-184, this slice):** a `CopyoverRequested` now takes a
/// *real* snapshot of this process's own running world (via
/// `snapshot_req_tx`, see `request_snapshot`'s doc) and then reclaims
/// *every* connection `World::live_connections()` reported as live at
/// that same instant (`loom_net::ReclaimRequest`, OBI-94/OBI-221 --
/// previously merged but unreachable from `loom-cli`) and immediately
/// re-adopts each one back into this same process under its original
/// `ConnId` (`loom_net::AdoptedConn`). That reclaim-then-readopt round
/// trip is deliberately a closed loop, not yet "send the reclaimed
/// connection to a standby": it proves `loom-net`'s own reclaim/adopt
/// primitives round-trip a real, live client connection with *no*
/// `NetEvent::Disconnected` anywhere in the middle (the actual
/// requirement §7.5 states: "zero disconnects"), before trusting them to
/// carry a connection across a process boundary in a later, not-yet-
/// built follow-up. A caller who was mid-session when this runs will see
/// their telnet codec state (GMCP/NAWS/echo negotiation) reset, since
/// re-adopting spins up a fresh `run_connection` task for that fd -- a
/// known, already-documented limitation (OBI-227's review), not new
/// here, and still not a disconnect.
fn run_control_responder(
    mut control: std::os::unix::net::UnixStream,
    snapshot_req_tx: std::sync::mpsc::Sender<SnapshotRequest>,
    reclaim_tx: mpsc::Sender<ReclaimRequest>,
    adopt_tx: mpsc::Sender<AdoptedConn>,
) {
    // CTO review (OBI-259): if a message this loop can't make sense of
    // ever arrives (a future, as-yet-undefined variant, or a genuinely
    // malformed stream), `read_message` returns `InvalidData` and this
    // loop exits via the `Err(err)` arm below -- the supervisor then
    // sees that as an EOF/error on its next request and (per its own
    // poisoning rule) stops using this channel rather than desyncing
    // against a reply that was never coming. Nothing special needs to
    // happen here for that case beyond exiting cleanly, which the
    // existing error handling already does.
    loop {
        match loom_supervise::control::read_message(&mut control) {
            Ok(loom_supervise::control::ControlMessage::CopyoverRequested { version }) => {
                info!(
                    version,
                    "loom serve: received a copyover request over the control socket -- \
                     taking a real world snapshot and exercising a reclaim/readopt round trip \
                     on every live connection (OBI-184: still no actual handoff to a standby)"
                );
                let ack_or_nack = match request_snapshot(&snapshot_req_tx) {
                    Ok((bytes, conn_ids)) => {
                        info!(
                            version,
                            snapshot_bytes = bytes.len(),
                            live_connections = conn_ids.len(),
                            "loom serve: world snapshot taken for the copyover request"
                        );
                        match reclaim_and_readopt_all(&reclaim_tx, &adopt_tx, &conn_ids) {
                            Ok(reclaimed) => {
                                info!(
                                    version,
                                    reclaimed,
                                    total = conn_ids.len(),
                                    "loom serve: reclaim/readopt round trip complete for the copyover request"
                                );
                                loom_supervise::control::ControlMessage::CopyoverAck
                            }
                            Err(reason) => {
                                warn!(version, %reason, "loom serve: reclaim/readopt round trip failed for a copyover request");
                                loom_supervise::control::ControlMessage::CopyoverNack { reason }
                            }
                        }
                    }
                    Err(reason) => {
                        warn!(version, %reason, "loom serve: failed to snapshot the world for a copyover request");
                        loom_supervise::control::ControlMessage::CopyoverNack { reason }
                    }
                };
                if let Err(err) = loom_supervise::control::write_message(&mut control, &ack_or_nack)
                {
                    warn!(%err, "loom serve: failed to reply to a copyover request; control responder exiting");
                    return;
                }
            }
            Ok(other) => {
                // The supervisor is only ever a client, never asked to
                // ack/nack anything of its own on this socket -- any
                // other message variant arriving here is out of protocol
                // for this direction.
                warn!(
                    ?other,
                    "loom serve: unexpected control message direction; ignoring"
                );
            }
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                // The supervisor closed its end (process exited, or a
                // copyover replaced it) -- this is an ordinary, expected
                // way for this loop to end, not a failure.
                debug!(
                    "loom serve: control socket closed by supervisor; control responder exiting"
                );
                return;
            }
            Err(err) => {
                warn!(%err, "loom serve: control socket read failed; control responder exiting");
                return;
            }
        }
    }
}

/// How long [`run_control_responder`] waits for the world thread to
/// answer a snapshot request before giving up and `CopyoverNack`ing
/// (CTO review pattern established for `COPYOVER_CONTROL_TIMEOUT`:
/// nothing in this control-protocol path should ever wait unbounded on
/// another thread/process). A world thread that cannot even respond
/// within this long is already in enough trouble that a `Nack` here is
/// the least of its problems -- this bound exists so *this* thread
/// doesn't also wedge waiting on it.
const SNAPSHOT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// CTO review non-blocking item (OBI-180): bounds how many `/api/v1/
/// files/*` file-op requests `spawn_world_thread`'s drain loop runs in
/// one world-tick pass. `loom_http::files::FILE_OP_QUEUE_DEPTH` (64) is
/// the most that could ever be queued; draining all of them unconditionally
/// in one pass is fine today (`read_file`/`write_file` are cheap, and a
/// `Compile` request only ever starts or queues a background compile
/// here -- see [`CompileSlot`] -- it never runs one inline), but the cap
/// is in place so a flood of cheap requests still can't monopolise a
/// tick indefinitely.
const FILE_OPS_PER_TICK_BUDGET: usize = 16;

/// Per-uid compile-queue state for `/api/v1/files/compile` (OBI-180
/// M-FS-5, CTO review of PR #119 on `c29c7a3`, must-fix 2): at most one
/// compile in flight and one queued per uid, tracked on the world
/// thread -- not the HTTP layer, which has no way to see (let alone
/// cancel) work already handed to `loom-vm`'s background compile-worker
/// thread. A newer `/compile` request for a uid that already has one in
/// flight replaces whatever was queued; the displaced request is
/// answered `409` (`FileOpError::Superseded`) immediately, without ever
/// running. When the in-flight compile finishes (`World::
/// take_finished_recompiles`), the queued request (if any) starts next.
#[derive(Default)]
struct CompileSlot {
    /// The compile currently running in the background, and the
    /// `/compile` request whose HTTP caller is waiting on its result.
    in_flight: Option<(
        loom_vm::world::RecompileToken,
        loom_http::files::FileOpRequest,
    )>,
    /// At most one newer request, displacing (with a `409`) whatever
    /// was queued before it.
    queued: Option<(String, loom_http::files::FileOpRequest)>,
}

/// Routes one `FileOpKind::Compile` request into `compile_slots` (CTO
/// review of PR #119, must-fix 2): starts it immediately via
/// `World::begin_file_compile` if nothing is in flight yet for this uid,
/// otherwise queues it -- displacing (with `409`,
/// `FileOpError::Superseded`) whatever request was queued before it, so
/// at most one compile is ever in flight and one queued per uid, no
/// matter how many `/compile` calls for the same uid land before the
/// first one finishes.
fn enqueue_compile(
    world: &mut World,
    host: &mut NetHost,
    compile_slots: &mut std::collections::HashMap<String, CompileSlot>,
    req: loom_http::files::FileOpRequest,
) {
    let uid = req.uid.clone();
    let path = req.path.clone();
    let slot = compile_slots.entry(uid.clone()).or_default();
    if slot.in_flight.is_some() {
        if let Some((_, displaced)) = slot.queued.take() {
            displaced.respond(Err(loom_http::files::FileOpError::Superseded));
        }
        slot.queued = Some((path, req));
    } else {
        match world.begin_file_compile(&uid, &path, host) {
            Ok(token) => slot.in_flight = Some((token, req)),
            Err(msg) => {
                req.respond(Err(loom_http::files::FileOpError::Refused(msg)));
                if slot.queued.is_none() {
                    compile_slots.remove(&uid);
                }
            }
        }
    }
}

/// Starts a queued compile for `uid`, if any, once its slot's previous
/// in-flight compile has finished (`drain_finished_recompiles` empties
/// `in_flight` before calling this). A `begin_file_compile` refusal here
/// (an authorization failure -- the same thing a direct `/compile` call
/// for this uid/path would also get) answers the queued request
/// immediately rather than leaving it stuck.
fn start_queued_compile(world: &mut World, host: &mut NetHost, uid: &str, slot: &mut CompileSlot) {
    let Some((path, req)) = slot.queued.take() else {
        return;
    };
    match world.begin_file_compile(uid, &path, host) {
        Ok(token) => slot.in_flight = Some((token, req)),
        Err(msg) => req.respond(Err(loom_http::files::FileOpError::Refused(msg))),
    }
}

/// Drains every compile `World::take_finished_recompiles` has installed
/// since the last call, answers the waiting `/compile` request for each
/// one, and starts that uid's queued compile (if any) next -- called
/// once per event-loop iteration, same cadence as `drain_db_events`/
/// `drain_admin_queries` (results only actually appear after a `World::
/// tick`, since that is what drives `World::poll_recompiles`, but
/// draining here rather than only on `NetEvent::Tick` costs nothing and
/// keeps this symmetric with the other drains).
fn drain_finished_recompiles(
    world: &mut World,
    host: &mut NetHost,
    compile_slots: &mut std::collections::HashMap<String, CompileSlot>,
) {
    for (token, result) in world.take_finished_recompiles() {
        let Some((uid, mut slot)) = compile_slots
            .iter()
            .find(|(_, slot)| slot.in_flight.as_ref().is_some_and(|(t, _)| *t == token))
            .map(|(uid, _)| uid.clone())
            .and_then(|uid| compile_slots.remove(&uid).map(|slot| (uid, slot)))
        else {
            // No request is waiting on this token (shouldn't happen --
            // every `begin_file_compile` call records its token in
            // exactly one slot's `in_flight` -- but answering nothing is
            // safer than panicking the world thread over a bookkeeping
            // bug).
            continue;
        };
        if let Some((_, req)) = slot.in_flight.take() {
            req.respond(Ok(file_op_value_from_recompile_result(result)));
        }
        start_queued_compile(world, host, &uid, &mut slot);
        if slot.in_flight.is_some() || slot.queued.is_some() {
            compile_slots.insert(uid, slot);
        }
    }
}

#[cfg(test)]
mod compile_queue_tests {
    //! M-FS-5 "one in-flight compile per uid, newest save wins" (CTO
    //! review of PR #119, must-fix 2), exercised against a real
    //! `World`/`enqueue_compile`/`drain_finished_recompiles` -- not a
    //! fake channel -- so these catch a regression in the actual queue
    //! bookkeeping, not just its wire-level status mapping (that part is
    //! covered in `loom-http`'s own tests).
    use super::*;
    use loom_http::files::{
        FileOpError, FileOpKind, FileOpValue, file_op_channel, request_file_op,
    };

    const MASTER: &str = r#"
fn valid_efun(name: string, class: int, ob: object) -> bool {
    return true
}

fn valid_read(path: string, ob: object, op: string) -> bool {
    return true
}

fn valid_write(path: string, ob: object, op: string) -> bool {
    return true
}

fn valid_compile(path: string, ob: object) -> bool {
    return true
}
"#;

    fn scratch(tag: &str) -> PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("loom-cli-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    fn boot(tag: &str) -> (World, NetHost) {
        let root = scratch(tag);
        let master = root.join("secure/master.wf");
        std::fs::create_dir_all(master.parent().unwrap()).unwrap();
        std::fs::write(&master, MASTER).unwrap();
        let prog = root.join("builders/frodo/a.wf");
        std::fs::create_dir_all(prog.parent().unwrap()).unwrap();
        std::fs::write(&prog, "var x: int = 1\n").unwrap();
        let world = World::boot(&root).expect("boot");
        let (command_tx, _command_rx) = mpsc::channel(8);
        (world, NetHost { command_tx })
    }

    /// Sends a `Compile` request on its own thread (mirroring how an
    /// `/api/v1/files/compile` handler really calls `request_file_op`,
    /// via `spawn_blocking`) and hands back the world-thread-side
    /// [`loom_http::files::FileOpRequest`] plus a handle to join for the
    /// eventual HTTP-side result.
    fn fake_compile_request(
        uid: &str,
        path: &str,
    ) -> (
        loom_http::files::FileOpRequest,
        std::thread::JoinHandle<Result<FileOpValue, FileOpError>>,
    ) {
        let (tx, rx) = file_op_channel();
        let uid = uid.to_string();
        let path = path.to_string();
        let handle =
            std::thread::spawn(move || request_file_op(&tx, &uid, &path, FileOpKind::Compile));
        let req = rx.recv().expect("the request we just sent");
        (req, handle)
    }

    /// A second `/compile` for a uid that already has one in flight
    /// queues instead of starting a second background compile; a third
    /// one displaces the second (`409`) rather than stacking up, and
    /// never touches the first (still in-flight) compile.
    #[test]
    fn a_third_request_displaces_the_second_with_409_not_the_first() {
        let (mut world, mut host) = boot("queue-displace");
        let mut compile_slots: std::collections::HashMap<String, CompileSlot> =
            std::collections::HashMap::new();

        let (first, _first_handle) = fake_compile_request("frodo", "/builders/frodo/a");
        enqueue_compile(&mut world, &mut host, &mut compile_slots, first);
        let slot = compile_slots.get("frodo").expect("frodo has a slot");
        let in_flight_token = slot.in_flight.as_ref().map(|(t, _)| *t);
        assert!(
            in_flight_token.is_some(),
            "first request should start a compile"
        );
        assert!(slot.queued.is_none());

        let (second, second_handle) = fake_compile_request("frodo", "/builders/frodo/a");
        enqueue_compile(&mut world, &mut host, &mut compile_slots, second);
        assert!(
            compile_slots.get("frodo").unwrap().queued.is_some(),
            "second request should queue behind the first"
        );

        let (third, _third_handle) = fake_compile_request("frodo", "/builders/frodo/a");
        enqueue_compile(&mut world, &mut host, &mut compile_slots, third);

        assert_eq!(
            second_handle.join().expect("second's thread"),
            Err(FileOpError::Superseded),
            "the displaced second request must answer 409, not run or hang"
        );
        let slot = compile_slots.get("frodo").expect("frodo still has a slot");
        assert_eq!(
            slot.in_flight.as_ref().map(|(t, _)| *t),
            in_flight_token,
            "the original in-flight compile is untouched"
        );
        assert!(slot.queued.is_some(), "the third request is now queued");
    }

    /// Once the in-flight compile finishes, the queued request starts
    /// next -- the uid never runs more than one compile at a time, but
    /// also never silently drops the one request that survived being
    /// queued.
    #[test]
    fn the_queued_request_starts_once_the_in_flight_one_finishes() {
        let (mut world, mut host) = boot("queue-advance");
        let mut compile_slots: std::collections::HashMap<String, CompileSlot> =
            std::collections::HashMap::new();

        let (first, first_handle) = fake_compile_request("frodo", "/builders/frodo/a");
        enqueue_compile(&mut world, &mut host, &mut compile_slots, first);
        let (second, _second_handle) = fake_compile_request("frodo", "/builders/frodo/a");
        enqueue_compile(&mut world, &mut host, &mut compile_slots, second);

        // Wait for the first (real, background) compile to finish.
        let mut drained = false;
        for _ in 0..200 {
            world.tick(&mut host);
            drain_finished_recompiles(&mut world, &mut host, &mut compile_slots);
            if compile_slots
                .get("frodo")
                .is_some_and(|slot| slot.queued.is_none())
            {
                drained = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(drained, "the first compile never finished");
        assert_eq!(
            first_handle.join().expect("first's thread"),
            Ok(FileOpValue::CompileOk)
        );
        let slot = compile_slots
            .get("frodo")
            .expect("the queued request started");
        assert!(
            slot.in_flight.is_some(),
            "the queued request should now be the in-flight one"
        );
    }
}

/// A snapshot-request reply: the encoded world bytes plus the `ConnId`s
/// `World::live_connections()` reported live at that same instant (see
/// `request_snapshot`'s own doc). Named so the channel types that carry
/// it (and the one-shot reply channel for each individual request)
/// don't read as clippy's "very complex type" nested-generic soup.
type SnapshotResult = Result<(Vec<u8>, Vec<u64>), String>;
/// One pending snapshot request: the control responder's reply-to
/// channel, sent to the world thread over `snapshot_req_tx`/`_rx`.
type SnapshotRequest = std::sync::mpsc::Sender<SnapshotResult>;

/// Ask the world thread (via `spawn_world_thread`'s inline `snapshot_
/// req_rx` drain) for a fresh snapshot of its current state plus the
/// `ConnId`s it considers live at that same instant, blocking this
/// (control-responder) thread until it answers or [`SNAPSHOT_REQUEST_
/// TIMEOUT`] elapses.
fn request_snapshot(snapshot_req_tx: &std::sync::mpsc::Sender<SnapshotRequest>) -> SnapshotResult {
    let (reply_tx, reply_rx) = std::sync::mpsc::channel();
    snapshot_req_tx
        .send(reply_tx)
        .map_err(|_| "world thread's snapshot-request channel is gone".to_string())?;
    reply_rx
        .recv_timeout(SNAPSHOT_REQUEST_TIMEOUT)
        .map_err(|err| format!("world thread did not answer the snapshot request: {err}"))?
}

/// Converts a [`Value`] returned by `World::call_file_efun`'s
/// `read_file` into the `Send`-safe [`loom_http::files::FileOpValue`]
/// mirror the file-op reply channel carries (defined in `loom-http`, not
/// here -- see that module's doc for why). `read_file` only ever returns
/// `Null` or a string (see its dispatch in `registry.rs`); anything else
/// is a driver bug, reported as `Err` (CTO review non-blocking item: an
/// earlier cut of this silently coerced an unrecognised shape to
/// `Null`, which the doc comment never actually said it did).
fn file_op_value_from_read(v: Value) -> Result<loom_http::files::FileOpValue, String> {
    use loom_http::files::FileOpValue;
    match v {
        Value::Null => Ok(FileOpValue::Null),
        other => other
            .as_str()
            .map(|s| FileOpValue::Str(s.to_string()))
            .ok_or_else(|| format!("read_file returned an unexpected value: {other:?}")),
    }
}

/// Converts a [`loom_vm::world::FileCasOutcome`] (the result of
/// `World::call_file_write_if_match`) into the matching
/// [`loom_http::files::FileOpValue`].
fn file_op_value_from_cas(
    outcome: loom_vm::world::FileCasOutcome,
) -> loom_http::files::FileOpValue {
    use loom_http::files::FileOpValue;
    use loom_vm::world::FileCasOutcome;
    match outcome {
        FileCasOutcome::Written => FileOpValue::Written,
        FileCasOutcome::QuotaExceeded => FileOpValue::QuotaExceeded,
        FileCasOutcome::PreconditionFailed => FileOpValue::PreconditionFailed,
    }
}

/// Converts a [`World::take_finished_recompiles`] outcome into the
/// matching [`loom_http::files::FileOpValue`] (CTO review of PR #119,
/// must-fix 1: the earlier `file_op_value_from_compile` converted a
/// dynamic `Value` `World::call_file_efun(uid, "compile_object", ..)`
/// returned, which ran the compile synchronously on the world thread --
/// `begin_file_compile`/`take_finished_recompiles` replace that whole
/// path, so there is no longer an "unexpected `Value` shape" case to
/// report as a driver bug (must-fix 3): `Result<(), String>` is
/// total -- `Ok(())` is always a clean compile, `Err` is always the
/// compiler's own diagnostics text (`RegistryHost::finish_recompile`'s
/// doc), never a transport-level surprise.
///
/// Caps `diagnostics` at [`loom_http::files::MAX_DIAGNOSTICS_BYTES`]
/// (CTO review, should-fix 4) -- truncates on a UTF-8 char boundary so
/// the kept prefix is never invalid UTF-8.
fn file_op_value_from_recompile_result(
    result: Result<(), String>,
) -> loom_http::files::FileOpValue {
    use loom_http::files::{FileOpValue, MAX_DIAGNOSTICS_BYTES};
    match result {
        Ok(()) => FileOpValue::CompileOk,
        Err(diagnostics) => {
            if diagnostics.len() <= MAX_DIAGNOSTICS_BYTES {
                FileOpValue::CompileFailed {
                    diagnostics,
                    truncated: false,
                }
            } else {
                let mut cut = MAX_DIAGNOSTICS_BYTES;
                while cut > 0 && !diagnostics.is_char_boundary(cut) {
                    cut -= 1;
                }
                FileOpValue::CompileFailed {
                    diagnostics: diagnostics[..cut].to_string(),
                    truncated: true,
                }
            }
        }
    }
}

/// Converts a [`loom_http::files::FilePrecondition`] (carried over the
/// file-op channel, which holds no `loom_vm` type -- see that module's
/// doc) into the `loom_vm::world::FileMatchPrecondition`
/// `World::call_file_write_if_match` actually takes.
fn vm_precondition_from_http(
    p: &loom_http::files::FilePrecondition,
) -> loom_vm::world::FileMatchPrecondition {
    use loom_http::files::FilePrecondition;
    use loom_vm::world::FileMatchPrecondition;
    match p {
        FilePrecondition::IfMatch(etag) => FileMatchPrecondition::IfMatch(etag.clone()),
        FilePrecondition::IfNoneMatchStar => FileMatchPrecondition::IfNoneMatchStar,
    }
}

/// How long [`reclaim_and_readopt_all`] waits for `loom-net`'s
/// `run_server_full` select loop to answer one reclaim request before
/// moving on to the next connection without counting this one as
/// reclaimed *yet* -- same bounded-wait principle as [`SNAPSHOT_REQUEST_
/// TIMEOUT`]/`COPYOVER_CONTROL_TIMEOUT`: a `run_server_full` task that
/// has wedged on one connection must not be allowed to wedge this whole
/// reclaim pass, and therefore the control responder, indefinitely. A
/// reply that arrives after this elapses is still re-adopted, never
/// dropped -- see [`reclaim_and_readopt_all`]'s own doc comment.
const RECLAIM_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Reclaim every connection in `conn_ids` (via `reclaim_tx`) and
/// immediately re-adopt each one back under the same `ConnId` (via
/// `adopt_tx`) -- see [`run_control_responder`]'s doc comment for why
/// this closed round trip, not yet a real hand-off, is this slice's
/// honest scope. Returns how many connections were confirmed reclaimed
/// and re-adopted *within [`RECLAIM_REQUEST_TIMEOUT`]* (whether or not
/// they were still live to reclaim at all -- a connection that
/// disconnected on its own in the gap between the snapshot and this
/// call is not an error, just one fewer to carry forward, exactly as a
/// real copyover would also need to tolerate).
///
/// **A reclaim reply that arrives *after* the timeout is still re-
/// adopted, never dropped (CTO review, OBI-266/B3):** dropping a
/// `TcpStream` closes the live socket underneath a client who did
/// nothing wrong, and leaves the world's own binding for that `ConnId`
/// pointing at a connection that no longer exists anywhere -- a ghost
/// binding, not a clean disconnect `net_dead()` could ever run for.
/// Instead, each reclaim races against the timeout on a background
/// thread that keeps waiting and re-adopts whatever arrives, however
/// late; this function's own return value only ever reports what
/// finished *in time*, so a late one isn't silently double-counted
/// either.
///
/// # Errors
/// Only for a genuine failure of the channel/round-trip machinery
/// itself (the `run_server_full` task is gone) -- never for an
/// individual connection simply not being live anymore, and never for a
/// single slow reply (that's handled per the paragraph above, not
/// surfaced as an error at all).
fn reclaim_and_readopt_all(
    reclaim_tx: &mpsc::Sender<ReclaimRequest>,
    adopt_tx: &mpsc::Sender<AdoptedConn>,
    conn_ids: &[u64],
) -> Result<usize, String> {
    let mut reclaimed = 0usize;
    for &conn_id in conn_ids {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        reclaim_tx
            .blocking_send((conn_id, reply_tx))
            .map_err(|_| "loom-net's run_server_full task is gone (reclaim)".to_string())?;

        // `done_tx`/`done_rx` only ever report "finished within budget,
        // and what happened" back to this loop -- the background thread
        // below does not depend on this call ever reading `done_rx` at
        // all; it owns the actual readopt unconditionally.
        let (done_tx, done_rx) = std::sync::mpsc::channel::<bool>();
        let adopt_tx_for_reply = adopt_tx.clone();
        std::thread::spawn(move || match reply_rx.blocking_recv() {
            Ok(Some(stream)) => {
                // Always readopt, no matter how late this thread's own
                // wait took -- see this function's doc comment.
                match adopt_tx_for_reply.blocking_send((conn_id, stream)) {
                    Ok(()) => {
                        let _ = done_tx.send(true);
                    }
                    Err(_) => {
                        warn!(
                            conn_id,
                            "loom serve: reclaimed a connection but loom-net's run_server_full \
                             task was gone by the time of the (possibly late) readopt; the \
                             connection is lost"
                        );
                        let _ = done_tx.send(false);
                    }
                }
            }
            Ok(None) => {
                // Already gone on its own (client disconnected between
                // the snapshot and this reclaim, or `run_server_full`
                // never had this id to begin with) -- not an error,
                // nothing to adopt.
                let _ = done_tx.send(false);
            }
            Err(_) => {
                // `reclaim_rx`'s side of `run_server_full` dropped the
                // reply channel without answering (the task exited) --
                // nothing to adopt, and the `reclaim_tx.blocking_send`
                // above already proved the channel accepted the request,
                // so this is reported the same as "gone", not escalated
                // to an error for this one connection.
                let _ = done_tx.send(false);
            }
        });

        match done_rx.recv_timeout(RECLAIM_REQUEST_TIMEOUT) {
            Ok(true) => reclaimed += 1,
            Ok(false) => {}
            Err(_) => {
                // The background thread is still waiting (or has just
                // finished and is racing this timeout) -- it will
                // re-adopt on its own once the reply arrives, per this
                // function's doc comment. Not counted as reclaimed by
                // *this* pass, since we can't confirm it happened in
                // time, but also not dropped.
                warn!(
                    conn_id,
                    "loom serve: reclaim reply for this connection is late; it will still be \
                     re-adopted once it arrives, but wasn't counted in this round trip"
                );
            }
        }
    }
    Ok(reclaimed)
}

/// `loom supervise` (OBI-184, design §7.5/§9.2): the in-pod supervisor
/// that owns the listening sockets and spawns `loom serve` as a standby
/// child, handing it those sockets over a private control-socket
/// `SCM_RIGHTS` channel (`loom_supervise::fdpass`) rather than letting
/// the child bind them itself.
///
/// **This is the first slice** (see OBI-184's tracking comments): it
/// proves the handoff mechanism end to end against one child and then
/// just waits for it to exit -- there is deliberately no version
/// watching, no cosign/GHCR artifact staging, no standby-vs-already-
/// running-process copyover yet. Each of those is a separate, tracked
/// follow-up; this function is not a stand-in implementation of them.
///
/// **Signal handling (OBI-184, this slice):** `SIGTERM`/`SIGINT`
/// delivered to this process are forwarded to the standby child (so
/// `serve`'s own graceful `shutdown_signal` drain in the child still
/// runs, instead of the supervisor exiting and leaving the child
/// orphaned -- CTO review, OBI-225), and the child has
/// `PR_SET_PDEATHSIG` installed so an unexpected supervisor death
/// (crash, `SIGKILL`, OOM) terminates it too rather than leaving it
/// running unsupervised. **Still not yet safe as a container entrypoint
/// for everything else named in OBI-225/OBI-184**: no version watching,
/// no cosign/GHCR staging, no copyover against an already-running
/// process -- those remain separate, tracked follow-ups.
///
/// **Respawn-on-crash (OBI-184, this slice):** a child that exits
/// without the supervisor having asked it to -- a crash, *or a clean
/// exit the supervisor itself never requested via a forwarded shutdown
/// signal (also respawned, exactly like a crash; this supervisor is the
/// only thing that should ever stop a child on purpose, so any other
/// exit is unexpected)* -- is treated as transient and respawned
/// against the *same already-bound* listening sockets --
/// `telnet_listener`/`http_listener` are owned by this function for its
/// whole lifetime and only ever lent out (as fds, over
/// `fdpass::send_fds`) to each successive child, so a respawn needs no
/// rebind and no client-visible gap beyond however long the crashed
/// child's own connections take to notice. Bounded by
/// [`MAX_CONSECUTIVE_CRASHES`] exits within [`CRASH_LOOP_WINDOW`] of
/// each other (a streak that resets once a child has run stably for at
/// least that long) -- past that, this gives up and returns an error
/// rather than spinning forever against a child that can never start
/// successfully (a bad binary, a broken mudlib, ...). A failure in the
/// spawn-and-handoff step itself (before the child is even a tracked
/// attempt -- e.g. `fork`/`exec` failing outright) is **not** retried
/// and propagates as a hard error immediately: only an already-running
/// child that then exits counts toward the crash-loop budget above.
///
/// **Dedicated OS thread, not Tokio's blocking pool (CTO review,
/// OBI-251):** `loom_supervise::signal::set_death_signal_on_parent_exit`
/// (installed on the child via `pre_exec`) ties `PR_SET_PDEATHSIG` to
/// the specific OS *thread* that called `Command::spawn`, not to the
/// supervisor process as a whole -- see that function's doc for the
/// full contract. A `tokio::task::spawn_blocking` pool thread does not
/// satisfy it: Tokio's blocking pool lets idle threads exit (10s
/// keep-alive by default), which would fire the death signal against a
/// perfectly healthy, still-running supervisor and silently tear down
/// the active server. `spawn_handoff_and_wait` below runs on one
/// `std::thread`, spawned fresh per attempt but each one alive for that
/// attempt's entire spawn-through-`wait()` lifetime, communicating back
/// to this `async fn` over plain channels.
const MAX_CONSECUTIVE_CRASHES: u32 = 5;
const CRASH_LOOP_WINDOW: Duration = Duration::from_secs(30);
const DEFAULT_VERSION_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// CTO review (OBI-259): a bound on the control-socket round trip
/// (`write_message` + `read_message`) the version-change arm does
/// inside `run_one_child_attempt`'s select loop. Without this, a child
/// that stops answering (`SIGSTOP`, a wedged responder thread, a future
/// child that holds the socket but never runs a responder at all) would
/// leave that arm's body awaiting forever -- and since the loop only
/// returns to `select!` once the current arm's body finishes, that also
/// silently stops SIGTERM forwarding and child-exit detection, a
/// liveness regression in the one process whose job is to stay alive
/// and keep doing both.
const COPYOVER_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

async fn supervise(mudlib_root: PathBuf) -> Result<(), String> {
    let bind_addr = loom_net::telnet_addr_from_env();
    let http_bind_addr = http_addr_from_env();

    // Bound with the plain `std` listener, not Tokio's: handed off to
    // the dedicated supervisor thread below, and the fds need to be
    // `BorrowedFd`-able for `fdpass::send_fds` regardless. Bound once,
    // for this function's entire lifetime -- every respawn attempt
    // below lends the *same* listener fds to a fresh child, not new
    // ones, so there is no rebind gap between crash and respawn.
    let telnet_listener = std::net::TcpListener::bind(&bind_addr)
        .map_err(|err| format!("supervise: failed to bind {bind_addr}: {err}"))?;
    let http_listener = std::net::TcpListener::bind(&http_bind_addr)
        .map_err(|err| format!("supervise: failed to bind {http_bind_addr}: {err}"))?;
    info!(
        bind = %bind_addr,
        http_bind = %http_bind_addr,
        "loom supervise: listening sockets bound, spawning standby child"
    );

    // Version-watching (OBI-184, this slice): detection only -- a
    // detected change is logged by `run_one_child_attempt` below, not
    // yet acted on (no copyover trigger exists). `None` when
    // `LOOM_DESIRED_VERSION_FILE` isn't set keeps version watching
    // fully disabled, matching this function's behavior before this
    // slice.
    //
    // CTO review (OBI-256): seeded with the *running build's own*
    // version (`running_version_from_env`), not the desired-version
    // file's content at boot -- the whole point of §9.9's reconcile
    // loop is noticing a mismatch between "what's running" and "what's
    // desired", and seeding from the file itself would make a desired-
    // version write that happened while the supervisor was down
    // invisible (the file and the "baseline" would already agree by the
    // time anything polls).
    let running_version = running_version_from_env();
    let mut version_rx = desired_version_file_from_env().map(|path| {
        let watcher = loom_supervise::VersionWatcher::new(
            Box::new(loom_supervise::FileVersionSource::new(&path)),
            Some(running_version.clone()),
        );
        info!(
            path = %path.display(),
            running_version,
            "loom supervise: version watching enabled"
        );
        spawn_version_watcher(watcher, version_poll_interval_from_env())
    });

    let mut shutdown = ShutdownSignals::new()?;
    let mut consecutive_crashes: u32 = 0;
    loop {
        let attempt_started = tokio::time::Instant::now();
        let outcome = run_one_child_attempt(
            mudlib_root.clone(),
            &telnet_listener,
            &http_listener,
            &mut shutdown,
            version_rx.as_mut(),
        )
        .await?;

        let status = match outcome {
            ChildAttemptOutcome::ShutdownRequested(status) => {
                if !status.success() {
                    return Err(format!(
                        "standby child exited with {status} after a forwarded shutdown signal"
                    ));
                }
                return Ok(());
            }
            ChildAttemptOutcome::ChildExited(status) => status,
        };

        // A child that ran for a while before exiting on its own is a
        // fresh problem, not a continuation of an earlier crash loop --
        // don't let an old streak count against it.
        if attempt_started.elapsed() >= CRASH_LOOP_WINDOW {
            consecutive_crashes = 0;
        }
        consecutive_crashes += 1;

        warn!(
            %status,
            consecutive_crashes,
            "loom supervise: standby child exited without a shutdown request (a crash, or any exit this \
             supervisor never asked for -- a clean exit is respawned exactly the same as a crashing one); respawning"
        );

        if consecutive_crashes >= MAX_CONSECUTIVE_CRASHES {
            return Err(format!(
                "standby child exited {consecutive_crashes} times within {CRASH_LOOP_WINDOW:?} of each other (most recently with {status}); giving up after {MAX_CONSECUTIVE_CRASHES} consecutive crashes"
            ));
        }

        // A short, fixed backoff before respawning: this is deliberately
        // not the full exponential-backoff-with-jitter a longer-lived
        // supervisor would want (tracked separately if it turns out to
        // matter) -- just enough to keep a hard crash loop from busy-
        // spinning `fork`/`exec` calls.
        //
        // CTO review (OBI-253): this sleep must itself be interruptible
        // by a shutdown signal using the *same* persistent `shutdown`
        // listener as `run_one_child_attempt` -- a fresh `shutdown_
        // signal()` call here (as a previous version of this function
        // had) would have silently missed any signal delivered in the
        // window between that call being made and its `signal()`
        // registration completing, exactly the race a real `SIGTERM`
        // sent to the supervisor during this backoff would hit.
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(1)) => {}
            () = shutdown.recv() => {
                info!("loom supervise: received shutdown signal during crash-backoff; exiting without respawning");
                return Ok(());
            }
        }
    }
}

/// One outcome of [`run_one_child_attempt`]: either the supervisor
/// itself asked the child to stop (a forwarded shutdown signal), or the
/// child exited on its own for some other reason (crash, or any exit the
/// supervisor never requested) and [`supervise`]'s respawn loop must
/// decide whether to try again.
enum ChildAttemptOutcome {
    ShutdownRequested(std::process::ExitStatus),
    ChildExited(std::process::ExitStatus),
}

/// Spawn one standby child, hand off the listening sockets, and wait for
/// either the child to exit on its own or a shutdown signal to arrive
/// (forwarded to the child if so) -- one full attempt of [`supervise`]'s
/// respawn loop. See [`supervise`]'s doc comment for why the actual
/// spawn+wait happens on a dedicated `std::thread`
/// ([`spawn_handoff_and_wait`]) rather than Tokio's blocking pool.
///
/// Takes `shutdown` as `&mut` from the caller rather than creating its
/// own (CTO review, OBI-253): a fresh `tokio::signal::unix::signal`
/// registration per call/per attempt would miss any signal delivered
/// between one attempt's handling finishing and the next one's
/// registration completing -- the same persistent listener must span
/// every attempt (and the backoff sleep between them, in `supervise`).
///
/// Known residual gap, not covered by this fix: a shutdown signal that
/// arrives while this function is still waiting for the child's ready
/// signal (inside [`spawn_handoff_and_wait`]'s blocking handoff, before
/// this function even learns the child's pid) is not specifically
/// detected here either -- that window is bounded by how long a `serve`
/// process takes to compile its mudlib and signal ready, not by
/// anything this function waits on per se, and was not part of OBI-253's
/// reported repro (which was specifically the crash-backoff window).
async fn run_one_child_attempt(
    mudlib_root: PathBuf,
    telnet_listener: &std::net::TcpListener,
    http_listener: &std::net::TcpListener,
    shutdown: &mut ShutdownSignals,
    mut version_rx: Option<&mut tokio::sync::watch::Receiver<String>>,
) -> Result<ChildAttemptOutcome, String> {
    // `spawn_handoff_and_wait` needs `'static` owned copies of the
    // listeners to move into its dedicated thread; `try_clone` is a
    // real `dup(2)`, the same primitive `fdpass::send_fds` itself uses
    // to hand a listener to the *child* process, just kept in this
    // process instead.
    let telnet_listener = telnet_listener
        .try_clone()
        .map_err(|err| format!("supervise: try_clone telnet listener: {err}"))?;
    let http_listener = http_listener
        .try_clone()
        .map_err(|err| format!("supervise: try_clone http listener: {err}"))?;

    let (ready_tx, ready_rx) =
        std::sync::mpsc::channel::<Result<(u32, std::os::unix::net::UnixStream), String>>();
    let (forward_signal_tx, forward_signal_rx) = std::sync::mpsc::channel::<()>();
    let (exit_tx, exit_rx) = std::sync::mpsc::channel::<Result<std::process::ExitStatus, String>>();

    let supervisor_thread = std::thread::Builder::new()
        .name("loom-supervise-child".to_string())
        .spawn(move || {
            spawn_handoff_and_wait(
                &mudlib_root,
                &telnet_listener,
                &http_listener,
                &ready_tx,
                &forward_signal_rx,
                &exit_tx,
            );
        })
        .map_err(|err| format!("supervise: spawn supervisor thread: {err}"))?;

    let (child_pid, control_stream) = tokio::task::spawn_blocking(move || ready_rx.recv())
        .await
        .map_err(|err| format!("supervise: ready-channel join: {err}"))?
        .map_err(|_| "supervise: supervisor thread exited before signalling ready".to_string())??;

    // CTO review (OBI-259): `control_stream` is `Option` from here on,
    // not because the handoff can ever hand back "no stream" (it can't
    // -- `spawn_and_handoff` always returns one), but because any
    // control-socket error or timeout *poisons* it to `None` for the
    // rest of this attempt: a timed-out request followed by a late reply
    // would otherwise desync the stream (the next request's `read_
    // message` would read the *previous* request's stale reply as its
    // own), so once anything goes wrong the only safe move is to stop
    // using this stream at all, not retry it.
    let mut control_stream = Some(control_stream);
    if let Some(stream) = control_stream.as_ref() {
        // Bounds the version-change arm's blocking round trip below --
        // see `COPYOVER_CONTROL_TIMEOUT`'s own doc comment for why an
        // unbounded wait here is a liveness regression, not just a slow
        // copyover. `set_read_timeout`/`set_write_timeout` are plain
        // `setsockopt` calls, not blocking I/O, so these run inline
        // rather than needing their own `spawn_blocking`.
        if let Err(err) = stream
            .set_read_timeout(Some(COPYOVER_CONTROL_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(COPYOVER_CONTROL_TIMEOUT)))
        {
            warn!(child_pid, %err, "loom supervise: failed to set control-socket timeouts; treating control channel as unavailable");
            control_stream = None;
        }
    }

    info!(
        child_pid,
        "loom supervise: standby child is now the active server; forwarding shutdown signals to it until it exits"
    );

    let mut exit_handle = tokio::task::spawn_blocking(move || exit_rx.recv());

    // Looped (not a single `select!`) so a detected version change --
    // logged only, nothing acts on it yet, see this function's doc
    // comment and `loom-supervise`'s own "not yet implemented" list --
    // doesn't end this attempt; it just reports and keeps waiting on
    // the same child.
    let outcome = loop {
        tokio::select! {
            result = &mut exit_handle => {
                let status = result
                    .map_err(|err| format!("supervise: exit-channel join: {err}"))?
                    .map_err(|_| "supervise: supervisor thread exited before reporting the child's status".to_string())??;
                break ChildAttemptOutcome::ChildExited(status);
            }
            () = shutdown.recv() => {
                info!(child_pid, "loom supervise: received shutdown signal, forwarding SIGTERM to child");
                // The supervisor thread does the actual `send_sigterm` (it
                // already holds the live `Child`); this channel just wakes
                // its wait loop up to do that instead of this async task
                // calling `send_sigterm` itself from an unrelated thread --
                // either would reach the same pid, but routing it through
                // the owning thread keeps "who may act on this `Child`" to
                // one place.
                let _ = forward_signal_tx.send(());
                let status = exit_handle
                    .await
                    .map_err(|err| format!("supervise: exit-channel join after signal: {err}"))?
                    .map_err(|_| "supervise: supervisor thread exited before reporting the child's status".to_string())??;
                break ChildAttemptOutcome::ShutdownRequested(status);
            }
            version = async {
                match version_rx.as_mut() {
                    Some(rx) => match rx.changed().await {
                        Ok(()) => rx.borrow_and_update().clone(),
                        // CTO review (OBI-256): the watcher task died --
                        // never resolving again has the same effect as
                        // `version_rx` being `None` (this arm is simply
                        // never picked again), rather than this `async`
                        // block returning immediately on every future
                        // poll and spinning the surrounding `loop`.
                        Err(_) => std::future::pending().await,
                    },
                    // No version watching configured: a `select!` arm
                    // whose future never resolves is simply never
                    // picked, same effect as not having this arm at all.
                    None => std::future::pending().await,
                }
            } => {
                info!(
                    child_pid,
                    new_version = %version,
                    "loom supervise: desired version changed -- forwarding a copyover request over the control socket (OBI-184: acknowledged only, no copyover action implemented yet)"
                );
                match control_stream.take() {
                    None => {
                        warn!(
                            child_pid,
                            new_version = %version,
                            "loom supervise: control channel unavailable (a previous request failed, timed out, or the socket could not be configured); cannot forward this copyover request"
                        );
                    }
                    Some(mut stream) => {
                        // Blocking write+read over the control
                        // `UnixStream`, off the async executor, bounded
                        // by `COPYOVER_CONTROL_TIMEOUT` (set on `stream`
                        // right after the handoff) so a child that stops
                        // answering can't stall this arm's body forever
                        // -- see `COPYOVER_CONTROL_TIMEOUT`'s own doc
                        // comment (CTO review, OBI-259). Moving `stream`
                        // into `spawn_blocking` and getting it back out
                        // via the tuple keeps the same stream (and its
                        // underlying fd) for the next round, exactly
                        // like `spawn_version_watcher`'s own
                        // move-out-and-back pattern for its
                        // `VersionWatcher`.
                        let version_for_control = version.clone();
                        let (result, stream) = tokio::task::spawn_blocking(move || {
                            let result = loom_supervise::control::write_message(
                                &mut stream,
                                &loom_supervise::control::ControlMessage::CopyoverRequested {
                                    version: version_for_control,
                                },
                            )
                            .and_then(|()| loom_supervise::control::read_message(&mut stream));
                            (result, stream)
                        })
                        .await
                        .map_err(|err| format!("supervise: control-socket task join: {err}"))?;
                        match result {
                            Ok(loom_supervise::control::ControlMessage::CopyoverAck) => {
                                info!(child_pid, new_version = %version, "loom supervise: child acknowledged the copyover request");
                                // Only a clean ack puts the stream back in
                                // play -- CTO review (OBI-259): any other
                                // outcome (below) poisons it instead, so a
                                // stale reply from this exchange can never
                                // be misread as the reply to a later one.
                                control_stream = Some(stream);
                            }
                            Ok(other) => {
                                warn!(child_pid, ?other, "loom supervise: child sent an unexpected reply to a copyover request; treating control channel as unavailable from now on");
                            }
                            Err(err) => {
                                warn!(child_pid, %err, "loom supervise: failed to deliver a copyover request over the control socket (possibly a timeout); treating control channel as unavailable from now on");
                            }
                        }
                    }
                }
            }
        }
    };

    // The thread's job is done once it has reported the child's exit;
    // join it so a panic inside it (which `recv()` on a dropped sender
    // would otherwise just look like a closed channel for) surfaces.
    if let Err(panic) = supervisor_thread.join() {
        return Err(format!("supervise: supervisor thread panicked: {panic:?}"));
    }

    Ok(outcome)
}

/// Runs on the one dedicated `std::thread` [`supervise`] spawns (see its
/// doc comment for why it must be this and not `spawn_blocking`): spawn
/// the standby child and hand off the listening sockets ([`spawn_and_
/// handoff`]), report the child's pid over `ready_tx`, then loop,
/// polling the child's exit status and `forward_signal_rx` (a request
/// from the async side to forward `SIGTERM`), until the child exits --
/// reporting the final status (or any error along the way) over
/// `exit_tx`.
fn spawn_handoff_and_wait(
    mudlib_root: &std::path::Path,
    telnet_listener: &std::net::TcpListener,
    http_listener: &std::net::TcpListener,
    ready_tx: &std::sync::mpsc::Sender<Result<(u32, std::os::unix::net::UnixStream), String>>,
    forward_signal_rx: &std::sync::mpsc::Receiver<()>,
    exit_tx: &std::sync::mpsc::Sender<Result<std::process::ExitStatus, String>>,
) {
    let (mut child, control_stream) =
        match spawn_and_handoff(mudlib_root, telnet_listener, http_listener) {
            Ok(pair) => pair,
            Err(err) => {
                let _ = ready_tx.send(Err(err));
                return;
            }
        };
    let _ = ready_tx.send(Ok((child.id(), control_stream)));

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let _ = exit_tx.send(Ok(status));
                return;
            }
            Ok(None) => {}
            Err(err) => {
                let _ = exit_tx.send(Err(format!("supervise: wait on standby child: {err}")));
                return;
            }
        }

        // Short poll interval: just needs to be responsive enough to a
        // forwarded shutdown signal to keep the measured copyover/
        // shutdown pause well under the design's 5s budget, not tight
        // enough to matter for CPU usage in what is otherwise an idle
        // wait.
        match forward_signal_rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(()) => match loom_supervise::signal::send_sigterm(child.id()) {
                Ok(()) => {}
                Err(err) if loom_supervise::signal::is_no_such_process(&err) => {
                    // CTO review (OBI-251): the child had already exited
                    // on its own in the small window between our last
                    // `try_wait` and this `send_sigterm` -- benign, the
                    // next loop iteration's `try_wait` will observe it.
                }
                Err(err) => {
                    let _ = exit_tx.send(Err(format!(
                        "supervise: forwarding SIGTERM to child {}: {err}",
                        child.id()
                    )));
                    return;
                }
            },
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                // The async side is gone (e.g. it already errored out of
                // `supervise` some other way) -- no further signal will
                // ever arrive, but the child itself still needs to be
                // waited on to avoid leaving a zombie; keep looping on
                // `try_wait` alone.
            }
        }
    }
}

/// Spawns a background task polling `watcher` on `poll_interval`,
/// sending every *detected change* (not every poll -- see
/// `VersionWatcher::poll_for_change`) through the returned channel.
/// OBI-184 version-watching slice: this is detection-only plumbing --
/// `run_one_child_attempt`'s only consumer of this channel today just
/// logs what it receives. Driving an actual copyover off a detected
/// change is a separate, not-yet-built follow-up.
fn spawn_version_watcher(
    mut watcher: loom_supervise::VersionWatcher,
    poll_interval: Duration,
) -> tokio::sync::watch::Receiver<String> {
    // CTO review (OBI-256): `watch`, not `mpsc`, is the right channel
    // shape for a desired-state signal -- `watch::Sender::send` always
    // overwrites with the latest value (no queue to go stale in), so a
    // consumer that's busy elsewhere (e.g. `supervise`'s crash-backoff
    // sleep) when several changes land in a row still only ever acts on
    // the newest one once it does check, never an older queued one.
    // Seeded with `watcher.current()`'s baseline (the running version,
    // per this function's caller) so the first real change is the first
    // thing `changed()` ever reports.
    let initial = watcher.current().unwrap_or_default().to_string();
    let (tx, rx) = tokio::sync::watch::channel(initial);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(poll_interval);
        // CTO review (OBI-256): `Delay`, not the default `Burst` --
        // a single slow poll (e.g. a stalled NFS/bind mount under the
        // blocking file read below) must not cause a run of immediate
        // catch-up ticks once it finally returns.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            // `VersionWatcher::poll_for_change` does blocking file I/O;
            // moving `watcher` into `spawn_blocking` and getting it back
            // out via the tuple keeps that off this task's own
            // (cooperative) poll, reusing the same watcher (with its
            // change-tracking state) across every tick rather than
            // rebuilding it.
            let (result, returned_watcher) = match tokio::task::spawn_blocking(move || {
                let result = watcher.poll_for_change();
                (result, watcher)
            })
            .await
            {
                Ok(pair) => pair,
                Err(err) => {
                    warn!(%err, "loom supervise: version-watch poll task panicked; stopping version watching");
                    return;
                }
            };
            watcher = returned_watcher;

            match result {
                Ok(Some(version)) => {
                    if tx.send(version).is_err() {
                        // The receiving end (inside `supervise`'s respawn
                        // loop) is gone -- `supervise` itself must have
                        // already returned, so there is nothing left
                        // for this task to report to.
                        return;
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    warn!(%err, "loom supervise: version-watch poll failed (will retry next interval)");
                }
            }
        }
    });
    rx
}

/// Spawn one `loom serve --adopt-control-fd <n>` standby child and hand
/// it `telnet_listener`/`http_listener` over a dedicated control
/// `UnixStream` pair. Blocks (by design -- see [`supervise`]'s doc) until
/// the child signals it's ready to receive the fds, then returns the
/// still-running `Child` for the caller to wait on (racing that wait
/// against shutdown signals is the caller's job now, not this
/// function's -- see [`supervise`]).
fn spawn_and_handoff(
    mudlib_root: &std::path::Path,
    telnet_listener: &std::net::TcpListener,
    http_listener: &std::net::TcpListener,
) -> Result<(std::process::Child, std::os::unix::net::UnixStream), String> {
    use std::io::Read;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    let (supervisor_end, child_end) =
        UnixStream::pair().map_err(|err| format!("supervise: UnixStream::pair: {err}"))?;
    loom_supervise::listener::clear_cloexec(loom_supervise::listener::raw_fd_of(&child_end))
        .map_err(|err| format!("supervise: clear_cloexec: {err}"))?;
    let child_fd = loom_supervise::listener::raw_fd_of(&child_end);

    let self_exe =
        std::env::current_exe().map_err(|err| format!("supervise: current_exe: {err}"))?;
    let mut cmd = std::process::Command::new(self_exe);
    cmd.arg("serve")
        .arg("--mudlib")
        .arg(mudlib_root)
        .arg("--adopt-control-fd")
        .arg(child_fd.to_string());
    // CTO review (OBI-225): if this supervisor process dies without
    // explicitly tearing the child down first (crash, `SIGKILL`,
    // OOM-kill), the kernel delivers `SIGTERM` to the child
    // automatically instead of leaving it an orphan nothing is
    // supervising. `die_with_parent` registers against *this* spawn's
    // parent -- the supervisor -- per `prctl(2)`'s semantics.
    loom_supervise::signal::die_with_parent(&mut cmd);
    let child = cmd
        .spawn()
        .map_err(|err| format!("supervise: spawn standby child: {err}"))?;
    // `Command::spawn` already duplicated the whole fd table (including
    // `child_end`, left non-close-on-exec by `clear_cloexec` above) into
    // the child; our own copy of `child_end` has nothing further to do
    // and must be dropped so the supervisor isn't itself holding a
    // second reference to the socket the child now owns its end of.
    drop(child_end);

    let mut ready = [0u8; 1];
    let mut supervisor_end_reader = &supervisor_end;
    // TODO(OBI-184 abort/fallback slice): no read timeout here -- see
    // the matching TODO on `acquire_listeners`'s adopt-control-fd path.
    supervisor_end_reader
        .read_exact(&mut ready)
        .map_err(|err| format!("supervise: waiting for standby ready signal: {err}"))?;
    if ready != *b"R" {
        // CTO review (OBI-225): a byte that isn't the expected marker
        // means this isn't the handshake we think it is -- handing off
        // the listening sockets anyway would be wrong (e.g. a corrupted
        // or out-of-protocol-version child).
        return Err(format!(
            "supervise: unexpected standby ready byte {:?} (expected {:?})",
            ready, b'R'
        ));
    }

    loom_supervise::fdpass::send_fds(
        &supervisor_end,
        &[telnet_listener.as_fd(), http_listener.as_fd()],
    )
    .map_err(|err| format!("supervise: send_fds: {err}"))?;
    info!(
        child_pid = child.id(),
        "loom supervise: listening sockets handed off to standby child"
    );

    // OBI-184 control-protocol slice: unlike the earlier implementation,
    // `supervisor_end` is *not* dropped here -- the caller keeps it open
    // for the rest of this child's life, to send post-handoff control
    // messages (`loom_supervise::control`) to it, which the child's own
    // `run_control_responder` thread is listening for on its matching
    // end.
    Ok((child, supervisor_end))
}

async fn serve(
    mudlib_root: PathBuf,
    save_dir: Option<PathBuf>,
    adopt_control_fd: Option<std::os::fd::RawFd>,
) -> Result<(), String> {
    let (listener, http_listener, control_stream) = acquire_listeners(adopt_control_fd).await?;
    let actual_addr = listener
        .local_addr()
        .map_err(|err| format!("failed to read local addr: {err}"))?;
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

    // OBI-184 (copyover-trigger slice): the world thread answers
    // snapshot requests from the control responder over this channel --
    // created before `spawn_world_thread` (which drains the receiving
    // end) and before the responder thread below (which holds the
    // sending end), so neither constructor needs an `Option`/placeholder
    // for the other side. The reply carries `World::live_connections()`
    // alongside the snapshot bytes -- both read from the same consistent
    // instant of world state, which is exactly the connection-id list a
    // reclaim pass needs to agree with.
    let (snapshot_req_tx, snapshot_req_rx) = std::sync::mpsc::channel::<SnapshotRequest>();

    // OBI-180 M-FS-1/M-FS-5: the file-op channel `/api/v1/files/*`
    // handlers send `read_file`/`write_file` requests on (created here,
    // alongside every other world-thread side channel, so
    // `spawn_world_thread` never needs an `Option` for it). Bounded
    // (`sync_channel`, depth defined in `loom_http::files` so the HTTP
    // and world-thread sides agree on one number): past that many
    // outstanding requests, `request_file_op`'s `try_send` fails
    // immediately instead of queueing (M-FS-5's "503 on backpressure").
    // The sender half goes to `HttpState::with_file_ops` below; this
    // binding stays alive for the rest of this function's scope (which
    // runs for the server's whole lifetime) so `file_op_rx`'s
    // sender-closed check in `spawn_world_thread` never trips.
    let (file_op_tx, file_op_rx) = loom_http::files::file_op_channel();

    // OBI-184 (copyover-trigger slice): real handles to `loom-net`'s
    // reclaim/adopt primitives (OBI-94/OBI-221, merged but previously
    // unreachable from `loom-cli` -- `run_server_with_ws` only ever wired
    // up placeholder channels nothing could use). `reclaim_tx` lets the
    // control responder pull a live connection's `TcpStream` back out
    // without a `NetEvent::Disconnected`; `adopt_tx` re-inserts a
    // `TcpStream` under a caller-chosen `ConnId`. This slice only uses
    // both together, *within this same process*, to prove a reclaim-
    // then-readopt round trip never disconnects a real client -- see
    // `run_control_responder`'s own doc comment for why that is
    // deliberately not yet "send the reclaimed connection to a standby".
    let (reclaim_tx, reclaim_rx) = mpsc::channel::<ReclaimRequest>(RECLAIM_QUEUE_DEPTH);
    let (adopt_tx, adopt_rx) = mpsc::channel::<AdoptedConn>(RECLAIM_QUEUE_DEPTH);

    // OBI-237 (OBI-234 follow-up): the admin `who`/object-browser query
    // channel -- bounded, `try_send`-only from the HTTP side
    // (`ChannelWorldQuery`), drained by the world thread's own event loop
    // every iteration, same bridging shape as `db_req_tx`/`db_event_rx`
    // above (request/reply direction reversed: HTTP calls into the world,
    // not the world calling out). See `loom_http::admin_query`'s module
    // doc for the full bound/backpressure/timeout contract this pairs
    // with.
    let (admin_query_tx, admin_query_rx) = mpsc::channel(ADMIN_QUERY_QUEUE_DEPTH);

    let world_handle = spawn_world_thread(
        mudlib_root.clone(),
        save_dir,
        event_rx,
        command_tx.clone(),
        db_req_tx,
        db_event_rx,
        tick_pending.clone(),
        roles_snapshot_rx,
        roles_reload_tx,
        audit_tx,
        admin_query_rx,
        persist.is_some(),
        persist.is_none(),
        snapshot_req_rx,
        file_op_rx,
    )?;

    // OBI-184 control-protocol slice: if this process was handed off to
    // by `loom supervise` (not the fresh-bind path), the control socket
    // stays open after the handoff handshake -- spawn a dedicated thread
    // to answer post-startup control messages on it for the rest of this
    // process's life. Blocking reads, so its own `std::thread`, not a
    // tokio task (same reasoning as `loom-supervise`'s dedicated-thread
    // doc comments elsewhere in this file). Spawned after the world
    // thread so it always has a live `snapshot_req_tx` to send to.
    if let Some(control) = control_stream {
        std::thread::Builder::new()
            .name("loom-serve-control".to_string())
            .spawn(move || run_control_responder(control, snapshot_req_tx, reclaim_tx, adopt_tx))
            .map_err(|err| format!("failed to spawn control-responder thread: {err}"))?;
    }

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
    let mut http_state = loom_http::HttpState::new(ws_accept_tx, readiness, metrics)
        .with_file_ops(file_op_tx)
        .with_world_query(std::sync::Arc::new(ChannelWorldQuery::new(admin_query_tx)));
    if let Some(web_root) = web_root_from_env() {
        http_state = http_state.with_web_root(web_root);
    }
    // OBI-174/OBI-197: `/auth/*` only mounted when both Postgres and an
    // EdDSA key file are configured -- staff web auth has nothing to
    // authenticate against otherwise (no `staff` table without Postgres)
    // and must never sign a token with a guessable or missing key.
    //
    // Deploy gate (OBI-195 follow-up tracking): `LOOM_JWT_SECRET` (the old
    // HS256 shared-secret var) is intentionally **not read anywhere in
    // this binary any more** -- setting it in any environment has no
    // effect, by construction, not just by convention.
    if let (Some(p), Some(key_file)) = (persist.clone(), jwt_key_file_from_env()) {
        let directory: std::sync::Arc<dyn loom_http::auth::StaffDirectory> = std::sync::Arc::new(p);
        let keys = loom_http::auth::JwtKeys::from_key_file(
            &key_file,
            jwt_issuer_from_env(),
            loom_http::auth::AUDIENCE,
        )
        .unwrap_or_else(|err| panic!("LOOM_JWT_KEY_FILE ({}): {err}", key_file.display()));
        http_state = http_state.with_auth(loom_http::auth::AuthService::new(directory, keys));
        http_state = http_state.with_staff_origins(staff_origins_from_env());

        // OBI-201 (M-AUTH-7): GitHub login mounts only once auth itself
        // is mounted *and* every GitHub OAuth app setting is present --
        // same "absent by default" shape, so an operator who hasn't
        // provisioned a GitHub OAuth app yet gets no `/auth/github/*`
        // routes at all rather than ones that 503 forever.
        if let Some(github_config) = github_oauth_config_from_env() {
            let login_config = loom_http::auth::GithubLoginConfig::new(
                github_config.client_id.clone(),
                github_config.redirect_uri.clone(),
            );
            let provider: std::sync::Arc<dyn loom_http::auth::GithubIdentityProvider> =
                std::sync::Arc::new(loom_http::auth::LiveGithubProvider::new(github_config));
            http_state = http_state.with_github(provider, login_config);
        } else {
            tracing::info!(
                "GitHub staff login (/auth/github/*) disabled: set LOOM_GITHUB_CLIENT_ID, \
                 LOOM_GITHUB_CLIENT_SECRET, and LOOM_GITHUB_REDIRECT_URI to enable it"
            );
        }
    } else {
        tracing::info!(
            "staff web auth (/auth/*) disabled: set both LOOM_DATABASE_URL (or DATABASE_URL) \
             and LOOM_JWT_KEY_FILE to enable it"
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

    let mut server = tokio::spawn(loom_net::run_server_full(
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
        adopt_rx,
        reclaim_rx,
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

/// `loom supervise`'s desired-version file (OBI-184 version-watching
/// slice, design §9.9): Docker-staging's `loom-gitops` reconciler writes
/// the desired driver version to this path (`loom_supervise::
/// FileVersionSource`'s own contract: trimmed, tolerant of a not-yet-
/// existing file). Unset (the default) disables version watching
/// entirely -- a safe default for tests, local runs, and any deployment
/// that hasn't wired up a reconciler yet; `supervise` runs exactly as it
/// did before this slice in that case.
fn desired_version_file_from_env() -> Option<PathBuf> {
    std::env::var_os("LOOM_DESIRED_VERSION_FILE").map(PathBuf::from)
}

/// This process's own running version, for seeding
/// [`loom_supervise::VersionWatcher`] (CTO review, OBI-256): §9.9's reconcile loop exists to
/// notice a mismatch between "what's running" and "what's desired", so
/// the baseline must be *this process's own identity*, not whatever the
/// desired-version file happens to say at boot (which would make a
/// desired-version write that happened while the supervisor was down
/// invisible -- see `supervise`'s own doc comment for the concrete
/// scenario). `LOOM_RUNNING_VERSION` is meant to be set by whatever
/// staged this specific build (the Docker-staging reconciler today;
/// cosign/GHCR artifact staging, not yet built, would be the eventual
/// source once it exists) to the version string that build actually is.
/// Falling back to the crate's own `CARGO_PKG_VERSION` keeps local/dev
/// runs (which never set this) working, though it's not a meaningful
/// "build identity" the way a staged artifact's tag/digest would be.
fn running_version_from_env() -> String {
    std::env::var("LOOM_RUNNING_VERSION").unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string())
}

/// Override for [`DEFAULT_VERSION_POLL_INTERVAL`] (CTO review, OBI-256's
/// nits): exists so a flaky CI timing margin can be tightened without
/// touching the default production cadence, and so a future test that
/// wants the version-watch loop to react faster than every 5s doesn't
/// have to wait on it.
fn version_poll_interval_from_env() -> Duration {
    parse_version_poll_interval_ms(
        std::env::var("LOOM_VERSION_POLL_INTERVAL_MS")
            .ok()
            .as_deref(),
    )
}

/// Pure parsing logic split out from [`version_poll_interval_from_env`]
/// so it's unit-testable without mutating process-global env vars (which
/// would race other tests in the same binary -- `cargo test` runs tests
/// in parallel threads by default).
fn parse_version_poll_interval_ms(raw: Option<&str>) -> Duration {
    match raw {
        Some(raw) => match raw.parse::<u64>() {
            // CTO review (OBI-257): `tokio::time::interval` panics on a
            // zero period. Refusing it here (falling back to the
            // default, with a warning) keeps an operator/reconciler typo
            // from crashing the whole version-watch task -- which would
            // otherwise silently disable version watching entirely (the
            // channel's sender just drops, and the consumer side's dead-
            // sender handling, by design, looks identical to "nothing
            // configured").
            Ok(0) => {
                warn!(
                    "loom supervise: LOOM_VERSION_POLL_INTERVAL_MS=0 is invalid (tokio::time::interval \
                     panics on a zero period); using the default {DEFAULT_VERSION_POLL_INTERVAL:?} instead"
                );
                DEFAULT_VERSION_POLL_INTERVAL
            }
            Ok(ms) => Duration::from_millis(ms),
            Err(err) => {
                // CTO review (OBI-258 nit): a garbage value silently
                // falling back is just as surprising as the zero case
                // above -- warn here too, consistently.
                warn!(
                    %err,
                    raw,
                    "loom supervise: LOOM_VERSION_POLL_INTERVAL_MS is not a valid number of \
                     milliseconds; using the default {DEFAULT_VERSION_POLL_INTERVAL:?} instead"
                );
                DEFAULT_VERSION_POLL_INTERVAL
            }
        },
        None => DEFAULT_VERSION_POLL_INTERVAL,
    }
}

#[cfg(test)]
mod version_poll_interval_tests {
    use super::*;

    #[test]
    fn unset_is_the_default() {
        assert_eq!(
            parse_version_poll_interval_ms(None),
            DEFAULT_VERSION_POLL_INTERVAL
        );
    }

    #[test]
    fn zero_is_refused_and_falls_back_to_the_default() {
        assert_eq!(
            parse_version_poll_interval_ms(Some("0")),
            DEFAULT_VERSION_POLL_INTERVAL
        );
    }

    #[test]
    fn garbage_falls_back_to_the_default() {
        assert_eq!(
            parse_version_poll_interval_ms(Some("not-a-number")),
            DEFAULT_VERSION_POLL_INTERVAL
        );
    }

    #[test]
    fn a_positive_value_is_used_as_milliseconds() {
        assert_eq!(
            parse_version_poll_interval_ms(Some("250")),
            Duration::from_millis(250)
        );
    }
}

/// Staff web auth's JWT signing keyset (OBI-174, OBI-197/M-AUTH-4, design
/// §9/D-P2.5). `/auth/*` is only mounted when this is set *and* Postgres
/// (`connect_persist`) is configured -- same "absent by default" shape as
/// `LOOM_WEB_ROOT`. Points at a mounted secret file holding the EdDSA
/// (Ed25519) keyset (active signing key + any still-being-rotated-out
/// verification keys) -- see `loom_http::auth::JwtKeys::from_key_file`
/// for its JSON shape. There is no insecure default: an operator who
/// wants staff auth must generate and mount a real keyset themselves
/// (e.g. `openssl genpkey -algorithm ed25519` plus a small script to emit
/// the 32-byte seed as base64 -- see `secrets.env.example`).
fn jwt_key_file_from_env() -> Option<PathBuf> {
    std::env::var_os("LOOM_JWT_KEY_FILE").map(PathBuf::from)
}

/// The `iss` claim staff access tokens are signed/verified with
/// (M-AUTH-4). Defaults to a fixed, documented value so a forgotten
/// `LOOM_JWT_ISSUER` doesn't silently sign tokens whose `iss` varies
/// between deploys (which would make outstanding tokens fail verification
/// after a redeploy for no operational reason).
fn jwt_issuer_from_env() -> String {
    std::env::var("LOOM_JWT_ISSUER").unwrap_or_else(|_| "https://build.loommud.com/".to_string())
}

/// The staff-origin allowlist (OBI-198, M-AUTH-6): exact `Origin` values
/// (scheme + host + port, comma-separated) that `/auth/refresh` and
/// `/auth/logout` accept. Unset by default, which refuses both routes
/// outright -- an operator who wants a browser staff client to be able to
/// refresh/log out must set this to that client's exact origin(s).
fn staff_origins_from_env() -> Vec<String> {
    std::env::var("LOOM_STAFF_ORIGINS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(|origin| origin.trim().to_string())
                .filter(|origin| !origin.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// GitHub OAuth app settings for staff login (OBI-201, M-AUTH-7). All
/// three (`LOOM_GITHUB_CLIENT_ID`, `LOOM_GITHUB_CLIENT_SECRET`,
/// `LOOM_GITHUB_REDIRECT_URI`) must be set, non-empty, or
/// `/auth/github/*` doesn't mount at all -- there is no "GitHub login
/// with no secret" state. An empty string (e.g. a compose/.env
/// placeholder someone forgot to fill in) is treated the same as unset,
/// not as a present-but-blank credential. The redirect URI must parse as
/// an `https://` URL -- GitHub itself enforces an exact match against
/// the OAuth app's registered callback, so a malformed value here just
/// means every callback fails closed, not a security hole, but failing
/// at startup is a much clearer signal than at the first login attempt.
fn github_oauth_config_from_env() -> Option<loom_http::auth::GithubOAuthConfig> {
    let client_id = non_empty_env("LOOM_GITHUB_CLIENT_ID")?;
    let client_secret = non_empty_env("LOOM_GITHUB_CLIENT_SECRET")?;
    let redirect_uri = non_empty_env("LOOM_GITHUB_REDIRECT_URI")?;
    if !redirect_uri.starts_with("https://") {
        tracing::warn!(
            "LOOM_GITHUB_REDIRECT_URI does not start with https://; GitHub staff login stays \
             disabled until it's a valid https URL"
        );
        return None;
    }
    Some(loom_http::auth::GithubOAuthConfig::new(
        client_id,
        client_secret,
        redirect_uri,
    ))
}

/// `std::env::var`, but an empty string reads the same as unset.
fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
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
    save_dir: Option<PathBuf>,
    mut event_rx: mpsc::Receiver<NetEvent>,
    command_tx: mpsc::Sender<NetCommand>,
    db_req_tx: mpsc::Sender<DbRequest>,
    mut db_event_rx: mpsc::Receiver<DbEvent>,
    tick_pending: Arc<AtomicBool>,
    mut roles_snapshot_rx: watch::Receiver<Option<std::sync::Arc<RolesSnapshot>>>,
    roles_reload_tx: mpsc::Sender<()>,
    audit_tx: mpsc::Sender<Vec<loom_vm::AuditRow>>,
    mut admin_query_rx: mpsc::Receiver<WorldQueryRequest>,
    has_audit_sink: bool,
    load_roles_seed: bool,
    snapshot_req_rx: std::sync::mpsc::Receiver<SnapshotRequest>,
    file_op_rx: std::sync::mpsc::Receiver<loom_http::files::FileOpRequest>,
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
            if let Some(dir) = save_dir {
                world.set_save_root(dir);
            }
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
            // OBI-180 M-FS-5 (CTO review of PR #119, must-fix 2): per-uid
            // compile queue state -- see `CompileSlot`'s doc comment.
            let mut compile_slots: std::collections::HashMap<String, CompileSlot> =
                std::collections::HashMap::new();
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

            // OBI-237 (OBI-234 follow-up): drain every pending admin
            // `who`/`objects`/`objects/:path/vars`/`errors` request, same
            // `try_recv` shape as `drain_db_events` above -- never
            // `blocking_recv`, drained once per event-loop iteration, so a
            // flood of admin queries degrades to the HTTP side's own
            // `Busy`/503 once `admin_query_rx`'s bounded channel fills,
            // never world-thread latency. Each reply is answered with its
            // own tick-budgeted `valid_read` apply (`World::
            // admin_list_objects`/`admin_object_vars`/`admin_errors`'s own
            // doc comments) and sent on a `oneshot`, which cannot block
            // either.
            //
            // CTO review (OBI-237 PR #102, non-blocking note): drained
            // once per event-loop iteration, same as `drain_db_events` --
            // on an otherwise-idle server that means once per
            // `NetEvent::Tick` (`WORLD_TICK_INTERVAL`, 100 ms), not
            // instantly on send; a query answered between two ticks still
            // meets the HTTP side's 2s `ADMIN_QUERY_TIMEOUT` with ample
            // margin, but this is the latency floor an admin request
            // actually has, not "as soon as it's sent".
            let mut drain_admin_queries = |world: &mut World, host: &mut NetHost| {
                while let Ok(request) = admin_query_rx.try_recv() {
                    match request {
                        WorldQueryRequest::Who { reply } => {
                            let who = world
                                .who_sessions()
                                .into_iter()
                                .map(|s| WhoEntry {
                                    conn_id: s.conn_id,
                                    account: s.account,
                                    connected_at: OffsetDateTime::from(s.connected_at),
                                    idle_secs: s.idle_secs,
                                })
                                .collect();
                            let _ = reply.send(Ok(who));
                        }
                        WorldQueryRequest::ListObjects { euid, tier, reply } => {
                            let result = world.admin_list_objects(&euid, tier, host).map(|objs| {
                                objs.into_iter()
                                    .map(|o| loom_http::admin_query::ObjectSummary {
                                        path: o.path,
                                        euid: o.euid,
                                    })
                                    .collect()
                            });
                            let result = result.map_err(|e| {
                                loom_http::admin_query::WorldQueryError::Internal(e.message)
                            });
                            let _ = reply.send(result);
                        }
                        WorldQueryRequest::ObjectVars {
                            euid,
                            tier,
                            path,
                            reply,
                        } => {
                            let result = match world.admin_object_vars(&euid, tier, &path, host) {
                                Ok(Some(vars)) => Ok(ObjectVars {
                                    path: vars.path,
                                    vars: vars
                                        .vars
                                        .into_iter()
                                        .map(|v| VarEntry {
                                            name: v.name,
                                            value: v.value,
                                        })
                                        .collect(),
                                }),
                                Ok(None) => {
                                    Err(loom_http::admin_query::WorldQueryError::NotFound)
                                }
                                Err(e) => Err(loom_http::admin_query::WorldQueryError::Internal(
                                    e.message,
                                )),
                            };
                            let _ = reply.send(result);
                        }
                        WorldQueryRequest::Errors {
                            euid,
                            tier,
                            program_prefix,
                            reply,
                        } => {
                            let result = world
                                .admin_errors(&euid, tier, program_prefix.as_deref(), host)
                                .map(|groups| {
                                    groups
                                        .into_iter()
                                        .map(|g| ErrorGroup {
                                            program: g.program,
                                            function: g.function,
                                            line: g.line,
                                            message: g.message,
                                            redacted: g.redacted,
                                            count: g.count,
                                            first_seen_unix_ms: g.first_seen_unix_ms,
                                            last_seen_unix_ms: g.last_seen_unix_ms,
                                            sample_trace: g.sample_trace,
                                        })
                                        .collect()
                                })
                                .map_err(|e| {
                                    loom_http::admin_query::WorldQueryError::Internal(e.message)
                                });
                            let _ = reply.send(result);
                        }
                    }
                }
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
                drain_admin_queries(&mut world, &mut host);
                // OBI-184 (copyover-trigger slice): a snapshot request
                // from `run_control_responder`'s control socket, drained
                // the same way as every other side-channel input to this
                // loop -- `try_recv`, never blocking, so an idle (or
                // never-sent) channel costs nothing and a request can
                // never stall a tick waiting on it.
                while let Ok(reply_tx) = snapshot_req_rx.try_recv() {
                    let result = world
                        .begin_snapshot()
                        .map_err(|err| err.to_string())
                        .and_then(|job| job.encode_all().map_err(|err| err.to_string()))
                        .map(|bytes| (bytes, world.live_connections()));
                    let _ = reply_tx.send(result);
                }
                // OBI-180 M-FS-5 (CTO review of PR #119, must-fix 1):
                // install any compile `World::tick`'s `poll_recompiles`
                // finished since the last pass, answer the request that
                // was waiting on it, and start that uid's queued compile
                // (if any) next -- see `drain_finished_recompiles`'s doc.
                drain_finished_recompiles(&mut world, &mut host, &mut compile_slots);
                // OBI-180 M-FS-1: a file-op request from an `/api/v1/files/*`
                // HTTP handler, drained the same non-blocking way as every
                // other side-channel input to this loop.
                // `World::call_file_efun`/`call_file_write_if_match` are the
                // whole mitigation: guard set exactly `{uid}`, the real
                // `valid_*` master apply, unchanged quotas/audit.
                //
                // CTO review non-blocking item: bounded per world-tick pass
                // (`FILE_OPS_PER_TICK_BUDGET`) rather than draining the whole
                // queue unconditionally -- `FILE_OP_QUEUE_DEPTH` (64) file
                // ops each running a full `exec` could otherwise all land in
                // one tick, at real cost to tick latency; this caps that
                // without needing backpressure to actually trip. A `Compile`
                // request never runs a full compile inline (see
                // `CompileSlot`'s doc) -- it only ever starts or queues one
                // -- so it counts against this budget the same cheap way
                // `Read`/`WriteIfMatch`/`List` do.
                for _ in 0..FILE_OPS_PER_TICK_BUDGET {
                    let Ok(req) = file_op_rx.try_recv() else {
                        break;
                    };
                    // `Compile` doesn't fit the immediate request/response
                    // shape every other `FileOpKind` does (CTO review of PR
                    // #119, must-fix 1/2): it either starts a background
                    // compile and parks `req` in `compile_slots` until
                    // `drain_finished_recompiles` answers it, queues it
                    // behind one already in flight for this uid, or (a
                    // newer request displacing an older queued one)
                    // answers `409` immediately -- never an `exec`-bounded
                    // result on this same pass.
                    if matches!(req.kind, loom_http::files::FileOpKind::Compile) {
                        enqueue_compile(&mut world, &mut host, &mut compile_slots, req);
                        continue;
                    }
                    let result: Result<loom_http::files::FileOpValue, loom_http::files::FileOpError> =
                        match &req.kind {
                            loom_http::files::FileOpKind::Read => world
                                .call_file_efun(
                                    &req.uid,
                                    "read_file",
                                    vec![Value::str(&req.path)],
                                    &mut host,
                                )
                                .map_err(loom_http::files::FileOpError::Refused)
                                .and_then(|v| {
                                    file_op_value_from_read(v)
                                        .map_err(loom_http::files::FileOpError::Refused)
                                }),
                            loom_http::files::FileOpKind::WriteIfMatch { precondition, text } => world
                                .call_file_write_if_match(
                                    &req.uid,
                                    &req.path,
                                    vm_precondition_from_http(precondition),
                                    text,
                                    &mut host,
                                )
                                .map(file_op_value_from_cas)
                                .map_err(loom_http::files::FileOpError::Refused),
                            loom_http::files::FileOpKind::List => match world
                                .list_dir(&req.uid, &req.path, &mut host)
                            {
                                Ok(Some(result)) => Ok(loom_http::files::FileOpValue::Entries {
                                    names: result.names,
                                    truncated: result.truncated,
                                }),
                                Ok(None) => Err(loom_http::files::FileOpError::Refused(
                                    "get_dir refused or the directory does not exist".to_string(),
                                )),
                                Err(loom_vm::world::ListDirError::Refused(msg)) => {
                                    Err(loom_http::files::FileOpError::Refused(msg))
                                }
                                Err(loom_vm::world::ListDirError::Internal(msg)) => {
                                    Err(loom_http::files::FileOpError::Internal(msg))
                                }
                            },
                            loom_http::files::FileOpKind::Compile => {
                                unreachable!("handled above, before this match")
                            }
                        };
                    req.respond(result);
                }
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

    fn set_echo(&mut self, conn: u64, enabled: bool) {
        let _ = self
            .command_tx
            .blocking_send(NetCommand::SetEcho(conn, enabled));
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

/// Persistent `SIGINT`/`SIGTERM` listener, for callers that need to
/// `recv()` more than once over their lifetime (CTO review, OBI-253):
/// unlike the one-shot [`shutdown_signal`] (fine for `serve`, which only
/// ever waits for a shutdown signal once), `tokio::signal::unix::signal`
/// streams must be created exactly once and reused -- each call installs
/// a fresh stream that only observes signals delivered *after* it was
/// created, so calling [`shutdown_signal`] repeatedly (as `supervise`'s
/// respawn loop originally did, once per attempt and again around its
/// backoff sleep) silently drops any signal that arrives in the gap
/// between one call returning and the next one's `signal()` call
/// finishing -- exactly the window `supervise`'s crash-backoff sleep sat
/// in.
struct ShutdownSignals {
    #[cfg(unix)]
    sigint: tokio::signal::unix::Signal,
    #[cfg(unix)]
    sigterm: tokio::signal::unix::Signal,
}

impl ShutdownSignals {
    fn new() -> Result<Self, String> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Self {
                sigint: signal(SignalKind::interrupt())
                    .map_err(|err| format!("install SIGINT handler: {err}"))?,
                sigterm: signal(SignalKind::terminate())
                    .map_err(|err| format!("install SIGTERM handler: {err}"))?,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }

    /// Waits for the next `SIGINT`/`SIGTERM` (Unix) or Ctrl-C (other
    /// platforms). Safe to call repeatedly across the lifetime of the
    /// one `ShutdownSignals` that owns the underlying stream(s) --
    /// unlike re-running [`shutdown_signal`], no signal delivered
    /// between calls is missed.
    async fn recv(&mut self) {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = self.sigint.recv() => {}
                _ = self.sigterm.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
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
