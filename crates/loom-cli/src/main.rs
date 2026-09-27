// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `loom` command-line entry point (`serve`, `check`, ...).

use std::path::PathBuf;
use std::thread;

use loom_net::{NetCommand, NetConfig, NetEvent};
use loom_vm::{Host, World};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tracing::{error, info};

const EVENT_CHANNEL_CAPACITY: usize = 1024;
const COMMAND_CHANNEL_CAPACITY: usize = 1024;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    init_tracing();

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

    let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let (command_tx, command_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let world_handle = spawn_world_thread(mudlib_root.clone(), event_rx, command_tx.clone())?;

    info!(bind = %actual_addr, mudlib = %mudlib_root.display(), "loom server started");

    let mut server = tokio::spawn(loom_net::run_server(
        listener,
        NetConfig::default(),
        event_tx,
        command_rx,
        shutdown_rx,
    ));

    tokio::select! {
        result = &mut server => {
            result
                .map_err(|err| format!("network server task failed: {err}"))?
                .map_err(|err| format!("network server failed: {err}"))?;
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
    drop(command_tx);

    world_handle
        .join()
        .map_err(|_| "world thread panicked".to_string())?;

    Ok(())
}

/// Spawn the world thread. The `World` is not `Send` (single-threaded heap,
/// spec §3.3), so it is booted *on* the world thread; boot errors are
/// reported back before we start accepting connections.
fn spawn_world_thread(
    mudlib_root: PathBuf,
    mut event_rx: mpsc::Receiver<NetEvent>,
    command_tx: mpsc::Sender<NetCommand>,
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
            let mut host = NetHost { command_tx };

            while let Some(event) = event_rx.blocking_recv() {
                match event {
                    NetEvent::Connected(conn) => world.connect(conn, &mut host),
                    NetEvent::Line(conn, line) => world.input(conn, &line, &mut host),
                    NetEvent::Disconnected(conn) => world.disconnect(conn, &mut host),
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
}

fn init_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::from_default_env();
    let use_json = std::env::var("LOOM_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    if use_json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .with_current_span(true)
            .with_span_list(true)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
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
