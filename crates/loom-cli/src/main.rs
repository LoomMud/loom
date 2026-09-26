// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

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
        other => Err(format!("unknown command: {other}")),
    }
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

    let world = World::boot(&mudlib_root).map_err(|err| format!("world boot failed: {err}"))?;
    let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let (command_tx, command_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let world_handle = spawn_world_thread(world, event_rx, command_tx.clone());

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

fn spawn_world_thread(
    mut world: World,
    mut event_rx: mpsc::Receiver<NetEvent>,
    command_tx: mpsc::Sender<NetCommand>,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("loom-world".to_string())
        .spawn(move || {
            let mut host = NetHost { command_tx };

            while let Some(event) = event_rx.blocking_recv() {
                match event {
                    NetEvent::Connected(conn) => world.connect(conn, &mut host),
                    NetEvent::Line(conn, line) => world.input(conn, &line, &mut host),
                    NetEvent::Disconnected(conn) => world.disconnect(conn, &mut host),
                }
            }
        })
        .expect("failed to spawn world thread")
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
