// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `loom-lsp` CLI: `--stdio` (default, for VS Code/neovim) or `--ws <addr>`
//! (the web IDE bridge, OBI-168). `--root <dir>` picks the mudlib/warp
//! checkout to serve; defaults to the client's `rootUri` over stdio, or
//! the current directory.

use std::net::SocketAddr;
use std::path::PathBuf;

use lsp_server::Connection;

enum Transport {
    Stdio,
    Ws(SocketAddr),
}

struct Args {
    transport: Transport,
    root: PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let mut transport = Transport::Stdio;
    let mut root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--stdio" => transport = Transport::Stdio,
            "--ws" => {
                let addr = it.next().ok_or("--ws needs an address, e.g. 127.0.0.1:7777")?;
                transport = Transport::Ws(
                    addr.parse()
                        .map_err(|e| format!("invalid --ws address {addr:?}: {e}"))?,
                );
            }
            "--root" => {
                root = it.next().ok_or("--root needs a path")?.into();
            }
            "-h" | "--help" => {
                println!(
                    "loom-lsp [--stdio | --ws HOST:PORT] [--root DIR]\n\n\
                     --stdio       run over stdin/stdout (default; VS Code, neovim)\n\
                     --ws ADDR     run a WebSocket bridge on ADDR (one LSP session per connection)\n\
                     --root DIR    the warp/mudlib checkout to serve (default: cwd, or the client's rootUri over stdio)"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?} (try --help)")),
        }
    }
    Ok(Args { transport, root })
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = parse_args().map_err(|e| {
        eprintln!("loom-lsp: {e}");
        e
    })?;

    match args.transport {
        Transport::Stdio => {
            let (connection, io_threads) = Connection::stdio();
            loom_lsp::server::run(connection, args.root)?;
            io_threads.join()?;
        }
        Transport::Ws(addr) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(loom_lsp::ws::serve(addr, args.root))?;
        }
    }
    Ok(())
}
