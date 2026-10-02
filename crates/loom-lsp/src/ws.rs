// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The WebSocket transport (for the web IDE, P2-B2, OBI-168 scope item
//! "runs ... over a WebSocket bridge"): each connection gets its own
//! [`lsp_server::Connection::memory`] pair, with one end driven by
//! [`crate::server::run`] (same code as stdio) and the other bridged to
//! the socket by this module -- a text WS frame per LSP message, no
//! `Content-Length` framing (the WS frame boundary already *is* the
//! message boundary).

use std::path::PathBuf;

use futures_util::{SinkExt, StreamExt};
use lsp_server::{Connection, Message};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// Serialize one [`Message`] the same way `lsp_server`'s stdio transport
/// does (a `{"jsonrpc":"2.0", ...}` object), just without the
/// `Content-Length` header a WS text frame doesn't need.
fn message_to_text(msg: &Message) -> serde_json::Result<String> {
    #[derive(serde::Serialize)]
    struct JsonRpc<'a> {
        jsonrpc: &'static str,
        #[serde(flatten)]
        msg: &'a Message,
    }
    serde_json::to_string(&JsonRpc {
        jsonrpc: "2.0",
        msg,
    })
}

/// Accept connections on `addr` until the process exits; each one runs an
/// independent `loom-lsp` session rooted at `root`.
pub async fn serve(addr: std::net::SocketAddr, root: PathBuf) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "loom-lsp: listening for WebSocket LSP clients");
    loop {
        let (stream, peer) = listener.accept().await?;
        let root = root.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, root).await {
                tracing::warn!(%peer, error = %e, "loom-lsp: WebSocket session ended with an error");
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    root: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ws = tokio_tungstenite::accept_async(stream).await?;
    let (mut ws_sink, mut ws_stream) = ws.split();

    let (server_conn, bridge_conn) = Connection::memory();

    // The synchronous protocol core runs on a blocking thread (it owns a
    // `Session`/`Workspace` that are not `Send`-across-await-points
    // friendly to juggle, and it never performs I/O itself -- only
    // channel send/recv -- so blocking a thread, not the executor, is the
    // right tool here).
    let _server_task = tokio::task::spawn_blocking(move || crate::server::run(server_conn, root));

    // Client -> server: one WS text frame is one LSP message. `Sender::send`
    // on an unbounded crossbeam channel never blocks, so this stays on the
    // async task directly.
    let sender = bridge_conn.sender.clone();
    let to_server = async move {
        while let Some(frame) = ws_stream.next().await {
            let frame = frame?;
            let text = match frame {
                WsMessage::Text(t) => t.to_string(),
                WsMessage::Close(_) => break,
                WsMessage::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
                _ => continue,
            };
            let msg: Message = serde_json::from_str(&text)?;
            if sender.send(msg).is_err() {
                break;
            }
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };

    // Server -> client: `bridge_conn.receiver.recv()` blocks synchronously,
    // so that side of the bridge runs on its own blocking thread and
    // forwards into an async-friendly mpsc channel the WS write loop reads.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
    let receiver = bridge_conn.receiver.clone();
    std::thread::spawn(move || {
        for msg in &receiver {
            if tx.send(msg).is_err() {
                break;
            }
        }
    });
    let to_client = async move {
        while let Some(msg) = rx.recv().await {
            let text = message_to_text(&msg)?;
            ws_sink.send(WsMessage::Text(text.into())).await?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };

    tokio::select! {
        r = to_server => { r?; }
        r = to_client => { r?; }
    }
    Ok(())
}
