// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The WebSocket transport (for the web IDE, P2-B2, OBI-168 scope item
//! "runs ... over a WebSocket bridge"): each connection gets its own
//! [`lsp_server::Connection::memory`] pair, with one end driven by
//! [`crate::server::run`] (same code as stdio) and the other bridged to
//! the socket by this module -- a text WS frame per LSP message, no
//! `Content-Length` framing (the WS frame boundary already *is* the
//! message boundary).
//!
//! **This bridge is a local/dev tool, not the production path** (CTO
//! review of OBI-168, F2): it has no authentication and, today, no
//! `Vfs`/`ReadAuthorizer` gating of its own -- `main.rs` wires `--ws` to
//! plain `Local` mode. Real staff exposure goes through `loom-http` with
//! a D-TM4 single-use ticket and a `GatedProvider` (OBI-180's job). To
//! keep an accidentally-public `--ws` from being a real `/secure`-reading
//! listener, [`serve`] refuses to bind anything but a loopback address
//! unless the caller explicitly opts in.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use lsp_server::{Connection, Message};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

/// Spec M-LSP-4: "WS `max_message_size` 4 MiB and `max_frame_size` 1 MiB"
/// (tungstenite's defaults are 64 MiB / 16 MiB).
const MAX_WS_MESSAGE_BYTES: usize = 4 << 20;
const MAX_WS_FRAME_BYTES: usize = 1 << 20;
/// Spec M-LSP-4: "\u2264 32 sessions total" (per-uid caps are OBI-180's job,
/// since this bridge has no uid concept of its own).
const MAX_SESSIONS: usize = 32;
/// Spec M-LSP-4: "a 60 s idle ping/pong timeout".
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_WS_FRAME_BYTES))
}

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
///
/// Refuses to bind a non-loopback address unless `allow_public` is set
/// (F2): this bridge is unauthenticated and, in `Local` mode, every file
/// under `root` is readable by anyone who can reach the port. Binding it
/// to `0.0.0.0` (or any non-loopback address) would make `loom-lsp` an
/// open file-read oracle over the network. If the web IDE (OBI-180) ever
/// needs this bridge reachable off-box, that needs its own D-TM4 ticket
/// auth and `Vfs` gating in front of it, not a relaxed bind check here.
pub async fn serve(addr: SocketAddr, root: PathBuf, allow_public: bool) -> std::io::Result<()> {
    if !addr.ip().is_loopback() && !allow_public {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing to bind non-loopback address {addr} for the unauthenticated --ws \
                 bridge (spec M-LSP-2/M-LSP-5, CTO review F2); use a loopback address, or pass \
                 --ws-insecure-public if you have deliberately put real auth/gating in front of \
                 this process"
            ),
        ));
    }
    if allow_public {
        tracing::warn!(
            %addr,
            "loom-lsp: --ws-insecure-public set; binding a non-loopback address with no \
             authentication and (in --root mode) every file readable. This is a dev/debug \
             escape hatch, not a supported deployment."
        );
    }
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "loom-lsp: listening for WebSocket LSP clients");
    let sessions = Arc::new(AtomicUsize::new(0));
    loop {
        let (stream, peer) = listener.accept().await?;
        let root = root.clone();
        let sessions = sessions.clone();
        // Spec M-LSP-4: "\u2264 32 sessions total". Checked here, not inside
        // `handle_connection`, so a refused connection never even reaches
        // the WS handshake.
        if sessions.fetch_add(1, Ordering::SeqCst) >= MAX_SESSIONS {
            sessions.fetch_sub(1, Ordering::SeqCst);
            tracing::warn!(%peer, "loom-lsp: refusing connection, at the session cap (M-LSP-4)");
            continue;
        }
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, root).await {
                tracing::warn!(%peer, error = %e, "loom-lsp: WebSocket session ended with an error");
            }
            sessions.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    root: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ws = tokio_tungstenite::accept_async_with_config(stream, Some(ws_config())).await?;
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
    // async task directly. (The channel is unbounded, but `server.rs`'s own
    // bounded job queue -- MAX_PENDING_REQUESTS -- is what actually bounds
    // outstanding work; a flood of messages here just queues cheap
    // `Message` values, not compiles.)
    let sender = bridge_conn.sender.clone();
    let to_server = async move {
        loop {
            let frame = match tokio::time::timeout(IDLE_TIMEOUT, ws_stream.next()).await {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(_) => {
                    return Err::<(), Box<dyn std::error::Error + Send + Sync>>(
                        "idle timeout (M-LSP-4, 60s)".into(),
                    );
                }
            };
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
        Ok(())
    };

    // Server -> client: `bridge_conn.receiver.recv()` blocks synchronously,
    // so that side of the bridge runs on its own blocking thread and
    // forwards into an async-friendly mpsc channel the WS write loop reads.
    // (Also unbounded; see the `to_server` comment above -- the same
    // bounded-job-queue argument applies to responses flowing back.)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// F2 (CTO review of OBI-168): `serve` must refuse a non-loopback
    /// bind address unless the caller explicitly opts in, since the
    /// bridge has no authentication of its own.
    #[tokio::test]
    async fn serve_refuses_non_loopback_without_opt_in() {
        let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let err = serve(addr, PathBuf::from("."), false).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    /// A loopback address is always allowed, with no opt-in needed (this
    /// is the documented, supported dev/local-editor path). Binds port 0
    /// (OS-assigned) and immediately drops the listener, just to prove
    /// `serve` gets past the bind-address check and into `TcpListener::bind`.
    #[tokio::test]
    async fn loopback_bind_check_allows_without_opt_in() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            serve(addr, PathBuf::from("."), false),
        )
        .await;
        // `serve` only returns if the bind itself fails (it loops forever
        // accepting connections otherwise); timing out means it got past
        // the bind-address check and is sitting in `listener.accept()`.
        assert!(
            result.is_err(),
            "serve should still be running (bind succeeded), not have returned"
        );
    }
}
