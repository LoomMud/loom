// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! WebSocket transport for the same `NetEvent`/`NetCommand` seam the
//! telnet codec (`lib.rs`) speaks (spec §8/§9, OBI-39). A browser session
//! is just another connection in `run_server`'s registry: it gets a
//! `ConnId` from the same counter, its outbound `ConnControl` channel has
//! the same `output_queue_depth` bound (so a slow WS reader is dropped by
//! the exact same "queue full -> disconnect" path in `run_server` as a
//! slow telnet client), and its inbound lines go through the same
//! [`TokenBucket`] rate limiter and `max_line_bytes` cap.
//!
//! Framing is a small JSON envelope rather than telnet's byte stream,
//! because a WS frame is already message-shaped and the acceptance
//! criteria call for "GMCP over WS as JSON messages": there is no telnet
//! subnegotiation to imitate, so both plain input lines and GMCP frames
//! use the same envelope shape, tagged by `type`.

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use axum::extract::ws::{Message, WebSocket};

use crate::{
    ConnControl, ConnId, MAX_SUBNEGOTIATION_BYTES, NetConfig, NetEvent, TokenBucket, telnet,
};

/// Inbound envelope a browser client sends. Unknown `type`s and malformed
/// JSON are dropped (logged at debug), not treated as a disconnect: a
/// forward-compatible client is expected to send fields we don't know
/// about yet, and dropping one bad frame is strictly better than tearing
/// down the session over it.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum ClientEnvelope {
    Line {
        text: String,
    },
    Gmcp {
        package: String,
        #[serde(default)]
        payload: serde_json::Value,
    },
}

/// Outbound envelope sent to the browser client.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum ServerEnvelope<'a> {
    Line {
        text: &'a str,
    },
    Gmcp {
        package: &'a str,
        payload: &'a serde_json::Value,
    },
    /// WS equivalent of telnet's `IAC WILL/WONT ECHO` (OBI-176): the web
    /// client masks its input field while `enabled` is `false` and
    /// restores plain text entry once it comes back `true`.
    Echo {
        enabled: bool,
    },
}

/// Runs one accepted WebSocket connection. Mirrors `run_connection` in
/// `lib.rs`: reads `control_rx` for outbound `ConnControl`s (already
/// backpressured by `run_server`) and the socket for inbound frames,
/// until either side closes.
pub(crate) async fn run_ws_connection(
    conn_id: ConnId,
    socket: WebSocket,
    config: NetConfig,
    mut control_rx: mpsc::Receiver<ConnControl>,
    event_tx: mpsc::Sender<NetEvent>,
    closed_tx: mpsc::Sender<ConnId>,
) {
    let (mut sink, mut stream) = socket.split();
    let mut bucket = TokenBucket::new(config.rate_limit_burst, config.rate_limit_per_second);

    loop {
        tokio::select! {
            control = control_rx.recv() => {
                let Some(control) = control else { break };
                match control {
                    ConnControl::Send(text) => {
                        let env = ServerEnvelope::Line { text: &text };
                        if send_json(&mut sink, &env).await.is_err() {
                            break;
                        }
                    }
                    ConnControl::SendGmcp(package_message, payload) => {
                        let env = ServerEnvelope::Gmcp {
                            package: &package_message,
                            payload: &payload,
                        };
                        if send_json(&mut sink, &env).await.is_err() {
                            break;
                        }
                    }
                    ConnControl::Close => {
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                    ConnControl::SetEcho(enabled) => {
                        let env = ServerEnvelope::Echo { enabled };
                        if send_json(&mut sink, &env).await.is_err() {
                            break;
                        }
                    }
                    ConnControl::Reclaim(reply_tx) => {
                        // Copyover fd hand-off (OBI-184) has no WebSocket
                        // story yet -- reclaiming a raw TCP fd back out of
                        // an upgraded `axum` WebSocket is a separate,
                        // not-yet-needed follow-up (today's E2.2-docker
                        // gate only exercises telnet bots). Answer `None`
                        // rather than silently dropping the request, so a
                        // caller that asks for a WS connection's socket
                        // gets a clear "not available", not a hang.
                        //
                        // Reviewed (OBI-227): `run_server_full` already
                        // removed this connection's `ConnEntry` before
                        // sending the `Reclaim` control, so nothing can
                        // route further `NetCommand`s here even if this
                        // loop kept running -- a zombie that still reads
                        // the client's input and emits `NetEvent::Line`s
                        // for a `conn_id` the registry no longer tracks.
                        // Since a `None` reply means this session does
                        // not survive the copyover, actually end it here:
                        // close the socket and fall through to the normal
                        // disconnect bookkeeping below.
                        let _ = reply_tx.send(None);
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                }
            }
            incoming = stream.next() => {
                let Some(incoming) = incoming else { break };
                let Ok(message) = incoming else { break };

                match message {
                    Message::Text(text) => {
                        if !bucket.try_take() {
                            warn!(conn_id, "disconnecting: input rate limit exceeded");
                            metrics::counter!("loom_net_rate_limit_disconnects_total")
                                .increment(1);
                            break;
                        }

                        if text.len() > config.max_line_bytes {
                            debug!(conn_id, len = text.len(), "disconnecting WS client: line over max_line_bytes");
                            break;
                        }

                        match serde_json::from_str::<ClientEnvelope>(&text) {
                            Ok(ClientEnvelope::Line { text }) => {
                                if event_tx.send(NetEvent::Line(conn_id, text)).await.is_err() {
                                    break;
                                }
                            }
                            Ok(ClientEnvelope::Gmcp { package, payload }) => {
                                if text.len() > MAX_SUBNEGOTIATION_BYTES {
                                    debug!(conn_id, "dropping oversized WS GMCP frame");
                                    continue;
                                }
                                let msg = telnet::classify_gmcp(&package, payload);
                                if event_tx.send(NetEvent::Gmcp(conn_id, msg)).await.is_err() {
                                    break;
                                }
                            }
                            Err(err) => {
                                debug!(conn_id, %err, "dropping malformed WS envelope");
                            }
                        }
                    }
                    Message::Close(_) => break,
                    Message::Binary(_) | Message::Ping(_) | Message::Pong(_) => {}
                }
            }
            else => break,
        }
    }

    let _ = event_tx.send(NetEvent::Disconnected(conn_id)).await;
    let _ = closed_tx.send(conn_id).await;
}

async fn send_json(
    sink: &mut (impl SinkExt<Message, Error = axum::Error> + Unpin),
    value: &impl Serialize,
) -> Result<(), axum::Error> {
    let text = serde_json::to_string(value).unwrap_or_default();
    sink.send(Message::Text(text.into())).await
}
