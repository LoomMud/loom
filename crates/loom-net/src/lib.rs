// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Telnet/WebSocket networking and sessions (§8.2). Owner: Legolas.

mod telnet;
mod ws;

use std::collections::HashMap;
use std::io;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

pub use telnet::GmcpMessage;
use telnet::{DO, DONT, IAC, SB, SE, TelnetEvent, TelnetOptionTable, WILL, WONT, encode_gmcp};

pub type ConnId = u64;

/// Cap on any telnet subnegotiation body (CTO decision, OBI-26): GMCP in
/// particular carries a client-controlled JSON parser on the network
/// edge, so an oversized frame gets dropped (and counted), not buffered
/// without bound.
pub(crate) const MAX_SUBNEGOTIATION_BYTES: usize = 8192;

pub const DEFAULT_TELNET_ADDR: &str = "0.0.0.0:4000";

pub fn telnet_addr_from_env() -> String {
    std::env::var("LOOM_TELNET_ADDR").unwrap_or_else(|_| DEFAULT_TELNET_ADDR.to_string())
}

#[derive(Debug, Clone)]
pub struct NetConfig {
    pub max_line_bytes: usize,
    pub read_buffer_bytes: usize,
    pub output_queue_depth: usize,
    pub rate_limit_burst: u32,
    pub rate_limit_per_second: f64,
    /// Static MSSP fields (spec §7), e.g. `NAME`, `CODEBASE`, `UPTIME`.
    /// Sent verbatim once the client accepts `WILL MSSP`; there is no
    /// dynamic refresh (player counts etc.) in the alpha.
    pub mssp_fields: Vec<(String, String)>,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            max_line_bytes: 4096,
            read_buffer_bytes: 1024,
            output_queue_depth: 64,
            rate_limit_burst: 20,
            rate_limit_per_second: 5.0,
            mssp_fields: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetEvent {
    Connected(ConnId),
    Line(ConnId, String),
    Disconnected(ConnId),
    /// World-tick timer (spec r5 N2, OBI-82): `loom-cli::serve()` sends one
    /// of these every `WORLD_TICK_INTERVAL` (100 ms) so the world thread can
    /// call `World::tick(host)` between other events. Carries no data: the
    /// world thread advances its own scheduler tick counter (`call_out`
    /// delays are in world ticks, not wall-clock time), so a `Tick` is only
    /// ever "advance by one", never "advance to time T". The timer that
    /// produces this coalesces (see `loom-cli`'s tick task): if the world
    /// thread falls behind, at most one `Tick` is ever pending in the event
    /// channel, not one per missed 100 ms interval.
    Tick,
    /// NAWS: the client's terminal window size in columns/rows.
    WindowSize(ConnId, u16, u16),
    /// TTYPE: one name in the client's MTTS terminal-type cycle. May fire
    /// more than once per connection (spec §7); the world keeps the latest
    /// and/or the richest (`MTTS <bitmask>`) one it understands.
    TerminalType(ConnId, String),
    /// GMCP: one parsed `package.message` frame.
    Gmcp(ConnId, GmcpMessage),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetCommand {
    Send(ConnId, String),
    Close(ConnId),
    /// Send a structured GMCP message (`package.message` + JSON payload) to
    /// one connection. Silently dropped if the connection never enabled
    /// GMCP or has since disconnected.
    SendGmcp(ConnId, String, serde_json::Value),
}

/// Output framing: the world sends text verbatim and owns its line breaks
/// (`send(ob, "...\n")`); on the wire every `\n` becomes telnet's `\r\n`.
/// Nothing is appended, so prompts without a newline stay on the same line.
fn to_wire(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + 8);
    let mut prev = 0_u8;
    for &b in text.as_bytes() {
        if b == b'\n' && prev != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        prev = b;
    }
    out
}

#[derive(Debug)]
enum ConnControl {
    Send(String),
    Close,
    SendGmcp(String, serde_json::Value),
}

#[derive(Debug)]
struct ConnEntry {
    tx: mpsc::Sender<ConnControl>,
    task: JoinHandle<()>,
}

/// Telnet-only server: no WebSocket connections ever arrive. Kept as a
/// thin wrapper over [`run_server_with_ws`] so existing callers (and
/// tests) don't have to thread through an unused channel.
pub async fn run_server(
    listener: TcpListener,
    config: NetConfig,
    event_tx: mpsc::Sender<NetEvent>,
    command_rx: mpsc::Receiver<NetCommand>,
    shutdown_rx: watch::Receiver<bool>,
) -> io::Result<()> {
    // Held for the lifetime of the call so the `ws_accept_rx` select arm
    // never sees a closed channel (which would otherwise short-circuit
    // `tokio::select!`'s `else` branch); nothing ever sends on it.
    let (_ws_accept_tx, ws_accept_rx) = mpsc::channel(1);
    run_server_with_ws(
        listener,
        config,
        event_tx,
        command_rx,
        shutdown_rx,
        ws_accept_rx,
    )
    .await
}

/// Telnet server that also accepts already-upgraded WebSocket connections
/// pushed in from `loom-http`'s `/ws` route (OBI-39). A WS connection
/// shares this function's `ConnId` counter, its `conns` registry (so
/// `NetCommand::Send`/`SendGmcp`/`Close` reach it exactly like a telnet
/// connection), and therefore the same `output_queue_depth` backpressure:
/// a slow WS reader is dropped by the same "queue full" path below as a
/// slow telnet client, not a separate one.
pub async fn run_server_with_ws(
    listener: TcpListener,
    config: NetConfig,
    event_tx: mpsc::Sender<NetEvent>,
    mut command_rx: mpsc::Receiver<NetCommand>,
    mut shutdown_rx: watch::Receiver<bool>,
    mut ws_accept_rx: mpsc::Receiver<axum::extract::ws::WebSocket>,
) -> io::Result<()> {
    let mut next_conn_id: ConnId = 1;
    let mut conns: HashMap<ConnId, ConnEntry> = HashMap::new();
    let (closed_tx, mut closed_rx) = mpsc::channel::<ConnId>(256);

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                debug!("shutdown signal received by net server");
                break;
            }
            Some(conn_id) = closed_rx.recv() => {
                conns.remove(&conn_id);
            }
            Some(socket) = ws_accept_rx.recv() => {
                let conn_id = next_conn_id;
                next_conn_id += 1;

                debug!(conn_id, "accepted websocket connection");
                if event_tx.send(NetEvent::Connected(conn_id)).await.is_err() {
                    break;
                }

                let (tx, rx) = mpsc::channel(config.output_queue_depth);
                let conn_event_tx = event_tx.clone();
                let conn_closed_tx = closed_tx.clone();
                let conn_config = config.clone();
                let task = tokio::spawn(async move {
                    ws::run_ws_connection(conn_id, socket, conn_config, rx, conn_event_tx, conn_closed_tx).await;
                });

                conns.insert(conn_id, ConnEntry { tx, task });
            }
            Some(cmd) = command_rx.recv() => {
                match cmd {
                    NetCommand::Send(conn, text) => {
                        let Some(entry) = conns.get(&conn) else {
                            continue;
                        };

                        match entry.tx.try_send(ConnControl::Send(text)) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                warn!(conn, "disconnecting slow client: output queue full");
                                if let Some(entry) = conns.remove(&conn) {
                                    entry.task.abort();
                                }
                                let _ = event_tx.send(NetEvent::Disconnected(conn)).await;
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                conns.remove(&conn);
                            }
                        }
                    }
                    NetCommand::Close(conn) => {
                        if let Some(entry) = conns.remove(&conn) {
                            match entry.tx.try_send(ConnControl::Close) {
                                Ok(()) => {}
                                Err(_) => {
                                    entry.task.abort();
                                    let _ = event_tx.send(NetEvent::Disconnected(conn)).await;
                                }
                            }
                        }
                    }
                    NetCommand::SendGmcp(conn, package_message, payload) => {
                        let Some(entry) = conns.get(&conn) else {
                            continue;
                        };

                        match entry
                            .tx
                            .try_send(ConnControl::SendGmcp(package_message, payload))
                        {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                warn!(conn, "disconnecting slow client: output queue full");
                                if let Some(entry) = conns.remove(&conn) {
                                    entry.task.abort();
                                }
                                let _ = event_tx.send(NetEvent::Disconnected(conn)).await;
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                conns.remove(&conn);
                            }
                        }
                    }
                }
            }
            accepted = listener.accept() => {
                let (stream, peer_addr) = accepted?;
                let conn_id = next_conn_id;
                next_conn_id += 1;

                debug!(conn_id, %peer_addr, "accepted connection");
                if event_tx.send(NetEvent::Connected(conn_id)).await.is_err() {
                    break;
                }

                let (tx, rx) = mpsc::channel(config.output_queue_depth);
                let conn_event_tx = event_tx.clone();
                let conn_closed_tx = closed_tx.clone();
                let conn_config = config.clone();
                let task = tokio::spawn(async move {
                    run_connection(conn_id, stream, conn_config, rx, conn_event_tx, conn_closed_tx).await;
                });

                conns.insert(conn_id, ConnEntry { tx, task });
            }
            else => break,
        }
    }

    for (conn, entry) in conns.drain() {
        entry.task.abort();
        let _ = event_tx.send(NetEvent::Disconnected(conn)).await;
    }

    Ok(())
}

async fn run_connection(
    conn_id: ConnId,
    stream: TcpStream,
    config: NetConfig,
    mut control_rx: mpsc::Receiver<ConnControl>,
    event_tx: mpsc::Sender<NetEvent>,
    closed_tx: mpsc::Sender<ConnId>,
) {
    let (mut reader, mut writer) = stream.into_split();
    let mut read_buf = vec![0_u8; config.read_buffer_bytes];
    let mut codec = TelnetCodec::new(
        config.max_line_bytes,
        config.rate_limit_burst,
        config.rate_limit_per_second,
        config.mssp_fields.clone(),
    );

    let mut disconnected_sent = false;

    let start_bytes = codec.start();
    if !start_bytes.is_empty() && writer.write_all(&start_bytes).await.is_err() {
        disconnected_sent = true;
        let _ = event_tx.send(NetEvent::Disconnected(conn_id)).await;
    }

    if !disconnected_sent {
        loop {
            tokio::select! {
                Some(control) = control_rx.recv() => {
                    match control {
                        ConnControl::Send(text) => {
                            if writer.write_all(&to_wire(&text)).await.is_err() {
                                break;
                            }
                        }
                        ConnControl::SendGmcp(package_message, payload) => {
                            if codec.gmcp_enabled() {
                                let bytes = encode_gmcp(&package_message, &payload);
                                if writer.write_all(&bytes).await.is_err() {
                                    break;
                                }
                            } else {
                                debug!(
                                    conn_id,
                                    package_message,
                                    "dropping SendGmcp: GMCP was never negotiated on this connection"
                                );
                            }
                        }
                        ConnControl::Close => {
                            break;
                        }
                    }
                }
                read = reader.read(&mut read_buf) => {
                    let Ok(n) = read else {
                        break;
                    };
                    if n == 0 {
                        break;
                    }

                    match codec.feed(&read_buf[..n]) {
                        CodecOutcome::Ok { lines, responses, events } => {
                            let mut should_break = false;
                            for response in responses {
                                if writer.write_all(&response).await.is_err() {
                                    disconnected_sent = true;
                                    let _ = event_tx.send(NetEvent::Disconnected(conn_id)).await;
                                    should_break = true;
                                    break;
                                }
                            }
                            if should_break {
                                break;
                            }

                            for event in events {
                                let net_event = match event {
                                    TelnetEvent::WindowSize(w, h) => NetEvent::WindowSize(conn_id, w, h),
                                    TelnetEvent::TerminalType(name) => NetEvent::TerminalType(conn_id, name),
                                    TelnetEvent::Gmcp(msg) => NetEvent::Gmcp(conn_id, msg),
                                };
                                if event_tx.send(net_event).await.is_err() {
                                    should_break = true;
                                    break;
                                }
                            }
                            if should_break {
                                break;
                            }

                            for line in lines {
                                if event_tx.send(NetEvent::Line(conn_id, line)).await.is_err() {
                                    should_break = true;
                                    break;
                                }
                            }
                            if should_break {
                                break;
                            }
                        }
                        CodecOutcome::Disconnect(reason) => {
                            warn!(conn_id, reason = reason.as_str(), "disconnecting: {}", reason.as_str());
                            if reason == DisconnectReason::RateLimited {
                                metrics::counter!("loom_net_rate_limit_disconnects_total")
                                    .increment(1);
                            }
                            break;
                        }
                    }
                }
                else => break,
            }
        }
    }

    if !disconnected_sent {
        let _ = event_tx.send(NetEvent::Disconnected(conn_id)).await;
    }
    let _ = closed_tx.send(conn_id).await;
}

#[derive(Debug)]
enum CodecOutcome {
    Ok {
        lines: Vec<String>,
        responses: Vec<Vec<u8>>,
        events: Vec<TelnetEvent>,
    },
    Disconnect(DisconnectReason),
}

/// Why [`CodecOutcome::Disconnect`] fired (OBI-149): logged at the one
/// call site that owns `conn_id` (`spawn_reader`) so a disconnect caused
/// by the input rate limit (20 burst, 5/s, `TokenBucket`) is
/// distinguishable in the logs from one caused by a client sending an
/// over-long line -- previously *both* closed the connection with no log
/// line at all, which cost an hour of flake-hunting in warp's smoke test
/// (a legitimate burst of input got rate-limited and disconnected, and
/// there was nothing to tell that apart from a client just hanging up).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisconnectReason {
    /// The per-connection input token bucket (burst/refill from
    /// `NetConfig::rate_limit_burst`/`rate_limit_per_second`) was empty.
    RateLimited,
    /// A line exceeded `max_line_bytes` before a terminator arrived.
    LineTooLong,
}

impl DisconnectReason {
    fn as_str(self) -> &'static str {
        match self {
            DisconnectReason::RateLimited => "input rate limit exceeded",
            DisconnectReason::LineTooLong => "input line too long",
        }
    }
}

#[derive(Debug)]
struct TelnetCodec {
    state: ParseState,
    line_buf: Vec<u8>,
    saw_cr: bool,
    max_line_bytes: usize,
    bucket: TokenBucket,
    options: TelnetOptionTable,
    sub_buf: Vec<u8>,
    sub_oversized: bool,
    oversize_subnegotiations: u64,
}

#[derive(Debug, Clone, Copy)]
enum ParseState {
    Data,
    Iac,
    IacVerb(u8),
    Subnegotiation,
    SubnegotiationIac,
}

impl TelnetCodec {
    fn new(
        max_line_bytes: usize,
        burst: u32,
        refill_per_second: f64,
        mssp_fields: Vec<(String, String)>,
    ) -> Self {
        Self {
            state: ParseState::Data,
            line_buf: Vec::with_capacity(128),
            saw_cr: false,
            max_line_bytes,
            bucket: TokenBucket::new(burst, refill_per_second),
            options: TelnetOptionTable::new(mssp_fields),
            sub_buf: Vec::new(),
            sub_oversized: false,
            oversize_subnegotiations: 0,
        }
    }

    /// Startup negotiation bytes to send right after accepting the
    /// connection, before reading anything from the client.
    fn start(&mut self) -> Vec<u8> {
        self.options.start()
    }

    /// Whether GMCP has actually been negotiated (`us == Yes`): gates
    /// `ConnControl::SendGmcp` so a caller can't push a GMCP frame onto a
    /// connection that never agreed to speak it.
    fn gmcp_enabled(&self) -> bool {
        self.options.is_enabled_us(telnet::OPT_GMCP)
    }

    fn feed(&mut self, chunk: &[u8]) -> CodecOutcome {
        let mut lines = Vec::new();
        let mut responses = Vec::new();
        let mut events = Vec::new();

        for byte in chunk {
            match self.state {
                ParseState::Data => {
                    if *byte == IAC {
                        self.state = ParseState::Iac;
                        continue;
                    }

                    if let Some(reason) = self.consume_data_byte(*byte, &mut lines) {
                        return CodecOutcome::Disconnect(reason);
                    }
                }
                ParseState::Iac => match *byte {
                    IAC => {
                        if let Some(reason) = self.consume_data_byte(IAC, &mut lines) {
                            return CodecOutcome::Disconnect(reason);
                        }
                        self.state = ParseState::Data;
                    }
                    DO | DONT | WILL | WONT => {
                        self.state = ParseState::IacVerb(*byte);
                    }
                    SB => {
                        self.sub_buf.clear();
                        self.sub_oversized = false;
                        self.state = ParseState::Subnegotiation;
                    }
                    _ => {
                        self.state = ParseState::Data;
                    }
                },
                ParseState::IacVerb(verb) => {
                    let response = if is_known_option(*byte) {
                        self.options.handle_verb(verb, *byte)
                    } else {
                        refusal_for(verb, *byte).unwrap_or_default()
                    };
                    if !response.is_empty() {
                        responses.push(response);
                    }
                    self.state = ParseState::Data;
                }
                ParseState::Subnegotiation => {
                    if *byte == IAC {
                        self.state = ParseState::SubnegotiationIac;
                    } else if self.sub_buf.len() >= MAX_SUBNEGOTIATION_BYTES {
                        // Cap any subnegotiation body at 8 KiB (CTO
                        // decision, OBI-26): a client-controlled parser
                        // (GMCP JSON in particular) sits on the network
                        // edge, so an oversized frame must be dropped and
                        // counted, not buffered forever or used to
                        // disconnect the connection outright.
                        self.sub_oversized = true;
                    } else {
                        self.sub_buf.push(*byte);
                    }
                }
                ParseState::SubnegotiationIac => {
                    if *byte == SE {
                        if self.sub_oversized {
                            self.oversize_subnegotiations += 1;
                            warn!(
                                total = self.oversize_subnegotiations,
                                "dropped oversized telnet subnegotiation (> {MAX_SUBNEGOTIATION_BYTES} bytes)"
                            );
                            // A flood of oversized junk frames is exactly
                            // the kind of client-controlled-parser cost
                            // the rate limit exists for (CTO review,
                            // OBI-26): charge a token here too, not just
                            // on successfully-parsed frames below.
                            if !self.bucket.try_take() {
                                return CodecOutcome::Disconnect(DisconnectReason::RateLimited);
                            }
                        } else {
                            let is_gmcp = self.sub_buf.first() == Some(&telnet::OPT_GMCP);
                            let (response, event) =
                                self.options.handle_subnegotiation(&self.sub_buf);
                            if !response.is_empty() {
                                responses.push(response);
                            }
                            if let Some(event) = event {
                                events.push(event);
                            }
                            // GMCP frames count against the same
                            // per-connection input rate limit as text
                            // lines (CTO decision, OBI-26): it's a
                            // client-controlled parser on the network
                            // edge, same as line input.
                            if is_gmcp && !self.bucket.try_take() {
                                return CodecOutcome::Disconnect(DisconnectReason::RateLimited);
                            }
                        }
                        self.sub_buf.clear();
                        self.sub_oversized = false;
                        self.state = ParseState::Data;
                    } else if *byte == IAC {
                        // Escaped 0xFF byte inside the subnegotiation body.
                        if !self.sub_oversized {
                            if self.sub_buf.len() >= MAX_SUBNEGOTIATION_BYTES {
                                self.sub_oversized = true;
                            } else {
                                self.sub_buf.push(IAC);
                            }
                        }
                        self.state = ParseState::Subnegotiation;
                    } else {
                        // Protocol violation: bail out of the subnegotiation
                        // rather than buffer forever.
                        self.sub_buf.clear();
                        self.sub_oversized = false;
                        self.state = ParseState::Data;
                    }
                }
            }
        }

        CodecOutcome::Ok {
            lines,
            responses,
            events,
        }
    }

    /// Returns `Some(reason)` when the connection should be disconnected.
    fn consume_data_byte(&mut self, byte: u8, lines: &mut Vec<String>) -> Option<DisconnectReason> {
        if self.saw_cr {
            self.saw_cr = false;
            if byte == b'\n' || byte == 0 {
                return self.finish_line(lines);
            }

            if let Some(reason) = self.finish_line(lines) {
                return Some(reason);
            }
        }

        match byte {
            b'\r' => {
                self.saw_cr = true;
                None
            }
            b'\n' => self.finish_line(lines),
            _ => {
                self.line_buf.push(byte);
                (self.line_buf.len() > self.max_line_bytes).then_some(DisconnectReason::LineTooLong)
            }
        }
    }

    /// Returns `Some(reason)` when the connection should be disconnected.
    fn finish_line(&mut self, lines: &mut Vec<String>) -> Option<DisconnectReason> {
        if !self.bucket.try_take() {
            return Some(DisconnectReason::RateLimited);
        }

        let text = String::from_utf8_lossy(&self.line_buf).into_owned();
        self.line_buf.clear();
        lines.push(text);
        None
    }
}

/// Shared by the telnet codec (this file) and the WebSocket connection
/// handler (`ws.rs`): both transports rate-limit input lines through the
/// same token-bucket algorithm and config fields (`rate_limit_burst`,
/// `rate_limit_per_second`), so a player can't get a materially different
/// input rate by switching transport.
#[derive(Debug)]
pub(crate) struct TokenBucket {
    tokens: f64,
    burst: f64,
    refill_per_second: f64,
    last_refill: Instant,
}

impl TokenBucket {
    pub(crate) fn new(burst: u32, refill_per_second: f64) -> Self {
        let burst = burst as f64;
        Self {
            tokens: burst,
            burst,
            refill_per_second,
            last_refill: Instant::now(),
        }
    }

    pub(crate) fn try_take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;

        self.tokens = (self.tokens + elapsed * self.refill_per_second).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

fn is_known_option(option: u8) -> bool {
    // OPT_MCCP2 is deliberately *not* here: MCCP2 is deferred to Phase 2
    // (spec R4), so it gets the same blanket refusal as any option we've
    // never heard of (see `mccp2_is_refused_like_any_unsupported_option`).
    matches!(
        option,
        telnet::OPT_NAWS | telnet::OPT_TTYPE | telnet::OPT_MSSP | telnet::OPT_GMCP
    )
}

fn refusal_for(verb: u8, option: u8) -> Option<Vec<u8>> {
    // RFC 854/1143: never acknowledge a state you are already in. For an
    // option we've never heard of, we are implicitly always in `No`/`No`
    // (never asked to do it, never offered to do it), so a peer telling us
    // `WONT`/`DONT` is telling us something we already believe -- replying
    // would let a peer that also "correctly" answers refusals ping-pong
    // forever. Only `WILL`/`DO` (the peer asking us to change state) gets
    // an answer.
    match verb {
        WILL => Some(vec![IAC, DONT, option]),
        DO => Some(vec![IAC, WONT, option]),
        WONT | DONT => None,
        _ => unreachable!("caller only dispatches DO/DONT/WILL/WONT"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    #[test]
    fn output_translates_newlines_and_appends_nothing() {
        assert_eq!(to_wire("a\nb\n"), b"a\r\nb\r\n");
        assert_eq!(to_wire("already\r\n"), b"already\r\n");
        assert_eq!(to_wire("> "), b"> ");
        assert_eq!(to_wire(""), b"");
    }

    #[test]
    fn strips_negotiation_bytes_and_refuses() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let outcome = codec.feed(&[IAC, WILL, 1, b'h', b'i', b'\n']);

        let CodecOutcome::Ok {
            lines, responses, ..
        } = outcome
        else {
            panic!("unexpected disconnect");
        };

        assert_eq!(lines, vec!["hi"]);
        assert_eq!(responses, vec![vec![IAC, DONT, 1]]);
    }

    #[test]
    fn supports_split_packets_and_cr_variants() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let a = codec.feed(b"hel");
        let b = codec.feed(b"lo\r\nworld\r\0foo\n");

        let CodecOutcome::Ok { lines: a_lines, .. } = a else {
            panic!("unexpected disconnect");
        };
        assert!(a_lines.is_empty());

        let CodecOutcome::Ok { lines: b_lines, .. } = b else {
            panic!("unexpected disconnect");
        };
        assert_eq!(b_lines, vec!["hello", "world", "foo"]);
    }

    #[test]
    fn handles_subnegotiation_and_escaped_iac() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let out = codec.feed(&[
            IAC, SB, 24, 1, b'v', b't', b'1', b'0', b'0', IAC, SE, b'A', IAC, IAC, b'B', b'\n',
        ]);

        let CodecOutcome::Ok {
            lines, responses, ..
        } = out
        else {
            panic!("unexpected disconnect");
        };
        assert_eq!(lines, vec!["A�B"]);
        assert!(responses.is_empty());
    }

    #[test]
    fn disconnects_on_overlong_line() {
        let mut codec = TelnetCodec::new(4, 20, 5.0, Vec::new());
        let out = codec.feed(b"abcde");
        assert!(matches!(
            out,
            CodecOutcome::Disconnect(DisconnectReason::LineTooLong)
        ));
    }

    // OBI-149: a disconnect from the input token bucket (burst exhausted)
    // must carry `DisconnectReason::RateLimited`, distinct from an
    // over-long line -- the caller (`spawn_reader`) logs the two
    // differently, and previously neither was logged at all.
    #[test]
    fn disconnects_with_rate_limited_reason_once_the_burst_is_exhausted() {
        let mut codec = TelnetCodec::new(4096, 1, 0.0, Vec::new());
        // First line consumes the lone burst token and is accepted.
        let out = codec.feed(b"one\n");
        assert!(matches!(out, CodecOutcome::Ok { .. }));
        // The bucket never refills (0.0/s), so a second line disconnects
        // -- and must be reported as rate-limited, not as an overlong line.
        let out = codec.feed(b"two\n");
        assert!(matches!(
            out,
            CodecOutcome::Disconnect(DisconnectReason::RateLimited)
        ));
    }

    #[test]
    fn replaces_invalid_utf8() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let out = codec.feed(&[0xf0, 0x28, 0x8c, 0xbc, b'\n']);

        let CodecOutcome::Ok { lines, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(lines[0], "�(��");
    }

    /// Startup negotiation is always the first bytes on the wire (`DO
    /// NAWS`, `DO TTYPE`, `WILL GMCP`, `WILL MSSP`); tests that assert on
    /// raw bytes read it off first so it doesn't get mixed into whatever
    /// they're actually asserting on.
    const STARTUP_PREAMBLE: &[u8] = &[
        IAC,
        DO,
        telnet::OPT_NAWS,
        IAC,
        DO,
        telnet::OPT_TTYPE,
        IAC,
        WILL,
        telnet::OPT_GMCP,
        IAC,
        WILL,
        telnet::OPT_MSSP,
    ];

    async fn drain_preamble(client: &mut TcpStream) {
        let mut buf = vec![0_u8; STARTUP_PREAMBLE.len()];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, STARTUP_PREAMBLE);
    }

    #[test]
    fn startup_negotiation_offers_alpha_options_once() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        assert_eq!(
            codec.start(),
            vec![
                IAC,
                DO,
                telnet::OPT_NAWS,
                IAC,
                DO,
                telnet::OPT_TTYPE,
                IAC,
                WILL,
                telnet::OPT_GMCP,
                IAC,
                WILL,
                telnet::OPT_MSSP,
            ]
        );
        // Calling start() again must not re-request: every option is
        // already `WantYes`, so a second call is a no-op (RFC 1143 §7).
        assert!(codec.start().is_empty());
    }

    #[test]
    fn mccp2_is_refused_like_any_unsupported_option() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let out = codec.feed(&[IAC, WILL, telnet::OPT_MCCP2]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(responses, vec![vec![IAC, DONT, telnet::OPT_MCCP2]]);

        let out = codec.feed(&[IAC, DO, telnet::OPT_MCCP2]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(responses, vec![vec![IAC, WONT, telnet::OPT_MCCP2]]);
    }

    #[test]
    fn unknown_option_refusals_are_never_acknowledged() {
        // RFC 854/1143: never acknowledge a state you're already in. For an
        // unknown option we're implicitly always No/No, so WONT/DONT (the
        // peer telling us something we already believe) must get silence,
        // not another refusal -- otherwise a peer that also "correctly"
        // answers refusals ping-pongs forever (CTO review, OBI-26).
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let out = codec.feed(&[IAC, WONT, 99]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert!(
            responses.is_empty(),
            "WONT for an unknown option must get silence"
        );

        let out = codec.feed(&[IAC, DONT, 99]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert!(
            responses.is_empty(),
            "DONT for an unknown option must get silence"
        );

        // WILL/DO for an unknown option still get an answer (that's how
        // the peer learns we won't do it).
        let out = codec.feed(&[IAC, WILL, 99]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(responses, vec![vec![IAC, DONT, 99]]);

        let out = codec.feed(&[IAC, DO, 99]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(responses, vec![vec![IAC, WONT, 99]]);
    }

    #[test]
    fn disabling_a_known_option_from_yes_is_acknowledged() {
        // RFC 1143: a Yes -> No transition (the peer disabling something
        // that was negotiated on) must be acknowledged, or a Q-method peer
        // is stuck in WANTNO forever waiting for our answer (CTO review,
        // OBI-26).
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start(); // sends `DO NAWS`; him[NAWS] = WantYes

        // Client agrees: him[NAWS] -> Yes (no reply needed, we already asked).
        let out = codec.feed(&[IAC, WILL, telnet::OPT_NAWS]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert!(responses.is_empty());

        // Client disables it: Yes -> No must be acked with exactly one DONT.
        let out = codec.feed(&[IAC, WONT, telnet::OPT_NAWS]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(responses, vec![vec![IAC, DONT, telnet::OPT_NAWS]]);

        // A second WONT (already No) must get silence, not another DONT.
        let out = codec.feed(&[IAC, WONT, telnet::OPT_NAWS]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert!(responses.is_empty());
    }

    #[test]
    fn send_gmcp_is_dropped_until_gmcp_is_negotiated() {
        // Condition 3 (CTO review, OBI-26): `NetCommand::SendGmcp` must be
        // gated on having actually negotiated GMCP, not just written
        // unconditionally to the wire.
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start(); // sends `WILL GMCP`; us[GMCP] = WantYes
        assert!(!codec.gmcp_enabled());

        let _ = codec.feed(&[IAC, DO, telnet::OPT_GMCP]); // client agrees
        assert!(codec.gmcp_enabled());
    }

    #[test]
    fn naws_subnegotiation_emits_window_size() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start();
        let out = codec.feed(&[
            IAC,
            WILL,
            telnet::OPT_NAWS,
            IAC,
            SB,
            telnet::OPT_NAWS,
            0,
            80,
            0,
            24,
            IAC,
            SE,
        ]);
        let CodecOutcome::Ok { events, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(events, vec![TelnetEvent::WindowSize(80, 24)]);
    }

    #[test]
    fn ttype_cycle_requests_again_until_client_repeats() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start();

        // Client agrees to do TTYPE; the codec immediately asks it to SEND.
        let out = codec.feed(&[IAC, WILL, telnet::OPT_TTYPE]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(responses, vec![telnet_send(telnet::OPT_TTYPE)]);

        // First name: keep cycling.
        let out = codec.feed(&ttype_is(b"xterm"));
        let CodecOutcome::Ok {
            events, responses, ..
        } = out
        else {
            panic!("unexpected disconnect");
        };
        assert_eq!(events, vec![TelnetEvent::TerminalType("xterm".into())]);
        assert_eq!(responses, vec![telnet_send(telnet::OPT_TTYPE)]);

        // Second name, different: keep cycling.
        let out = codec.feed(&ttype_is(b"MTTS 137"));
        let CodecOutcome::Ok {
            events, responses, ..
        } = out
        else {
            panic!("unexpected disconnect");
        };
        assert_eq!(events, vec![TelnetEvent::TerminalType("MTTS 137".into())]);
        assert_eq!(responses, vec![telnet_send(telnet::OPT_TTYPE)]);

        // Client repeats the first name: cycle is done, no more SEND.
        let out = codec.feed(&ttype_is(b"xterm"));
        let CodecOutcome::Ok {
            events, responses, ..
        } = out
        else {
            panic!("unexpected disconnect");
        };
        assert_eq!(events, vec![TelnetEvent::TerminalType("xterm".into())]);
        assert!(responses.is_empty());
    }

    #[test]
    fn ttype_cycle_stops_after_max_rounds_if_client_never_repeats() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start();
        let _ = codec.feed(&[IAC, WILL, telnet::OPT_TTYPE]);

        let mut last_responses = Vec::new();
        for i in 0..20 {
            let out = codec.feed(&ttype_is(format!("name-{i}").as_bytes()));
            let CodecOutcome::Ok { responses, .. } = out else {
                panic!("unexpected disconnect");
            };
            last_responses = responses;
        }
        assert!(
            last_responses.is_empty(),
            "cycle must terminate even if the client never repeats a name"
        );
    }

    #[test]
    fn gmcp_parses_core_hello_supports_and_char() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start();
        let _ = codec.feed(&[IAC, DO, telnet::OPT_GMCP]);

        let msg = feed_gmcp(
            &mut codec,
            "Core.Hello",
            r#"{"client":"Mudlet","version":"4.0"}"#,
        );
        assert_eq!(
            msg,
            GmcpMessage::CoreHello {
                client: "Mudlet".into(),
                version: "4.0".into()
            }
        );

        let msg = feed_gmcp(&mut codec, "Core.Supports.Set", r#"["Char 1", "Room 1"]"#);
        assert_eq!(
            msg,
            GmcpMessage::CoreSupportsSet(vec!["Char 1".into(), "Room 1".into()])
        );

        let msg = feed_gmcp(&mut codec, "Char.Login", r#"{"name":"frodo"}"#);
        assert_eq!(
            msg,
            GmcpMessage::Package {
                module: "Char.Login".into(),
                payload: serde_json::json!({"name": "frodo"}),
            }
        );

        let msg = feed_gmcp(&mut codec, "Room.Info", r#"{"num":1}"#);
        assert_eq!(
            msg,
            GmcpMessage::Package {
                module: "Room.Info".into(),
                payload: serde_json::json!({"num": 1}),
            }
        );
    }

    #[test]
    fn gmcp_malformed_json_drops_the_frame() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start();
        let _ = codec.feed(&[IAC, DO, telnet::OPT_GMCP]);

        let mut body = vec![IAC, SB, telnet::OPT_GMCP];
        body.extend_from_slice(b"Char.Login {not json");
        body.push(IAC);
        body.push(SE);
        let CodecOutcome::Ok { events, .. } = codec.feed(&body) else {
            panic!("unexpected disconnect");
        };
        assert!(
            events.is_empty(),
            "malformed JSON must drop the whole frame, not deliver payload: None"
        );
    }

    #[test]
    fn gmcp_oversize_subnegotiation_is_dropped_not_disconnected() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start();
        let _ = codec.feed(&[IAC, DO, telnet::OPT_GMCP]);

        let mut body = vec![IAC, SB, telnet::OPT_GMCP];
        body.extend_from_slice(b"Char.Login ");
        body.extend(std::iter::repeat_n(b'a', MAX_SUBNEGOTIATION_BYTES + 1));
        body.push(IAC);
        body.push(SE);
        let CodecOutcome::Ok { events, .. } = codec.feed(&body) else {
            panic!("oversized frame must be dropped, not disconnect the connection");
        };
        assert!(
            events.is_empty(),
            "oversized frame must not produce an event"
        );

        // The connection must still be usable afterwards.
        let msg = feed_gmcp(&mut codec, "Core.Hello", r#"{"client":"x","version":"1"}"#);
        assert_eq!(
            msg,
            GmcpMessage::CoreHello {
                client: "x".into(),
                version: "1".into()
            }
        );
    }

    #[test]
    fn gmcp_core_supports_is_tracked_per_connection() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start();
        let _ = codec.feed(&[IAC, DO, telnet::OPT_GMCP]);

        feed_gmcp(&mut codec, "Core.Supports.Set", r#"["Char 1", "Room 1"]"#);
        assert_eq!(
            codec.options.supports(),
            &["Char 1".to_string(), "Room 1".to_string()]
                .into_iter()
                .collect()
        );

        feed_gmcp(&mut codec, "Core.Supports.Add", r#"["Char 1"]"#);
        assert_eq!(
            codec.options.supports(),
            &["Char 1".to_string(), "Room 1".to_string()]
                .into_iter()
                .collect()
        );

        feed_gmcp(&mut codec, "Core.Supports.Remove", r#"["Room 1"]"#);
        assert_eq!(
            codec.options.supports(),
            &["Char 1".to_string()].into_iter().collect()
        );
    }

    #[test]
    fn mssp_emits_configured_fields_once_client_agrees() {
        let fields = vec![
            ("NAME".to_string(), "ObieMud".to_string()),
            ("CODEBASE".to_string(), "Loom".to_string()),
        ];
        let mut codec = TelnetCodec::new(4096, 20, 5.0, fields);
        let _ = codec.start();

        let out = codec.feed(&[IAC, DO, telnet::OPT_MSSP]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(
            responses,
            vec![vec![
                IAC,
                SB,
                telnet::OPT_MSSP,
                1,
                b'N',
                b'A',
                b'M',
                b'E',
                2,
                b'O',
                b'b',
                b'i',
                b'e',
                b'M',
                b'u',
                b'd',
                1,
                b'C',
                b'O',
                b'D',
                b'E',
                b'B',
                b'A',
                b'S',
                b'E',
                2,
                b'L',
                b'o',
                b'o',
                b'm',
                IAC,
                SE,
            ]]
        );

        // A repeated DO must not re-send the data (already `Yes`).
        let out = codec.feed(&[IAC, DO, telnet::OPT_MSSP]);
        let CodecOutcome::Ok { responses, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert!(responses.is_empty());
    }

    #[test]
    fn negotiation_settles_and_never_loops_under_repeated_offers() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0, Vec::new());
        let _ = codec.start();

        // A misbehaving/confused peer offers the same option over and over.
        let mut total_responses = 0;
        for _ in 0..100 {
            let out = codec.feed(&[IAC, WILL, telnet::OPT_NAWS]);
            let CodecOutcome::Ok { responses, .. } = out else {
                panic!("unexpected disconnect");
            };
            total_responses += responses.len();
        }
        // First WILL flips `him: WantYes -> Yes` silently (no reply needed,
        // we already sent DO at startup); every repeat after that is a
        // no-op in the `Yes` state. Total replies stay flat, not linear in
        // the number of repeats.
        assert!(
            total_responses <= 1,
            "repeated WILL must not keep provoking replies, got {total_responses}"
        );
    }

    fn telnet_send(option: u8) -> Vec<u8> {
        vec![IAC, SB, option, 1, IAC, SE]
    }

    fn ttype_is(name: &[u8]) -> Vec<u8> {
        let mut out = vec![IAC, SB, telnet::OPT_TTYPE, 0];
        out.extend_from_slice(name);
        out.push(IAC);
        out.push(SE);
        out
    }

    fn feed_gmcp(codec: &mut TelnetCodec, package_message: &str, json: &str) -> GmcpMessage {
        let mut body = vec![IAC, SB, telnet::OPT_GMCP];
        body.extend_from_slice(package_message.as_bytes());
        body.push(b' ');
        body.extend_from_slice(json.as_bytes());
        body.push(IAC);
        body.push(SE);
        let CodecOutcome::Ok { mut events, .. } = codec.feed(&body) else {
            panic!("unexpected disconnect");
        };
        let TelnetEvent::Gmcp(msg) = events.remove(0) else {
            panic!("expected a GMCP event");
        };
        msg
    }

    /// Fuzz seed corpus for the parser state machine (spec's acceptance
    /// criterion for OBI-26): hand-picked byte sequences that hit tricky
    /// transitions (option scanners, escaped `IAC`, truncated/unterminated
    /// subnegotiations, malformed GMCP payloads). Every seed must survive
    /// both a single `feed()` and a byte-at-a-time `feed()` per byte
    /// (the split-packet case) without panicking; `CodecOutcome::Disconnect`
    /// is a legitimate, non-panicking outcome.
    #[test]
    fn fuzz_seeds_never_panic() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/seeds");
        let mut seen = 0;
        for entry in std::fs::read_dir(&dir).expect("seeds dir") {
            let path = entry.expect("entry").path();
            if path.extension().is_none_or(|e| e != "bin") {
                continue;
            }
            seen += 1;
            let data = std::fs::read(&path).expect("read seed");

            let mut whole = TelnetCodec::new(4096, 1000, 1000.0, Vec::new());
            let _ = whole.start();
            let _ = whole.feed(&data);

            let mut byte_at_a_time = TelnetCodec::new(4096, 1000, 1000.0, Vec::new());
            let _ = byte_at_a_time.start();
            for b in &data {
                match byte_at_a_time.feed(std::slice::from_ref(b)) {
                    CodecOutcome::Disconnect(_) => break,
                    CodecOutcome::Ok { .. } => {}
                }
            }
        }
        assert!(seen > 0, "expected at least one seed file in {dir:?}");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        /// Arbitrary byte soup, fed in randomly-sized chunks (so state
        /// survives being split across `feed()` calls, same as real TCP
        /// reads), never panics.
        #[test]
        fn arbitrary_bytes_never_panic(
            bytes in prop::collection::vec(any::<u8>(), 0..512),
            chunk_sizes in prop::collection::vec(1..17_usize, 0..64),
        ) {
            let mut codec = TelnetCodec::new(256, 1000, 1000.0, Vec::new());
            let _ = codec.start();
            let mut offset = 0;
            let mut sizes = chunk_sizes.into_iter().cycle();
            while offset < bytes.len() {
                let take = sizes.next().unwrap_or(1).min(bytes.len() - offset);
                match codec.feed(&bytes[offset..offset + take]) {
                    CodecOutcome::Disconnect(_) => break,
                    CodecOutcome::Ok { .. } => {}
                }
                offset += take;
            }
        }

        /// Same idea, but built from telnet-protocol "tokens" (IAC/verbs/
        /// known option bytes/SB.../SE) instead of uniformly random bytes,
        /// to reach negotiation and subnegotiation states more often than
        /// pure random bytes would.
        #[test]
        fn telnet_token_soup_never_panics(idx in prop::collection::vec(0..TELNET_VOCAB.len(), 0..200)) {
            let mut bytes = Vec::new();
            for i in idx {
                bytes.extend_from_slice(TELNET_VOCAB[i]);
            }
            let mut codec = TelnetCodec::new(256, 1000, 1000.0, Vec::new());
            let _ = codec.start();
            let _ = codec.feed(&bytes);
        }
    }

    const TELNET_VOCAB: &[&[u8]] = &[
        &[IAC],
        &[DO],
        &[DONT],
        &[WILL],
        &[WONT],
        &[SB],
        &[SE],
        &[telnet::OPT_NAWS],
        &[telnet::OPT_TTYPE],
        &[telnet::OPT_MSSP],
        &[telnet::OPT_GMCP],
        &[telnet::OPT_MCCP2],
        &[0],
        &[1],
        b"\r",
        b"\n",
        b"Core.Hello ",
        b"Char.Foo ",
        b"{}",
        b"{\"a\":1}",
        b"line",
    ];

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_gmcp_over_the_wire_is_gated_on_negotiation() {
        // Condition 3 (CTO review, OBI-26), end to end: a `SendGmcp`
        // issued before the client has agreed to `DO GMCP` must produce no
        // bytes on the wire at all; one issued after negotiation completes
        // must produce the encoded frame.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = NetConfig::default();
        let (event_tx, mut event_rx) = mpsc::channel(256);
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server = tokio::spawn(run_server(listener, config, event_tx, cmd_rx, shutdown_rx));

        let mut client = TcpStream::connect(addr).await.unwrap();
        drain_preamble(&mut client).await;

        let conn = loop {
            match event_rx.recv().await.expect("event channel closed") {
                NetEvent::Connected(id) => break id,
                _ => continue,
            }
        };

        // Before negotiation: SendGmcp must be dropped, not written.
        cmd_tx
            .send(NetCommand::SendGmcp(
                conn,
                "Char.Foo".to_string(),
                serde_json::json!({"x": 1}),
            ))
            .await
            .unwrap();

        // Prove "no bytes" by racing the drop against something that *does*
        // produce bytes: send a line and read its echo-free response
        // ourselves isn't available here (no echo task), so instead confirm
        // no data arrives within a short window, then complete negotiation
        // and confirm the second SendGmcp *does* arrive.
        client.write_all(b"unrelated line\r\n").await.unwrap(); // keeps the connection alive; not read by anything in this test
        let mut probe = [0_u8; 1];
        let timed_out = tokio::time::timeout(
            std::time::Duration::from_millis(150),
            client.read(&mut probe),
        )
        .await
        .is_err();
        assert!(
            timed_out,
            "SendGmcp before negotiation must not put any bytes on the wire"
        );

        // Complete GMCP negotiation: client agrees to DO GMCP.
        client
            .write_all(&[IAC, DO, telnet::OPT_GMCP])
            .await
            .unwrap();
        // Give the server a moment to process the negotiation frame.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        cmd_tx
            .send(NetCommand::SendGmcp(
                conn,
                "Char.Foo".to_string(),
                serde_json::json!({"x": 1}),
            ))
            .await
            .unwrap();

        let expected = encode_gmcp("Char.Foo", &serde_json::json!({"x": 1}));
        let mut buf = vec![0_u8; expected.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_exact(&mut buf),
        )
        .await
        .expect("timed out waiting for the post-negotiation GMCP frame")
        .unwrap();
        assert_eq!(buf, expected);

        shutdown_tx.send(true).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn echo_integration_server_round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = NetConfig::default();
        let (event_tx, mut event_rx) = mpsc::channel(256);
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server = tokio::spawn(run_server(listener, config, event_tx, cmd_rx, shutdown_rx));

        let echo = tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                if let NetEvent::Line(conn, line) = event {
                    let _ = cmd_tx
                        .send(NetCommand::Send(conn, format!("{line}\n")))
                        .await;
                }
            }
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        drain_preamble(&mut client).await;
        client.write_all(b"hello\r\n").await.unwrap();

        let mut buf = [0_u8; 32];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello\r\n");

        shutdown_tx.send(true).unwrap();
        server.await.unwrap().unwrap();
        echo.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn supports_fifty_concurrent_clients() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = NetConfig::default();
        let (event_tx, mut event_rx) = mpsc::channel(1024);
        let (cmd_tx, cmd_rx) = mpsc::channel(1024);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server = tokio::spawn(run_server(listener, config, event_tx, cmd_rx, shutdown_rx));

        let echo = tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                if let NetEvent::Line(conn, line) = event {
                    let _ = cmd_tx
                        .send(NetCommand::Send(conn, format!("{line}\n")))
                        .await;
                }
            }
        });

        let mut clients = Vec::new();
        for _ in 0..50 {
            clients.push(TcpStream::connect(addr).await.unwrap());
        }

        for client in clients.iter_mut() {
            drain_preamble(client).await;
        }

        for (idx, client) in clients.iter_mut().enumerate() {
            client
                .write_all(format!("player-{idx}\n").as_bytes())
                .await
                .unwrap();
        }

        for (idx, client) in clients.iter_mut().enumerate() {
            let mut buf = [0_u8; 64];
            let n = client.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], format!("player-{idx}\r\n").as_bytes());
        }

        shutdown_tx.send(true).unwrap();
        server.await.unwrap().unwrap();
        echo.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_client_disconnect_does_not_affect_others() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = NetConfig {
            output_queue_depth: 1,
            ..NetConfig::default()
        };

        let (event_tx, mut event_rx) = mpsc::channel(256);
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server = tokio::spawn(run_server(listener, config, event_tx, cmd_rx, shutdown_rx));

        let mut slow = TcpStream::connect(addr).await.unwrap();
        let mut fast = TcpStream::connect(addr).await.unwrap();
        drain_preamble(&mut slow).await;
        drain_preamble(&mut fast).await;
        slow.write_all(b"slow\n").await.unwrap();
        fast.write_all(b"fast\n").await.unwrap();

        let mut slow_conn = None;
        let mut saw_slow_disconnect = false;
        let mut replied_fast = false;

        // Identify the clients by the line they sent, not by accept order:
        // the two connects race, and guessing wrong spams the client that
        // is never read from while the test waits forever (flake seen in CI).
        // Also keep going until the fast client got its reply: its line can
        // arrive after the slow client has already been dropped.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while !(saw_slow_disconnect && replied_fast) {
            let event = tokio::time::timeout_at(deadline, event_rx.recv())
                .await
                .expect("timed out waiting for the slow-client disconnect and the fast-client line")
                .expect("event channel closed");
            match event {
                NetEvent::Connected(_) => {}
                NetEvent::Line(id, line) => {
                    if line == "slow" {
                        slow_conn = Some(id);
                        for i in 0..200 {
                            let _ = cmd_tx
                                .send(NetCommand::Send(id, format!("spam-{i}\n")))
                                .await;
                        }
                    } else if line == "fast" {
                        let _ = cmd_tx.send(NetCommand::Send(id, "ok\n".to_string())).await;
                        replied_fast = true;
                    }
                }
                NetEvent::Disconnected(id) => {
                    if Some(id) == slow_conn {
                        saw_slow_disconnect = true;
                    }
                }
                NetEvent::Tick => {}
                NetEvent::WindowSize(..) | NetEvent::TerminalType(..) | NetEvent::Gmcp(..) => {}
            }
        }

        assert!(saw_slow_disconnect, "slow client never disconnected");

        let mut fast_buf = [0_u8; 32];
        let n = fast.read(&mut fast_buf).await.unwrap();
        assert_eq!(&fast_buf[..n], b"ok\r\n");

        let _ = slow.readable().await;

        shutdown_tx.send(true).unwrap();
        server.await.unwrap().unwrap();
    }
}
