// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Telnet/WebSocket networking and sessions (§8.2). Owner: Legolas.

use std::collections::HashMap;
use std::io;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

pub type ConnId = u64;

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
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            max_line_bytes: 4096,
            read_buffer_bytes: 1024,
            output_queue_depth: 64,
            rate_limit_burst: 20,
            rate_limit_per_second: 5.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetEvent {
    Connected(ConnId),
    Line(ConnId, String),
    Disconnected(ConnId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetCommand {
    Send(ConnId, String),
    Close(ConnId),
}

#[derive(Debug)]
enum ConnControl {
    Send(String),
    Close,
}

#[derive(Debug)]
struct ConnEntry {
    tx: mpsc::Sender<ConnControl>,
    task: JoinHandle<()>,
}

pub async fn run_server(
    listener: TcpListener,
    config: NetConfig,
    event_tx: mpsc::Sender<NetEvent>,
    mut command_rx: mpsc::Receiver<NetCommand>,
    mut shutdown_rx: watch::Receiver<bool>,
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
    );

    let mut disconnected_sent = false;

    loop {
        tokio::select! {
            Some(control) = control_rx.recv() => {
                match control {
                    ConnControl::Send(text) => {
                        if writer.write_all(text.as_bytes()).await.is_err() {
                            break;
                        }
                        if writer.write_all(b"\r\n").await.is_err() {
                            break;
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
                    CodecOutcome::Ok { lines, responses } => {
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
                    CodecOutcome::Disconnect => {
                        break;
                    }
                }
            }
            else => break,
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
    },
    Disconnect,
}

#[derive(Debug)]
struct TelnetCodec {
    state: ParseState,
    line_buf: Vec<u8>,
    saw_cr: bool,
    max_line_bytes: usize,
    bucket: TokenBucket,
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
    fn new(max_line_bytes: usize, burst: u32, refill_per_second: f64) -> Self {
        Self {
            state: ParseState::Data,
            line_buf: Vec::with_capacity(128),
            saw_cr: false,
            max_line_bytes,
            bucket: TokenBucket::new(burst, refill_per_second),
        }
    }

    fn feed(&mut self, chunk: &[u8]) -> CodecOutcome {
        let mut lines = Vec::new();
        let mut responses = Vec::new();

        for byte in chunk {
            match self.state {
                ParseState::Data => {
                    if *byte == IAC {
                        self.state = ParseState::Iac;
                        continue;
                    }

                    if self.consume_data_byte(*byte, &mut lines) {
                        return CodecOutcome::Disconnect;
                    }
                }
                ParseState::Iac => match *byte {
                    IAC => {
                        if self.consume_data_byte(IAC, &mut lines) {
                            return CodecOutcome::Disconnect;
                        }
                        self.state = ParseState::Data;
                    }
                    DO | DONT | WILL | WONT => {
                        self.state = ParseState::IacVerb(*byte);
                    }
                    SB => {
                        self.state = ParseState::Subnegotiation;
                    }
                    _ => {
                        self.state = ParseState::Data;
                    }
                },
                ParseState::IacVerb(verb) => {
                    responses.push(refusal_for(verb, *byte));
                    self.state = ParseState::Data;
                }
                ParseState::Subnegotiation => {
                    if *byte == IAC {
                        self.state = ParseState::SubnegotiationIac;
                    }
                }
                ParseState::SubnegotiationIac => {
                    if *byte == SE {
                        self.state = ParseState::Data;
                    } else {
                        self.state = ParseState::Subnegotiation;
                    }
                }
            }
        }

        CodecOutcome::Ok { lines, responses }
    }

    /// Returns true when the connection should be disconnected.
    fn consume_data_byte(&mut self, byte: u8, lines: &mut Vec<String>) -> bool {
        if self.saw_cr {
            self.saw_cr = false;
            if byte == b'\n' || byte == 0 {
                return self.finish_line(lines);
            }

            if self.finish_line(lines) {
                return true;
            }
        }

        match byte {
            b'\r' => {
                self.saw_cr = true;
                false
            }
            b'\n' => self.finish_line(lines),
            _ => {
                self.line_buf.push(byte);
                self.line_buf.len() > self.max_line_bytes
            }
        }
    }

    /// Returns true when the connection should be disconnected.
    fn finish_line(&mut self, lines: &mut Vec<String>) -> bool {
        if !self.bucket.try_take() {
            return true;
        }

        let text = String::from_utf8_lossy(&self.line_buf).into_owned();
        self.line_buf.clear();
        lines.push(text);
        false
    }
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    burst: f64,
    refill_per_second: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(burst: u32, refill_per_second: f64) -> Self {
        let burst = burst as f64;
        Self {
            tokens: burst,
            burst,
            refill_per_second,
            last_refill: Instant::now(),
        }
    }

    fn try_take(&mut self) -> bool {
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

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;

fn refusal_for(verb: u8, option: u8) -> Vec<u8> {
    let refusal = if verb == DO || verb == DONT {
        WONT
    } else {
        DONT
    };
    vec![IAC, refusal, option]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    #[test]
    fn strips_negotiation_bytes_and_refuses() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0);
        let outcome = codec.feed(&[IAC, WILL, 1, b'h', b'i', b'\n']);

        let CodecOutcome::Ok { lines, responses } = outcome else {
            panic!("unexpected disconnect");
        };

        assert_eq!(lines, vec!["hi"]);
        assert_eq!(responses, vec![vec![IAC, DONT, 1]]);
    }

    #[test]
    fn supports_split_packets_and_cr_variants() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0);
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
        let mut codec = TelnetCodec::new(4096, 20, 5.0);
        let out = codec.feed(&[
            IAC, SB, 24, 1, b'v', b't', b'1', b'0', b'0', IAC, SE, b'A', IAC, IAC, b'B', b'\n',
        ]);

        let CodecOutcome::Ok { lines, responses } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(lines, vec!["A�B"]);
        assert!(responses.is_empty());
    }

    #[test]
    fn disconnects_on_overlong_line() {
        let mut codec = TelnetCodec::new(4, 20, 5.0);
        let out = codec.feed(b"abcde");
        assert!(matches!(out, CodecOutcome::Disconnect));
    }

    #[test]
    fn replaces_invalid_utf8() {
        let mut codec = TelnetCodec::new(4096, 20, 5.0);
        let out = codec.feed(&[0xf0, 0x28, 0x8c, 0xbc, b'\n']);

        let CodecOutcome::Ok { lines, .. } = out else {
            panic!("unexpected disconnect");
        };
        assert_eq!(lines[0], "�(��");
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
                    let _ = cmd_tx.send(NetCommand::Send(conn, line)).await;
                }
            }
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
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
                    let _ = cmd_tx.send(NetCommand::Send(conn, line)).await;
                }
            }
        });

        let mut clients = Vec::new();
        for _ in 0..50 {
            clients.push(TcpStream::connect(addr).await.unwrap());
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
        slow.write_all(b"slow\n").await.unwrap();
        fast.write_all(b"fast\n").await.unwrap();

        let mut slow_conn = None;
        let mut fast_conn = None;
        let mut saw_slow_disconnect = false;

        for _ in 0..30 {
            if let Some(event) = event_rx.recv().await {
                match event {
                    NetEvent::Connected(id) => {
                        if slow_conn.is_none() {
                            slow_conn = Some(id);
                        } else if fast_conn.is_none() {
                            fast_conn = Some(id);
                        }
                    }
                    NetEvent::Line(id, _) => {
                        if Some(id) == slow_conn {
                            for i in 0..200 {
                                let _ =
                                    cmd_tx.send(NetCommand::Send(id, format!("spam-{i}"))).await;
                            }
                        }
                        if Some(id) == fast_conn {
                            let _ = cmd_tx.send(NetCommand::Send(id, "ok".to_string())).await;
                        }
                    }
                    NetEvent::Disconnected(id) => {
                        if Some(id) == slow_conn {
                            saw_slow_disconnect = true;
                            break;
                        }
                    }
                }
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
