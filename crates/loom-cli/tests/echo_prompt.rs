// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-176 acceptance: telnet `IAC WILL ECHO`/`IAC WONT ECHO` around a
//! no-echo input (and the WS equivalent), driven end to end through the
//! `set_echo()` efun from a warp-style login state machine (the `echo`
//! fixture) against a real `loom-cli serve` subprocess. The telnet half
//! reads the raw byte stream rather than a telnet-aware client library,
//! so the transcript is a literal `IAC WILL/WONT ECHO` byte sequence
//! around the password prompt and its reply, exactly as the acceptance
//! criterion asks for.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio_tungstenite::tungstenite::Message;

const IAC: u8 = 255;
const WILL: u8 = 251;
const WONT: u8 = 252;
const OPT_ECHO: u8 = 1;

#[test]
fn raw_telnet_transcript_shows_will_echo_then_wont_echo_around_password() {
    let mudlib = fixture("echo");
    let port = reserve_local_port();
    let bind = format!("127.0.0.1:{port}");
    let mut server = LoomServer::spawn(&mudlib, &bind);

    let mut stream = connect_with_retry(&bind, Duration::from_secs(5));
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    drain_telnet_preamble(&mut stream);

    // logon(): "Name: " with ordinary (enabled) echo -- no IAC bytes.
    let greeting = read_bytes(&mut stream, "Name: ".len());
    assert_eq!(greeting, b"Name: ");

    stream.write_all(b"legolas\r\n").unwrap();

    // process_input() turns echo off *before* writing the password
    // prompt: `IAC WILL ECHO` must be the very first thing on the wire,
    // immediately followed by the prompt text, both in the same write.
    let mut expected = vec![IAC, WILL, OPT_ECHO];
    expected.extend_from_slice(b"Password: ");
    let got = read_bytes(&mut stream, expected.len());
    assert_eq!(
        got, expected,
        "expected IAC WILL ECHO directly before the password prompt"
    );

    stream.write_all(b"hunter2\r\n").unwrap();

    // process_input() turns echo back on *before* the welcome line.
    let mut expected = vec![IAC, WONT, OPT_ECHO];
    expected.extend_from_slice(b"Welcome, hunter2.\r\n");
    let got = read_bytes(&mut stream, expected.len());
    assert_eq!(
        got, expected,
        "expected IAC WONT ECHO directly after the password line"
    );

    server.assert_alive();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_echo_flag_round_trips_before_and_after_a_password_prompt() {
    let mudlib = fixture("echo");
    let telnet_port = reserve_local_port();
    let http_port = reserve_local_port();
    let telnet_bind = format!("127.0.0.1:{telnet_port}");
    let http_bind = format!("127.0.0.1:{http_port}");

    let mut server = LoomServer::spawn_with_http(&mudlib, &telnet_bind, &http_bind);

    let url = format!("ws://{http_bind}/ws");
    let mut ws = connect_ws_with_retry(&url, Duration::from_secs(5)).await;

    let greeting = recv_envelope(&mut ws, Duration::from_secs(5)).await;
    assert_eq!(greeting["type"], "line");
    assert_eq!(greeting["text"], "Name: ");

    send_line(&mut ws, "legolas").await;

    // The echo flag arrives as its own envelope ahead of the prompt line,
    // not folded into it -- the web client is expected to flip its input
    // mode on `{"type":"echo","enabled":false}`, then render whatever
    // `line` text follows.
    let echo_off = recv_envelope(&mut ws, Duration::from_secs(2)).await;
    assert_eq!(echo_off["type"], "echo");
    assert_eq!(echo_off["enabled"], false);

    let prompt = recv_envelope(&mut ws, Duration::from_secs(2)).await;
    assert_eq!(prompt["type"], "line");
    assert_eq!(prompt["text"], "Password: ");

    send_line(&mut ws, "hunter2").await;

    let echo_on = recv_envelope(&mut ws, Duration::from_secs(2)).await;
    assert_eq!(echo_on["type"], "echo");
    assert_eq!(echo_on["enabled"], true);

    let welcome = recv_envelope(&mut ws, Duration::from_secs(2)).await;
    assert_eq!(welcome["type"], "line");
    assert_eq!(welcome["text"], "Welcome, hunter2.\n");

    server.assert_alive();
}

async fn send_line(ws: &mut WsStream, line: &str) {
    ws.send(Message::Text(
        serde_json::json!({"type": "line", "text": line})
            .to_string()
            .into(),
    ))
    .await
    .unwrap_or_else(|err| panic!("send `{line}` failed: {err}"));
}

async fn recv_envelope(ws: &mut WsStream, timeout: Duration) -> Value {
    let deadline = tokio::time::Instant::now() + timeout;
    let msg = tokio::time::timeout_at(deadline, ws.next())
        .await
        .expect("timed out waiting for a WS envelope")
        .expect("WS stream ended")
        .expect("WS read failed");
    let Message::Text(text) = msg else {
        panic!("expected a text frame, got {msg:?}");
    };
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("malformed WS envelope: {err}: {text}"))
}

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect_ws_with_retry(url: &str, timeout: Duration) -> WsStream {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio_tungstenite::connect_async(url).await {
            Ok((ws, _)) => return ws,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(err) => panic!("failed to connect WS to {url} before timeout: {err}"),
        }
    }
}

/// Reads exactly `n` bytes (blocking with the stream's read timeout,
/// retried until the deadline), so the telnet-level assertions above can
/// compare an exact byte sequence instead of scanning for a substring.
fn read_bytes(stream: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0_u8; n];
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut filled = 0;
    while filled < n {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => panic!(
                "connection closed after {filled}/{n} bytes: {:?}",
                &buf[..filled]
            ),
            Ok(k) => filled += k,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                if Instant::now() > deadline {
                    panic!("timed out after {filled}/{n} bytes: {:?}", &buf[..filled]);
                }
            }
            Err(err) => panic!("socket read failed after {filled}/{n} bytes: {err}"),
        }
    }
    buf
}

fn connect_with_retry(addr: &str, timeout: Duration) -> TcpStream {
    let deadline = Instant::now() + timeout;
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => return stream,
            Err(err) if Instant::now() < deadline => {
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::TimedOut
                ) {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                panic!("failed to connect to {addr}: {err}");
            }
            Err(err) => panic!("failed to connect to {addr} before timeout: {err}"),
        }
    }
}

/// `loom serve` opens with startup telnet option negotiation (OBI-26: `DO
/// NAWS`, `DO TTYPE`, `WILL GMCP`, `WILL MSSP` -- 12 bytes) before
/// anything else shows up on the wire; drop it so the byte-exact
/// assertions above start at `logon()`'s own output.
fn drain_telnet_preamble(stream: &mut TcpStream) {
    let mut preamble = [0_u8; 12];
    stream
        .read_exact(&mut preamble)
        .expect("read telnet negotiation preamble");
}

fn reserve_local_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("read local addr").port()
}

struct LoomServer {
    child: Child,
}

impl LoomServer {
    fn spawn(mudlib: &Path, bind: &str) -> Self {
        let http_port = reserve_local_port();
        Self::spawn_with_http(mudlib, bind, &format!("127.0.0.1:{http_port}"))
    }

    fn spawn_with_http(mudlib: &Path, telnet_bind: &str, http_bind: &str) -> Self {
        let loom_bin = std::env::var("CARGO_BIN_EXE_loom-cli")
            .or_else(|_| std::env::var("CARGO_BIN_EXE_loom_cli"))
            .expect("cargo binary path for loom-cli");

        let child = Command::new(loom_bin)
            .arg("serve")
            .arg("--mudlib")
            .arg(mudlib)
            .env("LOOM_TELNET_ADDR", telnet_bind)
            .env("LOOM_HTTP_ADDR", http_bind)
            .env_remove("DATABASE_URL")
            .env_remove("LOOM_SMOKE_DATABASE_URL")
            .env("RUST_LOG", "")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn loom serve");

        Self { child }
    }

    fn assert_alive(&mut self) {
        if let Some(status) = self.child.try_wait().expect("poll server process") {
            panic!("loom server exited early with status {status}");
        }
    }
}

impl Drop for LoomServer {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

static N: AtomicU32 = AtomicU32::new(0);

fn scratch(tag: &str) -> PathBuf {
    let n = N.fetch_add(1, Ordering::SeqCst);
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir scratch");
    dir
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("mkdir destination");
    for entry in std::fs::read_dir(from).expect("read fixture directory") {
        let path = entry.expect("fixture entry").path();
        let dest = to.join(path.file_name().expect("fixture filename"));
        if path.is_dir() {
            copy_dir(&path, &dest);
        } else {
            std::fs::copy(&path, &dest).expect("copy fixture file");
        }
    }
}

fn fixture(name: &str) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let dir = scratch(name);
    copy_dir(&src, &dir);
    dir
}
