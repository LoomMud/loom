// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! WebSocket adapter integration tests (OBI-39): a browser session walks
//! the `tworoom` fixture over `/ws` exactly like the telnet tests walk it
//! over raw TCP, and a WS reader that never drains its socket gets
//! dropped without taking any other connection down with it.

use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

const HALL: &str = "The Great Hall";
const YARD: &str = "The Yard";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_client_walks_two_rooms() {
    let mudlib = fixture("tworoom");
    let telnet_port = reserve_local_port();
    let http_port = reserve_local_port();
    let telnet_bind = format!("127.0.0.1:{telnet_port}");
    let http_bind = format!("127.0.0.1:{http_port}");

    let mut server = LoomServer::spawn(&mudlib, &telnet_bind, &http_bind);
    let mut ws = connect_ws_with_retry(&http_bind, Duration::from_secs(5)).await;

    // logon() drops the player in the Great Hall.
    let greeting = recv_line(&mut ws, Duration::from_secs(5)).await;
    assert!(greeting.contains(HALL), "{greeting}");

    send_line(&mut ws, "look").await;
    let hall = recv_line(&mut ws, Duration::from_secs(2)).await;
    assert!(hall.contains(HALL), "{hall}");
    assert!(hall.contains("Exits: north"), "{hall}");

    send_line(&mut ws, "go north").await;
    let yard = recv_line(&mut ws, Duration::from_secs(2)).await;
    assert!(yard.contains(YARD), "{yard}");
    assert!(yard.contains("Exits: south"), "{yard}");

    send_line(&mut ws, "go south").await;
    let back = recv_line(&mut ws, Duration::from_secs(2)).await;
    assert!(back.contains(HALL), "{back}");

    server.assert_alive();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_gmcp_round_trips_over_the_wire() {
    let mudlib = fixture("tworoom");
    let telnet_port = reserve_local_port();
    let http_port = reserve_local_port();
    let telnet_bind = format!("127.0.0.1:{telnet_port}");
    let http_bind = format!("127.0.0.1:{http_port}");

    let mut server = LoomServer::spawn(&mudlib, &telnet_bind, &http_bind);
    let mut ws = connect_ws_with_retry(&http_bind, Duration::from_secs(5)).await;
    let _ = recv_line(&mut ws, Duration::from_secs(5)).await; // logon greeting

    ws.send(Message::Text(
        json!({"type": "gmcp", "package": "Core.Hello", "payload": {"client": "web", "version": "1.0"}})
            .to_string()
            .into(),
    ))
    .await
    .expect("send GMCP frame");

    // The fixture doesn't do anything with GMCP itself; this just proves
    // the frame round-trips as JSON over the WS transport without
    // desyncing the line protocol that follows it.
    send_line(&mut ws, "look").await;
    let hall = recv_line(&mut ws, Duration::from_secs(2)).await;
    assert!(hall.contains(HALL), "{hall}");

    server.assert_alive();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_ws_reader_is_dropped_without_affecting_a_fast_one() {
    let mudlib = fixture("tworoom");
    let telnet_port = reserve_local_port();
    let http_port = reserve_local_port();
    let telnet_bind = format!("127.0.0.1:{telnet_port}");
    let http_bind = format!("127.0.0.1:{http_port}");

    let mut server = LoomServer::spawn(&mudlib, &telnet_bind, &http_bind);

    let mut slow = connect_ws_with_retry(&http_bind, Duration::from_secs(5)).await;
    let _ = recv_line(&mut slow, Duration::from_secs(5)).await; // logon greeting

    let mut fast = connect_ws_with_retry(&http_bind, Duration::from_secs(5)).await;
    let _ = recv_line(&mut fast, Duration::from_secs(5)).await; // logon greeting

    // Never read from `slow` again: flood it with output ("look" repeated)
    // until the server's bounded output queue fills and drops it, per the
    // OBI-26/OBI-39 backpressure contract (`output_queue_depth`, default
    // 64) -- the exact path the telnet `slow_client_disconnect` test pins
    // for the TCP transport. Once the server disconnects it, further
    // writes on this socket start failing locally too; that's expected,
    // not a test bug, so ignore send errors here.
    for _ in 0..500 {
        let _ = slow
            .send(Message::Text(
                json!({"type": "line", "text": "look"}).to_string().into(),
            ))
            .await;
    }

    // The fast client keeps getting served throughout: every "look" gets
    // its own reply, none dropped, none stalled by the slow one.
    for _ in 0..20 {
        send_line(&mut fast, "look").await;
        let reply = recv_line(&mut fast, Duration::from_secs(3)).await;
        assert!(reply.contains(HALL), "{reply}");
    }

    // The slow client's socket eventually observes the server-initiated
    // close (a WS close frame, or the read simply ending) once the world
    // thread's `NetCommand::Send`s hit an entry whose `output_queue_depth`
    // is full and `run_server_with_ws` disconnects it.
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match slow.next().await {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(_)) => break,
                _ => continue,
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "slow WS client was never dropped");

    server.assert_alive();
}

async fn send_line(ws: &mut WsStream, line: &str) {
    ws.send(Message::Text(
        json!({"type": "line", "text": line}).to_string().into(),
    ))
    .await
    .unwrap_or_else(|err| panic!("send `{line}` failed: {err}"));
}

/// Reads WS text frames, accumulating `text` fields, until the transcript
/// contains a full reply worth returning (heuristically: "Exits:" for a
/// room description, since that's the last line `look`/`go` output ends
/// with in the fixture). Non-`line` frames (e.g. a stray `gmcp` envelope)
/// are ignored.
async fn recv_line(ws: &mut WsStream, timeout: Duration) -> String {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut transcript = String::new();

    loop {
        let msg = tokio::time::timeout_at(deadline, ws.next())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for a line. So far:\n{transcript}"))
            .unwrap_or_else(|| panic!("WS stream ended. So far:\n{transcript}"))
            .unwrap_or_else(|err| panic!("WS read failed: {err}"));

        let Message::Text(text) = msg else { continue };
        let parsed: Value = serde_json::from_str(&text).unwrap_or_else(|err| {
            panic!("malformed WS envelope: {err}: {text}");
        });
        if parsed["type"] == "line"
            && let Some(text) = parsed["text"].as_str()
        {
            transcript.push_str(text);
            if transcript.contains("Exits:") {
                return transcript;
            }
        }
    }
}

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect_ws_with_retry(http_bind: &str, timeout: Duration) -> WsStream {
    let url = format!("ws://{http_bind}/ws");
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio_tungstenite::connect_async(&url).await {
            Ok((ws, _)) => return ws,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(err) => panic!("failed to connect WS to {url} before timeout: {err}"),
        }
    }
}

fn reserve_local_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("read local addr").port()
}

struct LoomServer {
    child: Child,
}

impl LoomServer {
    fn spawn(mudlib: &Path, telnet_bind: &str, http_bind: &str) -> Self {
        let loom_bin = std::env::var("CARGO_BIN_EXE_loom-cli")
            .or_else(|_| std::env::var("CARGO_BIN_EXE_loom_cli"))
            .expect("cargo binary path for loom-cli");

        let child = Command::new(loom_bin)
            .arg("serve")
            .arg("--mudlib")
            .arg(mudlib)
            .env("LOOM_TELNET_ADDR", telnet_bind)
            .env("LOOM_HTTP_ADDR", http_bind)
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
