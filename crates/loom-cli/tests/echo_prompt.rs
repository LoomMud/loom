// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-176 acceptance: telnet `IAC WILL ECHO`/`IAC WONT ECHO` around a
//! no-echo input (and the WS equivalent), driven end to end through the
//! `set_echo()` efun from a warp-style login state machine (the `echo`
//! fixture) against a real `loom-cli serve` subprocess. The telnet half
//! reads the raw byte stream rather than a telnet-aware client library, so
//! the transcript is a literal `IAC WILL/WONT ECHO` byte sequence around the
//! password prompt and its reply, exactly as the acceptance criterion asks
//! for.
//!
//! The subprocess, its ports, and the byte reads come from `loom_testing`
//! (OBI-305). [`loom_testing::Session::read_bytes`] is what keeps the
//! byte-exact assertions possible: it returns exactly `n` bytes, so
//! "IAC WILL ECHO was the very first thing on the wire" is a literal
//! comparison and not a substring search.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use loom_testing::Spawn;
use serde_json::Value;
use tokio_tungstenite::tungstenite::Message;

const IAC: u8 = 255;
const WILL: u8 = 251;
const WONT: u8 = 252;
const OPT_ECHO: u8 = 1;

/// How long one byte-exact read may take before the test calls it a stall.
const READ_BUDGET: Duration = Duration::from_secs(5);

#[test]
fn raw_telnet_transcript_shows_will_echo_then_wont_echo_around_password() {
    let mudlib = loom_testing::fixture(env!("CARGO_MANIFEST_DIR"), "echo");
    let mut server = Spawn::serve(&mudlib).start();
    // The connection readiness was proved on, with the 12-byte startup
    // negotiation already drained -- so this session starts exactly where
    // `logon()`'s own output starts.
    let mut session = server.session();

    // logon(): "Name: " with ordinary (enabled) echo -- no IAC bytes.
    let greeting = session.read_bytes("Name: ".len(), READ_BUDGET);
    assert_eq!(greeting, b"Name: ");

    session.write_bytes(b"legolas\r\n");

    // process_input() turns echo off *before* writing the password
    // prompt: `IAC WILL ECHO` must be the very first thing on the wire,
    // immediately followed by the prompt text, both in the same write.
    let mut expected = vec![IAC, WILL, OPT_ECHO];
    expected.extend_from_slice(b"Password: ");
    let got = session.read_bytes(expected.len(), READ_BUDGET);
    assert_eq!(
        got, expected,
        "expected IAC WILL ECHO directly before the password prompt"
    );

    session.write_bytes(b"hunter2\r\n");

    // process_input() turns echo back on *before* the welcome line.
    let mut expected = vec![IAC, WONT, OPT_ECHO];
    expected.extend_from_slice(b"Welcome, hunter2.\r\n");
    let got = session.read_bytes(expected.len(), READ_BUDGET);
    assert_eq!(
        got, expected,
        "expected IAC WONT ECHO directly after the password line"
    );

    server.assert_alive();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_echo_flag_round_trips_before_and_after_a_password_prompt() {
    let mudlib = loom_testing::fixture(env!("CARGO_MANIFEST_DIR"), "echo");
    let mut server = Spawn::serve(&mudlib).start();
    let url = format!("ws://{}/ws", server.http_bind());
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
