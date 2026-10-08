// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! WebSocket adapter integration tests (OBI-39): a browser session walks
//! the `tworoom` fixture over `/ws` exactly like the telnet tests walk it
//! over raw TCP, and a WS reader that never drains its socket gets
//! dropped without taking any other connection down with it.
//!
//! The server here comes from [`loom_testing::Spawn`], so it is only handed
//! back once it is actually serving (OBI-292/OBI-305) -- which is what makes
//! `connect_ws_with_retry` below slack rather than the thing that papers over
//! "did the process even bind?".

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use loom_testing::Spawn;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

const HALL: &str = "The Great Hall";
const YARD: &str = "The Yard";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_client_walks_two_rooms() {
    let mudlib = loom_testing::fixture(env!("CARGO_MANIFEST_DIR"), "tworoom");
    let mut server = Spawn::serve(&mudlib).start();
    let mut ws = connect_ws_with_retry(server.http_bind(), Duration::from_secs(5)).await;

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
    let mudlib = loom_testing::fixture(env!("CARGO_MANIFEST_DIR"), "tworoom");
    let mut server = Spawn::serve(&mudlib).start();
    let mut ws = connect_ws_with_retry(server.http_bind(), Duration::from_secs(5)).await;
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
    let mudlib = loom_testing::fixture(env!("CARGO_MANIFEST_DIR"), "tworoom");
    let mut server = Spawn::serve(&mudlib).start();
    let http_bind = server.http_bind().to_owned();

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
