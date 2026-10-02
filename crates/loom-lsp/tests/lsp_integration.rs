// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! End-to-end protocol tests against the `tests/fixtures/warp` fixture
//! tree (OBI-168 acceptance: "integration tests cover each of the four
//! features against a warp fixture tree"). Drives a real
//! [`lsp_server::Connection`] pair -- the exact same code path stdio and
//! the WebSocket bridge use -- with no mocking of the protocol layer.

use std::path::PathBuf;
use std::time::Duration;

use lsp_server::{Connection, Message, Notification, Request, RequestId, Response};
use serde_json::{Value, json};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/warp")
}

fn file_uri(path: &str) -> String {
    format!("file://{}{}.wf", fixture_root().to_str().unwrap(), path)
}

/// Start a server on a background thread and hand back the client side of
/// the channel pair, already past `initialize`/`initialized`.
struct TestClient {
    conn: Connection,
    next_id: i32,
}

impl TestClient {
    fn start() -> TestClient {
        let (server_conn, client_conn) = Connection::memory();
        std::thread::spawn(move || {
            let _ = loom_lsp::server::run(server_conn, fixture_root());
        });
        let mut c = TestClient { conn: client_conn, next_id: 1 };
        let id = c.send_request(
            "initialize",
            json!({
                "processId": null,
                "rootUri": null,
                "capabilities": {},
            }),
        );
        let resp = c.recv_response(id);
        assert!(resp.response_result.is_ok(), "initialize failed: {:?}", resp.response_result);
        c.send_notification("initialized", json!({}));
        c
    }

    fn send_request(&mut self, method: &str, params: Value) -> RequestId {
        let id = RequestId::from(self.next_id);
        self.next_id += 1;
        self.conn
            .sender
            .send(Message::Request(Request {
                id: id.clone(),
                method: method.to_string(),
                params,
            }))
            .unwrap();
        id
    }

    fn send_notification(&mut self, method: &str, params: Value) {
        self.conn
            .sender
            .send(Message::Notification(Notification {
                method: method.to_string(),
                params,
            }))
            .unwrap();
    }

    fn recv_response(&self, id: RequestId) -> Response {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(left > Duration::ZERO, "timed out waiting for response to {id:?}");
            match self.conn.receiver.recv_timeout(left) {
                Ok(Message::Response(r)) if r.id == id => return r,
                Ok(_) => continue,
                Err(e) => panic!("channel closed while waiting for response to {id:?}: {e}"),
            }
        }
    }

    /// Wait for a `textDocument/publishDiagnostics` notification for `uri`.
    fn recv_diagnostics(&self, uri: &str) -> Value {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(left > Duration::ZERO, "timed out waiting for diagnostics for {uri}");
            match self.conn.receiver.recv_timeout(left) {
                Ok(Message::Notification(n)) if n.method == "textDocument/publishDiagnostics" => {
                    if n.params["uri"] == *uri {
                        return n.params;
                    }
                }
                Ok(_) => continue,
                Err(e) => panic!("channel closed while waiting for diagnostics: {e}"),
            }
        }
    }

    fn did_open(&mut self, path: &str, text: &str) {
        self.send_notification(
            "textDocument/didOpen",
            json!({
                "textDocument": {
                    "uri": file_uri(path),
                    "languageId": "weft",
                    "version": 1,
                    "text": text,
                }
            }),
        );
    }
}

#[test]
fn diagnostics_report_a_type_error_with_a_w_code() {
    let mut c = TestClient::start();
    let src = std::fs::read_to_string(fixture_root().join("domains/start/broken.wf")).unwrap();
    c.did_open("/domains/start/broken", &src);
    let params = c.recv_diagnostics(&file_uri("/domains/start/broken"));
    let diags = params["diagnostics"].as_array().unwrap();
    assert!(!diags.is_empty(), "expected at least one diagnostic, got {params}");
    let code = diags[0]["code"].as_str().unwrap();
    assert!(code.starts_with('W'), "expected a W#### code, got {code}");
    assert_eq!(diags[0]["severity"], 1, "expected error severity");
}

#[test]
fn diagnostics_are_clean_for_a_well_typed_file() {
    let mut c = TestClient::start();
    let src = std::fs::read_to_string(fixture_root().join("domains/start/yard.wf")).unwrap();
    c.did_open("/domains/start/yard", &src);
    let params = c.recv_diagnostics(&file_uri("/domains/start/yard"));
    let diags = params["diagnostics"].as_array().unwrap();
    assert!(diags.is_empty(), "expected no diagnostics, got {diags:?}");
}

#[test]
fn hover_shows_the_inferred_type_of_a_local() {
    let mut c = TestClient::start();
    let src = std::fs::read_to_string(fixture_root().join("domains/start/yard.wf")).unwrap();
    c.did_open("/domains/start/yard", &src);
    // Drain the diagnostics notification before issuing the hover request.
    let _ = c.recv_diagnostics(&file_uri("/domains/start/yard"));

    let line = src.lines().position(|l| l.contains("Welcome to {who}")).unwrap() as u32;
    let character = src.lines().nth(line as usize).unwrap().find("who}").unwrap() as u32 + 1;
    let id = c.send_request(
        "textDocument/hover",
        json!({
            "textDocument": { "uri": file_uri("/domains/start/yard") },
            "position": { "line": line, "character": character },
        }),
    );
    let resp = c.recv_response(id);
    let result = resp.response_result.expect("hover result");
    let text = result["contents"].as_str().unwrap();
    assert!(text.contains("string"), "expected the `string` type in hover text, got {text:?}");
}

#[test]
fn go_to_definition_on_an_inherit_path_jumps_to_the_parent_file() {
    let mut c = TestClient::start();
    let src = std::fs::read_to_string(fixture_root().join("domains/start/yard.wf")).unwrap();
    c.did_open("/domains/start/yard", &src);
    let _ = c.recv_diagnostics(&file_uri("/domains/start/yard"));

    let line = src.lines().position(|l| l.starts_with("inherit")).unwrap() as u32;
    let character = src.lines().nth(line as usize).unwrap().find("/std/room").unwrap() as u32 + 1;
    let id = c.send_request(
        "textDocument/definition",
        json!({
            "textDocument": { "uri": file_uri("/domains/start/yard") },
            "position": { "line": line, "character": character },
        }),
    );
    let resp = c.recv_response(id);
    let result = resp.response_result.expect("definition result");
    let uri = result["uri"].as_str().unwrap();
    assert_eq!(uri, file_uri("/std/room"));
}

#[test]
fn go_to_definition_on_a_call_jumps_to_the_declaring_programs_function() {
    let mut c = TestClient::start();
    let src = std::fs::read_to_string(fixture_root().join("domains/start/yard.wf")).unwrap();
    c.did_open("/domains/start/yard", &src);
    let _ = c.recv_diagnostics(&file_uri("/domains/start/yard"));

    // `short()` inside `greet()` is overridden in yard.wf itself, so this
    // resolves within the same file -- still exercises the identifier path
    // distinctly from the inherit-path test above.
    let line = src.lines().position(|l| l.contains("let who = short()")).unwrap() as u32;
    let character = src.lines().nth(line as usize).unwrap().find("short()").unwrap() as u32 + 1;
    let id = c.send_request(
        "textDocument/definition",
        json!({
            "textDocument": { "uri": file_uri("/domains/start/yard") },
            "position": { "line": line, "character": character },
        }),
    );
    let resp = c.recv_response(id);
    let result = resp.response_result.expect("definition result");
    let uri = result["uri"].as_str().unwrap();
    assert_eq!(uri, file_uri("/domains/start/yard"));
    assert_ne!(result["range"]["start"]["line"], 0);
}

#[test]
fn completion_offers_efuns_applies_and_inherited_std_api() {
    let mut c = TestClient::start();
    let src = std::fs::read_to_string(fixture_root().join("domains/start/yard.wf")).unwrap();
    c.did_open("/domains/start/yard", &src);
    let _ = c.recv_diagnostics(&file_uri("/domains/start/yard"));

    let id = c.send_request(
        "textDocument/completion",
        json!({
            "textDocument": { "uri": file_uri("/domains/start/yard") },
            "position": { "line": 0, "character": 0 },
        }),
    );
    let resp = c.recv_response(id);
    let items = resp.response_result.expect("completion result");
    let labels: Vec<&str> = items.as_array().unwrap().iter().map(|i| i["label"].as_str().unwrap()).collect();
    assert!(labels.contains(&"send"), "expected the `send` efun, got {labels:?}");
    assert!(labels.contains(&"create"), "expected the `create` apply, got {labels:?}");
    // Inherited from /std/object via /std/room.
    assert!(labels.contains(&"query_name"), "expected inherited /std API, got {labels:?}");
}
