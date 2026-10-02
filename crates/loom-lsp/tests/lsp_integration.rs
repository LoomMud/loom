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

fn vfs_uri(path: &str) -> String {
    format!("loom-vfs://{path}.wf")
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
        TestClient::handshake(client_conn)
    }

    /// A session using the per-session/Vfs mode (spec M-LSP-2/M-LSP-3):
    /// reads are gated by `readable`, and `loom-vfs://` URIs replace
    /// `file://` ones.
    fn start_vfs(readable: &[&str]) -> TestClient {
        use loom_lsp::file_provider::{GatedProvider, LocalDirectoryProvider};
        use loom_lsp::workspace::Workspace;
        use std::collections::HashSet;
        use std::sync::Arc;

        struct AllowList(HashSet<String>);
        impl loom_lsp::file_provider::ReadAuthorizer for AllowList {
            fn can_read(&self, path: &str) -> bool {
                self.0.contains(path)
            }
        }

        let provider: Arc<dyn loom_lsp::file_provider::FileProvider> = Arc::new(GatedProvider {
            inner: LocalDirectoryProvider {
                root: fixture_root(),
            },
            authz: AllowList(readable.iter().map(|s| s.to_string()).collect()),
        });
        let ws = Workspace::new_vfs(provider);
        let (server_conn, client_conn) = Connection::memory();
        std::thread::spawn(move || {
            let _ = loom_lsp::server::run_with_workspace(server_conn, ws);
        });
        TestClient::handshake(client_conn)
    }

    fn handshake(conn: Connection) -> TestClient {
        let mut c = TestClient { conn, next_id: 1 };
        let id = c.send_request(
            "initialize",
            json!({
                "processId": null,
                "rootUri": null,
                "capabilities": {},
            }),
        );
        let resp = c.recv_response(id);
        assert!(
            resp.response_result.is_ok(),
            "initialize failed: {:?}",
            resp.response_result
        );
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
            assert!(
                left > Duration::ZERO,
                "timed out waiting for response to {id:?}"
            );
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
            assert!(
                left > Duration::ZERO,
                "timed out waiting for diagnostics for {uri}"
            );
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
        self.did_open_uri(&file_uri(path), text);
    }

    fn did_open_uri(&mut self, uri: &str, text: &str) {
        self.send_notification(
            "textDocument/didOpen",
            json!({
                "textDocument": {
                    "uri": uri,
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
    assert!(
        !diags.is_empty(),
        "expected at least one diagnostic, got {params}"
    );
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

    let line = src
        .lines()
        .position(|l| l.contains("Welcome to {who}"))
        .unwrap() as u32;
    let character = src
        .lines()
        .nth(line as usize)
        .unwrap()
        .find("who}")
        .unwrap() as u32
        + 1;
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
    assert!(
        text.contains("string"),
        "expected the `string` type in hover text, got {text:?}"
    );
}

#[test]
fn go_to_definition_on_an_inherit_path_jumps_to_the_parent_file() {
    let mut c = TestClient::start();
    let src = std::fs::read_to_string(fixture_root().join("domains/start/yard.wf")).unwrap();
    c.did_open("/domains/start/yard", &src);
    let _ = c.recv_diagnostics(&file_uri("/domains/start/yard"));

    let line = src.lines().position(|l| l.starts_with("inherit")).unwrap() as u32;
    let character = src
        .lines()
        .nth(line as usize)
        .unwrap()
        .find("/std/room")
        .unwrap() as u32
        + 1;
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
    let line = src
        .lines()
        .position(|l| l.contains("let who = short()"))
        .unwrap() as u32;
    let character = src
        .lines()
        .nth(line as usize)
        .unwrap()
        .find("short()")
        .unwrap() as u32
        + 1;
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
    let labels: Vec<&str> = items
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["label"].as_str().unwrap())
        .collect();
    assert!(
        labels.contains(&"send"),
        "expected the `send` efun, got {labels:?}"
    );
    assert!(
        labels.contains(&"create"),
        "expected the `create` apply, got {labels:?}"
    );
    // Inherited from /std/object via /std/room.
    assert!(
        labels.contains(&"query_name"),
        "expected inherited /std API, got {labels:?}"
    );
}

/// Spec `docs/threat-model-phase2.md` §6.3 **M-LSP-2**, T-LSP-2's own
/// named test case: "a T1 session doing go-to-definition from its
/// workroom into `/secure/master.wf` ... gets nothing, and the same
/// request from a T4 gets the location."
#[test]
fn m_lsp_2_a_session_that_cannot_read_the_target_gets_no_location() {
    let src = std::fs::read_to_string(fixture_root().join("domains/start/privileged.wf")).unwrap();
    let line = src.lines().position(|l| l.starts_with("inherit")).unwrap() as u32;
    let character = src
        .lines()
        .nth(line as usize)
        .unwrap()
        .find("/secure/master")
        .unwrap() as u32
        + 1;

    // "T1": can read its own workroom file but not /secure/master.
    let mut t1 = TestClient::start_vfs(&["/domains/start/privileged"]);
    t1.did_open_uri(&vfs_uri("/domains/start/privileged"), &src);
    let id = t1.send_request(
        "textDocument/definition",
        json!({
            "textDocument": { "uri": vfs_uri("/domains/start/privileged") },
            "position": { "line": line, "character": character },
        }),
    );
    let resp = t1.recv_response(id);
    assert_eq!(
        resp.response_result.unwrap(),
        Value::Null,
        "T1 must get no Location into an unreadable file"
    );

    // "T4": can read both.
    let mut t4 = TestClient::start_vfs(&["/domains/start/privileged", "/secure/master"]);
    t4.did_open_uri(&vfs_uri("/domains/start/privileged"), &src);
    let id = t4.send_request(
        "textDocument/definition",
        json!({
            "textDocument": { "uri": vfs_uri("/domains/start/privileged") },
            "position": { "line": line, "character": character },
        }),
    );
    let resp = t4.recv_response(id);
    let result = resp.response_result.expect("T4 must get a Location");
    assert_eq!(result["uri"].as_str().unwrap(), vfs_uri("/secure/master"));
}

#[test]
fn m_lsp_3_a_file_uri_is_rejected_in_vfs_mode() {
    let mut c = TestClient::start_vfs(&["/domains/start/yard", "/std/room", "/std/object"]);
    // A `file://` URI (host path) must never resolve to a program path in
    // Vfs mode (spec M-LSP-3: "no file: URIs ... in responses", and none
    // honoured as requests either).
    let id = c.send_request(
        "textDocument/hover",
        json!({
            "textDocument": { "uri": file_uri("/domains/start/yard") },
            "position": { "line": 0, "character": 0 },
        }),
    );
    let resp = c.recv_response(id);
    assert_eq!(resp.response_result.unwrap(), Value::Null);
}
