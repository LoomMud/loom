// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared harness for `loom-lsp`'s integration test binaries (OBI-317).
//!
//! Every file directly under `tests/` is compiled as its **own test binary**,
//! and cargo runs each binary as its own process, one binary at a time. A
//! module in a *sub*directory is not a binary of its own: it is simply included
//! by whichever test file names it, which is why both binaries below say
//! `mod support;` and this file lives in `tests/support/`.
//!
//! The split exists because `thread_ids()` / `thread_count()` read
//! `/proc/self/task` — a *process-wide* thread list — while
//! `TestClient::start()` runs a server in-process (6 threads: `run()` +
//! `MAX_CONCURRENT_REQUESTS` workers + 1 timer). When the G1 guard lived in
//! `lsp_integration.rs` it shared that process with ten other tests starting
//! and stopping sessions in parallel, so a measurement taken there moved by
//! more than the guard's slack whenever a sibling session came or went. See
//! `tests/lsp_thread_count.rs`, which keeps the one measurement that needs a
//! process to itself.
//!
//! `dead_code` is allowed because the two binaries use different halves of
//! these helpers; without it `cargo clippy --all-targets -D warnings` would
//! fail one of them for the other's imports.

#![allow(dead_code)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use lsp_server::{Connection, Message, Notification, Request, RequestId, Response};
use serde_json::{Value, json};

pub fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/warp")
}

pub fn file_uri(path: &str) -> String {
    format!("file://{}{}.wf", fixture_root().to_str().unwrap(), path)
}

pub fn vfs_uri(path: &str) -> String {
    format!("loom-vfs://{path}.wf")
}

/// Start a server on a background thread and hand back the client side of
/// the channel pair, already past `initialize`/`initialized`.
pub struct TestClient {
    pub conn: Connection,
    pub next_id: i32,
}

impl TestClient {
    pub fn start() -> TestClient {
        let (server_conn, client_conn) = Connection::memory();
        std::thread::spawn(move || {
            let _ = loom_lsp::server::run(server_conn, fixture_root());
        });
        TestClient::handshake(client_conn, None)
    }

    /// A session using the per-session/Vfs mode (spec M-LSP-2/M-LSP-3):
    /// reads are gated by `readable`, and `loom-vfs://` URIs replace
    /// `file://` ones.
    pub fn start_vfs(readable: &[&str]) -> TestClient {
        TestClient::start_vfs_with_root_uri(readable, None)
    }

    /// As [`TestClient::start_vfs`], but the `initialize` handshake sends
    /// `rootUri` = `root_uri` (spec M-LSP-2/M-LSP-3, CTO review F1: a
    /// `Vfs`-mode workspace must ignore this, not swap itself out for an
    /// ungated `Workspace::new(root)`).
    pub fn start_vfs_with_root_uri(readable: &[&str], root_uri: Option<&str>) -> TestClient {
        use loom_lsp::file_provider::{GatedProvider, LocalDirectoryProvider};
        use loom_lsp::workspace::Workspace;
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
        TestClient::handshake(client_conn, root_uri)
    }

    pub fn handshake(conn: Connection, root_uri: Option<&str>) -> TestClient {
        let mut c = TestClient { conn, next_id: 1 };
        let id = c.send_request(
            "initialize",
            json!({
                "processId": null,
                "rootUri": root_uri,
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

    pub fn send_request(&mut self, method: &str, params: Value) -> RequestId {
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

    pub fn send_notification(&mut self, method: &str, params: Value) {
        self.conn
            .sender
            .send(Message::Notification(Notification {
                method: method.to_string(),
                params,
            }))
            .unwrap();
    }

    pub fn recv_response(&self, id: RequestId) -> Response {
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
    pub fn recv_diagnostics(&self, uri: &str) -> Value {
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

    pub fn did_open(&mut self, path: &str, text: &str) {
        self.did_open_uri(&file_uri(path), text);
    }

    pub fn did_open_uri(&mut self, uri: &str, text: &str) {
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

/// Every thread id live in **this process**, as a set.
///
/// A set rather than a number: the OBI-317 flake was a count that moved for
/// reasons unrelated to the server, and a set difference names the threads
/// that *appeared* during the measurement window instead of only reporting
/// that the total changed. Requires Linux (the only CI runner); the `expect`
/// says so out loud if someone ports the suite.
pub fn thread_ids() -> HashSet<u32> {
    let mut ids = HashSet::new();
    for entry in std::fs::read_dir("/proc/self/task").expect("this test requires /proc (Linux)") {
        let name = entry.expect("unreadable /proc entry").file_name();
        if let Some(tid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) {
            ids.insert(tid);
        }
    }
    ids
}

/// Convenience count of [`thread_ids`].
pub fn thread_count() -> usize {
    thread_ids().len()
}
