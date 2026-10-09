// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! End-to-end protocol tests against the `tests/fixtures/warp` fixture
//! tree (OBI-168 acceptance: "integration tests cover each of the four
//! features against a warp fixture tree"). Drives a real
//! [`lsp_server::Connection`] pair -- the exact same code path stdio and
//! the WebSocket bridge use -- with no mocking of the protocol layer.
//!
//! The harness helpers live in `tests/support/mod.rs`, shared with
//! `tests/lsp_thread_count.rs`. Keep thread-count assertions out of *this*
//! binary: it runs its tests in parallel in one process, and a process-wide
//! thread count cannot be attributed to one server (OBI-317).

mod support;

use serde_json::{Value, json};

use support::{TestClient, file_uri, fixture_root, vfs_uri};

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

/// CTO review of OBI-168, F1 (critical): a client-supplied `rootUri` must
/// not replace a `Vfs`-mode workspace's gated provider with an ungated
/// `LocalDirectoryProvider`. Same scenario as the M-LSP-2 test above, but
/// this time the `initialize` handshake sends a real, existing directory
/// as `rootUri` -- exactly what the bug did silently honour.
#[test]
fn f1_a_client_supplied_root_uri_does_not_bypass_vfs_gating() {
    let src = std::fs::read_to_string(fixture_root().join("domains/start/privileged.wf")).unwrap();
    let line = src.lines().position(|l| l.starts_with("inherit")).unwrap() as u32;
    let character = src
        .lines()
        .nth(line as usize)
        .unwrap()
        .find("/secure/master")
        .unwrap() as u32
        + 1;

    // `rootUri` points at a real, existing directory laid out exactly
    // like this workspace's own fixture tree (the fixture root itself) --
    // the exact precondition `Workspace::new(root).is_dir()` needs to
    // fire, *and* a root an attacker would plausibly send to reach
    // `/secure/master.wf` if the bypass were live.
    let root_uri = format!("file://{}", fixture_root().to_str().unwrap());
    let mut t1 =
        TestClient::start_vfs_with_root_uri(&["/domains/start/privileged"], Some(&root_uri));

    // Discriminator #1: a well-formed `loom-vfs://` request for something
    // *readable* must still work. If the bug swapped the session into
    // `Local` mode, `program_path` would stop understanding the
    // `loom-vfs:` scheme at all (`UriMode::Local`'s match arm only parses
    // `file:`), so *every* vfs-scheme request -- not just unreadable ones
    // -- would start returning `null`. Seeing a real hover result here is
    // what proves the workspace is still genuinely gated, not merely
    // coincidentally denying the one path #2 checks.
    t1.did_open_uri(&vfs_uri("/domains/start/privileged"), &src);
    let id = t1.send_request(
        "textDocument/hover",
        json!({
            "textDocument": { "uri": vfs_uri("/domains/start/privileged") },
            "position": { "line": line, "character": character },
        }),
    );
    let resp = t1.recv_response(id);
    assert_ne!(
        resp.response_result.unwrap(),
        Value::Null,
        "a readable loom-vfs:// request must still work after a client rootUri -- if this is \
         null, the session silently fell back to Local mode and no longer understands \
         loom-vfs: URIs at all"
    );

    // Discriminator #2: go-to-definition into the unreadable `/secure/master`
    // must still return nothing.
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
        "a client-supplied rootUri must not turn Vfs mode into an ungated Local one"
    );

    // Also: a `file://` URI must still be rejected as a request target
    // (M-LSP-3), proving the workspace is still genuinely in Vfs mode and
    // not just coincidentally denying this one path.
    let id = t1.send_request(
        "textDocument/hover",
        json!({
            "textDocument": { "uri": file_uri("/domains/start/privileged") },
            "position": { "line": 0, "character": 0 },
        }),
    );
    let resp = t1.recv_response(id);
    assert_eq!(resp.response_result.unwrap(), Value::Null);
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
