// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The transport-agnostic protocol core: one [`run`] loop over any
//! [`Connection`] (stdio, in-memory-bridged WebSocket, or a test harness).
//!
//! Spec `docs/threat-model-phase2.md` \u00a76.3 **M-LSP-4**: every request runs
//! on a bounded worker pool (never the main loop thread, so the server
//! keeps reading `$/cancelRequest`/`didChange`/etc. while a slow compile
//! is in flight), with a 5 s deadline and cancellation honoured. The
//! worker itself cannot be force-stopped (Rust has no safe thread-kill),
//! so "cancellation honoured" means what most synchronous LSP servers
//! mean by it: the *response* is cancelled/timed-out immediately and the
//! stray in-flight compile's result, if it ever finishes, is discarded --
//! not that the CPU work inside `loom-compiler` stops early. Documented
//! limitation, not a silent gap.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use loom_compiler::Checked;
use loom_compiler::mudlib::{Outcome, Session};
use loom_syntax::ast;
use lsp_server::{Connection, ErrorCode, Message, Notification, Request, RequestId, Response};
use lsp_types::{
    CompletionItem, CompletionOptions, CompletionParams, DidChangeTextDocumentParams,
    DidCloseTextDocumentParams, DidOpenTextDocumentParams, GotoDefinitionParams,
    GotoDefinitionResponse, Hover, HoverContents, HoverParams, HoverProviderCapability,
    InitializeParams, Location, MarkedString, OneOf, Position, Range, ServerCapabilities,
    TextDocumentSyncCapability, TextDocumentSyncKind, Uri,
};

use crate::position::{position_to_byte_offset, span_to_range};
use crate::workspace::{LimitExceeded, Workspace};
use crate::{completion, definition, hover};

/// Spec M-LSP-4: "a bounded blocking pool ... with a 5 s per-request
/// deadline".
const MAX_CONCURRENT_REQUESTS: usize = 4;
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);

/// Parse (and, if it parses clean, type-check) `path`'s current buffer.
/// Returns `None` only if the buffer/file itself cannot be read at all
/// (OBI-168 scope note, `diagnostics` module docs: this always recompiles
/// from scratch, no incremental caching across requests).
fn compile_for(ws: &Workspace, path: &str) -> Option<(ast::Program, String, Option<Checked>)> {
    let src = ws.text(path).ok()?;
    let (ast_prog, diags) = loom_syntax::parse(&src);
    if !diags.is_empty() {
        return Some((ast_prog, src, None));
    }
    let mut session = Session::new(ws.loader());
    session.compile(path);
    let mut outcomes = session.into_outcomes();
    let checked = match outcomes.remove(path) {
        Some(Outcome::Ok(c)) => Some(c),
        _ => None,
    };
    Some((ast_prog, src, checked))
}

fn zero_range() -> Range {
    Range {
        start: Position::new(0, 0),
        end: Position::new(0, 0),
    }
}

fn server_capabilities() -> ServerCapabilities {
    ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
        hover_provider: Some(HoverProviderCapability::Simple(true)),
        definition_provider: Some(OneOf::Left(true)),
        completion_provider: Some(CompletionOptions {
            trigger_characters: Some(vec![".".to_string()]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// One in-flight request: whether it has already been answered (by its
/// worker finishing, by the deadline firing, or by a `$/cancelRequest`),
/// so whichever of those three happens first "wins" and the other two
/// become no-ops.
type Inflight = Arc<Mutex<HashMap<RequestId, Arc<AtomicBool>>>>;

/// Run the server against `connection` until the client shuts it down.
/// `root` is the warp/mudlib checkout this server serves (one server
/// instance per root; a multi-root client needs one server per folder,
/// same as most language servers without a project-system layer).
pub fn run(
    connection: Connection,
    root: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    run_with_workspace(connection, Workspace::new(root))
}

/// As [`run`], but with an already-constructed [`Workspace`] -- the entry
/// point the per-session/Vfs mode (web IDE bridge) uses, since it needs a
/// [`crate::file_provider::GatedProvider`] in place of a plain directory
/// (spec M-LSP-2/M-LSP-3).
pub fn run_with_workspace(
    connection: Connection,
    mut ws: Workspace,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let (id, params) = connection.initialize_start()?;
    let init_params: InitializeParams = serde_json::from_value(params)?;
    // Prefer a client-given workspace folder, falling back to the
    // deprecated single `rootUri` for older clients. Only meaningful in
    // `Local` mode; a `Vfs`-mode workspace ignores it (there is no
    // filesystem root to override -- M-LSP-3).
    let client_root = init_params
        .workspace_folders
        .as_ref()
        .and_then(|fs| fs.first())
        .map(|f| &f.uri)
        .or({
            #[allow(deprecated)]
            init_params.root_uri.as_ref()
        })
        .and_then(crate::workspace::uri_to_fs_path)
        .filter(|p| p.is_dir());
    if let Some(root) = client_root {
        ws = Workspace::new(root);
    }
    let init_result = serde_json::json!({
        "capabilities": server_capabilities(),
        "serverInfo": { "name": "loom-lsp", "version": env!("CARGO_PKG_VERSION") },
    });
    connection.initialize_finish(id, init_result)?;

    let permits = crossbeam_channel::bounded::<()>(MAX_CONCURRENT_REQUESTS);
    for _ in 0..MAX_CONCURRENT_REQUESTS {
        permits.0.send(()).ok();
    }
    let inflight: Inflight = Arc::new(Mutex::new(HashMap::new()));

    for msg in &connection.receiver {
        match msg {
            Message::Request(req) => {
                if connection.handle_shutdown(&req)? {
                    break;
                }
                spawn_request(&connection, &ws, &permits, &inflight, req);
            }
            Message::Notification(not) => {
                if not.method == "$/cancelRequest" {
                    handle_cancel(&connection, &inflight, not)?;
                } else {
                    handle_notification(&connection, &mut ws, not)?;
                }
            }
            Message::Response(_) => {}
        }
    }
    Ok(())
}

/// Hand `req` to a worker thread (spec M-LSP-4): acquires one of
/// `MAX_CONCURRENT_REQUESTS` permits (blocking further dispatch, not the
/// receive loop, if the pool is full), runs the handler on a second,
/// disposable thread so the deadline can be enforced even if the handler
/// never returns, and sends exactly one response -- whichever of
/// "finished", "timed out", or "cancelled" happens first.
fn spawn_request(
    connection: &Connection,
    ws: &Workspace,
    permits: &(
        crossbeam_channel::Sender<()>,
        crossbeam_channel::Receiver<()>,
    ),
    inflight: &Inflight,
    req: Request,
) {
    let id = req.id.clone();
    let answered = Arc::new(AtomicBool::new(false));
    inflight
        .lock()
        .unwrap()
        .insert(id.clone(), answered.clone());

    let ws = ws.clone();
    let sender = connection.sender.clone();
    let permit_tx = permits.0.clone();
    let permit_rx = permits.1.clone();
    let inflight = inflight.clone();

    std::thread::spawn(move || {
        // Block *this* dispatch thread (not the receive loop above) until
        // a pool slot frees up.
        let _ = permit_rx.recv();

        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        {
            let ws = ws.clone();
            let req = req.clone();
            std::thread::spawn(move || {
                let resp = dispatch_request(&ws, req);
                let _ = done_tx.send(resp);
            });
            // The inner worker is intentionally detached: see module docs
            // on why a timed-out compile cannot be force-stopped.
        }
        let resp = match done_rx.recv_timeout(REQUEST_DEADLINE) {
            Ok(resp) => resp,
            Err(_) => Response::new_err(
                id.clone(),
                ErrorCode::RequestFailed as i32,
                format!(
                    "exceeded the {:?} analysis deadline (M-LSP-4)",
                    REQUEST_DEADLINE
                ),
            ),
        };
        if !answered.swap(true, Ordering::SeqCst) {
            let _ = sender.send(Message::Response(resp));
        }
        inflight.lock().unwrap().remove(&id);
        let _ = permit_tx.send(());
    });
}

fn handle_cancel(
    connection: &Connection,
    inflight: &Inflight,
    not: Notification,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    #[derive(serde::Deserialize)]
    struct CancelParams {
        id: lsp_types::NumberOrString,
    }
    let p: CancelParams = serde_json::from_value(not.params)?;
    let id: RequestId = match p.id {
        lsp_types::NumberOrString::Number(n) => RequestId::from(n),
        lsp_types::NumberOrString::String(s) => RequestId::from(s),
    };
    if let Some(answered) = inflight.lock().unwrap().get(&id).cloned()
        && !answered.swap(true, Ordering::SeqCst)
    {
        let resp = Response::new_err(
            id,
            ErrorCode::RequestCanceled as i32,
            "cancelled by the client".to_string(),
        );
        connection.sender.send(Message::Response(resp))?;
    }
    Ok(())
}

fn dispatch_request(ws: &Workspace, req: Request) -> Response {
    match req.method.as_str() {
        "textDocument/hover" => reply::<HoverParams, _>(req, |p| handle_hover(ws, p)),
        "textDocument/definition" => {
            reply::<GotoDefinitionParams, _>(req, |p| handle_definition(ws, p))
        }
        "textDocument/completion" => {
            reply::<CompletionParams, _>(req, |p| handle_completion(ws, p))
        }
        _ => Response::new_err(
            req.id,
            ErrorCode::MethodNotFound as i32,
            format!("unhandled method {}", req.method),
        ),
    }
}

/// Deserialize `req`'s params as `P`, run `f`, and serialize whatever it
/// returns (including `None`, which LSP represents as a `null` result) as
/// the response -- the common shape of every request handler below.
fn reply<P, R>(req: Request, f: impl FnOnce(P) -> R) -> Response
where
    P: serde::de::DeserializeOwned,
    R: serde::Serialize,
{
    let id = req.id.clone();
    match serde_json::from_value::<P>(req.params) {
        Ok(params) => Response::new_ok(id, f(params)),
        Err(e) => Response::new_err(id, ErrorCode::InvalidParams as i32, e.to_string()),
    }
}

fn handle_notification(
    connection: &Connection,
    ws: &mut Workspace,
    not: Notification,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    match not.method.as_str() {
        "textDocument/didOpen" => {
            let p: DidOpenTextDocumentParams = serde_json::from_value(not.params)?;
            if let Some(path) = ws.program_path(&p.text_document.uri) {
                match ws.open(path.clone(), p.text_document.text) {
                    Ok(()) => publish(connection, ws, &path)?,
                    Err(e) => publish_limit_exceeded(connection, ws, &path, e)?,
                }
            }
        }
        "textDocument/didChange" => {
            let p: DidChangeTextDocumentParams = serde_json::from_value(not.params)?;
            if let Some(path) = ws.program_path(&p.text_document.uri)
                && let Some(last) = p.content_changes.into_iter().next_back()
            {
                // Full sync (`TextDocumentSyncKind::FULL`): the last (and
                // only) change event is the whole new document text.
                match ws.change(&path, last.text) {
                    Ok(()) => publish(connection, ws, &path)?,
                    Err(e) => publish_limit_exceeded(connection, ws, &path, e)?,
                }
            }
        }
        "textDocument/didClose" => {
            let p: DidCloseTextDocumentParams = serde_json::from_value(not.params)?;
            if let Some(path) = ws.program_path(&p.text_document.uri) {
                ws.close(&path);
            }
        }
        "exit" => return Err("exit".into()),
        _ => {}
    }
    Ok(())
}

fn publish(
    connection: &Connection,
    ws: &Workspace,
    path: &str,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let params = crate::diagnostics::publish_params(ws, path);
    let not = Notification {
        method: "textDocument/publishDiagnostics".to_string(),
        params: serde_json::to_value(params)?,
    };
    connection.sender.send(Message::Notification(not))?;
    Ok(())
}

/// Spec M-LSP-4: a refused buffer (over the size cap, or the open-document
/// cap) gets a single explanatory diagnostic instead of silently vanishing.
fn publish_limit_exceeded(
    connection: &Connection,
    ws: &Workspace,
    path: &str,
    e: LimitExceeded,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let message = match e {
        LimitExceeded::DocumentTooLarge { bytes } => format!(
            "document is {bytes} bytes, over loom-lsp's {}-byte limit (M-LSP-4); not analyzed",
            crate::workspace::MAX_DOCUMENT_BYTES
        ),
        LimitExceeded::TooManyOpenDocuments => format!(
            "this session already has {} open documents, loom-lsp's limit (M-LSP-4); close one first",
            crate::workspace::MAX_OPEN_DOCUMENTS
        ),
    };
    let params = lsp_types::PublishDiagnosticsParams {
        uri: ws.uri_for_path(path),
        diagnostics: vec![lsp_types::Diagnostic {
            range: zero_range(),
            severity: Some(lsp_types::DiagnosticSeverity::ERROR),
            code: None,
            code_description: None,
            source: Some("loom-lsp".to_string()),
            message,
            related_information: None,
            tags: None,
            data: None,
        }],
        version: None,
    };
    let not = Notification {
        method: "textDocument/publishDiagnostics".to_string(),
        params: serde_json::to_value(params)?,
    };
    connection.sender.send(Message::Notification(not))?;
    Ok(())
}

fn handle_hover(ws: &Workspace, p: HoverParams) -> Option<Hover> {
    let uri = p.text_document_position_params.text_document.uri;
    let path = ws.program_path(&uri)?;
    let (ast_prog, src, checked) = compile_for(ws, &path)?;
    let offset = position_to_byte_offset(&src, p.text_document_position_params.position) as u32;
    let checked_ref = checked.as_ref().map(|c| (&c.hir, &c.info));
    let r = hover::hover(&ast_prog, checked_ref, offset)?;
    Some(Hover {
        contents: HoverContents::Scalar(MarkedString::String(r.text)),
        range: Some(span_to_range(&src, r.span)),
    })
}

/// Spec M-LSP-2/T-LSP-2: a go-to-definition target the caller cannot read
/// gets **no** `Location` at all -- not a zero-range one, which would
/// still leak the target's existence and normalised path.
fn handle_definition(ws: &Workspace, p: GotoDefinitionParams) -> Option<GotoDefinitionResponse> {
    let uri = p.text_document_position_params.text_document.uri;
    let path = ws.program_path(&uri)?;
    let (ast_prog, src, checked) = compile_for(ws, &path)?;
    let offset = position_to_byte_offset(&src, p.text_document_position_params.position) as u32;

    if let Some(t) = definition::definition_for_path(&ast_prog, offset) {
        if !ws.can_read(&t.path) {
            return None;
        }
        return Some(single(ws.uri_for_path(&t.path), zero_range()));
    }
    let checked = checked?;
    let t = definition::definition_for_identifier(&checked.hir, &checked.info, offset)?;
    if !ws.can_read(&t.path) {
        return None;
    }
    let range = t
        .name
        .as_deref()
        .and_then(|name| {
            let (_, owner_src, owner_checked) = compile_for(ws, &t.path)?;
            let owner_checked = owner_checked?;
            let span = definition::resolve_span_in_owner(&owner_checked.hir, name)?;
            Some(span_to_range(&owner_src, span))
        })
        .unwrap_or_else(zero_range);
    Some(single(ws.uri_for_path(&t.path), range))
}

fn single(uri: Uri, range: Range) -> GotoDefinitionResponse {
    GotoDefinitionResponse::Scalar(Location { uri, range })
}

fn handle_completion(ws: &Workspace, p: CompletionParams) -> Option<Vec<CompletionItem>> {
    let uri = p.text_document_position.text_document.uri;
    let path = ws.program_path(&uri)?;
    let (_, _, checked) = compile_for(ws, &path)?;
    Some(completion::all_items(checked.as_ref().map(|c| &c.info)))
}
