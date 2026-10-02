// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The transport-agnostic protocol core: one [`run`] loop over any
//! [`Connection`] (stdio, in-memory-bridged WebSocket, or a test harness).
//!
//! Spec `docs/threat-model-phase2.md` §6.3 **M-LSP-4**: every request runs
//! on a bounded worker pool (never the main loop thread, so the server
//! keeps reading `$/cancelRequest`/`didChange`/etc. while a slow compile
//! is in flight), with a 5 s deadline and cancellation honoured.
//!
//! The pool is `MAX_CONCURRENT_REQUESTS` **persistent** worker threads
//! reading from a bounded job queue (CTO review of OBI-168, F3): a
//! worker calls `dispatch_request` directly and only picks up its next
//! job once that call actually returns, so a pool slot is occupied for
//! exactly as long as real compile work is running, never released early
//! just because the client-facing deadline fired. The deadline itself is
//! enforced by a separate, cheap (sleep-only) timer thread per in-flight
//! job, which sends a timeout response to the client without touching
//! the worker -- the worker keeps running to completion regardless (Rust
//! has no safe thread-kill, so "cancellation honoured" means the
//! *response* is cancelled/timed-out immediately, not that the CPU work
//! inside `loom-compiler` stops early; documented limitation, not a
//! silent gap). When the job queue is full, a new request is refused
//! immediately with no thread spawned at all (M-LSP-4's backpressure).

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
/// deadline". This many persistent worker threads exist for the whole
/// server lifetime; it is also the hard cap on concurrent compiles.
const MAX_CONCURRENT_REQUESTS: usize = 4;
/// How many requests may wait for a free worker before new ones are
/// refused outright (CTO review F3.2: "about 16 pending").
const MAX_PENDING_REQUESTS: usize = 16;
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

/// One request queued for a worker.
struct Job {
    req: Request,
    ws: Workspace,
}

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
    // F1 (CTO review of OBI-168): only honour a client-supplied root in
    // `Local` mode. A `Vfs`-mode workspace's reads are gated by a
    // `ReadAuthorizer` (spec M-LSP-2); swapping it for a plain
    // `Workspace::new(root)` here would silently replace that gate with
    // an ungated `LocalDirectoryProvider` and start accepting `file://`
    // URIs (M-LSP-3) the moment any client sent an `initialize` with a
    // `rootUri` -- exactly the bypass this review caught.
    if ws.is_local() {
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
    }
    let init_result = serde_json::json!({
        "capabilities": server_capabilities(),
        "serverInfo": { "name": "loom-lsp", "version": env!("CARGO_PKG_VERSION") },
    });
    connection.initialize_finish(id, init_result)?;

    let inflight: Inflight = Arc::new(Mutex::new(HashMap::new()));
    let (job_tx, job_rx) = crossbeam_channel::bounded::<Job>(MAX_PENDING_REQUESTS);
    for _ in 0..MAX_CONCURRENT_REQUESTS {
        spawn_worker(connection.sender.clone(), inflight.clone(), job_rx.clone());
    }

    for msg in &connection.receiver {
        match msg {
            Message::Request(req) => {
                if connection.handle_shutdown(&req)? {
                    break;
                }
                dispatch_or_refuse(&connection, &ws, &job_tx, &inflight, req)?;
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

/// Queue `req` for a worker (spec M-LSP-4), or refuse it immediately --
/// no thread spawned either way -- if `MAX_PENDING_REQUESTS` are already
/// waiting (CTO review F3.2: the previous design spawned one OS thread
/// per request *before* checking any bound, so a burst of requests was
/// unbounded thread growth; this one never spawns anything on the
/// receive-loop thread at all).
fn dispatch_or_refuse(
    connection: &Connection,
    ws: &Workspace,
    job_tx: &crossbeam_channel::Sender<Job>,
    inflight: &Inflight,
    req: Request,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let id = req.id.clone();
    let job = Job {
        req,
        ws: ws.clone(),
    };
    match job_tx.try_send(job) {
        Ok(()) => {
            inflight
                .lock()
                .unwrap()
                .insert(id, Arc::new(AtomicBool::new(false)));
        }
        Err(_) => {
            let resp = Response::new_err(
                id,
                ErrorCode::RequestFailed as i32,
                format!(
                    "loom-lsp is busy ({MAX_PENDING_REQUESTS} requests already pending, M-LSP-4)"
                ),
            );
            connection.sender.send(Message::Response(resp))?;
        }
    }
    Ok(())
}

/// One persistent worker thread (spec M-LSP-4): pulls a [`Job`] off the
/// queue, runs it to completion on *this* thread (so the pool never grows
/// past `MAX_CONCURRENT_REQUESTS`, and a slot only frees when the real
/// work is actually done -- CTO review F3.3), and races a cheap timer
/// thread against it purely to answer the client within
/// [`REQUEST_DEADLINE`] even if the compile itself runs long.
fn spawn_worker(
    sender: crossbeam_channel::Sender<Message>,
    inflight: Inflight,
    job_rx: crossbeam_channel::Receiver<Job>,
) {
    std::thread::spawn(move || {
        for job in job_rx {
            let id = job.req.id.clone();
            let answered = match inflight.lock().unwrap().get(&id).cloned() {
                Some(a) => a,
                None => Arc::new(AtomicBool::new(false)), // cancelled before dequeue is handled below anyway
            };

            // Cheap (sleep-only) deadline timer: never runs any compiler
            // code, so it can't itself become a resource problem.
            {
                let sender = sender.clone();
                let answered = answered.clone();
                let id = id.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(REQUEST_DEADLINE);
                    if !answered.swap(true, Ordering::SeqCst) {
                        let resp = Response::new_err(
                            id,
                            ErrorCode::RequestFailed as i32,
                            format!(
                                "exceeded the {REQUEST_DEADLINE:?} analysis deadline (M-LSP-4)"
                            ),
                        );
                        let _ = sender.send(Message::Response(resp));
                    }
                });
            }

            let resp = dispatch_request(&job.ws, job.req);
            if !answered.swap(true, Ordering::SeqCst) {
                let _ = sender.send(Message::Response(resp));
            }
            inflight.lock().unwrap().remove(&id);
        }
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
