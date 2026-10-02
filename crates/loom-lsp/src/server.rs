// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The transport-agnostic protocol core: one [`run`] loop over any
//! [`Connection`] (stdio, in-memory-bridged WebSocket, or a test harness).

use std::path::PathBuf;

use loom_compiler::Checked;
use loom_compiler::mudlib::{Outcome, Session};
use loom_syntax::ast;
use lsp_server::{Connection, Message, Notification, Request, Response};
use lsp_types::{
    CompletionItem, CompletionOptions, CompletionParams, DidChangeTextDocumentParams,
    DidCloseTextDocumentParams, DidOpenTextDocumentParams, GotoDefinitionParams,
    GotoDefinitionResponse, Hover, HoverContents, HoverParams, HoverProviderCapability,
    InitializeParams, Location, MarkedString, OneOf, Position, Range, ServerCapabilities,
    TextDocumentSyncCapability, TextDocumentSyncKind, Uri,
};

use crate::position::{position_to_byte_offset, span_to_range};
use crate::workspace::Workspace;
use crate::{completion, definition, hover};

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

/// Run the server against `connection` until the client shuts it down.
/// `root` is the warp/mudlib checkout this server serves (one server
/// instance per root; a multi-root client needs one server per folder,
/// same as most language servers without a project-system layer).
pub fn run(connection: Connection, root: PathBuf) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let (id, params) = connection.initialize_start()?;
    let init_params: InitializeParams = serde_json::from_value(params)?;
    // Prefer a client-given workspace folder, falling back to the
    // deprecated single `rootUri` for older clients, then the CLI/WS-query
    // root (e.g. a test harness with no client root at all).
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
    let root = client_root.unwrap_or(root);
    let init_result = serde_json::json!({
        "capabilities": server_capabilities(),
        "serverInfo": { "name": "loom-lsp", "version": env!("CARGO_PKG_VERSION") },
    });
    connection.initialize_finish(id, init_result)?;

    let mut ws = Workspace::new(root);
    for msg in &connection.receiver {
        match msg {
            Message::Request(req) => {
                if connection.handle_shutdown(&req)? {
                    break;
                }
                let resp = dispatch_request(&mut ws, req);
                connection.sender.send(Message::Response(resp))?;
            }
            Message::Notification(not) => {
                handle_notification(&connection, &mut ws, not)?;
            }
            Message::Response(_) => {}
        }
    }
    Ok(())
}

fn dispatch_request(ws: &mut Workspace, req: Request) -> Response {
    match req.method.as_str() {
        "textDocument/hover" => reply::<HoverParams, _>(req, |p| handle_hover(ws, p)),
        "textDocument/definition" => reply::<GotoDefinitionParams, _>(req, |p| handle_definition(ws, p)),
        "textDocument/completion" => reply::<CompletionParams, _>(req, |p| handle_completion(ws, p)),
        _ => Response::new_err(
            req.id,
            lsp_server::ErrorCode::MethodNotFound as i32,
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
        Err(e) => Response::new_err(id, lsp_server::ErrorCode::InvalidParams as i32, e.to_string()),
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
                ws.open(path.clone(), p.text_document.text);
                publish(connection, ws, &path)?;
            }
        }
        "textDocument/didChange" => {
            let p: DidChangeTextDocumentParams = serde_json::from_value(not.params)?;
            if let Some(path) = ws.program_path(&p.text_document.uri)
                && let Some(last) = p.content_changes.into_iter().next_back()
            {
                // Full sync (`TextDocumentSyncKind::FULL`): the last (and
                // only) change event is the whole new document text.
                ws.change(&path, last.text);
                publish(connection, ws, &path)?;
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

fn handle_definition(ws: &Workspace, p: GotoDefinitionParams) -> Option<GotoDefinitionResponse> {
    let uri = p.text_document_position_params.text_document.uri;
    let path = ws.program_path(&uri)?;
    let (ast_prog, src, checked) = compile_for(ws, &path)?;
    let offset = position_to_byte_offset(&src, p.text_document_position_params.position) as u32;

    if let Some(t) = definition::definition_for_path(&ast_prog, offset) {
        return Some(single(ws.uri_for_path(&t.path), zero_range()));
    }
    let checked = checked?;
    let t = definition::definition_for_identifier(&checked.hir, &checked.info, offset)?;
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

