// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `textDocument/publishDiagnostics`: compile `path` (plus its inherit/
//! import closure) against the workspace's current buffers and turn every
//! `W####` [`loom_syntax::Diagnostic`] -- parse errors, resolver/type
//! errors, and `09xx` lints -- into an LSP [`Diagnostic`].
//!
//! Scope note (OBI-168): this recompiles fresh (a new [`Session`] per
//! call) and only reports diagnostics for `path` itself, not for every
//! other open file that transitively inherits/imports it. A full
//! dependent-invalidation graph is out of scope for the M size estimate;
//! `Session::invalidate`'s own doc comment flags exactly this gap for a
//! future incremental pass. Re-running the request on every keystroke
//! (debounced by the client, same as any LSP server) keeps the file the
//! builder is actually editing accurate, which is what the acceptance
//! criterion asks for.

use loom_compiler::mudlib::{Outcome, Session, normalize_path};
use loom_syntax::Diagnostic as RawDiag;
use lsp_types::{
    Diagnostic, DiagnosticSeverity, NumberOrString, Position, PublishDiagnosticsParams,
};

use crate::position::span_to_range;
use crate::workspace::Workspace;

/// `W####` -> `error` or `warning` (never `hint`/`information`: driver
/// diagnostics don't have those severities, spec \u00a75.9).
fn severity(d: &RawDiag) -> DiagnosticSeverity {
    match d.severity {
        loom_syntax::Severity::Error => DiagnosticSeverity::ERROR,
        loom_syntax::Severity::Warning => DiagnosticSeverity::WARNING,
    }
}

fn to_lsp(src: &str, d: &RawDiag) -> Diagnostic {
    Diagnostic {
        range: span_to_range(src, d.span),
        severity: Some(severity(d)),
        code: Some(NumberOrString::String(d.code.to_string())),
        code_description: None,
        source: Some("loom".to_string()),
        message: match &d.hint {
            Some(h) => format!("{}\nhelp: {h}", d.message),
            None => d.message.clone(),
        },
        related_information: None,
        tags: None,
        data: None,
    }
}

/// Diagnostics for `path` (already normalised) given its *current* buffer
/// text in `ws`. Returns `(text used, diagnostics)`; the text is what the
/// caller should hand back in `PublishDiagnosticsParams`-adjacent logging
/// and is needed again nowhere else, but returning it saves a second
/// `ws.text()` lookup/clone at call sites that also want it.
pub fn diagnostics_for(ws: &Workspace, path: &str) -> (String, Vec<Diagnostic>) {
    let src = match ws.text(path) {
        Ok(s) => s,
        Err(_) => return (String::new(), Vec::new()),
    };
    let mut session = Session::new(ws.loader());
    session.compile(path);
    let mut out = Vec::new();
    match session.outcomes().get(path) {
        Some(Outcome::Ok(_)) | None => {}
        Some(Outcome::Failed(_)) => {
            for d in session.raw_diagnostics_for(path) {
                out.push(to_lsp(&src, d));
            }
        }
        Some(Outcome::Missing(_)) => {
            out.push(Diagnostic {
                range: lsp_types::Range {
                    start: Position::new(0, 0),
                    end: Position::new(0, 0),
                },
                severity: Some(DiagnosticSeverity::ERROR),
                code: None,
                code_description: None,
                source: Some("loom".to_string()),
                message: format!("{path}.wf: cannot read file"),
                related_information: None,
                tags: None,
                data: None,
            });
        }
    }
    for d in session.raw_warnings_for(path) {
        out.push(to_lsp(&src, d));
    }
    (src, out)
}

/// Build the whole `textDocument/publishDiagnostics` notification params
/// for `path`.
pub fn publish_params(ws: &Workspace, path: &str) -> PublishDiagnosticsParams {
    let (_, diags) = diagnostics_for(ws, path);
    PublishDiagnosticsParams {
        uri: ws.uri_for_path(path),
        diagnostics: diags,
        version: None,
    }
}

/// `normalize_path`, mapped to an LSP-friendly `Option` (a URI outside the
/// workspace root, or not a `.wf` file, is not this server's problem).
pub fn program_path_or_none(raw: &str) -> Option<String> {
    normalize_path(raw).ok()
}
