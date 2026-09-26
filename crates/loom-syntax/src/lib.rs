// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Weft lexer, parser, AST and diagnostics (§5, §10). Owner: Gimli.
//!
//! Full v1 grammar (spec v2 §5.3): see `docs/weft-grammar.md`. The entry point is [`parse`],
//! which never panics and always returns a (possibly partial) AST plus
//! diagnostics with spans; render them with [`Diagnostic::render`].

pub mod ast;
pub mod codes;
pub mod diag;
pub mod lexer;
pub mod parser;
pub mod pretty;

pub use diag::{Diagnostic, Severity, Span, line_col};
pub use parser::parse;
