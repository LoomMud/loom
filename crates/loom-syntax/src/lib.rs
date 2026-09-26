// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Weft lexer, parser, AST and diagnostics (§5, §10). Owner: Gimli.
//!
//! Phase 0 subset: see `docs/weft-phase0.md`. The entry point is [`parse`],
//! which never panics and always returns a (possibly partial) AST plus
//! diagnostics with spans; render them with [`Diagnostic::render`].

pub mod ast;
pub mod diag;
pub mod lexer;
pub mod parser;
pub mod pretty;

pub use diag::{Diagnostic, Span, line_col};
pub use parser::parse;
