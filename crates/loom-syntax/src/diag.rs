// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Source spans and builder-facing diagnostics.
//!
//! Every diagnostic carries a stable `W####` [code](crate::codes) (OBI-49):
//! the format is `W` plus a 4-digit number, assigned once and never reused
//! or renumbered. Severity is a separate field, not part of the code, so
//! the same code can never appear at two severities.

use std::fmt::Write as _;

/// A half-open byte range `[start, end)` into one source file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Span {
        Span {
            start: start as u32,
            end: end as u32,
        }
    }

    /// The smallest span covering both `self` and `other`.
    pub fn to(self, other: Span) -> Span {
        Span {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
}

/// How seriously a [`Diagnostic`] should be taken. Independent of the code:
/// the same `W####` code is always emitted at the same severity today, but
/// the two are stored separately so that is a policy choice, not a format
/// constraint (spec discussion, OBI-49).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
        }
    }
}

/// A problem found in Weft source: where, what, and (when we know) how to fix it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    /// Stable machine-readable code, e.g. `"W0201"`. See [`crate::codes`].
    pub code: &'static str,
    pub span: Span,
    pub message: String,
    pub hint: Option<String>,
}

impl Diagnostic {
    pub fn error(code: &'static str, span: Span, message: impl Into<String>) -> Diagnostic {
        Diagnostic {
            severity: Severity::Error,
            code,
            span,
            message: message.into(),
            hint: None,
        }
    }

    pub fn warning(code: &'static str, span: Span, message: impl Into<String>) -> Diagnostic {
        Diagnostic {
            severity: Severity::Warning,
            code,
            span,
            message: message.into(),
            hint: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Diagnostic {
        self.hint = Some(hint.into());
        self
    }

    /// 1-based `(line, column)` of the span start; columns count characters.
    pub fn line_col(&self, src: &str) -> (usize, usize) {
        line_col(src, self.span.start as usize)
    }

    /// Render as `path:line:col: error[W0001]: message`, the source line, a
    /// caret underline and the hint, rustc-style.
    pub fn render(&self, path: &str, src: &str) -> String {
        let (line, col) = self.line_col(src);
        let mut out = format!(
            "{path}:{line}:{col}: {}[{}]: {}\n",
            self.severity.label(),
            self.code,
            self.message
        );
        let start = (self.span.start as usize).min(src.len());
        let line_start = src[..start].rfind('\n').map_or(0, |i| i + 1);
        let line_end = src[start..].find('\n').map_or(src.len(), |i| start + i);
        let text = &src[line_start..line_end];
        let gutter = line.to_string();
        let pad = " ".repeat(gutter.len());
        let _ = writeln!(out, "{pad} |");
        let _ = writeln!(out, "{gutter} | {text}");
        let end = (self.span.end as usize).clamp(start, line_end);
        let width = src[start..end].chars().count().max(1);
        let _ = writeln!(
            out,
            "{pad} | {}{}",
            " ".repeat(col.saturating_sub(1)),
            "^".repeat(width)
        );
        if let Some(h) = &self.hint {
            let _ = writeln!(out, "{pad} = help: {h}");
        }
        out
    }
}

/// 1-based `(line, column)` for a byte offset (clamped, char-boundary safe).
pub fn line_col(src: &str, offset: usize) -> (usize, usize) {
    let mut off = offset.min(src.len());
    while !src.is_char_boundary(off) {
        off -= 1;
    }
    let before = &src[..off];
    let line = before.matches('\n').count() + 1;
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    let col = before[line_start..].chars().count() + 1;
    (line, col)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_line_col_and_caret() {
        let src = "fn a() {\n  let x = @\n}\n";
        let d = Diagnostic::error(
            crate::codes::LEX_UNEXPECTED_CHARACTER_LPC_C_STYLE,
            Span::new(19, 20),
            "unexpected character '@'",
        )
        .with_hint("remove it");
        let r = d.render("/t.wf", src);
        assert!(r.starts_with(&format!(
            "/t.wf:2:11: error[{}]: unexpected character '@'\n",
            crate::codes::LEX_UNEXPECTED_CHARACTER_LPC_C_STYLE
        )));
        assert!(r.contains("2 |   let x = @\n"));
        assert!(r.contains("  |           ^\n"));
        assert!(r.contains("= help: remove it"));
    }
}
