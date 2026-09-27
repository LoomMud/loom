// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Post-parse, pre-typecheck lints (`09xx` codes, spec §5.9): checks that
//! only need syntax, not resolved names or types. `loom check` runs these
//! over every file that parses cleanly, independent of whether it later
//! resolves/type-checks.
//!
//! ## D-P1.4: literal setters in `create()`
//!
//! `create()` runs once, at construction time, and is never re-run by
//! `upgrade()` (spec §7.2/§7.3: state migrates by declaring
//! program/name/type, bodies don't re-execute). A call statement in
//! `create()` of the shape `set_foo(<all-literal args>)` therefore sets a
//! value that silently goes stale on every future hot reload: the fix is to
//! move the literal into an overridable getter (`override fn foo() -> T { … }`)
//! and reserve `create()` for state that really is per-instance and mutable.
//! `loom check` warns about this (`W0900`) but does not fail the build; a
//! `// loom:allow(literal-setter-in-create)` comment on the line above the
//! call suppresses it for cases where re-derivation doesn't apply.

use loom_syntax::ast::{self, Arg, Else, Expr, ExprKind as E, InterpPart, Stmt, StmtKind as S};
use loom_syntax::{Diagnostic, Span, codes, line_col};

const SUPPRESS_MARKER: &str = "loom:allow(literal-setter-in-create)";

/// Run every syntax-level lint over one already-parsed program.
pub fn lint_program(ast: &ast::Program, src: &str) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for item in &ast.items {
        if let ast::Item::Fn(f) = item
            && f.name.name == "create"
        {
            lint_block(&f.body, src, &mut out);
        }
    }
    out
}

fn lint_block(block: &ast::Block, src: &str, out: &mut Vec<Diagnostic>) {
    for stmt in &block.stmts {
        lint_stmt(stmt, src, out);
    }
}

fn lint_stmt(stmt: &Stmt, src: &str, out: &mut Vec<Diagnostic>) {
    match &stmt.kind {
        S::Expr(e) => lint_call_stmt(stmt.span, e, src, out),
        S::If { then, els, .. } => {
            lint_block(then, src, out);
            if let Some(e) = els {
                lint_else(e, src, out);
            }
        }
        S::IfLet { then, els, .. } => {
            lint_block(then, src, out);
            if let Some(e) = els {
                lint_else(e, src, out);
            }
        }
        S::For { body, .. } | S::While { body, .. } => lint_block(body, src, out),
        S::Try { body, handler, .. } => {
            lint_block(body, src, out);
            lint_block(handler, src, out);
        }
        S::Local { .. }
        | S::Assign { .. }
        | S::Break
        | S::Continue
        | S::Return(_)
        | S::Throw(_) => {}
    }
}

fn lint_else(els: &Else, src: &str, out: &mut Vec<Diagnostic>) {
    match els {
        Else::Block(b) => lint_block(b, src, out),
        Else::If(s) => lint_stmt(s, src, out),
    }
}

fn lint_call_stmt(stmt_span: Span, e: &Expr, src: &str, out: &mut Vec<Diagnostic>) {
    let E::Call { name, args } = &e.kind else {
        return;
    };
    if !name.name.starts_with("set_") {
        return;
    }
    if !args.iter().all(is_literal_arg) {
        return;
    }
    if is_suppressed(src, stmt_span) {
        return;
    }
    let call_text = render_call(&name.name, args);
    let field = name.name.strip_prefix("set_").unwrap_or(&name.name);
    let ty = args.first().map_or("any", |a| literal_ty_name(&a.value));
    let sample = args
        .first()
        .map_or_else(|| "…".to_string(), |a| render_lit(&a.value));
    out.push(
        Diagnostic::warning(
            codes::LINT_LITERAL_SETTER_IN_CREATE,
            stmt_span,
            format!("`{call_text}` in `create()` is not re-applied on upgrade (D-P1.4)"),
        )
        .with_hint(format!(
            "move static content into an overridable function, e.g. \
             `override fn {field}() -> {ty} {{ return {sample}; }}`; keep `create()` \
             for per-instance mutable state"
        )),
    );
}

/// Every argument is a literal (recursively for array/map literals) or an
/// interpolated string with no `{expr}` holes. Named and positional
/// arguments are both allowed; a spread argument is never treated as a
/// literal (its contents aren't visible here).
fn is_literal_arg(a: &Arg) -> bool {
    !a.spread && is_literal(&a.value)
}

fn is_literal(e: &Expr) -> bool {
    match &e.kind {
        E::Int(_) | E::Float(_) | E::Str(_) | E::Bool(_) | E::Null => true,
        E::Interp(parts) => parts.iter().all(|p| matches!(p, InterpPart::Lit(_))),
        E::Array(items) => items.iter().all(is_literal),
        E::Map(pairs) => pairs.iter().all(|(k, v)| is_literal(k) && is_literal(v)),
        _ => false,
    }
}

fn literal_ty_name(e: &Expr) -> &'static str {
    match &e.kind {
        E::Int(_) => "int",
        E::Float(_) => "float",
        E::Bool(_) => "bool",
        E::Null => "any?",
        E::Str(_) | E::Interp(_) => "string",
        E::Array(_) => "array",
        E::Map(_) => "map",
        _ => "any",
    }
}

fn render_lit(e: &Expr) -> String {
    match &e.kind {
        E::Int(i) => i.to_string(),
        E::Float(f) => format!("{f}"),
        E::Bool(b) => b.to_string(),
        E::Null => "null".to_string(),
        E::Str(s) => format!("{s:?}"),
        E::Interp(parts) => {
            let mut s = String::new();
            for p in parts {
                if let InterpPart::Lit(l) = p {
                    s.push_str(l);
                }
            }
            format!("{s:?}")
        }
        E::Array(items) => format!(
            "[{}]",
            items.iter().map(render_lit).collect::<Vec<_>>().join(", ")
        ),
        E::Map(pairs) => format!(
            "{{{}}}",
            pairs
                .iter()
                .map(|(k, v)| format!("{}: {}", render_lit(k), render_lit(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        _ => "…".to_string(),
    }
}

fn render_call(name: &str, args: &[Arg]) -> String {
    format!(
        "{name}({})",
        args.iter()
            .map(|a| render_lit(&a.value))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Is there a `// loom:allow(literal-setter-in-create)` comment on the
/// source line immediately above `span`? Comments aren't kept in the AST
/// (the lexer drops them), so this looks at the raw line above.
fn is_suppressed(src: &str, span: Span) -> bool {
    let (line, _) = line_col(src, span.start as usize);
    if line < 2 {
        return false;
    }
    match src.lines().nth(line - 2) {
        Some(prev) => prev.contains(SUPPRESS_MARKER),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_syntax::codes::LINT_LITERAL_SETTER_IN_CREATE;

    fn lint(src: &str) -> Vec<Diagnostic> {
        let (ast, diags) = loom_syntax::parse(src);
        assert!(diags.is_empty(), "unexpected parse errors: {diags:?}");
        lint_program(&ast, src)
    }

    #[test]
    fn warns_on_literal_string_setter_in_create() {
        let d = lint(r#"fn create() { set_short("a lantern"); }"#);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].code, LINT_LITERAL_SETTER_IN_CREATE);
        assert!(d[0].message.contains("set_short"));
        assert!(d[0].message.contains("D-P1.4"));
    }

    #[test]
    fn warns_on_literal_map_setter_in_create() {
        let d = lint(r#"fn create() { set_exits({"n": "/a"}); }"#);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].code, LINT_LITERAL_SETTER_IN_CREATE);
        assert!(d[0].message.contains("set_exits"));
    }

    #[test]
    fn no_warning_for_non_literal_argument() {
        let d = lint(r#"fn create() { set_hp(max_hp()); }"#);
        assert!(d.is_empty());
        let d = lint(r#"fn create() { let n = f(); set_name(n); }"#);
        assert!(d.is_empty());
    }

    #[test]
    fn no_warning_outside_create() {
        let d = lint(r#"fn reset() { set_short("a lantern"); }"#);
        assert!(d.is_empty());
    }

    #[test]
    fn no_warning_for_non_setter_call() {
        let d = lint(r#"fn create() { describe("a lantern"); }"#);
        assert!(d.is_empty());
    }

    #[test]
    fn suppressed_by_allow_comment() {
        let d = lint(
            "fn create() {\n    // loom:allow(literal-setter-in-create)\n    set_short(\"a lantern\");\n}",
        );
        assert!(d.is_empty());
    }

    #[test]
    fn warns_inside_nested_blocks() {
        let d = lint(r#"fn create() { if true { set_short("a lantern"); } }"#);
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn no_warning_for_string_interpolation_with_a_hole() {
        let d = lint(r#"fn create() { let n = "x"; set_short($"a {n}"); }"#);
        assert!(d.is_empty());
    }

    #[test]
    fn warns_for_string_interpolation_without_a_hole() {
        let d = lint(r#"fn create() { set_short($"a lantern"); }"#);
        // No `{expr}` hole here: only literal text, so this still warns.
        assert_eq!(d.len(), 1);
    }
}
