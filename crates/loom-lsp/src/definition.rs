// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `textDocument/definition`: `inherit`/`import` paths jump to the start
//! of the target file (the acceptance-criterion case); a call or variable
//! reference jumps to its declaration in the owning program, when the
//! owner is known and compiles cleanly (best-effort: virtual dispatch
//! picks the statically-dominant owner the checker itself picked, which is
//! also what a human reading the file would expect `go to definition` to
//! mean, even though the *runtime* call could still be overridden further
//! down an inherit chain after a hot reload).

use std::rc::Rc;

use loom_compiler::hir::{Block, Callee, Expr, ExprKind, Place, Program as HirProgram, Stmt, StmtKind};
use loom_compiler::interface::ProgramInfo;
use loom_syntax::{Span, ast};

pub struct DefinitionTarget {
    /// Program path the definition is in (may differ from the file being
    /// hovered/queried).
    pub path: String,
    /// `None` means "top of file" (we don't have the target's own source
    /// loaded, e.g. it has a compile error of its own).
    pub span: Option<Span>,
    /// The function/variable/const name to look up in `path`'s own HIR to
    /// fill in `span` (see [`resolve_span_in_owner`]); `None` for an
    /// `inherit`/`import` target, which always means "top of file".
    pub name: Option<String>,
}

fn in_span(span: Span, offset: u32) -> bool {
    offset >= span.start && offset <= span.end
}

/// `inherit`/`import` path under the cursor, resolved to its target file
/// regardless of whether this program (or the target) currently compiles
/// clean -- this only needs the AST.
pub fn definition_for_path(ast_prog: &ast::Program, offset: u32) -> Option<DefinitionTarget> {
    for inh in &ast_prog.inherits {
        if in_span(inh.path_span, offset) {
            return Some(DefinitionTarget {
                path: loom_compiler::mudlib::normalize_path(&inh.path).ok()?,
                span: None,
                name: None,
            });
        }
    }
    for imp in &ast_prog.imports {
        if in_span(imp.path_span, offset) {
            return Some(DefinitionTarget {
                path: loom_compiler::mudlib::normalize_path(&imp.path).ok()?,
                span: None,
                name: None,
            });
        }
    }
    None
}

/// Identifier under the cursor in a checked HIR: a call resolves to its
/// owning program + the matching [`loom_compiler::hir::Function`]'s span;
/// a program-variable reference resolves to its `var`/`const` declaration.
pub fn definition_for_identifier(
    hir_prog: &HirProgram,
    info: &Rc<ProgramInfo>,
    offset: u32,
) -> Option<DefinitionTarget> {
    for f in &hir_prog.fns {
        if in_span(f.span, offset) {
            return find_in_block(&f.body, info, offset);
        }
    }
    for v in &hir_prog.vars {
        if in_span(v.span, offset)
            && let Some(init) = &v.init
        {
            return find_in_expr(init, info, offset);
        }
    }
    for c in &hir_prog.consts {
        if in_span(c.span, offset) {
            return find_in_expr(&c.value, info, offset);
        }
    }
    None
}

fn find_in_block(b: &Block, info: &Rc<ProgramInfo>, offset: u32) -> Option<DefinitionTarget> {
    if !in_span(b.span, offset) {
        return None;
    }
    b.stmts.iter().find_map(|s| find_in_stmt(s, info, offset))
}

fn find_in_stmt(s: &Stmt, info: &Rc<ProgramInfo>, offset: u32) -> Option<DefinitionTarget> {
    if !in_span(s.span, offset) {
        return None;
    }
    match &s.kind {
        StmtKind::Let { init, .. } => init.as_ref().and_then(|e| find_in_expr(e, info, offset)),
        StmtKind::Assign { place, value, .. } => {
            find_in_place(place, info, offset).or_else(|| find_in_expr(value, info, offset))
        }
        StmtKind::If { cond, then, els } => find_in_expr(cond, info, offset)
            .or_else(|| find_in_block(then, info, offset))
            .or_else(|| els.as_ref().and_then(|b| find_in_block(b, info, offset))),
        StmtKind::While { cond, body } => {
            find_in_expr(cond, info, offset).or_else(|| find_in_block(body, info, offset))
        }
        StmtKind::For { iter, body, .. } => {
            find_in_expr(iter, info, offset).or_else(|| find_in_block(body, info, offset))
        }
        StmtKind::Return(e) => e.as_ref().and_then(|e| find_in_expr(e, info, offset)),
        StmtKind::Try { body, handler, .. } => {
            find_in_block(body, info, offset).or_else(|| find_in_block(handler, info, offset))
        }
        StmtKind::Throw(e) => find_in_expr(e, info, offset),
        StmtKind::Expr(e) => find_in_expr(e, info, offset),
    }
}

fn find_in_place(place: &Place, info: &Rc<ProgramInfo>, offset: u32) -> Option<DefinitionTarget> {
    match place {
        Place::Local(_) => None,
        Place::Global(g, _) => info.vars.get(&g.name).map(|v| DefinitionTarget {
            path: v.owner.to_string(),
            span: None,
            name: Some(v.name.to_string()),
        }),
        Place::Index { base, index, .. } => {
            find_in_place(base, info, offset).or_else(|| find_in_expr(index, info, offset))
        }
    }
}

fn find_in_expr(e: &Expr, info: &Rc<ProgramInfo>, offset: u32) -> Option<DefinitionTarget> {
    if !in_span(e.span, offset) {
        return None;
    }
    let child = match &e.kind {
        ExprKind::Interp(parts) => parts.iter().find_map(|p| match p {
            loom_compiler::hir::InterpPart::Lit(_) => None,
            loom_compiler::hir::InterpPart::Expr(e) => find_in_expr(e, info, offset),
        }),
        ExprKind::Array(xs) => xs.iter().find_map(|x| find_in_expr(x, info, offset)),
        ExprKind::Map(kvs) => kvs.iter().find_map(|(k, v)| {
            find_in_expr(k, info, offset).or_else(|| find_in_expr(v, info, offset))
        }),
        ExprKind::Index { base, index, .. } => {
            find_in_expr(base, info, offset).or_else(|| find_in_expr(index, info, offset))
        }
        ExprKind::Unary { expr, .. } => find_in_expr(expr, info, offset),
        ExprKind::Binary { lhs, rhs, .. } => {
            find_in_expr(lhs, info, offset).or_else(|| find_in_expr(rhs, info, offset))
        }
        ExprKind::And(a, b) | ExprKind::Or(a, b) | ExprKind::Coalesce(a, b) => {
            find_in_expr(a, info, offset).or_else(|| find_in_expr(b, info, offset))
        }
        ExprKind::Call { args, .. } => args.iter().find_map(|a| find_in_expr(a, info, offset)),
        ExprKind::CallValue { callee, args } => find_in_expr(callee, info, offset)
            .or_else(|| args.iter().find_map(|a| find_in_expr(a, info, offset))),
        ExprKind::CallEfun { args, .. } => args.iter().find_map(|a| find_in_expr(a, info, offset)),
        ExprKind::CallOther { recv, args, .. } => find_in_expr(recv, info, offset)
            .or_else(|| args.iter().find_map(|a| find_in_expr(a, info, offset))),
        ExprKind::Cast(inner) => find_in_expr(inner, info, offset),
        _ => None,
    };
    if child.is_some() {
        return child;
    }
    match &e.kind {
        ExprKind::Global(g) => info.vars.get(&g.name).map(|v| DefinitionTarget {
            path: v.owner.to_string(),
            span: None,
            name: Some(v.name.to_string()),
        }),
        ExprKind::FnRef(callee) | ExprKind::Call { callee, .. } => callee_target(callee, info),
        _ => None,
    }
}

fn callee_target(callee: &Callee, info: &Rc<ProgramInfo>) -> Option<DefinitionTarget> {
    let name = match callee {
        Callee::Virtual { name } => name,
        Callee::Static { name, .. } => name,
    };
    info.fns.get(name).map(|f| DefinitionTarget {
        path: f.owner.to_string(),
        span: None,
        name: Some(f.name.to_string()),
    })
}

/// Fill in a [`DefinitionTarget`]'s span by name within `hir_prog` (the
/// owning program's own HIR, once compiled): the `Function`/`Var`/`Const`
/// declaration's span, for the function/variable last resolved by
/// [`definition_for_identifier`].
pub fn resolve_span_in_owner(hir_prog: &HirProgram, name: &str) -> Option<Span> {
    if let Some(f) = hir_prog.fns.iter().find(|f| &*f.name == name) {
        return Some(f.span);
    }
    if let Some(v) = hir_prog.vars.iter().find(|v| &*v.name == name) {
        return Some(v.span);
    }
    if let Some(c) = hir_prog.consts.iter().find(|c| &*c.name == name) {
        return Some(c.span);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherit_path_resolves_to_normalised_target() {
        let src = "inherit /std/object\nfn f() {}\n";
        let (ast, _diags) = loom_syntax::parse(src);
        let offset = src.find("/std/object").unwrap() as u32 + 1;
        let t = definition_for_path(&ast, offset).unwrap();
        assert_eq!(t.path, "/std/object");
        assert!(t.span.is_none());
        assert!(t.name.is_none());
    }

    #[test]
    fn import_path_resolves_to_normalised_target() {
        let src = "import /include/damage\nfn f() {}\n";
        let (ast, _diags) = loom_syntax::parse(src);
        let offset = src.find("/include/damage").unwrap() as u32 + 1;
        let t = definition_for_path(&ast, offset).unwrap();
        assert_eq!(t.path, "/include/damage");
    }

    #[test]
    fn call_resolves_to_declaring_program_and_fn_span_in_it() {
        let (parent_ast, _) = loom_syntax::parse("pub fn greet() -> string {\n  return \"hi\"\n}\n");
        let parent = loom_compiler::check_program("/std/object", &parent_ast, vec![], vec![]).unwrap();
        let child_src = "inherit /std/object\nfn f() {\n  greet()\n}\n";
        let (child_ast, _) = loom_syntax::parse(child_src);
        let parents = vec![loom_compiler::interface::ParentInfo {
            label: None,
            info: parent.info.clone(),
            span: Span::default(),
        }];
        let child = loom_compiler::check_program("/t", &child_ast, parents, vec![]).unwrap();
        let offset = child_src.find("greet()").unwrap() as u32;
        let t = definition_for_identifier(&child.hir, &child.info, offset).unwrap();
        assert_eq!(t.path, "/std/object");
        assert_eq!(t.name.as_deref(), Some("greet"));
        let span = resolve_span_in_owner(&parent.hir, "greet").unwrap();
        assert_eq!(span, parent.hir.fns[0].span);
    }
}
