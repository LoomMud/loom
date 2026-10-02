// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `textDocument/hover`: walk the checked HIR (or, for an `inherit`/
//! `import` path, the plain AST) to find the innermost node covering the
//! cursor and report its inferred [`Ty`] (spec \u00a75.3's gradual types --
//! this is literally "what did the checker decide", not a re-inference).

use std::rc::Rc;

use loom_compiler::hir::{
    Block, Callee, Expr, ExprKind, Function, InterpPart, Local, Place, Program as HirProgram, Stmt,
    StmtKind,
};
use loom_compiler::interface::ProgramInfo;
use loom_compiler::{efuns, ty::Ty};
use loom_syntax::{Span, ast};

/// One hover result: what to show, and the exact span it is anchored to
/// (so the client can underline just that token, not the whole file).
pub struct HoverResult {
    pub span: Span,
    pub text: String,
}

fn in_span(span: Span, offset: u32) -> bool {
    offset >= span.start && offset <= span.end
}

/// Hover at byte `offset` in a program whose current buffer parses to
/// `ast_prog`. `checked` is `Some` when the program (and its parents) type
/// -- checked clean; hover still works on `inherit`/`import` targets (and
/// the common case of "cursor is in a file with a type error elsewhere")
/// even when it is `None`.
pub fn hover(
    ast_prog: &ast::Program,
    checked: Option<(&HirProgram, &Rc<ProgramInfo>)>,
    offset: u32,
) -> Option<HoverResult> {
    for inh in &ast_prog.inherits {
        if in_span(inh.path_span, offset) {
            return Some(HoverResult {
                span: inh.path_span,
                text: format!("inherit `{}`", inh.path),
            });
        }
    }
    for imp in &ast_prog.imports {
        if in_span(imp.path_span, offset) {
            return Some(HoverResult {
                span: imp.path_span,
                text: format!("import `{}`", imp.path),
            });
        }
        if let Some(names) = &imp.names {
            for n in names {
                if in_span(n.span, offset) {
                    return Some(HoverResult {
                        span: n.span,
                        text: format!("imported from `{}`", imp.path),
                    });
                }
            }
        }
    }

    let (hir_prog, info) = checked?;

    for v in &hir_prog.vars {
        if in_span(v.span, offset) {
            if let Some(init) = &v.init
                && let Some(r) = hover_expr(init, &[], info, offset)
            {
                return Some(r);
            }
            let kw = if v.persistent {
                "persistent var"
            } else {
                "var"
            };
            return Some(HoverResult {
                span: v.span,
                text: format!("{kw} `{}`: {}", v.name, v.ty),
            });
        }
    }
    for c in &hir_prog.consts {
        if in_span(c.span, offset) {
            if let Some(r) = hover_expr(&c.value, &[], info, offset) {
                return Some(r);
            }
            return Some(HoverResult {
                span: c.span,
                text: format!("const `{}`: {}", c.name, c.ty),
            });
        }
    }
    for f in &hir_prog.fns {
        if in_span(f.span, offset) {
            if let Some(r) = hover_block(&f.body, &f.locals, info, offset) {
                return Some(r);
            }
            for l in &f.locals {
                if in_span(l.span, offset) {
                    return Some(HoverResult {
                        span: l.span,
                        text: local_text(l),
                    });
                }
            }
            return Some(HoverResult {
                span: f.span,
                text: fn_sig_text(f),
            });
        }
    }
    None
}

fn local_text(l: &Local) -> String {
    let kw = if l.mutable { "let mut" } else { "let" };
    format!("{kw} `{}`: {}", l.name, l.ty)
}

fn fn_sig_text(f: &Function) -> String {
    let params = f
        .params
        .iter()
        .map(|p| {
            let l = &f.locals[p.local as usize];
            format!("{}: {}", l.name, l.ty)
        })
        .collect::<Vec<_>>()
        .join(", ");
    let vis = match f.vis {
        loom_compiler::hir::Visibility::Public => "pub ",
        loom_compiler::hir::Visibility::Internal => "",
        loom_compiler::hir::Visibility::Private => "private ",
    };
    if matches!(f.ret, Ty::Void) {
        format!("{vis}fn `{}`({params})", f.name)
    } else {
        format!("{vis}fn `{}`({params}) -> {}", f.name, f.ret)
    }
}

fn hover_block(
    b: &Block,
    locals: &[Local],
    info: &Rc<ProgramInfo>,
    offset: u32,
) -> Option<HoverResult> {
    if !in_span(b.span, offset) {
        return None;
    }
    for s in &b.stmts {
        if let Some(r) = hover_stmt(s, locals, info, offset) {
            return Some(r);
        }
    }
    None
}

fn hover_stmt(
    s: &Stmt,
    locals: &[Local],
    info: &Rc<ProgramInfo>,
    offset: u32,
) -> Option<HoverResult> {
    if !in_span(s.span, offset) {
        return None;
    }
    match &s.kind {
        StmtKind::Let { local, init } => {
            if let Some(e) = init
                && let Some(r) = hover_expr(e, locals, info, offset)
            {
                return Some(r);
            }
            let l = &locals[*local as usize];
            if in_span(l.span, offset) {
                return Some(HoverResult {
                    span: l.span,
                    text: local_text(l),
                });
            }
            None
        }
        StmtKind::Assign { place, value, .. } => hover_place(place, locals, info, offset)
            .or_else(|| hover_expr(value, locals, info, offset)),
        StmtKind::If { cond, then, els } => hover_expr(cond, locals, info, offset)
            .or_else(|| hover_block(then, locals, info, offset))
            .or_else(|| {
                els.as_ref()
                    .and_then(|e| hover_block(e, locals, info, offset))
            }),
        StmtKind::While { cond, body } => hover_expr(cond, locals, info, offset)
            .or_else(|| hover_block(body, locals, info, offset)),
        StmtKind::For { iter, body, .. } => hover_expr(iter, locals, info, offset)
            .or_else(|| hover_block(body, locals, info, offset)),
        StmtKind::Return(e) => e.as_ref().and_then(|e| hover_expr(e, locals, info, offset)),
        StmtKind::Try { body, handler, .. } => hover_block(body, locals, info, offset)
            .or_else(|| hover_block(handler, locals, info, offset)),
        StmtKind::Throw(e) => hover_expr(e, locals, info, offset),
        StmtKind::Expr(e) => hover_expr(e, locals, info, offset),
    }
}

fn hover_place(
    place: &Place,
    locals: &[Local],
    info: &Rc<ProgramInfo>,
    offset: u32,
) -> Option<HoverResult> {
    match place {
        Place::Local(id) => {
            let l = &locals[*id as usize];
            in_span(l.span, offset).then(|| HoverResult {
                span: l.span,
                text: local_text(l),
            })
        }
        Place::Global(_, _) => {
            // No per-use span on a `Place::Global` write target distinct
            // from the owning statement; the statement itself already
            // covers hover for the assignment as a whole.
            None
        }
        Place::Index { base, index, .. } => hover_place(base, locals, info, offset)
            .or_else(|| hover_expr(index, locals, info, offset)),
    }
}

fn hover_expr(
    e: &Expr,
    locals: &[Local],
    info: &Rc<ProgramInfo>,
    offset: u32,
) -> Option<HoverResult> {
    if !in_span(e.span, offset) {
        return None;
    }
    // Recurse into children first: the innermost containing span wins.
    let child =
        match &e.kind {
            ExprKind::Interp(parts) => parts.iter().find_map(|p| match p {
                InterpPart::Lit(_) => None,
                InterpPart::Expr(e) => hover_expr(e, locals, info, offset),
            }),
            ExprKind::Array(xs) => xs.iter().find_map(|x| hover_expr(x, locals, info, offset)),
            ExprKind::Map(kvs) => kvs.iter().find_map(|(k, v)| {
                hover_expr(k, locals, info, offset).or_else(|| hover_expr(v, locals, info, offset))
            }),
            ExprKind::Closure(f, _) => hover_block(&f.body, &f.locals, info, offset),
            ExprKind::Index { base, index, .. } => hover_expr(base, locals, info, offset)
                .or_else(|| hover_expr(index, locals, info, offset)),
            ExprKind::Unary { expr, .. } => hover_expr(expr, locals, info, offset),
            ExprKind::Binary { lhs, rhs, .. } => hover_expr(lhs, locals, info, offset)
                .or_else(|| hover_expr(rhs, locals, info, offset)),
            ExprKind::And(a, b) | ExprKind::Or(a, b) | ExprKind::Coalesce(a, b) => {
                hover_expr(a, locals, info, offset).or_else(|| hover_expr(b, locals, info, offset))
            }
            ExprKind::Call { args, .. } => args
                .iter()
                .find_map(|a| hover_expr(a, locals, info, offset)),
            ExprKind::CallValue { callee, args } => hover_expr(callee, locals, info, offset)
                .or_else(|| {
                    args.iter()
                        .find_map(|a| hover_expr(a, locals, info, offset))
                }),
            ExprKind::CallEfun { args, .. } => args
                .iter()
                .find_map(|a| hover_expr(a, locals, info, offset)),
            ExprKind::CallOther { recv, args, .. } => hover_expr(recv, locals, info, offset)
                .or_else(|| {
                    args.iter()
                        .find_map(|a| hover_expr(a, locals, info, offset))
                }),
            ExprKind::Cast(inner) => hover_expr(inner, locals, info, offset),
            _ => None,
        };
    if child.is_some() {
        return child;
    }
    Some(HoverResult {
        span: e.span,
        text: expr_text(e, locals, info),
    })
}

fn expr_text(e: &Expr, locals: &[Local], info: &Rc<ProgramInfo>) -> String {
    match &e.kind {
        ExprKind::Local(id) => {
            let l = &locals[*id as usize];
            local_text(l)
        }
        ExprKind::Global(g) => format!("var `{}` (from {}): {}", g.name, g.owner, e.ty),
        ExprKind::SelfObj => format!("self: {}", e.ty),
        ExprKind::FnRef(callee) => {
            fn_ref_text(callee, info).unwrap_or_else(|| format!(": {}", e.ty))
        }
        ExprKind::Call { callee, .. } => {
            fn_ref_text(callee, info).unwrap_or_else(|| format!("call -> {}", e.ty))
        }
        ExprKind::CallEfun {
            name, privilege, ..
        } => match efuns::lookup(name) {
            Some(sig) => format!("efun `{name}` -> {} ({:?})", ret_text(&sig.ret), privilege),
            None => format!("efun `{name}` -> {}", e.ty),
        },
        ExprKind::CallOther { name, safe, .. } => {
            let op = if *safe { "?." } else { "." };
            format!("call_other `{op}{name}(...)` -> {}", e.ty)
        }
        _ => format!(": {}", e.ty),
    }
}

fn ret_text(ret: &efuns::Ret) -> String {
    match ret {
        efuns::Ret::Ty(t) => t.to_string(),
        efuns::Ret::KeysOf => "[K]".to_string(),
    }
}

fn fn_ref_text(callee: &Callee, info: &Rc<ProgramInfo>) -> Option<String> {
    let name = match callee {
        Callee::Virtual { name } => name,
        Callee::Static { name, .. } => name,
    };
    let f = info.fns.get(name)?;
    let params = f
        .params
        .iter()
        .map(|p| p.ty.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "fn `{}`({params}) -> {} (declared in {})",
        f.name, f.ret, f.owner
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_compiler::check_program;

    fn check(src: &str) -> (ast::Program, Option<loom_compiler::Checked>) {
        let (ast, diags) = loom_syntax::parse(src);
        assert!(diags.is_empty(), "{diags:?}");
        let r = check_program("/t", src, &ast, vec![], vec![]);
        (ast, r.ok())
    }

    #[test]
    fn hovers_a_local_use_with_its_type() {
        let src = "fn f() {\n  let x: int = 1\n  let y = x + 1\n}\n";
        let (ast, checked) = check(src);
        let checked = checked.unwrap();
        let offset = src.rfind("x + 1").unwrap() as u32; // the `x` in `x + 1`
        let r = hover(&ast, Some((&checked.hir, &checked.info)), offset).unwrap();
        assert!(r.text.contains("int"), "{}", r.text);
    }

    #[test]
    fn hovers_an_inherit_path() {
        let src = "inherit /std/object\nfn f() {}\n";
        let (ast, _diags) = loom_syntax::parse(src);
        let offset = src.find("/std/object").unwrap() as u32 + 1;
        let r = hover(&ast, None, offset).unwrap();
        assert_eq!(r.text, "inherit `/std/object`");
    }

    #[test]
    fn hovers_a_function_signature_from_the_header() {
        let src = "fn add(a: int, b: int) -> int {\n  return a + b\n}\n";
        let (ast, checked) = check(src);
        let checked = checked.unwrap();
        let offset = src.find("add").unwrap() as u32;
        let r = hover(&ast, Some((&checked.hir, &checked.info)), offset).unwrap();
        assert!(r.text.contains("a: int, b: int"), "{}", r.text);
        assert!(r.text.contains("-> int"), "{}", r.text);
    }
}
