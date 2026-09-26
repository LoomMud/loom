// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The Phase 0 gate: `loom-syntax` parses the whole v1 grammar (OBI-23), but
//! the tree-walking evaluator only runs the Phase 0 subset. Every construct
//! outside the subset is reported here as a `not yet supported` diagnostic
//! (with a span and a workaround) before linking, so `loom check` and
//! `compile_object` reject it cleanly instead of reaching the evaluator.
//!
//! Delete this module when the Phase 1 compiler + VM replace the evaluator.

use loom_syntax::ast::*;
use loom_syntax::{Diagnostic, Span};

/// Suffix of every gate message (tests and tooling match on it).
pub const NOT_YET: &str = "not yet supported by the Phase 0 evaluator";
const LATER: &str = "it parses, and runs once the Phase 1 VM lands";

/// All out-of-subset constructs in `prog`, in source order.
pub fn phase0_gate(prog: &Program) -> Vec<Diagnostic> {
    let mut g = Gate { diags: Vec::new() };
    if let Some(sp) = prog.lightweight {
        g.no("W0400", sp, "`lightweight` programs", None);
    }
    for (i, inh) in prog.inherits.iter().enumerate() {
        if let Some(l) = &inh.label {
            g.no(
                "W0401",
                l.span,
                "labelled `inherit`",
                Some("write `inherit /path/to/program` and call it with `super::`"),
            );
        }
        if i > 0 {
            g.no(
                "W0402",
                inh.span,
                "multiple inheritance",
                Some("Phase 0 runs one `inherit` per program"),
            );
        }
    }
    for imp in &prog.imports {
        g.no(
            "W0403",
            imp.span,
            "`import`",
            Some("use `inherit` for code reuse in Phase 0"),
        );
    }
    for item in &prog.items {
        g.item(item);
    }
    g.diags.sort_by_key(|d| d.span.start);
    g.diags
}

struct Gate {
    diags: Vec<Diagnostic>,
}

impl Gate {
    fn no(&mut self, code: &'static str, span: Span, what: &str, hint: Option<&str>) {
        self.diags.push(
            Diagnostic::error(code, span, format!("{what}: {NOT_YET}"))
                .with_hint(hint.unwrap_or(LATER)),
        );
    }

    fn mods(&mut self, m: &Modifiers, at: Span) {
        let sp = m.span.unwrap_or(at);
        if m.is_protected {
            self.no(
                "W0404",
                sp,
                "`protected` visibility",
                Some("use the default (internal) visibility or `private`"),
            );
        }
        if m.is_final {
            self.no("W0405", sp, "`final`", Some("drop it for now"));
        }
        if m.atomic {
            self.no(
                "W0406",
                sp,
                "`atomic` functions",
                Some("runtime errors abort the whole execution in Phase 0"),
            );
        }
    }

    fn item(&mut self, item: &Item) {
        match item {
            Item::Var(v) => {
                self.mods(&v.mods, v.span);
                self.opt_ty(&v.ty);
                self.opt_expr(&v.init);
            }
            Item::Const(c) => {
                self.no("W0407", c.name.span, "`const`", Some("use a `var` for now"));
            }
            Item::Struct(s) => {
                self.no(
                    "W0408",
                    s.name.span,
                    "`struct`",
                    Some("use a map `{string: any}` for now"),
                );
            }
            Item::Enum(e) => {
                self.no(
                    "W0409",
                    e.name.span,
                    "`enum`",
                    Some("use strings or ints for now"),
                );
            }
            Item::Fn(f) => {
                self.mods(&f.mods, f.span);
                self.params(&f.params);
                self.opt_ty(&f.ret);
                self.block(&f.body);
            }
        }
    }

    fn params(&mut self, ps: &[Param]) {
        for p in ps {
            if p.rest {
                self.no(
                    "W0410",
                    p.span,
                    "`...rest` parameters",
                    Some("take an array parameter instead"),
                );
            }
            self.opt_ty(&p.ty);
            self.opt_expr(&p.default);
        }
    }

    fn opt_ty(&mut self, t: &Option<Type>) {
        if let Some(t) = t {
            self.ty(t);
        }
    }

    fn ty(&mut self, t: &Type) {
        match &t.kind {
            TypeKind::Float => self.no("W0411", t.span, "the `float` type", Some("use `int`")),
            TypeKind::Error => self.no("W0412", t.span, "the `error` type", None),
            TypeKind::Fn { .. } => self.no("W0413", t.span, "function types", None),
            TypeKind::Array(e) | TypeKind::Optional(e) => self.ty(e),
            TypeKind::Map(k, v) => {
                self.ty(k);
                self.ty(v);
            }
            // Unknown names are reported by the linker (`unknown type`).
            _ => {}
        }
    }

    fn block(&mut self, b: &Block) {
        for s in &b.stmts {
            self.stmt(s);
        }
    }

    fn els(&mut self, e: &Option<Box<Else>>) {
        match e.as_deref() {
            Some(Else::Block(b)) => self.block(b),
            Some(Else::If(s)) => self.stmt(s),
            None => {}
        }
    }

    fn stmt(&mut self, s: &Stmt) {
        match &s.kind {
            StmtKind::Local { ty, init, .. } => {
                self.opt_ty(ty);
                self.opt_expr(init);
            }
            StmtKind::Assign { target, op, value } => {
                if matches!(op, AssignOp::Mul | AssignOp::Div | AssignOp::Rem) {
                    self.no(
                        "W0414",
                        s.span,
                        "`*=`, `/=` and `%=`",
                        Some("write `x = x * y`"),
                    );
                }
                self.expr(target);
                self.expr(value);
            }
            StmtKind::If { cond, then, els } => {
                self.expr(cond);
                self.block(then);
                self.els(els);
            }
            StmtKind::IfLet {
                ty,
                value,
                then,
                els,
                ..
            } => {
                self.no(
                    "W0415",
                    Span::new(s.span.start as usize, s.span.start as usize + 2),
                    "`if let`",
                    Some("compare with null instead: `if x != null { … }`"),
                );
                self.opt_ty(ty);
                self.expr(value);
                self.block(then);
                self.els(els);
            }
            StmtKind::For { iter, body, .. } => {
                self.expr(iter);
                self.block(body);
            }
            StmtKind::While { cond, body } => {
                self.expr(cond);
                self.block(body);
            }
            StmtKind::Break | StmtKind::Continue => self.no(
                "W0416",
                s.span,
                "`break` and `continue`",
                Some("use a flag in the `while` condition, or `return`"),
            ),
            StmtKind::Return(e) => self.opt_expr(e),
            StmtKind::Try { body, handler, .. } => {
                self.no(
                    "W0417",
                    Span::new(s.span.start as usize, s.span.start as usize + 3),
                    "`try`/`catch`",
                    Some("runtime errors abort the execution in Phase 0"),
                );
                self.block(body);
                self.block(handler);
            }
            StmtKind::Throw(e) => {
                self.no(
                    "W0418",
                    Span::new(s.span.start as usize, s.span.start as usize + 5),
                    "`throw`",
                    Some("runtime errors abort the execution in Phase 0"),
                );
                self.expr(e);
            }
            StmtKind::Expr(e) => self.expr(e),
        }
    }

    fn opt_expr(&mut self, e: &Option<Expr>) {
        if let Some(e) = e {
            self.expr(e);
        }
    }

    fn args(&mut self, args: &[Arg]) {
        for a in args {
            if let Some(n) = &a.name {
                self.no(
                    "W0419",
                    n.span,
                    "named arguments",
                    Some("pass arguments by position"),
                );
            }
            if a.spread {
                self.no("W0420", a.span, "`...` spread arguments", None);
            }
            self.expr(&a.value);
        }
    }

    fn expr(&mut self, e: &Expr) {
        match &e.kind {
            ExprKind::Int(_)
            | ExprKind::Str(_)
            | ExprKind::Bool(_)
            | ExprKind::Null
            | ExprKind::Ident(_)
            | ExprKind::Error => {}
            ExprKind::Float(_) => self.no("W0421", e.span, "float literals", Some("use `int`")),
            ExprKind::Interp(parts) => {
                for p in parts {
                    if let InterpPart::Expr(x) = p {
                        self.expr(x);
                    }
                }
            }
            ExprKind::Array(xs) => xs.iter().for_each(|x| self.expr(x)),
            ExprKind::Map(kvs) => {
                for (k, v) in kvs {
                    self.expr(k);
                    self.expr(v);
                }
            }
            ExprKind::Index { base, index } => {
                self.expr(base);
                self.expr(index);
            }
            ExprKind::Slice { base, lo, hi } => {
                self.no("W0422", e.span, "slices", None);
                self.expr(base);
                if let Some(x) = lo {
                    self.expr(x);
                }
                if let Some(x) = hi {
                    self.expr(x);
                }
            }
            ExprKind::Field { base, name, .. } => {
                self.no(
                    "W0423",
                    name.span,
                    "field access",
                    Some(&format!(
                        "objects have no fields; to call a function write `.{}()`",
                        name.name
                    )),
                );
                self.expr(base);
            }
            ExprKind::Unary { expr, .. } => self.expr(expr),
            ExprKind::Binary { lhs, rhs, .. } => {
                self.expr(lhs);
                self.expr(rhs);
            }
            ExprKind::Cast { expr, ty } => {
                self.no("W0424", e.span, "`as` casts", None);
                self.expr(expr);
                self.ty(ty);
            }
            ExprKind::Call { args, .. } => self.args(args),
            ExprKind::SuperCall { label, args, .. } => {
                if let Some(l) = label {
                    self.no(
                        "W0425",
                        l.span,
                        "labelled calls `label::fn()`",
                        Some("use `super::fn()`"),
                    );
                }
                self.args(args);
            }
            ExprKind::Method { recv, args, .. } => {
                self.expr(recv);
                self.args(args);
            }
            ExprKind::Apply { callee, args } => {
                self.no(
                    "W0426",
                    e.span,
                    "calling a computed value",
                    Some("call a named function instead"),
                );
                self.expr(callee);
                self.args(args);
            }
            ExprKind::Closure(_) => {
                self.no(
                    "W0427",
                    Span::new(e.span.start as usize, e.span.start as usize + 2),
                    "closures",
                    Some("call a named function instead"),
                );
            }
            ExprKind::Match { scrutinee, .. } => {
                self.no(
                    "W0428",
                    Span::new(e.span.start as usize, e.span.start as usize + 5),
                    "`match`",
                    Some("use `if` / `else if` for now"),
                );
                self.expr(scrutinee);
            }
            ExprKind::StructLit { name, .. } => self.no(
                "W0429",
                name.span,
                "struct literals",
                Some("use a map `{string: any}` for now"),
            ),
            ExprKind::Variant { .. } => self.no(
                "W0430",
                e.span,
                "enum variants",
                Some("use strings or ints for now"),
            ),
        }
    }
}
