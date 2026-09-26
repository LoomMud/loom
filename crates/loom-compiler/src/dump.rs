// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Stable text dump of the typed HIR, for golden tests and `loom check
//! --dump-hir`. One node per line, indented; every expression shows its type.

use std::fmt::Write as _;

use crate::hir::*;

pub fn program(p: &Program) -> String {
    let mut d = Dump {
        out: String::new(),
        locals: Vec::new(),
    };
    let _ = writeln!(d.out, "program {}", p.path);
    for i in &p.inherits {
        match &i.label {
            Some(l) => {
                let _ = writeln!(d.out, "  inherit {l} = {}", i.path);
            }
            None => {
                let _ = writeln!(d.out, "  inherit {}", i.path);
            }
        }
    }
    let _ = writeln!(d.out, "  linearization {}", p.linearization.join(" "));
    for v in &p.vars {
        let _ = writeln!(
            d.out,
            "  var {} {}: {}{}",
            vis(v.vis),
            v.name,
            v.ty,
            if v.persistent { " persistent" } else { "" }
        );
        if let Some(e) = &v.init {
            d.expr(e, 2);
        }
    }
    for c in &p.consts {
        let _ = writeln!(d.out, "  const {} {}: {}", vis(c.vis), c.name, c.ty);
        d.expr(&c.value, 2);
    }
    for f in &p.fns {
        d.locals = f.locals.iter().map(|l| l.name.to_string()).collect();
        let params: Vec<String> = f
            .params
            .iter()
            .map(|p| {
                let l = &f.locals[p.local as usize];
                format!(
                    "%{} {}: {}{}",
                    p.local,
                    l.name,
                    l.ty,
                    if p.default.is_some() { " = …" } else { "" }
                )
            })
            .collect();
        let _ = writeln!(
            d.out,
            "  fn {}{} {}({}) -> {}",
            vis(f.vis),
            if f.is_override { " override" } else { "" },
            f.name,
            params.join(", "),
            f.ret
        );
        for p in &f.params {
            if let Some(e) = &p.default {
                let _ = writeln!(d.out, "    default %{}", p.local);
                d.expr(e, 3);
            }
        }
        for (i, l) in f.locals.iter().enumerate().skip(f.params.len()) {
            let _ = writeln!(
                d.out,
                "    local %{i} {}{}: {}",
                if l.mutable { "var " } else { "" },
                l.name,
                l.ty
            );
        }
        d.block(&f.body, 2);
    }
    d.out
}

fn vis(v: Visibility) -> &'static str {
    match v {
        Visibility::Public => "pub",
        Visibility::Internal => "internal",
        Visibility::Private => "private",
    }
}

struct Dump {
    out: String,
    locals: Vec<String>,
}

impl Dump {
    fn line(&mut self, depth: usize, s: &str) {
        let _ = writeln!(self.out, "{}{s}", "  ".repeat(depth));
    }

    fn local(&self, id: LocalId) -> String {
        format!(
            "%{id}:{}",
            self.locals.get(id as usize).map_or("?", |s| s.as_str())
        )
    }

    fn block(&mut self, b: &Block, depth: usize) {
        for s in &b.stmts {
            self.stmt(s, depth);
        }
    }

    fn stmt(&mut self, s: &Stmt, depth: usize) {
        match &s.kind {
            StmtKind::Let { local, init } => {
                let l = self.local(*local);
                self.line(depth, &format!("let {l}"));
                if let Some(e) = init {
                    self.expr(e, depth + 1);
                }
            }
            StmtKind::Assign {
                place,
                op,
                kind,
                value,
            } => {
                let op = match op {
                    AssignOp::Set => "=".to_string(),
                    AssignOp::Add => format!("+= {kind:?}"),
                    AssignOp::Sub => format!("-= {kind:?}"),
                    AssignOp::Mul => format!("*= {kind:?}"),
                    AssignOp::Div => format!("/= {kind:?}"),
                    AssignOp::Rem => format!("%= {kind:?}"),
                };
                match place {
                    Place::Local(id) => {
                        let l = self.local(*id);
                        self.line(depth, &format!("assign {l} {op}"));
                    }
                    Place::Global(g) => {
                        self.line(
                            depth,
                            &format!("assign global {}::{} {op}", g.owner, g.name),
                        );
                    }
                    Place::Index { base, index, kind } => {
                        self.line(depth, &format!("assign index {kind:?} {op}"));
                        self.expr(base, depth + 1);
                        self.expr(index, depth + 1);
                    }
                }
                self.expr(value, depth + 1);
            }
            StmtKind::If { cond, then, els } => {
                self.line(depth, "if");
                self.expr(cond, depth + 1);
                self.line(depth, "then");
                self.block(then, depth + 1);
                if let Some(b) = els {
                    self.line(depth, "else");
                    self.block(b, depth + 1);
                }
            }
            StmtKind::While { cond, body } => {
                self.line(depth, "while");
                self.expr(cond, depth + 1);
                self.line(depth, "do");
                self.block(body, depth + 1);
            }
            StmtKind::For {
                local,
                iter,
                kind,
                body,
            } => {
                let l = self.local(*local);
                self.line(depth, &format!("for {l} in {kind:?}"));
                self.expr(iter, depth + 1);
                self.line(depth, "do");
                self.block(body, depth + 1);
            }
            StmtKind::Return(e) => {
                self.line(depth, "return");
                if let Some(e) = e {
                    self.expr(e, depth + 1);
                }
            }
            StmtKind::Expr(e) => {
                self.line(depth, "expr");
                self.expr(e, depth + 1);
            }
        }
    }

    fn callee(c: &Callee) -> String {
        match c {
            Callee::Virtual { name } => format!("virtual {name}"),
            Callee::Static { program, name } => format!("static {program}::{name}"),
        }
    }

    fn expr(&mut self, e: &Expr, depth: usize) {
        let ty = &e.ty;
        match &e.kind {
            ExprKind::Int(n) => self.line(depth, &format!("{n} : {ty}")),
            ExprKind::Float(x) => self.line(depth, &format!("{x} : {ty}")),
            ExprKind::Str(s) => self.line(depth, &format!("{s:?} : {ty}")),
            ExprKind::Bool(b) => self.line(depth, &format!("{b} : {ty}")),
            ExprKind::Null => self.line(depth, &format!("null : {ty}")),
            ExprKind::Interp(parts) => {
                self.line(depth, &format!("interp : {ty}"));
                for p in parts {
                    match p {
                        InterpPart::Lit(s) => self.line(depth + 1, &format!("{s:?}")),
                        InterpPart::Expr(e) => self.expr(e, depth + 1),
                    }
                }
            }
            ExprKind::Array(es) => {
                self.line(depth, &format!("array : {ty}"));
                for e in es {
                    self.expr(e, depth + 1);
                }
            }
            ExprKind::Map(kvs) => {
                self.line(depth, &format!("map : {ty}"));
                for (k, v) in kvs {
                    self.expr(k, depth + 1);
                    self.expr(v, depth + 2);
                }
            }
            ExprKind::Local(id) => {
                let l = self.local(*id);
                self.line(depth, &format!("{l} : {ty}"));
            }
            ExprKind::Global(g) => {
                self.line(depth, &format!("global {}::{} : {ty}", g.owner, g.name))
            }
            ExprKind::SelfObj => self.line(depth, &format!("self : {ty}")),
            ExprKind::FnRef(c) => self.line(depth, &format!("fnref {} : {ty}", Self::callee(c))),
            ExprKind::Index { base, index, kind } => {
                self.line(depth, &format!("index {kind:?} : {ty}"));
                self.expr(base, depth + 1);
                self.expr(index, depth + 1);
            }
            ExprKind::Unary { op, kind, expr } => {
                self.line(depth, &format!("{op:?} {kind:?} : {ty}"));
                self.expr(expr, depth + 1);
            }
            ExprKind::Binary { op, kind, lhs, rhs } => {
                self.line(depth, &format!("{op:?} {kind:?} : {ty}"));
                self.expr(lhs, depth + 1);
                self.expr(rhs, depth + 1);
            }
            ExprKind::And(a, b) | ExprKind::Or(a, b) | ExprKind::Coalesce(a, b) => {
                let n = match &e.kind {
                    ExprKind::And(..) => "and",
                    ExprKind::Or(..) => "or",
                    _ => "coalesce",
                };
                self.line(depth, &format!("{n} : {ty}"));
                self.expr(a, depth + 1);
                self.expr(b, depth + 1);
            }
            ExprKind::Call { callee, args } => {
                self.line(depth, &format!("call {} : {ty}", Self::callee(callee)));
                for a in args {
                    self.expr(a, depth + 1);
                }
            }
            ExprKind::CallValue { callee, args } => {
                self.line(depth, &format!("callvalue : {ty}"));
                self.expr(callee, depth + 1);
                for a in args {
                    self.expr(a, depth + 1);
                }
            }
            ExprKind::CallEfun {
                name,
                privilege,
                args,
            } => {
                self.line(depth, &format!("efun {name} {privilege:?} : {ty}"));
                for a in args {
                    self.expr(a, depth + 1);
                }
            }
            ExprKind::CallOther {
                recv,
                name,
                args,
                safe,
            } => {
                let dot = if *safe { "?." } else { "." };
                self.line(depth, &format!("callother {dot}{name} : {ty}"));
                self.expr(recv, depth + 1);
                for a in args {
                    self.expr(a, depth + 1);
                }
            }
            ExprKind::Cast(inner) => {
                self.line(depth, &format!("cast : {ty}"));
                self.expr(inner, depth + 1);
            }
            ExprKind::Closure(c) => {
                self.line(depth, &format!("closure({} params) : {ty}", c.params.len()));
                let saved = std::mem::replace(
                    &mut self.locals,
                    c.locals.iter().map(|l| l.name.to_string()).collect(),
                );
                for s in &c.body.stmts {
                    self.stmt(s, depth + 1);
                }
                self.locals = saved;
            }
        }
    }
}
