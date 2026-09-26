// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Compact S-expression rendering of the AST, used by golden tests and
//! `loom check --ast`. Spans are omitted; the format is stable-ish but not a
//! public contract.

use crate::ast::*;
use std::fmt::Write as _;

pub fn program(p: &Program) -> String {
    let mut out = String::new();
    if let Some(i) = &p.inherit {
        let _ = writeln!(out, "(inherit {})", i.path);
    }
    for item in &p.items {
        match item {
            Item::Var(v) => {
                let _ = writeln!(
                    out,
                    "(var{} {}{}{})",
                    mods(&v.mods),
                    v.name.name,
                    v.ty.as_ref()
                        .map(|t| format!(" : {}", ty(t)))
                        .unwrap_or_default(),
                    v.init
                        .as_ref()
                        .map(|e| format!(" = {}", expr(e)))
                        .unwrap_or_default()
                );
            }
            Item::Fn(f) => {
                let params: Vec<String> = f
                    .params
                    .iter()
                    .map(|p| {
                        format!(
                            "{}{}{}",
                            p.name.name,
                            p.ty.as_ref()
                                .map(|t| format!(": {}", ty(t)))
                                .unwrap_or_default(),
                            p.default
                                .as_ref()
                                .map(|e| format!(" = {}", expr(e)))
                                .unwrap_or_default()
                        )
                    })
                    .collect();
                let _ = writeln!(
                    out,
                    "(fn{} {} ({}){}",
                    mods(&f.mods),
                    f.name.name,
                    params.join(", "),
                    f.ret
                        .as_ref()
                        .map(|t| format!(" -> {}", ty(t)))
                        .unwrap_or_default()
                );
                block(&mut out, &f.body, 1);
                out.push_str(")\n");
            }
        }
    }
    out
}

fn mods(m: &Modifiers) -> String {
    let mut s = String::new();
    for (on, name) in [
        (m.is_pub, "pub"),
        (m.is_private, "private"),
        (m.persistent, "persistent"),
        (m.is_override, "override"),
    ] {
        if on {
            s.push(' ');
            s.push_str(name);
        }
    }
    s
}

pub fn ty(t: &Type) -> String {
    match &t.kind {
        TypeKind::Int => "int".into(),
        TypeKind::Bool => "bool".into(),
        TypeKind::String => "string".into(),
        TypeKind::Object => "object".into(),
        TypeKind::Any => "any".into(),
        TypeKind::Null => "null".into(),
        TypeKind::Array(e) => format!("[{}]", ty(e)),
        TypeKind::Map(k, v) => format!("{{{}: {}}}", ty(k), ty(v)),
        TypeKind::Optional(i) => format!("{}?", ty(i)),
        TypeKind::Named(n) => n.clone(),
    }
}

fn block(out: &mut String, b: &Block, indent: usize) {
    for s in &b.stmts {
        stmt(out, s, indent);
    }
}

fn stmt(out: &mut String, s: &Stmt, indent: usize) {
    let pad = "  ".repeat(indent);
    match &s.kind {
        StmtKind::Local {
            mutable,
            name,
            ty: t,
            init,
        } => {
            let _ = writeln!(
                out,
                "{pad}({} {}{}{})",
                if *mutable { "var" } else { "let" },
                name.name,
                t.as_ref()
                    .map(|t| format!(" : {}", ty(t)))
                    .unwrap_or_default(),
                init.as_ref()
                    .map(|e| format!(" = {}", expr(e)))
                    .unwrap_or_default()
            );
        }
        StmtKind::Assign { target, op, value } => {
            let op = match op {
                AssignOp::Set => "=",
                AssignOp::Add => "+=",
                AssignOp::Sub => "-=",
            };
            let _ = writeln!(out, "{pad}({op} {} {})", expr(target), expr(value));
        }
        StmtKind::If { cond, then, els } => {
            let _ = writeln!(out, "{pad}(if {}", expr(cond));
            block(out, then, indent + 1);
            match els.as_deref() {
                None => {}
                Some(Else::Block(b)) => {
                    let _ = writeln!(out, "{pad} else");
                    block(out, b, indent + 1);
                }
                Some(Else::If(s)) => {
                    let _ = writeln!(out, "{pad} else");
                    stmt(out, s, indent + 1);
                }
            }
            let _ = writeln!(out, "{pad})");
        }
        StmtKind::For { var, iter, body } => {
            let _ = writeln!(out, "{pad}(for {} in {}", var.name, expr(iter));
            block(out, body, indent + 1);
            let _ = writeln!(out, "{pad})");
        }
        StmtKind::While { cond, body } => {
            let _ = writeln!(out, "{pad}(while {}", expr(cond));
            block(out, body, indent + 1);
            let _ = writeln!(out, "{pad})");
        }
        StmtKind::Return(e) => {
            let _ = writeln!(
                out,
                "{pad}(return{})",
                e.as_ref()
                    .map(|e| format!(" {}", expr(e)))
                    .unwrap_or_default()
            );
        }
        StmtKind::Expr(e) => {
            let _ = writeln!(out, "{pad}{}", expr(e));
        }
    }
}

fn list(es: &[Expr]) -> String {
    es.iter().map(expr).collect::<Vec<_>>().join(" ")
}

pub fn expr(e: &Expr) -> String {
    match &e.kind {
        ExprKind::Int(n) => n.to_string(),
        ExprKind::Str(s) => format!("{s:?}"),
        ExprKind::Bool(b) => b.to_string(),
        ExprKind::Null => "null".into(),
        ExprKind::Interp(parts) => {
            let ps: Vec<String> = parts
                .iter()
                .map(|p| match p {
                    InterpPart::Lit(s) => format!("{s:?}"),
                    InterpPart::Expr(e) => expr(e),
                })
                .collect();
            format!("(interp {})", ps.join(" "))
        }
        ExprKind::Array(es) => format!("[{}]", list(es)),
        ExprKind::Map(kvs) => {
            if kvs.is_empty() {
                return "{:}".into();
            }
            let ps: Vec<String> = kvs
                .iter()
                .map(|(k, v)| format!("{}: {}", expr(k), expr(v)))
                .collect();
            format!("{{{}}}", ps.join(", "))
        }
        ExprKind::Ident(n) => n.clone(),
        ExprKind::Index { base, index } => format!("(index {} {})", expr(base), expr(index)),
        ExprKind::Unary { op, expr: x } => {
            let op = match op {
                UnOp::Neg => "neg",
                UnOp::Not => "not",
            };
            format!("({op} {})", expr(x))
        }
        ExprKind::Binary { op, lhs, rhs } => {
            let op = match op {
                BinOp::Add => "+",
                BinOp::Sub => "-",
                BinOp::Mul => "*",
                BinOp::Div => "/",
                BinOp::Rem => "%",
                BinOp::Eq => "==",
                BinOp::Ne => "!=",
                BinOp::Lt => "<",
                BinOp::Le => "<=",
                BinOp::Gt => ">",
                BinOp::Ge => ">=",
                BinOp::And => "and",
                BinOp::Or => "or",
                BinOp::In => "in",
                BinOp::Coalesce => "??",
            };
            format!("({op} {} {})", expr(lhs), expr(rhs))
        }
        ExprKind::Call { name, args } => {
            format!("(call {}{}{})", name.name, sep(args), list(args))
        }
        ExprKind::SuperCall { name, args } => {
            format!("(super::{}{}{})", name.name, sep(args), list(args))
        }
        ExprKind::Method {
            recv,
            name,
            args,
            safe,
        } => format!(
            "({} {} {}{}{})",
            if *safe { "?." } else { "." },
            expr(recv),
            name.name,
            sep(args),
            list(args)
        ),
        ExprKind::Error => "<error>".into(),
    }
}

fn sep(args: &[Expr]) -> &'static str {
    if args.is_empty() { "" } else { " " }
}
