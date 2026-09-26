// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Compact S-expression rendering of the AST, used by golden tests and
//! `loom check --ast`. Spans are omitted; the format is stable-ish but not a
//! public contract.

use crate::ast::*;
use std::fmt::Write as _;

pub fn program(p: &Program) -> String {
    let mut out = String::new();
    if p.lightweight.is_some() {
        out.push_str("(lightweight)\n");
    }
    for i in &p.inherits {
        match &i.label {
            Some(l) => {
                let _ = writeln!(out, "(inherit {} = {})", l.name, i.path);
            }
            None => {
                let _ = writeln!(out, "(inherit {})", i.path);
            }
        }
    }
    for i in &p.imports {
        match &i.names {
            Some(ns) => {
                let ns: Vec<&str> = ns.iter().map(|n| n.name.as_str()).collect();
                let _ = writeln!(out, "(import {} {{{}}})", i.path, ns.join(" "));
            }
            None => {
                let _ = writeln!(out, "(import {})", i.path);
            }
        }
    }
    for item in &p.items {
        match item {
            Item::Var(v) => {
                let _ = writeln!(
                    out,
                    "(var{} {}{}{})",
                    mods(&v.mods),
                    v.name.name,
                    opt_ty(&v.ty, " : "),
                    opt_expr(&v.init, " = ", 0)
                );
            }
            Item::Const(c) => {
                let _ = writeln!(
                    out,
                    "(const{} {}{} = {})",
                    mods(&c.mods),
                    c.name.name,
                    opt_ty(&c.ty, " : "),
                    expr_i(&c.value, 0)
                );
            }
            Item::Fn(f) => {
                let _ = writeln!(
                    out,
                    "(fn{} {} ({}){}",
                    mods(&f.mods),
                    f.name.name,
                    params(&f.params),
                    opt_ty(&f.ret, " -> ")
                );
                block(&mut out, &f.body, 1);
                out.push_str(")\n");
            }
            Item::Struct(s) => {
                let _ = writeln!(out, "(struct{} {}", mods(&s.mods), s.name.name);
                for f in &s.fields {
                    let _ = writeln!(
                        out,
                        "  (field {} : {}{})",
                        f.name.name,
                        ty(&f.ty),
                        opt_expr(&f.default, " = ", 1)
                    );
                }
                out.push_str(")\n");
            }
            Item::Enum(e) => {
                let vs: Vec<String> = e
                    .variants
                    .iter()
                    .map(|v| {
                        if v.payload.is_empty() {
                            v.name.name.clone()
                        } else {
                            let ts: Vec<String> = v.payload.iter().map(ty).collect();
                            format!("({} {})", v.name.name, ts.join(" "))
                        }
                    })
                    .collect();
                let _ = writeln!(
                    out,
                    "(enum{} {}{}{})",
                    mods(&e.mods),
                    e.name.name,
                    if vs.is_empty() { "" } else { " " },
                    vs.join(" ")
                );
            }
        }
    }
    out
}

fn opt_ty(t: &Option<Type>, pre: &str) -> String {
    t.as_ref()
        .map(|t| format!("{pre}{}", ty(t)))
        .unwrap_or_default()
}

fn opt_expr(e: &Option<Expr>, pre: &str, indent: usize) -> String {
    e.as_ref()
        .map(|e| format!("{pre}{}", expr_i(e, indent)))
        .unwrap_or_default()
}

fn params(ps: &[Param]) -> String {
    ps.iter()
        .map(|p| {
            format!(
                "{}{}{}{}",
                if p.rest { "..." } else { "" },
                p.name.name,
                opt_ty(&p.ty, ": "),
                opt_expr(&p.default, " = ", 0)
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn mods(m: &Modifiers) -> String {
    let mut s = String::new();
    for (on, name) in [
        (m.is_pub, "pub"),
        (m.is_protected, "protected"),
        (m.is_private, "private"),
        (m.persistent, "persistent"),
        (m.is_override, "override"),
        (m.is_final, "final"),
        (m.atomic, "atomic"),
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
        TypeKind::Float => "float".into(),
        TypeKind::Bool => "bool".into(),
        TypeKind::String => "string".into(),
        TypeKind::Object => "object".into(),
        TypeKind::Any => "any".into(),
        TypeKind::Null => "null".into(),
        TypeKind::Error => "error".into(),
        TypeKind::Array(e) => format!("[{}]", ty(e)),
        TypeKind::Map(k, v) => format!("{{{}: {}}}", ty(k), ty(v)),
        TypeKind::Optional(i) => match i.kind {
            TypeKind::Fn { .. } => format!("({})?", ty(i)),
            _ => format!("{}?", ty(i)),
        },
        TypeKind::Fn { params, ret } => {
            let ps: Vec<String> = params.iter().map(ty).collect();
            format!(
                "fn({}){}",
                ps.join(", "),
                ret.as_ref()
                    .map(|r| format!(" -> {}", ty(r)))
                    .unwrap_or_default()
            )
        }
        TypeKind::Named(n) => n.clone(),
    }
}

fn block(out: &mut String, b: &Block, indent: usize) {
    for s in &b.stmts {
        stmt(out, s, indent);
    }
}

fn els(out: &mut String, e: &Option<Box<Else>>, indent: usize) {
    let pad = "  ".repeat(indent);
    match e.as_deref() {
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
}

fn stmt(out: &mut String, s: &Stmt, indent: usize) {
    let pad = "  ".repeat(indent);
    let e = |x: &Expr| expr_i(x, indent);
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
                opt_ty(t, " : "),
                opt_expr(init, " = ", indent)
            );
        }
        StmtKind::Assign { target, op, value } => {
            let op = match op {
                AssignOp::Set => "=",
                AssignOp::Add => "+=",
                AssignOp::Sub => "-=",
                AssignOp::Mul => "*=",
                AssignOp::Div => "/=",
                AssignOp::Rem => "%=",
            };
            let _ = writeln!(out, "{pad}({op} {} {})", e(target), e(value));
        }
        StmtKind::If {
            cond,
            then,
            els: el,
        } => {
            let _ = writeln!(out, "{pad}(if {}", e(cond));
            block(out, then, indent + 1);
            els(out, el, indent);
            let _ = writeln!(out, "{pad})");
        }
        StmtKind::IfLet {
            name,
            ty: t,
            value,
            then,
            els: el,
        } => {
            let _ = writeln!(
                out,
                "{pad}(if let {}{} = {}",
                name.name,
                opt_ty(t, " : "),
                e(value)
            );
            block(out, then, indent + 1);
            els(out, el, indent);
            let _ = writeln!(out, "{pad})");
        }
        StmtKind::For { var, iter, body } => {
            let _ = writeln!(out, "{pad}(for {} in {}", var.name, e(iter));
            block(out, body, indent + 1);
            let _ = writeln!(out, "{pad})");
        }
        StmtKind::While { cond, body } => {
            let _ = writeln!(out, "{pad}(while {}", e(cond));
            block(out, body, indent + 1);
            let _ = writeln!(out, "{pad})");
        }
        StmtKind::Break => {
            let _ = writeln!(out, "{pad}(break)");
        }
        StmtKind::Continue => {
            let _ = writeln!(out, "{pad}(continue)");
        }
        StmtKind::Return(x) => {
            let _ = writeln!(out, "{pad}(return{})", opt_expr(x, " ", indent));
        }
        StmtKind::Try {
            body,
            catch_var,
            handler,
        } => {
            let _ = writeln!(out, "{pad}(try");
            block(out, body, indent + 1);
            let _ = writeln!(
                out,
                "{pad} catch{}",
                catch_var
                    .as_ref()
                    .map(|v| format!(" {}", v.name))
                    .unwrap_or_default()
            );
            block(out, handler, indent + 1);
            let _ = writeln!(out, "{pad})");
        }
        StmtKind::Throw(x) => {
            let _ = writeln!(out, "{pad}(throw {})", e(x));
        }
        StmtKind::Expr(x) => {
            let _ = writeln!(out, "{pad}{}", e(x));
        }
    }
}

fn args(a: &[Arg], indent: usize) -> String {
    let mut s = String::new();
    for arg in a {
        s.push(' ');
        if arg.spread {
            s.push_str("...");
        }
        if let Some(n) = &arg.name {
            let _ = write!(s, "{}: ", n.name);
        }
        s.push_str(&expr_i(&arg.value, indent));
    }
    s
}

pub fn expr(e: &Expr) -> String {
    expr_i(e, 0)
}

/// A block nested in an expression: `{`, indented statements, `}`.
fn inline_block(b: &Block, indent: usize) -> String {
    let mut s = String::from("{\n");
    block(&mut s, b, indent + 1);
    let _ = write!(s, "{}}}", "  ".repeat(indent));
    s
}

fn body(b: &Body, indent: usize) -> String {
    match b {
        Body::Expr(e) => format!("=> {}", expr_i(e, indent)),
        Body::Block(b) => inline_block(b, indent),
    }
}

pub fn pattern(p: &Pattern) -> String {
    match &p.kind {
        PatKind::Wild => "_".into(),
        PatKind::Bind(n) => n.clone(),
        PatKind::Int(n) => n.to_string(),
        PatKind::Float(x) => format!("{x:?}"),
        PatKind::Str(s) => format!("{s:?}"),
        PatKind::Bool(b) => b.to_string(),
        PatKind::Null => "null".into(),
        PatKind::Variant {
            enum_name,
            name,
            fields,
        } => {
            let head = match enum_name {
                Some(e) => format!("{}.{}", e.name, name.name),
                None => format!(".{}", name.name),
            };
            match fields {
                None => head,
                Some(fs) => {
                    let fs: Vec<String> = fs.iter().map(pattern).collect();
                    format!("({head} {})", fs.join(" "))
                }
            }
        }
        PatKind::Or(alts) => {
            let alts: Vec<String> = alts.iter().map(pattern).collect();
            format!("(| {})", alts.join(" "))
        }
    }
}

fn expr_i(e: &Expr, indent: usize) -> String {
    let x = |e: &Expr| expr_i(e, indent);
    match &e.kind {
        ExprKind::Int(n) => n.to_string(),
        ExprKind::Float(f) => format!("{f:?}"),
        ExprKind::Str(s) => format!("{s:?}"),
        ExprKind::Bool(b) => b.to_string(),
        ExprKind::Null => "null".into(),
        ExprKind::Interp(parts) => {
            let ps: Vec<String> = parts
                .iter()
                .map(|p| match p {
                    InterpPart::Lit(s) => format!("{s:?}"),
                    InterpPart::Expr(e) => x(e),
                })
                .collect();
            format!("(interp {})", ps.join(" "))
        }
        ExprKind::Array(es) => format!("[{}]", es.iter().map(x).collect::<Vec<_>>().join(" ")),
        ExprKind::Map(kvs) => {
            if kvs.is_empty() {
                return "{:}".into();
            }
            let ps: Vec<String> = kvs
                .iter()
                .map(|(k, v)| format!("{}: {}", x(k), x(v)))
                .collect();
            format!("{{{}}}", ps.join(", "))
        }
        ExprKind::Ident(n) => n.clone(),
        ExprKind::Index { base, index } => format!("(index {} {})", x(base), x(index)),
        ExprKind::Slice { base, lo, hi } => {
            let b = |o: &Option<Box<Expr>>| o.as_deref().map_or("_".to_string(), x);
            format!("(slice {} {} {})", x(base), b(lo), b(hi))
        }
        ExprKind::Field { base, name, safe } => format!(
            "({} {} {})",
            if *safe { "?field" } else { "field" },
            x(base),
            name.name
        ),
        ExprKind::Unary { op, expr: inner } => {
            let op = match op {
                UnOp::Neg => "neg",
                UnOp::Not => "not",
            };
            format!("({op} {})", x(inner))
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
            format!("({op} {} {})", x(lhs), x(rhs))
        }
        ExprKind::Cast { expr: inner, ty: t } => format!("(as {} {})", x(inner), ty(t)),
        ExprKind::Call { name, args: a } => format!("(call {}{})", name.name, args(a, indent)),
        ExprKind::SuperCall {
            label,
            name,
            args: a,
        } => format!(
            "({}::{}{})",
            label.as_ref().map_or("super", |l| l.name.as_str()),
            name.name,
            args(a, indent)
        ),
        ExprKind::Method {
            recv,
            name,
            args: a,
            safe,
        } => format!(
            "({} {} {}{})",
            if *safe { "?." } else { "." },
            x(recv),
            name.name,
            args(a, indent)
        ),
        ExprKind::Apply { callee, args: a } => format!("(apply {}{})", x(callee), args(a, indent)),
        ExprKind::Closure(c) => format!(
            "(closure ({}){} {})",
            params(&c.params),
            opt_ty(&c.ret, " -> "),
            body(&c.body, indent)
        ),
        ExprKind::Match { scrutinee, arms } => {
            let pad = "  ".repeat(indent + 1);
            let mut s = format!("(match {}", x(scrutinee));
            for a in arms {
                let _ = write!(
                    s,
                    "\n{pad}({}{} {})",
                    pattern(&a.pat),
                    a.guard
                        .as_ref()
                        .map(|g| format!(" if {}", expr_i(g, indent + 1)))
                        .unwrap_or_default(),
                    body(&a.body, indent + 1)
                );
            }
            s.push(')');
            s
        }
        ExprKind::StructLit { name, fields } => {
            let fs: Vec<String> = fields
                .iter()
                .map(|f| format!(" {}: {}", f.name.name, x(&f.value)))
                .collect();
            format!("(struct {}{})", name.name, fs.join(""))
        }
        ExprKind::Variant { name, args: a } => match a {
            None => format!(".{}", name.name),
            Some(a) => format!("(.{}{})", name.name, args(a, indent)),
        },
        ExprKind::Error => "<error>".into(),
    }
}
