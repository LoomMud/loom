// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Programs (compiled form of one source file) and the Phase 0 linker/checker.
//!
//! The Phase 0 "compiler" keeps the AST (the tree-walker executes it) and runs
//! a light semantic pass at link time so builders get errors at `update`
//! time, not when a player trips over them: unknown names, missing
//! `override`, assignments to `let`, unknown types, efun arity.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use loom_syntax::Diagnostic;
use loom_syntax::ast::*;

use crate::efuns;

/// One version of one program (§3.4). Immutable once built; running frames
/// hold an `Rc` so a recompile never mutates code that is executing (§7.2).
#[derive(Debug)]
pub struct Program {
    /// Mudlib path without extension, e.g. `/domains/start/hall`.
    pub path: Rc<str>,
    pub version: u32,
    pub parent: Option<Rc<Program>>,
    /// Program variables declared here, in declaration order.
    pub vars: Vec<Rc<VarDecl>>,
    /// Functions declared here.
    pub fns: HashMap<String, Rc<FnDecl>>,
    pub ast: Rc<loom_syntax::ast::Program>,
    pub src: Rc<str>,
}

impl Program {
    /// This program and its ancestors, root first.
    pub fn chain(self: &Rc<Self>) -> Vec<Rc<Program>> {
        let mut out = vec![self.clone()];
        let mut cur = self.parent.clone();
        while let Some(p) = cur {
            cur = p.parent.clone();
            out.push(p);
        }
        out.reverse();
        out
    }

    /// True if `path` is a strict ancestor of this program.
    pub fn inherits(&self, path: &str) -> bool {
        let mut cur = self.parent.as_deref();
        while let Some(p) = cur {
            if &*p.path == path {
                return true;
            }
            cur = p.parent.as_deref();
        }
        false
    }

    /// Virtual lookup from the most-derived program upward, ignoring private
    /// functions (those are only reachable from their own program's code).
    pub fn find_fn(self: &Rc<Self>, name: &str) -> Option<(Rc<Program>, Rc<FnDecl>)> {
        let mut cur = Some(self.clone());
        while let Some(p) = cur {
            if let Some(f) = p.fns.get(name)
                && !f.mods.is_private
            {
                return Some((p.clone(), f.clone()));
            }
            cur = p.parent.clone();
        }
        None
    }

    /// Resolve a variable name as seen from code declared in this program:
    /// own variables, then ancestors' non-private ones.
    pub fn find_var(self: &Rc<Self>, name: &str) -> Option<(Rc<Program>, Rc<VarDecl>)> {
        if let Some(v) = self.vars.iter().find(|v| v.name.name == name) {
            return Some((self.clone(), v.clone()));
        }
        let mut cur = self.parent.clone();
        while let Some(p) = cur {
            if let Some(v) = p
                .vars
                .iter()
                .find(|v| v.name.name == name && !v.mods.is_private)
            {
                return Some((p.clone(), v.clone()));
            }
            cur = p.parent.clone();
        }
        None
    }

    /// `path.wf:line:col` for a span in this program's source.
    pub fn location(&self, span: loom_syntax::Span) -> String {
        let (l, c) = loom_syntax::line_col(&self.src, span.start as usize);
        format!("{}.wf:{l}:{c}", self.path)
    }
}

/// Link a parsed program against its (already built) parent and run the
/// semantic checks. On error nothing is produced.
pub fn link(
    path: &str,
    src: Rc<str>,
    ast: Rc<loom_syntax::ast::Program>,
    parent: Option<Rc<Program>>,
    version: u32,
) -> Result<Program, Vec<Diagnostic>> {
    let mut diags = Vec::new();
    let mut vars: Vec<Rc<VarDecl>> = Vec::new();
    let mut fns: HashMap<String, Rc<FnDecl>> = HashMap::new();
    let mut names: HashSet<&str> = HashSet::new();

    for item in &ast.items {
        match item {
            Item::Var(v) => {
                if !names.insert(&v.name.name) {
                    diags.push(Diagnostic::error(
                        v.name.span,
                        format!("`{}` is declared twice in this program", v.name.name),
                    ));
                    continue;
                }
                if let Some(p) = &parent
                    && let Some((owner, _)) = p.find_var(&v.name.name)
                {
                    diags.push(
                        Diagnostic::error(
                            v.name.span,
                            format!(
                                "variable `{}` is already declared in {}",
                                v.name.name, owner.path
                            ),
                        )
                        .with_hint("use the inherited variable, or pick another name"),
                    );
                }
                if let Some(t) = &v.ty {
                    check_type(t, &mut diags);
                }
                vars.push(Rc::new(v.clone()));
            }
            Item::Fn(f) => {
                if !names.insert(&f.name.name) {
                    diags.push(Diagnostic::error(
                        f.name.span,
                        format!("`{}` is declared twice in this program", f.name.name),
                    ));
                    continue;
                }
                let inherited = parent.as_ref().and_then(|p| p.find_fn(&f.name.name));
                match (&inherited, f.mods.is_override) {
                    (Some((owner, _)), false) => diags.push(
                        Diagnostic::error(
                            f.name.span,
                            format!(
                                "`{}` redefines a function inherited from {}",
                                f.name.name, owner.path
                            ),
                        )
                        .with_hint(format!("write `override fn {}(…)`", f.name.name)),
                    ),
                    (None, true) => diags.push(
                        Diagnostic::error(
                            f.name.span,
                            format!("`override fn {}` overrides nothing", f.name.name),
                        )
                        .with_hint(if parent.is_some() {
                            "no inherited function has this name; remove `override`"
                        } else {
                            "this program has no `inherit`; remove `override`"
                        }),
                    ),
                    _ => {}
                }
                let mut seen_default = false;
                let mut pnames = HashSet::new();
                for p in &f.params {
                    if !pnames.insert(&p.name.name) {
                        diags.push(Diagnostic::error(
                            p.name.span,
                            format!("parameter `{}` is declared twice", p.name.name),
                        ));
                    }
                    if let Some(t) = &p.ty {
                        check_type(t, &mut diags);
                    }
                    if p.default.is_some() {
                        seen_default = true;
                    } else if seen_default {
                        diags.push(
                            Diagnostic::error(
                                p.name.span,
                                "a parameter without a default follows one with a default",
                            )
                            .with_hint("put parameters with defaults last"),
                        );
                    }
                }
                if let Some(t) = &f.ret {
                    check_type(t, &mut diags);
                }
                fns.insert(f.name.name.clone(), Rc::new(f.clone()));
            }
            // Rejected by `subset::phase0_gate` before linking.
            Item::Const(_) | Item::Struct(_) | Item::Enum(_) => {}
        }
    }

    let prog = Program {
        path: Rc::from(path),
        version,
        parent,
        vars,
        fns,
        ast,
        src,
    };
    let prog = Rc::new(prog);
    let mut ck = Checker {
        prog: &prog,
        scopes: Vec::new(),
        diags: &mut diags,
    };
    for v in &prog.vars {
        if let Some(e) = &v.init {
            ck.expr(e);
        }
    }
    for f in prog.fns.values() {
        ck.scopes.push(
            f.params
                .iter()
                .map(|p| (p.name.name.clone(), true))
                .collect(),
        );
        for p in &f.params {
            if let Some(d) = &p.default {
                ck.expr(d);
            }
        }
        ck.block(&f.body);
        ck.scopes.pop();
    }
    if !diags.is_empty() {
        diags.sort_by_key(|d| d.span.start);
        return Err(diags);
    }
    Rc::try_unwrap(prog).map_err(|_| Vec::new())
}

fn check_type(t: &Type, diags: &mut Vec<Diagnostic>) {
    match &t.kind {
        TypeKind::Named(n) => {
            let hint = match n.as_str() {
                "str" | "String" => "did you mean `string`?",
                "mapping" | "map" => "maps are written `{K: V}`",
                "array" => "arrays are written `[T]`",
                _ => "Phase 0 types: int, bool, string, object, any, null, [T], {K: V}, T?",
            };
            diags.push(Diagnostic::error(t.span, format!("unknown type `{n}`")).with_hint(hint));
        }
        TypeKind::Array(e) | TypeKind::Optional(e) => check_type(e, diags),
        TypeKind::Map(k, v) => {
            check_type(k, diags);
            check_type(v, diags);
        }
        _ => {}
    }
}

struct Checker<'a> {
    prog: &'a Rc<Program>,
    /// Local scopes: (name, mutable).
    scopes: Vec<Vec<(String, bool)>>,
    diags: &'a mut Vec<Diagnostic>,
}

enum Name {
    Local(bool),
    ProgramVar,
    SelfObj,
}

impl Checker<'_> {
    fn lookup(&self, name: &str) -> Option<Name> {
        for s in self.scopes.iter().rev() {
            if let Some((_, m)) = s.iter().rev().find(|(n, _)| n == name) {
                return Some(Name::Local(*m));
            }
        }
        if self.prog.find_var(name).is_some() {
            return Some(Name::ProgramVar);
        }
        if name == "self" {
            return Some(Name::SelfObj);
        }
        None
    }

    fn declare(&mut self, name: &str, mutable: bool) {
        if let Some(s) = self.scopes.last_mut() {
            s.push((name.to_string(), mutable));
        }
    }

    fn block(&mut self, b: &Block) {
        self.scopes.push(Vec::new());
        for s in &b.stmts {
            self.stmt(s);
        }
        self.scopes.pop();
    }

    fn stmt(&mut self, s: &Stmt) {
        match &s.kind {
            StmtKind::Local {
                mutable,
                name,
                ty,
                init,
            } => {
                if let Some(e) = init {
                    self.expr(e);
                }
                if let Some(t) = ty {
                    check_type(t, self.diags);
                }
                self.declare(&name.name, *mutable);
            }
            StmtKind::Assign { target, value, .. } => {
                match &target.kind {
                    ExprKind::Ident(n) => match self.lookup(n) {
                        Some(Name::Local(false)) => self.diags.push(
                            Diagnostic::error(
                                target.span,
                                format!("cannot assign to `{n}`: it was declared with `let`"),
                            )
                            .with_hint(format!("declare it with `var {n}` to make it mutable")),
                        ),
                        Some(Name::SelfObj) => self
                            .diags
                            .push(Diagnostic::error(target.span, "cannot assign to `self`")),
                        Some(_) => {}
                        None => self.unknown_var(n, target.span),
                    },
                    _ => self.expr(target),
                }
                self.expr(value);
            }
            StmtKind::If { cond, then, els } => {
                self.expr(cond);
                self.block(then);
                match els.as_deref() {
                    Some(Else::Block(b)) => self.block(b),
                    Some(Else::If(s)) => self.stmt(s),
                    None => {}
                }
            }
            StmtKind::For { var, iter, body } => {
                self.expr(iter);
                self.scopes.push(vec![(var.name.clone(), false)]);
                self.block(body);
                self.scopes.pop();
            }
            StmtKind::While { cond, body } => {
                self.expr(cond);
                self.block(body);
            }
            StmtKind::Return(Some(e)) | StmtKind::Expr(e) => self.expr(e),
            StmtKind::Return(None) => {}
            // Rejected by `subset::phase0_gate` before linking.
            _ => {}
        }
    }

    fn unknown_var(&mut self, n: &str, span: loom_syntax::Span) {
        let mut d = Diagnostic::error(span, format!("unknown variable `{n}`"));
        if self.prog.find_fn(n).is_some()
            || self.prog.fns.contains_key(n)
            || efuns::arity(n).is_some()
        {
            d = d.with_hint(format!(
                "`{n}` is a function; call it with `{n}()` (function values arrive in Phase 1)"
            ));
        } else {
            d = d.with_hint("declare it with `let`, `var`, or as a program variable");
        }
        self.diags.push(d);
    }

    fn exprs(&mut self, es: &[Expr]) {
        for e in es {
            self.expr(e);
        }
    }

    fn args(&mut self, args: &[Arg]) {
        for a in args {
            self.expr(&a.value);
        }
    }

    fn expr(&mut self, e: &Expr) {
        match &e.kind {
            ExprKind::Int(_)
            | ExprKind::Str(_)
            | ExprKind::Bool(_)
            | ExprKind::Null
            | ExprKind::Error => {}
            ExprKind::Interp(parts) => {
                for p in parts {
                    if let InterpPart::Expr(e) = p {
                        self.expr(e);
                    }
                }
            }
            ExprKind::Array(es) => self.exprs(es),
            ExprKind::Map(kvs) => {
                for (k, v) in kvs {
                    self.expr(k);
                    self.expr(v);
                }
            }
            ExprKind::Ident(n) => {
                if self.lookup(n).is_none() {
                    self.unknown_var(n, e.span);
                }
            }
            ExprKind::Index { base, index } => {
                self.expr(base);
                self.expr(index);
            }
            ExprKind::Unary { expr, .. } => self.expr(expr),
            ExprKind::Binary { lhs, rhs, .. } => {
                self.expr(lhs);
                self.expr(rhs);
            }
            ExprKind::Call { name, args } => {
                self.args(args);
                let n = name.name.as_str();
                if self.prog.fns.contains_key(n) || self.prog.find_fn(n).is_some() {
                    return;
                }
                match efuns::arity(n) {
                    Some((min, max)) => {
                        if args.len() < min || args.len() > max {
                            let want = if min == max {
                                format!("{min}")
                            } else {
                                format!("{min} to {max}")
                            };
                            self.diags.push(Diagnostic::error(
                                e.span,
                                format!(
                                    "`{n}` takes {want} argument{}, but {} were given",
                                    if max == 1 { "" } else { "s" },
                                    args.len()
                                ),
                            ));
                        }
                    }
                    None => self.diags.push(
                        Diagnostic::error(name.span, format!("unknown function `{n}`")).with_hint(
                            "it is not declared in this program, inherited, or an efun; \
                                 to call another object use `ob.fn()`",
                        ),
                    ),
                }
            }
            ExprKind::SuperCall { name, args, .. } => {
                self.args(args);
                let found = self
                    .prog
                    .parent
                    .as_ref()
                    .and_then(|p| p.find_fn(&name.name));
                if found.is_none() {
                    self.diags.push(Diagnostic::error(
                        name.span,
                        format!(
                            "`super::{}`: no inherited function with this name",
                            name.name
                        ),
                    ));
                }
            }
            ExprKind::Method { recv, args, .. } => {
                self.expr(recv);
                self.args(args);
            }
            // Everything else is rejected by `subset::phase0_gate` first.
            _ => {}
        }
    }
}
