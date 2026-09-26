// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 0 tree-walking evaluator.
//!
//! Every statement and expression evaluation costs one tick; an execution
//! that runs out of ticks or exceeds the call-depth limit aborts with an
//! error. Runtime errors are values ([`RtError`]) propagated with `?`; the
//! evaluator never panics on bad Weft code.

use std::rc::Rc;

use loom_syntax::Span;
use loom_syntax::ast::*;

use crate::host::Host;
use crate::object::ObjectId;
use crate::program::Program;
use crate::value::{Map, Value, display};
use crate::world::State;

/// Maximum elements in an array/map and bytes in a string (§5.8).
pub const MAX_ELEMS: usize = 1_000_000;
pub const MAX_STRING: usize = 16 * 1024 * 1024;

/// A Weft runtime error: message (with `path.wf:line:col`) plus call trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RtError {
    pub message: String,
    pub trace: Vec<String>,
}

impl RtError {
    pub fn new(message: impl Into<String>) -> RtError {
        RtError {
            message: message.into(),
            trace: Vec::new(),
        }
    }

    /// Message plus trace, one frame per line.
    pub fn report(&self) -> String {
        let mut s = self.message.clone();
        for t in &self.trace {
            s.push_str("\n  ");
            s.push_str(t);
        }
        s
    }
}

pub type R<T> = Result<T, RtError>;

struct Local {
    name: String,
    value: Value,
    ty: Option<Type>,
}

/// One activation: the object running, the program that *declares* the code
/// (for variable resolution and `super::`), and local scopes.
pub struct Frame {
    pub obj: ObjectId,
    pub prog: Rc<Program>,
    scopes: Vec<Vec<Local>>,
}

impl Frame {
    pub fn new(obj: ObjectId, prog: Rc<Program>) -> Frame {
        Frame {
            obj,
            prog,
            scopes: vec![Vec::new()],
        }
    }

    fn local_mut(&mut self, name: &str) -> Option<&mut Local> {
        self.scopes
            .iter_mut()
            .rev()
            .flat_map(|s| s.iter_mut().rev())
            .find(|l| l.name == name)
    }

    fn declare(&mut self, name: &str, value: Value, ty: Option<Type>) {
        if let Some(s) = self.scopes.last_mut() {
            s.push(Local {
                name: name.to_string(),
                value,
                ty,
            });
        }
    }
}

enum Flow {
    Next,
    Return(Value),
}

/// One execution (a driver-initiated call chain) with its tick budget.
pub struct Exec<'a> {
    pub st: &'a mut State,
    pub host: &'a mut dyn Host,
    pub ticks_left: u64,
    pub depth: u32,
    pub this_player: Option<ObjectId>,
    /// Connection that triggered this execution, if any.
    pub conn: Option<u64>,
    /// Programs currently being compiled (inherit-cycle detection).
    pub compiling: Vec<String>,
    /// Address of a local at execution start; see [`stack_addr`].
    pub stack_base: usize,
}

/// Approximate current stack position. The tree-walker recurses on the Rust
/// stack, so besides the Weft call-depth limit we bound the stack actually
/// used (debug builds use far more per Weft frame than release builds). A
/// stack overflow would abort the whole driver, so this check is what keeps
/// "a Weft error never takes the driver down" true.
#[inline(never)]
pub fn stack_addr() -> usize {
    let marker = 0u8;
    std::hint::black_box(&marker) as *const u8 as usize
}

impl Exec<'_> {
    pub fn err(&self, f: &Frame, span: Span, msg: impl AsRef<str>) -> RtError {
        RtError::new(format!("{}: {}", f.prog.location(span), msg.as_ref()))
    }

    fn tick(&mut self, f: &Frame, span: Span) -> R<()> {
        if self.ticks_left == 0 {
            return Err(self.err(f, span, "Too long evaluation (tick limit exceeded)"));
        }
        self.ticks_left -= 1;
        Ok(())
    }

    pub fn obj_name(&self, id: ObjectId) -> String {
        self.st
            .objects
            .get(id)
            .map_or_else(|| "<destructed>".to_string(), |o| o.name.clone())
    }

    pub fn show(&self, v: &Value) -> String {
        display(v, &|id| self.obj_name(id))
    }

    // ---- calls ------------------------------------------------------------

    /// Call `decl` (declared in `prog`) on `obj` with evaluated `args`.
    pub fn call_fn(
        &mut self,
        obj: ObjectId,
        prog: Rc<Program>,
        decl: Rc<FnDecl>,
        args: Vec<Value>,
    ) -> R<Value> {
        let where_ = format!(
            "in {}() at {}",
            decl.name.name,
            prog.location(decl.name.span)
        );
        let r = self.call_fn_inner(obj, prog, &decl, args);
        r.map_err(|mut e| {
            if e.trace.len() < 12 {
                e.trace.push(where_);
            }
            e
        })
    }

    fn call_fn_inner(
        &mut self,
        obj: ObjectId,
        prog: Rc<Program>,
        decl: &FnDecl,
        args: Vec<Value>,
    ) -> R<Value> {
        let mut f = Frame::new(obj, prog);
        let used = self.stack_base.abs_diff(stack_addr());
        if self.depth >= self.st.limits.max_depth || used > self.st.limits.max_stack_bytes {
            return Err(self.err(
                &f,
                decl.name.span,
                format!(
                    "Too deep recursion (call depth limit {} or stack budget exceeded)",
                    self.st.limits.max_depth
                ),
            ));
        }
        if args.len() > decl.params.len() {
            return Err(self.err(
                &f,
                decl.name.span,
                format!(
                    "{}() takes at most {} argument(s), got {}",
                    decl.name.name,
                    decl.params.len(),
                    args.len()
                ),
            ));
        }
        self.depth += 1;
        let r = self.run_body(&mut f, decl, args);
        self.depth -= 1;
        r
    }

    fn run_body(&mut self, f: &mut Frame, decl: &FnDecl, args: Vec<Value>) -> R<Value> {
        let mut args = args.into_iter();
        for p in &decl.params {
            let v = match args.next() {
                Some(v) => v,
                None => match &p.default {
                    Some(d) => self.eval(f, d)?,
                    None => {
                        return Err(self.err(
                            f,
                            p.span,
                            format!("{}(): missing argument `{}`", decl.name.name, p.name.name),
                        ));
                    }
                },
            };
            if let Some(t) = &p.ty
                && !v.conforms(t)
            {
                return Err(self.err(
                    f,
                    p.span,
                    format!(
                        "{}(): argument `{}` must be {}, got {}",
                        decl.name.name,
                        p.name.name,
                        loom_syntax::pretty::ty(t),
                        v.type_name()
                    ),
                ));
            }
            f.declare(&p.name.name, v, p.ty.clone());
        }
        let ret = match self.block(f, &decl.body)? {
            Flow::Return(v) => v,
            Flow::Next => Value::Null,
        };
        if let Some(t) = &decl.ret
            && !ret.conforms(t)
        {
            return Err(self.err(
                f,
                t.span,
                format!(
                    "{}() must return {}, but returned {}",
                    decl.name.name,
                    loom_syntax::pretty::ty(t),
                    ret.type_name()
                ),
            ));
        }
        Ok(ret)
    }

    /// Driver-side call of an apply (visibility is not enforced for the
    /// driver). Returns `None` if the object does not define `name`.
    pub fn call_apply(&mut self, obj: ObjectId, name: &str, args: Vec<Value>) -> R<Option<Value>> {
        let Some(prog) = self.st.objects.get(obj).map(|o| o.program.clone()) else {
            return Ok(None);
        };
        match prog.find_fn(name) {
            Some((p, d)) => self.call_fn(obj, p, d, args).map(Some),
            None => Ok(None),
        }
    }

    // ---- statements -------------------------------------------------------

    fn block(&mut self, f: &mut Frame, b: &Block) -> R<Flow> {
        f.scopes.push(Vec::new());
        let r = self.stmts(f, &b.stmts);
        f.scopes.pop();
        r
    }

    fn stmts(&mut self, f: &mut Frame, stmts: &[Stmt]) -> R<Flow> {
        for s in stmts {
            if let Flow::Return(v) = self.stmt(f, s)? {
                return Ok(Flow::Return(v));
            }
        }
        Ok(Flow::Next)
    }

    fn cond(&mut self, f: &mut Frame, e: &Expr, what: &str) -> R<bool> {
        match self.eval(f, e)? {
            Value::Bool(b) => Ok(b),
            v => Err(self.err(
                f,
                e.span,
                format!(
                    "{what} condition must be bool, got {} (Weft has no truthiness; compare explicitly, e.g. `x != null`)",
                    v.type_name()
                ),
            )),
        }
    }

    fn stmt(&mut self, f: &mut Frame, s: &Stmt) -> R<Flow> {
        self.tick(f, s.span)?;
        match &s.kind {
            StmtKind::Local { name, ty, init, .. } => {
                let v = match init {
                    Some(e) => self.eval(f, e)?,
                    None => Value::Null,
                };
                if let Some(t) = ty
                    && init.is_some()
                    && !v.conforms(t)
                {
                    return Err(self.type_mismatch(f, s.span, &name.name, t, &v));
                }
                f.declare(&name.name, v, ty.clone());
                Ok(Flow::Next)
            }
            StmtKind::Assign { target, op, value } => {
                self.assign(f, target, *op, value)?;
                Ok(Flow::Next)
            }
            StmtKind::If { cond, then, els } => {
                if self.cond(f, cond, "`if`")? {
                    self.block(f, then)
                } else {
                    match els.as_deref() {
                        Some(Else::Block(b)) => self.block(f, b),
                        Some(Else::If(s)) => self.stmt(f, s),
                        None => Ok(Flow::Next),
                    }
                }
            }
            StmtKind::While { cond, body } => {
                while self.cond(f, cond, "`while`")? {
                    if let Flow::Return(v) = self.block(f, body)? {
                        return Ok(Flow::Return(v));
                    }
                }
                Ok(Flow::Next)
            }
            StmtKind::For { var, iter, body } => {
                // Iterate a snapshot so the body may mutate the collection.
                let items: Vec<Value> = match self.eval(f, iter)? {
                    Value::Array(a) => a.borrow().clone(),
                    Value::Map(m) => m.borrow().entries.iter().map(|(k, _)| k.clone()).collect(),
                    v => {
                        return Err(self.err(
                            f,
                            iter.span,
                            format!("`for` needs an array or map, got {}", v.type_name()),
                        ));
                    }
                };
                for item in items {
                    self.tick(f, var.span)?;
                    f.scopes.push(Vec::new());
                    f.declare(&var.name, item, None);
                    let r = self.block(f, body);
                    f.scopes.pop();
                    if let Flow::Return(v) = r? {
                        return Ok(Flow::Return(v));
                    }
                }
                Ok(Flow::Next)
            }
            StmtKind::Return(e) => {
                let v = match e {
                    Some(e) => self.eval(f, e)?,
                    None => Value::Null,
                };
                Ok(Flow::Return(v))
            }
            StmtKind::Expr(e) => {
                self.eval(f, e)?;
                Ok(Flow::Next)
            }
            // Rejected by `subset::phase0_gate` before linking.
            _ => Err(self.err(f, s.span, "not supported by the Phase 0 evaluator")),
        }
    }

    fn type_mismatch(&self, f: &Frame, span: Span, name: &str, t: &Type, v: &Value) -> RtError {
        self.err(
            f,
            span,
            format!(
                "`{name}` is declared {} but the value is {}",
                loom_syntax::pretty::ty(t),
                v.type_name()
            ),
        )
    }

    fn assign(&mut self, f: &mut Frame, target: &Expr, op: AssignOp, value: &Expr) -> R<()> {
        match &target.kind {
            ExprKind::Ident(name) => {
                let rhs = self.eval(f, value)?;
                let new = match op {
                    AssignOp::Set => rhs,
                    _ => {
                        let cur = self.read_var(f, name, target.span)?;
                        self.arith(f, target.span, op_of(op), cur, rhs)?
                    }
                };
                self.write_var(f, name, target.span, new)
            }
            ExprKind::Index { base, index } => {
                let container = self.eval(f, base)?;
                let key = self.eval(f, index)?;
                let rhs = self.eval(f, value)?;
                let new = match op {
                    AssignOp::Set => rhs,
                    _ => {
                        let cur = self.index(f, target.span, &container, &key)?;
                        self.arith(f, target.span, op_of(op), cur, rhs)?
                    }
                };
                match container {
                    Value::Array(a) => {
                        let len = a.borrow().len();
                        let i = self.array_index(f, index.span, &key, len)?;
                        a.borrow_mut()[i] = new;
                        Ok(())
                    }
                    Value::Map(m) => {
                        if !key.is_valid_key() {
                            return Err(self.err(
                                f,
                                index.span,
                                format!(
                                    "map keys must be int, string, bool or object, got {}",
                                    key.type_name()
                                ),
                            ));
                        }
                        let mut m = m.borrow_mut();
                        if !m.contains(&key) && m.entries.len() >= MAX_ELEMS {
                            return Err(self.err(f, target.span, "map too large"));
                        }
                        m.insert(key, new);
                        Ok(())
                    }
                    v => Err(self.err(
                        f,
                        base.span,
                        format!("cannot assign into {} (need array or map)", v.type_name()),
                    )),
                }
            }
            _ => Err(self.err(f, target.span, "cannot assign to this expression")),
        }
    }

    fn read_var(&mut self, f: &mut Frame, name: &str, span: Span) -> R<Value> {
        if let Some(l) = f.local_mut(name) {
            return Ok(l.value.clone());
        }
        if let Some((owner, _)) = f.prog.find_var(name) {
            let v = self
                .st
                .objects
                .get(f.obj)
                .and_then(|o| o.vars.get(&owner.path))
                .and_then(|m| m.get(name))
                .cloned();
            return Ok(v.unwrap_or(Value::Null));
        }
        if name == "self" {
            return Ok(Value::Object(f.obj));
        }
        Err(self.err(f, span, format!("unknown variable `{name}`")))
    }

    fn write_var(&mut self, f: &mut Frame, name: &str, span: Span, v: Value) -> R<()> {
        if let Some(l) = f.local_mut(name) {
            if let Some(t) = &l.ty
                && !v.conforms(t)
            {
                let t = t.clone();
                return Err(self.type_mismatch(f, span, name, &t, &v));
            }
            l.value = v;
            return Ok(());
        }
        if let Some((owner, decl)) = f.prog.find_var(name) {
            if let Some(t) = &decl.ty
                && !v.conforms(t)
            {
                return Err(self.type_mismatch(f, span, name, t, &v));
            }
            let Some(obj) = self.st.objects.get_mut(f.obj) else {
                return Err(self.err(f, span, "object was destructed"));
            };
            obj.vars
                .entry(owner.path.clone())
                .or_default()
                .insert(Rc::from(name), v);
            return Ok(());
        }
        Err(self.err(f, span, format!("unknown variable `{name}`")))
    }

    // ---- expressions ------------------------------------------------------

    pub fn eval(&mut self, f: &mut Frame, e: &Expr) -> R<Value> {
        self.tick(f, e.span)?;
        match &e.kind {
            ExprKind::Int(n) => Ok(Value::Int(*n)),
            ExprKind::Str(s) => Ok(Value::str(s)),
            ExprKind::Bool(b) => Ok(Value::Bool(*b)),
            ExprKind::Null => Ok(Value::Null),
            ExprKind::Interp(parts) => {
                let mut s = String::new();
                for p in parts {
                    match p {
                        InterpPart::Lit(l) => s.push_str(l),
                        InterpPart::Expr(x) => {
                            let v = self.eval(f, x)?;
                            s.push_str(&self.show(&v));
                        }
                    }
                    if s.len() > MAX_STRING {
                        return Err(self.err(f, e.span, "string too long"));
                    }
                }
                Ok(Value::Str(Rc::from(s)))
            }
            ExprKind::Array(es) => {
                let mut out = Vec::with_capacity(es.len());
                for x in es {
                    out.push(self.eval(f, x)?);
                }
                Ok(Value::array(out))
            }
            ExprKind::Map(kvs) => {
                let mut m = Map::default();
                for (k, v) in kvs {
                    let kv = self.eval(f, k)?;
                    if !kv.is_valid_key() {
                        return Err(self.err(
                            f,
                            k.span,
                            format!(
                                "map keys must be int, string, bool or object, got {}",
                                kv.type_name()
                            ),
                        ));
                    }
                    let vv = self.eval(f, v)?;
                    m.insert(kv, vv);
                }
                Ok(Value::Map(Rc::new(std::cell::RefCell::new(m))))
            }
            ExprKind::Ident(n) => self.read_var(f, n, e.span),
            ExprKind::Index { base, index } => {
                let b = self.eval(f, base)?;
                let i = self.eval(f, index)?;
                self.index(f, e.span, &b, &i)
            }
            ExprKind::Unary { op, expr } => {
                let v = self.eval(f, expr)?;
                match (op, v) {
                    (UnOp::Neg, Value::Int(n)) => n
                        .checked_neg()
                        .map(Value::Int)
                        .ok_or_else(|| self.err(f, e.span, "integer overflow")),
                    (UnOp::Not, Value::Bool(b)) => Ok(Value::Bool(!b)),
                    (UnOp::Neg, v) => {
                        Err(self.err(f, e.span, format!("cannot negate {}", v.type_name())))
                    }
                    (UnOp::Not, v) => Err(self.err(
                        f,
                        e.span,
                        format!("`not` needs a bool, got {}", v.type_name()),
                    )),
                }
            }
            ExprKind::Binary { op, lhs, rhs } => self.binary(f, e.span, *op, lhs, rhs),
            ExprKind::Call { name, args } => {
                let argv = self.eval_args(f, args)?;
                self.call_named(f, name, argv, e.span)
            }
            ExprKind::SuperCall { name, args, .. } => {
                let argv = self.eval_args(f, args)?;
                let found = f.prog.parent.as_ref().and_then(|p| p.find_fn(&name.name));
                match found {
                    Some((p, d)) => self.call_fn(f.obj, p, d, argv),
                    None => Err(self.err(
                        f,
                        name.span,
                        format!("no inherited function `{}`", name.name),
                    )),
                }
            }
            ExprKind::Method {
                recv,
                name,
                args,
                safe,
            } => {
                let target = self.eval(f, recv)?;
                let id = match target {
                    Value::Null if *safe => return Ok(Value::Null),
                    Value::Null => {
                        return Err(self.err(
                            f,
                            recv.span,
                            format!(
                                "called `{}()` on null (use `?.` if the object may be missing)",
                                name.name
                            ),
                        ));
                    }
                    Value::Object(id) => id,
                    v => {
                        return Err(self.err(
                            f,
                            recv.span,
                            format!("cannot call `{}()` on {}", name.name, v.type_name()),
                        ));
                    }
                };
                let argv = self.eval_args(f, args)?;
                self.call_other(f, id, name, argv, *safe)
            }
            ExprKind::Error => Err(self.err(f, e.span, "internal: error node reached evaluator")),
            // Rejected by `subset::phase0_gate` before linking.
            _ => Err(self.err(f, e.span, "not supported by the Phase 0 evaluator")),
        }
    }

    fn eval_args(&mut self, f: &mut Frame, args: &[Arg]) -> R<Vec<Value>> {
        let mut out = Vec::with_capacity(args.len());
        for a in args {
            out.push(self.eval(f, &a.value)?);
        }
        Ok(out)
    }

    /// Unqualified `name(args)`: a private function of the declaring program,
    /// else virtual dispatch on the object's current program, else an efun.
    fn call_named(
        &mut self,
        f: &mut Frame,
        name: &Ident,
        args: Vec<Value>,
        span: Span,
    ) -> R<Value> {
        if let Some(d) = f.prog.fns.get(&name.name)
            && d.mods.is_private
        {
            return self.call_fn(f.obj, f.prog.clone(), d.clone(), args);
        }
        let prog = self.st.objects.get(f.obj).map(|o| o.program.clone());
        if let Some((p, d)) = prog.and_then(|p| p.find_fn(&name.name)) {
            return self.call_fn(f.obj, p, d, args);
        }
        if let Some(r) = self.efun(f, &name.name, args, span) {
            return r;
        }
        Err(self.err(f, name.span, format!("unknown function `{}`", name.name)))
    }

    /// `ob.fn(args)`: late-bound call_other; only `pub` functions.
    fn call_other(
        &mut self,
        f: &mut Frame,
        id: ObjectId,
        name: &Ident,
        args: Vec<Value>,
        safe: bool,
    ) -> R<Value> {
        let Some(prog) = self.st.objects.get(id).map(|o| o.program.clone()) else {
            if safe {
                return Ok(Value::Null);
            }
            return Err(self.err(
                f,
                name.span,
                format!("called `{}()` on a destructed object", name.name),
            ));
        };
        match prog.find_fn(&name.name) {
            Some((p, d)) if d.mods.is_pub => self.call_fn(id, p, d, args),
            Some((p, _)) => Err(self.err(
                f,
                name.span,
                format!(
                    "`{}` in {} is not `pub`, so other objects cannot call it",
                    name.name, p.path
                ),
            )),
            None => Err(self.err(
                f,
                name.span,
                format!("{} has no function `{}`", self.obj_name(id), name.name),
            )),
        }
    }

    fn binary(&mut self, f: &mut Frame, span: Span, op: BinOp, lhs: &Expr, rhs: &Expr) -> R<Value> {
        match op {
            BinOp::And | BinOp::Or => {
                let what = if op == BinOp::And { "`and`" } else { "`or`" };
                let l = self.eval(f, lhs)?;
                let Value::Bool(l) = l else {
                    return Err(self.err(
                        f,
                        lhs.span,
                        format!("{what} needs bool operands, got {}", l.type_name()),
                    ));
                };
                if (op == BinOp::And && !l) || (op == BinOp::Or && l) {
                    return Ok(Value::Bool(l));
                }
                let r = self.eval(f, rhs)?;
                match r {
                    Value::Bool(b) => Ok(Value::Bool(b)),
                    r => Err(self.err(
                        f,
                        rhs.span,
                        format!("{what} needs bool operands, got {}", r.type_name()),
                    )),
                }
            }
            BinOp::Coalesce => {
                let l = self.eval(f, lhs)?;
                if matches!(l, Value::Null) {
                    self.eval(f, rhs)
                } else {
                    Ok(l)
                }
            }
            _ => {
                let l = self.eval(f, lhs)?;
                let r = self.eval(f, rhs)?;
                self.arith(f, span, op, l, r)
            }
        }
    }

    fn arith(&mut self, f: &Frame, span: Span, op: BinOp, l: Value, r: Value) -> R<Value> {
        use Value::*;
        let overflow = || self.err(f, span, "integer overflow");
        Ok(match (op, &l, &r) {
            (BinOp::Add, Int(a), Int(b)) => Int(a.checked_add(*b).ok_or_else(overflow)?),
            (BinOp::Sub, Int(a), Int(b)) => Int(a.checked_sub(*b).ok_or_else(overflow)?),
            (BinOp::Mul, Int(a), Int(b)) => Int(a.checked_mul(*b).ok_or_else(overflow)?),
            (BinOp::Div | BinOp::Rem, Int(_), Int(0)) => {
                return Err(self.err(f, span, "division by zero"));
            }
            (BinOp::Div, Int(a), Int(b)) => Int(a.checked_div(*b).ok_or_else(overflow)?),
            (BinOp::Rem, Int(a), Int(b)) => Int(a.checked_rem(*b).ok_or_else(overflow)?),
            (BinOp::Add, Str(a), Str(b)) => {
                if a.len() + b.len() > MAX_STRING {
                    return Err(self.err(f, span, "string too long"));
                }
                let mut s = String::with_capacity(a.len() + b.len());
                s.push_str(a);
                s.push_str(b);
                Str(Rc::from(s))
            }
            (BinOp::Add, Array(a), Array(b)) => {
                let mut v = a.borrow().clone();
                v.extend(b.borrow().iter().cloned());
                if v.len() > MAX_ELEMS {
                    return Err(self.err(f, span, "array too large"));
                }
                Value::array(v)
            }
            (BinOp::Eq, _, _) => Bool(l.equals(&r)),
            (BinOp::Ne, _, _) => Bool(!l.equals(&r)),
            (BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge, Int(_), Int(_))
            | (BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge, Str(_), Str(_)) => {
                let ord = match (&l, &r) {
                    (Int(a), Int(b)) => a.cmp(b),
                    (Str(a), Str(b)) => a.cmp(b),
                    _ => std::cmp::Ordering::Equal,
                };
                Bool(match op {
                    BinOp::Lt => ord.is_lt(),
                    BinOp::Le => ord.is_le(),
                    BinOp::Gt => ord.is_gt(),
                    _ => ord.is_ge(),
                })
            }
            (BinOp::In, _, Array(a)) => Bool(a.borrow().iter().any(|x| x.equals(&l))),
            (BinOp::In, _, Map(m)) => Bool(m.borrow().contains(&l)),
            (BinOp::In, Str(needle), Str(hay)) => Bool(hay.contains(&**needle)),
            _ => {
                let sym = match op {
                    BinOp::Add => "+",
                    BinOp::Sub => "-",
                    BinOp::Mul => "*",
                    BinOp::Div => "/",
                    BinOp::Rem => "%",
                    BinOp::Lt => "<",
                    BinOp::Le => "<=",
                    BinOp::Gt => ">",
                    BinOp::Ge => ">=",
                    BinOp::In => "in",
                    _ => "?",
                };
                let hint = if op == BinOp::Add && (matches!(l, Str(_)) || matches!(r, Str(_))) {
                    " (build strings with $\"…{x}…\")"
                } else {
                    ""
                };
                return Err(self.err(
                    f,
                    span,
                    format!(
                        "cannot apply `{sym}` to {} and {}{hint}",
                        l.type_name(),
                        r.type_name()
                    ),
                ));
            }
        })
    }

    fn array_index(&self, f: &Frame, span: Span, key: &Value, len: usize) -> R<usize> {
        match key {
            Value::Int(i) if *i >= 0 && (*i as u64) < len as u64 => Ok(*i as usize),
            Value::Int(i) => {
                Err(self.err(f, span, format!("index {i} out of range (length {len})")))
            }
            v => Err(self.err(
                f,
                span,
                format!("array index must be int, got {}", v.type_name()),
            )),
        }
    }

    fn index(&self, f: &Frame, span: Span, base: &Value, key: &Value) -> R<Value> {
        match base {
            Value::Array(a) => {
                let a = a.borrow();
                let i = self.array_index(f, span, key, a.len())?;
                Ok(a[i].clone())
            }
            Value::Map(m) => Ok(m.borrow().get(key).cloned().unwrap_or(Value::Null)),
            Value::Str(s) => {
                let n = s.chars().count();
                let i = self.array_index(f, span, key, n)?;
                Ok(s.chars()
                    .nth(i)
                    .map_or(Value::Null, |c| Value::str(c.encode_utf8(&mut [0; 4]))))
            }
            v => Err(self.err(f, span, format!("cannot index {}", v.type_name()))),
        }
    }
}

fn op_of(op: AssignOp) -> BinOp {
    match op {
        AssignOp::Add => BinOp::Add,
        _ => BinOp::Sub,
    }
}
