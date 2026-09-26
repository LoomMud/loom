// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! The register-bytecode interpreter (spec §5.8/§5.9).
//!
//! **D-P1.3: Weft frames never live on the native stack.** [`Interpreter`]
//! keeps its own heap-allocated `Vec<Frame>` call stack; a Weft call that
//! recurses (directly, or `Static` back into the same module) pushes a
//! [`Frame`] and loops, it never makes a recursive Rust call. Call depth is
//! therefore a Weft-level limit ([`Interpreter::max_depth`]) checked as an
//! ordinary `Vec` length check, independent of the native thread's stack
//! size — a 10k-deep Weft recursion fails with "Too deep recursion" the
//! same way on a 64 KiB thread as on an 8 MiB one (see the test below).
//!
//! A cross-module call (`Virtual` dispatch, `CallOther`, `CallEfun`) is not
//! something this module can resolve on its own (it needs the object
//! table / program registry, which is `World`'s), so those go through the
//! [`Host`] trait. `Host::call_static`/`call_efun`/etc. run to completion
//! and return a [`Value`] or [`RtError`] to the calling frame; if a hosted
//! call needs to run *more* Weft frames of its own (e.g. `call_other` into
//! another object), the host's implementation must construct another
//! [`Interpreter`] over its own `Vec<Frame>` rather than recursing on the
//! Rust stack — this module cannot enforce that for a call it hands off,
//! which is why it is the one exception the doc comment calls out.

use loom_compiler::bytecode::{
    BinOp, CalleeOp, ConstValue, IndexKind, IterKind, Module, Op, OpKind, Reg, Ty, UnOp,
};

use crate::bcvm::heap::{Map, Value};
use crate::object::ObjectId;

/// A Weft runtime error: message (with `path.wf:line:col` when available)
/// plus a call trace, most recent frame first.
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

/// Callbacks for everything the interpreter cannot resolve from the
/// [`Module`] it is running alone (§5.5, §5.9): cross-object/program calls,
/// efuns, and `self`/program-variable access. `World` (OBI-31 follow-up)
/// is the production `Host`; tests use a small in-memory one.
pub trait Host {
    /// The object executing the current call chain.
    fn self_object(&self) -> ObjectId;
    /// `super::name(args)` / a specific program's function.
    fn call_static(&mut self, program: &str, name: &str, args: Vec<Value>) -> R<Value>;
    /// Unqualified `name(args)`: virtual dispatch on the running object's
    /// *current* program.
    fn call_virtual(&mut self, name: &str, args: Vec<Value>) -> R<Value>;
    /// `recv.name(args)`.
    fn call_other(&mut self, recv: Value, name: &str, args: Vec<Value>) -> R<Value>;
    /// An efun call not handled inline by the interpreter (see
    /// [`Interpreter::call_efun`] for the ones that are).
    fn call_efun(&mut self, name: &str, args: Vec<Value>) -> R<Value>;
    fn load_global(&mut self, owner: &str, name: &str) -> Value;
    fn store_global(&mut self, owner: &str, name: &str, v: Value);
}

/// One activation: which function, at which instruction, with its own
/// register file. Lives on [`Interpreter`]'s `Vec<Frame>`, never on the
/// native stack.
struct Frame {
    func: u32,
    pc: u32,
    regs: Vec<Value>,
    /// Register to write the callee's return value into, in the *caller*
    /// (the frame below this one). `None` for the outermost call.
    ret_into: Option<Reg>,
}

/// Per-execution limits (spec §5.9): every tick-metered op consumes one
/// tick; the call stack cannot exceed `max_depth` frames.
pub struct Limits {
    pub max_depth: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_depth: 512 }
    }
}

pub struct Interpreter<'a, H: Host> {
    module: &'a Module,
    host: &'a mut H,
    limits: &'a Limits,
    ticks_left: &'a mut u64,
    stack: Vec<Frame>,
}

impl<'a, H: Host> Interpreter<'a, H> {
    pub fn new(
        module: &'a Module,
        host: &'a mut H,
        limits: &'a Limits,
        ticks_left: &'a mut u64,
    ) -> Self {
        Interpreter {
            module,
            host,
            limits,
            ticks_left,
            stack: Vec::new(),
        }
    }

    /// Every [`Value`] currently reachable from live frames: a GC root set
    /// for [`crate::bcvm::heap::collect_cycles`].
    pub fn roots(&self) -> impl Iterator<Item = &Value> {
        self.stack.iter().flat_map(|f| f.regs.iter())
    }

    fn func_name(&self, idx: u32) -> &str {
        &self.module.strings[self.module.functions[idx as usize].name as usize]
    }

    fn str_of(&self, id: u32) -> &str {
        &self.module.strings[id as usize]
    }

    fn tick(&mut self) -> R<()> {
        if *self.ticks_left == 0 {
            return Err(self.err_with_trace("Too long evaluation (tick limit exceeded)"));
        }
        *self.ticks_left -= 1;
        Ok(())
    }

    fn err_with_trace(&self, msg: impl Into<String>) -> RtError {
        let mut e = RtError::new(msg);
        for f in self.stack.iter().rev().take(12) {
            e.trace.push(format!("in {}()", self.func_name(f.func)));
        }
        e
    }

    /// Call `name` in this module with `args`, from outside any running
    /// frame (the World-facing entry point: `call_apply`, etc.).
    pub fn call(&mut self, name: &str, args: Vec<Value>) -> R<Value> {
        let idx = self
            .module
            .functions
            .iter()
            .position(|f| self.str_of(f.name) == name)
            .ok_or_else(|| RtError::new(format!("no function `{name}` in {}", self.module.path)))?;
        self.push_call(idx as u32, args, None)?;
        self.run()
    }

    fn push_call(&mut self, idx: u32, args: Vec<Value>, ret_into: Option<Reg>) -> R<()> {
        if self.stack.len() as u32 >= self.limits.max_depth {
            return Err(self.err_with_trace(format!(
                "Too deep recursion (call depth limit {} exceeded)",
                self.limits.max_depth
            )));
        }
        let f = &self.module.functions[idx as usize];
        if args.len() != f.params as usize {
            return Err(self.err_with_trace(format!(
                "{}() takes {} argument(s), got {}",
                self.func_name(idx),
                f.params,
                args.len()
            )));
        }
        let mut regs: Vec<Value> = args;
        regs.resize(f.reg_types.len(), Value::Null);
        self.stack.push(Frame {
            func: idx,
            pc: 0,
            regs,
            ret_into,
        });
        Ok(())
    }

    /// Drive frames until the outermost call returns.
    fn run(&mut self) -> R<Value> {
        let base_depth = self.stack.len() - 1;
        loop {
            match self.step() {
                Ok(Some(v)) if self.stack.len() == base_depth => return Ok(v),
                Ok(_) => continue,
                Err(mut e) => {
                    // step() already pushed the innermost frame's name; add
                    // any remaining frames beneath it once, then unwind.
                    if e.trace.len() < 12 {
                        for f in self.stack.iter().rev().skip(1).take(12 - e.trace.len()) {
                            e.trace.push(format!("in {}()", self.func_name(f.func)));
                        }
                    }
                    self.stack.truncate(base_depth);
                    return Err(e);
                }
            }
        }
    }

    /// Execute one instruction of the top frame. `Ok(Some(v))` means a
    /// frame returned `v` (popped); the caller keeps looping until the
    /// frame count is back to where `run` started.
    fn step(&mut self) -> R<Option<Value>> {
        let func_idx = self.stack.last().unwrap().func;
        let pc = self.stack.last().unwrap().pc as usize;
        let code: &[Op] = &self.module.functions[func_idx as usize].code;
        let op = code.get(pc).cloned().ok_or_else(|| {
            self.err_with_trace("internal: program counter ran off the end of the function")
        })?;
        self.stack.last_mut().unwrap().pc += 1;

        macro_rules! reg {
            ($r:expr) => {
                self.stack.last().unwrap().regs[$r as usize].clone()
            };
        }
        macro_rules! set {
            ($r:expr, $v:expr) => {{
                let v = $v;
                self.stack.last_mut().unwrap().regs[$r as usize] = v;
            }};
        }
        macro_rules! jump {
            ($target:expr) => {{
                self.stack.last_mut().unwrap().pc = $target;
            }};
        }

        match op {
            Op::LoadConst { dst, idx } => {
                set!(dst, self.const_value(idx));
                Ok(None)
            }
            Op::Copy { dst, src } => {
                set!(dst, reg!(src));
                Ok(None)
            }
            Op::LoadSelf { dst } => {
                set!(dst, Value::Object(self.host.self_object()));
                Ok(None)
            }
            Op::LoadGlobal {
                dst, owner, name, ..
            } => {
                let (owner, name) = (
                    self.str_of(owner).to_string(),
                    self.str_of(name).to_string(),
                );
                let v = self.host.load_global(&owner, &name);
                set!(dst, v);
                Ok(None)
            }
            Op::StoreGlobal {
                owner, name, src, ..
            } => {
                let (owner, name) = (
                    self.str_of(owner).to_string(),
                    self.str_of(name).to_string(),
                );
                self.host.store_global(&owner, &name, reg!(src));
                Ok(None)
            }
            Op::UnOp { dst, op, kind, src } => {
                let v = self.un_op(op, kind, reg!(src))?;
                set!(dst, v);
                Ok(None)
            }
            Op::BinOp {
                dst,
                op,
                kind,
                a,
                b,
            } => {
                let v = self.bin_op(op, kind, reg!(a), reg!(b))?;
                set!(dst, v);
                Ok(None)
            }
            Op::NewArray { dst, elems, .. } => {
                let v = Value::array(elems.iter().map(|r| reg!(*r)).collect());
                set!(dst, v);
                Ok(None)
            }
            Op::NewMap { dst, entries, .. } => {
                let mut m = Map::default();
                for (k, v) in entries {
                    m.insert(reg!(k), reg!(v));
                }
                set!(dst, Value::map(m));
                Ok(None)
            }
            Op::Index {
                dst,
                base,
                index,
                kind,
            } => {
                let v = self.index(kind, reg!(base), reg!(index))?;
                set!(dst, v);
                Ok(None)
            }
            Op::IndexSet {
                base,
                index,
                kind,
                src,
            } => {
                self.index_set(kind, reg!(base), reg!(index), reg!(src))?;
                Ok(None)
            }
            Op::IterElems { dst, src, kind, .. } => {
                let v = self.iter_elems(kind, reg!(src))?;
                set!(dst, v);
                Ok(None)
            }
            Op::ToStr { dst, src } => {
                let s = self.show(&reg!(src));
                set!(dst, Value::str(&s));
                Ok(None)
            }
            Op::Cast { dst, src, ty } => {
                let v = reg!(src);
                if !ty_accepts(&ty, &v) {
                    return Err(self.err_with_trace(format!(
                        "expected {}, got {}",
                        ty_name(&ty),
                        v.type_name()
                    )));
                }
                set!(dst, v);
                Ok(None)
            }
            Op::Call { dst, callee, args } => {
                let argv: Vec<Value> = args.iter().map(|r| reg!(*r)).collect();
                match callee {
                    CalleeOp::Static { program, name }
                        if self.str_of(program) == &*self.module.path =>
                    {
                        let name = self.str_of(name).to_string();
                        let idx = self
                            .module
                            .functions
                            .iter()
                            .position(|f| self.str_of(f.name) == name)
                            .ok_or_else(|| self.err_with_trace(format!("no function `{name}`")))?;
                        self.push_call(idx as u32, argv, dst)?;
                        Ok(None)
                    }
                    CalleeOp::Static { program, name } => {
                        let (program, name) = (
                            self.str_of(program).to_string(),
                            self.str_of(name).to_string(),
                        );
                        let v = self.host.call_static(&program, &name, argv)?;
                        if let Some(dst) = dst {
                            set!(dst, v);
                        }
                        Ok(None)
                    }
                    CalleeOp::Virtual { name } => {
                        let name = self.str_of(name).to_string();
                        let v = self.host.call_virtual(&name, argv)?;
                        if let Some(dst) = dst {
                            set!(dst, v);
                        }
                        Ok(None)
                    }
                }
            }
            Op::CallOther {
                dst,
                recv,
                name,
                args,
            } => {
                let recv = reg!(recv);
                let argv: Vec<Value> = args.iter().map(|r| reg!(*r)).collect();
                let name = self.str_of(name).to_string();
                let v = self.host.call_other(recv, &name, argv)?;
                set!(dst, v);
                Ok(None)
            }
            Op::CallEfun { dst, name, args } => {
                let argv: Vec<Value> = args.iter().map(|r| reg!(*r)).collect();
                let name_s = self.str_of(name).to_string();
                let v = match self.call_efun(&name_s, &argv) {
                    Some(v) => v?,
                    None => self.host.call_efun(&name_s, argv)?,
                };
                if let Some(dst) = dst {
                    set!(dst, v);
                }
                Ok(None)
            }
            Op::Jump { target } => {
                jump!(target);
                Ok(None)
            }
            Op::Branch {
                cond,
                then_target,
                else_target,
            } => {
                let Value::Bool(b) = reg!(cond) else {
                    return Err(self.err_with_trace("internal: branch condition was not bool"));
                };
                jump!(if b { then_target } else { else_target });
                Ok(None)
            }
            Op::Return { src } => {
                let v = match src {
                    Some(r) => reg!(r),
                    None => Value::Null,
                };
                let frame = self.stack.pop().unwrap();
                if let Some(caller) = self.stack.last_mut()
                    && let Some(dst) = frame.ret_into
                {
                    caller.regs[dst as usize] = v.clone();
                }
                Ok(Some(v))
            }
            Op::TickCheck => {
                self.tick()?;
                Ok(None)
            }
        }
    }

    fn const_value(&self, idx: u32) -> Value {
        match &self.module.consts[idx as usize] {
            ConstValue::Int(n) => Value::Int(*n),
            ConstValue::Float(x) => Value::Float(*x),
            ConstValue::Bool(b) => Value::Bool(*b),
            ConstValue::Str(s) => Value::str(self.str_of(*s)),
            ConstValue::Null => Value::Null,
        }
    }

    pub fn show(&self, v: &Value) -> String {
        crate::bcvm::heap::display(v, &|_id| "<object>".to_string())
    }

    /// Efuns fundamental enough (no privilege gate, pure over values) to
    /// inline in the interpreter rather than round-trip through [`Host`]:
    /// `len` backs every `for` loop's bound check (see codegen's `IterElems`
    /// lowering), so it is on the hot path.
    fn call_efun(&self, name: &str, args: &[Value]) -> Option<R<Value>> {
        match name {
            "len" => Some(match args.first() {
                Some(v) if v.as_str().is_some() => {
                    Ok(Value::Int(v.as_str().unwrap().chars().count() as i64))
                }
                Some(v) if v.as_array().is_some() => {
                    Ok(Value::Int(v.as_array().unwrap().borrow().len() as i64))
                }
                Some(v) if v.as_map().is_some() => {
                    Ok(Value::Int(v.as_map().unwrap().borrow().entries.len() as i64))
                }
                Some(v) => {
                    Err(self.err_with_trace(format!("len(): {} has no length", v.type_name())))
                }
                None => Err(self.err_with_trace("len(): missing argument")),
            }),
            _ => None,
        }
    }

    fn un_op(&self, op: UnOp, _kind: OpKind, v: Value) -> R<Value> {
        match (op, v) {
            (UnOp::Neg, Value::Int(n)) => n
                .checked_neg()
                .map(Value::Int)
                .ok_or_else(|| self.err_with_trace("integer overflow")),
            (UnOp::Neg, Value::Float(x)) => Ok(Value::Float(-x)),
            (UnOp::Not, Value::Bool(b)) => Ok(Value::Bool(!b)),
            (op, v) => {
                Err(self.err_with_trace(format!("cannot apply {op:?} to {}", v.type_name())))
            }
        }
    }

    fn bin_op(&self, op: BinOp, _kind: OpKind, l: Value, r: Value) -> R<Value> {
        use Value::*;
        let overflow = || self.err_with_trace("integer overflow");
        Ok(match (op, &l, &r) {
            (BinOp::Add, Int(a), Int(b)) => Int(a.checked_add(*b).ok_or_else(overflow)?),
            (BinOp::Sub, Int(a), Int(b)) => Int(a.checked_sub(*b).ok_or_else(overflow)?),
            (BinOp::Mul, Int(a), Int(b)) => Int(a.checked_mul(*b).ok_or_else(overflow)?),
            (BinOp::Div | BinOp::Rem, Int(_), Int(0)) => {
                return Err(self.err_with_trace("division by zero"));
            }
            (BinOp::Div, Int(a), Int(b)) => Int(a.checked_div(*b).ok_or_else(overflow)?),
            (BinOp::Rem, Int(a), Int(b)) => Int(a.checked_rem(*b).ok_or_else(overflow)?),
            (BinOp::Add, Float(a), Float(b)) => Float(a + b),
            (BinOp::Sub, Float(a), Float(b)) => Float(a - b),
            (BinOp::Mul, Float(a), Float(b)) => Float(a * b),
            (BinOp::Div, Float(a), Float(b)) => Float(a / b),
            (BinOp::Add, a, b) if a.as_str().is_some() && b.as_str().is_some() => {
                let mut s =
                    String::with_capacity(a.as_str().unwrap().len() + b.as_str().unwrap().len());
                s.push_str(a.as_str().unwrap());
                s.push_str(b.as_str().unwrap());
                Value::str(&s)
            }
            (BinOp::Add, a, b) if a.as_array().is_some() && b.as_array().is_some() => {
                let mut v = a.as_array().unwrap().borrow().clone();
                v.extend(b.as_array().unwrap().borrow().iter().cloned());
                Value::array(v)
            }
            (BinOp::Eq, _, _) => Bool(l.equals(&r)),
            (BinOp::Ne, _, _) => Bool(!l.equals(&r)),
            (BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge, Int(a), Int(b)) => {
                cmp_bool(op, a.cmp(b))
            }
            (BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge, a, b)
                if a.as_str().is_some() && b.as_str().is_some() =>
            {
                cmp_bool(op, a.as_str().unwrap().cmp(b.as_str().unwrap()))
            }
            (BinOp::In, k, v) if v.as_array().is_some() => {
                Bool(v.as_array().unwrap().borrow().iter().any(|x| x.equals(k)))
            }
            (BinOp::In, k, v) if v.as_map().is_some() => {
                Bool(v.as_map().unwrap().borrow().contains(k))
            }
            (BinOp::In, a, b) if a.as_str().is_some() && b.as_str().is_some() => {
                Bool(b.as_str().unwrap().contains(a.as_str().unwrap()))
            }
            _ => {
                return Err(self.err_with_trace(format!(
                    "cannot apply {op:?} to {} and {}",
                    l.type_name(),
                    r.type_name()
                )));
            }
        })
    }

    fn array_index(&self, key: &Value, len: usize) -> R<usize> {
        match key {
            Value::Int(i) if *i >= 0 && (*i as u64) < len as u64 => Ok(*i as usize),
            Value::Int(i) => {
                Err(self.err_with_trace(format!("index {i} out of range (length {len})")))
            }
            v => {
                Err(self.err_with_trace(format!("array index must be int, got {}", v.type_name())))
            }
        }
    }

    fn index(&self, kind: IndexKind, base: Value, key: Value) -> R<Value> {
        match kind {
            IndexKind::Array => {
                let a = base
                    .as_array()
                    .ok_or_else(|| self.err_with_trace("internal: Index(Array) on non-array"))?;
                let a = a.borrow();
                let i = self.array_index(&key, a.len())?;
                Ok(a[i].clone())
            }
            IndexKind::String => {
                let s = base
                    .as_str()
                    .ok_or_else(|| self.err_with_trace("internal: Index(String) on non-string"))?;
                let n = s.chars().count();
                let i = self.array_index(&key, n)?;
                Ok(s.chars()
                    .nth(i)
                    .map_or(Value::Null, |c| Value::str(c.encode_utf8(&mut [0; 4]))))
            }
            IndexKind::Map | IndexKind::MapPresent => {
                let m = base
                    .as_map()
                    .ok_or_else(|| self.err_with_trace("internal: Index(Map) on non-map"))?;
                Ok(m.borrow().get(&key).cloned().unwrap_or(Value::Null))
            }
            IndexKind::Dyn => {
                if let Some(a) = base.as_array() {
                    let a = a.borrow();
                    let i = self.array_index(&key, a.len())?;
                    Ok(a[i].clone())
                } else if let Some(m) = base.as_map() {
                    Ok(m.borrow().get(&key).cloned().unwrap_or(Value::Null))
                } else if let Some(s) = base.as_str() {
                    let n = s.chars().count();
                    let i = self.array_index(&key, n)?;
                    Ok(s.chars()
                        .nth(i)
                        .map_or(Value::Null, |c| Value::str(c.encode_utf8(&mut [0; 4]))))
                } else {
                    Err(self.err_with_trace(format!("cannot index {}", base.type_name())))
                }
            }
        }
    }

    fn index_set(&self, kind: IndexKind, base: Value, key: Value, val: Value) -> R<()> {
        match kind {
            IndexKind::Array | IndexKind::Dyn if base.as_array().is_some() => {
                let a = base.as_array().unwrap();
                let len = a.borrow().len();
                let i = self.array_index(&key, len)?;
                a.borrow_mut()[i] = val;
                Ok(())
            }
            IndexKind::Map | IndexKind::MapPresent => {
                if !key.is_valid_key() {
                    return Err(self.err_with_trace(format!(
                        "map keys must be int, string, bool or object, got {}",
                        key.type_name()
                    )));
                }
                base.as_map()
                    .ok_or_else(|| self.err_with_trace("internal: IndexSet(Map) on non-map"))?
                    .borrow_mut()
                    .insert(key, val);
                Ok(())
            }
            IndexKind::Dyn if base.as_map().is_some() => {
                if !key.is_valid_key() {
                    return Err(self.err_with_trace(format!(
                        "map keys must be int, string, bool or object, got {}",
                        key.type_name()
                    )));
                }
                base.as_map().unwrap().borrow_mut().insert(key, val);
                Ok(())
            }
            _ => Err(self.err_with_trace(format!(
                "cannot assign into {} (need array or map)",
                base.type_name()
            ))),
        }
    }

    fn iter_elems(&self, kind: IterKind, src: Value) -> R<Value> {
        match kind {
            IterKind::Array => Ok(Value::array(
                src.as_array()
                    .ok_or_else(|| self.err_with_trace("`for` needs an array"))?
                    .borrow()
                    .clone(),
            )),
            IterKind::MapKeys => Ok(Value::array(
                src.as_map()
                    .ok_or_else(|| self.err_with_trace("`for` needs a map"))?
                    .borrow()
                    .entries
                    .iter()
                    .map(|(k, _)| k.clone())
                    .collect(),
            )),
            IterKind::Dyn => {
                if let Some(a) = src.as_array() {
                    Ok(Value::array(a.borrow().clone()))
                } else if let Some(m) = src.as_map() {
                    Ok(Value::array(
                        m.borrow().entries.iter().map(|(k, _)| k.clone()).collect(),
                    ))
                } else {
                    Err(self.err_with_trace(format!(
                        "`for` needs an array or map, got {}",
                        src.type_name()
                    )))
                }
            }
        }
    }
}

fn cmp_bool(op: BinOp, ord: std::cmp::Ordering) -> Value {
    Value::Bool(match op {
        BinOp::Lt => ord.is_lt(),
        BinOp::Le => ord.is_le(),
        BinOp::Gt => ord.is_gt(),
        _ => ord.is_ge(),
    })
}

fn ty_name(ty: &Ty) -> String {
    format!("{ty:?}")
}

fn ty_accepts(ty: &Ty, v: &Value) -> bool {
    match (ty, v) {
        (Ty::Any, _) => true,
        (Ty::Int, Value::Int(_)) => true,
        (Ty::Float, Value::Float(_)) => true,
        (Ty::Bool, Value::Bool(_)) => true,
        (Ty::Null, Value::Null) => true,
        (Ty::Object, Value::Object(_)) => true,
        (Ty::String, v) => v.as_str().is_some(),
        (Ty::Array(_), v) => v.as_array().is_some(),
        (Ty::Map(..), v) => v.as_map().is_some(),
        (Ty::Optional(inner), Value::Null) => {
            let _ = inner;
            true
        }
        (Ty::Optional(inner), v) => ty_accepts(inner, v),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_compiler::bytecode::{ConstValue, FunctionCode};

    /// A `Host` that cannot resolve anything outside the module: enough to
    /// run self-contained arithmetic/recursion tests.
    struct NoHost;
    impl Host for NoHost {
        fn self_object(&self) -> ObjectId {
            ObjectId {
                index: 0,
                generation: 0,
            }
        }
        fn call_static(&mut self, program: &str, name: &str, _args: Vec<Value>) -> R<Value> {
            Err(RtError::new(format!(
                "no such static call {program}::{name}"
            )))
        }
        fn call_virtual(&mut self, name: &str, _args: Vec<Value>) -> R<Value> {
            Err(RtError::new(format!("no such function `{name}`")))
        }
        fn call_other(&mut self, _recv: Value, name: &str, _args: Vec<Value>) -> R<Value> {
            Err(RtError::new(format!("no such function `{name}`")))
        }
        fn call_efun(&mut self, name: &str, _args: Vec<Value>) -> R<Value> {
            Err(RtError::new(format!("unknown efun `{name}`")))
        }
        fn load_global(&mut self, _owner: &str, _name: &str) -> Value {
            Value::Null
        }
        fn store_global(&mut self, _owner: &str, _name: &str, _v: Value) {}
    }

    /// `fn countdown(n: int) -> int { if n <= 0 { return n; } return
    /// countdown(n - 1); }` — a self-recursive function, hand-assembled, to
    /// exercise the call-stack path without needing a full codegen
    /// pipeline hookup (that's the World integration follow-up).
    fn countdown_module(max_depth_check: bool) -> Module {
        // Registers: 0 = n (param), 1 = 0 (const), 2 = cond, 3 = one, 4 = n-1, 5 = result
        let code = vec![
            Op::LoadConst { dst: 1, idx: 0 }, // 0
            Op::BinOp {
                dst: 2,
                op: BinOp::Le,
                kind: OpKind::Int,
                a: 0,
                b: 1,
            }, // 1
            Op::Branch {
                cond: 2,
                then_target: 3,
                else_target: 5,
            }, // 2
            Op::Return { src: Some(0) },      // 3 (then: base case)
            Op::Jump { target: 3 },           // 4 unreachable pad
            Op::LoadConst { dst: 3, idx: 1 }, // 5: one = 1
            Op::BinOp {
                dst: 4,
                op: BinOp::Sub,
                kind: OpKind::Int,
                a: 0,
                b: 3,
            }, // 6: n - 1
            Op::TickCheck,                    // 7
            Op::Call {
                dst: Some(5),
                callee: CalleeOp::Static {
                    program: 0,
                    name: 1,
                },
                args: vec![4],
            }, // 8
            Op::Return { src: Some(5) },      // 9
        ];
        let _ = max_depth_check;
        Module {
            path: std::rc::Rc::from("/test/countdown"),
            strings: vec![
                std::rc::Rc::from("/test/countdown"),
                std::rc::Rc::from("countdown"),
            ],
            consts: vec![ConstValue::Int(0), ConstValue::Int(1)],
            functions: vec![FunctionCode {
                name: 1,
                params: 1,
                ret: Ty::Int,
                reg_types: vec![Ty::Int; 6],
                code,
            }],
        }
    }

    #[test]
    fn recursive_call_uses_heap_stack_not_native_recursion() {
        let limits = Limits { max_depth: 20_000 };

        // Run on a thread with a tiny (64 KiB) native stack: if the
        // interpreter ever recursed on the Rust stack for a Weft call, this
        // would abort the process (stack overflow) long before 10,000
        // frames. Succeeding here is the D-P1.3 evidence. Everything the
        // VM touches (`Module`, `Value`) holds a non-`Send` `Rc`, so the
        // module is built *inside* the spawned closure and only a plain
        // `Result<i64, String>` crosses the thread boundary.
        let result = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || {
                let module = countdown_module(false);
                let mut host = NoHost;
                let mut ticks = 1_000_000u64;
                let mut interp = Interpreter::new(&module, &mut host, &limits, &mut ticks);
                match interp.call("countdown", vec![Value::Int(10_000)]) {
                    Ok(Value::Int(n)) => Ok(n),
                    Ok(v) => Err(format!("unexpected {v:?}")),
                    Err(e) => Err(e.message),
                }
            })
            .unwrap()
            .join()
            .unwrap();

        assert_eq!(result, Ok(0));
    }

    #[test]
    fn recursion_past_the_weft_depth_limit_is_a_weft_error_not_a_crash() {
        let limits = Limits { max_depth: 64 };

        let result = std::thread::Builder::new()
            .stack_size(64 * 1024) // default-ish small stack (§ test spec: "default-stack thread")
            .spawn(move || {
                let module = countdown_module(false);
                let mut host = NoHost;
                let mut ticks = 1_000_000u64;
                let mut interp = Interpreter::new(&module, &mut host, &limits, &mut ticks);
                match interp.call("countdown", vec![Value::Int(10_000)]) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e.message),
                }
            })
            .unwrap()
            .join()
            .unwrap();

        let message = result.unwrap_err();
        assert!(message.contains("Too deep recursion"), "{message}");
    }

    #[test]
    fn tick_metering_stops_a_runaway_call() {
        let module = countdown_module(false);
        let mut host = NoHost;
        let limits = Limits { max_depth: 20_000 };
        let mut ticks = 5u64; // far fewer ticks than the 10,000 needed

        let mut interp = Interpreter::new(&module, &mut host, &limits, &mut ticks);
        let err = interp
            .call("countdown", vec![Value::Int(10_000)])
            .unwrap_err();
        assert!(
            err.message.contains("Too long evaluation"),
            "{}",
            err.message
        );
    }

    #[test]
    fn error_carries_a_stack_trace() {
        let module = countdown_module(false);
        let mut host = NoHost;
        let limits = Limits { max_depth: 3 }; // recursion will exceed this quickly
        let mut ticks = 1_000_000u64;

        let mut interp = Interpreter::new(&module, &mut host, &limits, &mut ticks);
        let err = interp.call("countdown", vec![Value::Int(10)]).unwrap_err();
        assert!(!err.trace.is_empty());
        assert!(err.trace.iter().all(|t| t.contains("countdown")));
    }
}
