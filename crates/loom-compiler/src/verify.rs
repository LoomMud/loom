// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Bytecode verifier: the last gate before a [`Module`] may run (spec
//! §5.8/§5.9). Checks, per function: every register index and jump target
//! is in bounds, every instruction's registers have the type the
//! instruction needs (typed ops), and every call's argument count matches
//! what the callee expects where the callee is known statically (an
//! in-module `Static` call, or a `CallEfun`).
//!
//! What this does *not* check (documented scope, not an oversight): a
//! `Virtual` call's target is resolved at runtime against the receiving
//! object's *current* program (that is the point of hot-reload-friendly
//! virtual dispatch), so its arity cannot be verified ahead of time here;
//! the VM's call path (OBI-31) must still check arity when it resolves the
//! target. Likewise a cross-program `Static` call (`super::`) needs the
//! parent module loaded to verify, which is a link-time step, not this
//! per-module pass.
//!
//! `verify` never trusts [`decode`](crate::bytecode::decode)'s output
//! either: `decode` only guarantees well-formed *encoding* (bounds on the
//! wire, valid tags, UTF-8), not that the resulting `Module` is
//! *well-typed*. Fed a `Module` built by hand (as the proptests and the
//! fuzz target do), `verify` must never panic or index out of bounds — it
//! returns `Err` for anything it cannot prove safe.

use crate::bytecode::{CalleeOp, ConstValue, FunctionCode, Module, Op};
use crate::efuns;
use crate::ir::{BinOp, OpKind, UnOp};
use crate::ty::Ty;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyError(pub String);

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for VerifyError {}

pub fn verify(m: &Module) -> Result<(), VerifyError> {
    for c in &m.consts {
        if let ConstValue::Str(s) = c
            && *s as usize >= m.strings.len()
        {
            return Err(VerifyError(format!("const string index {s} out of bounds")));
        }
    }
    for f in &m.functions {
        if f.name as usize >= m.strings.len() {
            return Err(VerifyError("function name index out of bounds".into()));
        }
        verify_function(m, f)
            .map_err(|e| VerifyError(format!("{}: {}", m.strings[f.name as usize], e.0)))?;
    }
    Ok(())
}

struct Cx<'a> {
    m: &'a Module,
    f: &'a FunctionCode,
}

fn verify_function(m: &Module, f: &FunctionCode) -> Result<(), VerifyError> {
    if f.params as usize > f.reg_types.len() {
        return Err(VerifyError("params exceeds register count".into()));
    }
    if f.min_arity > f.params {
        return Err(VerifyError("min_arity exceeds params".into()));
    }
    let want_entries = (f.params - f.min_arity + 1) as usize;
    if f.entry_points.len() != want_entries {
        return Err(VerifyError(format!(
            "expected {want_entries} entry point(s) (params - min_arity + 1), got {}",
            f.entry_points.len()
        )));
    }
    if f.code.is_empty() {
        return Err(VerifyError("empty function body".into()));
    }
    // OBI-231: `lines` is debug info, not required for a function to run,
    // but if present at all it must cover every instruction -- a partial
    // table would silently misattribute whichever instructions fall past
    // its end to "no line" instead of failing loudly, which is a worse
    // failure mode than rejecting the module outright. `decode` already
    // enforces this for anything that arrived over the wire; checking it
    // again here covers a `Module` assembled directly in-process too (the
    // same reasoning as every other check in this function).
    if !f.lines.is_empty() && f.lines.len() != f.code.len() {
        return Err(VerifyError(format!(
            "line table has {} entries, code has {}",
            f.lines.len(),
            f.code.len()
        )));
    }
    for &pc in &f.entry_points {
        if pc as usize >= f.code.len() {
            return Err(VerifyError(format!("entry point {pc:04} out of bounds")));
        }
    }
    let cx = Cx { m, f };
    for (pc, op) in f.code.iter().enumerate() {
        cx.op(pc as u32, op)
            .map_err(|e| VerifyError(format!("@{pc}: {}", e.0)))?;
    }
    Ok(())
}

impl Cx<'_> {
    fn reg(&self, r: u32) -> Result<&Ty, VerifyError> {
        self.f
            .reg_types
            .get(r as usize)
            .ok_or_else(|| VerifyError(format!("register %{r} out of bounds")))
    }

    fn str(&self, idx: u32) -> Result<&str, VerifyError> {
        self.m
            .strings
            .get(idx as usize)
            .map(|s| s.as_ref())
            .ok_or_else(|| VerifyError(format!("string index {idx} out of bounds")))
    }

    fn expect(&self, r: u32, want: &Ty) -> Result<(), VerifyError> {
        let got = self.reg(r)?;
        if got != want {
            return Err(VerifyError(format!("%{r} has type {got}, expected {want}")));
        }
        Ok(())
    }

    /// Like [`Self::expect`], but accepts a register whose type is a
    /// subtype of `want` (e.g. `string` where `string?` is expected): a
    /// value-boundary widening the checker allows without an explicit
    /// `Cast` (only *narrowing* needs one, HIR invariant 3), so the
    /// verifier must allow it too.
    fn expect_assignable(&self, r: u32, want: &Ty) -> Result<(), VerifyError> {
        let got = self.reg(r)?;
        if !got.assignable_to(want) {
            return Err(VerifyError(format!(
                "%{r} has type {got}, not assignable to {want}"
            )));
        }
        Ok(())
    }

    fn pc(&self, target: u32) -> Result<(), VerifyError> {
        if target as usize >= self.f.code.len() {
            return Err(VerifyError(format!(
                "jump target {target:04} out of bounds"
            )));
        }
        Ok(())
    }

    fn args(&self, args: &[u32]) -> Result<(), VerifyError> {
        for &a in args {
            self.reg(a)?;
        }
        Ok(())
    }

    fn op(&self, _pc: u32, op: &Op) -> Result<(), VerifyError> {
        match op {
            Op::LoadConst { dst, idx } => {
                let c = self
                    .m
                    .consts
                    .get(*idx as usize)
                    .ok_or_else(|| VerifyError(format!("const #{idx} out of bounds")))?;
                let want = match c {
                    ConstValue::Int(_) => Ty::Int,
                    ConstValue::Float(_) => Ty::Float,
                    ConstValue::Bool(_) => Ty::Bool,
                    ConstValue::Str(s) => {
                        if *s as usize >= self.m.strings.len() {
                            return Err(VerifyError(format!(
                                "const string index {s} out of bounds"
                            )));
                        }
                        Ty::String
                    }
                    ConstValue::Null => Ty::Null,
                };
                let got = self.reg(*dst)?;
                // A `null` constant may legitimately target any nullable
                // register (codegen materialises `Const Null` at the
                // register's real declared type, e.g. `object?`).
                if want == Ty::Null {
                    if !got.is_nullable() {
                        return Err(VerifyError(format!(
                            "%{dst} of type {got} cannot hold null"
                        )));
                    }
                } else {
                    self.expect(*dst, &want)?;
                }
                Ok(())
            }
            Op::Copy { dst, src } => {
                self.reg(*src)?;
                self.reg(*dst)?;
                Ok(())
            }
            Op::LoadSelf { dst } => self.expect(*dst, &Ty::Object),
            Op::LoadGlobal {
                dst,
                owner,
                name,
                ty,
            } => {
                self.str(*owner)?;
                self.str(*name)?;
                self.expect(*dst, ty)
            }
            Op::StoreGlobal {
                owner,
                name,
                ty,
                src,
            } => {
                self.str(*owner)?;
                self.str(*name)?;
                self.expect(*src, ty)
            }
            Op::UnOp { dst, op, kind, src } => self.un_op(*dst, *op, *kind, *src),
            Op::BinOp {
                dst,
                op,
                kind,
                a,
                b,
            } => self.bin_op(*dst, *op, *kind, *a, *b),
            Op::NewArray {
                dst,
                elem_ty,
                elems,
            } => {
                for &e in elems {
                    self.expect_assignable(e, elem_ty)?;
                }
                self.expect(*dst, &Ty::array(elem_ty.clone()))
            }
            Op::NewMap {
                dst,
                key_ty,
                val_ty,
                entries,
            } => {
                for (k, v) in entries {
                    self.expect_assignable(*k, key_ty)?;
                    self.expect_assignable(*v, val_ty)?;
                }
                self.expect(*dst, &Ty::map(key_ty.clone(), val_ty.clone()))
            }
            Op::Index {
                dst,
                base,
                index,
                kind,
            } => {
                self.reg(*base)?;
                self.reg(*index)?;
                self.reg(*dst)?;
                let _ = kind;
                Ok(())
            }
            Op::IndexSet {
                base,
                index,
                kind,
                src,
            } => {
                self.reg(*base)?;
                self.reg(*index)?;
                self.reg(*src)?;
                let _ = kind;
                Ok(())
            }
            Op::IndexSetGlobal {
                owner,
                name,
                index,
                kind,
                src,
            } => {
                self.str(*owner)?;
                self.str(*name)?;
                self.reg(*index)?;
                self.reg(*src)?;
                let _ = kind;
                Ok(())
            }
            Op::IterElems {
                dst,
                src,
                kind,
                elem_ty,
            } => {
                self.reg(*src)?;
                let _ = kind;
                self.expect(*dst, &Ty::array(elem_ty.clone()))
            }
            Op::ToStr { dst, src } => {
                self.reg(*src)?;
                self.expect(*dst, &Ty::String)
            }
            Op::Call { dst, callee, args } => {
                self.args(args)?;
                if let Some(d) = dst {
                    self.reg(*d)?;
                }
                match callee {
                    CalleeOp::Virtual { name } => {
                        self.str(*name)?;
                        Ok(())
                    }
                    CalleeOp::Static { program, name } => {
                        let program_name = self.str(*program)?;
                        let fn_name = self.str(*name)?;
                        if program_name == self.m.path.as_ref() {
                            let target = self
                                .m
                                .functions
                                .iter()
                                .find(|g| {
                                    self.m.strings.get(g.name as usize).map(|s| s.as_ref())
                                        == Some(fn_name)
                                })
                                .ok_or_else(|| {
                                    VerifyError(format!(
                                        "no such function `{fn_name}` in this module"
                                    ))
                                })?;
                            if args.len() < target.min_arity as usize
                                || args.len() > target.params as usize
                            {
                                return Err(VerifyError(format!(
                                    "`{fn_name}` takes {}..={} argument(s), got {}",
                                    target.min_arity,
                                    target.params,
                                    args.len()
                                )));
                            }
                            for (i, &a) in args.iter().enumerate() {
                                self.expect_assignable(a, &target.reg_types[i])?;
                            }
                            match dst {
                                Some(d) => {
                                    if target.ret == Ty::Void {
                                        return Err(VerifyError(format!(
                                            "`{fn_name}` returns no value but the call has a destination register"
                                        )));
                                    }
                                    self.expect_assignable(*d, &target.ret)?;
                                }
                                None => {
                                    if target.ret != Ty::Void {
                                        return Err(VerifyError(format!(
                                            "`{fn_name}`'s result is discarded but it returns {}",
                                            target.ret
                                        )));
                                    }
                                }
                            }
                        }
                        Ok(())
                    }
                }
            }
            Op::CallOther {
                dst,
                recv,
                name,
                args,
            } => {
                self.reg(*recv)?;
                self.str(*name)?;
                self.args(args)?;
                self.expect(*dst, &Ty::Any)
            }
            Op::CallEfun { dst, name, args } => {
                let fn_name = self.str(*name)?;
                let sig = efuns::lookup(fn_name)
                    .ok_or_else(|| VerifyError(format!("unknown efun `{fn_name}`")))?;
                if args.len() < sig.min_args || args.len() > sig.params.len() {
                    return Err(VerifyError(format!(
                        "efun `{fn_name}` takes {}..={} argument(s), got {}",
                        sig.min_args,
                        sig.params.len(),
                        args.len()
                    )));
                }
                self.args(args)?;
                let ret_ty = match &sig.ret {
                    efuns::Ret::Ty(t) => Some(t.clone()),
                    // The precise element type of `keys()` depends on the
                    // (dynamic-only) map argument type; not checked here.
                    efuns::Ret::KeysOf => None,
                };
                match (dst, ret_ty) {
                    (Some(_), Some(Ty::Void)) => Err(VerifyError(format!(
                        "efun `{fn_name}` returns no value but the call has a destination register"
                    ))),
                    (None, None) => Err(VerifyError(format!(
                        "efun `{fn_name}`'s result type is unresolved and it discards the result"
                    ))),
                    (Some(d), Some(t)) => self.expect(*d, &t),
                    (Some(d), None) => {
                        self.reg(*d)?;
                        Ok(())
                    }
                    (None, Some(Ty::Void)) => Ok(()),
                    (None, Some(t)) => Err(VerifyError(format!(
                        "efun `{fn_name}`'s result is discarded but it returns {t}"
                    ))),
                }
            }
            Op::Cast { dst, src, ty } => {
                self.reg(*src)?;
                self.expect(*dst, ty)
            }
            Op::Jump { target } => self.pc(*target),
            Op::Branch {
                cond,
                then_target,
                else_target,
            } => {
                self.expect(*cond, &Ty::Bool)?;
                self.pc(*then_target)?;
                self.pc(*else_target)
            }
            Op::Return { src } => match src {
                Some(r) => {
                    if self.f.ret == Ty::Void {
                        return Err(VerifyError(
                            "return has a value but the function is void".into(),
                        ));
                    }
                    self.expect_assignable(*r, &self.f.ret)
                }
                None => {
                    if self.f.ret != Ty::Void {
                        return Err(VerifyError(format!(
                            "return has no value but the function returns {}",
                            self.f.ret
                        )));
                    }
                    Ok(())
                }
            },
            Op::TickCheck => Ok(()),
            Op::Throw { src } => {
                self.reg(*src)?;
                Ok(())
            }
            Op::PushHandler {
                catch_pc,
                catch_reg,
            } => {
                self.pc(*catch_pc)?;
                if let Some(r) = catch_reg {
                    // The caught value is always dynamically typed (a
                    // `throw`n value keeps its own runtime type; a
                    // built-in runtime error surfaces as a string), so
                    // the handler's binding register must be `any`.
                    self.expect(*r, &Ty::Any)?;
                }
                Ok(())
            }
            Op::PopHandler => Ok(()),
            Op::MakeFn { dst, callee } => {
                match callee {
                    CalleeOp::Virtual { name } => {
                        self.str(*name)?;
                    }
                    CalleeOp::Static { program, name } => {
                        self.str(*program)?;
                        self.str(*name)?;
                    }
                }
                match self.reg(*dst)? {
                    Ty::Fn(_) => Ok(()),
                    other => Err(VerifyError(format!(
                        "%{dst} has type {other}, expected a function type"
                    ))),
                }
            }
            Op::MakeClosure {
                dst,
                func,
                captures,
            } => {
                let target = self
                    .m
                    .functions
                    .get(*func as usize)
                    .ok_or_else(|| VerifyError(format!("closure #{func} out of bounds")))?;
                if captures.len() != target.capture_targets.len() {
                    return Err(VerifyError(format!(
                        "closure #{func} expects {} capture(s), got {}",
                        target.capture_targets.len(),
                        captures.len()
                    )));
                }
                for (&src, &t_reg) in captures.iter().zip(&target.capture_targets) {
                    let want = target.reg_types.get(t_reg as usize).ok_or_else(|| {
                        VerifyError(format!(
                            "closure #{func}'s capture target register %{t_reg} out of bounds"
                        ))
                    })?;
                    self.expect_assignable(src, want)?;
                }
                match self.reg(*dst)? {
                    Ty::Fn(_) => Ok(()),
                    other => Err(VerifyError(format!(
                        "%{dst} has type {other}, expected a function type"
                    ))),
                }
            }
            Op::CallValue { dst, func, args } => {
                self.args(args)?;
                let func_ty = self.reg(*func)?.clone();
                match &func_ty {
                    Ty::Fn(sig) => {
                        if args.len() != sig.params.len() {
                            return Err(VerifyError(format!(
                                "function value takes {} argument(s), got {}",
                                sig.params.len(),
                                args.len()
                            )));
                        }
                        for (i, &a) in args.iter().enumerate() {
                            self.expect_assignable(a, &sig.params[i])?;
                        }
                        match dst {
                            Some(d) => {
                                if sig.ret == Ty::Void {
                                    return Err(VerifyError(
                                        "function value returns no value but the call has a destination register".into(),
                                    ));
                                }
                                self.expect_assignable(*d, &sig.ret)?;
                            }
                            None => {
                                if sig.ret != Ty::Void {
                                    return Err(VerifyError(format!(
                                        "function value's result is discarded but it returns {}",
                                        sig.ret
                                    )));
                                }
                            }
                        }
                        Ok(())
                    }
                    Ty::Any => {
                        if let Some(d) = dst {
                            self.reg(*d)?;
                        }
                        Ok(())
                    }
                    other => Err(VerifyError(format!(
                        "%{func} has type {other}, expected a function type"
                    ))),
                }
            }
        }
    }

    fn un_op(&self, dst: u32, op: UnOp, kind: OpKind, src: u32) -> Result<(), VerifyError> {
        match (op, kind) {
            (UnOp::Neg, OpKind::Int) => {
                self.expect(src, &Ty::Int)?;
                self.expect(dst, &Ty::Int)
            }
            (UnOp::Neg, OpKind::Float) => {
                self.expect(src, &Ty::Float)?;
                self.expect(dst, &Ty::Float)
            }
            (UnOp::Not, OpKind::Bool) => {
                self.expect(src, &Ty::Bool)?;
                self.expect(dst, &Ty::Bool)
            }
            (_, OpKind::Dyn) => {
                self.reg(src)?;
                self.expect(dst, &Ty::Any)
            }
            _ => Err(VerifyError(format!("{op:?} is not defined for {kind:?}"))),
        }
    }

    fn bin_op(&self, dst: u32, op: BinOp, kind: OpKind, a: u32, b: u32) -> Result<(), VerifyError> {
        let is_compare = matches!(
            op,
            BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge
        );
        if is_compare {
            self.expect(dst, &Ty::Bool)?;
            return match kind {
                OpKind::Int => {
                    self.expect(a, &Ty::Int)?;
                    self.expect(b, &Ty::Int)
                }
                OpKind::Float => {
                    self.expect(a, &Ty::Float)?;
                    self.expect(b, &Ty::Float)
                }
                OpKind::Str => {
                    self.expect(a, &Ty::String)?;
                    self.expect(b, &Ty::String)
                }
                OpKind::Bool if matches!(op, BinOp::Eq | BinOp::Ne) => {
                    self.expect(a, &Ty::Bool)?;
                    self.expect(b, &Ty::Bool)
                }
                // Generic/Dyn/Object/Array/Map: a runtime comparison between
                // possibly-different static kinds (e.g. `object?` vs
                // `null`); only bounds-checked here.
                _ => {
                    self.reg(a)?;
                    self.reg(b)?;
                    Ok(())
                }
            };
        }
        match op {
            BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Rem => match kind {
                OpKind::Int => {
                    self.expect(a, &Ty::Int)?;
                    self.expect(b, &Ty::Int)?;
                    self.expect(dst, &Ty::Int)
                }
                OpKind::Float => {
                    self.expect(a, &Ty::Float)?;
                    self.expect(b, &Ty::Float)?;
                    self.expect(dst, &Ty::Float)
                }
                OpKind::Str if matches!(op, BinOp::Add) => {
                    self.expect(a, &Ty::String)?;
                    self.expect(b, &Ty::String)?;
                    self.expect(dst, &Ty::String)
                }
                // `[T] + [T]` (spec r5 arrays have value semantics, `+=`
                // is concatenation): `a`/`b`/`dst` must be the exact same
                // array type — the checker (`check.rs`) only ever picks
                // `OpKind::Array` for `BinOp::Add` when it already unified
                // both operands to one element type.
                OpKind::Array if matches!(op, BinOp::Add) => match self.reg(a)?.clone() {
                    want @ Ty::Array(_) => {
                        self.expect(b, &want)?;
                        self.expect(dst, &want)
                    }
                    other => Err(VerifyError(format!(
                        "%{a} has type {other}, expected an array"
                    ))),
                },
                OpKind::Dyn => {
                    self.reg(a)?;
                    self.reg(b)?;
                    self.expect(dst, &Ty::Any)
                }
                // Array concatenation (`xs += [x]`, spec r5 §5.2.1): the
                // checker's `arith()` only allows `Add` between two arrays
                // with consistent element types, so the verifier need only
                // confirm the operand and result *shapes* line up, the same
                // looseness `Dyn` gets above (element-type consistency was
                // already checked when this bytecode was produced).
                OpKind::Array if matches!(op, BinOp::Add) => {
                    match self.reg(a)? {
                        Ty::Array(_) => {}
                        t => {
                            return Err(VerifyError(format!(
                                "%{a} has type {t}, expected an array"
                            )));
                        }
                    }
                    match self.reg(b)? {
                        Ty::Array(_) => {}
                        t => {
                            return Err(VerifyError(format!(
                                "%{b} has type {t}, expected an array"
                            )));
                        }
                    }
                    match self.reg(dst)? {
                        Ty::Array(_) => Ok(()),
                        t => Err(VerifyError(format!(
                            "%{dst} has type {t}, expected an array"
                        ))),
                    }
                }
                _ => Err(VerifyError(format!("{op:?} is not defined for {kind:?}"))),
            },
            BinOp::In => {
                self.reg(a)?;
                self.reg(b)?;
                self.expect(dst, &Ty::Bool)
            }
            BinOp::And | BinOp::Or => {
                self.expect(a, &Ty::Bool)?;
                self.expect(b, &Ty::Bool)?;
                self.expect(dst, &Ty::Bool)
            }
            BinOp::Coalesce => {
                self.reg(a)?;
                self.reg(b)?;
                self.reg(dst)?;
                Ok(())
            }
            _ => unreachable!("comparisons handled above"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::{FunctionCode, Op};
    use std::rc::Rc;

    fn m1(f: FunctionCode) -> Module {
        Module {
            path: Rc::from("/t"),
            strings: vec![Rc::from("f")],
            consts: vec![],
            functions: vec![f],
        }
    }

    #[test]
    fn accepts_trivial_void_return() {
        let f = FunctionCode {
            name: 0,
            atomic: false,
            params: 0,
            min_arity: 0,
            ret: Ty::Void,
            reg_types: vec![],
            entry_points: vec![0],
            code: vec![Op::Return { src: None }].into(),
            lines: Vec::new(),
            capture_targets: vec![],
        };
        assert!(verify(&m1(f)).is_ok());
    }

    #[test]
    fn rejects_out_of_bounds_register() {
        let f = FunctionCode {
            name: 0,
            atomic: false,
            params: 0,
            min_arity: 0,
            ret: Ty::Int,
            reg_types: vec![Ty::Int],
            entry_points: vec![0],
            code: vec![Op::Return { src: Some(7) }].into(),
            lines: Vec::new(),
            capture_targets: vec![],
        };
        assert!(verify(&m1(f)).is_err());
    }

    #[test]
    fn rejects_type_mismatch_on_return() {
        let f = FunctionCode {
            name: 0,
            atomic: false,
            params: 0,
            min_arity: 0,
            ret: Ty::String,
            reg_types: vec![Ty::Int],
            entry_points: vec![0],
            code: vec![Op::Return { src: Some(0) }].into(),
            lines: Vec::new(),
            capture_targets: vec![],
        };
        assert!(verify(&m1(f)).is_err());
    }

    #[test]
    fn rejects_out_of_bounds_jump() {
        let f = FunctionCode {
            name: 0,
            atomic: false,
            params: 0,
            min_arity: 0,
            ret: Ty::Void,
            reg_types: vec![],
            entry_points: vec![0],
            code: vec![Op::Jump { target: 5 }].into(),
            lines: Vec::new(),
            capture_targets: vec![],
        };
        assert!(verify(&m1(f)).is_err());
    }

    #[test]
    fn rejects_bad_binop_kind() {
        let f = FunctionCode {
            name: 0,
            atomic: false,
            params: 0,
            min_arity: 0,
            ret: Ty::Void,
            reg_types: vec![Ty::Int, Ty::String],
            entry_points: vec![0],
            code: vec![
                Op::BinOp {
                    dst: 1,
                    op: BinOp::Add,
                    kind: OpKind::Int,
                    a: 0,
                    b: 0,
                },
                Op::Return { src: None },
            ]
            .into(),
            lines: Vec::new(),
            capture_targets: vec![],
        };
        // dst is typed `string` but Add.Int must produce `int`.
        assert!(verify(&m1(f)).is_err());
    }

    #[test]
    fn accepts_array_concatenation_xs_plus_eq() {
        // `xs += [x]` (spec r5 §5.2.1): Add.Array between two arrays,
        // producing an array.
        let f = FunctionCode {
            name: 0,
            atomic: false,
            params: 0,
            min_arity: 0,
            ret: Ty::Void,
            reg_types: vec![Ty::array(Ty::Int), Ty::array(Ty::Int), Ty::array(Ty::Int)],
            entry_points: vec![0],
            code: vec![
                Op::BinOp {
                    dst: 2,
                    op: BinOp::Add,
                    kind: OpKind::Array,
                    a: 0,
                    b: 1,
                },
                Op::Return { src: None },
            ]
            .into(),
            lines: Vec::new(),
            capture_targets: vec![],
        };
        assert!(verify(&m1(f)).is_ok());
    }

    #[test]
    fn rejects_array_add_with_a_non_array_operand() {
        let f = FunctionCode {
            name: 0,
            atomic: false,
            params: 0,
            min_arity: 0,
            ret: Ty::Void,
            reg_types: vec![Ty::array(Ty::Int), Ty::Int, Ty::array(Ty::Int)],
            entry_points: vec![0],
            code: vec![
                Op::BinOp {
                    dst: 2,
                    op: BinOp::Add,
                    kind: OpKind::Array,
                    a: 0,
                    b: 1,
                },
                Op::Return { src: None },
            ]
            .into(),
            lines: Vec::new(),
            capture_targets: vec![],
        };
        assert!(verify(&m1(f)).is_err());
    }

    #[test]
    fn accepts_arithmetic_matching_types() {
        let f = FunctionCode {
            name: 0,
            atomic: false,
            params: 0,
            min_arity: 0,
            ret: Ty::Int,
            reg_types: vec![Ty::Int, Ty::Int, Ty::Int],
            entry_points: vec![0],
            code: vec![
                Op::BinOp {
                    dst: 2,
                    op: BinOp::Add,
                    kind: OpKind::Int,
                    a: 0,
                    b: 1,
                },
                Op::Return { src: Some(2) },
            ]
            .into(),
            lines: Vec::new(),
            capture_targets: vec![],
        };
        assert!(verify(&m1(f)).is_ok());
    }
}
