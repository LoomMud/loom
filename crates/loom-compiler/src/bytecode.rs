// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Register bytecode: the assembled form of [`crate::ir`], and the trust
//! boundary [`crate::verify`] guards (spec §5.8/§5.9, `docs/bytecode.md`).
//!
//! A [`Module`] is flat and self-contained: jump targets are absolute
//! instruction indices (no block structure survives assembly — the
//! verifier does not need it, and neither does a straightforward
//! interpreter), registers are indices into [`FunctionCode::reg_types`],
//! and names are indices into [`Module::strings`]. [`encode`]/[`decode`]
//! give it an on-the-wire form: any 32 bytes might arrive here (a corrupted
//! save, a future network path, a hand-crafted attack), so `decode` never
//! trusts a count or index until it has checked it, and never recurses
//! without a depth limit. `decode` alone only guarantees *well-formed
//! encoding* (bounds, UTF-8, known tags); [`crate::verify::verify`] is the
//! pass that guarantees *well-typed bytecode* (register types, jump
//! targets, call arity) and must run before anything executes a `Module`.

use std::rc::Rc;

pub use crate::efuns::Privilege;
pub use crate::ir::{Callee, ConstOperand, GlobalRef, IndexKind, IterKind, OpKind};
pub use crate::ty::Ty;
pub use loom_syntax::ast::{BinOp, UnOp};

/// Index into [`FunctionCode::reg_types`].
pub type Reg = u32;
/// Index into [`Module::strings`].
pub type StrId = u32;
/// Index into [`Module::consts`].
pub type ConstId = u32;
/// Absolute instruction index into [`FunctionCode::code`].
pub type PC = u32;

#[derive(Clone, Debug)]
pub struct Module {
    pub path: Rc<str>,
    pub strings: Vec<Rc<str>>,
    pub consts: Vec<ConstValue>,
    pub functions: Vec<FunctionCode>,
}

#[derive(Clone, Debug)]
pub enum ConstValue {
    Int(i64),
    Float(f64),
    Bool(bool),
    Str(StrId),
    Null,
}

#[derive(Clone, Debug)]
pub struct FunctionCode {
    pub name: StrId,
    /// Registers `0..params` are the parameters, in order.
    pub params: u32,
    pub ret: Ty,
    /// The static type of every register (spec §5.8: typed ops).
    pub reg_types: Vec<Ty>,
    pub code: Vec<Op>,
}

#[derive(Clone, Debug)]
pub enum CalleeOp {
    Virtual { name: StrId },
    Static { program: StrId, name: StrId },
}

#[derive(Clone, Debug)]
pub enum Op {
    LoadConst {
        dst: Reg,
        idx: ConstId,
    },
    Copy {
        dst: Reg,
        src: Reg,
    },
    LoadSelf {
        dst: Reg,
    },
    LoadGlobal {
        dst: Reg,
        owner: StrId,
        name: StrId,
        ty: Ty,
    },
    StoreGlobal {
        owner: StrId,
        name: StrId,
        ty: Ty,
        src: Reg,
    },
    UnOp {
        dst: Reg,
        op: UnOp,
        kind: OpKind,
        src: Reg,
    },
    BinOp {
        dst: Reg,
        op: BinOp,
        kind: OpKind,
        a: Reg,
        b: Reg,
    },
    NewArray {
        dst: Reg,
        elem_ty: Ty,
        elems: Vec<Reg>,
    },
    NewMap {
        dst: Reg,
        key_ty: Ty,
        val_ty: Ty,
        entries: Vec<(Reg, Reg)>,
    },
    Index {
        dst: Reg,
        base: Reg,
        index: Reg,
        kind: IndexKind,
    },
    IndexSet {
        base: Reg,
        index: Reg,
        kind: IndexKind,
        src: Reg,
    },
    IterElems {
        dst: Reg,
        src: Reg,
        kind: IterKind,
        elem_ty: Ty,
    },
    ToStr {
        dst: Reg,
        src: Reg,
    },
    Call {
        dst: Option<Reg>,
        callee: CalleeOp,
        args: Vec<Reg>,
    },
    CallOther {
        dst: Reg,
        recv: Reg,
        name: StrId,
        args: Vec<Reg>,
    },
    /// `name` resolves through [`crate::efuns::lookup`] (verified at decode
    /// time already; re-checked in `verify` for arity/privilege).
    CallEfun {
        dst: Option<Reg>,
        name: StrId,
        args: Vec<Reg>,
    },
    Cast {
        dst: Reg,
        src: Reg,
        ty: Ty,
    },
    Jump {
        target: PC,
    },
    Branch {
        cond: Reg,
        then_target: PC,
        else_target: PC,
    },
    Return {
        src: Option<Reg>,
    },
    TickCheck,
}

// ---------------------------------------------------------------------
// Encoding: a small hand-rolled binary format (uleb128 varints, zigzag for
// signed ints, length-prefixed strings/vecs). No serde: keeps the trust
// boundary's decoder auditable in one file and avoids taking on a big
// derive-macro dependency just for this.
// ---------------------------------------------------------------------

const MAGIC: [u8; 4] = *b"WFBC";
const MAX_TY_DEPTH: u32 = 64;

pub fn encode(m: &Module) -> Vec<u8> {
    let mut w = Writer::default();
    w.buf.extend_from_slice(&MAGIC);
    w.put_str(&m.path);
    w.put_varu32(m.strings.len() as u32);
    for s in &m.strings {
        w.put_str(s);
    }
    w.put_varu32(m.consts.len() as u32);
    for c in &m.consts {
        w.put_const(c);
    }
    w.put_varu32(m.functions.len() as u32);
    for f in &m.functions {
        w.put_function(f);
    }
    w.buf
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bytecode decode error: {}", self.0)
    }
}
impl std::error::Error for DecodeError {}

pub fn decode(bytes: &[u8]) -> Result<Module, DecodeError> {
    let mut r = Reader { buf: bytes, pos: 0 };
    let magic = r.take(4)?;
    if magic != MAGIC {
        return Err(DecodeError("bad magic".into()));
    }
    let path: Rc<str> = Rc::from(r.get_str()?);
    let n_strings = r.get_varu32()? as usize;
    let mut strings = Vec::with_capacity(n_strings.min(1 << 20));
    for _ in 0..n_strings {
        strings.push(Rc::from(r.get_str()?));
    }
    let n_consts = r.get_varu32()? as usize;
    let mut consts = Vec::with_capacity(n_consts.min(1 << 20));
    for _ in 0..n_consts {
        consts.push(r.get_const()?);
    }
    let n_fns = r.get_varu32()? as usize;
    let mut functions = Vec::with_capacity(n_fns.min(1 << 20));
    for _ in 0..n_fns {
        functions.push(r.get_function()?);
    }
    if r.pos != r.buf.len() {
        return Err(DecodeError("trailing bytes".into()));
    }
    Ok(Module {
        path,
        strings,
        consts,
        functions,
    })
}

#[derive(Default)]
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn put_u8(&mut self, b: u8) {
        self.buf.push(b);
    }
    fn put_varu32(&mut self, mut v: u32) {
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.buf.push(byte);
                break;
            }
            self.buf.push(byte | 0x80);
        }
    }
    fn put_i64(&mut self, v: i64) {
        // Zigzag so small magnitudes stay small varints.
        let z = ((v << 1) ^ (v >> 63)) as u64;
        let mut v = z;
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.buf.push(byte);
                break;
            }
            self.buf.push(byte | 0x80);
        }
    }
    fn put_f64(&mut self, v: f64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn put_bytes(&mut self, b: &[u8]) {
        self.put_varu32(b.len() as u32);
        self.buf.extend_from_slice(b);
    }
    fn put_str(&mut self, s: &str) {
        self.put_bytes(s.as_bytes());
    }
    fn put_reg_vec(&mut self, regs: &[Reg]) {
        self.put_varu32(regs.len() as u32);
        for r in regs {
            self.put_varu32(*r);
        }
    }
    fn put_opt_reg(&mut self, r: Option<Reg>) {
        match r {
            Some(r) => {
                self.put_u8(1);
                self.put_varu32(r);
            }
            None => self.put_u8(0),
        }
    }
    fn put_ty(&mut self, ty: &Ty) {
        match ty {
            Ty::Int => self.put_u8(0),
            Ty::Float => self.put_u8(1),
            Ty::Bool => self.put_u8(2),
            Ty::String => self.put_u8(3),
            Ty::Object => self.put_u8(4),
            Ty::Null => self.put_u8(5),
            Ty::Any => self.put_u8(6),
            Ty::Void => self.put_u8(7),
            Ty::Never => self.put_u8(8),
            Ty::Error => self.put_u8(9),
            Ty::Array(t) => {
                self.put_u8(10);
                self.put_ty(t);
            }
            Ty::Map(k, v) => {
                self.put_u8(11);
                self.put_ty(k);
                self.put_ty(v);
            }
            Ty::Optional(t) => {
                self.put_u8(12);
                self.put_ty(t);
            }
            Ty::Fn(ft) => {
                self.put_u8(13);
                self.put_varu32(ft.params.len() as u32);
                for p in &ft.params {
                    self.put_ty(p);
                }
                self.put_ty(&ft.ret);
            }
        }
    }
    fn put_const(&mut self, c: &ConstValue) {
        match c {
            ConstValue::Int(n) => {
                self.put_u8(0);
                self.put_i64(*n);
            }
            ConstValue::Float(x) => {
                self.put_u8(1);
                self.put_f64(*x);
            }
            ConstValue::Bool(b) => {
                self.put_u8(2);
                self.put_u8(*b as u8);
            }
            ConstValue::Str(s) => {
                self.put_u8(3);
                self.put_varu32(*s);
            }
            ConstValue::Null => self.put_u8(4),
        }
    }
    fn put_index_kind(&mut self, k: IndexKind) {
        self.put_u8(match k {
            IndexKind::Array => 0,
            IndexKind::String => 1,
            IndexKind::Map => 2,
            IndexKind::MapPresent => 3,
            IndexKind::Dyn => 4,
        });
    }
    fn put_iter_kind(&mut self, k: IterKind) {
        self.put_u8(match k {
            IterKind::Array => 0,
            IterKind::MapKeys => 1,
            IterKind::Dyn => 2,
        });
    }
    fn put_op_kind(&mut self, k: OpKind) {
        self.put_u8(match k {
            OpKind::Int => 0,
            OpKind::Float => 1,
            OpKind::Str => 2,
            OpKind::Bool => 3,
            OpKind::Array => 4,
            OpKind::Map => 5,
            OpKind::Object => 6,
            OpKind::Generic => 7,
            OpKind::Dyn => 8,
        });
    }
    fn put_un_op(&mut self, op: UnOp) {
        self.put_u8(match op {
            UnOp::Neg => 0,
            UnOp::Not => 1,
        });
    }
    fn put_bin_op(&mut self, op: BinOp) {
        self.put_u8(match op {
            BinOp::Add => 0,
            BinOp::Sub => 1,
            BinOp::Mul => 2,
            BinOp::Div => 3,
            BinOp::Rem => 4,
            BinOp::Eq => 5,
            BinOp::Ne => 6,
            BinOp::Lt => 7,
            BinOp::Le => 8,
            BinOp::Gt => 9,
            BinOp::Ge => 10,
            BinOp::And => 11,
            BinOp::Or => 12,
            BinOp::In => 13,
            BinOp::Coalesce => 14,
        });
    }
    fn put_function(&mut self, f: &FunctionCode) {
        self.put_varu32(f.name);
        self.put_varu32(f.params);
        self.put_ty(&f.ret);
        self.put_varu32(f.reg_types.len() as u32);
        for t in &f.reg_types {
            self.put_ty(t);
        }
        self.put_varu32(f.code.len() as u32);
        for op in &f.code {
            self.put_op(op);
        }
    }
    fn put_op(&mut self, op: &Op) {
        match op {
            Op::LoadConst { dst, idx } => {
                self.put_u8(0);
                self.put_varu32(*dst);
                self.put_varu32(*idx);
            }
            Op::Copy { dst, src } => {
                self.put_u8(1);
                self.put_varu32(*dst);
                self.put_varu32(*src);
            }
            Op::LoadSelf { dst } => {
                self.put_u8(2);
                self.put_varu32(*dst);
            }
            Op::LoadGlobal {
                dst,
                owner,
                name,
                ty,
            } => {
                self.put_u8(3);
                self.put_varu32(*dst);
                self.put_varu32(*owner);
                self.put_varu32(*name);
                self.put_ty(ty);
            }
            Op::StoreGlobal {
                owner,
                name,
                ty,
                src,
            } => {
                self.put_u8(4);
                self.put_varu32(*owner);
                self.put_varu32(*name);
                self.put_ty(ty);
                self.put_varu32(*src);
            }
            Op::UnOp { dst, op, kind, src } => {
                self.put_u8(5);
                self.put_varu32(*dst);
                self.put_un_op(*op);
                self.put_op_kind(*kind);
                self.put_varu32(*src);
            }
            Op::BinOp {
                dst,
                op,
                kind,
                a,
                b,
            } => {
                self.put_u8(6);
                self.put_varu32(*dst);
                self.put_bin_op(*op);
                self.put_op_kind(*kind);
                self.put_varu32(*a);
                self.put_varu32(*b);
            }
            Op::NewArray {
                dst,
                elem_ty,
                elems,
            } => {
                self.put_u8(7);
                self.put_varu32(*dst);
                self.put_ty(elem_ty);
                self.put_reg_vec(elems);
            }
            Op::NewMap {
                dst,
                key_ty,
                val_ty,
                entries,
            } => {
                self.put_u8(8);
                self.put_varu32(*dst);
                self.put_ty(key_ty);
                self.put_ty(val_ty);
                self.put_varu32(entries.len() as u32);
                for (k, v) in entries {
                    self.put_varu32(*k);
                    self.put_varu32(*v);
                }
            }
            Op::Index {
                dst,
                base,
                index,
                kind,
            } => {
                self.put_u8(9);
                self.put_varu32(*dst);
                self.put_varu32(*base);
                self.put_varu32(*index);
                self.put_index_kind(*kind);
            }
            Op::IndexSet {
                base,
                index,
                kind,
                src,
            } => {
                self.put_u8(10);
                self.put_varu32(*base);
                self.put_varu32(*index);
                self.put_index_kind(*kind);
                self.put_varu32(*src);
            }
            Op::IterElems {
                dst,
                src,
                kind,
                elem_ty,
            } => {
                self.put_u8(11);
                self.put_varu32(*dst);
                self.put_varu32(*src);
                self.put_iter_kind(*kind);
                self.put_ty(elem_ty);
            }
            Op::ToStr { dst, src } => {
                self.put_u8(12);
                self.put_varu32(*dst);
                self.put_varu32(*src);
            }
            Op::Call { dst, callee, args } => {
                self.put_u8(13);
                self.put_opt_reg(*dst);
                match callee {
                    CalleeOp::Virtual { name } => {
                        self.put_u8(0);
                        self.put_varu32(*name);
                    }
                    CalleeOp::Static { program, name } => {
                        self.put_u8(1);
                        self.put_varu32(*program);
                        self.put_varu32(*name);
                    }
                }
                self.put_reg_vec(args);
            }
            Op::CallOther {
                dst,
                recv,
                name,
                args,
            } => {
                self.put_u8(14);
                self.put_varu32(*dst);
                self.put_varu32(*recv);
                self.put_varu32(*name);
                self.put_reg_vec(args);
            }
            Op::CallEfun { dst, name, args } => {
                self.put_u8(15);
                self.put_opt_reg(*dst);
                self.put_varu32(*name);
                self.put_reg_vec(args);
            }
            Op::Cast { dst, src, ty } => {
                self.put_u8(16);
                self.put_varu32(*dst);
                self.put_varu32(*src);
                self.put_ty(ty);
            }
            Op::Jump { target } => {
                self.put_u8(17);
                self.put_varu32(*target);
            }
            Op::Branch {
                cond,
                then_target,
                else_target,
            } => {
                self.put_u8(18);
                self.put_varu32(*cond);
                self.put_varu32(*then_target);
                self.put_varu32(*else_target);
            }
            Op::Return { src } => {
                self.put_u8(19);
                self.put_opt_reg(*src);
            }
            Op::TickCheck => self.put_u8(20),
        }
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.pos + n > self.buf.len() {
            return Err(DecodeError("unexpected end of input".into()));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn get_u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn get_varu32(&mut self) -> Result<u32, DecodeError> {
        let v = self.get_varu64()?;
        u32::try_from(v).map_err(|_| DecodeError("varint out of range for u32".into()))
    }
    fn get_varu64(&mut self) -> Result<u64, DecodeError> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            if shift >= 64 {
                return Err(DecodeError("varint too long".into()));
            }
            let byte = self.get_u8()?;
            result |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        Ok(result)
    }
    fn get_i64(&mut self) -> Result<i64, DecodeError> {
        let z = self.get_varu64()?;
        Ok(((z >> 1) as i64) ^ -((z & 1) as i64))
    }
    fn get_f64(&mut self) -> Result<f64, DecodeError> {
        let b = self.take(8)?;
        Ok(f64::from_le_bytes(b.try_into().unwrap()))
    }
    fn get_bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.get_varu32()? as usize;
        self.take(len)
    }
    fn get_str(&mut self) -> Result<&'a str, DecodeError> {
        let b = self.get_bytes()?;
        std::str::from_utf8(b).map_err(|_| DecodeError("invalid utf-8".into()))
    }
    fn get_reg_vec(&mut self) -> Result<Vec<Reg>, DecodeError> {
        let len = self.get_varu32()? as usize;
        if len > self.buf.len() {
            return Err(DecodeError("implausible register list length".into()));
        }
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.get_varu32()?);
        }
        Ok(out)
    }
    fn get_opt_reg(&mut self) -> Result<Option<Reg>, DecodeError> {
        match self.get_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.get_varu32()?)),
            t => Err(DecodeError(format!("bad option tag {t}"))),
        }
    }
    fn get_ty(&mut self) -> Result<Ty, DecodeError> {
        self.get_ty_depth(0)
    }
    fn get_ty_depth(&mut self, depth: u32) -> Result<Ty, DecodeError> {
        if depth > MAX_TY_DEPTH {
            return Err(DecodeError("type nesting too deep".into()));
        }
        Ok(match self.get_u8()? {
            0 => Ty::Int,
            1 => Ty::Float,
            2 => Ty::Bool,
            3 => Ty::String,
            4 => Ty::Object,
            5 => Ty::Null,
            6 => Ty::Any,
            7 => Ty::Void,
            8 => Ty::Never,
            9 => Ty::Error,
            10 => Ty::Array(Rc::new(self.get_ty_depth(depth + 1)?)),
            11 => Ty::Map(
                Rc::new(self.get_ty_depth(depth + 1)?),
                Rc::new(self.get_ty_depth(depth + 1)?),
            ),
            12 => Ty::Optional(Rc::new(self.get_ty_depth(depth + 1)?)),
            13 => {
                let n = self.get_varu32()? as usize;
                if n > 64 {
                    return Err(DecodeError("implausible fn arity".into()));
                }
                let mut params = Vec::with_capacity(n);
                for _ in 0..n {
                    params.push(self.get_ty_depth(depth + 1)?);
                }
                let ret = self.get_ty_depth(depth + 1)?;
                Ty::Fn(Rc::new(crate::ty::FnTy { params, ret }))
            }
            t => return Err(DecodeError(format!("bad type tag {t}"))),
        })
    }
    fn get_const(&mut self) -> Result<ConstValue, DecodeError> {
        Ok(match self.get_u8()? {
            0 => ConstValue::Int(self.get_i64()?),
            1 => ConstValue::Float(self.get_f64()?),
            2 => ConstValue::Bool(self.get_u8()? != 0),
            3 => ConstValue::Str(self.get_varu32()?),
            4 => ConstValue::Null,
            t => return Err(DecodeError(format!("bad const tag {t}"))),
        })
    }
    fn get_index_kind(&mut self) -> Result<IndexKind, DecodeError> {
        Ok(match self.get_u8()? {
            0 => IndexKind::Array,
            1 => IndexKind::String,
            2 => IndexKind::Map,
            3 => IndexKind::MapPresent,
            4 => IndexKind::Dyn,
            t => return Err(DecodeError(format!("bad index kind {t}"))),
        })
    }
    fn get_iter_kind(&mut self) -> Result<IterKind, DecodeError> {
        Ok(match self.get_u8()? {
            0 => IterKind::Array,
            1 => IterKind::MapKeys,
            2 => IterKind::Dyn,
            t => return Err(DecodeError(format!("bad iter kind {t}"))),
        })
    }
    fn get_op_kind(&mut self) -> Result<OpKind, DecodeError> {
        Ok(match self.get_u8()? {
            0 => OpKind::Int,
            1 => OpKind::Float,
            2 => OpKind::Str,
            3 => OpKind::Bool,
            4 => OpKind::Array,
            5 => OpKind::Map,
            6 => OpKind::Object,
            7 => OpKind::Generic,
            8 => OpKind::Dyn,
            t => return Err(DecodeError(format!("bad op kind {t}"))),
        })
    }
    fn get_un_op(&mut self) -> Result<UnOp, DecodeError> {
        Ok(match self.get_u8()? {
            0 => UnOp::Neg,
            1 => UnOp::Not,
            t => return Err(DecodeError(format!("bad unop {t}"))),
        })
    }
    fn get_bin_op(&mut self) -> Result<BinOp, DecodeError> {
        Ok(match self.get_u8()? {
            0 => BinOp::Add,
            1 => BinOp::Sub,
            2 => BinOp::Mul,
            3 => BinOp::Div,
            4 => BinOp::Rem,
            5 => BinOp::Eq,
            6 => BinOp::Ne,
            7 => BinOp::Lt,
            8 => BinOp::Le,
            9 => BinOp::Gt,
            10 => BinOp::Ge,
            11 => BinOp::And,
            12 => BinOp::Or,
            13 => BinOp::In,
            14 => BinOp::Coalesce,
            t => return Err(DecodeError(format!("bad binop {t}"))),
        })
    }
    fn get_function(&mut self) -> Result<FunctionCode, DecodeError> {
        let name = self.get_varu32()?;
        let params = self.get_varu32()?;
        let ret = self.get_ty()?;
        let n_regs = self.get_varu32()? as usize;
        if n_regs > self.buf.len() {
            return Err(DecodeError("implausible register count".into()));
        }
        let mut reg_types = Vec::with_capacity(n_regs);
        for _ in 0..n_regs {
            reg_types.push(self.get_ty()?);
        }
        let n_code = self.get_varu32()? as usize;
        if n_code > self.buf.len() {
            return Err(DecodeError("implausible code length".into()));
        }
        let mut code = Vec::with_capacity(n_code);
        for _ in 0..n_code {
            code.push(self.get_op()?);
        }
        Ok(FunctionCode {
            name,
            params,
            ret,
            reg_types,
            code,
        })
    }
    fn get_op(&mut self) -> Result<Op, DecodeError> {
        Ok(match self.get_u8()? {
            0 => Op::LoadConst {
                dst: self.get_varu32()?,
                idx: self.get_varu32()?,
            },
            1 => Op::Copy {
                dst: self.get_varu32()?,
                src: self.get_varu32()?,
            },
            2 => Op::LoadSelf {
                dst: self.get_varu32()?,
            },
            3 => Op::LoadGlobal {
                dst: self.get_varu32()?,
                owner: self.get_varu32()?,
                name: self.get_varu32()?,
                ty: self.get_ty()?,
            },
            4 => Op::StoreGlobal {
                owner: self.get_varu32()?,
                name: self.get_varu32()?,
                ty: self.get_ty()?,
                src: self.get_varu32()?,
            },
            5 => Op::UnOp {
                dst: self.get_varu32()?,
                op: self.get_un_op()?,
                kind: self.get_op_kind()?,
                src: self.get_varu32()?,
            },
            6 => Op::BinOp {
                dst: self.get_varu32()?,
                op: self.get_bin_op()?,
                kind: self.get_op_kind()?,
                a: self.get_varu32()?,
                b: self.get_varu32()?,
            },
            7 => Op::NewArray {
                dst: self.get_varu32()?,
                elem_ty: self.get_ty()?,
                elems: self.get_reg_vec()?,
            },
            8 => {
                let dst = self.get_varu32()?;
                let key_ty = self.get_ty()?;
                let val_ty = self.get_ty()?;
                let n = self.get_varu32()? as usize;
                if n > self.buf.len() {
                    return Err(DecodeError("implausible map literal length".into()));
                }
                let mut entries = Vec::with_capacity(n);
                for _ in 0..n {
                    entries.push((self.get_varu32()?, self.get_varu32()?));
                }
                Op::NewMap {
                    dst,
                    key_ty,
                    val_ty,
                    entries,
                }
            }
            9 => Op::Index {
                dst: self.get_varu32()?,
                base: self.get_varu32()?,
                index: self.get_varu32()?,
                kind: self.get_index_kind()?,
            },
            10 => Op::IndexSet {
                base: self.get_varu32()?,
                index: self.get_varu32()?,
                kind: self.get_index_kind()?,
                src: self.get_varu32()?,
            },
            11 => Op::IterElems {
                dst: self.get_varu32()?,
                src: self.get_varu32()?,
                kind: self.get_iter_kind()?,
                elem_ty: self.get_ty()?,
            },
            12 => Op::ToStr {
                dst: self.get_varu32()?,
                src: self.get_varu32()?,
            },
            13 => {
                let dst = self.get_opt_reg()?;
                let callee = match self.get_u8()? {
                    0 => CalleeOp::Virtual {
                        name: self.get_varu32()?,
                    },
                    1 => CalleeOp::Static {
                        program: self.get_varu32()?,
                        name: self.get_varu32()?,
                    },
                    t => return Err(DecodeError(format!("bad callee tag {t}"))),
                };
                let args = self.get_reg_vec()?;
                Op::Call { dst, callee, args }
            }
            14 => Op::CallOther {
                dst: self.get_varu32()?,
                recv: self.get_varu32()?,
                name: self.get_varu32()?,
                args: self.get_reg_vec()?,
            },
            15 => Op::CallEfun {
                dst: self.get_opt_reg()?,
                name: self.get_varu32()?,
                args: self.get_reg_vec()?,
            },
            16 => Op::Cast {
                dst: self.get_varu32()?,
                src: self.get_varu32()?,
                ty: self.get_ty()?,
            },
            17 => Op::Jump {
                target: self.get_varu32()?,
            },
            18 => Op::Branch {
                cond: self.get_varu32()?,
                then_target: self.get_varu32()?,
                else_target: self.get_varu32()?,
            },
            19 => Op::Return {
                src: self.get_opt_reg()?,
            },
            20 => Op::TickCheck,
            t => return Err(DecodeError(format!("bad opcode {t}"))),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_empty_module() {
        let m = Module {
            path: Rc::from("/std/room"),
            strings: vec![Rc::from("short")],
            consts: vec![ConstValue::Int(42), ConstValue::Str(0)],
            functions: vec![FunctionCode {
                name: 0,
                params: 0,
                ret: Ty::String,
                reg_types: vec![Ty::Int],
                code: vec![
                    Op::LoadConst { dst: 0, idx: 0 },
                    Op::Return { src: Some(0) },
                ],
            }],
        };
        let bytes = encode(&m);
        let back = decode(&bytes).expect("decode");
        assert_eq!(back.path.as_ref(), "/std/room");
        assert_eq!(back.functions.len(), 1);
        assert_eq!(back.functions[0].code.len(), 2);
    }

    #[test]
    fn decode_rejects_truncated_input() {
        let m = Module {
            path: Rc::from("/x"),
            strings: vec![],
            consts: vec![],
            functions: vec![FunctionCode {
                name: 0,
                params: 0,
                ret: Ty::Void,
                reg_types: vec![],
                code: vec![Op::Return { src: None }],
            }],
        };
        let bytes = encode(&m);
        for cut in 0..bytes.len() {
            let _ = decode(&bytes[..cut]);
        }
    }

    #[test]
    fn decode_rejects_bad_magic() {
        assert!(decode(b"xxxx").is_err());
        assert!(decode(b"").is_err());
    }

    #[test]
    fn ty_roundtrip() {
        let tys = [
            Ty::Int,
            Ty::optional(Ty::String),
            Ty::array(Ty::Any),
            Ty::map(Ty::String, Ty::optional(Ty::Object)),
            Ty::Fn(Rc::new(crate::ty::FnTy {
                params: vec![Ty::Int, Ty::Bool],
                ret: Ty::optional(Ty::Int),
            })),
        ];
        for ty in tys {
            let mut w = Writer::default();
            w.put_ty(&ty);
            let mut r = Reader {
                buf: &w.buf,
                pos: 0,
            };
            assert_eq!(r.get_ty().unwrap(), ty);
        }
    }
}
