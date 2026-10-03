// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! SSA-lite IR: the lowering target of the typed HIR, and the input to
//! bytecode assembly (spec §5.8/§5.9; design notes `docs/hir.md`,
//! `docs/bytecode.md`).
//!
//! "SSA-lite": every *temporary* register is written exactly once along any
//! execution path (true SSA for expression evaluation), but a register that
//! backs a mutable local or a branch-join result may be written from more
//! than one predecessor block — there are no phi nodes. This keeps codegen
//! a straightforward one-pass lowering (no dominance/phi placement) while
//! still giving every register a single static type for its whole lifetime,
//! which is what the verifier (`crate::verify`) checks. A later register
//! allocator or Cranelift tier can re-derive real SSA from this IR (each
//! block is already a maximal straight-line unit with one terminator), so
//! this is not a dead end for a JIT (Q15).
//!
//! Control flow is a graph of [`Block`]s ending in one [`Terminator`]; there
//! is no `break`/`continue` because the V1 HIR does not have them yet.
//! [`Inst::TickCheck`] marks the two places metering must not skip (§5.9):
//! the header of every loop (a back-edge target) and immediately before
//! every call (`Call`, `CallOther`, `CallEfun`) that could re-enter Weft
//! code or run unboundedly long.

use std::rc::Rc;

pub use crate::efuns::Privilege;
pub use crate::hir::{GlobalRef, IndexKind, IterKind, OpKind};
pub use crate::ty::Ty;
pub use loom_syntax::ast::{BinOp, UnOp};

/// A virtual register: dense, never reused, one static [`Ty`] for its whole
/// life (see the module docs). Index into [`Function::reg_types`].
pub type Reg = u32;

/// Index into [`Function::blocks`].
pub type BlockId = u32;

#[derive(Clone, Debug)]
pub struct Program {
    pub path: Rc<str>,
    pub functions: Vec<Function>,
}

#[derive(Clone, Debug)]
pub struct Function {
    pub name: Rc<str>,
    /// `atomic fn` (spec r5 §5.2.1): see `hir::Function::atomic`.
    pub atomic: bool,
    /// Registers `0..param_count` are the parameters, in order.
    pub param_count: u32,
    /// Number of leading parameters that are required (no default); see
    /// [`crate::bytecode::FunctionCode::min_arity`].
    pub min_arity: u32,
    pub ret: Ty,
    /// The static type of every register, indexed by [`Reg`].
    pub reg_types: Vec<Ty>,
    pub blocks: Vec<Block>,
    pub entry: BlockId,
    /// Entry block ids, indexed by `args_passed - min_arity`; see
    /// [`crate::bytecode::FunctionCode::entry_points`]. Length is always
    /// `param_count - min_arity + 1`; the last entry is always `entry`.
    pub default_entries: Vec<BlockId>,
    /// This function's own register ids that a [`Inst::MakeClosure`]
    /// referencing it must preload from its captured-by-value snapshot,
    /// before the callee's normal parameter prologue runs (spec r5
    /// §5.2.2, OBI-79). Empty for every function that is not a closure
    /// body.
    pub capture_targets: Vec<Reg>,
}

#[derive(Clone, Debug, Default)]
pub struct Block {
    pub insts: Vec<Inst>,
    /// 1-based source line for each entry of [`Self::insts`] (OBI-231,
    /// spec: the error inbox's `(program, line, message)` grouping), same
    /// length as `insts` always; `0` means "no span tracked this far"
    /// (never emitted by `codegen` today -- `FnLower` always has a current
    /// statement span by the time it emits anything -- but a future
    /// synthetic `Inst` with no source counterpart could still choose it).
    pub lines: Vec<u32>,
    pub term: Terminator,
    /// Source line for `term`'s assembled `Op` (see [`Self::lines`]).
    pub term_line: u32,
}

#[derive(Clone, Debug, Default)]
pub enum Terminator {
    #[default]
    Unset,
    Jump(BlockId),
    Branch {
        cond: Reg,
        then_blk: BlockId,
        else_blk: BlockId,
    },
    Return(Option<Reg>),
    /// `throw src` (spec r5 OBI-32): always transfers control, either to
    /// the nearest active handler on this frame's handler stack or, if
    /// none, to the caller as an `RtError` (uncaught throw). Never falls
    /// through, like `Return`.
    Throw(Reg),
}

#[derive(Clone, Debug)]
pub enum ConstOperand {
    Int(i64),
    Float(f64),
    Str(Rc<str>),
    Bool(bool),
    Null,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Callee {
    Virtual { name: Rc<str> },
    Static { program: Rc<str>, name: Rc<str> },
}

#[derive(Clone, Debug)]
pub enum Inst {
    Const {
        dst: Reg,
        value: ConstOperand,
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
        global: GlobalRef,
        ty: Ty,
    },
    StoreGlobal {
        global: GlobalRef,
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
    /// See `bytecode::Op::IndexSetGlobal` (OBI-108).
    IndexSetGlobal {
        global: GlobalRef,
        index: Reg,
        kind: IndexKind,
        src: Reg,
    },
    /// The array of elements to walk for a `for` loop (spec §5.3): identity
    /// for [`IterKind::Array`], `keys(src)` for [`IterKind::MapKeys`], a
    /// runtime check of `src`'s actual value kind for [`IterKind::Dyn`].
    IterElems {
        dst: Reg,
        src: Reg,
        kind: IterKind,
        elem_ty: Ty,
    },
    /// `any` → `string`, for interpolation (`$"...{e}..."`).
    ToStr {
        dst: Reg,
        src: Reg,
    },
    Call {
        dst: Option<Reg>,
        callee: Callee,
        args: Vec<Reg>,
    },
    /// `recv.name(args)`. Always produces `any`; `safe` (`?.`) is already
    /// lowered to a branch around this instruction by codegen, so by the
    /// time it reaches IR `recv` is known non-null on this path.
    CallOther {
        dst: Reg,
        recv: Reg,
        name: Rc<str>,
        args: Vec<Reg>,
    },
    CallEfun {
        dst: Option<Reg>,
        name: &'static str,
        args: Vec<Reg>,
    },
    /// A named function reference used as a value (`add_verb("x", do_x)`,
    /// spec r5 §5.2.2, OBI-79): no captures. Late-bound at call time — see
    /// `Inst::CallValue`.
    MakeFn {
        dst: Reg,
        callee: Callee,
    },
    /// An anonymous closure literal (spec r5 §5.2.2, OBI-79): `func` is the
    /// index (into this program's *flattened* function list — named
    /// functions first, then every closure body found anywhere in the
    /// program, in the order they were lowered) of the closure's body;
    /// `captures` are this function's registers to snapshot **by value**
    /// right now, in the order `Function::capture_targets` on that body
    /// expects them.
    MakeClosure {
        dst: Reg,
        func: u32,
        captures: Vec<Reg>,
    },
    /// Call a function *value* (`f(args)` where `f` is a local of type
    /// `fn(...)` or `any`): late-bound, spec r5 §5.2.2. `func` is not
    /// necessarily known statically; the VM resolves it from the runtime
    /// value itself (a named reference, or a pinned closure body).
    CallValue {
        dst: Option<Reg>,
        func: Reg,
        args: Vec<Reg>,
    },
    /// Runtime-checked conversion to `ty` (the gradual boundary, HIR
    /// invariant 3).
    Cast {
        dst: Reg,
        src: Reg,
        ty: Ty,
    },
    /// Tick-metering checkpoint (§5.9); see the module docs for placement.
    TickCheck,
    /// Push a `try`/`catch` handler onto this frame's handler stack: while
    /// active, a catchable error raised anywhere in this call chain (this
    /// frame or any frame it calls into) unwinds straight to `catch_blk`
    /// with the thrown/synthesised value in `catch_reg` (spec r5 OBI-32).
    /// Paired with a [`Inst::PopHandler`] at the end of the guarded region
    /// on every path that falls through normally.
    PushHandler {
        catch_blk: BlockId,
        catch_reg: Option<Reg>,
    },
    /// Pop the innermost handler pushed by [`Inst::PushHandler`] in this
    /// frame (the `try` region completed without throwing).
    PopHandler,
}
