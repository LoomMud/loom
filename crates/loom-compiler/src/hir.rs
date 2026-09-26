// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed HIR: the output of name resolution + type checking, and the input
//! of V2 lowering (IR → register bytecode). Design notes: `docs/hir.md`.
//!
//! Invariants a well-formed HIR guarantees to its consumer:
//!
//! 1. **Every name is resolved.** Locals are dense [`LocalId`]s into
//!    [`Function::locals`]; program variables are [`GlobalRef`]s keyed by
//!    *(declaring program, name)*, the hot-reload migration key (§7.3);
//!    calls carry a [`Callee`] that says whether dispatch is virtual (by name
//!    on the object's current program) or static (a fixed program's body).
//! 2. **Every expression has a type** ([`Expr::ty`]); `Ty::Error` never
//!    appears (a program with diagnostics produces no HIR).
//! 3. **The gradual boundary is explicit.** Wherever a value flows from a
//!    less precise type (`any`, `[any]`, …) into a precise one, the checker
//!    wraps it in [`ExprKind::Cast`]; codegen emits a runtime check exactly
//!    there and nowhere else is a type check needed for soundness.
//! 4. **Operators are resolved to operand kinds** ([`OpKind`]), so codegen
//!    can pick typed instructions (`AddInt`, `AddStr`, …) and only
//!    [`OpKind::Dyn`] needs a dynamic dispatch.
//! 5. **Sugar is gone:** `else if` is a nested `If`, compound assignment
//!    keeps its operator but the place is evaluated once.
//!
//! Default arguments are filled **callee-side**: a call passes only the
//! arguments written at the call site and the callee's prologue evaluates
//! [`Param::default`] for the rest. That keeps defaults out of callers, so a
//! recompile that changes a default does not require re-linking callers.

use std::rc::Rc;

use loom_syntax::Span;
pub use loom_syntax::ast::{AssignOp, BinOp, UnOp};

use crate::efuns::Privilege;
use crate::ty::{EnumTy, StructTy, Ty};

/// Index into [`Function::locals`] (parameters first, in order).
pub type LocalId = u32;

/// One checked program (one source file).
#[derive(Clone, Debug)]
pub struct Program {
    /// Mudlib path without extension, e.g. `/std/room`.
    pub path: Rc<str>,
    /// Direct parents in source order.
    pub inherits: Vec<Inherit>,
    /// Every program whose variables an instance of this program holds, root
    /// first, each exactly once (virtual inheritance: a diamond shares one
    /// copy), ending with this program. Instance layout is per entry.
    pub linearization: Vec<Rc<str>>,
    /// `struct`/`enum` declared *here* (spec r5 §7.3, D27, OBI-88), in
    /// declaration order.
    pub structs: Vec<StructDecl>,
    pub enums: Vec<EnumDecl>,
    /// Program variables declared *here*, in declaration order.
    pub vars: Vec<Var>,
    /// `[vis] const NAME = expr` declared *here* (§5.3): a single value shared
    /// by every instance, computed once. Not part of the virtual-inherit
    /// graph and never migrated by hot reload.
    pub consts: Vec<Const>,
    /// Functions declared here, in declaration order.
    pub fns: Vec<Function>,
}

/// `[vis] struct Name { field: T [= default], … }` declared here. Codegen
/// currently has no bytecode for constructing/reading a struct value
/// (`check.rs` still rejects struct literals and field access as "not
/// implemented by codegen yet" — OBI-88 scope): this is the type-level
/// declaration only, exactly what a schema hash and `import` need.
#[derive(Clone, Debug)]
pub struct StructDecl {
    pub name: Rc<str>,
    pub vis: Visibility,
    pub ty: Rc<StructTy>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct EnumDecl {
    pub name: Rc<str>,
    pub vis: Visibility,
    pub ty: Rc<EnumTy>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct Inherit {
    /// `label` in `inherit label = /path`; `None` for an unlabelled inherit.
    pub label: Option<Rc<str>>,
    pub path: Rc<str>,
    pub span: Span,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    /// `pub`: callable from other objects via `ob.f()`.
    Public,
    /// Default: this program and inheritors.
    Internal,
    /// `private`: this program only; not inherited, not overridable.
    Private,
}

#[derive(Clone, Debug)]
pub struct Var {
    pub name: Rc<str>,
    pub ty: Ty,
    pub vis: Visibility,
    pub persistent: bool,
    /// Runs with `self` = the object, on creation and when a hot reload
    /// cannot keep the old value. `None` means `null` (only for nullable types).
    pub init: Option<Expr>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct Const {
    pub name: Rc<str>,
    pub ty: Ty,
    pub vis: Visibility,
    pub value: Expr,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct Function {
    pub name: Rc<str>,
    pub vis: Visibility,
    pub is_override: bool,
    /// `atomic fn` (spec r5 §5.2.1, OBI-32): every call to this function
    /// journals object-variable writes (including clone/destruct) and
    /// rolls them back all-or-nothing if the call ends by propagating an
    /// error out of it (an error caught *inside* the function's own body
    /// does not roll back — the function handled it and returned
    /// normally).
    pub atomic: bool,
    pub params: Vec<Param>,
    /// `Ty::Void` when the function has no `-> T`.
    pub ret: Ty,
    /// All locals of the body: parameters first, then every `let`/`var`/`for`
    /// binding in order of appearance. Ids are never reused, so the register
    /// allocator is free to share slots of disjoint scopes.
    pub locals: Vec<Local>,
    pub body: Block,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct Param {
    pub local: LocalId,
    pub default: Option<Expr>,
}

#[derive(Clone, Debug)]
pub struct Local {
    pub name: Rc<str>,
    /// Declared (or inferred) type. Flow narrowing never changes this; a
    /// narrowed *use* has the narrower type on its [`Expr`].
    pub ty: Ty,
    pub mutable: bool,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct Stmt {
    pub kind: StmtKind,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum StmtKind {
    /// Initialise a local. `None` initialises it to `null`.
    Let {
        local: LocalId,
        init: Option<Expr>,
    },
    /// `place = value` or `place op= value` (place evaluated once).
    Assign {
        place: Place,
        op: AssignOp,
        /// Operand kind of `op` for compound assignment (`Set` ignores it).
        kind: OpKind,
        value: Expr,
    },
    If {
        cond: Expr,
        then: Block,
        els: Option<Block>,
    },
    While {
        cond: Expr,
        body: Block,
    },
    /// Iterates a snapshot of `iter`.
    For {
        local: LocalId,
        iter: Expr,
        kind: IterKind,
        body: Block,
    },
    Return(Option<Expr>),
    /// `try { body } catch [catch_var] { handler }` (spec r5 §5.5.?, OBI-32).
    /// `catch_var`'s type is always `Ty::Any`: a `throw`n value keeps
    /// whatever type it was thrown at, and a caught built-in runtime error
    /// (not caused by an explicit `throw`) surfaces as a string message.
    /// Tick/depth exhaustion is not catchable (never reaches a handler).
    Try {
        body: Block,
        catch_var: Option<LocalId>,
        handler: Block,
    },
    /// `throw expr`: always diverges (never falls through).
    Throw(Expr),
    Expr(Expr),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IterKind {
    /// Elements of an array.
    Array,
    /// Keys of a map, in insertion order.
    MapKeys,
    /// Static type `any`: array or map decided at runtime.
    Dyn,
}

/// A writable location: a local, a program variable, or an element path
/// rooted in one (spec r5 §5.2.1 rule 1). `Index::base` is itself a
/// `Place`, not a plain `Expr`: under value semantics an element write must
/// be lowered as *take → mutate → put back* through every level of a
/// nested path (§5.2.1 rule 3), which needs the whole chain down to the
/// root variable, not just a value read of the immediate container.
#[derive(Clone, Debug)]
pub enum Place {
    Local(LocalId),
    /// The type is the checker's current type for this variable at this
    /// assignment site (its declared type, or narrower — HIR invariant 1);
    /// codegen needs it to `LoadGlobal`/`StoreGlobal` when this place is
    /// the root of a nested element write (§5.2.1 rule 3).
    Global(GlobalRef, Ty),
    Index {
        base: Box<Place>,
        index: Box<Expr>,
        kind: IndexKind,
    },
}

/// A program variable, keyed the way hot reload migrates state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GlobalRef {
    /// The program that declares the variable (not the one using it).
    pub owner: Rc<str>,
    pub name: Rc<str>,
}

#[derive(Clone, Debug)]
pub struct Expr {
    pub kind: ExprKind,
    pub ty: Ty,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum InterpPart {
    Lit(Rc<str>),
    /// Any type; codegen converts to string.
    Expr(Expr),
}

/// Operand kind of an operator, resolved from the operand types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpKind {
    Int,
    Float,
    Str,
    Bool,
    Array,
    Map,
    Object,
    /// `==`/`!=` between values of different static kinds that may still be
    /// equal (e.g. `object?` vs `null`): compare by value/identity at runtime.
    Generic,
    /// At least one operand is `any`: dispatch on the runtime values.
    Dyn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexKind {
    Array,
    String,
    /// Missing key reads as `null` (the expression has type `V?`).
    Map,
    /// The key was proven present by an enclosing `k in m` test (both plain
    /// locals, unassigned since). Type `V`; codegen must still raise a
    /// runtime error if the key vanished (e.g. removed by a call).
    MapPresent,
    Dyn,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Callee {
    /// Look `name` up on the running object's *current* program (virtual
    /// dispatch; hot-reload friendly).
    Virtual { name: Rc<str> },
    /// A specific program's body: private functions and `super::`/`label::`
    /// calls.
    Static { program: Rc<str>, name: Rc<str> },
}

#[derive(Clone, Debug)]
pub struct ClosureFn {
    pub params: Vec<LocalId>,
    /// `Ty::Void` when the closure has no `-> T` and no inferred expr body.
    pub ret: Ty,
    pub locals: Vec<Local>,
    pub body: Block,
    /// This closure's own local ids that must be preloaded, in order, from
    /// the captured-by-value snapshot taken at the `Closure` expression
    /// (spec r5 §5.2.2, OBI-79): index `i` here pairs with `Closure`'s
    /// `captures[i]` (the *outer* local being captured). Empty for a
    /// closure that captures nothing.
    pub captures: Vec<LocalId>,
}

#[derive(Clone, Debug)]
pub enum ExprKind {
    Int(i64),
    Float(f64),
    Str(Rc<str>),
    Bool(bool),
    Null,
    Interp(Vec<InterpPart>),
    Array(Vec<Expr>),
    Map(Vec<(Expr, Expr)>),
    /// A local, with the flow-narrowed type on the expression.
    Local(LocalId),
    Global(GlobalRef),
    /// `self` / `self()`.
    SelfObj,
    /// A function of this program used as a value (`add_verb("x", do_x)`).
    FnRef(Callee),
    /// A closure literal `fn(params) => …` / `fn(params) { … }` (spec r5
    /// §5.2.2, OBI-79): captures the enclosing function's locals **by
    /// value**, snapshotted at this expression. The second field is the
    /// *outer* local ids being captured, in the same order as
    /// `ClosureFn::captures` (the closure's own local ids that receive
    /// them).
    Closure(Rc<ClosureFn>, Vec<LocalId>),
    Index {
        base: Box<Expr>,
        index: Box<Expr>,
        kind: IndexKind,
    },
    Unary {
        op: UnOp,
        kind: OpKind,
        expr: Box<Expr>,
    },
    /// Arithmetic, comparison, `in`. `and`/`or`/`??` are separate nodes
    /// because they short-circuit.
    Binary {
        op: BinOp,
        kind: OpKind,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    /// `lhs ?? rhs`: `rhs` is evaluated only if `lhs` is null.
    Coalesce(Box<Expr>, Box<Expr>),
    /// Call a function of this program (or an ancestor). Only the written
    /// arguments are passed; see the module docs on defaults.
    Call {
        callee: Callee,
        args: Vec<Expr>,
    },
    /// Call a function value (a local of type `fn(...)` or `any`).
    CallValue {
        callee: Box<Expr>,
        args: Vec<Expr>,
    },
    /// Driver built-in. `privilege` is the efun's class (§5.5); the VM gates it.
    CallEfun {
        name: &'static str,
        privilege: Privilege,
        args: Vec<Expr>,
    },
    /// `recv.name(args)` / `recv?.name(args)`: late-bound call_other to a
    /// `pub` function. Result type is `any`.
    CallOther {
        recv: Box<Expr>,
        name: Rc<str>,
        args: Vec<Expr>,
        safe: bool,
    },
    /// Runtime-checked conversion to [`Expr::ty`] (the gradual boundary).
    Cast(Box<Expr>),
}
