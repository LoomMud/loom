// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Weft abstract syntax tree (spec v2 §5.3, v1 grammar). Every node carries a
//! [`Span`]. The tree is purely syntactic: names are not resolved and types
//! are not checked (that is `loom-compiler`'s job), so e.g. `a.b` is a
//! [`ExprKind::Field`] whether `a` turns out to be a struct or an enum.

use crate::diag::Span;

/// One source file = one program (§3.4).
#[derive(Clone, Debug, PartialEq)]
pub struct Program {
    /// `lightweight` header: instances are GC'd, unnamed values (§5.2).
    pub lightweight: Option<Span>,
    /// Every `inherit`, in source order (§5.4 multiple inheritance).
    pub inherits: Vec<Inherit>,
    pub imports: Vec<Import>,
    pub items: Vec<Item>,
}

/// `inherit /std/item` or `inherit combat = /std/mixins/combat`.
#[derive(Clone, Debug, PartialEq)]
pub struct Inherit {
    /// Label for `label::fn()` calls into this parent.
    pub label: Option<Ident>,
    /// Mudlib path without extension, e.g. `/std/room`.
    pub path: String,
    pub path_span: Span,
    pub span: Span,
}

/// `import /include/damage` or `import /include/damage.{DamageKind, Damage}`.
#[derive(Clone, Debug, PartialEq)]
pub struct Import {
    pub path: String,
    pub path_span: Span,
    /// Selected names; `None` imports the whole module.
    pub names: Option<Vec<Ident>>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Item {
    Var(VarDecl),
    Const(ConstDecl),
    Fn(FnDecl),
    Struct(StructDecl),
    Enum(EnumDecl),
}

impl Item {
    pub fn span(&self) -> Span {
        match self {
            Item::Var(d) => d.span,
            Item::Const(d) => d.span,
            Item::Fn(d) => d.span,
            Item::Struct(d) => d.span,
            Item::Enum(d) => d.span,
        }
    }

    pub fn name(&self) -> &Ident {
        match self {
            Item::Var(d) => &d.name,
            Item::Const(d) => &d.name,
            Item::Fn(d) => &d.name,
            Item::Struct(d) => &d.name,
            Item::Enum(d) => &d.name,
        }
    }
}

/// Declaration modifiers. The parser guarantees at most one visibility
/// (`pub`/`protected`/`private`) and that each flag suits the item kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Modifiers {
    pub is_pub: bool,
    pub is_protected: bool,
    pub is_private: bool,
    /// Variables only: saved by save/restore and snapshots.
    pub persistent: bool,
    /// Functions only.
    pub is_override: bool,
    /// Functions only: cannot be overridden.
    pub is_final: bool,
    /// Functions only: DGD-style all-or-nothing execution.
    pub atomic: bool,
    /// Span of the first modifier keyword, if any.
    pub span: Option<Span>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ident {
    pub name: String,
    pub span: Span,
}

/// Program-level variable: `[vis] [persistent] var name: T = expr`.
#[derive(Clone, Debug, PartialEq)]
pub struct VarDecl {
    pub mods: Modifiers,
    pub name: Ident,
    pub ty: Option<Type>,
    pub init: Option<Expr>,
    pub span: Span,
}

/// `[vis] const NAME[: T] = expr`.
#[derive(Clone, Debug, PartialEq)]
pub struct ConstDecl {
    pub mods: Modifiers,
    pub name: Ident,
    pub ty: Option<Type>,
    pub value: Expr,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FnDecl {
    pub mods: Modifiers,
    pub name: Ident,
    pub params: Vec<Param>,
    pub ret: Option<Type>,
    pub body: Block,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Param {
    pub name: Ident,
    pub ty: Option<Type>,
    pub default: Option<Expr>,
    /// `...name`: collects the remaining positional arguments (always last).
    pub rest: bool,
    pub span: Span,
}

/// `[vis] struct Name { field: T [= default], … }`.
#[derive(Clone, Debug, PartialEq)]
pub struct StructDecl {
    pub mods: Modifiers,
    pub name: Ident,
    pub fields: Vec<FieldDecl>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FieldDecl {
    pub name: Ident,
    pub ty: Type,
    pub default: Option<Expr>,
    pub span: Span,
}

/// `[vis] enum Name { A, B(int), … }`.
#[derive(Clone, Debug, PartialEq)]
pub struct EnumDecl {
    pub mods: Modifiers,
    pub name: Ident,
    pub variants: Vec<VariantDecl>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VariantDecl {
    pub name: Ident,
    /// Positional payload types; empty for a plain tag.
    pub payload: Vec<Type>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Type {
    pub kind: TypeKind,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeKind {
    Int,
    Float,
    Bool,
    String,
    Object,
    Any,
    Null,
    /// The built-in `error` value (kind, message, trace).
    Error,
    Array(Box<Type>),
    Map(Box<Type>, Box<Type>),
    Optional(Box<Type>),
    /// `fn(A, B) -> R`; `ret` is `None` for `fn(A)` (returns nothing).
    Fn {
        params: Vec<Type>,
        ret: Option<Box<Type>>,
    },
    /// A struct, enum or imported name (resolved by the compiler).
    Named(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Stmt {
    pub kind: StmtKind,
    pub span: Span,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssignOp {
    Set,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
}

#[derive(Clone, Debug, PartialEq)]
pub enum StmtKind {
    /// `let x: T = e` (immutable) or `var x: T = e` (mutable) local.
    Local {
        mutable: bool,
        name: Ident,
        ty: Option<Type>,
        init: Option<Expr>,
    },
    /// `target op value`; `target` is an identifier, index or field.
    Assign {
        target: Expr,
        op: AssignOp,
        value: Expr,
    },
    If {
        cond: Expr,
        then: Block,
        els: Option<Box<Else>>,
    },
    /// `if let name[: T] = value { … } else { … }`: runs `then` with `name`
    /// bound when `value` is not `null` (narrows `T?` to `T`).
    IfLet {
        name: Ident,
        ty: Option<Type>,
        value: Expr,
        then: Block,
        els: Option<Box<Else>>,
    },
    For {
        var: Ident,
        iter: Expr,
        body: Block,
    },
    While {
        cond: Expr,
        body: Block,
    },
    Break,
    Continue,
    Return(Option<Expr>),
    /// `try { … } catch [e] { … }`.
    Try {
        body: Block,
        catch_var: Option<Ident>,
        handler: Block,
    },
    Throw(Expr),
    Expr(Expr),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Else {
    Block(Block),
    /// `else if …` / `else if let …`: always an `If` or `IfLet` statement.
    If(Stmt),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Expr {
    pub kind: ExprKind,
    pub span: Span,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnOp {
    Neg,
    Not,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    In,
    Coalesce,
}

#[derive(Clone, Debug, PartialEq)]
pub enum InterpPart {
    Lit(String),
    Expr(Expr),
}

/// One call argument: positional `e`, named `name: e`, or spread `...e`.
#[derive(Clone, Debug, PartialEq)]
pub struct Arg {
    pub name: Option<Ident>,
    pub spread: bool,
    pub value: Expr,
    pub span: Span,
}

/// `name: value` in a struct literal.
#[derive(Clone, Debug, PartialEq)]
pub struct FieldInit {
    pub name: Ident,
    pub value: Expr,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Closure {
    pub params: Vec<Param>,
    pub ret: Option<Type>,
    pub body: Body,
}

/// Body of a closure or `match` arm: `=> expr` or `{ block }`.
#[derive(Clone, Debug, PartialEq)]
pub enum Body {
    Expr(Box<Expr>),
    Block(Block),
}

#[derive(Clone, Debug, PartialEq)]
pub struct MatchArm {
    pub pat: Pattern,
    pub guard: Option<Expr>,
    pub body: Body,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Pattern {
    pub kind: PatKind,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PatKind {
    /// `_`
    Wild,
    /// A plain name binds the scrutinee.
    Bind(String),
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    Null,
    /// `.A`, `.B(p, …)`, `Kind.A`, `Kind.B(p, …)`.
    Variant {
        enum_name: Option<Ident>,
        name: Ident,
        /// `None` for a plain tag, `Some` for a payload pattern list.
        fields: Option<Vec<Pattern>>,
    },
    /// `p | q | …`
    Or(Vec<Pattern>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum ExprKind {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    Null,
    Interp(Vec<InterpPart>),
    Array(Vec<Expr>),
    Map(Vec<(Expr, Expr)>),
    Ident(String),
    Index {
        base: Box<Expr>,
        index: Box<Expr>,
    },
    /// `base[lo..hi]`, either bound optional.
    Slice {
        base: Box<Expr>,
        lo: Option<Box<Expr>>,
        hi: Option<Box<Expr>>,
    },
    /// `base.name` / `base?.name`: struct field or qualified enum variant.
    Field {
        base: Box<Expr>,
        name: Ident,
        safe: bool,
    },
    Unary {
        op: UnOp,
        expr: Box<Expr>,
    },
    Binary {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    /// `expr as T`
    Cast {
        expr: Box<Expr>,
        ty: Type,
    },
    /// `name(args)`: a function of this program (or inherited), a local
    /// closure, or an efun.
    Call {
        name: Ident,
        args: Vec<Arg>,
    },
    /// `super::name(args)` (`label: None`) or `label::name(args)` for a
    /// labelled inherit.
    SuperCall {
        label: Option<Ident>,
        name: Ident,
        args: Vec<Arg>,
    },
    /// `recv.name(args)` / `recv?.name(args)`: late-bound call_other (or an
    /// enum variant constructor `Kind.B(x)`; the compiler decides).
    Method {
        recv: Box<Expr>,
        name: Ident,
        args: Vec<Arg>,
        safe: bool,
    },
    /// `callee(args)` where `callee` is not a plain name, e.g. `fs[0](x)`.
    Apply {
        callee: Box<Expr>,
        args: Vec<Arg>,
    },
    Closure(Box<Closure>),
    Match {
        scrutinee: Box<Expr>,
        arms: Vec<MatchArm>,
    },
    /// `Name { field: e, … }`
    StructLit {
        name: Ident,
        fields: Vec<FieldInit>,
    },
    /// `.name` / `.name(args)`: enum variant with the enum inferred from the
    /// expected type (`var kind: DamageKind = .slash`).
    Variant {
        name: Ident,
        args: Option<Vec<Arg>>,
    },
    /// Placeholder produced by error recovery; never reaches a backend
    /// because programs with diagnostics are rejected.
    Error,
}
