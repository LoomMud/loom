// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Weft abstract syntax tree. Every node carries a [`Span`].

use crate::diag::Span;

/// One source file = one program (§3.4).
#[derive(Clone, Debug, PartialEq)]
pub struct Program {
    pub inherit: Option<Inherit>,
    pub items: Vec<Item>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Inherit {
    /// Mudlib path without extension, e.g. `/std/room`.
    pub path: String,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Item {
    Var(VarDecl),
    Fn(FnDecl),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Modifiers {
    pub is_pub: bool,
    pub is_private: bool,
    pub persistent: bool,
    pub is_override: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ident {
    pub name: String,
    pub span: Span,
}

/// Program-level variable: `[pub|private] [persistent] var name: T = expr`.
#[derive(Clone, Debug, PartialEq)]
pub struct VarDecl {
    pub mods: Modifiers,
    pub name: Ident,
    pub ty: Option<Type>,
    pub init: Option<Expr>,
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
    Bool,
    String,
    Object,
    Any,
    Null,
    Array(Box<Type>),
    Map(Box<Type>, Box<Type>),
    Optional(Box<Type>),
    /// A name the Phase 0 subset does not know (reported by the checker).
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
    For {
        var: Ident,
        iter: Expr,
        body: Block,
    },
    While {
        cond: Expr,
        body: Block,
    },
    Return(Option<Expr>),
    Expr(Expr),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Else {
    Block(Block),
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

#[derive(Clone, Debug, PartialEq)]
pub enum ExprKind {
    Int(i64),
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
    Unary {
        op: UnOp,
        expr: Box<Expr>,
    },
    Binary {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    /// `name(args)`: a function of this program (or inherited), else an efun.
    Call {
        name: Ident,
        args: Vec<Expr>,
    },
    /// `super::name(args)`
    SuperCall {
        name: Ident,
        args: Vec<Expr>,
    },
    /// `recv.name(args)` / `recv?.name(args)`: late-bound call_other.
    Method {
        recv: Box<Expr>,
        name: Ident,
        args: Vec<Expr>,
        safe: bool,
    },
    /// Placeholder produced by error recovery; never reaches the evaluator
    /// because programs with diagnostics are rejected.
    Error,
}
