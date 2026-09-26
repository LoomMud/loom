// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Recursive-descent + Pratt parser for the Phase 0 Weft subset.
//!
//! Error recovery works on statement boundaries (newline, `;`, `}`) inside
//! function bodies and on item boundaries (`fn`, `var`, modifiers at the start
//! of a line) at the top level, so one typo yields one diagnostic rather than a
//! cascade. The parser never panics; nesting is bounded by [`MAX_DEPTH`] so
//! hostile input cannot overflow the stack.

use crate::ast::*;
use crate::diag::{Diagnostic, Span};
use crate::lexer::{Piece, Tok, Token, lex, lex_range};

/// Maximum nesting of blocks/expressions before the parser gives up.
pub const MAX_DEPTH: u32 = 96;
/// Stop collecting diagnostics after this many (the rest are cascades).
const MAX_DIAGS: usize = 50;

/// Parse a whole source file. Returns the (possibly partial) AST and all
/// diagnostics; a program is only runnable when the diagnostics are empty.
pub fn parse(src: &str) -> (Program, Vec<Diagnostic>) {
    let (toks, mut diags) = lex(src);
    let mut p = Parser {
        src,
        toks,
        pos: 0,
        diags: Vec::new(),
        depth: 0,
        abort_block: false,
    };
    let prog = p.program();
    diags.append(&mut p.diags);
    diags.sort_by_key(|d| d.span.start);
    diags.truncate(MAX_DIAGS);
    (prog, diags)
}

/// Marker: a diagnostic has already been recorded.
struct Fail;
type PResult<T> = Result<T, Fail>;

struct Parser<'a> {
    src: &'a str,
    toks: Vec<Token>,
    pos: usize,
    diags: Vec<Diagnostic>,
    depth: u32,
    /// Set when a block was found unclosed at the next declaration: every
    /// enclosing block unwinds silently to item level (one diagnostic, not N).
    abort_block: bool,
}

const UNSUPPORTED: &[(&str, &str)] = &[
    ("import", "use `inherit` for code reuse in Phase 0"),
    ("const", "use a `var` for now"),
    ("enum", "use strings or ints for now"),
    ("struct", "use a map `{string: any}` for now"),
    ("atomic", "atomic functions arrive with the Phase 1 VM"),
    ("try", "runtime errors abort the execution in Phase 0"),
    ("catch", "runtime errors abort the execution in Phase 0"),
    ("throw", "runtime errors abort the execution in Phase 0"),
    ("match", "use `if` / `else if` for now"),
    (
        "protected",
        "use the default (internal) visibility or `private`",
    ),
    ("final", "`final` arrives with the Phase 1 compiler"),
];

fn unsupported_hint(name: &str) -> Option<&'static str> {
    UNSUPPORTED
        .iter()
        .find(|(k, _)| *k == name)
        .map(|(_, h)| *h)
}

impl Parser<'_> {
    // ---- token helpers -------------------------------------------------

    fn peek(&self) -> &Tok {
        &self.toks[self.pos.min(self.toks.len() - 1)].tok
    }

    fn peek_at(&self, n: usize) -> &Tok {
        &self.toks[(self.pos + n).min(self.toks.len() - 1)].tok
    }

    fn span(&self) -> Span {
        self.toks[self.pos.min(self.toks.len() - 1)].span
    }

    fn prev_span(&self) -> Span {
        if self.pos == 0 {
            Span::default()
        } else {
            self.toks[(self.pos - 1).min(self.toks.len() - 1)].span
        }
    }

    fn bump(&mut self) -> Token {
        let t = self.toks[self.pos.min(self.toks.len() - 1)].clone();
        if self.pos < self.toks.len() - 1 {
            self.pos += 1;
        }
        t
    }

    fn at(&self, t: &Tok) -> bool {
        self.peek() == t
    }

    fn eat(&mut self, t: &Tok) -> bool {
        if self.at(t) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn skip_nl(&mut self) {
        while self.at(&Tok::Newline) {
            self.bump();
        }
    }

    fn error(&mut self, span: Span, msg: impl Into<String>) -> Fail {
        self.diags.push(Diagnostic::error(span, msg));
        Fail
    }

    fn error_hint(&mut self, span: Span, msg: impl Into<String>, hint: impl Into<String>) -> Fail {
        self.diags
            .push(Diagnostic::error(span, msg).with_hint(hint));
        Fail
    }

    fn expected(&mut self, what: &str) -> Fail {
        let found = self.peek().describe();
        let span = self.span();
        self.error(span, format!("expected {what}, found {found}"))
    }

    fn expect(&mut self, t: &Tok, what: &str) -> PResult<Span> {
        if self.at(t) {
            Ok(self.bump().span)
        } else {
            Err(self.expected(what))
        }
    }

    fn ident(&mut self, what: &str) -> PResult<Ident> {
        if let Tok::Ident(name) = self.peek() {
            let name = name.clone();
            let span = self.bump().span;
            Ok(Ident { name, span })
        } else {
            Err(self.expected(what))
        }
    }

    fn enter(&mut self) -> PResult<()> {
        if self.depth >= MAX_DEPTH {
            let span = self.span();
            return Err(self.error_hint(
                span,
                "code is nested too deeply",
                "split it into smaller functions",
            ));
        }
        self.depth += 1;
        Ok(())
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }

    // ---- recovery -------------------------------------------------------

    /// Skip to the end of the current statement: consume through a newline or
    /// `;` at bracket depth 0, stop before a `}` at depth 0 or EOF.
    fn sync_stmt(&mut self) {
        let mut depth = 0i32;
        loop {
            match self.peek() {
                Tok::Eof => return,
                Tok::Newline | Tok::Semi if depth <= 0 => {
                    self.bump();
                    return;
                }
                Tok::RBrace if depth <= 0 => return,
                Tok::LParen | Tok::LBracket | Tok::LBrace => depth += 1,
                Tok::RParen | Tok::RBracket | Tok::RBrace => depth -= 1,
                _ => {}
            }
            self.bump();
        }
    }

    /// Skip to the next top-level item: a declaration keyword at the start of
    /// a line, outside any braces.
    fn sync_item(&mut self) {
        let mut depth = 0i32;
        let mut line_start = self.pos == 0 || self.toks[self.pos - 1].tok == Tok::Newline;
        loop {
            let t = self.peek();
            if *t == Tok::Eof {
                return;
            }
            if depth <= 0
                && line_start
                && matches!(
                    t,
                    Tok::Fn
                        | Tok::Var
                        | Tok::Pub
                        | Tok::Private
                        | Tok::Persistent
                        | Tok::Override
                        | Tok::Inherit
                )
                || depth <= 0
                    && line_start
                    && matches!(t, Tok::Ident(n) if unsupported_hint(n).is_some())
            {
                return;
            }
            line_start = false;
            match t {
                Tok::LBrace | Tok::LParen | Tok::LBracket => depth += 1,
                Tok::RBrace | Tok::RParen | Tok::RBracket => depth -= 1,
                Tok::Newline => line_start = true,
                _ => {}
            }
            self.bump();
        }
    }

    // ---- items ----------------------------------------------------------

    fn program(&mut self) -> Program {
        let mut prog = Program {
            inherit: None,
            items: Vec::new(),
        };
        loop {
            while matches!(self.peek(), Tok::Newline | Tok::Semi) {
                self.bump();
            }
            match self.peek() {
                Tok::Eof => break,
                Tok::Inherit => {
                    let start = self.span();
                    match self.inherit() {
                        Ok(inh) => {
                            if prog.inherit.is_some() {
                                self.error_hint(
                                    inh.span,
                                    "a program can inherit only once in Phase 0",
                                    "multiple and labelled inherit arrive in Phase 1",
                                );
                            } else if !prog.items.is_empty() {
                                self.error_hint(
                                    start,
                                    "`inherit` must come before any declarations",
                                    "move it to the top of the file",
                                );
                            } else {
                                prog.inherit = Some(inh);
                            }
                            self.end_of_decl();
                        }
                        Err(Fail) => self.sync_item(),
                    }
                }
                _ => {
                    let before = self.pos;
                    match self.item() {
                        Ok(item) => prog.items.push(item),
                        Err(Fail) => {
                            self.abort_block = false;
                            if self.pos == before {
                                // Guarantee progress on any input.
                                self.bump();
                            }
                            self.sync_item();
                        }
                    }
                }
            }
        }
        prog
    }

    fn end_of_decl(&mut self) {
        match self.peek() {
            Tok::Newline | Tok::Semi => {
                self.bump();
            }
            Tok::Eof => {}
            _ => {
                self.expected("end of line");
                self.sync_item();
            }
        }
    }

    fn inherit(&mut self) -> PResult<Inherit> {
        let kw = self.bump().span;
        if let (Tok::Ident(_), Tok::Eq) = (self.peek(), self.peek_at(1)) {
            let span = self.span();
            return Err(self.error_hint(
                span,
                "labelled inherit is not supported in Phase 0",
                "write `inherit /path/to/program`",
            ));
        }
        if let Tok::Str(_) = self.peek() {
            let span = self.span();
            return Err(self.error_hint(
                span,
                "inherit paths are not quoted",
                "write `inherit /std/room`",
            ));
        }
        let start = self.expect(&Tok::Slash, "a program path like `/std/room`")?;
        let mut end = start;
        loop {
            let seg = self.span();
            match self.peek() {
                Tok::Ident(_) | Tok::Int(_) if seg.start == end.end => {
                    end = self.bump().span;
                }
                _ => {
                    return Err(self.error_hint(
                        seg,
                        "expected a path segment after `/`",
                        "paths look like `/std/room` (no spaces, no extension)",
                    ));
                }
            }
            let next = self.span();
            if self.at(&Tok::Slash) && next.start == end.end {
                end = self.bump().span;
            } else {
                break;
            }
        }
        if self.at(&Tok::Dot) && self.span().start == end.end {
            let span = self.span();
            return Err(self.error_hint(
                span,
                "inherit paths have no file extension",
                "drop the `.wf`",
            ));
        }
        let span = start.to(end);
        Ok(Inherit {
            path: self.src[span.start as usize..span.end as usize].to_string(),
            span: kw.to(span),
        })
    }

    fn item(&mut self) -> PResult<Item> {
        let start = self.span();
        let mut mods = Modifiers::default();
        loop {
            let sp = self.span();
            let flag = match self.peek() {
                Tok::Pub => &mut mods.is_pub,
                Tok::Private => &mut mods.is_private,
                Tok::Persistent => &mut mods.persistent,
                Tok::Override => &mut mods.is_override,
                _ => break,
            };
            if *flag {
                self.bump();
                return Err(self.error(sp, "duplicate modifier"));
            }
            *flag = true;
            self.bump();
        }
        if mods.is_pub && mods.is_private {
            return Err(self.error_hint(
                start,
                "a declaration cannot be both `pub` and `private`",
                "pick one",
            ));
        }
        match self.peek().clone() {
            Tok::Var => {
                if mods.is_override {
                    return Err(self.error(start, "`override` applies to functions, not variables"));
                }
                self.bump();
                let name = self.ident("a variable name")?;
                let ty = if self.eat(&Tok::Colon) {
                    Some(self.ty()?)
                } else {
                    None
                };
                let init = if self.eat(&Tok::Eq) {
                    self.skip_nl();
                    Some(self.expr()?)
                } else {
                    None
                };
                if ty.is_none() && init.is_none() {
                    let sp = name.span;
                    return Err(self.error_hint(
                        sp,
                        "a program variable needs a type or an initial value",
                        format!("write `var {}: int = 0`", name.name),
                    ));
                }
                let span = start.to(self.prev_span());
                self.end_of_decl();
                Ok(Item::Var(VarDecl {
                    mods,
                    name,
                    ty,
                    init,
                    span,
                }))
            }
            Tok::Fn => {
                if mods.persistent {
                    return Err(
                        self.error(start, "`persistent` applies to variables, not functions")
                    );
                }
                self.bump();
                let name = self.ident("a function name")?;
                let params = self.params()?;
                let ret = if self.eat(&Tok::Arrow) {
                    Some(self.ty()?)
                } else {
                    None
                };
                if !self.at(&Tok::LBrace) {
                    return Err(self.expected("`{` to start the function body"));
                }
                let body = self.block()?;
                let span = start.to(body.span);
                Ok(Item::Fn(FnDecl {
                    mods,
                    name,
                    params,
                    ret,
                    body,
                    span,
                }))
            }
            Tok::Ident(name) if unsupported_hint(&name).is_some() => {
                let sp = self.span();
                let hint = unsupported_hint(&name).unwrap_or_default();
                Err(self.error_hint(
                    sp,
                    format!("`{name}` is not supported in the Phase 0 Weft subset"),
                    hint,
                ))
            }
            Tok::Let => {
                let sp = self.span();
                self.bump();
                Err(self.error_hint(
                    sp,
                    "`let` is only allowed inside functions",
                    "program variables are declared with `var`",
                ))
            }
            Tok::RBrace => {
                let sp = self.span();
                self.bump();
                Err(self.error(sp, "unmatched `}`"))
            }
            _ => Err(self.expected("`fn` or `var` declaration")),
        }
    }

    fn params(&mut self) -> PResult<Vec<Param>> {
        self.expect(&Tok::LParen, "`(` after the function name")?;
        let mut params = Vec::new();
        loop {
            self.skip_nl();
            if self.eat(&Tok::RParen) {
                break;
            }
            let name = self.ident("a parameter name")?;
            let ty = if self.eat(&Tok::Colon) {
                Some(self.ty()?)
            } else {
                None
            };
            let default = if self.eat(&Tok::Eq) {
                Some(self.expr()?)
            } else {
                None
            };
            let span = name.span.to(self.prev_span());
            params.push(Param {
                name,
                ty,
                default,
                span,
            });
            self.skip_nl();
            if !self.eat(&Tok::Comma) {
                self.skip_nl();
                self.expect(&Tok::RParen, "`,` or `)` in the parameter list")?;
                break;
            }
        }
        Ok(params)
    }

    fn ty(&mut self) -> PResult<Type> {
        self.enter()?;
        let r = self.ty_inner();
        self.leave();
        r
    }

    fn ty_inner(&mut self) -> PResult<Type> {
        let start = self.span();
        let kind = match self.peek().clone() {
            Tok::Null => {
                self.bump();
                TypeKind::Null
            }
            Tok::Ident(name) => {
                self.bump();
                match name.as_str() {
                    "int" => TypeKind::Int,
                    "bool" => TypeKind::Bool,
                    "string" => TypeKind::String,
                    "object" => TypeKind::Object,
                    "any" => TypeKind::Any,
                    _ => TypeKind::Named(name),
                }
            }
            Tok::LBracket => {
                self.bump();
                let elem = self.ty()?;
                self.expect(&Tok::RBracket, "`]` to close the array type")?;
                TypeKind::Array(Box::new(elem))
            }
            Tok::LBrace => {
                self.bump();
                let k = self.ty()?;
                self.expect(&Tok::Colon, "`:` in the map type `{K: V}`")?;
                let v = self.ty()?;
                self.expect(&Tok::RBrace, "`}` to close the map type")?;
                TypeKind::Map(Box::new(k), Box::new(v))
            }
            _ => return Err(self.expected("a type")),
        };
        let mut ty = Type {
            kind,
            span: start.to(self.prev_span()),
        };
        while self.at(&Tok::Question) {
            let q = self.bump().span;
            ty = Type {
                span: ty.span.to(q),
                kind: TypeKind::Optional(Box::new(ty)),
            };
        }
        Ok(ty)
    }

    // ---- statements -----------------------------------------------------

    fn block(&mut self) -> PResult<Block> {
        self.enter()?;
        let r = self.block_inner();
        self.leave();
        r
    }

    fn block_inner(&mut self) -> PResult<Block> {
        let open = self.expect(&Tok::LBrace, "`{`")?;
        let mut stmts = Vec::new();
        loop {
            while matches!(self.peek(), Tok::Newline | Tok::Semi) {
                self.bump();
            }
            match self.peek() {
                Tok::RBrace => {
                    let close = self.bump().span;
                    return Ok(Block {
                        stmts,
                        span: open.to(close),
                    });
                }
                Tok::Eof => {
                    if self.abort_block {
                        return Err(Fail);
                    }
                    self.abort_block = true;
                    return Err(self.error_hint(
                        open,
                        "this `{` is never closed",
                        "add a matching `}`",
                    ));
                }
                Tok::Fn | Tok::Pub | Tok::Private | Tok::Override | Tok::Persistent => {
                    // Likely a missing `}` before the next declaration.
                    if self.abort_block {
                        return Err(Fail);
                    }
                    self.abort_block = true;
                    return Err(self.error_hint(
                        open,
                        "this `{` is not closed before the next declaration",
                        "add a matching `}`",
                    ));
                }
                _ => {
                    let before = self.pos;
                    match self.stmt() {
                        Ok(s) => {
                            stmts.push(s);
                            self.end_of_stmt();
                        }
                        Err(Fail) => {
                            if self.abort_block {
                                return Err(Fail);
                            }
                            self.sync_stmt();
                            if self.pos == before && !self.at(&Tok::RBrace) {
                                self.bump();
                            }
                        }
                    }
                }
            }
        }
    }

    fn end_of_stmt(&mut self) {
        match self.peek() {
            Tok::Newline | Tok::Semi => {
                self.bump();
            }
            Tok::RBrace | Tok::Eof => {}
            _ => {
                let found = self.peek().describe();
                let span = self.span();
                self.error_hint(
                    span,
                    format!("expected end of statement, found {found}"),
                    "put each statement on its own line or separate them with `;`",
                );
                self.sync_stmt();
            }
        }
    }

    fn stmt(&mut self) -> PResult<Stmt> {
        let start = self.span();
        let kind = match self.peek().clone() {
            Tok::Let | Tok::Var => {
                let mutable = self.bump().tok == Tok::Var;
                let name = self.ident("a variable name")?;
                let ty = if self.eat(&Tok::Colon) {
                    Some(self.ty()?)
                } else {
                    None
                };
                let init = if self.eat(&Tok::Eq) {
                    self.skip_nl();
                    Some(self.expr()?)
                } else {
                    None
                };
                if init.is_none() && !mutable {
                    let sp = name.span;
                    return Err(self.error_hint(
                        sp,
                        "`let` needs an initial value",
                        "write `let x = …`, or use `var` for a variable assigned later",
                    ));
                }
                StmtKind::Local {
                    mutable,
                    name,
                    ty,
                    init,
                }
            }
            Tok::If => return self.if_stmt(),
            Tok::While => {
                self.bump();
                let cond = self.expr()?;
                let body = self.block()?;
                StmtKind::While { cond, body }
            }
            Tok::For => {
                self.bump();
                let var = self.ident("a loop variable name")?;
                self.expect(&Tok::In, "`in` after the loop variable")?;
                let iter = self.expr()?;
                let body = self.block()?;
                StmtKind::For { var, iter, body }
            }
            Tok::Return => {
                self.bump();
                if matches!(
                    self.peek(),
                    Tok::Newline | Tok::Semi | Tok::RBrace | Tok::Eof
                ) {
                    StmtKind::Return(None)
                } else {
                    StmtKind::Return(Some(self.expr()?))
                }
            }
            Tok::Else => {
                return Err(self.error_hint(
                    start,
                    "`else` without a matching `if`",
                    "`else` must follow the closing `}` of an `if` block",
                ));
            }
            Tok::Ident(name) if unsupported_hint(&name).is_some() && !self.call_follows() => {
                let hint = unsupported_hint(&name).unwrap_or_default();
                return Err(self.error_hint(
                    start,
                    format!("`{name}` is not supported in the Phase 0 Weft subset"),
                    hint,
                ));
            }
            _ => {
                let target = self.expr()?;
                let op = match self.peek() {
                    Tok::Eq => Some(AssignOp::Set),
                    Tok::PlusEq => Some(AssignOp::Add),
                    Tok::MinusEq => Some(AssignOp::Sub),
                    _ => None,
                };
                match op {
                    None => StmtKind::Expr(target),
                    Some(op) => {
                        self.bump();
                        if !matches!(target.kind, ExprKind::Ident(_) | ExprKind::Index { .. }) {
                            return Err(self.error_hint(
                                target.span,
                                "cannot assign to this expression",
                                "assign to a variable (`x = …`) or an element (`a[i] = …`)",
                            ));
                        }
                        self.skip_nl();
                        let value = self.expr()?;
                        StmtKind::Assign { target, op, value }
                    }
                }
            }
        };
        Ok(Stmt {
            kind,
            span: start.to(self.prev_span()),
        })
    }

    fn call_follows(&self) -> bool {
        matches!(self.peek_at(1), Tok::LParen | Tok::Eq | Tok::PlusEq)
    }

    fn if_stmt(&mut self) -> PResult<Stmt> {
        let start = self.bump().span;
        if self.at(&Tok::Let) {
            let sp = self.span();
            return Err(self.error_hint(
                sp,
                "`if let` is not supported in Phase 0",
                "compare with null instead: `if x != null { … }`",
            ));
        }
        let cond = self.expr()?;
        if !self.at(&Tok::LBrace) {
            return Err(self.error_hint(
                self.span(),
                format!(
                    "expected `{{` after the condition, found {}",
                    self.peek().describe()
                ),
                "braces are mandatory: `if cond { … }`",
            ));
        }
        let then = self.block()?;
        // Allow `}` newline `else`.
        let save = self.pos;
        self.skip_nl();
        let els = if self.eat(&Tok::Else) {
            if self.at(&Tok::If) {
                Some(Box::new(Else::If(self.if_stmt()?)))
            } else {
                if !self.at(&Tok::LBrace) {
                    return Err(self.error_hint(
                        self.span(),
                        format!(
                            "expected `{{` or `if` after `else`, found {}",
                            self.peek().describe()
                        ),
                        "braces are mandatory: `else { … }`",
                    ));
                }
                Some(Box::new(Else::Block(self.block()?)))
            }
        } else {
            self.pos = save;
            None
        };
        Ok(Stmt {
            kind: StmtKind::If { cond, then, els },
            span: start.to(self.prev_span()),
        })
    }

    // ---- expressions (Pratt) ------------------------------------------

    fn expr(&mut self) -> PResult<Expr> {
        self.expr_bp(0)
    }

    fn expr_bp(&mut self, min_bp: u8) -> PResult<Expr> {
        self.enter()?;
        let r = self.expr_bp_inner(min_bp);
        self.leave();
        r
    }

    fn expr_bp_inner(&mut self, min_bp: u8) -> PResult<Expr> {
        let mut lhs = self.prefix()?;
        loop {
            let (op, lbp, rbp) = match self.peek() {
                Tok::Or => (BinOp::Or, 1, 2),
                Tok::And => (BinOp::And, 3, 4),
                Tok::EqEq => (BinOp::Eq, 7, 8),
                Tok::NotEq => (BinOp::Ne, 7, 8),
                Tok::Lt => (BinOp::Lt, 7, 8),
                Tok::Le => (BinOp::Le, 7, 8),
                Tok::Gt => (BinOp::Gt, 7, 8),
                Tok::Ge => (BinOp::Ge, 7, 8),
                Tok::In => (BinOp::In, 7, 8),
                Tok::QQ => (BinOp::Coalesce, 10, 9),
                Tok::Plus => (BinOp::Add, 11, 12),
                Tok::Minus => (BinOp::Sub, 11, 12),
                Tok::Star => (BinOp::Mul, 13, 14),
                Tok::Slash => (BinOp::Div, 13, 14),
                Tok::Percent => (BinOp::Rem, 13, 14),
                _ => break,
            };
            if lbp < min_bp {
                break;
            }
            self.bump();
            self.skip_nl();
            let rhs = self.expr_bp(rbp)?;
            let span = lhs.span.to(rhs.span);
            lhs = Expr {
                kind: ExprKind::Binary {
                    op,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                },
                span,
            };
            if lbp == 7 && is_comparison_tok(self.peek()) {
                let sp = self.span();
                return Err(self.error_hint(
                    sp,
                    "comparison operators cannot be chained",
                    "combine comparisons with `and`: `a < b and b < c`",
                ));
            }
        }
        Ok(lhs)
    }

    fn prefix(&mut self) -> PResult<Expr> {
        let start = self.span();
        match self.peek() {
            Tok::Not => {
                self.bump();
                let e = self.expr_bp(5)?;
                Ok(Expr {
                    span: start.to(e.span),
                    kind: ExprKind::Unary {
                        op: UnOp::Not,
                        expr: Box::new(e),
                    },
                })
            }
            Tok::Minus => {
                self.bump();
                let e = self.expr_bp(15)?;
                // Fold `-<int literal>` so `-9223372036854775808`-style edge
                // cases and constants stay simple.
                if let ExprKind::Int(n) = e.kind {
                    return Ok(Expr {
                        span: start.to(e.span),
                        kind: ExprKind::Int(n.wrapping_neg()),
                    });
                }
                Ok(Expr {
                    span: start.to(e.span),
                    kind: ExprKind::Unary {
                        op: UnOp::Neg,
                        expr: Box::new(e),
                    },
                })
            }
            _ => self.postfix(),
        }
    }

    fn postfix(&mut self) -> PResult<Expr> {
        let mut e = self.primary()?;
        loop {
            match self.peek() {
                Tok::Dot | Tok::QDot => {
                    let safe = self.bump().tok == Tok::QDot;
                    let name = self.ident("a function name after `.`")?;
                    if !self.at(&Tok::LParen) {
                        let sp = name.span;
                        return Err(self.error_hint(
                            sp,
                            format!("objects have no fields; `{}` must be called", name.name),
                            format!("write `.{}()`", name.name),
                        ));
                    }
                    let args = self.args()?;
                    let span = e.span.to(self.prev_span());
                    e = Expr {
                        kind: ExprKind::Method {
                            recv: Box::new(e),
                            name,
                            args,
                            safe,
                        },
                        span,
                    };
                }
                Tok::LBracket => {
                    self.bump();
                    self.skip_nl();
                    let index = self.expr()?;
                    self.skip_nl();
                    self.expect(&Tok::RBracket, "`]` to close the index")?;
                    let span = e.span.to(self.prev_span());
                    e = Expr {
                        kind: ExprKind::Index {
                            base: Box::new(e),
                            index: Box::new(index),
                        },
                        span,
                    };
                }
                _ => return Ok(e),
            }
        }
    }

    fn args(&mut self) -> PResult<Vec<Expr>> {
        self.expect(&Tok::LParen, "`(`")?;
        self.list(&Tok::RParen, "`,` or `)` in the argument list", |p| {
            if let (Tok::Ident(_), Tok::Colon) = (p.peek(), p.peek_at(1)) {
                let sp = p.span();
                return Err(p.error_hint(
                    sp,
                    "named arguments are not supported in Phase 0",
                    "pass arguments by position",
                ));
            }
            p.expr()
        })
    }

    /// Comma-separated list up to `close` (already past the opener);
    /// newlines are insignificant and a trailing comma is allowed.
    fn list<T>(
        &mut self,
        close: &Tok,
        what: &str,
        mut elem: impl FnMut(&mut Self) -> PResult<T>,
    ) -> PResult<Vec<T>> {
        let mut out = Vec::new();
        loop {
            self.skip_nl();
            if self.eat(close) {
                return Ok(out);
            }
            out.push(elem(self)?);
            self.skip_nl();
            if !self.eat(&Tok::Comma) {
                self.skip_nl();
                self.expect(close, what)?;
                return Ok(out);
            }
        }
    }

    fn primary(&mut self) -> PResult<Expr> {
        let start = self.span();
        let tok = self.peek().clone();
        let kind = match tok {
            Tok::Int(n) => {
                self.bump();
                ExprKind::Int(n)
            }
            Tok::Str(s) => {
                self.bump();
                ExprKind::Str(s)
            }
            Tok::Interp(pieces) => {
                self.bump();
                ExprKind::Interp(self.interp(pieces)?)
            }
            Tok::True => {
                self.bump();
                ExprKind::Bool(true)
            }
            Tok::False => {
                self.bump();
                ExprKind::Bool(false)
            }
            Tok::Null => {
                self.bump();
                ExprKind::Null
            }
            Tok::Ident(name) => {
                self.bump();
                if self.at(&Tok::LParen) {
                    let args = self.args()?;
                    ExprKind::Call {
                        name: Ident { name, span: start },
                        args,
                    }
                } else {
                    ExprKind::Ident(name)
                }
            }
            Tok::Super => {
                self.bump();
                self.expect(&Tok::ColonColon, "`::` after `super`")?;
                let name = self.ident("a function name after `super::`")?;
                if !self.at(&Tok::LParen) {
                    return Err(self.expected("`(` to call the inherited function"));
                }
                let args = self.args()?;
                ExprKind::SuperCall { name, args }
            }
            Tok::LParen => {
                self.bump();
                self.skip_nl();
                let e = self.expr()?;
                self.skip_nl();
                self.expect(&Tok::RParen, "`)`")?;
                return Ok(Expr {
                    kind: e.kind,
                    span: start.to(self.prev_span()),
                });
            }
            Tok::LBracket => {
                self.bump();
                ExprKind::Array(self.list(&Tok::RBracket, "`,` or `]` in the array", |p| p.expr())?)
            }
            Tok::LBrace => {
                self.bump();
                self.skip_nl();
                if self.eat(&Tok::Colon) {
                    self.skip_nl();
                    self.expect(&Tok::RBrace, "`}` (the empty map is written `{:}`)")?;
                    ExprKind::Map(Vec::new())
                } else if self.at(&Tok::RBrace) {
                    let sp = self.bump().span;
                    return Err(self.error_hint(
                        start.to(sp),
                        "`{}` is ambiguous",
                        "write the empty map as `{:}`",
                    ));
                } else {
                    ExprKind::Map(self.list(&Tok::RBrace, "`,` or `}` in the map", |p| {
                        let k = p.expr()?;
                        p.skip_nl();
                        p.expect(&Tok::Colon, "`:` between map key and value")?;
                        p.skip_nl();
                        let v = p.expr()?;
                        Ok((k, v))
                    })?)
                }
            }
            Tok::Newline | Tok::Eof => return Err(self.expected("an expression")),
            _ => {
                let mut msg = format!("expected an expression, found {}", tok.describe());
                let mut hint = None;
                if tok == Tok::Fn {
                    msg = "closures are not supported in Phase 0".into();
                    hint = Some("call a named function instead");
                }
                let sp = self.span();
                self.diags.push(match hint {
                    Some(h) => Diagnostic::error(sp, msg).with_hint(h),
                    None => Diagnostic::error(sp, msg),
                });
                return Err(Fail);
            }
        };
        Ok(Expr {
            kind,
            span: start.to(self.prev_span()),
        })
    }

    fn interp(&mut self, pieces: Vec<Piece>) -> PResult<Vec<InterpPart>> {
        let mut parts = Vec::new();
        for piece in pieces {
            match piece {
                Piece::Lit(s) => parts.push(InterpPart::Lit(s)),
                Piece::Code(sp) => {
                    let (toks, mut ld) = lex_range(self.src, sp.start as usize, sp.end as usize);
                    let had_lex_errors = !ld.is_empty();
                    self.diags.append(&mut ld);
                    let mut sub = Parser {
                        src: self.src,
                        toks: toks.into_iter().filter(|t| t.tok != Tok::Newline).collect(),
                        pos: 0,
                        diags: Vec::new(),
                        depth: self.depth,
                        abort_block: false,
                    };
                    let r = sub.expr();
                    if r.is_ok() && !sub.at(&Tok::Eof) {
                        sub.expected("`}` to end the interpolated expression");
                    }
                    let failed = !sub.diags.is_empty() || had_lex_errors;
                    self.diags.append(&mut sub.diags);
                    match r {
                        Ok(e) if !failed => parts.push(InterpPart::Expr(e)),
                        _ => return Err(Fail),
                    }
                }
            }
        }
        Ok(parts)
    }
}

fn is_comparison_tok(t: &Tok) -> bool {
    matches!(
        t,
        Tok::EqEq | Tok::NotEq | Tok::Lt | Tok::Le | Tok::Gt | Tok::Ge | Tok::In
    )
}
