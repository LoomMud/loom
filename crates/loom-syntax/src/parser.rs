// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Recursive-descent + Pratt parser for the Weft v1 grammar (spec v2 §5.3,
//! reference: `docs/weft-grammar.md`).
//!
//! Error recovery works on statement boundaries (newline, `;`, `}`) inside
//! function bodies, on member boundaries (newline, `,`) inside `struct`,
//! `enum` and `match` bodies, and on item boundaries (declaration keywords at
//! the start of a line) at the top level, so one typo yields one diagnostic
//! rather than a cascade. The parser never panics; nesting is bounded by
//! [`MAX_DEPTH`] so hostile input cannot overflow the stack.

use crate::ast::*;
use crate::diag::{Diagnostic, Span};
use crate::lexer::{Piece, Tok, Token, lex, lex_range};

/// Maximum nesting of blocks/expressions/types/patterns before the parser
/// gives up.
pub const MAX_DEPTH: u32 = 96;
/// Stop collecting diagnostics after this many (the rest are cascades).
const MAX_DIAGS: usize = 50;

/// Parse a whole source file. Returns the (possibly partial) AST and all
/// diagnostics; a program is only compilable when the diagnostics are empty.
pub fn parse(src: &str) -> (Program, Vec<Diagnostic>) {
    let (toks, mut diags) = lex(src);
    let mut p = Parser::new(src, toks, 0);
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
    /// Struct literals `Name { … }` are not allowed here (the heads of `if`,
    /// `while`, `for` and `match`, where `{` starts the body).
    no_struct: bool,
}

enum IfHead {
    Cond(Expr),
    Let(Ident, Option<Type>, Expr),
}

/// What a modifier keyword may be applied to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ItemKind {
    Var,
    Const,
    Fn,
    Struct,
    Enum,
}

impl ItemKind {
    fn plural(self) -> &'static str {
        match self {
            ItemKind::Var => "variables",
            ItemKind::Const => "constants",
            ItemKind::Fn => "functions",
            ItemKind::Struct => "structs",
            ItemKind::Enum => "enums",
        }
    }
}

impl<'a> Parser<'a> {
    fn new(src: &'a str, toks: Vec<Token>, depth: u32) -> Parser<'a> {
        Parser {
            src,
            toks,
            pos: 0,
            diags: Vec::new(),
            depth,
            abort_block: false,
            no_struct: false,
        }
    }

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

    fn span_at(&self, n: usize) -> Span {
        self.toks[(self.pos + n).min(self.toks.len() - 1)].span
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

    fn at_stmt_end(&self) -> bool {
        matches!(
            self.peek(),
            Tok::Newline | Tok::Semi | Tok::RBrace | Tok::Eof
        )
    }

    fn error(&mut self, code: &'static str, span: Span, msg: impl Into<String>) -> Fail {
        self.diags.push(Diagnostic::error(code, span, msg));
        Fail
    }

    fn error_hint(
        &mut self,
        code: &'static str,
        span: Span,
        msg: impl Into<String>,
        hint: impl Into<String>,
    ) -> Fail {
        self.diags
            .push(Diagnostic::error(code, span, msg).with_hint(hint));
        Fail
    }

    /// `expected X, found Y`: one diagnostic kind reused at every parse
    /// point (like rustc's "mismatched types"), so every call site shares
    /// one code rather than minting a fresh one per grammar production.
    fn expected(&mut self, what: &str) -> Fail {
        let found = self.peek().describe();
        let span = self.span();
        self.error(
            crate::codes::PARSE_EXPECTED,
            span,
            format!("expected {what}, found {found}"),
        )
    }

    fn expected_hint(&mut self, what: &str, hint: &str) -> Fail {
        let found = self.peek().describe();
        let span = self.span();
        self.error_hint(
            crate::codes::PARSE_EXPECTED,
            span,
            format!("expected {what}, found {found}"),
            hint,
        )
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
        } else if self.peek().is_keyword() {
            let kw = self.peek().describe();
            let span = self.span();
            Err(self.error_hint(
                "W0032",
                span,
                format!("expected {what}, found keyword {kw}"),
                "keywords cannot be used as names; pick another name",
            ))
        } else {
            Err(self.expected(what))
        }
    }

    fn enter(&mut self) -> PResult<()> {
        if self.depth >= MAX_DEPTH {
            let span = self.span();
            return Err(self.error_hint(
                "W0033",
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

    /// Run `f` with struct literals allowed (`true`) or forbidden.
    fn with_struct<T>(&mut self, allowed: bool, f: impl FnOnce(&mut Self) -> T) -> T {
        let old = std::mem::replace(&mut self.no_struct, !allowed);
        let r = f(self);
        self.no_struct = old;
        r
    }

    /// An expression in a position followed by a `{` body.
    fn head_expr(&mut self) -> PResult<Expr> {
        self.with_struct(false, |p| p.expr())
    }

    /// An expression inside brackets, where struct literals are fine again.
    fn inner_expr(&mut self) -> PResult<Expr> {
        self.with_struct(true, |p| p.expr())
    }

    // ---- recovery -------------------------------------------------------

    /// Brackets opened (and not yet closed) on the current line between token
    /// `from` and the current position.
    fn open_on_line(&self, from: usize) -> i32 {
        let mut depth = 0i32;
        for t in &self.toks[from.min(self.pos)..self.pos.min(self.toks.len())] {
            match t.tok {
                Tok::Newline => depth = 0,
                Tok::LParen | Tok::LBracket | Tok::LBrace => depth += 1,
                Tok::RParen | Tok::RBracket | Tok::RBrace => depth = (depth - 1).max(0),
                _ => {}
            }
        }
        depth
    }

    /// Skip to the end of a broken statement (or member, with `comma`) that
    /// started at token `from`: consume through the next newline, or a `;`
    /// (or `,`) outside brackets; stop before a `}` that closes an enclosing
    /// block, or EOF. Brackets opened earlier on the error's line are skipped
    /// over, so `let p = Point { x }` does not eat the function's `}`.
    fn sync_to_end(&mut self, from: usize, comma: bool) {
        let mut depth = self.open_on_line(from);
        loop {
            match self.peek() {
                Tok::Eof => return,
                Tok::Newline => {
                    self.bump();
                    return;
                }
                Tok::Semi if depth <= 0 => {
                    self.bump();
                    return;
                }
                Tok::Comma if comma && depth <= 0 => {
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
            if depth <= 0 && line_start && t.starts_item() {
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

    // ---- program & header -------------------------------------------------

    fn program(&mut self) -> Program {
        let mut prog = Program {
            lightweight: None,
            inherits: Vec::new(),
            imports: Vec::new(),
            items: Vec::new(),
        };
        loop {
            while matches!(self.peek(), Tok::Newline | Tok::Semi) {
                self.bump();
            }
            let start = self.span();
            let header = match self.peek() {
                Tok::Eof => break,
                Tok::Inherit => Some(self.inherit().map(|i| prog.inherits.push(i))),
                Tok::Import => Some(self.import().map(|i| prog.imports.push(i))),
                Tok::Lightweight => {
                    let sp = self.bump().span;
                    if prog.lightweight.is_some() {
                        self.error("W0034", sp, "`lightweight` is declared twice");
                    }
                    prog.lightweight = Some(sp);
                    Some(Ok(()))
                }
                _ => None,
            };
            match header {
                Some(Ok(())) => {
                    if !prog.items.is_empty() {
                        let what = self.src[start.start as usize..start.end as usize].to_string();
                        self.error_hint(
                            "W0035",
                            start,
                            format!("`{what}` must come before any declarations"),
                            "move it to the top of the file",
                        );
                    }
                    self.end_of_decl();
                }
                Some(Err(Fail)) => self.sync_item(),
                None => {
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

    /// Is the token at `pos + n` glued to the previous one (no whitespace)?
    fn adjacent(&self, n: usize, end: Span) -> bool {
        self.span_at(n).start == end.end
    }

    /// A mudlib path `/a/b-c/d`: `/`-separated word segments with no spaces.
    fn path(&mut self, what: &str) -> PResult<(String, Span)> {
        if let Tok::Str(_) = self.peek() {
            let span = self.span();
            return Err(self.error_hint(
                "W0036",
                span,
                format!("{what} paths are not quoted"),
                format!("write `{what} /std/room`"),
            ));
        }
        let start = self.expect(&Tok::Slash, "a program path like `/std/room`")?;
        let mut end = start;
        loop {
            let seg_start = self.span();
            let mut any = false;
            while self.adjacent(0, end) {
                let sp = self.span();
                let text = &self.src[sp.start as usize..sp.end as usize];
                let word = !text.is_empty()
                    && text
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
                if !word || matches!(self.peek(), Tok::Eof) {
                    break;
                }
                end = self.bump().span;
                any = true;
            }
            if !any {
                return Err(self.error_hint(
                    "W0037",
                    seg_start,
                    "expected a path segment after `/`",
                    "paths look like `/std/room` (no spaces, no extension)",
                ));
            }
            if self.at(&Tok::Slash) && self.adjacent(0, end) {
                end = self.bump().span;
            } else {
                break;
            }
        }
        let span = start.to(end);
        Ok((
            self.src[span.start as usize..span.end as usize].to_string(),
            span,
        ))
    }

    fn inherit(&mut self) -> PResult<Inherit> {
        let kw = self.bump().span;
        let label = if matches!(self.peek(), Tok::Ident(_)) && *self.peek_at(1) == Tok::Eq {
            let l = self.ident("an inherit label")?;
            self.bump();
            Some(l)
        } else {
            None
        };
        let (path, path_span) = self.path("inherit")?;
        if self.at(&Tok::Dot) && self.adjacent(0, path_span) {
            let span = self.span();
            return Err(self.error_hint(
                "W0038",
                span,
                "inherit paths have no file extension",
                "drop the `.wf`",
            ));
        }
        Ok(Inherit {
            label,
            path,
            path_span,
            span: kw.to(path_span),
        })
    }

    fn import(&mut self) -> PResult<Import> {
        let kw = self.bump().span;
        let (path, path_span) = self.path("import")?;
        let mut names = None;
        if self.at(&Tok::Dot) && self.adjacent(0, path_span) {
            self.bump();
            match self.peek() {
                Tok::LBrace => {
                    self.bump();
                    let list = self.list(&Tok::RBrace, "`,` or `}` in the import list", |p| {
                        p.ident("a name to import")
                    })?;
                    if list.is_empty() {
                        let sp = self.prev_span();
                        return Err(self.error_hint(
                            "W0039",
                            sp,
                            "empty import list",
                            "name what to import, or drop `.{}` to import the whole module",
                        ));
                    }
                    names = Some(list);
                }
                Tok::Ident(n) if n == "wf" => {
                    let span = self.span();
                    return Err(self.error_hint(
                        "W0040",
                        span,
                        "import paths have no file extension",
                        "drop the `.wf`",
                    ));
                }
                _ => {
                    names = Some(vec![self.ident("a name or `{` after `.` in the import")?]);
                }
            }
        }
        Ok(Import {
            path,
            path_span,
            names,
            span: kw.to(self.prev_span()),
        })
    }

    // ---- items ----------------------------------------------------------

    fn modifiers(&mut self) -> PResult<(Modifiers, Vec<(&'static str, Span)>)> {
        let mut mods = Modifiers::default();
        let mut seen: Vec<(&'static str, Span)> = Vec::new();
        loop {
            let sp = self.span();
            let (name, flag) = match self.peek() {
                Tok::Pub => ("pub", &mut mods.is_pub),
                Tok::Protected => ("protected", &mut mods.is_protected),
                Tok::Private => ("private", &mut mods.is_private),
                Tok::Persistent => ("persistent", &mut mods.persistent),
                Tok::Override => ("override", &mut mods.is_override),
                Tok::Final => ("final", &mut mods.is_final),
                Tok::Atomic => ("atomic", &mut mods.atomic),
                _ => break,
            };
            if *flag {
                self.bump();
                return Err(self.error_hint(
                    "W0041",
                    sp,
                    format!("duplicate modifier `{name}`"),
                    "remove one of them",
                ));
            }
            *flag = true;
            mods.span.get_or_insert(sp);
            seen.push((name, sp));
            self.bump();
        }
        let vis: Vec<_> = seen
            .iter()
            .filter(|(n, _)| matches!(*n, "pub" | "protected" | "private"))
            .collect();
        if vis.len() > 1 {
            let (second, sp) = *vis[1];
            let (first, _) = *vis[0];
            return Err(self.error_hint(
                "W0042",
                sp,
                format!("a declaration cannot be both `{first}` and `{second}`"),
                "pick one visibility",
            ));
        }
        Ok((mods, seen))
    }

    fn check_mods(&mut self, seen: &[(&'static str, Span)], kind: ItemKind) -> PResult<()> {
        for &(name, sp) in seen {
            let ok = match name {
                "pub" | "protected" | "private" => true,
                "persistent" => kind == ItemKind::Var,
                _ => kind == ItemKind::Fn,
            };
            if !ok {
                let applies = if name == "persistent" {
                    "variables"
                } else {
                    "functions"
                };
                return Err(self.error(
                    "W0043",
                    sp,
                    format!("`{name}` applies to {applies}, not {}", kind.plural()),
                ));
            }
        }
        Ok(())
    }

    fn item(&mut self) -> PResult<Item> {
        let start = self.span();
        let (mods, seen) = self.modifiers()?;
        match self.peek().clone() {
            Tok::Var => {
                self.check_mods(&seen, ItemKind::Var)?;
                self.bump();
                let name = self.ident("a variable name")?;
                let ty = self.opt_type_ann()?;
                let init = if self.eat(&Tok::Eq) {
                    self.skip_nl();
                    Some(self.expr()?)
                } else {
                    None
                };
                if ty.is_none() && init.is_none() {
                    let sp = name.span;
                    return Err(self.error_hint(
                        "W0044",
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
            Tok::Const => {
                self.check_mods(&seen, ItemKind::Const)?;
                self.bump();
                let name = self.ident("a constant name")?;
                let ty = self.opt_type_ann()?;
                if !self.eat(&Tok::Eq) {
                    let sp = name.span;
                    return Err(self.error_hint(
                        "W0045",
                        sp,
                        "a constant needs a value",
                        format!("write `const {} = …`", name.name),
                    ));
                }
                self.skip_nl();
                let value = self.expr()?;
                let span = start.to(self.prev_span());
                self.end_of_decl();
                Ok(Item::Const(ConstDecl {
                    mods,
                    name,
                    ty,
                    value,
                    span,
                }))
            }
            Tok::Fn => {
                self.check_mods(&seen, ItemKind::Fn)?;
                let fn_span = self.bump().span;
                if self.at(&Tok::LParen) {
                    return Err(self.error_hint(
                        "W0046",
                        fn_span,
                        "a top-level function needs a name",
                        "write `fn name(…) { … }`; closures `fn(x) => …` are expressions",
                    ));
                }
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
            Tok::Struct => {
                self.check_mods(&seen, ItemKind::Struct)?;
                self.bump();
                let name = self.ident("a struct name")?;
                let open = self.expect(&Tok::LBrace, "`{` to start the struct fields")?;
                let fields = self.members(open, |p| {
                    let name = p.ident("a field name")?;
                    if !p.eat(&Tok::Colon) {
                        let sp = name.span;
                        return Err(p.error_hint(
                            "W0078",
                            sp,
                            format!("struct field `{}` needs a type", name.name),
                            format!("write `{}: int`", name.name),
                        ));
                    }
                    let ty = p.ty()?;
                    let default = if p.eat(&Tok::Eq) {
                        p.skip_nl();
                        Some(p.expr()?)
                    } else {
                        None
                    };
                    let span = name.span.to(p.prev_span());
                    Ok(FieldDecl {
                        name,
                        ty,
                        default,
                        span,
                    })
                })?;
                let span = start.to(self.prev_span());
                self.end_of_decl();
                Ok(Item::Struct(StructDecl {
                    mods,
                    name,
                    fields,
                    span,
                }))
            }
            Tok::Enum => {
                self.check_mods(&seen, ItemKind::Enum)?;
                self.bump();
                let name = self.ident("an enum name")?;
                let open = self.expect(&Tok::LBrace, "`{` to start the enum variants")?;
                let variants = self.members(open, |p| {
                    let name = p.ident("a variant name")?;
                    let mut payload = Vec::new();
                    if p.eat(&Tok::LParen) {
                        payload =
                            p.list(&Tok::RParen, "`,` or `)` in the payload types", |p| p.ty())?;
                    } else if p.at(&Tok::Eq) {
                        let sp = p.span();
                        return Err(p.error_hint(
                            "W0079",
                            sp,
                            "enum variants have no explicit values",
                            "use a `const` for a numeric value, or a payload: `Heavy(int)`",
                        ));
                    }
                    let span = name.span.to(p.prev_span());
                    Ok(VariantDecl {
                        name,
                        payload,
                        span,
                    })
                })?;
                let span = start.to(self.prev_span());
                self.end_of_decl();
                Ok(Item::Enum(EnumDecl {
                    mods,
                    name,
                    variants,
                    span,
                }))
            }
            Tok::Inherit | Tok::Import | Tok::Lightweight if !seen.is_empty() => {
                let sp = self.span();
                let what = self.peek().describe();
                Err(self.error("W0047", sp, format!("{what} takes no modifiers")))
            }
            Tok::Let => {
                let sp = self.span();
                self.bump();
                Err(self.error_hint(
                    "W0048",
                    sp,
                    "`let` is only allowed inside functions",
                    "program variables are declared with `var`, constants with `const`",
                ))
            }
            Tok::RBrace => {
                let sp = self.span();
                self.bump();
                Err(self.error("W0049", sp, "unmatched `}`"))
            }
            Tok::Ident(_) | Tok::If | Tok::For | Tok::While | Tok::Return if seen.is_empty() => {
                Err(self.expected_hint(
                    "a declaration",
                    "code runs inside functions; put it in `fn create() { … }`",
                ))
            }
            _ => Err(self.expected("a declaration (`fn`, `var`, `const`, `struct` or `enum`)")),
        }
    }

    fn opt_type_ann(&mut self) -> PResult<Option<Type>> {
        if self.eat(&Tok::Colon) {
            Ok(Some(self.ty()?))
        } else {
            Ok(None)
        }
    }

    /// Members of a `struct`/`enum` body (past `{`), separated by newlines or
    /// commas, up to the closing `}`. A bad member is reported and skipped.
    fn members<T>(
        &mut self,
        open: Span,
        mut member: impl FnMut(&mut Self) -> PResult<T>,
    ) -> PResult<Vec<T>> {
        let mut out = Vec::new();
        let mut failed = false;
        loop {
            while matches!(self.peek(), Tok::Newline | Tok::Comma | Tok::Semi) {
                self.bump();
            }
            match self.peek() {
                Tok::RBrace => {
                    self.bump();
                    return if failed { Err(Fail) } else { Ok(out) };
                }
                Tok::Eof if self.abort_block => return Err(Fail),
                Tok::Eof => {
                    self.abort_block = true;
                    return Err(self.error_hint(
                        "W0050",
                        open,
                        "this `{` is never closed",
                        "add a matching `}`",
                    ));
                }
                t if t.starts_item()
                    && self.pos > 0
                    && self.toks[self.pos - 1].tok == Tok::Newline =>
                {
                    if self.abort_block {
                        return Err(Fail);
                    }
                    self.abort_block = true;
                    return Err(self.error_hint(
                        "W0051",
                        open,
                        "this `{` is not closed before the next declaration",
                        "add a matching `}`",
                    ));
                }
                _ => {}
            }
            let before = self.pos;
            match member(self) {
                Ok(m) => {
                    out.push(m);
                    if !matches!(
                        self.peek(),
                        Tok::Newline | Tok::Comma | Tok::Semi | Tok::RBrace
                    ) {
                        self.expected_hint(
                            "`,`, a newline or `}`",
                            "separate members with `,` or put each on its own line",
                        );
                        failed = true;
                        self.sync_to_end(before, true);
                    }
                }
                Err(Fail) => {
                    if self.abort_block {
                        return Err(Fail);
                    }
                    failed = true;
                    self.sync_to_end(before, true);
                    if self.pos == before && !self.at(&Tok::RBrace) {
                        self.bump();
                    }
                }
            }
        }
    }

    fn params(&mut self) -> PResult<Vec<Param>> {
        self.expect(&Tok::LParen, "`(` after the function name")?;
        let mut params: Vec<Param> = Vec::new();
        loop {
            self.skip_nl();
            if self.eat(&Tok::RParen) {
                break;
            }
            if let Some(last) = params.last()
                && last.rest
            {
                let sp = self.span();
                return Err(self.error_hint(
                    "W0052",
                    sp,
                    format!("the `...{}` parameter must be last", last.name.name),
                    "move the rest parameter to the end of the list",
                ));
            }
            let start = self.span();
            let rest = self.eat(&Tok::Ellipsis);
            let name = self.ident("a parameter name")?;
            let ty = self.opt_type_ann()?;
            let default = if self.at(&Tok::Eq) {
                if rest {
                    let sp = self.span();
                    return Err(self.error_hint(
                        "W0053",
                        sp,
                        "a `...rest` parameter cannot have a default",
                        "it is an empty array when no extra arguments are passed",
                    ));
                }
                self.bump();
                Some(self.inner_expr()?)
            } else {
                None
            };
            let span = start.to(self.prev_span());
            params.push(Param {
                name,
                ty,
                default,
                rest,
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

    // ---- types ------------------------------------------------------------

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
                    "float" => TypeKind::Float,
                    "bool" => TypeKind::Bool,
                    "string" => TypeKind::String,
                    "object" => TypeKind::Object,
                    "any" => TypeKind::Any,
                    "error" => TypeKind::Error,
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
            Tok::Fn => {
                self.bump();
                if !self.eat(&Tok::LParen) {
                    return Err(self.expected_hint(
                        "`(` in the function type",
                        "function types are written `fn(int, string) -> bool`",
                    ));
                }
                let params = self.list(&Tok::RParen, "`,` or `)` in the function type", |p| {
                    if let (Tok::Ident(_), Tok::Colon) = (p.peek(), p.peek_at(1)) {
                        let sp = p.span();
                        return Err(p.error_hint(
                            "W0080",
                            sp,
                            "function types list parameter types only",
                            "drop the parameter name: `fn(int) -> bool`",
                        ));
                    }
                    p.ty()
                })?;
                let ret = if self.eat(&Tok::Arrow) {
                    Some(Box::new(self.ty()?))
                } else {
                    None
                };
                TypeKind::Fn { params, ret }
            }
            Tok::LParen => {
                self.bump();
                let inner = self.ty()?;
                self.expect(&Tok::RParen, "`)` to close the type")?;
                inner.kind
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
        let r = self.with_struct(true, |p| p.block_inner());
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
                        "W0054",
                        open,
                        "this `{` is never closed",
                        "add a matching `}`",
                    ));
                }
                t if self.decl_boundary(t) => {
                    // Likely a missing `}` before the next declaration.
                    if self.abort_block {
                        return Err(Fail);
                    }
                    self.abort_block = true;
                    return Err(self.error_hint(
                        "W0055",
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
                            self.sync_to_end(before, false);
                            if self.pos == before && !self.at(&Tok::RBrace) {
                                self.bump();
                            }
                        }
                    }
                }
            }
        }
    }

    /// Inside a block, does this token start a top-level declaration (so the
    /// block is probably missing its `}`)?
    fn decl_boundary(&self, t: &Tok) -> bool {
        match t {
            // `fn(` is a closure expression; `fn name` is a declaration.
            Tok::Fn => !matches!(self.peek_at(1), Tok::LParen),
            Tok::Pub
            | Tok::Protected
            | Tok::Private
            | Tok::Override
            | Tok::Persistent
            | Tok::Final
            | Tok::Atomic => true,
            _ => false,
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
                    "W0056",
                    span,
                    format!("expected end of statement, found {found}"),
                    "put each statement on its own line or separate them with `;`",
                );
                let here = self.pos;
                self.sync_to_end(here, false);
            }
        }
    }

    fn stmt(&mut self) -> PResult<Stmt> {
        let start = self.span();
        let kind = match self.peek().clone() {
            Tok::Let | Tok::Var => {
                let mutable = self.bump().tok == Tok::Var;
                let name = self.ident("a variable name")?;
                let ty = self.opt_type_ann()?;
                let init = if self.eat(&Tok::Eq) {
                    self.skip_nl();
                    Some(self.expr()?)
                } else {
                    None
                };
                if init.is_none() && !mutable {
                    let sp = name.span;
                    return Err(self.error_hint(
                        "W0057",
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
                if self.at(&Tok::Let) {
                    let sp = self.span();
                    return Err(self.error_hint(
                        "W0058",
                        sp,
                        "`while let` is not part of Weft",
                        "use `while true { if let x = … { … } else { break } }`",
                    ));
                }
                let cond = self.head_expr()?;
                let body = self.body_block("while")?;
                StmtKind::While { cond, body }
            }
            Tok::For => {
                self.bump();
                let var = self.ident("a loop variable name")?;
                self.expect(&Tok::In, "`in` after the loop variable")?;
                let iter = self.head_expr()?;
                let body = self.body_block("for")?;
                StmtKind::For { var, iter, body }
            }
            Tok::Break => {
                self.bump();
                StmtKind::Break
            }
            Tok::Continue => {
                self.bump();
                StmtKind::Continue
            }
            Tok::Return => {
                self.bump();
                if self.at_stmt_end() {
                    StmtKind::Return(None)
                } else {
                    StmtKind::Return(Some(self.expr()?))
                }
            }
            Tok::Throw => {
                self.bump();
                if self.at_stmt_end() {
                    return Err(self.error_hint(
                        "W0059",
                        start,
                        "`throw` needs an error value",
                        "write `throw e` to rethrow, or `throw error(\"message\")`",
                    ));
                }
                StmtKind::Throw(self.expr()?)
            }
            Tok::Try => {
                self.bump();
                let body = self.body_block("try")?;
                let save = self.pos;
                self.skip_nl();
                if !self.eat(&Tok::Catch) {
                    self.pos = save;
                    return Err(self.error_hint(
                        "W0060",
                        start,
                        "`try` needs a `catch` block",
                        "add `catch e { … }` after the `try` block",
                    ));
                }
                let catch_var = if matches!(self.peek(), Tok::Ident(_)) {
                    Some(self.ident("the error variable")?)
                } else {
                    None
                };
                let handler = self.body_block("catch")?;
                StmtKind::Try {
                    body,
                    catch_var,
                    handler,
                }
            }
            Tok::Catch => {
                return Err(self.error_hint(
                    "W0061",
                    start,
                    "`catch` without a matching `try`",
                    "`catch` must follow the closing `}` of a `try` block",
                ));
            }
            Tok::Else => {
                return Err(self.error_hint(
                    "W0062",
                    start,
                    "`else` without a matching `if`",
                    "`else` must follow the closing `}` of an `if` block",
                ));
            }
            Tok::Const
            | Tok::Import
            | Tok::Inherit
            | Tok::Lightweight
            | Tok::Struct
            | Tok::Enum => {
                let what = self.peek().describe();
                return Err(self.error_hint(
                    "W0063",
                    start,
                    format!("{what} is only allowed at the top level of a file"),
                    if *self.peek() == Tok::Const {
                        "use `let` for a local constant"
                    } else {
                        "move it to the top of the file"
                    },
                ));
            }
            _ => {
                let target = self.expr()?;
                let op = match self.peek() {
                    Tok::Eq => Some(AssignOp::Set),
                    Tok::PlusEq => Some(AssignOp::Add),
                    Tok::MinusEq => Some(AssignOp::Sub),
                    Tok::StarEq => Some(AssignOp::Mul),
                    Tok::SlashEq => Some(AssignOp::Div),
                    Tok::PercentEq => Some(AssignOp::Rem),
                    _ => None,
                };
                match op {
                    None => StmtKind::Expr(target),
                    Some(op) => {
                        self.bump();
                        let assignable = matches!(
                            target.kind,
                            ExprKind::Ident(_)
                                | ExprKind::Index { .. }
                                | ExprKind::Field { safe: false, .. }
                        );
                        if !assignable {
                            return Err(self.error_hint(
                                "W0064",
                                target.span,
                                "cannot assign to this expression",
                                "assign to a variable (`x = …`), an element (`a[i] = …`) \
                                 or a field (`p.x = …`)",
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

    /// The mandatory `{ … }` body of `kw`.
    fn body_block(&mut self, kw: &str) -> PResult<Block> {
        if !self.at(&Tok::LBrace) {
            let found = self.peek().describe();
            let span = self.span();
            return Err(self.error_hint(
                "W0065",
                span,
                format!("expected `{{` to start the `{kw}` body, found {found}"),
                format!("braces are mandatory: `{kw} … {{ … }}`"),
            ));
        }
        self.block()
    }

    fn if_stmt(&mut self) -> PResult<Stmt> {
        let start = self.bump().span;
        let head = if self.eat(&Tok::Let) {
            let name = self.ident("a name to bind after `if let`")?;
            let ty = self.opt_type_ann()?;
            if !self.eat(&Tok::Eq) {
                return Err(self.expected_hint(
                    "`=` after the `if let` binding",
                    "write `if let x = maybe_null { … }`",
                ));
            }
            let value = self.head_expr()?;
            IfHead::Let(name, ty, value)
        } else {
            IfHead::Cond(self.head_expr()?)
        };
        if !self.at(&Tok::LBrace) {
            return Err(self.error_hint(
                "W0066",
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
                        "W0067",
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
        let kind = match head {
            IfHead::Cond(cond) => StmtKind::If { cond, then, els },
            IfHead::Let(name, ty, value) => StmtKind::IfLet {
                name,
                ty,
                value,
                then,
                els,
            },
        };
        Ok(Stmt {
            kind,
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
                Tok::As => {
                    // `e as T` binds tighter than `*` and looser than unary `-`.
                    if 14 < min_bp {
                        break;
                    }
                    self.bump();
                    let ty = self.ty()?;
                    let span = lhs.span.to(ty.span);
                    lhs = Expr {
                        kind: ExprKind::Cast {
                            expr: Box::new(lhs),
                            ty,
                        },
                        span,
                    };
                    continue;
                }
                Tok::Arrow => {
                    let sp = self.span();
                    return Err(self.error_hint(
                        "W0068",
                        sp,
                        "`->` is not a call operator in Weft",
                        "call functions on objects with `.`: `ob.fn()`",
                    ));
                }
                Tok::Pipe => {
                    let sp = self.span();
                    return Err(self.error_hint(
                        "W0069",
                        sp,
                        "unexpected `|` in an expression",
                        "Weft uses `or` for logical disjunction; `|` separates `match` patterns",
                    ));
                }
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
                    "W0070",
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
                // Fold `-<literal>` so constants and patterns stay simple.
                let kind = match e.kind {
                    ExprKind::Int(n) => ExprKind::Int(n.wrapping_neg()),
                    ExprKind::Float(x) => ExprKind::Float(-x),
                    kind => ExprKind::Unary {
                        op: UnOp::Neg,
                        expr: Box::new(Expr { kind, span: e.span }),
                    },
                };
                Ok(Expr {
                    span: start.to(e.span),
                    kind,
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
                    let name = self.ident("a name after `.`")?;
                    if self.at(&Tok::LParen) {
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
                    } else {
                        let span = e.span.to(name.span);
                        e = Expr {
                            kind: ExprKind::Field {
                                base: Box::new(e),
                                name,
                                safe,
                            },
                            span,
                        };
                    }
                }
                Tok::LBracket => {
                    self.bump();
                    self.skip_nl();
                    let lo = if self.at(&Tok::DotDot) {
                        None
                    } else {
                        Some(self.inner_expr()?)
                    };
                    self.skip_nl();
                    let kind = if self.eat(&Tok::DotDot) {
                        self.skip_nl();
                        let hi = if self.at(&Tok::RBracket) {
                            None
                        } else {
                            Some(Box::new(self.inner_expr()?))
                        };
                        self.skip_nl();
                        self.expect(&Tok::RBracket, "`]` to close the slice")?;
                        ExprKind::Slice {
                            base: Box::new(e),
                            lo: lo.map(Box::new),
                            hi,
                        }
                    } else {
                        self.expect(&Tok::RBracket, "`]` or `..` in the index")?;
                        ExprKind::Index {
                            base: Box::new(e),
                            // `lo` is always `Some` here: `[..` took the slice path.
                            index: Box::new(lo.unwrap_or(Expr {
                                kind: ExprKind::Error,
                                span: Span::default(),
                            })),
                        }
                    };
                    let span_end = self.prev_span();
                    e = Expr {
                        span: start_of(&kind).to(span_end),
                        kind,
                    };
                }
                Tok::LParen => {
                    let args = self.args()?;
                    let span = e.span.to(self.prev_span());
                    e = Expr {
                        kind: ExprKind::Apply {
                            callee: Box::new(e),
                            args,
                        },
                        span,
                    };
                }
                _ => return Ok(e),
            }
        }
    }

    fn args(&mut self) -> PResult<Vec<Arg>> {
        self.expect(&Tok::LParen, "`(`")?;
        let mut seen_named: Option<Span> = None;
        let args = self.list(&Tok::RParen, "`,` or `)` in the argument list", |p| {
            let start = p.span();
            if let (Tok::Ident(_), Tok::Colon) = (p.peek(), p.peek_at(1)) {
                let name = p.ident("an argument name")?;
                p.bump();
                p.skip_nl();
                let value = p.inner_expr()?;
                seen_named.get_or_insert(name.span);
                return Ok(Arg {
                    span: start.to(value.span),
                    name: Some(name),
                    spread: false,
                    value,
                });
            }
            let spread = p.eat(&Tok::Ellipsis);
            let value = p.inner_expr()?;
            if seen_named.is_some() {
                return Err(p.error_hint(
                    "W0081",
                    start.to(value.span),
                    "positional argument after a named argument",
                    "put named arguments after all positional ones",
                ));
            }
            Ok(Arg {
                span: start.to(value.span),
                name: None,
                spread,
                value,
            })
        })?;
        Ok(args)
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
            Tok::Float(x) => {
                self.bump();
                ExprKind::Float(x)
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
                let id = Ident { name, span: start };
                match self.peek() {
                    Tok::LParen => {
                        let args = self.args()?;
                        ExprKind::Call { name: id, args }
                    }
                    Tok::ColonColon => {
                        self.bump();
                        let (name, args) = self.scoped_call(&id.name)?;
                        ExprKind::SuperCall {
                            label: Some(id),
                            name,
                            args,
                        }
                    }
                    Tok::LBrace if !self.no_struct => self.struct_lit(id)?,
                    _ => ExprKind::Ident(id.name),
                }
            }
            Tok::Super => {
                self.bump();
                self.expect(&Tok::ColonColon, "`::` after `super`")?;
                let (name, args) = self.scoped_call("super")?;
                ExprKind::SuperCall {
                    label: None,
                    name,
                    args,
                }
            }
            Tok::LParen => {
                self.bump();
                self.skip_nl();
                let e = self.inner_expr()?;
                self.skip_nl();
                self.expect(&Tok::RParen, "`)`")?;
                return Ok(Expr {
                    kind: e.kind,
                    span: start.to(self.prev_span()),
                });
            }
            Tok::LBracket => {
                self.bump();
                ExprKind::Array(self.list(&Tok::RBracket, "`,` or `]` in the array", |p| {
                    p.inner_expr()
                })?)
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
                        "W0071",
                        start.to(sp),
                        "`{}` is ambiguous",
                        "write the empty map as `{:}`",
                    ));
                } else {
                    ExprKind::Map(self.list(&Tok::RBrace, "`,` or `}` in the map", |p| {
                        let k = p.inner_expr()?;
                        p.skip_nl();
                        p.expect(&Tok::Colon, "`:` between map key and value")?;
                        p.skip_nl();
                        let v = p.inner_expr()?;
                        Ok((k, v))
                    })?)
                }
            }
            Tok::Dot => {
                self.bump();
                let name = self.ident("an enum variant name after `.`")?;
                let args = if self.at(&Tok::LParen) {
                    Some(self.args()?)
                } else {
                    None
                };
                ExprKind::Variant { name, args }
            }
            Tok::Fn => {
                self.bump();
                if !self.at(&Tok::LParen) {
                    return Err(self.error_hint(
                        "W0072",
                        start,
                        "a named function cannot be declared inside an expression",
                        "closures are anonymous: `fn(x) => x + 1`; declare named functions \
                         at the top level",
                    ));
                }
                ExprKind::Closure(Box::new(self.closure()?))
            }
            Tok::Match => {
                self.bump();
                self.match_expr()?
            }
            Tok::Newline | Tok::Eof => return Err(self.expected("an expression")),
            _ => {
                let msg = format!("expected an expression, found {}", tok.describe());
                let sp = self.span();
                self.diags.push(Diagnostic::error("W0073", sp, msg));
                return Err(Fail);
            }
        };
        Ok(Expr {
            kind,
            span: start.to(self.prev_span()),
        })
    }

    /// After `scope::`: the called function name and arguments.
    fn scoped_call(&mut self, scope: &str) -> PResult<(Ident, Vec<Arg>)> {
        let name = self.ident(&format!("a function name after `{scope}::`"))?;
        if !self.at(&Tok::LParen) {
            let sp = name.span;
            return Err(self.error_hint(
                "W0074",
                sp,
                format!("`{scope}::{}` must be called", name.name),
                "`::` calls an inherited function, e.g. `combat::roll()`; enum variants \
                 are written `Kind.A` or `.A`",
            ));
        }
        let args = self.args()?;
        Ok((name, args))
    }

    fn struct_lit(&mut self, name: Ident) -> PResult<ExprKind> {
        self.bump();
        let fields = self.list(&Tok::RBrace, "`,` or `}` in the struct literal", |p| {
            let fname = p.ident("a field name")?;
            if !p.eat(&Tok::Colon) {
                let sp = fname.span;
                return Err(p.error_hint(
                    "W0082",
                    sp,
                    format!("expected `:` after field `{}`", fname.name),
                    format!(
                        "write `{0}: {0}` to use a variable of the same name",
                        fname.name
                    ),
                ));
            }
            p.skip_nl();
            let value = p.inner_expr()?;
            Ok(FieldInit {
                span: fname.span.to(value.span),
                name: fname,
                value,
            })
        })?;
        Ok(ExprKind::StructLit { name, fields })
    }

    fn closure(&mut self) -> PResult<Closure> {
        let params = self.params()?;
        let ret = if self.eat(&Tok::Arrow) {
            Some(self.ty()?)
        } else {
            None
        };
        let body = if self.eat(&Tok::FatArrow) {
            self.skip_nl();
            Body::Expr(Box::new(self.expr()?))
        } else if self.at(&Tok::LBrace) {
            Body::Block(self.block()?)
        } else {
            return Err(self.expected_hint(
                "`=>` or `{` after the closure parameters",
                "closures are written `fn(x) => x + 1` or `fn(x) { return x + 1 }`",
            ));
        };
        Ok(Closure { params, ret, body })
    }

    fn match_expr(&mut self) -> PResult<ExprKind> {
        let scrutinee = self.head_expr()?;
        if !self.at(&Tok::LBrace) {
            return Err(self.expected_hint(
                "`{` after the `match` value",
                "write `match value { pattern => result }`",
            ));
        }
        let open = self.bump().span;
        let arms = self.with_struct(true, |p| {
            p.members(open, |p| {
                let pat = p.pattern()?;
                let guard = if p.eat(&Tok::If) {
                    Some(p.expr()?)
                } else {
                    None
                };
                if !p.eat(&Tok::FatArrow) {
                    return Err(p.expected_hint(
                        "`=>` after the pattern",
                        "match arms are written `pattern => result`",
                    ));
                }
                p.skip_nl();
                let body = if p.at(&Tok::LBrace) {
                    Body::Block(p.block()?)
                } else {
                    Body::Expr(Box::new(p.expr()?))
                };
                Ok(MatchArm {
                    span: pat.span.to(p.prev_span()),
                    pat,
                    guard,
                    body,
                })
            })
        })?;
        Ok(ExprKind::Match {
            scrutinee: Box::new(scrutinee),
            arms,
        })
    }

    // ---- patterns -----------------------------------------------------------

    fn pattern(&mut self) -> PResult<Pattern> {
        self.enter()?;
        let r = self.pattern_inner();
        self.leave();
        r
    }

    fn pattern_inner(&mut self) -> PResult<Pattern> {
        let first = self.pattern_single()?;
        if !self.at(&Tok::Pipe) {
            return Ok(first);
        }
        let mut alts = vec![first];
        while self.eat(&Tok::Pipe) {
            self.skip_nl();
            alts.push(self.pattern_single()?);
        }
        let span = alts[0].span.to(alts[alts.len() - 1].span);
        Ok(Pattern {
            kind: PatKind::Or(alts),
            span,
        })
    }

    fn pattern_single(&mut self) -> PResult<Pattern> {
        let start = self.span();
        let kind = match self.peek().clone() {
            Tok::Ident(n) if n == "_" => {
                self.bump();
                PatKind::Wild
            }
            Tok::Ident(n) => {
                let id = self.ident("a pattern")?;
                match self.peek() {
                    Tok::Dot => {
                        self.bump();
                        let name = self.ident("a variant name")?;
                        let fields = self.pattern_fields()?;
                        PatKind::Variant {
                            enum_name: Some(id),
                            name,
                            fields,
                        }
                    }
                    Tok::ColonColon => {
                        let sp = self.span();
                        return Err(self.error_hint(
                            "W0075",
                            sp,
                            "enum variants are not written with `::`",
                            format!("write `{n}.Variant` or just `.Variant`"),
                        ));
                    }
                    Tok::LParen => {
                        let sp = self.span();
                        return Err(self.error_hint(
                            "W0076",
                            sp,
                            format!("`{n}(…)` is not a pattern"),
                            format!("match an enum variant with `.{n}(…)`"),
                        ));
                    }
                    _ => PatKind::Bind(n),
                }
            }
            Tok::Dot => {
                self.bump();
                let name = self.ident("a variant name after `.`")?;
                let fields = self.pattern_fields()?;
                PatKind::Variant {
                    enum_name: None,
                    name,
                    fields,
                }
            }
            Tok::Int(n) => {
                self.bump();
                PatKind::Int(n)
            }
            Tok::Float(x) => {
                self.bump();
                PatKind::Float(x)
            }
            Tok::Minus => {
                self.bump();
                match self.peek().clone() {
                    Tok::Int(n) => {
                        self.bump();
                        PatKind::Int(n.wrapping_neg())
                    }
                    Tok::Float(x) => {
                        self.bump();
                        PatKind::Float(-x)
                    }
                    _ => return Err(self.expected("a number after `-` in the pattern")),
                }
            }
            Tok::Str(s) => {
                self.bump();
                PatKind::Str(s)
            }
            Tok::True => {
                self.bump();
                PatKind::Bool(true)
            }
            Tok::False => {
                self.bump();
                PatKind::Bool(false)
            }
            Tok::Null => {
                self.bump();
                PatKind::Null
            }
            Tok::Interp(_) => {
                let sp = self.span();
                return Err(self.error_hint(
                    "W0077",
                    sp,
                    "interpolated strings cannot be patterns",
                    "match a plain string literal, or bind a name and use an `if` guard",
                ));
            }
            _ => {
                return Err(self.expected_hint(
                    "a pattern",
                    "patterns are `_`, a name, a literal, or an enum variant like \
                     `.slash` or `.hit(n)`",
                ));
            }
        };
        Ok(Pattern {
            kind,
            span: start.to(self.prev_span()),
        })
    }

    fn pattern_fields(&mut self) -> PResult<Option<Vec<Pattern>>> {
        if self.eat(&Tok::LParen) {
            Ok(Some(self.list(
                &Tok::RParen,
                "`,` or `)` in the variant pattern",
                |p| p.pattern(),
            )?))
        } else {
            Ok(None)
        }
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
                    let mut sub = Parser::new(
                        self.src,
                        toks.into_iter().filter(|t| t.tok != Tok::Newline).collect(),
                        self.depth,
                    );
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

/// Span of the base expression of an index/slice (its left edge).
fn start_of(kind: &ExprKind) -> Span {
    match kind {
        ExprKind::Index { base, .. } | ExprKind::Slice { base, .. } => base.span,
        _ => Span::default(),
    }
}

fn is_comparison_tok(t: &Tok) -> bool {
    matches!(
        t,
        Tok::EqEq | Tok::NotEq | Tok::Lt | Tok::Le | Tok::Gt | Tok::Ge | Tok::In
    )
}
