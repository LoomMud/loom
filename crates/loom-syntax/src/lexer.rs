// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Hand-written Weft lexer. Newlines are significant (statement terminators),
//! so they are emitted as [`Tok::Newline`]; the parser skips them where a
//! statement cannot end (inside brackets, after binary operators, ...).

use crate::diag::{Diagnostic, Span};

/// One piece of an interpolated string `$"…{expr}…"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Piece {
    /// Literal text (escapes already processed).
    Lit(String),
    /// Source byte range of an embedded expression (between the braces).
    Code(Span),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Tok {
    Ident(String),
    Int(i64),
    Float(f64),
    Str(String),
    Interp(Vec<Piece>),
    // keywords
    Inherit,
    Var,
    Let,
    Fn,
    Pub,
    Private,
    Persistent,
    Override,
    If,
    Else,
    For,
    In,
    While,
    Return,
    True,
    False,
    Null,
    And,
    Or,
    Not,
    Super,
    Import,
    Const,
    Struct,
    Enum,
    Match,
    Try,
    Catch,
    Throw,
    Protected,
    Final,
    Atomic,
    As,
    Break,
    Continue,
    Lightweight,
    // punctuation
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Colon,
    ColonColon,
    Semi,
    Dot,
    DotDot,
    Ellipsis,
    QDot,
    QQ,
    Question,
    Arrow,
    FatArrow,
    Pipe,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Eq,
    PlusEq,
    MinusEq,
    StarEq,
    SlashEq,
    PercentEq,
    EqEq,
    NotEq,
    Lt,
    Le,
    Gt,
    Ge,
    Newline,
    Eof,
}

impl Tok {
    /// Is this a reserved word (not usable as a name)?
    pub fn is_keyword(&self) -> bool {
        keyword(self.text()).as_ref() == Some(self)
    }

    /// Can this token start a top-level declaration (used for recovery)?
    pub fn starts_item(&self) -> bool {
        matches!(
            self,
            Tok::Fn
                | Tok::Var
                | Tok::Const
                | Tok::Struct
                | Tok::Enum
                | Tok::Import
                | Tok::Inherit
                | Tok::Lightweight
                | Tok::Pub
                | Tok::Protected
                | Tok::Private
                | Tok::Persistent
                | Tok::Override
                | Tok::Final
                | Tok::Atomic
        )
    }

    /// Human-readable description for "expected X, found Y" messages.
    pub fn describe(&self) -> String {
        match self {
            Tok::Ident(s) => format!("identifier `{s}`"),
            Tok::Int(n) => format!("integer `{n}`"),
            Tok::Float(x) => format!("float `{x:?}`"),
            Tok::Str(_) => "string literal".into(),
            Tok::Interp(_) => "interpolated string".into(),
            Tok::Newline => "end of line".into(),
            Tok::Eof => "end of file".into(),
            other => format!("`{}`", other.text()),
        }
    }

    fn text(&self) -> &'static str {
        match self {
            Tok::Inherit => "inherit",
            Tok::Var => "var",
            Tok::Let => "let",
            Tok::Fn => "fn",
            Tok::Pub => "pub",
            Tok::Private => "private",
            Tok::Persistent => "persistent",
            Tok::Override => "override",
            Tok::If => "if",
            Tok::Else => "else",
            Tok::For => "for",
            Tok::In => "in",
            Tok::While => "while",
            Tok::Return => "return",
            Tok::True => "true",
            Tok::False => "false",
            Tok::Null => "null",
            Tok::And => "and",
            Tok::Or => "or",
            Tok::Not => "not",
            Tok::Super => "super",
            Tok::Import => "import",
            Tok::Const => "const",
            Tok::Struct => "struct",
            Tok::Enum => "enum",
            Tok::Match => "match",
            Tok::Try => "try",
            Tok::Catch => "catch",
            Tok::Throw => "throw",
            Tok::Protected => "protected",
            Tok::Final => "final",
            Tok::Atomic => "atomic",
            Tok::As => "as",
            Tok::Break => "break",
            Tok::Continue => "continue",
            Tok::Lightweight => "lightweight",
            Tok::LParen => "(",
            Tok::RParen => ")",
            Tok::LBracket => "[",
            Tok::RBracket => "]",
            Tok::LBrace => "{",
            Tok::RBrace => "}",
            Tok::Comma => ",",
            Tok::Colon => ":",
            Tok::ColonColon => "::",
            Tok::Semi => ";",
            Tok::Dot => ".",
            Tok::DotDot => "..",
            Tok::Ellipsis => "...",
            Tok::QDot => "?.",
            Tok::QQ => "??",
            Tok::Question => "?",
            Tok::Arrow => "->",
            Tok::FatArrow => "=>",
            Tok::Pipe => "|",
            Tok::Plus => "+",
            Tok::Minus => "-",
            Tok::Star => "*",
            Tok::Slash => "/",
            Tok::Percent => "%",
            Tok::Eq => "=",
            Tok::PlusEq => "+=",
            Tok::MinusEq => "-=",
            Tok::StarEq => "*=",
            Tok::SlashEq => "/=",
            Tok::PercentEq => "%=",
            Tok::EqEq => "==",
            Tok::NotEq => "!=",
            Tok::Lt => "<",
            Tok::Le => "<=",
            Tok::Gt => ">",
            Tok::Ge => ">=",
            _ => "?",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Token {
    pub tok: Tok,
    pub span: Span,
}

fn keyword(s: &str) -> Option<Tok> {
    Some(match s {
        "inherit" => Tok::Inherit,
        "var" => Tok::Var,
        "let" => Tok::Let,
        "fn" => Tok::Fn,
        "pub" => Tok::Pub,
        "private" => Tok::Private,
        "persistent" => Tok::Persistent,
        "override" => Tok::Override,
        "if" => Tok::If,
        "else" => Tok::Else,
        "for" => Tok::For,
        "in" => Tok::In,
        "while" => Tok::While,
        "return" => Tok::Return,
        "true" => Tok::True,
        "false" => Tok::False,
        "null" => Tok::Null,
        "and" => Tok::And,
        "or" => Tok::Or,
        "not" => Tok::Not,
        "super" => Tok::Super,
        "import" => Tok::Import,
        "const" => Tok::Const,
        "struct" => Tok::Struct,
        "enum" => Tok::Enum,
        "match" => Tok::Match,
        "try" => Tok::Try,
        "catch" => Tok::Catch,
        "throw" => Tok::Throw,
        "protected" => Tok::Protected,
        "final" => Tok::Final,
        "atomic" => Tok::Atomic,
        "as" => Tok::As,
        "break" => Tok::Break,
        "continue" => Tok::Continue,
        "lightweight" => Tok::Lightweight,
        _ => return None,
    })
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Lex the whole of `src`.
pub fn lex(src: &str) -> (Vec<Token>, Vec<Diagnostic>) {
    lex_range(src, 0, src.len())
}

/// Lex `src[start..end]`, producing spans relative to the whole of `src`
/// (used for expressions embedded in interpolated strings).
pub fn lex_range(src: &str, start: usize, end: usize) -> (Vec<Token>, Vec<Diagnostic>) {
    let mut lx = Lexer {
        src,
        pos: start,
        end,
        toks: Vec::new(),
        diags: Vec::new(),
    };
    lx.run();
    (lx.toks, lx.diags)
}

struct Lexer<'a> {
    src: &'a str,
    pos: usize,
    end: usize,
    toks: Vec<Token>,
    diags: Vec<Diagnostic>,
}

impl Lexer<'_> {
    fn peek(&self) -> Option<char> {
        self.src[self.pos..self.end].chars().next()
    }

    fn peek2(&self) -> Option<char> {
        let mut it = self.src[self.pos..self.end].chars();
        it.next();
        it.next()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    fn push(&mut self, tok: Tok, start: usize) {
        self.toks.push(Token {
            tok,
            span: Span::new(start, self.pos),
        });
    }

    fn run(&mut self) {
        while let Some(c) = self.peek() {
            let start = self.pos;
            match c {
                '\n' => {
                    self.bump();
                    self.push(Tok::Newline, start);
                }
                c if c.is_whitespace() => {
                    self.bump();
                }
                '/' if self.peek2() == Some('/') => {
                    while let Some(c) = self.peek() {
                        if c == '\n' {
                            break;
                        }
                        self.bump();
                    }
                }
                '/' if self.peek2() == Some('*') => self.block_comment(start),
                '"' => {
                    self.bump();
                    let pieces = self.string_body(start, false);
                    let s = pieces
                        .into_iter()
                        .map(|p| match p {
                            Piece::Lit(s) => s,
                            Piece::Code(_) => String::new(),
                        })
                        .collect();
                    self.push(Tok::Str(s), start);
                }
                '$' if self.peek2() == Some('"') => {
                    self.bump();
                    self.bump();
                    let pieces = self.string_body(start, true);
                    self.push(Tok::Interp(pieces), start);
                }
                c if c.is_ascii_digit() => self.number(start),
                c if is_ident_start(c) => {
                    while self.peek().is_some_and(is_ident_char) {
                        self.bump();
                    }
                    let text = &self.src[start..self.pos];
                    let tok = keyword(text).unwrap_or_else(|| Tok::Ident(text.to_string()));
                    self.push(tok, start);
                }
                _ => self.punct(start, c),
            }
        }
        let end = self.end;
        self.toks.push(Token {
            tok: Tok::Eof,
            span: Span::new(end, end),
        });
    }

    fn block_comment(&mut self, start: usize) {
        self.bump();
        self.bump();
        let mut depth = 1u32;
        while depth > 0 {
            match self.bump() {
                None => {
                    self.diags.push(
                        Diagnostic::error(
                            Span::new(start, start + 2),
                            "unterminated block comment",
                        )
                        .with_hint("close it with `*/`"),
                    );
                    return;
                }
                Some('/') if self.peek() == Some('*') => {
                    self.bump();
                    depth += 1;
                }
                Some('*') if self.peek() == Some('/') => {
                    self.bump();
                    depth -= 1;
                }
                // Newlines inside comments still terminate statements.
                Some('\n') => {
                    let p = self.pos;
                    self.toks.push(Token {
                        tok: Tok::Newline,
                        span: Span::new(p - 1, p),
                    });
                }
                Some(_) => {}
            }
        }
    }

    fn number(&mut self, start: usize) {
        let digits = |lx: &mut Self| {
            while lx.peek().is_some_and(|c| c.is_ascii_digit() || c == '_') {
                lx.bump();
            }
        };
        digits(self);
        let mut is_float = false;
        // `1.5` is a float; `1..3` (slice) and `1.foo()` are not.
        if self.peek() == Some('.') && self.peek2().is_some_and(|c| c.is_ascii_digit()) {
            is_float = true;
            self.bump();
            digits(self);
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            let rest = &self.src[self.pos + 1..self.end];
            let mut it = rest.chars();
            let exp_ok = match it.next() {
                Some(c) if c.is_ascii_digit() => true,
                Some('+' | '-') => it.next().is_some_and(|c| c.is_ascii_digit()),
                _ => false,
            };
            if exp_ok {
                is_float = true;
                self.bump();
                if matches!(self.peek(), Some('+' | '-')) {
                    self.bump();
                }
                digits(self);
            }
        }
        // Swallow trailing identifier characters so `12abc` is one bad token.
        let mut junk = false;
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            junk = true;
            self.bump();
        }
        let span = Span::new(start, self.pos);
        let text: String = self.src[start..self.pos]
            .chars()
            .filter(|&c| c != '_')
            .collect();
        if junk {
            let what = if is_float { "float" } else { "integer" };
            self.diags.push(
                Diagnostic::error(span, format!("invalid {what} literal"))
                    .with_hint("numbers are decimal: `42`, `1_000`, `2.5`, `1e-3`"),
            );
            self.push(
                if is_float {
                    Tok::Float(0.0)
                } else {
                    Tok::Int(0)
                },
                start,
            );
            return;
        }
        if is_float {
            match text.parse::<f64>() {
                Ok(x) if x.is_finite() => self.push(Tok::Float(x), start),
                _ => {
                    self.diags.push(Diagnostic::error(
                        span,
                        "float literal is out of range for `float` (64-bit)",
                    ));
                    self.push(Tok::Float(0.0), start);
                }
            }
            return;
        }
        match text.parse::<i64>() {
            Ok(n) => self.push(Tok::Int(n), start),
            Err(_) => {
                self.diags.push(
                    Diagnostic::error(span, "integer literal is too large for `int` (64-bit)")
                        .with_hint("write it as a float (`1e20`) if you need a larger magnitude"),
                );
                self.push(Tok::Int(0), start);
            }
        }
    }

    /// Lex a string body after the opening quote. For interpolated strings,
    /// `{…}` become [`Piece::Code`] ranges; nested braces and strings inside
    /// the expression are skipped over so `$"{m["k"]}"` works.
    fn string_body(&mut self, start: usize, interp: bool) -> Vec<Piece> {
        let mut pieces = Vec::new();
        let mut lit = String::new();
        loop {
            let Some(c) = self.peek() else {
                self.unterminated(start);
                break;
            };
            match c {
                '"' => {
                    self.bump();
                    break;
                }
                '\n' => {
                    self.unterminated(start);
                    break;
                }
                '\\' => {
                    let esc_start = self.pos;
                    self.bump();
                    match self.bump() {
                        Some('n') => lit.push('\n'),
                        Some('t') => lit.push('\t'),
                        Some('r') => lit.push('\r'),
                        Some('0') => lit.push('\0'),
                        Some(c @ ('"' | '\\' | '{' | '}')) => lit.push(c),
                        other => {
                            self.diags.push(
                                Diagnostic::error(
                                    Span::new(esc_start, self.pos),
                                    "unknown escape sequence",
                                )
                                .with_hint("valid escapes are \\n \\t \\r \\0 \\\" \\\\ \\{ \\}"),
                            );
                            if other == Some('\n') {
                                // keep line structure for recovery
                                self.pos -= 1;
                            }
                        }
                    }
                }
                '{' if interp => {
                    if !lit.is_empty() {
                        pieces.push(Piece::Lit(std::mem::take(&mut lit)));
                    }
                    let open = self.pos;
                    self.bump();
                    let code_start = self.pos;
                    let mut depth = 1u32;
                    loop {
                        match self.peek() {
                            None | Some('\n') => {
                                self.diags.push(
                                    Diagnostic::error(
                                        Span::new(open, open + 1),
                                        "unclosed `{` in interpolated string",
                                    )
                                    .with_hint(
                                        "close the expression with `}` or escape it as `\\{`",
                                    ),
                                );
                                return pieces;
                            }
                            Some('"') => {
                                // nested plain string inside the expression
                                self.bump();
                                while let Some(c) = self.peek() {
                                    if c == '\n' {
                                        break;
                                    }
                                    self.bump();
                                    if c == '\\' {
                                        self.bump();
                                    } else if c == '"' {
                                        break;
                                    }
                                }
                            }
                            Some('{') => {
                                depth += 1;
                                self.bump();
                            }
                            Some('}') => {
                                depth -= 1;
                                if depth == 0 {
                                    let code_end = self.pos;
                                    self.bump();
                                    if self.src[code_start..code_end].trim().is_empty() {
                                        self.diags.push(Diagnostic::error(
                                            Span::new(open, self.pos),
                                            "empty `{}` in interpolated string",
                                        ));
                                    } else {
                                        pieces.push(Piece::Code(Span::new(code_start, code_end)));
                                    }
                                    break;
                                }
                                self.bump();
                            }
                            Some(_) => {
                                self.bump();
                            }
                        }
                    }
                }
                _ => {
                    self.bump();
                    lit.push(c);
                }
            }
        }
        if !lit.is_empty() || pieces.is_empty() {
            pieces.push(Piece::Lit(lit));
        }
        pieces
    }

    fn unterminated(&mut self, start: usize) {
        self.diags.push(
            Diagnostic::error(Span::new(start, self.pos), "unterminated string literal")
                .with_hint("strings must close with `\"` on the same line"),
        );
    }

    fn punct(&mut self, start: usize, c: char) {
        self.bump();
        let next = self.peek();
        let two = |t| (t, true);
        let one = |t| (t, false);
        let (tok, double) = match (c, next) {
            ('(', _) => one(Tok::LParen),
            (')', _) => one(Tok::RParen),
            ('[', _) => one(Tok::LBracket),
            (']', _) => one(Tok::RBracket),
            ('{', _) => one(Tok::LBrace),
            ('}', _) => one(Tok::RBrace),
            (',', _) => one(Tok::Comma),
            (';', _) => one(Tok::Semi),
            ('.', Some('.')) => {
                self.bump();
                if self.peek() == Some('.') {
                    two(Tok::Ellipsis)
                } else {
                    one(Tok::DotDot)
                }
            }
            ('.', _) => one(Tok::Dot),
            (':', Some(':')) => two(Tok::ColonColon),
            (':', _) => one(Tok::Colon),
            ('?', Some('.')) => two(Tok::QDot),
            ('?', Some('?')) => two(Tok::QQ),
            ('?', _) => one(Tok::Question),
            ('-', Some('>')) => two(Tok::Arrow),
            ('-', Some('=')) => two(Tok::MinusEq),
            ('-', _) => one(Tok::Minus),
            ('+', Some('=')) => two(Tok::PlusEq),
            ('+', _) => one(Tok::Plus),
            ('*', Some('=')) => two(Tok::StarEq),
            ('*', _) => one(Tok::Star),
            ('/', Some('=')) => two(Tok::SlashEq),
            ('/', _) => one(Tok::Slash),
            ('%', Some('=')) => two(Tok::PercentEq),
            ('%', _) => one(Tok::Percent),
            ('=', Some('=')) => two(Tok::EqEq),
            ('=', Some('>')) => two(Tok::FatArrow),
            ('=', _) => one(Tok::Eq),
            ('!', Some('=')) => two(Tok::NotEq),
            ('<', Some('=')) => two(Tok::Le),
            ('<', _) => one(Tok::Lt),
            ('>', Some('=')) => two(Tok::Ge),
            ('>', _) => one(Tok::Gt),
            ('|', Some(c)) if c != '|' => one(Tok::Pipe),
            ('|', None) => one(Tok::Pipe),
            _ => {
                // LPC/C-isms: report once, then substitute the Weft token so
                // parsing continues without a cascade.
                let (msg, hint, subst): (String, Option<&str>, Option<Tok>) = match (c, next) {
                    ('!', _) => (
                        "unexpected `!`".into(),
                        Some("Weft uses `not` for logical negation"),
                        Some(Tok::Not),
                    ),
                    ('&', Some('&')) | ('|', Some('|')) => {
                        self.bump();
                        let (op, word, tok) = if c == '&' {
                            ("&&", "and", Tok::And)
                        } else {
                            ("||", "or", Tok::Or)
                        };
                        (
                            format!("unexpected `{op}`"),
                            Some(if word == "and" {
                                "Weft uses `and` for logical conjunction"
                            } else {
                                "Weft uses `or` for logical disjunction"
                            }),
                            Some(tok),
                        )
                    }
                    ('&', _) => (
                        "unexpected `&`".into(),
                        Some("Weft uses `and` for logical conjunction"),
                        Some(Tok::And),
                    ),
                    ('#', _) => {
                        // Swallow the whole would-be directive line.
                        while self.peek().is_some_and(|c| c != '\n') {
                            self.bump();
                        }
                        (
                            "preprocessor directives are not part of Weft".into(),
                            Some("use `import` for shared declarations and `const` for constants"),
                            None,
                        )
                    }
                    ('\'', _) => (
                        "unexpected character `'`".into(),
                        Some("strings use double quotes: \"text\""),
                        None,
                    ),
                    _ => (
                        format!("unexpected character `{}`", c.escape_default()),
                        None,
                        None,
                    ),
                };
                let mut d = Diagnostic::error(Span::new(start, self.pos), msg);
                if let Some(h) = hint {
                    d = d.with_hint(h);
                }
                self.diags.push(d);
                if let Some(t) = subst {
                    self.push(t, start);
                }
                return;
            }
        };
        if double {
            self.bump();
        }
        self.push(tok, start);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(src: &str) -> Vec<Tok> {
        let (t, d) = lex(src);
        assert!(d.is_empty(), "{d:?}");
        t.into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn basic_tokens() {
        assert_eq!(
            toks("let x = a?.b() ?? 1_000\n"),
            vec![
                Tok::Let,
                Tok::Ident("x".into()),
                Tok::Eq,
                Tok::Ident("a".into()),
                Tok::QDot,
                Tok::Ident("b".into()),
                Tok::LParen,
                Tok::RParen,
                Tok::QQ,
                Tok::Int(1000),
                Tok::Newline,
                Tok::Eof
            ]
        );
    }

    #[test]
    fn interpolation_pieces() {
        let src = r#"$"a{m["k"]}b\{""#;
        let (t, d) = lex(src);
        assert!(d.is_empty(), "{d:?}");
        let Tok::Interp(p) = &t[0].tok else {
            panic!("{t:?}")
        };
        assert_eq!(p[0], Piece::Lit("a".into()));
        let Piece::Code(sp) = p[1] else { panic!() };
        assert_eq!(&src[sp.start as usize..sp.end as usize], r#"m["k"]"#);
        assert_eq!(p[2], Piece::Lit("b{".into()));
    }

    #[test]
    fn errors_do_not_stop_lexing() {
        let (t, d) = lex("a ! b \"open\nc");
        assert_eq!(d.len(), 2);
        assert!(t.iter().any(|t| t.tok == Tok::Ident("c".into())));
    }
}
