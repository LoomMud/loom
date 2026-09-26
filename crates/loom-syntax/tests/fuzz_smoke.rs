// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Property smoke tests over the lexer/parser trust boundary: arbitrary input
//! never panics, diagnostics stay in bounds and render. (A `cargo fuzz`
//! target follows in Phase 1.)

use proptest::prelude::*;

fn check(src: &str) {
    let (_, diags) = loom_syntax::parse(src);
    for d in &diags {
        assert!(d.span.start <= d.span.end, "{d:?}");
        assert!(d.span.end as usize <= src.len(), "{d:?}");
        let _ = d.render("/fuzz.wf", src);
    }
}

const VOCAB: &[&str] = &[
    "inherit",
    " /std/room",
    "var",
    "let",
    "fn",
    "pub",
    "private",
    "persistent",
    "override",
    "if",
    "else",
    "for",
    "in",
    "while",
    "return",
    "true",
    "false",
    "null",
    "and",
    "or",
    "not",
    "super",
    "::",
    "(",
    ")",
    "[",
    "]",
    "{",
    "}",
    "{:}",
    ",",
    ":",
    ";",
    ".",
    "?.",
    "??",
    "?",
    "->",
    "+",
    "-",
    "*",
    "/",
    "%",
    "=",
    "+=",
    "-=",
    "==",
    "!=",
    "<",
    "<=",
    ">",
    ">=",
    "\n",
    " ",
    "x",
    "ob",
    "create",
    "42",
    "\"s\"",
    "$\"a{x}b\"",
    "$\"{",
    "\"",
    "//c\n",
    "/*",
    "*/",
    "int",
    "object?",
    "[string]",
    "{string: int}",
    "é",
    "\\",
    "@",
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn arbitrary_text_never_panics(s in "\\PC{0,200}") {
        check(&s);
    }

    #[test]
    fn token_soup_never_panics(idx in prop::collection::vec(0..VOCAB.len(), 0..120)) {
        let src: String = idx.iter().map(|&i| VOCAB[i]).collect();
        check(&src);
    }
}

#[test]
fn deep_nesting_is_a_diagnostic_not_a_crash() {
    for open in ["(", "[", "{\"k\": ", "-", "not ", "$\"{"] {
        let src = format!("fn f() {{ let x = {}1 }}", open.repeat(10_000));
        let (_, diags) = loom_syntax::parse(&src);
        assert!(!diags.is_empty(), "{open}");
    }
    let src = format!("fn f() {}", "{ if true ".repeat(5_000));
    let (_, diags) = loom_syntax::parse(&src);
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("nested too deeply"))
    );
}
