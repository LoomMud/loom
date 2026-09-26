// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Property smoke tests over the lexer/parser trust boundary: arbitrary input
//! never panics, diagnostics stay in bounds and render. The same property is
//! fuzzed with coverage guidance by `fuzz/fuzz_targets/parse.rs`.

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
    // v1 grammar (OBI-23)
    "import",
    " /include/damage.{A, B}",
    "const",
    "struct",
    "enum",
    "match",
    "try",
    "catch",
    "throw",
    "protected",
    "final",
    "atomic",
    "as",
    "break",
    "continue",
    "lightweight",
    "combat = ",
    "combat::",
    "..",
    "...",
    "=>",
    "|",
    "||",
    "&&",
    "!",
    "#",
    "*=",
    "/=",
    "%=",
    "1.5",
    "1e3",
    "2.5e-3",
    "1.",
    "_",
    ".slash",
    "Point",
    "float",
    "error",
    "fn(int) -> bool",
    "fn(x) => ",
    "if let ",
    "exclude: ",
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

/// Every golden file, truncated at every char boundary and with every single
/// line removed, still parses without panicking.
#[test]
fn golden_mutations_never_panic() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    for entry in std::fs::read_dir(dir).expect("golden dir") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|e| e != "wf") {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("read");
        for (i, _) in src.char_indices() {
            check(&src[..i]);
        }
        let lines: Vec<&str> = src.lines().collect();
        for skip in 0..lines.len() {
            let mutated: Vec<&str> = lines
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != skip)
                .map(|(_, l)| *l)
                .collect();
            check(&mutated.join("\n"));
        }
    }
}

#[test]
fn deep_nesting_is_a_diagnostic_not_a_crash() {
    for open in [
        "(",
        "[",
        "{\"k\": ",
        "-",
        "not ",
        "$\"{",
        "fn() => ",
        "match x { _ => ",
        "P { a: ",
        "s[..",
        "f(n: ",
        "x as ",
    ] {
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
    for (pre, rep) in [
        ("var x: ", "["),
        ("var x: ", "fn() -> "),
        ("fn f() { match x { ", ".A("),
        ("fn f() { match x { ", "(.A | "),
        ("fn f() { ", "try { "),
    ] {
        let src = format!("{pre}{}", rep.repeat(10_000));
        let (_, diags) = loom_syntax::parse(&src);
        assert!(!diags.is_empty(), "{pre}{rep}");
    }
}
