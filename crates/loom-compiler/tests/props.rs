// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Property tests for the checker: randomly assembled (syntactically valid,
//! arbitrarily typed) programs never panic the resolver/type checker, every
//! diagnostic has an in-bounds span and renders, and a program that checks
//! clean has no poison type anywhere in its HIR.

use loom_compiler::interface::ParentInfo;
use proptest::prelude::*;

const EXPRS: &[&str] = &[
    "a",
    "s",
    "o",
    "xs",
    "m",
    "d",
    "1",
    "\"str\"",
    "true",
    "null",
    "self",
    "[]",
    "{:}",
    "[1, 2]",
    "[\"x\", null]",
    "{\"k\": 1}",
    "xs[0]",
    "m[s]",
    "d[a]",
    "len(xs)",
    "keys(m)",
    "environment()",
    "o?.f()",
    "o.f()",
    "d.f(a)",
    "helper(a)",
    "helper()",
    "base_fn()",
    "super::base_fn()",
    "nope(1)",
    "g",
    "$\"{a} and {o}\"",
    "not true",
    "-a",
    "o ?? self",
    "m[s] ?? 0",
];

const BINOPS: &[&str] = &[
    "+", "-", "*", "/", "%", "==", "!=", "<", ">=", "and", "or", "in", "??",
];

const STMTS: &[&str] = &[
    "let v{n} = {e}",
    "var w{n}: int = {e}",
    "var q{n}: string? = {e}",
    "a = {e}",
    "a += {e}",
    "s = {e}",
    "xs[0] = {e}",
    "m[s] = {e}",
    "{e}",
    "if {e} {{ return {e} }}",
    "if o != null {{ o.f({e}) }} else {{ a = 1 }}",
    "if s in m {{ a = m[s] }}",
    "while {e} {{ a += 1 }}",
    "for x{n} in {e} {{ send(self, x{n}) }}",
    "return {e}",
    "return",
    "let g2 = helper",
    "g({e})",
];

fn expr(ix: &[usize]) -> String {
    match ix {
        [] => "a".to_string(),
        [e] => EXPRS[e % EXPRS.len()].to_string(),
        [l, op, rest @ ..] => format!(
            "{} {} {}",
            EXPRS[l % EXPRS.len()],
            BINOPS[op % BINOPS.len()],
            expr(rest)
        ),
    }
}

fn program(stmts: &[(usize, Vec<usize>, Vec<usize>)], ret: usize) -> String {
    let rets = ["", " -> int", " -> string?", " -> any"];
    let mut src = String::from(
        "inherit /base\nvar pv: int = 0\nfn helper(n: int = 1) -> int {\n    return n\n}\n",
    );
    src.push_str(&format!(
        "fn f(a: int, s: string, o: object?, xs: [string], m: {{string: int}}, d: any, g: any){} {{\n",
        rets[ret % rets.len()]
    ));
    for (n, (k, e1, e2)) in stmts.iter().enumerate() {
        let t = STMTS[k % STMTS.len()];
        // Replace the first `{e}` with e1 and any later ones with e2.
        let line = t.replacen("{e}", &expr(e1), 1).replace("{e}", &expr(e2));
        let line = line
            .replace("{n}", &n.to_string())
            .replace("{{", "{")
            .replace("}}", "}");
        src.push_str("    ");
        src.push_str(&line);
        src.push('\n');
    }
    src.push_str("}\n");
    src
}

fn base() -> ParentInfo {
    let src = "pub fn base_fn() -> int {\n    return 1\n}\n";
    let (ast, d) = loom_syntax::parse(src);
    assert!(d.is_empty());
    let c = loom_compiler::check_program("/base", &ast, vec![], vec![]).expect("base");
    ParentInfo {
        label: None,
        info: c.info,
        span: loom_syntax::Span::default(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1500))]

    #[test]
    fn checker_never_panics(
        stmts in prop::collection::vec(
            (0..64usize, prop::collection::vec(0..64usize, 0..6), prop::collection::vec(0..64usize, 0..4)),
            0..12,
        ),
        ret in 0..4usize,
    ) {
        let src = program(&stmts, ret);
        let (ast, pd) = loom_syntax::parse(&src);
        prop_assume!(pd.is_empty());
        match loom_compiler::check_program("/p", &ast, vec![base()], vec![]) {
            Ok(c) => {
                let dump = loom_compiler::dump::program(&c.hir);
                prop_assert!(!dump.contains("{error}"), "poison in clean HIR:\n{}\n{}", src, dump);
            }
            Err(diags) => {
                prop_assert!(!diags.is_empty());
                for d in &diags {
                    prop_assert!(d.span.start <= d.span.end);
                    prop_assert!(d.span.end as usize <= src.len());
                    let _ = d.render("/p.wf", &src);
                }
            }
        }
    }
}
