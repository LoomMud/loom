// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Unit tests over real (parsed + checked) HIR: small snippets exercising
//! one lowering path each, verified end to end (codegen → verify).

use std::collections::HashMap;

use crate::check::check_program;
use crate::verify::verify;

fn compile_one(src: &str) -> crate::bytecode::Module {
    let (ast, diags) = loom_syntax::parse(src);
    assert!(diags.is_empty(), "{diags:?}");
    let checked = check_program("/t", src, &ast, Vec::new(), Vec::new()).expect("checks");
    super::compile(&checked.hir, &checked.src).expect("codegen")
}

fn compile_mudlib(files: &[(&str, &str)]) -> Vec<crate::bytecode::Module> {
    let mut loader = HashMap::new();
    for (path, src) in files {
        loader.insert(path.to_string(), src.to_string());
    }
    let mut session = crate::mudlib::Session::new(loader);
    let mut out = Vec::new();
    for (path, _) in files {
        match session.compile(path) {
            crate::mudlib::Outcome::Ok(c) => {
                out.push(super::compile(&c.hir, &c.src).expect("codegen"));
            }
            crate::mudlib::Outcome::Failed(r) => panic!("{r}"),
            crate::mudlib::Outcome::Missing(r) => panic!("{r}"),
        }
    }
    out
}

#[test]
fn arithmetic_and_return() {
    let m = compile_one("fn f(x: int) -> int { return x + 1 }");
    verify(&m).expect("verify");
}

#[test]
fn if_else_and_locals() {
    let m = compile_one(
        r#"
        fn f(x: int) -> string {
            if x > 0 {
                let s = "pos"
                return s
            } else {
                return "nonpos"
            }
        }
        "#,
    );
    verify(&m).expect("verify");
}

#[test]
fn while_loop_ticks() {
    let m = compile_one(
        r#"
        fn f() -> int {
            var i = 0
            while i < 10 {
                i += 1
            }
            return i
        }
        "#,
    );
    verify(&m).expect("verify");
    let f = &m.functions[0];
    assert!(
        f.code
            .iter()
            .any(|op| matches!(op, crate::bytecode::Op::TickCheck)),
        "expected a tick check in the loop"
    );
}

#[test]
fn for_over_array() {
    let m = compile_one(
        r#"
        fn f(xs: [int]) -> int {
            var total = 0
            for x in xs {
                total += x
            }
            return total
        }
        "#,
    );
    verify(&m).expect("verify");
}

#[test]
fn string_interpolation() {
    let m = compile_one(
        r#"
        fn f(x: int) -> string {
            return $"x is {x}!"
        }
        "#,
    );
    verify(&m).expect("verify");
}

#[test]
fn and_or_coalesce() {
    let m = compile_one(
        r#"
        fn f(a: bool, b: bool, o: int?) -> int {
            if a and b {
                return 1
            }
            if a or b {
                return 2
            }
            return o ?? 0
        }
        "#,
    );
    verify(&m).expect("verify");
}

#[test]
fn efun_and_call_other() {
    let files = [(
        "/std/room",
        "pub fn short() -> string { return \"a room\" }\n\
             pub fn look(ob: object) -> string { return ob.short() }\n",
    )];
    let modules = compile_mudlib(&files);
    for m in &modules {
        verify(m).expect("verify");
    }
}

#[test]
fn map_and_index() {
    let m = compile_one(
        r#"
        fn f() -> {string: int} {
            let m = {"a": 1, "b": 2}
            return m
        }
        "#,
    );
    verify(&m).expect("verify");
}

#[test]
fn compound_assign_to_global() {
    let m = compile_one(
        r#"
        var n: int = 0
        pub fn bump() {
            n += 1
        }
        "#,
    );
    verify(&m).expect("verify");
}

/// r5 D24 / OBI-108: an index-assign into a global container (`exits[dir]
/// = dest`) must move the container out of the global (leaving `Null`)
/// rather than clone the global's own `Rc` into a register and mutate
/// that, then write the mutated register back — the codegen shape found
/// (by the `loom-vm` end-to-end test running this exact shape against the
/// VM) is a single `IndexSetGlobal` op, not a `LoadGlobal` + `IndexSet` +
/// `StoreGlobal` triple (the latter always sees the global's slot and the
/// register as two live owners of the same buffer, so `IndexSet` clones
/// the whole container on every single write — O(n²) filling one by
/// index).
#[test]
fn index_assign_into_a_global_container_writes_it_back() {
    let m = compile_one(
        r#"
        var exits: {string: string} = {:}
        pub fn add_exit(dir: string, dest: string) {
            exits[dir] = dest
        }
        "#,
    );
    verify(&m).expect("verify");
    let f = m
        .functions
        .iter()
        .find(|f| &*m.strings[f.name as usize] == "add_exit")
        .unwrap();
    let has_index_set_global = f
        .code
        .iter()
        .any(|op| matches!(op, crate::bytecode::Op::IndexSetGlobal { .. }));
    let has_old_shape = f.code.iter().any(|op| {
        matches!(
            op,
            crate::bytecode::Op::IndexSet { .. } | crate::bytecode::Op::StoreGlobal { .. }
        )
    });
    assert!(
        has_index_set_global,
        "expected an IndexSetGlobal op:\n{}",
        crate::disasm::module(&m)
    );
    assert!(
        !has_old_shape,
        "a plain `global[i] = v` should not need a separate LoadGlobal/IndexSet/StoreGlobal \
         triple any more (OBI-108):\n{}",
        crate::disasm::module(&m)
    );
}

#[test]
fn safe_call_other() {
    let files = [
        (
            "/std/room",
            "pub fn short() -> string { return \"a room\" }\n",
        ),
        (
            "/std/user",
            "pub fn look(ob: object?) -> string? { return ob?.short() }\n",
        ),
    ];
    let modules = compile_mudlib(&files);
    for m in &modules {
        verify(m).expect("verify");
    }
}

#[test]
fn default_params_prologue_min_arity_and_entry_points() {
    // Three params, two trailing defaults: `min_arity` is 1 and there must
    // be one entry point per possible call arity (1, 2 or 3 args).
    let m = compile_one(
        r#"
        fn greet(name: string, greeting: string = "hello", punct: string = "!") -> string {
            return greeting + " " + name + punct
        }
        "#,
    );
    verify(&m).expect("verify");
    let f = &m.functions[0];
    assert_eq!(f.params, 3);
    assert_eq!(f.min_arity, 1, "two trailing params have defaults");
    assert_eq!(
        f.entry_points.len(),
        3,
        "one entry point per arity in min_arity..=params: {}",
        crate::disasm::module(&m)
    );
    // The "every argument supplied" entry point is the function's real
    // body: codegen never disturbs it, so it stays at pc 0 and the
    // shorter-arity entries are the newly appended default-eval blocks
    // that fall through into it (or into each other).
    assert_eq!(
        f.entry_points[2],
        0,
        "full-arity entry point must be the unmodified function body:\n{}",
        crate::disasm::module(&m)
    );
    assert_ne!(f.entry_points[0], f.entry_points[1]);
    assert_ne!(f.entry_points[1], f.entry_points[2]);
    // No jump target may point past the end of the code (also covered by
    // `verify`, checked again here as the direct acceptance criterion).
    for &pc in &f.entry_points {
        assert!((pc as usize) < f.code.len());
    }
}

#[test]
fn default_params_reject_wrong_arity_at_verify() {
    // The verifier's static-call arity check must widen from an exact
    // match to the `[min_arity, params]` range (OBI-77).
    let src = r#"
    fn greet(name: string, greeting: string = "hi") -> string {
        return greeting + name
    }
    fn main() -> any {
        return greet()
    }
    "#;
    let (ast, diags) = loom_syntax::parse(src);
    assert!(diags.is_empty(), "{diags:?}");
    // Too few arguments is a checker-level error (missing required
    // argument), not something codegen ever sees: confirm the checker
    // rejects it up front.
    assert!(crate::check::check_program("/t", src, &ast, Vec::new(), Vec::new()).is_err());
}

// ---------------------------------------------------------------------
// Place-write lowering (OBI-53, spec r5 §5.2.1 rule 3): `a[i] = v`,
// `m[k] op= v`, nested `a[i][j] = v` and `xs += [x]` must lower as
// take → mutate → put back, one test per path, on both a local and a
// program variable. Assertions read the disassembly rather than counting
// registers, so they stay robust to register-allocation changes but still
// catch the original bug: a `LoadGlobal` (or nested `Index` read) with no
// matching `StoreGlobal` (or outer `IndexSet`) writing the mutation back.

fn disasm_fn(m: &crate::bytecode::Module, name: &str) -> String {
    let f = m
        .functions
        .iter()
        .find(|f| &*m.strings[f.name as usize] == name)
        .unwrap_or_else(|| panic!("no function {name}"));
    crate::disasm::function(m, f)
}

#[test]
fn element_write_array_index_on_local() {
    let m = compile_one(
        r#"
        fn f() {
            var xs = [1, 2, 3]
            xs[0] = 9
        }
        "#,
    );
    verify(&m).expect("verify");
    let text = disasm_fn(&m, "f");
    // The local's own register is mutated directly: one `IndexSet` and no
    // `LoadGlobal`/`StoreGlobal` (there is nowhere to load from or store
    // to — it is a local, not a program variable).
    assert!(text.contains("IndexSet.Array"), "{text}");
    assert!(!text.contains("LoadGlobal"), "{text}");
    assert!(!text.contains("StoreGlobal"), "{text}");
}

#[test]
fn element_write_array_index_on_global() {
    let m = compile_one(
        r#"
        var xs: [int] = [1, 2, 3]
        pub fn f() {
            xs[0] = 9
        }
        "#,
    );
    verify(&m).expect("verify");
    let text = disasm_fn(&m, "f");
    // Single-level global index-assign takes the OBI-108 fast path: a
    // single `IndexSetGlobal` op that takes the container straight out of
    // the global, mutates it in place, and commits it back -- no
    // `LoadGlobal`/`IndexSet`/`StoreGlobal` round trip (that shape is
    // exactly the O(n^2)-on-repeated-writes bug OBI-108 closed).
    assert!(!text.contains("LoadGlobal"), "{text}");
    assert!(!text.contains("StoreGlobal"), "{text}");
    assert!(!text.contains("IndexSet."), "{text}");
    assert!(text.contains("IndexSetGlobal.Array"), "{text}");
}

#[test]
fn compound_element_write_map_key_on_local() {
    let m = compile_one(
        r#"
        fn f() {
            var m = {"a": 1}
            m["a"] += 1
        }
        "#,
    );
    verify(&m).expect("verify");
    let text = disasm_fn(&m, "f");
    assert!(text.contains("Index.Map"), "{text}");
    assert!(text.contains("BinOp.Int Add"), "{text}");
    assert!(text.contains("IndexSet.Map"), "{text}");
    assert!(!text.contains("LoadGlobal"), "{text}");
    assert!(!text.contains("StoreGlobal"), "{text}");
}

#[test]
fn compound_element_write_map_key_on_global() {
    let m = compile_one(
        r#"
        var m: {string: int} = {"a": 1}
        pub fn f() {
            m["a"] += 1
        }
        "#,
    );
    verify(&m).expect("verify");
    let text = disasm_fn(&m, "f");
    // The compound case still needs a read-only `LoadGlobal` + `Index` to
    // combine the current element with the RHS (an O(1) element clone,
    // never followed by a mutation of that register -- OBI-108), then
    // writes the combined value back with the same single-op
    // `IndexSetGlobal` fast path the plain `Set` case uses: no ordinary
    // `IndexSet`/`StoreGlobal` round trip.
    assert!(text.contains("LoadGlobal"), "{text}");
    assert!(text.contains("Index.Map"), "{text}");
    assert!(text.contains("IndexSetGlobal.Map"), "{text}");
    assert!(!text.contains("IndexSet."), "{text}");
    assert!(!text.contains("StoreGlobal"), "{text}");
}

#[test]
fn nested_element_write_on_local() {
    let m = compile_one(
        r#"
        fn f() {
            var a = [[1, 2], [3, 4]]
            a[0][1] = 9
        }
        "#,
    );
    verify(&m).expect("verify");
    let text = disasm_fn(&m, "f");
    // Take the inner array out of `a[0]` (an `Index` read), mutate it, put
    // it back with an `IndexSet` into `a` — `a` itself is a local, so that
    // is the end of the chain, no `LoadGlobal`/`StoreGlobal` anywhere.
    let index_reads = text.matches("Index.Array %").count();
    let index_sets = text.matches("IndexSet.Array").count();
    assert_eq!(index_reads, 1, "exactly one read of a[0]:\n{text}");
    assert_eq!(
        index_sets, 2,
        "one IndexSet for a[0][1]=9, one put-back into a[0]:\n{text}"
    );
    assert!(!text.contains("LoadGlobal"), "{text}");
    assert!(!text.contains("StoreGlobal"), "{text}");
}

#[test]
fn nested_element_write_on_global() {
    let m = compile_one(
        r#"
        var a: [[int]] = [[1, 2], [3, 4]]
        pub fn f() {
            a[0][1] = 9
        }
        "#,
    );
    verify(&m).expect("verify");
    let text = disasm_fn(&m, "f");
    // Take `a` out (LoadGlobal), take `a[0]` out (Index), mutate, put
    // `a[0]` back into `a` (IndexSet), put `a` back (StoreGlobal): every
    // level of the chain writes back up to the root variable.
    assert!(text.contains("LoadGlobal"), "{text}");
    assert_eq!(
        text.matches("Index.Array %").count(),
        1,
        "exactly one read of a[0]:\n{text}"
    );
    assert_eq!(
        text.matches("IndexSet.Array").count(),
        2,
        "one IndexSet for a[0][1]=9, one put-back into a:\n{text}"
    );
    assert!(text.contains("StoreGlobal"), "{text}");
}

#[test]
fn compound_assign_whole_array_on_local() {
    // `xs += [x]` reassigns the whole local (array concatenation), not an
    // element write — `Place::Local`/`Place::Global` directly, already
    // correct before this change; kept as a regression test for the path
    // named explicitly in the ticket.
    let m = compile_one(
        r#"
        fn f() -> [int] {
            var xs = [1]
            xs += [2]
            return xs
        }
        "#,
    );
    verify(&m).expect("verify");
    let text = disasm_fn(&m, "f");
    assert!(text.contains("BinOp.Array Add"), "{text}");
    assert!(!text.contains("LoadGlobal"), "{text}");
    assert!(!text.contains("StoreGlobal"), "{text}");
}

#[test]
fn compound_assign_whole_array_on_global() {
    let m = compile_one(
        r#"
        var xs: [int] = [1]
        pub fn f() {
            xs += [2]
        }
        "#,
    );
    verify(&m).expect("verify");
    let text = disasm_fn(&m, "f");
    assert!(text.contains("BinOp.Array Add"), "{text}");
    assert!(text.contains("LoadGlobal"), "{text}");
    assert!(text.contains("StoreGlobal"), "{text}");
}

// ---------------------------------------------------------------------
// OBI-231: per-instruction line table.
// ---------------------------------------------------------------------

#[test]
fn every_function_has_a_line_table_the_same_length_as_its_code() {
    let m = compile_one(
        r#"
        fn f(x: int) -> int {
            var y = x + 1
            if y > 0 {
                return y
            }
            return 0
        }
        "#,
    );
    let f = &m.functions[0];
    assert_eq!(f.lines.len(), f.code.len());
    assert!(f.lines.iter().all(|&l| l >= 1), "{:?}", f.lines);
}

#[test]
fn line_table_tracks_statement_granularity_not_just_function_entry() {
    // Lines 1-indexed from the start of this literal: `fn f...` is line 2
    // (line 1 is the leading newline from the raw string), `return x + 1`
    // is line 3.
    let checked = {
        let src = "\nfn f(x: int) -> int {\n    return x + 1\n}\n";
        let (ast, diags) = loom_syntax::parse(src);
        assert!(diags.is_empty(), "{diags:?}");
        check_program("/t", src, &ast, Vec::new(), Vec::new()).expect("checks")
    };
    let m = super::compile(&checked.hir, &checked.src).expect("codegen");
    let f = &m.functions[0];
    // Every op in this one-statement body is attributed to line 3 (the
    // `return` statement), not line 1 or 2.
    assert!(
        f.lines.iter().all(|&l| l == 3),
        "expected every op on line 3, got {:?}",
        f.lines
    );
}

#[test]
fn distinct_statements_get_distinct_lines() {
    let src = "fn f(x: int) -> int {\n    var y = x + 1\n    return y\n}\n";
    let (ast, diags) = loom_syntax::parse(src);
    assert!(diags.is_empty(), "{diags:?}");
    let checked = check_program("/t", src, &ast, Vec::new(), Vec::new()).expect("checks");
    let m = super::compile(&checked.hir, &checked.src).expect("codegen");
    let f = &m.functions[0];
    // `var y = x + 1` is line 2, `return y` is line 3: the line table must
    // actually distinguish them, not just attribute everything to the
    // function's first line.
    assert!(f.lines.contains(&2), "{:?}", f.lines);
    assert!(f.lines.contains(&3), "{:?}", f.lines);
}
