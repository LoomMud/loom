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
    let checked = check_program("/t", &ast, Vec::new(), Vec::new()).expect("checks");
    super::compile(&checked.hir).expect("codegen")
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
                out.push(super::compile(&c.hir).expect("codegen"));
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

/// r5 D24: containers are copy-on-write values, so `IndexSet` mutates a
/// register that is *a copy* of what `LoadGlobal` produced, not the global
/// storage itself. An index-assign into a global container (`exits[dir] =
/// dest`) must therefore also `StoreGlobal` the mutated register back, or
/// the edit is invisible to every other read of that global (found by the
/// `loom-vm` end-to-end test running this exact shape against the VM).
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
    let has_index_set = f
        .code
        .iter()
        .any(|op| matches!(op, crate::bytecode::Op::IndexSet { .. }));
    let store_global_after_index_set = f
        .code
        .iter()
        .position(|op| matches!(op, crate::bytecode::Op::IndexSet { .. }))
        .and_then(|i| f.code.get(i + 1))
        .is_some_and(|op| matches!(op, crate::bytecode::Op::StoreGlobal { .. }));
    assert!(
        has_index_set,
        "expected an IndexSet op:\n{}",
        crate::disasm::module(&m)
    );
    assert!(
        store_global_after_index_set,
        "IndexSet into a global must be followed by a StoreGlobal to write the mutated copy back:\n{}",
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
