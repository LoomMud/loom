// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `try`/`catch`/`throw` runtime semantics (spec r5, OBI-32): typed error
//! values, cross-call unwinding to the nearest active handler, and
//! tick/depth exhaustion never reaching a `catch`.

mod common;

use common::{FakeHost, scratch};
use loom_vm::World;

fn run_files(files: &[(&str, &str)]) -> Result<String, String> {
    let root = scratch("try_catch");
    for (path, src) in files {
        let p = root.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, src).unwrap();
    }
    let mut world = World::boot(&root).map_err(|e| e.to_string())?;
    let master = world.find_object("/secure/master").unwrap();
    let v = world.call(master, "main", vec![], &mut FakeHost::default())?;
    Ok(world.display(&v))
}

fn ok(master: &str) -> String {
    run_files(&[("/secure/master.wf", master)]).unwrap_or_else(|e| panic!("unexpected error:\n{e}"))
}

fn main_returning(body: &str) -> String {
    format!("fn main() -> any {{\n{body}\n}}\n")
}

/// `throw` a value, catch it in the same function: `catch_var` is bound to
/// exactly the thrown value (spec: "typed error values" keep their type,
/// not just a message string).
#[test]
fn catch_binds_the_thrown_value_unchanged() {
    let out = ok(&main_returning(
        r#"try {
    throw "boom"
} catch e {
    return e
}
return "not reached""#,
    ));
    assert_eq!(out, "boom");
}

/// A `catch` with no binding still catches (grammar: `catch { }` is valid
/// alongside `catch e { }`).
#[test]
fn catch_without_a_binding_still_catches() {
    let out = ok(&main_returning(
        r#"try {
    throw 1
} catch {
    return "caught"
}
return "not reached""#,
    ));
    assert_eq!(out, "caught");
}

/// A `try` whose body completes normally skips the handler entirely.
#[test]
fn try_body_completing_normally_skips_the_handler() {
    let out = ok(&main_returning(
        r#"var result = "unset"
try {
    result = "tried"
} catch e {
    result = "caught"
}
return result"#,
    ));
    assert_eq!(out, "tried");
}

/// A built-in runtime error (not an explicit `throw`) is still catchable:
/// `catch_var` sees the error message as a string.
#[test]
fn built_in_runtime_errors_are_catchable_as_a_message_string() {
    let out = ok(&main_returning(
        r#"var out = "unset"
try {
    let z = 0
    let x = 1 / z
} catch e {
    out = e
}
return out"#,
    ));
    assert_eq!(out, "division by zero");
}

/// `throw` inside a callee, caught by the caller's `try` \u2014 the error
/// unwinds across the call boundary (D26: the whole chain is one flat
/// frame stack) straight to the nearest active handler, not necessarily
/// the immediate frame.
#[test]
fn catch_unwinds_across_a_nested_call() {
    let out = ok(r#"fn inner() -> int {
    throw "from inner"
}
fn middle() -> int {
    return inner()
}
fn main() -> any {
    try {
        return middle()
    } catch e {
        return e
    }
}
"#);
    assert_eq!(out, "from inner");
}

/// The innermost active handler wins (nested `try`/`catch`).
#[test]
fn innermost_handler_catches_first() {
    let out = ok(&main_returning(
        r#"try {
    try {
        throw "inner throw"
    } catch e {
        return "inner caught: " + e
    }
} catch e {
    return "outer caught: " + e
}"#,
    ));
    assert_eq!(out, "inner caught: inner throw");
}

/// An uncaught throw (no active handler) still surfaces as an ordinary
/// runtime error to the caller, with the thrown value's display form as
/// the message.
#[test]
fn uncaught_throw_surfaces_as_a_runtime_error() {
    let err = run_files(&[(
        "/secure/master.wf",
        &main_returning("throw \"unhandled\"\nreturn null"),
    )])
    .unwrap_err();
    assert!(err.contains("unhandled"), "{err}");
}

/// Tick exhaustion is not catchable (spec): a `try` around a runaway loop
/// does not stop the error from propagating.
#[test]
fn tick_exhaustion_is_not_catchable() {
    let err = run_files(&[(
        "/secure/master.wf",
        &main_returning(
            r#"try {
    var i = 0
    while true {
        i += 1
    }
    return i
} catch e {
    return "caught (should not happen)"
}"#,
        ),
    )])
    .unwrap_err();
    assert!(err.contains("Too long evaluation"), "{err}");
}

/// Call-depth exhaustion is not catchable either.
#[test]
fn depth_exhaustion_is_not_catchable() {
    let err = run_files(&[(
        "/secure/master.wf",
        r#"fn dive() -> int {
    try {
        return dive()
    } catch e {
        return -1
    }
}
fn main() -> any {
    return dive()
}
"#,
    )])
    .unwrap_err();
    assert!(err.contains("Too deep recursion"), "{err}");
}
