// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Regression tests for OBI-92 (`LoomMud/loom` @ `8fc70b6`), reported against
//! the Warp alpha mudlib:
//!
//! 1. A `const` (local, and imported via `import /path.{NAME}`) used to lower
//!    to `ExprKind::Global` and read back `null` at runtime, because a
//!    `const` is never stored as an object variable (§5.3) for a
//!    `LoadGlobal` to find. Fixed by folding every `const` reference to its
//!    literal value in HIR instead (`docs/hir.md`: "const folds to literals
//!    in HIR"); see `loom_compiler::check::eval_const_value`.
//! 2. A `let` bound to a map index (`object?`) narrowed by `!= null` and
//!    used where `object` is expected (an array literal, a `call_other`
//!    receiver) verified fine per the checker but failed bytecode
//!    verification at load time, because codegen read the *local's*
//!    register (still `object?`) instead of respecting the narrowed *use*
//!    type. Fixed by casting to the narrowed type at each such read; see
//!    `codegen::FnLower::expr`'s `ExprKind::Local` arm.

mod common;

use common::{FakeHost, scratch};
use loom_vm::World;

fn run_files(files: &[(&str, &str)]) -> Result<String, String> {
    let root = scratch("obi92");
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

fn ok(files: &[(&str, &str)]) -> String {
    run_files(files).unwrap_or_else(|e| panic!("unexpected error:\n{e}"))
}

/// Bug 1, local `const`: used to render `null`.
#[test]
fn local_const_string_is_read_back_not_null() {
    let master = r#"
const START: string = "/x/y"
fn main() -> string {
    return $"{START}"
}
"#;
    assert_eq!(ok(&[("/secure/master.wf", master)]), "/x/y");
}

/// Bug 1, imported `pub const`: same symptom through `import`.
#[test]
fn imported_pub_const_is_read_back_not_null() {
    let util = "pub const START: string = \"/x/y\"\n";
    let master = r#"
import /lib/util.{START}
fn main() -> string {
    return $"{START}"
}
"#;
    assert_eq!(
        ok(&[("/secure/master.wf", master), ("/lib/util.wf", util)]),
        "/x/y"
    );
}

/// A `const` used in ordinary arithmetic/other-typed positions also reads
/// back correctly (not just plain identifier interpolation).
#[test]
fn const_participates_in_expressions_normally() {
    let master = r#"
const MAX: int = 10
fn main() -> int {
    return MAX + 1
}
"#;
    assert_eq!(ok(&[("/secure/master.wf", master)]), "11");
}

/// A non-compile-time-constant `const` initialiser is now a diagnostic
/// (W0291), not a silent `null` at runtime (§5.3's "either codegen should
/// emit the narrowing, or the checker should reject the program" spirit
/// applied to bug 1: a const the compiler cannot fold must be rejected).
#[test]
fn non_foldable_const_initialiser_is_a_diagnostic_not_a_silent_null() {
    let master = r#"
fn helper() -> int { return 1 }
const X: int = helper()
fn main() -> int { return X }
"#;
    let e = run_files(&[("/secure/master.wf", master)]).unwrap_err();
    assert!(e.contains("W0291"), "{e}");
}

/// CTO review (OBI-92) item 4: a negative numeric literal is a unary
/// minus in the AST; it must still fold (it did before consts were
/// restricted to compile-time constants), for ints and floats.
#[test]
fn negative_numeric_consts_fold() {
    let master = r#"
const MIN: int = -1
const LOW: float = -1.5
const TWICE: int = - -3
fn main() -> string {
    return $"{MIN} {LOW} {TWICE} {MIN + 1}"
}
"#;
    assert_eq!(ok(&[("/secure/master.wf", master)]), "-1 -1.5 3 0");
}

/// CTO review item 5: an array of constants folds too (shared evaluator
/// with struct field defaults), locally and through `import`.
#[test]
fn array_consts_fold_locally_and_through_import() {
    let util = "pub const DIRS: [string] = [\"north\", \"south\"]\n";
    let master = r#"
import /lib/util.{DIRS}
const NUMS: [int] = [1, -2, 3]
fn main() -> string {
    var total = 0
    for n in NUMS {
        total += n
    }
    return $"{len(DIRS)} {DIRS[1]} {total}"
}
"#;
    assert_eq!(
        ok(&[("/secure/master.wf", master), ("/lib/util.wf", util)]),
        "2 south 2"
    );
}

/// Arithmetic is not a compile-time constant in Phase 1 (D-P1.8): still
/// the W0291 diagnostic, pointing at the offending expression.
#[test]
fn const_arithmetic_is_still_rejected() {
    let master = r#"
const X: int = 1 + 2
fn main() -> int { return X }
"#;
    let e = run_files(&[("/secure/master.wf", master)]).unwrap_err();
    assert!(e.contains("W0291"), "{e}");
}

/// Bug 2: a `let` bound to a map index, narrowed by `!= null`, used as the
/// receiver of a call and inside an array literal (both `object`-typed
/// positions) used to pass `loom check` but fail bytecode verification at
/// load time (`verify: online: @26: %2 has type object?, not assignable to
/// object`).
#[test]
fn narrowed_optional_from_map_index_loads_and_runs() {
    let player = r#"
pub fn is_connected() -> bool {
    return true
}
"#;
    let master = r#"
var players: {string: object} = {:}

pub fn add(name: string, p: object) {
    players[name] = p
}

pub fn online() -> [object] {
    var out: [object] = []
    for n in players {
        let p = players[n]
        if p != null and (p.is_connected() as bool) {
            out += [p]
        }
    }
    return out
}

fn main() -> any {
    let p = clone_object("/obj/player")
    add("alice", p)
    let result = online()
    return len(result) == 1 and result[0] == p
}
"#;
    assert_eq!(
        ok(&[("/secure/master.wf", master), ("/obj/player.wf", player)]),
        "true"
    );
}
