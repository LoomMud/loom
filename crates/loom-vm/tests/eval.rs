// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Evaluator unit tests: each case is a tiny mudlib whose master defines
//! `main()`; the result is rendered as Weft interpolation would.

mod common;

use common::{FakeHost, scratch};
use loom_vm::World;

/// Boot a mudlib from `(path, source)` pairs and call `main()` on the master.
fn run_files(files: &[(&str, &str)]) -> Result<String, String> {
    let root = scratch("eval");
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

fn run(master: &str) -> Result<String, String> {
    run_files(&[("/secure/master.wf", master)])
}

fn ok(master: &str) -> String {
    run(master).unwrap_or_else(|e| panic!("unexpected error:\n{e}"))
}

fn err(master: &str) -> String {
    match run(master) {
        Ok(v) => panic!("expected an error, got {v}"),
        Err(e) => e,
    }
}

fn main_returning(body: &str) -> String {
    format!("fn main() -> any {{\n{body}\n}}\n")
}

#[test]
fn arithmetic_and_precedence() {
    assert_eq!(ok(&main_returning("return 1 + 2 * 3 - 10 / 3 % 2")), "6");
    assert_eq!(ok(&main_returning("return -(2 + 3) * -1")), "5");
    let e = err(&main_returning("return 9223372036854775807 + 1"));
    assert!(e.contains("integer overflow"), "{e}");
    let e = err(&main_returning("let z = 0\nreturn 1 % z"));
    assert!(e.contains("master.wf:3:8: division by zero"), "{e}");
}

#[test]
fn strings_and_interpolation() {
    assert_eq!(
        ok(&main_returning(
            "let n = 3\nlet m = {\"k\": [1, \"two\"]}\nreturn $\"n={n} m={m} {n * 2}! {\"lit\"} \\{x\\}\""
        )),
        "n=3 m={\"k\": [1, \"two\"]} 6! lit {x}"
    );
    assert_eq!(ok(&main_returning("return \"ab\" + \"cd\"")), "abcd");
    assert_eq!(ok(&main_returning("return \"ell\" in \"hello\"")), "true");
    assert_eq!(ok(&main_returning("return \"héllo\"[1]")), "é");
    let e = err(&main_returning("return \"n=\" + 1"));
    assert!(e.contains("cannot apply `+` to string and int"), "{e}");
    assert!(e.contains("$\""), "{e}");
}

#[test]
fn arrays_maps_and_loops() {
    let src = main_returning(
        r#"var xs = [1, 2, 3]
xs[0] = 10
xs[1] += 5
xs += [4]
var m: {string: int} = {:}
m["b"] = 2
m["a"] = 1
m["b"] += 40
var total = 0
for x in xs {
    total += x
}
var ks = ""
for k in m {
    ks = ks + k
}
return [total, ks, keys(m), m["zz"], len(m), 3 in xs, "a" in m]"#,
    );
    assert_eq!(
        ok(&src),
        "[24, \"ba\", [\"b\", \"a\"], null, 2, true, true]"
    );
    let e = err(&main_returning("let xs = [1]\nreturn xs[1]"));
    assert!(e.contains("index 1 out of range (length 1)"), "{e}");
}

#[test]
fn arrays_have_reference_semantics() {
    let src = main_returning("let a = [1]\nlet b = a\nb[0] = 2\nreturn [a[0], a == b, [1] == [1]]");
    assert_eq!(ok(&src), "[2, true, false]");
}

#[test]
fn while_if_else_chain() {
    let src = r#"
fn classify(n: int) -> string {
    if n < 0 {
        return "neg"
    } else if n == 0 {
        return "zero"
    } else {
        return "pos"
    }
}

fn main() -> any {
    var i = -1
    var out: [string] = []
    while i <= 1 {
        out += [classify(i)]
        i += 1
    }
    return join(out, ",")
}
"#;
    assert_eq!(ok(src), "neg,zero,pos");
}

#[test]
fn no_truthiness() {
    let e = err(&main_returning("if 1 {\n  return 1\n}\nreturn 0"));
    assert!(e.contains("`if` condition must be bool, got int"), "{e}");
    let e = err(&main_returning("return 1 and true"));
    assert!(e.contains("`and` needs bool operands"), "{e}");
    let e = err(&main_returning("return not null"));
    assert!(e.contains("`not` needs a bool"), "{e}");
}

#[test]
fn short_circuit_and_null_handling() {
    // `and`/`or` do not evaluate the right side when decided.
    let src = main_returning(
        "let xs: [int] = []\nlet a = len(xs) > 0 and xs[0] == 1\nlet b = true or xs[5] == 0\nlet o: object? = null\nreturn [a, b, o?.anything(), o ?? \"dflt\", 5 ?? 6]",
    );
    assert_eq!(ok(&src), "[false, true, null, \"dflt\", 5]");
    let e = err(&main_returning("let o: object? = null\nreturn o.name()"));
    assert!(e.contains("called `name()` on null"), "{e}");
    assert!(e.contains("?."), "{e}");
}

#[test]
fn functions_defaults_and_runtime_type_checks() {
    let src = r#"
fn greet(name: string, greeting: string = "hello") -> string {
    return $"{greeting} {name}"
}

fn main() -> any {
    return [greet("bob"), greet("amy", "hi")]
}
"#;
    assert_eq!(ok(src), "[\"hello bob\", \"hi amy\"]");
    let e = err("fn f(n: int) -> int {\n  return n\n}\nfn main() -> any {\n  return f(\"x\")\n}\n");
    assert!(e.contains("argument `n` must be int, got string"), "{e}");
    let e = err("fn f() -> int {\n  return \"s\"\n}\nfn main() -> any {\n  return f()\n}\n");
    assert!(
        e.contains("f() must return int, but returned string"),
        "{e}"
    );
    let e = err("fn f(a: int) {\n}\nfn main() -> any {\n  return f()\n}\n");
    assert!(e.contains("missing argument `a`"), "{e}");
    let e = err("var n: int = 0\nfn main() -> any {\n  n = \"x\"\n  return n\n}\n");
    assert!(
        e.contains("`n` is declared int but the value is string"),
        "{e}"
    );
    let e = err(&main_returning("let s: string = 5\nreturn s"));
    assert!(
        e.contains("`s` is declared string but the value is int"),
        "{e}"
    );
}

#[test]
fn link_time_diagnostics() {
    let e = err(&main_returning("let x = 1\nx = 2\nreturn x"));
    assert!(
        e.contains("cannot assign to `x`: it was declared with `let`"),
        "{e}"
    );
    assert!(e.contains("help: declare it with `var x`"), "{e}");
    let e = err(&main_returning("return nope"));
    assert!(e.contains("unknown variable `nope`"), "{e}");
    let e = err(&main_returning("return set_shrot(1)"));
    assert!(e.contains("unknown function `set_shrot`"), "{e}");
    let e = err(&main_returning("return len(1, 2)"));
    assert!(
        e.contains("`len` takes 1 argument, but 2 were given"),
        "{e}"
    );
    let e = err("var x: float = 1\nfn main() {\n}\n");
    assert!(e.contains("unknown type `float`"), "{e}");
    let e = err("override fn main() {\n}\n");
    assert!(e.contains("overrides nothing"), "{e}");
    let e = err("fn main() {\n}\nfn main() {\n}\n");
    assert!(e.contains("declared twice"), "{e}");
    let e = err(&main_returning("for x in [1] {\n  x = 2\n}\nreturn 0"));
    assert!(e.contains("cannot assign to `x`"), "{e}");
    let e = err(&main_returning("let y = 1\nreturn len"));
    assert!(e.contains("`len` is a function"), "{e}");
}

#[test]
fn syntax_errors_are_reported_with_line_and_column() {
    let e = err("fn main() {\n  let x = (1 + \n}\n");
    assert!(e.contains("/secure/master.wf:3:1: error"), "{e}");
}

const ROOM: &str = r#"
var short_desc: string = "room"
var log: [string] = []

fn create() {
    log += ["room.create"]
}

fn note(s: string) {
    log += [s]
}

pub fn short() -> string {
    return short_desc
}

pub fn describe() -> string {
    return $"<{short()}>"
}

pub fn history() -> [string] {
    return log
}

fn helper() -> string {
    return "internal"
}

private fn secret() -> string {
    return "room-secret"
}

pub fn reveal() -> string {
    return secret()
}
"#;

const HALL: &str = r#"
inherit /std/room

override fn create() {
    super::create()
    note("hall.create")
    short_desc = "hall"
}

override fn short() -> string {
    return $"The {super::short()}"
}

private fn secret() -> string {
    return "hall-secret"
}

pub fn both() -> string {
    return $"{secret()}/{reveal()}/{helper()}"
}
"#;

#[test]
fn inheritance_super_override_and_private() {
    let master = r#"
fn main() -> any {
    let h = load_object("/domains/hall")
    return [h.describe(), h.history(), h.both(), object_name(h), find_object("/domains/hall") == h]
}
"#;
    let r = run_files(&[
        ("/secure/master.wf", master),
        ("/std/room.wf", ROOM),
        ("/domains/hall.wf", HALL),
    ])
    .unwrap();
    assert_eq!(
        r,
        "[\"<The hall>\", [\"room.create\", \"hall.create\"], \"hall-secret/room-secret/internal\", \"/domains/hall\", true]"
    );
}

#[test]
fn cross_object_calls_need_pub_and_existing_functions() {
    let files = |main: &'static str| {
        [
            ("/secure/master.wf", main),
            ("/std/room.wf", ROOM),
            ("/domains/hall.wf", HALL),
        ]
    };
    let e = run_files(&files(
        "fn main() -> any {\n  return load_object(\"/domains/hall\").helper()\n}\n",
    ))
    .unwrap_err();
    assert!(e.contains("`helper` in /std/room is not `pub`"), "{e}");
    let e = run_files(&files(
        "fn main() -> any {\n  return load_object(\"/domains/hall\").fly()\n}\n",
    ))
    .unwrap_err();
    assert!(e.contains("/domains/hall has no function `fly`"), "{e}");
    assert!(e.contains("master.wf:2:"), "{e}");
}

#[test]
fn objects_clones_and_movement() {
    let thing = "pub fn id() -> string {\n  return \"thing\"\n}\npub fn go(dest: object) {\n  move_to(dest)\n}\n";
    let master = r#"
fn main() -> any {
    let box = load_object("/obj/thing")
    let a = clone_object("/obj/thing")
    let b = clone_object("/obj/thing")
    a.go(box)
    b.go(box)
    b.go(a)
    return [object_name(a), a == b, inventory(box), environment(b) == a, environment(box), self() == self, a.id()]
}
"#;
    let r = run_files(&[("/secure/master.wf", master), ("/obj/thing.wf", thing)]).unwrap();
    assert_eq!(
        r,
        "[\"/obj/thing#1\", false, [/obj/thing#1], true, null, true, \"thing\"]"
    );
    let bad = r#"
fn main() -> any {
    let a = clone_object("/obj/thing")
    let b = clone_object("/obj/thing")
    b.go(a)
    a.go(b)
    return 0
}
"#;
    let e = run_files(&[("/secure/master.wf", bad), ("/obj/thing.wf", thing)]).unwrap_err();
    assert!(e.contains("cannot move an object into itself"), "{e}");
}

#[test]
fn string_efuns() {
    assert_eq!(
        ok(&main_returning(
            "return [split(\"a b  c\", \" \"), join([\"x\", \"y\"], \"-\"), trim(\"  hi \\n\"), len(\"héllo\")]"
        )),
        "[[\"a\", \"b\", \"\", \"c\"], \"x-y\", \"hi\", 5]"
    );
    let e = err(&main_returning("return join([1], \",\")"));
    assert!(e.contains("join(): array elements must be strings"), "{e}");
}

#[test]
fn load_errors_surface_as_runtime_errors() {
    let e = err(&main_returning("return load_object(\"/nope\")"));
    assert!(e.contains("load_object(\"/nope\") failed"), "{e}");
    assert!(e.contains("cannot read"), "{e}");
    let e = err(&main_returning("return load_object(\"../etc/passwd\")"));
    assert!(e.contains("must be absolute"), "{e}");
    let e = err(&main_returning("return load_object(\"/a/../b\")"));
    assert!(e.contains("invalid program path"), "{e}");
}

#[test]
fn inherit_cycles_are_reported() {
    let r = run_files(&[
        (
            "/secure/master.wf",
            "fn main() -> any {\n  return load_object(\"/a\")\n}\n",
        ),
        ("/a.wf", "inherit /b\n"),
        ("/b.wf", "inherit /a\n"),
    ]);
    let e = r.unwrap_err();
    assert!(e.contains("inherit cycle"), "{e}");
}

#[test]
fn bind_connection_is_master_only() {
    let other = "pub fn steal() {\n  bind_connection(self)\n}\n";
    let master = "fn main() -> any {\n  load_object(\"/obj/other\").steal()\n  return 0\n}\n";
    let e = run_files(&[("/secure/master.wf", master), ("/obj/other.wf", other)]).unwrap_err();
    assert!(e.contains("may only be called by /secure/master"), "{e}");
}
