// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-108 (CTO review of PR #8): `Op::IndexSetGlobal` really moves a
//! global's container out for an in-place index-assign, instead of
//! `LoadGlobal` cloning the global's own `Rc` and leaving both the
//! register and the global's slot as live owners for `IndexSet`'s
//! copy-on-write check to see (and clone the whole container on account
//! of). This is the semantic half of that fix: a write that fails midway
//! (an out-of-range index) must leave the global exactly as it was, not
//! `null` from the take that never got undone. The scaling half is
//! `crates/loom-vm/examples/vm_bench.rs`'s `global_map_fill*`/
//! `global_array_fill*` workloads.

mod common;

use common::{FakeHost, scratch};
use loom_vm::World;

fn boot(master: &str) -> World {
    let root = scratch("obi-108");
    let p = root.join("secure/master.wf");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, master).unwrap();
    World::boot(&root).expect("boot")
}

#[test]
fn an_out_of_range_index_write_leaves_the_global_array_intact() {
    let mut world = boot(
        r#"
        var arr: [int] = [1, 2, 3]
        pub fn boom() -> any {
            arr[10] = 99
            return arr
        }
        pub fn read_arr() -> any {
            return arr
        }
        "#,
    );
    let master = world.find_object("/secure/master").unwrap();
    let mut host = FakeHost::default();

    let e = world
        .call(master, "boom", vec![], &mut host)
        .expect_err("index 10 is out of range for a length-3 array");
    assert!(e.contains("out of range"), "{e}");

    // The failed write must not have applied even `arr[10] = null`-style
    // partial state: `arr` is exactly the length-3 original, unchanged.
    let after = world.call(master, "read_arr", vec![], &mut host).unwrap();
    assert_eq!(world.display(&after), "[1, 2, 3]");
}

#[test]
fn a_type_error_on_a_global_map_key_leaves_the_map_intact() {
    let mut world = boot(
        r#"
        var m: any = {"a": 1}
        pub fn boom() -> any {
            let k: any = [1, 2]
            m[k] = 2
            return m
        }
        pub fn read_map() -> any {
            return m
        }
        "#,
    );
    let master = world.find_object("/secure/master").unwrap();
    let mut host = FakeHost::default();

    let e = world
        .call(master, "boom", vec![], &mut host)
        .expect_err("an array is not a valid map key");
    assert!(e.contains("map keys must be"), "{e}");

    let after = world.call(master, "read_map", vec![], &mut host).unwrap();
    assert_eq!(world.display(&after), "{\"a\": 1}");
}

#[test]
fn a_successful_indexed_write_into_a_global_map_is_visible_on_the_next_call() {
    let mut world = boot(
        r#"
        var m: {int: int} = {:}
        pub fn set(k: int, v: int) -> any {
            m[k] = v
            return m[k]
        }
        pub fn read_map() -> any {
            return m
        }
        "#,
    );
    let master = world.find_object("/secure/master").unwrap();
    let mut host = FakeHost::default();

    let v = world
        .call(
            master,
            "set",
            vec![loom_vm::Value::Int(7), loom_vm::Value::Int(42)],
            &mut host,
        )
        .unwrap();
    assert_eq!(world.display(&v), "42");
    let after = world.call(master, "read_map", vec![], &mut host).unwrap();
    assert_eq!(world.display(&after), "{7: 42}");
}
