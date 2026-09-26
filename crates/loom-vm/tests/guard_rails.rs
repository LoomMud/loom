// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Runaway Weft code aborts the execution with an error to the player; the
//! driver keeps serving.

mod common;

use common::{FakeHost, fixture, on_world_thread};
use loom_vm::World;

#[test]
fn infinite_loop_and_runaway_recursion_abort_and_world_keeps_serving() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        world.connect(2, &mut host);
        host.out.clear();

        world.input(1, "loop", &mut host);
        let out = host.take(1);
        assert!(out.starts_with("*Error: "), "{out}");
        assert!(out.contains("Too long evaluation"), "{out}");
        assert!(out.contains("/std/player.wf:"), "{out}");

        world.input(1, "recurse", &mut host);
        let out = host.take(1);
        assert!(out.contains("Too deep recursion"), "{out}");
        assert!(out.contains("in dive()"), "{out}");

        // Both players are still connected and served.
        world.input(1, "look", &mut host);
        assert!(host.take(1).contains("The Great Hall"));
        world.input(2, "go north", &mut host);
        assert!(host.take(2).contains("The Yard"));
        assert!(host.closed.is_empty());
    });
}

#[test]
fn master_connect_failure_closes_only_that_connection() {
    let root = fixture("tworoom");
    let mut world = World::boot(&root).expect("boot");
    let mut host = FakeHost::default();
    world.connect(1, &mut host);
    std::fs::write(
        root.join("std/player.wf"),
        "fn create() {\n  let x = 1 / 0\n}\n",
    )
    .unwrap();
    // Player program still v1 in memory: clones keep working.
    world.connect(2, &mut host);
    assert!(world.connection_object(2).is_some());
    // Recompile to the broken-at-runtime version succeeds (it links), but
    // create() fails for new clones: connect errors, conn 3 is closed.
    assert_eq!(world.compile_object("/std/player", &mut host), None);
    world.connect(3, &mut host);
    let out = host.take(3);
    assert!(out.contains("division by zero"), "{out}");
    assert_eq!(host.closed, vec![3]);
    assert!(world.connection_object(1).is_some());
}

#[test]
fn stack_budget_stops_recursion_before_the_rust_stack_overflows() {
    // Default 2 MiB test thread, call-depth limit effectively off: only the
    // stack budget stands between runaway recursion and an abort.
    std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(|| {
            let root = fixture("tworoom");
            let limits = loom_vm::Limits {
                max_depth: 1_000_000,
                max_stack_bytes: 1 << 20,
                ..loom_vm::Limits::default()
            };
            let mut world = World::boot_with_limits(&root, limits).expect("boot");
            let mut host = FakeHost::default();
            world.connect(1, &mut host);
            host.out.clear();
            world.input(1, "recurse", &mut host);
            let out = host.take(1);
            assert!(out.contains("Too deep recursion"), "{out}");
            world.input(1, "look", &mut host);
            assert!(host.take(1).contains("The Great Hall"));
        })
        .unwrap()
        .join()
        .expect("no overflow");
}
