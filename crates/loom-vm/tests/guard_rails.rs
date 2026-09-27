// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Runaway Weft code aborts the execution with an error to the player; the
//! driver keeps serving.

mod common;

use common::{FakeHost, fixture, on_world_thread};
use loom_vm::World;

#[test]
fn tick_cost_is_charged_at_call_efun_not_just_declared() {
    // CTO review (OBI-33): the `EFUNS` doc comment claims tick cost is
    // charged, but it wasn't. Pin it: a loop of `compile_object` calls
    // (declared cost 500) must exhaust a much smaller `max_ticks` budget
    // in far fewer iterations than the same loop of `len` calls
    // (declared cost 1), which a shared `TickCheck`-only meter (one tick
    // per loop backedge, ignoring what the call inside it costs) could
    // not distinguish.
    on_world_thread(|| {
        let root = fixture("tworoom");
        let limits = loom_vm::Limits {
            max_ticks: 5_000,
            max_depth: 512,
        };
        let mut world = World::boot_with_limits(&root, limits).expect("boot");
        let mut host = FakeHost::default();

        world.connect(1, &mut host);
        host.out.clear();
        world.input(1, "burnlen", &mut host);
        assert!(host.take(1).contains("Too long evaluation"));
        world.input(1, "burncount", &mut host);
        let len_iters: i64 = host.take(1).trim().parse().unwrap();

        world.connect(2, &mut host);
        host.take(2);
        world.input(2, "burncompile", &mut host);
        assert!(host.take(2).contains("Too long evaluation"));
        world.input(2, "burncount", &mut host);
        let compile_iters: i64 = host.take(2).trim().parse().unwrap();

        assert!(
            len_iters > 10 * compile_iters,
            "len loop should run far more iterations than the same budget \
             affords a compile_object loop: len={len_iters} compile={compile_iters}"
        );
        assert!(compile_iters >= 1, "budget must allow at least one call");
    });
}

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
        // Deviation from the tree-walker (spec r5, flagged not hidden): the
        // bytecode VM's runtime trace is function names only (`RtError`,
        // `bcvm::vm::Interpreter::err_with_trace`) — it does not yet carry
        // a `path.wf:line:col` per frame the way `crate::interp`'s
        // AST-walking errors did, so this only checks the frame name.
        assert!(out.contains("in process_input()"), "{out}");

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

// `stack_budget_stops_recursion_before_the_rust_stack_overflows` (Phase 0)
// no longer applies: the bytecode VM's call stack is heap-allocated
// (D-P1.3, `bcvm::vm::Interpreter`'s `Vec<Frame>`), never the native Rust
// stack, so `max_depth` alone bounds recursion regardless of the running
// thread's stack size — see `bcvm::vm::tests::recursive_call_uses_heap_stack_not_native_recursion`.
