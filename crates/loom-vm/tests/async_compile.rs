// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Compile off the world thread, install on it (spec §7.2, D-P1.5, OBI-90,
//! OBI-34 slice 3): a slow `compile_object`/`update` must not stall ticks
//! for unrelated objects in the meantime.

mod common;

use std::time::Duration;

use common::{FakeHost, fixture, on_world_thread};
use loom_vm::World;

/// The base AC this ticket exists for: "recompile off the world thread,
/// install on it; test shows ticks continue during a large compile."
/// `/std/room`'s recompile here is deliberately slowed down
/// (`begin_recompile_after`, spec r5 amendment's own suggested stand-in
/// for an actually large dependent tree) so it is still in flight across
/// several `World::tick()` calls; the player's `heartbeat()` (which
/// increments its `beats` var every tick) must keep firing on schedule the
/// whole time, and the recompile must still land once the background
/// thread finishes.
#[test]
fn ticks_keep_advancing_during_a_slow_background_compile() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();

        world.connect(1, &mut host);
        host.out.clear();
        world.input(1, "hbon", &mut host);
        host.take(1);
        let player = world.connection_object(1).expect("bound");

        assert_eq!(world.program_version("/std/room"), Some(1));

        let token = world.begin_recompile_after("/std/room", Duration::from_millis(150));
        assert!(world.recompile_pending(token));

        // Several ticks while the background thread is (almost certainly)
        // still sleeping: heartbeat must not skip a single one, and the
        // recompile must not have landed yet.
        for expected_beats in 1..=5i64 {
            world.tick(&mut host);
            let beats = world.var(player, "beats");
            assert!(
                matches!(beats, Some(loom_vm::Value::Int(n)) if n == expected_beats),
                "heartbeat {expected_beats} must fire on schedule while a compile is in flight"
            );
        }
        // Not a hard requirement of the design (a very slow test machine
        // could finish the background compile before 5 ticks elapse), but
        // true on any machine sane enough to run CI on, and pins the
        // scenario this test is actually for: catch a regression back to
        // "compile blocks the tick loop" that would make this constant
        // false as soon as `begin_recompile_after` set the delay above any
        // per-tick duration.
        assert_eq!(world.program_version("/std/room"), Some(1));

        // Wait for it to actually finish and get installed by a tick.
        let mut installed = false;
        for _ in 0..200 {
            world.tick(&mut host);
            if !world.recompile_pending(token) {
                installed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(installed, "background compile never finished");

        let results = world.take_finished_recompiles();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, token);
        assert_eq!(results[0].1, Ok(()));
        assert_eq!(world.program_version("/std/room"), Some(2));

        // Ticks kept advancing the whole time, including the ticks spent
        // waiting for the background thread above.
        assert!(matches!(world.var(player, "beats"), Some(loom_vm::Value::Int(n)) if n >= 5));
    });
}

/// A failing background compile reports its diagnostics through
/// `take_finished_recompiles` instead of panicking or silently dropping
/// them, and never touches the registry (mirrors the synchronous
/// `compile_object`'s all-or-nothing guarantee).
#[test]
fn a_failing_background_compile_reports_diagnostics_and_installs_nothing() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);

        std::fs::write(root.join("std/room.wf"), "this is not valid Weft {{{\n").unwrap();

        let token = world.begin_recompile("/std/room");
        let mut results = Vec::new();
        for _ in 0..200 {
            world.tick(&mut host);
            results = world.take_finished_recompiles();
            if !results.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, token);
        assert!(results[0].1.is_err(), "expected a compile error");
        assert_eq!(world.program_version("/std/room"), Some(1));
    });
}

/// CTO review (OBI-93) item 1: a background compile's `ProgramSnapshot` is
/// taken at `begin_recompile`, but only applied at `finish_recompile` —
/// arbitrarily later. If a *synchronous* `compile_object` of the same path
/// lands in between, the background result is stale (it would otherwise
/// silently claim the same next version number the synchronous call
/// already took, and migrate objects that are already on that program).
/// `finish_recompile` must detect this, install nothing, and report it
/// rather than corrupt the registry.
#[test]
fn a_stale_background_compile_is_rejected_not_installed() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        assert_eq!(world.program_version("/std/room"), Some(1));

        // Kick off a slow background recompile of `/std/room`...
        let token = world.begin_recompile_after("/std/room", Duration::from_millis(200));
        assert!(world.recompile_pending(token));

        // ...then, while it's still asleep, recompile the very same path
        // synchronously (a second admin `update`, or a driver retry).
        let sync = world.compile_object("/std/room", &mut host);
        assert_eq!(
            sync,
            Ok(Vec::new()),
            "synchronous compile_object should succeed"
        );
        assert_eq!(world.program_version("/std/room"), Some(2));

        // Now wait for the background job: it must notice the registry
        // moved out from under it and refuse to install, leaving the
        // synchronous call's version 2 alone.
        let mut results = Vec::new();
        for _ in 0..300 {
            world.tick(&mut host);
            if !world.recompile_pending(token) {
                results = world.take_finished_recompiles();
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, token);
        let err = results[0].1.as_ref().expect_err("expected a stale error");
        assert!(
            err.contains("stale"),
            "expected a staleness error, got: {err}"
        );
        assert_eq!(
            world.program_version("/std/room"),
            Some(2),
            "the stale background result must not overwrite the synchronous compile's version"
        );
    });
}

/// CTO review (OBI-93) item 2: the background worker re-reads and
/// re-typechecks every ancestor it needs from disk through its own private
/// `Session`, including ones that aren't themselves being recompiled. If
/// one of those (`/std/room`, the parent of `/domains/start/hall` here)
/// changed on disk after it was last installed but before the background
/// compile read it, the batch was type-checked against an interface that
/// `registry.program(..)` won't actually link it to (the *old*, still-
/// installed one). `finish_recompile` must detect that drift and refuse
/// to install, rather than link a program against a different interface
/// than the one it was verified against.
#[test]
fn an_ancestor_that_changed_on_disk_mid_compile_is_rejected() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host); // loads /std/room and /domains/start/hall
        assert_eq!(world.program_version("/domains/start/hall"), Some(1));

        let token = world.begin_recompile_after("/domains/start/hall", Duration::from_millis(200));
        assert!(world.recompile_pending(token));

        // `/std/room` (hall's parent, not itself part of this batch)
        // changes on disk while the background thread is still asleep, but
        // is never `update`d/installed.
        let room_src = std::fs::read_to_string(root.join("std/room.wf")).unwrap();
        std::fs::write(
            root.join("std/room.wf"),
            format!("{room_src}\nfn extra_after_the_fact() {{}}\n"),
        )
        .unwrap();

        let mut results = Vec::new();
        for _ in 0..300 {
            world.tick(&mut host);
            if !world.recompile_pending(token) {
                results = world.take_finished_recompiles();
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, token);
        let err = results[0]
            .1
            .as_ref()
            .expect_err("expected an ancestor-drift error");
        assert!(
            err.contains("/std/room") && err.contains("changed on disk"),
            "expected an ancestor-drift error naming /std/room, got: {err}"
        );
        assert_eq!(world.program_version("/domains/start/hall"), Some(1));
    });
}
