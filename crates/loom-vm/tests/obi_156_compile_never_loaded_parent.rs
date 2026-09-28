// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-156 regression: `compile_object`/`begin_recompile` of a program
//! that has never been loaded must still link its `inherit` parent, even
//! when *that* ancestor has never been loaded/registered either.
//!
//! Before the fix, `Compiler::recompile` (and its background twin,
//! `compile_worker::run_recompile`) resolved a program's parent only from
//! already-registered programs (`new_set`/`registry.program(..)` on the
//! synchronous path, `snapshot.entry(..)` in the background one). A
//! program whose parent had never been compiled by anyone yet installed
//! with `parent: None`, so every inherited function silently disappeared
//! — `/domains/start/hall` inherits `/std/room`'s `short`/`exit_dest`/
//! `look`; a driver root never loads `/std/room` on its own (only
//! `load_object("/domains/start/hall")` would, and only as a side effect
//! of building the leaf's own chain).

mod common;

use std::time::Duration;

use common::{FakeHost, fixture};
use loom_vm::World;

const HALL: &str = "/domains/start/hall";
const ROOM: &str = "/std/room";

#[test]
fn compile_object_of_a_never_loaded_program_keeps_its_never_loaded_parent_link() {
    let root = fixture("tworoom");
    let mut world = World::boot(&root).expect("boot");
    let mut host = FakeHost::default();

    // Neither `hall` nor its parent `room` has ever been loaded/compiled
    // by anyone yet (a fresh `World::boot` only touches `/secure/master`).
    assert_eq!(world.program_version(HALL), None);
    assert_eq!(world.program_version(ROOM), None);

    // Synchronous path: `compile_object` on the never-loaded leaf.
    let warnings = world.compile_object(HALL, &mut host).expect("compile ok");
    assert!(warnings.is_empty(), "{warnings:?}");

    // Now load it and call an *inherited* function (`look`, defined on
    // `/std/room`, calling `short`/`exit_dest`, also inherited) — before
    // the fix this failed with "no function `short`"/"no function
    // `exit_dest`" because `hall`'s `CompiledProgram.parent` was `None`.
    let hall = world.load_object(HALL, &mut host).expect("load hall");
    let out = world
        .call(hall, "look", vec![], &mut host)
        .expect("inherited `look` must resolve");
    assert!(
        out.as_str().is_some_and(|s| s.contains("The Great Hall")),
        "{out:?}"
    );
}

#[test]
fn begin_recompile_of_a_never_loaded_program_keeps_its_never_loaded_parent_link() {
    let root = fixture("tworoom");
    let mut world = World::boot(&root).expect("boot");
    let mut host = FakeHost::default();

    assert_eq!(world.program_version(HALL), None);
    assert_eq!(world.program_version(ROOM), None);

    // Background path: `begin_recompile` on the never-loaded leaf, same
    // gap in `compile_worker::run_recompile`/`finish_recompile`.
    let token = world.begin_recompile_after(HALL, Duration::from_millis(20));
    assert!(world.recompile_pending(token));
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
    let (_, result) = results
        .into_iter()
        .find(|(t, _)| *t == token)
        .expect("this job's result must be present");
    result.expect("background recompile of a never-loaded leaf must succeed");

    let hall = world.load_object(HALL, &mut host).expect("load hall");
    let out = world
        .call(hall, "look", vec![], &mut host)
        .expect("inherited `look` must resolve");
    assert!(
        out.as_str().is_some_and(|s| s.contains("The Great Hall")),
        "{out:?}"
    );
}
