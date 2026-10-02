// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `Compiler::recompile_set`'s compile stage, off the world thread (spec
//! §7.2 D-B3.14, OBI-207 P2-B3.1b): the multi-root generalisation of
//! `tests/async_compile.rs`'s single-root coverage. `RecompileReport`'s
//! shape is unchanged (`tests/mudlib_sync.rs`'s 7 cases cover that); this
//! file covers the two behaviours that only exist once the compile stage
//! is a background batch: ticks keep advancing while it runs, and a
//! registry drift mid-compile refuses the whole install and reports it.

mod common;

use std::time::Duration;

use common::{FakeHost, fixture, on_world_thread};
use loom_vm::{ChangeSet, World};

fn change(changed: &[&str]) -> ChangeSet {
    ChangeSet {
        changed: changed.iter().map(|s| s.to_string()).collect(),
        deleted: Vec::new(),
        source_sha: "deadbeef".to_string(),
    }
}

/// The P2-B3.1b base AC: "the world keeps ticking while a batch compiles."
/// `/std/room` plus its reverse-inherit dependent `/domains/start/hall`
/// are recompiled as one batch, deliberately slowed down
/// (`begin_recompile_set_after`, same stand-in `tests/async_compile.rs`
/// uses for a large dependent tree); the player's `heartbeat()` must keep
/// firing on schedule the whole time, and the batch must still land --
/// both programs upgraded -- once the background thread finishes.
#[test]
fn ticks_keep_advancing_during_a_slow_background_batch_compile() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let limits = loom_vm::Limits {
            heartbeat_interval_ticks: 1,
            ..Default::default()
        };
        let mut world = World::boot_with_limits(&root, limits).expect("boot");
        let mut host = FakeHost::default();

        world.connect(1, &mut host);
        host.out.clear();
        world.input(1, "hbon", &mut host);
        host.take(1);
        let player = world.connection_object(1).expect("bound");

        // `logon()` already loaded `/std/room` (hall's parent) and
        // `/domains/start/hall` itself.
        assert_eq!(world.program_version("/std/room"), Some(1));
        assert_eq!(world.program_version("/domains/start/hall"), Some(1));

        std::fs::write(
            root.join("std/room.wf"),
            "var short_desc: string = \"A room\"\nvar exits: {string: string} = {:}\n\nfn create() {\n}\n\nfn set_short(s: string) {\n    short_desc = s\n}\n\nfn add_exit(dir: string, dest: string) {\n    exits[dir] = dest\n}\n\npub fn short() -> string {\n    return short_desc\n}\n\npub fn long() -> string {\n    return \"An empty room.\"\n}\n\npub fn exit_dest(dir: string) -> string? {\n    return exits[dir]\n}\n\npub fn look() -> string {\n    let names = keys(exits)\n    return $\"{short()}\\n{long()}\\n\" + \"Exits: \" + join(names, \", \")\n}\n\npub fn marker() -> string {\n    return \"room-v2\"\n}\n",
        )
        .unwrap();

        let token =
            world.begin_recompile_set_after(&change(&["/std/room"]), Duration::from_millis(150));
        assert!(world.recompile_set_pending(token));

        // Several ticks while the background thread is (almost certainly)
        // still sleeping: heartbeat must not skip a single one, and the
        // batch must not have landed yet.
        for expected_beats in 1..=5i64 {
            world.tick(&mut host);
            let beats = world.var(player, "beats");
            assert!(
                matches!(beats, Some(loom_vm::Value::Int(n)) if n == expected_beats),
                "heartbeat {expected_beats} must fire on schedule while a batch compile is in flight"
            );
        }
        assert_eq!(world.program_version("/std/room"), Some(1));
        assert_eq!(world.program_version("/domains/start/hall"), Some(1));

        let mut installed = false;
        for _ in 0..200 {
            world.tick(&mut host);
            if !world.recompile_set_pending(token) {
                installed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(installed, "background batch compile never finished");

        let results = world.take_finished_recompile_sets();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, token);
        let report = &results[0].1;
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert_eq!(
            report.recompiled,
            vec![
                "/std/room".to_string(),
                "/domains/start/hall".to_string()
            ],
            "parents before children, across the background batch too"
        );
        assert_eq!(world.program_version("/std/room"), Some(2));
        assert_eq!(world.program_version("/domains/start/hall"), Some(2));

        // Ticks kept advancing the whole time, including the ticks spent
        // waiting for the background thread above.
        assert!(matches!(world.var(player, "beats"), Some(loom_vm::Value::Int(n)) if n >= 5));
    });
}

/// A registry drift during the background batch compile refuses the
/// install and reports it, rather than silently clobbering a concurrent
/// synchronous recompile of the same path (the multi-root generalisation
/// of `tests/async_compile.rs`'s `a_stale_background_compile_is_rejected_
/// not_installed`).
#[test]
fn a_registry_drift_during_the_batch_compile_refuses_the_install_and_reports_it() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host); // loads /std/room and /domains/start/hall
        assert_eq!(world.program_version("/std/room"), Some(1));
        assert_eq!(world.program_version("/domains/start/hall"), Some(1));

        // Kick off a slow background batch recompile of `/std/room` (plus
        // its dependent `/domains/start/hall`)...
        let token =
            world.begin_recompile_set_after(&change(&["/std/room"]), Duration::from_millis(200));
        assert!(world.recompile_set_pending(token));

        // ...then, while it's still asleep, recompile the very same path
        // synchronously (a second overlapping post-merge sync, or an
        // admin `update`) -- this bumps `/std/room` (and `/domains/start/
        // hall`, its dependent) to version 2 out from under the pending
        // batch.
        let sync = world.compile_object("/std/room", &mut host);
        assert_eq!(
            sync,
            Ok(Vec::new()),
            "synchronous compile_object should succeed"
        );
        assert_eq!(world.program_version("/std/room"), Some(2));
        assert_eq!(world.program_version("/domains/start/hall"), Some(2));

        // Now wait for the background batch: it must notice the registry
        // moved out from under it and refuse to install anything, leaving
        // the synchronous call's version 2 alone.
        let mut results = Vec::new();
        for _ in 0..300 {
            world.tick(&mut host);
            if !world.recompile_set_pending(token) {
                results = world.take_finished_recompile_sets();
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, token);
        let report = &results[0].1;
        assert!(
            report.recompiled.is_empty(),
            "nothing should have installed: {:?}",
            report.recompiled
        );
        assert_eq!(report.failures.len(), 1);
        assert!(
            report.failures[0].1.contains("stale"),
            "expected a staleness error, got: {}",
            report.failures[0].1
        );
        assert_eq!(
            world.program_version("/std/room"),
            Some(2),
            "the stale background batch must not overwrite the synchronous compile's version"
        );
        assert_eq!(world.program_version("/domains/start/hall"), Some(2));
        assert_eq!(world.mudlib_sync_total("compile_failed"), 1);
    });
}
