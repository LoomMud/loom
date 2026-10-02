// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-169 (grouped runtime errors / the `errors` efun /
//! `/api/v1/errors`): grouping, permission filtering, and the
//! `errors()` efun's shape, exercised end to end through [`World`].

mod common;

use common::{FakeHost, fixture, on_world_thread};
use loom_vm::World;

#[test]
fn repeated_runtime_errors_on_the_same_program_function_message_group_and_count() {
    on_world_thread(|| {
        let root = fixture("errors_inbox");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.take(1);

        world.input(1, "boom", &mut host);
        let first = host.take(1);
        assert!(
            first.contains("random(): n must be > 0"),
            "the raised error is reported to the player: {first}"
        );
        world.input(1, "boom", &mut host);
        host.take(1);

        let rows = world.errors_snapshot(None);
        assert_eq!(rows.len(), 1, "one group: same program/function/message");
        let row = &rows[0];
        assert_eq!(row.program, "/std/player");
        assert_eq!(row.message, "random(): n must be > 0");
        assert_eq!(row.count, 2);
        assert!(row.first_seen_unix_ms <= row.last_seen_unix_ms);
        assert!(
            !row.sample_trace.is_empty(),
            "a sample trace is captured, not just the message"
        );
    });
}

#[test]
fn a_different_message_on_the_same_program_is_a_different_group() {
    on_world_thread(|| {
        let root = fixture("errors_inbox");
        let limits = loom_vm::Limits {
            heartbeat_interval_ticks: 1,
            ..Default::default()
        };
        let mut world = World::boot_with_limits(&root, limits).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.take(1);

        // `boom` -> random(0) -> "random(): n must be > 0".
        world.input(1, "boom", &mut host);
        host.take(1);
        // An unknown verb goes through a different code path but is not
        // itself an error (the `else` branch sends "What?\n" rather than
        // raising) -- use the vault's heartbeat to get a second, distinct
        // program/message group instead.
        world.input(1, "spawnvault", &mut host);
        host.take(1);
        world.tick(&mut host);

        let rows = world.errors_snapshot(None);
        assert_eq!(rows.len(), 2, "player's and vault's errors are distinct groups");
        assert!(rows.iter().any(|r| r.program == "/std/player"));
        assert!(rows.iter().any(|r| r.program == "/std/vault"));
    });
}

#[test]
fn the_errors_efun_omits_programs_the_caller_cannot_valid_read() {
    on_world_thread(|| {
        let root = fixture("errors_inbox");
        let limits = loom_vm::Limits {
            heartbeat_interval_ticks: 1,
            ..Default::default()
        };
        let mut world = World::boot_with_limits(&root, limits).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.take(1);

        // The player's own error is visible...
        world.input(1, "boom", &mut host);
        host.take(1);
        // ...but the vault's is not: `secure/master.wf`'s `valid_read`
        // denies `/std/vault` specifically.
        world.input(1, "spawnvault", &mut host);
        host.take(1);
        world.tick(&mut host);

        // The Rust-side inbox (no permission filter) sees both groups...
        assert_eq!(world.errors_snapshot(None).len(), 2);

        // ...but the in-game `errors()` efun, filtered by the caller's
        // own `valid_read`, sees only the player's.
        world.input(1, "errorcount", &mut host);
        assert_eq!(host.take(1), "1\n");
    });
}

#[test]
fn the_errors_efun_prefix_filter_narrows_by_program() {
    on_world_thread(|| {
        let root = fixture("errors_inbox");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.take(1);

        world.input(1, "boom", &mut host);
        host.take(1);

        world.input(1, "errorcount /std/player", &mut host);
        assert_eq!(host.take(1), "1\n");

        world.input(1, "errorcount /nowhere", &mut host);
        assert_eq!(host.take(1), "0\n");
    });
}
