// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-89 (loom-vm slice 2 of OBI-34's hot-reload AC): lazy per-instance
//! upgrade on access, and `upgrade_all(path)` spread across ticks with a
//! bounded per-tick budget.

mod common;

use common::{FakeHost, fixture, on_world_thread};
use loom_vm::{Limits, World};

#[test]
fn an_object_not_accessed_since_a_recompile_still_reports_its_old_version_until_touched() {
    on_world_thread(|| {
        let root = fixture("eager_upgrade");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.take(1);

        world.input(1, "clone_thing", &mut host);
        let out = host.take(1);
        let name = out
            .strip_prefix("cloned ")
            .and_then(|s| s.strip_suffix('\n'))
            .expect(&out)
            .to_string();
        let thing = world.find_object(&name).expect("cloned");
        assert_eq!(
            world.object_program_version(thing),
            Some(("/std/thing".into(), 1))
        );

        // Widen the schema (a new var) so this is a real migration, not
        // the O(1) unchanged-schema-hash pointer swap.
        std::fs::write(
            root.join("std/thing.wf"),
            "var counter: int = 0\nvar tag: string = \"v2\"\n\npub fn get_counter() -> int {\n    return counter\n}\n",
        )
        .unwrap();
        world.input(1, "update /std/thing", &mut host);
        assert_eq!(host.take(1), "Updated /std/thing.\n");

        // The registry-level program is v2 (a *new* clone would get it)...
        assert_eq!(world.program_version("/std/thing"), Some(2));
        // ...but this pre-existing, not-yet-accessed instance still
        // reports v1: lazy by default (spec §7.2/§7.3, OBI-89), not
        // install-time eager migration.
        assert_eq!(
            world.object_program_version(thing),
            Some(("/std/thing".into(), 1)),
            "not accessed since the recompile: must still report the old version"
        );
        assert!(world.take_lazy_upgrade_warnings().is_empty());

        // Any access — here, a fresh clone_object isn't one (it's a new
        // object), but a direct driver call on the *existing* clone is —
        // triggers the lazy upgrade.
        world
            .call(thing, "get_counter", vec![], &mut host)
            .expect("access");
        assert_eq!(
            world.object_program_version(thing),
            Some(("/std/thing".into(), 2)),
            "accessed: must now report the current version"
        );
    });
}

#[test]
fn upgrade_all_spreads_migration_across_ticks_within_its_budget_without_starving_other_objects() {
    on_world_thread(|| {
        let root = fixture("eager_upgrade");
        let mut world = World::boot_with_limits(
            &root,
            Limits {
                eager_upgrade_batch: 10,
                ..Limits::default()
            },
        )
        .expect("boot");
        let mut host = FakeHost::default();

        // Player A clones 25 `/std/thing`s and will drive `upgrade_all`.
        world.connect(1, &mut host);
        host.take(1);
        const N: usize = 25;
        let mut things = Vec::with_capacity(N);
        for _ in 0..N {
            world.input(1, "clone_thing", &mut host);
            let out = host.take(1);
            let name = out
                .strip_prefix("cloned ")
                .and_then(|s| s.strip_suffix('\n'))
                .expect(&out)
                .to_string();
            things.push(world.find_object(&name).expect("cloned"));
        }

        // Player B just proves the tick queue is not starved by
        // `upgrade_all`: subscribed to heartbeat, its own count must keep
        // advancing one per tick throughout.
        world.connect(2, &mut host);
        host.take(2);
        world.input(2, "hbon", &mut host);
        host.take(2);

        std::fs::write(
            root.join("std/thing.wf"),
            "var counter: int = 0\nvar tag: string = \"v2\"\n\npub fn get_counter() -> int {\n    return counter\n}\n",
        )
        .unwrap();
        world.input(1, "update /std/thing", &mut host);
        assert_eq!(host.take(1), "Updated /std/thing.\n");
        for &t in &things {
            assert_eq!(
                world.object_program_version(t),
                Some(("/std/thing".into(), 1))
            );
        }

        world.input(1, "upgrade_all /std/thing", &mut host);
        assert_eq!(host.take(1), "queued 25\n");
        assert_eq!(world.eager_upgrade_queue_len(), N);

        let version_of =
            |world: &World, t: loom_vm::ObjectId| world.object_program_version(t).map(|(_, v)| v);
        let migrated_count = |world: &World| {
            things
                .iter()
                .filter(|&&t| version_of(world, t) == Some(2))
                .count()
        };

        // Tick 1: exactly one batch (10) migrates, never more than the
        // configured budget in a single tick — and player B's heartbeat
        // still ran this same tick.
        world.tick(&mut host);
        assert_eq!(
            migrated_count(&world),
            10,
            "must not exceed one tick's budget"
        );
        assert_eq!(world.eager_upgrade_queue_len(), N - 10);
        world.input(2, "beats", &mut host);
        assert_eq!(host.take(2), "1\n");

        // Tick 2: a second batch (10 more, 20 total).
        world.tick(&mut host);
        assert_eq!(migrated_count(&world), 20);
        assert_eq!(world.eager_upgrade_queue_len(), N - 20);
        world.input(2, "beats", &mut host);
        assert_eq!(host.take(2), "2\n");

        // Tick 3: the remainder (5), queue drains to empty.
        world.tick(&mut host);
        assert_eq!(migrated_count(&world), N);
        assert_eq!(world.eager_upgrade_queue_len(), 0);
        world.input(2, "beats", &mut host);
        assert_eq!(host.take(2), "3\n");

        // A fourth tick with nothing left queued is a no-op for the
        // eager path and does not disturb anyone.
        world.tick(&mut host);
        assert_eq!(migrated_count(&world), N);
        world.input(2, "beats", &mut host);
        assert_eq!(host.take(2), "4\n");

        assert!(world.take_lazy_upgrade_warnings().is_empty());
    });
}
