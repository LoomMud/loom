// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! P2-B7 (OBI-182, spec §7.4): `canary_update(path, pct, window_ticks,
//! max_new_errors)` routes a fraction of lazily-upgraded clones to the
//! new version and auto-promotes or auto-rolls-back based on the P2-B4
//! error inbox -- exercised end to end through [`World`].

mod common;

use common::{FakeHost, fixture, on_world_thread};
use loom_vm::World;

/// Clone `n` `/std/thing`s through the fixture's `clone_thing` verb and
/// return their object ids.
fn clone_things(world: &mut World, host: &mut FakeHost, n: usize) -> Vec<loom_vm::ObjectId> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        world.input(1, "clone_thing", host);
        let line = host.take(1);
        let name = line
            .strip_prefix("cloned ")
            .and_then(|s| s.strip_suffix('\n'))
            .expect(&line)
            .to_string();
        out.push(world.find_object(&name).expect("cloned"));
    }
    out
}

#[test]
fn a_canary_within_its_error_budget_auto_promotes_once_the_window_elapses() {
    on_world_thread(|| {
        let root = fixture("canary");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.take(1);

        const N: usize = 20;
        let things = clone_things(&mut world, &mut host, N);
        for &t in &things {
            assert_eq!(
                world.object_program_version(t),
                Some(("/std/thing".into(), 1))
            );
        }

        // v2: a harmless change (new var, same behaviour) -- a real
        // migration, not the O(1) unchanged-schema-hash pointer swap.
        std::fs::write(
            root.join("std/thing.wf"),
            "var tag: string = \"v2\"\nvar extra: int = 0\n\npub fn touch() -> string {\n    return tag\n}\n",
        )
        .unwrap();

        world.input(1, "canary /std/thing 50 5 0", &mut host);
        assert_eq!(host.take(1), "ok\n");
        assert!(world.canary_active("/std/thing"));

        // Access every clone: with pct=50, some land in the cohort (v2)
        // and some stay pinned to v1 -- a real fraction, not all-or-
        // nothing.
        for &t in &things {
            world.call(t, "touch", vec![], &mut host).expect("access");
        }
        let v1 = things
            .iter()
            .filter(|&&t| world.object_program_version(t) == Some(("/std/thing".into(), 1)))
            .count();
        let v2 = things
            .iter()
            .filter(|&&t| world.object_program_version(t) == Some(("/std/thing".into(), 2)))
            .count();
        assert_eq!(v1 + v2, N);
        assert!(
            v1 > 0,
            "pct=50 must leave some instances on the stable version"
        );
        assert!(v2 > 0, "pct=50 must move some instances to the candidate");

        // Window is 5 ticks; nothing errors, so it auto-promotes exactly
        // once that many ticks have passed.
        for _ in 0..4 {
            world.tick(&mut host);
            assert!(
                world.canary_active("/std/thing"),
                "must not promote before the window elapses"
            );
        }
        world.tick(&mut host);
        assert!(
            !world.canary_active("/std/thing"),
            "must auto-promote once the window elapses within budget"
        );

        // Every remaining v1 instance migrates to v2 on its next access,
        // same as any ordinary lazy upgrade after a plain recompile.
        for &t in &things {
            world.call(t, "touch", vec![], &mut host).expect("access");
            assert_eq!(
                world.object_program_version(t),
                Some(("/std/thing".into(), 2))
            );
        }
    });
}

#[test]
fn a_canary_that_exceeds_its_error_budget_auto_rolls_back_without_waiting_for_the_window() {
    on_world_thread(|| {
        let root = fixture("canary");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.take(1);

        let things = clone_things(&mut world, &mut host, 3);

        // v2 has a bug: every `touch()` raises a runtime error.
        std::fs::write(
            root.join("std/thing.wf"),
            "var tag: string = \"v2\"\n\npub fn touch() -> string {\n    random(0)\n    return tag\n}\n",
        )
        .unwrap();

        // pct=100 (deterministic: every access migrates), a long window
        // (100 ticks -- must never be reached) and a zero error budget,
        // so even one new error rolls it back immediately.
        world.input(1, "canary /std/thing 100 100 0", &mut host);
        assert_eq!(host.take(1), "ok\n");
        assert!(world.canary_active("/std/thing"));

        let first = things[0];
        let err = world.call(first, "touch", vec![], &mut host).unwrap_err();
        assert!(err.contains("random(): n must be > 0"), "{err}");
        assert_eq!(
            world.object_program_version(first),
            Some(("/std/thing".into(), 2)),
            "the access itself still migrates (pct=100) before the next tick rolls it back"
        );

        world.tick(&mut host);
        assert!(
            !world.canary_active("/std/thing"),
            "one new error against a budget of 0 must roll back immediately, not wait out the window"
        );

        // The already-migrated instance reverts to v1 on its next access
        // (`RegistryHost::upgrade` is symmetric: no special "downgrade"
        // path needed), and stops erroring.
        let v = world
            .call(first, "touch", vec![], &mut host)
            .expect("access after rollback");
        assert_eq!(v.as_str(), Some("v1"));
        assert_eq!(
            world.object_program_version(first),
            Some(("/std/thing".into(), 1))
        );

        // An instance never touched during the canary window was never
        // migrated at all, so rollback is a no-op for it.
        let untouched = things[1];
        assert_eq!(
            world.object_program_version(untouched),
            Some(("/std/thing".into(), 1))
        );
    });
}

#[test]
fn canary_status_reports_live_state_and_null_once_resolved() {
    on_world_thread(|| {
        let root = fixture("canary");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.take(1);
        let _things = clone_things(&mut world, &mut host, 1);

        world.input(1, "status /std/thing", &mut host);
        assert_eq!(host.take(1), "none\n");

        std::fs::write(
            root.join("std/thing.wf"),
            "var tag: string = \"v2\"\n\npub fn touch() -> string {\n    return tag\n}\n",
        )
        .unwrap();
        world.input(1, "canary /std/thing 10 2 0", &mut host);
        assert_eq!(host.take(1), "ok\n");

        world.input(1, "status /std/thing", &mut host);
        assert_eq!(
            host.take(1),
            "pct=10 new_errors=0 max_new_errors=0 ticks_left=2\n"
        );

        world.tick(&mut host);
        world.tick(&mut host);
        world.input(1, "status /std/thing", &mut host);
        assert_eq!(host.take(1), "none\n", "promoted: no longer in flight");
    });
}

#[test]
fn starting_a_second_canary_for_a_path_already_in_flight_is_refused() {
    on_world_thread(|| {
        let root = fixture("canary");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.take(1);
        let _things = clone_things(&mut world, &mut host, 1);

        std::fs::write(
            root.join("std/thing.wf"),
            "var tag: string = \"v2\"\n\npub fn touch() -> string {\n    return tag\n}\n",
        )
        .unwrap();
        world.input(1, "canary /std/thing 10 50 0", &mut host);
        assert_eq!(host.take(1), "ok\n");

        world.input(1, "canary /std/thing 90 50 0", &mut host);
        assert_eq!(
            host.take(1),
            "canary_update(): a canary is already in flight for /std/thing\n"
        );
    });
}
