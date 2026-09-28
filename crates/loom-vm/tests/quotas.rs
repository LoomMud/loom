// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-121 (S2c): loom-vm per-tier quotas, object owner + R1 clone euid,
//! confinement flags (design note ยง3, ยง4, ยง7; builds on OBI-120's
//! `RolesSnapshot`).

mod common;

use std::sync::Arc;

use common::{FakeHost, fixture};
use loom_vm::{RolesSnapshot, Value, World};

fn boot() -> (World, FakeHost) {
    let root = fixture("quotas");
    let world = World::boot(&root).expect("boot");
    (world, FakeHost::default())
}

/// `appr` is T1, `staffer` is T3; `guest` has no `staff` row at all (T0).
/// `row_json` becomes T1's `tier_policy` row.
fn roles_with_row(row_json: &str) -> RolesSnapshot {
    RolesSnapshot::from_seed_json(&format!(
        r#"{{"staff": {{"appr": 1, "staffer": 3}}, "tier_policy": {{"1": {row_json}}}}}"#
    ))
    .expect("seed parses")
}

fn connect_appr(world: &mut World, host: &mut FakeHost, conn: u64) -> loom_vm::ObjectId {
    world.connect(conn, host);
    host.take(conn);
    world.connection_object(conn).expect("bound")
}

// -- max_ticks_exec + the player-input world-default AC ---------------------

#[test]
fn max_ticks_exec_row_tick_exhausts_a_heartbeat_but_player_input_still_gets_the_world_default() {
    let (mut world, mut host) = boot();
    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"max_ticks_exec": 200}"#)));
    let ob = connect_appr(&mut world, &mut host, 1);
    assert_eq!(world.owner_uid(ob), Some("appr"));

    // Player input: still gets the 1M default even though appr's T1 row
    // caps ticks at 200 -- large enough work still completes.
    world.input(1, "grow 5000", &mut host);
    assert_eq!(host.take(1), "grown 5000\n");

    // The same amount of work through a heartbeat (tier-gated) tick-exhausts:
    // `heartbeat()` runs (the counter increments) but never finishes the
    // loop, so `heartbeat_grown` stays at its initial value.
    world.input(1, "sethbn 5000", &mut host);
    host.take(1);
    world.input(1, "heartbeaton", &mut host);
    host.take(1);
    for _ in 0..25 {
        world.tick(&mut host);
    }
    assert!(matches!(
        world.var(ob, "heartbeat_runs"),
        Some(Value::Int(1))
    ));
    assert!(matches!(
        world.var(ob, "heartbeat_grown"),
        Some(Value::Int(0))
    ));
}

// -- max_mem_exec_mb, per-object, by the owner's tier -----------------------

#[test]
fn max_mem_exec_mb_row_rejects_a_write_that_exceeds_it() {
    let (mut world, mut host) = boot();
    let workroom = world
        .load_object("/builders/appr/workroom", &mut host)
        .expect("load");
    assert_eq!(world.owner_uid(workroom), Some("appr"));

    // No tier row yet: T1 gets the world default (16 MB) -- a few
    // thousand ints is nowhere near that.
    world
        .call(workroom, "grow", vec![Value::Int(2_000)], &mut host)
        .expect("within the world default");

    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"max_mem_exec_mb": 1}"#)));
    let e = world
        .call(workroom, "grow", vec![Value::Int(500_000)], &mut host)
        .unwrap_err();
    assert!(e.contains("memory quota exceeded"), "{e}");
}

// -- max_objects, and R1's clone-euid confinement ---------------------------

#[test]
fn r1_confines_a_daemon_clones_owner_to_the_apprentices_own_uid_and_charges_its_object_count() {
    let (mut world, mut host) = boot();
    let workroom = world
        .load_object("/builders/appr/workroom", &mut host)
        .expect("load");
    let before = world.object_count_for_uid("appr");

    let clone = world
        .call(workroom, "spawn_daemon", Vec::new(), &mut host)
        .expect("spawn_daemon");
    let Value::Object(clone_id) = clone else {
        panic!("spawn_daemon must return an object, got {clone:?}");
    };
    assert_eq!(
        world.owner_uid(clone_id),
        Some("appr"),
        "R1: /daemons/thing's own uid isn't in the caller's guard set"
    );
    assert_eq!(world.euid_name(clone_id), Some("appr"));
    assert_eq!(
        world.object_count_for_uid("appr"),
        before + 1,
        "the clone's object count is charged to the apprentice"
    );
}

#[test]
fn max_objects_row_denies_a_clone_once_the_apprentices_count_is_at_the_limit() {
    let (mut world, mut host) = boot();
    let workroom = world
        .load_object("/builders/appr/workroom", &mut host)
        .expect("load");
    // The workroom object itself already counts as 1 against `appr`.
    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"max_objects": 2}"#)));

    world
        .call(workroom, "spawn_daemon", Vec::new(), &mut host)
        .expect("first clone is within the limit (workroom + this = 2)");
    let e = world
        .call(workroom, "spawn_daemon", Vec::new(), &mut host)
        .unwrap_err();
    assert!(e.contains("object quota exceeded"), "{e}");

    // CTO review S4: every quota denial is audited, not just counted in
    // the metric.
    let last = world.audit_log().last().expect("an audit entry");
    assert!(!last.allowed);
    assert_eq!(last.apply, "quota");
}

// -- max_heartbeats ----------------------------------------------------------

#[test]
fn max_heartbeats_row_denies_a_second_apprentice_owned_subscriber() {
    let (mut world, mut host) = boot();
    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"max_heartbeats": 1}"#)));
    connect_appr(&mut world, &mut host, 1);
    world.connect(2, &mut host); // guest
    host.take(2);
    world.connect(3, &mut host); // staffer
    host.take(3);
    connect_appr(&mut world, &mut host, 4);

    world.input(1, "heartbeaton", &mut host);
    assert_eq!(host.take(1), "on\n");

    world.input(4, "heartbeaton", &mut host);
    let out = host.take(4);
    assert!(out.contains("max_heartbeats"), "{out:?}");
}

// -- max_callouts_obj / max_callouts_uid -------------------------------------

#[test]
fn max_callouts_obj_row_denies_a_second_pending_call_out_on_the_same_object() {
    let (mut world, mut host) = boot();
    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"max_callouts_obj": 1}"#)));
    connect_appr(&mut world, &mut host, 1);

    world.input(1, "callout", &mut host);
    assert_eq!(host.take(1), "scheduled\n");
    world.input(1, "callout", &mut host);
    let out = host.take(1);
    assert!(out.contains("max_callouts_obj"), "{out:?}");
}

#[test]
fn max_callouts_uid_row_denies_a_second_pending_call_out_from_a_different_object_same_owner() {
    let (mut world, mut host) = boot();
    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"max_callouts_uid": 1}"#)));
    connect_appr(&mut world, &mut host, 1);
    world.connect(2, &mut host); // guest
    host.take(2);
    world.connect(3, &mut host); // staffer
    host.take(3);
    connect_appr(&mut world, &mut host, 4);

    world.input(1, "callout", &mut host);
    assert_eq!(host.take(1), "scheduled\n");
    world.input(4, "callout", &mut host);
    let out = host.take(4);
    assert!(out.contains("max_callouts_uid"), "{out:?}");
}

// -- tick_share_per_min: a sliding window; heartbeats/call_outs are
// deferred on breach, player input never is ------------------------------

#[test]
fn tick_share_per_min_defers_a_call_out_but_never_defers_player_input() {
    let (mut world, mut host) = boot();
    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"tick_share_per_min": 1}"#)));
    connect_appr(&mut world, &mut host, 1);

    world.input(1, "sethbn 0", &mut host);
    host.take(1);
    world.input(1, "callout", &mut host);
    host.take(1);
    world.tick(&mut host); // the first call_out fires, using >=1 tick:
    // the T1 tick-share window is now breached (limit 1).

    world.input(1, "callout", &mut host);
    host.take(1);
    let pending_before = world.pending_call_outs();
    world.tick(&mut host); // deferred: re-queued, not run and not lost.
    assert_eq!(
        world.pending_call_outs(),
        pending_before,
        "a deferred call_out stays pending, it is not dropped"
    );

    // Player input is never deferred, breach or not.
    world.input(1, "grow 10", &mut host);
    assert_eq!(host.take(1), "grown 10\n");
}

// -- disk_quota_mb on write_file into /builders/<u>/** -----------------------

#[test]
fn disk_quota_mb_row_denies_a_write_that_would_exceed_the_builders_directory_total() {
    let (mut world, mut host) = boot();
    let workroom = world
        .load_object("/builders/appr/workroom", &mut host)
        .expect("load");
    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"disk_quota_mb": 1}"#)));

    let chunk = "a".repeat(700_000);
    world
        .call(
            workroom,
            "write_disk",
            vec![Value::str("/builders/appr/a.txt"), Value::str(&chunk)],
            &mut host,
        )
        .expect("700_000 bytes is within the 1 MB quota");

    let e = world
        .call(
            workroom,
            "write_disk",
            vec![Value::str("/builders/appr/b.txt"), Value::str(&chunk)],
            &mut host,
        )
        .unwrap_err();
    assert!(e.contains("disk_quota_mb"), "{e}");
}

// -- move_to confinement (spec ยง7) -------------------------------------------

#[test]
fn confined_object_cannot_move_into_a_live_room() {
    let (mut world, mut host) = boot();
    let thing = world
        .load_object("/std/confined_thing", &mut host)
        .expect("load");
    let room = world
        .load_object("/std/live_room", &mut host)
        .expect("load");
    assert_eq!(world.program_flags("/std/confined_thing"), "confined");
    assert_eq!(world.program_flags("/std/live_room"), "live");

    let e = world
        .call(thing, "move_into_obj", vec![Value::Object(room)], &mut host)
        .unwrap_err();
    assert!(e.contains("live room"), "{e}");
}

#[test]
fn confined_object_cannot_move_into_a_tier0_players_inventory_but_can_into_a_staff_players() {
    let (mut world, mut host) = boot();
    world.set_roles_snapshot(Arc::new(
        RolesSnapshot::from_seed_json(r#"{"staff": {"staffer": 3}}"#).unwrap(),
    ));
    connect_appr(&mut world, &mut host, 1);
    world.connect(2, &mut host); // guest, T0
    host.take(2);
    let guest = world.connection_object(2).expect("bound");
    world.connect(3, &mut host); // staffer, T3
    host.take(3);
    let staffer = world.connection_object(3).expect("bound");

    let thing = world
        .load_object("/std/confined_thing", &mut host)
        .expect("load");

    let e = world
        .call(
            thing,
            "move_into_obj",
            vec![Value::Object(guest)],
            &mut host,
        )
        .unwrap_err();
    assert!(e.contains("tier-0 player"), "{e}");

    world
        .call(
            thing,
            "move_into_obj",
            vec![Value::Object(staffer)],
            &mut host,
        )
        .expect("a staff player's inventory is not confined");
}

#[test]
fn a_tier0_player_cannot_enter_a_confined_room() {
    let (mut world, mut host) = boot();
    world.connect(1, &mut host);
    host.take(1);
    world.connect(2, &mut host); // guest, T0
    host.take(2);
    let guest = world.connection_object(2).expect("bound");
    let room = world
        .load_object("/std/confined_room", &mut host)
        .expect("load");

    let e = world
        .call(guest, "move_into_obj", vec![Value::Object(room)], &mut host)
        .unwrap_err();
    assert!(e.contains("tier-0 player cannot enter"), "{e}");
}

// -- CTO review B4: `program_flags` must be recomputed as part of
// `install`, not lazily on the next `load_object`/`clone_object` -- else
// an already-live confined object reads the fail-open default (a
// confinement bypass) until someone happens to re-load/clone that exact
// path -----------------------------------------------------------------

#[test]
fn recompiling_a_confined_program_keeps_its_existing_clone_confined() {
    let (mut world, mut host) = boot();
    let thing = world
        .load_object("/std/confined_thing", &mut host)
        .expect("load");
    let room = world
        .load_object("/std/live_room", &mut host)
        .expect("load");
    assert_eq!(world.program_flags("/std/confined_thing"), "confined");

    // Recompile `/std/confined_thing` (a builder editing the file, no
    // content change needed to reproduce the bug: `Registry::install`
    // used to just drop the path's cached `program_flags`, so the next
    // read served the fail-open default until *something* re-triggered
    // `ensure_program_flags` -- which only `load_object`/`clone_object` do,
    // and neither runs again in this test after the recompile).
    world
        .compile_object("/std/confined_thing", &mut host)
        .expect("recompile");
    assert_eq!(
        world.program_flags("/std/confined_thing"),
        "confined",
        "recomputed as part of install, not left at the fail-open default"
    );

    let e = world
        .call(thing, "move_into_obj", vec![Value::Object(room)], &mut host)
        .unwrap_err();
    assert!(
        e.contains("live room"),
        "still confined after the recompile: {e}"
    );
}

// -- CTO review B2: "unlimited" (root/mudlib/domain:*) is unlimited
// *counts*, never unlimited per-execution ticks -- a mudlib heartbeat with
// an infinite loop must tick-exhaust at the world default, not hang the
// driver ------------------------------------------------------------------

#[test]
fn a_mudlib_owned_heartbeat_with_an_infinite_loop_aborts_at_the_world_default() {
    let (mut world, mut host) = boot();
    let looper = world
        .load_object("/daemons/looper", &mut host)
        .expect("load");
    assert_eq!(world.owner_uid(looper), Some("mudlib"));

    world.call(looper, "on", Vec::new(), &mut host).expect("on");
    for _ in 0..25 {
        world.tick(&mut host);
    }

    // The infinite loop never lets the heartbeat return normally, but it
    // must still have run (and tick-exhausted) rather than the driver
    // hanging forever inside this one `tick`.
    assert!(matches!(
        world.var(looper, "heartbeat_runs"),
        Some(Value::Int(1))
    ));
}
