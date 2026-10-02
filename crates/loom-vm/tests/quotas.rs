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

#[test]
fn tick_share_per_min_bumps_the_breach_metric_only_once_per_transition_into_breach() {
    // OBI-137 S2: `loom_tier_quota_breaches_total` must bump once per
    // window *transition* into breach, not once per deferred
    // heartbeat/call_out tick -- several ticks in a row while still over
    // the share must not each add to the count.
    let (mut world, mut host) = boot();
    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"tick_share_per_min": 1}"#)));
    connect_appr(&mut world, &mut host, 1);

    world.input(1, "sethbn 0", &mut host);
    host.take(1);
    world.input(1, "callout", &mut host);
    host.take(1);
    world.tick(&mut host); // the call_out fires; the window is now breached.
    assert_eq!(
        world.quota_breach_count(1, "tick_share_per_min"),
        0,
        "not breached yet at the moment this one fired"
    );

    // Several more ticks in a row while still breached: each one's
    // `tick_share_breached` check finds the uid still over its share
    // (nothing new was scheduled, so there is nothing to defer either),
    // but the metric must not grow past the single transition.
    for _ in 0..5 {
        world.tick(&mut host);
    }

    // Now actually schedule and let several ticks find it breached and
    // defer it, to prove the *defer* path itself does not re-bump either.
    world.input(1, "callout", &mut host);
    host.take(1);
    for _ in 0..5 {
        world.tick(&mut host); // each one finds it still breached, defers
    }
    assert_eq!(
        world.quota_breach_count(1, "tick_share_per_min"),
        1,
        "one bump for the one transition into breach, not one per deferred tick"
    );
}

#[test]
fn max_callouts_obj_counter_frees_up_again_after_remove_call_out() {
    // OBI-137 S3: `pending_count_for_obj` must reflect a cancelled
    // call_out immediately, not keep counting it until it would have
    // become due.
    let (mut world, mut host) = boot();
    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"max_callouts_obj": 1}"#)));
    connect_appr(&mut world, &mut host, 1);

    world.input(1, "callout", &mut host);
    assert_eq!(host.take(1), "scheduled\n");
    world.input(1, "callout", &mut host);
    assert!(host.take(1).contains("max_callouts_obj"));

    world.input(1, "cancelcallout", &mut host);
    assert_eq!(host.take(1), "true\n");

    // The slot freed by the cancel must be usable again immediately.
    world.input(1, "callout", &mut host);
    assert_eq!(host.take(1), "scheduled\n");
}

#[test]
fn max_heartbeats_counter_frees_up_again_after_destruct() {
    // OBI-137 S3: destructing a still-subscribed object must free its
    // owner's per-owner heartbeat count immediately, not leave it charged
    // until some later scan happens to notice the object is gone.
    //
    // (Connections 2 and 3 are the fixture's guest/staffer special cases
    // -- `connect_appr` on connection 4 is this fixture's second
    // `appr`-owned player, same convention as
    // `max_heartbeats_row_denies_a_second_apprentice_owned_subscriber`.)
    let (mut world, mut host) = boot();
    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"max_heartbeats": 1}"#)));
    let ob1 = connect_appr(&mut world, &mut host, 1);
    world.input(1, "heartbeaton", &mut host);
    assert_eq!(host.take(1), "on\n");

    world.connect(2, &mut host); // guest
    host.take(2);
    world.connect(3, &mut host); // staffer
    host.take(3);
    let ob4 = connect_appr(&mut world, &mut host, 4);
    world.input(4, "heartbeaton", &mut host);
    assert!(host.take(4).contains("max_heartbeats"));

    world.destruct(ob1, &mut host);
    world.input(4, "heartbeaton", &mut host);
    assert_eq!(host.take(4), "on\n");
    let _ = ob4;
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
    let ok = world
        .call(
            workroom,
            "write_disk",
            vec![Value::str("/builders/appr/a.txt"), Value::str(&chunk)],
            &mut host,
        )
        .expect("700_000 bytes is within the 1 MB quota");
    assert!(matches!(ok, Value::Bool(true)));

    // OBI-137 S1: over quota returns `false` and writes an audit entry --
    // it must not raise.
    let audit_before = world.audit_log().len();
    let result = world
        .call(
            workroom,
            "write_disk",
            vec![Value::str("/builders/appr/b.txt"), Value::str(&chunk)],
            &mut host,
        )
        .expect("an over-quota write_file must not raise");
    assert!(matches!(result, Value::Bool(false)), "{result:?}");
    let new_entries = &world.audit_log()[audit_before..];
    assert!(
        new_entries
            .iter()
            .any(|e| e.apply == "quota" && e.efun == "disk_quota_mb" && !e.allowed),
        "expected a disk_quota_mb audit entry, got {new_entries:?}"
    );
    assert!(
        !std::path::Path::new(&format!("{}/builders/appr/b.txt", world.root().display())).exists(),
        "a rejected write must not land on disk"
    );
}

#[test]
fn disk_quota_mb_counter_stays_correct_across_overwrite_shrink_and_a_later_write() {
    let (mut world, mut host) = boot();
    let workroom = world
        .load_object("/builders/appr/workroom", &mut host)
        .expect("load");
    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"disk_quota_mb": 1}"#)));

    let big = "a".repeat(900_000);
    world
        .call(
            workroom,
            "write_disk",
            vec![Value::str("/builders/appr/a.txt"), Value::str(&big)],
            &mut host,
        )
        .expect("900_000 bytes is within the 1 MB quota");

    // Shrink the same file: the counter must reflect the *new* (smaller)
    // size, not keep charging the old 900_000 bytes -- so a second write
    // that would only fit if the shrink was accounted for must succeed.
    let small = "a".repeat(10_000);
    world
        .call(
            workroom,
            "write_disk",
            vec![Value::str("/builders/appr/a.txt"), Value::str(&small)],
            &mut host,
        )
        .expect("overwriting with a smaller file must succeed");

    let bigger = "a".repeat(900_000);
    let result = world
        .call(
            workroom,
            "write_disk",
            vec![Value::str("/builders/appr/b.txt"), Value::str(&bigger)],
            &mut host,
        )
        .expect("must not raise");
    assert!(
        matches!(result, Value::Bool(true)),
        "the shrink must have freed enough of the quota for this write to fit: {result:?}"
    );
}

// -- disk_quota_mb on save_object into the save root (OBI-171) --------------

/// CTO review on PR #75, must-fix 2: `save_object` must go through
/// `disk_quota_mb` the same way `write_file` does -- charged to the
/// *writing object's own uid* (`appr`, since a save path carries no uid
/// in its text the way `/builders/<u>/**` does), seeded from the save
/// root instead of the mudlib root.
#[test]
fn disk_quota_mb_row_denies_a_save_object_that_would_exceed_the_quota() {
    let (mut world, mut host) = boot();
    world.set_save_root(common::scratch("quotas-save-root"));
    let workroom = world
        .load_object("/builders/appr/workroom", &mut host)
        .expect("load");
    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"disk_quota_mb": 1}"#)));

    // Within quota: comfortably under 1 MB including the JSON envelope's
    // own overhead.
    let small = "a".repeat(700_000);
    world
        .call(workroom, "set_blob", vec![Value::str(&small)], &mut host)
        .expect("set_blob");
    let ok = world
        .call(
            workroom,
            "save_disk",
            vec![Value::str("/appr-save")],
            &mut host,
        )
        .expect("a save within quota must not raise");
    assert!(matches!(ok, Value::Bool(true)), "{ok:?}");

    // Over quota: a second, larger save to a *different* path must be
    // rejected -- `false`, not an error -- and must not land on disk.
    let big = "a".repeat(900_000);
    world
        .call(workroom, "set_blob", vec![Value::str(&big)], &mut host)
        .expect("set_blob");
    let audit_before = world.audit_log().len();
    let result = world
        .call(
            workroom,
            "save_disk",
            vec![Value::str("/appr-save-2")],
            &mut host,
        )
        .expect("an over-quota save_object must not raise");
    assert!(matches!(result, Value::Bool(false)), "{result:?}");
    let new_entries = &world.audit_log()[audit_before..];
    assert!(
        new_entries
            .iter()
            .any(|e| e.apply == "quota" && e.efun == "disk_quota_mb" && !e.allowed),
        "expected a disk_quota_mb audit entry, got {new_entries:?}"
    );
    assert!(
        !world.save_root().join("appr-save-2.o").exists(),
        "a rejected save must not land on disk"
    );
}

// -- disk_quota_mb seed order (OBI-236, follow-up to CTO re-review of PR #75) -

/// Save seeds first: before this fix, `DiskUsage` kept one shared counter
/// per `<u>` (`entry().or_insert_with`), so whichever of `seeded_total`
/// (the `/builders/<u>/**` walk) or `seeded_save_total` (the save file's
/// own size) ran first for a given `<u>` silently won that `<u>`'s whole
/// seed. A `save_object` that ran before the builder ever wrote anything
/// left the shared counter seeded at the save file's size alone, and the
/// `/builders/appr/**` tree was never walked at all -- so a builder near
/// quota could still write about one extra full quota's worth of
/// `write_file` after that. This drives `save_object` first, then a
/// `write_file` that only fits if the save's own bytes *and* the
/// pre-existing `/builders/appr/**` tree both count toward `appr`'s
/// `disk_quota_mb`.
#[test]
fn disk_quota_mb_counts_the_builders_tree_even_when_save_object_seeds_first() {
    let (mut world, mut host) = boot();
    world.set_save_root(common::scratch("quotas-save-order-save-first"));
    let workroom = world
        .load_object("/builders/appr/workroom", &mut host)
        .expect("load");

    // A file already sits under `/builders/appr/**` from a previous
    // session, well before any quota row exists.
    let preexisting = "a".repeat(600_000);
    world
        .call(
            workroom,
            "write_disk",
            vec![
                Value::str("/builders/appr/old.txt"),
                Value::str(&preexisting),
            ],
            &mut host,
        )
        .expect("write before any quota row is unconditional");

    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"disk_quota_mb": 1}"#)));

    // `save_object` runs first under the new quota row: this seeds
    // `appr`'s save pool (a small save, well within quota on its own).
    let small_save = "a".repeat(1_000);
    world
        .call(
            workroom,
            "set_blob",
            vec![Value::str(&small_save)],
            &mut host,
        )
        .expect("set_blob");
    let ok = world
        .call(
            workroom,
            "save_disk",
            vec![Value::str("/appr-save")],
            &mut host,
        )
        .expect("small save within quota must not raise");
    assert!(matches!(ok, Value::Bool(true)), "{ok:?}");

    // Now `write_file`: the pre-existing 600_000-byte `/builders/appr/**`
    // tree plus this new 600_000-byte file is over the 1 MB quota. If the
    // directory pool had been left unseeded (the old shared-counter bug),
    // this write would incorrectly be accepted.
    let chunk = "a".repeat(600_000);
    let result = world
        .call(
            workroom,
            "write_disk",
            vec![Value::str("/builders/appr/new.txt"), Value::str(&chunk)],
            &mut host,
        )
        .expect("an over-quota write_file must not raise");
    assert!(
        matches!(result, Value::Bool(false)),
        "the pre-existing /builders/appr/** tree must count toward the quota: {result:?}"
    );
    assert!(
        !std::path::Path::new(&format!("{}/builders/appr/new.txt", world.root().display()))
            .exists(),
        "a rejected write must not land on disk"
    );
}

/// `write_file` seeds first: before this fix, seeding the shared counter
/// from the directory walk alone (no save file in it) meant
/// `check_save_disk_quota` still unconditionally subtracted the save
/// file's `old_bytes` from that *same* counter on a later overwrite --
/// the saturating subtraction then silently undercounted usage by the
/// size of the old save from that point on, letting further writes
/// through that should have been rejected. This drives `write_file`
/// first (seeding the directory pool), then a `save_object` overwrite of
/// an already-existing save file, and checks the overwrite's own quota
/// decision is still correct (no undercount).
#[test]
fn disk_quota_mb_save_object_overwrite_is_not_undercounted_when_write_file_seeds_first() {
    let (mut world, mut host) = boot();
    world.set_save_root(common::scratch("quotas-save-order-write-first"));
    let workroom = world
        .load_object("/builders/appr/workroom", &mut host)
        .expect("load");

    // A save file already exists on disk from a previous process, before
    // `save_object` has gone through `DiskUsage` this run at all.
    world
        .call(
            workroom,
            "set_blob",
            vec![Value::str("preexisting")],
            &mut host,
        )
        .expect("set_blob");
    let pre_ok = world
        .call(
            workroom,
            "save_disk",
            vec![Value::str("/appr-save")],
            &mut host,
        )
        .expect("unconditional pre-quota save");
    assert!(matches!(pre_ok, Value::Bool(true)));
    let old_save_bytes = std::fs::metadata(world.save_root().join("appr-save.o"))
        .expect("save file exists")
        .len();
    assert!(
        old_save_bytes > 0,
        "sanity: the pre-existing save has bytes"
    );

    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"disk_quota_mb": 1}"#)));

    // `write_file` runs first under the new quota row: seeds the
    // directory pool at (close to) the 1 MB quota, leaving only just
    // enough headroom for the old save's own bytes plus a hair more.
    let max_bytes = 1u64 << 20;
    let dir_bytes = max_bytes - old_save_bytes - 10_000;
    let chunk = "a".repeat(dir_bytes as usize);
    let ok = world
        .call(
            workroom,
            "write_disk",
            vec![Value::str("/builders/appr/a.txt"), Value::str(&chunk)],
            &mut host,
        )
        .expect("within quota once the old save's own bytes are counted");
    assert!(matches!(ok, Value::Bool(true)), "{ok:?}");

    // Overwrite the existing save with something a little bigger: if the
    // old save's size were undercounted (treated as 0 before the
    // subtraction, the pre-fix bug), this would be wrongly accepted.
    let bigger_save = "a".repeat(20_000);
    world
        .call(
            workroom,
            "set_blob",
            vec![Value::str(&bigger_save)],
            &mut host,
        )
        .expect("set_blob");
    let result = world
        .call(
            workroom,
            "save_disk",
            vec![Value::str("/appr-save")],
            &mut host,
        )
        .expect("an over-quota save_object must not raise");
    assert!(
        matches!(result, Value::Bool(false)),
        "the old save's real on-disk size must be counted, not undercounted to 0: {result:?}"
    );
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

/// A room the master loads from its own `create()` exists before the
/// driver has a master to ask `program_flags` (warp's zones: every start
/// room). It must still read as `live` once the master is up, not as a
/// permanently cached `none` (found by warp's tier smoke test, OBI-36).
#[test]
fn a_room_loaded_during_master_boot_still_gets_its_live_flag() {
    let (mut world, mut host) = boot();
    let room = world
        .find_object("/std/boot_live_room")
        .expect("loaded by the master's create()");
    let thing = world
        .load_object("/std/confined_thing", &mut host)
        .expect("load");
    let e = world
        .call(thing, "move_into_obj", vec![Value::Object(room)], &mut host)
        .unwrap_err();
    assert!(e.contains("live room"), "{e}");
    assert_eq!(world.program_flags("/std/boot_live_room"), "live");
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

// -- CTO re-review N1: `mem_quota_cache` must key on a generation
// counter, not the roles snapshot `Arc`'s own address (an ABA problem in
// principle -- a dropped `Arc`'s address can be reused) -----------------

#[test]
fn mem_quota_cache_is_invalidated_by_every_roles_snapshot_swap_not_just_the_first() {
    let (mut world, mut host) = boot();
    let workroom = world
        .load_object("/builders/appr/workroom", &mut host)
        .expect("load");

    // World default (16 MB): a few thousand ints is fine.
    world
        .call(workroom, "grow", vec![Value::Int(2_000)], &mut host)
        .expect("within the world default");

    // Swap #1: a tight 1 MB row -- must reject immediately (not serve a
    // cached "unlimited" answer from before any snapshot was set).
    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"max_mem_exec_mb": 1}"#)));
    world
        .call(workroom, "grow", vec![Value::Int(500_000)], &mut host)
        .unwrap_err();

    // Swap #2: back to a generous row -- must accept again (not keep
    // serving swap #1's cached rejection-causing quota).
    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"max_mem_exec_mb": 64}"#)));
    world
        .call(workroom, "grow", vec![Value::Int(500_000)], &mut host)
        .expect("swap #2's more generous quota must actually take effect");
}

// -- CTO re-review N2: confinement rule 2 must walk dest's entire
// environment chain, not only dest itself -------------------------------

#[test]
fn confined_object_cannot_reach_a_tier0_player_through_a_container_in_their_inventory() {
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
    let bag = world.load_object("/std/bag", &mut host).expect("load");

    // The bag itself is unflagged (not a player, not confined/live), so
    // placing it in either inventory is unrestricted.
    world
        .call(bag, "move_into_obj", vec![Value::Object(guest)], &mut host)
        .expect("an ordinary container may enter any inventory");

    let e = world
        .call(thing, "move_into_obj", vec![Value::Object(bag)], &mut host)
        .unwrap_err();
    assert!(
        e.contains("tier-0 player"),
        "a confined item must not reach a tier-0 player through a container \
         in their inventory: {e}"
    );

    // Move the (still empty -- the write above failed) bag into the
    // staff player's inventory instead, and the same move must now
    // succeed.
    world
        .call(
            bag,
            "move_into_obj",
            vec![Value::Object(staffer)],
            &mut host,
        )
        .expect("moving the bag itself is unrestricted");
    world
        .call(thing, "move_into_obj", vec![Value::Object(bag)], &mut host)
        .expect("a staff player's container is not confined");
}

// -- CTO re-review N3: a heartbeat on an R1 clone is billed to the
// clone's owner, not to the program's own (always-unlimited) uid --------

#[test]
fn an_r1_clones_heartbeat_is_billed_to_the_apprentices_max_heartbeats_quota() {
    let (mut world, mut host) = boot();
    let workroom = world
        .load_object("/builders/appr/workroom", &mut host)
        .expect("load");
    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"max_heartbeats": 1}"#)));

    let clone1 = world
        .call(workroom, "spawn_daemon", Vec::new(), &mut host)
        .expect("spawn_daemon");
    let Value::Object(clone1) = clone1 else {
        panic!("expected an object");
    };
    world
        .call(clone1, "subscribe", Vec::new(), &mut host)
        .expect("the apprentice's first heartbeat subscriber is within the limit");

    let clone2 = world
        .call(workroom, "spawn_daemon", Vec::new(), &mut host)
        .expect("spawn_daemon");
    let Value::Object(clone2) = clone2 else {
        panic!("expected an object");
    };
    let e = world
        .call(clone2, "subscribe", Vec::new(), &mut host)
        .unwrap_err();
    assert!(
        e.contains("max_heartbeats"),
        "the clone's heartbeat must be billed to `appr` (owner), not to \
         `/daemons/thing`'s own (always-unlimited) uid: {e}"
    );
}

// -- CTO re-review N4: `caller_quota_uid` must skip always-unlimited
// principals when ranking the guard set by tier --------------------------

#[test]
fn a_call_through_a_mudlib_helper_still_bills_the_calling_apprentice() {
    let (mut world, mut host) = boot();
    let workroom = world
        .load_object("/builders/appr/workroom", &mut host)
        .expect("load");

    let clone = world
        .call(
            workroom,
            "spawn_via_helper",
            vec![Value::str("/builders/senior/thing")],
            &mut host,
        )
        .expect("spawn_via_helper");
    let Value::Object(clone_id) = clone else {
        panic!("expected an object, got {clone:?}");
    };
    assert_eq!(
        world.owner_uid(clone_id),
        Some("appr"),
        "the guard set is {{appr(T1), mudlib(T0-but-unbillable)}}: the \
         lowest *billable* tier is appr's, not mudlib's"
    );

    world.tick(&mut host); // the scheduled call_out (delay 1) fires here.
    assert_eq!(
        world.last_call_out_quota_uid(),
        Some("appr"),
        "the helper's own call_out must be billed to the caller, not to \
         its own (always-unlimited) uid"
    );
}

// -- OBI-149 (D-S2.4 amendment): a command-context clone of an
// always-unlimited-uid program must still be billed to the calling
// staff principal, even when the guard set *already* contains that
// program's own uid (as every `/cmds/**` command frame's `mudlib`
// euid does) --------------------------------------------------------------

#[test]
fn a_clone_from_a_mudlib_command_frame_is_still_billed_to_the_apprentice() {
    let (mut world, mut host) = boot();
    let workroom = world
        .load_object("/builders/appr/workroom", &mut host)
        .expect("load");
    // The workroom object itself already counts as 1 against `appr`.
    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"max_objects": 2}"#)));

    // `/cmds/goto` is a mudlib-owned command object (no `/builders`/
    // `/domains` prefix, so its own uid is `mudlib`) -- exactly the
    // `/cmds/**` shape every player command runs through. Its `run`
    // pushes `mudlib` onto the guard *before* `workroom.spawn_daemon()`
    // ever calls `clone_object("/daemons/thing")`, so by the time R1
    // asks "is `/daemons/thing`'s own uid (`mudlib`) already in the
    // guard set?" the answer is yes -- without the amendment the clone
    // would be billed to `mudlib` (never billed at all) instead of
    // `appr`, letting `max_objects` be evaded just by routing the same
    // call through a command.
    let cmd = world
        .load_object("/cmds/goto", &mut host)
        .expect("load cmd");

    let clone = world
        .call(cmd, "run", vec![Value::Object(workroom)], &mut host)
        .expect("first clone is within the limit (workroom + this = 2)");
    let Value::Object(clone_id) = clone else {
        panic!("expected an object, got {clone:?}");
    };
    assert_eq!(
        world.owner_uid(clone_id),
        Some("appr"),
        "billed to the apprentice, not laundered through mudlib's guard"
    );

    // A second clone the same way is refused -- `max_objects` actually
    // applies once the clones are billed to a real (billable) uid.
    let e = world
        .call(cmd, "run", vec![Value::Object(workroom)], &mut host)
        .unwrap_err();
    assert!(e.contains("object quota exceeded"), "{e}");
}

// -- OBI-153: the billing-owner amendment must skip a tier-0 principal
// even when it ranks as "lowest tier" in the whole guard -- it must
// pick the lowest-tier principal *with tier >= 1* instead, or a tier-0
// player sitting next to the apprentice on the stack (e.g. the
// apprentice's own alt walking into the apprentice's room) launders the
// clone back onto `mudlib` and defeats the D-S2.4 amendment entirely.
// -------------------------------------------------------------------------

#[test]
fn a_tier0_player_next_to_the_apprentice_does_not_launder_the_clone_back_to_mudlib() {
    let (mut world, mut host) = boot();
    let workroom = world
        .load_object("/builders/appr/workroom", &mut host)
        .expect("load");
    // The workroom object and the dummy connect(1) apprentice-player
    // clone below (needed only to advance `connect_count` so the next
    // connect becomes `guest`) already count 2 against `appr`.
    world.set_roles_snapshot(Arc::new(roles_with_row(r#"{"max_objects": 3}"#)));
    // master's `connect_count` so the *next* connect (2) becomes `guest`
    // (T0) -- `/std/player`'s own account is picked by call order, not
    // by the connection id passed to `World::connect`.
    world.connect(1, &mut host);
    host.take(1);
    world.connect(2, &mut host); // guest, T0 (no staff row at all)
    host.take(2);
    let guest = world.connection_object(2).expect("bound");
    let cmd = world
        .load_object("/cmds/goto", &mut host)
        .expect("load cmd");

    // Guard, innermost last: {guest (T0 player), cmd (mudlib), workroom
    // (appr, T1)} -- `guest.do_cmd` pushes the tier-0 player onto the
    // guard *below* the mudlib command frame, exactly like a real player
    // typing a command whose target code then clones something. Plain
    // `caller_quota_uid` ranking (lowest tier in the whole guard, ties to
    // the most recent frame) would pick `guest` here (T0, and pushed
    // before `workroom`) -- this is the exact evasion this amendment
    // closes.
    let clone = world
        .call(
            guest,
            "do_cmd",
            vec![Value::Object(cmd), Value::Object(workroom)],
            &mut host,
        )
        .expect("first clone is within the limit (workroom + connect(1)'s appr player + this = 3)");
    let Value::Object(clone_id) = clone else {
        panic!("expected an object, got {clone:?}");
    };
    assert_eq!(
        world.owner_uid(clone_id),
        Some("appr"),
        "billed to the T1 apprentice, not laundered onto the tier-0 \
         player's guard slot or back onto mudlib"
    );

    // A second clone the same way is refused -- `max_objects` actually
    // applies to `appr`, not evadable by routing the same call through
    // the apprentice's own alt (a tier-0 principal) every time.
    let e = world
        .call(
            guest,
            "do_cmd",
            vec![Value::Object(cmd), Value::Object(workroom)],
            &mut host,
        )
        .unwrap_err();
    assert!(e.contains("object quota exceeded"), "{e}");
}
