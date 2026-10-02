// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! P2-B3.1 (OBI-189, spec §7.2 D-B3.14): `World::recompile_set` /
//! `RegistryHost::recompile_set` -- the changed-set, dependency-ordered,
//! all-or-nothing recompile a post-merge `GitWorker` sync drives. The five
//! acceptance tests from the task description, one per `#[test]`.

mod common;

use common::fixture;
use loom_vm::{ChangeSet, Value, World};

fn boot() -> World {
    let root = fixture("mudlib_sync");
    World::boot(&root).expect("boot")
}

fn change(changed: &[&str]) -> ChangeSet {
    ChangeSet {
        changed: changed.iter().map(|s| s.to_string()).collect(),
        deleted: Vec::new(),
        source_sha: "deadbeef".to_string(),
    }
}

/// (a) Two unrelated changed, already-loaded programs both upgrade in one
/// batch.
#[test]
fn two_unrelated_changed_loaded_programs_both_upgrade() {
    let mut world = boot();
    let mut host = common::FakeHost::default();
    let root = world.root().to_path_buf();

    let alpha = world.load_object("/std/alpha", &mut host).expect("load");
    let beta = world.load_object("/std/beta", &mut host).expect("load");
    assert_eq!(world.program_version("/std/alpha"), Some(1));
    assert_eq!(world.program_version("/std/beta"), Some(1));

    std::fs::write(
        root.join("std/alpha.wf"),
        "var tag: string = \"alpha-v1\"\n\npub fn get_tag() -> string {\n    return tag\n}\n\npub fn marker() -> string {\n    return \"alpha-v2\"\n}\n",
    )
    .unwrap();
    std::fs::write(
        root.join("std/beta.wf"),
        "var tag: string = \"beta-v1\"\n\npub fn get_tag() -> string {\n    return tag\n}\n\npub fn marker() -> string {\n    return \"beta-v2\"\n}\n",
    )
    .unwrap();

    let report = world.recompile_set(&change(&["/std/alpha", "/std/beta"]), &mut host);
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.recompiled.len(), 2);
    assert!(report.recompiled.contains(&"/std/alpha".to_string()));
    assert!(report.recompiled.contains(&"/std/beta".to_string()));
    assert_eq!(report.upgraded_instances, 2);
    assert!(report.skipped_unloaded.is_empty());
    assert!(report.deleted_loaded.is_empty());

    assert_eq!(world.program_version("/std/alpha"), Some(2));
    assert_eq!(world.program_version("/std/beta"), Some(2));
    // Both pre-existing instances now run the new code (same object ids,
    // and the new `marker()` exists on each).
    assert_eq!(
        world
            .call(alpha, "marker", vec![], &mut host)
            .unwrap()
            .as_str(),
        Some("alpha-v2")
    );
    assert_eq!(
        world
            .call(beta, "marker", vec![], &mut host)
            .unwrap()
            .as_str(),
        Some("beta-v2")
    );
    // Old state survived the upgrade (schema-compatible var kept).
    assert_eq!(
        world
            .call(alpha, "get_tag", vec![], &mut host)
            .unwrap()
            .as_str(),
        Some("alpha-v1")
    );
}

/// (b) Changing a parent recompiles a loaded child once, parents first.
#[test]
fn changing_a_parent_recompiles_a_loaded_child_once_parents_first() {
    let mut world = boot();
    let mut host = common::FakeHost::default();
    let root = world.root().to_path_buf();

    let hall = world.load_object("/domains/hall", &mut host).expect("load");
    assert_eq!(world.program_version("/std/room"), Some(1));
    assert_eq!(world.program_version("/domains/hall"), Some(1));

    std::fs::write(
        root.join("std/room.wf"),
        "var short_desc: string = \"An empty room\"\n\npub fn short() -> string {\n    return short_desc\n}\n\npub fn long() -> string {\n    return short() + \" (nothing else to see)\"\n}\n",
    )
    .unwrap();

    // Only the parent is in the changed set; the child is pulled in
    // purely through the reverse-inherit graph.
    let report = world.recompile_set(&change(&["/std/room"]), &mut host);
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(
        report.recompiled,
        vec!["/std/room".to_string(), "/domains/hall".to_string()],
        "parents before children, and the child appears exactly once"
    );
    assert_eq!(report.upgraded_instances, 1, "one live hall instance");

    assert_eq!(world.program_version("/std/room"), Some(2));
    assert_eq!(world.program_version("/domains/hall"), Some(2));
    let long = world.call(hall, "long", vec![], &mut host).unwrap();
    assert_eq!(long.as_str(), Some("The Great Hall (nothing else to see)"));
}

/// (c) One failure in the batch means nothing installs; old versions keep
/// running; the report lists the diagnostic.
#[test]
fn one_failure_means_nothing_installs_and_old_versions_keep_running() {
    let mut world = boot();
    let mut host = common::FakeHost::default();
    let root = world.root().to_path_buf();

    world.load_object("/std/alpha", &mut host).expect("load");
    world.load_object("/std/doomed", &mut host).expect("load");
    assert_eq!(world.program_version("/std/alpha"), Some(1));
    assert_eq!(world.program_version("/std/doomed"), Some(1));

    // A good edit to `/std/alpha` alongside a syntax error in `/std/doomed`.
    std::fs::write(
        root.join("std/alpha.wf"),
        "var tag: string = \"alpha-v1\"\n\npub fn get_tag() -> string {\n    return tag\n}\n\npub fn marker() -> string {\n    return \"alpha-v2\"\n}\n",
    )
    .unwrap();
    std::fs::write(
        root.join("std/doomed.wf"),
        "pub fn get_tag() -> string {\n    return \"oops\" +\n}\n",
    )
    .unwrap();

    let report = world.recompile_set(&change(&["/std/alpha", "/std/doomed"]), &mut host);
    assert!(report.recompiled.is_empty(), "{:?}", report.recompiled);
    assert_eq!(report.upgraded_instances, 0);
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].0, "/std/doomed");
    assert!(
        report.failures[0].1.contains("error"),
        "{}",
        report.failures[0].1
    );

    // Both programs kept their old version -- nothing installed at all.
    assert_eq!(world.program_version("/std/alpha"), Some(1));
    assert_eq!(world.program_version("/std/doomed"), Some(1));
    assert_eq!(world.mudlib_sync_total("compile_failed"), 1);
    assert_eq!(world.mudlib_sync_total("ok"), 0);
}

/// (d) A changed path that was never loaded is skipped (lazy load), not
/// force-compiled.
#[test]
fn an_unloaded_changed_path_is_skipped() {
    let mut world = boot();
    let mut host = common::FakeHost::default();

    assert_eq!(world.program_version("/std/unloaded"), None);
    let report = world.recompile_set(&change(&["/std/unloaded"]), &mut host);
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert!(report.recompiled.is_empty());
    assert_eq!(report.upgraded_instances, 0);
    assert_eq!(report.skipped_unloaded, vec!["/std/unloaded".to_string()]);
    // Still not registered -- genuinely untouched, lazy load still pending.
    assert_eq!(world.program_version("/std/unloaded"), None);

    // It loads fine fresh from disk whenever something actually needs it.
    let ob = world.load_object("/std/unloaded", &mut host).expect("load");
    assert_eq!(
        world
            .call(ob, "get_tag", vec![], &mut host)
            .unwrap()
            .as_str(),
        Some("never loaded")
    );
}

/// (e) Master in the set flushes the `program_flags` cache: a reflagged
/// path is reflected without a further `load_object`/`clone_object` of
/// that path (CTO review B4, carried from the single-root `install` to
/// the whole-batch `recompile_set`). Confinement (`move_to`) is the real
/// driver code path that reads `program_flags` lazily -- the plain
/// `World::program_flags` test getter never recomputes anything itself,
/// so this exercises the same enforcement path `quotas.rs` does.
#[test]
fn master_in_the_set_flushes_the_program_flags_cache() {
    let mut world = boot();
    let mut host = common::FakeHost::default();
    let root = world.root().to_path_buf();

    let the_box = world.load_object("/std/box", &mut host).expect("load");
    let room = world
        .load_object("/std/live_room", &mut host)
        .expect("load");
    assert_eq!(world.program_flags("/std/box"), "none");
    assert_eq!(world.program_flags("/std/live_room"), "none");

    // Before the master recompile, neither is flagged: the move succeeds.
    world
        .call(
            the_box,
            "move_into_obj",
            vec![Value::Object(room)],
            &mut host,
        )
        .expect("move succeeds before the reflag");

    // Flip `/std/box` to CONFINED and `/std/live_room` to LIVE in the
    // master's own code -- neither path itself is in the changed set and
    // neither is reloaded.
    std::fs::write(
        root.join("secure/master.wf"),
        "fn valid_efun(name: string, class: int, ob: object) -> bool {\n    return true\n}\n\nfn valid_compile(path: string, ob: object) -> bool {\n    return true\n}\n\nfn valid_upgrade(path: string, ob: object) -> bool {\n    return true\n}\n\nfn program_flags(path: string) -> int {\n    if path == \"/std/box\" {\n        return 1\n    }\n    if path == \"/std/live_room\" {\n        return 2\n    }\n    return 0\n}\n",
    )
    .unwrap();

    let report = world.recompile_set(&change(&["/secure/master"]), &mut host);
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.recompiled, vec!["/secure/master".to_string()]);

    // Neither instance was itself recompiled/reloaded...
    assert_eq!(world.program_version("/std/box"), Some(1));
    assert_eq!(world.program_version("/std/live_room"), Some(1));
    // ...yet confinement now enforces the *new* master's answer on the
    // very next access -- the cache was flushed by the master recompile
    // alone, not by a further load/clone of `/std/box`/`/std/live_room`.
    let e = world
        .call(
            the_box,
            "move_into_obj",
            vec![Value::Object(room)],
            &mut host,
        )
        .unwrap_err();
    assert!(e.contains("live room"), "{e}");
}

/// Bonus (scope, not an explicit acceptance test): a deleted-but-loaded
/// path keeps running on its last-compiled program and is reported, not
/// treated as a failure or silently dropped.
#[test]
fn a_deleted_loaded_path_keeps_running_and_is_warned_about() {
    let mut world = boot();
    let mut host = common::FakeHost::default();

    let alpha = world.load_object("/std/alpha", &mut host).expect("load");

    let report = world.recompile_set(
        &ChangeSet {
            changed: Vec::new(),
            deleted: vec!["/std/alpha".to_string()],
            source_sha: "deadbeef".to_string(),
        },
        &mut host,
    );
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert!(report.recompiled.is_empty());
    assert_eq!(report.deleted_loaded, vec!["/std/alpha".to_string()]);

    // Still running, same version, same state.
    assert_eq!(world.program_version("/std/alpha"), Some(1));
    assert_eq!(
        world
            .call(alpha, "get_tag", vec![], &mut host)
            .unwrap()
            .as_str(),
        Some("alpha-v1")
    );
}
