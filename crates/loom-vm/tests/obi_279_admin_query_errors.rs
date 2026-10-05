// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-279 (follow-up to the CTO review of OBI-237 PR #102, non-blocking
//! notes 1 and 3):
//!
//! 1. `World::admin_list_objects`/`admin_object_vars`/`admin_errors`
//!    must return `Err` when the master's `valid_read` fails to produce
//!    a real decision (a tick-budget or other runtime failure), not an
//!    empty/`None`, successful-looking result -- the HTTP edge turns
//!    that `Err` into a `503`.
//! 2. The `"admin_query"` audit kind must show up in the audit trail as
//!    `"admin_query"`, not `"?"`.

mod common;

use common::{FakeHost, fixture, on_world_thread};
use loom_vm::World;

#[test]
fn admin_list_objects_errors_when_valid_read_exhausts_its_budget() {
    on_world_thread(|| {
        let root = fixture("admin_query_budget");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();

        world.connect(1, &mut host);
        host.take(1);
        world.input(1, "spawnitem", &mut host);
        let _item_path = host.take(1).trim().to_string();

        // `secure/master.wf`'s `valid_read` busy-loops forever: the
        // first (and only) distinct program in the registry trips its
        // own `APPLY_TICKS` budget, which must surface as `Err`, not an
        // empty `Vec` (CTO review, OBI-237 PR #102, non-blocking note
        // 1).
        let err = world
            .admin_list_objects("guest", 0, &mut host)
            .expect_err("a tick-exhausted valid_read must be an error, not an empty list");
        assert!(
            !err.catchable,
            "tick exhaustion is always uncatchable (spec: not a `try`/`catch`-able error)"
        );
    });
}

#[test]
fn admin_object_vars_errors_when_valid_read_exhausts_its_budget() {
    on_world_thread(|| {
        let root = fixture("admin_query_budget");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();

        world.connect(1, &mut host);
        host.take(1);
        world.input(1, "spawnitem", &mut host);
        let item_path = host.take(1).trim().to_string();

        let err = world
            .admin_object_vars("guest", 0, &item_path, &mut host)
            .expect_err("a tick-exhausted valid_read must be an error, not `None`");
        assert!(!err.catchable);
    });
}

#[test]
fn admin_errors_errors_when_valid_read_exhausts_its_budget() {
    on_world_thread(|| {
        let root = fixture("admin_query_budget");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();

        world.connect(1, &mut host);
        host.take(1);
        world.input(1, "spawnitem", &mut host);
        let item_path = host.take(1).trim().to_string();
        // An object whose own bytecode raises, so `errors_snapshot`
        // actually has a row to filter by `valid_read` in the first
        // place (an empty snapshot would trivially "pass" with an empty
        // `Vec`, proving nothing).
        world.input(1, "boom", &mut host);
        let _ = host.take(1);
        let _ = item_path;

        let err = world
            .admin_errors("guest", 0, None, &mut host)
            .expect_err("a tick-exhausted valid_read must be an error, not an empty list");
        assert!(!err.catchable);
    });
}

/// OBI-279 non-blocking note 2: `admin_valid_read`'s `authorize` call is
/// recorded in the audit trail as `"admin_query"`, not `"?"`.
#[test]
fn admin_query_audit_entries_use_the_admin_query_kind_not_a_question_mark() {
    on_world_thread(|| {
        let root = fixture("admin_query");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();

        world.connect(1, &mut host);
        host.take(1);
        world.input(1, "spawnitem", &mut host);
        let _item_path = host.take(1).trim().to_string();

        let _ = world
            .admin_list_objects("guest", 0, &mut host)
            .expect("admin_query fixture's valid_read always answers");

        let log = world.audit_log();
        assert!(
            log.iter().any(|e| e.efun == "admin_query"),
            "expected an `admin_query` audit entry, got kinds: {:?}",
            log.iter().map(|e| e.efun).collect::<Vec<_>>()
        );
        assert!(
            !log.iter().any(|e| e.efun == "?"),
            "no admin-query decision should ever be recorded as `?`"
        );
    });
}
