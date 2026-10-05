// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-237 (the world-thread side of the admin query channel, OBI-234
//! follow-up): `World::who_sessions`/`admin_list_objects`/
//! `admin_object_vars`, exercised directly against [`World`] -- the
//! `loom-cli` receiver loop and `loom-http`'s routes are thin wiring
//! around these three methods, so this is where the actual behaviour
//! (session timing, and the real `valid_read` enforcement) is tested.

mod common;

use common::{FakeHost, fixture, on_world_thread};
use loom_vm::World;

#[test]
fn who_sessions_reports_live_connections_with_no_email_or_ip() {
    on_world_thread(|| {
        let root = fixture("admin_query");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();

        world.connect(1, &mut host);
        host.take(1);
        world.connect(2, &mut host);
        host.take(2);

        let who = world.who_sessions();
        assert_eq!(who.len(), 2);
        assert_eq!(who[0].conn_id, 1);
        assert_eq!(who[1].conn_id, 2);
        // Still at the login prompt (never `seteuid`'d): no account yet.
        assert_eq!(who[0].account, None);
        assert_eq!(who[1].account, None);
        // The type has no email/IP field at all (M-ADM-3) -- there is
        // nothing more to assert here than "it compiles with exactly
        // these fields", which the struct literal below exercises.
        let _ = loom_vm::SessionSummary {
            conn_id: who[0].conn_id,
            account: who[0].account.clone(),
            connected_at: who[0].connected_at,
            idle_secs: who[0].idle_secs,
        };

        world.disconnect(2, &mut host);
        let who = world.who_sessions();
        assert_eq!(who.len(), 1, "a disconnected session drops out of `who`");
        assert_eq!(who[0].conn_id, 1);
    });
}

#[test]
fn who_sessions_account_appears_only_after_a_real_seteuid() {
    on_world_thread(|| {
        let root = fixture("admin_query");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();

        world.connect(1, &mut host);
        host.take(1);
        assert_eq!(world.who_sessions()[0].account, None);

        world.input(1, "become alice", &mut host);
        assert_eq!(host.take(1), "ok\n");

        let who = world.who_sessions();
        assert_eq!(who.len(), 1);
        assert_eq!(who[0].account.as_deref(), Some("alice"));
    });
}

#[test]
fn list_objects_is_filtered_by_the_real_valid_read_not_a_stand_in() {
    on_world_thread(|| {
        let root = fixture("admin_query");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();

        world.connect(1, &mut host);
        host.take(1);
        world.input(1, "spawnitem", &mut host);
        let item_path = host.take(1).trim().to_string();
        world.input(1, "spawnvault", &mut host);
        let vault_path = host.take(1).trim().to_string();

        // `auditor` is a non-reserved euid this fixture's `valid_read`
        // happens to trust with `/std/vault` specifically (CTO review,
        // OBI-237 PR #102, must-fix B1: `root` is refused by
        // `admin_list_objects` itself before `valid_read` is ever asked,
        // so it can no longer stand in for "a caller `valid_read`
        // allows").
        let as_auditor = world
            .admin_list_objects("auditor", 5, &mut host)
            .expect("no budget exhaustion in this fixture");
        assert!(as_auditor.iter().any(|o| o.path == item_path));
        assert!(
            as_auditor.iter().any(|o| o.path == vault_path),
            "auditor is specifically allowed /std/vault by this fixture's valid_read"
        );

        // Any other euid actually goes through `secure/master.wf`'s
        // `valid_read`, which denies `/std/vault` specifically.
        let as_guest = world
            .admin_list_objects("guest", 0, &mut host)
            .expect("no budget exhaustion in this fixture");
        assert!(
            as_guest.iter().any(|o| o.path == item_path),
            "a readable program's objects are still listed"
        );
        assert!(
            !as_guest.iter().any(|o| o.path == vault_path),
            "a denied program's objects are silently omitted, not an error"
        );
    });
}

#[test]
fn object_vars_renders_real_state_once_valid_read_passes() {
    on_world_thread(|| {
        let root = fixture("admin_query");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();

        world.connect(1, &mut host);
        host.take(1);
        world.input(1, "spawnitem", &mut host);
        let item_path = host.take(1).trim().to_string();

        let vars = world
            .admin_object_vars("guest", 0, &item_path, &mut host)
            .expect("no budget exhaustion in this fixture")
            .expect("readable program");
        assert_eq!(vars.path, item_path);
        let count = vars.vars.iter().find(|v| v.name == "count").expect("count");
        assert_eq!(count.value, "42");
        let label = vars.vars.iter().find(|v| v.name == "label").expect("label");
        assert_eq!(label.value, "sword");
    });
}

#[test]
fn object_vars_a_valid_read_refusal_and_an_unknown_path_are_both_not_found() {
    on_world_thread(|| {
        let root = fixture("admin_query");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();

        world.connect(1, &mut host);
        host.take(1);
        world.input(1, "spawnvault", &mut host);
        let vault_path = host.take(1).trim().to_string();

        // Denied by `valid_read`: `None`, same shape as a path that does
        // not resolve to a live object at all -- the trait contract this
        // mirrors (`loom_http::admin_query::WorldAdminQuery::object_vars`)
        // requires these be indistinguishable.
        assert!(
            world
                .admin_object_vars("guest", 0, &vault_path, &mut host)
                .expect("no budget exhaustion in this fixture")
                .is_none()
        );
        assert!(
            world
                .admin_object_vars("guest", 0, "/std/does_not_exist#1", &mut host)
                .expect("no budget exhaustion in this fixture")
                .is_none()
        );

        // `auditor` is specifically allowed `/std/vault` by this
        // fixture's `valid_read` (CTO review, OBI-237 PR #102, must-fix
        // B1: `root` is refused by `admin_object_vars` itself before
        // `valid_read` is ever asked).
        let vars = world
            .admin_object_vars("auditor", 5, &vault_path, &mut host)
            .expect("no budget exhaustion in this fixture")
            .expect("auditor can read /std/vault");
        let secret = vars
            .vars
            .iter()
            .find(|v| v.name == "secret")
            .expect("secret");
        assert_eq!(secret.value, "99");
    });
}

#[test]
fn a_flood_of_admin_queries_never_stalls_world_ticks() {
    // OBI-237 acceptance: "a flooded admin-query rate degrades to 503s,
    // not world-thread latency". `loom-http`'s own bounded channel
    // (`ChannelWorldQuery`'s `full_channel_is_busy_not_blocking` test,
    // `crates/loom-http/src/admin_query.rs`) already proves a full queue
    // never blocks the *sending* side; this proves the *answering* side
    // (what `loom-cli`'s world-thread `try_recv` drain loop calls per
    // request) is itself cheap and bounded -- each `admin_list_objects`/
    // `admin_object_vars` call is one tick-metered master apply per
    // distinct program (same cost class as any other `valid_read`
    // call-site), not an unbounded or blocking operation -- so draining
    // many of them back-to-back between two world ticks cannot itself
    // become the world-thread latency source the acceptance criterion
    // rules out.
    on_world_thread(|| {
        let root = fixture("admin_query");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();

        world.connect(1, &mut host);
        host.take(1);
        world.input(1, "spawnitem", &mut host);
        let item_path = host.take(1).trim().to_string();

        let before = world.world_tick();
        let start = std::time::Instant::now();
        // Simulates `ADMIN_QUERY_QUEUE_DEPTH` (32) worth of requests
        // landing many times over inside one event-loop iteration's
        // worth of draining -- the exact shape a flooding HTTP client
        // produces once its own requests start queueing.
        for _ in 0..5_000 {
            let objects = world
                .admin_list_objects("guest", 0, &mut host)
                .expect("no budget exhaustion in this fixture");
            assert!(objects.iter().any(|o| o.path == item_path));
            let vars = world
                .admin_object_vars("guest", 0, &item_path, &mut host)
                .expect("no budget exhaustion in this fixture")
                .expect("readable");
            assert!(!vars.vars.is_empty());
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "5,000 admin queries took {elapsed:?} -- each one is a bounded, \
             tick-metered master apply, not an unbounded operation"
        );

        // A world tick in between (and after) the flood still advances
        // normally -- the flood above shares nothing with the scheduler
        // or tick counter, so it cannot have stalled it.
        world.tick(&mut host);
        assert_eq!(world.world_tick(), before + 1);
    });
}

/// CTO review (OBI-237 PR #102, must-fix B1): a staff `sub` of a reserved
/// driver principal (`root`, `mudlib`, any `domain:*`) must be refused by
/// every admin-query method, not granted the driver's own root privilege
/// by accident. `syms.intern("root")` reuses `security::ROOT` (sym 0),
/// which `GuardSet::with` drops as the identity element -- an unchecked
/// caller_euid of `"root"` would silently build an *empty* guard, which
/// D-S1.2 allows unconditionally, `/secure` included.
#[test]
fn admin_list_objects_refuses_a_reserved_principal_as_caller_euid() {
    on_world_thread(|| {
        let root = fixture("admin_query");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();

        world.connect(1, &mut host);
        host.take(1);
        world.input(1, "spawnitem", &mut host);
        let item_path = host.take(1).trim().to_string();

        for reserved in ["root", "mudlib", "domain:shire"] {
            let objects = world
                .admin_list_objects(reserved, 5, &mut host)
                .expect("a reserved principal is refused, never a budget error");
            assert!(
                objects.is_empty(),
                "caller_euid={reserved:?} must not see anything, got {objects:?}"
            );
        }

        // Sanity: a non-reserved euid still sees the readable object (the
        // guard above isn't just denying everything unconditionally).
        let as_guest = world
            .admin_list_objects("guest", 5, &mut host)
            .expect("no budget exhaustion in this fixture");
        assert!(as_guest.iter().any(|o| o.path == item_path));
    });
}

#[test]
fn admin_object_vars_refuses_a_reserved_principal_as_caller_euid() {
    on_world_thread(|| {
        let root = fixture("admin_query");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();

        world.connect(1, &mut host);
        host.take(1);
        world.input(1, "spawnitem", &mut host);
        let item_path = host.take(1).trim().to_string();

        for reserved in ["root", "mudlib", "domain:shire"] {
            assert!(
                world
                    .admin_object_vars(reserved, 5, &item_path, &mut host)
                    .expect("a reserved principal is refused, never a budget error")
                    .is_none(),
                "caller_euid={reserved:?} must not read {item_path}"
            );
        }

        // Sanity: a non-reserved euid still reads it.
        assert!(
            world
                .admin_object_vars("guest", 5, &item_path, &mut host)
                .expect("no budget exhaustion in this fixture")
                .is_some()
        );
    });
}
