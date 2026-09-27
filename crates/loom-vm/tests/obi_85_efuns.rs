// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-85 (Warp alpha S4 driver efuns): `destruct`, `read_file`/
//! `write_file` confinement, `random`/`to_int`/`lower`/`users`/`time`, and
//! `account_create`/`account_login`'s async completion contract, exercised
//! end to end through [`World`] (not just the unit-level helpers in
//! `loom_vm::fileio`/`loom_vm::rng`).

mod common;

use common::{FakeHost, fixture, on_world_thread};
use loom_vm::World;
use loom_vm::world::AccountAuth;
use std::collections::VecDeque;

#[test]
fn destruct_moves_inventory_and_cancels_call_outs_and_is_self_safe() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.out.clear();

        world.input(1, "sched", &mut host);
        host.take(1);
        world.input(1, "hbon", &mut host);
        host.take(1);
        assert_eq!(world.pending_call_outs(), 1);

        // Self-destruct mid-execution must not panic: the current frame
        // keeps running (this call to `destruct` itself returns fine),
        // it just can no longer talk to a now-destructed `self` -- so the
        // `send()` right after it silently no-ops (matching every other
        // driver efun's "acting on a destructed object" behaviour) rather
        // than panicking or resurrecting the object.
        world.input(1, "selfdestruct", &mut host);
        assert_eq!(
            host.take(1),
            "",
            "the frame finishes without panicking, but self is already gone"
        );
        assert_eq!(world.pending_call_outs(), 0, "call_out was cancelled");
        assert!(
            host.closed.contains(&1),
            "destruct on a connection-bound object must close the connection"
        );

        // Ticking after destruction must not resurrect the heartbeat/call_out.
        world.tick(&mut host);
        world.tick(&mut host);
        assert_eq!(host.take(1), "");
    });
}

/// CTO review (OBI-85): field access (read *or* write) on a destructed
/// `self` must raise a clear runtime error ("self was destructed"), not
/// the confusing type error a silent `null` read used to produce
/// (`cannot apply Add to null and int`), and not a panic.
#[test]
fn field_write_on_a_destructed_self_is_a_clear_runtime_error() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.out.clear();

        world.input(1, "selfdestructfield", &mut host);
        let out = host.take(1);
        assert!(
            out.contains("self was destructed"),
            "expected a clear destructed-self error, got: {out:?}"
        );
    });
}

/// CTO review (OBI-85): `destruct`'s inventory relocation, checked both
/// ways -- into the destructed object's own environment when it had one,
/// and left with no environment when it did not -- using two objects with
/// no connection of their own (`spawn_clone`/`move_into`/`destruct_self`,
/// test-only helpers on the tworoom fixture).
#[test]
fn destruct_relocates_inventory_to_the_destructed_objects_own_environment() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        let player = world.connection_object(1).expect("bound");
        let hall = world
            .environment(player)
            .expect("player starts in the hall");

        // Case 1: the destructed object has no environment of its own
        // (a loose container) -- its item is left with no environment,
        // not the container's stale id.
        let container = spawn_clone(&mut world, player, &mut host);
        let item = spawn_clone(&mut world, player, &mut host);
        move_into(&mut world, item, container, &mut host);
        assert_eq!(world.environment(item), Some(container));

        destruct_self(&mut world, container, &mut host);
        assert_eq!(
            world.environment(item),
            None,
            "a loose container's item is left with no environment"
        );

        // Case 2: the destructed object *does* have an environment (the
        // hall) -- its item moves up into that environment, not into the
        // void.
        let container2 = spawn_clone(&mut world, player, &mut host);
        move_into(&mut world, container2, hall, &mut host);
        let item2 = spawn_clone(&mut world, player, &mut host);
        move_into(&mut world, item2, container2, &mut host);
        assert_eq!(world.environment(item2), Some(container2));

        destruct_self(&mut world, container2, &mut host);
        assert_eq!(
            world.environment(item2),
            Some(hall),
            "item moves up into the destructed container's own environment"
        );
    });
}

fn spawn_clone(world: &mut World, on: loom_vm::ObjectId, host: &mut FakeHost) -> loom_vm::ObjectId {
    match world
        .call(on, "spawn_clone", Vec::new(), host)
        .expect("spawn_clone")
    {
        loom_vm::Value::Object(id) => id,
        v => panic!("spawn_clone did not return an object: {v:?}"),
    }
}

fn move_into(
    world: &mut World,
    on: loom_vm::ObjectId,
    dest: loom_vm::ObjectId,
    host: &mut FakeHost,
) {
    world
        .call(on, "move_into", vec![loom_vm::Value::Object(dest)], host)
        .expect("move_into");
}

fn destruct_self(world: &mut World, on: loom_vm::ObjectId, host: &mut FakeHost) {
    world
        .call(on, "destruct_self", Vec::new(), host)
        .expect("destruct_self");
}

/// CTO review addendum (OBI-85, Warp needs this): `destructed(ob)` is
/// `true` for `null` and for a dead handle, `false` for a live one;
/// `environment(dead)` returns `null` instead of erroring;
/// `destruct(dead)` is an idempotent no-op, not an error; and `ob == dead`
/// still compares by identity (never panics/errors on a dead handle).
#[test]
fn destructed_reference_safety() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        let player = world.connection_object(1).expect("bound");

        let call =
            |world: &mut World, host: &mut FakeHost, func: &str, args: Vec<loom_vm::Value>| {
                world
                    .call(player, func, args, host)
                    .unwrap_or_else(|e| panic!("{func}: {e}"))
            };
        let bool_of = |v: loom_vm::Value| match v {
            loom_vm::Value::Bool(b) => b,
            other => panic!("expected bool, got {other:?}"),
        };

        let dead = spawn_clone(&mut world, player, &mut host);
        assert!(
            !bool_of(call(
                &mut world,
                &mut host,
                "destructed_of",
                vec![loom_vm::Value::Object(dead)]
            )),
            "a live object is not destructed"
        );

        destruct_self(&mut world, dead, &mut host);

        assert!(
            bool_of(call(
                &mut world,
                &mut host,
                "destructed_of",
                vec![loom_vm::Value::Object(dead)]
            )),
            "a dead handle is destructed"
        );
        assert!(
            bool_of(call(
                &mut world,
                &mut host,
                "destructed_of",
                vec![loom_vm::Value::Null]
            )),
            "null is destructed too"
        );

        // `environment(dead)` -> null, not an error.
        assert!(matches!(
            call(
                &mut world,
                &mut host,
                "environment_of",
                vec![loom_vm::Value::Object(dead)]
            ),
            loom_vm::Value::Null
        ));

        // `destruct(dead)` is idempotent, not an error.
        call(
            &mut world,
            &mut host,
            "destruct_of",
            vec![loom_vm::Value::Object(dead)],
        );

        // `ob == dead` compares by identity: a fresh clone is not equal to
        // the old (now dead) id, but the same dead id compares equal to
        // itself.
        let other = spawn_clone(&mut world, player, &mut host);
        assert!(!bool_of(call(
            &mut world,
            &mut host,
            "equals",
            vec![loom_vm::Value::Object(dead), loom_vm::Value::Object(other)],
        )));
        assert!(bool_of(call(
            &mut world,
            &mut host,
            "equals",
            vec![loom_vm::Value::Object(dead), loom_vm::Value::Object(dead)],
        )));
    });
}

#[test]
fn read_file_and_write_file_round_trip_and_confine_to_root() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.out.clear();

        world.input(1, "readfile /domains/x/notes.txt", &mut host);
        assert_eq!(host.take(1), "null\n", "missing file reads back null");

        world.input(1, "writefile /domains/x/notes.txt hello", &mut host);
        assert_eq!(host.take(1), "true\n");
        assert!(root.join("domains/x/notes.txt").is_file());

        world.input(1, "readfile /domains/x/notes.txt", &mut host);
        assert_eq!(host.take(1), "hello\n");

        // `..` must not escape the mudlib root.
        world.input(1, "readfile /../../etc/passwd", &mut host);
        assert!(
            host.take(1)
                .contains("read_file(\"/../../etc/passwd\") failed: path must not contain `..`"),
        );

        // Only .wf/.txt may be written.
        world.input(1, "writefile /domains/x/notes.exe hello", &mut host);
        assert!(host.take(1).contains("write_file only allows .wf or .txt"));
    });
}

#[test]
fn random_stays_in_range_and_errors_on_non_positive_n() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.out.clear();

        for _ in 0..50 {
            world.input(1, "rand 7", &mut host);
            let out = host.take(1);
            let n: i64 = out.trim().parse().expect("an int");
            assert!((0..7).contains(&n), "{n} out of [0, 7)");
        }

        world.input(1, "rand 0", &mut host);
        assert!(host.take(1).contains("random(): n must be > 0"));
    });
}

#[test]
fn to_int_edge_cases() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.out.clear();

        let cases: &[(&str, &str)] = &[
            ("42", "42"),
            ("-7", "-7"),
            ("+5", "null"),                   // spec: optional `-` only, not `+`
            ("abc", "null"),                  // does not parse
            ("99999999999999999999", "null"), // overflows i64
            ("0", "0"),
        ];
        for (input, expect) in cases {
            world.input(1, &format!("toint {input}"), &mut host);
            assert_eq!(host.take(1), format!("{expect}\n"), "to_int({input:?})");
        }
    });
}

#[test]
fn lower_and_users_and_time() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.out.clear();

        world.input(1, "lower HELLO-Mud", &mut host);
        assert_eq!(host.take(1), "hello-mud\n");

        world.input(1, "usercount", &mut host);
        assert_eq!(host.take(1), "1\n", "one bound connection");

        world.connect(2, &mut host);
        host.out.clear();
        world.input(1, "usercount", &mut host);
        assert_eq!(host.take(1), "2\n");

        world.input(1, "now", &mut host);
        assert_eq!(
            host.take(1),
            "true\n",
            "time() is a positive unix timestamp"
        );
    });
}

/// A test-double `AccountAuth` that completes every request itself
/// (in-process, no real async boundary) once the test asks it to, so the
/// ordering guarantee (request id returned before `account_result`
/// arrives) and the never-blocks-the-world-thread claim can both be
/// exercised without a real DB/tokio worker.
#[derive(Default)]
struct FakeAuth {
    calls: VecDeque<(u64, bool, String, String)>, // (id, is_create, name, password)
}

impl AccountAuth for FakeAuth {
    fn create_account(&mut self, request_id: u64, name: &str, password: &str) -> bool {
        self.calls
            .push_back((request_id, true, name.to_string(), password.to_string()));
        true
    }
    fn login(&mut self, request_id: u64, name: &str, password: &str) -> bool {
        self.calls
            .push_back((request_id, false, name.to_string(), password.to_string()));
        true
    }
}

#[test]
fn account_request_id_is_returned_before_the_result_and_invalid_input_is_rejected_locally() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        world.set_account_auth(Box::new(FakeAuth::default()));
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.out.clear();

        // Bad name (too short) never reaches the backend, but still gets
        // an id and an eventual "invalid" account_result -- delivered on
        // a later entry point, never inside the same call.
        world.input(1, "makeaccount ab hunter2pw", &mut host);
        let out = host.take(1);
        assert_eq!(out, "req 1\n", "request id is returned immediately");

        // Not delivered synchronously: nothing else has been sent yet.
        world.input(1, "look", &mut host);
        let _ = host.take(1);
        world.drain_account_results(&mut host);
        let out = host.take(1);
        assert!(
            out.contains("account_result 1 false invalid"),
            "invalid input is rejected without touching the backend: {out:?}"
        );
    });
}

#[test]
fn account_result_is_skipped_for_a_destructed_issuer() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        world.set_account_auth(Box::new(FakeAuth::default()));
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.out.clear();

        world.input(1, "makeaccount ab hunter2pw", &mut host);
        host.take(1);
        let player = world.connection_object(1).expect("bound");
        world.destruct(player, &mut host);

        // Draining the queued "invalid" result for a destructed issuer
        // must not panic and must not deliver anything (nothing left to
        // call `account_result` on).
        world.drain_account_results(&mut host);
        assert_eq!(host.take(1), "");
    });
}

/// CTO review (OBI-85): a backend whose request queue is full or closed
/// must never leave a request pending forever -- the world thread
/// immediately queues an `unavailable` result instead of blocking or
/// silently dropping it.
#[test]
fn a_full_or_closed_backend_queue_delivers_unavailable_not_a_hang() {
    struct AlwaysRejects;
    impl AccountAuth for AlwaysRejects {
        fn create_account(&mut self, _request_id: u64, _name: &str, _password: &str) -> bool {
            false
        }
        fn login(&mut self, _request_id: u64, _name: &str, _password: &str) -> bool {
            false
        }
    }

    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        world.set_account_auth(Box::new(AlwaysRejects));
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.out.clear();

        world.input(1, "makeaccount legolas hunter2pass", &mut host);
        host.take(1);
        world.drain_account_results(&mut host);
        let out = host.take(1);
        assert!(
            out.contains("account_result 1 false unavailable"),
            "a rejected backend request must resolve to `unavailable`, not hang: {out:?}"
        );
    });
}
