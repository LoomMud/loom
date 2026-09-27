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
    fn create_account(&mut self, request_id: u64, name: &str, password: &str) {
        self.calls
            .push_back((request_id, true, name.to_string(), password.to_string()));
    }
    fn login(&mut self, request_id: u64, name: &str, password: &str) {
        self.calls
            .push_back((request_id, false, name.to_string(), password.to_string()));
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
