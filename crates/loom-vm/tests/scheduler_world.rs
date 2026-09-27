// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `call_out`/heartbeat scheduler on a live `World` (OBI-33): ordering,
//! cancellation, per-object metering and removal on destruction.

mod common;

use common::{FakeHost, fixture, on_world_thread};
use loom_vm::World;

#[test]
fn call_out_fires_after_the_scheduled_number_of_ticks_not_before() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.out.clear();

        world.input(1, "sched", &mut host); // call_out("pong", 2)
        assert!(host.take(1).starts_with("scheduled "));
        assert_eq!(world.pending_call_outs(), 1);

        world.tick(&mut host); // tick 1: not due yet (delay 2)
        assert_eq!(host.take(1), "");
        assert_eq!(world.pending_call_outs(), 1);

        world.tick(&mut host); // tick 2: due
        assert_eq!(host.take(1), "pong 0\n");
        assert_eq!(world.pending_call_outs(), 0);
    });
}

#[test]
fn remove_call_out_cancels_before_it_fires() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.out.clear();

        world.input(1, "sched", &mut host);
        host.take(1);
        world.input(1, "cancel", &mut host);
        assert_eq!(host.take(1), "cancelled true\n");
        assert_eq!(world.pending_call_outs(), 0);

        world.tick(&mut host);
        world.tick(&mut host);
        assert_eq!(host.take(1), ""); // pong never runs
    });
}

#[test]
fn call_outs_due_the_same_tick_run_in_scheduling_order_across_objects() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        world.connect(2, &mut host);
        host.out.clear();

        // Both scheduled for the same due tick (delay 2); object 1's
        // call_out was scheduled first, so it must run first regardless
        // of object identity (fairness, not insertion by object order).
        world.input(2, "sched", &mut host);
        host.take(2);
        world.input(1, "sched", &mut host);
        host.take(1);

        world.tick(&mut host);
        assert_eq!(host.take(1), "");
        assert_eq!(host.take(2), "");
        world.tick(&mut host);
        assert_eq!(host.take(2), "pong 0\n", "scheduled first, runs first");
        assert_eq!(host.take(1), "pong 1\n");
    });
}

#[test]
fn heart_beat_runs_every_tick_for_every_subscribed_object() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.out.clear();

        world.input(1, "beats", &mut host);
        assert_eq!(host.take(1), "0\n");

        world.input(1, "hbon", &mut host);
        host.take(1);
        world.tick(&mut host);
        world.tick(&mut host);
        world.tick(&mut host);
        world.input(1, "beats", &mut host);
        assert_eq!(host.take(1), "3\n");

        world.input(1, "hboff", &mut host);
        host.take(1);
        world.tick(&mut host);
        world.input(1, "beats", &mut host);
        assert_eq!(host.take(1), "3\n", "stopped counting after hboff");
    });
}

#[test]
fn destructing_an_object_drops_its_pending_call_outs_and_heartbeat() {
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

        let player = world.connection_object(1).expect("bound");
        world.destruct(player);
        assert_eq!(world.pending_call_outs(), 0);

        // Ticking after destruction must not panic or resurrect the call.
        world.tick(&mut host);
        world.tick(&mut host);
        assert_eq!(host.take(1), "");
    });
}

#[test]
fn call_out_is_a_gated_p1_efun_and_gets_audited() {
    on_world_thread(|| {
        let root = fixture("tworoom");
        let mut world = World::boot(&root).expect("boot");
        let mut host = FakeHost::default();
        world.connect(1, &mut host);
        host.out.clear();
        assert!(world.audit_log().is_empty());

        world.input(1, "sched", &mut host);
        host.take(1);

        let log = world.audit_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].efun, "call_out");
        assert_eq!(log[0].privilege, loom_vm::efuns::Privilege::P1);
        assert!(log[0].allowed);
    });
}
