// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Copyover, world/VM-side half (design §7.5 steps 1 and 3, OBI-221, a
//! child of OBI-184): the old process's full snapshot (OBI-173's binary
//! format, which already carries the connection table --
//! `registry.conns`/`bind_seq`) plus [`World::reconnect`]/
//! [`World::reconnect_all`], the new-process hook that lets mudlib code
//! re-bind to its connection once the driver has re-adopted the
//! handed-off socket.
//!
//! This does *not* cover `loom-supervise`'s `SCM_RIGHTS` fd-passing or
//! `loom-net`'s session table (Legolas's/OBI-184's side, and a later
//! wiring slice) -- it proves the piece this issue actually owns: boot a
//! world, connect a session, snapshot it, load a fresh world from that
//! snapshot, re-attach a stub session under the *same* conn id the
//! snapshot recorded, and observe `reconnect()` fire on the previously
//! connected object with that session visibly rebound (it can `send()`
//! through the new connection).

mod common;

use common::{FakeHost, fixture};
use loom_vm::{Limits, Value, World};

/// The full copyover round trip the issue's acceptance criteria ask for:
/// boot -> connect -> snapshot -> load into a fresh `World` (standing in
/// for the new process) -> re-attach a stub session under the recorded
/// conn id -> `reconnect_all()` -> the object's `reconnect()` fired
/// exactly once, through the newly-attached session.
#[test]
fn snapshot_round_trip_then_reconnect_fires_on_the_reattached_session() {
    let root = fixture("tworoom");
    let mut world = World::boot(&root).expect("boot");
    let mut old_host = FakeHost::default();

    const CONN: u64 = 7;
    world.connect(CONN, &mut old_host);
    old_host.take(CONN);
    world.input(CONN, "name bob", &mut old_host);
    old_host.take(CONN);
    let player = world.connection_object(CONN).expect("bound");
    assert!(matches!(
        world.var(player, "reconnect_count"),
        Some(Value::Int(0))
    ));

    // --- old process side: stop taking new input (implicit -- this test
    // just never calls `world.input`/`world.connect` again on `world`),
    // let in-flight execution finish (already true above), snapshot. ---
    let bytes = world
        .begin_snapshot()
        .expect("capture")
        .encode_all()
        .expect("encode");

    // --- new process side: load the snapshot into a fresh World (a new
    // process would do this with an empty object table) ---------------
    let mut new_world =
        World::load_snapshot(&root, Limits::default(), &bytes).expect("load_snapshot");
    assert_eq!(new_world.connection_object(CONN), Some(player));

    // The supervisor's fd-passing (`loom-supervise::fdpass`, OBI-184)
    // hands the new process raw, already-connected fds in the exact
    // order `World::live_connections()` lists them in; the new process's
    // job (not this test's, which stubs the socket directly with a
    // second `FakeHost`) is turning each one into a live `loom-net`
    // session keyed by that same conn id before calling `reconnect_all`.
    let live = new_world.live_connections();
    assert_eq!(live, vec![CONN]);

    let mut new_host = FakeHost::default();
    new_world.reconnect_all(&mut new_host);

    assert!(
        matches!(
            new_world.var(player, "reconnect_count"),
            Some(Value::Int(1))
        ),
        "reconnect() must fire exactly once on the reattached object"
    );
    assert_eq!(new_host.take(CONN), "reconnected\n");

    // The old world (still running, hypothetically up until the real
    // process exits after handing off its fds) never saw its own
    // `reconnect_count` bumped -- only the loaded copy did.
    assert!(matches!(
        world.var(player, "reconnect_count"),
        Some(Value::Int(0))
    ));
}

/// `reconnect_all` is a no-op (not a panic, not an error) against a
/// snapshot that bound no connections at all -- a copyover with zero
/// players online must still load and "reconnect" cleanly.
#[test]
fn reconnect_all_on_a_snapshot_with_no_connections_is_a_no_op() {
    let root = fixture("tworoom");
    let world = World::boot(&root).expect("boot");
    let bytes = world
        .begin_snapshot()
        .expect("capture")
        .encode_all()
        .expect("encode");

    let mut new_world =
        World::load_snapshot(&root, Limits::default(), &bytes).expect("load_snapshot");
    assert!(new_world.live_connections().is_empty());
    let mut host = FakeHost::default();
    new_world.reconnect_all(&mut host);
    assert!(host.out.is_empty());
}

/// Calling `reconnect` on a conn id the snapshot never bound is a no-op,
/// not a panic -- the copyover driver is only expected to drive this off
/// `live_connections()`, but a stray/duplicate call must stay harmless.
#[test]
fn reconnect_on_an_unbound_conn_id_is_a_no_op() {
    let root = fixture("tworoom");
    let world = World::boot(&root).expect("boot");
    let bytes = world
        .begin_snapshot()
        .expect("capture")
        .encode_all()
        .expect("encode");
    let mut new_world =
        World::load_snapshot(&root, Limits::default(), &bytes).expect("load_snapshot");
    let mut host = FakeHost::default();
    new_world.reconnect(999, &mut host);
    assert!(host.out.is_empty());
}

/// Two connected players, reconnected via `reconnect_all` in
/// `live_connections()` (ascending conn id) order -- both get their
/// hook, each through its own reattached session, not cross-wired.
#[test]
fn reconnect_all_covers_every_restored_connection_independently() {
    let root = fixture("tworoom");
    let mut world = World::boot(&root).expect("boot");
    let mut host = FakeHost::default();

    world.connect(2, &mut host);
    host.take(2);
    world.connect(1, &mut host);
    host.take(1);
    let p2 = world.connection_object(2).expect("bound 2");
    let p1 = world.connection_object(1).expect("bound 1");
    assert_ne!(p1, p2);

    let bytes = world
        .begin_snapshot()
        .expect("capture")
        .encode_all()
        .expect("encode");
    let mut new_world =
        World::load_snapshot(&root, Limits::default(), &bytes).expect("load_snapshot");
    assert_eq!(new_world.live_connections(), vec![1, 2]);

    let mut new_host = FakeHost::default();
    new_world.reconnect_all(&mut new_host);

    assert_eq!(new_host.take(1), "reconnected\n");
    assert_eq!(new_host.take(2), "reconnected\n");
    let np1 = new_world.connection_object(1).expect("bound 1");
    let np2 = new_world.connection_object(2).expect("bound 2");
    assert!(matches!(
        new_world.var(np1, "reconnect_count"),
        Some(Value::Int(1))
    ));
    assert!(matches!(
        new_world.var(np2, "reconnect_count"),
        Some(Value::Int(1))
    ));
}
