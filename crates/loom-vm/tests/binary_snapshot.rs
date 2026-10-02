// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Binary world snapshots (design spec §8.1 model 2, OBI-173): round-trip
//! correctness (`binary_snapshot_round_trip_preserves_object_state`) and
//! the E1.2-scale (10k live `/std/item` clones) benchmark the issue's
//! acceptance criteria ask for (`ignore`d -- see that test's own doc
//! comment).

mod common;

use std::time::Instant;

use common::{FakeHost, fixture};
use loom_vm::{Limits, Value, World};

/// Round-trip: snapshot a small, structurally rich world (a map var, an
/// object var round trip through `env`/`inventory`, a live connection
/// binding), load it into a fresh [`World`] (standing in for "a fresh
/// driver process" -- the standby side of copyover), and check every
/// piece of state the original had is identical in the loaded copy.
#[test]
fn binary_snapshot_round_trip_preserves_object_state() {
    let root = fixture("tworoom");
    let mut world = World::boot(&root).expect("boot");
    let mut host = FakeHost::default();

    world.connect(1, &mut host);
    host.take(1);
    let player = world.connection_object(1).expect("bound");
    let hall = world.environment(player).expect("player placed in hall");

    world.input(1, "name bob", &mut host);
    host.take(1);
    world.input(1, "go north", &mut host);
    host.take(1);
    world.input(1, "go south", &mut host);
    host.take(1);

    // Sanity on the pre-snapshot state this test is actually proving
    // round-trips, not just asserting on the loaded copy in isolation.
    assert!(
        world
            .var(player, "name")
            .unwrap()
            .equals(&Value::str("bob"))
    );
    assert!(matches!(world.var(player, "moves"), Some(Value::Int(2))));
    assert_eq!(world.object_name(hall).unwrap(), "/domains/start/hall");
    assert!(world.inventory(hall).contains(&player));
    let original_exits = world.var(hall, "exits").expect("hall has exits");

    // --- capture (the only synchronous "pause") + encode ---------------
    let pause_start = Instant::now();
    let job = world.begin_snapshot().expect("capture");
    let pause = pause_start.elapsed();
    let object_count = job.object_count();

    let total_start = Instant::now();
    let bytes = job.encode_all().expect("encode");
    let total = total_start.elapsed();
    eprintln!(
        "OBI-173 binary snapshot (tworoom, {object_count} objects): \
         pause = {pause:?}, total = {total:?}, {} bytes",
        bytes.len()
    );

    // --- load into a fresh World (the standby side of copyover) --------
    let loaded = World::load_snapshot(&root, Limits::default(), &bytes).expect("load_snapshot");

    assert_eq!(loaded.object_count(), world.object_count());
    assert_eq!(loaded.object_name(player), world.object_name(player));
    assert_eq!(loaded.object_name(hall), world.object_name(hall));
    assert_eq!(loaded.environment(player), Some(hall));
    assert!(loaded.inventory(hall).contains(&player));
    assert!(
        loaded
            .var(player, "name")
            .unwrap()
            .equals(&Value::str("bob"))
    );
    assert!(matches!(loaded.var(player, "moves"), Some(Value::Int(2))));
    assert!(matches!(loaded.var(player, "beats"), Some(Value::Int(0))));
    assert!(
        loaded
            .var(hall, "exits")
            .expect("restored exits")
            .equals(&original_exits)
    );
    assert_eq!(loaded.owner_uid(player), world.owner_uid(player));
    assert_eq!(loaded.euid_name(player), world.euid_name(player));
    assert_eq!(
        loaded.object_mem_bytes(player),
        world.object_mem_bytes(player)
    );
    assert_eq!(
        loaded.program_version("/std/player"),
        world.program_version("/std/player")
    );
    // The live connection binding itself round-trips too (copyover's
    // whole point: the standby process can re-attach the same socket to
    // the same object without it looking like a fresh login).
    assert_eq!(loaded.connection_object(1), Some(player));
}

/// A snapshot whose bytes have been tampered with fails cleanly (spec
/// §8.1 "a load from an incompatible ABI fails cleanly") -- never panics.
#[test]
fn bad_magic_and_bad_abi_are_clean_errors_not_panics() {
    let root = fixture("tworoom");
    let world = World::boot(&root).expect("boot");
    let bytes = world
        .begin_snapshot()
        .expect("capture")
        .encode_all()
        .expect("encode");

    let mut garbage = bytes.clone();
    garbage[0] = garbage[0].wrapping_add(1);
    let err = match World::load_snapshot(&root, Limits::default(), &garbage) {
        Err(e) => e,
        Ok(_) => panic!("bad magic must not load"),
    };
    assert!(matches!(err, loom_vm::SnapshotError::BadMagic), "{err:?}");

    let mut bad_abi = bytes.clone();
    // Byte 8..10 is the format version, 10..12 is the ABI version (little
    // endian) -- see `loom_vm::snapshot`'s header layout.
    bad_abi[10] = 0xFF;
    bad_abi[11] = 0xFF;
    let err = match World::load_snapshot(&root, Limits::default(), &bad_abi) {
        Err(e) => e,
        Ok(_) => panic!("bad abi must not load"),
    };
    assert!(
        matches!(err, loom_vm::SnapshotError::UnsupportedAbi { .. }),
        "{err:?}"
    );

    let truncated = &bytes[..bytes.len() / 2];
    let err = match World::load_snapshot(&root, Limits::default(), truncated) {
        Err(e) => e,
        Ok(_) => panic!("truncated bytes must not load"),
    };
    assert!(
        matches!(err, loom_vm::SnapshotError::Truncated(_)),
        "{err:?}"
    );
}

const N_ITEMS: usize = 10_000;

/// OBI-173 acceptance: benchmark on the E1.2 world (10k live `/std/item`
/// clones) -- pause per tick (the capture step) and total snapshot time
/// (capture + full encode), both reported (not just thresholded), plus a
/// round trip through a fresh `World` proving every clone's state
/// (`count`) survived identically.
///
/// `#[ignore]`d per the same convention as `exit_10k_item_upgrade.rs` (a
/// multi-second 10k-object run, meant for a nightly job): run explicitly
/// with `cargo test -p loom-vm --test binary_snapshot -- --ignored --nocapture`.
#[test]
#[ignore = "10k clones; run in the nightly E1.2 job, not every cargo test"]
fn ten_thousand_item_clones_snapshot_and_reload_with_identical_state() {
    let root = fixture("exit_10k_item");
    let mut world = World::boot(&root).expect("boot");
    let mut host = FakeHost::default();

    const OPERATOR: u64 = 1;
    world.connect(OPERATOR, &mut host);
    host.take(OPERATOR);

    let mut items = Vec::with_capacity(N_ITEMS);
    for i in 0..N_ITEMS {
        world.input(OPERATOR, "clone_item", &mut host);
        let out = host.take(OPERATOR);
        let name = out
            .strip_prefix("cloned ")
            .and_then(|s| s.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("unexpected clone_item output: {out:?}"))
            .to_string();
        let id = world.find_object(&name).expect("cloned item");
        world
            .call(id, "set_count", vec![Value::Int(i as i64)], &mut host)
            .expect("set_count");
        items.push(id);
    }
    assert!(world.object_count() >= N_ITEMS);

    let pause_start = Instant::now();
    let job = world.begin_snapshot().expect("capture");
    let pause = pause_start.elapsed();
    let object_count = job.object_count();

    // One more tick right after capture, timed, to show the capture
    // really did not hold up the world thread: this is the "pause per
    // tick" the acceptance criteria ask to record, isolated from the
    // (much larger) encode that follows.
    let post_capture_tick_start = Instant::now();
    world.tick(&mut host);
    let post_capture_tick = post_capture_tick_start.elapsed();

    let total_start = Instant::now();
    let bytes = job.encode_all().expect("encode");
    let encode_only = total_start.elapsed();
    let total = pause + encode_only;

    eprintln!(
        "OBI-173 binary snapshot (exit_10k_item, {object_count} objects): \
         capture pause = {pause:?}, tick right after capture = {post_capture_tick:?}, \
         encode = {encode_only:?}, total = {total:?}, {} bytes",
        bytes.len()
    );
    assert!(
        pause < std::time::Duration::from_millis(200),
        "capture pause blew up: {pause:?}"
    );

    let loaded = World::load_snapshot(&root, Limits::default(), &bytes).expect("load_snapshot");
    assert_eq!(loaded.object_count(), world.object_count());
    for (i, &id) in items.iter().enumerate() {
        assert!(
            matches!(loaded.var(id, "count"), Some(Value::Int(n)) if n == i as i64),
            "item {i} count not preserved by the snapshot round trip: {:?}",
            loaded.var(id, "count")
        );
        assert_eq!(loaded.object_name(id), world.object_name(id));
    }
}
