// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-348 (spec §8.1): `save_object`'s durable half runs on the world's
//! durability worker, not on the thread that serves every player.
//!
//! These tests drive real [`World`] entry points (`connect` / `input` / `tick`
//! / `disconnect` / `begin_snapshot`) against the `durability` fixture -- the
//! `persist` fixture's player with an `autosave()` that calls `save_object`,
//! like a real `/std/player` -- and use `SaveQueueConfig::commit_delay` to
//! stand in for a slow disk: the worker sleeps *before* its `fsync`, so "the
//! world thread did not wait for the disk" is a wall-clock fact rather than a
//! hopeful `sleep`. `commit_delay` is test-only (`Default` is `None`);
//! production never sleeps.
//!
//! What this file deliberately does *not* do: reproduce 150 simultaneous
//! logouts against a real save root. That is the shape OBI-344 measured in CI
//! (`ad489db`: 304-562 ms world-loop iterations,
//! `loom_world_loop_stalls_total{kind="disconnect"}`), and the board directive
//! on OBI-306/307 rules out generating that load from here. Before/after
//! numbers for this change belong on OBI-344's next run.

mod common;

use common::{FakeHost, fixture};
use loom_vm::World;
use loom_vm::save_queue::{SaveDurability, SaveQueueConfig};
use std::path::Path;
use std::time::{Duration, Instant};

/// Slow enough that a 100 ms assertion margin cannot be met by accident,
/// short enough to keep the whole file well under a second.
const SLOW_DISK: Duration = Duration::from_millis(200);

fn slow_world(tag: &str, durability: SaveDurability) -> (World, FakeHost, std::path::PathBuf) {
    let root = fixture("durability");
    let save_root = common::scratch(tag);
    let mut world = World::boot(&root).expect("boot");
    world.set_save_root(save_root.clone());
    world.set_save_queue_config(SaveQueueConfig {
        commit_delay: Some(SLOW_DISK),
        ..SaveQueueConfig::default()
    });
    world.set_save_durability(durability);
    (world, FakeHost::default(), save_root)
}

/// The save file's §7.3 envelope, checked as text: it exists and carries the
/// program identity it was written from.
fn assert_save_file(path: &Path) {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{} should be on disk: {e}", path.display()));
    assert!(
        text.contains("\"program\"") && text.contains("/std/player"),
        "not a §7.3 save envelope: {text}"
    );
}

/// The headline: a save -- and with it `World::disconnect`'s `autosave()`,
/// which is the path OBI-344 measured at 304-562 ms -- returns while the disk
/// is still busy, and the queue reports hand-off rather than inline work.
#[test]
fn a_save_returns_before_the_disk_has_finished() {
    let (mut world, mut host, save_root) = slow_world("durability-async", SaveDurability::Deferred);
    world.connect(1, &mut host);
    host.take(1);
    world.input(1, "sethp 61", &mut host);
    host.take(1);

    let at = Instant::now();
    world.input(1, "savefile /whoever", &mut host);
    let elapsed = at.elapsed();

    assert_eq!(host.take(1), "true\n", "the save must be accepted");
    assert!(
        elapsed < SLOW_DISK / 2,
        "the world thread spent {elapsed:?} on a save whose disk work takes \
         {SLOW_DISK:?}; deferred durability is supposed to hand that off"
    );
    let file = save_root.join("whoever.o");
    assert!(!file.exists(), "the write has not reached the disk yet");

    let stats = world.save_queue_stats();
    assert_eq!(stats.queued, 1, "exactly one save handed to the worker");
    assert_eq!(
        stats.inline_commits, 0,
        "no durable write on the world thread"
    );
    assert_eq!(stats.pending, 1);

    // And it is not lost: the barrier lands it and reports it durable.
    assert_eq!(world.flush_pending_saves(), 1);
    assert_save_file(&file);
    let stats = world.save_queue_stats();
    assert_eq!(stats.pending, 0);
    assert_eq!(stats.committed, 1);
    assert_eq!(stats.failed, 0);
}

/// `World::disconnect` is the path the E1.1 stall counter watches: it must
/// still *make* the autosave, and still not wait for it.
#[test]
fn disconnect_autosaves_without_paying_for_the_disk() {
    let (mut world, mut host, save_root) =
        slow_world("durability-disconnect", SaveDurability::Deferred);
    world.connect(1, &mut host);
    host.take(1);
    world.input(1, "sethp 61", &mut host);
    host.take(1);

    let at = Instant::now();
    world.disconnect(1, &mut host);
    let elapsed = at.elapsed();

    assert!(
        elapsed < SLOW_DISK / 2,
        "`disconnect` took {elapsed:?} against a {SLOW_DISK:?} disk -- its \
         autosave's durable write belongs to the queue, not this thread"
    );
    let stats = world.save_queue_stats();
    assert_eq!(
        stats.queued + stats.inline_commits,
        1,
        "disconnect's autosave must still produce exactly one save"
    );
    assert_eq!(stats.inline_commits, 0, "and must not do it inline");

    // Nothing was lost by the disconnect: the barrier (which `World::drop`
    // also runs) makes it durable.
    assert_eq!(world.flush_pending_saves(), 1);
    assert_save_file(&save_root.join("whoever.o"));
}

/// Read-your-writes, without the caller opting in: `restore_object` waits for
/// *its own path*, so it can never silently read the previous file. The save
/// under test is queued behind another object's save, and `hp` is changed
/// again in between -- if the read went to the stale disk state it would see
/// `99` (no restore at all), not the `7` that was only ever in the queue.
#[test]
fn restore_waits_for_its_own_path() {
    let (mut world, mut host, save_root) =
        slow_world("durability-rewrites", SaveDurability::Deferred);
    world.connect(1, &mut host);
    host.take(1);

    world.input(1, "sethp 7", &mut host);
    host.take(1);
    world.input(1, "savefile /whoever", &mut host);
    assert_eq!(host.take(1), "true\n");
    world.input(1, "sethp 99", &mut host);
    host.take(1);
    world.input(1, "savefile /other", &mut host);
    assert_eq!(host.take(1), "true\n");
    assert_eq!(world.save_queue_stats().pending, 2, "both still queued");
    let file = save_root.join("whoever.o");
    assert!(!file.exists(), "neither has landed yet");

    world.input(1, "restorefile /whoever", &mut host);
    assert_eq!(host.take(1), "true\n", "the restore must succeed");
    world.input(1, "gethp", &mut host);
    assert_eq!(
        host.take(1),
        "7\n",
        "read-your-writes: the restore must see the save that was still in flight"
    );
    assert_save_file(&file);
    // The worker is FIFO, so waiting for `/whoever` landed everything before
    // it too; `/other` was behind it and is landed by the same barrier the
    // world does not have to think about.
    world.flush_pending_saves();
    assert_save_file(&save_root.join("other.o"));
}

/// `World::tick` is the reaper. Without it the queue would saturate and every
/// later save would fall back to an inline `fsync` on the world thread -- so
/// the reap itself must be bookkeeping only, and must actually run.
///
/// The worker is waited for by *polling*, never by a guessed sleep. The first
/// version of this test slept `SLOW_DISK * 2` and then asserted the reap had
/// happened; that failed on CI (`save_durability.rs:203`, `pending` still 1)
/// because 400 ms is not a bound on "200 ms `commit_delay` + write + fsync +
/// the OS scheduling the worker at all" on a contended runner -- precisely the
/// hard-coded-budget-loses-to-contention class OBI-329 tracks. `pending` only
/// moves when the world looks, so the honest shape is: look until it moved,
/// and price the tick that did it.
#[test]
fn ticking_reaps_committed_saves_without_doing_disk_work() {
    let (mut world, mut host, save_root) = slow_world("durability-tick", SaveDurability::Deferred);
    world.connect(1, &mut host);
    host.take(1);
    world.input(1, "savefile /whoever", &mut host);
    host.take(1);

    // The worker is asleep for the whole of `commit_delay` before it even
    // touches the file, so a tick issued while that save is outstanding must
    // return without waiting for it. Bounded at half the disk's own delay, the
    // budget every other test in this file uses.
    let at = Instant::now();
    world.tick(&mut host);
    let first_tick = at.elapsed();
    assert!(
        first_tick < SLOW_DISK / 2,
        "a tick issued while a save is in flight must not wait for the worker: \
         {first_tick:?} against a {SLOW_DISK:?} disk"
    );

    // Poll until a tick finds something to reap. `pending` only moves when the
    // world looks, so this waits for the fact rather than guessing how long the
    // worker needs; the loop is bounded so a queue that never reports fails
    // loudly instead of hanging the suite.
    //
    // Timing is asserted on exactly two ticks -- the first one and the one that
    // reaped -- which is the same number of wall-clock budgets this test always
    // had. Asserting on every poll tick would multiply the file's exposure to
    // unrelated runner stalls (OBI-344's tail), and it proves nothing the
    // reaping tick does not already prove: `poll` is a non-blocking `try_recv`.
    let started = Instant::now();
    let mut slowest_poll_tick = Duration::ZERO;
    let reaping_tick = loop {
        let at = Instant::now();
        world.tick(&mut host);
        let elapsed = at.elapsed();
        slowest_poll_tick = slowest_poll_tick.max(elapsed);
        if world.save_queue_stats().pending == 0 {
            break elapsed;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the worker never reported the queued save (stats: {:?}, {} landed \
             on disk after {:?}; slowest poll tick {slowest_poll_tick:?})",
            world.save_queue_stats(),
            if save_root.join("whoever.o").exists() {
                "it"
            } else {
                "nothing has"
            },
            started.elapsed()
        );
        std::thread::sleep(Duration::from_millis(5));
    };

    // The tick that reaped did bookkeeping only: a quarter of the disk's own
    // delay, so the bound stays meaningful if `SLOW_DISK` is retuned.
    assert!(
        reaping_tick < SLOW_DISK / 4,
        "reaping a finished outcome must be bookkeeping, not disk work: {reaping_tick:?}"
    );
    let stats = world.save_queue_stats();
    assert_eq!(stats.pending, 0);
    assert_eq!(stats.committed, 1, "the save is billed exactly once");
    assert_eq!(stats.inline_commits, 0, "and never on the world thread");
}

/// A snapshot is the world's own idea of "what is saved", and copyover's boot
/// side reads save files back off the disk -- so `begin_snapshot` is a
/// durability barrier, not a cheap read.
#[test]
fn begin_snapshot_is_a_durability_barrier() {
    let (mut world, mut host, save_root) =
        slow_world("durability-snapshot", SaveDurability::Deferred);
    world.connect(1, &mut host);
    host.take(1);
    world.input(1, "savefile /whoever", &mut host);
    host.take(1);
    assert_eq!(world.save_queue_stats().pending, 1);
    assert!(!save_root.join("whoever.o").exists());

    let _job = world.begin_snapshot().expect("capture");
    assert_eq!(world.save_queue_stats().pending, 0, "the snapshot flushed");
    assert_save_file(&save_root.join("whoever.o"));
}

/// `SaveDurability::Sync` means exactly what `save_object` meant before
/// OBI-348: this thread does the durable write, so `true` means durable. It is
/// the escape hatch for an embedder that wants the old contract, and the
/// fallback shape the benchmark measures against.
#[test]
fn sync_mode_restores_the_pre_348_meaning() {
    let (mut world, mut host, save_root) = slow_world("durability-sync", SaveDurability::Sync);
    world.connect(1, &mut host);
    host.take(1);

    let at = Instant::now();
    world.input(1, "savefile /whoever", &mut host);
    let elapsed = at.elapsed();

    assert_eq!(host.take(1), "true\n");
    assert!(
        elapsed >= SLOW_DISK,
        "sync mode is supposed to pay the disk cost inline, got {elapsed:?}"
    );
    assert_save_file(&save_root.join("whoever.o"));
    let stats = world.save_queue_stats();
    assert_eq!(stats.inline_commits, 1);
    assert_eq!(stats.queued, 0, "the worker is never even started");
    assert_eq!(stats.pending, 0);
}

/// A durable write that fails on the worker is a reported error -- not a lost
/// character, not a panic, and not a wedged queue. It lands in the world's
/// error inbox against the program that asked for the save (spec §8.3).
#[test]
fn a_deferred_write_failure_reaches_the_error_inbox() {
    let root = fixture("durability");
    let mut world = World::boot(&root).expect("boot");
    // The save root is a *regular file*: nothing under it can be created, so
    // the durable write fails -- on the worker, after acceptance.
    let blocked = common::scratch("durability-blocked");
    std::fs::remove_dir_all(&blocked).expect("drop the empty scratch dir");
    std::fs::write(&blocked, "not a directory").expect("make it a file");
    world.set_save_root(blocked);
    world.set_save_queue_config(SaveQueueConfig {
        commit_delay: Some(SLOW_DISK),
        ..SaveQueueConfig::default()
    });
    let mut host = FakeHost::default();

    world.connect(1, &mut host);
    host.take(1);
    world.input(1, "savefile /whoever", &mut host);
    assert_eq!(
        host.take(1),
        "true\n",
        "acceptance is not where this fails -- the write does, later"
    );

    assert_eq!(world.flush_pending_saves(), 1);
    assert_eq!(world.save_queue_stats().failed, 1);
    assert_eq!(
        world.save_queue_stats().committed,
        0,
        "a failed write must not also be counted as durable"
    );
    let reports = world.errors_snapshot(None);
    assert!(
        reports.iter().any(|r| {
            r.function == "save_object"
                && r.program.contains("/std/player")
                && !r.message.is_empty()
        }),
        "expected the deferred save failure in the error inbox, got {reports:?}"
    );

    // The queue still works: a second save is accepted and fails the same way.
    world.input(1, "savefile /other", &mut host);
    assert_eq!(host.take(1), "true\n");
    world.flush_pending_saves();
    assert_eq!(world.save_queue_stats().failed, 2);
    assert_eq!(world.save_queue_stats().pending, 0);
}
