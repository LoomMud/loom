// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-348: measure what moving `save_object`'s durable half off the world
//! thread buys, and what the remaining per-save syscalls still cost.
//!
//! ```text
//! cargo run --release -p loom-vm --example save_durability_bench [saves]
//! ```
//!
//! Deliberately **not** part of the `bench-gate` comparison: that gate diffs
//! `vm_bench` rows against the base commit, and teaching it a new binary would
//! make it compare something it does not know. Numbers from here go in the PR
//! and on OBI-344.
//!
//! Three arms, all sequential and single-threaded -- no synthetic contention,
//! per the board directive on OBI-306/307:
//!
//! 1. **logout loop** -- `World::connect` + `World::disconnect` (whose
//!    `autosave()` calls `save_object`) N times, once per durability mode, and
//!    again with `commit_delay` standing in for a slow disk. Times only the
//!    *world-thread* half of a logout, which is the quantity
//!    `loom_world_loop_stalls_total{kind="disconnect"}` watches (OBI-344
//!    measured 304-562 ms of it per logout in CI at 150 sessions).
//! 2. **`write_file_atomic`** -- the durable sequence itself (write + `fsync`
//!    content + `rename` + `fsync` parent dir), N sequential calls through the
//!    same entry point the worker uses. This is what the worker now absorbs.
//! 3. **syscall split** -- `sync_all` on a file vs on a directory, N each: the
//!    data for the follow-up question of whether the parent-dir `fsync` (one
//!    per save today, identical for every save in a batch) is worth coalescing
//!    to one per batch.
//!
//! `commit_delay` is a test/bench-only knob (`Default` is `None`); production
//! never sleeps.

use loom_vm::save_queue::{SaveDurability, SaveQueueConfig, SaveQueueStats};
use loom_vm::{Host, World};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// A [`Host`] that swallows output: the logout path sends nothing to observe.
struct Sink {
    out: HashMap<u64, String>,
}

impl Host for Sink {
    fn send(&mut self, conn: u64, text: &str) {
        self.out.entry(conn).or_default().push_str(text);
    }
    fn close(&mut self, conn: u64) {
        self.out.remove(&conn);
    }
    fn set_echo(&mut self, _conn: u64, _enabled: bool) {}
}

fn main() {
    let saves = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(25)
        .max(1);
    let root = scratch("mudlib");
    write_mudlib(&root);
    println!("OBI-348 save durability -- {saves} saves per arm, sequential\n");

    println!(
        "| arm | world-thread ms/logout | median | p95 | min | wall ms/logout | queued | inline |"
    );
    println!("|---|---|---|---|---|---|---|---|");
    for (mode, delay) in [
        (SaveDurability::Sync, None),
        (SaveDurability::Deferred, None),
        (SaveDurability::Sync, Some(Duration::from_millis(5))),
        (SaveDurability::Deferred, Some(Duration::from_millis(5))),
    ] {
        let arm = logout_arm(&root, mode, delay, saves);
        println!("{arm}");
    }

    let atomic = write_file_atomic_arm(saves);
    println!("\n`write_file_atomic` inline (what the worker now absorbs): {atomic:.3} ms/save");
    let (file_sync, dir_sync) = sync_split_arm(saves);
    println!(
        "  split: content fsync {file_sync:.3} ms, parent-dir fsync {dir_sync:.3} ms ({:.0}% of the two)",
        100.0 * dir_sync / (file_sync + dir_sync).max(1e-6)
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// One row of arm 1. `world_ms` is what the thread that serves every player
/// spends per logout; `wall_ms` is the whole batch including the final drain,
/// so nobody reads the first column as "the disk got faster".
struct Row {
    label: String,
    mean: f64,
    median: f64,
    p95: f64,
    min: f64,
    wall_ms: f64,
    stats: SaveQueueStats,
}

impl std::fmt::Display for Row {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "| {} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {} | {} |",
            self.label,
            self.mean,
            self.median,
            self.p95,
            self.min,
            self.wall_ms,
            self.stats.queued,
            self.stats.inline_commits
        )
    }
}

fn logout_arm(root: &Path, mode: SaveDurability, delay: Option<Duration>, saves: usize) -> Row {
    let name = format!(
        "logout-{}",
        match mode {
            SaveDurability::Sync => "sync",
            SaveDurability::Deferred => "deferred",
        }
    );
    let mut world = World::boot(root).expect("boot");
    world.set_save_root(scratch(&name));
    world.set_save_queue_config(SaveQueueConfig {
        commit_delay: delay,
        ..SaveQueueConfig::default()
    });
    world.set_save_durability(mode);
    let mut host = Sink {
        out: HashMap::new(),
    };

    let mut samples = Vec::with_capacity(saves);
    let mut total = Duration::ZERO;
    let wall_at = Instant::now();
    for conn in 1..=saves as u64 {
        world.connect(conn, &mut host);
        // The measurement: how long the thread that serves every player spends
        // on this logout.
        let at = Instant::now();
        world.disconnect(conn, &mut host);
        let dt = at.elapsed();
        total += dt;
        samples.push(dt);
        // Reap, exactly as the real loop's `World::tick` does, so the queue
        // cannot saturate into the inline fallback.
        world.tick(&mut host);
    }
    // Nothing is owed to the disk past this point.
    world.flush_pending_saves();
    let wall = wall_at.elapsed();
    let stats = world.save_queue_stats();

    samples.sort_unstable();
    let n = samples.len();
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    Row {
        label: name_label(mode, delay),
        mean: ms(total) / n as f64,
        median: ms(samples[n / 2]),
        p95: ms(samples[(n * 95) / 100].min(samples[n - 1])),
        min: ms(samples[0]),
        wall_ms: ms(wall) / n as f64,
        stats,
    }
}

fn name_label(mode: SaveDurability, delay: Option<Duration>) -> String {
    let mode = match mode {
        SaveDurability::Sync => "Sync (pre-348 shape)",
        SaveDurability::Deferred => "Deferred (shipped)",
    };
    match delay {
        None => format!("disconnect, {mode}"),
        Some(d) => format!("disconnect, {mode}, {} ms disk", d.as_millis()),
    }
}

/// Arm 2: the durable sequence on its own, through the same `fileio` entry
/// point the worker calls.
fn write_file_atomic_arm(saves: usize) -> f64 {
    let save_root = scratch("atomic");
    let text = "x".repeat(4096);
    let at = Instant::now();
    for i in 0..saves {
        loom_vm::fileio::write_file_atomic(&save_root, &format!("/bench-{i}.o"), &text)
            .expect("write");
    }
    at.elapsed().as_secs_f64() * 1000.0 / saves as f64
}

/// Arm 3: how much of a save's cost is the parent-directory `fsync` -- the one
/// syscall that is the same for every save in a batch, and therefore the one
/// worth coalescing if it is a real share.
fn sync_split_arm(saves: usize) -> (f64, f64) {
    let dir = scratch("syncsplit");
    let n = saves as f64;
    let text = "x".repeat(4096);

    let at = Instant::now();
    for i in 0..saves {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(dir.join(format!("f{i}.o")))
            .expect("open");
        std::io::Write::write_all(&mut f, text.as_bytes()).expect("write");
        f.sync_all().expect("fsync file");
    }
    let file_sync = at.elapsed().as_secs_f64() * 1000.0 / n;

    let at = Instant::now();
    for _ in 0..saves {
        std::fs::File::open(&dir)
            .expect("open dir")
            .sync_all()
            .expect("fsync dir");
    }
    (file_sync, at.elapsed().as_secs_f64() * 1000.0 / n)
}

fn scratch(tag: &str) -> PathBuf {
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "loom-save-durability-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

/// The minimum the disconnect path needs: a master that allows everything
/// (spec §4's fail-closed applies to real mudlibs, not benchmarks) and a
/// player whose `autosave()` does what `/std/player`'s does -- calls
/// `save_object`.
fn write_mudlib(root: &Path) {
    std::fs::create_dir_all(root.join("secure")).expect("mkdir");
    std::fs::create_dir_all(root.join("std")).expect("mkdir");
    std::fs::write(
        root.join("secure/master.wf"),
        r#"pub fn connect() -> object {
    return clone_object("/std/player")
}
fn valid_efun(name: string, class: int, ob: object) -> bool { return true }
fn valid_compile(path: string, ob: object) -> bool { return true }
fn valid_upgrade(path: string, ob: object) -> bool { return true }
fn valid_read(path: string, ob: object, op: string) -> bool { return true }
fn valid_write(path: string, ob: object, op: string) -> bool { return true }
"#,
    )
    .expect("write master");
    std::fs::write(
        root.join("std/player.wf"),
        r#"persistent var hp: int = 100
var junk: int = 0

pub fn logon() {
    send(self, "ok\n")
}

pub fn net_dead() {
}

pub fn autosave() {
    save_object("/whoever")
}

pub fn process_input(line: string) {
    junk = len(line)
}
"#,
    )
    .expect("write player");
}
