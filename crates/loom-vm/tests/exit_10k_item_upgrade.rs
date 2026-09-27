// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-91 (OBI-34 slice 4, exit criterion E1.2): 10k live `/std/item`
//! clones, recompile `/std/item` with a schema change, drive the
//! resulting migration through `upgrade_all` (OBI-89's tick-budgeted
//! eager path) while a background compile is also in flight (OBI-90's
//! off-thread `begin_recompile_after`, using the spec r5 amendment's own
//! sanctioned slow-compile stand-in rather than an actually huge
//! dependent tree). Asserts: every clone eventually reports the new
//! version, each one's state migrated correctly (old var carried over,
//! new var initialised through `upgrade()`), zero disconnects the whole
//! time, and reports (not just thresholds) p99 tick latency during the
//! `upgrade_all` drain.
//!
//! `#[ignore]`d per the AC (10k clones + a full tick-budgeted drain is a
//! multi-second run): meant for a nightly job, not every `cargo test`.
//! Run explicitly with:
//! `cargo test -p loom-vm --test exit_10k_item_upgrade -- --ignored --nocapture`

mod common;

use std::time::{Duration, Instant};

use common::{FakeHost, fixture, on_world_thread};
use loom_vm::{Limits, Value, World};

const N_ITEMS: usize = 10_000;
/// "Connected test clients" distinct from the operator connection: kept
/// small enough to run fast, but nonzero so "zero disconnects" is an
/// actual assertion about live connections, not a vacuous one.
const N_CLIENTS: usize = 50;

#[test]
#[ignore = "10k clones + a full upgrade_all drain; run in the nightly E1.2 job, not every cargo test"]
fn ten_thousand_item_clones_survive_a_recompile_and_upgrade_all_with_zero_disconnects() {
    on_world_thread(|| {
        let root = fixture("exit_10k_item");
        let mut world = World::boot_with_limits(
            &root,
            Limits {
                eager_upgrade_batch: 200,
                // Every world tick fires heartbeats (OBI-82 made the
                // default 20): the per-tick "not starved" check below
                // needs a heartbeat on every tick.
                heartbeat_interval_ticks: 1,
                ..Limits::default()
            },
        )
        .expect("boot");
        let mut host = FakeHost::default();

        // Operator connection: clones every item and drives the
        // recompile/upgrade_all.
        const OPERATOR: u64 = 1;
        world.connect(OPERATOR, &mut host);
        host.take(OPERATOR);

        // N_CLIENTS "live players", heartbeat subscribed, standing in for
        // the connected test clients the AC asks for.
        let clients: Vec<u64> = (2..2 + N_CLIENTS as u64).collect();
        for &c in &clients {
            world.connect(c, &mut host);
            host.take(c);
            world.input(c, "hbon", &mut host);
            assert_eq!(host.take(c), "heartbeat on\n");
        }

        // Clone 10k /std/item, giving each a distinct `count` so "state
        // migrated correctly" below is checking real per-object data, not
        // just a shared default.
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
        assert_eq!(world.program_version("/std/item"), Some(1));

        // Schema change: add `durability`, backfilled by `upgrade()` from
        // the carried-over `count` — proves both var carry-over *and* the
        // user upgrade hook ran during the migration, not just a
        // pointer-swap.
        std::fs::write(
            root.join("std/item.wf"),
            "var name: string = \"widget\"\nvar count: int = 0\nvar durability: int = 100\n\npub fn set_count(n: int) {\n    count = n\n}\n\npub fn upgrade(from_version: int, old: {string: any}) {\n    durability = 100 + count\n}\n",
        )
        .unwrap();

        // Recompile off the world thread (OBI-90): delayed so it is still
        // in flight across several ticks, proving ticks (here: every
        // client's heartbeat) keep advancing during the compile itself,
        // not just during the later upgrade_all drain.
        let token = world.begin_recompile_after("/std/item", Duration::from_millis(100));
        assert!(world.recompile_pending(token));
        for _ in 0..3 {
            world.tick(&mut host);
        }
        for &c in &clients {
            world.input(c, "beats", &mut host);
            let beats: i64 = host.take(c).trim().parse().expect("beats");
            assert!(
                beats >= 3,
                "heartbeat must keep firing during the background compile"
            );
        }
        assert_eq!(
            world.program_version("/std/item"),
            Some(1),
            "background compile should not have landed yet"
        );

        let mut installed = false;
        for _ in 0..500 {
            world.tick(&mut host);
            if !world.recompile_pending(token) {
                installed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(installed, "background compile of /std/item never finished");
        let results = world.take_finished_recompiles();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, Ok(()));
        assert_eq!(world.program_version("/std/item"), Some(2));

        // Nothing has migrated yet: install is lazy by default (OBI-89).
        for &id in items.iter().take(50) {
            assert_eq!(
                world.object_program_version(id),
                Some(("/std/item".into(), 1))
            );
        }

        // Explicit upgrade_all: queue every stale /std/item for a
        // tick-budgeted eager migration.
        world.input(OPERATOR, "upgrade_item", &mut host);
        let queued = host.take(OPERATOR);
        assert_eq!(queued, format!("queued {N_ITEMS}\n"));
        assert_eq!(world.eager_upgrade_queue_len(), N_ITEMS);

        // Drain it, timing every tick and checking after every single one
        // that nobody was disconnected and every client's heartbeat is
        // still advancing (not starved by the migration batch).
        let mut tick_durations = Vec::new();
        let mut prior_beats = vec![0i64; clients.len()];
        let mut ticks = 0usize;
        while world.eager_upgrade_queue_len() > 0 {
            let start = Instant::now();
            world.tick(&mut host);
            tick_durations.push(start.elapsed());
            ticks += 1;
            assert!(
                host.closed.is_empty(),
                "zero disconnects required, got {:?}",
                host.closed
            );
            for (i, &c) in clients.iter().enumerate() {
                world.input(c, "beats", &mut host);
                let beats: i64 = host.take(c).trim().parse().expect("beats");
                assert!(
                    beats > prior_beats[i],
                    "client {c}'s heartbeat must not be starved by upgrade_all"
                );
                prior_beats[i] = beats;
            }
            assert!(
                ticks < 10_000,
                "upgrade_all drain did not converge (queue stuck?)"
            );
        }
        assert!(world.take_lazy_upgrade_warnings().is_empty());
        assert!(
            host.closed.is_empty(),
            "zero disconnects required over the whole run"
        );

        // Every clone must now report v2, with count carried over exactly
        // and durability backfilled by upgrade() from that carried-over
        // count (proves state migrated correctly, not just version-bumped).
        for (i, &id) in items.iter().enumerate() {
            assert_eq!(
                world.object_program_version(id),
                Some(("/std/item".into(), 2)),
                "item {i} must report the new version"
            );
            assert!(
                matches!(world.var(id, "count"), Some(Value::Int(n)) if n == i as i64),
                "item {i} count not carried over correctly: {:?}",
                world.var(id, "count")
            );
            assert!(
                matches!(world.var(id, "durability"), Some(Value::Int(n)) if n == 100 + i as i64),
                "item {i} durability not backfilled by upgrade(): {:?}",
                world.var(id, "durability")
            );
        }

        // p99 tick latency during the upgrade_all drain: reported, not
        // just asserted under a threshold (per the AC).
        tick_durations.sort();
        let p99_idx = ((tick_durations.len() as f64) * 0.99) as usize;
        let p99_idx = p99_idx.min(tick_durations.len() - 1);
        let p99 = tick_durations[p99_idx];
        let max = *tick_durations.last().unwrap();
        let mean: Duration = tick_durations.iter().sum::<Duration>() / tick_durations.len() as u32;
        eprintln!(
            "OBI-91 upgrade_all drain: {} ticks, batch size {}, mean tick = {:?}, p99 tick = {:?}, max tick = {:?}",
            tick_durations.len(),
            200,
            mean,
            p99,
            max,
        );
        // Generous regression guard only — the number above is the actual
        // proof the AC asks for, not this bound.
        assert!(
            p99 < Duration::from_secs(1),
            "p99 tick latency during upgrade_all blew up: {p99:?}"
        );
    });
}
