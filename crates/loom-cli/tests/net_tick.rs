// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `serve()` drives `World::tick()` from a real 100 ms `NetEvent::Tick`
//! timer (spec r5 N2, OBI-82): boot the `tworoom` fixture as a real
//! subprocess, schedule a `call_out(f, 3)`, and let the timer (not a test
//! harness clock) advance the world. `f` must run exactly once, after (not
//! before) the 3rd world tick.
//!
//! The subprocess, its ports and the transcript reading come from
//! `loom_testing` (OBI-305). Both tests here measure *elapsed real time*, so
//! the readiness barrier matters twice over: without it, the first
//! connection -- and therefore `scheduled_at` -- could land before the world
//! thread had even started ticking.

use std::time::Duration;

use loom_testing::{Spawn, assert_no_output_within, read_until_contains, send_line};

/// `WORLD_TICK_INTERVAL` in `loom-cli/src/main.rs`; kept in sync by eye
/// (not `pub`, so not importable) since this is a black-box process test.
const WORLD_TICK_MS: u64 = 100;

/// The per-socket read timeout these tests have always set: short enough that
/// a stalled server is reported by the needle's own timeout rather than
/// hanging the test binary.
const READ_TIMEOUT: Duration = Duration::from_millis(200);

#[test]
fn call_out_fires_exactly_once_after_three_world_ticks() {
    let mudlib = loom_testing::fixture(env!("CARGO_MANIFEST_DIR"), "tworoom");
    let mut server = Spawn::serve(&mudlib).start();
    let mut reader = server.session().into_reader(READ_TIMEOUT);

    // logon() greets and looks around; drain it before scheduling.
    let _ = read_until_contains(&mut reader, "Exits:", Duration::from_secs(5));

    send_line(&mut reader, "sched3"); // call_out("pong", 3)
    let scheduled_at = std::time::Instant::now();
    let scheduled = read_until_contains(&mut reader, "scheduled ", Duration::from_secs(2));
    assert!(scheduled.contains("scheduled 0"), "{scheduled}");

    // A 3-world-tick delay is at least ~2 ticks away no matter where in the
    // current tick period it was scheduled (it could have been scheduled
    // an instant before a tick boundary, in which case it is due after only
    // a little over 2 further ticks): well under that, nothing should have
    // arrived yet.
    assert_no_output_within(&mut reader, Duration::from_millis(WORLD_TICK_MS));

    // Comfortably past the 3rd world tick (300 ms from *scheduling*, not
    // from server boot -- the tick counter keeps running from boot, so
    // `call_out`'s delay is relative to whatever tick it happened to be
    // scheduled on) but with generous CI slack.
    let after = read_until_contains(&mut reader, "pong 0", Duration::from_secs(3));
    assert!(after.contains("pong 0\n"), "{after}");
    let fired_after = scheduled_at.elapsed();
    assert!(
        fired_after >= Duration::from_millis(WORLD_TICK_MS),
        "pong fired suspiciously fast ({fired_after:?}) for a 3-world-tick call_out"
    );

    // No second `pong`: give the world several more ticks' worth of real
    // time and confirm nothing else arrives.
    assert_no_output_within(&mut reader, Duration::from_millis(5 * WORLD_TICK_MS));

    server.assert_alive();
}

#[test]
fn a_world_thread_that_falls_behind_never_has_more_than_one_pending_tick() {
    // There is no test-only hook into `serve()`'s internal `tick_pending`
    // flag (a black-box process test can't reach into another process's
    // `Arc<AtomicBool>`), so this pins the *externally observable*
    // consequence of coalescing instead: a `heart_beat()` that counts every
    // `World::tick()` call must, over several seconds of real (wall-clock)
    // time on a live server, land within one tick of
    // `elapsed / WORLD_TICK_INTERVAL` -- not run away to some much larger
    // number the way an unbounded queue of missed `Tick`s replayed back to
    // back would produce once the process got a chance to catch up (e.g.
    // after being descheduled by the OS scheduler under load).
    let mudlib = loom_testing::fixture(env!("CARGO_MANIFEST_DIR"), "tworoom");
    let mut server = Spawn::serve(&mudlib).start();
    let mut reader = server.session().into_reader(READ_TIMEOUT);
    let _ = read_until_contains(&mut reader, "Exits:", Duration::from_secs(5));

    send_line(&mut reader, "hbon");
    let _ = read_until_contains(&mut reader, "heartbeat on", Duration::from_secs(2));

    let start = std::time::Instant::now();
    std::thread::sleep(Duration::from_secs(3));

    send_line(&mut reader, "beats");
    let out = read_until_contains(&mut reader, "\n", Duration::from_secs(2));
    let beats: u64 = out.trim().parse().expect("numeric beats count");
    let elapsed_ticks = start.elapsed().as_millis() as u64 / WORLD_TICK_MS;

    // Default heartbeat cadence is every 20 world ticks; a bounded (never
    // more than one pending `Tick`) driver falls at most a handful of
    // ticks behind wall-clock even under CI scheduling jitter, so this
    // generous factor-of-2 slack still rejects "ticks queued up and never
    // coalesced" (which would run heartbeats far more often once the world
    // thread got CPU time back) while tolerating a slow CI host.
    let max_plausible_beats = elapsed_ticks / 20 + 2;
    assert!(
        beats <= max_plausible_beats,
        "heartbeat ran {beats} times in ~{elapsed_ticks} world ticks; \
         expected at most {max_plausible_beats} if ticks are bounded/coalesced, not queued"
    );

    server.assert_alive();
}
