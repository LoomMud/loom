// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-85 acceptance criterion: "in-memory backend. Create -> account_result
//! (ok), duplicate -> exists, wrong password -> bad_credentials. The world
//! thread is never blocked by hashing (show it: another connection's input
//! is processed while a login is pending)." Exercised end to end against a
//! real `loom-cli serve` subprocess with `DATABASE_URL` unset, so it runs
//! the in-memory dev account backend CI/the load bot use.
//!
//! OBI-329 -- this file's half of the timing-flake class that already cost us
//! OBI-292. The waits here used to be hard-coded wall-clock budgets:
//! `Duration::from_secs(2)` per `account_result`, and `elapsed < 500 ms` for
//! "the world thread is not hashing". Neither can tell a blocked world thread
//! apart from a busy CI runner, and the dev backend hashes *serially* at
//! ~400 ms an account operation in a debug build (measured: `result n` lines
//! land 400 ms apart, and on this host an idle round trip costs ~1 ms), so
//! four of them already sat at 1.6 s of a 2 s budget on an idle machine and
//! blew it on a shared one. Now:
//!
//! * waiting for **state** (a result arrived) uses [`READY_DEADLINE`], a hang
//!   detector, never a performance claim;
//! * the one **timing** property the file cares about is decided by
//!   [`serve_verdict`], a pure function of three durations measured on the host
//!   in the same run, so common-mode contention cancels out;
//! * the probes are pinned to actually queue hashing ([`pipeline_name`] and
//!   [`pipelined_names_pass_the_drivers_own_validation`]): the names this file
//!   used before were rejected by the driver's own validation, so the test was
//!   asserting on an empty queue; and
//! * the client no longer nudges the world thread at all ([`PROBE`]). The
//!   100 ms `look` loop predates `NetEvent::Tick` (OBI-82), and at 10 Hz it ran
//!   at twice `loom_net`'s per-connection input limit -- which is what actually
//!   capped these waits at 2 s, because past the burst the driver hangs up on
//!   the test; and
//! * the probe window ends on "nothing left to measure" ([`next_pace`]), not on a
//!   sample count, because `World::drain_account_results` hands the outbox over in
//!   one batch per tick, and a tail that lands two-at-a-time used to leave the
//!   loop unable to finish inside [`READY_DEADLINE`]; and
//! * reads are line-complete ([`Lines`]): an unterminated tail is carried across
//!   polls instead of dropped with the poll's scratch buffer, because a 2 ms poll
//!   that loses half an `ok` is the OBI-302 lost-bytes class wearing a timing
//!   costume ([`a_partial_line_survives_the_poll_boundary`]).

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// Waiting for *state* is a hang detector, not a timing assertion: no amount
/// of runner contention should reach it, so "this CI box is busy" can never
/// read as a driver bug (OBI-329). A driver that genuinely never answers still
/// fails -- at 60 s, and with the transcript.
const READY_DEADLINE: Duration = Duration::from_secs(60);

/// How many `account_create`s connection `a` pipelines while connection `b` is
/// probed. Eight keeps the dev worker's serial hashing queue (~3 s here,
/// longer on a loaded runner) big compared with a CI box's scheduling stalls,
/// which is what makes "b waited behind the queue" measurable without the test
/// having to name a wall-clock budget.
const PIPELINED_CREATES: usize = 8;

/// Round trips sampled per connection. Medians, because any single round trip
/// on a shared runner is one scheduling coin-flip.
const FLOOR_SAMPLES: usize = 7;
const LOADED_SAMPLES: usize = 5;

/// [`serve_verdict`]'s allowance is `max(HASH_TOLERANCE x one hash,
/// FLOOR_TOLERANCE x one round trip, MIN_ALLOWANCE)` -- every term measured on
/// this host during this run.
const FLOOR_TOLERANCE: u32 = 10;
const HASH_TOLERANCE: u32 = 2;
/// The smallest the allowance can be, so a measurement that lands at ~0 cannot
/// make the assertion vacuous. Unlike the `elapsed < 500 ms` it replaces it is
/// a *lower* bound: a slower host can only loosen this test, never lose it.
const MIN_ALLOWANCE: Duration = Duration::from_millis(50);

/// The line connection `b` is probed with. `look` is what the fixture's
/// `process_input` answers with a plain `ok`, and it costs the driver no
/// hashing and no DB round trip, so it measures the world thread's willingness
/// to service input rather than anything the command itself does.
///
/// It is *not* a nudge. This file used to also send `look` on `a` every 100 ms
/// to force the world thread to drain the account backend's result channel,
/// because before `NetEvent::Tick` (OBI-82) nothing else woke the loop. The tick
/// has landed -- `loom-cli serve` sends one every 100 ms
/// (`WORLD_TICK_INTERVAL`), and `World::tick` calls `World::drain_account_results`
/// -- so no client traffic is needed to make results appear, and giving some up
/// the file's timing is what the OBI-329 rewrite is made of. The cadence that
/// used to force the drain (10 Hz) was also twice `loom_net`'s per-connection
/// input limit (one token per line, 5/s refill, 20 burst), which disconnects a
/// client that exceeds it: the old 2 s budgets were not a judgement about how
/// long hashing takes, they were how long the *test* could afford to talk before
/// the driver dropped it. See [`client_traffic_stays_inside_the_drivers_input_limit`].
const PROBE: &str = "look";

#[test]
fn client_traffic_stays_inside_the_drivers_input_limit() {
    // The driver disconnects a client that runs out of input tokens, so a test
    // that talks too much does not get slow, it gets dropped -- and the failure
    // then looks like a driver bug. Every line this file sends on one
    // connection has to fit the burst, because the window it fits into is
    // whatever the host's hashing takes, not something the test can predict.
    let config = loom_net::NetConfig::default();
    // Connection `a` only ever sees one line per command a test types: 4 in the
    // create/duplicate/login test, `PIPELINED_CREATES` here. `b` sees the floor
    // samples plus the probes, and the floor samples are the burstiest thing in
    // the file (7 lines inside 7 x 20 ms).
    let on_a = PIPELINED_CREATES;
    let on_b = FLOOR_SAMPLES + LOADED_SAMPLES;
    assert!(
        on_a <= config.rate_limit_burst as usize && on_b <= config.rate_limit_burst as usize,
        "this test sends {on_a} lines on `a` and {on_b} on `b` against a burst of {}; widen \
         the burst or send less",
        config.rate_limit_burst,
    );
    // And the probes, if they must be paced at all, are paced on results --
    // never on a fixed interval that could out-run the bucket. Checked at
    // compile time, since nothing about it depends on the host.
    const {
        assert!(
            LOADED_SAMPLES <= PIPELINED_CREATES,
            "one probe per outstanding create at most"
        );
    }
}

/// The socket read timeout while the probe window is open. A *poll* interval,
/// not a budget: the loops below keep going until [`READY_DEADLINE`]. It has to
/// be short because one thread watches both connections, and every millisecond
/// spent blocked in a read on `a` is a millisecond `b`'s reply goes unstamped.
const POLL: Duration = Duration::from_millis(2);

/// Read timeout for the single-connection helpers, which only ever watch one
/// socket and so can afford a longer sleep between polls.
const LONG_POLL: Duration = Duration::from_millis(200);

/// Password for the pipelined creates. `World::issue_account_request` accepts
/// 6..=128 bytes and nothing else; see
/// [`pipelined_names_pass_the_drivers_own_validation`].
const PIPELINE_PASSWORD: &str = "hunter2password";

#[test]
fn in_memory_account_backend_create_duplicate_and_bad_password() {
    let mudlib = fixture("accounts");
    let port = reserve_local_port();
    let bind = format!("127.0.0.1:{port}");
    let mut server = LoomServer::spawn(&mudlib, &bind);

    let stream_a = connect_with_retry(&bind, READY_DEADLINE);
    stream_a.set_read_timeout(Some(LONG_POLL)).unwrap();
    let mut a = BufReader::new(stream_a);
    read_until_contains(&mut a, "Welcome.", READY_DEADLINE);

    // Each of these is a *state* wait: the exact reply text is the assertion
    // and the deadline only catches a hang. One Argon2id hash apiece on the
    // serial dev worker, so `result 4` legitimately lands seconds after the
    // request on a quiet box and considerably later on a loaded one.
    send_line(&mut a, "create legolas hunter2pass");
    let out = read_until_contains(&mut a, "req ", READY_DEADLINE);
    assert!(out.contains("req 1\n"), "{out}");
    let out = read_until_contains(&mut a, "result 1 ", READY_DEADLINE);
    assert!(
        out.contains("result 1 true "),
        "expected a successful create: {out}"
    );

    send_line(&mut a, "create legolas hunter2pass");
    let out = read_until_contains(&mut a, "result 2 ", READY_DEADLINE);
    assert!(
        out.contains("result 2 false exists"),
        "duplicate account must be rejected as `exists`: {out}"
    );

    send_line(&mut a, "login legolas wrong-password");
    let out = read_until_contains(&mut a, "result 3 ", READY_DEADLINE);
    assert!(
        out.contains("result 3 false bad_credentials"),
        "wrong password must be `bad_credentials`: {out}"
    );

    send_line(&mut a, "login legolas hunter2pass");
    let out = read_until_contains(&mut a, "result 4 ", READY_DEADLINE);
    assert!(
        out.contains("result 4 true "),
        "correct login must succeed: {out}"
    );

    server.assert_alive();
}

/// The world thread never blocks on Argon2 hashing: pipeline a batch of
/// `account_create` requests on one connection (without waiting for their
/// results -- the hashing for each happens off the world thread), then check
/// that a *second* connection's unrelated input keeps making progress across
/// the whole hashing window.
#[test]
fn a_pending_login_does_not_block_another_connections_input() {
    let mudlib = fixture("accounts");
    let port = reserve_local_port();
    let bind = format!("127.0.0.1:{port}");
    let mut server = LoomServer::spawn(&mudlib, &bind);

    let stream_a = connect_with_retry(&bind, READY_DEADLINE);
    stream_a.set_read_timeout(Some(LONG_POLL)).unwrap();
    let mut a = BufReader::new(stream_a);
    read_until_contains(&mut a, "Welcome.", READY_DEADLINE);

    let stream_b = connect_with_retry(&bind, READY_DEADLINE);
    stream_b.set_read_timeout(Some(LONG_POLL)).unwrap();
    let mut b = BufReader::new(stream_b);
    read_until_contains(&mut b, "Welcome.", READY_DEADLINE);

    // The host's own round-trip floor, measured before any account work is
    // outstanding. Everything downstream is compared with this, never with a
    // constant.
    let floor = median(&round_trips(&mut b, FLOOR_SAMPLES));

    let window = probe_hashing_window(&mut a, &mut b);

    // (1) The pipelined creates must really have been hashed, or this test
    // measures nothing: the driver answers a name it dislikes `invalid`
    // synchronously, with no hashing queued at all, and that is exactly how
    // this test silently defanged itself before OBI-329.
    assert_eq!(
        window.results.len(),
        PIPELINED_CREATES,
        "expected every pipelined create to come back, got {:?}",
        window.results
    );
    for (index, line) in window.results.iter().enumerate() {
        assert!(
            line.contains(" true "),
            "create #{} came back {line}, not `true`: the pipelined names or \
             PIPELINE_PASSWORD stopped satisfying World::issue_account_request's validation, so \
             this test would be asserting on an empty hashing queue",
            index + 1
        );
    }

    // (2) The causal claim: b's input was serviced while the queue was still
    // moving, not after it had drained.
    assert!(
        window.results_before_first_probe < PIPELINED_CREATES,
        "all {} pipelined creates had already been answered before connection b's first probe \
         arrived, while the world thread should have been doing {} hashes of work off-thread",
        PIPELINED_CREATES,
        PIPELINED_CREATES,
    );

    // (3) The timing claim, in host-relative terms only.
    let verdict = serve_verdict(floor, window.loaded, window.hash);
    assert_eq!(
        verdict,
        Verdict::KeptServing,
        "connection b's input looks stalled behind the hashing queue. Measured on this host: \
         idle round trip {floor:?}, round trip while creates pending {:?}, one hash {:?}, {} of \
         {} results already delivered when b was first answered",
        window.loaded,
        window.hash,
        window.results_before_first_probe,
        PIPELINED_CREATES,
    );

    server.assert_alive();
}

/// What the one timing assertion in this file means, as a pure function of
/// three durations measured on the host in this very run.
///
/// The property under test is "`World::issue_account_request` never hashes on
/// the world thread" -- it only ever does a `try_send` on a bounded channel.
/// The naive version, "b's input came back within 500 ms", cannot tell a
/// blocked world thread apart from a runner that is busy, which is the class
/// that cost OBI-292 and OBI-329 their green builds. Contention is *common
/// mode*: it inflates the idle floor and the loaded round trip together, so the
/// only quantity that means anything is their difference. A world thread that
/// hashed inline would pay for the whole queue in that difference
/// (`PIPELINED_CREATES` hashes), and the allowance -- two hashes, or ten round
/// trips, whichever is larger -- is sized to keep that visible on a quiet
/// runner while never becoming unreachable on a loaded one.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// b's input made progress while hashing was outstanding.
    KeptServing,
    /// b's input waited on the hashing queue for longer than the host's own
    /// work can account for.
    BlockedBehindHashing {
        /// How much longer b waited than an idle round trip on this host.
        extra: Duration,
        /// How much longer it was allowed to take.
        allowance: Duration,
    },
}

fn serve_verdict(floor: Duration, loaded: Duration, hash: Duration) -> Verdict {
    let allowance = (hash * HASH_TOLERANCE)
        .max(floor * FLOOR_TOLERANCE)
        .max(MIN_ALLOWANCE);
    let extra = loaded.saturating_sub(floor);
    if extra > allowance {
        Verdict::BlockedBehindHashing { extra, allowance }
    } else {
        Verdict::KeptServing
    }
}

/// Deterministic guards for [`serve_verdict`] (`loom-cli`'s copy of the
/// OBI-292 lesson): the shapes below are what a real runner produces, written
/// down as numbers so the reasoning is pinned without losing a build to
/// discover it.
#[test]
fn serve_verdict_passes_a_busy_but_correct_runner() {
    // A box so contended that an idle round trip costs 400 ms and one hash
    // 1.6 s, with b's loaded round trip 90 ms above its own floor: busy, and
    // correctly so -- the world thread is not sitting in Argon2.
    let floor = Duration::from_millis(400);
    let loaded = Duration::from_millis(490);
    let hash = Duration::from_millis(1600);
    assert_eq!(serve_verdict(floor, loaded, hash), Verdict::KeptServing);
}

#[test]
fn serve_verdict_flags_a_world_thread_that_hashes_inline() {
    // Same host, same hash cost, but hashing moved onto the world thread: b is
    // answered only after the whole pipelined queue drained.
    let floor = Duration::from_millis(400);
    let hash = Duration::from_millis(1600);
    let loaded = floor + hash * PIPELINED_CREATES as u32;
    assert!(
        matches!(
            serve_verdict(floor, loaded, hash),
            Verdict::BlockedBehindHashing { .. }
        ),
        "a full hashing queue in front of b's input must not read as KeptServing"
    );
}

#[test]
fn serve_verdict_can_see_three_hashes_of_blocking_on_a_quiet_host() {
    // How much detection power the allowance leaves, stated rather than
    // assumed: on a quiet host the allowance is two hashes, so a regression
    // worth three or more is visible and a single hash's stall is not.
    // `PIPELINED_CREATES` hashes queued inline is far above that line.
    let floor = Duration::from_millis(2);
    let hash = Duration::from_millis(400);
    assert_eq!(
        serve_verdict(floor, floor + hash * 2, hash),
        Verdict::KeptServing,
        "two hashes of stall is inside the allowance by design"
    );
    let verdict = serve_verdict(floor, floor + hash * 3, hash);
    let Verdict::BlockedBehindHashing { extra, allowance } = verdict else {
        panic!("three hashes of stall must be flagged, got {verdict:?}");
    };
    assert!(
        extra > allowance,
        "a flagged verdict must report more stall than allowed: {extra:?} vs {allowance:?}"
    );
}

#[test]
fn serve_verdict_never_uses_an_absolute_wall_clock_budget() {
    // Slowing the host down uniformly (every measurement by the same factor)
    // must never turn a pass into a failure: that is precisely the property the
    // `elapsed < 500 ms` this replaced did not have.
    for scale in [1_u64, 3, 17, 200, 4_000] {
        let floor = Duration::from_millis(scale);
        let loaded = floor + floor / 2;
        let hash = Duration::from_millis(scale * 400);
        assert_eq!(
            serve_verdict(floor, loaded, hash),
            Verdict::KeptServing,
            "scale x{scale}"
        );
    }
}

/// Connection `a`'s pipelined account names: unique, lowercase ASCII only,
/// 3..=16 chars.
///
/// Not cosmetic. The names used before (`player0` .. `player9`) contain digits,
/// and `World::issue_account_request` requires
/// `(3..=16).contains(&name.chars().count()) && name.chars().all(ascii
/// lowercase)`, so every one of them was answered `invalid` from the validation
/// branch -- synchronously, with **no hashing queued at all**. The test then
/// asserted that the world thread was not blocked on hashing while there was no
/// hashing to be blocked on: it could not fail for any driver bug.
fn pipeline_name(index: usize) -> String {
    let letter = |i: usize| (b'a' + (i % 26) as u8) as char;
    format!("acct{}{}", letter(index), letter(index / 26))
}

#[test]
fn pipelined_names_pass_the_drivers_own_validation() {
    // Mirror of `World::issue_account_request`'s rules. Anything that fails one
    // is answered `invalid` without touching the hashing path, which silently
    // defangs the test instead of failing it.
    assert!(
        (6..=128).contains(&PIPELINE_PASSWORD.len()),
        "a password outside 6..=128 bytes is rejected without hashing"
    );
    let mut names: Vec<String> = (0..PIPELINED_CREATES).map(pipeline_name).collect();
    for name in &names {
        assert!(
            (3..=16).contains(&name.chars().count()),
            "`{name}` is not a valid account name"
        );
        assert!(
            name.chars().all(|c| c.is_ascii_lowercase()),
            "`{name}` has a character the driver rejects without hashing"
        );
    }
    names.sort();
    let unique = names.len();
    names.dedup();
    assert_eq!(
        unique,
        names.len(),
        "duplicate pipelined names are answered `exists`, not hashed as a create"
    );
}

/// What one [`probe_hashing_window`] pass measured. Every field is a property of
/// the host during this run, which is the only basis on which a timing
/// assertion here can be made (OBI-329).
struct Window {
    /// Median round trip on `b` for the probes sent while creates were
    /// outstanding.
    loaded: Duration,
    /// Median gap between consecutive `account_result` deliveries: what one hash
    /// cost this host during the window.
    hash: Duration,
    /// How many pipelined results had been delivered by the time `b`'s first
    /// probe was answered.
    results_before_first_probe: usize,
    /// The `account_result` applies, in delivery order.
    results: Vec<String>,
}

/// Pipeline [`PIPELINED_CREATES`] creates on `a`, probe `b` across the resulting
/// hashing window, and collect the measurements.
///
/// Probes are paced on the host's own progress rather than on a clock: the next
/// one goes out once another slice of the queue has been delivered, so every
/// sample is taken while account work is genuinely outstanding, however long
/// the queue takes on this runner.
fn probe_hashing_window(a: &mut BufReader<TcpStream>, b: &mut BufReader<TcpStream>) -> Window {
    a.get_mut().set_read_timeout(Some(POLL)).unwrap();
    b.get_mut().set_read_timeout(Some(POLL)).unwrap();
    // One carry-over buffer per connection, for as long as that connection is
    // polled -- see [`Lines`].
    let mut a_carry = Lines::default();
    let mut b_carry = Lines::default();

    for index in 0..PIPELINED_CREATES {
        send_line(
            a,
            &format!("create {} {PIPELINE_PASSWORD}", pipeline_name(index)),
        );
    }

    let deadline = Instant::now() + READY_DEADLINE;

    let mut results: Vec<String> = Vec::with_capacity(PIPELINED_CREATES);
    let mut result_arrivals: Vec<Instant> = Vec::with_capacity(PIPELINED_CREATES);
    let mut probe_rtt: Vec<Duration> = Vec::with_capacity(LOADED_SAMPLES);
    let mut results_before_first_probe = PIPELINED_CREATES;
    let mut transcript_a = String::new();
    let mut transcript_b = String::new();

    // The first probe goes out immediately, with the whole queue ahead of it.
    send_line(b, PROBE);
    let first_probe_sent = Instant::now();
    let mut probe_sent = Some(first_probe_sent);

    loop {
        let Drain {
            lines: a_lines,
            closed: a_closed,
        } = a_carry.poll(a);
        note(&mut transcript_a, &a_lines);
        for line in a_lines {
            if line.starts_with("result ") {
                result_arrivals.push(Instant::now());
                results.push(line);
            }
        }

        let Drain {
            lines: b_lines,
            closed: b_closed,
        } = b_carry.poll(b);
        note(&mut transcript_b, &b_lines);

        if let Some(sent) = probe_sent
            && b_lines.iter().any(|line| line == "ok")
        {
            probe_rtt.push(sent.elapsed());
            probe_sent = None;
            if probe_rtt.len() == 1 {
                results_before_first_probe = result_arrivals.len();
            }
        }

        // One decision per drain, taken by the same pure function the replay test
        // drives, so the loop's termination is a property of the counters and not
        // of how the host happened to batch this run's deliveries.
        let pace = next_pace(probe_rtt.len(), results.len(), probe_sent.is_some());
        // A hang-up is only a defect while the window still has work outstanding;
        // once the probes are answered and the results are in, a driver that closes
        // on its way out has nothing left to tell us. Hence the decision above,
        // taken after this drain's lines have all been accounted for.
        if (a_closed || b_closed) && !matches!(pace, Pace::Done) {
            panic!(
                "the driver closed {}while {} of {PIPELINED_CREATES} pipelined creates were \
                 still outstanding.\n--- connection a ---\n{transcript_a}\n--- connection b \
                 ---\n{transcript_b}",
                if a_closed && b_closed {
                    "both connections"
                } else if a_closed {
                    "connection a"
                } else {
                    "connection b"
                },
                PIPELINED_CREATES - results.len(),
            );
        }

        match pace {
            Pace::Send => {
                send_line(b, PROBE);
                probe_sent = Some(Instant::now());
            }
            Pace::Done => break,
            Pace::Wait => {}
        }
        if Instant::now() > deadline {
            panic!(
                "timed out after {READY_DEADLINE:?} draining the hashing window: {} of \
                 {PIPELINED_CREATES} results, {} of {LOADED_SAMPLES} probes answered.\n--- \
                 connection a ---\n{transcript_a}\n--- connection b ---\n{transcript_b}",
                results.len(),
                probe_rtt.len(),
            );
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    // Terminating early is legal only if it still leaves something to report: a
    // window that collected no sample cannot back the timing claim, and must say
    // so with the counts rather than silently taking the median of nothing.
    assert!(
        !probe_rtt.is_empty(),
        "the probe window ended with no round trip sampled inside it: {} of {LOADED_SAMPLES} \
         probes answered, {} of {PIPELINED_CREATES} results delivered\n--- connection a \
         ---\n{transcript_a}\n--- connection b ---\n{transcript_b}",
        probe_rtt.len(),
        results.len(),
    );
    Window {
        loaded: median(&probe_rtt),
        // The gap between consecutive deliveries is the dev worker's own
        // per-hash cost; with one result there is no gap to measure, so fall
        // back to the whole window.
        hash: median(&gaps(&result_arrivals)),
        results_before_first_probe,
        results,
    }
}

/// Pace the probes on delivered results, not on wall clock. The last probe is
/// held back until one create is still outstanding, so no sample is taken after
/// the hashing work is gone.
fn should_send_next_probe(probes_answered: usize, results_delivered: usize) -> bool {
    let outstanding = PIPELINED_CREATES.saturating_sub(1);
    results_delivered >= (probes_answered + 1) * outstanding / LOADED_SAMPLES
}

/// What one drain of [`probe_hashing_window`] does, as a pure function of the
/// counters it has collected. Pure so
/// [`batched_drains_still_terminate_the_probe_window`] can replay delivery
/// schedules a live host only produces sometimes, instead of hoping to catch
/// one (OBI-329 review).
#[derive(Debug, PartialEq, Eq)]
enum Pace {
    /// A probe is outstanding, or the pacing threshold is not met yet: keep
    /// reading and come back next drain.
    Wait,
    /// The previous sample is in and the queue still has work in it: sample again.
    Send,
    /// Nothing left to measure: every result has landed and no probe is waiting.
    Done,
}

/// `World::drain_account_results` (crates/loom-vm/src/world.rs) pops the whole
/// outbox in one tick, so results arrive in batches, not one per drain. On a host
/// where a hash costs less than the 100 ms tick -- and on a contended runner where
/// the world thread wakes late with two results ready -- the drain that carries
/// result 7 can carry result 8 too. An exit condition of
/// `samples == LOADED_SAMPLES && results == PIPELINED_CREATES` cannot survive
/// that: the 5th probe was gated on `results < PIPELINED_CREATES`, so once the
/// batch closed the queue no further probe could go out, the sample count could
/// never reach 5, and the loop spun to [`READY_DEADLINE`] -- turning a host
/// difference into the timeout this file exists to remove.
///
/// So termination asks only "is there anything left to measure". It stays honest
/// about the sample count at the end of the window, where a missing sample is
/// reported as such instead of hanging.
fn next_pace(probes_answered: usize, results_delivered: usize, probe_in_flight: bool) -> Pace {
    if probe_in_flight {
        // Its answer is the next sample; taking the queue down as "done" while a
        // probe is outstanding would throw a measurement away.
        Pace::Wait
    } else if results_delivered >= PIPELINED_CREATES {
        Pace::Done
    } else if probes_answered >= LOADED_SAMPLES {
        // Fully sampled but still hashing: the caller asserts every create came
        // back, so keep draining rather than exiting into a false failure.
        Pace::Wait
    } else if should_send_next_probe(probes_answered, results_delivered) {
        Pace::Send
    } else {
        Pace::Wait
    }
}

/// The largest number of drains a replay may run before the window is called
/// un-terminating. [`READY_DEADLINE`] divided by the loop's 1 ms sleep is far
/// larger, so a replay that needs more than this is a schedule no host produces.
const REPLAY_DRAIN_CAP: usize = 100;

/// What a replayed drain schedule ended up doing.
#[derive(Debug)]
struct Replay {
    /// Whether the loop reached `Done`, and how many drains it took.
    terminated: bool,
    drains: usize,
    /// Round trips sampled inside the window.
    samples: usize,
    results_delivered: usize,
}

/// Replay [`next_pace`] over a scripted delivery schedule: `per_drain[i]` results
/// land in drain `i` (the last entry repeats once the script runs out) and a probe
/// sent in one drain is answered in the next -- the smallest model of the socket
/// loop that still contains batching.
fn replay_probe_window(per_drain: &[usize]) -> Replay {
    replay(per_drain, |answered, delivered, in_flight| {
        next_pace(answered, delivered, in_flight)
    })
}

/// The same replay driven by an arbitrary pacing rule, so the old exit condition
/// can be shown failing on the same schedule the new rule finishes.
fn replay(per_drain: &[usize], rule: impl Fn(usize, usize, bool) -> Pace) -> Replay {
    assert!(!per_drain.is_empty(), "a replay needs at least one drain");
    let mut answered = 0;
    let mut delivered = 0;
    // The window sends its first probe before the loop starts.
    let mut in_flight = true;
    for drain in 0..REPLAY_DRAIN_CAP {
        delivered = (delivered + per_drain[drain.min(per_drain.len() - 1)]).min(PIPELINED_CREATES);
        if in_flight {
            in_flight = false;
            answered += 1;
        }
        match rule(answered, delivered, in_flight) {
            Pace::Send => in_flight = true,
            Pace::Done => {
                return Replay {
                    terminated: true,
                    drains: drain + 1,
                    samples: answered,
                    results_delivered: delivered,
                };
            }
            Pace::Wait => {}
        }
    }
    Replay {
        terminated: false,
        drains: REPLAY_DRAIN_CAP,
        samples: answered,
        results_delivered: delivered,
    }
}

/// The termination property, decided without a host: every delivery schedule a
/// batched outbox can produce must end the window, and end it with at least one
/// sample. This is the regression guard for the failure mode the review found --
/// results 7 and 8 landing in one drain used to leave the loop unable to finish,
/// which is a 60 s timeout in the exact class this file was rewritten to remove.
#[test]
fn batched_drains_still_terminate_the_probe_window() {
    for schedule in [
        [1usize, 1, 2, 2, 2].as_slice(), // one result per tick, then batching
        [6, 2].as_slice(),               // the tail lands in one drain
        [4, 4].as_slice(),
        [8].as_slice(),                      // the whole queue drains in one tick
        [1, 1, 1, 1, 1, 1, 1, 1].as_slice(), // a slow host: one per drain
    ] {
        let run = replay_probe_window(schedule);
        assert!(
            run.terminated,
            "{schedule:?}: the probe window never terminated in {} drains -- {} samples, {} of \
             {PIPELINED_CREATES} results delivered",
            run.drains, run.samples, run.results_delivered,
        );
        assert!(
            run.samples >= 1,
            "{schedule:?}: terminated with no round trip sampled inside the window, so `loaded` \
             would be a median over nothing",
        );
    }

    // Teeth: the same replay under the old exit condition must *not* finish on the
    // batched tail, otherwise this test would pass against any rule at all.
    let old_exit_only_on_a_full_sample_set = |answered, delivered, in_flight: bool| {
        if in_flight {
            Pace::Wait
        } else if answered >= LOADED_SAMPLES && delivered >= PIPELINED_CREATES {
            Pace::Done
        } else if answered < LOADED_SAMPLES
            && delivered < PIPELINED_CREATES
            && should_send_next_probe(answered, delivered)
        {
            Pace::Send
        } else {
            Pace::Wait
        }
    };
    for schedule in [[6, 2].as_slice(), [8].as_slice()] {
        let old = replay(schedule, old_exit_only_on_a_full_sample_set);
        assert!(
            !old.terminated,
            "{schedule:?}: the pre-OBI-329 rule finished, so the guard above proves nothing",
        );
        assert!(
            replay_probe_window(schedule).terminated,
            "{schedule:?}: the schedule the review named is not covered by the case above",
        );
    }
}

#[test]
fn probes_are_paced_across_the_whole_hashing_window() {
    // The pacing is what keeps every `loaded` sample inside the window. Guard
    // it directly: no probe may be scheduled after the last result, and the
    // five samples must spread over more than half the queue.
    let thresholds: Vec<usize> = (0..LOADED_SAMPLES)
        .map(|k| {
            (0..PIPELINED_CREATES)
                .find(|delivered| should_send_next_probe(k, *delivered))
                .unwrap_or(PIPELINED_CREATES)
        })
        .collect();
    assert!(
        thresholds.iter().all(|t| *t < PIPELINED_CREATES),
        "{thresholds:?}: a probe scheduled only after the queue drained"
    );
    assert!(
        thresholds[LOADED_SAMPLES - 1] > PIPELINED_CREATES / 2,
        "{thresholds:?}: the probes never reach the back of the queue"
    );
}

/// Every whole line currently readable from `reader`, blocking no longer than
/// one [`POLL`] interval. `closed` is set when the peer ended the stream, which
/// the callers turn into a panic that carries the transcript -- writing to a
/// closed connection only says "Broken pipe", which explains nothing (OBI-329).
struct Drain {
    lines: Vec<String>,
    closed: bool,
}

/// Bytes read off a connection that no newline has completed yet, kept **across
/// polls** for one connection.
///
/// This is what the OBI-329 review caught in the shape of [`Drain`]'s reader.
/// `BufRead::read_line` copies whatever it has buffered into the caller's
/// `String` and *then* discovers the line is unterminated, so it returns
/// `Err(TimedOut)` with those bytes already consumed from the buffer. A caller
/// that allocates a fresh `String` per poll -- which is what a poll loop does --
/// drops them, and the next poll sees only the tail: `hello` arrives as `lo`, an
/// `ok` is never recognised, and the round trip dies at [`READY_DEADLINE`]
/// shouting "this connection is not being answered" about a driver that answered
/// on time. At [`POLL`] = 2 ms that is a coin-flip on a contended runner, and it
/// is the same lost-bytes class as OBI-302. [`Lines::poll`] completes a line only
/// on `\n` and reads bytes rather than `String`s, so a mid-line timeout costs
/// nothing and a non-UTF-8 byte cannot desynchronise the reader either.
#[derive(Default)]
struct Lines {
    carry: Vec<u8>,
}

impl Lines {
    fn poll(&mut self, reader: &mut BufReader<TcpStream>) -> Drain {
        let mut lines = Vec::new();
        let mut closed = false;
        loop {
            // `fill_buf` blocks only when the buffer is empty, which is what makes
            // the socket read timeout act as the poll interval here; `consume`
            // moves those bytes into `carry`, where they wait for a newline.
            match reader.fill_buf() {
                Ok(buf) => {
                    if buf.is_empty() {
                        closed = true;
                        break;
                    }
                    let taken = buf.len();
                    self.carry.extend_from_slice(buf);
                    reader.consume(taken);
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    break;
                }
                Err(err) => panic!("socket read failed: {err}"),
            }
            while let Some(newline) = self.carry.iter().position(|byte| *byte == b'\n') {
                let raw: Vec<u8> = self.carry.drain(..=newline).collect();
                let text = String::from_utf8_lossy(&raw[..raw.len() - 1]);
                let text = text.trim_end_matches('\r');
                if !text.is_empty() {
                    lines.push(text.to_string());
                }
            }
        }
        // A peer that hangs up mid-line still said something; hand it back rather
        // than swallow it, because these transcripts are how the failures get
        // diagnosed.
        if closed && !self.carry.is_empty() {
            let text = String::from_utf8_lossy(&self.carry).to_string();
            self.carry.clear();
            lines.push(text);
        }
        Drain { lines, closed }
    }
}

/// A connected pair on loopback: `peer` writes what a server would, `reader`
/// polls it with the same [`POLL`] timeout the live tests use. Hermetic -- no
/// driver, no ports from the test band, no load -- so the boundary behaviour is
/// asserted deterministically rather than hoped for (OBI-329 review).
fn probe_pair() -> (TcpStream, BufReader<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("loopback addr");
    let peer = TcpStream::connect(addr).expect("connect loopback");
    let accepted = listener.accept().expect("accept loopback").0;
    accepted
        .set_read_timeout(Some(POLL))
        .expect("set poll timeout");
    (peer, BufReader::new(accepted))
}

#[test]
fn a_partial_line_survives_the_poll_boundary() {
    let (mut peer, mut reader) = probe_pair();
    let mut carry = Lines::default();

    // Half a line, then a wait clearly longer than the poll interval, so this is
    // the timeout path and not a fast read.
    peer.write_all(b"hel").expect("write partial line");
    peer.flush().expect("flush partial line");
    std::thread::sleep(POLL * 10);
    let first = carry.poll(&mut reader);
    assert!(
        first.lines.is_empty() && !first.closed,
        "an unterminated line must not be handed back as one: {:?}",
        first.lines,
    );

    // The rest of it. `read_line` had already consumed `hel` out of the buffer on
    // the timed-out poll above, so the reader that dropped it reported `lo` here.
    peer.write_all(b"lo\n").expect("write line tail");
    peer.flush().expect("flush line tail");
    let second = carry.poll(&mut reader);
    assert_eq!(
        second.lines,
        vec!["hello".to_string()],
        "the two halves must come back as the one line the driver sent"
    );
    assert!(!second.closed);

    // And nothing is invented on the poll after that.
    let third = carry.poll(&mut reader);
    assert!(
        third.lines.is_empty() && !third.closed,
        "a completed line must not be re-delivered: {:?}",
        third.lines,
    );
}

#[test]
fn a_needle_split_across_the_poll_boundary_is_still_found() {
    // `read_until_contains` had the same shape, and it is the helper that waits
    // for `Welcome.` / `Exits:` -- so a split line reads as "the driver never
    // booted" rather than as the test losing bytes.
    let (peer, mut reader) = probe_pair();
    // The helper does its own polling, so the boundary has to be crossed while it
    // is waiting: the head goes out, the gap is ten poll intervals, the tail
    // follows. One writer thread, no traffic elsewhere in the process.
    let writer = std::thread::spawn(move || {
        let mut peer = peer;
        peer.write_all(b"Welcome").expect("write needle head");
        peer.flush().expect("flush needle head");
        std::thread::sleep(POLL * 10);
        peer.write_all(b".\n").expect("write needle tail");
        peer.flush().expect("flush needle tail");
    });
    let transcript = read_until_contains(&mut reader, "Welcome.", READY_DEADLINE);
    writer.join().expect("writer thread");
    assert!(
        transcript.contains("Welcome."),
        "{transcript:?}: `read_until_contains` returned without the needle it waited for"
    );
}

/// Append `lines` to a transcript for failure messages.
fn note(transcript: &mut String, lines: &[String]) {
    for line in lines {
        transcript.push_str(line);
        transcript.push('\n');
    }
}

fn gaps(at: &[Instant]) -> Vec<Duration> {
    at.windows(2).map(|w| w[1].duration_since(w[0])).collect()
}

/// The middle of `samples`. With five or seven samples this is robust against
/// the odd scheduling spike a shared runner throws at any single round trip.
fn median(samples: &[Duration]) -> Duration {
    assert!(
        !samples.is_empty(),
        "median of no samples -- the measurement collected nothing"
    );
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

/// `count` `look`/`ok` round trips on `reader`, each bounded only by
/// [`READY_DEADLINE`].
fn round_trips(reader: &mut BufReader<TcpStream>, count: usize) -> Vec<Duration> {
    let mut out = Vec::with_capacity(count);
    let mut carry = Lines::default();
    for i in 0..count {
        if i > 0 {
            // Space the samples out: back-to-back round trips on one connection
            // can all land in the same world-thread wakeup.
            std::thread::sleep(Duration::from_millis(20));
        }
        out.push(round_trip(reader, &mut carry));
    }
    out
}

fn round_trip(reader: &mut BufReader<TcpStream>, carry: &mut Lines) -> Duration {
    let started = Instant::now();
    send_line(reader, PROBE);
    loop {
        let drain = carry.poll(reader);
        if drain.lines.iter().any(|line| line == "ok") {
            return started.elapsed();
        }
        assert!(!drain.closed, "peer closed the connection mid-measurement");
        assert!(
            started.elapsed() < READY_DEADLINE,
            "no reply to `{PROBE}` within {READY_DEADLINE:?}: this connection is not being \
             answered at all"
        );
    }
}

fn send_line(reader: &mut BufReader<TcpStream>, line: &str) {
    let stream = reader.get_mut();
    stream
        .write_all(line.as_bytes())
        .unwrap_or_else(|err| panic!("write command `{line}` failed: {err}"));
    stream
        .write_all(b"\n")
        .unwrap_or_else(|err| panic!("write newline for `{line}` failed: {err}"));
    stream
        .flush()
        .unwrap_or_else(|err| panic!("flush command `{line}` failed: {err}"));
}

fn read_until_contains(
    reader: &mut BufReader<TcpStream>,
    needle: &str,
    timeout: Duration,
) -> String {
    let started = Instant::now();
    let mut transcript = String::new();
    let mut carry = Lines::default();

    loop {
        if started.elapsed() > timeout {
            panic!(
                "timed out waiting for `{needle}` after {timeout:?}. Transcript so far:\n\
                 {transcript}"
            );
        }

        let drain = carry.poll(reader);
        note(&mut transcript, &drain.lines);
        if transcript.contains(needle) {
            return transcript;
        }
        // Only a close that left the needle unsaid is a failure: a driver that
        // hangs up right after the line you were waiting for has answered.
        if drain.closed {
            panic!(
                "connection closed while waiting for `{needle}`. Transcript so far:\n{transcript}"
            );
        }
    }
}

fn connect_with_retry(addr: &str, timeout: Duration) -> TcpStream {
    let deadline = Instant::now() + timeout;
    loop {
        match TcpStream::connect(addr) {
            Ok(mut stream) => {
                drain_telnet_preamble(&mut stream);
                return stream;
            }
            Err(err) if Instant::now() < deadline => {
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::TimedOut
                ) {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                panic!("failed to connect to {addr}: {err}");
            }
            Err(err) => panic!("failed to connect to {addr} before timeout: {err}"),
        }
    }
}

/// `loom serve` opens with startup telnet option negotiation (OBI-26: `DO
/// NAWS`, `DO TTYPE`, `WILL GMCP`, `WILL MSSP` -- 12 bytes, none of them
/// valid UTF-8 on their own) before anything text-protocol shows up on the
/// wire. These tests read lines as UTF-8 text, so they don't speak telnet
/// back; just drop the fixed-size preamble rather than negotiate.
fn drain_telnet_preamble(stream: &mut TcpStream) {
    use std::io::Read;
    let mut preamble = [0_u8; 12];
    stream
        .read_exact(&mut preamble)
        .expect("read telnet negotiation preamble");
}

fn reserve_local_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("read local addr").port()
}

struct LoomServer {
    child: Child,
}

impl LoomServer {
    fn spawn(mudlib: &Path, bind: &str) -> Self {
        let loom_bin = std::env::var("CARGO_BIN_EXE_loom-cli")
            .or_else(|_| std::env::var("CARGO_BIN_EXE_loom_cli"))
            .expect("cargo binary path for loom-cli");
        let http_port = reserve_local_port();

        let child = Command::new(loom_bin)
            .arg("serve")
            .arg("--mudlib")
            .arg(mudlib)
            .env("LOOM_TELNET_ADDR", bind)
            .env("LOOM_HTTP_ADDR", format!("127.0.0.1:{http_port}"))
            .env_remove("DATABASE_URL")
            .env_remove("LOOM_SMOKE_DATABASE_URL")
            .env("RUST_LOG", "")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn loom serve");

        Self { child }
    }

    fn assert_alive(&mut self) {
        if let Some(status) = self.child.try_wait().expect("poll server process") {
            panic!("loom server exited early with status {status}");
        }
    }
}

impl Drop for LoomServer {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

static N: AtomicU32 = AtomicU32::new(0);

fn scratch(tag: &str) -> PathBuf {
    let n = N.fetch_add(1, Ordering::SeqCst);
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir scratch");
    dir
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("mkdir destination");
    for entry in std::fs::read_dir(from).expect("read fixture directory") {
        let path = entry.expect("fixture entry").path();
        let dest = to.join(path.file_name().expect("fixture filename"));
        if path.is_dir() {
            copy_dir(&path, &dest);
        } else {
            std::fs::copy(&path, &dest).expect("copy fixture file");
        }
    }
}

fn fixture(name: &str) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let dir = scratch(name);
    copy_dir(&src, &dir);
    dir
}
