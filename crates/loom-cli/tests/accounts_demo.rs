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
//!   asserting on an empty queue.

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

/// Command sent to give the world thread something to drain on, and to probe
/// connection `b`'s latency. `look` costs the driver no hashing and no DB round
/// trip. It stands in for `NetEvent::Tick` (OBI-82, not landed yet): without a
/// periodic tick nothing re-polls the account backend's result channel on an
/// otherwise idle connection, so these tests nudge often enough that the drain
/// in `spawn_world_thread` runs promptly. Once OBI-82 lands the nudges become
/// redundant, not wrong.
const NUDGE: &str = "look";

/// How often to send [`NUDGE`] -- derived from the driver's own input rate limit,
/// never guessed.
///
/// `loom_net` gives every connection a token bucket (`NetConfig::rate_limit_*`)
/// that costs one token per input line, and disconnects the player when it runs
/// out. This file used to nudge every 100 ms, i.e. 10 Hz against a 5 Hz refill
/// with a 20-token burst: the burst buys about two seconds, after which the
/// *test* is disconnected by its own traffic. That is the real reason the old
/// hard-coded 2 s budgets appeared sufficient -- waiting longer than that was
/// never an option, so a slow CI runner could only time out.
fn nudge_interval() -> Duration {
    let limit = loom_net::NetConfig::default().rate_limit_per_second;
    let sustained = Duration::from_secs_f64(1.0 / limit);
    // Half a refill period slower than the limit, so the bucket always has more
    // tokens coming back than this test spends -- even at startup, when the
    // pipelined creates have already taken a bite out of the burst.
    sustained + sustained / 2
}

#[test]
fn nudges_stay_under_the_drivers_own_input_rate_limit() {
    // The cadence has to survive a whole hashing window, not just a burst. If
    // someone raises the driver's limit this test still passes; if someone
    // lowers it, or nudges faster here, this fails instead of a build losing
    // its connection mid-test.
    let config = loom_net::NetConfig::default();
    let per_second = 1.0 / nudge_interval().as_secs_f64();
    assert!(
        per_second < config.rate_limit_per_second,
        "nudging at {per_second:.2} lines/s against a {} lines/s limit: the driver would drop \
         the connection",
        config.rate_limit_per_second,
    );

    // Worst realistic window: one hash per second for every pipelined create,
    // plus the probes. Everything the test sends on one connection over that
    // window must fit the burst plus what the bucket refills in the same time.
    let window = Duration::from_secs(PIPELINED_CREATES as u64);
    let lines_sent = window.as_secs_f64() * per_second + PIPELINED_CREATES as f64;
    let affordable =
        f64::from(config.rate_limit_burst) + window.as_secs_f64() * config.rate_limit_per_second;
    assert!(
        lines_sent <= affordable,
        "{lines_sent:.1} lines over a {window:?} window against {affordable:.1} affordable"
    );
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
    let out = poll_until_contains(&mut a, "result 1 ", READY_DEADLINE);
    assert!(
        out.contains("result 1 true "),
        "expected a successful create: {out}"
    );

    send_line(&mut a, "create legolas hunter2pass");
    let out = poll_until_contains(&mut a, "result 2 ", READY_DEADLINE);
    assert!(
        out.contains("result 2 false exists"),
        "duplicate account must be rejected as `exists`: {out}"
    );

    send_line(&mut a, "login legolas wrong-password");
    let out = poll_until_contains(&mut a, "result 3 ", READY_DEADLINE);
    assert!(
        out.contains("result 3 false bad_credentials"),
        "wrong password must be `bad_credentials`: {out}"
    );

    send_line(&mut a, "login legolas hunter2pass");
    let out = poll_until_contains(&mut a, "result 4 ", READY_DEADLINE);
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
    send_line(b, NUDGE);
    let first_probe_sent = Instant::now();
    let mut probe_sent = Some(first_probe_sent);
    let mut last_input = first_probe_sent;

    loop {
        let Drain {
            lines: a_lines,
            closed: a_closed,
        } = drain(a);
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
        } = drain(b);
        note(&mut transcript_b, &b_lines);

        if a_closed || b_closed {
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

        if let Some(sent) = probe_sent {
            if b_lines.iter().any(|line| line == "ok") {
                probe_rtt.push(sent.elapsed());
                probe_sent = None;
                if probe_rtt.len() == 1 {
                    results_before_first_probe = result_arrivals.len();
                }
            }
        } else if probe_rtt.len() < LOADED_SAMPLES
            && results.len() < PIPELINED_CREATES
            && should_send_next_probe(probe_rtt.len(), result_arrivals.len())
        {
            send_line(b, NUDGE);
            probe_sent = Some(Instant::now());
            last_input = Instant::now();
        }

        if probe_rtt.len() == LOADED_SAMPLES && results.len() == PIPELINED_CREATES {
            break;
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
        if last_input.elapsed() >= nudge_interval() {
            // Nothing sent, nothing arriving: keep giving the world thread a
            // reason to run the result drain (OBI-82).
            send_line(a, NUDGE);
            last_input = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    assert!(
        !probe_rtt.is_empty() && !result_arrivals.is_empty(),
        "the probe window collected nothing at all"
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

fn drain(reader: &mut BufReader<TcpStream>) -> Drain {
    let mut lines = Vec::new();
    let mut closed = false;
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                closed = true;
                return Drain { lines, closed };
            }
            Ok(_) => {
                let text = line.trim_end_matches(['\r', '\n']);
                if !text.is_empty() {
                    lines.push(text.to_string());
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Drain { lines, closed };
            }
            Err(err) => panic!("socket read failed: {err}"),
        }
    }
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
    for i in 0..count {
        if i > 0 {
            // Space the samples out: back-to-back round trips on one connection
            // can all land in the same world-thread wakeup.
            std::thread::sleep(Duration::from_millis(20));
        }
        out.push(round_trip(reader));
    }
    out
}

fn round_trip(reader: &mut BufReader<TcpStream>) -> Duration {
    let started = Instant::now();
    send_line(reader, NUDGE);
    loop {
        let drain = drain(reader);
        assert!(!drain.closed, "peer closed the connection mid-measurement");
        if drain.lines.iter().any(|line| line == "ok") {
            return started.elapsed();
        }
        assert!(
            started.elapsed() < READY_DEADLINE,
            "no reply to `{NUDGE}` within {READY_DEADLINE:?}: this connection is not being \
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

/// [`read_until_contains`], but also sends [`NUDGE`] on `reader` every
/// [`nudge_interval`] while waiting, so an idle connection still gives the world
/// thread something to drain (see [`NUDGE`]).
fn poll_until_contains(
    reader: &mut BufReader<TcpStream>,
    needle: &str,
    timeout: Duration,
) -> String {
    let started = Instant::now();
    let mut transcript = String::new();
    let mut last_nudge = started - Duration::from_secs(1);

    loop {
        if transcript.contains(needle) {
            return transcript;
        }
        if started.elapsed() > timeout {
            panic!(
                "timed out waiting for `{needle}` after {timeout:?}. Transcript so far:\n\
                 {transcript}"
            );
        }
        if last_nudge.elapsed() >= nudge_interval() {
            send_line(reader, NUDGE);
            last_nudge = Instant::now();
        }

        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => panic!(
                "connection closed while waiting for `{needle}`. Transcript so far:\n{transcript}"
            ),
            Ok(_) => transcript.push_str(&line.replace("\r\n", "\n")),
            Err(err)
                if err.kind() == std::io::ErrorKind::TimedOut
                    || err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => panic!(
                "socket read failed while waiting for `{needle}`: {err}. Transcript so far:\n\
                 {transcript}"
            ),
        }
    }
}

fn read_until_contains(
    reader: &mut BufReader<TcpStream>,
    needle: &str,
    timeout: Duration,
) -> String {
    let started = Instant::now();
    let mut transcript = String::new();

    loop {
        if started.elapsed() > timeout {
            panic!(
                "timed out waiting for `{needle}` after {timeout:?}. Transcript so far:\n\
                 {transcript}"
            );
        }

        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => panic!(
                "connection closed while waiting for `{needle}`. Transcript so far:\n{transcript}"
            ),
            Ok(_) => {
                let normalized = line.replace("\r\n", "\n");
                transcript.push_str(&normalized);
                if transcript.contains(needle) {
                    return transcript;
                }
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::TimedOut
                    || err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => panic!(
                "socket read failed while waiting for `{needle}`: {err}. Transcript so far:\n\
                 {transcript}"
            ),
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
