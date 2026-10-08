// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! G1 / spec M-LSP-4 thread-count guard, in a process of its own (OBI-317).
//!
//! **This file must contain exactly one `#[test]`.** Cargo compiles every file
//! directly under `tests/` into its own test binary and runs one binary per
//! process, so this guard gets a process holding a single LSP session — which
//! is the only thing that makes the number it reads mean anything. Add a second
//! session-starting test here and you have re-created the flake this file
//! exists to remove; put it in `lsp_integration.rs` instead.
//!
//! Why it was flaky: `support::thread_ids()` reads `/proc/self/task`, a
//! *process-wide* thread list, while `TestClient::start()` runs a server
//! in-process (6 threads: `run()` + `MAX_CONCURRENT_REQUESTS` workers + 1
//! timer). Sharing `lsp_integration.rs` with nine other tests meant any
//! sibling session starting or stopping inside the measurement window moved
//! the count by more than the guard's 8-thread slack, and the guard failed on
//! code that had not changed (CI 37674762546 / 37674844425: baseline 51 there
//! against 15 on a dev machine, both with a fixed-size pool). No slack is
//! correct against a process-wide count, so the measurement moves instead.

mod support;

use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use serde_json::json;

use support::{TestClient, thread_ids};

/// The guard's tolerance, deliberately **unchanged** from OBI-228: the pool is
/// 4 workers + 1 timer, so 8 absorbs one whole pool and nothing more. This is
/// not the number that made the guard flaky — process-wide measurement was —
/// so it stays. Note the positive control below cannot police it either (it
/// scales with `SLACK`), so treat any change here as a review question: what
/// would the extra tolerance hide?
const SLACK: usize = 8;

/// Trivial (unknown-method, so never compiled) requests to pipeline.
const REQUESTS: usize = 10_000;

/// Threads the positive control parks on purpose. Must stay above [`SLACK`].
const CONTROL_THREADS: usize = SLACK + 4;

/// A scope tripwire, not a proof. The count is process-wide, so it is only
/// "one server's thread count" if this process really holds one server. It
/// measures 8 here (6 session threads — see `crates/loom-lsp/src/server.rs` —
/// plus libtest's main thread and the test thread); the slack above that
/// leaves room for a future std/harness helper thread rather than guessing
/// "exactly 8" and failing the lane when one appears. The hard rule — this
/// binary contains exactly one `#[test]` — is checked statically in CI's
/// `hygiene` job, which is the only place that can enforce it without
/// guessing what the harness adds to the number.
const SINGLE_SESSION_MAX_THREADS: usize = 20;

/// Spec `docs/threat-model-phase2.md` §6.3 **M-LSP-4**, CTO re-review of
/// OBI-168 (G1, OBI-228): a client pipelining a flood of *trivial* (here:
/// unknown-method, so they never even reach the compiler) requests must
/// not grow the server's OS thread count. Before this fix, every job got
/// its own sleeping 5 s deadline-timer thread, spawned from inside the
/// worker before the (microsecond-fast) real work even started, so this
/// exact scenario created one thread per request. Now there is exactly
/// one timer thread for the whole session, so the thread count should
/// stay essentially flat.
///
/// OBI-317 re-homed it: the *assertion* is the same one, only measured
/// somewhere it can actually see one server.
#[test]
fn g1_pipelining_many_trivial_requests_does_not_grow_the_thread_count() {
    let mut c = TestClient::start();
    // Let the fixed-size worker pool and the one timer thread actually
    // spin up before baselining -- the first request's dispatch starts
    // them lazily relative to test start, not `TestClient::start` itself.
    let id = c.send_request("loom-lsp/warmup", json!({}));
    let resp = c.recv_response(id);
    assert!(resp.response_result.is_err(), "unknown method must error");
    std::thread::sleep(Duration::from_millis(200));
    let baseline = thread_ids();

    // Scope check: `/proc/self/task` is process-wide, so "the server did not
    // leak" is only what this reads if this process contains one server. The
    // cap is deliberately loose -- one extra session (14 threads) still fits
    // under it, because guessing at a harness's thread count is the same
    // mistake that made this guard flaky. It shouts at gross contamination
    // only; the "exactly one #[test]" rule itself lives in CI's `hygiene` job.
    assert!(
        baseline.len() <= SINGLE_SESSION_MAX_THREADS,
        "harness precondition (OBI-317): this binary is meant to host exactly one \
         in-process LSP session, i.e. at most {SINGLE_SESSION_MAX_THREADS} threads \
         (6 server + harness); the baseline was {}. Something else is sharing the \
         process, and a process-wide count cannot separate its threads from the \
         server's — move the other test to lsp_integration.rs.",
        baseline.len()
    );

    for _ in 0..REQUESTS {
        let id = c.send_request("loom-lsp/trivial", json!({}));
        let resp = c.recv_response(id);
        assert!(resp.response_result.is_err(), "unknown method must error");
    }

    // Give any (incorrectly) spawned per-request threads a moment to
    // exist before counting -- they'd be alive immediately on spawn, this
    // just absorbs scheduling jitter.
    std::thread::sleep(Duration::from_millis(200));
    let after = thread_ids();
    let leaked: Vec<u32> = after.difference(&baseline).copied().collect();
    assert!(
        leaked.len() <= SLACK,
        "thread count grew from {} to {} after pipelining {REQUESTS} trivial requests \
         (G1, M-LSP-4): {leaked:?} appeared, more than the {SLACK}-thread slack \
         (4 workers + 1 timer + margin), so this is a per-request thread leak",
        baseline.len(),
        after.len(),
    );

    // Positive control (OBI-317): prove the instrument is not blind.
    //
    // Isolating the measurement also creates a new way to pass for the wrong
    // reason — if reading `/proc/self/task` ever stopped reflecting this
    // process, the guard above would report zero leaks forever. So park
    // CONTROL_THREADS live threads, take the same measurement, and require it
    // to cross the very threshold the guard tolerates. The two barriers make
    // that deterministic rather than a sleep race: once `arrive.wait()`
    // returns *here*, every control thread exists and is blocked until *this*
    // thread reaches `release.wait()`, so the count cannot race their exit.
    let arrive = Arc::new(Barrier::new(CONTROL_THREADS + 1));
    let release = Arc::new(Barrier::new(CONTROL_THREADS + 1));
    let handles: Vec<_> = (0..CONTROL_THREADS)
        .map(|_| {
            let (arrive, release) = (arrive.clone(), release.clone());
            std::thread::spawn(move || {
                arrive.wait();
                release.wait();
            })
        })
        .collect();
    arrive.wait();
    let polluted = thread_ids();
    release.wait();
    for h in handles {
        h.join().unwrap();
    }

    let seen = polluted.difference(&after).count();
    assert!(
        seen > SLACK,
        "harness self-check (OBI-317): parked {CONTROL_THREADS} threads and the measurement \
         window saw only {seen} of them, at or under the +{SLACK} slack the G1 guard \
         tolerates. `thread_ids()` is not seeing this process's threads, so the guard above \
         is vacuous — fix the instrument before trusting a green run."
    );

    // ...and that it sees them leave. Every control thread was `join()`ed, so
    // none may still be listed once the kernel catches up — but `/proc` lags
    // `pthread_join` by a scheduling tick or two (measured here: 1-2 of the 12
    // still appeared immediately after the joins returned, all gone within
    // 100 ms), so this polls against a deadline instead of asserting one exact
    // snapshot. Same reason the flood guard gets slack: the instrument is
    // asynchronous. A thread that never leaves the list is the leak this
    // control would be reporting.
    let mut lingering: Vec<u32> = thread_ids().difference(&after).copied().collect();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !lingering.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
        lingering = thread_ids().difference(&after).copied().collect();
    }
    assert!(
        lingering.is_empty(),
        "harness self-check (OBI-317): {} of the {CONTROL_THREADS} control threads were still \
         in /proc/self/task 5 s after `join()` returned: {lingering:?}. Either the instrument \
         is wedged (and the G1 guard above is measuring nothing) or joined threads really do \
         outlive their handles here — re-check before trusting a green run.",
        lingering.len()
    );
}
