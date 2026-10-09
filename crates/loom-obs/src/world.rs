// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! World-thread stall attribution (OBI-344).
//!
//! Exit criterion E1.1 measures command -> prompt latency from the *bot's*
//! side. When that distribution grows a tail, the bot cannot tell you
//! whether the world thread stopped answering, the net task stopped
//! draining, the bot's own runtime was starved, or nothing on the server
//! moved at all. Before OBI-344 the driver's only server-side signal was
//! the end-of-run `/metrics` scrape: a cumulative counter, so a 400 ms
//! stall somewhere in a 90 s run left no trace of *when* it happened and
//! could not be lined up with the samples that paid for it.
//!
//! [`WorldLoopProbe`] closes that gap. It is driven by the world thread's
//! event loop (`loom-cli`'s `spawn_world_thread`) once per iteration, and
//! publishes:
//!
//! - `loom_world_loop_iterations_total` -- every iteration handled.
//! - `loom_world_loop_ticks_total` -- the world's **tick id**, i.e. how
//!   many `World::tick` passes have completed. This is the sequence number
//!   a stall report names ("the tail sits in tick 412..415").
//! - `loom_world_loop_duration_ms_max` -- the slowest *processing*
//!   iteration since boot (a `World::tick`/`input` that ran long).
//! - `loom_world_loop_gap_ms_max` -- the slowest *wait* between two
//!   iterations since boot. The loop is woken by a 100 ms tick timer, so a
//!   gap much larger than that means the world thread was not running at
//!   all (descheduled, blocked on a full channel, page-faulting) even when
//!   no single iteration looked slow.
//! - `loom_world_loop_stalls_total{kind}` -- iterations that breached the
//!   threshold, split by what was being handled (`tick`, `input`,
//!   `connect`, `disconnect`, `negotiation`, `drain`).
//! - `loom_world_loop_stall_ms_total` -- cumulative milliseconds spent
//!   inside stalled iterations. `delta(stall_ms) / delta(stalls)` over a
//!   scrape interval is that interval's mean stall length.
//! - `loom_world_loop_last_stall_unix_ms`,
//!   `loom_world_loop_last_stall_duration_ms`,
//!   `loom_world_loop_last_stall_tick` -- wall-clock time, length, and the
//!   tick id of the most recent breach, so a scraper polling at 1 Hz can
//!   bracket a stall to within one polling interval without keeping a
//!   per-stall series.
//!
//! and `loom_net_command_blocked_total` /
//! `loom_net_command_blocked_last_unix_ms` /
//! `loom_net_command_blocked_ms_max`, recorded by [`NetCommandProbe`] from
//! the world thread's `Host` implementation: `blocking_send` on the
//! world -> net command channel is the one place in the serve path where
//! the world thread can wait on the net task, and a full command channel
//! holds up every other connection's output.
//!
//! All of it is `metrics`-facade recording into the process-global
//! recorder: no allocation per iteration beyond the label strings the
//! facade already interns, no locks held across the world thread, and no
//! I/O. Nothing here awaits.

use std::time::{Duration, Instant};

/// Env var read by [`WorldLoopProbe::from_env`] and
/// [`NetCommandProbe::from_env`]: the stall threshold in milliseconds.
/// Defaults to [`DEFAULT_STALL_THRESHOLD_MS`].
pub const STALL_THRESHOLD_ENV: &str = "LOOM_WORLD_STALL_MS";

/// The default stall threshold: E1.1's own SLA number (50 ms), so anything
/// the probe calls a stall is by definition long enough to be on the hook
/// for a tail sample.
pub const DEFAULT_STALL_THRESHOLD_MS: u64 = 50;

/// What the world thread's event loop was doing during a measured
/// iteration. The `kind` label on `loom_world_loop_stalls_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorldEventKind {
    /// `World::tick` plus the per-tick drains that ride on it.
    Tick,
    /// `World::input` for one line from one session.
    Input,
    /// `World::connect`.
    Connect,
    /// `World::disconnect`.
    Disconnect,
    /// Telnet negotiation side-channel (NAWS/TTYPE/GMCP).
    Negotiation,
    /// An iteration that only drained side channels (db/admin/
    /// recompile/file-op/snapshot/roles), or a copyover request.
    Drain,
}

impl WorldEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tick => "tick",
            Self::Input => "input",
            Self::Connect => "connect",
            Self::Disconnect => "disconnect",
            Self::Negotiation => "negotiation",
            Self::Drain => "drain",
        }
    }
}

/// Stall threshold resolution: `LOOM_WORLD_STALL_MS`, else `default`.
/// A malformed or `0` value falls back to the default -- a zero threshold
/// would flag every tick and flood the log.
fn resolve_threshold(env: Option<&str>, default: u64) -> Duration {
    Duration::from_millis(
        env.and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|ms| *ms > 0)
            .unwrap_or(default),
    )
}

/// Per-iteration observer for the world thread's event loop. See the
/// [module docs](self).
///
/// The clock is always injected (`now`, `now_unix_ms` are parameters of
/// the record methods) so the stall decision is testable without sleeping.
#[derive(Debug)]
pub struct WorldLoopProbe {
    threshold: Duration,
    iterations: u64,
    ticks: u64,
    /// When the most recent iteration *finished*; the distance to the next
    /// iteration's start is the gap the world thread spent not running.
    last_iter_end: Option<Instant>,
    duration_ms_max: u64,
    gap_ms_max: u64,
    /// Suppresses the per-stall `warn!` so a pathological loop (a stall on
    /// every tick) logs at most once per [`Self::LOG_INTERVAL`] while the
    /// counters keep counting every breach.
    last_stall_log: Option<Instant>,
}

/// Minimum spacing between per-stall `warn!` lines: the counters always
/// count, only the log is rate limited.
const STALL_LOG_INTERVAL: Duration = Duration::from_millis(5_000);

/// Rate-limited logging helper: `true` (and records the sighting) when
/// `last` is unset or at least `interval` older than `now`.
fn log_now(last: &mut Option<Instant>, now: Instant, interval: Duration) -> bool {
    match *last {
        Some(prev) if now.duration_since(prev) < interval => false,
        _ => {
            *last = Some(now);
            true
        }
    }
}

impl WorldLoopProbe {
    pub fn new(threshold: Duration) -> Self {
        Self {
            threshold,
            iterations: 0,
            ticks: 0,
            last_iter_end: None,
            duration_ms_max: 0,
            gap_ms_max: 0,
            last_stall_log: None,
        }
    }

    /// `LOOM_WORLD_STALL_MS` (see [`STALL_THRESHOLD_ENV`]), else 50 ms.
    pub fn from_env() -> Self {
        Self::new(resolve_threshold(
            std::env::var(STALL_THRESHOLD_ENV).ok().as_deref(),
            DEFAULT_STALL_THRESHOLD_MS,
        ))
    }

    pub fn threshold(&self) -> Duration {
        self.threshold
    }

    /// Number of `World::tick` passes recorded so far -- the tick id a
    /// stall report names.
    pub fn ticks(&self) -> u64 {
        self.ticks
    }

    /// Record one completed loop iteration.
    ///
    /// `started` is the `Instant` captured immediately *before* the work
    /// (i.e. right after the event was received), `finished` the `Instant`
    /// after it; `now_unix_ms` is wall-clock milliseconds since the epoch
    /// at `finished`, stamped onto the last-stall gauge so an external
    /// scraper can place the stall in time.
    ///
    /// `Ok(true)` when the iteration breached the threshold.
    pub fn record_iteration(
        &mut self,
        kind: WorldEventKind,
        started: Instant,
        finished: Instant,
        now_unix_ms: u64,
    ) -> bool {
        let duration = finished.saturating_duration_since(started);
        let gap = self
            .last_iter_end
            .map(|prev| finished.saturating_duration_since(prev))
            .unwrap_or(Duration::ZERO);
        self.last_iter_end = Some(finished);
        self.iterations += 1;
        if kind == WorldEventKind::Tick {
            self.ticks += 1;
        }

        let duration_ms = duration.as_millis() as u64;
        // The gap includes the work itself; what matters for starvation is
        // the time the loop was *not* processing, so subtract it. A
        // negative result (a reordered clock) clamps to zero.
        let idle = gap.saturating_sub(duration);
        let idle_ms = idle.as_millis() as u64;

        metrics::counter!("loom_world_loop_iterations_total").increment(1);
        if kind == WorldEventKind::Tick {
            metrics::counter!("loom_world_loop_ticks_total").increment(1);
        }
        if duration_ms > self.duration_ms_max {
            self.duration_ms_max = duration_ms;
            metrics::gauge!("loom_world_loop_duration_ms_max").set(duration_ms as f64);
        }
        if idle_ms > self.gap_ms_max {
            self.gap_ms_max = idle_ms;
            metrics::gauge!("loom_world_loop_gap_ms_max").set(idle_ms as f64);
        }

        let stalled = duration > self.threshold;
        if stalled {
            metrics::counter!("loom_world_loop_stalls_total", "kind" => kind.as_str()).increment(1);
            metrics::counter!("loom_world_loop_stall_ms_total").increment(duration_ms);
            metrics::gauge!("loom_world_loop_last_stall_unix_ms").set(now_unix_ms as f64);
            metrics::gauge!("loom_world_loop_last_stall_duration_ms").set(duration_ms as f64);
            // The tick id the stalled iteration ran under: ticks are only
            // counted when a `World::tick` completes, so this is "tick N
            // was the last one finished at the time of the stall".
            metrics::gauge!("loom_world_loop_last_stall_tick").set(self.ticks as f64);
            if log_now(&mut self.last_stall_log, finished, STALL_LOG_INTERVAL) {
                tracing::warn!(
                    kind = kind.as_str(),
                    tick = self.ticks,
                    duration_ms,
                    idle_ms,
                    threshold_ms = self.threshold.as_millis() as u64,
                    "world thread iteration exceeded the stall threshold (OBI-344)"
                );
            }
        }
        stalled
    }

    #[cfg(test)]
    fn for_test(threshold: Duration) -> Self {
        Self::new(threshold)
    }
}

/// Observer for the world -> net command channel's `blocking_send` calls
/// (see [`NetCommandProbe`]).
#[derive(Debug)]
pub struct NetCommandProbe {
    threshold: Duration,
    blocked_ms_max: u64,
    last_block_log: Option<Instant>,
}

impl NetCommandProbe {
    pub fn new(threshold: Duration) -> Self {
        Self {
            threshold,
            blocked_ms_max: 0,
            last_block_log: None,
        }
    }

    /// `LOOM_WORLD_STALL_MS` too: the command channel is the same
    /// world-thread stall budget seen from the other end.
    pub fn from_env() -> Self {
        Self::new(resolve_threshold(
            std::env::var(STALL_THRESHOLD_ENV).ok().as_deref(),
            DEFAULT_STALL_THRESHOLD_MS,
        ))
    }

    /// Record one `blocking_send` that took `waited` to complete. `now` is
    /// the monotonic clock at completion, `now_unix_ms` its wall-clock
    /// equivalent. A send that completed without the channel ever being
    /// full (`waited <= threshold`) only costs a subtraction.
    pub fn record_send(&mut self, waited: Duration, now: Instant, now_unix_ms: u64) {
        if waited <= self.threshold {
            return;
        }
        let waited_ms = waited.as_millis() as u64;
        metrics::counter!("loom_net_command_blocked_total").increment(1);
        metrics::counter!("loom_net_command_blocked_ms_total").increment(waited_ms);
        metrics::gauge!("loom_net_command_blocked_last_unix_ms").set(now_unix_ms as f64);
        if waited_ms > self.blocked_ms_max {
            self.blocked_ms_max = waited_ms;
            metrics::gauge!("loom_net_command_blocked_ms_max").set(waited_ms as f64);
        }
        if log_now(&mut self.last_block_log, now, STALL_LOG_INTERVAL) {
            tracing::warn!(
                waited_ms,
                threshold_ms = self.threshold.as_millis() as u64,
                "world thread blocked sending to the net task: the command channel was full (OBI-344)"
            );
        }
    }
}

/// Milliseconds since the Unix epoch, saturated (the driver uses `0` for
/// "unknown" elsewhere, see `World::note_error`).
pub fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(base: Instant, m: u64) -> Instant {
        base + Duration::from_millis(m)
    }

    #[test]
    fn resolve_threshold_defaults_on_unset_zero_or_garbage() {
        assert_eq!(resolve_threshold(None, 50), Duration::from_millis(50));
        assert_eq!(resolve_threshold(Some("0"), 50), Duration::from_millis(50));
        assert_eq!(
            resolve_threshold(Some("nonsense"), 50),
            Duration::from_millis(50)
        );
        assert_eq!(
            resolve_threshold(Some(" 120 "), 50),
            Duration::from_millis(120)
        );
    }

    #[test]
    fn iteration_under_threshold_is_not_a_stall() {
        let base = Instant::now();
        let mut probe = WorldLoopProbe::for_test(Duration::from_millis(50));
        let stalled = probe.record_iteration(WorldEventKind::Tick, ms(base, 0), ms(base, 49), 1);
        assert!(!stalled);
        assert_eq!(probe.ticks(), 1);
    }

    #[test]
    fn slow_tick_counts_a_stall_and_advances_the_tick_id() {
        let base = Instant::now();
        let mut probe = WorldLoopProbe::for_test(Duration::from_millis(50));
        assert!(probe.record_iteration(WorldEventKind::Tick, ms(base, 0), ms(base, 240), 240));
        assert_eq!(probe.ticks(), 1);
        assert_eq!(probe.duration_ms_max, 240);
        // A later fast tick does not reset the high-water mark, and the
        // tick id keeps counting: this is what a scraper diffs.
        assert!(!probe.record_iteration(WorldEventKind::Tick, ms(base, 340), ms(base, 345), 345));
        assert_eq!(probe.ticks(), 2);
        assert_eq!(probe.duration_ms_max, 240);
        // Previous iteration ended at 240, this one ended at 345 and ran
        // for 5 ms: the loop was not working for 100 ms. Measured against
        // the *previous end*, not the previous start, so a slow iteration
        // never inflates the gap as well as the duration.
        assert_eq!(probe.gap_ms_max, 100);
    }

    #[test]
    fn starvation_between_iterations_shows_in_the_gap_not_the_duration() {
        let base = Instant::now();
        let mut probe = WorldLoopProbe::for_test(Duration::from_millis(50));
        // Two 1 ms iterations 400 ms apart: the world thread was not
        // running (or was starved of events) for 399 ms of that.
        assert!(!probe.record_iteration(WorldEventKind::Input, ms(base, 0), ms(base, 1), 1));
        assert!(!probe.record_iteration(WorldEventKind::Input, ms(base, 400), ms(base, 401), 401));
        assert_eq!(probe.duration_ms_max, 1);
        assert_eq!(probe.gap_ms_max, 399);
    }

    #[test]
    fn non_tick_iterations_do_not_advance_the_tick_id() {
        let base = Instant::now();
        let mut probe = WorldLoopProbe::for_test(Duration::from_millis(50));
        probe.record_iteration(WorldEventKind::Input, ms(base, 0), ms(base, 10), 10);
        probe.record_iteration(WorldEventKind::Drain, ms(base, 20), ms(base, 30), 30);
        assert_eq!(probe.ticks(), 0);
        assert_eq!(probe.iterations, 2);
    }

    #[test]
    fn net_command_send_only_counts_past_its_threshold() {
        let base = Instant::now();
        let mut probe = NetCommandProbe::new(Duration::from_millis(50));
        probe.record_send(Duration::from_millis(49), ms(base, 49), 49);
        assert_eq!(probe.blocked_ms_max, 0);
        probe.record_send(Duration::from_millis(300), ms(base, 350), 350);
        assert_eq!(probe.blocked_ms_max, 300);
        probe.record_send(Duration::from_millis(120), ms(base, 480), 480);
        assert_eq!(probe.blocked_ms_max, 300);
    }
}
