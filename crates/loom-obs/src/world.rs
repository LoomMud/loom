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
//! - `loom_world_loop_stall_ms_by_kind_total{kind}` and, for the most recent
//!   breach, `loom_world_loop_last_stall_phase_ms{phase}` -- **where inside**
//!   the stalled iteration the milliseconds went.
//!
//! ## Why `kind` is not the answer
//!
//! `kind` names the event that *woke* the loop, not the work that ran. One
//! iteration of the serve loop handles that event **and** every side channel
//! that has queued up behind it (db results, admin queries, a snapshot
//! request, finished recompiles, file ops, the roles swap), and several of
//! them run a real `exec`. A stall labelled `input` is therefore not evidence
//! that a player command was slow: in run `37880215784` the arms labelled
//! `negotiation` are log-only (OBI-26 leaves the NAWS/TTYPE/GMCP hooks
//! unmade), so that label cannot describe 875 ms of work at all. [`WorldPhase`]
//! fixes the question by measuring the loop body in segments and attributing a
//! breach to the segment that held it.
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

/// A segment of one serve-loop iteration. The serve loop calls
/// [`WorldLoopProbe::begin_phase`] at each boundary; the time between two
/// marks belongs to the earlier one and [`WorldLoopProbe::record_iteration`]
/// closes the last. See the module docs for why this exists next to
/// [`WorldEventKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorldPhase {
    /// The event arm: `World::tick` / `input` / `connect` / `disconnect`, or
    /// a log-only negotiation. This is where mudlib `exec` work happens.
    Exec,
    /// `drain_db_events`: applying async DB results to the world.
    DbDrain,
    /// `drain_admin_queries`.
    AdminDrain,
    /// A snapshot request from the control socket -- `World::begin_snapshot`
    /// plus `encode_all()`, the copyover serialisation of the whole world.
    Snapshot,
    /// `drain_finished_recompiles` and the file-op queue: installs, compiles
    /// and `/api/v1/files/*` requests, which run real `exec` calls.
    FileOps,
    /// Swapping in a new roles snapshot.
    RolesSwap,
    /// Iteration time covered by no mark. Kept so a breach's phase totals add
    /// up to the iteration duration: a non-zero `other` means the loop does
    /// work outside the marks, which is a gap in the instrumentation, not a
    /// kind of stall.
    ///
    /// Blocked `blocking_send` time is **not** a phase here: it happens
    /// inside the event arm and the drains, so making it a bucket would
    /// double-count. It travels as its own number
    /// ([`WorldLoopProbe::last_stall_net_send_ms`]).
    Other,
}

impl WorldPhase {
    /// Number of phases: the width of the probe's fixed-size accumulators.
    pub const COUNT: usize = 7;

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::DbDrain => "db_drain",
            Self::AdminDrain => "admin_drain",
            Self::Snapshot => "snapshot",
            Self::FileOps => "file_ops",
            Self::RolesSwap => "roles_swap",
            Self::Other => "other",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Exec => 0,
            Self::DbDrain => 1,
            Self::AdminDrain => 2,
            Self::Snapshot => 3,
            Self::FileOps => 4,
            Self::RolesSwap => 5,
            Self::Other => 6,
        }
    }

    fn from_index(idx: usize) -> Self {
        [
            Self::Exec,
            Self::DbDrain,
            Self::AdminDrain,
            Self::Snapshot,
            Self::FileOps,
            Self::RolesSwap,
            Self::Other,
        ][idx]
    }
}

thread_local! {
    /// Milliseconds the world thread has spent blocked in `blocking_send`
    /// since the last [`WorldLoopProbe::record_iteration`]. `Host`'s send path
    /// and the probe are separate owners on the same thread, so the hand-off
    /// is a thread-local cell rather than a shared reference; it is read and
    /// reset once per iteration.
    static NET_SEND_MS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Add `ms` of blocked `blocking_send` time to the current iteration's
/// [`WorldPhase::NetSend`] bucket. Called by [`NetCommandProbe::record_send`].
pub fn note_net_send_blocked_ms(ms: u64) {
    NET_SEND_MS.with(|cell| cell.set(cell.get().saturating_add(ms)));
}

fn take_net_send_blocked_ms() -> u64 {
    NET_SEND_MS.with(std::cell::Cell::take)
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
    /// Per-iteration phase accumulator: which phase is open, and when it
    /// started.
    phase_started: Option<Instant>,
    current_phase: Option<WorldPhase>,
    /// Milliseconds per phase. These are **per iteration**: `record_iteration`
    /// takes and resets them, so a breach can be attributed without keeping a
    /// per-stall series.
    phase_ms: [u64; WorldPhase::COUNT],
    /// The breakdown of the most recent breach, kept after the live buckets
    /// reset, for [`Self::last_stall_breakdown`].
    phase_ms_of_last_stall: [u64; WorldPhase::COUNT],
    /// Blocked world -> net command-channel time carried by the most recent
    /// breach. Overlaps the phase buckets (it happens inside them), so it is
    /// reported beside them, never as one.
    net_send_ms_of_last_stall: u64,
    last_stall_phase: Option<WorldPhase>,
    last_stall_phase_ms: u64,
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
            phase_started: None,
            current_phase: None,
            phase_ms: [0; WorldPhase::COUNT],
            phase_ms_of_last_stall: [0; WorldPhase::COUNT],
            net_send_ms_of_last_stall: 0,
            last_stall_phase: None,
            last_stall_phase_ms: 0,
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

    /// Mark the start of `phase`, closing the previous one. The serve loop
    /// calls this at each boundary of an iteration; `record_iteration` closes
    /// the last phase, so there is no matching end call.
    pub fn begin_phase(&mut self, phase: WorldPhase, now: Instant) {
        self.close_phase(now);
        self.current_phase = Some(phase);
        self.phase_started = Some(now);
    }

    /// Fold the open phase's elapsed time into its bucket.
    fn close_phase(&mut self, now: Instant) {
        if let (Some(started), Some(phase)) = (self.phase_started, self.current_phase) {
            let elapsed = now.saturating_duration_since(started).as_millis() as u64;
            self.phase_ms[phase.index()] = self.phase_ms[phase.index()].saturating_add(elapsed);
        }
        self.phase_started = None;
    }

    /// The phase that held the most time in the most recent stalled
    /// iteration. `None` until a breach has been recorded.
    pub fn last_stall_phase(&self) -> Option<WorldPhase> {
        self.last_stall_phase
    }

    pub fn last_stall_phase_ms(&self) -> u64 {
        self.last_stall_phase_ms
    }

    /// The whole breakdown of the most recent stalled iteration, non-zero
    /// phases first. This is what makes a red run readable: `[(Exec, 812)]`
    /// with `last_stall_net_send_ms() == 0` says the mudlib ran for that
    /// long; `[(Exec, 875)]` with `last_stall_net_send_ms() == 875` says the
    /// net task was not draining and the world thread was waiting on it.
    pub fn last_stall_breakdown(&self) -> Vec<(WorldPhase, u64)> {
        let mut rows: Vec<(WorldPhase, u64)> = self
            .phase_ms_of_last_stall
            .iter()
            .enumerate()
            .filter(|(_, ms)| **ms > 0)
            .map(|(idx, ms)| (WorldPhase::from_index(idx), *ms))
            .collect();
        rows.sort_by_key(|row| std::cmp::Reverse(row.1));
        rows
    }

    /// Blocked world -> net `blocking_send` time inside the most recent
    /// stalled iteration. See [`Self::last_stall_breakdown`].
    pub fn last_stall_net_send_ms(&self) -> u64 {
        self.net_send_ms_of_last_stall
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

        // Close the last phase, then take the buckets: they describe *this*
        // iteration. Time the marks did not cover lands in `other`, so the
        // phases add up to `duration_ms` and a missing mark stays visible.
        self.close_phase(finished);
        // Held beside the buckets, never inside them: blocked send time is
        // already counted in the phase that made the send.
        let net_send_ms = take_net_send_blocked_ms();
        let accounted: u64 = self.phase_ms.iter().sum::<u64>().min(duration_ms);
        let residual = duration_ms.saturating_sub(accounted);
        if residual > 0 {
            let cell = &mut self.phase_ms[WorldPhase::Other.index()];
            *cell = cell.saturating_add(residual);
        }
        let breakdown = self.phase_ms;
        self.phase_ms = [0; WorldPhase::COUNT];

        let stalled = duration > self.threshold;
        if stalled {
            let mut dominant = WorldPhase::Other;
            let mut dominant_ms = 0u64;
            for (idx, ms) in breakdown.iter().enumerate() {
                if *ms > dominant_ms {
                    dominant_ms = *ms;
                    dominant = WorldPhase::from_index(idx);
                }
                if *ms > 0 {
                    metrics::gauge!(
                        "loom_world_loop_last_stall_phase_ms",
                        "phase" => WorldPhase::from_index(idx).as_str()
                    )
                    .set(*ms as f64);
                }
            }
            metrics::gauge!("loom_world_loop_last_stall_net_send_ms").set(net_send_ms as f64);
            metrics::counter!("loom_world_loop_stall_ms_by_kind_total", "kind" => kind.as_str())
                .increment(duration_ms);
            metrics::counter!("loom_world_loop_stall_ms_by_phase_total", "phase" => dominant.as_str())
                .increment(dominant_ms);
            self.last_stall_phase = Some(dominant);
            self.last_stall_phase_ms = dominant_ms;
            self.phase_ms_of_last_stall = breakdown;
            self.net_send_ms_of_last_stall = net_send_ms;
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
                    phase = dominant.as_str(),
                    phase_ms = dominant_ms,
                    tick = self.ticks,
                    duration_ms,
                    idle_ms,
                    phases = %breakdown
                        .iter()
                        .enumerate()
                        .filter(|(_, ms)| **ms > 0)
                        .map(|(idx, ms)| format!("{}={ms}", WorldPhase::from_index(idx).as_str()))
                        .collect::<Vec<_>>()
                        .join(" "),
                    net_send_ms,
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

/// Drop any blocked-send time accumulated by another test on this thread.
/// The `net_send` bucket is thread-local, and cargo runs tests from a pool of
/// worker threads that tests are scheduled onto in an unstable order, so a
/// phase assertion has to start from a known-empty accumulator.
#[cfg(test)]
fn clear_net_send_blocked_ms() {
    take_net_send_blocked_ms();
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
        let waited_ms = waited.as_millis() as u64;
        // Every blocked millisecond belongs to this iteration's `net_send`
        // phase, whether or not it is individually worth a counter: the phase
        // attribution has to add up even when nothing breaches.
        if waited_ms > 0 {
            note_net_send_blocked_ms(waited_ms);
        }
        if waited <= self.threshold {
            return;
        }
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

    /// The bug OBI-344 is left with after #159: a breach labelled `input` or
    /// `negotiation` names the event that woke the loop, not the work that ran.
    /// A stalled iteration must be attributed to the phase that held its time.
    #[test]
    fn a_stalled_iteration_is_attributed_to_the_phase_that_held_it() {
        clear_net_send_blocked_ms();
        let base = Instant::now();
        let mut probe = WorldLoopProbe::for_test(Duration::from_millis(50));
        // The shape of run 37880215784: the event arm is cheap, the snapshot
        // request drained behind it encodes the whole world for 870 ms.
        probe.begin_phase(WorldPhase::Exec, ms(base, 0));
        probe.begin_phase(WorldPhase::Snapshot, ms(base, 5));
        let stalled =
            probe.record_iteration(WorldEventKind::Input, ms(base, 0), ms(base, 875), 875);
        assert!(stalled);
        assert_eq!(probe.last_stall_phase(), Some(WorldPhase::Snapshot));
        assert_eq!(probe.last_stall_phase_ms(), 870);
        assert_eq!(
            probe.last_stall_breakdown(),
            vec![(WorldPhase::Snapshot, 870), (WorldPhase::Exec, 5)]
        );
        // The arithmetic is honest: the phases cover the iteration exactly.
        let total: u64 = probe.last_stall_breakdown().iter().map(|(_, ms)| *ms).sum();
        assert_eq!(total, 875);
    }

    #[test]
    fn phases_reset_every_iteration_so_a_window_never_blurs_two_of_them() {
        clear_net_send_blocked_ms();
        let base = Instant::now();
        let mut probe = WorldLoopProbe::for_test(Duration::from_millis(50));
        probe.begin_phase(WorldPhase::Exec, ms(base, 0));
        assert!(probe.record_iteration(WorldEventKind::Tick, ms(base, 0), ms(base, 200), 200));
        assert_eq!(probe.last_stall_breakdown(), vec![(WorldPhase::Exec, 200)]);
        // A second, cheaper breach under a different mark must not inherit the
        // first iteration's 200 ms.
        probe.begin_phase(WorldPhase::FileOps, ms(base, 210));
        assert!(probe.record_iteration(WorldEventKind::Drain, ms(base, 210), ms(base, 300), 300));
        assert_eq!(probe.last_stall_phase(), Some(WorldPhase::FileOps));
        assert_eq!(
            probe.last_stall_breakdown(),
            vec![(WorldPhase::FileOps, 90)]
        );
    }

    /// An iteration the loop never marked -- a future arm added without a
    /// `begin_phase`, or a probe used by a caller that has no marks at all --
    /// has to land somewhere, or the phase numbers would quietly stop adding
    /// up to the duration they are supposed to explain.
    #[test]
    fn an_unmarked_iteration_is_named_other_not_silently_zero() {
        clear_net_send_blocked_ms();
        let base = Instant::now();
        let mut probe = WorldLoopProbe::for_test(Duration::from_millis(50));
        assert!(probe.record_iteration(WorldEventKind::Tick, ms(base, 0), ms(base, 120), 120));
        assert_eq!(probe.last_stall_phase(), Some(WorldPhase::Other));
        assert_eq!(probe.last_stall_breakdown(), vec![(WorldPhase::Other, 120)]);
        // And a marked iteration never leaves residue behind: the open mark is
        // closed at `finished`, so the buckets are the duration.
        probe.begin_phase(WorldPhase::Exec, ms(base, 130));
        assert!(probe.record_iteration(WorldEventKind::Tick, ms(base, 130), ms(base, 200), 200));
        assert_eq!(probe.last_stall_breakdown(), vec![(WorldPhase::Exec, 70)]);
    }

    /// A world thread that spent its stall inside `blocking_send` is a
    /// *net-side* problem wearing an `exec` label. The two numbers together
    /// tell them apart; a bucket sum would have double-counted instead.
    #[test]
    fn blocked_send_time_travels_beside_the_phases_not_inside_them() {
        clear_net_send_blocked_ms();
        let base = Instant::now();
        let mut probe = WorldLoopProbe::for_test(Duration::from_millis(50));
        let mut cmd = NetCommandProbe::new(Duration::from_millis(50));
        probe.begin_phase(WorldPhase::Exec, ms(base, 0));
        // A 63 ms wait on the command channel happened during the event arm.
        cmd.record_send(Duration::from_millis(63), ms(base, 63), 63);
        assert!(probe.record_iteration(WorldEventKind::Input, ms(base, 0), ms(base, 120), 120));
        assert_eq!(probe.last_stall_net_send_ms(), 63);
        assert_eq!(probe.last_stall_breakdown(), vec![(WorldPhase::Exec, 120)]);
        // Taken once: the next iteration starts from zero.
        assert!(probe.record_iteration(WorldEventKind::Input, ms(base, 130), ms(base, 200), 200));
        assert_eq!(probe.last_stall_net_send_ms(), 0);
        clear_net_send_blocked_ms();
    }
}
