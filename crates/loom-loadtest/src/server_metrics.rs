// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Reading the world thread's own counters out of a `/metrics` scrape, and
//! turning a series of scrapes into stall windows (OBI-344, OBI-371).
//!
//! The driver publishes `loom_world_loop_*` (see `loom_obs::world`); a
//! single end-of-run scrape of those cumulative counters says nothing about
//! *when* a stall happened. Scraping them once per second during the run
//! does, and the driver makes that placement exact: every stalled iteration
//! stamps its own finish time and length onto
//! `loom_world_loop_last_stall_unix_ms` /
//! `loom_world_loop_last_stall_duration_ms`, so a scraper can put the window
//! at `[finish - duration, finish]` instead of guessing which 1 s slice it
//! fell in. [`stall_windows_detail`] produces those windows, converting the
//! server's wall clock onto the run's `t+` axis once, from the scrape rows
//! that carried both clocks.
//!
//! When the absolute stamps are not there -- a server built before them, or
//! a report archived from one -- the only signal is a cumulative counter
//! that increased between two scrapes. That yields a *bracket*, not a
//! measurement, and the bracket has to be widened backwards: a stall is
//! observable one scrape after it finished, while the samples that paid for
//! it were sent before it started. OBI-344 used the bare scrape interval as
//! the window, which is why the run on `7086b58` recorded an 875 ms stall
//! and attributed 0 of its ~250 damaged samples to it.

use crate::attribution::Window;
use serde::{Deserialize, Serialize};

/// The world-thread counters this module understands. Each is a
/// `loom-obs`/`loom-cli` metric name; a run that predates OBI-344's
/// instrumentation simply reports `None` for all of them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WorldCounters {
    /// `loom_world_loop_ticks_total` -- the world's tick id.
    pub ticks: Option<f64>,
    /// `loom_world_loop_iterations_total`.
    pub iterations: Option<f64>,
    /// `loom_world_loop_stalls_total`, summed over its `kind` labels.
    pub stalls: Option<f64>,
    /// `loom_world_loop_stall_ms_total` -- cumulative stall milliseconds.
    pub stall_ms: Option<f64>,
    /// `loom_world_loop_duration_ms_max` -- slowest iteration since boot.
    pub duration_ms_max: Option<f64>,
    /// `loom_world_loop_gap_ms_max` -- longest not-running gap since boot.
    pub gap_ms_max: Option<f64>,
    /// `loom_world_loop_last_stall_unix_ms` -- wall-clock milliseconds since
    /// the epoch at the *finish* of the most recent stalled iteration.
    /// Absent until the first stall, exactly like a counter family.
    pub last_stall_unix_ms: Option<f64>,
    /// `loom_world_loop_last_stall_duration_ms` -- how long that stalled
    /// iteration ran, so `unix_ms - duration_ms` is where it began.
    pub last_stall_duration_ms: Option<f64>,
    /// `loom_world_loop_last_stall_tick` -- the tick id it ran under.
    pub last_stall_tick: Option<f64>,
    /// `loom_net_command_blocked_last_unix_ms` -- wall clock of the most
    /// recent world -> net send that had to wait on a full command channel.
    pub command_blocked_last_unix_ms: Option<f64>,
    /// `loom_net_command_blocked_total` -- world -> net sends that had to
    /// wait on a full command channel.
    pub command_blocked: Option<f64>,
    /// `loom_net_command_blocked_ms_total` -- cumulative milliseconds spent
    /// blocked on those sends.
    pub command_blocked_ms: Option<f64>,
    /// `loom_runtime_errors_total`, summed over its `program` labels.
    pub runtime_errors: Option<f64>,
}

impl WorldCounters {
    /// Every counter present (the shape a `loom serve` built after OBI-344
    /// has from its first tick). `None`-for-everything is what an un-
    /// instrumented server scrapes as, and callers must not read it as
    /// "zero stalls".
    pub fn is_instrumented(&self) -> bool {
        self.ticks.is_some() || self.stalls.is_some() || self.iterations.is_some()
    }

    /// Whether this scrape could place a stall by absolute timestamp rather
    /// than by diffing two scrapes (OBI-371). Drives the note that tells a
    /// reader whether to expect exact windows or brackets.
    pub fn has_absolute_stall_clock(&self) -> bool {
        self.last_stall_unix_ms.is_some()
    }
}

/// One scrape: when it happened (ms since the run started) and what it saw.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ServerRow {
    pub at_ms: u64,
    /// Wall-clock milliseconds since the epoch, read in the same instant as
    /// `at_ms` (OBI-371). This is what maps the server's absolute stall
    /// stamps onto the run's `t+` axis; a row from a report written before
    /// the loadtest recorded it has `None`, which forces the bracketing
    /// path. Only meaningful when the server runs on the same host as the
    /// loadtest -- which is what CI guarantees, and
    /// [`StallWindows::clock_spread_ms`] is the visible symptom when it is
    /// not true.
    #[serde(default)]
    pub unix_ms: Option<u64>,
    pub counters: WorldCounters,
}

/// How the windows of a run's server-stall series were placed on the time
/// axis. Reported next to the attribution because "unexplained tail" means
/// something different under each of these.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StallWindowPrecision {
    /// Every window is the server's own measurement: the stalled
    /// iteration's start and finish, from `loom_world_loop_last_stall_*`.
    Absolute,
    /// Every window is a scrape-interval bracket, widened backwards.
    #[default]
    ScrapeInterval,
    /// Some windows were measured, others only bracketed -- which is what a
    /// server does when more stalls land in one scrape interval than the
    /// last-stall gauge can name.
    Mixed,
    /// No window could be placed at all: either the world loop recorded no
    /// stall, or the series is too short to bracket one.
    NotPlaced,
}

impl StallWindowPrecision {
    /// The sentence the report puts next to the attribution.
    pub fn sentence(&self) -> &'static str {
        match self {
            Self::Absolute => {
                "every server stall window below is the server's own measurement \
                 (`loom_world_loop_last_stall_*`), placed on the run's `t+` axis from the \
                 wall clock read at scrape time"
            }
            Self::ScrapeInterval => {
                "every server stall window below is a bracket: the scrape interval \
                 widened backwards by one interval plus the stall milliseconds recorded in it, \
                 because a stall is only observable one scrape after it finished. Lower \
                 `--metrics-scrape-ms` (250 ms) shrinks that bracket"
            }
            Self::Mixed => {
                "some server stall windows below are the server's own measurement and some \
                 are scrape-interval brackets widened backwards (marked `approx`); a bracket \
                 covers more than one interval precisely because the scrape could not name \
                 which stall inside it did the damage"
            }
            Self::NotPlaced => {
                "no server stall window could be placed for this run, so nothing here \
                 attributes the tail to the world thread"
            }
        }
    }
}

/// The server stall windows of one run, and how much of them is measurement.
#[derive(Debug, Clone, Default)]
pub struct StallWindows {
    pub windows: Vec<Window>,
    /// Stall events placed by the server's absolute timestamps.
    pub localized_events: u64,
    /// Stall events only bracketed between two scrapes.
    pub bracketed_events: u64,
    /// Whether the scrape series carried a wall clock at all, i.e. whether
    /// the absolute path was available for this server.
    pub absolute_clock: bool,
    /// Spread of the per-scrape clock anchors in milliseconds: how jittery
    /// the monotonic/wall-clock mapping was across the run. A few hundred ms
    /// is a loaded runner; seconds means the server is not on this host and
    /// the windows above are brackets, not stamps.
    pub clock_spread_ms: u64,
}

impl StallWindows {
    pub fn precision(&self) -> StallWindowPrecision {
        if self.windows.is_empty() {
            return StallWindowPrecision::NotPlaced;
        }
        let approx = self.windows.iter().filter(|w| w.approximate).count();
        match (approx == 0, approx == self.windows.len()) {
            (true, _) => StallWindowPrecision::Absolute,
            (false, true) => StallWindowPrecision::ScrapeInterval,
            _ => StallWindowPrecision::Mixed,
        }
    }
}

/// The run's `t+ = 0` moment in the server's wall clock, and how steady that
/// mapping looked across the scrape series. Returns `None` when no row
/// carries `unix_ms`, which is the "old report / uninstrumented clock" case.
fn clock_anchor(rows: &[ServerRow]) -> Option<(f64, u64)> {
    let mut candidates: Vec<f64> = rows
        .iter()
        .filter_map(|r| r.unix_ms.map(|u| u as f64 - r.at_ms as f64))
        .collect();
    if candidates.is_empty() {
        return None;
    }
    candidates.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    // Median, not mean: one scrape whose body arrived late drags a mean, and
    // the whole series shares this one number.
    let mid = candidates[candidates.len() / 2];
    let spread = (candidates.last().unwrap() - candidates.first().unwrap())
        .max(0.0)
        .round() as u64;
    Some((mid, spread))
}

/// Cumulative-counter delta across a scrape pair, treating a counter that has
/// only just appeared as an increase from zero.
///
/// `loom_world_loop_stalls_total` is a Prometheus counter family that the
/// `metrics` facade creates on its *first* increment, so the scrape before
/// the run's first stall reads the series as absent and the scrape after it
/// reads `1`. Diffing those two as "no information" -- which is what
/// `now.zip(before)` did -- silently deleted the first stall of every run,
/// including the 875 ms one that decided `7086b58`'s E1.1 verdict (OBI-371).
/// A counter that *decreases* is a restarted process, i.e. genuinely no
/// information, and is not the same thing.
fn counter_delta(prev: Option<f64>, next: Option<f64>) -> f64 {
    match (prev, next) {
        (None, Some(now)) => now.max(0.0),
        (Some(before), Some(now)) if now > before => now - before,
        _ => 0.0,
    }
}

/// The bracket a cumulative-counter delta buys us: the stall finished
/// somewhere before this scrape, and the samples it damaged were sent before
/// it started, so the window reaches back from `next.at_ms` by one scrape
/// interval (`width`) plus the stall milliseconds the pair recorded.
fn bracket_window(next: &ServerRow, width: u64, events: u64, stall_ms: u64) -> Window {
    Window::bracket(
        next.at_ms.saturating_sub(width.saturating_add(stall_ms)),
        next.at_ms,
        events,
        stall_ms,
    )
}

/// What one scrape row can say about the stall events observed since the
/// previous row.
#[derive(Debug, Default)]
struct Placement {
    /// A window placed by the server's own absolute stamps, when it had any.
    exact: Option<Window>,
    /// Events the stamps could not name -- more than one stall in the
    /// interval, a stamp outside the run's axis, or a server that publishes
    /// none -- which only a backwards-widened bracket can cover.
    rest: u64,
    /// Stall milliseconds belonging to `rest`.
    rest_ms: u64,
}

/// Place one row's stall events, preferring the server's absolute stamps.
///
/// `loom_world_loop_last_stall_unix_ms` names exactly one stall: the most
/// recent one. So a row that observed two events can name one of them and
/// has to bracket the other, and a row whose stamp is missing, unchanged,
/// or outside the run's axis brackets everything it observed.
fn place_stalls(
    prev: Option<&ServerRow>,
    row: &ServerRow,
    run_start_unix: f64,
    width: u64,
    events_observed: u64,
    stall_ms_observed: u64,
) -> Placement {
    let stamp = row.counters.last_stall_unix_ms;
    let named = match prev.and_then(|p| p.counters.last_stall_unix_ms) {
        // Either the first row of the series, or the first stall the process
        // ever recorded -- in both cases this scrape is where it appeared.
        None => true,
        Some(before) => stamp.is_some_and(|now| now > before),
    };
    let Some(stamp) = stamp.filter(|_| named) else {
        return Placement {
            exact: None,
            rest: events_observed,
            rest_ms: stall_ms_observed,
        };
    };
    let end = stamp - run_start_unix;
    // A stamp outside the run's own axis means the same-host clock assumption
    // broke (a remote server, a host whose clock moved): bracket it instead of
    // inventing a window at `t-8 h`.
    if end < 0.0 || end > row.at_ms as f64 + (width as f64 + 1_000.0) {
        return Placement {
            exact: None,
            rest: events_observed,
            rest_ms: stall_ms_observed,
        };
    }
    let end_ms = end.round().max(0.0) as u64;
    let placed = match row.counters.last_stall_duration_ms {
        Some(duration) if duration > 0.0 => {
            let duration_ms = duration.round().max(0.0) as u64;
            // A stall whose measured start falls before `t+ = 0` has a left
            // edge we cannot trust, even though its finish is right.
            Window {
                approximate: end_ms < duration_ms,
                ..Window::exact(end_ms.saturating_sub(duration_ms), end_ms, 1, duration_ms)
            }
        }
        // No length recorded: the finish is still exact, so keep the window
        // but only as wide as one scrape interval, and say it is a bracket.
        _ => Window::bracket(end_ms.saturating_sub(width.max(1)), end_ms, 1, 0),
    };
    Placement {
        exact: Some(placed),
        rest: events_observed.saturating_sub(1),
        rest_ms: stall_ms_observed.saturating_sub(placed.stall_ms),
    }
}

/// The server-side stall windows: the intervals in which the world loop
/// stalled, placed as exactly as this scrape series allows.
///
/// Prefers the server's own absolute stamps; falls back to a backwards-
/// widened bracket per scrape pair. Stalls recorded by the very first scrape
/// of the series, with nothing before it to diff against and no stamp inside
/// the run's axis, are deliberately left unplaced rather than spread across
/// the whole interval since the server booted -- see [`counter_delta`] for
/// the other half of that argument.
pub fn stall_windows_detail(rows: &[ServerRow]) -> StallWindows {
    let anchor = clock_anchor(rows);
    let run_start_unix = anchor.map(|a| a.0);
    let clock_spread_ms = anchor.map_or(0, |a| a.1);
    let mut out = StallWindows {
        // Whether this server is one whose stalls can be *measured* rather
        // than bracketed -- the metric's presence, not whether a placement
        // succeeded, which is what `localized_events` says.
        absolute_clock: rows.iter().any(|r| r.counters.has_absolute_stall_clock()),
        clock_spread_ms,
        ..Default::default()
    };
    for (idx, row) in rows.iter().enumerate() {
        let prev = idx.checked_sub(1).map(|i| &rows[i]);
        let width = prev.map_or(1, |p| row.at_ms.saturating_sub(p.at_ms).max(1));
        // The first row has no previous scrape to diff against, so a counter
        // delta is not available for it; only its absolute stamps can place a
        // window.
        let events_observed = prev
            .map_or(0.0, |p| {
                counter_delta(p.counters.stalls, row.counters.stalls)
            })
            .round()
            .max(0.0) as u64;
        let stall_ms_observed = prev
            .map_or(0.0, |p| {
                counter_delta(p.counters.stall_ms, row.counters.stall_ms)
            })
            .round()
            .max(0.0) as u64;

        if let Some(run_start_unix) = run_start_unix {
            let placement = place_stalls(
                prev,
                row,
                run_start_unix,
                width,
                events_observed,
                stall_ms_observed,
            );
            if let Some(window) = placement.exact {
                out.localized_events += window.events;
                out.windows.push(window);
            }
            if placement.rest > 0 {
                out.bracketed_events += placement.rest;
                out.windows.push(bracket_window(
                    row,
                    width,
                    placement.rest,
                    placement.rest_ms,
                ));
            }
        } else if events_observed > 0 {
            out.bracketed_events += events_observed;
            out.windows.push(bracket_window(
                row,
                width,
                events_observed,
                stall_ms_observed,
            ));
        }
    }
    // Chronological for the report table. An interval that yields both a
    // measured window and a bracket for its older stall puts the bracket
    // first, since it opens earlier.
    out.windows.sort_by_key(|w| (w.start_ms, w.end_ms));
    out
}

/// The windows a run's server side attributes against: world-loop stalls
/// (placed as exactly as the scrape series allows), followed by
/// world -> net command-channel blocks.
///
/// `main` and the re-render both go through here, so re-rendering an archived
/// report produces the same window set a live run would have produced from the
/// same scrape rows -- which is the only way the comparison is about the
/// window logic rather than about two different builders.
pub fn server_windows(rows: &[ServerRow]) -> (Vec<Window>, StallWindows) {
    let stall = stall_windows_detail(rows);
    let mut windows = stall.windows.clone();
    windows.extend(command_blocked_windows(rows));
    (windows, stall)
}

/// The intervals in which the world -> net command channel blocked (a
/// distinct mechanism: the world thread itself is fine, the net task is not
/// draining).
///
/// The blocked-command counter has no per-event length series -- only
/// `loom_net_command_blocked_ms_max`, which is a since-boot maximum, not the
/// length of the last wait -- so these windows are always brackets, widened
/// backwards exactly like a stall bracket whose length is unknown.
pub fn command_blocked_windows(rows: &[ServerRow]) -> Vec<Window> {
    let mut windows = Vec::new();
    for (idx, row) in rows.iter().enumerate() {
        let Some(prev) = idx.checked_sub(1).map(|i| &rows[i]) else {
            continue;
        };
        let events = counter_delta(prev.counters.command_blocked, row.counters.command_blocked);
        if events <= 0.0 {
            continue;
        }
        let width = row.at_ms.saturating_sub(prev.at_ms).max(1);
        windows.push(bracket_window(row, width, events.round() as u64, 0));
    }
    windows
}

/// The value of a Prometheus series by name, summed across every label
/// set, from `text` (the `/metrics` exposition body). `_created`
/// zero-injection series and comment lines are ignored; an unparseable
/// value is skipped rather than poisoning the sum.
///
/// Returns `None` when the name is absent entirely -- which is how a caller
/// distinguishes "this server never recorded it" from "it recorded zero".
pub fn metric_value(text: &str, name: &str) -> Option<f64> {
    let mut total = 0.0_f64;
    let mut found = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((series, value)) = line.rsplit_once(char::is_whitespace) else {
            continue;
        };
        let Ok(value) = value.parse::<f64>() else {
            continue;
        };
        // Strip the label set, if any, then match the base name exactly so
        // `foo_total` never matches `foo_total_created` or `foo_total_x`.
        let series_name = match series.find('{') {
            Some(i) => &series[..i],
            None => series,
        };
        if series_name == name {
            found = true;
            total += value;
        }
    }
    found.then_some(total)
}

/// Extract the world-thread counters from one scrape body.
pub fn world_counters(text: &str) -> WorldCounters {
    WorldCounters {
        ticks: metric_value(text, "loom_world_loop_ticks_total"),
        iterations: metric_value(text, "loom_world_loop_iterations_total"),
        stalls: metric_value(text, "loom_world_loop_stalls_total"),
        stall_ms: metric_value(text, "loom_world_loop_stall_ms_total"),
        duration_ms_max: metric_value(text, "loom_world_loop_duration_ms_max"),
        gap_ms_max: metric_value(text, "loom_world_loop_gap_ms_max"),
        last_stall_unix_ms: metric_value(text, "loom_world_loop_last_stall_unix_ms"),
        last_stall_duration_ms: metric_value(text, "loom_world_loop_last_stall_duration_ms"),
        last_stall_tick: metric_value(text, "loom_world_loop_last_stall_tick"),
        command_blocked_last_unix_ms: metric_value(text, "loom_net_command_blocked_last_unix_ms"),
        command_blocked: metric_value(text, "loom_net_command_blocked_total"),
        command_blocked_ms: metric_value(text, "loom_net_command_blocked_ms_total"),
        runtime_errors: metric_value(text, "loom_runtime_errors_total"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = concat!(
        "# HELP loom_world_loop_stalls_total World loop iterations over the stall threshold.\n",
        "# TYPE loom_world_loop_stalls_total counter\n",
        "loom_world_loop_stalls_total{kind=\"tick\"} 2\n",
        "loom_world_loop_stalls_total{kind=\"input\"} 1\n",
        "# TYPE loom_world_loop_ticks_total counter\n",
        "loom_world_loop_ticks_total 412\n",
        "# TYPE loom_world_loop_stall_ms_total counter\n",
        "loom_world_loop_stall_ms_total 740\n",
        "# TYPE loom_world_loop_duration_ms_max gauge\n",
        "loom_world_loop_duration_ms_max 475\n",
        "# TYPE loom_world_loop_last_stall_unix_ms gauge\n",
        "loom_world_loop_last_stall_unix_ms 1767225601500\n",
        "# TYPE loom_world_loop_last_stall_duration_ms gauge\n",
        "loom_world_loop_last_stall_duration_ms 475\n",
        "# TYPE loom_world_loop_last_stall_tick gauge\n",
        "loom_world_loop_last_stall_tick 411\n",
        "# TYPE loom_net_command_blocked_last_unix_ms gauge\n",
        "loom_net_command_blocked_last_unix_ms 1767225600900\n",
        "# TYPE loom_net_command_blocked_total counter\n",
        "loom_net_command_blocked_total 3\n",
        "loom_net_command_blocked_ms_total 41\n",
        "# TYPE loom_runtime_errors_total counter\n",
        "loom_runtime_errors_total_created 1767225600\n",
        "loom_runtime_errors_total{program=\"/std/player\"} 150\n",
        "loom_runtime_errors_total{program=\"/std/room\"} 5\n",
        "loom_players 150\n",
        "loom_broken_series NaN\n",
    );

    #[test]
    fn sums_across_label_sets_and_ignores_created_and_comments() {
        assert_eq!(
            metric_value(FIXTURE, "loom_world_loop_stalls_total"),
            Some(3.0)
        );
        assert_eq!(
            metric_value(FIXTURE, "loom_runtime_errors_total"),
            Some(155.0)
        );
        assert_eq!(metric_value(FIXTURE, "loom_players"), Some(150.0));
        // The 155 above is the whole point: the fixture carries a
        // `loom_runtime_errors_total_created 1767225600` zero-injection
        // series, and folding it in would swamp the counter. It is only ever
        // readable under its own name.
        assert_eq!(
            metric_value(FIXTURE, "loom_runtime_errors_total_created"),
            Some(1767225600.0)
        );
        // A series the server never recorded is `None`, not `Some(0.0)`:
        // that is the difference between "no stalls" and "not instrumented".
        assert_eq!(metric_value(FIXTURE, "loom_world_loop_gap_ms_max"), None);
    }

    #[test]
    fn counters_read_the_instrumented_surface() {
        let c = world_counters(FIXTURE);
        assert!(c.is_instrumented());
        assert_eq!(c.ticks, Some(412.0));
        assert_eq!(c.stalls, Some(3.0));
        assert_eq!(c.stall_ms, Some(740.0));
        assert_eq!(c.duration_ms_max, Some(475.0));
        assert_eq!(c.command_blocked, Some(3.0));
        assert_eq!(c.command_blocked_ms, Some(41.0));
        assert_eq!(c.runtime_errors, Some(155.0));
        assert_eq!(c.iterations, None);
        // The absolute stall stamps OBI-371 attributes from: the driver
        // publishes them only once a stall has happened, and a scrape that
        // reads them can place the window without guessing.
        assert_eq!(c.last_stall_unix_ms, Some(1_767_225_601_500.0));
        assert_eq!(c.last_stall_duration_ms, Some(475.0));
        assert_eq!(c.last_stall_tick, Some(411.0));
        assert_eq!(c.command_blocked_last_unix_ms, Some(1_767_225_600_900.0));
        // A server that has not stalled yet publishes none of them, which is
        // `None`, not `Some(0.0)`: a zero unix stamp would map to a window
        // decades before the run started.
        assert!(!world_counters("loom_players 150\n").has_absolute_stall_clock());
    }

    #[test]
    fn an_uninstrumented_server_is_not_reported_as_zero_stalls() {
        let c = world_counters("loom_players 150\n");
        assert!(!c.is_instrumented());
        assert_eq!(c.stalls, None);
    }

    /// A scrape row with no wall clock and no absolute stall stamps -- the
    /// shape a report written before OBI-371 carries.
    fn row(at_ms: u64, ticks: f64, stalls: f64, stall_ms: f64) -> ServerRow {
        ServerRow {
            at_ms,
            unix_ms: None,
            counters: WorldCounters {
                ticks: Some(ticks),
                stalls: Some(stalls),
                stall_ms: Some(stall_ms),
                ..Default::default()
            },
        }
    }

    /// The run's `t+ = 0` in the server's wall clock, for the stamped
    /// fixtures below: a same-host clock, offset far enough that a report
    /// rendered in `t+` could never accidentally match a raw unix stamp.
    const RUN_START_UNIX: f64 = 1_767_225_600_000.0;

    /// A scrape row that carries the wall clock (`unix_ms`) and, when
    /// `last_stall` is given, the server's own stamp for its most recent
    /// stalled iteration: `(finish unix ms, duration ms)`.
    fn stamped(
        at_ms: u64,
        stalls: Option<f64>,
        stall_ms: Option<f64>,
        last_stall: Option<(f64, f64)>,
    ) -> ServerRow {
        ServerRow {
            at_ms,
            unix_ms: Some((RUN_START_UNIX + at_ms as f64) as u64),
            counters: WorldCounters {
                stalls,
                stall_ms,
                last_stall_unix_ms: last_stall.map(|(finish, _)| finish),
                last_stall_duration_ms: last_stall.map(|(_, duration)| duration),
                ..Default::default()
            },
        }
    }

    /// The windows alone, for tests that do not care how they were placed.
    fn stall_windows(rows: &[ServerRow]) -> Vec<Window> {
        stall_windows_detail(rows).windows
    }

    #[test]
    fn a_counter_increase_brackets_backwards_from_its_scrape_pair() {
        // No absolute stamps on these rows: all we know is that two stalls
        // totalling 480 ms finished somewhere before the 3 s scrape, and the
        // samples they damaged were sent before that started. So the window
        // reaches back from 3 s by the interval (1 s) plus 480 ms -- it does
        // not start at the previous scrape.
        let rows = vec![
            row(1_000, 10.0, 0.0, 0.0),
            row(2_000, 20.0, 0.0, 0.0),
            row(3_000, 30.0, 2.0, 480.0),
            row(4_000, 40.0, 2.0, 480.0),
        ];
        let detail = stall_windows_detail(&rows);
        assert_eq!(
            detail.windows,
            vec![Window::bracket(1_520, 3_000, 2, 480)],
            "{:#?}",
            detail.windows
        );
        assert_eq!(detail.precision(), StallWindowPrecision::ScrapeInterval);
        assert_eq!(detail.bracketed_events, 2);
        assert_eq!(detail.localized_events, 0);
        assert!(!detail.absolute_clock);
    }

    #[test]
    fn a_counter_that_only_appears_between_two_scrapes_still_gets_a_window() {
        // The stall-counter family does not exist until its first increment,
        // so `None -> Some(1)` IS the increase. Diffing it as "no
        // information" is the bug that left `7086b58`'s 875 ms stall with no
        // window at all -- the only window that run reported came from a
        // later, much smaller stall.
        let rows = vec![
            ServerRow {
                at_ms: 10_304,
                unix_ms: None,
                counters: WorldCounters {
                    ticks: Some(1_000.0),
                    ..Default::default()
                },
            },
            row(11_304, 1_100.0, 1.0, 875.0),
        ];
        let windows = stall_windows(&rows);
        assert_eq!(windows.len(), 1, "{windows:?}");
        assert_eq!(windows[0].events, 1);
        assert_eq!(windows[0].stall_ms, 875);
        // Widened back far enough to cover samples sent while the world
        // thread was stuck: the stall finished by 11 304 and ran 875 ms, so
        // the bracket opens no later than 9 429.
        assert_eq!(windows[0].start_ms, 9_429);
        assert!(windows[0].approximate);
    }

    #[test]
    fn the_absolute_stall_stamp_places_the_window_at_the_stall_not_the_scrape() {
        // The same run, scraped with the OBI-371 columns. The 875 ms stall
        // finished at t+10 500, so the window is [9 625, 10 500] even though
        // the scrape that saw it ran at t+11 304 -- and a sample sent at
        // t+10.3 s sits inside it.
        let rows = vec![
            stamped(10_304, None, None, None),
            stamped(
                11_304,
                Some(1.0),
                Some(875.0),
                Some((RUN_START_UNIX + 10_500.0, 875.0)),
            ),
        ];
        let detail = stall_windows_detail(&rows);
        assert_eq!(
            detail.windows,
            vec![Window::exact(9_625, 10_500, 1, 875)],
            "{:#?}",
            detail.windows
        );
        assert_eq!(detail.precision(), StallWindowPrecision::Absolute);
        assert_eq!(detail.localized_events, 1);
        assert_eq!(detail.bracketed_events, 0);
        assert_eq!(detail.clock_spread_ms, 0, "fixture clock is exact");
    }

    #[test]
    fn two_stalls_in_one_interval_name_one_and_bracket_the_other() {
        // The last-stall gauge can only point at the newest stall, so the
        // older one of the pair stays a bracket. Carrying both precisions is
        // what keeps that difference visible in the report.
        let rows = vec![
            stamped(1_000, Some(0.0), Some(0.0), None),
            stamped(
                2_000,
                Some(2.0),
                Some(700.0),
                Some((RUN_START_UNIX + 1_900.0, 500.0)),
            ),
        ];
        let detail = stall_windows_detail(&rows);
        assert_eq!(
            detail.windows,
            vec![
                Window::bracket(800, 2_000, 1, 200),
                Window::exact(1_400, 1_900, 1, 500),
            ],
            "{:#?}",
            detail.windows
        );
        assert_eq!(detail.precision(), StallWindowPrecision::Mixed);
        assert_eq!(detail.localized_events, 1);
        assert_eq!(detail.bracketed_events, 1);
    }

    #[test]
    fn a_stamp_outside_the_run_is_bracketed_not_believed() {
        // A server on another host (or a host whose clock jumped) puts the
        // stall's finish nowhere near the run's axis. `t-8 h` would be a
        // window that attributes nothing at all, so fall back to the bracket.
        let rows = vec![
            stamped(10_304, Some(0.0), Some(0.0), None),
            stamped(
                11_304,
                Some(1.0),
                Some(875.0),
                Some((RUN_START_UNIX - 8.0 * 3_600_000.0, 875.0)),
            ),
        ];
        let detail = stall_windows_detail(&rows);
        assert_eq!(detail.windows.len(), 1, "{:#?}", detail.windows);
        assert_eq!(detail.windows[0].start_ms, 9_429);
        assert!(detail.windows[0].approximate);
        assert_eq!(detail.bracketed_events, 1);
        assert_eq!(detail.localized_events, 0);
    }

    #[test]
    fn a_stall_recorded_by_the_first_scrape_needs_its_stamp_to_be_placed() {
        // The first row has nothing to diff against. Its absolute stamps can
        // still place a stall (below), but a bare counter with no previous
        // scrape must not become "the whole run stalled" -- the server may
        // have been up, and stalling, long before `t+ = 0`.
        let rows = vec![
            stamped(
                1_000,
                Some(1.0),
                Some(900.0),
                Some((RUN_START_UNIX + 900.0, 900.0)),
            ),
            stamped(
                2_000,
                Some(1.0),
                Some(900.0),
                Some((RUN_START_UNIX + 900.0, 900.0)),
            ),
        ];
        let detail = stall_windows_detail(&rows);
        assert_eq!(detail.windows, vec![Window::exact(0, 900, 1, 900)]);
        assert_eq!(detail.localized_events, 1);

        let no_clock = vec![row(1_000, 10.0, 1.0, 900.0), row(2_000, 20.0, 1.0, 900.0)];
        assert!(
            stall_windows(&no_clock).is_empty(),
            "a counter with no baseline is not a window"
        );
    }

    #[test]
    fn a_decreasing_counter_is_no_information() {
        let rows = vec![row(1_000, 50.0, 4.0, 300.0), row(2_000, 10.0, 0.0, 0.0)];
        assert!(stall_windows(&rows).is_empty());
    }

    #[test]
    fn a_jittery_clock_mapping_is_reported_as_spread() {
        // The loadtest reads `unix_ms` and `at_ms` in the same instant, so
        // the per-row anchor should agree to within the runner's scheduling
        // noise. A seconds-wide spread is the visible symptom that the
        // server is not on this host, and the report says so.
        let mut rows = vec![
            stamped(1_000, Some(0.0), Some(0.0), None),
            stamped(2_000, Some(0.0), Some(0.0), None),
        ];
        rows[0].unix_ms = Some((RUN_START_UNIX + 1_000.0 - 2_000.0) as u64);
        let detail = stall_windows_detail(&rows);
        assert_eq!(detail.clock_spread_ms, 2_000, "{detail:?}");
        assert_eq!(detail.precision(), StallWindowPrecision::NotPlaced);
    }

    #[test]
    fn rows_without_the_metric_produce_no_windows() {
        let rows = vec![
            ServerRow {
                at_ms: 1_000,
                unix_ms: None,
                counters: WorldCounters::default(),
            },
            ServerRow {
                at_ms: 2_000,
                unix_ms: None,
                counters: WorldCounters::default(),
            },
        ];
        assert!(stall_windows(&rows).is_empty());
        assert!(command_blocked_windows(&rows).is_empty());
    }

    #[test]
    fn command_blocked_windows_bracket_backwards_too() {
        let mut rows = vec![row(4_000, 10.0, 0.0, 0.0), row(5_000, 20.0, 0.0, 0.0)];
        rows[1].counters.command_blocked = Some(2.0);
        let windows = command_blocked_windows(&rows);
        // No per-event length for blocked sends, so the bracket is one
        // interval wide, reaching back from the scrape that saw the increase.
        assert_eq!(windows, vec![Window::bracket(4_000, 5_000, 2, 0)]);
    }
}
