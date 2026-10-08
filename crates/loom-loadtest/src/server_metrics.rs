// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Reading the world thread's own counters out of a `/metrics` scrape, and
//! turning a series of scrapes into stall windows (OBI-344).
//!
//! The driver publishes `loom_world_loop_*` (see `loom_obs::world`); a
//! single end-of-run scrape of those cumulative counters says nothing about
//! *when* a stall happened. Scraping them once per second during the run
//! does: a counter that increased between two scrapes puts its stall inside
//! the interval between them, which is exactly the shape
//! [`stall_windows`] produces and [`crate::attribution`] consumes.

use crate::attribution::Window;
use serde::Serialize;

/// The world-thread counters this module understands. Each is a
/// `loom-obs`/`loom-cli` metric name; a run that predates OBI-344's
/// instrumentation simply reports `None` for all of them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
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
}

/// One scrape: when it happened (ms since the run started) and what it saw.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ServerRow {
    pub at_ms: u64,
    pub counters: WorldCounters,
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
        command_blocked: metric_value(text, "loom_net_command_blocked_total"),
        command_blocked_ms: metric_value(text, "loom_net_command_blocked_ms_total"),
        runtime_errors: metric_value(text, "loom_runtime_errors_total"),
    }
}

/// One increasing-counter series of scrapes -> the windows in which it
/// increased.
///
/// Each scrape only says "the counter was `v` at `at_ms`", so an increase is
/// attributed to the whole interval since the previous scrape: the stall
/// resolution is the scrape interval, and that is stated in the report
/// rather than hidden. A counter that decreased (a server restart, a
/// re-scrape of a fresh process) is treated as no information, not as a
/// negative stall.
pub fn windows_for(
    rows: &[ServerRow],
    field: impl Fn(&WorldCounters) -> Option<f64>,
    ms_field: impl Fn(&WorldCounters) -> Option<f64>,
) -> Vec<Window> {
    let mut windows = Vec::new();
    for pair in rows.windows(2) {
        let (prev, next) = (&pair[0], &pair[1]);
        let Some(delta) = field(&next.counters)
            .zip(field(&prev.counters))
            .map(|(now, before)| if now > before { now - before } else { 0.0 })
        else {
            continue;
        };
        if delta <= 0.0 {
            continue;
        }
        let stall_ms = ms_field(&next.counters)
            .zip(ms_field(&prev.counters))
            .map(|(now, before)| (now - before).max(0.0))
            .unwrap_or(0.0);
        windows.push(Window {
            start_ms: prev.at_ms,
            end_ms: next.at_ms,
            events: delta.round() as u64,
            stall_ms: stall_ms.round() as u64,
        });
    }
    windows
}

/// The server-side stall windows: intervals in which
/// `loom_world_loop_stalls_total` increased.
pub fn stall_windows(rows: &[ServerRow]) -> Vec<Window> {
    windows_for(rows, |c| c.stalls, |c| c.stall_ms)
}

/// The intervals in which the world -> net command channel blocked (a
/// distinct mechanism: the world thread itself is fine, the net task is not
/// draining).
pub fn command_blocked_windows(rows: &[ServerRow]) -> Vec<Window> {
    // The blocked-command counter has no paired milliseconds series: the
    // window's width is the scrape interval itself, which is what we know.
    windows_for(rows, |c| c.command_blocked, |_| None)
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
    }

    #[test]
    fn an_uninstrumented_server_is_not_reported_as_zero_stalls() {
        let c = world_counters("loom_players 150\n");
        assert!(!c.is_instrumented());
        assert_eq!(c.stalls, None);
    }

    fn row(at_ms: u64, ticks: f64, stalls: f64, stall_ms: f64) -> ServerRow {
        ServerRow {
            at_ms,
            counters: WorldCounters {
                ticks: Some(ticks),
                stalls: Some(stalls),
                stall_ms: Some(stall_ms),
                ..Default::default()
            },
        }
    }

    #[test]
    fn a_counter_increase_becomes_the_interval_between_two_scrapes() {
        let rows = vec![
            row(1_000, 10.0, 0.0, 0.0),
            row(2_000, 20.0, 0.0, 0.0),   // no stall
            row(3_000, 30.0, 2.0, 480.0), // stall between 2s and 3s
            row(4_000, 40.0, 2.0, 480.0), // no new stall
        ];
        let windows = stall_windows(&rows);
        assert_eq!(
            windows,
            vec![Window {
                start_ms: 2_000,
                end_ms: 3_000,
                events: 2,
                stall_ms: 480
            }]
        );
    }

    #[test]
    fn a_decreasing_counter_is_no_information() {
        let rows = vec![row(1_000, 50.0, 4.0, 300.0), row(2_000, 10.0, 0.0, 0.0)];
        assert!(stall_windows(&rows).is_empty());
    }

    #[test]
    fn rows_without_the_metric_produce_no_windows() {
        let rows = vec![
            ServerRow {
                at_ms: 1_000,
                counters: WorldCounters::default(),
            },
            ServerRow {
                at_ms: 2_000,
                counters: WorldCounters::default(),
            },
        ];
        assert!(stall_windows(&rows).is_empty());
        assert!(command_blocked_windows(&rows).is_empty());
    }
}
