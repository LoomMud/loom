// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Tail attribution: turning "p99 was 227 ms in that run" into "these N
//! samples were slow because the world thread was stalled in these
//! windows" (OBI-344).
//!
//! Everything here is pure and clock-free -- `at_ms`/`latency_ms` offsets are
//! captured by the bot task against the run's own start, and the server-side
//! windows arrive pre-placed by [`crate::server_metrics`] -- so the
//! classification rules are unit-testable without a server, and the numbers in
//! a committed report can be recomputed from its own JSON (every at-or-over-SLA
//! sample is carried in it, which is what makes OBI-371's re-render of an old
//! artifact possible).
//!
//! A tail sample is *explained* by a window when the sample's own
//! in-flight interval `[at, at + latency]` intersects it. That intersection
//! test is deliberately generous: a sample sent 10 ms before a stall and
//! answered 10 ms after it did wait for the stall, even though neither of
//! its endpoints falls inside the window.
//!
//! What a window *means* depends on how it was placed, and the two cases are
//! kept apart rather than averaged together (OBI-371):
//!
//! * `approximate == false` -- the server stamped the stall itself
//!   (`loom_world_loop_last_stall_unix_ms` minus
//!   `loom_world_loop_last_stall_duration_ms`), mapped onto the run's `t+`
//!   axis. The edges are the stalled iteration's own finish and start.
//! * `approximate == true` -- all we know is that a cumulative counter was
//!   higher at the next scrape than at the previous one. Such a window is the
//!   scrape interval **widened backwards**, by one interval plus the stall
//!   milliseconds it recorded, because a stall is only observable one scrape
//!   after it finished while the samples it damaged were sent before it
//!   started. Using the bare scrape interval -- what OBI-344 first did --
//!   shifts every attribution later than the damage it explains, and the
//!   shift is silently downward-friendly: the tail samples that paid for a
//!   stall fall outside the window and land in `unattributed`.
//!
//! `TailAttribution::unattributed` is the honest remainder: tail samples
//! with no server stall, no bot-side timer starvation, and no login-ramp
//! overlap to explain them. It is only worth reading once
//! `TailAttribution::stall_window_precision` says the windows were placed
//! exactly; against bracketing windows it is a resolution artefact, not a
//! finding.

use serde::{Deserialize, Serialize};

/// A time interval, in milliseconds since the run started, in which a
/// candidate cause was observed.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Window {
    pub start_ms: u64,
    pub end_ms: u64,
    /// How many stall events were observed in this window (for a server
    /// window: the counter delta between the two scrapes that bracket it).
    pub events: u64,
    /// Total milliseconds of stall observed, when the source reports it
    /// (`loom_world_loop_stall_ms_total`); `0` for bot-side windows.
    pub stall_ms: u64,
    /// Whether the edges bracket a cause rather than measure it: true for a
    /// window reconstructed from a cumulative-counter delta between two
    /// scrapes, false for one placed by the server's own absolute stall
    /// timestamps. Bot-side starvation windows are self-measured, so they are
    /// never approximate.
    #[serde(default)]
    pub approximate: bool,
}

impl Window {
    /// A window whose edges are a measurement.
    pub fn exact(start_ms: u64, end_ms: u64, events: u64, stall_ms: u64) -> Self {
        Self {
            start_ms,
            end_ms,
            events,
            stall_ms,
            approximate: false,
        }
    }

    /// A window that only brackets when the cause could have happened.
    pub fn bracket(start_ms: u64, end_ms: u64, events: u64, stall_ms: u64) -> Self {
        Self {
            start_ms,
            end_ms,
            events,
            stall_ms,
            approximate: true,
        }
    }
}

/// One latency sample: sent `at_ms` after the run started, answered
/// `latency_ms` later.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TailSample {
    pub at_ms: u64,
    pub latency_ms: f64,
}

/// What the collected samples say about where the tail came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailAttribution {
    /// The threshold a "tail sample" is defined against: E1.1's SLA.
    pub threshold_ms: f64,
    /// Samples at or above `threshold_ms`.
    pub tail_count: usize,
    /// ... of which overlap a window in which the server's own world-loop
    /// stall counters increased.
    pub server_stall: usize,
    /// ... of those `server_stall` samples whose explaining window is a
    /// measurement rather than a bracket (see
    /// [`crate::server_metrics::StallWindowPrecision`]). The gap between
    /// this and `server_stall` is how much of the attribution is only
    /// "somewhere in this interval".
    #[serde(default)]
    pub server_stall_precise: usize,
    /// ... of which overlap a window in which the loadtest process's own
    /// timer was late firing (i.e. the bot side, not the server, was
    /// starved).
    pub bot_starvation: usize,
    /// ... of which fall inside the login ramp (plus its tail), where
    /// Argon2id login work is competing with the mix.
    pub login_ramp: usize,
    /// ... of which have none of the above explanations.
    pub unattributed: usize,
    /// `server_stall / tail_count`, the single number the OBI-344
    /// instrumentation was added to produce.
    pub server_stall_pct: f64,
    /// p99 over all samples -- the number the gate uses.
    pub p99_ms: f64,
    /// p99 recomputed with server-stall-attributed samples removed.
    /// Informational only: it is *not* a gate, and the SLA stays measured
    /// by `p99_ms`. It exists to answer "is the gate failing because of the
    /// server, or because of the measurement?" with a number instead of an
    /// argument.
    pub p99_excluding_server_stall_ms: f64,
    pub server_stall_windows: Vec<Window>,
    pub bot_starvation_windows: Vec<Window>,
    /// Milliseconds of ramp + last login, i.e. the end of the window in
    /// which login work could still be competing.
    pub login_ramp_end_ms: u64,
    /// The scrape interval the server windows were derived at, so a reader
    /// knows the attribution's resolution.
    pub scrape_resolution_ms: u64,
    /// How those windows were placed: by the server's own absolute stall
    /// timestamps, or only bracketed between two scrapes. A reader must know
    /// this before drawing any conclusion from `unattributed` (OBI-371).
    #[serde(default)]
    pub stall_window_precision: crate::server_metrics::StallWindowPrecision,
}

/// Does the sample's in-flight interval `[at, at + latency]` intersect
/// `window`?
pub fn sample_overlaps(sample_start_ms: u64, sample_end_ms: u64, window: &Window) -> bool {
    window.start_ms <= sample_end_ms && sample_start_ms <= window.end_ms
}

/// The first window that explains a sample, preferring a *measured* window
/// over a bracket when several overlap.
///
/// The preference matters for how the report reads: `server_stall_precise`
/// counts the tail samples explained by a window whose edges are the
/// server's own timestamps, and a sample that overlaps both an exact stall
/// window and the wider bracket covering its older sibling is precisely
/// explained by the former.
pub fn explaining_window(
    sample_start_ms: u64,
    sample_end_ms: u64,
    windows: &[Window],
) -> Option<&Window> {
    let mut bracket = None;
    for w in windows {
        if !sample_overlaps(sample_start_ms, sample_end_ms, w) {
            continue;
        }
        if !w.approximate {
            return Some(w);
        }
        bracket.get_or_insert(w);
    }
    bracket
}

/// Turn self-measured lag samples into starvation windows.
///
/// A timer that was supposed to fire at `T` but only fired at `T + lag`
/// means the runtime could not run that task over `[T, T + lag]` -- and
/// neither it, nor anything else scheduled on that worker, got CPU. Samples
/// arrive as `(offset observed, lag ms)`, so the window is
/// `[at - lag, at]`. Only lag at or above `threshold_ms` is windowed:
/// sub-threshold jitter is normal scheduling noise and would swallow the
/// whole run in windows.
pub fn lag_windows(samples: &[(u64, f64)], threshold_ms: f64) -> Vec<Window> {
    let mut windows: Vec<Window> = samples
        .iter()
        .filter(|(_, lag)| *lag >= threshold_ms)
        .map(|(at, lag)| Window::exact(at.saturating_sub(*lag as u64), *at, 1, *lag as u64))
        .collect();
    // Merge overlapping windows so the report shows episodes, not one row
    // per sample.
    windows.sort_by_key(|w| w.start_ms);
    let mut merged: Vec<Window> = Vec::with_capacity(windows.len());
    for w in windows {
        match merged.last_mut() {
            Some(prev) if w.start_ms <= prev.end_ms => {
                prev.end_ms = prev.end_ms.max(w.end_ms);
                prev.events += 1;
                prev.stall_ms = prev.stall_ms.max(w.stall_ms);
                // A merge keeps the weaker claim: once a bracket is in the
                // window, the window is a bracket.
                prev.approximate |= w.approximate;
            }
            _ => merged.push(w),
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(start: u64, end: u64) -> Window {
        Window::exact(start, end, 1, 0)
    }

    #[test]
    fn a_sample_inside_a_window_is_explained() {
        assert!(sample_overlaps(1_050, 1_300, &w(1_000, 2_000)));
    }

    #[test]
    fn a_measurement_wins_over_a_bracket_that_also_covers_the_sample() {
        // Two stalls in one scrape interval: the newer one is measured, the
        // older is bracketed across both. A sample inside the measured window
        // must be reported as precisely attributed, not as a lucky guess.
        let windows = [
            Window::bracket(800, 2_000, 1, 200),
            Window::exact(1_400, 1_900, 1, 500),
        ];
        let explained = explaining_window(1_500, 1_600, &windows).expect("overlap");
        assert!(!explained.approximate);
        // A sample only the bracket reaches is still explained -- just not
        // precisely.
        let only_bracket = explaining_window(850, 860, &windows).expect("overlap");
        assert!(only_bracket.approximate);
    }

    #[test]
    fn bot_starvation_windows_are_measurements_not_brackets() {
        // The bot stamps its own starvation windows from lag it measured, so
        // they must not carry the `approximate` caveat that a scrape-interval
        // bracket does.
        let windows = lag_windows(&[(1_000, 60.0)], 50.0);
        assert_eq!(windows.len(), 1);
        assert!(!windows[0].approximate, "{windows:?}");
    }

    #[test]
    fn lag_samples_become_starvation_windows_and_merge() {
        let samples = [(1_000, 60.0), (1_040, 80.0), (5_000, 5.0)];
        let windows = lag_windows(&samples, 50.0);
        // The 5 ms sample is ordinary jitter and is dropped; the two slow
        // ones overlap and merge into one episode.
        assert_eq!(windows.len(), 1, "{windows:?}");
        assert_eq!(windows[0].start_ms, 940);
        assert_eq!(windows[0].end_ms, 1_040);
        assert_eq!(windows[0].events, 2);
        assert_eq!(windows[0].stall_ms, 80);
        assert!(lag_windows(&samples, 100.0).is_empty());
    }

    #[test]
    fn a_sample_spanning_a_window_is_explained() {
        // Sent before the stall, answered after it: it waited for it.
        assert!(sample_overlaps(900, 2_100, &w(1_000, 2_000)));
        assert!(
            explaining_window(900, 2_100, &[w(500, 600), w(1_000, 2_000)])
                .unwrap()
                .start_ms
                == 1_000
        );
    }

    #[test]
    fn samples_outside_every_window_are_not_explained() {
        let windows = [w(1_000, 2_000)];
        assert!(!sample_overlaps(2_500, 2_510, &windows[0]));
        assert!(!sample_overlaps(500, 900, &windows[0]));
        assert!(explaining_window(2_500, 2_510, &windows).is_none());
    }

    #[test]
    fn zero_length_sample_at_a_window_edge_still_matches() {
        assert!(sample_overlaps(1_000, 1_000, &w(1_000, 2_000)));
        assert!(sample_overlaps(2_000, 2_000, &w(1_000, 2_000)));
        assert!(!sample_overlaps(999, 999, &w(1_000, 2_000)));
    }
}
