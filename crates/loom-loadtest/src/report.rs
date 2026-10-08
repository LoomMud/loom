// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Latency percentile computation and the run report format committed
//! under `results/` per the E1.1 acceptance criteria (OBI-40).
//!
//! OBI-344: a percentile alone cannot explain its own tail. Every sample is
//! now recorded with the offset it was taken at, and the report carries the
//! run's timeline, the slowest samples, the server's own counter series, and
//! the attribution computed from them (see [`crate::attribution`]).

use serde::Serialize;
use std::time::Duration;

use crate::attribution::{TailAttribution, TailSample, Window, explaining_window};

/// Nearest-rank percentile over an already-sorted microsecond series,
/// returned in microseconds. `p` is `0.0..=1.0`. Empty input yields `0`;
/// callers that must distinguish "no samples" check `is_empty` first.
fn nearest_rank(sorted_us: &[u64], p: f64) -> u64 {
    if sorted_us.is_empty() {
        return 0;
    }
    let idx = ((p * sorted_us.len() as f64).ceil() as usize)
        .saturating_sub(1)
        .min(sorted_us.len() - 1);
    sorted_us[idx]
}

#[derive(Debug, Default, Clone)]
pub struct Samples {
    /// `(offset ms since the run started, latency in whole microseconds)`.
    timed: Vec<(u64, u64)>,
}

impl Samples {
    /// Record a sample together with when it was sent, in milliseconds since
    /// the run started. This is what makes tail attribution possible.
    pub fn push_at(&mut self, at_ms: u64, d: Duration) {
        self.timed.push((at_ms, d.as_micros() as u64));
    }

    pub fn len(&self) -> usize {
        self.timed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.timed.is_empty()
    }

    /// Every sample as `(offset ms, micros)`, in the order recorded.
    pub fn timed(&self) -> &[(u64, u64)] {
        &self.timed
    }

    /// Nearest-rank percentile (`p` in `0.0..=1.0`) over the collected
    /// samples, in whole microseconds. Panics if empty; callers check
    /// `is_empty()` first.
    pub fn percentile(&self, p: f64) -> u64 {
        assert!(!self.timed.is_empty(), "percentile of empty sample set");
        let mut sorted: Vec<u64> = self.timed.iter().map(|(_, us)| *us).collect();
        sorted.sort_unstable();
        nearest_rank(&sorted, p)
    }

    pub fn mean_micros(&self) -> f64 {
        if self.timed.is_empty() {
            return 0.0;
        }
        self.timed.iter().map(|(_, us)| *us).sum::<u64>() as f64 / self.timed.len() as f64
    }

    /// The `n` slowest samples, slowest first (offsets break ties), with
    /// their send offsets.
    pub fn slowest(&self, n: usize) -> Vec<TailSample> {
        let mut sorted: Vec<&(u64, u64)> = self.timed.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(&a.0)));
        sorted
            .into_iter()
            .take(n)
            .map(|(at_ms, us)| TailSample {
                at_ms: *at_ms,
                latency_ms: *us as f64 / 1000.0,
            })
            .collect()
    }

    /// Every sample at or above `threshold_ms`, in send order.
    pub fn exceeding(&self, threshold_ms: f64) -> Vec<TailSample> {
        let threshold_us = (threshold_ms * 1000.0) as u64;
        let mut out: Vec<TailSample> = self
            .timed
            .iter()
            .filter(|(_, us)| *us >= threshold_us)
            .map(|(at_ms, us)| TailSample {
                at_ms: *at_ms,
                latency_ms: *us as f64 / 1000.0,
            })
            .collect();
        out.sort_by_key(|s| s.at_ms);
        out
    }

    /// Percentiles over fixed-width time buckets -- the shape of the run, so
    /// a tail can be seen to be a burst rather than inferred from a number.
    /// `sla_ms` is what each bucket's `over_sla` counts against.
    pub fn buckets(&self, bucket_ms: u64, sla_ms: f64) -> Vec<TimelineBucket> {
        if self.timed.is_empty() || bucket_ms == 0 {
            return Vec::new();
        }
        let last_at = self.timed.iter().map(|(at, _)| *at).max().unwrap_or(0);
        let over_sla_us = (sla_ms * 1000.0) as u64;
        let mut out = Vec::new();
        let mut start = 0;
        while start <= last_at {
            let items: Vec<u64> = self
                .timed
                .iter()
                .filter(|(at, _)| *at >= start && *at < start + bucket_ms)
                .map(|(_, us)| *us)
                .collect();
            if !items.is_empty() {
                out.push(TimelineBucket::one(start, &items, over_sla_us));
            }
            start += bucket_ms;
        }
        out
    }
}

/// Latency percentiles within one slice of the run.
#[derive(Debug, Clone, Serialize)]
pub struct TimelineBucket {
    pub start_ms: u64,
    pub count: usize,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub mean_ms: f64,
    /// How many of this bucket's samples are at or above the SLA threshold.
    pub over_sla: usize,
    /// Whether the server's world-loop stall counters increased inside this
    /// bucket (OBI-344). `None` when the run scraped no metrics URL, which
    /// the report renders as "not observed" rather than as "no stalls".
    pub server_stalled: Option<bool>,
}

impl TimelineBucket {
    fn one(start_ms: u64, sorted_us: &[u64], over_sla_us: u64) -> Self {
        let mut sorted = sorted_us.to_vec();
        sorted.sort_unstable();
        let pct = |p: f64| nearest_rank(&sorted, p) as f64 / 1000.0;
        Self {
            start_ms,
            count: sorted.len(),
            p50_ms: pct(0.50),
            p95_ms: pct(0.95),
            p99_ms: pct(0.99),
            max_ms: pct(1.0),
            mean_ms: sorted.iter().sum::<u64>() as f64 / sorted.len() as f64 / 1000.0,
            over_sla: sorted.iter().filter(|us| **us >= over_sla_us).count(),
            server_stalled: None,
        }
    }

    /// Stamp each bucket with whether any of `windows` overlaps it, so the
    /// timeline table lines the latency shape up against the server's own
    /// stall counters in one view. `bucket_ms` is the width the buckets were
    /// built with.
    pub fn mark_server_stalls(buckets: &mut [Self], windows: &[Window], bucket_ms: u64) {
        for b in buckets.iter_mut() {
            let end = b.start_ms.saturating_add(bucket_ms);
            b.server_stalled = Some(
                windows
                    .iter()
                    .any(|w| w.start_ms < end && b.start_ms < w.end_ms.max(w.start_ms + 1)),
            );
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct LatencyReport {
    pub count: usize,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub mean_ms: f64,
}

impl LatencyReport {
    pub fn from_samples(s: &Samples) -> Option<Self> {
        if s.is_empty() {
            return None;
        }
        Some(Self {
            count: s.len(),
            p50_ms: s.percentile(0.50) as f64 / 1000.0,
            p95_ms: s.percentile(0.95) as f64 / 1000.0,
            p99_ms: s.percentile(0.99) as f64 / 1000.0,
            max_ms: s.percentile(1.0) as f64 / 1000.0,
            mean_ms: s.mean_micros() / 1000.0,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct RunReport {
    pub players: usize,
    pub slow_reader_fraction: f64,
    pub requested_duration_secs: u64,
    pub actual_duration_secs: f64,
    pub login_failures: usize,
    pub disconnects: usize,
    pub commands_sent: usize,
    pub sla_p99_ms: f64,
    /// Latency of normal-cohort commands only; this is what E1.1 is
    /// measured against. Slow-reader latency is reported separately so an
    /// intentionally-delayed cohort can't mask (or inflate) the SLA number.
    pub command_latency: Option<LatencyReport>,
    pub slow_reader_command_latency: Option<LatencyReport>,
    pub login_latency: Option<LatencyReport>,
    /// The account-service half of each login (Argon2id + `login_start`),
    /// split out because it is the only part of a slow login that does *not*
    /// involve the world thread (OBI-344).
    pub login_auth_latency: Option<LatencyReport>,
    /// Commands that never reached the prompt within the bot's timeout and
    /// were therefore excluded from `command_latency`. A gate that reports
    /// p99 without this number cannot prove its distribution is complete.
    pub prompt_timeouts: usize,
    pub e1_1_pass: bool,
    pub notes: Vec<String>,
    /// Latency percentiles per fixed-width slice of the run (OBI-344).
    pub latency_timeline: Vec<TimelineBucket>,
    /// The slowest command samples with the offset they were sent at
    /// (OBI-344): the raw material behind `command_latency.max_ms`.
    pub tail_samples: Vec<TailSample>,
    /// Where the tail came from (OBI-344). `None` when the run collected
    /// nothing to attribute against; that is reported as "not observed",
    /// never as "no stalls".
    pub tail_attribution: Option<TailAttribution>,
    /// The world thread's own counters, scraped once per scrape interval
    /// during the run (OBI-344).
    pub server_timeline: Vec<crate::server_metrics::ServerRow>,
    /// Whether the scraped server actually publishes `loom_world_loop_*`.
    pub server_instrumented: bool,
    /// Self-measured scheduling lag of the loadtest process: how late a
    /// fixed-interval timer actually fired. The bot side of the attribution
    /// -- a starved measuring process cannot report 50 ms honestly.
    pub bot_timer_lag: Option<LatencyReport>,
    /// Raw `/metrics` scrape from `loom-http` at the end of the run
    /// (OBI-177), if `--metrics-url` was given. Not parsed/aggregated here
    /// -- bot-side latency remains the E1.1 source of truth -- this is
    /// just carried through so a report has the server's own counters
    /// alongside the bot's view.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_metrics: Option<String>,
}

/// Everything [`attribute_tail`] needs, assembled by `main` from the data
/// this run collected.
pub struct AttributionInput<'a> {
    pub samples: &'a Samples,
    pub sla_p99_ms: f64,
    pub server_stall_windows: Vec<Window>,
    pub bot_starvation_windows: Vec<Window>,
    /// Ramp end plus the slowest login: the window in which Argon2id login
    /// work can still be competing with the command mix.
    pub login_ramp_end_ms: u64,
    pub scrape_resolution_ms: u64,
}

/// Classify every SLA-exceeding sample against the windows this run
/// observed, and report the single number OBI-344 asked for: how much of the
/// tail sits inside a server stall window.
///
/// Causes are ranked, so a sample is counted once: a server stall outranks
/// bot starvation, which outranks the login ramp. The window overlap test
/// uses the sample's whole in-flight interval (`at ..= at + latency`), see
/// [`crate::attribution`].
pub fn attribute_tail(input: &AttributionInput<'_>) -> Option<TailAttribution> {
    if input.samples.is_empty() {
        return None;
    }
    let tail = input.samples.exceeding(input.sla_p99_ms);
    let p99_ms = input.samples.percentile(0.99) as f64 / 1000.0;

    let mut server_stall = 0usize;
    let mut bot_starvation = 0usize;
    let mut login_ramp = 0usize;
    let mut unattributed = 0usize;
    // The same pass builds the "excluding server stalls" re-rank: every
    // sample that no stall window explains.
    let mut rest: Vec<u64> = Vec::with_capacity(input.samples.len());
    for (at_ms, us) in input.samples.timed() {
        let end = at_ms.saturating_add((*us as f64 / 1000.0).ceil() as u64);
        if explaining_window(*at_ms, end, &input.server_stall_windows).is_none() {
            rest.push(*us);
        }
    }
    rest.sort_unstable();
    for s in &tail {
        let end = s.at_ms.saturating_add(s.latency_ms.ceil() as u64);
        if explaining_window(s.at_ms, end, &input.server_stall_windows).is_some() {
            server_stall += 1;
        } else if explaining_window(s.at_ms, end, &input.bot_starvation_windows).is_some() {
            bot_starvation += 1;
        } else if s.at_ms <= input.login_ramp_end_ms {
            login_ramp += 1;
        } else {
            unattributed += 1;
        }
    }

    Some(TailAttribution {
        threshold_ms: input.sla_p99_ms,
        tail_count: tail.len(),
        server_stall,
        bot_starvation,
        login_ramp,
        unattributed,
        server_stall_pct: if tail.is_empty() {
            0.0
        } else {
            server_stall as f64 * 100.0 / tail.len() as f64
        },
        p99_ms,
        p99_excluding_server_stall_ms: nearest_rank(&rest, 0.99) as f64 / 1000.0,
        server_stall_windows: input.server_stall_windows.clone(),
        bot_starvation_windows: input.bot_starvation_windows.clone(),
        login_ramp_end_ms: input.login_ramp_end_ms,
        scrape_resolution_ms: input.scrape_resolution_ms,
    })
}

impl RunReport {
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("# Load-test run: {} players\n\n", self.players));
        out.push_str(&format!(
            "- Requested duration: {}s (actual: {:.1}s)\n",
            self.requested_duration_secs, self.actual_duration_secs
        ));
        out.push_str(&format!(
            "- Slow-reader cohort: {:.0}%\n",
            self.slow_reader_fraction * 100.0
        ));
        out.push_str(&format!("- Login failures: {}\n", self.login_failures));
        out.push_str(&format!(
            "- Disconnects (incl. slow-reader backpressure drops): {}\n",
            self.disconnects
        ));
        out.push_str(&format!(
            "- Commands sent (normal cohort): {}\n",
            self.commands_sent
        ));
        out.push_str(&format!(
            "- Prompt timeouts, excluded from the distribution: {}\n",
            self.prompt_timeouts
        ));
        if self.prompt_timeouts > 0 {
            out.push_str("  _(a command that never reached the prompt is not a fast sample: this run's percentiles describe only what completed)_\n");
        }
        out.push('\n');
        if let Some(l) = &self.command_latency {
            out.push_str("## Command latency (normal cohort, send -> prompt)\n\n");
            out.push_str(&format!(
                "| p50 | p95 | p99 | max | mean | n |\n|---|---|---|---|---|---|\n\
                 | {:.2} ms | {:.2} ms | {:.2} ms | {:.2} ms | {:.2} ms | {} |\n\n",
                l.p50_ms, l.p95_ms, l.p99_ms, l.max_ms, l.mean_ms, l.count
            ));
            out.push_str(&format!(
                "**E1.1 (p99 < {:.0} ms): {}**\n\n",
                self.sla_p99_ms,
                if self.e1_1_pass { "PASS" } else { "FAIL" }
            ));
        } else {
            out.push_str("## Command latency\n\nNo samples collected.\n\n");
        }
        if let Some(l) = &self.slow_reader_command_latency {
            out.push_str("## Command latency (slow-reader cohort, informational only)\n\n");
            out.push_str(&format!(
                "| p50 | p95 | p99 | max | mean | n |\n|---|---|---|---|---|---|\n\
                 | {:.2} ms | {:.2} ms | {:.2} ms | {:.2} ms | {:.2} ms | {} |\n\n",
                l.p50_ms, l.p95_ms, l.p99_ms, l.max_ms, l.mean_ms, l.count
            ));
        }
        if let Some(l) = &self.login_latency {
            out.push_str("## Login latency (name -> first prompt, Argon2id included)\n\n");
            out.push_str(&format!(
                "| p50 | p95 | p99 | max | mean | n |\n|---|---|---|---|---|---|\n\
                 | {:.2} ms | {:.2} ms | {:.2} ms | {:.2} ms | {:.2} ms | {} |\n\n",
                l.p50_ms, l.p95_ms, l.p99_ms, l.max_ms, l.mean_ms, l.count
            ));
        }
        if let Some(a) = &self.login_auth_latency {
            out.push_str(&format!(
                "Login split, account-service half only (Argon2id + `login_start`, off the world thread): p50 {:.2} ms, p99 {:.2} ms, max {:.2} ms. Whatever is left of the login p50 above happens on the world thread.\n\n",
                a.p50_ms, a.p99_ms, a.max_ms
            ));
        }
        self.push_tail_sections(&mut out);
        if !self.notes.is_empty() {
            out.push_str("## Notes\n\n");
            for n in &self.notes {
                out.push_str(&format!("- {n}\n"));
            }
            out.push('\n');
        }
        if let Some(m) = &self.server_metrics {
            out.push_str(&format!(
                "## Server-side metrics (`/metrics` scrape, OBI-177)\n\n```\n{m}\n```\n"
            ));
        }
        out
    }

    /// The OBI-344 sections: where in the run the tail sits, what the
    /// server's own counters were doing at those moments, and the
    /// attribution that follows.
    fn push_tail_sections(&self, out: &mut String) {
        if !self.latency_timeline.is_empty() {
            out.push_str("## Latency timeline (normal cohort)\n\n");
            out.push_str("| t+ (s) | n | p50 | p95 | p99 | max | > SLA | server stall in slice |\n|---|---|---|---|---|---|---|---|\n");
            for b in &self.latency_timeline {
                let stalled = match b.server_stalled {
                    Some(true) => "yes",
                    Some(false) => "no",
                    None => "not scraped",
                };
                out.push_str(&format!(
                    "| {:.1} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {} | {stalled} |\n",
                    b.start_ms as f64 / 1000.0,
                    b.count,
                    b.p50_ms,
                    b.p95_ms,
                    b.p99_ms,
                    b.max_ms,
                    b.over_sla,
                ));
            }
            out.push('\n');
        }
        if !self.tail_samples.is_empty() {
            out.push_str(&format!(
                "## Slowest samples (top {}, informational)\n\n",
                self.tail_samples.len()
            ));
            out.push_str("| sent at t+ (s) | latency (ms) |\n|---|---|\n");
            for s in &self.tail_samples {
                out.push_str(&format!(
                    "| {:.3} | {:.2} |\n",
                    s.at_ms as f64 / 1000.0,
                    s.latency_ms
                ));
            }
            out.push('\n');
        }
        if let Some(a) = &self.tail_attribution {
            out.push_str("## Tail attribution (OBI-344)\n\n");
            out.push_str(&format!(
                "- Samples at or over the {:.0} ms SLA: **{}** of {}\n",
                a.threshold_ms, a.tail_count, self.commands_sent
            ));
            out.push_str(&format!(
                "- overlapping a server world-loop stall window: **{}** ({:.0}% of the tail)\n",
                a.server_stall, a.server_stall_pct
            ));
            out.push_str(&format!(
                "- overlapping a loadtest-process timer-starvation window: {}\n",
                a.bot_starvation
            ));
            out.push_str(&format!(
                "- inside the login ramp (t+ <= {:.1} s): {}\n",
                a.login_ramp_end_ms as f64 / 1000.0,
                a.login_ramp
            ));
            out.push_str(&format!(
                "- unexplained by any of the above: **{}**\n",
                a.unattributed
            ));
            out.push_str(&format!(
                "- p99 as measured: {:.2} ms; p99 with server-stall-attributed slices removed: {:.2} ms. Informational only -- the gate stays the former.\n",
                a.p99_ms, a.p99_excluding_server_stall_ms
            ));
            out.push_str(&format!(
                "- Server stall windows are resolved to the {} ms `--metrics-scrape-ms` interval, so attribution is \"inside the same second as a recorded stall\", not per-millisecond.\n\n",
                a.scrape_resolution_ms
            ));
            if !a.server_stall_windows.is_empty() {
                out.push_str("| server stall window (t+ s) | stalls | stall ms |\n|---|---|---|\n");
                for w in &a.server_stall_windows {
                    out.push_str(&format!(
                        "| {:.1} - {:.1} | {} | {} |\n",
                        w.start_ms as f64 / 1000.0,
                        w.end_ms as f64 / 1000.0,
                        w.events,
                        w.stall_ms
                    ));
                }
                out.push('\n');
            }
        } else if self.command_latency.is_some() {
            out.push_str("## Tail attribution (OBI-344)\n\nNothing to attribute against: this run collected no timed samples or no server counters, so the tail is *unexplained* by this report -- not explained. Re-run with `--metrics-url` and a server built with the `loom_world_loop_*` counters.\n\n");
        }
        if let Some(l) = &self.bot_timer_lag {
            out.push_str("## Loadtest process timer lag (self-measured)\n\n");
            out.push_str(&format!(
                "| p50 | p95 | p99 | max | n |\n|---|---|---|---|---|\n\
                 | {:.2} ms | {:.2} ms | {:.2} ms | {:.2} ms | {} |\n\n",
                l.p50_ms, l.p95_ms, l.p99_ms, l.max_ms, l.count
            ));
            out.push_str("How late a fixed-interval timer fired inside the loadtest process. Lag here inflates every latency number this run reports, including the gate's, which is why it is measured rather than assumed away.\n\n");
        }
        if !self.server_timeline.is_empty() {
            out.push_str("## Server world-loop counters (scraped during the run)\n\n");
            if !self.server_instrumented {
                out.push_str("_This server publishes no `loom_world_loop_*` series: the OBI-344 stall counters were absent, so no server-side stall window could be identified._\n\n");
            } else {
                out.push_str("| t+ (s) | tick id | iterations | stalls | stall ms | dur max | gap max | cmd blocked | runtime errors |\n|---|---|---|---|---|---|---|---|---|\n");
                for r in &self.server_timeline {
                    let c = |v: Option<f64>| {
                        v.map(|v| format!("{v:.0}"))
                            .unwrap_or_else(|| "-".to_string())
                    };
                    out.push_str(&format!(
                        "| {:.1} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                        r.at_ms as f64 / 1000.0,
                        c(r.counters.ticks),
                        c(r.counters.iterations),
                        c(r.counters.stalls),
                        c(r.counters.stall_ms),
                        c(r.counters.duration_ms_max),
                        c(r.counters.gap_ms_max),
                        c(r.counters.command_blocked),
                        c(r.counters.runtime_errors),
                    ));
                }
                out.push('\n');
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(start: u64, end: u64) -> Window {
        Window {
            start_ms: start,
            end_ms: end,
            events: 1,
            stall_ms: end.saturating_sub(start),
        }
    }

    #[test]
    fn percentile_of_known_set() {
        let mut s = Samples::default();
        for ms in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] {
            s.push_at(0, Duration::from_millis(ms));
        }
        // Nearest-rank p50 of 10 samples 1..=10 is the 5th value = 5ms.
        assert_eq!(s.percentile(0.50), 5_000);
        assert_eq!(s.percentile(0.99), 10_000);
        assert_eq!(s.percentile(1.0), 10_000);
    }

    #[test]
    fn report_from_samples_converts_to_millis() {
        let mut s = Samples::default();
        s.push_at(0, Duration::from_millis(20));
        s.push_at(0, Duration::from_millis(40));
        let r = LatencyReport::from_samples(&s).unwrap();
        assert_eq!(r.count, 2);
        assert!((r.p50_ms - 20.0).abs() < 0.001 || (r.p50_ms - 40.0).abs() < 0.001);
    }

    #[test]
    fn report_from_empty_samples_is_none() {
        assert!(LatencyReport::from_samples(&Samples::default()).is_none());
    }

    #[test]
    fn timed_samples_keep_their_offset() {
        let mut s = Samples::default();
        s.push_at(1_000, Duration::from_millis(10));
        s.push_at(9_000, Duration::from_millis(400));
        let slowest = s.slowest(1);
        assert_eq!(slowest[0].at_ms, 9_000);
        assert_eq!(slowest[0].latency_ms, 400.0);
        let over = s.exceeding(50.0);
        assert_eq!(over.len(), 1);
        assert_eq!(over[0].at_ms, 9_000);
    }

    #[test]
    fn buckets_slice_the_run_and_count_over_sla() {
        let mut s = Samples::default();
        for (at, ms) in [(0, 5), (1_000, 60), (5_000, 5), (5_500, 90)] {
            s.push_at(at, Duration::from_millis(ms));
        }
        let b = s.buckets(5_000, 50.0);
        assert_eq!(b.len(), 2);
        assert_eq!(b[0].count, 2);
        assert_eq!(b[0].start_ms, 0);
        assert_eq!(b[0].over_sla, 1);
        assert_eq!(b[1].count, 2);
        assert_eq!(b[1].start_ms, 5_000);
        assert_eq!(b[1].max_ms, 90.0);
        assert_eq!(b[1].over_sla, 1);
        assert!(s.buckets(0, 50.0).is_empty());
    }

    #[test]
    fn buckets_flag_the_slice_a_stall_window_touches() {
        let mut s = Samples::default();
        s.push_at(0, Duration::from_millis(5));
        s.push_at(6_000, Duration::from_millis(5));
        let mut b = s.buckets(5_000, 50.0);
        TimelineBucket::mark_server_stalls(&mut b, &[window(5_500, 6_500)], 5_000);
        assert_eq!(b.len(), 2);
        assert_eq!(b[0].server_stalled, Some(false));
        assert_eq!(b[1].server_stalled, Some(true));
        // Without a scrape the bucket stays `None`: "not observed".
        assert_eq!(s.buckets(5_000, 50.0)[0].server_stalled, None);
    }

    #[test]
    fn attribution_ranks_causes_and_counts_the_tail() {
        let mut s = Samples::default();
        s.push_at(500, Duration::from_millis(4));
        // Over SLA, inside a server stall window.
        s.push_at(2_050, Duration::from_millis(400));
        // Over SLA, no server stall, inside a bot-starvation window.
        s.push_at(30_050, Duration::from_millis(300));
        // Over SLA, inside the login ramp and nothing else.
        s.push_at(8_010, Duration::from_millis(120));
        // Over SLA and unexplained.
        s.push_at(60_000, Duration::from_millis(75));

        let a = attribute_tail(&AttributionInput {
            samples: &s,
            sla_p99_ms: 50.0,
            server_stall_windows: vec![window(2_000, 3_000)],
            bot_starvation_windows: vec![window(30_000, 30_500)],
            login_ramp_end_ms: 10_000,
            scrape_resolution_ms: 1_000,
        })
        .unwrap();
        assert_eq!(a.tail_count, 4);
        assert_eq!(a.server_stall, 1);
        assert_eq!(a.bot_starvation, 1);
        assert_eq!(a.login_ramp, 1);
        assert_eq!(a.unattributed, 1);
        assert!((a.server_stall_pct - 25.0).abs() < 0.001);
        assert!(a.p99_ms >= 300.0);
        assert!(a.p99_excluding_server_stall_ms < a.p99_ms);
    }

    #[test]
    fn a_sample_spanning_a_stall_window_is_attributed_to_the_server() {
        // The OBI-344 shape: sent just before a stall, answered after it.
        let mut s = Samples::default();
        s.push_at(60_000, Duration::from_millis(750));
        let a = attribute_tail(&AttributionInput {
            samples: &s,
            sla_p99_ms: 50.0,
            server_stall_windows: vec![window(60_500, 61_000)],
            bot_starvation_windows: vec![],
            login_ramp_end_ms: 0,
            scrape_resolution_ms: 500,
        })
        .unwrap();
        assert_eq!(a.server_stall, 1);
        assert_eq!(a.unattributed, 0);
    }

    #[test]
    fn no_tail_yet_still_reports() {
        let mut s = Samples::default();
        s.push_at(0, Duration::from_millis(3));
        let a = attribute_tail(&AttributionInput {
            samples: &s,
            sla_p99_ms: 50.0,
            server_stall_windows: vec![],
            bot_starvation_windows: vec![],
            login_ramp_end_ms: 10_000,
            scrape_resolution_ms: 1_000,
        })
        .unwrap();
        assert_eq!(a.tail_count, 0);
        assert_eq!(a.server_stall_pct, 0.0);
        assert_eq!(a.p99_ms, 3.0);
    }

    #[test]
    fn no_samples_is_no_attribution() {
        assert!(
            attribute_tail(&AttributionInput {
                samples: &Samples::default(),
                sla_p99_ms: 50.0,
                server_stall_windows: vec![],
                bot_starvation_windows: vec![],
                login_ramp_end_ms: 0,
                scrape_resolution_ms: 1_000,
            })
            .is_none()
        );
    }

    fn empty_report(s: &Samples, attribution: Option<TailAttribution>) -> RunReport {
        RunReport {
            players: 150,
            slow_reader_fraction: 0.1,
            requested_duration_secs: 90,
            actual_duration_secs: 90.4,
            login_failures: 0,
            disconnects: 0,
            commands_sent: s.len(),
            sla_p99_ms: 50.0,
            command_latency: LatencyReport::from_samples(s),
            slow_reader_command_latency: None,
            login_latency: None,
            login_auth_latency: None,
            prompt_timeouts: 0,
            e1_1_pass: s.percentile(0.99) < 50_000,
            notes: vec![],
            latency_timeline: s.buckets(5_000, 50.0),
            tail_samples: s.slowest(5),
            tail_attribution: attribution,
            server_timeline: vec![],
            server_instrumented: false,
            bot_timer_lag: None,
            server_metrics: None,
        }
    }

    #[test]
    fn markdown_reports_pass_when_under_sla() {
        let mut s = Samples::default();
        for _ in 0..100 {
            s.push_at(0, Duration::from_millis(10));
        }
        let md = empty_report(&s, None).to_markdown();
        assert!(md.contains("PASS"));
        assert!(md.contains("150 players"));
        // A report with nothing to attribute must say so rather than imply
        // there were no stalls.
        assert!(
            md.contains("not observed") || md.contains("Nothing to attribute"),
            "{md}"
        );
    }

    #[test]
    fn markdown_carries_the_timeline_and_attribution() {
        let mut s = Samples::default();
        s.push_at(500, Duration::from_millis(4));
        s.push_at(2_500, Duration::from_millis(300));
        let attribution = attribute_tail(&AttributionInput {
            samples: &s,
            sla_p99_ms: 50.0,
            server_stall_windows: vec![window(2_000, 3_000)],
            bot_starvation_windows: vec![],
            login_ramp_end_ms: 10_000,
            scrape_resolution_ms: 1_000,
        });
        let md = empty_report(&s, attribution).to_markdown();
        assert!(md.contains("Latency timeline"), "{md}");
        assert!(md.contains("Slowest samples"), "{md}");
        assert!(md.contains("Tail attribution"), "{md}");
        assert!(
            md.contains("unexplained by any of the above: **0**"),
            "{md}"
        );
        assert!(md.contains("2.0 - 3.0"), "{md}");
    }

    /// OBI-326: a number has to name its inputs. The load lane passes the pinned
    /// mudlib as a note, and the committed Markdown report is where a reader (or
    /// a later bisect) finds out which `warp` commit produced the p99.
    #[test]
    fn markdown_carries_the_mudlib_provenance_note() {
        let mut s = Samples::default();
        s.push(Duration::from_millis(9));
        let report = RunReport {
            players: 150,
            slow_reader_fraction: 0.1,
            requested_duration_secs: 90,
            actual_duration_secs: 90.1,
            login_failures: 0,
            disconnects: 0,
            commands_sent: 1,
            sla_p99_ms: 50.0,
            command_latency: LatencyReport::from_samples(&s),
            slow_reader_command_latency: None,
            login_latency: None,
            e1_1_pass: true,
            notes: vec![
                "mudlib LoomMud/warp@1b0cd394d4cd41586e1a2d5fd449786b75c96976 (pinned in warp.ref)"
                    .to_string(),
            ],
            server_metrics: None,
        };
        let md = report.to_markdown();
        assert!(md.contains("## Notes"), "no notes section in:\n{md}");
        assert!(
            md.contains("warp@1b0cd394"),
            "provenance note missing:\n{md}"
        );
        let json = serde_json::to_string(&report).expect("report serializes");
        assert!(json.contains("1b0cd394"), "note missing from json: {json}");
    }
}
