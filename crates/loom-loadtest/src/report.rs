// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Latency percentile computation and the run report format committed
//! under `results/` per the E1.1 acceptance criteria (OBI-40).

use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Default, Clone)]
pub struct Samples {
    micros: Vec<u64>,
}

impl Samples {
    pub fn push(&mut self, d: Duration) {
        self.micros.push(d.as_micros() as u64);
    }

    pub fn len(&self) -> usize {
        self.micros.len()
    }

    pub fn is_empty(&self) -> bool {
        self.micros.is_empty()
    }

    /// Nearest-rank percentile (`p` in `0.0..=1.0`) over the collected
    /// samples, in whole microseconds. Panics if empty; callers check
    /// `is_empty()` first.
    pub fn percentile(&self, p: f64) -> u64 {
        assert!(!self.micros.is_empty(), "percentile of empty sample set");
        let mut sorted = self.micros.clone();
        sorted.sort_unstable();
        let idx = ((p * sorted.len() as f64).ceil() as usize)
            .saturating_sub(1)
            .min(sorted.len() - 1);
        sorted[idx]
    }

    pub fn mean_micros(&self) -> f64 {
        if self.micros.is_empty() {
            return 0.0;
        }
        self.micros.iter().sum::<u64>() as f64 / self.micros.len() as f64
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
    pub e1_1_pass: bool,
    pub notes: Vec<String>,
    /// Raw `/metrics` scrape from `loom-http` at the end of the run
    /// (OBI-177), if `--metrics-url` was given. Not parsed/aggregated here
    /// -- bot-side latency remains the E1.1 source of truth -- this is
    /// just carried through so a report has the server's own counters
    /// alongside the bot's view.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_metrics: Option<String>,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_of_known_set() {
        let mut s = Samples::default();
        for ms in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] {
            s.push(Duration::from_millis(ms));
        }
        // Nearest-rank p50 of 10 samples 1..=10 is the 5th value = 5ms.
        assert_eq!(s.percentile(0.50), 5_000);
        assert_eq!(s.percentile(0.99), 10_000);
        assert_eq!(s.percentile(1.0), 10_000);
    }

    #[test]
    fn report_from_samples_converts_to_millis() {
        let mut s = Samples::default();
        s.push(Duration::from_millis(20));
        s.push(Duration::from_millis(40));
        let r = LatencyReport::from_samples(&s).unwrap();
        assert_eq!(r.count, 2);
        assert!((r.p50_ms - 20.0).abs() < 0.001 || (r.p50_ms - 40.0).abs() < 0.001);
    }

    #[test]
    fn report_from_empty_samples_is_none() {
        assert!(LatencyReport::from_samples(&Samples::default()).is_none());
    }

    #[test]
    fn markdown_reports_pass_when_under_sla() {
        let mut s = Samples::default();
        for _ in 0..100 {
            s.push(Duration::from_millis(10));
        }
        let report = RunReport {
            players: 150,
            slow_reader_fraction: 0.1,
            requested_duration_secs: 60,
            actual_duration_secs: 60.2,
            login_failures: 0,
            disconnects: 0,
            commands_sent: 100,
            sla_p99_ms: 50.0,
            command_latency: LatencyReport::from_samples(&s),
            slow_reader_command_latency: None,
            login_latency: None,
            e1_1_pass: true,
            notes: vec![],
            server_metrics: None,
        };
        let md = report.to_markdown();
        assert!(md.contains("PASS"));
        assert!(md.contains("150 players"));
    }
}
