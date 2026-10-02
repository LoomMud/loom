// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! P2-B5: `profile <program>` per-function tick/time sampling (OBI-170,
//! Loom Phase 2 plan §8.3).
//!
//! One [`Profiler`] is a single open sampling window, owned by
//! `bcvm::registry::Registry` (same home as `CowMetrics`/
//! `QuotaBreachMetrics`: a counters struct read back through `World`) for
//! the lifetime between `profile_start(program)` and `profile_stop()`.
//! While `Registry::profiler` is `None` (the common case — profiling is
//! off), the only cost on the call hot path is the single `is_some_and`
//! branch in `Host::profiling_active`'s default-false check
//! (`bcvm::vm::Interpreter::push_call`/`pop_frame`): no clock read, no
//! allocation, no hashing. That is the "overhead when profiling is off is
//! unmeasurable" acceptance bar (OBI-170) — this module itself only ever
//! does work while a window is actually open.
//!
//! **Scope note (flagged, not a silent gap):** this samples calls *into
//! one program* (`profile <program>`'s own argument), by (inclusive) wall
//! time and ticks charged while each call's frame was on the stack,
//! keyed by function name. Time attributed to a function therefore
//! includes whatever it called (gprof-style "cumulative", not "self"
//! time) — simpler to collect correctly, and the acceptance criterion
//! ("per-function tick/time sampling... a known hot function") does not
//! ask for self/exclusive separation. A suspended call
//! (`Interpreter::suspend_after_ticks`/`resume`, D26) left parked across a
//! real-time gap (e.g. an efun awaiting a DB round trip) would count that
//! gap as wall time too; this is a builder profiling aid, not a billing
//! or SLA measurement, so that skew is accepted rather than engineered
//! around here.

use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Default, Clone, Copy)]
struct FuncStat {
    calls: u64,
    ticks: u64,
    wall: Duration,
}

/// One open sampling window for a single program (spec: `profile
/// <program>`). Created by `World::profile_start`/the `profile_start`
/// efun, consumed by `World::profile_stop`/`profile_stop`.
pub struct Profiler {
    program: String,
    started: Instant,
    stats: HashMap<String, FuncStat>,
}

impl Profiler {
    pub fn new(program: String) -> Self {
        Profiler {
            program,
            started: Instant::now(),
            stats: HashMap::new(),
        }
    }

    pub fn program(&self) -> &str {
        &self.program
    }

    /// `Host::profiling_active`'s cheap check (called on every Weft
    /// function call, profiling on or off): is `program` the one this
    /// window is sampling?
    pub fn wants(&self, program: &str) -> bool {
        self.program == program
    }

    /// Record one completed call into the sampled program: `function`'s
    /// name, `ticks` charged while its frame was active, and `wall` time
    /// elapsed over the same span.
    pub fn record(&mut self, function: &str, ticks: u64, wall: Duration) {
        let entry = self.stats.entry(function.to_string()).or_default();
        entry.calls += 1;
        entry.ticks += ticks;
        entry.wall += wall;
    }

    /// Close the window out as a [`ProfileReport`] (does not consume
    /// `self` — the caller, `World::profile_stop`, owns discarding the
    /// `Profiler`).
    pub fn report(&self) -> ProfileReport {
        let mut rows: Vec<ProfileRow> = self
            .stats
            .iter()
            .map(|(function, s)| ProfileRow {
                function: function.clone(),
                calls: s.calls,
                ticks: s.ticks,
                wall_us: s.wall.as_micros() as u64,
            })
            .collect();
        // Busiest (most ticks charged) function first -- the one a
        // builder chasing a "too long evaluation" tick-limit error, or a
        // slow command, wants to see at the top.
        rows.sort_by(|a, b| b.ticks.cmp(&a.ticks).then(b.wall_us.cmp(&a.wall_us)));
        ProfileReport {
            program: self.program.clone(),
            window_ms: self.started.elapsed().as_millis() as u64,
            rows,
        }
    }
}

/// One function's totals over a sampling window.
pub struct ProfileRow {
    pub function: String,
    pub calls: u64,
    pub ticks: u64,
    pub wall_us: u64,
}

/// `profile <program>`'s result: every function of `program` observed
/// during the window, busiest first.
pub struct ProfileReport {
    pub program: String,
    pub window_ms: u64,
    pub rows: Vec<ProfileRow>,
}

impl ProfileReport {
    /// Builder-facing in-game text (OBI-170 acceptance: "output is
    /// readable in-game") — a fixed-width table, one line per sampled
    /// function.
    pub fn render(&self) -> String {
        let mut out = format!("profile {} ({} ms window)\n", self.program, self.window_ms);
        if self.rows.is_empty() {
            out.push_str("  (no calls observed)\n");
            return out;
        }
        out.push_str(&format!(
            "  {:<28} {:>8} {:>10} {:>10} {:>10}\n",
            "FUNCTION", "CALLS", "TICKS", "US", "US/CALL"
        ));
        for r in &self.rows {
            let us_per_call = r.wall_us.checked_div(r.calls).unwrap_or(0);
            out.push_str(&format!(
                "  {:<28} {:>8} {:>10} {:>10} {:>10}\n",
                r.function, r.calls, r.ticks, r.wall_us, us_per_call
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wants_matches_only_its_own_program() {
        let p = Profiler::new("/std/room".to_string());
        assert!(p.wants("/std/room"));
        assert!(!p.wants("/std/npc"));
    }

    #[test]
    fn record_accumulates_calls_ticks_and_wall_per_function() {
        let mut p = Profiler::new("/std/room".to_string());
        p.record("look", 5, Duration::from_micros(100));
        p.record("look", 7, Duration::from_micros(200));
        p.record("enter", 2, Duration::from_micros(50));
        let report = p.report();
        let look = report.rows.iter().find(|r| r.function == "look").unwrap();
        assert_eq!(look.calls, 2);
        assert_eq!(look.ticks, 12);
        assert_eq!(look.wall_us, 300);
        let enter = report.rows.iter().find(|r| r.function == "enter").unwrap();
        assert_eq!(enter.calls, 1);
        assert_eq!(enter.ticks, 2);
    }

    /// Acceptance: "a test covers a known hot function" -- the busiest
    /// function (most ticks charged over the window) sorts first, so a
    /// builder reading the report top-down finds it immediately.
    #[test]
    fn report_sorts_hottest_function_first() {
        let mut p = Profiler::new("/std/room".to_string());
        p.record("cold", 1, Duration::from_micros(1));
        p.record("hot", 1000, Duration::from_micros(500));
        p.record("warm", 50, Duration::from_micros(10));
        let report = p.report();
        let names: Vec<&str> = report.rows.iter().map(|r| r.function.as_str()).collect();
        assert_eq!(names, vec!["hot", "warm", "cold"]);
    }

    #[test]
    fn render_is_readable_in_game_text() {
        let mut p = Profiler::new("/std/room".to_string());
        p.record("look", 500, Duration::from_micros(1200));
        let report = p.report();
        let text = report.render();
        assert!(text.starts_with("profile /std/room ("));
        assert!(text.contains("FUNCTION"));
        assert!(text.contains("look"));
        assert!(text.contains("500")); // ticks
    }

    #[test]
    fn render_handles_an_empty_window() {
        let p = Profiler::new("/std/room".to_string());
        let text = p.report().render();
        assert!(text.contains("no calls observed"));
    }
}
