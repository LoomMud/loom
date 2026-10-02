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

use std::cell::Cell;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Auto-expiry caps (CTO review, OBI-170 PR #67 should-fix 5 / OBI-232):
/// a forgotten window stops sampling on its own rather than running
/// forever. Whichever limit is hit first wins; both are generous enough
/// that a builder chasing a real hot path never notices them in normal
/// use (a `profile`/`profile_stop` session is typically seconds, not
/// minutes, and far fewer than a million calls).
const MAX_WINDOW: Duration = Duration::from_secs(5 * 60);
const MAX_CALLS: u64 = 1_000_000;

#[derive(Default, Clone, Copy)]
struct FuncStat {
    calls: u64,
    /// Inclusive (gprof "cumulative"): everything charged/elapsed while
    /// a call's frame was on the stack, including whatever it called.
    ticks: u64,
    wall: Duration,
    /// Self (gprof "self"/"exclusive", CTO review OBI-170 PR #67
    /// must-fix 2): the same call's own cost with every directly-nested
    /// call into this same sampled program subtracted out --
    /// `Interpreter::pop_frame`'s `ProfFrame::child_ticks`/`child_wall`.
    /// This is what a builder chasing a hot function actually wants:
    /// recursion no longer inflates it depth-many times over.
    self_ticks: u64,
    self_wall: Duration,
}

/// One open sampling window for a single program (spec: `profile
/// <program>`). Created by `World::profile_start`/the `profile_start`
/// efun, consumed by `World::profile_stop`/`profile_stop`.
///
/// **Ownership (CTO review, OBI-170 PR #67 should-fix 4 / OBI-232):**
/// `owner` is the principal (euid name, or whatever identifier the host
/// caller uses) that opened this window. `World`/`RegistryHost` refuse a
/// second `profile_start` from a *different* principal while one is
/// still open, and refuse a `profile_stop` from a different principal
/// unless that caller forces it (see their doc comments) -- this struct
/// itself just carries the name and answers `owner()`; it does not
/// enforce anything (it has no concept of privilege).
pub struct Profiler {
    program: String,
    owner: String,
    started: Instant,
    stats: HashMap<String, FuncStat>,
    /// Total calls recorded so far, across every function -- the
    /// auto-expiry call cap's running count (`MAX_CALLS`).
    total_calls: u64,
    /// Cached result of the first `expiry_reason()` call that actually
    /// found a cap hit (OBI-238: `Profiler::wants` must stop returning
    /// `true` for an expired window, on *every* call into the sampled
    /// program, not just the first one past the cap -- recomputing
    /// `started.elapsed()` on every single call for the rest of the
    /// process's life is exactly the "forgotten window still costs
    /// every call" overhead this closes). `Cell`, not a plain `bool`,
    /// because `wants` only ever gets `&self` (it is called from the
    /// interpreter's hot path on *every* Weft call, on-or-off, and must
    /// not need `&mut self` there) -- this is the one piece of interior
    /// mutability in the module, confined to caching an already-true
    /// fact about a monotonic condition (once expired, always expired).
    expired: Cell<Option<&'static str>>,
}

impl Profiler {
    pub fn new(program: String, owner: String) -> Self {
        Profiler {
            program,
            owner,
            started: Instant::now(),
            stats: HashMap::new(),
            total_calls: 0,
            expired: Cell::new(None),
        }
    }

    pub fn program(&self) -> &str {
        &self.program
    }

    /// The principal that opened this window (see the struct doc).
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// `Host::profiling_active`'s cheap check (called on every Weft
    /// function call, profiling on or off): is `program` the one this
    /// window is sampling, *and* is that window still actually
    /// recording?
    ///
    /// A window that has hit an auto-expiry cap (OBI-238, follow-up to
    /// should-fix 5 / OBI-232) answers `false` here, not just inside
    /// `record`: `record` dropping the sample stopped `stats` from
    /// growing, but every call still paid for a `Box<ProfFrame>`
    /// allocation, two `Instant` reads, and a `profile_record` call that
    /// recomputed `expiry_reason` all over again -- a forgotten window
    /// cost real CPU on every call into the sampled program forever.
    /// Checking `self.program == program` first (a string compare) and
    /// `total_calls` before `started.elapsed()` inside `expiry_reason`
    /// (an integer compare before an `Instant::now()` syscall) keeps the
    /// common "not this program"/"not expired yet" paths cheap.
    pub fn wants(&self, program: &str) -> bool {
        self.program == program && self.expiry_reason().is_none()
    }

    /// Whether this window has hit an auto-expiry cap (should-fix 5,
    /// OBI-232) -- used by `profile_start`'s ownership check (OBI-238):
    /// a different principal may replace an *expired* window outright,
    /// without `profile_stop`/P3-force, because an expired window is no
    /// longer doing anything a live owner could be relying on.
    pub fn is_expired(&self) -> bool {
        self.expiry_reason().is_some()
    }

    /// **Test-only.** Force this window straight to expired, standing in
    /// for actually waiting out `MAX_WINDOW` or making `MAX_CALLS`
    /// real calls (OBI-238's integration test: "use an injectable clock
    /// or the call cap to trigger expiry" -- a literal million calls
    /// through the interpreter is not a reasonable thing to do in a
    /// test). Same shape as `World::begin_recompile_after`'s test-only
    /// `delay` knob: `#[doc(hidden)]`, not gated behind a cfg, because it
    /// does not expose anything a caller couldn't already reach by
    /// legitimately waiting five minutes or making a million calls.
    #[doc(hidden)]
    pub fn force_expire_for_test(&mut self) {
        self.expired.set(Some("call cap (1,000,000 calls) reached"));
    }

    /// `None` while the window is still recording; `Some(reason)` once
    /// it has hit an auto-expiry cap (should-fix 5, OBI-232):
    /// `MAX_WINDOW` wall-clock time open, or `MAX_CALLS` calls recorded,
    /// whichever comes first. `record` consults this to stop
    /// accumulating past the cap; `report` puts the reason in the
    /// rendered header so a forgotten window's output says so instead of
    /// quietly looking like a normal, complete report.
    ///
    /// Cached in `self.expired` the first time either cap is found hit
    /// (OBI-238): both caps are monotonic (calls and wall time only ever
    /// go up), so once true it is true forever, and every subsequent
    /// call -- in particular `wants`, on the interpreter's per-call hot
    /// path -- can skip straight past `started.elapsed()` instead of
    /// reading the clock again.
    fn expiry_reason(&self) -> Option<&'static str> {
        if let Some(reason) = self.expired.get() {
            return Some(reason);
        }
        let reason = if self.total_calls >= MAX_CALLS {
            Some("call cap (1,000,000 calls) reached")
        } else if self.started.elapsed() >= MAX_WINDOW {
            Some("time cap (5 minutes) reached")
        } else {
            None
        };
        if reason.is_some() {
            self.expired.set(reason);
        }
        reason
    }

    /// Record one completed call into the sampled program: `function`'s
    /// name, `ticks`/`wall` charged while its frame was active
    /// (inclusive -- includes whatever it called), and
    /// `self_ticks`/`self_wall`, the same call's own cost with nested
    /// same-program calls subtracted (CTO review, OBI-170, PR #67
    /// must-fix 2).
    pub fn record(
        &mut self,
        function: &str,
        ticks: u64,
        self_ticks: u64,
        wall: Duration,
        self_wall: Duration,
    ) {
        // Should-fix 5 (OBI-232): once a cap is hit, stop accumulating --
        // a forgotten window freezes at its first cap instead of
        // sampling (and growing `stats`) forever.
        if self.expiry_reason().is_some() {
            return;
        }
        let entry = self.stats.entry(function.to_string()).or_default();
        entry.calls += 1;
        entry.ticks += ticks;
        entry.wall += wall;
        entry.self_ticks += self_ticks;
        entry.self_wall += self_wall;
        self.total_calls += 1;
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
                self_ticks: s.self_ticks,
                self_wall_us: s.self_wall.as_micros() as u64,
            })
            .collect();
        // Busiest by **self** ticks first (CTO review, OBI-170, PR #67
        // must-fix 2): inclusive ticks sort the outermost entry point
        // (`process_input`, `heartbeat`) to the top every time (it
        // always has the largest inclusive total, by construction --
        // it's on the stack for the whole call), hiding the actually hot
        // function underneath it. Self ticks is where the function a
        // builder chasing a tick-limit/slow-command actually spent time
        // surfaces.
        rows.sort_by(|a, b| {
            b.self_ticks
                .cmp(&a.self_ticks)
                .then(b.self_wall_us.cmp(&a.self_wall_us))
        });
        ProfileReport {
            program: self.program.clone(),
            owner: self.owner.clone(),
            window_ms: self.started.elapsed().as_millis() as u64,
            stopped_early: self.expiry_reason(),
            rows,
        }
    }
}

/// One function's totals over a sampling window. `self_*` sorts the
/// report (CTO review, OBI-170, PR #67 must-fix 2); `ticks`/`wall_us`
/// (inclusive) are kept as a second column, not dropped.
pub struct ProfileRow {
    pub function: String,
    pub calls: u64,
    pub ticks: u64,
    pub wall_us: u64,
    pub self_ticks: u64,
    pub self_wall_us: u64,
}

/// `profile <program>`'s result: every function of `program` observed
/// during the window, busiest first.
pub struct ProfileReport {
    pub program: String,
    pub owner: String,
    pub window_ms: u64,
    /// `Some(reason)` if the window hit an auto-expiry cap (should-fix
    /// 5, OBI-232) before this report was taken -- rendered into the
    /// header so a forgotten window's output says so plainly instead of
    /// quietly looking like a short, complete run.
    pub stopped_early: Option<&'static str>,
    pub rows: Vec<ProfileRow>,
}

impl ProfileReport {
    /// Builder-facing in-game text (OBI-170 acceptance: "output is
    /// readable in-game") — a fixed-width table, one line per sampled
    /// function.
    pub fn render(&self) -> String {
        let mut out = format!(
            "profile {} ({} ms window, opened by {})\n",
            self.program, self.window_ms, self.owner
        );
        if let Some(reason) = self.stopped_early {
            out.push_str(&format!(
                "  (recording stopped early: {reason} -- report reflects samples up to that point, not the whole window)\n"
            ));
        }
        if self.rows.is_empty() {
            out.push_str("  (no calls observed)\n");
            return out;
        }
        out.push_str(&format!(
            "  {:<28} {:>8} {:>10} {:>10} {:>10} {:>10}\n",
            "FUNCTION", "CALLS", "SELF_TICKS", "TICKS", "SELF_US", "US"
        ));
        for r in &self.rows {
            out.push_str(&format!(
                "  {:<28} {:>8} {:>10} {:>10} {:>10} {:>10}\n",
                r.function, r.calls, r.self_ticks, r.ticks, r.self_wall_us, r.wall_us
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
        let p = Profiler::new("/std/room".to_string(), "builder_alice".to_string());
        assert!(p.wants("/std/room"));
        assert!(!p.wants("/std/npc"));
    }

    #[test]
    fn record_accumulates_calls_ticks_and_wall_per_function() {
        let mut p = Profiler::new("/std/room".to_string(), "builder_alice".to_string());
        p.record(
            "look",
            5,
            5,
            Duration::from_micros(100),
            Duration::from_micros(100),
        );
        p.record(
            "look",
            7,
            7,
            Duration::from_micros(200),
            Duration::from_micros(200),
        );
        p.record(
            "enter",
            2,
            2,
            Duration::from_micros(50),
            Duration::from_micros(50),
        );
        let report = p.report();
        let look = report.rows.iter().find(|r| r.function == "look").unwrap();
        assert_eq!(look.calls, 2);
        assert_eq!(look.ticks, 12);
        assert_eq!(look.wall_us, 300);
        assert_eq!(look.self_ticks, 12);
        assert_eq!(look.self_wall_us, 300);
        let enter = report.rows.iter().find(|r| r.function == "enter").unwrap();
        assert_eq!(enter.calls, 1);
        assert_eq!(enter.ticks, 2);
    }

    /// Acceptance: "a test covers a known hot function" -- the busiest
    /// function by **self** ticks sorts first (CTO review, OBI-170, PR
    /// #67 must-fix 2), so a builder reading the report top-down finds
    /// it immediately -- `outer`'s inclusive total is the largest here
    /// (it's on the stack for the whole call, same as any entry point),
    /// but its own self cost is small; sorting by inclusive instead
    /// would have hidden `hot` underneath it.
    #[test]
    fn report_sorts_by_self_ticks_not_inclusive() {
        let mut p = Profiler::new("/std/room".to_string(), "builder_alice".to_string());
        p.record(
            "cold",
            1,
            1,
            Duration::from_micros(1),
            Duration::from_micros(1),
        );
        p.record(
            "hot",
            1000,
            1000,
            Duration::from_micros(500),
            Duration::from_micros(500),
        );
        p.record(
            "warm",
            50,
            50,
            Duration::from_micros(10),
            Duration::from_micros(10),
        );
        // `outer`'s inclusive total (2000) dwarfs everything above, but
        // its self cost (10) does not.
        p.record(
            "outer",
            2000,
            10,
            Duration::from_micros(2000),
            Duration::from_micros(10),
        );
        let report = p.report();
        let names: Vec<&str> = report.rows.iter().map(|r| r.function.as_str()).collect();
        assert_eq!(names, vec!["hot", "warm", "outer", "cold"]);
    }

    #[test]
    fn render_is_readable_in_game_text() {
        let mut p = Profiler::new("/std/room".to_string(), "builder_alice".to_string());
        p.record(
            "look",
            500,
            500,
            Duration::from_micros(1200),
            Duration::from_micros(1200),
        );
        let report = p.report();
        let text = report.render();
        assert!(text.starts_with("profile /std/room ("));
        assert!(text.contains("FUNCTION"));
        assert!(text.contains("SELF_TICKS"));
        assert!(text.contains("look"));
        assert!(text.contains("500")); // ticks
    }

    #[test]
    fn render_handles_an_empty_window() {
        let p = Profiler::new("/std/room".to_string(), "builder_alice".to_string());
        let text = p.report().render();
        assert!(text.contains("no calls observed"));
    }

    /// Should-fix 4 (OBI-232): the window carries its owning principal,
    /// and that owner shows up in the rendered header -- `World`/
    /// `RegistryHost` are what refuse a second `profile_start`/un-owned
    /// `profile_stop` (this struct just needs to answer `owner()`
    /// correctly and surface it).
    #[test]
    fn owner_is_recorded_and_rendered() {
        let p = Profiler::new("/std/room".to_string(), "builder_alice".to_string());
        assert_eq!(p.owner(), "builder_alice");
        assert!(p.report().render().contains("opened by builder_alice"));
    }

    /// Should-fix 5 (OBI-232): the call cap stops accumulation (not just
    /// reporting) once `MAX_CALLS` is hit, and the report header says so.
    #[test]
    fn call_cap_stops_recording_and_is_reported() {
        let mut p = Profiler::new("/std/room".to_string(), "builder_alice".to_string());
        p.total_calls = MAX_CALLS - 1;
        p.record(
            "look",
            1,
            1,
            Duration::from_micros(1),
            Duration::from_micros(1),
        );
        // That call pushed total_calls to MAX_CALLS -- one more must be
        // dropped, not counted.
        p.record(
            "look",
            1,
            1,
            Duration::from_micros(1),
            Duration::from_micros(1),
        );
        let report = p.report();
        let look = report.rows.iter().find(|r| r.function == "look").unwrap();
        assert_eq!(look.calls, 1);
        assert_eq!(
            report.stopped_early,
            Some("call cap (1,000,000 calls) reached")
        );
        assert!(report.render().contains("recording stopped early"));
        assert!(report.render().contains("call cap"));
    }

    /// Should-fix 5 (OBI-232): a window open past `MAX_WINDOW` wall time
    /// stops accumulating new samples and reports why, even though
    /// nothing about `record`'s own arguments changed.
    #[test]
    fn time_cap_stops_recording_and_is_reported() {
        let mut p = Profiler::new("/std/room".to_string(), "builder_alice".to_string());
        p.started = Instant::now() - MAX_WINDOW - Duration::from_secs(1);
        p.record(
            "look",
            1,
            1,
            Duration::from_micros(1),
            Duration::from_micros(1),
        );
        let report = p.report();
        assert!(
            report.rows.is_empty(),
            "a call past the time cap must not be recorded"
        );
        assert_eq!(report.stopped_early, Some("time cap (5 minutes) reached"));
        assert!(report.render().contains("time cap"));
    }

    /// OBI-238 (follow-up to PR #67 / OBI-232 should-fix 5): once a
    /// window has hit an auto-expiry cap, `wants` -- the interpreter's
    /// per-call hot-path check -- must answer `false`, not just
    /// `record` silently dropping the sample. Otherwise a forgotten
    /// window keeps costing every call into the sampled program (a
    /// `Box<ProfFrame>` allocation plus two clock reads) forever, even
    /// though nothing is accumulated anymore.
    #[test]
    fn expired_window_wants_returns_false() {
        let mut p = Profiler::new("/std/room".to_string(), "builder_alice".to_string());
        assert!(
            p.wants("/std/room"),
            "a fresh window should still want its program"
        );
        p.total_calls = MAX_CALLS;
        assert!(
            !p.wants("/std/room"),
            "a window past the call cap must stop wanting calls, not just drop them in record"
        );
        assert!(p.is_expired());
    }

    /// The time-cap variant of the same check (OBI-238): `wants` must
    /// not recompute `started.elapsed()` from scratch for the rest of
    /// the process's life either -- `is_expired`/`wants` cache the
    /// answer the first time either cap is found hit.
    #[test]
    fn expired_time_window_wants_returns_false_and_caches() {
        let mut p = Profiler::new("/std/room".to_string(), "builder_alice".to_string());
        p.started = Instant::now() - MAX_WINDOW - Duration::from_secs(1);
        assert!(!p.wants("/std/room"));
        // Move `started` back to "not expired" -- if the cache were not
        // sticky, a naive recompute would now say "not expired" again.
        // The cached answer must still say expired.
        p.started = Instant::now();
        assert!(
            !p.wants("/std/room"),
            "the cached expiry must stick even if the underlying clock condition would no longer hold"
        );
    }
}
