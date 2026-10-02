// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The runtime error inbox (OBI-169, Loom design spec §8.3): every
//! runtime error that reaches a top-level entry point uncaught -- player
//! input, `connect`/`logon`, a heartbeat, a `call_out`, an eager
//! `upgrade_all` migration, or an `account_result`/`roles_result` drain --
//! is grouped here so a builder can see what their code broke without
//! reading logs. `World::exec` is the single call site that feeds this
//! (see its tail): every `Err` any execution returns is recorded exactly
//! once, independent of whether the error was also reported to a player
//! ([`crate::world::World::report`]) or silently dropped (a heartbeat, a
//! `call_out`, `net_dead`, ...).
//!
//! **Spec deviation (flagged for the CTO, OBI-169):** the acceptance
//! criterion groups by `(program, line, message)`. The bytecode carries
//! no per-instruction source-line debug info yet -- `loom-compiler`'s
//! `codegen.rs` lowers HIR (which does have spans) straight to flat `Op`s
//! with none retained, so [`vm::RtError`]'s call trace is function names
//! only ("in `foo`()"), not `path.wf:line:col`. This groups by `(program,
//! function, message)` instead: the finest attribution available without
//! a `loom-compiler` change to carry a `lines: Vec<u32>` debug table
//! through `FunctionCode`/`Op` to the interpreter. Filed as a follow-up in
//! the OBI-169 task comment rather than done here, to keep this change
//! scoped to the error inbox itself.
//!
//! Exported metric (P2-O4/P2-B7): every [`ErrorInbox::record`] bumps
//! `loom_runtime_errors_total{program}` through the process-global
//! `metrics` facade (same mechanism `loom-net` already uses for
//! `loom_net_rate_limit_disconnects_total` -- an in-memory atomic
//! increment, no I/O, safe on the deterministic world thread).

use std::collections::HashMap;

use crate::bcvm::vm::RtError;

/// Cap on distinct `(program, function, message)` groups kept at once: a
/// message that embeds player/attacker-controlled data (an item name,
/// say) could otherwise mint unbounded distinct groups. Beyond this, the
/// least-recently-*touched* group is evicted to make room for a new one
/// (an existing group can always still have its `count` grow without
/// evicting anything).
pub const MAX_GROUPS: usize = 4096;

/// Grouping key (spec: "(program, line, message)" -- see the module doc's
/// flagged deviation: `function` stands in for `line` here).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ErrorKey {
    program: String,
    function: String,
    message: String,
}

#[derive(Clone, Debug)]
struct ErrorEntry {
    count: u64,
    first_seen_unix_ms: u64,
    last_seen_unix_ms: u64,
    /// The call trace captured the *first* time this group was seen
    /// (most recent frame first, same shape as [`RtError::trace`]):
    /// representative of the group, not necessarily the latest
    /// occurrence's.
    sample_trace: Vec<String>,
}

/// One row of [`ErrorInbox::snapshot`]: an owned, read-only view of a
/// group, for the `errors` efun / `/api/v1/errors` to serialize however
/// they like without borrowing the inbox.
///
/// `Serialize` (OBI-194): `loom-http`'s `/api/v1/errors` route renders
/// this straight to JSON -- field names are the wire contract, so rename
/// deliberately, not incidentally.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct ErrorRecord {
    pub program: String,
    pub function: String,
    pub message: String,
    pub count: u64,
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    pub sample_trace: Vec<String>,
}

/// Grouped runtime errors, owned by [`crate::world::World`].
#[derive(Default)]
pub struct ErrorInbox {
    groups: HashMap<ErrorKey, ErrorEntry>,
    /// Monotonic "logical clock" for LRU eviction (bumped on every
    /// `record`): cheaper and tie-free compared to comparing wall-clock
    /// millis, which two `record`s in the same millisecond would tie on.
    clock: u64,
    last_touch: HashMap<ErrorKey, u64>,
}

impl ErrorInbox {
    pub fn new() -> ErrorInbox {
        ErrorInbox::default()
    }

    /// Record one occurrence. `now_unix_ms` is injected rather than read
    /// from `SystemTime::now()` internally, so tests can drive first/last
    /// seen deterministically; `World` passes the real wall clock.
    pub fn record(
        &mut self,
        program: &str,
        function: &str,
        message: &str,
        trace: &[String],
        now_unix_ms: u64,
    ) {
        self.clock += 1;
        metrics::counter!("loom_runtime_errors_total", "program" => program.to_string())
            .increment(1);
        let key = ErrorKey {
            program: program.to_string(),
            function: function.to_string(),
            message: message.to_string(),
        };
        if let Some(entry) = self.groups.get_mut(&key) {
            entry.count += 1;
            entry.last_seen_unix_ms = now_unix_ms;
            self.last_touch.insert(key, self.clock);
            return;
        }
        if self.groups.len() >= MAX_GROUPS {
            self.evict_oldest();
        }
        self.last_touch.insert(key.clone(), self.clock);
        self.groups.insert(
            key,
            ErrorEntry {
                count: 1,
                first_seen_unix_ms: now_unix_ms,
                last_seen_unix_ms: now_unix_ms,
                sample_trace: trace.to_vec(),
            },
        );
    }

    fn evict_oldest(&mut self) {
        if let Some(oldest) = self
            .last_touch
            .iter()
            .min_by_key(|(_, t)| **t)
            .map(|(k, _)| k.clone())
        {
            self.groups.remove(&oldest);
            self.last_touch.remove(&oldest);
        }
    }

    pub fn len(&self) -> usize {
        self.groups.len()
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Every group, optionally filtered by `program_prefix` (a plain
    /// string-prefix match on the program path, e.g. `"/domains/shire"`
    /// matches `/domains/shire/...`), newest-`last_seen` first, ties
    /// broken by highest count first.
    pub fn snapshot(&self, program_prefix: Option<&str>) -> Vec<ErrorRecord> {
        let mut rows: Vec<ErrorRecord> = self
            .groups
            .iter()
            .filter(|(k, _)| program_prefix.is_none_or(|p| k.program.starts_with(p)))
            .map(|(k, e)| ErrorRecord {
                program: k.program.clone(),
                function: k.function.clone(),
                message: k.message.clone(),
                count: e.count,
                first_seen_unix_ms: e.first_seen_unix_ms,
                last_seen_unix_ms: e.last_seen_unix_ms,
                sample_trace: e.sample_trace.clone(),
            })
            .collect();
        rows.sort_by(|a, b| {
            b.last_seen_unix_ms
                .cmp(&a.last_seen_unix_ms)
                .then_with(|| b.count.cmp(&a.count))
                .then_with(|| a.program.cmp(&b.program))
                .then_with(|| a.function.cmp(&b.function))
        });
        rows
    }

    /// Distinct program paths with at least one recorded group, sorted.
    /// Used by the `errors` efun's per-program `valid_read` permission
    /// filter: cheaper to authorize once per *program* than once per
    /// group (a program can have many error groups).
    pub fn programs(&self) -> Vec<String> {
        let mut v: Vec<String> = self.groups.keys().map(|k| k.program.clone()).collect();
        v.sort();
        v.dedup();
        v
    }
}

/// Derive the grouping key's `function` component from an [`RtError`]'s
/// trace (its innermost frame, formatted `"in name()"` by the
/// interpreter -- see `bcvm::vm::Interpreter::run`), falling back to `"?"`
/// for an error with no trace at all (e.g. one raised before any frame
/// ever pushed, such as `start`'s "no function" lookup failure).
pub fn function_of(e: &RtError) -> String {
    match e.trace.first() {
        Some(f) => f
            .strip_prefix("in ")
            .unwrap_or(f)
            .strip_suffix("()")
            .unwrap_or(f)
            .to_string(),
        None => "?".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(msg: &str, trace: &[&str]) -> RtError {
        let mut e = RtError::new(msg);
        e.trace = trace.iter().map(|s| s.to_string()).collect();
        e
    }

    #[test]
    fn groups_by_program_function_message_and_counts_occurrences() {
        let mut inbox = ErrorInbox::new();
        let e = err("division by zero", &["in calc()"]);
        inbox.record("/d/shire/calc.wf", &function_of(&e), &e.message, &e.trace, 1_000);
        inbox.record("/d/shire/calc.wf", &function_of(&e), &e.message, &e.trace, 2_000);
        // A different message on the same program/function is a
        // different group.
        let e2 = err("index out of range", &["in calc()"]);
        inbox.record(
            "/d/shire/calc.wf",
            &function_of(&e2),
            &e2.message,
            &e2.trace,
            3_000,
        );

        assert_eq!(inbox.len(), 2);
        let rows = inbox.snapshot(None);
        let calc_div = rows
            .iter()
            .find(|r| r.message == "division by zero")
            .unwrap();
        assert_eq!(calc_div.count, 2);
        assert_eq!(calc_div.first_seen_unix_ms, 1_000);
        assert_eq!(calc_div.last_seen_unix_ms, 2_000);
        assert_eq!(calc_div.function, "calc");
        assert_eq!(calc_div.sample_trace, vec!["in calc()".to_string()]);
    }

    #[test]
    fn snapshot_filters_by_program_prefix() {
        let mut inbox = ErrorInbox::new();
        inbox.record("/d/shire/a.wf", "f", "boom", &[], 1);
        inbox.record("/d/mordor/b.wf", "g", "boom", &[], 1);

        let shire_only = inbox.snapshot(Some("/d/shire"));
        assert_eq!(shire_only.len(), 1);
        assert_eq!(shire_only[0].program, "/d/shire/a.wf");

        assert_eq!(inbox.snapshot(None).len(), 2);
        assert_eq!(inbox.snapshot(Some("/nowhere")).len(), 0);
    }

    #[test]
    fn evicts_the_least_recently_touched_group_once_at_capacity() {
        let mut inbox = ErrorInbox::new();
        for i in 0..MAX_GROUPS {
            inbox.record("/p.wf", "f", &format!("err {i}"), &[], i as u64);
        }
        assert_eq!(inbox.len(), MAX_GROUPS);
        // One more distinct group evicts the oldest-touched one (group 0,
        // never touched again) rather than growing past the cap.
        inbox.record("/p.wf", "f", "err new", &[], MAX_GROUPS as u64);
        assert_eq!(inbox.len(), MAX_GROUPS);
        let rows = inbox.snapshot(None);
        assert!(!rows.iter().any(|r| r.message == "err 0"));
        assert!(rows.iter().any(|r| r.message == "err new"));
    }

    #[test]
    fn function_of_strips_the_trace_frame_formatting() {
        let e = err("x", &["in look()"]);
        assert_eq!(function_of(&e), "look");
        let no_trace = RtError::new("x");
        assert_eq!(function_of(&no_trace), "?");
    }

    /// P2-O4/P2-B7: every `record` bumps `loom_runtime_errors_total` through
    /// the process-global `metrics` facade. A local recorder
    /// (`metrics::with_local_recorder`, scoped to this test's closure, not
    /// installed process-wide) captures the increments without racing any
    /// other test in this binary that might install/use the real global
    /// recorder.
    #[test]
    fn record_bumps_the_runtime_errors_metric() {
        use metrics::{Key, Recorder};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        struct Counter(Arc<AtomicU64>);
        impl metrics::CounterFn for Counter {
            fn increment(&self, value: u64) {
                self.0.fetch_add(value, Ordering::SeqCst);
            }
            fn absolute(&self, value: u64) {
                self.0.store(value, Ordering::SeqCst);
            }
        }

        struct TestRecorder(Arc<AtomicU64>);
        impl Recorder for TestRecorder {
            fn describe_counter(
                &self,
                _: metrics::KeyName,
                _: Option<metrics::Unit>,
                _: metrics::SharedString,
            ) {
            }
            fn describe_gauge(
                &self,
                _: metrics::KeyName,
                _: Option<metrics::Unit>,
                _: metrics::SharedString,
            ) {
            }
            fn describe_histogram(
                &self,
                _: metrics::KeyName,
                _: Option<metrics::Unit>,
                _: metrics::SharedString,
            ) {
            }
            fn register_counter(
                &self,
                key: &Key,
                _: &metrics::Metadata<'_>,
            ) -> metrics::Counter {
                assert_eq!(key.name(), "loom_runtime_errors_total");
                metrics::Counter::from_arc(Arc::new(Counter(self.0.clone())))
            }
            fn register_gauge(&self, _: &Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
                unreachable!("errors.rs only emits a counter")
            }
            fn register_histogram(
                &self,
                _: &Key,
                _: &metrics::Metadata<'_>,
            ) -> metrics::Histogram {
                unreachable!("errors.rs only emits a counter")
            }
        }

        let count = Arc::new(AtomicU64::new(0));
        let recorder = TestRecorder(count.clone());
        metrics::with_local_recorder(&recorder, || {
            let mut inbox = ErrorInbox::new();
            inbox.record("/std/vault", "heartbeat", "boom", &[], 1);
            inbox.record("/std/vault", "heartbeat", "boom", &[], 2);
        });
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }
}
