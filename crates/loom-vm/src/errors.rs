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
//! **M-ERR-1 (CTO review, OBI-169/PR #72, design `docs/threat-model-
//! phase2.md`):** a group's `program` is always the **innermost frame's**
//! own declaring program (`RtError::trace_programs`, parallel to
//! `trace`), never the entry object's -- a cross-object/program call
//! chain (`call_other`, an apply) can fail several frames deep inside a
//! program the entry object's own caller has no `valid_read` access to
//! at all, and attributing to the entry object instead would leak that
//! program's error text (which can embed input) to anyone who can read
//! the entry object's own, less-privileged program. On top of that:
//! an entry whose `program` is under `/secure/` is always recorded
//! [`ErrorEntry::redacted`], `message` is capped to [`MAX_MESSAGE_BYTES`]
//! before it's stored or grouped, and the `errors` efun
//! (`crate::bcvm::registry::RegistryHost::errors_efun`) masks a redacted
//! message to `"<redacted>"` unless the caller's own euid is tier 5.
//!
//! **OBI-231 (closes the OBI-169 flagged deviation):** the acceptance
//! criterion groups by `(program, line, message)`, literally now --
//! `loom-compiler`'s `codegen.rs` attaches a 1-based source line to every
//! assembled `Op` (`bytecode::FunctionCode::lines`), and
//! [`vm::RtError::trace_lines`] carries the innermost frame's line
//! alongside its formatted trace string, so [`ErrorKey`] groups by that
//! line instead of standing in with the function name. The function name
//! is kept too (`ErrorEntry::function`/`ErrorRecord::function`): still
//! useful context, just no longer part of the grouping key. A line of
//! `0` means "unknown" (see `vm::RtError::trace_lines`'s doc for when
//! that happens -- hand-assembled bytecode with no line table, or an
//! error raised before any frame's `pc` advanced) and groups like any
//! other line value, not specially.
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

/// Message-size cap (M-ERR-1, CTO review on PR #72, must-fix 3): a
/// message that embeds player/attacker-controlled data (an item name,
/// say) is truncated to this many bytes, on a UTF-8 char boundary,
/// *before* it becomes part of the grouping key or is stored -- so an
/// attacker who varies a message's tail past this length still groups
/// into the same entry instead of minting a fresh one every time, and
/// this plus [`MAX_GROUPS`] together bound the inbox's total memory at
/// `MAX_GROUPS * MAX_MESSAGE_BYTES` for message text alone.
pub const MAX_MESSAGE_BYTES: usize = 512;

/// Truncate `message` to at most [`MAX_MESSAGE_BYTES`] bytes, landing on
/// a `char` boundary (never splitting a multi-byte UTF-8 sequence) so the
/// result is always valid UTF-8.
fn cap_message(message: &str) -> &str {
    if message.len() <= MAX_MESSAGE_BYTES {
        return message;
    }
    let mut end = MAX_MESSAGE_BYTES;
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    &message[..end]
}

/// Grouping key (spec: "(program, line, message)", OBI-231: now literally
/// that -- see [`line_of`]).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ErrorKey {
    program: String,
    /// `0` = unknown (see [`RtError::trace_lines`]): still a valid group,
    /// distinct from any known line, the same way a different `function`
    /// used to be before OBI-231.
    line: u32,
    message: String,
}

#[derive(Clone, Debug)]
struct ErrorEntry {
    /// The innermost frame's function name the *first* time this group
    /// was seen (OBI-231: no longer part of the grouping key, but still
    /// useful context alongside the line -- kept for the `errors` efun and
    /// `ErrorRecord`'s existing `function` column).
    function: String,
    count: u64,
    first_seen_unix_ms: u64,
    last_seen_unix_ms: u64,
    /// The call trace captured the *first* time this group was seen
    /// (most recent frame first, same shape as [`RtError::trace`]):
    /// representative of the group, not necessarily the latest
    /// occurrence's.
    sample_trace: Vec<String>,
    /// `true` if the origin program (the grouping key's `program`) is
    /// under `/secure/` (M-ERR-1, CTO review on PR #72, must-fix 2):
    /// the `errors` efun must show `message: "<redacted>"` instead of
    /// the real text to anyone below T5, and the HTTP consumer (#74,
    /// OBI-194) must apply the same rule -- this flag, not a path check
    /// of its own, is what both are expected to key on.
    redacted: bool,
}

/// One row of [`ErrorInbox::snapshot`]: an owned, read-only view of a
/// group, for the `errors` efun / `/api/v1/errors` to serialize however
/// they like without borrowing the inbox.
#[derive(Clone, Debug, PartialEq)]
pub struct ErrorRecord {
    pub program: String,
    pub function: String,
    /// `0` = unknown (see [`RtError::trace_lines`]'s doc).
    pub line: u32,
    pub message: String,
    pub count: u64,
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    pub sample_trace: Vec<String>,
    /// See [`ErrorEntry::redacted`]'s doc.
    pub redacted: bool,
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
    /// `message` is capped to [`MAX_MESSAGE_BYTES`] (on a char boundary)
    /// before it becomes part of the grouping key or is stored (M-ERR-1
    /// must-fix 3). `redacted` is the caller's own M-ERR-1 call: `World::
    /// note_error` sets it when the origin `program` is under `/secure/`.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        program: &str,
        function: &str,
        line: u32,
        message: &str,
        trace: &[String],
        now_unix_ms: u64,
        redacted: bool,
    ) {
        let message = cap_message(message);
        self.clock += 1;
        metrics::counter!("loom_runtime_errors_total", "program" => program.to_string())
            .increment(1);
        let key = ErrorKey {
            program: program.to_string(),
            line,
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
                function: function.to_string(),
                count: 1,
                first_seen_unix_ms: now_unix_ms,
                last_seen_unix_ms: now_unix_ms,
                sample_trace: trace.to_vec(),
                redacted,
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
                function: e.function.clone(),
                line: k.line,
                message: k.message.clone(),
                count: e.count,
                first_seen_unix_ms: e.first_seen_unix_ms,
                last_seen_unix_ms: e.last_seen_unix_ms,
                sample_trace: e.sample_trace.clone(),
                redacted: e.redacted,
            })
            .collect();
        rows.sort_by(|a, b| {
            b.last_seen_unix_ms
                .cmp(&a.last_seen_unix_ms)
                .then_with(|| b.count.cmp(&a.count))
                .then_with(|| a.program.cmp(&b.program))
                .then_with(|| a.line.cmp(&b.line))
        });
        rows
    }

    /// Total occurrence count across every group whose `program` is
    /// exactly `program` (not a prefix match, unlike `snapshot` -- the
    /// canary error watch (P2-B7, OBI-182) wants "errors attributed to
    /// this one declaring program", never a whole subtree). Used as the
    /// canary baseline/delta: `World::tick` compares this before and
    /// after a canary's install to decide auto-promote vs. auto-rollback
    /// (spec §7.4).
    pub fn count_for_program(&self, program: &str) -> u64 {
        self.groups
            .iter()
            .filter(|(k, _)| k.program == program)
            .map(|(_, e)| e.count)
            .sum()
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
/// trace (its innermost frame, formatted `"in name()"` or `"in name() at
/// path:line"` by the interpreter -- see `bcvm::vm::Interpreter::run`),
/// falling back to `"?"` for an error with no trace at all (e.g. one
/// raised before any frame ever pushed, such as `start`'s "no function"
/// lookup failure).
pub fn function_of(e: &RtError) -> String {
    match e.trace.first() {
        Some(f) => {
            let f = f.strip_prefix("in ").unwrap_or(f);
            let f = f.split(" at ").next().unwrap_or(f);
            f.strip_suffix("()").unwrap_or(f).to_string()
        }
        None => "?".to_string(),
    }
}

/// The grouping key's `line` component (OBI-231, spec §8.3): the innermost
/// frame's source line, or `0` ("unknown") for an error with no trace, or
/// whose innermost frame's line was never recovered -- see
/// [`RtError::trace_lines`]'s doc for when that happens.
pub fn line_of(e: &RtError) -> u32 {
    e.trace_lines.first().copied().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(msg: &str, trace: &[&str]) -> RtError {
        let mut e = RtError::new(msg);
        e.trace = trace.iter().map(|s| s.to_string()).collect();
        e.trace_lines = vec![0; e.trace.len()];
        e
    }

    #[test]
    fn groups_by_program_line_message_and_counts_occurrences() {
        let mut inbox = ErrorInbox::new();
        let mut e = err("division by zero", &["in calc()"]);
        e.trace_lines = vec![12];
        inbox.record(
            "/d/shire/calc.wf",
            &function_of(&e),
            line_of(&e),
            &e.message,
            &e.trace,
            1_000,
            false,
        );
        inbox.record(
            "/d/shire/calc.wf",
            &function_of(&e),
            line_of(&e),
            &e.message,
            &e.trace,
            2_000,
            false,
        );
        // A different message on the same program/line is a different
        // group.
        let mut e2 = err("index out of range", &["in calc()"]);
        e2.trace_lines = vec![12];
        inbox.record(
            "/d/shire/calc.wf",
            &function_of(&e2),
            line_of(&e2),
            &e2.message,
            &e2.trace,
            3_000,
            false,
        );
        // Same message, same program, but a *different* line is also a
        // different group (spec §8.3: "(program, line, message)", OBI-231).
        let mut e3 = err("division by zero", &["in calc()"]);
        e3.trace_lines = vec![40];
        inbox.record(
            "/d/shire/calc.wf",
            &function_of(&e3),
            line_of(&e3),
            &e3.message,
            &e3.trace,
            4_000,
            false,
        );

        assert_eq!(inbox.len(), 3);
        let rows = inbox.snapshot(None);
        let calc_div = rows
            .iter()
            .find(|r| r.message == "division by zero" && r.line == 12)
            .unwrap();
        assert_eq!(calc_div.count, 2);
        assert_eq!(calc_div.first_seen_unix_ms, 1_000);
        assert_eq!(calc_div.last_seen_unix_ms, 2_000);
        assert_eq!(calc_div.function, "calc");
        assert_eq!(calc_div.sample_trace, vec!["in calc()".to_string()]);
        let other_line = rows
            .iter()
            .find(|r| r.message == "division by zero" && r.line == 40)
            .unwrap();
        assert_eq!(other_line.count, 1);
    }

    #[test]
    fn snapshot_filters_by_program_prefix() {
        let mut inbox = ErrorInbox::new();
        inbox.record("/d/shire/a.wf", "f", 1, "boom", &[], 1, false);
        inbox.record("/d/mordor/b.wf", "g", 1, "boom", &[], 1, false);

        let shire_only = inbox.snapshot(Some("/d/shire"));
        assert_eq!(shire_only.len(), 1);
        assert_eq!(shire_only[0].program, "/d/shire/a.wf");

        assert_eq!(inbox.snapshot(None).len(), 2);
        assert_eq!(inbox.snapshot(Some("/nowhere")).len(), 0);
    }

    /// P2-B7 (OBI-182): `count_for_program` sums across every distinct
    /// `(function, message)` group for the exact program path, and is
    /// unaffected by a different program's groups.
    #[test]
    fn count_for_program_sums_every_group_for_an_exact_program_match() {
        let mut inbox = ErrorInbox::new();
        inbox.record("/d/shire/calc.wf", "f", 1, "boom one", &[], 1, false);
        inbox.record("/d/shire/calc.wf", "f", 1, "boom one", &[], 2, false);
        inbox.record("/d/shire/calc.wf", "g", 1, "boom two", &[], 3, false);
        // A different program (even a prefix match of the first) must not
        // be counted: `snapshot`'s prefix filter is deliberately not what
        // this method does.
        inbox.record("/d/shire/calc.wf.bak", "f", 1, "boom one", &[], 4, false);

        assert_eq!(inbox.count_for_program("/d/shire/calc.wf"), 3);
        assert_eq!(inbox.count_for_program("/d/shire/calc.wf.bak"), 1);
        assert_eq!(inbox.count_for_program("/nowhere.wf"), 0);
    }

    #[test]
    fn evicts_the_least_recently_touched_group_once_at_capacity() {
        let mut inbox = ErrorInbox::new();
        for i in 0..MAX_GROUPS {
            inbox.record("/p.wf", "f", 1, &format!("err {i}"), &[], i as u64, false);
        }
        assert_eq!(inbox.len(), MAX_GROUPS);
        // One more distinct group evicts the oldest-touched one (group 0,
        // never touched again) rather than growing past the cap.
        inbox.record("/p.wf", "f", 1, "err new", &[], MAX_GROUPS as u64, false);
        assert_eq!(inbox.len(), MAX_GROUPS);
        let rows = inbox.snapshot(None);
        assert!(!rows.iter().any(|r| r.message == "err 0"));
        assert!(rows.iter().any(|r| r.message == "err new"));
    }

    #[test]
    fn function_of_strips_the_trace_frame_formatting() {
        let e = err("x", &["in look()"]);
        assert_eq!(function_of(&e), "look");
        let with_line = err("x", &["in look() at /std/room:7"]);
        assert_eq!(function_of(&with_line), "look");
        let no_trace = RtError::new("x");
        assert_eq!(function_of(&no_trace), "?");
    }

    /// M-ERR-1 (CTO review on PR #72, must-fix 3): a 10 KB message is
    /// capped to [`MAX_MESSAGE_BYTES`] bytes, on a UTF-8 char boundary,
    /// before it is stored or becomes part of the grouping key -- so two
    /// occurrences that only differ past the cap still group together.
    #[test]
    fn a_message_over_the_cap_is_truncated_on_a_char_boundary_and_variants_past_it_still_group() {
        let mut inbox = ErrorInbox::new();
        // A multi-byte char (3 bytes, U+2603 SNOWMAN) straddling exactly
        // where a naive byte-slice truncation would land, so this also
        // exercises `cap_message` backing off to a valid boundary instead
        // of panicking/producing invalid UTF-8.
        let huge = format!("boom {}☃{}", "a".repeat(10_000), "tail-one");
        let huge2 = format!("boom {}☃{}", "a".repeat(10_000), "tail-two");
        inbox.record("/p.wf", "f", 1, &huge, &[], 1, false);
        inbox.record("/p.wf", "f", 1, &huge2, &[], 2, false);

        assert_eq!(
            inbox.len(),
            1,
            "both messages are identical up to the cap, so they must group together"
        );
        let rows = inbox.snapshot(None);
        assert!(rows[0].message.len() <= MAX_MESSAGE_BYTES);
        assert!(
            rows[0].message.is_char_boundary(rows[0].message.len()),
            "truncation must never split a multi-byte char"
        );
        assert_eq!(rows[0].count, 2);
    }

    #[test]
    fn line_of_reads_the_innermost_frame_and_defaults_to_unknown() {
        let mut e = err("x", &["in look() at /std/room:7"]);
        e.trace_lines = vec![7];
        assert_eq!(line_of(&e), 7);
        let no_trace = RtError::new("x");
        assert_eq!(line_of(&no_trace), 0);
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
            fn register_counter(&self, key: &Key, _: &metrics::Metadata<'_>) -> metrics::Counter {
                assert_eq!(key.name(), "loom_runtime_errors_total");
                metrics::Counter::from_arc(Arc::new(Counter(self.0.clone())))
            }
            fn register_gauge(&self, _: &Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
                unreachable!("errors.rs only emits a counter")
            }
            fn register_histogram(&self, _: &Key, _: &metrics::Metadata<'_>) -> metrics::Histogram {
                unreachable!("errors.rs only emits a counter")
            }
        }

        let count = Arc::new(AtomicU64::new(0));
        let recorder = TestRecorder(count.clone());
        metrics::with_local_recorder(&recorder, || {
            let mut inbox = ErrorInbox::new();
            inbox.record("/std/vault", "heartbeat", 1, "boom", &[], 1, false);
            inbox.record("/std/vault", "heartbeat", 1, "boom", &[], 2, false);
        });
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }
}
