// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `loom_git_push_total{result}`, `loom_git_live_ahead_commits`,
//! `loom_git_sync_total{result}` (spec §8.5 scope). Emitted through the
//! `metrics` crate directly, same pattern as `loom-net`'s rate-limit
//! counter: a no-op until some binary installs a global recorder
//! (`loom-obs::PrometheusBuilder`).

pub fn record_push(result: &'static str) {
    metrics::counter!("loom_git_push_total", "result" => result).increment(1);
}

pub fn record_sync(result: &'static str) {
    metrics::counter!("loom_git_sync_total", "result" => result).increment(1);
}

pub fn set_live_ahead_commits(n: u64) {
    metrics::gauge!("loom_git_live_ahead_commits").set(n as f64);
}
