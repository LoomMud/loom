// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Per-tier execution quotas (OBI-36 design note §3/§4, OBI-121/S2c).
//!
//! Quotas are resolved from the S2 [`crate::roles::RolesSnapshot`]
//! (`tier_policy`), keyed on a uid: `root`, `mudlib` and `domain:*` are
//! always unlimited (never staff-owned, never billed), everyone else gets
//! their [`RolesSnapshot::tier`]'s policy row, falling back to the world
//! default for `max_ticks_exec`/`max_mem_exec_mb` (the two quotas every
//! execution/object always has a finite value for) and to "no limit" for
//! every count-based quota the row does not mention.
//!
//! `bcvm::registry::RegistryHost` and `World` are the enforcement points:
//! see `RegistryHost::instantiate` (R1 + `max_objects`), `store_global`
//! (`max_mem_exec_mb`, per-object), `World::exec`/`World::tick`
//! (`max_ticks_exec`, `tick_share_per_min`), the `call_out`/`set_heartbeat`
//! efun arms (`max_callouts_obj`/`max_callouts_uid`/`max_heartbeats`) and
//! the `write_file` efun arm (`disk_quota_mb`).

use std::collections::HashMap;

use crate::roles::RolesSnapshot;

/// World default `max_ticks_exec` (spec: "the world default (1M ticks /
/// 16 MB) for player input and for non-staff uids").
pub const WORLD_DEFAULT_MAX_TICKS_EXEC: u64 = 1_000_000;
/// World default `max_mem_exec_mb`.
pub const WORLD_DEFAULT_MAX_MEM_EXEC_MB: u64 = 16;

pub const MB: u64 = 1024 * 1024;

/// `tier_policy` row keys (also the `quota` label on
/// `loom_tier_quota_breaches_total`).
pub const MAX_TICKS_EXEC: &str = "max_ticks_exec";
pub const MAX_MEM_EXEC_MB: &str = "max_mem_exec_mb";
pub const TICK_SHARE_PER_MIN: &str = "tick_share_per_min";
pub const MAX_OBJECTS: &str = "max_objects";
pub const MAX_HEARTBEATS: &str = "max_heartbeats";
pub const MAX_CALLOUTS_OBJ: &str = "max_callouts_obj";
pub const MAX_CALLOUTS_UID: &str = "max_callouts_uid";
pub const DISK_QUOTA_MB: &str = "disk_quota_mb";

/// `root`, `mudlib` and every `domain:*` uid are always unlimited (spec:
/// "unlimited counts for `root`/`mudlib`/`domain:*`"). A pure string test
/// -- no `RolesSnapshot` needed -- so callers that only have a uid string
/// (e.g. `Registry::insert`/`remove`'s object-count bookkeeping) can skip
/// tracking a count for these without asking the driver for anything.
#[inline]
pub fn is_unlimited_uid(uid: &str) -> bool {
    uid == "root" || uid == "mudlib" || uid.starts_with("domain:")
}

/// The resolved quota set for one owner/quota uid (spec §3/§4). `None` on
/// a count-based field means "no limit" (either the uid is one of the
/// always-unlimited ones, or its tier's policy row simply has no entry
/// for that key).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TierQuotas {
    pub max_ticks_exec: u64,
    pub max_mem_exec_mb: u64,
    pub tick_share_per_min: Option<u64>,
    pub max_objects: Option<u64>,
    pub max_heartbeats: Option<u64>,
    pub max_callouts_obj: Option<u64>,
    pub max_callouts_uid: Option<u64>,
    pub disk_quota_mb: Option<u64>,
}

impl TierQuotas {
    /// **Unlimited counts, but still the world default for the two
    /// per-execution limits** (spec §3/§4: "`root`, `mudlib`, `domain:*`
    /// and players: the world default for per-execution limits and
    /// unlimited counts"). A `u64::MAX` tick/mem budget here would let a
    /// single mudlib heartbeat or call_out with a `while (1) {}` bug hang
    /// the whole driver -- a liveness regression the design note does not
    /// ask for (CTO review, OBI-121 B2). Per-execution limits are *never*
    /// unbounded; only the counts (objects, heartbeats, call_outs, disk)
    /// are.
    pub fn unlimited() -> TierQuotas {
        TierQuotas {
            max_ticks_exec: WORLD_DEFAULT_MAX_TICKS_EXEC,
            max_mem_exec_mb: WORLD_DEFAULT_MAX_MEM_EXEC_MB,
            tick_share_per_min: None,
            max_objects: None,
            max_heartbeats: None,
            max_callouts_obj: None,
            max_callouts_uid: None,
            disk_quota_mb: None,
        }
    }

    /// `max_mem_exec_mb` in bytes (saturating: `u64::MAX` stays
    /// `u64::MAX` rather than overflowing on the `* MB`).
    pub fn max_mem_exec_bytes(&self) -> u64 {
        self.max_mem_exec_mb.saturating_mul(MB)
    }
}

/// Resolve `uid`'s effective quota set from `roles` (spec §3/§4). Always
/// unlimited for `root`/`mudlib`/`domain:*`; otherwise `roles.tier(uid)`'s
/// policy row, falling back to the world default for the two
/// always-finite quotas and to "no limit" for every count-based one the
/// row omits.
#[inline]
pub fn resolve(roles: &RolesSnapshot, uid: &str) -> TierQuotas {
    if is_unlimited_uid(uid) {
        return TierQuotas::unlimited();
    }
    let tier = roles.tier(uid);
    // `policy_row` (a borrow), not `policy` (an owned `HashMap` clone with
    // per-key `String` allocations) -- `resolve` runs on *every*
    // `store_global` (the per-object mem quota) and every heartbeat/
    // call_out tick check, so cloning the whole row here was a measured
    // hot-path regression (CI's V7 bench gate: `array_fill`, a tight
    // var-write loop, +26% over `origin/main`).
    let row = roles.policy_row(tier);
    let pos_u64 = |k: &str| -> Option<u64> {
        row.and_then(|r| r.get(k))
            .copied()
            .filter(|v| *v > 0)
            .map(|v| v as u64)
    };
    TierQuotas {
        max_ticks_exec: pos_u64(MAX_TICKS_EXEC).unwrap_or(WORLD_DEFAULT_MAX_TICKS_EXEC),
        max_mem_exec_mb: pos_u64(MAX_MEM_EXEC_MB).unwrap_or(WORLD_DEFAULT_MAX_MEM_EXEC_MB),
        tick_share_per_min: pos_u64(TICK_SHARE_PER_MIN),
        max_objects: pos_u64(MAX_OBJECTS),
        max_heartbeats: pos_u64(MAX_HEARTBEATS),
        max_callouts_obj: pos_u64(MAX_CALLOUTS_OBJ),
        max_callouts_uid: pos_u64(MAX_CALLOUTS_UID),
        disk_quota_mb: pos_u64(DISK_QUOTA_MB),
    }
}

/// In-process `loom_tier_quota_breaches_total{tier,quota}` counter table
/// (spec's metric), the same shape as `bcvm::registry::CowMetrics` and
/// for the same reason: this repo has no metrics-export story for
/// `loom-vm` yet (see `CowMetrics`'s doc comment), so this is only an
/// in-process table, read back via `World::quota_breach_count`.
#[derive(Default)]
pub struct QuotaBreachMetrics {
    counts: HashMap<(u32, &'static str), u64>,
}

impl QuotaBreachMetrics {
    pub fn record(&mut self, tier: u32, quota: &'static str) {
        *self.counts.entry((tier, quota)).or_insert(0) += 1;
    }

    pub fn get(&self, tier: u32, quota: &str) -> u64 {
        self.counts
            .iter()
            .find(|((t, q), _)| *t == tier && *q == quota)
            .map(|(_, n)| *n)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as Map;

    fn snap(tier_policy: Map<u32, Map<String, i64>>, staff: Map<String, u32>) -> RolesSnapshot {
        RolesSnapshot::new(staff, Map::new(), tier_policy, Vec::new())
    }

    #[test]
    fn unlimited_uids_never_consult_the_snapshot() {
        for uid in ["root", "mudlib", "domain:shire", "domain:"] {
            assert_eq!(
                resolve(&RolesSnapshot::empty(), uid),
                TierQuotas::unlimited()
            );
        }
        assert!(!is_unlimited_uid("appr"));
        assert!(!is_unlimited_uid("domain")); // no colon: not a domain uid
    }

    #[test]
    fn unlimited_uids_still_get_the_world_default_per_execution_budget() {
        // OBI-121 B2: unlimited *counts*, not unlimited ticks/mem -- a
        // mudlib heartbeat with an infinite loop must still abort at the
        // world default rather than hang the driver.
        let q = TierQuotas::unlimited();
        assert_eq!(q.max_ticks_exec, WORLD_DEFAULT_MAX_TICKS_EXEC);
        assert_eq!(q.max_mem_exec_mb, WORLD_DEFAULT_MAX_MEM_EXEC_MB);
        assert_eq!(q.max_objects, None);
    }

    #[test]
    fn non_staff_uid_gets_the_world_default() {
        let q = resolve(&RolesSnapshot::empty(), "appr");
        assert_eq!(q.max_ticks_exec, WORLD_DEFAULT_MAX_TICKS_EXEC);
        assert_eq!(q.max_mem_exec_mb, WORLD_DEFAULT_MAX_MEM_EXEC_MB);
        assert_eq!(q.max_objects, None);
    }

    #[test]
    fn a_tier_row_overrides_the_world_default_and_sets_count_quotas() {
        let mut row = Map::new();
        row.insert(MAX_TICKS_EXEC.to_string(), 50_000i64);
        row.insert(MAX_MEM_EXEC_MB.to_string(), 2i64);
        row.insert(MAX_OBJECTS.to_string(), 10i64);
        let mut tp = Map::new();
        tp.insert(1u32, row);
        let mut staff = Map::new();
        staff.insert("appr".to_string(), 1u32);
        let q = resolve(&snap(tp, staff), "appr");
        assert_eq!(q.max_ticks_exec, 50_000);
        assert_eq!(q.max_mem_exec_mb, 2);
        assert_eq!(q.max_mem_exec_bytes(), 2 * MB);
        assert_eq!(q.max_objects, Some(10));
        assert_eq!(q.max_heartbeats, None, "row never mentioned it: unlimited");
    }

    #[test]
    fn quota_breach_metrics_are_keyed_by_tier_and_quota_name() {
        let mut m = QuotaBreachMetrics::default();
        m.record(1, MAX_OBJECTS);
        m.record(1, MAX_OBJECTS);
        m.record(2, MAX_OBJECTS);
        assert_eq!(m.get(1, MAX_OBJECTS), 2);
        assert_eq!(m.get(2, MAX_OBJECTS), 1);
        assert_eq!(m.get(1, MAX_HEARTBEATS), 0);
    }
}
