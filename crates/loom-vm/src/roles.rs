// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The S2 roles snapshot (OBI-36 design note D-S2.1/D-S2.2): the
//! driver-owned, immutable cache of the tier model (`staff`,
//! `domain_members`, `tier_policy`, `active_grants`). `/secure/roles.wf`
//! is its only mudlib facade, through the secure-only read efuns
//! (`crate::bcvm::registry::RegistryHost::driver_efun`'s `roles_*` arms).
//! It keeps no Weft-side copy: every read goes through the driver.
//!
//! [`World::set_roles_snapshot`](crate::world::World::set_roles_snapshot)
//! swaps the whole thing in between executions (a pointer write: this type
//! is always held behind an `Arc`) and flushes the security decision
//! cache, so a stale policy decision is never served against the new
//! snapshot.
//!
//! Loaded either from Postgres (`loom-persist`'s eventual
//! `Persist::load_roles_snapshot`, wired by `loom-cli`, OBI-119/S2a) or,
//! for dev/CI without Postgres, from a JSON seed file named by
//! `LOOM_ROLES_SEED` ([`RolesSnapshot::from_seed_json`] /
//! [`load_seed_from_env`]) -- the design note's "TOML/JSON seed file",
//! JSON here since `serde_json` is already a workspace dependency
//! (`loom-persist`) and this crate needs no new parser.

use std::collections::HashMap;
use std::path::Path;

/// A domain membership role (`domain_members.role`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainRole {
    Member,
    Lead,
}

/// One row of `active_grants` (already expiry-filtered by whoever built
/// the snapshot -- the Postgres view, or [`RolesSnapshot::from_seed_json`]
/// for a seed file): a time-boxed, per-uid exception.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub uid: String,
    pub kind: String,
    pub target: String,
    /// Unix seconds, `None` for a grant with no expiry.
    pub expires_at: Option<i64>,
}

/// The driver-owned, immutable tier-model cache (D-S2.1). Plain `String`
/// uids/domains: unlike `crate::security::GuardSet` (which is compared on
/// every efun call and so is worth interning), a roles-efun call is a
/// handful of ticks and runs only from `/secure/**`, so there is no hot
/// path here that would justify coupling this type to the VM's
/// `Interner`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RolesSnapshot {
    /// uid -> tier (0-5). A uid with no row here has tier 0 (design note
    /// §1: "A uid with no `staff` row has tier 0").
    staff: HashMap<String, u32>,
    /// domain -> uid -> role.
    domain_members: HashMap<String, HashMap<String, DomainRole>>,
    /// tier -> policy column name -> value (`tier_policy`; S2c's quota
    /// enforcement is the main reader, but `roles_policy` serves it to
    /// the mudlib too).
    tier_policy: HashMap<u32, HashMap<String, i64>>,
    grants: Vec<Grant>,
}

impl RolesSnapshot {
    /// Tier 0 for everyone, no domains, no policy, no grants -- the
    /// boot-time default before any snapshot has ever loaded.
    pub fn empty() -> RolesSnapshot {
        RolesSnapshot::default()
    }

    pub fn new(
        staff: HashMap<String, u32>,
        domain_members: HashMap<String, HashMap<String, DomainRole>>,
        tier_policy: HashMap<u32, HashMap<String, i64>>,
        grants: Vec<Grant>,
    ) -> RolesSnapshot {
        RolesSnapshot {
            staff,
            domain_members,
            tier_policy,
            grants,
        }
    }

    /// `roles_tier(uid)`.
    pub fn tier(&self, uid: &str) -> u32 {
        self.staff.get(uid).copied().unwrap_or(0)
    }

    /// `roles_is_member(uid, domain)`: true for a lead too (a lead is a
    /// member).
    pub fn is_member(&self, uid: &str, domain: &str) -> bool {
        self.domain_members
            .get(domain)
            .is_some_and(|m| m.contains_key(uid))
    }

    /// `roles_is_lead(uid, domain)`.
    pub fn is_lead(&self, uid: &str, domain: &str) -> bool {
        self.domain_members
            .get(domain)
            .and_then(|m| m.get(uid))
            .is_some_and(|r| *r == DomainRole::Lead)
    }

    /// `roles_has_grant(uid, kind, target)`.
    pub fn has_grant(&self, uid: &str, kind: &str, target: &str) -> bool {
        self.grants
            .iter()
            .any(|g| g.uid == uid && g.kind == kind && g.target == target)
    }

    /// `roles_policy(tier)`: empty for a tier with no row (never an
    /// error -- callers ask `roles_tier` first if they need to know
    /// whether the uid is staff at all).
    pub fn policy(&self, tier: u32) -> HashMap<String, i64> {
        self.tier_policy.get(&tier).cloned().unwrap_or_default()
    }

    /// `roles_policy`'s per-tier row, for S2c's quota enforcement.
    pub fn policy_row(&self, tier: u32) -> Option<&HashMap<String, i64>> {
        self.tier_policy.get(&tier)
    }

    /// `roles_domains(uid)`: every domain `uid` is a member or lead of,
    /// sorted.
    pub fn domains(&self, uid: &str) -> Vec<String> {
        let mut out: Vec<String> = self
            .domain_members
            .iter()
            .filter(|(_, m)| m.contains_key(uid))
            .map(|(d, _)| d.clone())
            .collect();
        out.sort();
        out
    }

    /// Parse a dev/CI seed file (`LOOM_ROLES_SEED`): a JSON object with
    /// `staff` (`{uid: tier}`), `domain_members`
    /// (`{domain: {uid: "member"|"lead"}}`), `tier_policy`
    /// (`{"<tier>": {column: value}}`, tier as a string key -- JSON object
    /// keys are always strings) and `grants`
    /// (`[{uid, kind, target, expires_at}]`, `expires_at` an integer or
    /// `null`). Every top-level key is optional and defaults to empty.
    pub fn from_seed_json(text: &str) -> Result<RolesSnapshot, String> {
        let v: serde_json::Value =
            serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;
        let obj = v.as_object().ok_or("top level must be a JSON object")?;

        let mut staff = HashMap::new();
        if let Some(s) = obj.get("staff") {
            for (uid, tier) in s.as_object().ok_or("`staff` must be an object")? {
                let t = tier
                    .as_u64()
                    .ok_or_else(|| format!("staff.{uid}: tier must be a non-negative integer"))?;
                staff.insert(uid.clone(), t as u32);
            }
        }

        let mut domain_members = HashMap::new();
        if let Some(d) = obj.get("domain_members") {
            for (domain, members) in d.as_object().ok_or("`domain_members` must be an object")? {
                let mut m = HashMap::new();
                for (uid, role) in members
                    .as_object()
                    .ok_or_else(|| format!("domain_members.{domain}: must be an object"))?
                {
                    let role = match role.as_str() {
                        Some("member") => DomainRole::Member,
                        Some("lead") => DomainRole::Lead,
                        _ => {
                            return Err(format!(
                                "domain_members.{domain}.{uid}: role must be \"member\" or \"lead\""
                            ));
                        }
                    };
                    m.insert(uid.clone(), role);
                }
                domain_members.insert(domain.clone(), m);
            }
        }

        let mut tier_policy = HashMap::new();
        if let Some(p) = obj.get("tier_policy") {
            for (tier, cols) in p.as_object().ok_or("`tier_policy` must be an object")? {
                let tier_num: u32 = tier
                    .parse()
                    .map_err(|_| format!("tier_policy.{tier}: key must be an integer tier"))?;
                let mut m = HashMap::new();
                for (k, val) in cols
                    .as_object()
                    .ok_or_else(|| format!("tier_policy.{tier}: must be an object"))?
                {
                    let n = val
                        .as_i64()
                        .ok_or_else(|| format!("tier_policy.{tier}.{k}: must be an integer"))?;
                    m.insert(k.clone(), n);
                }
                tier_policy.insert(tier_num, m);
            }
        }

        let mut grants = Vec::new();
        if let Some(g) = obj.get("grants") {
            for (i, entry) in g
                .as_array()
                .ok_or("`grants` must be an array")?
                .iter()
                .enumerate()
            {
                let e = entry
                    .as_object()
                    .ok_or_else(|| format!("grants[{i}]: must be an object"))?;
                let str_field = |name: &str| -> Result<String, String> {
                    e.get(name)
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                        .ok_or_else(|| format!("grants[{i}]: missing string `{name}`"))
                };
                let uid = str_field("uid")?;
                let kind = str_field("kind")?;
                let target = str_field("target")?;
                let expires_at = match e.get("expires_at") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(v) => Some(v.as_i64().ok_or_else(|| {
                        format!("grants[{i}].expires_at: must be an integer or null")
                    })?),
                };
                grants.push(Grant {
                    uid,
                    kind,
                    target,
                    expires_at,
                });
            }
        }

        Ok(RolesSnapshot::new(
            staff,
            domain_members,
            tier_policy,
            grants,
        ))
    }
}

/// Env var naming the dev/CI seed file (D-S2.1).
pub const SEED_ENV: &str = "LOOM_ROLES_SEED";

/// Load the seed file named by `$LOOM_ROLES_SEED`, if set. `None` if the
/// variable is unset -- nothing to load, e.g. a Postgres-backed boot
/// (`loom-cli`'s DB-worker loader, S2a); `Some(Err(_))` if it is set but
/// the file is missing or malformed, which callers should treat as a boot
/// failure, never a silent fall-back to an empty snapshot.
pub fn load_seed_from_env() -> Option<Result<RolesSnapshot, String>> {
    let path = std::env::var_os(SEED_ENV)?;
    Some(
        std::fs::read_to_string(&path)
            .map_err(|e| format!("{}: {e}", Path::new(&path).display()))
            .and_then(|text| RolesSnapshot::from_seed_json(&text)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_snapshot_is_tier_zero_for_everyone() {
        let s = RolesSnapshot::empty();
        assert_eq!(s.tier("frodo"), 0);
        assert!(!s.is_member("frodo", "shire"));
        assert!(!s.is_lead("frodo", "shire"));
        assert!(!s.has_grant("frodo", "efun", "write_file"));
        assert_eq!(s.policy(0), HashMap::new());
        assert_eq!(s.domains("frodo"), Vec::<String>::new());
    }

    #[test]
    fn seed_json_round_trips_every_field() {
        let json = r#"{
            "staff": {"frodo": 3, "sam": 1},
            "domain_members": {
                "shire": {"frodo": "lead", "sam": "member"},
                "mordor": {"sam": "member"}
            },
            "tier_policy": {"3": {"max_ticks_exec": 2000000, "max_objects": 500}},
            "grants": [
                {"uid": "sam", "kind": "efun", "target": "write_file", "expires_at": 1000},
                {"uid": "sam", "kind": "path", "target": "/domains/shire", "expires_at": null}
            ]
        }"#;
        let s = RolesSnapshot::from_seed_json(json).expect("parse");
        assert_eq!(s.tier("frodo"), 3);
        assert_eq!(s.tier("sam"), 1);
        assert_eq!(s.tier("stranger"), 0);
        assert!(s.is_member("frodo", "shire"));
        assert!(s.is_lead("frodo", "shire"));
        assert!(s.is_member("sam", "shire"));
        assert!(!s.is_lead("sam", "shire"));
        assert!(s.is_member("sam", "mordor"));
        assert!(!s.is_member("frodo", "mordor"));
        let mut domains = s.domains("sam");
        domains.sort();
        assert_eq!(domains, vec!["mordor".to_string(), "shire".to_string()]);
        assert_eq!(s.policy(3).get("max_ticks_exec"), Some(&2_000_000));
        assert_eq!(s.policy(3).get("max_objects"), Some(&500));
        assert!(s.policy(1).is_empty());
        assert!(s.has_grant("sam", "efun", "write_file"));
        assert!(s.has_grant("sam", "path", "/domains/shire"));
        assert!(!s.has_grant("sam", "efun", "read_file"));
        assert!(!s.has_grant("frodo", "efun", "write_file"));
    }

    #[test]
    fn seed_json_defaults_every_missing_section_to_empty() {
        let s = RolesSnapshot::from_seed_json("{}").expect("parse");
        assert_eq!(s, RolesSnapshot::empty());
    }

    #[test]
    fn seed_json_rejects_malformed_input() {
        for bad in [
            "not json",
            "[]",
            r#"{"staff": {"frodo": "high"}}"#,
            r#"{"domain_members": {"shire": {"frodo": "wizard"}}}"#,
            r#"{"tier_policy": {"three": {}}}"#,
            r#"{"grants": [{"uid": "sam"}]}"#,
        ] {
            assert!(RolesSnapshot::from_seed_json(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn load_seed_from_env_is_none_when_unset() {
        // SAFETY-adjacent test hygiene, not `unsafe`: just make sure the
        // var really is unset for this check (other tests in this binary
        // never set it).
        assert!(std::env::var_os(SEED_ENV).is_none());
        assert!(load_seed_from_env().is_none());
    }
}
