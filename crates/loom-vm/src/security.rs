// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Driver half of the security model (spec r5 §5.7 layer 3, §5.11.4,
//! §5.2.2 D25; OBI-35 design note D-S1.1–D-S1.8).
//!
//! - A [`Principal`] is an interned `(uid, euid)` pair. `uid` comes from
//!   the master's `creator_file(path)` and never changes (quotas,
//!   ownership); `euid` starts equal to it and only changes through a
//!   master-validated `seteuid` (rights).
//! - A [`GuardSet`] is the set of distinct principals on the stack down to
//!   the nearest cut. A privileged operation is allowed **iff the master
//!   allows it for every euid in the set** (intersection, D-S1.2). `root`
//!   is the identity element and is never stored, so an all-root stack has
//!   an empty set and is allowed without asking the master.
//! - [`SecurityState`] (owned by `World`) holds the decision cache, the
//!   policy epoch and the audit ring buffer. The guard *stack* itself lives
//!   in `bcvm::registry::RegistryHost`, parallel to its `self_stack`.

use std::collections::HashMap;
use std::rc::Rc;

use crate::efuns::Privilege;
use crate::object::ObjectId;

/// An interned uid/euid string (index into [`Interner`]).
pub type Sym = u32;

/// The one uid the driver knows specially: the owner of `/secure/**`.
pub const ROOT: Sym = 0;

/// Driver-wide string interner for uids/euids. Index 0 is always `root`.
pub struct Interner {
    map: HashMap<Rc<str>, Sym>,
    names: Vec<Rc<str>>,
}

impl Default for Interner {
    fn default() -> Self {
        let mut i = Interner {
            map: HashMap::new(),
            names: Vec::new(),
        };
        let root = i.intern("root");
        debug_assert_eq!(root, ROOT);
        i
    }
}

impl Interner {
    pub fn intern(&mut self, s: &str) -> Sym {
        if let Some(&id) = self.map.get(s) {
            return id;
        }
        let id = self.names.len() as Sym;
        let rc: Rc<str> = Rc::from(s);
        self.names.push(rc.clone());
        self.map.insert(rc, id);
        id
    }

    pub fn name(&self, s: Sym) -> &str {
        self.names.get(s as usize).map_or("?", |n| n)
    }
}

/// `(uid, euid)` of one stack frame (D-S1.1). 8 bytes, `Copy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Principal {
    pub uid: Sym,
    pub euid: Sym,
}

impl Principal {
    pub const ROOT: Principal = Principal {
        uid: ROOT,
        euid: ROOT,
    };
}

/// Distinct non-root principals on the stack down to the nearest cut, in
/// push order (D-S1.2 rule 4). Cloning is an `Rc` bump; [`GuardSet::with`]
/// re-uses `self`'s allocation when the principal is already present or is
/// root, so a frame push that adds nothing new never allocates.
#[derive(Clone, Debug)]
pub struct GuardSet(Rc<[Principal]>);

impl GuardSet {
    /// The empty set: an all-root stack, or the start of a cut.
    pub fn empty() -> GuardSet {
        thread_local! {
            static EMPTY: Rc<[Principal]> = Rc::from(Vec::new());
        }
        GuardSet(EMPTY.with(Rc::clone))
    }

    /// `self ∪ {p}` (root is the identity element and is never stored).
    pub fn with(&self, p: Principal) -> GuardSet {
        if p.euid == ROOT || self.0.contains(&p) {
            return self.clone();
        }
        let mut v = Vec::with_capacity(self.0.len() + 1);
        v.extend_from_slice(&self.0);
        v.push(p);
        GuardSet(Rc::from(v))
    }

    /// `self ∪ other`, `other`'s new elements appended in its order (the
    /// synthetic creator frame of a function value, D-S1.7).
    pub fn union(&self, other: &GuardSet) -> GuardSet {
        if Rc::ptr_eq(&self.0, &other.0) || other.0.is_empty() {
            return self.clone();
        }
        if self.0.is_empty() {
            return other.clone();
        }
        let mut out = self.clone();
        for p in other.0.iter() {
            out = out.with(*p);
        }
        out
    }

    /// Same allocation (cheap identity test for memoisation).
    pub fn ptr_eq(&self, other: &GuardSet) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn principals(&self) -> &[Principal] {
        &self.0
    }

    /// Distinct euids, in push order (the unit the master is asked about).
    pub fn euids(&self) -> impl Iterator<Item = Sym> + '_ {
        self.0
            .iter()
            .enumerate()
            .filter(|(i, p)| !self.0[..*i].iter().any(|q| q.euid == p.euid))
            .map(|(_, p)| p.euid)
    }

    /// Does the set contain `euid`?
    pub fn has_euid(&self, euid: Sym) -> bool {
        (euid == ROOT && self.0.is_empty()) || self.0.iter().any(|p| p.euid == euid)
    }
}

/// A privileged operation the driver asks the master about (D-S1.3).
/// Efun/op names are `'static` (from the efun registry) so that a cache
/// lookup never allocates.
#[derive(Clone, Debug)]
pub enum Operation<'a> {
    /// → `valid_efun(name, class, ob)`, first for every P1+ efun.
    Efun {
        name: &'static str,
        class: Privilege,
    },
    /// → `valid_read(path, ob, op)`.
    Read { path: &'a str, op: &'static str },
    /// → `valid_write(path, ob, op)`.
    Write { path: &'a str, op: &'static str },
    /// → `valid_compile(path, ob)` (the OBI-35 AC's `valid_exec`).
    Compile { path: &'a str },
    /// → `valid_upgrade(path, ob)` (OBI-121/S2c): checked in `upgrade_all`
    /// after `valid_efun`, exactly like `compile_object`'s `valid_compile`.
    Upgrade { path: &'a str },
    /// → `valid_bind(ob, target)` (`bind_connection`, the spec's `exec`).
    Bind { target: ObjectId },
    /// → `valid_seteuid(ob, euid)`.
    SetEuid { euid: &'a str },
}

impl Operation<'_> {
    pub fn apply(&self) -> &'static str {
        match self {
            Operation::Efun { .. } => "valid_efun",
            Operation::Read { .. } => "valid_read",
            Operation::Write { .. } => "valid_write",
            Operation::Compile { .. } => "valid_compile",
            Operation::Upgrade { .. } => "valid_upgrade",
            Operation::Bind { .. } => "valid_bind",
            Operation::SetEuid { .. } => "valid_seteuid",
        }
    }

    /// `(tag, arg)` of the cache key (D-S1.8), `None` if never cached.
    /// The efun class is not part of the key: it is fixed per efun name.
    fn cache_parts(&self) -> Option<(&'static str, &str)> {
        match self {
            Operation::Efun { name, .. } => Some(("", name)),
            Operation::Read { path, op } | Operation::Write { path, op } => Some((op, path)),
            Operation::Compile { path } => Some(("", path)),
            Operation::Upgrade { path } => Some(("", path)),
            Operation::SetEuid { euid } => Some(("", euid)),
            Operation::Bind { .. } => None,
        }
    }

    /// The operation's argument as recorded in the audit entry.
    fn audit_arg(&self) -> &str {
        match self {
            Operation::Efun { .. } | Operation::Bind { .. } => "",
            Operation::Read { path, .. }
            | Operation::Write { path, .. }
            | Operation::Compile { path }
            | Operation::Upgrade { path } => path,
            Operation::SetEuid { euid } => euid,
        }
    }

    /// Short human description for denial messages.
    pub fn describe(&self) -> String {
        match self {
            Operation::Efun { name, class } => format!("efun {name} ({class:?})"),
            Operation::Read { path, op } => format!("{op} {path}"),
            Operation::Write { path, op } => format!("{op} {path}"),
            Operation::Compile { path } => format!("compile {path}"),
            Operation::Upgrade { path } => format!("upgrade {path}"),
            Operation::Bind { .. } => "bind_connection".to_string(),
            Operation::SetEuid { euid } => format!("seteuid {euid}"),
        }
    }
}

/// Outer cache key: (apply, euid, op tag); the inner map is keyed by the
/// operation argument (path / efun name / euid), looked up by `&str`.
type Bucket = (&'static str, Sym, &'static str);

/// Entries kept in the decision cache before it is cleared whole (D-S1.8).
pub const CACHE_CAPACITY: usize = 8192;
/// Audit entries retained (ring buffer).
pub const AUDIT_LOG_CAPACITY: usize = 1024;
/// Own tick budget of one `valid_*` apply execution (D-S1.3).
pub const APPLY_TICKS: u64 = 50_000;
/// Ticks charged to the caller for every cache miss (D-S1.3).
pub const MISS_CHARGE: u64 = 100;

/// One privileged decision, allowed or denied. Cheap to record: no string
/// formatting on the hot path; resolve [`Sym`]s to names with
/// `World::principal_name`.
#[derive(Clone, Debug)]
pub struct AuditEntry {
    pub caller: ObjectId,
    /// The efun that triggered the decision.
    pub efun: &'static str,
    pub privilege: Privilege,
    /// Which decision: `valid_efun`, `valid_write`, …, or `unguarded`.
    pub apply: &'static str,
    /// The decided path / euid / function name (empty for the efun gate).
    pub arg: Box<str>,
    /// The guard set at decision time.
    pub guard: GuardSet,
    pub allowed: bool,
    /// The euid the master denied for, if denied by policy.
    pub denied_by: Option<Sym>,
}

/// A pending cache fill, returned by a missed [`SecurityState::lookup`].
pub(crate) struct Miss {
    bucket: Bucket,
    arg: Box<str>,
}

/// World-owned security state: decision cache + epoch + audit.
#[derive(Default)]
pub struct SecurityState {
    cache: HashMap<Bucket, HashMap<Box<str>, bool>>,
    cached: usize,
    epoch: u64,
    /// Ring buffer as a `Vec` of up to 2×capacity, trimmed by half when
    /// full: amortised O(1) and always one contiguous slice.
    audit: Vec<AuditEntry>,
    audit_total: u64,
    /// Cache hits/misses and denials, for ops tooling and tests.
    pub hits: u64,
    pub misses: u64,
    pub denials: u64,
}

impl SecurityState {
    pub fn new() -> SecurityState {
        SecurityState::default()
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Drop every cached decision (D-S1.8: roles snapshot swap, master
    /// recompile, grant expiry, `flush_security_cache`).
    pub fn bump_epoch(&mut self) {
        self.epoch += 1;
        self.cache.clear();
        self.cached = 0;
    }

    /// `Ok(decision)` on a hit; `Err(Some(miss))` for a cacheable miss
    /// (pass it to [`Self::store`]); `Err(None)` for a never-cached op.
    pub(crate) fn lookup(&mut self, op: &Operation<'_>, euid: Sym) -> Result<bool, Option<Miss>> {
        let Some((tag, arg)) = op.cache_parts() else {
            return Err(None);
        };
        let bucket = (op.apply(), euid, tag);
        if let Some(&b) = self.cache.get(&bucket).and_then(|m| m.get(arg)) {
            self.hits += 1;
            return Ok(b);
        }
        Err(Some(Miss {
            bucket,
            arg: arg.into(),
        }))
    }

    pub(crate) fn store(&mut self, miss: Miss, allowed: bool) {
        if self.cached >= CACHE_CAPACITY {
            self.cache.clear();
            self.cached = 0;
        }
        self.cache
            .entry(miss.bucket)
            .or_default()
            .insert(miss.arg, allowed);
        self.cached += 1;
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record(
        &mut self,
        caller: ObjectId,
        efun: &'static str,
        privilege: Privilege,
        op: &Operation<'_>,
        guard: &GuardSet,
        allowed: bool,
        denied_by: Option<Sym>,
    ) {
        self.push(AuditEntry {
            caller,
            efun,
            privilege,
            apply: op.apply(),
            arg: op.audit_arg().into(),
            guard: guard.clone(),
            allowed,
            denied_by,
        });
    }

    pub(crate) fn push(&mut self, entry: AuditEntry) {
        if !entry.allowed {
            self.denials += 1;
        }
        if self.audit.len() >= 2 * AUDIT_LOG_CAPACITY {
            self.audit.drain(..AUDIT_LOG_CAPACITY);
        }
        self.audit.push(entry);
        self.audit_total += 1;
    }

    /// The retained audit window (the last ≤ [`AUDIT_LOG_CAPACITY`]
    /// decisions), oldest first.
    pub fn log(&self) -> &[AuditEntry] {
        let n = self.audit.len();
        &self.audit[n.saturating_sub(AUDIT_LOG_CAPACITY)..]
    }

    /// Every decision ever recorded (monotonic).
    pub fn audit_total(&self) -> u64 {
        self.audit_total
    }
}

/// Built-in `creator_file` fallback (D-S1.1) for a mudlib whose master has
/// no `creator_file` apply.
pub fn default_creator(path: &str) -> String {
    let mut segs = path.trim_start_matches('/').split('/');
    match (segs.next(), segs.next()) {
        (Some("secure"), _) => "root".to_string(),
        (Some("builders"), Some(u)) if !u.is_empty() => u.to_string(),
        (Some("domains"), Some(d)) if !d.is_empty() => format!("domain:{d}"),
        _ => "mudlib".to_string(),
    }
}

/// Normalise a VFS file path for `read_file`/`write_file`: absolute, no
/// empty/`.`/`..` segments, segments limited to `[A-Za-z0-9_.-]`.
pub fn normalize_file_path(p: &str) -> Result<String, String> {
    if !p.starts_with('/') {
        return Err(format!("`{p}`: file paths must be absolute"));
    }
    for seg in p[1..].split('/') {
        if seg.is_empty()
            || seg == "."
            || seg == ".."
            || !seg
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        {
            return Err(format!("`{p}`: invalid file path"));
        }
    }
    Ok(p.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(uid: Sym, euid: Sym) -> Principal {
        Principal { uid, euid }
    }

    #[test]
    fn root_is_the_identity_and_never_stored() {
        let g = GuardSet::empty().with(Principal::ROOT);
        assert!(g.is_empty());
        assert!(g.has_euid(ROOT));
    }

    #[test]
    fn pushing_a_present_principal_reuses_the_allocation() {
        let g = GuardSet::empty().with(p(1, 1));
        let g2 = g.with(p(1, 1));
        assert!(Rc::ptr_eq(&g.0, &g2.0));
        let g3 = g2.with(p(2, 2));
        assert_eq!(g3.principals(), &[p(1, 1), p(2, 2)]);
    }

    #[test]
    fn euids_are_distinct_in_push_order() {
        let g = GuardSet::empty().with(p(1, 3)).with(p(2, 3)).with(p(2, 2));
        assert_eq!(g.euids().collect::<Vec<_>>(), vec![3, 2]);
    }

    #[test]
    fn union_appends_only_new_principals() {
        let a = GuardSet::empty().with(p(1, 1)).with(p(2, 2));
        let b = GuardSet::empty().with(p(2, 2)).with(p(3, 3));
        assert_eq!(a.union(&b).principals(), &[p(1, 1), p(2, 2), p(3, 3)]);
        assert!(Rc::ptr_eq(&a.union(&GuardSet::empty()).0, &a.0));
    }

    #[test]
    fn default_creator_mapping() {
        assert_eq!(default_creator("/secure/master"), "root");
        assert_eq!(default_creator("/builders/frodo/x"), "frodo");
        assert_eq!(default_creator("/domains/shire/live/inn"), "domain:shire");
        assert_eq!(default_creator("/std/room"), "mudlib");
    }

    #[test]
    fn file_paths_reject_escapes() {
        assert!(normalize_file_path("/builders/frodo/notes.txt").is_ok());
        for bad in ["relative", "/a/../b", "/a//b", "/a/./b", "/a/b c", "/"] {
            assert!(normalize_file_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn cache_hits_after_store_and_epoch_clears_it() {
        let mut s = SecurityState::new();
        let op = Operation::Compile { path: "/x" };
        let miss = s.lookup(&op, 1).unwrap_err().unwrap();
        s.store(miss, true);
        assert_eq!(s.lookup(&op, 1).ok(), Some(true));
        assert!(s.lookup(&op, 2).is_err(), "keyed by euid");
        s.bump_epoch();
        assert!(s.lookup(&op, 1).is_err());
        let bind = Operation::Bind {
            target: ObjectId {
                index: 0,
                generation: 0,
            },
        };
        assert!(matches!(s.lookup(&bind, 1), Err(None)));
    }

    #[test]
    fn audit_window_is_bounded_and_contiguous() {
        let mut s = SecurityState::new();
        let op = Operation::Compile { path: "/x" };
        let ob = ObjectId {
            index: 0,
            generation: 0,
        };
        for _ in 0..(3 * AUDIT_LOG_CAPACITY + 7) {
            s.record(
                ob,
                "compile_object",
                Privilege::P1,
                &op,
                &GuardSet::empty(),
                true,
                None,
            );
        }
        assert_eq!(s.log().len(), AUDIT_LOG_CAPACITY);
        assert_eq!(s.audit_total(), 3 * AUDIT_LOG_CAPACITY as u64 + 7);
    }
}
