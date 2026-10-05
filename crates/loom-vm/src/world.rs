// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The world: object table, program registry, connection bindings, and the
//! driver ↔ VM seam (`World::boot/connect/input/disconnect`).
//!
//! Runs on the bytecode VM (`crate::bcvm`): [`Registry`]/[`Compiler`] hold
//! the disk-backed program registry and object table, and
//! [`RegistryHost`] is the [`crate::bcvm::vm::Host`] every call executes
//! against (OBI-72, following on from OBI-31's `bcvm::registry` slice).
//! `World`'s outward API (`boot`/`connect`/`input`/`disconnect`, plus the
//! introspection helpers below) is unchanged from the tree-walker it
//! replaces.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};

use crate::bcvm::Value;
use crate::bcvm::compile_worker::{RecompileJob, RecompileSetJob};
use crate::bcvm::registry::{Compiler, Registry, RegistryHost};
use crate::bcvm::vm::{Host as VmHost, Limits as VmLimits, RtError};
use crate::host::{Host, NullHost};
use crate::object::ObjectId;
use crate::roles::RolesSnapshot;
use crate::scheduler::Scheduler;
use crate::security::{AuditEntry, SecurityState};
use std::sync::Arc;

/// Path of the master object.
pub const MASTER_PATH: &str = "/secure/master";

/// Default player-save root (spec §8.1, OBI-171): a `saves` directory
/// *beside* the mudlib root, not inside it -- deliberately outside
/// whatever directory `compile_object`/the Git-backed VFS (§8.5) treats
/// as the mudlib's own working tree, so player save files are never
/// candidates for `git add`, a `revert <file>`, or a recompile sweep.
/// Falls back to a `saves` subdirectory of `mudlib_root` itself only if
/// it has no parent at all (e.g. booted at a filesystem root, which
/// real deployments never do -- `loom-cli`'s `--save-dir` is there for
/// anyone who needs a different layout).
fn default_save_root(mudlib_root: &Path) -> PathBuf {
    match mudlib_root.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join("saves"),
        _ => mudlib_root.join("saves"),
    }
}

/// One [`AuditEntry`], resolved to owned strings, ready for a driver-side
/// Postgres sink (OBI-36 D-S2.5; see [`World::drain_audit_since`]).
/// `kind` and `apply` name the decision (`"unguarded"`,
/// `"roles_set_tier"`, an efun name, ...) and the master apply it went
/// through (`"valid_efun"`, `"roles_actor"`, ...); `class` is the
/// `Privilege` numeric value (0-4); `allowed` is the verdict; `detail` is
/// the denying euid's name, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRow {
    pub kind: &'static str,
    pub caller: Option<String>,
    pub effective_principal: Option<String>,
    pub apply: &'static str,
    pub class: i16,
    pub argument: String,
    pub guard_set: Vec<String>,
    pub allowed: bool,
    pub detail: Option<String>,
    /// Unix milliseconds when the decision was made (`AuditEntry::push`'s
    /// own timestamp, not whenever a sink eventually writes the row --
    /// CTO review, OBI-123 N2).
    pub at_unix_ms: i64,
}

/// One live connection, as reported by the OBI-237 admin-query
/// world-thread side (`World::who_sessions`). Mirrors
/// `loom_http::admin_query::WhoEntry` field-for-field; defined here
/// (rather than depending on `loom-http` from `loom-vm`) so `loom-cli`'s
/// bridging code is the only place that needs to know both shapes --
/// see that module's doc comment (M-ADM-3: never an email or an IP,
/// neither of which exists anywhere in `World`'s own state for a
/// connection, so there is no field here to leak one from).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSummary {
    pub conn_id: u64,
    /// The bound account uid, if logged in -- see
    /// [`World::who_sessions`]'s doc comment for exactly what "logged in"
    /// means here.
    pub account: Option<String>,
    pub connected_at: std::time::SystemTime,
    pub idle_secs: i64,
}

/// One object in the OBI-237 admin-query `list_objects` answer, already
/// filtered by `valid_read` (see [`World::admin_list_objects`]). Mirrors
/// `loom_http::admin_query::ObjectSummary`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminObjectSummary {
    pub path: String,
    pub euid: String,
}

/// One rendered variable in the OBI-237 admin-query `object_vars` answer.
/// Mirrors `loom_http::admin_query::VarEntry`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminVarEntry {
    pub name: String,
    pub value: String,
}

/// The OBI-237 admin-query `object_vars` answer for one live object, once
/// `valid_read` has already passed (see [`World::admin_object_vars`]).
/// Mirrors `loom_http::admin_query::ObjectVars`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminObjectVars {
    pub path: String,
    pub vars: Vec<AdminVarEntry>,
}

/// One group in the OBI-235/OBI-237 admin-query `errors` answer, already
/// `valid_read`-filtered per program and M-ERR-1-redacted (see
/// [`World::admin_errors`]). Mirrors `loom_http::admin_query::ErrorGroup`
/// field-for-field (which itself mirrors `crate::errors::ErrorRecord`,
/// except `line` is `Option<u32>` here/there vs. `ErrorRecord`'s `0`-for-
/// unknown convention).
#[derive(Clone, Debug, PartialEq)]
pub struct AdminErrorGroup {
    pub program: String,
    pub function: String,
    pub line: Option<u32>,
    pub message: String,
    pub redacted: bool,
    pub count: u64,
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    pub sample_trace: Vec<String>,
}

/// A connection's session timing (OBI-237): `connected_at` is wall-clock
/// (what `who` reports), `last_activity` is monotonic (`Instant`, so
/// `idle_secs` can never go backwards under a clock adjustment). Kept
/// separate from `BcObject` (which already tracks `conn`) because a
/// connection outlives any single bound object across a `seteuid`/login
/// flow, and because `Registry::capture`'s snapshot (OBI-173) has no
/// reason to carry wall-clock session metadata across a copyover --
/// `World::reconnect` re-seeds it fresh instead (see that method's doc
/// comment).
struct ConnSession {
    connected_at: std::time::SystemTime,
    last_activity: std::time::Instant,
}

/// The `account_create`/`account_login` async backend (spec, OBI-85):
/// `World` calls this to *issue* a request (never blocking); the answer
/// comes back out-of-band, through whatever channel the implementation
/// uses, and the driver (`loom-cli`) hands it to
/// [`World::deliver_account_result`] using the same `request_id`.
///
/// [`NullAccountAuth`] (the default until `loom-cli` wires a real one) never
/// answers at all -- fine for every test/tool that does not exercise
/// accounts, since a request that never completes is silently inert, not a
/// hang (nothing awaits it synchronously).
pub trait AccountAuth {
    /// Issue the request; `false` (the queue to the real backend is full
    /// or closed) means the caller must treat it as `unavailable` right
    /// away (spec/CTO review OBI-85: never leave a request pending
    /// forever just because the backend channel briefly backed up).
    fn create_account(&mut self, request_id: u64, name: &str, password: &str) -> bool;
    fn login(&mut self, request_id: u64, name: &str, password: &str) -> bool;
}

/// Default [`AccountAuth`]: never answers (see the trait's doc).
pub struct NullAccountAuth;

impl AccountAuth for NullAccountAuth {
    fn create_account(&mut self, _request_id: u64, _name: &str, _password: &str) -> bool {
        true
    }
    fn login(&mut self, _request_id: u64, _name: &str, _password: &str) -> bool {
        true
    }
}

/// The `roles_set_tier`/`roles_set_member`/`roles_grant`/`roles_revoke_grant`/
/// `roles_propose_tier`/`roles_approve` async mutation backend (OBI-36
/// design note D-S2.2). `World` calls this to *issue* a mutation (never
/// blocking, and never touching Postgres itself -- that is `loom-cli`'s
/// wiring over `loom-persist`'s `SECURITY DEFINER` functions, S2a). The
/// answer comes back out-of-band and is handed to
/// [`World::deliver_roles_result`] using the same `request_id`, exactly
/// like [`AccountAuth`].
///
/// Every method's `actor` is the driver-computed actor-rule euid name
/// (the euid of the interactive whose input started the execution, taken
/// from the registry, never a string read from Weft -- see
/// `bcvm::registry::RegistryHost::roles_mutation_gate`), resolved to a
/// plain `&str` only here, at the boundary to this trait.
pub trait RolesMutations {
    fn set_tier(
        &mut self,
        request_id: u64,
        actor: &str,
        target: &str,
        tier: i64,
        reason: &str,
    ) -> bool;
    #[allow(clippy::too_many_arguments)]
    fn set_member(
        &mut self,
        request_id: u64,
        actor: &str,
        domain: &str,
        target: &str,
        role: &str,
        reason: &str,
    ) -> bool;
    #[allow(clippy::too_many_arguments)]
    fn grant(
        &mut self,
        request_id: u64,
        actor: &str,
        target: &str,
        kind: &str,
        what: &str,
        expires_at: Option<i64>,
        reason: &str,
    ) -> bool;
    #[allow(clippy::too_many_arguments)]
    fn revoke_grant(
        &mut self,
        request_id: u64,
        actor: &str,
        target: &str,
        kind: &str,
        what: &str,
        reason: &str,
    ) -> bool;
    fn propose_tier(
        &mut self,
        request_id: u64,
        actor: &str,
        target: &str,
        tier: i64,
        reason: &str,
    ) -> bool;
    fn approve(&mut self, request_id: u64, actor: &str, proposal_id: i64) -> bool;
}

/// Default [`RolesMutations`]: never answers (see the trait's doc; same
/// rationale as [`NullAccountAuth`]).
pub struct NullRolesMutations;

impl RolesMutations for NullRolesMutations {
    fn set_tier(
        &mut self,
        _id: u64,
        _actor: &str,
        _target: &str,
        _tier: i64,
        _reason: &str,
    ) -> bool {
        true
    }
    fn set_member(
        &mut self,
        _id: u64,
        _actor: &str,
        _domain: &str,
        _target: &str,
        _role: &str,
        _reason: &str,
    ) -> bool {
        true
    }
    fn grant(
        &mut self,
        _id: u64,
        _actor: &str,
        _target: &str,
        _kind: &str,
        _what: &str,
        _expires_at: Option<i64>,
        _reason: &str,
    ) -> bool {
        true
    }
    fn revoke_grant(
        &mut self,
        _id: u64,
        _actor: &str,
        _target: &str,
        _kind: &str,
        _what: &str,
        _reason: &str,
    ) -> bool {
        true
    }
    fn propose_tier(
        &mut self,
        _id: u64,
        _actor: &str,
        _target: &str,
        _tier: i64,
        _reason: &str,
    ) -> bool {
        true
    }
    fn approve(&mut self, _id: u64, _actor: &str, _proposal_id: i64) -> bool {
        true
    }
}

/// `roles_*` mutation efun bookkeeping (OBI-36 D-S2.2), borrowed by
/// `RegistryHost`'s `Driver` for the lifetime of one call -- the same
/// shape as `AccountsCtx`, one request-id counter/pending map/result
/// queue pair per async efun family.
pub struct RolesCtx<'a> {
    pub next_id: &'a mut u64,
    pub pending: &'a mut HashMap<u64, ObjectId>,
    pub results: &'a mut VecDeque<(u64, ObjectId, bool, String)>,
    pub backend: &'a mut dyn RolesMutations,
}

/// `account_create`/`account_login` bookkeeping (OBI-85), borrowed by
/// `RegistryHost`'s `Driver` for the lifetime of one call: a shared request
/// id counter, the map of requests still awaiting an out-of-band answer
/// (`request_id` → the object that issued it, so a since-destructed issuer
/// is silently skipped, per spec), the queue of results ready to deliver on
/// the *next* top-level entry (`World::drain_account_results`), and the
/// backend itself.
pub struct AccountsCtx<'a> {
    pub next_id: &'a mut u64,
    pub pending: &'a mut HashMap<u64, ObjectId>,
    pub results: &'a mut VecDeque<(u64, ObjectId, bool, String)>,
    pub auth: &'a mut dyn AccountAuth,
}
/// Heartbeat cadence (spec r5 N2): with a 100 ms world-tick granularity
/// (`loom-cli::serve`'s timer, OBI-82), a heartbeat every 20 world ticks
/// is once every 2 s. A `Limits` field, not a magic number in `World::tick`,
/// so tests (and eventually builder config) can dial it down.
pub const DEFAULT_HEARTBEAT_INTERVAL_TICKS: u64 = 20;

/// Player autosave cadence (spec §8.1: "players autosave every 5 min",
/// OBI-171): at the same 100 ms world-tick granularity, 5 minutes is
/// 3,000 world ticks. A `Limits` field for the same reason
/// `heartbeat_interval_ticks` is -- tests dial it down instead of
/// waiting out a real 5 minutes of simulated ticks.
pub const DEFAULT_AUTOSAVE_INTERVAL_TICKS: u64 = 3_000;

/// Per-execution guard rails (§5.8).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_ticks: u64,
    pub max_depth: u32,
    /// Per-object (deep, transitively-accounted) memory quota in bytes;
    /// see `bcvm::vm::Limits::mem_quota_bytes`.
    pub mem_quota_bytes: u64,
    /// `upgrade_all(path)` (OBI-89, eager mode): how many queued objects
    /// [`World::tick`] migrates per world tick. Bounded, not all-at-once,
    /// so a mass upgrade spreads across ticks instead of starving every
    /// other object/player's own call_out/heartbeat that tick (spec:
    /// "bounded per-tick budget").
    pub eager_upgrade_batch: usize,
    /// Every `heart_beat()`-subscribed object is called once every this
    /// many `World::tick()` calls (world ticks), not every tick (OBI-82).
    /// `call_out` delays remain in world ticks and are unaffected by this.
    pub heartbeat_interval_ticks: u64,
    /// Every currently-connected (interactive) object gets an
    /// `autosave()` apply once every this many world ticks (spec §8.1,
    /// OBI-171) -- the driver-side half of "players autosave every 5
    /// min"; see `World::tick`'s doc comment for the other two triggers
    /// (quit, net-dead), both routed through `World::disconnect`.
    pub autosave_interval_ticks: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_ticks: 1_000_000,
            max_depth: 512,
            mem_quota_bytes: VmLimits::default().mem_quota_bytes,
            eager_upgrade_batch: 200,
            heartbeat_interval_ticks: DEFAULT_HEARTBEAT_INTERVAL_TICKS,
            autosave_interval_ticks: DEFAULT_AUTOSAVE_INTERVAL_TICKS,
        }
    }
}

impl Limits {
    fn vm_limits(&self) -> VmLimits {
        VmLimits {
            max_depth: self.max_depth,
            mem_quota_bytes: self.mem_quota_bytes,
        }
    }
}

/// Failure to boot a world from a mudlib root.
#[derive(Debug)]
pub enum BootError {
    /// The mudlib root does not exist or is not a directory.
    NoMudlib(PathBuf),
    /// `/secure/master.wf` failed to compile or its `create()` failed.
    Master(String),
}

impl std::fmt::Display for BootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootError::NoMudlib(p) => write!(f, "mudlib root {} is not a directory", p.display()),
            BootError::Master(e) => write!(f, "cannot load {MASTER_PATH}:\n{e}"),
        }
    }
}

impl std::error::Error for BootError {}

/// The game world. Driven by exactly one thread (the world thread, §3.3).
pub struct World {
    root: PathBuf,
    /// Player-save root for `save_object`/`restore_object` (spec §8.1,
    /// OBI-171). Defaults to a `saves` directory *next to* (not inside)
    /// the mudlib root -- see [`default_save_root`] -- so player save
    /// data never lands inside the Git-backed `.wf` tree a `revert`/
    /// recompile or `git pull` operates on; overridable with
    /// [`World::set_save_root`] (`loom-cli`'s `--save-dir`).
    save_root: PathBuf,
    registry: Registry,
    compiler: Compiler,
    master: Option<ObjectId>,
    limits: Limits,
    /// `call_out`/heartbeat scheduler (OBI-33), advanced by `World::tick`.
    scheduler: Scheduler,
    /// `compile_object`/`update` requests dispatched to a background
    /// thread but not yet applied (OBI-90/D-P1.5): `World::tick` installs
    /// each one as soon as it finishes, so ticks in between are never
    /// blocked on a slow compile.
    pending_recompiles: Vec<(RecompileToken, RecompileJob)>,
    /// Every background compile `World::tick`/`poll_recompiles` has
    /// installed (or failed to) since the last `take_finished_recompiles`.
    finished_recompiles: Vec<(RecompileToken, Result<(), String>)>,
    next_recompile_token: u64,
    /// `recompile_set`'s background compile stage (D-B3.14, OBI-207
    /// P2-B3.1b): the multi-root generalisation of `pending_recompiles`/
    /// `finished_recompiles`, same "tick installs as soon as it finishes"
    /// contract.
    pending_recompile_sets: Vec<(RecompileSetToken, RecompileSetJob)>,
    finished_recompile_sets: Vec<(RecompileSetToken, crate::bcvm::RecompileReport)>,
    next_recompile_set_token: u64,
    /// `account_create`/`account_login` (OBI-85): see `AccountsCtx`.
    account_auth: Box<dyn AccountAuth>,
    account_next_id: u64,
    account_pending: HashMap<u64, ObjectId>,
    account_results: VecDeque<(u64, ObjectId, bool, String)>,
    /// Stack-based privilege check state (OBI-35): decision cache, policy
    /// epoch, audit ring buffer.
    security: SecurityState,
    /// The S2 roles snapshot (OBI-36 D-S2.1): `RolesSnapshot::empty()`
    /// (tier 0 for everyone, no domains, no policy, no grants) until
    /// `set_roles_snapshot` is first called. `Arc` so a swap is a
    /// pointer write and every in-flight `RegistryHost`'s borrowed copy
    /// stays valid for the execution it was built for even if a new
    /// snapshot lands the instant after.
    roles: Arc<RolesSnapshot>,
    /// Bumped by every [`World::set_roles_snapshot`] (OBI-121 S2c N1): a
    /// monotonic counter, not the snapshot `Arc`'s own pointer -- an
    /// `Arc`'s address can be reused after it is dropped (ABA), so a
    /// per-object cache keyed on it (`BcObject::mem_quota_cache`) could
    /// wrongly serve a stale value after two swaps land back-to-back at
    /// the same address. A `u64` counter cannot repeat within a boot.
    roles_generation: u64,
    /// `roles_set_tier`/... (OBI-36 D-S2.2): see `RolesCtx`.
    roles_backend: Box<dyn RolesMutations>,
    roles_next_id: u64,
    roles_pending: HashMap<u64, ObjectId>,
    roles_results: VecDeque<(u64, ObjectId, bool, String)>,
    /// The `quota_uid` (OBI-35 D-S1.6) of the most recently executed
    /// call_out, for tests/introspection asserting AC 3 ("its execution
    /// reports quota uid = the apprentice's"). `None` until the first
    /// call_out runs; tier quota *enforcement* against this uid is S2
    /// (OBI-36).
    last_call_out_quota_uid: Option<crate::security::Sym>,
    /// `tick_share_per_min`'s per-uid sliding usage window (OBI-121 S2c):
    /// see `TickShareWindow`.
    tick_share: HashMap<crate::security::Sym, TickShareWindow>,
    /// `disk_quota_mb`'s per-`<u>` byte counter (OBI-137 S1): see
    /// `crate::disk_usage::DiskUsage`.
    disk_usage: crate::disk_usage::DiskUsage,
    /// Grouped runtime-error inbox (OBI-169, spec §8.3): see
    /// `crate::errors::ErrorInbox`. Fed uniformly by `World::exec`.
    errors: crate::errors::ErrorInbox,
    /// Per-connection session timing (OBI-237 admin query `who`): see
    /// [`ConnSession`].
    sessions: HashMap<u64, ConnSession>,
}

/// Identifies one [`World::begin_recompile`] call, so its eventual result
/// (in [`World::take_finished_recompiles`]) can be matched back to the
/// caller that asked for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecompileToken(u64);

/// Identifies one [`World::begin_recompile_set`] call (D-B3.14, OBI-207
/// P2-B3.1b), so its eventual [`crate::bcvm::RecompileReport`] (in
/// [`World::take_finished_recompile_sets`]) can be matched back to the
/// caller that asked for it -- the multi-root generalisation of
/// [`RecompileToken`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecompileSetToken(u64);

/// `tick_share_per_min`'s per-uid sliding-window tick usage (OBI-121 S2c
/// §3, OBI-137 S2). A true 60-slot sliding window (design note: "for
/// example a 60-slot ring of per-second buckets", superseding OBI-121's
/// original fixed-bucket simplification, which reset wholesale once a
/// window turned 60s old and so could pass up to 2x a uid's share across
/// a burst straddling that reset).
///
/// **Clocked on world ticks, not the wall clock** (flagged spec
/// deviation): each bucket spans [`TICKS_PER_BUCKET`] world ticks (10 --
/// a world tick is 100 ms, `World::tick`'s own doc comment, so 10 ticks
/// is one second of *real* time when the driver is ticking on its normal
/// 100 ms timer) rather than a real `Instant`. This makes the window
/// entirely deterministic from the world-tick counter
/// (`Scheduler::tick`) alone, so a test can drive a whole 60-second
/// window's worth of buckets with plain repeated `World::tick()` calls
/// instead of a real 60-second sleep -- see
/// `tick_share_per_min_caps_a_burst_straddling_a_window_boundary` in
/// `tests/quotas.rs`.
const TICKS_PER_BUCKET: u64 = 10;
const BUCKET_COUNT: usize = 60;

struct TickShareWindow {
    /// Ticks used in each bucket, indexed by `(world_tick / TICKS_PER_BUCKET)
    /// % BUCKET_COUNT`.
    buckets: [u64; BUCKET_COUNT],
    /// Which absolute bucket index (`world_tick / TICKS_PER_BUCKET`,
    /// never wrapped) `buckets[i]` currently holds usage for --
    /// `u64::MAX` for a slot that has never been written. A slot whose
    /// `bucket_index` is more than `BUCKET_COUNT` behind the *current*
    /// bucket index is stale (older than the 60-slot window) and is
    /// treated as zero without needing to eagerly zero all 60 slots on
    /// every roll.
    bucket_index: [u64; BUCKET_COUNT],
    /// Whether this uid's usage was already at/over its limit as of the
    /// most recent [`World::tick_share_breached`] check (OBI-137 S2:
    /// `loom_tier_quota_breaches_total` must bump once per *transition*
    /// into breach, not once per deferred heartbeat/call_out tick).
    breached: bool,
}

impl TickShareWindow {
    fn fresh() -> TickShareWindow {
        TickShareWindow {
            buckets: [0; BUCKET_COUNT],
            bucket_index: [u64::MAX; BUCKET_COUNT],
            breached: false,
        }
    }

    fn slot(world_tick: u64) -> (usize, u64) {
        let bucket_index = world_tick / TICKS_PER_BUCKET;
        ((bucket_index as usize) % BUCKET_COUNT, bucket_index)
    }

    /// Charge `ticks` against the bucket `world_tick` falls in, first
    /// zeroing that slot if it belongs to an earlier bucket (a slot is
    /// only ever reused once the ring has come all the way back around
    /// to it, `BUCKET_COUNT` buckets later).
    fn add(&mut self, world_tick: u64, ticks: u64) {
        let (slot, bucket_index) = TickShareWindow::slot(world_tick);
        if self.bucket_index[slot] != bucket_index {
            self.bucket_index[slot] = bucket_index;
            self.buckets[slot] = 0;
        }
        self.buckets[slot] = self.buckets[slot].saturating_add(ticks);
    }

    /// Total ticks used across the [`BUCKET_COUNT`] buckets ending at
    /// (and including) whichever bucket `world_tick` falls in -- a true
    /// sliding sum, not a fixed-bucket total, so a burst that straddles
    /// what would have been a fixed-bucket reset boundary is still
    /// capped at the same 1x share as one that does not.
    fn used(&self, world_tick: u64) -> u64 {
        let (_, current_bucket) = TickShareWindow::slot(world_tick);
        let mut total = 0u64;
        for i in 0..BUCKET_COUNT {
            if self.bucket_index[i] != u64::MAX
                && current_bucket.saturating_sub(self.bucket_index[i]) < BUCKET_COUNT as u64
            {
                total = total.saturating_add(self.buckets[i]);
            }
        }
        total
    }
}

/// `PUT /api/v1/files/content`'s precondition (OBI-180 M-FS-6): either
/// the caller's `ETag` must match the file's current contents (update),
/// or the file must not exist yet (create).
#[derive(Debug, Clone)]
pub enum FileMatchPrecondition {
    /// `If-Match: "<etag>"` -- the file must currently exist and hash to
    /// exactly this `sha256` hex digest (quoted or not; compared after
    /// stripping surrounding `"`).
    IfMatch(String),
    /// `If-None-Match: *` -- the file must not currently exist.
    IfNoneMatchStar,
}

/// Outcome of [`World::call_file_write_if_match`], distinct from its
/// `Err(String)` (an authorization refusal or I/O failure, same shape as
/// [`World::call_file_efun`]'s): all three of these are a successful,
/// authorized attempt that ran to completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileCasOutcome {
    /// The write happened.
    Written,
    /// `write_file` refused for disk quota, not authorization (OBI-137
    /// S1) -- the precondition was satisfied, the write itself just
    /// didn't happen.
    QuotaExceeded,
    /// The precondition didn't hold (stale `If-Match`, or
    /// `If-None-Match: *` against a file that already exists).
    PreconditionFailed,
}

/// `sha256(contents)`, hex-encoded (OBI-180 M-FS-6). Deliberately
/// duplicated in `loom_http::files::etag_for` rather than shared: sharing
/// it would mean `loom-http` depending on `loom-vm` (or vice versa) just
/// for a ten-line hash function, a dependency edge neither crate
/// otherwise needs (see that module's doc for why `loom-http` stays
/// `loom-vm`-free). Both sides must still agree byte-for-byte, so any
/// change here needs the matching change there, and vice versa -- a unit
/// test on each side pins the same fixture string to the same digest.
fn file_etag_hex(contents: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(contents.as_bytes());
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// `true` if `contents` hashes to `expected` (already unquoted). Used
/// only by [`World::call_file_write_if_match`]'s `If-Match` branch.
fn file_etag_matches(contents: &str, expected: &str) -> bool {
    file_etag_hex(contents) == expected
}

#[cfg(test)]
mod file_etag_tests {
    use super::*;

    /// Pins `file_etag_hex` to the exact same digest
    /// `loom_http::files::etag_for`'s own test pins for the same fixture
    /// string (minus quoting) -- both sides must agree byte-for-byte on
    /// what `sha256("int x;")` hex-encodes to, since one computes the
    /// `ETag` a client sees and the other independently verifies the
    /// `If-Match` built from it.
    #[test]
    fn pinned_against_the_loom_http_fixture() {
        assert_eq!(
            file_etag_hex("int x;"),
            "e13e332bd08e13cbe2aee094e130ed23878b3b554be5b9a665a83e63caa987ae"
        );
    }
}

impl World {
    /// Boot a world from `mudlib_root`: compile and load `/secure/master.wf`.
    pub fn boot(mudlib_root: &Path) -> Result<World, BootError> {
        World::boot_with_limits(mudlib_root, Limits::default())
    }

    pub fn boot_with_limits(mudlib_root: &Path, limits: Limits) -> Result<World, BootError> {
        if !mudlib_root.is_dir() {
            return Err(BootError::NoMudlib(mudlib_root.to_path_buf()));
        }
        let mut w = World {
            root: mudlib_root.to_path_buf(),
            save_root: default_save_root(mudlib_root),
            registry: Registry::default(),
            compiler: Compiler::new(mudlib_root.to_path_buf()),
            master: None,
            limits,
            scheduler: Scheduler::new(),
            pending_recompiles: Vec::new(),
            finished_recompiles: Vec::new(),
            next_recompile_token: 0,
            pending_recompile_sets: Vec::new(),
            finished_recompile_sets: Vec::new(),
            next_recompile_set_token: 0,
            account_auth: Box::new(NullAccountAuth),
            account_next_id: 0,
            account_pending: HashMap::new(),
            account_results: VecDeque::new(),
            security: SecurityState::new(),
            roles: Arc::new(RolesSnapshot::empty()),
            roles_generation: 0,
            roles_backend: Box::new(NullRolesMutations),
            roles_next_id: 0,
            roles_pending: HashMap::new(),
            roles_results: VecDeque::new(),
            last_call_out_quota_uid: None,
            tick_share: HashMap::new(),
            disk_usage: crate::disk_usage::DiskUsage::default(),
            errors: crate::errors::ErrorInbox::new(),
            sessions: HashMap::new(),
        };
        let mut null = NullHost;
        let sentinel = ObjectId {
            index: u32::MAX,
            generation: 0,
        };
        let master = w
            .exec(&mut null, sentinel, None, None, None, None, None, |h| {
                h.load_object(MASTER_PATH)
            })
            .map_err(|e| BootError::Master(e.report()))?;
        w.master = Some(master);
        Ok(w)
    }

    /// Begin a binary world snapshot (design spec §8.1 model 2, OBI-173):
    /// captures the object graph copy-on-write and returns a job the
    /// caller drives to completion with
    /// `SnapshotJob::encode_step`/`encode_all` -- see `crate::snapshot`'s
    /// module docs for the full copy-on-write story and current scope
    /// limits. The capture itself (`Registry::capture`) is the *entire*
    /// synchronous "pause" this costs the world thread: its result does
    /// not borrow `self`, so further `World::tick` calls can run
    /// immediately after this returns, even while the job's bytes are
    /// still being encoded.
    ///
    /// `Err` only while an `atomic fn` scope is open (see
    /// `Registry::capture`'s own docs for why).
    pub fn begin_snapshot(
        &self,
    ) -> Result<crate::snapshot::SnapshotJob, crate::snapshot::SnapshotError> {
        self.registry
            .capture()
            .map(crate::snapshot::SnapshotJob::new)
            .map_err(|_| crate::snapshot::SnapshotError::AtomicScopeOpen)
    }

    /// Load a binary world snapshot into a fresh driver process (the
    /// standby side of copyover, design spec §8.1/OBI-173): `mudlib_root`
    /// is compiled on demand per distinct program path the snapshot
    /// references, exactly as [`World::boot`] would, and every object's
    /// dynamic state (vars, placement, connections) is restored from
    /// `bytes`. Does **not** run master's `connect()`/boot-time applies --
    /// `master` is simply whichever restored object was registered under
    /// [`MASTER_PATH`], `None` if the snapshot had none.
    ///
    /// Fails cleanly (no panic) on a bad magic, an incompatible ABI
    /// version, a truncated/corrupt file, a value kind this build cannot
    /// yet decode, or a program path that no longer compiles against this
    /// `mudlib_root` -- see `crate::snapshot::SnapshotError`.
    pub fn load_snapshot(
        mudlib_root: &Path,
        limits: Limits,
        bytes: &[u8],
    ) -> Result<World, crate::snapshot::SnapshotError> {
        if !mudlib_root.is_dir() {
            return Err(crate::snapshot::SnapshotError::Restore(format!(
                "{} is not a directory",
                mudlib_root.display()
            )));
        }
        let decoded = crate::snapshot::decode_snapshot(bytes)?;
        let mut registry = Registry::default();
        let mut compiler = Compiler::new(mudlib_root.to_path_buf());
        registry
            .restore(decoded, &mut compiler)
            .map_err(crate::snapshot::SnapshotError::Restore)?;
        let master = registry.names.get(MASTER_PATH).copied();
        Ok(World {
            root: mudlib_root.to_path_buf(),
            registry,
            compiler,
            master,
            limits,
            scheduler: Scheduler::new(),
            pending_recompiles: Vec::new(),
            finished_recompiles: Vec::new(),
            next_recompile_token: 0,
            pending_recompile_sets: Vec::new(),
            finished_recompile_sets: Vec::new(),
            next_recompile_set_token: 0,
            save_root: default_save_root(mudlib_root),
            account_auth: Box::new(NullAccountAuth),
            account_next_id: 0,
            account_pending: HashMap::new(),
            account_results: VecDeque::new(),
            security: SecurityState::new(),
            roles: Arc::new(RolesSnapshot::empty()),
            roles_generation: 0,
            roles_backend: Box::new(NullRolesMutations),
            roles_next_id: 0,
            roles_pending: HashMap::new(),
            roles_results: VecDeque::new(),
            last_call_out_quota_uid: None,
            tick_share: HashMap::new(),
            disk_usage: crate::disk_usage::DiskUsage::default(),
            errors: crate::errors::ErrorInbox::new(),
            sessions: HashMap::new(),
        })
    }

    /// Install the real `account_create`/`account_login` backend (OBI-85);
    /// until this is called, every account request is issued but never
    /// answered ([`NullAccountAuth`]).
    pub fn set_account_auth(&mut self, auth: Box<dyn AccountAuth>) {
        self.account_auth = auth;
    }

    /// Deliver an out-of-band `account_create`/`account_login` result
    /// (OBI-85): the driver calls this after receiving the matching event
    /// from whatever channel its [`AccountAuth`] impl uses. A no-op if
    /// `request_id` is unknown (already delivered, or never issued).
    /// Queues the result rather than calling the apply immediately, so
    /// delivery always happens on a later top-level entry, same as a
    /// validation failure (see `RegistryHost::issue_account_request`).
    pub fn deliver_account_result(&mut self, request_id: u64, ok: bool, detail: &str) {
        if let Some(ob) = self.account_pending.remove(&request_id) {
            self.account_results
                .push_back((request_id, ob, ok, detail.to_string()));
        }
    }

    /// Run every `account_result` apply queued by
    /// [`Self::deliver_account_result`] or by a validation failure. Skips
    /// (drops) a result whose issuing object has since been destructed, per
    /// spec. The driver should call this on every event-loop iteration and
    /// on every tick, so login latency is bounded by how often the loop
    /// runs, not by how much other traffic there is.
    ///
    /// The apply runs in the issuer's *connection context* (OBI-38): if the
    /// issuing object is bound to a connection, `this_player()` is that
    /// object and the execution carries its connection, exactly as for
    /// `process_input`. A login object can then hand its connection to the
    /// player (`bind_connection` via the master) from inside
    /// `account_result`, which is where a login flow finishes.
    pub fn drain_account_results(&mut self, host: &mut dyn Host) {
        while let Some((id, ob, ok, detail)) = self.account_results.pop_front() {
            if let Some(o) = self.registry.get(ob) {
                let conn = o.conn;
                let this_player = conn.map(|_| ob);
                let _ = self.exec(host, ob, this_player, conn, None, None, None, |h| {
                    h.call_apply(
                        ob,
                        "account_result",
                        vec![Value::Int(id as i64), Value::Bool(ok), Value::str(&detail)],
                    )
                });
            }
        }
    }

    /// Install the S2 roles snapshot (OBI-36 D-S2.1): swaps it in between
    /// executions (a pointer write) and flushes the security decision
    /// cache ([`Self::flush_security_cache`]), so the *next* execution
    /// after this call sees both the new roles and no stale cached
    /// `valid_*` decision from before the swap. The driver
    /// (`loom-cli`, S2a wiring) calls this at boot (the DB-worker loader,
    /// or the `LOOM_ROLES_SEED` dev/CI path -- see `crate::roles`), on
    /// every `LISTEN roles_changed` notification, after every roles
    /// mutation completes, and on a timer at the earliest `expires_at`
    /// among loaded grants.
    pub fn set_roles_snapshot(&mut self, snap: Arc<RolesSnapshot>) {
        self.roles = snap;
        self.roles_generation += 1;
        self.flush_security_cache();
    }

    /// The roles snapshot currently in effect (tests/introspection, and
    /// `loom-cli`'s expiry timer, which needs to read the loaded grants'
    /// `expires_at`s to schedule its next reload).
    pub fn roles_snapshot(&self) -> &Arc<RolesSnapshot> {
        &self.roles
    }

    /// Install the real `roles_set_tier`/... backend (OBI-36 D-S2.2); until
    /// this is called, every roles mutation request is issued but never
    /// answered ([`NullRolesMutations`]).
    pub fn set_roles_backend(&mut self, backend: Box<dyn RolesMutations>) {
        self.roles_backend = backend;
    }

    /// Deliver an out-of-band `roles_*` mutation result (OBI-36 D-S2.2):
    /// the driver calls this after `loom-persist`'s `SECURITY DEFINER`
    /// function returns (S2a). A no-op if `request_id` is unknown (already
    /// delivered, or never issued). Queued rather than delivered
    /// immediately, exactly like [`Self::deliver_account_result`], so
    /// `roles_result` always runs on a later top-level entry.
    pub fn deliver_roles_result(&mut self, request_id: u64, ok: bool, detail: &str) {
        if let Some(ob) = self.roles_pending.remove(&request_id) {
            self.roles_results
                .push_back((request_id, ob, ok, detail.to_string()));
        }
    }

    /// Run every `roles_result` apply queued by
    /// [`Self::deliver_roles_result`] or by a gate failure inside the
    /// mutation efun itself (secure-only/actor-rule refusal, or a backend
    /// whose request queue is briefly full). See
    /// [`Self::drain_account_results`] for the connection-context and
    /// destructed-issuer semantics, which are the same here (`/secure/roles`
    /// is the usual issuer, and is never destructed in practice, but the
    /// rule is uniform).
    pub fn drain_roles_results(&mut self, host: &mut dyn Host) {
        while let Some((id, ob, ok, detail)) = self.roles_results.pop_front() {
            if let Some(o) = self.registry.get(ob) {
                let conn = o.conn;
                let this_player = conn.map(|_| ob);
                let _ = self.exec(host, ob, this_player, conn, None, None, None, |h| {
                    h.call_apply(
                        ob,
                        "roles_result",
                        vec![Value::Int(id as i64), Value::Bool(ok), Value::str(&detail)],
                    )
                });
            }
        }
    }

    /// The mudlib root this world was booted from.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The player-save root (spec §8.1, OBI-171) `save_object`/
    /// `restore_object` read and write under.
    pub fn save_root(&self) -> &Path {
        &self.save_root
    }

    /// Override the player-save root (`loom-cli`'s `--save-dir`); defaults
    /// to [`default_save_root`] of the mudlib root this world was booted
    /// from. Takes effect for every save/restore from this call on.
    pub fn set_save_root(&mut self, dir: PathBuf) {
        self.save_root = dir;
    }

    /// Run `body` against a fresh [`RegistryHost`] with driver context
    /// wired up (network host, `this_player`, bound connection, master).
    /// `acting` is the object whose own euid seeds this execution's guard
    /// cut (OBI-35 D-S1.2 rule 5), independent of `this_player` (the
    /// connected user, if any — `this_player()`'s answer). `cut_guard`
    /// overrides that derived cut for a scheduled call_out, whose guard
    /// must be exactly its captured set (D-S1.7).
    ///
    /// `ticks_quota_uid` (OBI-121 S2c §3/§4): `None` gets the world
    /// default `max_ticks_exec` (player input, `connect`, `disconnect`,
    /// the account/roles result drains, and every driver-only
    /// introspection/tooling call below) -- "the world default ... for
    /// player input" applies even when the input travelled through a
    /// tier-owned object (AC: "a player-input execution through a T1
    /// object still gets the 1M-tick default"). `Some(uid)` resolves
    /// `uid`'s owner tier's row instead: only `World::tick`'s heartbeat
    /// (keyed on the object's own euid) and call_out (keyed on its
    /// captured `quota_uid`) pass this.
    #[allow(clippy::too_many_arguments)]
    fn exec<T>(
        &mut self,
        host: &mut dyn Host,
        acting: ObjectId,
        this_player: Option<ObjectId>,
        conn: Option<u64>,
        cut_guard: Option<crate::security::GuardSet>,
        input_actor: Option<crate::security::Sym>,
        ticks_quota_uid: Option<crate::security::Sym>,
        body: impl FnOnce(&mut RegistryHost<'_>) -> Result<T, RtError>,
    ) -> Result<T, RtError> {
        self.registry.debug_assert_atomic_scope_closed();
        let max_ticks = match ticks_quota_uid {
            // Player input, `connect`/`disconnect`, and every driver-only
            // introspection/tooling call: the *configured* world default
            // (`self.limits.max_ticks`, `Limits::default()` == the spec's
            // 1,000,000 -- CTO review B2: a hardcoded constant here would
            // silently ignore a world that configures a different default,
            // e.g. `loom-vm`'s own `examples/vm_bench.rs`, which raises it
            // to benchmark workloads heavier than the spec default without
            // tripping a false quota breach).
            None => self.limits.max_ticks,
            Some(uid) => {
                let name = self.registry.syms.name(uid).to_string();
                let defaults = crate::quota::Defaults::from_limits(
                    self.limits.max_ticks,
                    self.limits.mem_quota_bytes,
                );
                crate::quota::resolve(&self.roles, &name, defaults).max_ticks_exec
            }
        };
        let mut rh = RegistryHost::with_driver(
            &mut self.registry,
            acting,
            self.limits.vm_limits(),
            max_ticks,
            &mut self.compiler,
            host,
            this_player,
            conn,
            self.master,
            &mut self.scheduler,
            crate::world::AccountsCtx {
                next_id: &mut self.account_next_id,
                pending: &mut self.account_pending,
                results: &mut self.account_results,
                auth: self.account_auth.as_mut(),
            },
            &mut self.security,
            self.roles.clone(),
            self.roles_generation,
            crate::world::RolesCtx {
                next_id: &mut self.roles_next_id,
                pending: &mut self.roles_pending,
                results: &mut self.roles_results,
                backend: self.roles_backend.as_mut(),
            },
            cut_guard,
            input_actor,
            &mut self.disk_usage,
            &mut self.errors,
            self.save_root.clone(),
        );
        let result = body(&mut rh);
        // OBI-121 S2c `tick_share_per_min`: charge whatever ticks this
        // execution actually used against its quota uid's sliding window
        // -- player input (`ticks_quota_uid: None`) never participates,
        // per spec ("player input is never deferred").
        if let Some(uid) = ticks_quota_uid {
            let used = max_ticks.saturating_sub(rh.ticks_left);
            self.record_tick_share_usage(uid, used);
        }
        self.registry.debug_assert_atomic_scope_closed();
        // OBI-169: every execution's `Err` is recorded in the error inbox
        // here, uniformly -- independent of whether the caller also
        // reports it to a player (`World::report`) or silently drops it
        // (a heartbeat, a `call_out`, `net_dead`, an eager upgrade
        // migration, an `account_result`/`roles_result` drain).
        if let Err(e) = &result {
            self.note_error(acting, e);
        }
        result
    }

    /// Record `e` in the error inbox (OBI-169), attributed to the
    /// **innermost** frame's own declaring program (`e.trace_programs`'s
    /// first entry -- most recent frame first, same order as
    /// `e.trace`), falling back to `acting`'s own program only when the
    /// error carries no trace at all (raised before any frame ever
    /// pushed, e.g. `start`'s "no function" lookup failure).
    ///
    /// CTO review (OBI-169, PR #72, must-fix 1): attributing to
    /// `acting`'s program instead -- the *entry* object, not where the
    /// error actually originated -- would leak a `/secure` program's
    /// error message (which can embed input) to anyone who can
    /// `valid_read` the entry object's own, less-privileged program, any
    /// time a cross-object/program call chain (`call_other`, an apply)
    /// fails several frames deep inside something the caller could never
    /// read directly. The grouping key's `program` (and the redaction
    /// rule below) must both be keyed on the real origin.
    ///
    /// Grouped by `(program, line, message)` per spec §8.3 (OBI-231):
    /// `line` comes from the same innermost frame as `program`
    /// (`e.trace_lines`, parallel to `e.trace_programs`).
    fn note_error(&mut self, acting: ObjectId, e: &RtError) {
        let program = e.trace_programs.first().cloned().unwrap_or_else(|| {
            self.registry
                .get(acting)
                .map(|o| o.program.path.to_string())
                .unwrap_or_else(|| "?".to_string())
        });
        let function = crate::errors::function_of(e);
        let line = crate::errors::line_of(e);
        let now_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let redacted = program.starts_with("/secure/");
        self.errors.record(
            &program,
            &function,
            line,
            &e.message,
            &e.trace,
            now_unix_ms,
            redacted,
        );
    }

    /// The grouped runtime-error inbox (OBI-169), unfiltered by
    /// permission: for tests/introspection and the driver's
    /// `/api/v1/errors` HTTP handler, which has no in-game caller to
    /// filter by (unlike the `errors` efun -- see `loom-http`'s doc
    /// comment on that route for the admin-only rationale).
    /// `program_prefix` matches [`crate::errors::ErrorInbox::snapshot`].
    pub fn errors_snapshot(&self, program_prefix: Option<&str>) -> Vec<crate::errors::ErrorRecord> {
        self.errors.snapshot(program_prefix)
    }

    /// `GET /api/v1/admin/who`'s real data (OBI-237, the world-thread side
    /// of the admin query channel, OBI-234 follow-up): one row per live
    /// connection, in ascending `conn` id order.
    ///
    /// `account` is the bound object's current *euid*, but only once it
    /// differs from the object's immutable `uid` -- i.e. only once
    /// something has `seteuid`'d it, which in a real mudlib is exactly
    /// what `/secure/login` does once a connection authenticates (see
    /// `bcvm::registry::RegistryHost::check_confinement`'s doc comment
    /// for the same euid-is-the-account convention this driver already
    /// relies on for `move_to` confinement). A connection still at a
    /// login/creation prompt -- never `seteuid`'d -- reports `None`. This
    /// is a convention, not a dedicated "logged in" flag: the driver has
    /// no concept of its own of what "logged in" means (spec: entirely
    /// mudlib policy), so this is the best available proxy, not an
    /// invented parallel one.
    ///
    /// Never an email or an IP address: neither exists anywhere in
    /// `World`'s own state for a connection (M-ADM-3), so there is no
    /// field here to leak one from even by accident.
    pub fn who_sessions(&self) -> Vec<SessionSummary> {
        let mut out: Vec<SessionSummary> = self
            .registry
            .conns
            .iter()
            .filter_map(|(&conn_id, &ob)| {
                let o = self.registry.get(ob)?;
                let session = self.sessions.get(&conn_id)?;
                let account = (o.euid != o.uid).then(|| self.principal_name(o.euid).to_string());
                let idle_secs = std::time::Instant::now()
                    .saturating_duration_since(session.last_activity)
                    .as_secs() as i64;
                Some(SessionSummary {
                    conn_id,
                    account,
                    connected_at: session.connected_at,
                    idle_secs,
                })
            })
            .collect();
        out.sort_unstable_by_key(|s| s.conn_id);
        out
    }

    /// `GET /api/v1/admin/objects`'s real data (OBI-237): every live
    /// object whose *declaring program* `caller_euid` can `valid_read` --
    /// the exact `Operation::Read`/`authorize` call path every other
    /// `valid_read` call-site uses (`bcvm::registry::RegistryHost::
    /// admin_valid_read`'s doc comment; the `errors` efun's own
    /// per-program filter is the closest existing precedent, down to "a
    /// denied program's objects are silently omitted, not an error" --
    /// see `errors_efun`'s doc comment). The decision is cached per
    /// distinct program for the duration of this one call (same reason
    /// `errors_efun` does it: many objects commonly share one program,
    /// and the security decision cache would dedupe the `valid_read`
    /// apply calls anyway, but this skips even the cache lookups).
    ///
    /// Run inside a `cut_guard` carrying exactly `caller_euid` as both
    /// `uid` and `euid` (D-S1.2 rule 5's cut semantics): the admin caller
    /// has no live in-game object at all (an HTTP request, not a
    /// connection), so there is no `self_object` principal to derive a
    /// guard from the normal way -- this is the explicit substitute,
    /// exactly as a scheduled `call_out`'s captured guard substitutes for
    /// its own missing "current" principal.
    ///
    /// `caller_tier` is accepted for parity with `loom_http::admin_query::
    /// WorldAdminQuery`'s signature but intentionally unused: the world
    /// side's permission boundary is `valid_read` alone, never a parallel
    /// tier-based rule (HTTP's own T3 floor has already run by the time
    /// this is called -- this is the *real* gate behind it, same spec
    /// reasoning as `errors_efun`'s T5 redaction note).
    ///
    /// CTO review (OBI-279, follow-up to OBI-237 PR #102, non-blocking
    /// note 1): `Err` (a tick-budget or other runtime failure inside
    /// `valid_read` itself, surfaced by [`RegistryHost::admin_valid_read`]
    /// rather than silently treated as a denial the way it would be for
    /// an in-game efun's `valid_*` gate) propagates out of this method,
    /// not swallowed into an empty, successful-looking `Vec` -- the HTTP
    /// edge turns this into a `503` (`WorldQueryError`), not "nothing
    /// readable". A `valid_read` that runs and returns a plain `bool`,
    /// allow or deny, is unaffected: this only changes what happens when
    /// `valid_read` *itself* fails to produce an answer at all.
    pub fn admin_list_objects(
        &mut self,
        caller_euid: &str,
        _caller_tier: i16,
        host: &mut dyn Host,
    ) -> Result<Vec<AdminObjectSummary>, RtError> {
        // CTO review (OBI-237 PR #102, must-fix B1): `caller_euid` is an
        // HTTP-authenticated staff `sub`, never validated against the
        // driver's reserved-principal rule the way an in-game `seteuid`
        // is (`bcvm::registry::RegistryHost::check_reserved_euid`,
        // D-S3.1/M-FS-1). Refused *before* interning: `syms.intern("root")`
        // reuses `security::ROOT` (sym 0), which `GuardSet::with` drops
        // as the identity element, leaving an **empty** guard -- D-S1.2's
        // "an all-root stack is allowed without asking the master" rule,
        // meaning a staff account literally named `root` (or `mudlib`, or
        // any `domain:*`) would silently get root's own unconditional
        // `valid_read` pass, `/secure` included, instead of being denied.
        // `is_reserved_principal` denies exactly those names, the same
        // check `check_reserved_euid` applies to an in-game `seteuid`.
        if crate::security::is_reserved_principal(caller_euid) {
            return Ok(Vec::new());
        }
        let master = self.master_or_sentinel();
        let euid_sym = self.registry.syms.intern(caller_euid);
        let guard = crate::security::GuardSet::empty().with(crate::security::Principal {
            uid: euid_sym,
            euid: euid_sym,
        });
        let ids = self.registry.ids();
        self.exec(host, master, None, None, Some(guard), None, None, |h| {
            let mut decided: HashMap<String, bool> = HashMap::new();
            let mut out = Vec::new();
            for id in ids {
                let Some(o) = h.registry.get(id) else {
                    continue;
                };
                let program_path = o.program.path.to_string();
                let name = o.name.clone();
                let euid_sym = o.euid;
                let allowed = match decided.get(&program_path) {
                    Some(&a) => a,
                    None => {
                        let a = h.admin_valid_read("list_objects", &program_path)?;
                        decided.insert(program_path, a);
                        a
                    }
                };
                if !allowed {
                    continue;
                }
                let euid = h.registry.syms.name(euid_sym).to_string();
                out.push(AdminObjectSummary { path: name, euid });
            }
            Ok(out)
        })
    }

    /// `GET /api/v1/admin/objects/:path/vars`'s real data (OBI-237):
    /// `path`'s variables, once `caller_euid` passes the exact same
    /// `valid_read` gate as [`World::admin_list_objects`] -- on `path`'s
    /// *declaring program*, not the instance path, same as every other
    /// `valid_read` call-site.
    ///
    /// `None` both for a `path` that does not resolve to a live object
    /// ([`World::find_object`]) and for one `valid_read` refuses --
    /// deliberately indistinguishable (the trait doc comment this
    /// mirrors, `loom_http::admin_query::WorldAdminQuery::object_vars`,
    /// requires exactly this: "never a different error shape", so the
    /// HTTP layer can't be used to probe which `/secure` paths exist).
    /// This is also where `/secure` confidentiality is actually
    /// enforced -- the HTTP edge's T5 tier floor is a convenience, not
    /// the real boundary; a master whose `valid_read` denies a
    /// `/secure/**` program to a tier-5 caller is still obeyed here.
    ///
    /// CTO review (OBI-237 PR #102, non-blocking note): this renders
    /// *every* variable `valid_read` lets the caller see, with no
    /// credential-shaped-name scrubbing of its own (e.g. `/secure/login`'s
    /// transient `pending_pw` would render like any other var). That is
    /// deliberate, not an oversight: `valid_read` is the one real
    /// confidentiality boundary this method enforces (the line above),
    /// and a master whose policy lets a caller read a program at all is
    /// trusted to have already decided that caller may see its state --
    /// adding a second, driver-guessed "looks like a credential" filter
    /// on top would be exactly the kind of parallel permission rule this
    /// issue's design note says not to invent. A mudlib that stores a
    /// real secret in a plain (non-`persistent`, non-`/secure`-gated)
    /// var is a mudlib-side `valid_read` policy bug, not something this
    /// method can detect from here.
    ///
    /// CTO review (OBI-279, follow-up to OBI-237 PR #102, non-blocking
    /// note 1): `Err` (a tick-budget or other runtime failure inside
    /// `valid_read` itself) propagates out of this method, same as
    /// [`World::admin_list_objects`]'s doc comment -- distinct from the
    /// `Ok(None)` this method already uses for "doesn't exist" and "a
    /// real, completed `valid_read` denied it", which stay deliberately
    /// indistinguishable from each other, just not from "the permission
    /// check itself never completed".
    pub fn admin_object_vars(
        &mut self,
        caller_euid: &str,
        _caller_tier: i16,
        path: &str,
        host: &mut dyn Host,
    ) -> Result<Option<AdminObjectVars>, RtError> {
        // CTO review (OBI-237 PR #102, must-fix B1): see
        // `admin_list_objects`'s doc comment for why this check must run
        // before `syms.intern(caller_euid)`, not after.
        if crate::security::is_reserved_principal(caller_euid) {
            return Ok(None);
        }
        let master = self.master_or_sentinel();
        let euid_sym = self.registry.syms.intern(caller_euid);
        let guard = crate::security::GuardSet::empty().with(crate::security::Principal {
            uid: euid_sym,
            euid: euid_sym,
        });
        let target = self.find_object(path);
        let path = path.to_string();
        self.exec(host, master, None, None, Some(guard), None, None, |h| {
            let Some(id) = target else {
                return Ok(None);
            };
            let Some(o) = h.registry.get(id) else {
                return Ok(None);
            };
            let program_path = o.program.path.to_string();
            if !h.admin_valid_read("object_vars", &program_path)? {
                return Ok(None);
            }
            let Some(o) = h.registry.get(id) else {
                return Ok(None);
            };
            let raw: Vec<(String, Value)> = o
                .vars
                .iter()
                .map(|((_, name), v)| (name.to_string(), v.clone()))
                .collect();
            let mut vars: Vec<AdminVarEntry> = raw
                .into_iter()
                .map(|(name, value)| {
                    let value = crate::bcvm::heap::display(&value, &|oid| {
                        h.registry
                            .get(oid)
                            .map_or_else(|| "<destructed>".to_string(), |o| o.name.clone())
                    });
                    AdminVarEntry { name, value }
                })
                .collect();
            vars.sort_unstable_by(|a, b| a.name.cmp(&b.name));
            Ok(Some(AdminObjectVars {
                path: path.clone(),
                vars,
            }))
        })
    }

    /// `GET /api/v1/admin/errors`'s real data (OBI-235, OBI-237): every
    /// error-inbox group (`World::errors_snapshot`, OBI-169) whose
    /// *program* `caller_euid` can `valid_read`, optionally narrowed to
    /// `program_prefix` first (`errors_snapshot`'s own filter -- same
    /// semantics as the `errors` efun's own `filter` argument). Exactly
    /// `errors_efun`'s own per-program permission filter and M-ERR-1
    /// redaction rule, just invoked for an HTTP admin caller instead of
    /// an in-game one: a denied program's groups are silently omitted,
    /// not an error, and a `/secure/**` origin's message is redacted to
    /// any caller below `caller_tier` 5, independent of whether
    /// `valid_read` itself already let a lower tier through (see
    /// `errors_efun`'s own doc comment for why that floor is
    /// driver-enforced, not conditioned on the master's policy).
    ///
    /// `caller_tier` here *is* used (unlike `admin_list_objects`/
    /// `admin_object_vars`'s `_caller_tier`): M-ERR-1's redaction rule is
    /// specifically tier-keyed, not `valid_read`-keyed, both in the
    /// `errors` efun and here -- the HTTP-authenticated staff tier is
    /// the same tier space the master's roles snapshot uses (T5 is
    /// `/secure`'s own floor throughout the admin-query surface, e.g.
    /// `loom-http`'s `SECURE_VARS_MIN_TIER`).
    ///
    /// CTO review (OBI-279, follow-up to OBI-237 PR #102, non-blocking
    /// note 1): `Err` (a tick-budget or other runtime failure inside
    /// `valid_read` itself) propagates out of this method, same as
    /// [`World::admin_list_objects`]'s doc comment.
    pub fn admin_errors(
        &mut self,
        caller_euid: &str,
        caller_tier: i16,
        program_prefix: Option<&str>,
        host: &mut dyn Host,
    ) -> Result<Vec<AdminErrorGroup>, RtError> {
        // CTO review (OBI-237 PR #102, must-fix B1): see
        // `admin_list_objects`'s doc comment for why this check must run
        // before `syms.intern(caller_euid)`, not after.
        if crate::security::is_reserved_principal(caller_euid) {
            return Ok(Vec::new());
        }
        let master = self.master_or_sentinel();
        let euid_sym = self.registry.syms.intern(caller_euid);
        let guard = crate::security::GuardSet::empty().with(crate::security::Principal {
            uid: euid_sym,
            euid: euid_sym,
        });
        let rows = self.errors_snapshot(program_prefix);
        self.exec(host, master, None, None, Some(guard), None, None, |h| {
            let mut decided: HashMap<String, bool> = HashMap::new();
            let mut out = Vec::new();
            for row in rows {
                let allowed = match decided.get(&row.program) {
                    Some(&a) => a,
                    None => {
                        let a = h.admin_valid_read("errors", &row.program)?;
                        decided.insert(row.program.clone(), a);
                        a
                    }
                };
                if !allowed {
                    continue;
                }
                let message = if row.redacted && caller_tier < 5 {
                    "<redacted>".to_string()
                } else {
                    row.message
                };
                out.push(AdminErrorGroup {
                    program: row.program,
                    function: row.function,
                    line: if row.line == 0 { None } else { Some(row.line) },
                    message,
                    redacted: row.redacted,
                    count: row.count,
                    first_seen_unix_ms: row.first_seen_unix_ms,
                    last_seen_unix_ms: row.last_seen_unix_ms,
                    sample_trace: row.sample_trace,
                });
            }
            Ok(out)
        })
    }

    /// `tick_share_per_min` (OBI-121 S2c §3, OBI-137 S2): does `uid`'s
    /// sliding-window usage already meet or exceed its tier's
    /// `tick_share_per_min`? A uid with no such row (unlimited, or the
    /// row just doesn't mention it) is never breached.
    ///
    /// Bumps `loom_tier_quota_breaches_total` exactly once per
    /// *transition* into breach (OBI-137 S2): a heartbeat/call_out
    /// deferred on every subsequent tick while still over its share does
    /// not bump it again, only the first tick that found it breached
    /// after last being under it.
    fn tick_share_breached(&mut self, uid: crate::security::Sym) -> bool {
        let name = self.registry.syms.name(uid).to_string();
        let defaults =
            crate::quota::Defaults::from_limits(self.limits.max_ticks, self.limits.mem_quota_bytes);
        let Some(limit) = crate::quota::resolve(&self.roles, &name, defaults).tick_share_per_min
        else {
            return false;
        };
        let world_tick = self.scheduler.tick();
        let w = self
            .tick_share
            .entry(uid)
            .or_insert_with(TickShareWindow::fresh);
        let used = w.used(world_tick);
        let is_breached = used >= limit;
        if is_breached {
            if !w.breached {
                w.breached = true;
                let tier = self.roles.tier(&name);
                self.registry
                    .quota_breaches
                    .record(tier, crate::quota::TICK_SHARE_PER_MIN);
            }
        } else {
            w.breached = false;
        }
        is_breached
    }

    fn record_tick_share_usage(&mut self, uid: crate::security::Sym, ticks: u64) {
        if ticks == 0 {
            return;
        }
        let world_tick = self.scheduler.tick();
        let w = self
            .tick_share
            .entry(uid)
            .or_insert_with(TickShareWindow::fresh);
        w.add(world_tick, ticks);
    }

    fn report(host: &mut dyn Host, conn: u64, e: &RtError) {
        host.send(conn, &format!("*Error: {}\n", e.report()));
    }

    /// `self.master`, or the boot-time sentinel if it is not yet set (only
    /// possible while `boot_with_limits` is still loading it).
    fn master_or_sentinel(&self) -> ObjectId {
        self.master.unwrap_or(ObjectId {
            index: u32::MAX,
            generation: 0,
        })
    }

    /// A new connection arrived: master `connect()` returns the player
    /// object, the driver binds the connection to it, then calls `logon()`.
    pub fn connect(&mut self, conn: u64, host: &mut dyn Host) {
        let Some(master) = self.master else {
            host.close(conn);
            return;
        };
        let r = self.exec(
            host,
            master,
            None,
            Some(conn),
            None,
            None,
            None,
            |h| match h.call_apply(master, "connect", Vec::new())? {
                Some(Value::Object(id)) if h.registry.get(id).is_some() => Ok(id),
                Some(v) => Err(RtError::new(format!(
                    "{MASTER_PATH}: connect() must return object, got {}",
                    v.type_name()
                ))),
                None => Err(RtError::new(format!("{MASTER_PATH} has no connect()"))),
            },
        );
        let player = match r {
            Ok(p) => p,
            Err(e) => {
                World::report(host, conn, &e);
                host.close(conn);
                return;
            }
        };
        self.registry.bind(conn, player);
        // OBI-237: session timing for the admin `who` query -- recorded
        // only once the connection is actually bound to a live object
        // (never for a connection master's own `connect()` refused and
        // closed above).
        self.sessions.insert(
            conn,
            ConnSession {
                connected_at: std::time::SystemTime::now(),
                last_activity: std::time::Instant::now(),
            },
        );
        if let Err(e) = self.exec(
            host,
            player,
            Some(player),
            Some(conn),
            None,
            None,
            None,
            |h| h.call_apply(player, "logon", Vec::new()),
        ) {
            World::report(host, conn, &e);
        }
    }

    /// A line of input: `process_input(line)` on the bound object.
    ///
    /// **OBI-36 D-S2.2 actor rule.** This is the *input cut*: the
    /// interactive's own euid, read from the registry right now (never
    /// re-read once the execution is running), becomes `input_actor` for
    /// the whole call -- available to `roles_*` mutation efuns however
    /// deep the call chain goes (e.g. `process_input` -> `/secure/roles`
    /// -> the efun). Every other entry point (`connect`, `disconnect`,
    /// `tick`'s heartbeats/call_outs, `drain_account_results`,
    /// `drain_roles_results`) passes `None`, so a mutation efun called
    /// from any of those is refused, per spec.
    pub fn input(&mut self, conn: u64, line: &str, host: &mut dyn Host) {
        let Some(&ob) = self.registry.conns.get(&conn) else {
            return;
        };
        // OBI-237: any input at all resets the idle clock `who` reports,
        // independent of whether `process_input` itself succeeds below.
        if let Some(session) = self.sessions.get_mut(&conn) {
            session.last_activity = std::time::Instant::now();
        }
        let actor = self.registry.get(ob).map(|o| o.euid);
        let r = self.exec(
            host,
            ob,
            Some(ob),
            Some(conn),
            None,
            actor,
            None,
            |h| match h.call_apply(ob, "process_input", vec![Value::str(line)])? {
                Some(_) => Ok(()),
                None => Err(RtError::new(format!(
                    "{} has no process_input()",
                    h.registry.obj_name(ob)
                ))),
            },
        );
        if let Err(e) = r {
            World::report(host, conn, &e);
        }
    }

    /// Copyover handoff, new-process side (design §7.5 step 3, OBI-221):
    /// call once per connection the driver has just re-adopted (its raw
    /// fd handed over by the supervisor via `loom-supervise`'s
    /// `SCM_RIGHTS` fd-passing and turned into a live `loom-net` session
    /// bound to this same `conn` id) after loading a world from
    /// [`World::load_snapshot`]. Unlike [`World::connect`], the
    /// conn->object binding already exists -- restored verbatim from the
    /// snapshot's connection table (`registry.conns`/`bind_seq`, OBI-173)
    /// -- so this does *not* call master's `connect()`/`logon()` again;
    /// it only gives the bound object a hook to re-bind any local state
    /// (e.g. re-subscribe GMCP, print a reconnect banner) to its new
    /// connection. A missing `reconnect()` apply is not an error: not
    /// every interactive type needs one, and a snapshot taken before this
    /// apply existed in the mudlib must still load and run.
    ///
    /// Does nothing if `conn` is not a connection the loaded snapshot
    /// actually bound (the caller is expected to drive this once per
    /// entry of the connection table it got back from the snapshot, but
    /// an unknown/already-handled id here is a caller bug, not a panic).
    pub fn reconnect(&mut self, conn: u64, host: &mut dyn Host) {
        let Some(&ob) = self.registry.conns.get(&conn) else {
            return;
        };
        // OBI-237: a copyover's new process has no memory of the old
        // process's session timing (it is wall-clock metadata, not part
        // of `Registry::capture`'s snapshot -- see `ConnSession`'s doc
        // comment), so `who` treats every reconnected session as freshly
        // connected at copyover time rather than silently omitting it.
        self.sessions.entry(conn).or_insert_with(|| ConnSession {
            connected_at: std::time::SystemTime::now(),
            last_activity: std::time::Instant::now(),
        });
        let r = self.exec(host, ob, Some(ob), Some(conn), None, None, None, |h| {
            h.call_apply(ob, "reconnect", Vec::new())
        });
        if let Err(e) = r {
            World::report(host, conn, &e);
        }
    }

    /// Run the `reconnect()` apply once on **every** loaded object
    /// (docs/copyover.md, OBI-184 decision): the scheduler is not part of
    /// the snapshot, so a fresh process starts with no pending
    /// `call_out`s and no heartbeat subscribers, and `reconnect()` is
    /// where any object -- interactive or not -- re-arms them.
    ///
    /// Order: first every connection the loaded snapshot bound, in
    /// ascending `conn` id order, through [`World::reconnect`] (so the
    /// body runs with that connection bound and can write to it
    /// immediately); then every other live object, in ascending object
    /// index order, with no connection context. An object destructed by
    /// an earlier `reconnect()` body in the same pass is skipped.
    ///
    /// The copyover driver calls this once, after it has finished
    /// re-adopting every handed-off socket into `loom-net`'s session
    /// table under the same `conn` ids the snapshot recorded, not before
    /// (a `reconnect()` apply that tries to write to its connection
    /// before the session exists has nothing to write to).
    pub fn reconnect_all(&mut self, host: &mut dyn Host) {
        let conns = self.live_connections();
        let bound: std::collections::HashSet<ObjectId> = conns
            .iter()
            .filter_map(|c| self.registry.conns.get(c).copied())
            .collect();
        for conn in conns {
            self.reconnect(conn, host);
        }
        let mut rest: Vec<ObjectId> = self
            .registry
            .ids()
            .into_iter()
            .filter(|ob| !bound.contains(ob))
            .collect();
        rest.sort_unstable_by_key(|ob| ob.index);
        for ob in rest {
            if self.registry.get(ob).is_none() {
                continue;
            }
            // Same as `World::tick`'s heartbeat/call_out errors: there is
            // no connection to report to, and one object's failing hook
            // must not stop the rest of the pass.
            let _ = self.exec(host, ob, None, None, None, None, None, |h| {
                h.call_apply(ob, "reconnect", Vec::new())
            });
        }
    }

    /// The live connection ids a loaded snapshot bound, in ascending
    /// order -- the exact order/identity the copyover driver must adopt
    /// handed-off fds under (see `crate::snapshot`'s connection-table
    /// docs and `loom-supervise::fdpass`'s fixed-order handoff) before
    /// calling [`World::reconnect_all`].
    pub fn live_connections(&self) -> Vec<u64> {
        let mut conns: Vec<u64> = self.registry.conns.keys().copied().collect();
        conns.sort_unstable();
        conns
    }

    /// The connection went away: `autosave()` (spec §8.1, OBI-171: both
    /// an explicit `quit` -- the mudlib's `quit` command calls the
    /// `disconnect()` efun, which closes the connection and lands here
    /// once the transport reports it closed -- and a real net-dead drop
    /// end up on this exact path, so one hook covers both triggers), then
    /// unbind, then `net_dead()` on the object. Each runs as its own
    /// `exec` so an `autosave()` failure can never suppress `net_dead()`.
    pub fn disconnect(&mut self, conn: u64, host: &mut dyn Host) {
        let Some(ob) = self.registry.conns.remove(&conn) else {
            return;
        };
        self.sessions.remove(&conn);
        // Errors have nowhere to go (the connection is gone).
        let _ = self.exec(host, ob, Some(ob), None, None, None, None, |h| {
            h.call_apply(ob, "autosave", Vec::new())
        });
        if let Some(o) = self.registry.get_mut(ob) {
            o.conn = None;
        }
        let _ = self.exec(host, ob, Some(ob), None, None, None, None, |h| {
            h.call_apply(ob, "net_dead", Vec::new())
        });
    }

    /// Advance the world by one world tick (100 ms granularity, OBI-82's
    /// `serve()` timer): `Scheduler::advance()` first (so `call_out` due
    /// times and the world-tick counter used below agree), then every
    /// `heart_beat()`-subscribed object, in subscription order, but only
    /// once every `Limits::heartbeat_interval_ticks` world ticks (default
    /// 20, i.e. every 2 s) -- not every call, unlike OBI-33's original
    /// one-tick-is-one-heartbeat design, superseded by the CTO's OBI-82 N2
    /// decision once `World::tick` started being driven by a real 100 ms
    /// timer instead of standing in for the heartbeat interval itself --
    /// then every `call_out` now due, in scheduling order, then a bounded
    /// batch (`Limits::eager_upgrade_batch`) of any `upgrade_all(path)`
    /// queue (OBI-89, spec §7.2/§7.3 "upgrade_all spread across ticks"),
    /// which runs every world tick and is *not* gated by the heartbeat
    /// interval. Each call runs against a fresh `RegistryHost` with its
    /// own metered tick budget (`Limits::max_ticks`), exactly like
    /// `input`/`connect`, so one slow callback (or one slow migration)
    /// cannot starve another. Errors have nowhere to report to (neither
    /// path has a connection) and are swallowed, matching `disconnect`'s
    /// `net_dead`.
    ///
    /// **OBI-35 D-S1.2 rule 5 / D-S1.7:** a heartbeat is a cut of exactly
    /// `[ob.euid]` (`acting = ob`, no `cut_guard` override — the default
    /// derivation from `acting` already gives that). A call_out's cut is
    /// exactly its captured `guard` (`cut_guard = Some(call.guard)`), and
    /// its quota root uid is `call.quota_uid`, recorded here for tests
    /// (AC 3: "its execution reports quota uid = the apprentice's").
    pub fn tick(&mut self, host: &mut dyn Host) {
        self.poll_recompiles(host);
        self.poll_recompile_sets(host);
        let due = self.scheduler.advance();
        let world_tick = self.scheduler.tick();
        let interval = self.limits.heartbeat_interval_ticks.max(1);
        if world_tick.is_multiple_of(interval) {
            for ob in self.scheduler.heartbeat_targets() {
                if self.registry.get(ob).is_none() {
                    continue; // destructed since it subscribed
                }
                // OBI-121 S2c (CTO review N3): quotas are keyed on the
                // execution's quota uid, which for a driver-started run
                // with no roles/tier snapshot pick is the acting object's
                // own **owner** (not `uid` -- an R1 clone's `uid` stays
                // the program's declared uid, but its billing identity is
                // `owner`; keying this on `uid` would let an R1 clone's
                // heartbeat usage escape back onto the program uid,
                // exactly the evasion R1 was meant to close), so a
                // heartbeat and a call_out from the same object are
                // billed identically regardless of any `seteuid` in
                // between.
                let heartbeat_quota_uid = self
                    .registry
                    .get(ob)
                    .map_or(crate::security::ROOT, |o| o.owner);
                // `tick_share_per_min` (OBI-121 S2c §3): a heartbeat whose
                // owner already met its ticks-per-minute share this
                // window is deferred (skipped this cycle, retried next
                // interval) rather than run -- never lost, per spec.
                if self.tick_share_breached(heartbeat_quota_uid) {
                    continue;
                }
                let _ = self.exec(
                    host,
                    ob,
                    None,
                    None,
                    None,
                    None,
                    Some(heartbeat_quota_uid),
                    |h| h.call_apply(ob, "heartbeat", Vec::new()),
                );
            }
        }
        // Player autosave (spec §8.1, OBI-171): every currently-connected
        // object gets an `autosave()` apply once every
        // `Limits::autosave_interval_ticks` world ticks (default 5 min).
        // Collected into a `Vec` first -- `conns` borrows `self.registry`
        // and `exec` needs `&mut self` -- sorted by connection id for a
        // stable, reproducible order instead of whatever a `HashMap`
        // iteration happens to produce.
        let autosave_interval = self.limits.autosave_interval_ticks.max(1);
        if world_tick.is_multiple_of(autosave_interval) {
            let mut targets: Vec<(u64, ObjectId)> = self
                .registry
                .conns
                .iter()
                .map(|(&c, &ob)| (c, ob))
                .collect();
            targets.sort_by_key(|(c, _)| *c);
            for (_, ob) in targets {
                if self.registry.get(ob).is_none() {
                    continue; // destructed since it connected
                }
                let autosave_quota_uid = self
                    .registry
                    .get(ob)
                    .map_or(crate::security::ROOT, |o| o.owner);
                if self.tick_share_breached(autosave_quota_uid) {
                    continue;
                }
                let _ = self.exec(
                    host,
                    ob,
                    Some(ob),
                    None,
                    None,
                    None,
                    Some(autosave_quota_uid),
                    |h| h.call_apply(ob, "autosave", Vec::new()),
                );
            }
        }
        for call in due {
            if self.registry.get(call.ob).is_none() {
                continue; // destructed in the same tick it was scheduled for
            }
            // `tick_share_per_min` (OBI-137 S2): defer a due call_out the
            // same way -- re-queue it one tick out instead of running it
            // now, rather than dropping it (spec: "deferred", not
            // cancelled), keeping its *original* id and FIFO position
            // (`Scheduler::defer`) rather than scheduling a brand new
            // pending call with a fresh (higher) id -- a call that was
            // deferred must still run before a later call_out that
            // becomes due on the same tick it is retried on.
            if self.tick_share_breached(call.quota_uid) {
                self.scheduler.defer(call);
                continue;
            }
            self.last_call_out_quota_uid = Some(call.quota_uid);
            let guard = call.guard.clone();
            let _ = self.exec(
                host,
                call.ob,
                None,
                None,
                Some(guard),
                None,
                Some(call.quota_uid),
                move |h| h.call_apply(call.ob, &call.func, call.args),
            );
        }
        let batch = self
            .scheduler
            .drain_eager_upgrades(self.limits.eager_upgrade_batch);
        for (ob, path) in batch {
            if self.registry.get(ob).is_none() {
                continue; // destructed since `upgrade_all` queued it
            }
            let Some(current) = self.registry.program(&path) else {
                continue; // path no longer registered at all
            };
            let master = self.master_or_sentinel();
            let _ = self.exec(host, master, None, None, None, None, None, move |h| {
                // Someone may have already lazily upgraded `ob` (an
                // ordinary access) between `upgrade_all` queuing it and
                // this tick draining it -- `RegistryHost::upgrade` itself
                // does not check that, so guard it here.
                // Runs at tick top level, so `ob` can't have a live frame
                // (OBI-89 CTO review: never migrate under a running frame).
                debug_assert!(
                    !h.has_live_frame(ob),
                    "eager upgrade drain must run at top level"
                );
                if let Some(o) = h.registry.get(ob)
                    && !std::rc::Rc::ptr_eq(&o.program, &current)
                    && let Err(w) = h.upgrade(ob, current)
                {
                    h.registry.lazy_upgrade_warnings.push(w);
                }
                Ok(())
            });
        }
        // OBI-85: flush any account_create/account_login result queued
        // since the last tick, so login latency is bounded even on an
        // otherwise idle world.
        self.drain_account_results(host);
        // OBI-36: same reasoning for roles_result -- bounded latency even
        // on an otherwise idle world.
        self.drain_roles_results(host);
        self.poll_canaries();
    }

    /// P2-B7 (OBI-182, spec §7.4): decide every in-flight canary's fate
    /// for this tick -- auto-rollback the instant its new-error budget
    /// (P2-B4) is exceeded, or auto-promote once its window has elapsed
    /// without that happening. Runs every tick (cheap: one `HashMap`
    /// lookup into the error inbox per active canary, and there is never
    /// more than a handful of these live at once) rather than on its own
    /// cadence, so a tight `max_new_errors: 0` budget rolls back within
    /// one tick of the first new error, not up to a whole heartbeat
    /// interval later.
    fn poll_canaries(&mut self) {
        if self.registry.canaries.is_empty() {
            return;
        }
        let now_tick = self.scheduler.tick();
        // Collect decisions before mutating `self.registry.canaries`
        // (promote/rollback both remove the entry): iterating and
        // mutating the same map at once would either not compile (an
        // active borrow) or skip entries after a removal, depending on
        // iteration order.
        enum Decision {
            Promote,
            Rollback,
        }
        let mut decisions: Vec<(String, Decision)> = Vec::new();
        for (path, canary) in self.registry.canaries.iter() {
            let new_errors = self
                .errors
                .count_for_program(path)
                .saturating_sub(canary.errors_at_start);
            if new_errors > canary.max_new_errors {
                decisions.push((path.clone(), Decision::Rollback));
            } else if now_tick >= canary.started_tick + canary.window_ticks {
                decisions.push((path.clone(), Decision::Promote));
            }
        }
        for (path, decision) in decisions {
            match decision {
                Decision::Promote => {
                    self.registry.promote_canary(&path);
                    metrics::counter!("loom_canary_promoted_total", "program" => path).increment(1);
                }
                Decision::Rollback => {
                    self.registry.rollback_canary(&path);
                    metrics::counter!("loom_canary_rolled_back_total", "program" => path)
                        .increment(1);
                }
            }
        }
    }

    /// The current world tick (`Scheduler::advance`'s counter; advanced by
    /// `World::tick`), for tests/introspection.
    pub fn world_tick(&self) -> u64 {
        self.scheduler.tick()
    }

    /// Destroy `ob`: move its inventory up into its own environment (or
    /// drop it loose if it had none), unlink it from its environment's
    /// inventory and its name/connection bindings, close its connection if
    /// it had one (OBI-85), and cancel every pending `call_out`/heartbeat
    /// subscription for it (OBI-33) before freeing its slot. A no-op if
    /// `ob` is already gone.
    pub fn destruct(&mut self, ob: ObjectId, host: &mut dyn Host) {
        if let Some(conn) = self.registry.destruct(ob, &mut self.scheduler) {
            host.close(conn);
        }
    }

    /// The retained window of privileged decisions (OBI-35): every P1+
    /// efun's `valid_efun` gate plus every path/bind/seteuid decision,
    /// allowed or denied, oldest first.
    pub fn audit_log(&self) -> &[AuditEntry] {
        self.security.log()
    }

    /// Every audit decision recorded since `cursor`, resolved to owned
    /// strings for a driver-side sink (`loom-cli`'s Postgres `audit_log`
    /// writer, OBI-36 design §5/D-S2.5, wired by OBI-123): P2+
    /// `valid_efun`/`valid_read`/`valid_write`/... decisions (allowed and
    /// denied), `unguarded`, every `roles_*` mutation gate, and (once S2c
    /// lands) quota breaches all flow through the same
    /// `SecurityState::push`, so this one drain covers all of them.
    /// `cursor` is [`SecurityState::audit_total`] as of the *last* call (0
    /// for the very first); the returned `u64` is this call's total, to
    /// pass in next time. The audit ring is bounded
    /// ([`crate::security::AUDIT_LOG_CAPACITY`]): if the sink falls behind
    /// by more than that many entries between calls, the oldest
    /// still-retained entries are returned rather than erroring or
    /// blocking the world thread -- a gap in the Postgres sink is
    /// preferable to either.
    pub fn drain_audit_since(&self, cursor: u64) -> (Vec<AuditRow>, u64) {
        let log = self.security.log();
        let total = self.security.audit_total();
        let start = total.saturating_sub(log.len() as u64);
        let skip = cursor.saturating_sub(start).min(log.len() as u64) as usize;
        let rows = log[skip..].iter().map(|e| self.audit_row(e)).collect();
        (rows, total)
    }

    fn audit_row(&self, e: &AuditEntry) -> AuditRow {
        AuditRow {
            kind: e.efun,
            caller: self.object_name(e.caller).map(str::to_string),
            effective_principal: e
                .guard
                .principals()
                .last()
                .map(|p| self.principal_name(p.euid).to_string()),
            apply: e.apply,
            class: e.privilege as i16,
            argument: e.arg.to_string(),
            guard_set: e
                .guard
                .euids()
                .map(|s| self.principal_name(s).to_string())
                .collect(),
            allowed: e.allowed,
            detail: e.denied_by.map(|s| self.principal_name(s).to_string()),
            at_unix_ms: e.at_unix_ms,
        }
    }

    /// Stack-check state (OBI-35): cache hit/miss/denial counters, the
    /// policy epoch, the audit window.
    pub fn security(&self) -> &SecurityState {
        &self.security
    }

    /// The uid/euid name behind a [`crate::security::Sym`] (audit entries).
    pub fn principal_name(&self, s: crate::security::Sym) -> &str {
        self.registry.syms.name(s)
    }

    /// Drop every cached privilege decision (OBI-35 D-S1.8), e.g. after a
    /// roles snapshot swap.
    pub fn flush_security_cache(&mut self) {
        self.security.bump_epoch();
    }

    /// Pending `call_out` count (tests/introspection).
    pub fn pending_call_outs(&self) -> usize {
        self.scheduler.pending_count()
    }

    /// Objects still queued by `upgrade_all(path)` waiting for a future
    /// tick's batch (OBI-89, tests/introspection).
    pub fn eager_upgrade_queue_len(&self) -> usize {
        self.scheduler.eager_upgrade_queue_len()
    }

    /// Whether `path` has a canary in flight right now (P2-B7, OBI-182,
    /// tests/introspection) -- cleared the instant `World::tick`
    /// auto-promotes or auto-rolls-back.
    pub fn canary_active(&self, path: &str) -> bool {
        self.registry.canaries.contains_key(path)
    }

    /// Drain every warning recorded by a *lazy* per-instance upgrade since
    /// the last call (OBI-89: an access-triggered migration or its
    /// `upgrade()` hook that failed and rolled back that one object,
    /// spec §7.2 step 6.4 — not fatal, so this is the only place it
    /// surfaces, mirroring `compile_object`'s own `Vec<String>` return for
    /// the eager-at-install-time case).
    pub fn take_lazy_upgrade_warnings(&mut self) -> Vec<crate::bcvm::UpgradeWarning> {
        std::mem::take(&mut self.registry.lazy_upgrade_warnings)
    }

    /// The `quota_uid` (OBI-35 D-S1.6, AC 3) the most recently executed
    /// call_out charged against, resolved to its uid string. `None` before
    /// any call_out has run.
    ///
    /// **Test-only introspection.** S2 (OBI-36) replaces this single-slot
    /// snapshot with real per-uid tick/memory quota accounting; this stays
    /// only as long as nothing but tests reads it.
    #[doc(hidden)]
    pub fn last_call_out_quota_uid(&self) -> Option<&str> {
        self.last_call_out_quota_uid
            .map(|s| self.registry.syms.name(s))
    }

    // ---- introspection / tooling (tests, `loom` admin commands) -----------

    /// Recompile a program as `compile_object` would. `Ok(warnings)` on
    /// success — empty unless some existing instance's migration failed
    /// and was rolled back (spec r5 amendment §7.2 step 6.4: per-object,
    /// not fatal) — `Err(diagnostics)` only for a genuine compile-stage
    /// failure (nothing installed at all).
    pub fn compile_object(
        &mut self,
        path: &str,
        host: &mut dyn Host,
    ) -> Result<Vec<String>, String> {
        let master = self.master_or_sentinel();
        self.exec(host, master, None, None, None, None, None, |h| {
            Ok(h.recompile(path))
        })
        .unwrap_or_else(|e| Err(e.report()))
        .map(|warnings| {
            warnings
                .into_iter()
                .map(|w| format!("object {:?} on {}: {}", w.object, w.program, w.message))
                .collect()
        })
    }

    /// `compile_object`/`update` (spec §7.2), off the world thread
    /// (OBI-90/D-P1.5): kicks off parse/check/codegen/verify on a
    /// background OS thread and returns immediately — nothing about this
    /// call touches `self.registry`, so `tick`/`input`/`connect` in the
    /// meantime are unaffected. `World::tick` (via `poll_recompiles`)
    /// installs the result — registry mutation + per-object migration —
    /// on the world thread as soon as the background thread finishes;
    /// poll [`Self::take_finished_recompiles`] for the outcome, or
    /// [`Self::recompile_pending`] to check without draining it.
    ///
    /// `compile_object` above is unchanged and still fully synchronous
    /// (existing callers/tests keep working); this is the additive path a
    /// driver that wants non-blocking `update` should move to.
    pub fn begin_recompile(&mut self, path: &str) -> RecompileToken {
        self.begin_recompile_after(path, std::time::Duration::ZERO)
    }

    /// [`Self::begin_recompile`], but the background thread sleeps for
    /// `delay` before it starts compiling — stands in for a large/slow
    /// compile in tests without needing an actually huge dependent tree
    /// (spec r5 amendment's own suggested alternative).
    #[doc(hidden)]
    pub fn begin_recompile_after(
        &mut self,
        path: &str,
        delay: std::time::Duration,
    ) -> RecompileToken {
        let token = RecompileToken(self.next_recompile_token);
        self.next_recompile_token += 1;
        let job = self
            .compiler
            .begin_recompile_after(&self.root, &self.registry, path, delay);
        self.pending_recompiles.push((token, job));
        token
    }

    /// Non-blocking: install every background compile that has finished
    /// since the last call. `World::tick` calls this automatically; it is
    /// also exposed directly for a caller that drives `begin_recompile`
    /// without ticking (e.g. a test, or a `loom` admin command run between
    /// ticks).
    pub fn poll_recompiles(&mut self, host: &mut dyn Host) {
        if self.pending_recompiles.is_empty() {
            return;
        }
        let jobs = std::mem::take(&mut self.pending_recompiles);
        let mut still_pending = Vec::new();
        for (token, job) in jobs {
            match job.poll() {
                None => still_pending.push((token, job)),
                Some(outcome) => {
                    let root_path = job.path().to_string();
                    let begin_snapshot = job.begin_snapshot().clone();
                    let master = self.master_or_sentinel();
                    let result = self
                        .exec(host, master, None, None, None, None, None, |h| {
                            Ok(h.finish_recompile(&root_path, &begin_snapshot, outcome))
                        })
                        .unwrap_or_else(|e| Err(e.report()));
                    self.finished_recompiles.push((token, result));
                }
            }
        }
        self.pending_recompiles = still_pending;
    }

    /// Every background compile that has finished (successfully installed,
    /// or failed) since the last call, oldest first. Draining is
    /// destructive: call it once per token you care about.
    pub fn take_finished_recompiles(&mut self) -> Vec<(RecompileToken, Result<(), String>)> {
        std::mem::take(&mut self.finished_recompiles)
    }

    /// True while `token`'s background compile is still running (not yet
    /// picked up by `poll_recompiles`/`tick`).
    pub fn recompile_pending(&self, token: RecompileToken) -> bool {
        self.pending_recompiles.iter().any(|(t, _)| *t == token)
    }

    /// Load (compile + create) `path` as the driver would for a preload.
    pub fn load_object(&mut self, path: &str, host: &mut dyn Host) -> Result<ObjectId, String> {
        let master = self.master_or_sentinel();
        self.exec(host, master, None, None, None, None, None, |h| {
            h.load_object(path)
        })
        .map_err(|e| e.report())
    }

    /// Call a function on an object as the driver (visibility not enforced).
    pub fn call(
        &mut self,
        ob: ObjectId,
        func: &str,
        args: Vec<Value>,
        host: &mut dyn Host,
    ) -> Result<Value, String> {
        let master = self.master_or_sentinel();
        self.exec(host, master, None, None, None, None, None, |h| {
            h.call_apply(ob, func, args)?
                .ok_or_else(|| RtError::new(format!("no function `{func}`")))
        })
        .map_err(|e| e.report())
    }

    /// Spec M-FS-1 (OBI-180/OBI-179 threat model): run `efun` (`read_file`,
    /// `write_file`, `compile_object`, and nothing else so far) as a
    /// world-thread execution whose *entire* guard set is exactly `{uid}`
    /// -- no inherited call stack, no `this_player`/connection context.
    /// This is the seam a driver-side caller (`/api/v1/files/*`, OBI-180's
    /// HTTP handlers; the `/lsp` route's `ReadAuthorizer`) goes through
    /// instead of running LPC bytecode: `h.call_efun` is the exact same
    /// dispatch a running program's `CallEfun` instruction would reach, so
    /// `security::normalize_file_path` -> `authorize()`'s `valid_*` apply
    /// on the real master -> `fileio` all run unchanged (D-TM5: this is
    /// deliberately *not* a second, HTTP-side permission check mirroring
    /// the master -- it *is* the master's own check, just entered by the
    /// driver). Quotas (`ticks_quota_uid: Some(sym)`) and the audit log
    /// (`exec`'s own `note_error`, plus `authorize`'s `SecurityState::
    /// record`) are the same unmodified paths every other caller gets.
    ///
    /// Refuses a reserved principal (`root`, `mudlib`, `*:*`) outright
    /// (D-S3.1) -- there is no HTTP-reachable way to mint one of those
    /// guards, unlike `seteuid`, which at least requires `/secure` code.
    ///
    /// `efun` is restricted to the small allowlist this driver entry
    /// point is meant for (OBI-180 review, non-blocking item 1): a public
    /// `World` method that ran *any* named efun on the master's behalf
    /// would be a general driver-side efun runner, not the narrow
    /// file-op seam this is documented as.
    pub fn call_file_efun(
        &mut self,
        uid: &str,
        efun: &str,
        args: Vec<Value>,
        host: &mut dyn Host,
    ) -> Result<Value, String> {
        if crate::security::is_reserved_principal(uid) {
            return Err(format!("`{uid}` is a reserved principal"));
        }
        if !matches!(efun, "read_file" | "write_file" | "compile_object") {
            return Err(format!("`{efun}` is not a file-op efun"));
        }
        let sym = self.registry.syms.intern(uid);
        let guard = crate::security::GuardSet::empty().with(crate::security::Principal {
            uid: sym,
            euid: sym,
        });
        let acting = self.master_or_sentinel();
        self.exec(
            host,
            acting,
            None,
            None,
            Some(guard),
            None,
            Some(sym),
            |h| h.call_efun(efun, args),
        )
        .map_err(|e| e.report())
    }

    /// Atomic compare-and-swap `write_file` (OBI-180 M-FS-6, CTO review
    /// must-fix 1): reads the file, checks `precondition` against its
    /// current contents, and -- only if it holds -- writes `new_text`,
    /// all inside **one** [`Self::exec`] call. The world thread processes
    /// one `exec` to completion before looking at anything else (another
    /// HTTP request, a scheduled `call_out`, LPC code calling `write_file`
    /// directly), so nothing can land between the read and the write the
    /// way it could across two separate [`Self::call_file_efun`] calls
    /// (the lost-update window the CTO review flagged) -- this replaces
    /// that two-request shape for `PUT`, not just adds to it.
    ///
    /// A failed read (refused by `valid_read`, or an I/O error) is
    /// propagated as `Err` without ever reaching `write_file` -- never a
    /// fail-open fall-through to an unconditional write (review must-fix
    /// 2).
    pub fn call_file_write_if_match(
        &mut self,
        uid: &str,
        path: &str,
        precondition: FileMatchPrecondition,
        new_text: &str,
        host: &mut dyn Host,
    ) -> Result<FileCasOutcome, String> {
        if crate::security::is_reserved_principal(uid) {
            return Err(format!("`{uid}` is a reserved principal"));
        }
        let sym = self.registry.syms.intern(uid);
        let guard = crate::security::GuardSet::empty().with(crate::security::Principal {
            uid: sym,
            euid: sym,
        });
        let acting = self.master_or_sentinel();
        let path_for_read = Value::str(path);
        let path_for_write = Value::str(path);
        let new_text = new_text.to_string();
        self.exec(
            host,
            acting,
            None,
            None,
            Some(guard),
            None,
            Some(sym),
            move |h| {
                let current = h.call_efun("read_file", vec![path_for_read])?;
                let existing: Option<String> = match current {
                    Value::Null => None,
                    other => other.as_str().map(|s| s.to_string()),
                };
                let satisfied = match &precondition {
                    FileMatchPrecondition::IfNoneMatchStar => existing.is_none(),
                    FileMatchPrecondition::IfMatch(expected) => existing
                        .as_deref()
                        .map(|contents| file_etag_matches(contents, expected.trim_matches('"')))
                        .unwrap_or(false),
                };
                if !satisfied {
                    return Ok(FileCasOutcome::PreconditionFailed);
                }
                match h.call_efun("write_file", vec![path_for_write, Value::str(&new_text)])? {
                    Value::Bool(true) => Ok(FileCasOutcome::Written),
                    Value::Bool(false) => Ok(FileCasOutcome::QuotaExceeded),
                    other => Err(RtError::new(format!(
                        "write_file returned an unexpected value: {other:?}"
                    ))),
                }
            },
        )
        .map_err(|e| e.report())
    }

    /// `GET /api/v1/files/list?path=...` (OBI-180 M-FS-3): immediate
    /// entries of a mudlib-absolute directory, filtered by `valid_read`.
    /// `None` if the directory itself doesn't authorize for `uid` or
    /// doesn't exist (M-FS-3: a listing you can't read looks exactly
    /// like one that doesn't exist, same as `read_file`'s `Null`) --
    /// otherwise each entry's bare name is *additionally* checked
    /// against `valid_read` on its own full path and dropped if refused,
    /// the same per-entry filtering `World::admin_list_objects` already
    /// does for live objects (`RegistryHost::admin_valid_read`'s doc
    /// comment).
    ///
    /// Deliberately goes through `admin_valid_read` rather than a new
    /// LPC-visible `get_dir` efun: no new efun means no new
    /// language-surface addition (`EFUNS` table, `driver_efun` dispatch,
    /// `valid_efun` privilege class) for a feature that is really just a
    /// driver-side read, exactly the same reasoning `admin_list_objects`/
    /// `admin_object_vars` already apply.
    pub fn list_dir(
        &mut self,
        uid: &str,
        path: &str,
        host: &mut dyn Host,
    ) -> Result<Option<Vec<String>>, String> {
        if crate::security::is_reserved_principal(uid) {
            return Err(format!("`{uid}` is a reserved principal"));
        }
        let path = crate::security::normalize_file_path(path)?;
        let sym = self.registry.syms.intern(uid);
        let guard = crate::security::GuardSet::empty().with(crate::security::Principal {
            uid: sym,
            euid: sym,
        });
        let acting = self.master_or_sentinel();
        let root = self.root().to_path_buf();
        self.exec(
            host,
            acting,
            None,
            None,
            Some(guard),
            None,
            Some(sym),
            move |h| {
                if !h.admin_valid_read("get_dir", &path) {
                    return Ok(None);
                }
                match crate::fileio::list_dir(&root, &path) {
                    Ok(Some(entries)) => {
                        let trimmed = path.trim_end_matches('/');
                        let filtered: Vec<String> = entries
                            .into_iter()
                            .filter(|name| {
                                let child = format!("{trimmed}/{name}");
                                h.admin_valid_read("get_dir", &child)
                            })
                            .collect();
                        Ok(Some(filtered))
                    }
                    Ok(None) => Ok(None),
                    Err(e) => Err(RtError::new(e)),
                }
            },
        )
        .map_err(|e| e.report())
    }

    pub fn find_object(&self, name: &str) -> Option<ObjectId> {
        self.registry
            .names
            .get(name)
            .copied()
            .filter(|id| self.registry.get(*id).is_some())
    }

    /// The object bound to connection `conn`.
    pub fn connection_object(&self, conn: u64) -> Option<ObjectId> {
        self.registry.conns.get(&conn).copied()
    }

    pub fn object_name(&self, ob: ObjectId) -> Option<&str> {
        self.registry.get(ob).map(|o| o.name.as_str())
    }

    pub fn environment(&self, ob: ObjectId) -> Option<ObjectId> {
        self.registry.get(ob).and_then(|o| o.env)
    }

    /// `ob`'s current inventory (tests/introspection; mirrors
    /// `environment`, its inverse).
    pub fn inventory(&self, ob: ObjectId) -> Vec<ObjectId> {
        self.registry
            .get(ob)
            .map(|o| o.inventory.clone())
            .unwrap_or_default()
    }

    /// Current version of a registered program.
    pub fn program_version(&self, path: &str) -> Option<u32> {
        self.registry.program(path).map(|p| p.version)
    }

    /// Version of the program `ob` currently runs.
    pub fn object_program_version(&self, ob: ObjectId) -> Option<(String, u32)> {
        self.registry
            .get(ob)
            .map(|o| (o.program.path.to_string(), o.program.version))
    }

    /// Read variable `name` of `ob` (searching all declaring programs,
    /// most-derived first).
    pub fn var(&self, ob: ObjectId, name: &str) -> Option<Value> {
        let o = self.registry.get(ob)?;
        o.program.chain().into_iter().rev().find_map(|p| {
            o.vars
                .get(&(p.path.clone(), std::rc::Rc::from(name)))
                .cloned()
        })
    }

    /// `loom_cow_copies_total{program}` (spec r5 §5.2.1, D24): how many
    /// times a write through `Value::array_mut`/`map_mut` has had to clone
    /// a shared buffer while executing `program`'s bytecode. See
    /// `bcvm::registry::CowMetrics` for where/how this is collected and why
    /// there is no exporter wired up yet.
    pub fn cow_copies_total(&self, program: &str) -> u64 {
        self.registry.cow_metrics.get(program)
    }

    /// `loom_mudlib_sync_total{result=ok|compile_failed}` (D-B3.14): see
    /// `bcvm::registry::SyncMetrics` for where/how this is collected and
    /// why there is no exporter wired up yet (same posture as
    /// `cow_copies_total`).
    pub fn mudlib_sync_total(&self, result: &str) -> u64 {
        self.registry.sync_metrics.get(result)
    }

    /// spec §7.2 D-B3.14 (P2-B3.1): recompile the changed, already-loaded
    /// programs in `change_set` (plus their reverse-inherit dependents) as
    /// one dependency-ordered, all-or-nothing batch. The world-thread
    /// entry point B3.2's `GitWorker` calls after a merge to `main` is
    /// pulled onto staging and `live` is fast-forwarded -- see
    /// `bcvm::registry::RegistryHost::recompile_set` for the install-stage
    /// semantics (master-first cache flush, all-or-nothing) and
    /// `bcvm::registry::Compiler::recompile_set` for the compile stage.
    ///
    /// **OBI-207 (P2-B3.1b):** the compile stage (parse/check/codegen/
    /// verify of the whole batch) now runs off the world thread -- see
    /// [`Self::begin_recompile_set`]/[`Self::poll_recompile_sets`] for the
    /// non-blocking entry point `GitWorker` should actually use. This
    /// synchronous wrapper stays source-compatible with every existing
    /// caller/test: it kicks off the same background compile and polls (1 ms sleep)
    /// it to completion (no `tick`, no heartbeat/call_out side effect --
    /// just the one background OS thread doing the compile work, same as
    /// `begin_recompile_set` would, just waited out here instead of
    /// returned as a token).
    pub fn recompile_set(
        &mut self,
        change_set: &crate::bcvm::ChangeSet,
        host: &mut dyn Host,
    ) -> crate::bcvm::RecompileReport {
        let token = self.begin_recompile_set(change_set);
        loop {
            self.poll_recompile_sets(host);
            if let Some(pos) = self
                .finished_recompile_sets
                .iter()
                .position(|(t, _)| *t == token)
            {
                return self.finished_recompile_sets.remove(pos).1;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    /// `recompile_set`'s compile stage, off the world thread (D-B3.14,
    /// OBI-207 P2-B3.1b) -- the multi-root generalisation of
    /// [`Self::begin_recompile`]: returns immediately, nothing about this
    /// call touches `self.registry`, so `tick`/`input`/`connect` in the
    /// meantime are unaffected. `World::tick` (via [`Self::
    /// poll_recompile_sets`]) installs the result -- registry mutation +
    /// per-object migration, all-or-nothing, including the drift check --
    /// on the world thread as soon as the background thread finishes; poll
    /// [`Self::take_finished_recompile_sets`] for the
    /// [`crate::bcvm::RecompileReport`], or [`Self::recompile_set_pending`]
    /// to check without draining it.
    pub fn begin_recompile_set(
        &mut self,
        change_set: &crate::bcvm::ChangeSet,
    ) -> RecompileSetToken {
        self.begin_recompile_set_after(change_set, std::time::Duration::ZERO)
    }

    /// [`Self::begin_recompile_set`], but the background thread sleeps for
    /// `delay` before it starts compiling -- test/tooling support, same as
    /// [`Self::begin_recompile_after`].
    #[doc(hidden)]
    pub fn begin_recompile_set_after(
        &mut self,
        change_set: &crate::bcvm::ChangeSet,
        delay: std::time::Duration,
    ) -> RecompileSetToken {
        let token = RecompileSetToken(self.next_recompile_set_token);
        self.next_recompile_set_token += 1;
        let job = self.compiler.begin_recompile_set_after(
            &self.root,
            &self.registry,
            &change_set.changed,
            &change_set.deleted,
            delay,
        );
        self.pending_recompile_sets.push((token, job));
        token
    }

    /// Non-blocking: install every background batch compile that has
    /// finished since the last call. `World::tick` calls this
    /// automatically; also exposed directly, same as [`Self::
    /// poll_recompiles`].
    pub fn poll_recompile_sets(&mut self, host: &mut dyn Host) {
        if self.pending_recompile_sets.is_empty() {
            return;
        }
        let jobs = std::mem::take(&mut self.pending_recompile_sets);
        let mut still_pending = Vec::new();
        for (token, job) in jobs {
            match job.poll() {
                None => still_pending.push((token, job)),
                Some(outcome) => {
                    let changed = job.changed().to_vec();
                    let deleted = job.deleted().to_vec();
                    let begin_snapshot = job.begin_snapshot().clone();
                    let master = self.master_or_sentinel();
                    let report = self
                        .exec(host, master, None, None, None, None, None, |h| {
                            Ok(
                                h.finish_recompile_set(
                                    &changed,
                                    &deleted,
                                    &begin_snapshot,
                                    outcome,
                                ),
                            )
                        })
                        .unwrap_or_else(|e| crate::bcvm::RecompileReport {
                            recompiled: Vec::new(),
                            upgraded_instances: 0,
                            skipped_unloaded: Vec::new(),
                            deleted_loaded: Vec::new(),
                            failures: vec![("<world>".to_string(), e.report())],
                        });
                    self.finished_recompile_sets.push((token, report));
                }
            }
        }
        self.pending_recompile_sets = still_pending;
    }

    /// Every background batch compile that has finished (successfully
    /// installed, or reported failures) since the last call, oldest first.
    /// Draining is destructive: call it once per token you care about.
    pub fn take_finished_recompile_sets(
        &mut self,
    ) -> Vec<(RecompileSetToken, crate::bcvm::RecompileReport)> {
        std::mem::take(&mut self.finished_recompile_sets)
    }

    /// True while `token`'s background batch compile is still running (not
    /// yet picked up by `poll_recompile_sets`/`tick`).
    pub fn recompile_set_pending(&self, token: RecompileSetToken) -> bool {
        self.pending_recompile_sets.iter().any(|(t, _)| *t == token)
    }

    /// `loom_tier_quota_breaches_total{tier,quota}` (OBI-121 S2c): see
    /// `crate::quota::QuotaBreachMetrics` for where/how this is collected
    /// and why there is no exporter wired up yet (same reasoning as
    /// `cow_copies_total`). `quota` is one of the `crate::quota` key
    /// constants (`max_ticks_exec`, `max_objects`, ...).
    pub fn quota_breach_count(&self, tier: u32, quota: &str) -> u64 {
        self.registry.quota_breaches.get(tier, quota)
    }

    /// `profile <program>` (spec Phase 2 B5, OBI-170): open a sampling
    /// window on `program` (normalized, same rule as `compile_object`'s
    /// path argument) -- mirrors the `profile_start` efun, for a
    /// host-side (test/admin-command) caller that doesn't want to go
    /// through a Weft call to use it.
    ///
    /// `owner` is this caller's principal (CTO review, OBI-170 PR #67
    /// should-fix 4 / OBI-232): if a window is already open under a
    /// *different* owner, this fails instead of silently discarding it
    /// (no more "last write wins") -- the caller must have that owner
    /// call `profile_stop` first, or call `profile_stop` here with
    /// `force: true` themselves (a host-side caller is trusted to decide
    /// that for itself; there is no master/efun-privilege gate at this
    /// level, unlike the `profile_stop` efun's P3 check).
    ///
    /// Exception (OBI-238, follow-up to should-fix 5): a window that has
    /// already hit its own auto-expiry cap is replaced outright, even by
    /// a different owner, no `profile_stop`/`force` required -- an
    /// expired window is not sampling anything anymore (`wants` already
    /// answers `false` for it), so refusing to replace it would just let
    /// a builder who forgot to close their window block everyone else's
    /// profiling indefinitely.
    pub fn profile_start(&mut self, program: &str, owner: &str) -> Result<(), String> {
        let path = loom_compiler::mudlib::normalize_path(program)?;
        if let Some(existing) = &self.registry.profiler
            && existing.owner() != owner
            && !existing.is_expired()
        {
            return Err(format!(
                "profile: a window on {:?} is already open, owned by {} -- profile_stop() it \
                 first (or force-close it)",
                existing.program(),
                existing.owner()
            ));
        }
        self.registry.profiler = Some(crate::profiler::Profiler::new(path, owner.to_string()));
        Ok(())
    }

    /// Close the window `profile_start` opened and render its report
    /// (see `crate::profiler::ProfileReport::render`) -- mirrors the
    /// `profile_stop` efun. `None` if no window was open.
    ///
    /// Refuses to close a window owned by a different `caller` unless
    /// `force` is set (should-fix 4, OBI-232) -- the caller decides for
    /// itself whether it is entitled to force (this host-side entry
    /// point has no master/privilege model of its own to check against).
    pub fn profile_stop(&mut self, caller: &str, force: bool) -> Option<String> {
        let owner = self.registry.profiler.as_ref()?.owner().to_string();
        if owner != caller && !force {
            return Some(format!(
                "profile_stop(): this window is owned by {owner}, not {caller} -- pass \
                 force: true to close it anyway"
            ));
        }
        self.registry.profiler.take().map(|p| p.report().render())
    }

    /// The program path a `profile` window is currently sampling, if one
    /// is open.
    pub fn profiling_program(&self) -> Option<&str> {
        self.registry.profiler.as_ref().map(|p| p.program())
    }

    /// **Test-only.** Force the currently-open `profile` window straight
    /// to expired -- see `Profiler::force_expire_for_test`'s doc for why
    /// (OBI-238's integration test needs to exercise auto-expiry without
    /// actually waiting `MAX_WINDOW` or making `MAX_CALLS` real calls).
    /// A no-op if no window is open.
    #[doc(hidden)]
    pub fn force_expire_profiler_for_test(&mut self) {
        if let Some(p) = self.registry.profiler.as_mut() {
            p.force_expire_for_test();
        }
    }

    /// `ob`'s owner uid (OBI-121 S2c: immutable, set at creation --
    /// `BcObject::uid`), resolved to its name.
    /// `ob`'s owner uid (OBI-121 S2c: immutable, set at creation --
    /// `BcObject::owner`), resolved to its name.
    pub fn owner_uid(&self, ob: ObjectId) -> Option<&str> {
        self.registry
            .get(ob)
            .map(|o| self.registry.syms.name(o.owner))
    }

    /// `ob`'s current euid, resolved to its name (tests/introspection;
    /// `getuid`/`geteuid` are the Weft-level equivalent).
    pub fn euid_name(&self, ob: ObjectId) -> Option<&str> {
        self.registry
            .get(ob)
            .map(|o| self.registry.syms.name(o.euid))
    }

    /// Live object count currently charged to `uid` (OBI-121 S2c
    /// `max_objects`, tests/introspection).
    pub fn object_count_for_uid(&mut self, uid: &str) -> u64 {
        let sym = self.registry.syms.intern(uid);
        self.registry.object_count_for_uid(sym)
    }

    /// `program_flags(path)`'s cached result (OBI-121 S2c §7,
    /// tests/introspection): `"confined"`/`"live"`, matching the master
    /// apply's own vocabulary rather than exposing `bcvm::registry::
    /// ProgramFlags` (an implementation detail) in the public API.
    /// `program_flags(path)`'s cached result (OBI-121 S2c §7,
    /// tests/introspection): `"confined"`/`"live"`/`"none"`, matching the
    /// master apply's own vocabulary rather than exposing `bcvm::registry
    /// ::ProgramFlags` (an implementation detail) in the public API.
    pub fn program_flags(&self, path: &str) -> &'static str {
        self.registry.program_flags(path).as_str()
    }

    /// Current (deep, transitively-accounted, see `bcvm::heap::cost`)
    /// memory of `ob`'s program variables (spec r5 §5.2.1 "memory quotas
    /// with per-object accounting").
    pub fn object_mem_bytes(&self, ob: ObjectId) -> Option<u64> {
        self.registry.get(ob).map(|o| o.mem_bytes)
    }

    /// Render a value as Weft interpolation would.
    pub fn display(&self, v: &Value) -> String {
        crate::bcvm::heap::display(v, &|id| {
            self.object_name(id)
                .map_or_else(|| "<destructed>".to_string(), str::to_string)
        })
    }

    pub fn object_count(&self) -> usize {
        self.registry.ids().len()
    }
}

#[cfg(test)]
mod tick_share_window_tests {
    use super::*;

    // -- OBI-137 S2: a true sliding window, not a fixed bucket ------------

    #[test]
    fn a_burst_straddling_what_would_be_a_fixed_bucket_reset_is_still_capped() {
        let mut w = TickShareWindow::fresh();
        // A fixed 60-second bucket resets wholesale at tick 600 (bucket
        // 60): charge right up to that boundary, then straddle it.
        w.add(590, 5); // just before the old fixed-bucket reset point
        w.add(605, 5); // just after it
        // A fixed-bucket implementation would show `used(605) == 5` here
        // (the bucket wholesale-reset at 600, forgetting the tick-590
        // usage) -- letting a uid burst 2x its share right at the
        // boundary. The sliding window must still see both charges as
        // long as they are within 60 buckets (600 ticks) of each other.
        assert_eq!(
            w.used(605),
            10,
            "the sliding window must still see both bursts"
        );
    }

    #[test]
    fn usage_older_than_the_window_falls_off() {
        let mut w = TickShareWindow::fresh();
        w.add(0, 7);
        assert_eq!(w.used(0), 7);
        // Still inside the 60-bucket window (599 - 0 < 600 ticks).
        assert_eq!(w.used(599), 7);
        // Exactly 600 ticks later (60 buckets on): the tick-0 usage has
        // rolled all the way off the ring.
        assert_eq!(w.used(600), 0);
    }

    #[test]
    fn usage_accumulates_within_the_same_bucket() {
        let mut w = TickShareWindow::fresh();
        w.add(3, 2);
        w.add(4, 3); // ticks 3 and 4 are in the same 10-tick bucket
        assert_eq!(w.used(4), 5);
    }

    #[test]
    fn a_reused_ring_slot_does_not_see_a_much_older_buckets_leftover_count() {
        let mut w = TickShareWindow::fresh();
        w.add(0, 9); // bucket 0
        w.add(6000, 4); // bucket 600, same ring slot as bucket 0 (600 % 60 == 0)
        assert_eq!(
            w.used(6000),
            4,
            "a slot's stale usage from 60 buckets ago must not leak into a reused slot"
        );
    }
}

/// OBI-279 (CTO review of PR #102, must-fix 1): `RegistryHost::
/// admin_valid_read`'s per-euid decision loop must behave exactly like
/// `authorize`'s own (both now share `RegistryHost::decide`) -- a
/// src-level unit test, not a `tests/obi_279_admin_query_errors.rs`
/// integration test, because exercising a genuinely multi-principal cut
/// guard means calling `World::exec`/`RegistryHost::admin_valid_read`
/// directly (both `pub(crate)`/private, not reachable from outside this
/// crate) -- `World`'s own public admin-query methods only ever build a
/// single-principal guard (one HTTP-authenticated staff euid), so this
/// is the only way to prove the shared loop's multi-euid behavior at
/// all.
#[cfg(test)]
mod admin_query_tests {
    use super::*;
    use crate::security::{GuardSet, Principal};

    fn fixture(name: &str) -> PathBuf {
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures")).join(name)
    }

    /// A cut guard carrying two distinct euids, `"first"` pushed before
    /// `"second"` (push order, `GuardSet::euids`): `secure/master.wf`'s
    /// `valid_read` denies outright for `"first"` and raises a runtime
    /// error for `"second"`. If the per-euid loop incorrectly kept
    /// asking after `"first"` already denied (the bug this guards
    /// against: an earlier, hand-duplicated copy of this loop in
    /// `admin_valid_read` only stopped early on an apply *error*, not on
    /// an ordinary denial), this would see `"second"`'s error and answer
    /// `Err`, not the plain `Ok(false)` a single, shared decision loop
    /// gives.
    #[test]
    fn admin_valid_read_stops_at_the_first_denying_euid_in_a_multi_principal_guard() {
        let root = fixture("admin_query_two_euid");
        let mut world = World::boot(&root).expect("boot");
        let mut host = NullHost;

        let master = world.master.expect("fixture has a master");
        let first = world.registry.syms.intern("first");
        let second = world.registry.syms.intern("second");
        let guard = GuardSet::empty()
            .with(Principal {
                uid: first,
                euid: first,
            })
            .with(Principal {
                uid: second,
                euid: second,
            });

        let result = world.exec(
            &mut host,
            master,
            None,
            None,
            Some(guard),
            None,
            None,
            |h| h.admin_valid_read("x", "/std/item"),
        );
        assert!(
            matches!(result, Ok(false)),
            "must deny at the first (\"first\") euid and never reach the \
             second (\"second\") euid's error-raising valid_read, got {result:?}"
        );
    }
}
