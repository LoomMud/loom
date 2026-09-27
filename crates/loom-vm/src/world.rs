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
use crate::bcvm::compile_worker::RecompileJob;
use crate::bcvm::registry::{Compiler, Registry, RegistryHost};
use crate::bcvm::vm::{Limits as VmLimits, RtError};
use crate::host::{Host, NullHost};
use crate::object::ObjectId;
use crate::scheduler::Scheduler;
use crate::security::{AuditEntry, SecurityState};

/// Path of the master object.
pub const MASTER_PATH: &str = "/secure/master";

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

/// Per-execution guard rails (§5.8).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_ticks: u64,
    pub max_depth: u32,
    /// Per-object (shallow) memory quota in bytes; see
    /// `bcvm::vm::Limits::mem_quota_bytes`.
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
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_ticks: 1_000_000,
            max_depth: 512,
            mem_quota_bytes: VmLimits::default().mem_quota_bytes,
            eager_upgrade_batch: 200,
            heartbeat_interval_ticks: DEFAULT_HEARTBEAT_INTERVAL_TICKS,
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
    /// `account_create`/`account_login` (OBI-85): see `AccountsCtx`.
    account_auth: Box<dyn AccountAuth>,
    account_next_id: u64,
    account_pending: HashMap<u64, ObjectId>,
    account_results: VecDeque<(u64, ObjectId, bool, String)>,
    /// Stack-based privilege check state (OBI-35): decision cache, policy
    /// epoch, audit ring buffer.
    security: SecurityState,
}

/// Identifies one [`World::begin_recompile`] call, so its eventual result
/// (in [`World::take_finished_recompiles`]) can be matched back to the
/// caller that asked for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecompileToken(u64);

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
            registry: Registry::default(),
            compiler: Compiler::new(mudlib_root.to_path_buf()),
            master: None,
            limits,
            scheduler: Scheduler::new(),
            pending_recompiles: Vec::new(),
            finished_recompiles: Vec::new(),
            next_recompile_token: 0,
            account_auth: Box::new(NullAccountAuth),
            account_next_id: 0,
            account_pending: HashMap::new(),
            account_results: VecDeque::new(),
            security: SecurityState::new(),
        };
        let mut null = NullHost;
        let master = w
            .exec(&mut null, None, None, |h| h.load_object(MASTER_PATH))
            .map_err(|e| BootError::Master(e.report()))?;
        w.master = Some(master);
        Ok(w)
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
                let _ = self.exec(host, this_player, conn, |h| {
                    h.call_apply(
                        ob,
                        "account_result",
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

    /// Run `body` against a fresh [`RegistryHost`] with driver context
    /// wired up (network host, `this_player`, bound connection, master).
    fn exec<T>(
        &mut self,
        host: &mut dyn Host,
        this_player: Option<ObjectId>,
        conn: Option<u64>,
        body: impl FnOnce(&mut RegistryHost<'_>) -> Result<T, RtError>,
    ) -> Result<T, RtError> {
        self.registry.debug_assert_atomic_scope_closed();
        let self_object = this_player.or(self.master).unwrap_or(ObjectId {
            index: u32::MAX,
            generation: 0,
        });
        let mut rh = RegistryHost::with_driver(
            &mut self.registry,
            self_object,
            self.limits.vm_limits(),
            self.limits.max_ticks,
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
        );
        let result = body(&mut rh);
        self.registry.debug_assert_atomic_scope_closed();
        result
    }

    fn report(host: &mut dyn Host, conn: u64, e: &RtError) {
        host.send(conn, &format!("*Error: {}\n", e.report()));
    }

    /// A new connection arrived: master `connect()` returns the player
    /// object, the driver binds the connection to it, then calls `logon()`.
    pub fn connect(&mut self, conn: u64, host: &mut dyn Host) {
        let Some(master) = self.master else {
            host.close(conn);
            return;
        };
        let r = self.exec(host, None, Some(conn), |h| {
            match h.call_apply(master, "connect", Vec::new())? {
                Some(Value::Object(id)) if h.registry.get(id).is_some() => Ok(id),
                Some(v) => Err(RtError::new(format!(
                    "{MASTER_PATH}: connect() must return object, got {}",
                    v.type_name()
                ))),
                None => Err(RtError::new(format!("{MASTER_PATH} has no connect()"))),
            }
        });
        let player = match r {
            Ok(p) => p,
            Err(e) => {
                World::report(host, conn, &e);
                host.close(conn);
                return;
            }
        };
        self.registry.bind(conn, player);
        if let Err(e) = self.exec(host, Some(player), Some(conn), |h| {
            h.call_apply(player, "logon", Vec::new())
        }) {
            World::report(host, conn, &e);
        }
    }

    /// A line of input: `process_input(line)` on the bound object.
    pub fn input(&mut self, conn: u64, line: &str, host: &mut dyn Host) {
        let Some(&ob) = self.registry.conns.get(&conn) else {
            return;
        };
        let r = self.exec(host, Some(ob), Some(conn), |h| {
            match h.call_apply(ob, "process_input", vec![Value::str(line)])? {
                Some(_) => Ok(()),
                None => Err(RtError::new(format!(
                    "{} has no process_input()",
                    h.registry.obj_name(ob)
                ))),
            }
        });
        if let Err(e) = r {
            World::report(host, conn, &e);
        }
    }

    /// The connection went away: unbind, then `net_dead()` on the object.
    pub fn disconnect(&mut self, conn: u64, host: &mut dyn Host) {
        let Some(ob) = self.registry.conns.remove(&conn) else {
            return;
        };
        if let Some(o) = self.registry.get_mut(ob) {
            o.conn = None;
        }
        // Errors have nowhere to go (the connection is gone).
        let _ = self.exec(host, Some(ob), None, |h| {
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
    pub fn tick(&mut self, host: &mut dyn Host) {
        self.poll_recompiles(host);
        let due = self.scheduler.advance();
        let world_tick = self.scheduler.tick();
        let interval = self.limits.heartbeat_interval_ticks.max(1);
        if world_tick.is_multiple_of(interval) {
            for ob in self.scheduler.heartbeat_targets() {
                if self.registry.get(ob).is_none() {
                    continue; // destructed since it subscribed
                }
                let _ = self.exec(host, None, None, |h| {
                    h.call_apply(ob, "heartbeat", Vec::new())
                });
            }
        }
        for call in due {
            if self.registry.get(call.ob).is_none() {
                continue; // destructed in the same tick it was scheduled for
            }
            let _ = self.exec(host, None, None, move |h| {
                h.call_apply(call.ob, &call.func, call.args)
            });
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
            let _ = self.exec(host, None, None, move |h| {
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

    /// Drain every warning recorded by a *lazy* per-instance upgrade since
    /// the last call (OBI-89: an access-triggered migration or its
    /// `upgrade()` hook that failed and rolled back that one object,
    /// spec §7.2 step 6.4 — not fatal, so this is the only place it
    /// surfaces, mirroring `compile_object`'s own `Vec<String>` return for
    /// the eager-at-install-time case).
    pub fn take_lazy_upgrade_warnings(&mut self) -> Vec<crate::bcvm::UpgradeWarning> {
        std::mem::take(&mut self.registry.lazy_upgrade_warnings)
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
        self.exec(host, None, None, |h| Ok(h.recompile(path)))
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
                    let result = self
                        .exec(host, None, None, |h| {
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
        self.exec(host, None, None, |h| h.load_object(path))
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
        self.exec(host, None, None, |h| {
            h.call_apply(ob, func, args)?
                .ok_or_else(|| RtError::new(format!("no function `{func}`")))
        })
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

    /// Current (shallow, see `bcvm::heap::shallow_bytes`) accounted memory
    /// of `ob`'s program variables (spec r5 §5.2.1 "memory quotas with
    /// per-object accounting").
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
