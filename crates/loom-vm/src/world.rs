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

use std::path::{Path, PathBuf};

use crate::bcvm::Value;
use crate::bcvm::compile_worker::RecompileJob;
use crate::bcvm::registry::{Compiler, Registry, RegistryHost};
use crate::bcvm::vm::{Limits as VmLimits, RtError};
use crate::host::{Host, NullHost};
use crate::object::ObjectId;
use crate::privilege::{AllowAllAudited, AuditEntry, PrivilegeCheck};
use crate::scheduler::Scheduler;

/// Path of the master object.
pub const MASTER_PATH: &str = "/secure/master";

/// Per-execution guard rails (§5.8).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_ticks: u64,
    pub max_depth: u32,
    /// Per-object (shallow) memory quota in bytes; see
    /// `bcvm::vm::Limits::mem_quota_bytes`.
    pub mem_quota_bytes: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_ticks: 1_000_000,
            max_depth: 512,
            mem_quota_bytes: VmLimits::default().mem_quota_bytes,
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
    /// P1+ enforcement hook (OBI-33): stubbed allow-all + audit log until
    /// S1's policy replaces it (see `crate::privilege`).
    privilege: Box<dyn PrivilegeCheck>,
    /// `compile_object`/`update` requests dispatched to a background
    /// thread but not yet applied (OBI-90/D-P1.5): `World::tick` installs
    /// each one as soon as it finishes, so ticks in between are never
    /// blocked on a slow compile.
    pending_recompiles: Vec<(RecompileToken, RecompileJob)>,
    /// Every background compile `World::tick`/`poll_recompiles` has
    /// installed (or failed to) since the last `take_finished_recompiles`.
    finished_recompiles: Vec<(RecompileToken, Result<(), String>)>,
    next_recompile_token: u64,
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
            privilege: Box::new(AllowAllAudited::new()),
            pending_recompiles: Vec::new(),
            finished_recompiles: Vec::new(),
            next_recompile_token: 0,
        };
        let mut null = NullHost;
        let master = w
            .exec(&mut null, None, None, |h| h.load_object(MASTER_PATH))
            .map_err(|e| BootError::Master(e.report()))?;
        w.master = Some(master);
        Ok(w)
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
            self.privilege.as_mut(),
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

    /// Advance the world by one tick (OBI-33): `heartbeat()` on every
    /// subscribed object, in subscription order, then every `call_out` now
    /// due, in scheduling order (`Scheduler::advance`). Each call runs
    /// against a fresh `RegistryHost` with its own metered tick budget
    /// (`Limits::max_ticks`), exactly like `input`/`connect`, so one slow
    /// callback cannot starve another. Errors have nowhere to report to
    /// (neither path has a connection) and are swallowed, matching
    /// `disconnect`'s `net_dead`.
    pub fn tick(&mut self, host: &mut dyn Host) {
        self.poll_recompiles(host);
        for ob in self.scheduler.heartbeat_targets() {
            if self.registry.get(ob).is_none() {
                continue; // destructed since it subscribed
            }
            let _ = self.exec(host, None, None, |h| {
                h.call_apply(ob, "heartbeat", Vec::new())
            });
        }
        for call in self.scheduler.advance() {
            if self.registry.get(call.ob).is_none() {
                continue; // destructed in the same tick it was scheduled for
            }
            let _ = self.exec(host, None, None, move |h| {
                h.call_apply(call.ob, &call.func, call.args)
            });
        }
    }

    /// Destroy `ob`: move its inventory up into its own environment (or
    /// drop it loose if it had none), unlink it from its environment's
    /// inventory and its name/connection bindings, and cancel every
    /// pending `call_out`/heartbeat subscription for it (OBI-33) before
    /// freeing its slot. A no-op if `ob` is already gone. Not yet exposed
    /// as a Weft efun (no ticket asks for `destruct_object()` yet); this
    /// is the primitive such an efun and `World`'s tests both call.
    pub fn destruct(&mut self, ob: ObjectId) {
        let Some(existing_env) = self.registry.get(ob).map(|o| o.env) else {
            return;
        };
        let inventory = self
            .registry
            .get(ob)
            .map(|o| o.inventory.clone())
            .unwrap_or_default();
        for item in inventory {
            match existing_env {
                Some(dest) => self.registry.move_object(item, dest),
                None => {
                    if let Some(i) = self.registry.get_mut(item) {
                        i.env = None;
                    }
                }
            }
        }
        if let Some(env) = existing_env
            && let Some(o) = self.registry.get_mut(env)
        {
            o.inventory.retain(|i| *i != ob);
        }
        if let Some(conn) = self.registry.get(ob).and_then(|o| o.conn) {
            self.registry.conns.remove(&conn);
        }
        let name = self.registry.obj_name(ob);
        self.registry.names.remove(&name);
        self.scheduler.remove_for_object(ob);
        self.registry.remove(ob);
    }

    /// Every P1+ efun call recorded so far by the enforcement hook
    /// (OBI-33; empty until an efun with a gated `Privilege` runs).
    pub fn audit_log(&self) -> &[AuditEntry] {
        self.privilege.log()
    }

    /// Pending `call_out` count (tests/introspection).
    pub fn pending_call_outs(&self) -> usize {
        self.scheduler.pending_count()
    }

    // ---- introspection / tooling (tests, `loom` admin commands) -----------

    /// Recompile a program as `compile_object` would. `None` on success,
    /// else the diagnostics.
    pub fn compile_object(&mut self, path: &str, host: &mut dyn Host) -> Option<String> {
        self.exec(host, None, None, |h| Ok(h.recompile(path)))
            .unwrap_or_else(|e| Err(e.report()))
            .err()
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
