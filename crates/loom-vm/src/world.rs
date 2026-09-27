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
use crate::bcvm::registry::{Compiler, Registry, RegistryHost};
use crate::bcvm::vm::{Limits as VmLimits, RtError};
use crate::host::{Host, NullHost};
use crate::object::ObjectId;

/// Path of the master object.
pub const MASTER_PATH: &str = "/secure/master";

/// Per-execution guard rails (§5.8).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_ticks: u64,
    pub max_depth: u32,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_ticks: 1_000_000,
            max_depth: 512,
        }
    }
}

impl Limits {
    fn vm_limits(&self) -> VmLimits {
        VmLimits {
            max_depth: self.max_depth,
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
            registry: Registry::default(),
            compiler: Compiler::new(mudlib_root.to_path_buf()),
            master: None,
            limits,
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
        );
        body(&mut rh)
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

    // ---- introspection / tooling (tests, `loom` admin commands) -----------

    /// Recompile a program as `compile_object` would. `None` on success,
    /// else the diagnostics.
    pub fn compile_object(&mut self, path: &str, host: &mut dyn Host) -> Option<String> {
        self.exec(host, None, None, |h| Ok(h.recompile(path)))
            .unwrap_or_else(|e| Err(e.report()))
            .err()
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
