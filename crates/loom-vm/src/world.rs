// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The world: object table, program registry, connection bindings, and the
//! driver ↔ VM seam (`World::boot/connect/input/disconnect`).
//!
//! Phase 0 deviations from spec §7.2 (by design, see docs/weft-grammar.md, Part 3):
//! compilation runs on the world thread and reads the mudlib from disk
//! synchronously; instance upgrade is eager (every object of a recompiled
//! program switches immediately); there is no `upgrade()` apply.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::host::{Host, NullHost};
use crate::interp::{Exec, Frame, R, RtError};
use crate::object::{Object, ObjectId, ObjectTable, Vars};
use crate::program::{Program, link};
use crate::value::Value;

/// Path of the master object.
pub const MASTER_PATH: &str = "/secure/master";

/// Minimum stack for the thread that drives a [`World`]. The tree-walker
/// recurses on the Rust stack; 200 Weft frames of nested expressions need
/// more than the 2 MiB default of spawned threads.
pub const WORLD_THREAD_STACK: usize = 64 * 1024 * 1024;

/// Default Rust-stack budget per execution (must stay well below
/// [`WORLD_THREAD_STACK`]).
pub const DEFAULT_STACK_BUDGET: usize = 32 * 1024 * 1024;

/// Per-execution guard rails (§5.8).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_ticks: u64,
    pub max_depth: u32,
    /// Rust stack bytes an execution may use (tree-walker recursion guard).
    pub max_stack_bytes: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_ticks: 1_000_000,
            max_depth: 200,
            max_stack_bytes: DEFAULT_STACK_BUDGET,
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

impl fmt::Display for BootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootError::NoMudlib(p) => write!(f, "mudlib root {} is not a directory", p.display()),
            BootError::Master(e) => write!(f, "cannot load {MASTER_PATH}:\n{e}"),
        }
    }
}

impl std::error::Error for BootError {}

/// World state shared by all executions.
pub struct State {
    pub root: PathBuf,
    pub objects: ObjectTable,
    /// Program registry: path → current version.
    pub programs: HashMap<String, Rc<Program>>,
    /// Object names (`/std/room`, `/std/room#3`) → id.
    pub names: HashMap<String, ObjectId>,
    pub next_clone: u64,
    pub conns: HashMap<u64, ObjectId>,
    pub master: Option<ObjectId>,
    pub limits: Limits,
}

impl State {
    pub fn move_object(&mut self, id: ObjectId, dest: ObjectId) {
        let old = self.objects.get(id).and_then(|o| o.env);
        if let Some(old) = old
            && let Some(o) = self.objects.get_mut(old)
        {
            o.inventory.retain(|i| *i != id);
        }
        if let Some(d) = self.objects.get_mut(dest) {
            d.inventory.push(id);
        }
        if let Some(o) = self.objects.get_mut(id) {
            o.env = Some(dest);
        }
    }

    /// Bind connection `conn` to object `id` (unbinding both sides' previous
    /// partners).
    pub fn bind(&mut self, conn: u64, id: ObjectId) {
        if let Some(prev) = self.conns.insert(conn, id)
            && prev != id
            && let Some(o) = self.objects.get_mut(prev)
        {
            o.conn = None;
        }
        if let Some(o) = self.objects.get_mut(id) {
            if let Some(old_conn) = o.conn
                && old_conn != conn
            {
                self.conns.remove(&old_conn);
            }
            o.conn = Some(conn);
        }
    }
}

/// Normalise a mudlib program path: leading `/`, no `.`/`..`, no extension.
pub fn normalize_path(p: &str) -> Result<String, String> {
    let p = p.trim();
    let p = p.strip_suffix(".wf").unwrap_or(p);
    if !p.starts_with('/') {
        return Err(format!(
            "`{p}`: program paths must be absolute (start with `/`)"
        ));
    }
    for seg in p[1..].split('/') {
        if seg.is_empty()
            || seg == "."
            || seg == ".."
            || !seg
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(format!(
                "`{p}`: invalid program path (segments may use letters, digits, `_` and `-`)"
            ));
        }
    }
    Ok(p.to_string())
}

fn render_diags(path: &str, src: &str, diags: &[loom_syntax::Diagnostic]) -> String {
    let file = format!("{path}.wf");
    diags
        .iter()
        .map(|d| d.render(&file, src))
        .collect::<Vec<_>>()
        .join("")
        .trim_end()
        .to_string()
}

impl Exec<'_> {
    /// Compile `path` from disk into a new (unregistered) program. The parent
    /// comes from `overrides`, else the registry, else is compiled and
    /// registered first.
    fn compile_file(
        &mut self,
        path: &str,
        overrides: &HashMap<String, Rc<Program>>,
    ) -> Result<Program, String> {
        let file = self.st.root.join(format!("{}.wf", &path[1..]));
        let src: Rc<str> = std::fs::read_to_string(&file)
            .map_err(|e| format!("{path}.wf: cannot read: {e}"))?
            .into();
        let (ast, diags) = loom_syntax::parse(&src);
        if !diags.is_empty() {
            return Err(render_diags(path, &src, &diags));
        }
        let gate = crate::subset::phase0_gate(&ast);
        if !gate.is_empty() {
            return Err(render_diags(path, &src, &gate));
        }
        let parent = match ast.inherits.first() {
            None => None,
            Some(inh) => {
                let ppath = normalize_path(&inh.path)?;
                let loc = || {
                    let (l, c) = loom_syntax::line_col(&src, inh.span.start as usize);
                    format!("{path}.wf:{l}:{c}")
                };
                if self.compiling.len() > 32 {
                    return Err(format!("{}: inherit chain is too deep", loc()));
                }
                if ppath == path || self.compiling.contains(&ppath) {
                    return Err(format!("{}: inherit cycle through {ppath}", loc()));
                }
                let parent = match overrides.get(&ppath) {
                    Some(p) => p.clone(),
                    None => {
                        self.compiling.push(path.to_string());
                        let r = self.ensure_program(&ppath);
                        self.compiling.pop();
                        r.map_err(|e| format!("{}: cannot inherit {ppath}:\n{e}", loc()))?
                    }
                };
                Some(parent)
            }
        };
        let version = self.st.programs.get(path).map_or(1, |p| p.version + 1);
        link(path, src.clone(), Rc::new(ast), parent, version)
            .map_err(|d| render_diags(path, &src, &d))
    }

    /// The current program for `path`, compiling and registering it if needed.
    pub fn ensure_program(&mut self, path: &str) -> Result<Rc<Program>, String> {
        let path = normalize_path(path)?;
        if let Some(p) = self.st.programs.get(&path) {
            return Ok(p.clone());
        }
        let prog = Rc::new(self.compile_file(&path, &HashMap::new())?);
        self.st.programs.insert(path, prog.clone());
        Ok(prog)
    }

    /// `load_object`: the blueprint for `path`, loading it if needed.
    pub fn load_object(&mut self, path: &str) -> Result<ObjectId, String> {
        let path = normalize_path(path)?;
        if let Some(id) = self.st.names.get(&path)
            && self.st.objects.get(*id).is_some()
        {
            return Ok(*id);
        }
        let prog = self.ensure_program(&path)?;
        self.new_object(prog, path).map_err(|e| e.report())
    }

    /// `clone_object`: a new clone `path#N`.
    pub fn clone_object(&mut self, path: &str) -> Result<ObjectId, String> {
        let path = normalize_path(path)?;
        let prog = self.ensure_program(&path)?;
        self.st.next_clone += 1;
        let name = format!("{path}#{}", self.st.next_clone);
        self.new_object(prog, name).map_err(|e| e.report())
    }

    /// Create an object, run variable initialisers and `create()`. On error
    /// the half-built object is removed.
    fn new_object(&mut self, prog: Rc<Program>, name: String) -> R<ObjectId> {
        let id = self.st.objects.insert(Object {
            name: name.clone(),
            program: prog.clone(),
            vars: Vars::new(),
            env: None,
            inventory: Vec::new(),
            conn: None,
        });
        self.st.names.insert(name.clone(), id);
        let r = self
            .init_vars(id, &prog, None)
            .and_then(|()| self.call_apply(id, "create", Vec::new()));
        match r {
            Ok(_) => Ok(id),
            Err(e) => {
                self.st.objects.remove(id);
                self.st.names.remove(&name);
                Err(e)
            }
        }
    }

    /// Set up `id`'s variables for `prog`, root program first. Variables in
    /// `keep` matched by (declaring program, name) and still type-correct
    /// keep their value; all others get their initialiser.
    fn init_vars(&mut self, id: ObjectId, prog: &Rc<Program>, keep: Option<&Vars>) -> R<()> {
        for p in prog.chain() {
            for v in &p.vars {
                let kept = keep
                    .and_then(|k| k.get(&p.path))
                    .and_then(|m| m.get(v.name.name.as_str()))
                    .filter(|val| v.ty.as_ref().is_none_or(|t| val.conforms(t)))
                    .cloned();
                let val = match (kept, &v.init) {
                    (Some(val), _) => val,
                    (None, Some(e)) => {
                        let mut f = Frame::new(id, p.clone());
                        let val = self.eval(&mut f, e)?;
                        if let Some(t) = &v.ty
                            && !val.conforms(t)
                        {
                            return Err(self.err(
                                &f,
                                v.span,
                                format!(
                                    "`{}` is declared {} but its initialiser is {}",
                                    v.name.name,
                                    loom_syntax::pretty::ty(t),
                                    val.type_name()
                                ),
                            ));
                        }
                        val
                    }
                    (None, None) => Value::Null,
                };
                if let Some(o) = self.st.objects.get_mut(id) {
                    o.vars
                        .entry(p.path.clone())
                        .or_default()
                        .insert(Rc::from(v.name.name.as_str()), val);
                }
            }
        }
        Ok(())
    }

    /// `compile_object` / `update` (§7.2, Phase 0): recompile `path` and its
    /// dependents; on success install all of them and switch every existing
    /// object to the new versions, migrating variables. All-or-nothing: any
    /// failure leaves the old programs and objects untouched.
    pub fn recompile(&mut self, path: &str) -> Result<(), String> {
        let path = normalize_path(path)?;
        let newp = Rc::new(self.compile_file(&path, &HashMap::new())?);
        if let std::collections::hash_map::Entry::Vacant(e) = self.st.programs.entry(path.clone()) {
            e.insert(newp);
            return Ok(());
        }
        let mut new_set: HashMap<String, Rc<Program>> = HashMap::new();
        new_set.insert(path.clone(), newp);

        // Dependents, parents before children.
        let mut deps: Vec<Rc<Program>> = self
            .st
            .programs
            .values()
            .filter(|p| p.inherits(&path))
            .cloned()
            .collect();
        deps.sort_by_key(|p| (p.chain().len(), p.path.clone()));
        for d in deps {
            let Some(pp) = d.parent.as_ref().map(|p| p.path.to_string()) else {
                continue;
            };
            let parent = new_set
                .get(&pp)
                .or_else(|| self.st.programs.get(&pp))
                .cloned();
            let relinked = link(&d.path, d.src.clone(), d.ast.clone(), parent, d.version + 1)
                .map_err(|diags| {
                    format!(
                        "{path} changed, but dependent {} no longer compiles:\n{}",
                        d.path,
                        render_diags(&d.path, &d.src, &diags)
                    )
                })?;
            new_set.insert(d.path.to_string(), Rc::new(relinked));
        }
        self.install(new_set)
    }

    fn install(&mut self, new_set: HashMap<String, Rc<Program>>) -> Result<(), String> {
        let old_programs: Vec<(String, Option<Rc<Program>>)> = new_set
            .keys()
            .map(|k| (k.clone(), self.st.programs.get(k).cloned()))
            .collect();
        for (k, v) in &new_set {
            self.st.programs.insert(k.clone(), v.clone());
        }
        let affected: Vec<(ObjectId, Rc<Program>)> = self
            .st
            .objects
            .ids()
            .into_iter()
            .filter_map(|id| {
                let o = self.st.objects.get(id)?;
                new_set.get(&*o.program.path).map(|p| (id, p.clone()))
            })
            .collect();
        let mut saved: Vec<(ObjectId, Rc<Program>, Vars)> = Vec::new();
        let mut failure = None;
        for (id, newp) in affected {
            let Some(o) = self.st.objects.get_mut(id) else {
                continue;
            };
            let old_prog = std::mem::replace(&mut o.program, newp.clone());
            let old_vars = std::mem::take(&mut o.vars);
            saved.push((id, old_prog, old_vars.clone()));
            if let Err(e) = self.init_vars(id, &newp, Some(&old_vars)) {
                failure = Some((id, e));
                break;
            }
        }
        if let Some((id, e)) = failure {
            // Roll back everything: programs and every touched object.
            for (k, old) in old_programs {
                match old {
                    Some(p) => self.st.programs.insert(k, p),
                    None => self.st.programs.remove(&k),
                };
            }
            for (sid, prog, vars) in saved {
                if let Some(o) = self.st.objects.get_mut(sid) {
                    o.program = prog;
                    o.vars = vars;
                }
            }
            return Err(format!(
                "upgrade of {} failed, nothing was changed:\n{}",
                self.obj_name(id),
                e.report()
            ));
        }
        Ok(())
    }
}

/// The game world. Driven by exactly one thread (the world thread, §3.3).
pub struct World {
    st: State,
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
            st: State {
                root: mudlib_root.to_path_buf(),
                objects: ObjectTable::default(),
                programs: HashMap::new(),
                names: HashMap::new(),
                next_clone: 0,
                conns: HashMap::new(),
                master: None,
                limits,
            },
        };
        let master = w
            .exec(&mut NullHost, None, None, |x| {
                x.load_object(MASTER_PATH).map_err(RtError::new)
            })
            .map_err(|e| BootError::Master(e.report()))?;
        w.st.master = Some(master);
        Ok(w)
    }

    /// The mudlib root this world was booted from.
    pub fn root(&self) -> &Path {
        &self.st.root
    }

    fn exec<T>(
        &mut self,
        host: &mut dyn Host,
        this_player: Option<ObjectId>,
        conn: Option<u64>,
        body: impl FnOnce(&mut Exec<'_>) -> R<T>,
    ) -> R<T> {
        let mut x = Exec {
            ticks_left: self.st.limits.max_ticks,
            st: &mut self.st,
            host,
            depth: 0,
            this_player,
            conn,
            compiling: Vec::new(),
            stack_base: crate::interp::stack_addr(),
        };
        body(&mut x)
    }

    fn report(host: &mut dyn Host, conn: u64, e: &RtError) {
        host.send(conn, &format!("*Error: {}\n", e.report()));
    }

    /// A new connection arrived: master `connect()` returns the player
    /// object, the driver binds the connection to it, then calls `logon()`.
    pub fn connect(&mut self, conn: u64, host: &mut dyn Host) {
        let Some(master) = self.st.master else {
            host.close(conn);
            return;
        };
        let r = self.exec(host, None, Some(conn), |x| {
            match x.call_apply(master, "connect", Vec::new())? {
                Some(Value::Object(id)) if x.st.objects.get(id).is_some() => Ok(id),
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
        self.st.bind(conn, player);
        if let Err(e) = self.exec(host, Some(player), Some(conn), |x| {
            x.call_apply(player, "logon", Vec::new())
        }) {
            World::report(host, conn, &e);
        }
    }

    /// A line of input: `process_input(line)` on the bound object.
    pub fn input(&mut self, conn: u64, line: &str, host: &mut dyn Host) {
        let Some(&ob) = self.st.conns.get(&conn) else {
            return;
        };
        let r = self.exec(host, Some(ob), Some(conn), |x| {
            match x.call_apply(ob, "process_input", vec![Value::str(line)])? {
                Some(_) => Ok(()),
                None => Err(RtError::new(format!(
                    "{} has no process_input()",
                    x.obj_name(ob)
                ))),
            }
        });
        if let Err(e) = r {
            World::report(host, conn, &e);
        }
    }

    /// The connection went away: unbind, then `net_dead()` on the object.
    pub fn disconnect(&mut self, conn: u64, host: &mut dyn Host) {
        let Some(ob) = self.st.conns.remove(&conn) else {
            return;
        };
        if let Some(o) = self.st.objects.get_mut(ob) {
            o.conn = None;
        }
        // Errors have nowhere to go (the connection is gone).
        let _ = self.exec(host, Some(ob), None, |x| {
            x.call_apply(ob, "net_dead", Vec::new())
        });
    }

    // ---- introspection / tooling (tests, `loom` admin commands) -----------

    /// Recompile a program as `compile_object` would. `None` on success,
    /// else the diagnostics.
    pub fn compile_object(&mut self, path: &str, host: &mut dyn Host) -> Option<String> {
        self.exec(host, None, None, |x| Ok(x.recompile(path)))
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
        self.exec(host, None, None, |x| {
            x.call_apply(ob, func, args)?
                .ok_or_else(|| RtError::new(format!("no function `{func}`")))
        })
        .map_err(|e| e.report())
    }

    pub fn find_object(&self, name: &str) -> Option<ObjectId> {
        self.st
            .names
            .get(name)
            .copied()
            .filter(|id| self.st.objects.get(*id).is_some())
    }

    /// The object bound to connection `conn`.
    pub fn connection_object(&self, conn: u64) -> Option<ObjectId> {
        self.st.conns.get(&conn).copied()
    }

    pub fn object_name(&self, ob: ObjectId) -> Option<&str> {
        self.st.objects.get(ob).map(|o| o.name.as_str())
    }

    pub fn environment(&self, ob: ObjectId) -> Option<ObjectId> {
        self.st.objects.get(ob).and_then(|o| o.env)
    }

    /// Current version of a registered program.
    pub fn program_version(&self, path: &str) -> Option<u32> {
        self.st.programs.get(path).map(|p| p.version)
    }

    /// Version of the program `ob` currently runs.
    pub fn object_program_version(&self, ob: ObjectId) -> Option<(String, u32)> {
        self.st
            .objects
            .get(ob)
            .map(|o| (o.program.path.to_string(), o.program.version))
    }

    /// Read variable `name` of `ob` (searching all declaring programs,
    /// most-derived first).
    pub fn var(&self, ob: ObjectId, name: &str) -> Option<Value> {
        let o = self.st.objects.get(ob)?;
        o.program
            .chain()
            .iter()
            .rev()
            .find_map(|p| o.vars.get(&p.path).and_then(|m| m.get(name)).cloned())
    }

    /// Render a value as Weft interpolation would.
    pub fn display(&self, v: &Value) -> String {
        crate::value::display(v, &|id| {
            self.object_name(id)
                .map_or_else(|| "<destructed>".to_string(), str::to_string)
        })
    }

    pub fn object_count(&self) -> usize {
        self.st.objects.len()
    }
}
