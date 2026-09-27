// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! A minimal, multi-object [`Host`] for the bytecode VM: a program
//! registry with a per-program dispatch table (name → function slot,
//! spec §5.8) and an object table so `call_virtual`/`call_static`/
//! `call_other` resolve against *real* inheritance and object identity
//! instead of the single-module stand-in `bcvm_e2e.rs` used for the first
//! codegen-bridge slice.
//!
//! [`crate::world::World`] runs every `.wf` program through this module
//! (OBI-72): [`Compiler`] loads/recompiles programs from disk,
//! [`RegistryHost`] is the production [`Host`].
//!
//! **Spec r5 D26 (flat, suspendable call chain):** Weft-level calls that
//! leave the running module — unqualified `f()` (virtual dispatch),
//! `super::`/`program::f()`, and `ob.f()` — are answered through
//! [`Host::dispatch`] with [`HostCall::Enter`], so the calling
//! [`Interpreter`] pushes the callee as a frame on its *own* stack (with
//! `self` switched via `enter_self`/`leave_self`). One call chain across any
//! number of objects is one heap `Vec<Frame>`, bounded by one `max_depth`,
//! and suspendable at any `TickCheck` (see
//! `cross_object_chain_is_one_flat_suspendable_stack`).
//!
//! **Remaining nesting (bounded, not suspendable):** a *driver* entry
//! point that has to start Weft code from Rust — `World`'s applies,
//! `$init`, and driver efuns that run code (`load_object`/`clone_object`
//! running `create()`, `compile_object`) — still starts a fresh
//! [`Interpreter`] via [`RegistryHost::call_in`], guarded by
//! [`NESTED_CALL_STACK_BUDGET`]. Function values/`apply` do not exist in
//! the VM yet; when they land they must dispatch through
//! [`Host::dispatch`] too.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use loom_compiler::bytecode::{Callee, Module};
use loom_compiler::hir;
use loom_compiler::mudlib::{self, Outcome, Session};
use loom_compiler::ty::Ty;

use crate::bcvm::Value;
use crate::bcvm::compile::{CompileError, compile_and_verify};
use crate::bcvm::compile_worker;
use crate::bcvm::heap;
use crate::bcvm::heap::FnBody;
use crate::bcvm::vm::{
    CallSite, CallTarget, Host, HostCall, Interpreter, Limits, ProgramCode, R, RtError,
};
use crate::efuns::Privilege;
use crate::object::ObjectId;
use crate::security::{
    self, APPLY_TICKS, AuditEntry, GuardSet, Interner, MISS_CHARGE, Operation, Principal, ROOT,
    SecurityState, Sym,
};

/// `(uid, euid)` of `obj`, or root for an id that is not (or no longer)
/// in the registry (the synthetic `World::exec` base object).
fn principal_of(registry: &Registry, obj: ObjectId) -> Principal {
    registry.get(obj).map_or(Principal::ROOT, |o| Principal {
        uid: o.uid,
        euid: o.euid,
    })
}

/// The name of the synthetic per-program initialiser function
/// [`synth_init_function`] adds, run once per ancestor (root first) when an
/// object is created (spec §7.2's `init_vars`, done here instead of in the
/// tree-walker's `World::init_vars`). Chosen to be unwritable Weft source
/// (`$` cannot start an identifier), so a real program can never collide
/// with or call it directly.
pub const INIT_FN: &str = "$init";

/// One program variable's migration-relevant metadata (spec §7.2/§7.3: hot
/// reload matches state by *(declaring program, name)* and keeps the old
/// value only if it still type-conforms; a var with no initialiser has
/// nothing to (re-)run and always keeps whatever is already stored, or
/// `null` if nothing is). Built once per [`CompiledProgram`] from its
/// `hir::Program.vars`, in declaration order.
#[derive(Clone, Debug)]
pub struct VarSpec {
    pub name: Rc<str>,
    pub ty: Ty,
    pub has_init: bool,
}

/// One object whose migration to a newer program version failed and was
/// rolled back to its previous program/vars (spec §7.2 step 6.4: "On
/// error → rollback, object stays on vN, error reported to builder &
/// master `runtime_error`"). Not fatal to [`RegistryHost::install`] —
/// every other affected object still migrates.
#[derive(Clone, Debug)]
pub struct UpgradeWarning {
    pub object: ObjectId,
    pub program: String,
    pub message: String,
}

/// Build a synthetic, private function whose body conditionally assigns
/// every declared `var`'s initialiser expression to that global — exactly
/// the statements `crate::program::link`'s tree-walker equivalent
/// (`World::init_vars`) evaluates by hand, but lowered through the same
/// `codegen`/`verify` pipeline as everything else so a var initialiser
/// gets the same tick metering, dispatch, and verification as any other
/// code (spec §5.8: nothing runs unverified).
///
/// One `bool` parameter per var-with-an-initialiser (in declaration order,
/// matching [`CompiledProgram::init_specs`]) lets a caller say "keep the
/// value already stored for this var, don't run its initialiser" — the
/// hot-reload migration decision (spec §7.2/D-hot-reload: a recompile keeps
/// a var's old value when it still type-conforms, and only re-runs the
/// initialiser when it doesn't, or on first creation when nothing is kept).
/// `None` if `p` declares no vars with an initialiser (no function is
/// added, and [`RegistryHost::run_init`] is a no-op for that program).
fn synth_init_function(p: &hir::Program) -> Option<hir::Function> {
    let with_init: Vec<&hir::Var> = p.vars.iter().filter(|v| v.init.is_some()).collect();
    if with_init.is_empty() {
        return None;
    }
    let locals: Vec<hir::Local> = with_init
        .iter()
        .enumerate()
        .map(|(i, v)| hir::Local {
            name: Rc::from(format!("$keep{i}").as_str()),
            ty: Ty::Bool,
            mutable: false,
            span: v.span,
        })
        .collect();
    let params: Vec<hir::Param> = (0..with_init.len() as u32)
        .map(|local| hir::Param {
            local,
            default: None,
        })
        .collect();
    let stmts: Vec<hir::Stmt> = with_init
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let init = v
                .init
                .clone()
                .expect("filtered to vars with an initialiser");
            let assign = hir::Stmt {
                kind: hir::StmtKind::Assign {
                    place: hir::Place::Global(hir::GlobalRef {
                        owner: p.path.clone(),
                        name: v.name.clone(),
                    }),
                    op: hir::AssignOp::Set,
                    kind: hir::OpKind::Dyn,
                    value: init,
                },
                span: v.span,
            };
            // `if !$keep_i { global = init_expr }`
            hir::Stmt {
                kind: hir::StmtKind::If {
                    cond: hir::Expr {
                        kind: hir::ExprKind::Unary {
                            op: hir::UnOp::Not,
                            kind: hir::OpKind::Bool,
                            expr: Box::new(hir::Expr {
                                kind: hir::ExprKind::Local(i as u32),
                                ty: Ty::Bool,
                                span: v.span,
                            }),
                        },
                        ty: Ty::Bool,
                        span: v.span,
                    },
                    then: hir::Block {
                        stmts: vec![assign],
                        span: v.span,
                    },
                    els: None,
                },
                span: v.span,
            }
        })
        .collect();
    let span = stmts[0].span;
    Some(hir::Function {
        name: Rc::from(INIT_FN),
        vis: hir::Visibility::Private,
        is_override: false,
        atomic: false,
        params,
        ret: Ty::Void,
        locals,
        body: hir::Block { stmts, span },
        span,
    })
}

/// The compile-only (parse/check already done by the caller; this is
/// codegen + verify, see [`compile_and_verify`]) output of
/// [`compile_hir_unit`] — everything [`compile_hir_program`] needs to
/// build a [`CompiledProgram`] *except* `version`/`parent`, which only
/// matter once the result is being linked into a live [`Registry`].
/// Deliberately holds no `Rc<CompiledProgram>` (only `Module`'s own
/// `Rc<str>`, which never leaves whichever thread built it): this is the
/// seam [`crate::bcvm::compile_worker`] hangs a background compile off of
/// (OBI-90/D-P1.5) — it calls this same function on a background OS
/// thread, then encodes the result across the `Send` boundary instead of
/// handing back a live `Rc`.
pub(crate) struct CompiledUnit {
    pub module: Module,
    pub var_specs: Vec<VarSpec>,
    pub non_public: std::collections::HashSet<Rc<str>>,
}

/// Codegen + verify one already-checked `hir::Program`, plus the synthetic
/// `$init` function (see [`synth_init_function`]) that lets
/// [`Registry::instantiate`] run var initialisers on the bytecode VM
/// instead of needing a separate tree-walking evaluator for them.
pub(crate) fn compile_hir_unit(hir: &hir::Program) -> Result<CompiledUnit, CompileError> {
    let var_specs: Vec<VarSpec> = hir
        .vars
        .iter()
        .map(|v| VarSpec {
            name: v.name.clone(),
            ty: v.ty.clone(),
            has_init: v.init.is_some(),
        })
        .collect();
    let module = if let Some(init_fn) = synth_init_function(hir) {
        let mut augmented = hir.clone();
        augmented.fns.push(init_fn);
        compile_and_verify(&augmented)?
    } else {
        compile_and_verify(hir)?
    };
    // `ob.f()` may only reach `pub` functions (spec §5.3; the deleted
    // tree-walker enforced this in `call_other` too). The synthetic
    // `$init` is never `pub`.
    let non_public = hir
        .fns
        .iter()
        .filter(|f| f.vis != hir::Visibility::Public)
        .map(|f| f.name.clone())
        .chain(std::iter::once(Rc::from(INIT_FN)))
        .collect();
    Ok(CompiledUnit {
        module,
        var_specs,
        non_public,
    })
}

/// Compile one already-checked `hir::Program` into a [`CompiledProgram`]
/// (the synchronous path: [`Compiler::ensure_program`]/[`Compiler::recompile`]).
/// See [`compile_hir_unit`] for the codegen+verify itself.
pub fn compile_hir_program(
    hir: &hir::Program,
    version: u32,
    parent: Option<Rc<CompiledProgram>>,
) -> Result<CompiledProgram, CompileError> {
    let unit = compile_hir_unit(hir)?;
    let mut prog = CompiledProgram::new(unit.module, version, parent, unit.var_specs);
    prog.non_public = unit.non_public;
    Ok(prog)
}

/// Disk-backed program registration (spec §7.2's `compile_object`/`update`,
/// the bytecode-VM analogue of `crate::world::World::compile_file`\/
/// `ensure_program`): parses, resolves imports/inherits, and type-checks
/// through [`loom_compiler::mudlib::Session`] (which already knows how to
/// load `<root>/<path>.wf` from disk and walk an inherit chain, parents
/// first), then registers every not-yet-registered ancestor as a
/// [`CompiledProgram`] in [`Registry`], root first.
///
/// **Scope of this slice:** first-load only (`ensure_program`), matching
/// the acceptance-criteria's "real `.wf` programs run on this VM" step.
/// Recompiling an *already-loaded* program in place (`compile_object`'s
/// all-or-nothing relink-and-migrate-every-instance semantics, which
/// `World::recompile`/`install` already implement for the tree-walker) is
/// not ported yet — tracked as the next slice on this issue, not silently
/// skipped: [`Compiler`] only ever *adds* new entries to a [`Registry`],
/// it never replaces one, so calling it again for an already-registered
/// path is a no-op that returns the existing [`CompiledProgram`] (stale if
/// the source changed on disk since).
///
/// **Known simplification, carried over from the existing tree-walker**
/// (`crate::program::link` also does this): only the *first* `inherit` is
/// used as this program's single parent chain link. `hir::Program` and
/// `mudlib::Session` already resolve full multi-parent linearisation
/// (diamond-safe); [`CompiledProgram`] does not represent that yet
/// (`parent: Option<Rc<CompiledProgram>>` is a single link), so a program
/// with more than one `inherit` compiles and type-checks correctly but
/// only virtually dispatches into its first parent's chain here.
pub struct Compiler {
    session: Session<mudlib::FsLoader>,
    /// Duplicated from `session`'s private `FsLoader` (OBI-90): both the
    /// synchronous path and `begin_recompile`/`finish_recompile` need to
    /// hash a program's `.wf` source (`compile_worker::source_hash`) to
    /// detect drift, and `Session`'s loader isn't exposed for that.
    /// Also `read_file`/`write_file`'s confinement root (OBI-85).
    root: PathBuf,
}

impl Compiler {
    pub fn new(root: PathBuf) -> Self {
        Compiler {
            session: Session::new(mudlib::FsLoader { root: root.clone() }),
            root,
        }
    }

    /// The mudlib root this compiler loads programs from (OBI-85:
    /// `read_file`/`write_file`'s confinement root).
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Ensure `path` (and every ancestor it needs) is compiled and
    /// registered in `registry`, returning the leaf [`CompiledProgram`].
    /// Rendered diagnostics / "file not found" on failure, exactly like
    /// `World::ensure_program`'s `Result<_, String>`.
    pub fn ensure_program(
        &mut self,
        registry: &mut Registry,
        path: &str,
    ) -> Result<Rc<CompiledProgram>, String> {
        let path = mudlib::normalize_path(path)?;
        if let Some(p) = registry.program(&path) {
            return Ok(p);
        }
        let linearization: Vec<Rc<str>> = match self.session.compile(&path) {
            Outcome::Ok(checked) => checked.info.linearization.clone(),
            Outcome::Failed(msg) => return Err(msg.clone()),
            Outcome::Missing(msg) => return Err(msg.clone()),
        };
        for anc in &linearization {
            if registry.program(anc).is_some() {
                continue;
            }
            let anc_hir = match self.session.outcomes().get(&**anc) {
                Some(Outcome::Ok(c)) => c.hir.clone(),
                _ => {
                    return Err(format!(
                        "internal: {anc} missing from the compile session after compiling {path}"
                    ));
                }
            };
            // Phase 0's/`crate::program::link`'s restriction, see the
            // module doc comment: only the first `inherit` becomes this
            // program's `CompiledProgram` parent link.
            let parent = anc_hir
                .inherits
                .first()
                .and_then(|inh| registry.program(&inh.path));
            let mut compiled =
                compile_hir_program(&anc_hir, 1, parent).map_err(|e| format!("{anc}: {e}"))?;
            compiled.source_hash = compile_worker::source_hash(&self.root, anc).unwrap_or(0);
            registry.register_program(Rc::new(compiled));
        }
        Ok(registry
            .program(&path)
            .expect("just registered by the loop above"))
    }

    /// spec §7.2 `compile_object`/`update`: recompile `path` and every
    /// currently-registered program that (directly or transitively)
    /// inherits it, against fresh disk contents, all against *mutually
    /// consistent* interfaces — the bytecode-VM analogue of
    /// `World::recompile`. Returns the new [`CompiledProgram`]s, keyed by
    /// path, **not yet installed**: nothing in `registry` or any live
    /// object changes until the caller passes this to
    /// [`RegistryHost::install`], which is what makes the whole operation
    /// all-or-nothing (a compile error here changes nothing at all, and an
    /// `install` failure rolls back every object it had already touched).
    ///
    /// Every *other* ancestor of `path` (i.e. anything not itself `path` or
    /// one of its dependents) is assumed unchanged and reused as-is from
    /// `registry`, exactly like `World::recompile`'s `overrides`/registry
    /// lookup — this does not silently recompile the whole mudlib on every
    /// `update`.
    ///
    /// **Known simplification (flagged, not hidden):** unlike
    /// `World::recompile` (which relinks a dependent from its own already-
    /// parsed, cached AST), this re-reads and re-parses every dependent's
    /// `.wf` source from disk on every call — `CompiledProgram` does not
    /// retain the checked `hir::Program`/source needed to relink without
    /// going back through `Session`. Correct, but more I/O than the
    /// tree-walker's incremental relink; acceptable for how rarely
    /// `update`/`compile_object` runs relative to normal object traffic,
    /// not something a hot path depends on.
    pub fn recompile(
        &mut self,
        registry: &Registry,
        path: &str,
    ) -> Result<HashMap<String, Rc<CompiledProgram>>, String> {
        let path = mudlib::normalize_path(path)?;
        let mut dependents: Vec<Rc<CompiledProgram>> = registry
            .programs
            .values()
            .filter(|p| p.inherits(&path))
            .cloned()
            .collect();
        // Parents before children, so a child's rebuild can find its
        // freshly-rebuilt parent already in `new_set` below.
        dependents.sort_by_key(|p| p.chain().len());

        self.session.invalidate(&path);
        for d in &dependents {
            self.session.invalidate(&d.path);
        }

        let mut to_compile: Vec<String> = vec![path.clone()];
        to_compile.extend(dependents.iter().map(|d| d.path.to_string()));

        let mut new_set: HashMap<String, Rc<CompiledProgram>> = HashMap::new();
        for p in &to_compile {
            if new_set.contains_key(p) {
                continue;
            }
            match self.session.compile(p) {
                Outcome::Ok(_) => {}
                Outcome::Failed(msg) => return Err(msg.clone()),
                Outcome::Missing(msg) => return Err(msg.clone()),
            }
            let anc_hir = match self.session.outcomes().get(p) {
                Some(Outcome::Ok(c)) => c.hir.clone(),
                _ => return Err(format!("internal: {p} missing from the compile session")),
            };
            // Same Phase 0 restriction as `ensure_program`: only the first
            // `inherit` becomes this program's parent link.
            let parent = anc_hir.inherits.first().and_then(|inh| {
                new_set
                    .get(&*inh.path)
                    .cloned()
                    .or_else(|| registry.program(&inh.path))
            });
            let version = registry.program(p).map_or(1, |old| old.version + 1);
            let mut compiled =
                compile_hir_program(&anc_hir, version, parent).map_err(|e| format!("{p}: {e}"))?;
            compiled.source_hash = compile_worker::source_hash(&self.root, p).unwrap_or(0);
            new_set.insert(p.clone(), Rc::new(compiled));
        }
        Ok(new_set)
    }

    /// Send-safe snapshot of `registry`'s current program topology (OBI-90/
    /// D-P1.5): everything [`compile_worker::run_recompile`] needs to find
    /// `path`'s dependents and assign versions, without a `Rc<CompiledProgram>`
    /// (or the `Rc<str>` inside its `Module`) ever crossing to the
    /// background thread — `Rc` is never `Send`, no matter who allocated it.
    pub fn snapshot(&self, registry: &Registry) -> compile_worker::ProgramSnapshot {
        compile_worker::ProgramSnapshot::capture(registry)
    }

    /// Kick off `recompile`'s parse/check/codegen/verify on a background OS
    /// thread (OBI-90/D-P1.5, spec §7.2 steps 1–3): returns immediately.
    /// Does not touch `registry` or `self.session` again — only the
    /// snapshot captured right now — until [`Compiler::finish_recompile`]
    /// applies its result. `root` is `World`'s mudlib root (the background
    /// thread does its own disk reads through a private `Session`, never
    /// `self.session`, so a `recompile` from the world thread and a
    /// `finish_recompile` for an earlier background job never race on the
    /// same cache).
    pub fn begin_recompile(
        &self,
        root: &Path,
        registry: &Registry,
        path: &str,
    ) -> compile_worker::RecompileJob {
        self.begin_recompile_after(root, registry, path, std::time::Duration::ZERO)
    }

    /// [`Compiler::begin_recompile`], but the background thread sleeps for
    /// `delay` before compiling — test/tooling support for standing in for
    /// a large/slow compile, see `compile_worker::spawn_recompile_after`.
    #[doc(hidden)]
    pub fn begin_recompile_after(
        &self,
        root: &Path,
        registry: &Registry,
        path: &str,
        delay: std::time::Duration,
    ) -> compile_worker::RecompileJob {
        let snapshot = self.snapshot(registry);
        compile_worker::spawn_recompile_after(root.to_path_buf(), path.to_string(), snapshot, delay)
    }

    /// Apply a finished [`compile_worker::RecompileJob`]'s outcome (OBI-90,
    /// spec §7.2 step 4 up to `install`): invalidate every recompiled path
    /// in `self.session` — exactly like the synchronous [`Compiler::recompile`]
    /// does before it starts, just deferred until here so a concurrent
    /// `ensure_program` for a brand-new file during the background compile
    /// still sees the *old*, still-installed interface — then decode and
    /// **re-verify** (spec §5.8/§5.9: nothing runs unverified, including a
    /// `Module` that round-tripped across this `Send` boundary the same way
    /// it would across `encode`/`decode`) each program the background
    /// thread produced, wiring `parent` to whichever `Rc<CompiledProgram>`
    /// is live for that path (this batch first, then `registry`). Returns
    /// the new [`CompiledProgram`]s exactly like [`Compiler::recompile`],
    /// **not yet installed** — the caller still passes this to
    /// [`RegistryHost::install`].
    /// Apply a finished [`compile_worker::RecompileJob`]'s outcome (OBI-90,
    /// spec §7.2 step 4 up to `install`).
    ///
    /// **First (OBI-93 CTO review item 1, staleness):** re-snapshot
    /// `registry` right now and compare it with `begin_snapshot` (the one
    /// [`Compiler::begin_recompile`] captured before the background thread
    /// started). If any program in this batch, or the dependent set of
    /// `root_path`, has changed in the meantime — a second overlapping
    /// `update`, a synchronous `compile_object`, or a brand-new dependent
    /// loaded through `ensure_program` all count — refuse the whole batch
    /// (`Err`, nothing installed) rather than risk two builds of the same
    /// program both claiming the same version, or linking a dependent that
    /// no longer exists/appeared mid-flight. Same check for every
    /// out-of-batch ancestor the background compile actually consulted
    /// (OBI-93 review item 2): if its on-disk source has changed since it
    /// was installed, this batch was type-checked against an interface
    /// that is no longer what `registry.program(..)` would link it to, so
    /// refuse it too rather than silently mixing interfaces.
    ///
    /// **Then:** invalidate every recompiled path in `self.session` —
    /// exactly like the synchronous [`Compiler::recompile`] does before it
    /// starts, just deferred until here (and until *after* every check
    /// above has passed) so a concurrent `ensure_program` for a brand-new
    /// file during the background compile still sees the *old*,
    /// still-installed interface — then decode and **re-verify** (spec
    /// §5.8/§5.9: nothing runs unverified, including a `Module` that
    /// round-tripped across this `Send` boundary the same way it would
    /// across `encode`/`decode`) each program the background thread
    /// produced, wiring `parent` to whichever `Rc<CompiledProgram>` is live
    /// for that path (this batch first, then `registry`). Returns the new
    /// [`CompiledProgram`]s exactly like [`Compiler::recompile`], **not yet
    /// installed** — the caller still passes this to
    /// [`RegistryHost::install`].
    pub fn finish_recompile(
        &mut self,
        registry: &Registry,
        root_path: &str,
        begin_snapshot: &compile_worker::ProgramSnapshot,
        outcome: compile_worker::CompileOutcome,
    ) -> Result<HashMap<String, Rc<CompiledProgram>>, String> {
        let result = match outcome {
            compile_worker::CompileOutcome::Ready(r) => r,
            compile_worker::CompileOutcome::Failed(e) => return Err(e),
        };

        let now = compile_worker::ProgramSnapshot::capture(registry);
        for wp in &result.programs {
            if now.entry(&wp.path) != begin_snapshot.entry(&wp.path) {
                return Err(format!(
                    "stale: registry changed during background compile of {}; re-issue update",
                    wp.path
                ));
            }
        }
        let mut begin_deps = begin_snapshot.dependents_of(root_path);
        let mut now_deps = now.dependents_of(root_path);
        begin_deps.sort_unstable();
        now_deps.sort_unstable();
        if begin_deps != now_deps {
            return Err(format!(
                "stale: dependent set of {root_path} changed during background compile; re-issue update"
            ));
        }
        for (path, hash) in &result.ancestor_hashes {
            if now.source_hash_of(path) != Some(*hash) {
                return Err(format!(
                    "ancestor {path} changed on disk since it was installed; update it first"
                ));
            }
        }

        for p in &result.programs {
            self.session.invalidate(&p.path);
        }
        let mut new_set: HashMap<String, Rc<CompiledProgram>> = HashMap::new();
        for wp in result.programs {
            let module = loom_compiler::bytecode::decode(&wp.module_bytes)
                .map_err(|e| format!("{}: corrupt background compile result: {e}", wp.path))?;
            loom_compiler::verify::verify(&module)
                .map_err(|e| format!("{}: failed re-verification: {e}", wp.path))?;
            let var_specs: Vec<VarSpec> = wp
                .var_specs
                .iter()
                .map(|v| {
                    Ok(VarSpec {
                        name: Rc::from(v.name.as_str()),
                        ty: loom_compiler::bytecode::decode_ty(&v.ty_bytes)
                            .map_err(|e| format!("{}: corrupt var type: {e}", wp.path))?,
                        has_init: v.has_init,
                    })
                })
                .collect::<Result<_, String>>()?;
            let parent = wp
                .parent_path
                .as_ref()
                .and_then(|pp| new_set.get(pp).cloned().or_else(|| registry.program(pp)));
            let mut prog = CompiledProgram::new(module, wp.version, parent, var_specs);
            prog.non_public = wp.non_public.iter().map(|s| Rc::from(s.as_str())).collect();
            prog.source_hash = wp.source_hash;
            new_set.insert(wp.path.clone(), Rc::new(prog));
        }
        Ok(new_set)
    }
}

/// A verified [`Module`] plus the metadata dispatch needs: its own
/// (unmerged) name → function-slot table, and a link to its parent
/// program's [`CompiledProgram`] for `super::`/inherited lookups.
pub struct CompiledProgram {
    pub path: Rc<str>,
    pub version: u32,
    pub module: Module,
    /// name → index into `module.functions`, built once at link time
    /// (spec §5.8 "per-program dispatch tables"): every call to a name
    /// declared in this program is a single hash lookup here, never a
    /// linear scan of `module.functions`.
    dispatch: HashMap<Rc<str>, u32>,
    pub parent: Option<Rc<CompiledProgram>>,
    /// Every `var` declared *here* (not ancestors), in declaration order —
    /// the hot-reload migration key (spec §7.2/§7.3) and, filtered to
    /// `has_init`, the order [`synth_init_function`]'s `$init` parameters
    /// expect (see [`CompiledProgram::init_specs`]).
    pub var_specs: Vec<VarSpec>,
    /// Functions declared here that are *not* `pub`, so
    /// [`RegistryHost::call_other`] (`ob.f()`) must refuse them. Filled by
    /// [`compile_hir_program`] from HIR visibility; empty for hand-assembled
    /// test modules built directly with [`CompiledProgram::new`].
    pub non_public: std::collections::HashSet<Rc<str>>,
    /// [`compile_worker::source_hash`] of this program's own `.wf` file at
    /// the moment it was compiled (OBI-93 CTO review item 2: lets a later
    /// background compile that treats this program as an out-of-batch
    /// ancestor detect that it has drifted on disk since). `0` for
    /// hand-assembled test modules built directly with
    /// [`CompiledProgram::new`] that never went through disk at all — not
    /// a guaranteed-unused sentinel, just this type's default.
    pub source_hash: u64,
    /// Hash of this program's **variable layout** (spec §7.2/§7.3): every
    /// declared-here var's `(name, Ty)`, folded with the parent's own
    /// `schema_hash` so a change anywhere in the inherit chain propagates.
    /// Two versions with an *equal* `schema_hash` differ only in function
    /// bodies, so [`RegistryHost::upgrade`] can skip straight to an O(1)
    /// pointer swap: no var copy, no `$init` re-run, no `upgrade()` call
    /// (spec §7.3 "the common case"). Each var's type contributes its
    /// recursive [`loom_compiler::ty::Ty::schema_hash`] (spec r5 D27), so a
    /// struct/enum field-type change reached through a var changes this
    /// hash, while a pure field/variant reorder does not.
    pub schema_hash: u64,
}

/// [`CompiledProgram::schema_hash`]: fold `parent_hash` with every
/// declared-here var's `(name, Ty)`, in declaration order. Declaration
/// order (not sorted) is enough here because these are a *program*'s own
/// vars, not a struct/enum's fields — reordering `var` declarations in
/// source is not a change spec r5 promises is hash-stable (only struct
/// fields/enum variants are, via their own recursive type schema hash).
///
/// FNV-1a over an explicit little-endian encoding (same scheme as
/// `Ty::schema_hash`), not `DefaultHasher`: this value is compared across
/// processes and persisted, so it must be stable across Rust releases.
fn compute_schema_hash(var_specs: &[VarSpec], parent_hash: u64) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    fn feed(h: &mut u64, bytes: &[u8]) {
        for &b in bytes {
            *h ^= u64::from(b);
            *h = h.wrapping_mul(PRIME);
        }
    }
    let mut h = OFFSET;
    feed(&mut h, &parent_hash.to_le_bytes());
    feed(&mut h, &(var_specs.len() as u64).to_le_bytes());
    for v in var_specs {
        feed(&mut h, &(v.name.len() as u64).to_le_bytes());
        feed(&mut h, v.name.as_bytes());
        feed(&mut h, &v.ty.schema_hash().to_le_bytes());
    }
    h
}

impl ProgramCode for CompiledProgram {
    fn module(&self) -> &Module {
        &self.module
    }

    fn version(&self) -> u32 {
        self.version
    }
}

impl CompiledProgram {
    pub fn new(
        module: Module,
        version: u32,
        parent: Option<Rc<CompiledProgram>>,
        var_specs: Vec<VarSpec>,
    ) -> Self {
        let path = module.path.clone();
        let dispatch = module
            .functions
            .iter()
            .enumerate()
            .map(|(i, f)| (module.strings[f.name as usize].clone(), i as u32))
            .collect();
        let parent_hash = parent.as_ref().map(|p| p.schema_hash).unwrap_or(0);
        let schema_hash = compute_schema_hash(&var_specs, parent_hash);
        CompiledProgram {
            path,
            version,
            module,
            dispatch,
            parent,
            var_specs,
            non_public: Default::default(),
            source_hash: 0,
            schema_hash,
        }
    }

    /// `var_specs` filtered to the ones with an initialiser, in the order
    /// `$init`'s `bool` parameters expect (must track `synth_init_function`'s
    /// filter+order exactly — both iterate `var_specs`/`hir::Program.vars`
    /// in declaration order and filter on the same predicate).
    pub fn init_specs(&self) -> impl Iterator<Item = &VarSpec> {
        self.var_specs.iter().filter(|v| v.has_init)
    }

    /// Resolve `name` starting at this program and walking toward the
    /// root, most-derived first — i.e. virtual dispatch when `self` is
    /// the object's own (leaf) program: an override in a subclass is
    /// already the program this method is called on, so this always
    /// finds the most-derived definition first.
    pub fn resolve(self: &Rc<Self>, name: &str) -> Option<(Rc<CompiledProgram>, u32)> {
        let mut cur = self.clone();
        loop {
            if let Some(&idx) = cur.dispatch.get(name) {
                return Some((cur, idx));
            }
            cur = cur.parent.clone()?;
        }
    }

    /// Resolve `name` declared in *this exact* program only (no walking to
    /// parents) — what `super::name()` after locating the target ancestor
    /// program needs.
    pub fn resolve_own(&self, name: &str) -> Option<u32> {
        self.dispatch.get(name).copied()
    }

    pub fn chain(self: &Rc<Self>) -> Vec<Rc<CompiledProgram>> {
        let mut v = Vec::new();
        let mut cur = Some(self.clone());
        while let Some(p) = cur {
            cur = p.parent.clone();
            v.push(p);
        }
        v.reverse();
        v
    }

    /// True if `path` is a strict ancestor of this program (mirrors
    /// `crate::program::Program::inherits`, used the same way: finding
    /// every currently-registered dependent of a program being
    /// recompiled).
    pub fn inherits(&self, path: &str) -> bool {
        let mut cur = self.parent.as_deref();
        while let Some(p) = cur {
            if &*p.path == path {
                return true;
            }
            cur = p.parent.as_deref();
        }
        false
    }
}

/// An object's variables, keyed by (declaring program path, name) exactly
/// like the tree-walker's `crate::object::Vars` (§7.2: hot reload matches
/// state by declaring program + name).
pub type Vars = HashMap<(Rc<str>, Rc<str>), Value>;

pub struct BcObject {
    /// `/std/sword` (blueprint) or `/std/sword#12` (clone).
    pub name: String,
    pub program: Rc<CompiledProgram>,
    pub vars: Vars,
    pub env: Option<ObjectId>,
    pub inventory: Vec<ObjectId>,
    /// Connection bound to this object (interactive), if any.
    pub conn: Option<u64>,
    /// Sum of [`heap::cost`] over every value currently in `vars` (spec
    /// r5 §5.2.1 "memory quotas with per-object accounting", deep
    /// accounting per OBI-80), maintained incrementally by
    /// [`RegistryHost::store_global`] so a quota check never has to
    /// re-walk `vars`.
    pub mem_bytes: u64,
    /// [`Registry::install_generation`] as of the last time
    /// [`RegistryHost::ensure_current`] checked whether this object's
    /// program is still the one currently registered for its path (spec
    /// §7.2/§7.3 "lazy per-instance upgrade on access", OBI-89). Equal to
    /// the *current* `install_generation` means "already checked, nothing
    /// to do" — the common steady-state case between recompiles — so a
    /// dispatch never re-does the program-registry lookup per call once no
    /// recompile is in flight, only the one `u64` compare.
    pub checked_generation: u64,
    /// Owner (spec §5.7, OBI-35 D-S1.1): from the master's
    /// `creator_file(path)` at load/clone, never changes.
    pub uid: Sym,
    /// Effective uid for rights: starts equal to `uid`, changed only by a
    /// master-validated `seteuid`.
    pub euid: Sym,
}

impl BcObject {
    /// A fresh, unnamed, unplaced object over `program` — the common case
    /// for tests and [`RegistryHost::instantiate`], which sets `name`
    /// afterwards (mirrors `crate::object::Object`'s tree-walker fields,
    /// minus the ones only `World` fills in).
    pub fn new(program: Rc<CompiledProgram>) -> BcObject {
        BcObject {
            name: String::new(),
            program,
            vars: Vars::new(),
            env: None,
            inventory: Vec::new(),
            conn: None,
            mem_bytes: 0,
            checked_generation: 0,
            uid: ROOT,
            euid: ROOT,
        }
    }

    /// Re-derive [`BcObject::mem_bytes`] from `vars` from scratch. Needed
    /// wherever `vars` is replaced wholesale rather than written through
    /// [`RegistryHost::store_global`] (hot-reload `upgrade`, `install`
    /// rollback), or the incremental count drifts: vars dropped by a
    /// migration would stay charged forever.
    pub fn recompute_mem_bytes(&mut self) {
        self.mem_bytes = self.vars.values().map(heap::cost).sum();
    }
}

struct Slot {
    generation: u32,
    obj: Option<BcObject>,
}

/// In-process `loom_cow_copies_total{program}` counter (spec r5 §5.2.1,
/// D24): how many times a write through `Value::array_mut`/`map_mut`
/// actually had to clone a shared buffer, per executing program path.
///
/// **Where this is collected/exposed, and why (flagged, not silently
/// decided):** the repo has no metrics-export story outside
/// `loom-net`/`loom-persist` yet, so this is *only* an in-process counter
/// table, owned by [`Registry`] (long-lived, one per [`crate::world::World`])
/// and read back via `World::cow_copies_total`. Wiring it to an actual
/// `/metrics` (or similar) endpoint is a cross-seam decision — whoever owns
/// `loom-net`'s HTTP/ops surface, or the CTO if that is not yet decided —
/// not made here.
#[derive(Default)]
pub struct CowMetrics {
    counts: HashMap<String, u64>,
}

impl CowMetrics {
    pub fn record(&mut self, program: &str) {
        *self.counts.entry(program.to_string()).or_insert(0) += 1;
    }

    pub fn get(&self, program: &str) -> u64 {
        self.counts.get(program).copied().unwrap_or(0)
    }
}

/// A slab of [`BcObject`]s addressed by generational id, and the program
/// registry every object's `program` field points into. Kept separate
/// from `crate::object::ObjectTable` (which is specialised to the
/// tree-walker's `crate::program::Program`) rather than made generic over
/// it, to avoid touching the Phase 0 conformance path in this slice.
#[derive(Default)]
pub struct Registry {
    slots: Vec<Slot>,
    free: Vec<u32>,
    pub programs: HashMap<String, Rc<CompiledProgram>>,
    /// Object names (`/std/room`, `/std/room#3`) → id, kept here (not in
    /// `World`) because efuns like `find_object`/`object_name` need it from
    /// inside a running call, mirroring `crate::world::State::names`.
    pub names: HashMap<String, ObjectId>,
    pub next_clone: u64,
    /// Connection id → the object it is bound to (mirrors
    /// `crate::world::State::conns`).
    pub conns: HashMap<u64, ObjectId>,
    /// Connection id → the order it was (most recently) bound in (OBI-85
    /// `users()`: "in bind order"). Stale entries for connections no
    /// longer in `conns` are harmless (never read except through `conns`).
    bind_seq: HashMap<u64, u64>,
    next_bind_seq: u64,
    /// `random()`'s PRNG (OBI-85), seeded once at boot.
    pub rng: crate::rng::Rng,
    /// `loom_cow_copies_total{program}` (spec r5 §5.2.1, D24); see
    /// [`CowMetrics`].
    pub cow_metrics: CowMetrics,
    /// `atomic fn` journal (spec r5 §5.2.1, OBI-32): every object-variable
    /// write and `clone_object` while [`Self::atomic_active`] is nonzero,
    /// oldest first, undoable back to any earlier mark by
    /// [`Self::journal_rollback`]. Empty (and every write skips recording)
    /// whenever no atomic scope is open — journaling has no cost outside
    /// one.
    journal: Vec<JournalEntry>,
    /// Depth of nested `atomic fn` calls currently on the interpreter's
    /// frame stack. The journal is only cleared (nothing left that could
    /// ever need undoing) when this returns to zero: a nested atomic call
    /// that itself commits does not clear entries an *outer* atomic scope
    /// may still need to roll back if it later fails.
    atomic_active: u32,
    /// Bumped by every [`RegistryHost::install`] call (spec §7.2/§7.3,
    /// OBI-89: "lazy per-instance upgrade on access"): the cheap
    /// per-object staleness check ([`RegistryHost::ensure_current`])
    /// compares this to [`BcObject::checked_generation`] instead of doing
    /// a `programs` lookup on every single call — a mismatch is what
    /// tells `ensure_current` it actually has to look, and possibly
    /// migrate.
    pub install_generation: u64,
    /// Warnings from a *lazy* per-instance upgrade (an object accessed
    /// after a recompile whose migration or `upgrade()` hook failed and
    /// was rolled back), appended by [`RegistryHost::ensure_current`] and
    /// drained by `World::take_lazy_upgrade_warnings` for
    /// introspection/tests — a lazy trigger has no direct caller to hand
    /// an [`UpgradeWarning`] to the way [`RegistryHost::install`]'s own
    /// (eager, at-install-time) callers do, mirroring how
    /// `World::tick`'s heartbeat/call_out errors have nowhere to report
    /// to either (spec §7.2 step 6.4: "not fatal").
    pub lazy_upgrade_warnings: Vec<UpgradeWarning>,
    /// uid/euid interner (OBI-35 D-S1.1); index 0 is `root`.
    pub syms: Interner,
}

/// One undoable effect recorded while an `atomic fn` scope is open.
enum JournalEntry {
    /// An object-variable write (`Op::StoreGlobal`): includes an array/map
    /// mutation written back through `IndexSet` + `StoreGlobal` (r5
    /// amendment: a container is a value, so mutating one *is* an
    /// object-variable write, journaled as one `Rc` clone of the old
    /// value — that clone is exactly `old`, cheap by construction since
    /// containers are copy-on-write).
    VarWrite {
        obj: ObjectId,
        key: (Rc<str>, Rc<str>),
        /// `None` if the variable had no entry yet (a fresh object whose
        /// initialiser had not run for it); rollback removes the entry
        /// rather than inserting a spurious one.
        old: Option<Value>,
    },
    /// `clone_object`: rollback deletes the clone. Does not attempt to
    /// undo anything the clone's own `create()` did to *other* objects
    /// beyond their variables (those are separately journaled `VarWrite`
    /// entries) — its own `move_to`/inventory linkage *is* covered, by a
    /// separate `Move` entry (below) pushed by the same call that moved
    /// it; replay runs most-recent-first, so that `Move` is always
    /// undone before this `Clone` entry deletes the object.
    Clone { obj: ObjectId, name: String },
    /// `move_to` (`Registry::move_object`): rollback relinks `obj` back
    /// into `old_env`'s inventory at `old_index` (or unenvironed, if
    /// `old_env` is `None`) instead of leaving it in whatever `atomic`
    /// moved it to. Spec §5.2.1 names inventory moves as *the* `atomic`
    /// use case (`transfer_to`); without this, a failed `atomic fn` left
    /// `move_to` applied, and `clone_object` + `move_to(room)` + throw
    /// left a dangling id in `room.inventory` after the clone itself was
    /// deleted.
    Move {
        obj: ObjectId,
        old_env: Option<ObjectId>,
        old_index: Option<usize>,
    },
}

impl Registry {
    pub fn register_program(&mut self, prog: Rc<CompiledProgram>) {
        self.programs.insert(prog.path.to_string(), prog);
    }

    pub fn program(&self, path: &str) -> Option<Rc<CompiledProgram>> {
        self.programs.get(path).cloned()
    }

    pub fn insert(&mut self, obj: BcObject) -> ObjectId {
        if let Some(index) = self.free.pop() {
            let slot = &mut self.slots[index as usize];
            slot.generation = slot.generation.wrapping_add(1);
            slot.obj = Some(obj);
            ObjectId {
                index,
                generation: slot.generation,
            }
        } else {
            let index = self.slots.len() as u32;
            self.slots.push(Slot {
                generation: 0,
                obj: Some(obj),
            });
            ObjectId {
                index,
                generation: 0,
            }
        }
    }

    pub fn get(&self, id: ObjectId) -> Option<&BcObject> {
        self.slots
            .get(id.index as usize)
            .filter(|s| s.generation == id.generation)
            .and_then(|s| s.obj.as_ref())
    }

    pub fn get_mut(&mut self, id: ObjectId) -> Option<&mut BcObject> {
        self.slots
            .get_mut(id.index as usize)
            .filter(|s| s.generation == id.generation)
            .and_then(|s| s.obj.as_mut())
    }

    /// Remove an object; its id becomes stale (mirrors
    /// `crate::object::ObjectTable::remove`).
    pub fn remove(&mut self, id: ObjectId) -> Option<BcObject> {
        let slot = self.slots.get_mut(id.index as usize)?;
        if slot.generation != id.generation {
            return None;
        }
        let obj = slot.obj.take()?;
        self.free.push(id.index);
        Some(obj)
    }

    /// Every live object id (mirrors `crate::object::ObjectTable::ids`),
    /// used by [`RegistryHost::install`] to find every object an upgrade
    /// set affects.
    pub fn ids(&self) -> Vec<ObjectId> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.obj.is_some())
            .map(|(i, s)| ObjectId {
                index: i as u32,
                generation: s.generation,
            })
            .collect()
    }

    /// Move `id` out of its current environment (if any) and into `dest`'s
    /// inventory (mirrors `crate::world::State::move_object`; the caller
    /// is responsible for cycle checks, see `RegistryHost`'s `move_to`
    /// efun). Journals a [`JournalEntry::Move`] if an `atomic` scope is
    /// open (spec §5.2.1), recording exactly enough (`old_env`,
    /// `old_index`) to relink `id` back into its original inventory slot
    /// on rollback rather than merely appending it back to the end.
    pub fn move_object(&mut self, id: ObjectId, dest: ObjectId) {
        let old_env = self.get(id).and_then(|o| o.env);
        let old_index = old_env.and_then(|old| {
            self.get(old)
                .and_then(|o| o.inventory.iter().position(|i| *i == id))
        });
        if let Some(old) = old_env
            && let Some(o) = self.get_mut(old)
        {
            o.inventory.retain(|i| *i != id);
        }
        if let Some(d) = self.get_mut(dest) {
            d.inventory.push(id);
        }
        if let Some(o) = self.get_mut(id) {
            o.env = Some(dest);
        }
        self.journal_move(id, old_env, old_index);
    }

    /// Bind connection `conn` to object `id` (unbinding both sides'
    /// previous partners), mirrors `crate::world::State::bind`.
    pub fn bind(&mut self, conn: u64, id: ObjectId) {
        if let Some(prev) = self.conns.insert(conn, id)
            && prev != id
            && let Some(o) = self.get_mut(prev)
        {
            o.conn = None;
        }
        let old_conn = self.get(id).and_then(|o| o.conn);
        if let Some(old_conn) = old_conn
            && old_conn != conn
        {
            self.conns.remove(&old_conn);
            self.bind_seq.remove(&old_conn);
        }
        if let Some(o) = self.get_mut(id) {
            o.conn = Some(conn);
        }
        self.next_bind_seq += 1;
        self.bind_seq.insert(conn, self.next_bind_seq);
    }

    /// Every object with a bound connection, in bind order (OBI-85
    /// `users()`).
    pub fn users_in_bind_order(&self) -> Vec<ObjectId> {
        let mut v: Vec<(u64, ObjectId)> = self.conns.iter().map(|(c, o)| (*c, *o)).collect();
        v.sort_by_key(|(c, _)| self.bind_seq.get(c).copied().unwrap_or(0));
        v.into_iter().map(|(_, o)| o).collect()
    }

    /// Destroy `ob` (spec: inventory moves up into its own environment or
    /// is dropped loose, `call_out`/heartbeat cancelled, name/connection
    /// unbound); a no-op if `ob` is already gone. Returns the connection
    /// that was bound to `ob`, if any, so the caller can close it (OBI-85
    /// `destruct()`: "If `ob` is bound to a connection, close the
    /// connection too"). Shared by `World::destruct` (the pre-efun
    /// primitive, used by tests) and the `destruct` efun itself.
    pub fn destruct(
        &mut self,
        ob: ObjectId,
        scheduler: &mut crate::scheduler::Scheduler,
    ) -> Option<u64> {
        let existing_env = self.get(ob).map(|o| o.env)?;
        let inventory = self
            .get(ob)
            .map(|o| o.inventory.clone())
            .unwrap_or_default();
        for item in inventory {
            match existing_env {
                Some(dest) => self.move_object(item, dest),
                None => {
                    if let Some(i) = self.get_mut(item) {
                        i.env = None;
                    }
                }
            }
        }
        if let Some(env) = existing_env
            && let Some(o) = self.get_mut(env)
        {
            o.inventory.retain(|i| *i != ob);
        }
        let conn = self.get(ob).and_then(|o| o.conn);
        if let Some(c) = conn {
            self.conns.remove(&c);
            self.bind_seq.remove(&c);
        }
        let name = self.obj_name(ob);
        self.names.remove(&name);
        scheduler.remove_for_object(ob);
        self.remove(ob);
        conn
    }

    /// The name `id` is registered under, or a placeholder if it was
    /// destructed or never named (mirrors `crate::interp::Exec::obj_name`).
    pub fn obj_name(&self, id: ObjectId) -> String {
        self.get(id)
            .map(|o| o.name.clone())
            .unwrap_or_else(|| format!("<destructed:{id:?}>"))
    }

    /// [`Host::begin_atomic`]: open a journal scope, returning its mark
    /// (the journal length at this instant — rollback undoes everything
    /// recorded after it).
    fn journal_begin(&mut self) -> u64 {
        self.atomic_active += 1;
        self.journal.len() as u64
    }

    /// [`Host::commit_atomic`]: the scope at `mark` returned normally.
    /// Only actually discards journal entries once no atomic scope is
    /// left open at all (see [`Registry::atomic_active`]'s doc) — an
    /// enclosing scope may still need everything recorded so far.
    fn journal_commit(&mut self, _mark: u64) {
        self.atomic_active = self.atomic_active.saturating_sub(1);
        if self.atomic_active == 0 {
            self.journal.clear();
        }
    }

    /// [`Host::rollback_atomic`]: undo every entry recorded since `mark`,
    /// most recent first (so a var written twice restores its
    /// *original* value, not an intermediate one), then close this scope.
    fn journal_rollback(&mut self, mark: u64) {
        while self.journal.len() as u64 > mark {
            match self.journal.pop().unwrap() {
                JournalEntry::VarWrite { obj, key, old } => {
                    if let Some(o) = self.get_mut(obj) {
                        match old {
                            Some(v) => {
                                o.vars.insert(key, v);
                            }
                            None => {
                                o.vars.remove(&key);
                            }
                        }
                    }
                }
                JournalEntry::Clone { obj, name } => {
                    self.remove(obj);
                    self.names.remove(&name);
                }
                JournalEntry::Move {
                    obj,
                    old_env,
                    old_index,
                } => {
                    let cur_env = self.get(obj).and_then(|o| o.env);
                    if let Some(cur) = cur_env
                        && let Some(o) = self.get_mut(cur)
                    {
                        o.inventory.retain(|i| *i != obj);
                    }
                    if let Some(old) = old_env
                        && let Some(o) = self.get_mut(old)
                    {
                        let idx = old_index.unwrap_or(o.inventory.len());
                        let idx = idx.min(o.inventory.len());
                        o.inventory.insert(idx, obj);
                    }
                    if let Some(o) = self.get_mut(obj) {
                        o.env = old_env;
                    }
                }
            }
        }
        self.atomic_active = self.atomic_active.saturating_sub(1);
    }

    /// Record an object-variable write for the currently open atomic
    /// scope(s), if any (a no-op, no allocation, whenever none is open).
    fn journal_var_write(&mut self, obj: ObjectId, key: (Rc<str>, Rc<str>), old: Option<Value>) {
        if self.atomic_active > 0 {
            self.journal.push(JournalEntry::VarWrite { obj, key, old });
        }
    }

    /// Record a `clone_object`, if an atomic scope is open.
    fn journal_clone(&mut self, obj: ObjectId, name: String) {
        if self.atomic_active > 0 {
            self.journal.push(JournalEntry::Clone { obj, name });
        }
    }

    /// Record a `move_to`, if an atomic scope is open.
    fn journal_move(&mut self, obj: ObjectId, old_env: Option<ObjectId>, old_index: Option<usize>) {
        if self.atomic_active > 0 {
            self.journal.push(JournalEntry::Move {
                obj,
                old_env,
                old_index,
            });
        }
    }

    /// No atomic scope should ever still be open, nor anything left in
    /// its journal, at a `World::exec` boundary (CTO review of OBI-32,
    /// should-do #3): every `atomic fn` call opens exactly one scope in
    /// `Interpreter::push_call` and closes it in either `Op::Return`
    /// (commit) or `Interpreter::run`'s error-unwind path (rollback), so
    /// this only fires if some future suspend/unusual-exit path manages
    /// to leave one open — which would otherwise silently journal every
    /// write from then on, forever, since `journal_commit` only clears
    /// the journal once `atomic_active` returns to zero.
    pub(crate) fn debug_assert_atomic_scope_closed(&self) {
        debug_assert!(
            self.atomic_active == 0 && self.journal.is_empty(),
            "atomic scope leaked across a World::exec boundary (atomic_active={}, journal has {} entries)",
            self.atomic_active,
            self.journal.len()
        );
    }
}

/// A [`Host`] backed by a real [`Registry`] (multiple objects, multiple
/// programs, inheritance): virtual dispatch resolves against the calling
/// object's *own* program chain, `super::` resolves against a named
/// ancestor program, and `recv.name()` resolves against the receiver
/// object's program chain, matching spec §5.8/§5.9's dispatch semantics.
pub struct RegistryHost<'a> {
    pub registry: &'a mut Registry,
    /// The object each currently-running (possibly nested) call is
    /// executing as; `self_object()` is always the top.
    self_stack: Vec<ObjectId>,
    /// Guard stack (OBI-35 D-S1.2): `guards.last()` is the set of distinct
    /// principals on the stack down to the nearest cut. Pushed with every
    /// `self_stack` push, by creator frames and by cuts.
    guards: Vec<GuardSet>,
    /// Euid currently being evaluated by a `valid_*` apply, innermost
    /// last (`effective_principal()`).
    evaluating: Vec<Sym>,
    /// Ticks to charge the running interpreter after the current efun
    /// returns (policy cache misses, D-S1.3); see `Host::take_extra_ticks`.
    extra_ticks: u64,
    /// One-entry memo for [`Self::push_self`]: `(parent, principal) →
    /// parent ∪ {principal}`. A loop calling into another principal's
    /// object would otherwise allocate a fresh set on every call; holding
    /// `parent` keeps its `Rc` alive, so pointer equality is sound.
    push_memo: Option<(GuardSet, Principal, GuardSet)>,
    pub limits: Limits,
    pub ticks_left: u64,
    /// Driver-level context (network host, compiler, `this_player`,
    /// bound connection): only `World` provides this (`None` for the
    /// unit tests in this module, which never call a driver efun).
    driver: Option<Driver<'a>>,
    /// Stack pointer at construction, for [`NESTED_CALL_STACK_BUDGET`].
    stack_base: usize,
    /// Per-call-site inline cache (spec §5.8): `Op::Call`/`Op::CallOther`
    /// site → last resolution, valid as long as [`CacheEntry::guard`] is
    /// still `Rc::ptr_eq` to the current receiver's leaf program. Scoped to
    /// this `RegistryHost`'s lifetime, i.e. one top-level `World::call`/
    /// driver entry (a fresh `RegistryHost` is built per call, see
    /// `World::exec`) — which already covers the hot case a cache exists
    /// for: a tight loop of monomorphic calls inside one running function.
    call_cache: HashMap<CallSite, CacheEntry>,
}

/// One [`RegistryHost::call_cache`] entry: what `dispatch` resolved to last
/// time this call site ran, and the guard to re-check before trusting it.
struct CacheEntry {
    /// The receiver's leaf program at resolution time (self's own program
    /// for `Virtual`/`Static`, `recv`'s for `Other`). A hot-reload `upgrade`
    /// always installs a brand-new `Rc<CompiledProgram>` on the object (see
    /// `RegistryHost::upgrade`), so this pointer naturally stops matching
    /// after any upgrade — no separate version check or explicit
    /// invalidation needed.
    guard: Rc<CompiledProgram>,
    target: Rc<CompiledProgram>,
    func: u32,
}

/// Everything a driver efun (`send`, `bind_connection`, `compile_object`,
/// …) needs beyond the object/program registry, borrowed for the
/// duration of one [`RegistryHost`] (mirrors `crate::interp::Exec`'s
/// `host`/`this_player`/`conn`/`compiling` fields).
struct Driver<'a> {
    compiler: &'a mut Compiler,
    net: &'a mut dyn crate::host::Host,
    this_player: Option<ObjectId>,
    conn: Option<u64>,
    master: Option<ObjectId>,
    /// `call_out`/heartbeat scheduler (OBI-33), owned by `World`.
    scheduler: &'a mut crate::scheduler::Scheduler,
    /// `account_create`/`account_login` bookkeeping (OBI-85), owned by
    /// `World`; see `crate::world::AccountsCtx`.
    accounts: crate::world::AccountsCtx<'a>,
    /// Decision cache, policy epoch and audit (OBI-35), owned by `World`.
    security: &'a mut SecurityState,
    /// The S2 roles snapshot (OBI-36 D-S2.1), owned by `World`; cloned
    /// (an `Arc` bump) into every `RegistryHost` so a snapshot swap mid-way
    /// through some other execution never changes what *this* one sees.
    roles: std::sync::Arc<crate::roles::RolesSnapshot>,
    /// `roles_set_tier`/... bookkeeping (OBI-36 D-S2.2), owned by `World`;
    /// see `crate::world::RolesCtx`.
    roles_ctx: crate::world::RolesCtx<'a>,
    /// The euid of the interactive whose input started this execution
    /// (D-S2.2's actor rule), fixed at the input cut by `World::input` and
    /// never re-read; `None` for every other entry point (`connect`,
    /// `disconnect`, a heartbeat, a call_out, a `roles_result`/
    /// `account_result` drain, a driver-started apply/introspection call).
    input_actor: Option<Sym>,
    /// Mudlib root, for the `read_file`/`write_file` VFS.
    root: PathBuf,
}

/// Approximate current native stack position (mirrors the tree-walker's
/// `crate::interp::stack_addr`, kept for the same reason: see
/// [`NESTED_CALL_STACK_BUDGET`]).
#[inline(never)]
fn stack_addr() -> usize {
    let marker = 0u8;
    std::hint::black_box(&marker) as *const u8 as usize
}

/// Native-stack budget for [`RegistryHost::call_in`]'s nested
/// `Interpreter`s. Ordinary Weft calls no longer nest (D26, see the module
/// doc); this only bounds driver-started runs that recurse through efuns
/// (e.g. `create()` calling `load_object` of an object whose `create()`
/// calls `load_object` …). A stack-pointer distance, not a counter, for
/// the same reason as the tree-walker's `max_stack_bytes`: a debug build
/// costs far more native stack per nested run than a release build.
const NESTED_CALL_STACK_BUDGET: usize = 1_000_000;

/// Bench/test-only escape hatch: `LOOM_VM_DISABLE_INLINE_CACHE=1` makes
/// [`RegistryHost::dispatch`]/[`RegistryHost::dispatch_cached`] behave as
/// they did before the per-call-site inline cache existed (every call
/// re-does the dispatch-table hash lookup), so `examples/vm_bench.rs` can
/// report cache-on vs. cache-off numbers for the *same* binary without a
/// second build. Not a runtime feature flag — nothing in `World`'s own API
/// reads this.
fn inline_cache_disabled() -> bool {
    static DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DISABLED.get_or_init(|| std::env::var_os("LOOM_VM_DISABLE_INLINE_CACHE").is_some())
}

impl<'a> RegistryHost<'a> {
    /// Resolve `name` on `recv`'s program chain (most-derived first). With
    /// `require_pub`, a non-`pub` target is refused with the same wording
    /// the Phase 0 tree-walker used.
    /// Resolve `name` on `recv`'s program chain (most-derived first). With
    /// `require_pub`, a non-`pub` target is refused with the same wording
    /// the Phase 0 tree-walker used. Also returns `recv`'s own (leaf)
    /// program, unwalked — the inline-cache guard: two calls through this
    /// same call site resolve identically as long as the receiving
    /// object's *leaf* program is `Rc::ptr_eq` to what was cached, whether
    /// or not `name` is inherited from an ancestor of it (see
    /// [`RegistryHost::dispatch`]).
    fn resolve_on(
        &mut self,
        recv: Value,
        name: &str,
        require_pub: bool,
    ) -> R<(ObjectId, Rc<CompiledProgram>, Rc<CompiledProgram>, u32)> {
        let Value::Object(recv_id) = recv else {
            return Err(RtError::new(format!(
                "cannot call `{name}` on a {}",
                recv.type_name()
            )));
        };
        // Spec §7.2/§7.3 "lazy per-instance upgrade on access" (OBI-89):
        // any cross-object call is exactly such an access, whether or not
        // `recv` is `self` — bring it up to whatever program is currently
        // registered for its path before resolving `name` against it.
        self.ensure_current(recv_id);
        let prog = self
            .registry
            .get(recv_id)
            .ok_or_else(|| RtError::new(format!("call `{name}` on a destructed object")))?
            .program
            .clone();
        let (target, idx) = prog
            .resolve(name)
            .ok_or_else(|| RtError::new(format!("no function `{name}` on {}", prog.path)))?;
        if require_pub && target.non_public.contains(name) {
            return Err(RtError::new(format!(
                "`{name}` in {} is not `pub`, so other objects cannot call it",
                target.path
            )));
        }
        Ok((recv_id, prog, target, idx))
    }

    /// `super::name()` / `program::name()`: `name` declared in exactly
    /// `program` (an ancestor of self's program), never an override. Also
    /// returns self's own (leaf) program as the inline-cache guard; see
    /// [`RegistryHost::resolve_on`].
    fn resolve_static(
        &self,
        program: &str,
        name: &str,
    ) -> R<(ObjectId, Rc<CompiledProgram>, Rc<CompiledProgram>, u32)> {
        let self_id = self.self_object();
        let prog = self
            .registry
            .get(self_id)
            .ok_or_else(|| RtError::new("call on a destructed object"))?
            .program
            .clone();
        let target = prog
            .chain()
            .into_iter()
            .find(|p| &*p.path == program)
            .ok_or_else(|| {
                RtError::new(format!("`{program}` is not an ancestor of {}", prog.path))
            })?;
        let idx = target
            .resolve_own(name)
            .ok_or_else(|| RtError::new(format!("no function `{name}` in {program}")))?;
        Ok((self_id, prog, target, idx))
    }

    fn resolve_target(
        &mut self,
        t: CallTarget<'_>,
    ) -> R<(ObjectId, Rc<CompiledProgram>, Rc<CompiledProgram>, u32)> {
        match t {
            CallTarget::Static { program, name } => self.resolve_static(program, name),
            // Unqualified `f()` on self: internal/private visibility was
            // already enforced by the checker, so no `pub` check here.
            CallTarget::Virtual { name } => {
                self.resolve_on(Value::Object(self.self_object()), name, false)
            }
            // `ob.f()`: `ob` may be generically typed (`object`/`any`), so
            // the checker cannot always see the callee; enforce `pub` here.
            CallTarget::Other { recv, name } => self.resolve_on(recv, name, true),
        }
    }

    /// Run-to-completion form of a resolved call (nested [`Interpreter`]);
    /// only reached via the non-flat `Host::call_*` entry points.
    fn run_target(&mut self, t: CallTarget<'_>, args: Vec<Value>) -> R<Value> {
        let (on, _guard, target, idx) = self.resolve_target(t)?;
        self.call_in(on, &target, idx, args)
    }

    /// The inline-cache guard `dispatch`/`dispatch_cached` would resolve
    /// `recv`/self against *right now*, without doing the actual name
    /// lookup: self's leaf program for `Virtual`/`Static` (`recv ==
    /// None`), or `recv`'s for `Other`. `None` if the relevant object is
    /// already destructed or `recv` is not an object (the slow path's own
    /// error reporting handles those cases).
    ///
    /// Also returns the receiver object itself: a cache hit must run the
    /// callee on *this* receiver, never on the object the entry was
    /// resolved for (two clones of one program share the guard).
    fn current_guard(&self, recv: Option<&Value>) -> Option<(ObjectId, Rc<CompiledProgram>)> {
        let id = match recv {
            None => self.self_object(),
            Some(Value::Object(id)) => *id,
            Some(_) => return None,
        };
        self.registry.get(id).map(|o| (id, o.program.clone()))
    }

    /// Spec §7.2/§7.3 "lazy per-instance upgrade on access" (default mode,
    /// OBI-89): before running anything *as* or *against* `id` from an
    /// entry point that did not just create it — a cross-object call
    /// ([`RegistryHost::resolve_on`]), a driver-started apply
    /// (`create()`/`heartbeat()`/a `call_out` callback/`process_input`/…,
    /// see [`RegistryHost::call_apply`]/[`RegistryHost::call_on`]), or the
    /// inline-cache fast path ([`RegistryHost::dispatch_cached`]) — bring
    /// it up to whatever program is now registered for its path, if
    /// anything has changed since [`BcObject::checked_generation`] was
    /// last stamped. A no-op (one `u64` compare, no lookup) once nothing
    /// has installed since `id` was last checked: the common steady-state
    /// case between recompiles, so this never re-does a
    /// `Registry::programs` lookup per call while no recompile is in
    /// flight.
    ///
    /// A failing migration (rolled back to the old program/vars by
    /// [`RegistryHost::upgrade`]) is queued to
    /// [`Registry::lazy_upgrade_warnings`] rather than propagated: a lazy
    /// trigger has no direct caller to hand an [`UpgradeWarning`] to
    /// (mirrors how `World::tick`'s heartbeat/call_out errors are
    /// swallowed — spec §7.2 step 6.4, "not fatal"). The object stays on
    /// its (rolled-back) old program and is not re-attempted until the
    /// *next* `install` bumps [`Registry::install_generation`] again.
    ///
    /// **Never migrates an object with a live frame** (OBI-89 CTO review):
    /// if `id` is executing anywhere on the current call chain (e.g. its
    /// `m()` just recompiled its own program and now calls `self.g()`, or
    /// something it called calls back into it), swapping its program here
    /// would run the rest of that frame's old bytecode against the new
    /// program. Such an object is left stale *without* stamping
    /// `checked_generation`, so it upgrades on its first access after its
    /// frames unwind. This scan only runs on the slow path (generation
    /// mismatch), never in steady state.
    fn ensure_current(&mut self, id: ObjectId) {
        let generation = self.registry.install_generation;
        let Some(o) = self.registry.get(id) else {
            return;
        };
        if o.checked_generation == generation {
            return;
        }
        if self.has_live_frame(id) {
            return;
        }
        let current = self.registry.programs.get(&*o.program.path).cloned();
        if let Some(current) = current
            && !Rc::ptr_eq(&current, &o.program)
            && let Err(w) = self.upgrade(id, current)
        {
            self.registry.lazy_upgrade_warnings.push(w);
        }
        if let Some(o) = self.registry.get_mut(id) {
            o.checked_generation = generation;
        }
    }

    /// True if `id` has a frame on the current call chain. `self_stack[0]`
    /// is the entry's base `self` (the `this_player`/master placeholder a
    /// `World` entry point starts from), not a running frame: every frame
    /// that actually executes is pushed on top of it by
    /// [`RegistryHost::call_in`] or [`Host::enter_self`].
    pub(crate) fn has_live_frame(&self, id: ObjectId) -> bool {
        self.self_stack.iter().skip(1).any(|&s| s == id)
    }

    pub fn new(registry: &'a mut Registry, self_object: ObjectId) -> Self {
        let base = GuardSet::empty().with(principal_of(registry, self_object));
        RegistryHost {
            registry,
            self_stack: vec![self_object],
            guards: vec![base],
            evaluating: Vec::new(),
            extra_ticks: 0,
            push_memo: None,
            limits: Limits::default(),
            ticks_left: 1_000_000,
            driver: None,
            stack_base: stack_addr(),
            call_cache: HashMap::new(),
        }
    }

    /// A [`RegistryHost`] with driver efuns (`send`, `load_object`, …)
    /// enabled, used by [`crate::world::World`]. `cut_guard` overrides the
    /// cut's starting guard set (OBI-35 D-S1.7): `Some(g)` for a scheduled
    /// call_out, whose guard must be exactly its captured `g`, not
    /// `self_object`'s own principal; `None` for every other entry point
    /// (a player command, a heartbeat, a master apply), which starts at
    /// `self_object`'s own euid as before (D-S1.2 rule 5).
    #[allow(clippy::too_many_arguments)]
    pub fn with_driver(
        registry: &'a mut Registry,
        self_object: ObjectId,
        limits: Limits,
        ticks_left: u64,
        compiler: &'a mut Compiler,
        net: &'a mut dyn crate::host::Host,
        this_player: Option<ObjectId>,
        conn: Option<u64>,
        master: Option<ObjectId>,
        scheduler: &'a mut crate::scheduler::Scheduler,
        accounts: crate::world::AccountsCtx<'a>,
        security: &'a mut SecurityState,
        roles: std::sync::Arc<crate::roles::RolesSnapshot>,
        roles_ctx: crate::world::RolesCtx<'a>,
        cut_guard: Option<GuardSet>,
        input_actor: Option<Sym>,
    ) -> Self {
        let base = cut_guard
            .unwrap_or_else(|| GuardSet::empty().with(principal_of(registry, self_object)));
        let root = compiler.root().to_path_buf();
        RegistryHost {
            registry,
            self_stack: vec![self_object],
            guards: vec![base],
            evaluating: Vec::new(),
            extra_ticks: 0,
            push_memo: None,
            limits,
            ticks_left,
            driver: Some(Driver {
                compiler,
                net,
                this_player,
                conn,
                master,
                scheduler,
                accounts,
                security,
                roles,
                roles_ctx,
                input_actor,
                root,
            }),
            stack_base: stack_addr(),
            call_cache: HashMap::new(),
        }
    }

    /// Driver-side call of an apply (visibility is not enforced for the
    /// driver). `Ok(None)` if the object does not define `name` (mirrors
    /// `crate::interp::Exec::call_apply`).
    pub fn call_apply(&mut self, on: ObjectId, name: &str, args: Vec<Value>) -> R<Option<Value>> {
        // Spec §7.2/§7.3 (OBI-89): a driver-started apply is exactly the
        // kind of "access" a lazily-stale object upgrades on —
        // `heartbeat()`, a `call_out` callback, `create()`, `connect()`/
        // `logon()`/`process_input()`/`net_dead()`, …
        self.ensure_current(on);
        let Some(prog) = self.registry.get(on).map(|o| o.program.clone()) else {
            return Ok(None);
        };
        match prog.resolve(name) {
            Some((target, idx)) => self.call_in(on, &target, idx, args).map(Some),
            None => Ok(None),
        }
    }

    /// `load_object`: the blueprint for `path`, loading (compiling +
    /// instantiating + `create()`) it if needed — the bytecode-VM analogue
    /// of `crate::world::Exec::load_object`.
    pub fn load_object(&mut self, path: &str) -> R<ObjectId> {
        let path = mudlib::normalize_path(path).map_err(RtError::new)?;
        if let Some(id) = self.registry.names.get(&path).copied()
            && self.registry.get(id).is_some()
        {
            return Ok(id);
        }
        let prog = self.ensure_program(&path)?;
        self.new_object(prog, path)
    }

    /// `clone_object`: a new clone `path#N`.
    pub fn clone_object(&mut self, path: &str) -> R<ObjectId> {
        let path = mudlib::normalize_path(path).map_err(RtError::new)?;
        let prog = self.ensure_program(&path)?;
        // Kept on the registry, not `Driver`, so it is never lost across
        // per-call `RegistryHost` construction (mirrors `State::next_clone`).
        self.registry.next_clone += 1;
        let name = format!("{path}#{}", self.registry.next_clone);
        let id = self.new_object(prog, name.clone())?;
        // spec r5 §5.2.1: a clone is undoable by an enclosing `atomic fn`
        // scope (a no-op, no allocation, when none is open).
        self.registry.journal_clone(id, name);
        Ok(id)
    }

    fn ensure_program(&mut self, path: &str) -> R<Rc<CompiledProgram>> {
        let driver = self
            .driver
            .as_mut()
            .expect("ensure_program needs a driver context");
        driver
            .compiler
            .ensure_program(self.registry, path)
            .map_err(RtError::new)
    }

    /// Create an object, run variable initialisers (via [`Self::instantiate`])
    /// then `create()`. On error the half-built object is removed (mirrors
    /// `crate::world::Exec::new_object`).
    fn new_object(&mut self, prog: Rc<CompiledProgram>, name: String) -> R<ObjectId> {
        let id = self.instantiate(prog)?;
        if let Some(o) = self.registry.get_mut(id) {
            o.name = name.clone();
        }
        self.registry.names.insert(name.clone(), id);
        match self.call_apply(id, "create", Vec::new()) {
            Ok(_) => Ok(id),
            Err(e) => {
                self.registry.remove(id);
                self.registry.names.remove(&name);
                Err(e)
            }
        }
    }

    /// `compile_object`/`update` (§7.2): recompile `path` (all-or-nothing
    /// at the *compile* stage — see [`Compiler::recompile`]) and install
    /// it. Per-object migration failures are reported as
    /// [`UpgradeWarning`]s rather than aborting the whole recompile (spec
    /// r5 amendment, mirrors [`RegistryHost::install`]).
    pub fn recompile(&mut self, path: &str) -> Result<Vec<UpgradeWarning>, String> {
        let path = mudlib::normalize_path(path)?;
        let new_set = {
            let driver = self
                .driver
                .as_mut()
                .expect("recompile needs a driver context");
            driver.compiler.recompile(self.registry, &path)?
        };
        let touches_secure =
            path.starts_with("/secure/") || new_set.keys().any(|k| k.starts_with("/secure/"));
        let r = self.install(new_set);
        if touches_secure && let Some(d) = self.driver.as_mut() {
            // D-S1.8: a master (or anything under /secure) recompile
            // invalidates every cached decision.
            d.security.bump_epoch();
        }
        r
    }

    /// Apply a background [`compile_worker::RecompileJob`]'s outcome
    /// (OBI-90/D-P1.5, spec §7.2 step 4): decode + re-verify each program
    /// the background thread produced, refuse it if the registry drifted
    /// while it was running (OBI-93 CTO review), wire up `Rc<CompiledProgram>`
    /// parent links against the *current* registry, then [`Self::install`]
    /// — registry mutation + per-object migration — exactly like the
    /// synchronous [`Self::recompile`], all still on the world thread, all
    /// still all-or-nothing.
    pub fn finish_recompile(
        &mut self,
        root_path: &str,
        begin_snapshot: &compile_worker::ProgramSnapshot,
        outcome: compile_worker::CompileOutcome,
    ) -> Result<(), String> {
        let new_set = {
            let driver = self
                .driver
                .as_mut()
                .expect("finish_recompile needs a driver context");
            driver
                .compiler
                .finish_recompile(self.registry, root_path, begin_snapshot, outcome)?
        };
        // Lazy install (OBI-89): migration warnings surface later through
        // `Registry::lazy_upgrade_warnings`, not here.
        self.install(new_set).map(|_| ())
    }

    /// Call `name` on `on` (the object executing this call) as an
    /// outermost entry point (a `World`-facing `call_apply` equivalent).
    pub fn call_on(&mut self, on: ObjectId, name: &str, args: Vec<Value>) -> R<Value> {
        // Spec §7.2/§7.3 (OBI-89): see `RegistryHost::call_apply`.
        self.ensure_current(on);
        let prog = self
            .registry
            .get(on)
            .ok_or_else(|| RtError::new("call on a destructed object"))?
            .program
            .clone();
        let (target, idx) = prog
            .resolve(name)
            .ok_or_else(|| RtError::new(format!("no function `{name}`")))?;
        self.call_in(on, &target, idx, args)
    }

    // ---- security (OBI-35) -------------------------------------------

    fn top_guard(&self) -> &GuardSet {
        self.guards
            .last()
            .expect("guards is never empty while a Host call is in flight")
    }

    /// Push a frame running as `obj`: `self_stack` and the guard stack
    /// move together (D-S1.2 rule 1).
    fn push_self(&mut self, obj: ObjectId) {
        // A call on the same object (virtual self-call, `super::`) adds
        // nothing: re-use the current entry without touching the object
        // table. (After a `seteuid` in the calling frame this keeps the
        // old euid too, i.e. it is at most more restrictive: D-S1.2 rule 3.)
        if self.self_stack.last() == Some(&obj) {
            let g = self.top_guard().clone();
            self.self_stack.push(obj);
            self.guards.push(g);
            return;
        }
        let p = principal_of(self.registry, obj);
        let top = self.top_guard();
        let g = match &self.push_memo {
            Some((parent, mp, out)) if *mp == p && parent.ptr_eq(top) => out.clone(),
            _ => {
                let out = top.with(p);
                if !out.ptr_eq(top) {
                    self.push_memo = Some((top.clone(), p, out.clone()));
                }
                out
            }
        };
        self.self_stack.push(obj);
        self.guards.push(g);
    }

    fn pop_self(&mut self) {
        self.self_stack.pop();
        self.guards.pop();
    }

    /// The guard set a privileged check made right now would evaluate.
    pub fn guard(&self) -> &GuardSet {
        self.top_guard()
    }

    /// The euid names in the current guard set (tests, diagnostics).
    pub fn guard_names(&self) -> Vec<String> {
        let g = self.top_guard();
        g.euids()
            .map(|e| self.registry.syms.name(e).to_string())
            .collect()
    }

    /// The master, if booted and alive.
    fn master(&self) -> Option<ObjectId> {
        self.driver
            .as_ref()
            .and_then(|d| d.master)
            .filter(|m| self.registry.get(*m).is_some())
    }

    /// uid for a new object of program `path` (D-S1.1): the master's
    /// `creator_file(path)` if it has one and returns a string, else the
    /// built-in fallback. `/secure/**` is always `root` (the master cannot
    /// hand root to code outside `/secure`, nor take it from `/secure`).
    fn uid_for(&mut self, path: &str) -> Sym {
        let secure = path.starts_with("/secure/");
        let name = if secure {
            "root".to_string()
        } else {
            let from_master = match self.master() {
                Some(m) => self
                    .run_cut(m, "creator_file", vec![Value::str(path)], None)
                    .ok()
                    .flatten()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .filter(|u| !u.is_empty() && u != "root"),
                None => None,
            };
            from_master.unwrap_or_else(|| security::default_creator(path))
        };
        self.registry.syms.intern(&name)
    }

    /// Run apply `name` on `on` from a **cut** (an empty guard stack
    /// entry, D-S1.2 rule 5) with its own [`APPLY_TICKS`] budget, not
    /// charged to the caller. `evaluating` is the euid
    /// `effective_principal()` reports inside it. `Ok(None)`: no such apply.
    fn run_cut(
        &mut self,
        on: ObjectId,
        name: &str,
        args: Vec<Value>,
        evaluating: Option<Sym>,
    ) -> R<Option<Value>> {
        let saved_ticks = std::mem::replace(&mut self.ticks_left, APPLY_TICKS);
        self.guards.push(GuardSet::empty());
        if let Some(e) = evaluating {
            self.evaluating.push(e);
        }
        let r = self.call_apply(on, name, args);
        if evaluating.is_some() {
            self.evaluating.pop();
        }
        self.guards.pop();
        self.ticks_left = saved_ticks;
        r
    }

    /// Decide `op` for the current guard set (D-S1.2/D-S1.3): allowed iff
    /// the guard set is empty (all root) or the master's apply returns
    /// `true` for **every** euid in it. Fails closed: no master, no apply,
    /// an error or a non-bool result all deny. Audited either way.
    fn authorize(&mut self, efun: &str, class: Privilege, op: Operation<'_>) -> R<()> {
        let efun = crate::efuns::static_name(efun).unwrap_or("?");
        let guard = self.top_guard().clone();
        let caller = self.self_object();
        let mut denied_by = None;
        if !guard.is_empty() {
            let master = self.master();
            for euid in guard.euids() {
                let looked = self
                    .driver
                    .as_mut()
                    .expect("authorize needs a driver")
                    .security
                    .lookup(&op, euid);
                let allowed = match looked {
                    Ok(b) => b,
                    Err(miss) => {
                        self.extra_ticks += MISS_CHARGE;
                        let b = match master {
                            None => false,
                            Some(m) => {
                                let args = self.apply_args(&op, caller);
                                matches!(
                                    self.run_cut(m, op.apply(), args, Some(euid)),
                                    Ok(Some(Value::Bool(true)))
                                )
                            }
                        };
                        let sec = &mut self.driver.as_mut().expect("driver").security;
                        sec.misses += 1;
                        if let Some(miss) = miss {
                            sec.store(miss, b);
                        }
                        b
                    }
                };
                if !allowed {
                    denied_by = Some(euid);
                    break;
                }
            }
        }
        let sec = &mut self.driver.as_mut().expect("driver").security;
        sec.record(
            caller,
            efun,
            class,
            &op,
            &guard,
            denied_by.is_none(),
            denied_by,
        );
        match denied_by {
            None => Ok(()),
            Some(who) => Err(RtError::new(format!(
                "{efun}(): permission denied ({} for `{}`)",
                op.describe(),
                self.registry.syms.name(who)
            ))),
        }
    }

    fn apply_args(&self, op: &Operation<'_>, caller: ObjectId) -> Vec<Value> {
        let ob = Value::Object(caller);
        match op {
            Operation::Efun { name, class } => {
                vec![Value::str(name), Value::Int(*class as i64), ob]
            }
            Operation::Read { path, op } | Operation::Write { path, op } => {
                vec![Value::str(path), ob, Value::str(op)]
            }
            Operation::Compile { path } => vec![Value::str(path), ob],
            Operation::Bind { target } => vec![ob, Value::Object(*target)],
            Operation::SetEuid { euid } => vec![ob, Value::str(euid)],
        }
    }

    fn want_obj(&self, efun: &str, v: &Value) -> R<ObjectId> {
        match v {
            Value::Object(id) if self.registry.get(*id).is_some() => Ok(*id),
            Value::Object(_) => Err(RtError::new(format!("{efun}(): object was destructed"))),
            v => Err(RtError::new(format!(
                "{efun}(): expected object, got {}",
                v.type_name()
            ))),
        }
    }

    /// Like [`Self::want_obj`], but a destructed handle is accepted (not an
    /// error): callers that are themselves safe on a dead reference
    /// (`environment`, `destruct`, spec/CTO review OBI-85) use this
    /// instead so a stale `object` var doesn't turn every read of it into
    /// a runtime error -- only [`Self::want_obj`]'s callers (`move_to`,
    /// `object_name`, `inventory`, ...) still refuse a dead handle.
    fn want_obj_or_dead(&self, efun: &str, v: &Value) -> R<ObjectId> {
        match v {
            Value::Object(id) => Ok(*id),
            v => Err(RtError::new(format!(
                "{efun}(): expected object, got {}",
                v.type_name()
            ))),
        }
    }

    /// Driver efuns not handled inline by the interpreter (spec §5.5),
    /// ported from `crate::efuns::Exec::efun_inner`. `Err` ("needs full
    /// World integration") when this `RegistryHost` has no [`Driver`]
    /// context (the unit tests in this module).
    fn driver_efun(&mut self, name: &str, args: Vec<Value>) -> R<Value> {
        if self.driver.is_none() {
            return Err(RtError::new(format!(
                "efun `{name}` is not available in this Host (needs full World integration)"
            )));
        }
        // `unguarded` is P4-sensitive but gated by a driver rule (caller's
        // program under /secure), not by `valid_efun`: every caller it
        // exists for has lower-privileged frames below it (D-S1.5).
        if let Some(p) = crate::efuns::privilege(name)
            && p.gated()
            && !matches!(
                name,
                "unguarded"
                    | "roles_set_tier"
                    | "roles_set_member"
                    | "roles_grant"
                    | "roles_revoke_grant"
                    | "roles_propose_tier"
                    | "roles_approve"
            )
        {
            let sname = crate::efuns::static_name(name).unwrap_or("?");
            self.authorize(
                name,
                p,
                Operation::Efun {
                    name: sname,
                    class: p,
                },
            )?;
        }
        let a0 = args.first().cloned().unwrap_or(Value::Null);
        let a1 = args.get(1).cloned().unwrap_or(Value::Null);
        let a2 = args.get(2).cloned().unwrap_or(Value::Null);
        let a3 = args.get(3).cloned().unwrap_or(Value::Null);
        let a4 = args.get(4).cloned().unwrap_or(Value::Null);
        match name {
            "self" => Ok(Value::Object(self.self_object())),
            "this_player" => Ok(self
                .driver
                .as_ref()
                .and_then(|d| d.this_player)
                .map_or(Value::Null, Value::Object)),
            "load_object" => {
                let p = a0
                    .as_str()
                    .ok_or_else(|| RtError::new("load_object(): expected string"))?
                    .to_string();
                self.load_object(&p).map(Value::Object).map_err(|e| {
                    RtError::new(format!("load_object(\"{p}\") failed:\n{}", e.report()))
                })
            }
            "clone_object" => {
                let p = a0
                    .as_str()
                    .ok_or_else(|| RtError::new("clone_object(): expected string"))?
                    .to_string();
                self.clone_object(&p).map(Value::Object).map_err(|e| {
                    RtError::new(format!("clone_object(\"{p}\") failed:\n{}", e.report()))
                })
            }
            "find_object" => {
                let p = a0
                    .as_str()
                    .ok_or_else(|| RtError::new("find_object(): expected string"))?;
                let key = p.strip_suffix(".wf").unwrap_or(p);
                Ok(self
                    .registry
                    .names
                    .get(key)
                    .copied()
                    .filter(|id| self.registry.get(*id).is_some())
                    .map_or(Value::Null, Value::Object))
            }
            "object_name" => {
                let id = self.want_obj(name, &a0)?;
                Ok(Value::str(&self.registry.obj_name(id)))
            }
            "environment" => {
                let id = if args.is_empty() {
                    self.self_object()
                } else {
                    self.want_obj_or_dead(name, &a0)?
                };
                Ok(self
                    .registry
                    .get(id)
                    .and_then(|o| o.env)
                    .map_or(Value::Null, Value::Object))
            }
            "inventory" => {
                let id = self.want_obj(name, &a0)?;
                let inv = self
                    .registry
                    .get(id)
                    .map(|o| o.inventory.iter().map(|i| Value::Object(*i)).collect())
                    .unwrap_or_default();
                Ok(Value::array(inv))
            }
            "move_to" => {
                let dest = self.want_obj(name, &a0)?;
                let me = self.self_object();
                let mut cur = Some(dest);
                while let Some(c) = cur {
                    if c == me {
                        return Err(RtError::new(
                            "move_to(): cannot move an object into itself or its contents",
                        ));
                    }
                    cur = self.registry.get(c).and_then(|o| o.env);
                }
                self.registry.move_object(me, dest);
                Ok(Value::Null)
            }
            "send" => {
                let text = a1
                    .as_str()
                    .ok_or_else(|| RtError::new("send(): expected string"))?
                    .to_string();
                if let Value::Object(id) = a0 {
                    let conn = self.registry.get(id).and_then(|o| o.conn);
                    if let Some(conn) = conn
                        && let Some(d) = self.driver.as_mut()
                    {
                        d.net.send(conn, &text);
                    }
                } else if !matches!(a0, Value::Null) {
                    return Err(RtError::new(format!(
                        "send(): expected object, got {}",
                        a0.type_name()
                    )));
                }
                Ok(Value::Null)
            }
            "disconnect" => {
                if let Value::Object(id) = a0 {
                    let conn = self.registry.get(id).and_then(|o| o.conn);
                    if let Some(conn) = conn
                        && let Some(d) = self.driver.as_mut()
                    {
                        d.net.close(conn);
                    }
                } else if !matches!(a0, Value::Null) {
                    return Err(RtError::new(format!(
                        "disconnect(): expected object, got {}",
                        a0.type_name()
                    )));
                }
                Ok(Value::Null)
            }
            "bind_connection" => {
                let me = self.self_object();
                let master = self.driver.as_ref().and_then(|d| d.master);
                if master != Some(me) {
                    return Err(RtError::new(
                        "bind_connection() may only be called by the master object",
                    ));
                }
                let id = self.want_obj(name, &a0)?;
                self.authorize(name, Privilege::P3, Operation::Bind { target: id })?;
                let Some(conn) = self.driver.as_ref().and_then(|d| d.conn) else {
                    return Err(RtError::new(
                        "bind_connection(): no connection in this execution",
                    ));
                };
                self.registry.bind(conn, id);
                Ok(Value::Null)
            }
            "compile_object" => {
                let p = a0
                    .as_str()
                    .ok_or_else(|| RtError::new("compile_object(): expected string"))?
                    .to_string();
                let norm = mudlib::normalize_path(&p).map_err(RtError::new)?;
                self.authorize(name, Privilege::P1, Operation::Compile { path: &norm })?;
                Ok(match self.recompile(&p) {
                    // Per-object migration failures are reported (not
                    // fatal, spec §7.2 step 6.4) but there is no
                    // builder/master `runtime_error` apply wired up yet to
                    // hand them to (tracked on OBI-34, not silently
                    // dropped): surface them on stderr for now so a
                    // recompile with partial migration failures is at
                    // least visible somewhere.
                    Ok(warnings) => {
                        for w in &warnings {
                            eprintln!(
                                "upgrade warning: object {:?} on {}: {}",
                                w.object, w.program, w.message
                            );
                        }
                        Value::Null
                    }
                    Err(e) => Value::str(&e),
                })
            }
            // Eager mode (spec §7.2/§7.3, OBI-89): queue every live instance
            // of `path` still on a stale program for `World::tick` to
            // migrate a bounded batch of per tick (`Registry::eager_upgrade_queue`),
            // rather than blocking this call (or the whole tick queue) on
            // migrating all of them synchronously. A no-op (returns 0) for
            // an unregistered path or one with nothing stale to migrate.
            // P1, same tier as `compile_object` (D-P1.6): it only brings
            // forward what lazy mode would do on next access anyway.
            // S2: gate like `compile_object` — `valid_write`-style
            // confinement on `path` (OBI-36).
            "upgrade_all" => {
                let p = a0
                    .as_str()
                    .ok_or_else(|| RtError::new("upgrade_all(): expected string"))?;
                let path = mudlib::normalize_path(p).map_err(RtError::new)?;
                let Some(current) = self.registry.program(&path) else {
                    return Err(RtError::new(format!(
                        "upgrade_all(): no program registered for {path}"
                    )));
                };
                let stale: Vec<ObjectId> = self
                    .registry
                    .ids()
                    .into_iter()
                    .filter(|id| {
                        self.registry.get(*id).is_some_and(|o| {
                            !Rc::ptr_eq(&o.program, &current) && *o.program.path == *path
                        })
                    })
                    .collect();
                let queued = stale.len() as i64;
                let driver = self.driver.as_mut().expect("checked above");
                for id in stale {
                    driver.scheduler.enqueue_eager_upgrade(id, path.clone());
                }
                Ok(Value::Int(queued))
            }
            "call_out" => {
                let func = a0
                    .as_str()
                    .ok_or_else(|| RtError::new("call_out(): expected string function name"))?
                    .to_string();
                let Value::Int(delay) = a1 else {
                    return Err(RtError::new("call_out(): expected int delay"));
                };
                if delay < 0 {
                    return Err(RtError::new("call_out(): delay must not be negative"));
                }
                let me = self.self_object();
                let guard = Host::current_guard(self);
                let quota_uid = Host::current_uid(self);
                let id = self
                    .driver
                    .as_mut()
                    .expect("checked above")
                    .scheduler
                    .call_out(me, delay as u64, func, Vec::new(), guard, quota_uid);
                Ok(Value::Int(id as i64))
            }
            "remove_call_out" => {
                let Value::Int(id) = a0 else {
                    return Err(RtError::new("remove_call_out(): expected int id"));
                };
                let me = self.self_object();
                let removed = id >= 0
                    && self
                        .driver
                        .as_mut()
                        .expect("checked above")
                        .scheduler
                        .remove_call_out(me, id as u64);
                Ok(Value::Bool(removed))
            }
            "set_heartbeat" => {
                let Value::Bool(on) = a0 else {
                    return Err(RtError::new("set_heartbeat(): expected bool"));
                };
                let me = self.self_object();
                self.driver
                    .as_mut()
                    .expect("checked above")
                    .scheduler
                    .set_heart_beat(me, on);
                Ok(Value::Null)
            }
            "random" => {
                let Value::Int(n) = a0 else {
                    return Err(RtError::new("random(): expected int"));
                };
                if n <= 0 {
                    return Err(RtError::new("random(): n must be > 0"));
                }
                Ok(Value::Int(self.registry.rng.gen_range(n)))
            }
            "time" => {
                let secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                Ok(Value::Int(secs))
            }
            "users" => Ok(Value::array(
                self.registry
                    .users_in_bind_order()
                    .into_iter()
                    .map(Value::Object)
                    .collect(),
            )),
            "destructed" => Ok(Value::Bool(match a0 {
                Value::Null => true,
                Value::Object(id) => self.registry.get(id).is_none(),
                v => {
                    return Err(RtError::new(format!(
                        "destructed(): expected object?, got {}",
                        v.type_name()
                    )));
                }
            })),
            "destruct" => {
                let id = self.want_obj_or_dead(name, &a0)?;
                let driver = self.driver.as_mut().expect("checked above");
                let conn = self.registry.destruct(id, driver.scheduler);
                if let Some(c) = conn {
                    driver.net.close(c);
                }
                Ok(Value::Null)
            }
            "getuid" | "geteuid" => {
                let me = self.self_object();
                let o = self.registry.get(me);
                let sym = o.map_or(ROOT, |o| if name == "getuid" { o.uid } else { o.euid });
                Ok(Value::str(self.registry.syms.name(sym)))
            }
            "effective_principal" => match self.evaluating.last() {
                Some(e) => Ok(Value::str(self.registry.syms.name(*e))),
                None => Err(RtError::new(
                    "effective_principal(): only valid inside a valid_* apply",
                )),
            },
            "seteuid" => {
                let e = a0
                    .as_str()
                    .ok_or_else(|| RtError::new("seteuid(): expected string"))?
                    .to_string();
                if e.is_empty() {
                    return Err(RtError::new("seteuid(): empty euid"));
                }
                self.authorize(name, Privilege::P3, Operation::SetEuid { euid: &e })?;
                let me = self.self_object();
                let new = self.registry.syms.intern(&e);
                let uid = match self.registry.get_mut(me) {
                    Some(o) => {
                        o.euid = new;
                        o.uid
                    }
                    None => return Err(RtError::new("seteuid(): object was destructed")),
                };
                // D-S1.2 rule 3: monotone within the frame. The current
                // guard keeps the old euid and gains the new one; only
                // frames pushed later see the new euid alone.
                let top = self.guards.pop().expect("guards non-empty");
                self.guards.push(top.with(Principal { uid, euid: new }));
                Ok(Value::Null)
            }
            "read_file" => {
                let p = a0
                    .as_str()
                    .ok_or_else(|| RtError::new("read_file(): expected string"))?;
                let p = security::normalize_file_path(p).map_err(RtError::new)?;
                self.authorize(
                    name,
                    Privilege::P0,
                    Operation::Read {
                        path: &p,
                        op: "read_file",
                    },
                )?;
                let root = &self.driver.as_ref().expect("checked above").root;
                crate::fileio::read_file(root, &p)
                    .map(|s| s.map_or(Value::Null, |s| Value::str(&s)))
                    .map_err(|e| RtError::new(format!("read_file(\"{p}\") failed: {e}")))
            }
            "write_file" => {
                let p = a0
                    .as_str()
                    .ok_or_else(|| RtError::new("write_file(): expected string path"))?;
                let p = security::normalize_file_path(p).map_err(RtError::new)?;
                let text = a1
                    .as_str()
                    .ok_or_else(|| RtError::new("write_file(): expected string contents"))?;
                self.authorize(
                    name,
                    Privilege::P1,
                    Operation::Write {
                        path: &p,
                        op: "write_file",
                    },
                )?;
                let root = &self.driver.as_ref().expect("checked above").root;
                crate::fileio::write_file(root, &p, text)
                    .map(Value::Bool)
                    .map_err(|e| RtError::new(format!("write_file(\"{p}\") failed: {e}")))
            }
            "account_create" => self.issue_account_request(true, &a0, &a1),
            "account_login" => self.issue_account_request(false, &a0, &a1),
            "unguarded" => self.unguarded(a0, a1),
            "roles_tier" => {
                self.require_secure_caller("roles_tier")?;
                let uid = a0
                    .as_str()
                    .ok_or_else(|| RtError::new("roles_tier(): expected string uid"))?;
                let roles = self.driver.as_ref().expect("checked above").roles.clone();
                Ok(Value::Int(roles.tier(uid) as i64))
            }
            "roles_is_member" => {
                self.require_secure_caller("roles_is_member")?;
                let uid = a0
                    .as_str()
                    .ok_or_else(|| RtError::new("roles_is_member(): expected string uid"))?;
                let domain = a1
                    .as_str()
                    .ok_or_else(|| RtError::new("roles_is_member(): expected string domain"))?;
                let roles = self.driver.as_ref().expect("checked above").roles.clone();
                Ok(Value::Bool(roles.is_member(uid, domain)))
            }
            "roles_is_lead" => {
                self.require_secure_caller("roles_is_lead")?;
                let uid = a0
                    .as_str()
                    .ok_or_else(|| RtError::new("roles_is_lead(): expected string uid"))?;
                let domain = a1
                    .as_str()
                    .ok_or_else(|| RtError::new("roles_is_lead(): expected string domain"))?;
                let roles = self.driver.as_ref().expect("checked above").roles.clone();
                Ok(Value::Bool(roles.is_lead(uid, domain)))
            }
            "roles_has_grant" => {
                self.require_secure_caller("roles_has_grant")?;
                let uid = a0
                    .as_str()
                    .ok_or_else(|| RtError::new("roles_has_grant(): expected string uid"))?;
                let kind = a1
                    .as_str()
                    .ok_or_else(|| RtError::new("roles_has_grant(): expected string kind"))?;
                let target = a2
                    .as_str()
                    .ok_or_else(|| RtError::new("roles_has_grant(): expected string target"))?;
                let roles = self.driver.as_ref().expect("checked above").roles.clone();
                Ok(Value::Bool(roles.has_grant(uid, kind, target)))
            }
            "roles_policy" => {
                self.require_secure_caller("roles_policy")?;
                let tier = match a0 {
                    Value::Int(n) if n >= 0 => n as u32,
                    _ => {
                        return Err(RtError::new(
                            "roles_policy(): expected non-negative int tier",
                        ));
                    }
                };
                let roles = self.driver.as_ref().expect("checked above").roles.clone();
                let mut m = heap::MapData::default();
                for (k, v) in roles.policy(tier) {
                    m.insert(Value::str(&k), Value::Int(v));
                }
                Ok(Value::map(m))
            }
            "roles_domains" => {
                self.require_secure_caller("roles_domains")?;
                let uid = a0
                    .as_str()
                    .ok_or_else(|| RtError::new("roles_domains(): expected string uid"))?;
                let roles = self.driver.as_ref().expect("checked above").roles.clone();
                Ok(Value::array(
                    roles
                        .domains(uid)
                        .into_iter()
                        .map(|d| Value::str(&d))
                        .collect(),
                ))
            }
            "roles_set_tier" => self.roles_set_tier(&a0, &a1, &a2),
            "roles_set_member" => self.roles_set_member(&a0, &a1, &a2, &a3),
            "roles_grant" => self.roles_grant(&a0, &a1, &a2, &a3, &a4),
            "roles_revoke_grant" => self.roles_revoke_grant(&a0, &a1, &a2, &a3),
            "roles_propose_tier" => self.roles_propose_tier(&a0, &a1, &a2),
            "roles_approve" => self.roles_approve(&a0),
            _ => Err(RtError::new(format!(
                "internal: efun `{name}` not implemented"
            ))),
        }
    }

    /// `account_create`/`account_login` (spec, OBI-85): validates `name`/
    /// `password` synchronously (never touches the DB for that), assigns
    /// a request id, and either queues the real async lookup with
    /// [`crate::world::AccountAuth`] or -- for a validation failure --
    /// enqueues the `"invalid"` result locally. Either way, `account_result`
    /// is only ever delivered on a *later* top-level entry (`World::drain_account_results`),
    /// never inside this call, so the caller always sees its own request id
    /// returned before it sees the matching `account_result` apply.
    fn issue_account_request(&mut self, create: bool, name: &Value, password: &Value) -> R<Value> {
        let name = name
            .as_str()
            .ok_or_else(|| RtError::new("account_create/account_login: expected string name"))?;
        let password = password.as_str().ok_or_else(|| {
            RtError::new("account_create/account_login: expected string password")
        })?;
        let caller = self.self_object();
        let driver = self.driver.as_mut().expect("checked above");
        *driver.accounts.next_id += 1;
        let id = *driver.accounts.next_id;
        let valid_name = (3..=16).contains(&name.chars().count())
            && name.chars().all(|c| c.is_ascii_lowercase());
        let valid_password = (6..=128).contains(&password.len());
        if !valid_name || !valid_password {
            driver
                .accounts
                .results
                .push_back((id, caller, false, "invalid".to_string()));
        } else {
            driver.accounts.pending.insert(id, caller);
            let issued = if create {
                driver.accounts.auth.create_account(id, name, password)
            } else {
                driver.accounts.auth.login(id, name, password)
            };
            if !issued {
                // The backend's request queue is full or closed: never
                // leave this pending forever (spec/CTO review OBI-85).
                driver.accounts.pending.remove(&id);
                driver
                    .accounts
                    .results
                    .push_back((id, caller, false, "unavailable".to_string()));
            }
        }
        Ok(Value::Int(id as i64))
    }

    /// `unguarded(fname, args)` (OBI-35 D-S1.5): call `self.<fname>(args…)`
    /// from a cut whose guard restarts at `{self.euid}`. Only for code
    /// compiled from `/secure/**` (a driver rule, not master policy); takes
    /// a function *name*, never a function value, so a captured guard can
    /// never be laundered through it. Always audited.
    fn unguarded(&mut self, fname: Value, args: Value) -> R<Value> {
        let fname = fname
            .as_str()
            .ok_or_else(|| RtError::new("unguarded(): expected string function name"))?
            .to_string();
        let argv = match args {
            Value::Null => Vec::new(),
            v => v
                .as_array()
                .map(|a| a.to_vec())
                .ok_or_else(|| RtError::new("unguarded(): expected array of arguments"))?,
        };
        let me = self.self_object();
        let prog = self
            .registry
            .get(me)
            .map(|o| o.program.clone())
            .ok_or_else(|| RtError::new("unguarded(): object was destructed"))?;
        let secure = prog.path.starts_with("/secure/");
        let guard = self.top_guard().clone();
        let d = self.driver.as_mut().expect("unguarded needs a driver");
        d.security.push(AuditEntry {
            caller: me,
            efun: "unguarded",
            privilege: Privilege::P4,
            apply: "unguarded",
            arg: fname.as_str().into(),
            guard,
            allowed: secure,
            denied_by: None,
        });
        if !secure {
            return Err(RtError::new(format!(
                "unguarded(): only code under /secure may cut the stack ({} may not)",
                prog.path
            )));
        }
        let (target, idx) = prog
            .resolve(&fname)
            .ok_or_else(|| RtError::new(format!("unguarded(): no function `{fname}`")))?;
        // The cut: an empty entry; `call_in`'s push adds self's own euid.
        self.guards.push(GuardSet::empty());
        let r = self.call_in(me, &target, idx, argv);
        self.guards.pop();
        r
    }

    /// Driver rule shared by every `roles_*` **read** efun (OBI-36
    /// D-S2.2, same shape as `unguarded`'s D-S1.5): only code compiled
    /// from `/secure/**` may call it. Not master policy, no `valid_efun`
    /// check -- this is why the table classes them `Privilege::P0`.
    /// Checked against the *immediate* caller's own leaf program, not
    /// "somewhere on the stack".
    fn require_secure_caller(&self, efun: &'static str) -> R<()> {
        let me = self.self_object();
        match self.registry.get(me).map(|o| o.program.path.clone()) {
            Some(p) if p.starts_with("/secure/") => Ok(()),
            Some(p) => Err(RtError::new(format!(
                "{efun}(): only code under /secure may call this ({p} may not)"
            ))),
            None => Err(RtError::new(format!("{efun}(): object was destructed"))),
        }
    }

    /// The actor-rule euid (D-S2.2), if the execution was started by
    /// player input (`Driver::input_actor`, set once by `World::input`)
    /// *and* that euid is still in the current guard set. `None` refuses
    /// the call: a call_out/heartbeat/`roles_result`/`account_result`
    /// drain never has an `input_actor` at all, and an interactive that
    /// has since `seteuid`'d away (or whose frame dropped off the guard
    /// set some other way) no longer satisfies the rule either. Never a
    /// string read from Weft -- resolved purely from the registry state
    /// `World::input` captured at the cut.
    fn roles_actor(&self) -> Option<Sym> {
        let actor = self.driver.as_ref()?.input_actor?;
        self.top_guard().has_euid(actor).then_some(actor)
    }

    /// Driver rule shared by every `roles_*` **mutation** efun (D-S2.2):
    /// the immediate caller must be `/secure/**` *and* the actor rule must
    /// resolve. Always audited, allowed or denied, independent of
    /// `valid_efun` (`driver_efun` exempts these efuns from it: a T3
    /// lead's own tier does not include P3, so that check would wrongly
    /// deny a legitimate promotion). The SQL function re-checks rank
    /// independently (`docs/persistence.md`); this gate is the driver's
    /// half.
    fn roles_mutation_gate(&mut self, efun: &'static str) -> R<Sym> {
        let me = self.self_object();
        let path = self.registry.get(me).map(|o| o.program.path.clone());
        let secure = path.as_deref().is_some_and(|p| p.starts_with("/secure/"));
        let actor = if secure { self.roles_actor() } else { None };
        let guard = self.top_guard().clone();
        let d = self.driver.as_mut().expect("roles mutation needs a driver");
        d.security.push(AuditEntry {
            caller: me,
            efun,
            privilege: Privilege::P3,
            apply: "roles_actor",
            arg: Box::from(""),
            guard,
            allowed: actor.is_some(),
            denied_by: None,
        });
        match (secure, actor, path) {
            (true, Some(a), _) => Ok(a),
            (false, _, Some(p)) => Err(RtError::new(format!(
                "{efun}(): only code under /secure may call this ({p} may not)"
            ))),
            (false, _, None) => Err(RtError::new(format!("{efun}(): object was destructed"))),
            (true, None, _) => Err(RtError::new(format!(
                "{efun}(): refused -- not called from an execution started by player \
                 input, or the actor's euid has left the guard set"
            ))),
        }
    }

    /// A new correlation id for a `roles_*` mutation request: bumps
    /// `World`'s counter and records `caller` as pending (mirrors
    /// `issue_account_request`'s bookkeeping).
    fn roles_next_request(&mut self, caller: ObjectId) -> u64 {
        let d = self.driver.as_mut().expect("driver");
        *d.roles_ctx.next_id += 1;
        let id = *d.roles_ctx.next_id;
        d.roles_ctx.pending.insert(id, caller);
        id
    }

    /// The backend's request queue was full or closed (`false` from a
    /// [`crate::world::RolesMutations`] method): never leave the request
    /// pending forever (same rule as `issue_account_request`, OBI-85 CTO
    /// review).
    fn roles_request_unavailable(&mut self, id: u64, caller: ObjectId) {
        let d = self.driver.as_mut().expect("driver");
        d.roles_ctx.pending.remove(&id);
        d.roles_ctx
            .results
            .push_back((id, caller, false, "unavailable".to_string()));
    }

    fn want_str(v: &Value, msg: &'static str) -> R<String> {
        v.as_str()
            .map(str::to_string)
            .ok_or_else(|| RtError::new(msg))
    }

    fn want_int(v: &Value, msg: &'static str) -> R<i64> {
        match v {
            Value::Int(n) => Ok(*n),
            _ => Err(RtError::new(msg)),
        }
    }

    fn roles_set_tier(&mut self, target: &Value, tier: &Value, reason: &Value) -> R<Value> {
        let actor = self.roles_mutation_gate("roles_set_tier")?;
        let target = Self::want_str(target, "roles_set_tier(): expected string target")?;
        let tier = Self::want_int(tier, "roles_set_tier(): expected int tier")?;
        let reason = Self::want_str(reason, "roles_set_tier(): expected string reason")?;
        let caller = self.self_object();
        let actor_name = self.registry.syms.name(actor).to_string();
        let id = self.roles_next_request(caller);
        let d = self.driver.as_mut().expect("driver");
        let issued = d
            .roles_ctx
            .backend
            .set_tier(id, &actor_name, &target, tier, &reason);
        if !issued {
            self.roles_request_unavailable(id, caller);
        }
        Ok(Value::Int(id as i64))
    }

    fn roles_set_member(
        &mut self,
        domain: &Value,
        target: &Value,
        role: &Value,
        reason: &Value,
    ) -> R<Value> {
        let actor = self.roles_mutation_gate("roles_set_member")?;
        let domain = Self::want_str(domain, "roles_set_member(): expected string domain")?;
        let target = Self::want_str(target, "roles_set_member(): expected string target")?;
        let role = Self::want_str(role, "roles_set_member(): expected string role")?;
        let reason = Self::want_str(reason, "roles_set_member(): expected string reason")?;
        let caller = self.self_object();
        let actor_name = self.registry.syms.name(actor).to_string();
        let id = self.roles_next_request(caller);
        let d = self.driver.as_mut().expect("driver");
        let issued =
            d.roles_ctx
                .backend
                .set_member(id, &actor_name, &domain, &target, &role, &reason);
        if !issued {
            self.roles_request_unavailable(id, caller);
        }
        Ok(Value::Int(id as i64))
    }

    fn roles_grant(
        &mut self,
        target: &Value,
        kind: &Value,
        what: &Value,
        expires_at: &Value,
        reason: &Value,
    ) -> R<Value> {
        let actor = self.roles_mutation_gate("roles_grant")?;
        let target = Self::want_str(target, "roles_grant(): expected string target")?;
        let kind = Self::want_str(kind, "roles_grant(): expected string kind")?;
        let what = Self::want_str(what, "roles_grant(): expected string what")?;
        let expires_at = match expires_at {
            Value::Null => None,
            Value::Int(n) => Some(*n),
            _ => return Err(RtError::new("roles_grant(): expected int? expires_at")),
        };
        let reason = Self::want_str(reason, "roles_grant(): expected string reason")?;
        let caller = self.self_object();
        let actor_name = self.registry.syms.name(actor).to_string();
        let id = self.roles_next_request(caller);
        let d = self.driver.as_mut().expect("driver");
        let issued =
            d.roles_ctx
                .backend
                .grant(id, &actor_name, &target, &kind, &what, expires_at, &reason);
        if !issued {
            self.roles_request_unavailable(id, caller);
        }
        Ok(Value::Int(id as i64))
    }

    fn roles_revoke_grant(
        &mut self,
        target: &Value,
        kind: &Value,
        what: &Value,
        reason: &Value,
    ) -> R<Value> {
        let actor = self.roles_mutation_gate("roles_revoke_grant")?;
        let target = Self::want_str(target, "roles_revoke_grant(): expected string target")?;
        let kind = Self::want_str(kind, "roles_revoke_grant(): expected string kind")?;
        let what = Self::want_str(what, "roles_revoke_grant(): expected string what")?;
        let reason = Self::want_str(reason, "roles_revoke_grant(): expected string reason")?;
        let caller = self.self_object();
        let actor_name = self.registry.syms.name(actor).to_string();
        let id = self.roles_next_request(caller);
        let d = self.driver.as_mut().expect("driver");
        let issued =
            d.roles_ctx
                .backend
                .revoke_grant(id, &actor_name, &target, &kind, &what, &reason);
        if !issued {
            self.roles_request_unavailable(id, caller);
        }
        Ok(Value::Int(id as i64))
    }

    fn roles_propose_tier(&mut self, target: &Value, tier: &Value, reason: &Value) -> R<Value> {
        let actor = self.roles_mutation_gate("roles_propose_tier")?;
        let target = Self::want_str(target, "roles_propose_tier(): expected string target")?;
        let tier = Self::want_int(tier, "roles_propose_tier(): expected int tier")?;
        let reason = Self::want_str(reason, "roles_propose_tier(): expected string reason")?;
        let caller = self.self_object();
        let actor_name = self.registry.syms.name(actor).to_string();
        let id = self.roles_next_request(caller);
        let d = self.driver.as_mut().expect("driver");
        let issued = d
            .roles_ctx
            .backend
            .propose_tier(id, &actor_name, &target, tier, &reason);
        if !issued {
            self.roles_request_unavailable(id, caller);
        }
        Ok(Value::Int(id as i64))
    }

    fn roles_approve(&mut self, proposal_id: &Value) -> R<Value> {
        let actor = self.roles_mutation_gate("roles_approve")?;
        let proposal_id = Self::want_int(proposal_id, "roles_approve(): expected int proposal_id")?;
        let caller = self.self_object();
        let actor_name = self.registry.syms.name(actor).to_string();
        let id = self.roles_next_request(caller);
        let d = self.driver.as_mut().expect("driver");
        let issued = d.roles_ctx.backend.approve(id, &actor_name, proposal_id);
        if !issued {
            self.roles_request_unavailable(id, caller);
        }
        Ok(Value::Int(id as i64))
    }

    /// Run `name` declared in exactly `target` as `on` in a *fresh*
    /// [`Interpreter`] — the driver-started path (applies, `$init`, efuns
    /// that run Weft code, and the run-to-completion `Host::call_*`
    /// methods). Weft-to-Weft calls inside that run stay on its one flat
    /// stack via [`Host::dispatch`]; only driver re-entry nests here, and
    /// both `self_stack.len()` and [`NESTED_CALL_STACK_BUDGET`] bound it.
    fn call_in(
        &mut self,
        on: ObjectId,
        target: &Rc<CompiledProgram>,
        idx: u32,
        args: Vec<Value>,
    ) -> R<Value> {
        let func_name =
            target.module.strings[target.module.functions[idx as usize].name as usize].to_string();
        let used = self.stack_base.abs_diff(stack_addr());
        if self.self_stack.len() as u32 >= self.limits.max_depth || used > NESTED_CALL_STACK_BUDGET
        {
            let mut e = RtError::new(
                "Too deep recursion (call depth limit or native stack budget exceeded)",
            );
            e.trace.push(format!("in {func_name}()"));
            return Err(e);
        }
        self.push_self(on);
        let limits = self.limits;
        let mut ticks = self.ticks_left;
        let result = {
            let mut interp = Interpreter::new(&target.module, self, &limits, &mut ticks);
            interp.call(&func_name, args)
        };
        self.ticks_left = ticks;
        self.pop_self();
        result
    }

    /// Create a new object of `prog` and run every ancestor's own `$init`
    /// (root first, spec §7.2 var-initialiser order — the same order
    /// `crate::world::World::init_vars` uses for the tree-walker): each
    /// ancestor only ever sets *its own* declared variables, in program
    /// order, so a child's initialiser can already see (and read) a
    /// parent's already-initialised variable, but never the reverse.
    /// Rolls back (removes the half-built object) on the first failing
    /// initialiser, matching `World::new_object`'s all-or-nothing create.
    pub fn instantiate(&mut self, prog: Rc<CompiledProgram>) -> R<ObjectId> {
        let uid = self.uid_for(&prog.path);
        let mut obj = BcObject::new(prog.clone());
        obj.uid = uid;
        obj.euid = uid;
        // Freshly created against whatever is registered right now:
        // nothing to lazily migrate until a *later* install changes it
        // (spec §7.2/§7.3, OBI-89). Stamping this now (rather than leaving
        // the `BcObject::new` default of 0) skips one no-op
        // `ensure_current` lookup the first time this object is touched.
        obj.checked_generation = self.registry.install_generation;
        let id = self.registry.insert(obj);
        for ancestor in prog.chain() {
            let keep = vec![false; ancestor.init_specs().count()];
            if let Err(e) = self.run_init(id, &ancestor, &keep) {
                self.registry.remove(id);
                return Err(e);
            }
        }
        Ok(id)
    }

    /// Run `target`'s own `$init` (if it has one) as `on`, with `keep[i]`
    /// true for each var-with-an-initialiser (in [`CompiledProgram::init_specs`]
    /// order) whose old value should be left alone rather than
    /// re-initialised. A no-op if `target` declares no vars with an
    /// initialiser (`resolve_own(INIT_FN)` is `None`).
    fn run_init(&mut self, on: ObjectId, target: &Rc<CompiledProgram>, keep: &[bool]) -> R<()> {
        let Some(idx) = target.resolve_own(INIT_FN) else {
            return Ok(());
        };
        let args = keep.iter().map(|&k| Value::Bool(k)).collect();
        self.call_in(on, target, idx, args)?;
        Ok(())
    }

    /// Recompile-in-place `id` onto `new_prog` (spec §7.2/§7.3: `update()`),
    /// migrating every var whose old value is still present and
    /// type-conforms to its (possibly changed) declared type; every other
    /// var re-runs its initialiser (or is `null` if it has none), exactly
    /// like `crate::world::World::install`'s tree-walker equivalent. Vars
    /// declared by a program no longer in the chain are dropped. All the
    /// migration decisions are made and applied to a fresh `vars` map
    /// before any `$init` runs, so a failing initialiser rolls back to the
    /// caller's snapshot (see `RegistryHost::upgrade_or_err`'s caller in
    /// `Registry`/`World` integration) rather than leaving the object
    /// half-migrated.
    pub fn upgrade(
        &mut self,
        id: ObjectId,
        new_prog: Rc<CompiledProgram>,
    ) -> Result<(), UpgradeWarning> {
        let program_label = new_prog.path.to_string();
        let warn = |message: String| UpgradeWarning {
            object: id,
            program: program_label.clone(),
            message,
        };
        let Some(old_program) = self.registry.get(id).map(|o| o.program.clone()) else {
            return Err(warn("upgrade of a destructed object".to_string()));
        };
        // Spec §7.3 "the common case": an unchanged variable layout is an
        // O(1) pointer swap — no var copy, no `$init` re-run, no
        // `upgrade()` call, because there is nothing for either to do.
        if old_program.schema_hash == new_prog.schema_hash {
            if let Some(o) = self.registry.get_mut(id) {
                o.program = new_prog;
            }
            self.call_cache.clear();
            return Ok(());
        }
        let old_vars = self.registry.get(id).expect("checked above").vars.clone();
        let from_version = old_program.version;
        let chain = new_prog.chain();
        let new_spec_by_key: HashMap<(Rc<str>, Rc<str>), &VarSpec> = chain
            .iter()
            .flat_map(|anc| {
                anc.var_specs
                    .iter()
                    .map(move |s| ((anc.path.clone(), s.name.clone()), s))
            })
            .collect();
        let mut new_vars = Vars::new();
        let mut plan: Vec<(Rc<CompiledProgram>, Vec<bool>)> = Vec::new();
        for ancestor in &chain {
            let mut keep = Vec::new();
            for spec in ancestor.init_specs() {
                let key = (ancestor.path.clone(), spec.name.clone());
                match old_vars.get(&key).filter(|v| value_conforms(v, &spec.ty)) {
                    Some(v) => {
                        new_vars.insert(key, v.clone());
                        keep.push(true);
                    }
                    None => keep.push(false),
                }
            }
            // Vars without an initialiser always keep whatever was already
            // stored (or stay absent, reading back as `null`): there is no
            // initialiser to fall back to if the type no longer conforms.
            for spec in ancestor.var_specs.iter().filter(|s| !s.has_init) {
                let key = (ancestor.path.clone(), spec.name.clone());
                if let Some(v) = old_vars.get(&key).filter(|v| value_conforms(v, &spec.ty)) {
                    new_vars.insert(key, v.clone());
                }
            }
            plan.push((ancestor.clone(), keep));
        }
        // Spec §7.2 step 6.3: variables removed or whose type changed
        // incompatibly are handed to `upgrade(from_version, old)` in
        // portable form. For the types the checker supports today (no
        // struct/enum yet, W0208/W0209) "portable form" is just the raw
        // stored value; struct/enum by-name conversion (spec r5 D27) is
        // out of scope until those types exist (tracked separately).
        let mut old_map = heap::MapData::default();
        for (key, old_val) in old_vars.iter() {
            let survives = new_spec_by_key
                .get(key)
                .is_some_and(|spec| value_conforms(old_val, &spec.ty));
            if !survives {
                old_map.insert(Value::str(&key.1), old_val.clone());
            }
        }
        // Everything from here on must be all-or-nothing for *this object*
        // (spec §7.2 step 6.4): on any failure the object stays on
        // `old_program`/`old_vars`, the error is reported (not fatal), and
        // `create()` is never re-run (D-P1.4) — only `$init` for vars whose
        // value didn't survive, and the user's own `upgrade()`, if defined.
        let outcome: R<()> = (|| {
            if let Some(o) = self.registry.get_mut(id) {
                o.program = new_prog.clone();
                o.vars = new_vars.clone();
                o.recompute_mem_bytes();
            }
            self.call_cache.clear();
            for (ancestor, keep) in &plan {
                self.run_init(id, ancestor, keep)?;
            }
            if let Some((target, idx)) = new_prog.resolve("upgrade") {
                let mark = self.begin_atomic();
                let args = vec![Value::Int(from_version as i64), Value::map(old_map.clone())];
                match self.call_in(id, &target, idx, args) {
                    Ok(_) => self.commit_atomic(mark),
                    Err(e) => {
                        self.rollback_atomic(mark);
                        return Err(e);
                    }
                }
            }
            Ok(())
        })();
        match outcome {
            Ok(()) => Ok(()),
            Err(e) => {
                if let Some(o) = self.registry.get_mut(id) {
                    o.program = old_program;
                    o.vars = old_vars;
                    o.recompute_mem_bytes();
                }
                self.call_cache.clear();
                Err(warn(e.report()))
            }
        }
    }

    /// Install the output of [`Compiler::recompile`]: register every new
    /// [`CompiledProgram`] (the compile wave is already all-or-nothing —
    /// see [`Compiler::recompile`] — so registering it here never fails).
    ///
    /// **Lazy by default (spec §7.2/§7.3, OBI-89):** unlike the eager,
    /// synchronous-migrate-everything behaviour this replaces, `install`
    /// itself does not touch any existing object's program pointer at all
    /// — it only bumps [`Registry::install_generation`], which is what
    /// makes every affected object *stale* the next time anything checks
    /// ([`RegistryHost::ensure_current`], run from every cross-object
    /// call, driver-started apply, and the inline-cache fast path). An
    /// object not accessed since this call still reports its old program
    /// version until it is. This always returns `Ok(vec![])` now — there
    /// is nothing left to attempt synchronously — kept as
    /// `Result<Vec<UpgradeWarning>, String>` for source compatibility with
    /// existing callers (`World::compile_object`); lazy migration failures
    /// surface instead through [`Registry::lazy_upgrade_warnings`].
    ///
    /// **Eager mode** is not install-time at all in this slice: a builder
    /// (or the mudlib) opts a path into it explicitly with the
    /// `upgrade_all(path)` efun, which queues every affected object onto
    /// [`Registry::eager_upgrade_queue`] for `World::tick` to migrate a
    /// bounded batch of per tick, rather than blocking. A per-program
    /// pragma choosing eager as the *default* for that program (spec §7.2
    /// step 5) is deferred to Phase 2 (D-P1.7): lazy everywhere, eager only
    /// via an explicit `upgrade_all`.
    pub fn install(
        &mut self,
        new_set: HashMap<String, Rc<CompiledProgram>>,
    ) -> Result<Vec<UpgradeWarning>, String> {
        for v in new_set.values() {
            self.registry.register_program(v.clone());
        }
        self.registry.install_generation += 1;
        // Programs were replaced: an old `Rc<CompiledProgram>` may now be
        // freed and its address reused by new code, which would make a
        // stale `CallSite` (keyed by code address) collide with a live
        // one. Clear the per-call-site inline cache on every install
        // outcome (still needed even though no object is touched here: a
        // path with zero live instances drops its old `CompiledProgram`
        // to refcount 0 immediately on `register_program`, and any cache
        // entry naming it would otherwise be the only thing keeping that
        // address's reuse unsafe to ignore).
        self.call_cache.clear();
        Ok(Vec::new())
    }
}

/// Shallow runtime conformance check of a stored value against a HIR type,
/// used by [`RegistryHost::upgrade`] to decide whether a var's old value
/// survives a recompile (spec §7.2/§7.3). Mirrors `Value::conforms`
/// (`crate::bcvm::heap`), which checks against the AST-level `Type` the
/// checker builds expressions with; this checks against
/// `loom_compiler::ty::Ty`, the HIR-level type `hir::Var::ty` uses,
/// because `CompiledProgram` only keeps the HIR var declarations.
fn value_conforms(v: &Value, ty: &Ty) -> bool {
    match ty {
        Ty::Any => true,
        Ty::Optional(inner) => matches!(v, Value::Null) || value_conforms(v, inner),
        Ty::Null => matches!(v, Value::Null),
        Ty::Int => matches!(v, Value::Int(_)),
        Ty::Float => matches!(v, Value::Float(_)),
        Ty::Bool => matches!(v, Value::Bool(_)),
        Ty::String => v.as_str().is_some(),
        Ty::Object => matches!(v, Value::Object(_)),
        Ty::Array(_) => v.as_array().is_some(),
        Ty::Map(..) => v.as_map().is_some(),
        // Vars can't declare `void`/`never`/`fn`/`error` (spec r5 §5.2.2
        // rule 4 bans function-typed persistents; the checker never lets
        // the others through as a var's declared type) — conservative
        // false rather than a panic if one ever does.
        Ty::Void | Ty::Never | Ty::Fn(_) | Ty::Error => false,
        // Shallow nominal check only (module + name): does not verify the
        // stored value's fields/variant still match the *current* schema
        // field-by-field. `crate::bcvm::schema_convert` does that deep,
        // by-name, lossless-or-portable comparison (spec r5 §7.3); wiring
        // it into this by-name var carry-over is OBI-34's own follow-up,
        // not this check (see OBI-88).
        Ty::Struct(s) => v.as_struct().is_some_and(|sv| sv.name == s.name),
        Ty::Enum(e) => v.as_enum().is_some_and(|ev| ev.name == e.name),
    }
}

impl Host for RegistryHost<'_> {
    fn self_object(&self) -> ObjectId {
        *self
            .self_stack
            .last()
            .expect("self_stack is never empty while a Host call is in flight")
    }

    fn call_static(&mut self, program: &str, name: &str, args: Vec<Value>) -> R<Value> {
        self.run_target(CallTarget::Static { program, name }, args)
    }

    fn call_virtual(&mut self, name: &str, args: Vec<Value>) -> R<Value> {
        self.run_target(CallTarget::Virtual { name }, args)
    }

    fn call_other(&mut self, recv: Value, name: &str, args: Vec<Value>) -> R<Value> {
        self.run_target(CallTarget::Other { recv, name }, args)
    }

    /// D26: hand the resolved function back to the interpreter so it runs
    /// as a frame on the caller's own flat stack (no nested `Interpreter`,
    /// no native recursion, suspendable at any `TickCheck`).
    ///
    /// **Per-call-site inline cache (spec §5.8):** the actual dispatch
    /// resolution (`resolve_target`, itself already a single hash lookup
    /// per program via `CompiledProgram::resolve`/`resolve_own`, not a
    /// linear scan) always runs here; [`RegistryHost::dispatch_cached`] is
    /// what lets a monomorphic call site skip both that lookup *and* the
    /// interpreter materializing the callee name at all. This method
    /// always (re-)populates the cache slot for `site`, so a call that
    /// missed once still gets cached for next time.
    fn dispatch(
        &mut self,
        site: CallSite,
        target: CallTarget<'_>,
        args: Vec<Value>,
    ) -> R<HostCall> {
        let (self_obj, guard, code, func) = self.resolve_target(target)?;
        if !inline_cache_disabled() {
            self.call_cache.insert(
                site,
                CacheEntry {
                    guard,
                    target: code.clone(),
                    func,
                },
            );
        }
        Ok(HostCall::Enter {
            code,
            func,
            self_obj,
            args,
            captures: Vec::new(),
        })
    }

    /// Fast path: served entirely from [`RegistryHost::call_cache`], no
    /// name lookup, if `site` is cached and its guard still matches the
    /// current receiver (self for `recv == None`, `recv` itself
    /// otherwise). See [`Host::dispatch_cached`]'s doc for why this exists
    /// as its own method instead of just an internal fast path inside
    /// `dispatch`: skipping the *interpreter's own* `str_of(..).to_string()`
    /// on a cache hit needs the interpreter to ask before it has a name to
    /// hand `dispatch` at all.
    fn dispatch_cached(
        &mut self,
        site: CallSite,
        recv: Option<&Value>,
        args: Vec<Value>,
    ) -> Result<HostCall, Vec<Value>> {
        if inline_cache_disabled() {
            return Err(args);
        }
        // Spec §7.2/§7.3 (OBI-89): a cache hit would otherwise keep
        // serving a *stale* target forever — the cached guard is the
        // receiver's own leaf program at resolution time, which never
        // changes just because `Registry::programs` now holds something
        // newer for its path, only `RegistryHost::upgrade` changes it.
        // `ensure_current` is the one `u64` compare in the common case
        // (nothing installed since last checked); only an actual stale
        // object pays for the lookup, and it always changes `o.program`
        // when it migrates, which then naturally misses the guard check
        // below.
        let target_id = match recv {
            None => Some(self.self_object()),
            Some(Value::Object(id)) => Some(*id),
            Some(_) => None,
        };
        if let Some(id) = target_id {
            self.ensure_current(id);
        }
        let Some(entry) = self.call_cache.get(&site) else {
            return Err(args);
        };
        match self.current_guard(recv) {
            Some((receiver, g)) if Rc::ptr_eq(&g, &entry.guard) => Ok(HostCall::Enter {
                code: entry.target.clone(),
                func: entry.func,
                self_obj: receiver,
                args,
                captures: Vec::new(),
            }),
            _ => Err(args),
        }
    }

    /// See [`Host::dispatch_value`] (spec r5 §5.2.2, OBI-79). `creator`
    /// must still be a live object for either shape (the destructed-object
    /// AC); a `Named` reference then late-binds `callee` on `creator`'s
    /// *current* program — unlike `call_other`, this may reach a private
    /// or `super::`-declared function, because the value itself could
    /// only ever have been formed by code of `creator`'s own program
    /// naming it in the first place.
    fn dispatch_value(
        &mut self,
        creator: ObjectId,
        body: &FnBody,
        args: Vec<Value>,
    ) -> R<HostCall> {
        let prog = self
            .registry
            .get(creator)
            .ok_or_else(|| RtError::new("call on a destructed object"))?
            .program
            .clone();
        match body {
            FnBody::Named(callee) => {
                let (target, idx) = match callee {
                    Callee::Virtual { name } => prog.resolve(name).ok_or_else(|| {
                        RtError::new(format!(
                            "stale closure: no function `{name}` on {}",
                            prog.path
                        ))
                    })?,
                    Callee::Static { program, name } => {
                        let target = prog
                            .chain()
                            .into_iter()
                            .find(|p| p.path.as_ref() == program.as_ref())
                            .ok_or_else(|| {
                                RtError::new(format!(
                                    "`{program}` is not an ancestor of {}",
                                    prog.path
                                ))
                            })?;
                        let idx = target.resolve_own(name).ok_or_else(|| {
                            RtError::new(format!("no function `{name}` in {program}"))
                        })?;
                        (target, idx)
                    }
                };
                Ok(HostCall::Enter {
                    code: target,
                    func: idx,
                    self_obj: creator,
                    args,
                    captures: Vec::new(),
                })
            }
            FnBody::Closure {
                code,
                func,
                captures,
                ..
            } => Ok(HostCall::Enter {
                code: code.clone(),
                func: *func,
                self_obj: creator,
                args,
                captures: captures.clone(),
            }),
        }
    }

    /// See [`Host::current_program`].
    fn current_program(&self) -> R<Rc<dyn ProgramCode>> {
        let id = self.self_object();
        let prog = self
            .registry
            .get(id)
            .ok_or_else(|| RtError::new("call on a destructed object"))?
            .program
            .clone();
        Ok(prog as Rc<dyn ProgramCode>)
    }

    fn enter_self(&mut self, obj: ObjectId) {
        self.push_self(obj);
    }

    fn leave_self(&mut self) {
        self.pop_self();
    }

    fn current_guard(&self) -> GuardSet {
        self.top_guard().clone()
    }

    /// See [`Host::current_uid`] (OBI-35 D-S1.6): the uid a function value
    /// created right now records as `quota_uid`, absent a roles/tier
    /// snapshot to pick "the lowest-tier principal" from instead.
    fn current_uid(&self) -> Sym {
        principal_of(self.registry, self.self_object()).uid
    }

    fn enter_creator_frame(&mut self, guard: &GuardSet) {
        let g = self.top_guard().union(guard);
        self.guards.push(g);
    }

    fn leave_creator_frame(&mut self) {
        self.guards.pop();
    }

    fn take_extra_ticks(&mut self) -> u64 {
        std::mem::take(&mut self.extra_ticks)
    }

    fn call_efun(&mut self, name: &str, args: Vec<Value>) -> R<Value> {
        self.driver_efun(name, args)
    }

    fn load_global(&mut self, owner: &str, name: &str) -> R<Value> {
        let self_id = self.self_object();
        let Some(o) = self.registry.get(self_id) else {
            // OBI-85 CTO review: a plain `Ok(Null)` here would make a
            // stale `self` (destructed mid-call, e.g. by its own
            // `destruct(self)`) silently read every field back as `null`
            // instead of surfacing the runtime error it actually is.
            return Err(RtError::new("self was destructed"));
        };
        Ok(o.vars
            .get(&(Rc::from(owner), Rc::from(name)))
            .cloned()
            .unwrap_or(Value::Null))
    }

    fn store_global(&mut self, owner: &str, name: &str, v: Value) -> R<()> {
        let self_id = self.self_object();
        let quota = self.limits.mem_quota_bytes;
        let key: (Rc<str>, Rc<str>) = (Rc::from(owner), Rc::from(name));
        let new_bytes = heap::cost(&v);
        let Some(o) = self.registry.get_mut(self_id) else {
            // OBI-85 CTO review: writing a field on a destructed `self`
            // is a runtime error, same as reading one (`load_global`
            // above), not a silent no-op.
            return Err(RtError::new("self was destructed"));
        };
        let old_bytes = o.vars.get(&key).map(heap::cost).unwrap_or(0);
        let new_total = o
            .mem_bytes
            .saturating_sub(old_bytes)
            .saturating_add(new_bytes);
        if new_total > quota {
            return Err(RtError::new(format!(
                "{}: memory quota exceeded writing `{name}` ({new_total} bytes of vars would be \
                 in use, quota is {quota} bytes)",
                o.name
            )));
        }
        let old = o.vars.get(&key).cloned();
        o.mem_bytes = new_total;
        o.vars.insert(key.clone(), v);
        self.registry.journal_var_write(self_id, key, old);
        Ok(())
    }

    fn record_cow_copy(&mut self, program: &str) {
        self.registry.cow_metrics.record(program);
    }

    fn begin_atomic(&mut self) -> u64 {
        self.registry.journal_begin()
    }

    fn commit_atomic(&mut self, mark: u64) {
        self.registry.journal_commit(mark);
    }

    fn rollback_atomic(&mut self, mark: u64) {
        self.registry.journal_rollback(mark);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bcvm::vm::Exec;
    use loom_compiler::mudlib::{Outcome, Session};
    use proptest::prelude::*;

    #[test]
    fn self_recursive_virtual_call_hits_the_depth_guard_not_the_native_stack() {
        const WF: &str = r#"
fn dive(n: int) -> int {
    return dive(n + 1)
}

pub fn go() -> int {
    return dive(0)
}
"#;
        let module = compile("/obj/thing", &[("/obj/thing", WF)]);
        let mut registry = Registry::default();
        let prog = Rc::new(CompiledProgram::new(module, 1, None, Vec::new()));
        registry.register_program(prog.clone());
        let obj = make_object(&mut registry, prog);
        let mut host = RegistryHost::new(&mut registry, obj);
        let err = host.call_on(obj, "go", vec![]).unwrap_err();
        assert!(
            err.report().contains("Too deep recursion"),
            "{}",
            err.report()
        );
    }

    fn compile(path: &str, files: &[(&str, &str)]) -> Module {
        let map: HashMap<String, String> = files
            .iter()
            .map(|(p, s)| (p.to_string(), s.to_string()))
            .collect();
        let mut session = Session::new(map);
        match session.compile(path) {
            Outcome::Ok(checked) => {
                crate::bcvm::compile_and_verify(&checked.hir).expect("codegen + verify")
            }
            Outcome::Failed(report) => panic!("check failed:\n{report}"),
            Outcome::Missing(msg) => panic!("{msg}"),
        }
    }

    fn compile_program(
        path: &str,
        files: &[(&str, &str)],
        version: u32,
        parent: Option<Rc<CompiledProgram>>,
    ) -> CompiledProgram {
        let map: HashMap<String, String> = files
            .iter()
            .map(|(p, s)| (p.to_string(), s.to_string()))
            .collect();
        let mut session = Session::new(map);
        match session.compile(path) {
            Outcome::Ok(checked) => {
                compile_hir_program(&checked.hir, version, parent).expect("codegen + verify")
            }
            Outcome::Failed(report) => panic!("check failed:\n{report}"),
            Outcome::Missing(msg) => panic!("{msg}"),
        }
    }

    // ---- OBI-79: closures / function-value runtime ----------------------

    /// A named function reference (`let f = add_one`) is late-bound at
    /// call time by `(creator, name)` on the creator's *current* program
    /// (spec r5 §5.2.2): a private function — which `ob.f()` could never
    /// reach — is still callable through a value formed from inside its
    /// own program. Closures capture by value: `make_adder(10)`'s closure
    /// keeps its own snapshot of `n` independent of the object's later
    /// state.
    #[test]
    fn named_function_values_and_by_value_closure_capture() {
        const WF: &str = r#"
fn add_one(x: int) -> int {
    return x + 1
}

pub fn named_ref() -> fn(int) -> int {
    return add_one
}

pub fn call_named() -> int {
    let g = named_ref()
    return g(41)
}

pub fn make_adder(n: int) -> fn(int) -> int {
    return fn(x: int) => x + n
}

var n: int = 999

pub fn use_adder() -> int {
    let f = make_adder(10)
    n = -1
    return f(5)
}
"#;
        let module = compile("/obj/fns", &[("/obj/fns", WF)]);
        let mut registry = Registry::default();
        let prog = Rc::new(CompiledProgram::new(module, 1, None, Vec::new()));
        registry.register_program(prog.clone());
        let obj = make_object(&mut registry, prog);
        let mut host = RegistryHost::new(&mut registry, obj);

        let got = host.call_on(obj, "call_named", vec![]).unwrap();
        assert!(
            got.equals(&Value::Int(42)),
            "private named ref, late-bound call: {got:?}"
        );

        // The closure's capture of `n` (the *parameter*, by value) must not
        // be confused with the program variable of the same name that
        // `use_adder` mutates right after creating the closure: `f(5)` must
        // still see the captured `10`, not the object's `-1`.
        let got = host.call_on(obj, "use_adder", vec![]).unwrap();
        assert!(
            got.equals(&Value::Int(15)),
            "closure must capture its own parameter by value: {got:?}"
        );
    }

    /// Invoking a function value whose creator object was destructed in the
    /// meantime fails cleanly (a plain runtime error), not a panic or a
    /// call into freed state (OBI-32 original AC, carried into OBI-79).
    #[test]
    fn calling_a_function_value_whose_creator_was_destructed_fails_cleanly() {
        const OWNER_WF: &str = r#"
pub fn make_cb() -> fn() -> int {
    return fn() => 1
}
"#;
        const CALLER_WF: &str = r#"
pub fn call_stored(f: fn() -> int) -> int {
    return f()
}
"#;
        let owner_module = compile("/obj/owner", &[("/obj/owner", OWNER_WF)]);
        let caller_module = compile("/obj/caller", &[("/obj/caller", CALLER_WF)]);
        let mut registry = Registry::default();
        let owner_prog = Rc::new(CompiledProgram::new(owner_module, 1, None, Vec::new()));
        let caller_prog = Rc::new(CompiledProgram::new(caller_module, 1, None, Vec::new()));
        registry.register_program(owner_prog.clone());
        registry.register_program(caller_prog.clone());
        let owner = make_object(&mut registry, owner_prog);
        let caller = make_object(&mut registry, caller_prog);

        let mut host = RegistryHost::new(&mut registry, owner);
        let f = host.call_on(owner, "make_cb", vec![]).unwrap();
        host.registry.remove(owner);

        let err = host
            .call_on(caller, "call_stored", vec![f])
            .expect_err("the creator is gone: this must not panic or silently succeed");
        assert!(err.report().contains("destructed"), "{}", err.report());
    }

    /// An anonymous closure keeps the creator's program version it was
    /// created under, even after the creator is hot-reload-upgraded to a
    /// new version: the old `CompiledProgram` is kept alive by the
    /// closure's own `Rc` (spec r5 §5.2.2's "old version stays alive via
    /// the closures' refcount, freed after the last one dies") and the
    /// closure's body keeps running the *old* code, not the new one.
    #[test]
    fn anonymous_closures_pin_their_creators_program_version_across_an_upgrade() {
        const V1: &str = r#"
pub fn make_cb() -> fn() -> string {
    return fn() => "v1"
}

pub fn call_stored(f: fn() -> string) -> string {
    return f()
}
"#;
        const V2: &str = r#"
pub fn make_cb() -> fn() -> string {
    return fn() => "v2"
}

pub fn call_stored(f: fn() -> string) -> string {
    return f()
}
"#;
        let module1 = compile("/obj/cb", &[("/obj/cb", V1)]);
        let module2 = compile("/obj/cb", &[("/obj/cb", V2)]);
        let mut registry = Registry::default();
        let prog1 = Rc::new(CompiledProgram::new(module1, 1, None, Vec::new()));
        registry.register_program(prog1.clone());
        let obj = make_object(&mut registry, prog1.clone());
        let mut host = RegistryHost::new(&mut registry, obj);

        let f = host.call_on(obj, "make_cb", vec![]).unwrap();
        match &f.as_fn().unwrap().body {
            FnBody::Closure {
                program_version, ..
            } => assert_eq!(*program_version, 1),
            other => panic!("expected a closure, got {other:?}"),
        }

        let with_pin = Rc::strong_count(&prog1);

        let prog2 = Rc::new(CompiledProgram::new(module2, 2, None, Vec::new()));
        host.registry.register_program(prog2.clone());
        host.upgrade(obj, prog2).unwrap();
        assert_eq!(host.registry.get(obj).unwrap().program.version, 2);

        // Still callable after the upgrade, and still running the *old*
        // body — the AC's "anonymous closures keep their program version".
        let got = host.call_on(obj, "call_stored", vec![f.clone()]).unwrap();
        assert_eq!(got.as_str(), Some("v1"));

        drop(f);
        assert!(
            Rc::strong_count(&prog1) < with_pin,
            "the pinned v1 program must be freed once the last closure holding it is dropped"
        );
    }

    fn make_object(reg: &mut Registry, prog: Rc<CompiledProgram>) -> ObjectId {
        reg.insert(BcObject::new(prog))
    }

    /// D24 aliasing test, cross-object case (spec r5): a `pub fn` on one
    /// object returns a program variable (a map); a *different* object
    /// mutates the map it got back. The original object's own variable is
    /// unchanged — proving the value crossed the `call_other` boundary by
    /// copy-on-write value, not by shared reference, exactly like the
    /// in-module aliasing test in `bcvm::vm`, but now through two distinct
    /// `Host`-mediated objects (standing in for "another uid" until the
    /// security/uid model exists).
    #[test]
    fn cross_object_call_other_returns_a_value_not_a_shared_reference() {
        const OWNER_WF: &str = r#"
var data: {string: int} = {"a": 1}

pub fn get_data() -> {string: int} {
    return data
}
"#;
        const CALLER_WF: &str = r#"
pub fn mutate_and_return(m: {string: int}) -> {string: int} {
    m["a"] = 999
    return m
}
"#;
        let owner_module = compile("/obj/owner", &[("/obj/owner", OWNER_WF)]);
        let caller_module = compile("/obj/caller", &[("/obj/caller", CALLER_WF)]);

        let mut registry = Registry::default();
        let owner_prog = Rc::new(CompiledProgram::new(owner_module, 1, None, Vec::new()));
        let caller_prog = Rc::new(CompiledProgram::new(caller_module, 1, None, Vec::new()));
        registry.register_program(owner_prog.clone());
        registry.register_program(caller_prog.clone());

        let owner = make_object(&mut registry, owner_prog.clone());
        let caller = make_object(&mut registry, caller_prog);
        // Var initialisers aren't emitted into bytecode by codegen (that is
        // `World::init_vars`'s job, still tree-walker-only); seed the
        // declared default by hand, the same way `bcvm_e2e.rs` does.
        registry.get_mut(owner).unwrap().vars.insert(
            (owner_prog.path.clone(), Rc::from("data")),
            Value::map({
                let mut m = crate::bcvm::MapData::default();
                m.insert(Value::str("a"), Value::Int(1));
                m
            }),
        );

        let mut host = RegistryHost::new(&mut registry, owner);
        let got = host.call_on(owner, "get_data", vec![]).unwrap();
        let mutated = host
            .call_on(caller, "mutate_and_return", vec![got])
            .unwrap();
        assert!(
            mutated
                .as_map()
                .unwrap()
                .get(&Value::str("a"))
                .unwrap()
                .equals(&Value::Int(999))
        );

        // The owner's own copy must be untouched by the caller's mutation.
        let still = host.call_on(owner, "get_data", vec![]).unwrap();
        assert!(
            still
                .as_map()
                .unwrap()
                .get(&Value::str("a"))
                .unwrap()
                .equals(&Value::Int(1))
        );
    }

    /// Per-program dispatch: an override in a child program is what
    /// `call_virtual`/`call_other` resolve to; `super::` reaches the
    /// parent's own definition explicitly.
    #[test]
    fn virtual_dispatch_picks_the_most_derived_override_and_super_reaches_the_parent() {
        const PARENT_WF: &str = r#"
pub fn greet() -> string {
    return "hello from parent"
}
"#;
        const CHILD_WF: &str = r#"
inherit /obj/parent

pub override fn greet() -> string {
    return "hello from child"
}

pub fn parent_greet() -> string {
    return super::greet()
}
"#;
        let parent_module = compile("/obj/parent", &[("/obj/parent", PARENT_WF)]);
        let files = [("/obj/parent", PARENT_WF), ("/obj/child", CHILD_WF)];
        let child_module = compile("/obj/child", &files);

        let mut registry = Registry::default();
        let parent_prog = Rc::new(CompiledProgram::new(parent_module, 1, None, Vec::new()));
        registry.register_program(parent_prog.clone());
        let child_prog = Rc::new(CompiledProgram::new(
            child_module,
            1,
            Some(parent_prog),
            Vec::new(),
        ));
        registry.register_program(child_prog.clone());

        let mut registry2 = registry;
        let child = make_object(&mut registry2, child_prog);

        let mut host = RegistryHost::new(&mut registry2, child);
        let greet = host.call_on(child, "greet", vec![]).unwrap();
        assert_eq!(greet.as_str(), Some("hello from child"));

        let via_super = host.call_on(child, "parent_greet", vec![]).unwrap();
        assert_eq!(via_super.as_str(), Some("hello from parent"));
    }

    /// `$init` (spec §7.2 var initialisers, synthesised by
    /// [`synth_init_function`]) runs automatically on
    /// [`RegistryHost::instantiate`], root ancestor first: a child's
    /// variable initialiser can already read a parent's initialised
    /// variable (via `super::`-free virtual dispatch reaching the parent's
    /// `pub fn`), proving both the ordering and that no test needs to seed
    /// vars by hand the way `bcvm_e2e.rs`/the earlier cross-object test
    /// did.
    #[test]
    fn instantiate_runs_var_initialisers_root_first_without_manual_seeding() {
        const PARENT_WF: &str = r#"
var base: int = 10

pub fn get_base() -> int {
    return base
}
"#;
        const CHILD_WF: &str = r#"
inherit /obj/parent

var derived: int = get_base() + 5

pub fn get_derived() -> int {
    return derived
}
"#;
        let parent = compile_program("/obj/parent", &[("/obj/parent", PARENT_WF)], 1, None);
        let parent_prog = Rc::new(parent);
        let files = [("/obj/parent", PARENT_WF), ("/obj/child", CHILD_WF)];
        let child = compile_program("/obj/child", &files, 1, Some(parent_prog.clone()));
        let child_prog = Rc::new(child);

        let mut registry = Registry::default();
        registry.register_program(parent_prog);
        registry.register_program(child_prog.clone());

        // `RegistryHost::new` needs a starting `self`, but `instantiate`
        // doesn't have an object yet — a placeholder id is fine, it is
        // never read before `instantiate` pushes the real one.
        let placeholder = ObjectId {
            index: u32::MAX,
            generation: 0,
        };
        let mut host = RegistryHost::new(&mut registry, placeholder);
        let obj = host.instantiate(child_prog).expect("instantiate");

        let base = host.call_on(obj, "get_base", vec![]).unwrap();
        assert!(base.equals(&Value::Int(10)));
        let derived = host.call_on(obj, "get_derived", vec![]).unwrap();
        assert!(derived.equals(&Value::Int(15)));
    }

    /// `RegistryHost::upgrade` (spec §7.2/§7.3 `update()`): a var whose
    /// declared type didn't change keeps its live value across the
    /// upgrade — the initialiser does *not* re-run — proven by mutating
    /// the var away from its initialiser's value before upgrading.
    #[test]
    fn upgrade_keeps_a_type_compatible_var_instead_of_rerunning_its_initialiser() {
        const V1_WF: &str = r#"
var counter: int = 1

pub fn get_counter() -> int {
    return counter
}

pub fn set_counter(n: int) {
    counter = n
}
"#;
        // Same var, same type, but a new function and a changed initialiser
        // expression — recompiling must not reset an already-mutated value.
        const V2_WF: &str = r#"
var counter: int = 1

pub fn get_counter() -> int {
    return counter
}

pub fn set_counter(n: int) {
    counter = n
}

pub fn doubled() -> int {
    return counter * 2
}
"#;
        let v1 = Rc::new(compile_program(
            "/obj/thing",
            &[("/obj/thing", V1_WF)],
            1,
            None,
        ));
        let mut registry = Registry::default();
        registry.register_program(v1.clone());
        let placeholder = ObjectId {
            index: u32::MAX,
            generation: 0,
        };
        let mut host = RegistryHost::new(&mut registry, placeholder);
        let obj = host.instantiate(v1).expect("instantiate");
        host.call_on(obj, "set_counter", vec![Value::Int(42)])
            .unwrap();

        let v2 = Rc::new(compile_program(
            "/obj/thing",
            &[("/obj/thing", V2_WF)],
            2,
            None,
        ));
        registry.register_program(v2.clone());
        let mut host = RegistryHost::new(&mut registry, obj);
        host.upgrade(obj, v2).expect("upgrade");

        let counter = host.call_on(obj, "get_counter", vec![]).unwrap();
        assert!(
            counter.equals(&Value::Int(42)),
            "upgrade must keep the mutated value, not rerun `var counter: int = 1`"
        );
        let doubled = host.call_on(obj, "doubled", vec![]).unwrap();
        assert!(doubled.equals(&Value::Int(84)));
    }

    /// A var whose declared type *changed* incompatibly can't keep its old
    /// value (spec §7.2/§7.3: migrate by declaring-program+name+type, else
    /// re-run the initialiser) — the upgrade re-initialises it instead of
    /// leaving a value of the wrong type behind.
    #[test]
    fn upgrade_reinitialises_a_var_whose_type_changed() {
        const V1_WF: &str = r#"
var data: int = 1

pub fn get_data() -> int {
    return data
}
"#;
        const V2_WF: &str = r#"
var data: string = "fresh"

pub fn get_data() -> string {
    return data
}
"#;
        let v1 = Rc::new(compile_program(
            "/obj/thing",
            &[("/obj/thing", V1_WF)],
            1,
            None,
        ));
        let mut registry = Registry::default();
        registry.register_program(v1.clone());
        let placeholder = ObjectId {
            index: u32::MAX,
            generation: 0,
        };
        let mut host = RegistryHost::new(&mut registry, placeholder);
        let obj = host.instantiate(v1).expect("instantiate");

        let v2 = Rc::new(compile_program(
            "/obj/thing",
            &[("/obj/thing", V2_WF)],
            2,
            None,
        ));
        registry.register_program(v2.clone());
        let mut host = RegistryHost::new(&mut registry, obj);
        host.upgrade(obj, v2).expect("upgrade");

        let data = host.call_on(obj, "get_data", vec![]).unwrap();
        assert_eq!(data.as_str(), Some("fresh"));
    }

    /// OBI-78 review: `upgrade` replaces `vars` wholesale, so `mem_bytes`
    /// must be re-derived, not carried over. Otherwise a var dropped by the
    /// migration stays charged forever and repeated hot-reloads push the
    /// object toward a false quota error.
    #[test]
    fn upgrade_recomputes_mem_bytes_instead_of_carrying_dropped_vars() {
        const V1_WF: &str = r#"
var blob: string = "0123456789012345678901234567890123456789"
"#;
        const V2_WF: &str = r#"
var other: int = 1
"#;
        let v1 = Rc::new(compile_program(
            "/obj/thing",
            &[("/obj/thing", V1_WF)],
            1,
            None,
        ));
        let mut registry = Registry::default();
        registry.register_program(v1.clone());
        let placeholder = ObjectId {
            index: u32::MAX,
            generation: 0,
        };
        let mut host = RegistryHost::new(&mut registry, placeholder);
        let obj = host.instantiate(v1).expect("instantiate");
        // OBI-80 deep accounting: a var's cost is its own 16-byte slot plus
        // the value's cached `deep_bytes` (here just the 40-byte string;
        // primitives/short containers still stay under any real quota, but
        // there is no such thing as a *free* var slot any more).
        assert_eq!(registry.get(obj).unwrap().mem_bytes, 56);

        let v2 = Rc::new(compile_program(
            "/obj/thing",
            &[("/obj/thing", V2_WF)],
            2,
            None,
        ));
        registry.register_program(v2.clone());
        let mut host = RegistryHost::new(&mut registry, obj);
        host.upgrade(obj, v2).expect("upgrade");
        assert_eq!(
            registry.get(obj).unwrap().mem_bytes,
            16,
            "`blob` was dropped by the upgrade (freeing its 56 bytes) and replaced by \
             `other: int = 1`, whose own slot still costs 16 — it must not still be carrying \
             `blob`'s share"
        );
    }

    /// Spec §7.3 "the common case": recompiling a program without
    /// touching its variable layout (only a function body changed) must
    /// leave `schema_hash` unchanged, so `upgrade` takes the O(1)
    /// pointer-swap path — proven here by checking the hash directly and
    /// by upgrading an object whose var was mutated away from its
    /// initialiser: a body-only change must not re-run `$init` either.
    #[test]
    fn unchanged_var_layout_keeps_the_same_schema_hash_and_skips_reinit() {
        const V1_WF: &str = r#"
var counter: int = 1

pub fn get_counter() -> int {
    return counter
}

pub fn set_counter(n: int) {
    counter = n
}
"#;
        const V2_WF: &str = r#"
var counter: int = 1

pub fn get_counter() -> int {
    return counter
}

pub fn set_counter(n: int) {
    counter = n
}

pub fn tripled() -> int {
    return counter * 3
}
"#;
        let v1 = Rc::new(compile_program(
            "/obj/thing",
            &[("/obj/thing", V1_WF)],
            1,
            None,
        ));
        let v2 = Rc::new(compile_program(
            "/obj/thing",
            &[("/obj/thing", V2_WF)],
            2,
            None,
        ));
        assert_eq!(
            v1.schema_hash, v2.schema_hash,
            "only a function body changed; the variable layout did not"
        );

        let mut registry = Registry::default();
        registry.register_program(v1.clone());
        let placeholder = ObjectId {
            index: u32::MAX,
            generation: 0,
        };
        let mut host = RegistryHost::new(&mut registry, placeholder);
        let obj = host.instantiate(v1).expect("instantiate");
        host.call_on(obj, "set_counter", vec![Value::Int(7)])
            .unwrap();

        registry.register_program(v2.clone());
        let mut host = RegistryHost::new(&mut registry, obj);
        host.upgrade(obj, v2).expect("upgrade");

        let counter = host.call_on(obj, "get_counter", vec![]).unwrap();
        assert!(counter.equals(&Value::Int(7)));
        let tripled = host.call_on(obj, "tripled", vec![]).unwrap();
        assert!(tripled.equals(&Value::Int(21)));
    }

    /// Spec §7.2 step 6.3/6.4: a var whose type changed incompatibly is
    /// handed to `upgrade(from_version, old)` in `old` (keyed by name, raw
    /// value — no struct/enum types exist yet to need portable form); a
    /// user-defined `upgrade()` can inspect it and set the new var itself,
    /// overriding the freshly-run initialiser.
    #[test]
    fn upgrade_hook_receives_from_version_and_the_dropped_vars_old_value() {
        const V1_WF: &str = r#"
var data: int = 41
"#;
        const V2_WF: &str = r#"
var data: string = "unset"

pub fn upgrade(from_version: int, old: {string: any}) {
    if "data" in old {
        if old["data"] == 41 and from_version == 1 {
            data = "was 41 from v1"
        } else {
            data = "unexpected"
        }
    }
}

pub fn get_data() -> string {
    return data
}
"#;
        let v1 = Rc::new(compile_program(
            "/obj/thing",
            &[("/obj/thing", V1_WF)],
            1,
            None,
        ));
        let mut registry = Registry::default();
        registry.register_program(v1.clone());
        let placeholder = ObjectId {
            index: u32::MAX,
            generation: 0,
        };
        let mut host = RegistryHost::new(&mut registry, placeholder);
        let obj = host.instantiate(v1.clone()).expect("instantiate");

        let v2 = Rc::new(compile_program(
            "/obj/thing",
            &[("/obj/thing", V2_WF)],
            2,
            None,
        ));
        assert_ne!(v1.schema_hash, v2.schema_hash, "the var's type changed");
        registry.register_program(v2.clone());
        let mut host = RegistryHost::new(&mut registry, obj);
        host.upgrade(obj, v2).expect("upgrade");

        let data = host.call_on(obj, "get_data", vec![]).unwrap();
        assert_eq!(data.as_str(), Some("was 41 from v1"));
    }

    /// Spec §7.2 step 6.4 (r5 amendment): a failing `upgrade()` rolls back
    /// *that object* (program and vars) and is reported, not fatal — and
    /// [`RegistryHost::install`] still migrates every *other* affected
    /// object instead of aborting the whole set.
    #[test]
    fn a_failing_upgrade_hook_rolls_back_only_that_object_not_the_whole_install() {
        const ROOM_V1: &str = r#"
var short_desc: string = "An empty room"

pub fn short() -> string {
    return short_desc
}

pub fn set_short(s: string) {
    short_desc = s
}
"#;
        // `short_desc`'s type is unchanged, so it survives the automatic
        // carry-over *before* `upgrade()` runs, letting `upgrade()` see
        // each object's own prior value through `self` and decide per
        // object whether to fail — proving a failure only rolls back the
        // one object it happened on, not the whole install.
        const ROOM_V2: &str = r#"
var short_desc: string = "An empty room"
var upgraded_marker: bool = false

pub fn short() -> string {
    return short_desc
}

pub fn set_short(s: string) {
    short_desc = s
}

pub fn upgrade(from_version: int, old: {string: any}) {
    if short_desc == "BREAK ME" {
        throw "boom"
    }
}
"#;
        let v1 = Rc::new(compile_program(
            "/std/room",
            &[("/std/room", ROOM_V1)],
            1,
            None,
        ));
        let mut registry = Registry::default();
        registry.register_program(v1.clone());
        let placeholder = ObjectId {
            index: u32::MAX,
            generation: 0,
        };
        let (broken, fine) = {
            let mut host = RegistryHost::new(&mut registry, placeholder);
            let broken = host.instantiate(v1.clone()).expect("instantiate");
            let fine = host.instantiate(v1.clone()).expect("instantiate");
            host.call_on(broken, "set_short", vec![Value::str("BREAK ME")])
                .unwrap();
            (broken, fine)
        };

        let v2 = Rc::new(compile_program(
            "/std/room",
            &[("/std/room", ROOM_V2)],
            2,
            None,
        ));
        let mut new_set = HashMap::new();
        new_set.insert("/std/room".to_string(), v2.clone());
        let mut host = RegistryHost::new(&mut registry, placeholder);
        let warnings = host.install(new_set).expect("install itself does not fail");

        // Lazy by default (spec §7.2/§7.3, OBI-89): `install` itself no
        // longer touches any object, so there is nothing to report yet —
        // both objects are still on v1 until something accesses them.
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(host.registry.get(broken).unwrap().program.version, 1);
        assert_eq!(host.registry.get(fine).unwrap().program.version, 1);

        // The broken object stayed on v1 (old program, old var untouched)
        // once accessed — its lazy upgrade attempt fails and rolls back;
        // the fine object's lazy upgrade succeeds and it migrates to v2.
        let short = host.call_on(fine, "short", vec![]).unwrap();
        assert_eq!(short.as_str(), Some("An empty room"));
        let broken_short = host.call_on(broken, "short", vec![]).unwrap();
        assert_eq!(broken_short.as_str(), Some("BREAK ME"));
        assert_eq!(host.registry.get(broken).unwrap().program.version, 1);
        assert_eq!(host.registry.get(fine).unwrap().program.version, 2);

        assert_eq!(
            host.registry.lazy_upgrade_warnings.len(),
            1,
            "exactly the broken object's lazy upgrade should have failed"
        );
        assert_eq!(host.registry.lazy_upgrade_warnings[0].object, broken);
    }

    /// End-to-end proof that the disk-backed [`Compiler`] (spec §7.2's
    /// `compile_object`/`ensure_program`, the bytecode-VM analogue of
    /// `crate::world::World::ensure_program`) actually loads real `.wf`
    /// files from a mudlib root, parent first, and that the resulting
    /// object dispatches correctly across the inherit chain — the same
    /// proof `crate::world`'s own tests give the tree-walker, but for this
    /// VM. Uses a real temp directory (not the in-memory `HashMap`
    /// `SourceLoader` the other tests in this module use), because this is
    /// specifically testing the disk-loading path `World` will need.
    #[test]
    fn compiler_loads_real_wf_files_from_disk_parent_first() {
        let root = std::env::temp_dir().join(format!(
            "loom-vm-bcvm-registry-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let write = |rel: &str, src: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, src).unwrap();
        };
        write(
            "std/room.wf",
            r#"
var short_desc: string = "An empty room"

pub fn short() -> string {
    return short_desc
}
"#,
        );
        write(
            "domains/start/hall.wf",
            r#"
inherit /std/room

fn create() {
    short_desc = "The Great Hall"
}
"#,
        );

        let mut compiler = Compiler::new(root.clone());
        let mut registry = Registry::default();
        let hall = compiler
            .ensure_program(&mut registry, "/domains/start/hall")
            .expect("ensure_program");
        // Both the child and its parent must now be registered.
        assert!(registry.program("/std/room").is_some());
        assert_eq!(&*hall.path, "/domains/start/hall");

        let placeholder = ObjectId {
            index: u32::MAX,
            generation: 0,
        };
        let mut host = RegistryHost::new(&mut registry, placeholder);
        let obj = host.instantiate(hall).expect("instantiate");
        // `create()` isn't called automatically by `instantiate` (that is
        // `World::new_object`'s job, not ported yet); call it explicitly
        // the way this slice's other tests call functions directly.
        host.call_on(obj, "create", vec![]).unwrap();
        let short = host.call_on(obj, "short", vec![]).unwrap();
        assert_eq!(short.as_str(), Some("The Great Hall"));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Three objects `a -> b -> c` on disk, loaded through [`Compiler`].
    fn three_object_chain(tag: &str) -> (std::path::PathBuf, Registry, [ObjectId; 3]) {
        let root = tmp_mudlib_root(tag);
        let write = |rel: &str, src: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, src).unwrap();
        };
        write(
            "t/c.wf",
            "pub fn spin(n: int) -> int {\n    var i = 0\n    var acc = 0\n    while i < n {\n        acc += i\n        i += 1\n    }\n    return acc\n}\n\npub fn dive(n: int) -> int {\n    return dive(n + 1)\n}\n",
        );
        write(
            "t/b.wf",
            "pub fn via(c: object, n: int) -> any {\n    return c.spin(n)\n}\n",
        );
        write(
            "t/a.wf",
            "pub fn top(b: object, c: object, n: int) -> any {\n    return [b.via(c, n), self]\n}\n",
        );
        let mut compiler = Compiler::new(root.clone());
        let mut registry = Registry::default();
        let placeholder = ObjectId {
            index: u32::MAX,
            generation: 0,
        };
        let mut ids = [placeholder; 3];
        for (i, path) in ["/t/a", "/t/b", "/t/c"].into_iter().enumerate() {
            let prog = compiler.ensure_program(&mut registry, path).unwrap();
            let mut host = RegistryHost::new(&mut registry, placeholder);
            ids[i] = host.instantiate(prog).unwrap();
        }
        (root, registry, ids)
    }

    /// Spec r5 D26: a call chain spanning three objects runs on *one* flat
    /// frame stack — suspending at a `TickCheck` inside `c.spin` (two
    /// objects deep) parks all three frames, `self` is `c` while parked,
    /// and resuming yields exactly the uninterrupted result with `self`
    /// correctly restored on the way back out.
    #[test]
    fn cross_object_chain_is_one_flat_suspendable_stack() {
        let (root, mut registry, [a, b, c]) = three_object_chain("d26-suspend");
        let prog_a = registry.get(a).unwrap().program.clone();
        let args = || vec![Value::Object(b), Value::Object(c), Value::Int(50)];
        let limits = Limits::default();

        // Uninterrupted reference run.
        let expected = {
            let mut host = RegistryHost::new(&mut registry, a);
            let mut ticks = 1_000_000u64;
            let mut interp = Interpreter::new(&prog_a.module, &mut host, &limits, &mut ticks);
            match interp.start("top", args()).unwrap() {
                Exec::Done(v) => v,
                Exec::Suspended => panic!("not armed, must not suspend"),
            }
        };

        let mut host = RegistryHost::new(&mut registry, a);
        let mut ticks = 1_000_000u64;
        let mut interp = Interpreter::new(&prog_a.module, &mut host, &limits, &mut ticks);
        interp.suspend_after_ticks(20);
        assert!(matches!(
            interp.start("top", args()).unwrap(),
            Exec::Suspended
        ));
        assert_eq!(interp.depth(), 3, "a.top -> b.via -> c.spin, one stack");
        let mut suspensions = 1;
        let got = loop {
            interp.suspend_after_ticks(7);
            match interp.resume().unwrap() {
                Exec::Done(v) => break v,
                Exec::Suspended => suspensions += 1,
            }
        };
        drop(interp);
        assert!(suspensions > 1);
        assert_eq!(format!("{got:?}"), format!("{expected:?}"));
        assert_eq!(host.self_stack, vec![a], "self restored after unwinding");
        assert_eq!(
            format!("{got:?}"),
            format!(
                "{:?}",
                Value::array(vec![Value::Int(1225), Value::Object(a)])
            )
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// D-P1.3 + D26: unbounded Weft recursion through the host
    /// (`dive` compiles to `CalleeOp::Virtual`) hits the flat stack's own
    /// 10k-frame limit on a small native thread, because every frame
    /// lives on the interpreter's heap stack — no native recursion at all.
    /// The thread is 512 KiB (the debug-build parser/checker needs more than
    /// 64 KiB just to *compile* the fixture), below the old nested-call
    /// guard's 1 MB budget, so 10k nested `Interpreter`s would abort here.
    #[test]
    fn host_dispatched_recursion_never_touches_the_native_stack() {
        let out = std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(|| {
                let (root, mut registry, [_, _, c]) = three_object_chain("d26-deep");
                let prog = registry.get(c).unwrap().program.clone();
                let limits = Limits {
                    max_depth: 10_000,
                    ..Limits::default()
                };
                let mut host = RegistryHost::new(&mut registry, c);
                let mut ticks = 10_000_000u64;
                let mut interp = Interpreter::new(&prog.module, &mut host, &limits, &mut ticks);
                let e = interp.call("dive", vec![Value::Int(0)]).unwrap_err();
                drop(interp);
                let depth_after = host.self_stack.len();
                let _ = std::fs::remove_dir_all(&root);
                (e.message, depth_after)
            })
            .unwrap()
            .join()
            .expect("no native stack overflow");
        assert!(
            out.0.contains("call depth limit 10000 exceeded"),
            "{}",
            out.0
        );
        assert_eq!(out.1, 1, "every entered self popped on unwind");
    }

    fn tmp_mudlib_root(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "loom-vm-bcvm-registry-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    /// End-to-end proof that [`Compiler::recompile`] +
    /// [`RegistryHost::install`] (spec §7.2 `compile_object`/`update`) work
    /// together the way `World::recompile`/`install` do for the
    /// tree-walker: recompiling `/std/room` on disk, then installing that
    /// recompile, (a) upgrades a *dependent* program (`/domains/start/hall`,
    /// which inherits `/std/room`) too, not just `/std/room` itself, (b)
    /// makes newly added inherited behaviour (`long()`) reachable from an
    /// object that already existed before the recompile, without
    /// disconnecting or re-instantiating it, and (c) preserves that
    /// existing object's already-set, type-compatible variable
    /// (`short_desc`, set by `hall`'s `create()` before the recompile)
    /// instead of resetting it to the freshly declared default.
    #[test]
    fn recompile_and_install_upgrade_a_live_dependent_in_place() {
        let root = tmp_mudlib_root("recompile");
        let write = |rel: &str, src: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, src).unwrap();
        };
        write(
            "std/room.wf",
            r#"
var short_desc: string = "An empty room"

pub fn short() -> string {
    return short_desc
}
"#,
        );
        write(
            "domains/start/hall.wf",
            r#"
inherit /std/room

fn create() {
    short_desc = "The Great Hall"
}
"#,
        );

        let mut compiler = Compiler::new(root.clone());
        let mut registry = Registry::default();
        let hall = compiler
            .ensure_program(&mut registry, "/domains/start/hall")
            .expect("ensure_program");
        let placeholder = ObjectId {
            index: u32::MAX,
            generation: 0,
        };
        let obj = {
            let mut host = RegistryHost::new(&mut registry, placeholder);
            let obj = host.instantiate(hall).expect("instantiate");
            host.call_on(obj, "create", vec![]).unwrap();
            obj
        };

        // Change `/std/room` on disk: add `long()`. `short_desc`'s default
        // is unchanged (still type-compatible), so the *existing* object's
        // mutated value must survive the upgrade.
        write(
            "std/room.wf",
            r#"
var short_desc: string = "An empty room"

pub fn short() -> string {
    return short_desc
}

pub fn long() -> string {
    return short() + " (nothing else to see)"
}
"#,
        );
        let new_set = compiler
            .recompile(&registry, "/std/room")
            .expect("recompile");
        // Both /std/room and its dependent /domains/start/hall must be in
        // the recompiled set.
        assert!(new_set.contains_key("/std/room"));
        assert!(new_set.contains_key("/domains/start/hall"));

        let mut host = RegistryHost::new(&mut registry, obj);
        host.install(new_set).expect("install");

        // The pre-existing object now has `long()` (added by the
        // recompile) and its old `short_desc` value survived the upgrade.
        let long = host.call_on(obj, "long", vec![]).unwrap();
        assert_eq!(long.as_str(), Some("The Great Hall (nothing else to see)"));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// spec r5 §5.2.1 "memory quotas with per-object accounting": a
    /// program-variable write that would push the object's accounted
    /// (shallow) `vars` bytes past the configured quota is rejected as an
    /// `RtError`, not silently allowed — and the error carries a Weft
    /// stack trace (the frame it happened in), like any other `RtError`.
    #[test]
    fn store_global_rejects_a_write_that_exceeds_the_memory_quota() {
        const WF: &str = r#"
var data: [int] = []

pub fn grow(n: int) {
    var a: [int] = []
    var i = 0
    while i < n {
        a = a + [i]
        i += 1
    }
    data = a
}
"#;
        let module = compile("/obj/thing", &[("/obj/thing", WF)]);
        let mut registry = Registry::default();
        let prog = Rc::new(CompiledProgram::new(module, 1, None, Vec::new()));
        registry.register_program(prog.clone());
        let obj = make_object(&mut registry, prog);
        let mut host = RegistryHost::new(&mut registry, obj);
        // A handful of ints, not the 1000 `grow` is about to build.
        host.limits.mem_quota_bytes = 64;
        let err = host
            .call_on(obj, "grow", vec![Value::Int(1000)])
            .unwrap_err();
        assert!(
            err.report().contains("memory quota exceeded"),
            "{}",
            err.report()
        );
        assert!(
            err.report().contains("in grow()"),
            "a quota error must carry a Weft stack trace like any other RtError:\n{}",
            err.report()
        );
    }

    // -- atomic fn journaling + rollback (spec r5 §5.2.1, OBI-32) --------

    /// A `Registry` with one object whose vars live purely in `vars`
    /// (no declared program variables needed: `store_global`/`load_global`
    /// only ever look the key up in that map).
    fn atomic_test_object() -> (Registry, ObjectId) {
        let module = compile("/t/obj", &[("/t/obj", "fn create() {}\n")]);
        let mut registry = Registry::default();
        let prog = Rc::new(CompiledProgram::new(module, 1, None, Vec::new()));
        registry.register_program(prog.clone());
        let obj = make_object(&mut registry, prog);
        (registry, obj)
    }

    /// A write that stays within quota succeeds and `mem_bytes` tracks it
    /// (no false rejection, and the accounting is actually maintained, not
    /// just checked-and-discarded).
    #[test]
    fn store_global_accepts_a_write_within_quota_and_tracks_mem_bytes() {
        const WF: &str = r#"
var data: [int] = []

pub fn set(n: int) {
    var a: [int] = []
    var i = 0
    while i < n {
        a = a + [i]
        i += 1
    }
    data = a
}
"#;
        let module = compile("/obj/thing", &[("/obj/thing", WF)]);
        let mut registry = Registry::default();
        let prog = Rc::new(CompiledProgram::new(module, 1, None, Vec::new()));
        registry.register_program(prog.clone());
        let obj = make_object(&mut registry, prog);
        let mut host = RegistryHost::new(&mut registry, obj);
        host.call_on(obj, "set", vec![Value::Int(4)]).unwrap();
        let mem = host.registry.get(obj).unwrap().mem_bytes;
        assert!(mem > 0, "a non-empty array var must be charged some bytes");
    }

    /// `loom_cow_copies_total{program}` (spec r5 §5.2.1, D24): only an
    /// *actual* clone-on-write counts. A uniquely-owned array (taken by
    /// value as a parameter — no other register/var holds a reference to
    /// its buffer) mutated in place must never increment the counter for
    /// its program; a program that keeps a second reference alive before
    /// mutating (forcing `Rc::make_mut` to clone) must increment it by
    /// exactly one per such write.
    ///
    /// (Deliberately takes `a` as a parameter, not a `var a: [int] = [...]`
    /// local with a literal initialiser: codegen currently lowers every
    /// `let`/`var` initialiser through a temp register plus a `Copy` into
    /// the local — a codegen inefficiency, not Weft-level aliasing — which
    /// would leave a second live `Rc` in the dead temp register and make
    /// even a "no other Weft code ever aliases this" body clone on its
    /// first write. A parameter *is* its register directly, so this
    /// isolates the metric from that unrelated codegen artifact.)
    #[test]
    fn cow_metric_counts_only_actual_clones_not_every_write() {
        const UNIQUE_WF: &str = r#"
pub fn touch(a: [int]) -> int {
    a[0] = 99
    a[1] = 100
    return a[0]
}
"#;
        const ALIASED_WF: &str = r#"
pub fn touch(a: [int]) -> int {
    var b = a
    a[0] = 99
    return b[0]
}
"#;
        let unique_module = compile("/obj/unique", &[("/obj/unique", UNIQUE_WF)]);
        let aliased_module = compile("/obj/aliased", &[("/obj/aliased", ALIASED_WF)]);
        let mut registry = Registry::default();
        let unique_prog = Rc::new(CompiledProgram::new(unique_module, 1, None, Vec::new()));
        let aliased_prog = Rc::new(CompiledProgram::new(aliased_module, 1, None, Vec::new()));
        registry.register_program(unique_prog.clone());
        registry.register_program(aliased_prog.clone());
        let unique_obj = make_object(&mut registry, unique_prog);
        let aliased_obj = make_object(&mut registry, aliased_prog);

        let mut host = RegistryHost::new(&mut registry, unique_obj);
        // Two writes on the unique object: still zero clones.
        let arg = Value::array(vec![Value::Int(1), Value::Int(2), Value::Int(3)]);
        assert!(matches!(
            host.call_on(unique_obj, "touch", vec![arg]).unwrap(),
            Value::Int(99)
        ));
        assert_eq!(host.registry.cow_metrics.get("/obj/unique"), 0);

        // One write on the aliased object: exactly one clone.
        let arg = Value::array(vec![Value::Int(1), Value::Int(2), Value::Int(3)]);
        assert!(
            matches!(
                host.call_on(aliased_obj, "touch", vec![arg]).unwrap(),
                Value::Int(1)
            ),
            "b must still see the pre-mutation value (COW, not shared mutation)"
        );
        assert_eq!(host.registry.cow_metrics.get("/obj/aliased"), 1);
    }

    /// Per-call-site inline cache (spec §5.8): a megamorphic call site
    /// (virtual dispatch on `self` from a function two different
    /// subclasses both inherit unmodified) must still resolve *correctly*
    /// for whichever object is currently running it, even though both
    /// calls go through the very same `Op::Call` instruction/cache slot —
    /// the guard check must catch the receiver-program mismatch and
    /// re-resolve, not serve object A's cached target to object B.
    #[test]
    fn inline_cache_guard_reresolves_for_a_different_receiver_program() {
        const PARENT_WF: &str = r#"
pub fn describe() -> string {
    return kind()
}
fn kind() -> string {
    return "parent"
}
"#;
        let mut registry = Registry::default();
        let parent_prog = Rc::new(compile_program(
            "/obj/parent",
            &[("/obj/parent", PARENT_WF)],
            1,
            None,
        ));
        registry.register_program(parent_prog.clone());

        const CHILD_A_WF: &str = r#"
inherit /obj/parent
override fn kind() -> string {
    return "A"
}
"#;
        const CHILD_B_WF: &str = r#"
inherit /obj/parent
override fn kind() -> string {
    return "B"
}
"#;
        let child_a = Rc::new(compile_program(
            "/obj/child_a",
            &[("/obj/parent", PARENT_WF), ("/obj/child_a", CHILD_A_WF)],
            1,
            Some(parent_prog.clone()),
        ));
        let child_b = Rc::new(compile_program(
            "/obj/child_b",
            &[("/obj/parent", PARENT_WF), ("/obj/child_b", CHILD_B_WF)],
            1,
            Some(parent_prog.clone()),
        ));
        registry.register_program(child_a.clone());
        registry.register_program(child_b.clone());
        let obj_a = make_object(&mut registry, child_a);
        let obj_b = make_object(&mut registry, child_b);

        // Same `RegistryHost`, so the inline cache persists across both
        // calls below (see `RegistryHost::call_cache`'s doc comment).
        let mut host = RegistryHost::new(&mut registry, obj_a);
        assert_eq!(
            host.call_on(obj_a, "describe", vec![]).unwrap().as_str(),
            Some("A")
        );
        // If the cache served A's cached resolution here without checking
        // the guard, this would wrongly come back "A" too.
        assert_eq!(
            host.call_on(obj_b, "describe", vec![]).unwrap().as_str(),
            Some("B")
        );
        // And a third call back on A must still be correct (the cache
        // slot bounced between two guards, proving it re-checks every
        // time rather than latching onto whichever guard it saw last).
        assert_eq!(
            host.call_on(obj_a, "describe", vec![]).unwrap().as_str(),
            Some("A")
        );
    }

    /// Regression (OBI-38): two clones of the *same* program share the
    /// inline-cache guard, so a cache hit must run on the current
    /// receiver, not on the object the entry was first resolved for.
    /// Before the fix `b.outer()` (and the nested unqualified `inner()`
    /// call inside it) ran on `a` and returned "A".
    #[test]
    fn inline_cache_hit_runs_on_the_current_receiver_not_the_cached_one() {
        const KID_WF: &str = r#"
var name: string = ""
pub fn set_name(n: string) {
    name = n
}
pub fn inner() -> string {
    return name
}
pub fn outer() -> string {
    return inner()
}
"#;
        let mut registry = Registry::default();
        let prog = Rc::new(compile_program(
            "/obj/kid",
            &[("/obj/kid", KID_WF)],
            1,
            None,
        ));
        registry.register_program(prog.clone());
        let a = make_object(&mut registry, prog.clone());
        let b = make_object(&mut registry, prog);
        let mut host = RegistryHost::new(&mut registry, a);
        host.call_on(a, "set_name", vec![Value::str("A")]).unwrap();
        host.call_on(b, "set_name", vec![Value::str("B")]).unwrap();
        for (ob, want) in [(a, "A"), (b, "B"), (a, "A"), (b, "B")] {
            assert_eq!(
                host.call_on(ob, "outer", vec![]).unwrap().as_str(),
                Some(want)
            );
            assert_eq!(
                host.call_on(ob, "inner", vec![]).unwrap().as_str(),
                Some(want)
            );
        }
    }

    #[test]
    fn atomic_fn_rolls_back_a_plain_var_write_on_error() {
        const WF: &str = r#"
var n: int = 0

atomic fn bump_then_fail() {
    n = 1
    throw "boom"
}

pub fn get_n() -> int {
    return n
}
"#;
        let prog = Rc::new(compile_program("/t/obj", &[("/t/obj", WF)], 1, None));
        let mut registry = Registry::default();
        registry.register_program(prog.clone());
        let placeholder = ObjectId {
            index: u32::MAX,
            generation: 0,
        };
        let mut host = RegistryHost::new(&mut registry, placeholder);
        let obj = host.instantiate(prog).expect("instantiate");

        let err = host.call_on(obj, "bump_then_fail", vec![]).unwrap_err();
        assert!(err.report().contains("boom"), "{}", err.report());

        let n = host.call_on(obj, "get_n", vec![]).unwrap();
        assert!(n.equals(&Value::Int(0)), "n must be rolled back, got {n:?}");
    }

    /// r5 amendment: an array/map mutation is an object-variable write, so
    /// a nested element write on a program variable inside `atomic` is
    /// journaled and rolled back exactly like a plain `n = 1`.
    #[test]
    fn atomic_fn_rolls_back_a_nested_container_write() {
        const WF: &str = r#"
var xs: [int] = [1, 2, 3]

atomic fn mutate_then_fail() {
    xs[0] = 99
    throw "boom"
}

pub fn get_xs() -> [int] {
    return xs
}
"#;
        let prog = Rc::new(compile_program("/t/obj", &[("/t/obj", WF)], 1, None));
        let mut registry = Registry::default();
        registry.register_program(prog.clone());
        let placeholder = ObjectId {
            index: u32::MAX,
            generation: 0,
        };
        let mut host = RegistryHost::new(&mut registry, placeholder);
        let obj = host.instantiate(prog).expect("instantiate");

        host.call_on(obj, "mutate_then_fail", vec![]).unwrap_err();

        let xs = host.call_on(obj, "get_xs", vec![]).unwrap();
        let want = Value::array(vec![Value::Int(1), Value::Int(2), Value::Int(3)]);
        assert!(
            xs.equals(&want),
            "xs must be rolled back exactly, got {xs:?}"
        );
    }

    #[test]
    fn atomic_fn_commits_its_writes_on_a_normal_return() {
        const WF: &str = r#"
var n: int = 0

atomic fn bump() {
    n = 1
}

pub fn get_n() -> int {
    return n
}
"#;
        let prog = Rc::new(compile_program("/t/obj", &[("/t/obj", WF)], 1, None));
        let mut registry = Registry::default();
        registry.register_program(prog.clone());
        let placeholder = ObjectId {
            index: u32::MAX,
            generation: 0,
        };
        let mut host = RegistryHost::new(&mut registry, placeholder);
        let obj = host.instantiate(prog).expect("instantiate");

        host.call_on(obj, "bump", vec![]).unwrap();
        let n = host.call_on(obj, "get_n", vec![]).unwrap();
        assert!(n.equals(&Value::Int(1)));
    }

    /// An error caught *inside* the atomic function's own body does not
    /// roll back — the function handled it and returned normally.
    #[test]
    fn atomic_fn_does_not_roll_back_an_error_it_catches_itself() {
        const WF: &str = r#"
var n: int = 0

atomic fn bump_and_catch() {
    n = 1
    try {
        throw "boom"
    } catch e {
    }
}

pub fn get_n() -> int {
    return n
}
"#;
        let prog = Rc::new(compile_program("/t/obj", &[("/t/obj", WF)], 1, None));
        let mut registry = Registry::default();
        registry.register_program(prog.clone());
        let placeholder = ObjectId {
            index: u32::MAX,
            generation: 0,
        };
        let mut host = RegistryHost::new(&mut registry, placeholder);
        let obj = host.instantiate(prog).expect("instantiate");

        host.call_on(obj, "bump_and_catch", vec![]).unwrap();
        let n = host.call_on(obj, "get_n", vec![]).unwrap();
        assert!(n.equals(&Value::Int(1)), "caught error must not roll back");
    }

    /// Tick exhaustion inside `atomic` rolls back (spec §5.9's table:
    /// "rollback if atomic"). `Interpreter::run`'s error-unwind path calls
    /// `Host::rollback_atomic` for every atomic frame it pops on *any*
    /// error, tick exhaustion included — the code path already existed,
    /// this pins it specifically since tick/depth exhaustion are handled
    /// separately from ordinary `RtError`s (uncatchable by `try`/`catch`,
    /// spec r5) everywhere else in the VM.
    #[test]
    fn atomic_fn_rolls_back_on_tick_exhaustion() {
        const WF: &str = r#"
var n: int = 0

atomic fn bump_then_spin() {
    n = 1
    while true {
        n = n
    }
}

pub fn get_n() -> int {
    return n
}
"#;
        let prog = Rc::new(compile_program("/t/obj", &[("/t/obj", WF)], 1, None));
        let mut registry = Registry::default();
        registry.register_program(prog.clone());
        let placeholder = ObjectId {
            index: u32::MAX,
            generation: 0,
        };
        let mut host = RegistryHost::new(&mut registry, placeholder);
        let obj = host.instantiate(prog).expect("instantiate");

        // Far fewer ticks than the infinite loop needs.
        host.ticks_left = 50;
        let err = host.call_on(obj, "bump_then_spin", vec![]).unwrap_err();
        assert!(
            err.report().contains("Too long evaluation"),
            "{}",
            err.report()
        );

        host.ticks_left = 1_000_000;
        let n = host.call_on(obj, "get_n", vec![]).unwrap();
        assert!(
            n.equals(&Value::Int(0)),
            "n must be rolled back on tick exhaustion inside atomic, got {n:?}"
        );
    }

    /// Nested atomic calls telescope: an inner atomic call that commits is
    /// still undone if the *outer* atomic scope it ran inside later fails.
    #[test]
    fn outer_atomic_failure_rolls_back_an_inner_atomic_call_that_already_committed() {
        const WF: &str = r#"
var n: int = 0

atomic fn inner() {
    n = 1
}

atomic fn outer_then_fail() {
    inner()
    throw "boom"
}

pub fn get_n() -> int {
    return n
}
"#;
        let prog = Rc::new(compile_program("/t/obj", &[("/t/obj", WF)], 1, None));
        let mut registry = Registry::default();
        registry.register_program(prog.clone());
        let placeholder = ObjectId {
            index: u32::MAX,
            generation: 0,
        };
        let mut host = RegistryHost::new(&mut registry, placeholder);
        let obj = host.instantiate(prog).expect("instantiate");

        host.call_on(obj, "outer_then_fail", vec![]).unwrap_err();
        let n = host.call_on(obj, "get_n", vec![]).unwrap();
        assert!(
            n.equals(&Value::Int(0)),
            "outer's failure must also undo the inner atomic call's committed write, got {n:?}"
        );
    }

    // Property test (spec r5 §5.2.1 AC): an arbitrary sequence of writes
    // made while an atomic scope is open — including a nested element
    // write on a program variable (`xs[0] = ...`, exactly the `IndexSet`
    // + `StoreGlobal` pair codegen emits for `global[i] = v`) — is undone
    // back to the exact prior state on rollback, no matter what it was.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]
        #[test]
        fn atomic_rollback_restores_exact_prior_state(
            setup in prop::collection::vec((0usize..3, arb_value()), 0..6),
            during in prop::collection::vec((0usize..3, arb_value()), 1..12),
            mutate_xs_element in any::<bool>(),
        ) {
            let (mut registry, obj) = atomic_test_object();
            let mut host = RegistryHost::new(&mut registry, obj);
            let keys = ["a", "xs", "m"];

            for (i, v) in &setup {
                host.store_global("/t/obj", keys[*i], v.clone()).unwrap();
            }
            let snapshot: Vec<Value> = keys
                .iter()
                .map(|k| host.load_global("/t/obj", k).unwrap())
                .collect();

            let mark = host.begin_atomic();
            for (i, v) in &during {
                host.store_global("/t/obj", keys[*i], v.clone()).unwrap();
            }
            if mutate_xs_element {
                // The nested-element-write case the AC calls out by name:
                // read the container, mutate a copy (COW), write the whole
                // (new) value back over the global slot.
                let mut xs = host.load_global("/t/obj", "xs").unwrap();
                if let Some(arr) = xs.array_mut()
                    && !arr.is_empty()
                {
                    arr.set(0, Value::Int(-1));
                    host.store_global("/t/obj", "xs", xs).unwrap();
                }
            }
            host.rollback_atomic(mark);

            for (k, want) in keys.iter().zip(&snapshot) {
                let got = host.load_global("/t/obj", k).unwrap();
                prop_assert!(
                    want.equals(&got),
                    "rollback did not restore the exact prior state of `{k}`: want {want:?}, got {got:?}"
                );
            }
        }
    }

    fn arb_value() -> impl Strategy<Value = Value> {
        prop_oneof![
            any::<i64>().prop_map(Value::Int),
            prop::collection::vec(any::<i64>(), 0..5)
                .prop_map(|v| Value::array(v.into_iter().map(Value::Int).collect())),
        ]
    }

    /// Three bare objects (one "item", two "rooms") sharing the same
    /// single-function program used by [`atomic_test_object`], for the
    /// move-journaling property test below.
    fn atomic_move_test_objects() -> (Registry, ObjectId, [ObjectId; 2]) {
        let module = compile("/t/obj", &[("/t/obj", "fn create() {}\n")]);
        let mut registry = Registry::default();
        let prog = Rc::new(CompiledProgram::new(module, 1, None, Vec::new()));
        registry.register_program(prog.clone());
        let item = make_object(&mut registry, prog.clone());
        let rooms = [
            make_object(&mut registry, prog.clone()),
            make_object(&mut registry, prog),
        ];
        (registry, item, rooms)
    }

    // Property test (CTO review of OBI-32, "add a move op to the proptest
    // too if that's cheap"): an arbitrary sequence of `move_to`s made
    // while an atomic scope is open is undone back to the exact prior
    // environment and inventories on rollback, matching the var-write
    // property test above but for `Registry::move_object`/`JournalEntry
    // ::Move` instead of `store_global`/`JournalEntry::VarWrite`.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]
        #[test]
        fn atomic_move_rollback_restores_exact_prior_inventories(
            start_room in 0usize..2,
            moves in prop::collection::vec(0usize..2, 0..8),
        ) {
            let (mut registry, item, rooms) = atomic_move_test_objects();
            registry.move_object(item, rooms[start_room]);

            let snapshot_env = registry.get(item).and_then(|o| o.env);
            let snapshot_inv: Vec<Vec<ObjectId>> = rooms
                .iter()
                .map(|r| registry.get(*r).unwrap().inventory.clone())
                .collect();

            let mut host = RegistryHost::new(&mut registry, item);
            let mark = host.begin_atomic();
            for m in &moves {
                host.registry.move_object(item, rooms[*m]);
            }
            host.rollback_atomic(mark);

            let got_env = host.registry.get(item).and_then(|o| o.env);
            prop_assert_eq!(got_env, snapshot_env);
            for (i, r) in rooms.iter().enumerate() {
                let got_inv = &host.registry.get(*r).unwrap().inventory;
                prop_assert_eq!(got_inv, &snapshot_inv[i]);
            }
        }
    }

    /// OBI-80 acceptance criterion: nesting a large local container one
    /// level inside a global-var write must count against the quota. This
    /// is exactly the bypass OBI-78's shallow accounting had (`data =
    /// [big_local_array]` cost 16 bytes, i.e. only the outer array's one
    /// slot) — with deep accounting the nested array's own contents are
    /// charged too, so a small quota rejects it.
    #[test]
    fn deep_accounting_rejects_a_large_local_container_nested_in_a_global_write() {
        let zeros = (0..200).map(|_| "0").collect::<Vec<_>>().join(",");
        let wf = format!(
            r#"
var data: any = null

pub fn set_it() {{
    let big: [int] = [{zeros}]
    data = [big]
}}
"#
        );
        let module = compile("/obj/thing", &[("/obj/thing", &wf)]);
        let mut registry = Registry::default();
        let prog = Rc::new(CompiledProgram::new(module, 1, None, Vec::new()));
        registry.register_program(prog.clone());
        let obj = make_object(&mut registry, prog);
        let mut host = RegistryHost::new(&mut registry, obj);
        // 200 ints nested one level in cost 200 * 16 = 3200 bytes deep, plus
        // the outer array's own slot; a shallow accounting of "one element"
        // would only ever charge 16 bytes here and never trip this quota.
        host.limits.mem_quota_bytes = 1000;
        let err = host
            .call_on(obj, "set_it", vec![])
            .expect_err("nested container must push the object over a 1000-byte quota");
        assert!(
            err.report().contains("memory quota exceeded"),
            "{}",
            err.report()
        );

        // Same program, quota big enough to hold it: must succeed.
        let mut registry2 = Registry::default();
        let prog2 = Rc::new(CompiledProgram::new(
            compile("/obj/thing", &[("/obj/thing", &wf)]),
            1,
            None,
            Vec::new(),
        ));
        registry2.register_program(prog2.clone());
        let obj2 = make_object(&mut registry2, prog2);
        let mut host2 = RegistryHost::new(&mut registry2, obj2);
        host2.limits.mem_quota_bytes = 1_000_000;
        host2
            .call_on(obj2, "set_it", vec![])
            .expect("comfortably under a 1_000_000 byte quota");
    }

    /// OBI-80 acceptance criterion: writing the same (shared) substructure
    /// into two different objects' globals charges both in full (no
    /// dedup/single-owner attribution), and releasing it from one holder
    /// does not free the other's charged share.
    #[test]
    fn shared_substructure_written_into_two_objects_charges_both_independently() {
        const WF: &str = r#"
var data: any = null

pub fn set(v: any) {
    data = v
}

pub fn clear() {
    data = 0
}
"#;
        let module_a = compile("/obj/a", &[("/obj/a", WF)]);
        let module_b = compile("/obj/b", &[("/obj/b", WF)]);
        let mut registry = Registry::default();
        let prog_a = Rc::new(CompiledProgram::new(module_a, 1, None, Vec::new()));
        let prog_b = Rc::new(CompiledProgram::new(module_b, 1, None, Vec::new()));
        registry.register_program(prog_a.clone());
        registry.register_program(prog_b.clone());
        let a = make_object(&mut registry, prog_a);
        let b = make_object(&mut registry, prog_b);

        let shared = Value::array(vec![Value::str(&"z".repeat(2000))]);

        let mut host = RegistryHost::new(&mut registry, a);
        host.call_on(a, "set", vec![shared.clone()]).unwrap();
        host.call_on(b, "set", vec![shared]).unwrap();

        let bytes_a = host.registry.get(a).unwrap().mem_bytes;
        let bytes_b = host.registry.get(b).unwrap().mem_bytes;
        assert!(
            bytes_a > 2000,
            "holder a must be charged the shared payload's full cost"
        );
        assert_eq!(
            bytes_a, bytes_b,
            "both holders charged the same, full amount"
        );

        // Release it from `a`: `b`'s charged share must be unaffected.
        host.call_on(a, "clear", vec![]).unwrap();
        let after_a = host.registry.get(a).unwrap().mem_bytes;
        let after_b = host.registry.get(b).unwrap().mem_bytes;
        assert!(after_a < bytes_a, "a released its share");
        assert_eq!(after_b, bytes_b, "releasing from a must not free b's share");
    }

    /// OBI-80 acceptance criterion: filling an n-element global array by
    /// index is O(n) total `cost()` calls, not O(n²) (CTO review: a
    /// timing-ratio bound can't distinguish O(n) from a mild O(n²)
    /// regression -- the review's own O(n²) re-walk only showed about 16x
    /// on a 4x input, comfortably under the old, loose `< 20` ratio bound).
    /// Each `data[i] = x` write does exactly four `cost()` calls: two in
    /// `ArrayData::set` (the old element, the new one) and two in
    /// `store_global`'s own quota bookkeeping (the whole array's old cost,
    /// its new cost -- both O(1) reads of the array's own cached
    /// `deep_bytes`, not a walk of its elements). O(1) per write, so n
    /// writes make exactly `4n` calls, deterministically. An O(n) re-walk
    /// per write (the regression this guards against) would make `O(n)`
    /// calls *per write*, i.e. `O(n²)` total: caught exactly, no timing
    /// noise, no threshold to tune.
    #[test]
    fn filling_a_global_array_by_index_makes_on_not_on_squared_cost_calls() {
        fn cost_calls_to_fill(n: usize) -> u64 {
            let zeros = vec!["0"; n].join(",");
            let wf = format!(
                r#"
var data: [int] = [{zeros}]

pub fn fill() {{
    var i = 0
    while i < {n} {{
        data[i] = i
        i += 1
    }}
}}
"#
            );
            let prog = Rc::new(compile_program(
                "/obj/thing",
                &[("/obj/thing", &wf)],
                1,
                None,
            ));
            let mut registry = Registry::default();
            registry.register_program(prog.clone());
            let placeholder = ObjectId {
                index: u32::MAX,
                generation: 0,
            };
            let mut host = RegistryHost::new(&mut registry, placeholder);
            let obj = host.instantiate(prog).expect("instantiate");
            host.limits.mem_quota_bytes = u64::MAX;
            heap::reset_cost_calls();
            host.call_on(obj, "fill", vec![]).expect("fill");
            heap::cost_calls()
        }

        let small = cost_calls_to_fill(2_000);
        let large = cost_calls_to_fill(8_000); // 4x the elements
        assert_eq!(
            small,
            4 * 2_000,
            "O(1) per write: exactly 4 cost() calls per element"
        );
        assert_eq!(
            large,
            4 * 8_000,
            "O(1) per write: exactly 4 cost() calls per element"
        );
    }
}
