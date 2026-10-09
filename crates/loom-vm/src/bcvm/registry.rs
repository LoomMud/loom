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
    /// `persistent var` (spec §8.1, OBI-171): [`RegistryHost::save_object`]
    /// writes only these, keyed the same (declaring program, name) way
    /// hot-reload migration is (§7.2/§7.3) -- a persisted var and an
    /// upgraded var share one identity.
    pub persistent: bool,
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

/// spec §7.2 D-B3.14 / P2-B3.1's interface contract with B3.2 (Legolas):
/// one GitHub-merge-sized batch of mudlib-tree changes, posted to the
/// world thread after `live` is rebased onto `main` and the real work
/// tree is fast-forwarded. `changed`/`deleted` are mudlib-rooted paths
/// (`/domains/x/y`, no `.wf` suffix — same convention as every other path
/// in this module). Kept in `loom-vm` (not `loom-git`) per that contract:
/// `RegistryHost::recompile_set` is the only thing that needs to agree on
/// its shape with whatever posts it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChangeSet {
    pub changed: Vec<String>,
    pub deleted: Vec<String>,
    pub source_sha: String,
}

/// [`RegistryHost::recompile_set`]'s result (spec §7.2 D-B3.14): what
/// B3.3 (Legolas) posts verbatim as the post-merge PR comment.
///
/// - `recompiled`: every path actually recompiled and installed (the
///   changed, already-loaded roots plus their reverse-inherit dependents),
///   parents-first. Empty whenever `failures` is non-empty — nothing was
///   installed at all.
/// - `upgraded_instances`: how many currently-live objects run one of
///   `recompiled`'s programs, counted just before `install` (OBI-89:
///   install itself is lazy, so this counts who *will* migrate on next
///   access, not a synchronous migration that already happened).
/// - `skipped_unloaded`: changed paths with no registered program —
///   nothing to do, the next `ensure_program` compiles them fresh.
/// - `deleted_loaded`: deleted paths that are still registered — they
///   keep running on their last-compiled program; a warning, not a
///   failure.
/// - `failures`: every compile diagnostic collected across the whole
///   batch. Non-empty means `recompiled`/`upgraded_instances` are empty
///   and nothing was installed (all-or-nothing).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecompileReport {
    pub recompiled: Vec<String>,
    pub upgraded_instances: usize,
    pub skipped_unloaded: Vec<String>,
    pub deleted_loaded: Vec<String>,
    pub failures: Vec<(String, String)>,
}

/// [`Compiler::recompile_set`]'s result: everything [`RegistryHost::
/// recompile_set`] needs to either install `new_set` as a whole (when
/// `failures` is empty) or report `failures` and install nothing.
/// `new_set`/`recompiled` are kept distinct from the public
/// [`RecompileReport`] because `new_set` must never leak out of
/// `RegistryHost` un-installed -- a caller holding a `CompiledProgram`
/// that was never registered could observe a program whose parent link
/// silently changes underneath it on a later install.
#[derive(Default)]
pub struct RecompileSetOutcome {
    pub new_set: HashMap<String, Rc<CompiledProgram>>,
    pub recompiled: Vec<String>,
    pub skipped_unloaded: Vec<String>,
    pub deleted_loaded: Vec<String>,
    pub failures: Vec<(String, String)>,
}

/// In-process `loom_mudlib_sync_total{result=ok|compile_failed}` counter
/// (D-B3.14), same "no exporter wired up yet" posture as
/// [`CowMetrics`]/`crate::quota::QuotaBreachMetrics`: owned by [`Registry`]
/// and read back through `World::mudlib_sync_total`.
#[derive(Default)]
pub struct SyncMetrics {
    ok: u64,
    compile_failed: u64,
}

impl SyncMetrics {
    fn record(&mut self, ok: bool) {
        if ok {
            self.ok += 1;
        } else {
            self.compile_failed += 1;
        }
    }

    pub fn get(&self, result: &str) -> u64 {
        match result {
            "ok" => self.ok,
            "compile_failed" => self.compile_failed,
            _ => 0,
        }
    }
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
                    place: hir::Place::Global(
                        hir::GlobalRef {
                            owner: p.path.clone(),
                            name: v.name.clone(),
                        },
                        v.ty.clone(),
                    ),
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
pub(crate) fn compile_hir_unit(
    hir: &hir::Program,
    src: &str,
) -> Result<CompiledUnit, CompileError> {
    let var_specs: Vec<VarSpec> = hir
        .vars
        .iter()
        .map(|v| VarSpec {
            name: v.name.clone(),
            ty: v.ty.clone(),
            has_init: v.init.is_some(),
            persistent: v.persistent,
        })
        .collect();
    let module = if let Some(init_fn) = synth_init_function(hir) {
        let mut augmented = hir.clone();
        augmented.fns.push(init_fn);
        compile_and_verify(&augmented, src)?
    } else {
        compile_and_verify(hir, src)?
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
    src: &str,
    version: u32,
    parent: Option<Rc<CompiledProgram>>,
) -> Result<CompiledProgram, CompileError> {
    let unit = compile_hir_unit(hir, src)?;
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
            let (anc_hir, anc_src) = match self.session.outcomes().get(&**anc) {
                Some(Outcome::Ok(c)) => (c.hir.clone(), c.src.clone()),
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
            let mut compiled = compile_hir_program(&anc_hir, &anc_src, 1, parent)
                .map_err(|e| format!("{anc}: {e}"))?;
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

        // OBI-156: `path` may inherit an ancestor that has never been
        // loaded/registered at all (only ever referenced from source, not
        // yet compiled by anyone). The loop below resolves each program's
        // `parent` link purely from `new_set`/`registry` — if such an
        // ancestor is in neither, `path` silently installs with a `None`
        // parent and every inherited function goes missing. `ensure_program`
        // already handles this (it walks the whole linearization); mirror
        // that here: ask the session to compile `path` (which recursively
        // compiles and checks every ancestor, same as `ensure_program`),
        // then queue any linearization member that isn't registered yet,
        // in ancestor-first order, so a never-loaded ancestor gets a fresh
        // `CompiledProgram` (and thus a real parent link) built for it in
        // this same batch before `path` itself is built.
        let linearization: Vec<Rc<str>> = match self.session.compile(&path) {
            Outcome::Ok(checked) => checked.info.linearization.clone(),
            Outcome::Failed(msg) => return Err(msg.clone()),
            Outcome::Missing(msg) => return Err(msg.clone()),
        };
        let mut to_compile: Vec<String> = Vec::new();
        for anc in &linearization {
            if **anc == *path {
                // `path` itself is queued explicitly below regardless of
                // whether it was already registered: recompile always
                // rebuilds `path`, that's the whole point of the call.
                continue;
            }
            if registry.program(anc).is_none() {
                to_compile.push(anc.to_string());
            }
        }
        to_compile.push(path.clone());
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
            let anc_src = match self.session.outcomes().get(p) {
                Some(Outcome::Ok(c)) => c.src.clone(),
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
            let mut compiled = compile_hir_program(&anc_hir, &anc_src, version, parent)
                .map_err(|e| format!("{p}: {e}"))?;
            compiled.source_hash = compile_worker::source_hash(&self.root, p).unwrap_or(0);
            new_set.insert(p.clone(), Rc::new(compiled));
        }
        Ok(new_set)
    }

    /// spec §7.2 D-B3.14 (P2-B3.1): the multi-root generalisation of
    /// [`Self::recompile`] -- `changed`/`deleted` are a GitHub-merge-sized
    /// batch of mudlib paths, not one `update`. Every *changed* path that
    /// is currently registered becomes a root; every currently-registered
    /// program that (directly or transitively) inherits any root is
    /// pulled in too (the reverse-inherit expansion, unioned across every
    /// root), sorted parents-first across the whole batch. A changed path
    /// with no registered program needs nothing (lazy load from disk) and
    /// is reported in [`RecompileSetOutcome::skipped_unloaded`] instead of
    /// being compiled. A deleted path that is still registered keeps
    /// running on its last-compiled program -- there is nothing on disk to
    /// recompile it from -- and is reported in
    /// [`RecompileSetOutcome::deleted_loaded`].
    ///
    /// **All-or-nothing (D-B3.14):** every target is compiled, collecting
    /// *every* failure instead of stopping at the first one (a merge can
    /// touch several unrelated programs, and the caller's report should
    /// show every diagnostic at once) -- but [`RecompileSetOutcome::new_set`]
    /// is only ever non-empty when [`RecompileSetOutcome::failures`] is
    /// empty. The caller ([`RegistryHost::recompile_set`]) installs
    /// `new_set` as a whole or not at all, exactly like [`Self::recompile`]/
    /// [`RegistryHost::install`] already do for one root.
    ///
    /// **Known simplification, same as [`Self::recompile`]/[`Self::
    /// finish_recompile`]:** this is the synchronous compile path, not yet
    /// off the world thread (unlike OBI-90's single-root `begin_recompile`/
    /// `finish_recompile`). Flagged, not hidden: batching an
    /// arbitrary-size changed set onto the existing background-thread
    /// machinery (`compile_worker::RecompileJob`, built for one root) is
    /// real follow-up work, not done in this slice -- see the P2-B3.1 task
    /// note. Nothing about `RecompileReport`'s shape depends on which
    /// thread compiled it, so that follow-up is purely additive.
    pub fn recompile_set(
        &mut self,
        registry: &Registry,
        changed: &[String],
        deleted: &[String],
    ) -> RecompileSetOutcome {
        let mut skipped_unloaded = Vec::new();
        let mut failures: Vec<(String, String)> = Vec::new();
        let mut roots: Vec<String> = Vec::new();
        for raw in changed {
            match mudlib::normalize_path(raw) {
                Ok(path) => {
                    if registry.program(&path).is_some() {
                        roots.push(path);
                    } else {
                        skipped_unloaded.push(path);
                    }
                }
                Err(e) => failures.push((raw.clone(), e)),
            }
        }
        let mut deleted_loaded = Vec::new();
        for raw in deleted {
            if let Ok(path) = mudlib::normalize_path(raw)
                && registry.program(&path).is_some()
            {
                deleted_loaded.push(path);
            }
        }

        let bail = |skipped_unloaded: Vec<String>,
                    deleted_loaded: Vec<String>,
                    failures: Vec<(String, String)>| {
            RecompileSetOutcome {
                new_set: HashMap::new(),
                recompiled: Vec::new(),
                skipped_unloaded,
                deleted_loaded,
                failures,
            }
        };

        if !failures.is_empty() || roots.is_empty() {
            return bail(skipped_unloaded, deleted_loaded, failures);
        }

        // Reverse-inherit expansion (D-B3.14), unioned across every root:
        // every currently-registered program that (directly or
        // transitively) inherits *any* changed, loaded path joins the
        // batch alongside its root(s).
        // A deleted-but-loaded dependent is *not* a target: it has no
        // source left to recompile from, so pulling it in would fail the
        // whole batch (e.g. a merge that deletes a subclass and edits its
        // base). It keeps running on its last-compiled program, reported
        // in `deleted_loaded` (CTO review).
        let mut targets: std::collections::BTreeSet<String> = roots.iter().cloned().collect();
        for p in registry.programs.values() {
            if !deleted_loaded.iter().any(|d| **d == *p.path) && roots.iter().any(|r| p.inherits(r))
            {
                targets.insert(p.path.to_string());
            }
        }
        // Parents before children across the *whole* batch: chain length
        // is still a valid topological key when roots share ancestors
        // (single-inherit chains, same restriction `Self::recompile` has).
        let mut ordered: Vec<String> = targets.into_iter().collect();
        ordered.sort_by_key(|p| registry.program(p).map_or(0, |cp| cp.chain().len()));

        for p in &ordered {
            self.session.invalidate(p);
        }

        // OBI-156 (generalised to a batch): a root may inherit an ancestor
        // that was never loaded/registered at all. Compiling each root
        // through the session resolves its whole linearization; queue any
        // member that isn't registered yet, ancestor-first, ahead of every
        // target below.
        let mut to_compile: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for root in &roots {
            match self.session.compile(root) {
                Outcome::Ok(checked) => {
                    for anc in &checked.info.linearization {
                        if **anc == *root.as_str() {
                            continue;
                        }
                        if registry.program(anc).is_none() && seen.insert(anc.to_string()) {
                            to_compile.push(anc.to_string());
                        }
                    }
                }
                Outcome::Failed(msg) | Outcome::Missing(msg) => {
                    failures.push((root.clone(), msg.to_string()))
                }
            }
        }
        for p in &ordered {
            if seen.insert(p.clone()) {
                to_compile.push(p.clone());
            }
        }
        if !failures.is_empty() {
            return bail(skipped_unloaded, deleted_loaded, failures);
        }

        for p in &to_compile {
            match self.session.compile(p) {
                Outcome::Ok(_) => {}
                Outcome::Failed(msg) | Outcome::Missing(msg) => {
                    failures.push((p.clone(), msg.to_string()))
                }
            }
        }
        if !failures.is_empty() {
            return bail(skipped_unloaded, deleted_loaded, failures);
        }

        let mut new_set: HashMap<String, Rc<CompiledProgram>> = HashMap::new();
        for p in &to_compile {
            let (anc_hir, anc_src) = match self.session.outcomes().get(p) {
                Some(Outcome::Ok(c)) => (c.hir.clone(), c.src.clone()),
                _ => {
                    failures.push((
                        p.clone(),
                        format!("internal: {p} missing from the compile session"),
                    ));
                    continue;
                }
            };
            // Same Phase 0 restriction as `Self::recompile`: only the first
            // `inherit` becomes this program's parent link.
            let parent = anc_hir.inherits.first().and_then(|inh| {
                new_set
                    .get(&*inh.path)
                    .cloned()
                    .or_else(|| registry.program(&inh.path))
            });
            let version = registry.program(p).map_or(1, |old| old.version + 1);
            match compile_hir_program(&anc_hir, &anc_src, version, parent) {
                Ok(mut compiled) => {
                    compiled.source_hash = compile_worker::source_hash(&self.root, p).unwrap_or(0);
                    new_set.insert(p.clone(), Rc::new(compiled));
                }
                Err(e) => failures.push((p.clone(), format!("{p}: {e}"))),
            }
        }
        if !failures.is_empty() {
            return bail(skipped_unloaded, deleted_loaded, failures);
        }

        RecompileSetOutcome {
            new_set,
            recompiled: ordered,
            skipped_unloaded,
            deleted_loaded,
            failures: Vec::new(),
        }
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
    ///
    /// **Redaction (OBI-296 T-FS-3):** every `Err` branch below returns
    /// `(path, message)` rather than one joined `String` -- `path` is
    /// always the specific program the diagnostic is about, named only
    /// in that first slot, never folded into `message`'s text. That is
    /// deliberate: the caller with per-uid `valid_read` context
    /// (`World::poll_recompiles`) decides whether `path` is safe to echo
    /// to whichever uid asked for this compile, and redacts the whole
    /// thing (`"<redacted>: compile failed"`) rather than just hiding
    /// `path` if not -- `message` alone could still name an identifier or
    /// quote a source fragment from a program that uid has no business
    /// reading (e.g. an inherited `/secure` dependent pulled in by `root_path`'s
    /// own widely-inherited recompile).
    pub fn finish_recompile(
        &mut self,
        registry: &Registry,
        root_path: &str,
        begin_snapshot: &compile_worker::ProgramSnapshot,
        outcome: compile_worker::CompileOutcome,
    ) -> Result<HashMap<String, Rc<CompiledProgram>>, (String, String)> {
        let result = match outcome {
            compile_worker::CompileOutcome::Ready(r) => r,
            compile_worker::CompileOutcome::Failed { path, message } => {
                return Err((path, message));
            }
        };

        let now = compile_worker::ProgramSnapshot::capture(registry);
        for wp in &result.programs {
            if now.entry(&wp.path) != begin_snapshot.entry(&wp.path) {
                return Err((
                    wp.path.clone(),
                    "stale: registry changed during background compile; re-issue update"
                        .to_string(),
                ));
            }
        }
        let mut begin_deps = begin_snapshot.dependents_of(root_path);
        let mut now_deps = now.dependents_of(root_path);
        begin_deps.sort_unstable();
        now_deps.sort_unstable();
        if begin_deps != now_deps {
            return Err((
                root_path.to_string(),
                "stale: dependent set changed during background compile; re-issue update"
                    .to_string(),
            ));
        }
        for (path, hash) in &result.ancestor_hashes {
            if now.source_hash_of(path) != Some(*hash) {
                return Err((
                    path.clone(),
                    "changed on disk since it was installed; update it first".to_string(),
                ));
            }
        }

        for p in &result.programs {
            self.session.invalidate(&p.path);
        }
        let mut new_set: HashMap<String, Rc<CompiledProgram>> = HashMap::new();
        for wp in result.programs {
            let module = loom_compiler::bytecode::decode(&wp.module_bytes).map_err(|e| {
                (
                    wp.path.clone(),
                    format!("corrupt background compile result: {e}"),
                )
            })?;
            loom_compiler::verify::verify(&module)
                .map_err(|e| (wp.path.clone(), format!("failed re-verification: {e}")))?;
            let var_specs: Vec<VarSpec> = wp
                .var_specs
                .iter()
                .map(|v| {
                    Ok(VarSpec {
                        name: Rc::from(v.name.as_str()),
                        ty: loom_compiler::bytecode::decode_ty(&v.ty_bytes)
                            .map_err(|e| (wp.path.clone(), format!("corrupt var type: {e}")))?,
                        has_init: v.has_init,
                        persistent: v.persistent,
                    })
                })
                .collect::<Result<_, (String, String)>>()?;
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

    /// Kick off `recompile_set`'s compile stage (D-B3.14, OBI-207 P2-B3.1b)
    /// on a background OS thread -- the multi-root generalisation of
    /// [`Self::begin_recompile`]. Returns immediately; nothing about
    /// `root`/`changed`/`deleted` is shared with anything the world thread
    /// touches afterwards except the [`compile_worker::ProgramSnapshot`]
    /// captured right now.
    pub fn begin_recompile_set(
        &self,
        root: &Path,
        registry: &Registry,
        changed: &[String],
        deleted: &[String],
    ) -> compile_worker::RecompileSetJob {
        self.begin_recompile_set_after(root, registry, changed, deleted, std::time::Duration::ZERO)
    }

    /// [`Self::begin_recompile_set`], but the background thread sleeps for
    /// `delay` before compiling -- test/tooling support, same as
    /// [`Self::begin_recompile_after`].
    #[doc(hidden)]
    pub fn begin_recompile_set_after(
        &self,
        root: &Path,
        registry: &Registry,
        changed: &[String],
        deleted: &[String],
        delay: std::time::Duration,
    ) -> compile_worker::RecompileSetJob {
        let snapshot = self.snapshot(registry);
        compile_worker::spawn_recompile_set_after(
            root.to_path_buf(),
            changed.to_vec(),
            deleted.to_vec(),
            snapshot,
            delay,
        )
    }

    /// Apply a finished [`compile_worker::RecompileSetJob`]'s outcome
    /// (D-B3.14, OBI-207 P2-B3.1b): the multi-root generalisation of
    /// [`Self::finish_recompile`].
    ///
    /// **Staleness (same three checks as `finish_recompile`, generalised
    /// to a batch):** re-snapshot `registry` right now and compare it with
    /// `begin_snapshot`. Refuse the whole batch (empty `new_set`, the
    /// diagnostic in `failures`) if:
    /// - any program this compile actually produced has a different
    ///   `(parent, version, source_hash)` now than at `begin_recompile_set`
    ///   time (someone else already changed it, e.g. a second overlapping
    ///   `recompile_set`/`recompile`/`ensure_program`);
    /// - re-classifying `changed`/`deleted` against the fresh snapshot
    ///   (same [`compile_worker::classify_targets`] the background thread
    ///   used) no longer agrees with what the background thread saw --
    ///   a different root set, a changed reverse-inherit expansion, or a
    ///   newly-(un)loaded path all count; or
    /// - any out-of-batch ancestor this compile actually consulted has a
    ///   different on-disk source now than what is currently installed.
    ///
    /// Otherwise: invalidate every compiled path in `self.session`, decode
    /// and **re-verify** each program (same trust boundary as
    /// `finish_recompile`), wire up real `Rc<CompiledProgram>` parent
    /// links, and return a [`RecompileSetOutcome`] ready for
    /// [`RegistryHost::install`] -- still all on the world thread, still
    /// all-or-nothing.
    pub fn finish_recompile_set(
        &mut self,
        registry: &Registry,
        changed: &[String],
        deleted: &[String],
        begin_snapshot: &compile_worker::ProgramSnapshot,
        outcome: compile_worker::CompileSetOutcome,
    ) -> RecompileSetOutcome {
        let bail = |failures: Vec<(String, String)>| RecompileSetOutcome {
            new_set: HashMap::new(),
            recompiled: Vec::new(),
            skipped_unloaded: Vec::new(),
            deleted_loaded: Vec::new(),
            failures,
        };
        let result = match outcome {
            compile_worker::CompileSetOutcome::Ready(r) => r,
            compile_worker::CompileSetOutcome::Failed(failures) => return bail(failures),
        };

        let now = compile_worker::ProgramSnapshot::capture(registry);
        for wp in &result.programs {
            if now.entry(&wp.path) != begin_snapshot.entry(&wp.path) {
                return bail(vec![(
                    wp.path.clone(),
                    format!(
                        "stale: registry changed during background compile of {}; re-issue update",
                        wp.path
                    ),
                )]);
            }
        }
        let then = compile_worker::classify_targets(begin_snapshot, changed, deleted);
        let now_classified = compile_worker::classify_targets(&now, changed, deleted);
        if then != now_classified {
            return bail(vec![(
                "<batch>".to_string(),
                "stale: changed-set classification (roots/dependents) changed during background \
                 compile; re-issue update"
                    .to_string(),
            )]);
        }
        for (path, hash) in &result.ancestor_hashes {
            if now.source_hash_of(path) != Some(*hash) {
                return bail(vec![(
                    path.clone(),
                    format!(
                        "ancestor {path} changed on disk since it was installed; update it first"
                    ),
                )]);
            }
        }

        for p in &result.programs {
            self.session.invalidate(&p.path);
        }
        let mut new_set: HashMap<String, Rc<CompiledProgram>> = HashMap::new();
        let mut failures: Vec<(String, String)> = Vec::new();
        for wp in result.programs {
            let decoded = (|| -> Result<CompiledProgram, String> {
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
                            persistent: v.persistent,
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
                Ok(prog)
            })();
            match decoded {
                Ok(prog) => {
                    new_set.insert(wp.path.clone(), Rc::new(prog));
                }
                Err(e) => failures.push((wp.path.clone(), e)),
            }
        }
        if !failures.is_empty() {
            return bail(failures);
        }

        RecompileSetOutcome {
            new_set,
            recompiled: result.recompiled,
            skipped_unloaded: result.skipped_unloaded,
            deleted_loaded: result.deleted_loaded,
            failures: Vec::new(),
        }
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

    fn program_path(&self) -> Option<&str> {
        Some(&self.path)
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

/// A copy-on-write capture of a whole [`Registry`]'s object graph (spec
/// §8.1 model 2, OBI-173): the output of [`Registry::capture`], and the
/// input to `crate::snapshot::SnapshotJob`'s byte encoder. Every `BcObject`
/// here still points at this process's live `Rc<CompiledProgram>` --
/// that pointer is never serialized (see `crate::snapshot`'s module docs);
/// only `BcObject::program`'s `path` is.
pub struct RegistrySnapshot {
    /// `(generation, Some(object))` per slot, in slot-index order, so a
    /// byte decoder can rebuild `ObjectId`s unchanged just by replaying
    /// index order (`Registry::restore`).
    pub slots: Vec<(u32, Option<BcObject>)>,
    pub free: Vec<u32>,
    pub names: HashMap<String, ObjectId>,
    pub next_clone: u64,
    pub conns: HashMap<u64, ObjectId>,
    pub bind_seq: HashMap<u64, u64>,
    pub next_bind_seq: u64,
    pub rng_state: u64,
    /// [`Interner::all_names`] at capture time, indexed by [`Sym`].
    pub sym_names: Vec<Rc<str>>,
}

/// `#[derive(Clone)]`: cheap -- every field is either `Copy`, a `String`/
/// `Vec` of plain data, or an `Rc` (OBI-173 binary snapshots:
/// `Registry::capture` clones every live slot's `BcObject` this way, which
/// is exactly the "O(object count) `Rc` bumps, not O(bytes)" copy-on-write
/// capture the spec's binary-snapshot model relies on -- see
/// `crate::snapshot`).
#[derive(Clone)]
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
    /// The object's `uid` (spec §5.7, OBI-35 D-S1.1): from the master's
    /// `creator_file(path)` at load/clone. **Immutable for the rest of
    /// the object's life, including across R1** (CTO review, OBI-121 B1:
    /// the spec explicitly keeps `uid` as `creator_file(p)` always, so it
    /// stays the single source of truth for "which program declared
    /// this"). Quotas are keyed on [`BcObject::owner`], not this field.
    pub uid: Sym,
    /// Effective uid for rights: starts equal to [`BcObject::owner`],
    /// changed only by a master-validated `seteuid`.
    pub euid: Sym,
    /// Owner (OBI-121 S2c §4): every owner-keyed quota (`max_objects`,
    /// `max_heartbeats`, `max_callouts_obj`, `max_mem_exec_mb`) is keyed
    /// on this field, not `uid`. Immutable once set at creation. **R1:**
    /// a load/clone whose current guard set does not already contain
    /// `creator_file(path)`'s (i.e. `uid`'s) own euid gets `owner` (and
    /// starting `euid`) set to the caller's own quota uid instead of
    /// `uid` (see `RegistryHost::instantiate`) -- otherwise equal to
    /// `uid`.
    pub owner: Sym,
    /// `mem_quota_bytes_for(owner)`'s result, cached (OBI-121 S2c CTO
    /// review, V7 bench gate follow-up): keyed on `World::roles_generation`
    /// (a monotonic counter), not the roles snapshot's own `Arc` pointer
    /// (N1: an `Arc`'s address can be reused after it is dropped -- ABA --
    /// so a pointer-keyed cache could wrongly serve a stale value after
    /// two snapshot swaps land back-to-back at the same address; a `u64`
    /// counter cannot repeat within a boot). `store_global` is a hot loop
    /// (a tight global-array index-write is O(1) per write, spec r5
    /// §5.2.1/OBI-80); re-resolving the owner's tier/policy row through
    /// the roles snapshot on every single write was a measured regression
    /// against the pre-quota baseline.
    pub mem_quota_cache: std::cell::Cell<Option<(u64, u64)>>,
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
            owner: ROOT,
            mem_quota_cache: std::cell::Cell::new(None),
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

/// `program_flags(path)`'s bitset value (OBI-121 S2c §7, CTO review B4):
/// `CONFINED = 1`, `LIVE = 2`, and **`0` (neither) is a real, distinct
/// state** -- most programs (`/std`, `/secure`, ordinary containers, the
/// void, ...) are neither confined nor live, and `move_to`'s confinement
/// rules simply stay inactive for them. This is *not* the same as
/// `LIVE`: rule 1 ("a confined object cannot move into a live room")
/// must not fire against an unflagged environment, only an explicitly
/// `LIVE` one. Absent a master apply (or an apply that errors), the
/// value is `0`, not `LIVE` -- a fail-*open* default in the sense that
/// nothing is granted or denied by it (this is a data classification,
/// not a privilege decision), but it must not silently promote every
/// unflagged program to `LIVE`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProgramFlags(u8);

impl ProgramFlags {
    pub const NONE: ProgramFlags = ProgramFlags(0);
    pub const CONFINED: ProgramFlags = ProgramFlags(1);
    pub const LIVE: ProgramFlags = ProgramFlags(2);

    fn from_master(v: Option<Value>) -> ProgramFlags {
        match v {
            Some(Value::Int(n)) if n >= 0 => ProgramFlags((n as u64 & 0b11) as u8),
            _ => ProgramFlags::NONE,
        }
    }

    pub fn is_confined(self) -> bool {
        self.0 & Self::CONFINED.0 != 0
    }

    pub fn is_live(self) -> bool {
        self.0 & Self::LIVE.0 != 0
    }

    /// `program_flags`'s own vocabulary for `World::program_flags`
    /// (tests/introspection), which predates the bitset and only ever
    /// asked about one flag at a time.
    pub fn as_str(self) -> &'static str {
        if self.is_confined() {
            "confined"
        } else if self.is_live() {
            "live"
        } else {
            "none"
        }
    }
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
    /// `loom_mudlib_sync_total{result}` (D-B3.14); see [`SyncMetrics`].
    pub sync_metrics: SyncMetrics,
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
    /// `program_flags(path)` (OBI-121 S2c §7): a cached master apply,
    /// called at most once per path per compile (`RegistryHost::
    /// ensure_program_flags`, invalidated by `Registry::install` whenever
    /// that path is recompiled). Absent means "never asked yet" -- the
    /// getter [`Registry::program_flags`] treats that the same as
    /// [`ProgramFlags::NONE`].
    program_flags_cache: HashMap<String, ProgramFlags>,
    /// Live object count per owner uid (OBI-121 S2c `max_objects`), kept
    /// only for uids [`crate::quota::is_unlimited_uid`] says are not
    /// always-unlimited -- `root`/`mudlib`/`domain:*` are never billed,
    /// so never tracked here at all. Maintained by [`Registry::insert`]/
    /// [`Registry::remove`], the only two places an object's slot is ever
    /// created or freed.
    objects_by_uid: HashMap<Sym, u64>,
    /// `loom_tier_quota_breaches_total{tier,quota}` (OBI-121 S2c); see
    /// `crate::quota::QuotaBreachMetrics`.
    pub quota_breaches: crate::quota::QuotaBreachMetrics,
    /// `profile <program>`'s currently open sampling window (spec Phase
    /// 2 B5, OBI-170), `None` the overwhelming rest of the time --
    /// started by `World::profile_start`/the `profile_start` efun,
    /// consumed by `World::profile_stop`/`profile_stop`. See
    /// `crate::profiler`'s module doc for the "unmeasurable overhead
    /// when off" cost argument this field's `Option` is central to.
    pub profiler: Option<crate::profiler::Profiler>,
    /// Canary updates in flight (P2-B7, OBI-182, spec §7.4), keyed by
    /// program path. At most one per path: starting a new one for a path
    /// that already has one active is refused by `RegistryHost::
    /// canary_update_efun`, and any *plain* recompile of the path (not
    /// through `canary_update`) implicitly cancels it (`Registry::
    /// install`) rather than leaving it pointed at a candidate that is no
    /// longer `programs[path]`.
    pub canaries: HashMap<String, CanaryState>,
}

/// One in-flight canary (P2-B7, OBI-182, spec §7.4): `canary_update(path,
/// ..)` installs `candidate` as `programs[path]` same as any recompile,
/// but only `pct`% of instances (chosen by a deterministic hash of the
/// object id, spec: "by object id hash") migrate to it on access while
/// this is active -- the rest stay pinned to `stable` (see `RegistryHost::
/// ensure_current`). `World::tick` watches `errors_at_start` vs. the
/// error inbox's live count for `candidate`'s path (P2-B4) and either
/// promotes (clears this, letting the remaining instances lazily migrate
/// like a normal install) or rolls back (re-points `programs[path]` at
/// `stable` and clears this, so every instance already on `candidate`
/// lazily migrates *back* -- `RegistryHost::upgrade` is symmetric, it has
/// no notion of "forward"/"backward").
pub struct CanaryState {
    /// The program that was live immediately before this canary started;
    /// what a rollback re-installs.
    pub stable: Rc<CompiledProgram>,
    /// The new version being canaried; `programs[path]` for as long as
    /// this canary is active (promotion is a no-op on `programs`, it only
    /// clears this entry and lets the rest of the cohort catch up).
    pub candidate: Rc<CompiledProgram>,
    /// 1..=100: the percentage of accessed instances routed to
    /// `candidate` while this is active.
    pub pct: u8,
    /// The world tick (`Scheduler::tick`) this canary started on --
    /// ticks, not wall-clock time, deliberately (same deviation as
    /// `TickShareWindow`, `World::tick`'s own doc comment: a world tick is
    /// a fixed 100 ms when the driver is ticking on its normal timer, so
    /// this is fully deterministic from the tick counter alone and a test
    /// can drive a whole window with repeated `World::tick()` calls
    /// instead of a real sleep).
    pub started_tick: u64,
    /// How many world ticks this canary watches for before auto-promoting
    /// (if the error budget was never exceeded).
    pub window_ticks: u64,
    /// The error inbox's `count_for_program(candidate.path)` the instant
    /// this canary started (P2-B4): `World::tick` compares the *current*
    /// count against this baseline, not the raw count, so pre-existing
    /// errors unrelated to this candidate never count against it.
    pub errors_at_start: u64,
    /// How many *new* errors (current count minus `errors_at_start`) this
    /// candidate may accrue before `World::tick` rolls it back
    /// immediately, without waiting for `window_ticks` to elapse.
    pub max_new_errors: u64,
}

/// Spec §7.4: "installs the new version for a fraction of ... clones (by
/// object id hash)". A fast, deterministic spread (Knuth's multiplicative
/// hash) over `id`'s slot index -- stable for as long as the object lives
/// (an index is only reused after the slot frees and is handed back out,
/// at which point it is a different object with a different generation,
/// so revisiting this function for it is correct, not a stale decision
/// leaking across objects). `pct` is clamped to `0..=100` by the caller
/// (`RegistryHost::canary_update_efun`); `0` never selects anything,
/// `100` always does.
pub fn canary_cohort(id: ObjectId, pct: u8) -> bool {
    if pct == 0 {
        return false;
    }
    if pct >= 100 {
        return true;
    }
    let hashed = (id.index as u64).wrapping_mul(2_654_435_761);
    (hashed % 100) < pct as u64
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

/// Validate every cross-reference a decoded snapshot carries *before*
/// [`Registry::restore`] touches `self` with any of it (PR #69 review,
/// OBI-173 R1): a snapshot file is attacker-reachable the moment it
/// touches disk or a copyover channel (same trust boundary as
/// `crate::snapshot`'s own module docs), so a hand-crafted or merely
/// corrupt file must become a clean `Err` here, never a `Registry` left
/// with a dangling `ObjectId`, a `free` list that hands out a live slot
/// as empty, or an `env`/`inventory` pair that disagree about who
/// contains whom.
///
/// Checks, in order:
/// - every `env`/`inventory`/`conns`/`names` [`ObjectId`] points at a
///   slot that is both in range and *live* (`Some` object) with a
///   matching `generation` -- a stale generation is exactly the "this
///   object was destroyed and its slot reused" case [`ObjectId`] exists
///   to detect;
/// - every `free` entry is an in-range, *empty* slot, and the list has no
///   duplicate index (two free-list entries for the same slot would let
///   two different `instantiate` calls hand out the same `ObjectId`);
/// - every live object whose `env` is `Some(e)` is actually present in
///   `e`'s own `inventory` (the two sides of placement must agree, or a
///   later `move_object`/`destruct` walk -- which trusts exactly this
///   invariant -- silently corrupts the graph instead of panicking or
///   erroring).
fn validate_decoded_snapshot(snap: &crate::snapshot::DecodedSnapshot) -> Result<(), String> {
    let slot_count = snap.slots.len();

    let live_generation = |idx: u32| -> Option<u32> {
        snap.slots
            .get(idx as usize)
            .and_then(|(generation, obj)| obj.as_ref().map(|_| *generation))
    };

    let check_id = |id: ObjectId, what: &str| -> Result<(), String> {
        match live_generation(id.index) {
            Some(g) if g == id.generation => Ok(()),
            Some(g) => Err(format!(
                "{what} references object {}#{} but the live slot's generation is {g}",
                id.index, id.generation
            )),
            None => Err(format!(
                "{what} references object {}#{} but slot {} is empty or out of range",
                id.index, id.generation, id.index
            )),
        }
    };

    let mut seen_free = std::collections::HashSet::new();
    for &idx in &snap.free {
        if idx as usize >= slot_count {
            return Err(format!("free list references out-of-range slot {idx}"));
        }
        if snap.slots[idx as usize].1.is_some() {
            return Err(format!("free list references live slot {idx}"));
        }
        if !seen_free.insert(idx) {
            return Err(format!("free list contains duplicate slot {idx}"));
        }
    }

    for (name, id) in &snap.names {
        check_id(*id, &format!("name {name:?}"))?;
    }
    for (conn, id) in &snap.conns {
        check_id(*id, &format!("connection {conn}"))?;
    }

    for (i, (generation, obj)) in snap.slots.iter().enumerate() {
        let Some(obj) = obj else { continue };
        let this_id = ObjectId {
            index: i as u32,
            generation: *generation,
        };
        if let Some(env) = obj.env {
            check_id(env, &format!("object {:?} (slot {i}) env", obj.name))?;
            // `check_id` above already proved `env.index` is in range and
            // live, so the slot access here cannot panic.
            let env_obj = snap.slots[env.index as usize].1.as_ref().unwrap();
            if !env_obj.inventory.contains(&this_id) {
                return Err(format!(
                    "object {:?} (slot {i}) has env slot {} but is not in that object's inventory",
                    obj.name, env.index
                ));
            }
        }
        for inv_id in &obj.inventory {
            check_id(
                *inv_id,
                &format!("object {:?} (slot {i}) inventory", obj.name),
            )?;
        }
    }

    Ok(())
}

impl Registry {
    pub fn register_program(&mut self, prog: Rc<CompiledProgram>) {
        self.programs.insert(prog.path.to_string(), prog);
    }

    pub fn program(&self, path: &str) -> Option<Rc<CompiledProgram>> {
        self.programs.get(path).cloned()
    }

    /// P2-B7 (OBI-182): promote `path`'s in-flight canary -- clears the
    /// entry and bumps `install_generation` so every instance still
    /// pinned to `stable` (because it was not in the fraction cohort)
    /// re-checks on its next access and lazily migrates to `candidate`,
    /// which has been `programs[path]` all along. A no-op (returns
    /// `false`) if `path` has no active canary.
    pub fn promote_canary(&mut self, path: &str) -> bool {
        if self.canaries.remove(path).is_none() {
            return false;
        }
        self.install_generation += 1;
        true
    }

    /// P2-B7 (OBI-182): roll `path`'s in-flight canary back -- re-points
    /// `programs[path]` at `stable` and clears the entry, then bumps
    /// `install_generation` so every instance already migrated to
    /// `candidate` (the fraction cohort) re-checks on its next access and
    /// lazily migrates *back* (`RegistryHost::upgrade` works on any
    /// target program, not only a "newer" one). A no-op (returns `false`)
    /// if `path` has no active canary.
    pub fn rollback_canary(&mut self, path: &str) -> bool {
        let Some(canary) = self.canaries.remove(path) else {
            return false;
        };
        self.programs.insert(path.to_string(), canary.stable);
        self.install_generation += 1;
        true
    }

    pub fn insert(&mut self, obj: BcObject) -> ObjectId {
        let owner = obj.owner;
        let id = if let Some(index) = self.free.pop() {
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
        };
        self.bump_object_count(owner, 1);
        id
    }

    pub fn get(&self, id: ObjectId) -> Option<&BcObject> {
        self.slots
            .get(id.index as usize)
            .filter(|s| s.generation == id.generation)
            .and_then(|s| s.obj.as_ref())
    }

    /// [`RecompileReport::upgraded_instances`] (D-B3.14): how many
    /// currently-live objects run one of `paths`' programs right now,
    /// taken just before `RegistryHost::install` -- a point-in-time count,
    /// not a guarantee every one of them is still live (or still on that
    /// program) by the time a caller reads the report back.
    pub(crate) fn live_instance_count(&self, paths: &std::collections::HashSet<&str>) -> usize {
        self.slots
            .iter()
            .filter_map(|s| s.obj.as_ref())
            .filter(|o| paths.contains(o.program.path.as_ref()))
            .count()
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
        self.bump_object_count(obj.owner, -1);
        Some(obj)
    }

    /// `objects_by_uid` bookkeeping (OBI-121 S2c `max_objects`): a
    /// `delta` of `1` on [`Registry::insert`], `-1` on [`Registry::
    /// remove`]. Skipped entirely for `root`/`mudlib`/`domain:*`
    /// ([`crate::quota::is_unlimited_uid`]) -- they are never billed, so
    /// never worth tracking.
    fn bump_object_count(&mut self, uid: Sym, delta: i64) {
        if crate::quota::is_unlimited_uid(self.syms.name(uid)) {
            return;
        }
        let e = self.objects_by_uid.entry(uid).or_insert(0);
        *e = (*e as i64 + delta).max(0) as u64;
    }

    /// Live object count currently charged to `uid` (OBI-121 S2c
    /// `max_objects`); `0` for an always-unlimited uid, since those are
    /// never tracked.
    pub fn object_count_for_uid(&self, uid: Sym) -> u64 {
        self.objects_by_uid.get(&uid).copied().unwrap_or(0)
    }

    /// `program_flags(path)`'s cached result (OBI-121 S2c §7):
    /// [`ProgramFlags::NONE`] if never computed (or the path is not
    /// registered at all) -- the fail-open default, not `Live` (CTO
    /// review B4/N nits).
    pub fn program_flags(&self, path: &str) -> ProgramFlags {
        self.program_flags_cache
            .get(path)
            .copied()
            .unwrap_or_default()
    }

    /// Has `path`'s `program_flags` already been computed and cached?
    /// (`RegistryHost::ensure_program_flags`'s cache-hit check.)
    fn has_program_flags(&self, path: &str) -> bool {
        self.program_flags_cache.contains_key(path)
    }

    /// Cache `path`'s `program_flags` result, or drop it (recompile
    /// invalidation: `Registry::install` calls this with `None` for every
    /// path it just replaced, so the next `ensure_program_flags` recomputes
    /// it against the master rather than serving the pre-recompile value).
    fn set_program_flags(&mut self, path: &str, flags: Option<ProgramFlags>) {
        match flags {
            Some(f) => {
                self.program_flags_cache.insert(path.to_string(), f);
            }
            None => {
                self.program_flags_cache.remove(path);
            }
        }
    }

    /// Drop every cached `program_flags` result (CTO review nit): used by
    /// `RegistryHost::install` when `/secure/master` itself is one of the
    /// recompiled paths, since every entry -- not only the recompiled
    /// ones -- was computed by calling the *old* master's apply.
    fn clear_program_flags_cache(&mut self) {
        self.program_flags_cache.clear();
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

    /// Capture a copy-on-write snapshot of the whole object graph (spec
    /// §8.1 model 2, OBI-173): `O(live object count)` `Rc` clones (every
    /// object's `vars`/`inventory`/`program` pointer is bumped, nothing is
    /// deep-copied), not `O(bytes)`. This is the *entire* synchronous cost
    /// a binary snapshot charges the world thread -- the much larger job
    /// of turning this into bytes (`crate::snapshot::SnapshotJob`) runs
    /// against the returned, now-independent [`RegistrySnapshot`] and can
    /// be spread across many later ticks without ever re-borrowing this
    /// `Registry`, because every `Value` here is immutable-once-shared
    /// (module docs on `bcvm::heap`): a later in-place write anywhere in
    /// the live registry goes through `Rc::make_mut`, which clones the
    /// buffer instead of mutating through this snapshot's own `Rc`.
    ///
    /// Refused (not silently wrong) while an `atomic fn` scope is open:
    /// the journal only makes sense relative to one in-flight call's frame
    /// stack, and a snapshot taken mid-scope could later be loaded into a
    /// process with no frame to roll back against.
    pub fn capture(&self) -> Result<RegistrySnapshot, &'static str> {
        if self.atomic_active != 0 {
            return Err("cannot snapshot while an atomic fn scope is open");
        }
        let slots = self
            .slots
            .iter()
            .map(|s| (s.generation, s.obj.clone()))
            .collect();
        Ok(RegistrySnapshot {
            slots,
            free: self.free.clone(),
            names: self.names.clone(),
            next_clone: self.next_clone,
            conns: self.conns.clone(),
            bind_seq: self.bind_seq.clone(),
            next_bind_seq: self.next_bind_seq,
            rng_state: self.rng.state(),
            sym_names: self.syms.all_names().to_vec(),
        })
    }

    /// The load side of [`Registry::capture`] (OBI-173): rebuild every
    /// field [`Registry::capture`] reads, from a [`crate::snapshot::
    /// DecodedSnapshot`] that has just been parsed back out of bytes
    /// (possibly in a brand new process -- the "standby side of copyover",
    /// spec §8.1). `ObjectId`s are preserved exactly: slots are rebuilt at
    /// the same `(index, generation)` they were captured at, so every
    /// `env`/`inventory`/`conns`/`names` reference the snapshot carried
    /// stays valid without any remapping pass.
    ///
    /// Every cross-reference the snapshot carries is validated by
    /// [`validate_decoded_snapshot`] *before* anything below touches
    /// `self` (PR #69 review, OBI-173 R1): a corrupt or hand-crafted
    /// snapshot must become a clean `Err`, never a `Registry` with a
    /// dangling `env`/`inventory`/`conns`/`names` reference or a
    /// `free` list that silently hands out a live slot as if it were
    /// empty.
    ///
    /// `compiler` compiles (or reuses an already-compiled) program for
    /// every distinct path referenced by a restored object, exactly like a
    /// normal boot would -- a binary snapshot carries *dynamic* state
    /// (vars, placement, connections), never a program's bytecode, so the
    /// fresh process's own mudlib on disk is always the source of truth
    /// for code. A path the snapshot references that no longer compiles
    /// (or no longer exists) is a clean `Err`, not a panic.
    pub fn restore(
        &mut self,
        snap: crate::snapshot::DecodedSnapshot,
        compiler: &mut Compiler,
    ) -> Result<(), String> {
        validate_decoded_snapshot(&snap)?;
        let mut syms = Interner::default();
        for name in &snap.sym_names {
            syms.intern(name);
        }
        let mut slots = Vec::with_capacity(snap.slots.len());
        let mut objects_by_uid: HashMap<Sym, u64> = HashMap::new();
        for (generation, obj) in snap.slots {
            let obj = match obj {
                None => None,
                Some(d) => {
                    let prog = compiler
                        .ensure_program(self, &d.program_path)
                        .map_err(|e| format!("{}: {e}", d.program_path))?;
                    let mut o = BcObject::new(prog);
                    o.name = d.name;
                    o.vars = d.vars.into_iter().collect();
                    o.env = d.env;
                    o.inventory = d.inventory;
                    o.conn = d.conn;
                    o.uid = d.uid;
                    o.euid = d.euid;
                    o.owner = d.owner;
                    o.recompute_mem_bytes();
                    if !crate::quota::is_unlimited_uid(syms.name(o.owner)) {
                        *objects_by_uid.entry(o.owner).or_insert(0) += 1;
                    }
                    Some(o)
                }
            };
            slots.push(Slot { generation, obj });
        }
        self.slots = slots;
        self.free = snap.free;
        self.names = snap.names;
        self.next_clone = snap.next_clone;
        self.conns = snap.conns;
        self.bind_seq = snap.bind_seq;
        self.next_bind_seq = snap.next_bind_seq;
        self.rng = crate::rng::Rng::from_state(snap.rng_state);
        self.syms = syms;
        self.objects_by_uid = objects_by_uid;
        Ok(())
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
    ///
    /// **OBI-80:** each `VarWrite` restore bypasses
    /// [`RegistryHost::store_global`] (there is nothing to re-check a quota
    /// against on a rollback), but it must still keep [`BcObject::mem_bytes`]
    /// correct — the same O(1) cost-delta `store_global` does, not a
    /// [`BcObject::recompute_mem_bytes`] walk per restored var. Without this,
    /// a rolled-back var write left `mem_bytes` charging bytes for whatever
    /// the *failed* attempt had written, not what `vars` actually holds
    /// after the rollback.
    fn journal_rollback(&mut self, mark: u64) {
        while self.journal.len() as u64 > mark {
            match self.journal.pop().unwrap() {
                JournalEntry::VarWrite { obj, key, old } => {
                    if let Some(o) = self.get_mut(obj) {
                        let prev_cost = o.vars.get(&key).map(heap::cost).unwrap_or(0);
                        match old {
                            Some(v) => {
                                let new_cost = heap::cost(&v);
                                o.mem_bytes = o
                                    .mem_bytes
                                    .saturating_sub(prev_cost)
                                    .saturating_add(new_cost);
                                o.vars.insert(key, v);
                            }
                            None => {
                                o.mem_bytes = o.mem_bytes.saturating_sub(prev_cost);
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
    /// The program each nested [`RegistryHost::call_in`] handed its
    /// interpreter as the base module, innermost last. A closure made by a
    /// base-module frame belongs to *that* program, which is an ancestor
    /// when the function is inherited, not to the object's leaf program
    /// (OBI-37: pinning the leaf made an inherited closure index the wrong
    /// module's function table).
    base_code: Vec<Rc<CompiledProgram>>,
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
    /// `World::roles_generation` as of this snapshot (OBI-121 S2c N1):
    /// what `BcObject::mem_quota_cache` keys on instead of `roles`'s own
    /// `Arc` pointer (which can be reused after a drop -- ABA -- while a
    /// `u64` counter cannot repeat within a boot).
    roles_generation: u64,
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
    /// Player-save root for `save_object`/`restore_object` (spec §8.1,
    /// OBI-171): deliberately **not** the mudlib VFS root above -- save
    /// data is driver state, not mudlib source, and must never end up
    /// inside the Git-backed `.wf` tree (§8.5) or get swept up by a
    /// `revert`/recompile. Confined the same way (`crate::fileio`'s
    /// lexical + symlink-escape checks), just against this root instead.
    save_root: PathBuf,
    /// `disk_quota_mb`'s per-`<u>` byte counter (OBI-137 S1), owned by
    /// `World`; see `crate::disk_usage::DiskUsage`.
    disk_usage: &'a mut crate::disk_usage::DiskUsage,
    /// The deferred-durability queue for `save_object` (OBI-348, spec §8.1),
    /// owned by `World` exactly like `disk_usage`/`errors` next to it; see
    /// [`crate::save_queue`]. `save_object` enqueues here instead of calling
    /// `write_file_atomic` itself, which is what takes the two `fsync`s a
    /// save costs off the world thread.
    save_queue: &'a mut crate::save_queue::SaveQueue,
    /// Grouped runtime-error inbox (OBI-169), owned by `World`; the
    /// `errors` efun reads it back (filtered by the caller's own
    /// `valid_read` permission on each distinct program it covers).
    /// `World::exec` itself is what *writes* to this (every `Err` an
    /// execution returns is recorded there, uniformly, independent of
    /// whether this efun is ever called) -- see `World::note_error`.
    errors: &'a mut crate::errors::ErrorInbox,
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
        let path = o.program.path.clone();
        let current = self.registry.programs.get(&*path).cloned();
        if let Some(current) = current {
            // P2-B7 (OBI-182): a path with an active canary routes by the
            // object id hash instead of unconditionally migrating to
            // `current` (which, for the duration of the canary, *is*
            // `candidate` -- see `CanaryState`'s own doc comment). Not in
            // the cohort means "stay on `stable`", which is a no-op here
            // whenever that is already `o.program` (the overwhelmingly
            // common case: an object this function has already stamped
            // once during this same canary's window).
            let target = match self.registry.canaries.get(&*path) {
                Some(canary) if canary_cohort(id, canary.pct) => current.clone(),
                Some(canary) => canary.stable.clone(),
                None => current.clone(),
            };
            if !Rc::ptr_eq(&target, &o.program)
                && let Err(w) = self.upgrade(id, target)
            {
                self.registry.lazy_upgrade_warnings.push(w);
            }
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
            base_code: Vec::new(),
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
        roles_generation: u64,
        roles_ctx: crate::world::RolesCtx<'a>,
        cut_guard: Option<GuardSet>,
        input_actor: Option<Sym>,
        disk_usage: &'a mut crate::disk_usage::DiskUsage,
        errors: &'a mut crate::errors::ErrorInbox,
        save_queue: &'a mut crate::save_queue::SaveQueue,
        save_root: PathBuf,
    ) -> Self {
        let base = cut_guard
            .unwrap_or_else(|| GuardSet::empty().with(principal_of(registry, self_object)));
        let root = compiler.root().to_path_buf();
        RegistryHost {
            registry,
            self_stack: vec![self_object],
            base_code: Vec::new(),
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
                roles_generation,
                roles_ctx,
                input_actor,
                root,
                save_root,
                disk_usage,
                save_queue,
                errors,
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
        self.ensure_program_flags(&path);
        // R1 does not apply here (OBI-121 S2c §7, flagged for CTO
        // re-review): `load_object` returns the *same* singleton for
        // `path` to every caller forever after (the early return just
        // above) -- it never multiplies billed objects, so it is not the
        // clone-spam quota-evasion R1 targets, and applying R1 anyway
        // would let whichever caller *happens* to `load_object` a given
        // path first silently steal that path's owner/euid assignment
        // (a real regression: `security.rs`'s `a_lower_privileged_caller_
        // denies_a_higher_privileged_callee` loads `/builders/arch/daemon`
        // from `appr`'s stack and still expects it owned/euid'd `arch`).
        self.new_object(prog, path, false)
    }

    /// `clone_object`: a new clone `path#N`.
    pub fn clone_object(&mut self, path: &str) -> R<ObjectId> {
        let path = mudlib::normalize_path(path).map_err(RtError::new)?;
        let prog = self.ensure_program(&path)?;
        self.ensure_program_flags(&path);
        // Kept on the registry, not `Driver`, so it is never lost across
        // per-call `RegistryHost` construction (mirrors `State::next_clone`).
        self.registry.next_clone += 1;
        let name = format!("{path}#{}", self.registry.next_clone);
        let id = self.new_object(prog, name.clone(), true)?;
        // spec r5 §5.2.1: a clone is undoable by an enclosing `atomic fn`
        // scope (a no-op, no allocation, when none is open).
        self.registry.journal_clone(id, name);
        Ok(id)
    }

    /// `program_flags(path)` (OBI-121 S2c §7): a cached master apply, run
    /// at most once per path (until the next recompile of it,
    /// `RegistryHost::install`). A no-op with no master (boot, or the
    /// driver-less unit tests in this module): `Registry::program_flags`
    /// then defaults every path to [`ProgramFlags::NONE`], same as an
    /// explicit apply that returned anything but `1`/`2`.
    /// `program_flags(path)` (OBI-121 S2c §7) fail-open default: with no
    /// master (boot, or the driver-less unit tests in this module),
    /// `Registry::program_flags` defaults every path to `ProgramFlags::
    /// NONE` -- not `LIVE` (CTO review B4: defaulting to `LIVE` would
    /// make an unflagged `/std`/`/secure` environment silently start
    /// refusing every confined object, which is not what "fail open" on a
    /// missing data-classification apply should mean).
    fn ensure_program_flags(&mut self, path: &str) {
        if self.registry.has_program_flags(path) {
            return;
        }
        // No master yet (boot: everything `/secure/master`'s own
        // `create()` loads, e.g. its zones' rooms) -- leave the path
        // uncached, so the first confinement check after boot asks the
        // real master (`Self::program_flags_of`). Caching `NONE` here
        // made every boot-loaded room permanently unflagged, i.e. a
        // `CONFINED` object could be dropped into a live start room.
        let Some(m) = self.master() else {
            return;
        };
        let r = self.run_cut(m, "program_flags", vec![Value::str(path)], None);
        let flags = ProgramFlags::from_master(r.ok().flatten());
        self.registry.set_program_flags(path, Some(flags));
    }

    /// `path`'s confinement flags, computing them first if they were
    /// never cached (a program loaded before the master existed).
    fn program_flags_of(&mut self, path: &str) -> ProgramFlags {
        if !self.registry.has_program_flags(path) {
            self.ensure_program_flags(path);
        }
        self.registry.program_flags(path)
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
    fn new_object(
        &mut self,
        prog: Rc<CompiledProgram>,
        name: String,
        apply_r1: bool,
    ) -> R<ObjectId> {
        let id = self.instantiate(prog, apply_r1)?;
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
    ) -> Result<(), (String, String)> {
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
        // `Registry::lazy_upgrade_warnings`, not here. `install` never
        // actually returns `Err` today, but its signature still carries a
        // `String` error -- pair it with `root_path` rather than widen
        // this method's own `Err` type to a three-case enum for a branch
        // that can't be hit.
        self.install(new_set)
            .map(|_| ())
            .map_err(|e| (root_path.to_string(), e))
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

    /// `crate::quota::Defaults` for every `quota::resolve` call in this
    /// file (CTO review N5): all of them (`max_objects`, `max_heartbeats`,
    /// `max_callouts_obj`/`max_callouts_uid`, `max_mem_exec_mb`,
    /// `disk_quota_mb`) only ever read a count field or
    /// `max_mem_exec_bytes()`, never `max_ticks_exec`, so the tick side of
    /// `Defaults` here is a placeholder, not a real fallback -- the two
    /// call sites that *do* read `max_ticks_exec` (`World::exec`'s
    /// tier-resolved tick budget, `World::tick_share_breached`) build
    /// their own `Defaults` directly from `self.limits.max_ticks`, since
    /// only `World` (not `RegistryHost`) has that field. The mem side is
    /// real: `self.limits.mem_quota_bytes`, the same configured default
    /// `store_global` used before this quota model existed.
    fn quota_defaults(&self) -> crate::quota::Defaults {
        crate::quota::Defaults::from_limits(
            crate::quota::WORLD_DEFAULT_MAX_TICKS_EXEC,
            self.limits.mem_quota_bytes,
        )
    }

    /// "The caller's quota uid" (OBI-121 S2c §4, CTO review B1/N4): **the
    /// lowest-tier *billable* principal in the current guard set, ties
    /// broken by the most recently pushed frame.** "Billable" excludes
    /// every always-unlimited uid (`root`/`mudlib`/`domain:*`,
    /// `crate::quota::is_unlimited_uid`) from the ranking entirely (N4:
    /// `RolesSnapshot::tier` returns 0 -- the *lowest* tier -- for any uid
    /// with no `staff` row, and that includes every unlimited uid, so
    /// ranking them alongside real tiers let an apprentice's call through
    /// any `/std`/`/daemons` helper come out as `mudlib`'s quota uid
    /// instead of the apprentice's own -- exactly the evasion R1/this
    /// method exist to close). A tier-0 *player* (a real, billed uid whose
    /// tier just happens to be 0) still correctly outranks an apprentice.
    ///
    /// Falls back to `Host::current_uid` (the self object's own uid) with
    /// no driver/roles snapshot available (unit tests), an empty guard set
    /// (an all-root call chain has no principal to rank), or when *every*
    /// principal on the guard is an unlimited uid (nothing billable to
    /// pick).
    fn caller_quota_uid(&self) -> Sym {
        self.lowest_tier_guard_principal(0)
            .unwrap_or_else(|| self.current_uid())
    }

    /// The shared ranking `caller_quota_uid` uses, parameterised by a
    /// minimum tier (D-S2.4 amendment, OBI-153): the lowest-tier
    /// *billable* principal in the current guard set with `tier >=
    /// min_tier`, ties broken by the most recently pushed frame. Always
    /// excludes every always-unlimited uid from the ranking, same as
    /// `caller_quota_uid` (see its doc comment for why: an unlimited uid
    /// has no real tier and must never be picked as a billing owner).
    /// Returns `None` with an empty guard, no driver/roles snapshot, or
    /// no principal meeting `min_tier` -- callers decide their own
    /// fallback.
    fn lowest_tier_guard_principal(&self, min_tier: u32) -> Option<Sym> {
        let guard = self.top_guard();
        if guard.is_empty() {
            return None;
        }
        let driver = self.driver.as_ref()?;
        let mut best: Option<(u32, Sym)> = None;
        for p in guard.principals() {
            let name = self.registry.syms.name(p.euid);
            if crate::quota::is_unlimited_uid(name) {
                continue;
            }
            let tier = driver.roles.tier(name);
            if tier < min_tier {
                continue;
            }
            // `<=` so a later (more recently pushed) frame wins a tie,
            // per spec ("ties to the most recent frame") -- push order
            // means later entries in `principals()` were pushed later.
            if best.is_none_or(|(bt, _)| tier <= bt) {
                best = Some((tier, p.euid));
            }
        }
        best.map(|(_, euid)| euid)
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

    /// `max_objects` (OBI-121 S2c): denies `instantiate` (before the
    /// object is even inserted) when `uid` is already at its tier's live
    /// object count. A no-op without a driver (unit tests) or for an
    /// always-unlimited uid.
    fn check_max_objects(&mut self, uid: Sym) -> R<()> {
        let Some(driver) = self.driver.as_ref() else {
            return Ok(());
        };
        let name = self.registry.syms.name(uid).to_string();
        if crate::quota::is_unlimited_uid(&name) {
            return Ok(());
        }
        let tier = driver.roles.tier(&name);
        let q = crate::quota::resolve(&driver.roles, &name, self.quota_defaults());
        let Some(max) = q.max_objects else {
            return Ok(());
        };
        if self.registry.object_count_for_uid(uid) >= max {
            self.registry
                .quota_breaches
                .record(tier, crate::quota::MAX_OBJECTS);
            return Err(self.deny_quota(
                crate::quota::MAX_OBJECTS,
                format!("object quota exceeded for `{name}` (limit {max})"),
            ));
        }
        Ok(())
    }

    /// `max_callouts_obj`/`max_callouts_uid` (OBI-121 S2c): checked before
    /// `call_out` schedules the new pending call. `me` is charged under
    /// its own owner uid's tier row; `quota_uid` (the execution's quota
    /// uid, OBI-35 D-S1.6) separately, since one uid's objects can
    /// collectively schedule more `call_out`s than any one of them alone.
    fn check_callout_quota(&mut self, me: ObjectId, quota_uid: Sym) -> R<()> {
        let Some(driver) = self.driver.as_ref() else {
            return Ok(());
        };
        let me_uid = self.registry.get(me).map_or(quota_uid, |o| o.owner);
        let me_name = self.registry.syms.name(me_uid).to_string();
        if !crate::quota::is_unlimited_uid(&me_name) {
            let tier = driver.roles.tier(&me_name);
            if let Some(max) = crate::quota::resolve(&driver.roles, &me_name, self.quota_defaults())
                .max_callouts_obj
            {
                let current = driver.scheduler.pending_count_for_obj(me) as u64;
                if current >= max {
                    self.registry
                        .quota_breaches
                        .record(tier, crate::quota::MAX_CALLOUTS_OBJ);
                    return Err(self.deny_quota(
                        crate::quota::MAX_CALLOUTS_OBJ,
                        format!("max_callouts_obj quota exceeded for `{me_name}` (limit {max})"),
                    ));
                }
            }
        }
        let uid_name = self.registry.syms.name(quota_uid).to_string();
        if !crate::quota::is_unlimited_uid(&uid_name) {
            let driver = self.driver.as_ref().expect("checked above");
            let tier = driver.roles.tier(&uid_name);
            if let Some(max) =
                crate::quota::resolve(&driver.roles, &uid_name, self.quota_defaults())
                    .max_callouts_uid
            {
                let current = driver.scheduler.pending_count_for_quota_uid(quota_uid) as u64;
                if current >= max {
                    self.registry
                        .quota_breaches
                        .record(tier, crate::quota::MAX_CALLOUTS_UID);
                    return Err(self.deny_quota(
                        crate::quota::MAX_CALLOUTS_UID,
                        format!("max_callouts_uid quota exceeded for `{uid_name}` (limit {max})"),
                    ));
                }
            }
        }
        Ok(())
    }

    /// `max_heartbeats` (OBI-121 S2c, OBI-137 S3): checked before
    /// `set_heartbeat(true)` subscribes `me`, keyed on `me`'s own owner
    /// uid. `Scheduler::heartbeat_count_for_owner` is an `O(1)` `HashMap`
    /// lookup (OBI-137 S3), not a scan of every heartbeat target.
    fn check_heartbeat_quota(&mut self, me: ObjectId) -> R<()> {
        let Some(driver) = self.driver.as_ref() else {
            return Ok(());
        };
        let Some(uid) = self.registry.get(me).map(|o| o.owner) else {
            return Ok(());
        };
        let name = self.registry.syms.name(uid).to_string();
        if crate::quota::is_unlimited_uid(&name) {
            return Ok(());
        }
        let tier = driver.roles.tier(&name);
        let Some(max) =
            crate::quota::resolve(&driver.roles, &name, self.quota_defaults()).max_heartbeats
        else {
            return Ok(());
        };
        if driver.scheduler.is_heartbeat_target(me) {
            return Ok(()); // re-subscribing does not add to the count
        }
        let current = driver.scheduler.heartbeat_count_for_owner(uid);
        if current >= max {
            self.registry
                .quota_breaches
                .record(tier, crate::quota::MAX_HEARTBEATS);
            return Err(self.deny_quota(
                crate::quota::MAX_HEARTBEATS,
                format!("max_heartbeats quota exceeded for `{name}` (limit {max})"),
            ));
        }
        Ok(())
    }

    /// The effective per-object vars quota (bytes) for an object whose
    /// owner is `uid` (OBI-121 S2c: `max_mem_exec_mb`, "applied as the
    /// per-object vars limit by the owner's tier"). Without a driver
    /// (unit tests), falls back to `self.limits.mem_quota_bytes` --
    /// preserves the pre-OBI-121 test contract of a fixed quota set
    /// directly on `Limits`.
    #[inline]
    fn mem_quota_bytes_for(&self, uid: Sym) -> u64 {
        let Some(driver) = self.driver.as_ref() else {
            return self.limits.mem_quota_bytes;
        };
        let name = self.registry.syms.name(uid);
        crate::quota::resolve(&driver.roles, name, self.quota_defaults()).max_mem_exec_bytes()
    }

    /// Bump `loom_tier_quota_breaches_total{tier,max_mem_exec_mb}` for a
    /// `store_global` denial (a no-op without a driver, or when `uid` is
    /// `None` -- `self` was already destructed by the time the write was
    /// attempted, so there is nothing to bill).
    fn record_mem_quota_breach(&mut self, uid: Option<Sym>) {
        let (Some(driver), Some(uid)) = (self.driver.as_ref(), uid) else {
            return;
        };
        let name = self.registry.syms.name(uid).to_string();
        let tier = driver.roles.tier(&name);
        self.registry
            .quota_breaches
            .record(tier, crate::quota::MAX_MEM_EXEC_MB);
    }

    /// `disk_quota_mb` (OBI-121 S2c, OBI-137 S1): only paths under
    /// `/builders/<u>/**` are quota-scoped (spec), keyed on `<u>` itself
    /// (the directory's owner), not the caller -- a grant/staff write
    /// into someone else's `/builders/<u>` still counts against `<u>`'s
    /// own quota. A no-op (returns `Ok(true)`) without a driver, for a
    /// path outside `/builders/**`, or for an always-unlimited (or
    /// policy-silent) `<u>`.
    ///
    /// Returns `Ok(false)` (never `Err`) for an over-quota write, after
    /// pushing the audit entry and bumping the breach metric itself
    /// (OBI-137 S1: `write_file` over quota must return `false`, not
    /// raise) -- the caller (`write_file`'s efun arm) turns that into
    /// `Ok(Value::Bool(false))`, never an `RtError`.
    ///
    /// **No `O(files)` walk here** (OBI-137 S1): the directory total
    /// comes from `DiskUsage::seeded_total` (one walk, the first time
    /// `<u>` is ever asked about, cached from then on) and the file's old
    /// size from `fileio::file_size_bytes` (`metadata().len()`, never its
    /// contents). On acceptance, the counter is updated here too (the
    /// caller writes unconditionally right after this returns `true`, on
    /// the single-threaded world thread, so nothing else can race it in
    /// between). **OBI-348 deliberately leaves `write_file` charging at the
    /// call:** it is a synchronous, mudlib-visible write; only
    /// `save_object`'s durability moved to the queue, so only its quota
    /// charge moved with it -- see [`Self::check_save_disk_quota`].
    ///
    /// **OBI-236 fix:** the directory pool (`seeded_total`/`note_write`)
    /// and the save pool (`DiskUsage::seeded_save_total`, used by
    /// `check_save_disk_quota`) are seeded independently, so whichever of
    /// the two a given `<u>` happens to hit first no longer determines
    /// what the *other* pool starts from. `disk_quota_mb` still has to
    /// cover everything `<u>` has on disk, so `projected` here folds in
    /// `DiskUsage::save_total`'s current save-pool total (0 if `<u>` has
    /// never gone through `check_save_disk_quota` yet -- this never
    /// forces a save-file stat on an unrelated `write_file`).
    fn check_disk_quota(&mut self, path: &str, new_bytes: u64) -> R<bool> {
        let Some(driver) = self.driver.as_ref() else {
            return Ok(true);
        };
        let mut segs = path.trim_start_matches('/').split('/');
        if segs.next() != Some("builders") {
            return Ok(true);
        }
        let Some(u) = segs.next().filter(|s| !s.is_empty()).map(|s| s.to_string()) else {
            return Ok(true);
        };
        if crate::quota::is_unlimited_uid(&u) {
            return Ok(true);
        }
        let tier = driver.roles.tier(&u);
        let Some(max_mb) =
            crate::quota::resolve(&driver.roles, &u, self.quota_defaults()).disk_quota_mb
        else {
            return Ok(true);
        };
        let root = driver.root.clone();
        let old_bytes = crate::fileio::file_size_bytes(&root, path).unwrap_or(0);
        let max_bytes = max_mb.saturating_mul(crate::quota::MB);
        let driver = self.driver.as_mut().expect("checked above");
        let seeded = driver.disk_usage.seeded_total(&root, &u);
        let save_now = driver.disk_usage.save_total(&u);
        // OBI-348: a `save_object` accepted but not yet durable is charged to
        // `DiskUsage` only when it lands, so its bytes have to be folded in
        // here too -- otherwise a builder with saves in flight could write
        // past `disk_quota_mb` through `write_file`.
        let save_queued = driver.save_queue.pending_bytes_for_uid(&u);
        let projected = seeded
            .saturating_sub(old_bytes)
            .saturating_add(new_bytes)
            .saturating_add(save_now)
            .saturating_add(save_queued);
        if projected > max_bytes {
            self.registry
                .quota_breaches
                .record(tier, crate::quota::DISK_QUOTA_MB);
            self.audit_quota_denial(
                crate::quota::DISK_QUOTA_MB,
                format!(
                    "disk_quota_mb quota exceeded for `{u}` ({projected} bytes would be in \
                     use under /builders/{u}, quota is {max_bytes} bytes)"
                ),
            );
            return Ok(false);
        }
        let driver = self.driver.as_mut().expect("checked above");
        driver.disk_usage.note_write(&u, old_bytes, new_bytes);
        Ok(true)
    }

    /// `disk_quota_mb` for `save_object` (OBI-171, CTO review on PR #75,
    /// must-fix 2): `check_disk_quota` attributes a write to the `<u>`
    /// named *in the path* (`/builders/<u>/**`), but a save path carries
    /// no uid in its text at all -- so without this, any P1 object could
    /// fill the disk by calling `save_object` against arbitrarily many
    /// paths, entirely outside `disk_quota_mb`. Instead this charges the
    /// *writing* object's own uid (`principal_of(self_object()).uid`),
    /// the same principal the master's save-path authorization contract
    /// (`docs/save-objects.md`) is responsible for confining each save to
    /// in the first place. Same seeded-once/`O(1)`-after contract and the
    /// same non-raising `Ok(None)`-on-breach shape as `check_disk_quota`;
    /// see [`crate::disk_usage::DiskUsage::seeded_save_total`] for why the
    /// seed here is one `metadata()` stat instead of a directory walk.
    ///
    /// **OBI-348: this projects, it no longer charges.** Under deferred
    /// durability the bytes are not on disk when this returns, so charging
    /// `note_save_write` at *accept* time would bill the world for a write
    /// that may never land (and would have to be unwound if the durable
    /// write then failed). This returns the size the write replaces --
    /// which `save_object` carries in the queued task -- and the charge is
    /// applied exactly once, from the real post-rename size, when the
    /// outcome is reaped ([`crate::save_queue::apply_outcomes`]). The
    /// projection is what keeps the cap honest in the meantime: a second
    /// save to a path whose first save has not landed yet is measured
    /// against the **queued** content, not the stale file
    /// ([`crate::save_queue::SaveQueue::pending_for_path`]), so N queued
    /// saves to one path can neither be billed N times nor slip past the cap
    /// as if each were the only one.
    ///
    /// **OBI-236 fix:** this uses its own save pool
    /// (`seeded_save_total`/`note_save_write`), seeded independently of
    /// `check_disk_quota`'s directory pool -- whichever of the two runs
    /// first for a given `<u>` no longer determines what the other
    /// starts from. `projected` folds in the directory pool via
    /// `seeded_total` (seeding it with one walk if `<u>` has never gone
    /// through `check_disk_quota` yet, since the walk root is known here)
    /// so a save is checked against everything `<u>` has on disk, not
    /// just its own save file, even when the save runs first.
    fn check_save_disk_quota(&mut self, save_file_rel: &str, new_bytes: u64) -> R<Option<u64>> {
        let Some(driver) = self.driver.as_ref() else {
            return Ok(Some(0));
        };
        let uid = principal_of(self.registry, self.self_object()).uid;
        let u = self.registry.syms.name(uid).to_string();
        if crate::quota::is_unlimited_uid(&u) {
            return Ok(Some(0));
        }
        let tier = driver.roles.tier(&u);
        let Some(max_mb) =
            crate::quota::resolve(&driver.roles, &u, self.quota_defaults()).disk_quota_mb
        else {
            return Ok(Some(0));
        };
        let save_root = driver.save_root.clone();
        let root = driver.root.clone();
        // The "old" side of the projection: the newest queued save for this
        // path if one is still waiting to land, else the file on disk.
        let queued_same = driver
            .save_queue
            .pending_for_path(save_file_rel)
            .map(|(_, b)| b);
        let old_bytes = match queued_same {
            Some(bytes) => bytes,
            None => crate::fileio::file_size_bytes(&save_root, save_file_rel).unwrap_or(0),
        };
        // Everything else this uid has queued is uncharged too, and must
        // still count against the cap (OBI-348).
        let queued_other = driver
            .save_queue
            .pending_bytes_for_uid(&u)
            .saturating_sub(queued_same.unwrap_or(0));
        let max_bytes = max_mb.saturating_mul(crate::quota::MB);
        let driver = self.driver.as_mut().expect("checked above");
        let seeded = driver
            .disk_usage
            .seeded_save_total(&save_root, &u, save_file_rel);
        let dir_now = driver.disk_usage.seeded_total(&root, &u);
        let projected = seeded
            .saturating_sub(old_bytes)
            .saturating_add(new_bytes)
            .saturating_add(queued_other)
            .saturating_add(dir_now);
        if projected > max_bytes {
            self.registry
                .quota_breaches
                .record(tier, crate::quota::DISK_QUOTA_MB);
            self.audit_quota_denial(
                crate::quota::DISK_QUOTA_MB,
                format!(
                    "disk_quota_mb quota exceeded for `{u}` ({projected} bytes would be in \
                     use for save_object(\"{save_file_rel}\"), quota is {max_bytes} bytes)"
                ),
            );
            return Ok(None);
        }
        Ok(Some(old_bytes))
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

    /// Decide `op` for every euid in `guard` (D-S1.2/D-S1.3): the
    /// shared core of [`Self::authorize`] and [`Self::admin_valid_read`].
    /// Stops at the **first** euid (push order, [`GuardSet::euids`]) that
    /// does not get a real `true`: either a plain denial (the cached
    /// decision, or the master's apply, answered `false`/non-`bool`) or
    /// an apply failure (the master has no apply, or the apply itself
    /// errored -- tick/call-depth exhaustion, a thrown value, any
    /// runtime error). A later euid is never asked once an earlier one
    /// has already decided the outcome, same as a single-euid guard --
    /// callers must not see a second, deeper apply's error (or its tick
    /// cost) for a decision that was already made.
    ///
    /// Returns `(denied_by, apply_err)`: `denied_by` is the first euid
    /// that didn't get a real `true` (`None` iff the guard is empty or
    /// every euid did); `apply_err` is `Some` iff that denial was an
    /// apply failure rather than an actual `false` answer (CTO review,
    /// OBI-279, must-fix 1: this is what lets [`Self::admin_valid_read`]
    /// surface a tick-budget/runtime failure as `Err` while
    /// [`Self::authorize`] still fails closed -- same decision, two
    /// different things to do with it, instead of two separately
    /// maintained copies of this loop that can drift apart from each
    /// other, which is exactly what happened here).
    ///
    /// A policy-cache hit/miss-then-answer is stored in the cache either
    /// way (an apply that completed, allow or deny); an apply failure is
    /// never cached (an answer that never actually arrived must not
    /// poison the decision cache for the next lookup of the same euid).
    fn decide(
        &mut self,
        guard: &GuardSet,
        caller: ObjectId,
        op: &Operation<'_>,
    ) -> (Option<Sym>, Option<RtError>) {
        if guard.is_empty() {
            return (None, None);
        }
        let master = self.master();
        for euid in guard.euids() {
            let looked = self
                .driver
                .as_mut()
                .expect("decide needs a driver")
                .security
                .lookup(op, euid);
            let (allowed, err) = match looked {
                Ok(b) => (b, None),
                Err(miss) => {
                    self.extra_ticks += MISS_CHARGE;
                    let outcome = match master {
                        None => Ok(false),
                        Some(m) => {
                            let args = self.apply_args(op, caller);
                            match self.run_cut(m, op.apply(), args, Some(euid)) {
                                Ok(Some(Value::Bool(b))) => Ok(b),
                                Ok(_) => Ok(false),
                                Err(e) => Err(e),
                            }
                        }
                    };
                    let sec = &mut self.driver.as_mut().expect("driver").security;
                    sec.misses += 1;
                    match outcome {
                        Ok(b) => {
                            if let Some(miss) = miss {
                                sec.store(miss, b);
                            }
                            (b, None)
                        }
                        Err(e) => (false, Some(e)),
                    }
                }
            };
            if !allowed {
                return (Some(euid), err);
            }
        }
        (None, None)
    }

    /// Decide `op` for the current guard set (D-S1.2/D-S1.3): allowed iff
    /// the guard set is empty (all root) or the master's apply returns
    /// `true` for **every** euid in it. Fails closed: no master, no apply,
    /// an error or a non-bool result all deny. Audited either way.
    fn authorize(&mut self, efun: &str, class: Privilege, op: Operation<'_>) -> R<()> {
        // OBI-279 (CTO review, PR #102, non-blocking note 2):
        // `audit_kind_name` resolves both a registered efun name and the
        // small set of driver-internal, never-player-callable call sites
        // (`"admin_query"`) that still want a real audit `kind`, not the
        // `"?"` fallback `static_name` alone would give the latter.
        let efun = crate::efuns::audit_kind_name(efun);
        let guard = self.top_guard().clone();
        let caller = self.self_object();
        // Fails closed: `decide`'s `apply_err` (an apply that couldn't
        // answer at all) is deliberately not distinguished from a plain
        // `false` here -- both just deny the call, same as before this
        // was extracted into a function shared with `admin_valid_read`
        // (CTO review, OBI-279, must-fix 1).
        let (denied_by, _apply_err) = self.decide(&guard, caller, &op);
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

    /// Authorizes a compile for `raw_path` exactly as the synchronous
    /// `compile_object` efun arm does -- same `authorize(P1,
    /// Operation::Compile)` call, same audit record -- but does not run
    /// [`Self::recompile`] itself. Used by `World::begin_file_compile`
    /// (OBI-180 M-FS-5, CTO review of PR #119, must-fix 1): the
    /// permission check and its audit entry happen here, inside one
    /// `World::exec` on the world thread, exactly like every other
    /// file-op efun; the actual parse/check/codegen/verify work (and,
    /// for a widely-inherited path, every dependent) then runs off the
    /// world thread via `World::begin_recompile`, which has no
    /// authorization of its own to run (D-P1.5's existing background
    /// compile path was only ever reachable from driver-internal
    /// callers, e.g. tests and tooling, never straight from an
    /// HTTP-authenticated uid before this). Returns the normalized path
    /// so the caller hands `begin_recompile` the same string `authorize`
    /// just checked, not whatever the caller happened to pass in.
    pub(crate) fn authorize_compile(&mut self, raw_path: &str) -> R<String> {
        let norm = mudlib::normalize_path(raw_path).map_err(RtError::new)?;
        self.authorize(
            "compile_object",
            Privilege::P1,
            Operation::Compile { path: &norm },
        )?;
        Ok(norm)
    }

    /// Driver-side `valid_read` check (OBI-237, the admin query
    /// world-thread side, OBI-234 follow-up): the exact `authorize`/
    /// `Operation::Read` call path every other `valid_read` call-site
    /// uses (`read_file`, the `errors` efun's per-program filter) --
    /// same decision cache, same master apply, same audit trail -- just
    /// invoked directly by `World`'s admin-query handling instead of
    /// from inside a running program (there is no in-game efun call, or
    /// caller object, to attribute this to; `World::admin_list_objects`/
    /// `admin_object_vars` instead run this inside a `cut_guard`
    /// carrying the HTTP-authenticated staff account's own euid, see
    /// their doc comments). The `"admin_query"` name passed to
    /// `authorize` does not match any registered efun (never
    /// player-callable), but is a recognized [`crate::efuns::
    /// NON_EFUN_AUDIT_KINDS`] entry (OBI-279, CTO review of PR #102,
    /// non-blocking note 2), so it is still recorded in the audit
    /// trail's `kind` field as `"admin_query"`, not `"?"` -- the actual
    /// allow/deny decision and the audit record's other fields (euid,
    /// operation, verdict) were always real; only the `kind` label was
    /// the gap, and it's now fixed.
    ///
    /// CTO review (OBI-279, follow-up to PR #102, non-blocking note 1):
    /// this is **not** a thin call to [`Self::authorize`] -- `authorize`
    /// fails closed by design (spec: an in-game efun's `valid_*` apply
    /// that errors, including tick/call-depth exhaustion, must still
    /// just *deny* the call, never let the error itself escape into the
    /// calling program's own unwind). That is the right contract for
    /// every player-facing `valid_*` gate, but wrong for this one: an
    /// HTTP admin query has no running program to fail safely back into
    /// -- a `valid_read` that could not produce a real answer (its own
    /// tick budget ([`APPLY_TICKS`]) ran out, or it raised/threw) must
    /// surface as `Err` here, so `World::admin_list_objects`/
    /// `admin_object_vars`/`admin_errors` can propagate it out to the
    /// HTTP edge's `503`, not silently fold it into "nothing readable"
    /// (`exec(...).unwrap_or_default()`'s bug, fixed alongside this).
    ///
    /// CTO review (OBI-279, must-fix 1): shares [`Self::decide`]'s
    /// per-euid loop with `authorize` instead of a second, hand-copied
    /// one -- an earlier version of this method forked that loop and
    /// drifted from it (it only stopped early on an apply failure, not
    /// on an ordinary denial), which a two-euid guard where the first
    /// euid denies and the second euid's `valid_read` itself errors
    /// would have wrongly surfaced as `Err` instead of a plain `Ok(false)`
    /// (`decide`'s own doc comment, and `World`'s unit test
    /// `admin_valid_read_stops_at_the_first_denying_euid_in_a_multi_
    /// principal_guard`, cover this).
    pub(crate) fn admin_valid_read(&mut self, op: &'static str, path: &str) -> R<bool> {
        let kind = crate::efuns::audit_kind_name("admin_query");
        let operation = Operation::Read { path, op };
        let guard = self.top_guard().clone();
        let caller = self.self_object();
        let (denied_by, apply_err) = self.decide(&guard, caller, &operation);
        let sec = &mut self.driver.as_mut().expect("driver").security;
        sec.record(
            caller,
            kind,
            Privilege::P1,
            &operation,
            &guard,
            denied_by.is_none(),
            denied_by,
        );
        match apply_err {
            Some(e) => Err(e),
            None => Ok(denied_by.is_none()),
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
            Operation::Upgrade { path } => vec![Value::str(path), ob],
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

    /// `move_to`'s three confinement rules (OBI-121 S2c §7, CTO review
    /// B3): a pure data lookup against `Registry::program_flags`, each
    /// object's `conn` (is it interactive, i.e. has a connection bound to
    /// it *right now*?) and the roles snapshot's tier of its **euid** --
    /// no master apply, so this adds nothing but O(1) map reads to
    /// `move_to`'s existing O(depth) cycle-check walk (V7 bench gate).
    ///
    /// 1. A `Confined` object cannot move into a `Live` room.
    /// 2. A `Confined` object cannot move into a tier-0 player's
    ///    inventory, but can move into a staff player's. "Tier-0 player's
    ///    inventory" means **anywhere in `dest`'s environment chain**, not
    ///    only `dest` itself -- `dest_chain_has_tier0_interactive` is
    ///    precomputed by `move_to`'s own chain walk so this rule sees a
    ///    confined item smuggled into a bag that is itself in a tier-0
    ///    player's inventory.
    /// 3. A tier-0 player cannot enter a `Confined` room.
    ///
    /// **Interactive, not owner/creator** (fixes B3): a real mudlib player
    /// is a `mudlib`-owned `/std/player` clone whose *euid* is
    /// `seteuid`'d to the account by `/secure/login` -- keying rules 2/3
    /// on `uid`/`owner` would make every player (staff included) tier 0,
    /// since `mudlib` itself is never staff. "Is this object a player"
    /// is instead "does it have a connection bound to it right now"
    /// (`BcObject::conn`), and its tier is its **euid**'s tier, not its
    /// owner's.
    fn check_confinement(
        &mut self,
        me: ObjectId,
        dest: ObjectId,
        dest_chain_has_tier0_interactive: bool,
    ) -> R<()> {
        let Some(me_ob) = self.registry.get(me) else {
            return Ok(());
        };
        let Some(dest_ob) = self.registry.get(dest) else {
            return Ok(());
        };
        let me_prog = me_ob.program.clone();
        let dest_prog = dest_ob.program.clone();
        let me_euid = self.registry.syms.name(me_ob.euid).to_string();
        let me_is_interactive_tier0 = me_ob.conn.is_some() && self.euid_tier(&me_euid) == 0;
        let me_flags = self.program_flags_of(&me_prog.path);
        let dest_flags = self.program_flags_of(&dest_prog.path);

        if me_flags.is_confined() {
            if dest_chain_has_tier0_interactive {
                return Err(self.deny_confinement(
                    me,
                    "move_to(): a confined object cannot move into a tier-0 player's inventory",
                ));
            } else if dest_flags.is_live() {
                return Err(self.deny_confinement(
                    me,
                    "move_to(): a confined object cannot move into a live room",
                ));
            }
        }
        if me_is_interactive_tier0 && dest_flags.is_confined() {
            return Err(self.deny_confinement(
                me,
                "move_to(): a tier-0 player cannot enter a confined room",
            ));
        }
        Ok(())
    }

    /// `roles.tier(euid)`, or tier 0 with no driver/roles snapshot at all
    /// (driver-less unit tests: nothing is ever staff without a snapshot,
    /// same default `RolesSnapshot::tier` itself uses for an unknown uid).
    fn euid_tier(&self, euid_name: &str) -> u32 {
        self.driver.as_ref().map_or(0, |d| d.roles.tier(euid_name))
    }

    /// Audits a `move_to` confinement denial (spec: "an error and an audit
    /// entry on violation") and returns the error to raise. Not routed
    /// through `authorize`/`Operation`: confinement is a driver rule
    /// derived from cached data, not a master `valid_*` decision.
    fn deny_confinement(&mut self, caller: ObjectId, msg: &'static str) -> RtError {
        if let Some(d) = self.driver.as_mut() {
            d.security.push(AuditEntry {
                caller,
                efun: "move_to",
                privilege: Privilege::P0,
                apply: "confinement",
                arg: msg.into(),
                guard: GuardSet::empty(),
                allowed: false,
                denied_by: None,
                at_unix_ms: 0, // stamped by `push` itself
            });
        }
        RtError::new(msg)
    }

    /// Audits a quota denial (spec §3/§5: "quota breaches" go to the audit
    /// sink, same as every other decision, CTO review S4). Not routed
    /// through `authorize`/`Operation`: a quota breach is a driver rule
    /// derived from the S2 roles snapshot, not a master `valid_*`
    /// decision.
    fn audit_quota_denial(&mut self, quota: &'static str, msg: String) {
        let caller = self.self_object();
        if let Some(d) = self.driver.as_mut() {
            d.security.push(AuditEntry {
                caller,
                efun: quota,
                privilege: Privilege::P0,
                apply: "quota",
                arg: msg.into(),
                guard: GuardSet::empty(),
                allowed: false,
                denied_by: None,
                at_unix_ms: 0, // stamped by `push` itself
            });
        }
    }

    /// Same audit as [`Self::audit_quota_denial`], but for a quota whose
    /// enforcement point raises rather than returning a sentinel value
    /// (every quota except `disk_quota_mb`, OBI-137 S1: `write_file` over
    /// quota returns `false` instead, see `check_disk_quota`).
    fn deny_quota(&mut self, quota: &'static str, msg: String) -> RtError {
        self.audit_quota_denial(quota, msg.clone());
        RtError::new(msg)
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
        // `destruct` is exempted too (OBI-149): whether it needs
        // `valid_efun` at all depends on its *argument* (`self()` is a
        // P0 driver rule, anything else is still P2 -- see the
        // `"destruct"` match arm below), which this generic pre-check
        // cannot see before `args` is parsed.
        if let Some(p) = crate::efuns::privilege(name)
            && p.gated()
            && !matches!(
                name,
                "unguarded"
                    | "destruct"
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
                // The confined-chain check (rule 2) folds into this same
                // O(depth) cycle-check walk (V7 bench gate: no extra pass,
                // no master apply) -- "tier-0 player's inventory" means
                // anywhere in `dest`'s environment chain, not only `dest`
                // itself.
                let mut cur = Some(dest);
                let mut dest_chain_has_tier0_interactive = false;
                while let Some(c) = cur {
                    if c == me {
                        return Err(RtError::new(
                            "move_to(): cannot move an object into itself or its contents",
                        ));
                    }
                    if !dest_chain_has_tier0_interactive
                        && let Some(o) = self.registry.get(c)
                        && o.conn.is_some()
                    {
                        let euid = self.registry.syms.name(o.euid).to_string();
                        if self.euid_tier(&euid) == 0 {
                            dest_chain_has_tier0_interactive = true;
                        }
                    }
                    cur = self.registry.get(c).and_then(|o| o.env);
                }
                self.check_confinement(me, dest, dest_chain_has_tier0_interactive)?;
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
            "set_echo" => {
                let Value::Bool(enabled) = a1 else {
                    return Err(RtError::new("set_echo(): expected bool"));
                };
                if let Value::Object(id) = a0 {
                    let conn = self.registry.get(id).and_then(|o| o.conn);
                    if let Some(conn) = conn
                        && let Some(d) = self.driver.as_mut()
                    {
                        d.net.set_echo(conn, enabled);
                    }
                } else if !matches!(a0, Value::Null) {
                    return Err(RtError::new(format!(
                        "set_echo(): expected object, got {}",
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
                self.authorize(name, Privilege::P1, Operation::Upgrade { path: &path })?;
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
            // Spec Phase 2 B5 (OBI-170), ownership added per CTO review
            // should-fix 4 (OBI-232): open a per-function tick/time
            // sampling window on `path`. The generic P1 `valid_efun`
            // pre-check above already gated this call; no path-specific
            // apply (it reads nothing it couldn't already see by calling
            // into `path` itself, and writes only the profiler's own
            // counters).
            //
            // No longer "last write wins" (the OBI-170 PR #67 should-fix
            // this closes): a window already open, owned by a *different*
            // principal than the one calling now, is left alone and this
            // call fails -- one P1 caller (a builder debugging their own
            // area) can no longer silently discard another's in-progress
            // profile. The same owner re-calling `profile_start` (e.g. to
            // retarget to a different program) still just replaces their
            // own window, same as before.
            //
            // Exception (OBI-238): a window that has already hit its own
            // auto-expiry cap (`Profiler::is_expired`) is replaced
            // outright, even by a different principal -- it is not
            // sampling anything anymore (`wants` already answers `false`
            // for it), so holding the ownership lock on it would just let
            // a builder who forgot to call `profile_stop` block everyone
            // else's profiling indefinitely.
            "profile_start" => {
                let p = a0
                    .as_str()
                    .ok_or_else(|| RtError::new("profile_start(): expected string"))?;
                let path = mudlib::normalize_path(p).map_err(RtError::new)?;
                let owner = self
                    .registry
                    .syms
                    .name(principal_of(self.registry, self.self_object()).euid)
                    .to_string();
                if let Some(existing) = self.registry.profiler.as_ref()
                    && existing.owner() != owner
                    && !existing.is_expired()
                {
                    return Err(RtError::new(format!(
                        "profile_start(): a profiling window on {:?} is already open, owned by \
                         {} -- have them call profile_stop() first, or force-close it yourself \
                         with profile_stop(true) if you hold P3 privilege",
                        existing.program(),
                        existing.owner()
                    )));
                }
                self.registry.profiler = Some(crate::profiler::Profiler::new(path, owner));
                Ok(Value::Null)
            }
            // Close the window opened by `profile_start` and return its
            // report, already rendered as the in-game-readable text
            // `crate::profiler::ProfileReport::render` produces (OBI-170
            // acceptance: "output is readable in-game"). A string, not a
            // struct, because Weft has no `profile`-shaped record type to
            // hand one back as yet -- a builder command wraps this in a
            // single `send(this_player(), profile_stop())`.
            //
            // `force` (should-fix 4, OBI-232): optional second arg,
            // default `false`. A caller who isn't the window's owner
            // normally gets a permission error instead of silently
            // closing someone else's in-progress profile (mirrors
            // `profile_start`'s new refusal); passing `true` still
            // requires passing this efun's own P3 `valid_efun` check
            // (same mechanism `seteuid`/`account_create` use), so only a
            // caller the master actually grants P3 to can force-close
            // another principal's window.
            "profile_stop" => {
                let force = matches!(a0, Value::Bool(true));
                let Some(open_owner) = self
                    .registry
                    .profiler
                    .as_ref()
                    .map(|p| p.owner().to_string())
                else {
                    return Ok(Value::str(
                        "profile: no sampling window is open (call profile_start() first)\n",
                    ));
                };
                let caller_owner = self
                    .registry
                    .syms
                    .name(principal_of(self.registry, self.self_object()).euid)
                    .to_string();
                if open_owner != caller_owner {
                    if !force {
                        return Err(RtError::new(format!(
                            "profile_stop(): this window is owned by {open_owner}, not you -- \
                             pass true to force-close it (requires P3 privilege)"
                        )));
                    }
                    // A distinct `Operation::Efun` name from plain
                    // "profile_stop" (not a registered efun -- it never
                    // needs to be, `Operation::Efun`'s `name` is just an
                    // opaque cache-key/describe() tag here): the policy
                    // decision cache keys *only* on efun name, not
                    // name+class (`Operation::cache_parts`, "the efun
                    // class is not part of the key: it is fixed per efun
                    // name") -- reusing "profile_stop" here would let the
                    // generic P1 pre-check's cached `true` answer this
                    // unrelated P3 question too, defeating the whole
                    // check (caught by this file's own
                    // `force_without_p3_is_still_denied` integration
                    // test).
                    self.authorize(
                        "profile_stop",
                        Privilege::P3,
                        Operation::Efun {
                            name: "profile_stop(force)",
                            class: Privilege::P3,
                        },
                    )?;
                }
                let text = self
                    .registry
                    .profiler
                    .take()
                    .expect("checked Some above")
                    .report()
                    .render();
                Ok(Value::str(&text))
            }
            // P2-B7 (OBI-182, spec §7.4): `update --canary N%` --
            // recompile `path` same as `compile_object`, but only route
            // `pct`% of accessed instances (by object id hash) to the new
            // version while `World::tick` watches the P2-B4 error inbox
            // for `window_ticks`, auto-promoting (if the new-error budget
            // is never exceeded) or auto-rolling-back (the instant it is).
            // Same tier as `compile_object`/`upgrade_all` (D-P1.6): a
            // canary is strictly less exposure than either (it starts at
            // a *fraction*, not everyone).
            "canary_update" => self.canary_update_efun(&a0, &a1, &a2, &a3),
            // Introspection for the builder command/web IDE driving the
            // above: `null` if `path` has no canary in flight, else a map
            // of its live state. Same `valid_upgrade`/P1 gate as
            // `canary_update` -- whoever can manage a path's canary is who
            // should be able to see its state; no separate `valid_read`
            // dependency.
            "canary_status" => self.canary_status_efun(&a0),
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
                // OBI-121 S2c §4, CTO review B1: the execution's quota
                // uid is the lowest-tier principal on the guard stack, not
                // just whichever object happens to be running `call_out`
                // right now.
                let quota_uid = self.caller_quota_uid();
                self.check_callout_quota(me, quota_uid)?;
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
                if on {
                    self.check_heartbeat_quota(me)?;
                }
                // OBI-137 S3: `set_heart_beat` records `me`'s owner at
                // subscribe time so it can decrement the right per-owner
                // count again on unsubscribe/destruct without needing the
                // registry (which may already be gone by then).
                let owner = self.registry.get(me).map_or(ROOT, |o| o.owner);
                self.driver
                    .as_mut()
                    .expect("checked above")
                    .scheduler
                    .set_heart_beat(me, owner, on);
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
                let me = self.self_object();
                if id == me {
                    // P0 driver rule (OBI-149), not master policy:
                    // `destruct(self())` is always allowed. `remove()` ->
                    // `destruct(self())` runs with players on the stack
                    // (kills, corpses, `dest`), so the generic P2
                    // `valid_efun` gate -- which cannot see the argument
                    // -- would otherwise force every master to allow
                    // `destruct` unconditionally just so objects can
                    // clean up after themselves (warp's
                    // `account_efuns()` did exactly that). Destructing
                    // *another* object is still P2 below. Always
                    // audited, like `unguarded`.
                    let guard = self.top_guard().clone();
                    let d = self.driver.as_mut().expect("checked above");
                    d.security.push(AuditEntry {
                        caller: me,
                        efun: "destruct",
                        privilege: Privilege::P0,
                        apply: "destruct-self",
                        arg: "".into(),
                        guard,
                        allowed: true,
                        denied_by: None,
                        at_unix_ms: 0, // stamped by `push` itself
                    });
                } else {
                    self.authorize(
                        name,
                        Privilege::P2,
                        Operation::Efun {
                            name: "destruct",
                            class: Privilege::P2,
                        },
                    )?;
                }
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
                let me = self.self_object();
                self.check_reserved_euid(me, &e)?;
                self.authorize(name, Privilege::P3, Operation::SetEuid { euid: &e })?;
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
                if !self.check_disk_quota(&p, text.len() as u64)? {
                    // OBI-137 S1: over-quota is not an error -- `write_file`
                    // reports it the same way any other efun reports "no"
                    // (a `false` return), not a raised `RtError`.
                    return Ok(Value::Bool(false));
                }
                let root = &self.driver.as_ref().expect("checked above").root;
                crate::fileio::write_file(root, &p, text)
                    .map(Value::Bool)
                    .map_err(|e| RtError::new(format!("write_file(\"{p}\") failed: {e}")))
            }
            "save_object" => {
                let p = a0
                    .as_str()
                    .ok_or_else(|| RtError::new("save_object(): expected string path"))?;
                let p = security::normalize_file_path(p).map_err(RtError::new)?;
                self.authorize(
                    name,
                    Privilege::P1,
                    Operation::Write {
                        path: &p,
                        op: "save_object",
                    },
                )?;
                self.save_object(&p).map(Value::Bool)
            }
            "restore_object" => {
                let p = a0
                    .as_str()
                    .ok_or_else(|| RtError::new("restore_object(): expected string path"))?;
                let p = security::normalize_file_path(p).map_err(RtError::new)?;
                self.authorize(
                    name,
                    Privilege::P0,
                    Operation::Read {
                        path: &p,
                        op: "restore_object",
                    },
                )?;
                self.restore_object(&p).map(Value::Bool)
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
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                Ok(Value::Bool(roles.has_grant(uid, kind, target, now)))
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
            "errors" => self.errors_efun(&a0),
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
            at_unix_ms: 0, // stamped by `push` itself
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

    /// D-S3.1 (OBI-37), a driver rule rather than master policy, like
    /// `unguarded`: only `/secure` code (uid root) may `seteuid` onto a
    /// reserved principal (`root`, `mudlib`, `domain:*`, see
    /// [`security::is_reserved_principal`]). Not even an object's own
    /// reserved uid: a mudlib body that took an account's euid must not
    /// be able to take `mudlib` back, which is exactly what logging in as
    /// an account named `mudlib` would do. This closes the path where the
    /// master's "is this an account name" check passes for a player who
    /// registered as `root` or `mudlib`. Audited when refused.
    fn check_reserved_euid(&mut self, me: ObjectId, e: &str) -> R<()> {
        if !security::is_reserved_principal(e) {
            return Ok(());
        }
        if self.registry.get(me).map(|o| o.uid) == Some(security::ROOT) {
            return Ok(());
        }
        let guard = self.top_guard().clone();
        if let Some(d) = self.driver.as_mut() {
            d.security.push(AuditEntry {
                caller: me,
                efun: "seteuid",
                privilege: Privilege::P3,
                apply: "reserved-euid",
                arg: e.into(),
                guard,
                allowed: false,
                denied_by: None,
                at_unix_ms: 0, // stamped by `push` itself
            });
        }
        Err(RtError::new(format!(
            "seteuid(): `{e}` is a reserved driver principal"
        )))
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
    ///
    /// `target` is the operation-specific description recorded in the
    /// audit entry's `arg` (`"<efun> <target>"`, e.g.
    /// `"roles_set_tier frodo->4"`) so a denied or allowed mutation is
    /// legible in `audit_log` without joining back to the correlation id
    /// (CTO review, OBI-123: previously always empty).
    fn roles_mutation_gate(&mut self, efun: &'static str, target: &str) -> R<Sym> {
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
            arg: format!("{efun} {target}").into_boxed_str(),
            guard,
            allowed: actor.is_some(),
            denied_by: None,
            at_unix_ms: 0, // stamped by `push` itself
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

    /// Who a `roles_result(id, ok, detail)` apply is delivered to (OBI-123
    /// bugfix): **not** `self_object()`. Every mutation efun is called
    /// through `/secure/roles.wf`'s facade (the only documented, intended
    /// way to reach these efuns -- design §5, `docs/security.md`), so by
    /// the time the efun itself runs, `self_object()` is `/secure/roles`,
    /// not the connected interactive who actually issued the request and
    /// is waiting on the reply. `/secure/roles` is never bound to a
    /// connection, so recording it as the recipient meant
    /// `World::drain_roles_results` looked up an object with no `conn`,
    /// found no `roles_result` apply on `/secure/roles.wf` either, and
    /// silently delivered the reply nowhere -- the interactive's request
    /// hung forever with no error. `this_player` is the right answer: set
    /// once per top-level execution (`World::input`'s `exec` call) and
    /// unchanged across every nested call in the chain, unlike
    /// `self_object()`. Falls back to `self_object()` only for the
    /// vanishingly unlikely case of no `this_player` at all (every real
    /// caller already failed `roles_mutation_gate`'s actor-rule check
    /// before reaching this point, since that also requires player input).
    fn roles_result_recipient(&self) -> ObjectId {
        let this_player = self.driver.as_ref().and_then(|d| d.this_player);
        debug_assert!(
            this_player.is_some(),
            "roles_result_recipient(): no this_player -- falling back to self_object() means \
             roles_result will be delivered to whatever object's method is currently \
             executing, not a connected interactive; every legitimate caller already failed \
             roles_mutation_gate's actor rule (which requires this_player) before reaching \
             this point, so reaching here with none at all is a driver bug, not a normal \
             runtime condition (CTO review, OBI-123 N3)"
        );
        this_player.unwrap_or_else(|| self.self_object())
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
        let target = Self::want_str(target, "roles_set_tier(): expected string target")?;
        let tier = Self::want_int(tier, "roles_set_tier(): expected int tier")?;
        let reason = Self::want_str(reason, "roles_set_tier(): expected string reason")?;
        let actor = self.roles_mutation_gate("roles_set_tier", &format!("{target} tier={tier}"))?;
        let caller = self.roles_result_recipient();
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
        let domain = Self::want_str(domain, "roles_set_member(): expected string domain")?;
        let target = Self::want_str(target, "roles_set_member(): expected string target")?;
        let role = Self::want_str(role, "roles_set_member(): expected string role")?;
        let reason = Self::want_str(reason, "roles_set_member(): expected string reason")?;
        let actor = self.roles_mutation_gate(
            "roles_set_member",
            &format!("{target} domain={domain} role={role}"),
        )?;
        let caller = self.roles_result_recipient();
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
        let target = Self::want_str(target, "roles_grant(): expected string target")?;
        let kind = Self::want_str(kind, "roles_grant(): expected string kind")?;
        let what = Self::want_str(what, "roles_grant(): expected string what")?;
        let expires_at = match expires_at {
            Value::Null => None,
            Value::Int(n) => Some(*n),
            _ => return Err(RtError::new("roles_grant(): expected int? expires_at")),
        };
        let reason = Self::want_str(reason, "roles_grant(): expected string reason")?;
        let actor = self.roles_mutation_gate("roles_grant", &format!("{target} {kind}:{what}"))?;
        let caller = self.roles_result_recipient();
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
        let target = Self::want_str(target, "roles_revoke_grant(): expected string target")?;
        let kind = Self::want_str(kind, "roles_revoke_grant(): expected string kind")?;
        let what = Self::want_str(what, "roles_revoke_grant(): expected string what")?;
        let reason = Self::want_str(reason, "roles_revoke_grant(): expected string reason")?;
        let actor =
            self.roles_mutation_gate("roles_revoke_grant", &format!("{target} {kind}:{what}"))?;
        let caller = self.roles_result_recipient();
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
        let target = Self::want_str(target, "roles_propose_tier(): expected string target")?;
        let tier = Self::want_int(tier, "roles_propose_tier(): expected int tier")?;
        let reason = Self::want_str(reason, "roles_propose_tier(): expected string reason")?;
        let actor =
            self.roles_mutation_gate("roles_propose_tier", &format!("{target} tier={tier}"))?;
        let caller = self.roles_result_recipient();
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
        let proposal_id = Self::want_int(proposal_id, "roles_approve(): expected int proposal_id")?;
        let actor =
            self.roles_mutation_gate("roles_approve", &format!("proposal={proposal_id}"))?;
        let caller = self.roles_result_recipient();
        let actor_name = self.registry.syms.name(actor).to_string();
        let id = self.roles_next_request(caller);
        let d = self.driver.as_mut().expect("driver");
        let issued = d.roles_ctx.backend.approve(id, &actor_name, proposal_id);
        if !issued {
            self.roles_request_unavailable(id, caller);
        }
        Ok(Value::Int(id as i64))
    }

    /// `errors(program_prefix)` (OBI-169): every grouped runtime-error row
    /// whose program starts with `program_prefix` (`""`/`null`: every
    /// program), further filtered to only the programs the caller can
    /// `valid_read` -- exactly `read_file`'s VFS gate, applied once per
    /// distinct program in the result rather than once per group (a
    /// program can have many error groups; the decision is the same for
    /// all of them and the security decision cache would dedupe the
    /// `valid_read` apply calls anyway, but this skips even the cache
    /// lookups). A denied program's groups are silently omitted, not an
    /// error -- same as a `ls`-style listing a user has partial access
    /// to, not a single all-or-nothing permission check.
    fn errors_efun(&mut self, filter: &Value) -> R<Value> {
        let prefix = match filter {
            Value::Null => None,
            v => match v.as_str() {
                Some(s) if !s.is_empty() => Some(s.to_string()),
                Some(_) => None,
                None => return Err(RtError::new("errors(): expected string")),
            },
        };
        let rows = self
            .driver
            .as_ref()
            .expect("checked above")
            .errors
            .snapshot(prefix.as_deref());
        // M-ERR-1 fix (OBI-287): the redaction tier is the caller's,
        // decided off the guard set (`top_guard().euids()`) the same way
        // `authorize` decides access -- not off `self_object()`'s own
        // euid, which for a command object such as Warp's
        // `/cmds/builder/errors` is the command object's, not the
        // player's. Every euid on the stack must be T5 or higher (the
        // minimum, so one low-tier frame anywhere -- e.g. builder code
        // the player called into -- keeps the redaction), except the
        // driver's lib principals: `root` (never stored in a `GuardSet`
        // at all) and `mudlib` (the default owner of `/cmds/**`, `/std/**`
        // and other lib code, D-S1.1; a reserved principal no account or
        // workroom can take, D-S3.1). Mudlib code is not a caller with a
        // tier of its own -- counting it as tier 0 would redact every
        // T5 player who used a lib command, which is the bug -- and
        // counting it as staff would be wrong too (a player body still
        // running as `mudlib` before its post-login `seteuid` is no
        // one's T5). So `mudlib` is skipped and the tier comes from the
        // other euids on the stack. Only an empty guard set (an
        // all-root stack) un-redacts. A stack whose only euids are
        // `mudlib` has no caller with a tier, so it stays redacted
        // (fail closed).
        let guard = self.top_guard();
        let min_caller_tier = if guard.is_empty() {
            5
        } else {
            guard
                .euids()
                .map(|euid| self.registry.syms.name(euid).to_string())
                .filter(|name| name != "mudlib")
                .map(|name| self.euid_tier(&name))
                .min()
                .unwrap_or(0)
        };
        let mut decided: HashMap<String, bool> = HashMap::new();
        let mut out = Vec::new();
        for row in rows {
            let allowed = match decided.get(&row.program) {
                Some(b) => *b,
                None => {
                    let ok = self
                        .authorize(
                            "errors",
                            Privilege::P1,
                            Operation::Read {
                                path: &row.program,
                                op: "errors",
                            },
                        )
                        .is_ok();
                    decided.insert(row.program.clone(), ok);
                    ok
                }
            };
            if !allowed {
                continue;
            }
            // M-ERR-1 (CTO review on PR #72, must-fix 2): a `/secure/**`
            // origin's message is only ever shown to T5 (`root`), even
            // though the program-level `valid_read` gate above may well
            // already have let a lower tier through (a master could, in
            // principle, grant `/secure/foo` read access to someone
            // below T5 -- this redaction is a driver-enforced floor, not
            // conditioned on the master's own policy).
            let message = if row.redacted && min_caller_tier < 5 {
                "<redacted>".to_string()
            } else {
                row.message.clone()
            };
            let mut m = heap::MapData::default();
            m.insert(Value::str("program"), Value::str(&row.program));
            m.insert(Value::str("function"), Value::str(&row.function));
            m.insert(
                Value::str("line"),
                if row.line == 0 {
                    Value::Null
                } else {
                    Value::Int(row.line as i64)
                },
            );
            m.insert(Value::str("message"), Value::str(&message));
            m.insert(Value::str("redacted"), Value::Bool(row.redacted));
            m.insert(Value::str("count"), Value::Int(row.count as i64));
            m.insert(
                Value::str("first_seen_unix_ms"),
                Value::Int(row.first_seen_unix_ms as i64),
            );
            m.insert(
                Value::str("last_seen_unix_ms"),
                Value::Int(row.last_seen_unix_ms as i64),
            );
            m.insert(
                Value::str("sample_trace"),
                Value::array(row.sample_trace.iter().map(|s| Value::str(s)).collect()),
            );
            out.push(Value::map(m));
        }
        Ok(Value::array(out))
    }

    /// `canary_update(path, pct, window_ticks, max_new_errors)` (P2-B7,
    /// OBI-182, spec §7.4): compile `path` exactly like `compile_object`
    /// (install is lazy either way, so nothing migrates synchronously
    /// here), then start a canary that routes `pct`% of future accesses
    /// (by object id hash) to the new version instead of all of them.
    /// `window_ticks` is how long (in world ticks, `World::tick`'s own
    /// counter -- not wall-clock time, same deviation as
    /// `TickShareWindow`) the canary runs before auto-promoting if it
    /// stays within budget; `max_new_errors` is how many *new*
    /// `errors`-inbox occurrences (P2-B4) for `path` it may accrue before
    /// `World::tick` rolls it back immediately instead of waiting out the
    /// window. Returns `null` on success (a canary is now in flight) or a
    /// diagnostics/error string, mirroring `compile_object`'s
    /// `Optional<String>`.
    fn canary_update_efun(
        &mut self,
        path: &Value,
        pct: &Value,
        window_ticks: &Value,
        max_new_errors: &Value,
    ) -> R<Value> {
        let p = Self::want_str(path, "canary_update(): expected string path")?;
        let path = mudlib::normalize_path(&p).map_err(RtError::new)?;
        let pct = Self::want_int(pct, "canary_update(): expected int pct")?;
        let window_ticks =
            Self::want_int(window_ticks, "canary_update(): expected int window_ticks")?;
        let max_new_errors = Self::want_int(
            max_new_errors,
            "canary_update(): expected int max_new_errors",
        )?;
        if !(1..=100).contains(&pct) {
            return Err(RtError::new("canary_update(): pct must be 1..=100"));
        }
        if window_ticks < 1 {
            return Err(RtError::new("canary_update(): window_ticks must be >= 1"));
        }
        if max_new_errors < 0 {
            return Err(RtError::new("canary_update(): max_new_errors must be >= 0"));
        }
        self.authorize(
            "canary_update",
            Privilege::P1,
            Operation::Upgrade { path: &path },
        )?;
        if self.registry.canaries.contains_key(&path) {
            return Ok(Value::str(&format!(
                "canary_update(): a canary is already in flight for {path}"
            )));
        }
        if self.registry.program(&path).is_none() {
            return Ok(Value::str(&format!(
                "canary_update(): no program registered for {path}"
            )));
        }
        // `self.recompile` both compiles (all-or-nothing, same as
        // `compile_object`) and installs: install is lazy-only (OBI-89),
        // so this never touches a single existing instance -- the
        // `CanaryState` below is what then governs who, if anyone, moves
        // to it before it is promoted or rolled back.
        let stable = self.registry.program(&path).expect("checked above");
        match self.recompile(&path) {
            Err(e) => Ok(Value::str(&e)),
            Ok(_warnings) => {
                let candidate = self
                    .registry
                    .program(&path)
                    .expect("recompile just installed it");
                let driver = self.driver.as_ref().expect("checked above");
                let started_tick = driver.scheduler.tick();
                let errors_at_start = driver.errors.count_for_program(&path);
                self.registry.canaries.insert(
                    path.clone(),
                    CanaryState {
                        stable,
                        candidate,
                        pct: pct as u8,
                        started_tick,
                        window_ticks: window_ticks as u64,
                        errors_at_start,
                        max_new_errors: max_new_errors as u64,
                    },
                );
                metrics::counter!("loom_canary_started_total", "program" => path.clone())
                    .increment(1);
                Ok(Value::Null)
            }
        }
    }

    /// `canary_status(path)`: `null` if `path` has no canary in flight,
    /// else `{"program": string, "pct": int, "ticks_left": int,
    /// "new_errors": int, "max_new_errors": int}` -- `ticks_left` is
    /// already saturated at 0 (never negative) and `new_errors` is the
    /// live `errors`-inbox delta `World::tick` itself compares against
    /// `max_new_errors`, so a builder command can show progress without
    /// duplicating that arithmetic.
    fn canary_status_efun(&mut self, path: &Value) -> R<Value> {
        let p = Self::want_str(path, "canary_status(): expected string path")?;
        let path = mudlib::normalize_path(&p).map_err(RtError::new)?;
        self.authorize(
            "canary_status",
            Privilege::P1,
            Operation::Upgrade { path: &path },
        )?;
        let Some(canary) = self.registry.canaries.get(&path) else {
            return Ok(Value::Null);
        };
        let driver = self.driver.as_ref().expect("checked above");
        let now_tick = driver.scheduler.tick();
        let new_errors = driver
            .errors
            .count_for_program(&path)
            .saturating_sub(canary.errors_at_start);
        let ticks_left = (canary.started_tick + canary.window_ticks).saturating_sub(now_tick);
        let mut m = heap::MapData::default();
        m.insert(Value::str("program"), Value::str(&path));
        m.insert(Value::str("pct"), Value::Int(canary.pct as i64));
        m.insert(Value::str("ticks_left"), Value::Int(ticks_left as i64));
        m.insert(Value::str("new_errors"), Value::Int(new_errors as i64));
        m.insert(
            Value::str("max_new_errors"),
            Value::Int(canary.max_new_errors as i64),
        );
        Ok(Value::map(m))
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
            e.trace_programs.push(target.path.to_string());
            e.trace_lines.push(0);
            return Err(e);
        }
        self.push_self(on);
        self.base_code.push(target.clone());
        let limits = self.limits;
        let mut ticks = self.ticks_left;
        let result = {
            let mut interp = Interpreter::new(&target.module, self, &limits, &mut ticks)
                .with_base_program(target.path.clone());
            interp.call(&func_name, args)
        };
        self.ticks_left = ticks;
        self.base_code.pop();
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
    pub fn instantiate(&mut self, prog: Rc<CompiledProgram>, apply_r1: bool) -> R<ObjectId> {
        let prog_uid = self.uid_for(&prog.path);
        let guard = self.top_guard().clone();
        // R1 (OBI-121 S2c spec §7, CTO review B1): a load/clone whose
        // current guard set does not already contain the program's own
        // declared uid (`prog_uid`, from `creator_file(path)`) gets
        // `owner`/starting `euid` set to the caller's own quota uid
        // instead -- e.g. a T1-owned workroom object cloning a
        // `/daemons`-style program cannot launder a clone into a
        // higher-privileged owner it does not itself have; the clone is
        // charged (and confined) to the apprentice, not to whatever
        // `/daemons` would otherwise own. `uid` itself (`creator_file`)
        // never changes -- R1 only redirects `owner`/`euid` (spec: "Its
        // `uid` stays `creator_file(p)`"; "Clone uid = caller" is
        // explicitly rejected).
        //
        // Applies to **every** program uid, not just the always-unlimited
        // ones (root/mudlib/domain:*) -- narrowing this to only those
        // uids was a quota-evasion hole (CTO review B1): an apprentice at
        // `max_objects` could loop `clone_object("/builders/senior/x")`
        // and have every clone billed to `senior` instead. Skipped
        // entirely when the guard is empty (an all-root call chain, e.g.
        // boot loading `/secure/master`).
        //
        // **`apply_r1` is `false` for `load_object`** (flagged deviation,
        // CTO re-review requested): `load_object` returns the *same*
        // object for `path` to every future caller (see `RegistryHost::
        // load_object`'s cache check) -- it never multiplies billed
        // objects, so it is not the clone-spam quota evasion R1 targets,
        // and applying R1 there would let whichever caller happens to
        // `load_object` a path *first* silently steal that path's
        // owner/euid assignment forever (a regression against the
        // pre-existing `security.rs` contract that a daemon object's own
        // uid/euid do not depend on who first resolved it -- see
        // `a_lower_privileged_caller_denies_a_higher_privileged_callee`,
        // which loads `/builders/arch/daemon` from `appr`'s stack and
        // still requires it owned/euid'd `arch`). `clone_object` always
        // passes `true`.
        let mut owner = if apply_r1 && !guard.is_empty() && !guard.has_euid(prog_uid) {
            self.caller_quota_uid()
        } else {
            prog_uid
        };
        // D-S2.4 amendment (OBI-149, refined OBI-153): the R1 test
        // above skips the redirect whenever the guard already contains
        // `prog_uid` -- which every `/cmds/**` command frame does for
        // any always-unlimited program (`root`/`mudlib`/`domain:*`),
        // since command objects are themselves mudlib-owned and so push
        // `mudlib` onto the guard before the apprentice's own code ever
        // runs. Without this, an apprentice cloning `/std/item` (or any
        // other mudlib/root/domain-owned program) from inside a command
        // handler gets the clone billed to `mudlib`, which is never
        // billed at all -- `max_objects`/`max_heartbeats`/
        // `max_callouts_obj` become unenforceable simply by routing the
        // same call through a command instead of calling the builder's
        // own object directly. Bill it to the lowest-tier *billable*
        // staff principal on the stack instead -- but unlike plain
        // `caller_quota_uid`, only ranking principals with `tier >= 1`
        // (OBI-153 fix: plain `caller_quota_uid` picks the lowest tier in
        // the *whole* guard, which can be a tier-0 player principal
        // sitting next to the apprentice on the stack -- e.g. the
        // apprentice's own alt walks into the apprentice's room and the
        // room's `create()` clones something; the tier-0 alt would then
        // outrank the T1 apprentice as "lowest tier" and the clone would
        // stay billed to `mudlib`, letting the apprentice repeat the
        // clone through the alt to evade `max_objects`/`max_heartbeats`/
        // `max_callouts_obj` indefinitely). If no guard principal is
        // tier >= 1 (only unlimited uids and/or bare tier-0 players are
        // present), this amendment does not fire and `owner` keeps R1's
        // answer from above (today's rule) -- a bare tier-0 player has
        // no policy row and must stay unaffected (spec: "Players (tier
        // 0, no policy row) are unaffected"). `euid` itself is untouched
        // -- R1 above already decided it and this amendment only ever
        // narrows *billing*, never confinement.
        if apply_r1
            && crate::quota::is_unlimited_uid(self.registry.syms.name(prog_uid))
            && let Some(candidate) = self.lowest_tier_guard_principal(1)
        {
            owner = candidate;
        }
        self.check_max_objects(owner)?;
        let mut obj = BcObject::new(prog.clone());
        obj.uid = prog_uid;
        obj.owner = owner;
        obj.euid = owner;
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
        // P2-B7 (OBI-182): a plain recompile of a path that has an active
        // canary supersedes it -- `new_set`'s value just became the new
        // `programs[path]` directly (not gated by the old canary's
        // fraction any more), so the stale `CanaryState` (whose
        // `candidate` is no longer what's installed) must not linger to
        // confuse `ensure_current`'s routing or `World::tick`'s window
        // check.
        for path in new_set.keys() {
            self.registry.canaries.remove(path);
        }
        // OBI-121 S2c (CTO review B4): a recompiled path's cached
        // `program_flags` result is stale (the master may return
        // something different for the new code, or `program_flags` itself
        // may only just have been added). Recompute it **now**, as part of
        // install, not lazily on the next `load_object`/`clone_object` --
        // an already-live clone of a workroom item that just got flagged
        // `CONFINED` must be confined starting with this install, not
        // starting with the next time anyone clones or loads that same
        // path (a confinement bypass window otherwise: `move_to`'s
        // `check_confinement` reads the cache by path, shared by every
        // existing instance, so recomputing it here closes the gap for
        // all of them at once).
        let paths: Vec<String> = new_set.keys().cloned().collect();
        // If `/secure/master` itself is being recompiled, every cached
        // `program_flags` entry -- not only the recompiled paths -- came
        // from calling the *old* master's apply, so drop the whole cache
        // (CTO review nit) rather than just the paths in `new_set`.
        let master_recompiled = self
            .driver
            .as_ref()
            .and_then(|d| d.master)
            .and_then(|m| self.registry.get(m))
            .is_some_and(|o| new_set.contains_key(o.program.path.as_ref()));
        if master_recompiled {
            self.registry.clear_program_flags_cache();
        } else {
            for path in &paths {
                self.registry.set_program_flags(path, None);
            }
        }
        for path in &paths {
            self.ensure_program_flags(path);
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

    /// spec §7.2 D-B3.14 (P2-B3.1): recompile the changed set, expanded
    /// with the reverse-inherit graph, as one dependency-ordered,
    /// all-or-nothing batch -- the multi-root generalisation of
    /// [`Self::recompile`] (see [`Compiler::recompile_set`] for the actual
    /// compile-stage logic; this is the world-thread install stage, same
    /// split as `Self::recompile`/`Compiler::recompile`).
    ///
    /// One compile failure anywhere in the batch means nothing is
    /// installed at all: every old version keeps running, and every
    /// diagnostic collected is returned in [`RecompileReport::failures`].
    ///
    /// If `/secure/master` or `/secure/roles` is in the recompiled set,
    /// `self.install` (called below) already recomputes `program_flags`
    /// for every recompiled path against the *new* master, and -- because
    /// the master itself is in the batch -- drops the *whole*
    /// `program_flags` cache rather than just the recompiled paths (see
    /// `install`'s own doc comment). This additionally bumps the
    /// security-decision epoch (D-S1.8), exactly like [`Self::recompile`]'s
    /// `touches_secure` handling, so a cached privilege decision made
    /// against the old master/roles code is never reused after this call.
    pub fn recompile_set(&mut self, changed: &[String], deleted: &[String]) -> RecompileReport {
        let set = {
            let driver = self
                .driver
                .as_mut()
                .expect("recompile_set needs a driver context");
            driver
                .compiler
                .recompile_set(self.registry, changed, deleted)
        };
        self.finish_set_outcome(set)
    }

    /// Kick off [`Self::recompile_set`]'s compile stage on a background OS
    /// thread (D-B3.14, OBI-207 P2-B3.1b) -- the multi-root generalisation
    /// of [`RegistryHost`]'s existing single-root `begin_recompile`
    /// (`Compiler::begin_recompile`, driven by `World`). Returns
    /// immediately; nothing about `registry`/`self.session` is touched
    /// until [`Self::finish_recompile_set`] applies the result.
    pub fn begin_recompile_set(
        &self,
        root: &Path,
        changed: &[String],
        deleted: &[String],
    ) -> compile_worker::RecompileSetJob {
        let driver = self
            .driver
            .as_ref()
            .expect("begin_recompile_set needs a driver context");
        driver
            .compiler
            .begin_recompile_set(root, self.registry, changed, deleted)
    }

    /// Apply a background [`compile_worker::RecompileSetJob`]'s outcome
    /// (D-B3.14, OBI-207 P2-B3.1b): decode + re-verify each program the
    /// background thread produced, refuse the whole batch if the registry
    /// drifted while it was running (same staleness contract as
    /// [`Self::finish_recompile`], generalised to a batch -- see
    /// [`Compiler::finish_recompile_set`]), then install -- registry
    /// mutation + per-object migration, master/cache flush, security-epoch
    /// bump -- exactly like [`Self::recompile_set`], all still on the
    /// world thread, all still all-or-nothing.
    pub fn finish_recompile_set(
        &mut self,
        changed: &[String],
        deleted: &[String],
        begin_snapshot: &compile_worker::ProgramSnapshot,
        outcome: compile_worker::CompileSetOutcome,
    ) -> RecompileReport {
        let set = {
            let driver = self
                .driver
                .as_mut()
                .expect("finish_recompile_set needs a driver context");
            driver.compiler.finish_recompile_set(
                self.registry,
                changed,
                deleted,
                begin_snapshot,
                outcome,
            )
        };
        self.finish_set_outcome(set)
    }

    /// Shared tail of [`Self::recompile_set`]/[`Self::finish_recompile_set`]
    /// (D-B3.14): given a [`RecompileSetOutcome`] from either the
    /// synchronous or background compile stage, either report its
    /// failures (nothing installed) or install `new_set` as a whole --
    /// master/`program_flags`-cache rule, security-epoch bump,
    /// `loom_mudlib_sync_total` -- and build the public
    /// [`RecompileReport`].
    fn finish_set_outcome(&mut self, set: RecompileSetOutcome) -> RecompileReport {
        if !set.failures.is_empty() {
            self.registry.sync_metrics.record(false);
            return RecompileReport {
                recompiled: Vec::new(),
                upgraded_instances: 0,
                skipped_unloaded: set.skipped_unloaded,
                deleted_loaded: set.deleted_loaded,
                failures: set.failures,
            };
        }
        // Same broader-than-D-B3.14's-letter rule `Self::recompile` already
        // uses for its single-root `touches_secure`: anything under
        // `/secure/` bumps the epoch, not only `/secure/master`/
        // `/secure/roles` -- a strict superset is never less safe.
        let touches_secure = set.new_set.keys().any(|k| k.starts_with("/secure/"));
        let target_paths: std::collections::HashSet<&str> =
            set.recompiled.iter().map(String::as_str).collect();
        let upgraded_instances = self.registry.live_instance_count(&target_paths);
        let _ = self.install(set.new_set);
        if touches_secure && let Some(d) = self.driver.as_mut() {
            // D-S1.8: a master/roles recompile invalidates every cached
            // privilege decision.
            d.security.bump_epoch();
        }
        self.registry.sync_metrics.record(true);
        RecompileReport {
            recompiled: set.recompiled,
            upgraded_instances,
            skipped_unloaded: set.skipped_unloaded,
            deleted_loaded: set.deleted_loaded,
            failures: Vec::new(),
        }
    }

    /// `<path>` normalised to the on-disk save-file name `save_object`/
    /// `restore_object` use under the save root: `.o` appended unless
    /// already present (classic LPMud convention: `save_object("bob")`
    /// and `save_object("bob.o")` name the same file).
    fn save_file_name(path: &str) -> String {
        if path.ends_with(".o") {
            path.to_string()
        } else {
            format!("{path}.o")
        }
    }

    /// `save_object(path)` (spec §8.1, OBI-171): serialise every
    /// `persistent` var of `self()`, across its whole inherit chain, keyed
    /// by *(declaring program, name)* -- the same identity hot-reload
    /// migration uses, §7.2/§7.3 -- into a JSON document (`crate::bcvm::
    /// persist::encode_value`, spec r5 §7.3's portable form) alongside
    /// the declaring program's path/version/schema hash, and write it
    /// atomically (write + rename, `crate::fileio::write_file_atomic`)
    /// under the save root (never the mudlib VFS -- see
    /// `World::save_root`'s docs) at `<path>.o`. `Ok(false)`: the write
    /// failed (oversized, a filesystem error, over `disk_quota_mb`) -- this
    /// never mutates the object itself, so a failed save can't corrupt live
    /// state.
    ///
    /// **OBI-348 (spec §8.1): the durable half is deferred.** Everything up
    /// to the hand-off is unchanged and stays on the world thread -- the
    /// §7.3 render, the size cap, the master's save-path authorisation, the
    /// `disk_quota_mb` projection. What moves to
    /// [`crate::save_queue`]'s worker is the content `fsync`, the `rename`
    /// and the parent-directory `fsync`, i.e. the two blocking calls that
    /// made a mass teardown (`World::disconnect` -> `autosave()` ->
    /// `save_character()`) the world thread's worst iteration. So a `true`
    /// here now means "**accepted, in order**": the bytes cannot be lost, but
    /// they are durable at the next flush ([`crate::world::World::
    /// flush_pending_saves`]`, which `begin_snapshot` and `World`'s own drop
    /// both call) rather than at this return. Rejections (`Ok(false)`, an
    /// `Err`) still happen exactly where they used to. `SaveDurability::Sync`
    /// restores the old contract for an embedder or a test that wants it.
    fn save_object(&mut self, raw_path: &str) -> R<bool> {
        let id = self.self_object();
        let Some(obj) = self.registry.get(id) else {
            return Err(RtError::new("save_object(): object was destructed"));
        };
        let program = obj.program.clone();
        let mut vars = serde_json::Map::new();
        for ancestor in &program.chain() {
            for spec in &ancestor.var_specs {
                if !spec.persistent {
                    continue;
                }
                let key = (ancestor.path.clone(), spec.name.clone());
                let v = self
                    .registry
                    .get(id)
                    .and_then(|o| o.vars.get(&key))
                    .cloned()
                    .unwrap_or(Value::Null);
                vars.insert(
                    format!("{}\u{0}{}", ancestor.path, spec.name),
                    crate::bcvm::persist::encode_value(&v),
                );
            }
        }
        let doc = serde_json::json!({
            "program": &*program.path,
            "version": program.version,
            "schema_hash": program.schema_hash,
            "vars": serde_json::Value::Object(vars),
        });
        let text =
            serde_json::to_string(&doc).map_err(|e| RtError::new(format!("save_object(): {e}")))?;
        let save_file = Self::save_file_name(raw_path);
        let Some(old_bytes) = self.check_save_disk_quota(&save_file, text.len() as u64)? else {
            // Same shape as `write_file`'s own `disk_quota_mb` breach
            // (OBI-137 S1): over quota is not an error, so `upgrade()`'s
            // caller-visible contract (never silently mutating on a
            // rejected save) still holds -- this runs before anything is
            // queued, not after.
            return Ok(false);
        };
        // The billing identity the deferred charge has to land on, captured
        // now (the object could be destructed by the time the worker reports
        // back, and `disk_quota_mb` is keyed on the uid, not the object).
        let uid = principal_of(self.registry, id).uid;
        let uid_name = self.registry.syms.name(uid).to_string();
        let program_path = program.path.to_string();
        let driver = self.driver.as_mut().expect("save_object: driver context");
        let task = crate::save_queue::SaveTask {
            seq: 0, // `SaveQueue::enqueue` assigns the ordering key
            save_root: driver.save_root.clone(),
            path: save_file,
            content: text,
            uid: uid_name,
            program: program_path,
            old_bytes,
        };
        match driver.save_queue.enqueue(task) {
            // Accepted by the worker: durable at the next flush, not yet.
            crate::save_queue::Enqueued::Queued => Ok(true),
            // This thread did the durable write itself, because there was no
            // other writer to hand it to (`Sync` mode, no worker, a worker
            // confirmed gone) or because the save alone exceeds the queue's
            // byte budget. `true` means exactly what it meant before OBI-348,
            // so the quota charge is applied here and now rather than deferred
            // (CTO review: a full queue *waits*, it does not start a second
            // writer -- see `save_queue`'s single-writer invariant).
            crate::save_queue::Enqueued::Inline(outcome) => match outcome.committed_bytes {
                Some(committed) => {
                    driver
                        .disk_usage
                        .note_save_write(&outcome.uid, outcome.old_bytes, committed);
                    Ok(true)
                }
                None => Err(RtError::new(format!(
                    "save_object(\"{raw_path}\") failed: {}",
                    outcome
                        .error
                        .unwrap_or_else(|| "durable write failed".to_string())
                ))),
            },
        }
    }

    /// `restore_object(path)` (spec §8.1/§7.3, OBI-171): the converse of
    /// [`Self::save_object`]. Reads `<path>.o` from the save root
    /// (`Ok(false)`, not an error, if it does not exist or fails to
    /// parse -- a missing/corrupt save is not a crash).
    ///
    /// **OBI-348 read-your-writes:** because `save_object` no longer waits
    /// for its own durable write, a `restore_object` of a path with a save
    /// still queued would otherwise read the *previous* file. So this waits
    /// for that one path first ([`crate::save_queue::SaveQueue::flush_path`])
    /// -- which costs a block only when a save for exactly this file is in
    /// flight, and never a filesystem walk otherwise.
    ///
    /// For every
    /// `persistent` var in `self()`'s *current* inherit chain, the saved
    /// value (decoded to a type-erased portable form,
    /// `crate::bcvm::persist::decode_value`) either carries straight over
    /// if it still conforms to the var's declared type
    /// (`crate::bcvm::schema_convert::hydrate`), or is hashed into
    /// `upgrade(from_version, old)`'s `old` map in portable form --
    /// exactly the §7.2/§7.3 hot-reload migration path, run here against
    /// the save file's recorded version instead of a recompiled program
    /// (spec: "restoring an old save into a new program runs the same
    /// migration path"). A var the save has nothing for keeps whatever
    /// it already holds (e.g. `create()`'s own default), unchanged.
    ///
    /// All-or-nothing for this object (spec §7.2 step 6.4's rollback
    /// rule, mirrored here): if `upgrade()` is defined and raises, every
    /// var this call touched reverts to what it held before the call and
    /// `Ok(false)` is returned. There is no `runtime_error` apply wired up
    /// yet to report this to (OBI-34 tracks that), so the detail goes to
    /// stderr in the meantime, same as `compile_object`'s per-object
    /// upgrade-warning reporting.
    fn restore_object(&mut self, raw_path: &str) -> R<bool> {
        let id = self.self_object();
        let Some(obj) = self.registry.get(id) else {
            return Err(RtError::new("restore_object(): object was destructed"));
        };
        let program = obj.program.clone();
        let save_file = Self::save_file_name(raw_path);
        let save_root = self
            .driver
            .as_ref()
            .expect("checked above")
            .save_root
            .clone();
        // OBI-348: land any queued save for *this* path before reading.
        {
            let driver = self.driver.as_mut().expect("checked above");
            if driver.save_queue.has_pending_for_path(&save_file) {
                let outcomes = driver.save_queue.flush_path(&save_file);
                crate::save_queue::apply_outcomes(
                    &outcomes,
                    driver.disk_usage,
                    driver.errors,
                    crate::world::unix_now_ms(),
                );
            }
        }
        let text = match crate::fileio::read_file(&save_root, &save_file) {
            Ok(Some(t)) => t,
            Ok(None) => return Ok(false),
            Err(e) => {
                eprintln!("restore_object(\"{raw_path}\") failed: {e}");
                return Ok(false);
            }
        };
        let doc: serde_json::Value = match serde_json::from_str(&text) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("restore_object(\"{raw_path}\"): corrupt save: {e}");
                return Ok(false);
            }
        };
        let from_version = doc.get("version").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let saved_vars = doc.get("vars").and_then(|v| v.as_object());
        let old_vars_snapshot = obj.vars.clone();
        let mut new_vars = old_vars_snapshot.clone();
        let mut old_map = heap::MapData::default();
        for ancestor in &program.chain() {
            for spec in &ancestor.var_specs {
                if !spec.persistent {
                    continue;
                }
                let saved_key = format!("{}\u{0}{}", ancestor.path, spec.name);
                let Some(saved_json) = saved_vars.and_then(|m| m.get(&saved_key)) else {
                    continue;
                };
                let portable = crate::bcvm::persist::decode_value(saved_json);
                match crate::bcvm::schema_convert::hydrate(&portable, &spec.ty) {
                    crate::bcvm::schema_convert::Migrated::Lossless(v) => {
                        new_vars.insert((ancestor.path.clone(), spec.name.clone()), v);
                    }
                    crate::bcvm::schema_convert::Migrated::Lossy { portable } => {
                        old_map.insert(Value::str(&spec.name), portable);
                    }
                }
            }
        }
        let outcome: R<()> = (|| {
            if let Some(o) = self.registry.get_mut(id) {
                o.vars = new_vars.clone();
                o.recompute_mem_bytes();
            }
            self.call_cache.clear();
            if !old_map.entries.is_empty()
                && let Some((target, idx)) = program.resolve("upgrade")
            {
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
            Ok(()) => Ok(true),
            Err(e) => {
                if let Some(o) = self.registry.get_mut(id) {
                    o.vars = old_vars_snapshot;
                    o.recompute_mem_bytes();
                }
                self.call_cache.clear();
                eprintln!(
                    "restore_object(\"{raw_path}\"): upgrade() failed: {}",
                    e.report()
                );
                Ok(false)
            }
        }
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

    /// See [`Host::current_program`]: the innermost `call_in`'s base
    /// program, else (a host driven without `call_in`, e.g. unit tests)
    /// the running object's own program.
    fn current_program(&self) -> R<Rc<dyn ProgramCode>> {
        if let Some(p) = self.base_code.last() {
            return Ok(p.clone() as Rc<dyn ProgramCode>);
        }
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

    /// The memory quota this write must respect (OBI-121 S2c §3/§4:
    /// `max_mem_exec_mb`, "applied as the per-object vars limit by the
    /// owner's tier"), cached on the object (`BcObject::mem_quota_cache`,
    /// V7 bench gate follow-up: re-resolving the owner's tier/policy row
    /// through the roles snapshot on every single write was a measured
    /// regression against the pre-quota baseline on a tight global-array
    /// index-write loop) and keyed on `World::roles_generation`, not the
    /// snapshot `Arc`'s own address (N1: an `Arc` can be reused after a
    /// drop, so a pointer-keyed cache has an ABA problem a monotonic
    /// counter does not).
    fn store_global(&mut self, owner: &str, name: &str, v: Value) -> R<()> {
        let self_id = self.self_object();
        let quota = match self.registry.get(self_id) {
            None => self.limits.mem_quota_bytes,
            Some(o) => {
                let generation = self.driver.as_ref().map(|d| d.roles_generation);
                match (generation, o.mem_quota_cache.get()) {
                    (Some(current), Some((cached_gen, cached_bytes))) if current == cached_gen => {
                        cached_bytes
                    }
                    (Some(current), _) => {
                        let bytes = self.mem_quota_bytes_for(o.owner);
                        o.mem_quota_cache.set(Some((current, bytes)));
                        bytes
                    }
                    (None, _) => self.limits.mem_quota_bytes,
                }
            }
        };
        let owner_uid = self.registry.get(self_id).map(|o| o.owner);
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
            let obj_name = o.name.clone();
            self.record_mem_quota_breach(owner_uid);
            return Err(self.deny_quota(
                crate::quota::MAX_MEM_EXEC_MB,
                format!(
                    "{obj_name}: memory quota exceeded writing `{name}` ({new_total} bytes of vars would be \
                 in use, quota is {quota} bytes)"
                ),
            ));
        }
        let old = o.vars.get(&key).cloned();
        o.mem_bytes = new_total;
        o.vars.insert(key.clone(), v);
        self.registry.journal_var_write(self_id, key, old);
        Ok(())
    }

    /// See `bcvm::vm::Host::take_global` (OBI-108 CTO review of PR #8): a
    /// real move out of `o.vars`, not a clone — `LoadGlobal`'s `.cloned()`
    /// (see `load_global` above) is exactly the extra `Rc` owner that made
    /// `IndexSet` see refcount 2 and clone the whole container on every
    /// single element write, an O(n²) fill of a global array/map by
    /// index. `mem_bytes` is deliberately left untouched (CTO review of
    /// PR #47, OBI-108: a prior version subtracted this container's bytes
    /// here, which made the very next `reserve_global_growth` check run
    /// against a total that no longer counted the container being grown —
    /// a map could then grow past quota for free). It stays as the
    /// pre-take total until the matching `commit_global`/`restore_global`
    /// corrects it in one step, using the `old_bytes` its caller captured
    /// right after this call returns. The pre-take value is still
    /// journaled once, right here, if an atomic scope is open — the one
    /// place that still holds it whole.
    fn take_global(&mut self, owner: &str, name: &str) -> R<Value> {
        let self_id = self.self_object();
        let key: (Rc<str>, Rc<str>) = (Rc::from(owner), Rc::from(name));
        let Some(o) = self.registry.get_mut(self_id) else {
            return Err(RtError::new("self was destructed"));
        };
        let old = o
            .vars
            .insert(key.clone(), Value::Null)
            .unwrap_or(Value::Null);
        self.registry
            .journal_var_write(self_id, key, Some(old.clone()));
        Ok(old)
    }

    /// See `bcvm::vm::Host::commit_global`. `old_bytes` is `heap::cost`
    /// of the value as `take_global` handed it out; since `take_global`
    /// left `mem_bytes` counting it, this is the one place that subtracts
    /// it back out before adding the new (possibly larger -- an array
    /// element replace or a map key insert/replace can each grow the
    /// container under deep accounting, CTO re-review of PR #47 after
    /// OBI-80 landed) size -- a single atomic correction rather than the
    /// subtract-in-`take`/add-in-`commit` split that let
    /// `reserve_global_growth` see a stale total (CTO review of PR #47).
    /// No quota re-check here: any growth was already reserved, before the
    /// mutation, by `reserve_global_growth` (see `bcvm::vm::Interpreter::
    /// index_growth`) -- this is just the actual write-back.
    fn commit_global(&mut self, owner: &str, name: &str, old_bytes: u64, v: Value) -> R<()> {
        let self_id = self.self_object();
        let key: (Rc<str>, Rc<str>) = (Rc::from(owner), Rc::from(name));
        let new_bytes = heap::cost(&v);
        let Some(o) = self.registry.get_mut(self_id) else {
            return Err(RtError::new("self was destructed"));
        };
        o.mem_bytes = o.mem_bytes.saturating_sub(old_bytes) + new_bytes;
        o.vars.insert(key, v);
        Ok(())
    }

    /// See `bcvm::vm::Host::restore_global`. No quota check (it fit
    /// before this take, it fits now) and no new journal entry
    /// (`take_global` already recorded the one undo point for this
    /// write). `v` is exactly the value `take_global` handed out, so
    /// `heap::cost(&v) == old_bytes` and this is always a net-zero
    /// correction to `mem_bytes` — same formula as `commit_global`, for
    /// symmetry and so a future caller that (mistakenly) restores a
    /// different value still gets a consistent total rather than a
    /// silently stale one.
    fn restore_global(&mut self, owner: &str, name: &str, old_bytes: u64, v: Value) -> R<()> {
        let self_id = self.self_object();
        let key: (Rc<str>, Rc<str>) = (Rc::from(owner), Rc::from(name));
        let new_bytes = heap::cost(&v);
        let Some(o) = self.registry.get_mut(self_id) else {
            return Err(RtError::new("self was destructed"));
        };
        o.mem_bytes = o.mem_bytes.saturating_sub(old_bytes) + new_bytes;
        o.vars.insert(key, v);
        Ok(())
    }

    /// See `bcvm::vm::Host::reserve_global_growth`. Checked against
    /// `o.mem_bytes` while it is still the *pre-take* total (CTO review of
    /// PR #47, OBI-108: `take_global` no longer subtracts this container's
    /// own bytes before this check runs, which is what let a write grow
    /// past quota for free — the check was comparing against a total that
    /// had already forgotten the very container being grown). `added_bytes`
    /// is the exact `heap::cost` delta the caller's `index_growth` computed
    /// for this specific element write (array replace, map replace, or a
    /// brand new map key), not a fixed per-kind estimate — deep accounting
    /// (OBI-80) makes every one of those able to grow the container, not
    /// just a new map key the way OBI-78's shallow accounting did.
    fn reserve_global_growth(&mut self, _owner: &str, name: &str, added_bytes: u64) -> R<()> {
        let self_id = self.self_object();
        let quota = self.limits.mem_quota_bytes;
        let Some(o) = self.registry.get(self_id) else {
            return Err(RtError::new("self was destructed"));
        };
        let new_total = o.mem_bytes + added_bytes;
        if new_total > quota {
            return Err(RtError::new(format!(
                "{}: memory quota exceeded writing `{name}` ({new_total} bytes of vars would be \
                 in use, quota is {quota} bytes)",
                o.name
            )));
        }
        Ok(())
    }

    fn record_cow_copy(&mut self, program: &str) {
        self.registry.cow_metrics.record(program);
    }

    /// Spec Phase 2 B5 (OBI-170): called on every Weft function call,
    /// whether or not a `profile` window is open -- see
    /// `crate::profiler`'s module doc for why `Registry::profiler` being
    /// `None` (the default, and the rest of the time) makes this a
    /// single cheap `is_some_and` and nothing else.
    fn profiling_active(&self, program: &str) -> bool {
        self.registry
            .profiler
            .as_ref()
            .is_some_and(|p| p.wants(program))
    }

    fn profile_record(
        &mut self,
        _program: &str,
        function: &str,
        ticks: u64,
        self_ticks: u64,
        wall: std::time::Duration,
        self_wall: std::time::Duration,
    ) {
        if let Some(p) = self.registry.profiler.as_mut() {
            p.record(function, ticks, self_ticks, wall, self_wall);
        }
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

    /// P2-B7 (OBI-182): `canary_cohort`'s endpoints are exact (0% never
    /// selects, 100% always does) and an interior percentage selects
    /// roughly its own share over a large id range -- the spread just
    /// needs to be deterministic and non-degenerate, not a particular
    /// distribution.
    #[test]
    fn canary_cohort_endpoints_are_exact_and_an_interior_pct_is_roughly_proportional() {
        let ids: Vec<ObjectId> = (0..10_000)
            .map(|i| ObjectId {
                index: i,
                generation: 0,
            })
            .collect();
        assert!(
            ids.iter().all(|&id| !canary_cohort(id, 0)),
            "0% must never select anything"
        );
        assert!(
            ids.iter().all(|&id| canary_cohort(id, 100)),
            "100% must always select"
        );
        let selected = ids.iter().filter(|&&id| canary_cohort(id, 25)).count();
        assert!(
            (2_000..3_000).contains(&selected),
            "25% of 10,000 ids should land near 2,500, got {selected}"
        );
    }

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
            Outcome::Ok(checked) => crate::bcvm::compile_and_verify(&checked.hir, &checked.src)
                .expect("codegen + verify"),
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
                compile_hir_program(&checked.hir, &checked.src, version, parent)
                    .expect("codegen + verify")
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
        let obj = host.instantiate(child_prog, true).expect("instantiate");

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
        let obj = host.instantiate(v1, true).expect("instantiate");
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
        let obj = host.instantiate(v1, true).expect("instantiate");

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
        let obj = host.instantiate(v1, true).expect("instantiate");
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
        let obj = host.instantiate(v1, true).expect("instantiate");
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
        let obj = host.instantiate(v1.clone(), true).expect("instantiate");

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
            let broken = host.instantiate(v1.clone(), true).expect("instantiate");
            let fine = host.instantiate(v1.clone(), true).expect("instantiate");
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
        let obj = host.instantiate(hall, true).expect("instantiate");
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
            ids[i] = host.instantiate(prog, true).unwrap();
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
            let obj = host.instantiate(hall, true).expect("instantiate");
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

    /// CTO review of PR #47 (OBI-108): `Op::IndexSetGlobal`'s `take_global`
    /// must not remove the container's own bytes from `mem_bytes` before
    /// `reserve_global_growth` checks it — that let a global map grow
    /// without bound as long as the object's *other* vars plus one entry
    /// still fit under the quota, since the check no longer saw the map
    /// being grown at all. A regression of this bypasses the same
    /// §5.2.1 quota guarantee `store_global_rejects_a_write_that_exceeds_the_memory_quota`
    /// checks, through the indexed-write path instead of a whole-var
    /// assignment.
    #[test]
    fn cto_index_set_global_map_growth_respects_quota() {
        const WF: &str = r#"
var m: {int: int} = {:}

pub fn grow(n: int) {
    m = {:}
    var i = 0
    while i < n {
        m[i] = i
        i += 1
    }
}
"#;
        let module = compile("/obj/thing", &[("/obj/thing", WF)]);
        let mut registry = Registry::default();
        let prog = Rc::new(CompiledProgram::new(module, 1, None, Vec::new()));
        registry.register_program(prog.clone());
        let obj = make_object(&mut registry, prog);
        let mut host = RegistryHost::new(&mut registry, obj);
        host.limits.mem_quota_bytes = 256;
        let err = host
            .call_on(obj, "grow", vec![Value::Int(1000)])
            .unwrap_err();
        assert!(
            err.report().contains("memory quota exceeded"),
            "an IndexSetGlobal map growth must be quota-checked against the \
             pre-take total, same as a whole-var store_global write:\n{}",
            err.report()
        );
        let mem = host.registry.get(obj).unwrap().mem_bytes;
        assert!(
            mem <= 256,
            "a rejected growth must never actually apply: mem_bytes={mem}, quota=256"
        );
    }

    /// CTO re-review of PR #47 (OBI-108, after OBI-80 deep accounting
    /// landed): `IndexSetGlobal` must reserve the deep cost delta for an
    /// *array* element replace too, not only a new/replaced map key --
    /// `g[0] = big_local_array` is exactly the OBI-78 nested-container
    /// bypass (`deep_accounting_rejects_a_large_local_container_nested_in_a_global_write`
    /// above closes it for a whole-var `data = [big]` write; this is the
    /// same nesting, through an indexed element write instead).
    #[test]
    fn cto_index_set_global_array_element_growth_respects_quota() {
        let zeros = (0..200).map(|_| "0").collect::<Vec<_>>().join(",");
        let wf = format!(
            r#"
var g: [any] = [0]

pub fn set_it() {{
    g = [0]
    let big: [int] = [{zeros}]
    g[0] = big
}}
"#
        );
        let module = compile("/obj/thing", &[("/obj/thing", &wf)]);
        let mut registry = Registry::default();
        let prog = Rc::new(CompiledProgram::new(module, 1, None, Vec::new()));
        registry.register_program(prog.clone());
        let obj = make_object(&mut registry, prog);
        let mut host = RegistryHost::new(&mut registry, obj);
        // `g` starts at cost 32 (its own slot + one `Int(0)` element, 16
        // bytes each); 200 ints nested into `g[0]` cost 200 * 16 = 3200
        // bytes deep. A quota that only charged the replaced element's old
        // 16-byte slot (the bypass this test guards against) would never
        // trip a 1000-byte quota here.
        host.limits.mem_quota_bytes = 1000;
        let err = host
            .call_on(obj, "set_it", vec![])
            .expect_err("a large element replace must push the object over a 1000-byte quota");
        assert!(
            err.report().contains("memory quota exceeded"),
            "{}",
            err.report()
        );
        let mem = host.registry.get(obj).unwrap().mem_bytes;
        assert!(
            mem <= 1000,
            "a rejected growth must never actually apply: mem_bytes={mem}, quota=1000"
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
        let obj = host.instantiate(prog, true).expect("instantiate");

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
        let obj = host.instantiate(prog, true).expect("instantiate");

        host.call_on(obj, "mutate_then_fail", vec![]).unwrap_err();

        let xs = host.call_on(obj, "get_xs", vec![]).unwrap();
        let want = Value::array(vec![Value::Int(1), Value::Int(2), Value::Int(3)]);
        assert!(
            xs.equals(&want),
            "xs must be rolled back exactly, got {xs:?}"
        );
    }

    /// OBI-80: `journal_rollback` restores each rolled-back var directly
    /// (bypassing `store_global`'s O(1) delta), so it must apply the same
    /// delta itself — otherwise a rolled-back write leaves `mem_bytes`
    /// charging for the *failed* attempt's value instead of what `vars`
    /// actually holds after the rollback.
    #[test]
    fn atomic_rollback_keeps_mem_bytes_consistent_with_the_restored_vars() {
        const WF: &str = r#"
var xs: [int] = [1, 2, 3]

atomic fn grow_then_fail() {
    xs = xs + [4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    throw "boom"
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
        let obj = host.instantiate(prog, true).expect("instantiate");
        let before = host.registry.get(obj).unwrap().mem_bytes;

        host.call_on(obj, "grow_then_fail", vec![]).unwrap_err();

        let after = host.registry.get(obj).unwrap().mem_bytes;
        assert_eq!(
            after, before,
            "mem_bytes must be back to its pre-atomic value, not still charging the \
             rolled-back (larger) array"
        );
        let o = host.registry.get_mut(obj).unwrap();
        let vars = o.vars.clone();
        o.recompute_mem_bytes();
        assert_eq!(
            o.mem_bytes, after,
            "incremental accounting after rollback must match a full recompute over {vars:?}"
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
        let obj = host.instantiate(prog, true).expect("instantiate");

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
        let obj = host.instantiate(prog, true).expect("instantiate");

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
        let obj = host.instantiate(prog, true).expect("instantiate");

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
        let obj = host.instantiate(prog, true).expect("instantiate");

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

    /// OBI-80 CTO re-review (function values, OBI-87/79 landed since this
    /// was first written): a closure capturing a large local array is the
    /// same one-level-of-nesting bypass as a plain array — storing the
    /// closure in a global must count the captured array's bytes, not just
    /// the closure value's own 16-byte slot.
    #[test]
    fn deep_accounting_rejects_a_closure_capturing_a_large_local_array() {
        let zeros = (0..200).map(|_| "0").collect::<Vec<_>>().join(",");
        let wf = format!(
            r#"
var data: any = null

pub fn set_it() {{
    let big: [int] = [{zeros}]
    data = fn() -> int {{
        return big[0]
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
        let obj = host.instantiate(prog, true).expect("instantiate");
        // Same 200-int nested payload as the array test above; a closure
        // that only charged its own slot (the OBI-78 bypass, or leaving
        // `HeapObj::Fn` at a flat 0 the way this cost() briefly did) would
        // never trip this quota.
        host.limits.mem_quota_bytes = 1000;
        let err = host
            .call_on(obj, "set_it", vec![])
            .expect_err("a closure's captured array must push the object over a 1000-byte quota");
        assert!(
            err.report().contains("memory quota exceeded"),
            "{}",
            err.report()
        );
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
    /// Each `data[i] = x` write -- one `Op::IndexSetGlobal` (OBI-108) --
    /// makes exactly six `cost()` calls, all O(1) reads of a cached total,
    /// never a walk of the array's elements: one for `take_global`'s
    /// pre-mutation total (`old_bytes`), two for `index_growth`'s exact
    /// pre-mutation reservation (the old element's cost, the new value's
    /// cost -- CTO re-review after OBI-80 landed: an array element
    /// *replace* can grow the container under deep accounting, not only a
    /// map's new key, so this has to be reserved *before* mutating, same
    /// as the array bounds check), two more in `ArrayData::set` itself
    /// (the same old/new costs, recomputed rather than threaded through --
    /// see the note below), and one in `commit_global`'s bookkeeping (the
    /// whole array's new cost, an O(1) read of its cached `deep_bytes`).
    /// O(1) per write, so n writes make exactly `6n` calls,
    /// deterministically. An O(n) re-walk per write (the regression this
    /// guards against) would make `O(n)` calls *per write*, i.e. `O(n²)`
    /// total: caught exactly, no timing noise, no threshold to tune.
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
            let obj = host.instantiate(prog, true).expect("instantiate");
            host.limits.mem_quota_bytes = u64::MAX;
            heap::reset_cost_calls();
            host.call_on(obj, "fill", vec![]).expect("fill");
            heap::cost_calls()
        }

        let small = cost_calls_to_fill(2_000);
        let large = cost_calls_to_fill(8_000); // 4x the elements
        assert_eq!(
            small,
            6 * 2_000,
            "O(1) per write: exactly 6 cost() calls per element"
        );
        assert_eq!(
            large,
            6 * 8_000,
            "O(1) per write: exactly 6 cost() calls per element"
        );
    }
}
