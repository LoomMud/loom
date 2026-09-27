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
use std::path::PathBuf;
use std::rc::Rc;

use loom_compiler::bytecode::Module;
use loom_compiler::hir;
use loom_compiler::mudlib::{self, Outcome, Session};
use loom_compiler::ty::Ty;

use crate::bcvm::Value;
use crate::bcvm::compile::{CompileError, compile_and_verify};
use crate::bcvm::heap;
use crate::bcvm::vm::{
    CallSite, CallTarget, Host, HostCall, Interpreter, Limits, ProgramCode, R, RtError,
};
use crate::object::ObjectId;

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

/// Compile one already-checked `hir::Program` into a [`CompiledProgram`]:
/// codegen + verify (never skipped, see [`compile_and_verify`]) plus the
/// synthetic `$init` function (see [`synth_init_function`]) that lets
/// [`Registry::instantiate`] run var initialisers on the bytecode VM
/// instead of needing a separate tree-walking evaluator for them.
pub fn compile_hir_program(
    hir: &hir::Program,
    version: u32,
    parent: Option<Rc<CompiledProgram>>,
) -> Result<CompiledProgram, CompileError> {
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
    let mut prog = CompiledProgram::new(module, version, parent, var_specs);
    // `ob.f()` may only reach `pub` functions (spec §5.3; the deleted
    // tree-walker enforced this in `call_other` too). The synthetic
    // `$init` is never `pub`.
    prog.non_public = hir
        .fns
        .iter()
        .filter(|f| f.vis != hir::Visibility::Public)
        .map(|f| f.name.clone())
        .chain(std::iter::once(Rc::from(INIT_FN)))
        .collect();
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
}

impl Compiler {
    pub fn new(root: PathBuf) -> Self {
        Compiler {
            session: Session::new(mudlib::FsLoader { root }),
        }
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
            let compiled =
                compile_hir_program(&anc_hir, 1, parent).map_err(|e| format!("{anc}: {e}"))?;
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
            let compiled =
                compile_hir_program(&anc_hir, version, parent).map_err(|e| format!("{p}: {e}"))?;
            new_set.insert(p.clone(), Rc::new(compiled));
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
}

impl ProgramCode for CompiledProgram {
    fn module(&self) -> &Module {
        &self.module
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
        CompiledProgram {
            path,
            version,
            module,
            dispatch,
            parent,
            var_specs,
            non_public: Default::default(),
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
    /// Sum of [`heap::shallow_bytes`] over every value currently in `vars`
    /// (spec r5 §5.2.1 "memory quotas with per-object accounting"),
    /// maintained incrementally by [`RegistryHost::store_global`] so a
    /// quota check never has to re-walk `vars`.
    pub mem_bytes: u64,
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
        }
    }

    /// Re-derive [`BcObject::mem_bytes`] from `vars` from scratch. Needed
    /// wherever `vars` is replaced wholesale rather than written through
    /// [`RegistryHost::store_global`] (hot-reload `upgrade`, `install`
    /// rollback), or the incremental count drifts: vars dropped by a
    /// migration would stay charged forever.
    pub fn recompute_mem_bytes(&mut self) {
        self.mem_bytes = self.vars.values().map(heap::shallow_bytes).sum();
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
        }
        if let Some(o) = self.get_mut(id) {
            o.conn = Some(conn);
        }
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
    self_obj: ObjectId,
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
    /// P1+ enforcement hook (OBI-33): stubbed allow-all + audit log until
    /// S1's security-model policy lands, see `crate::privilege`.
    privilege: &'a mut dyn crate::privilege::PrivilegeCheck,
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
        &self,
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
        &self,
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
    fn current_guard(&self, recv: Option<&Value>) -> Option<Rc<CompiledProgram>> {
        let id = match recv {
            None => self.self_object(),
            Some(Value::Object(id)) => *id,
            Some(_) => return None,
        };
        self.registry.get(id).map(|o| o.program.clone())
    }

    pub fn new(registry: &'a mut Registry, self_object: ObjectId) -> Self {
        RegistryHost {
            registry,
            self_stack: vec![self_object],
            limits: Limits::default(),
            ticks_left: 1_000_000,
            driver: None,
            stack_base: stack_addr(),
            call_cache: HashMap::new(),
        }
    }

    /// A [`RegistryHost`] with driver efuns (`send`, `load_object`, …)
    /// enabled, used by [`crate::world::World`].
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
        privilege: &'a mut dyn crate::privilege::PrivilegeCheck,
    ) -> Self {
        RegistryHost {
            registry,
            self_stack: vec![self_object],
            limits,
            ticks_left,
            driver: Some(Driver {
                compiler,
                net,
                this_player,
                conn,
                master,
                scheduler,
                privilege,
            }),
            stack_base: stack_addr(),
            call_cache: HashMap::new(),
        }
    }

    /// Driver-side call of an apply (visibility is not enforced for the
    /// driver). `Ok(None)` if the object does not define `name` (mirrors
    /// `crate::interp::Exec::call_apply`).
    pub fn call_apply(&mut self, on: ObjectId, name: &str, args: Vec<Value>) -> R<Option<Value>> {
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

    /// `compile_object`/`update` (§7.2): recompile `path` and install it,
    /// all-or-nothing (mirrors `crate::world::Exec::recompile` +
    /// [`RegistryHost::install`]).
    pub fn recompile(&mut self, path: &str) -> Result<(), String> {
        let path = mudlib::normalize_path(path)?;
        let new_set = {
            let driver = self
                .driver
                .as_mut()
                .expect("recompile needs a driver context");
            driver.compiler.recompile(self.registry, &path)?
        };
        self.install(new_set)
    }

    /// Call `name` on `on` (the object executing this call) as an
    /// outermost entry point (a `World`-facing `call_apply` equivalent).
    pub fn call_on(&mut self, on: ObjectId, name: &str, args: Vec<Value>) -> R<Value> {
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
        if let Some(p) = crate::efuns::privilege(name)
            && p.gated()
        {
            let caller = self.self_object();
            let driver = self.driver.as_mut().expect("checked above");
            driver
                .privilege
                .check(caller, name, p)
                .map_err(|e| RtError::new(format!("{name}(): {e}")))?;
        }
        let a0 = args.first().cloned().unwrap_or(Value::Null);
        let a1 = args.get(1).cloned().unwrap_or(Value::Null);
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
                    self.want_obj(name, &a0)?
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
                Ok(match self.recompile(&p) {
                    Ok(()) => Value::Null,
                    Err(e) => Value::str(&e),
                })
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
                let id = self
                    .driver
                    .as_mut()
                    .expect("checked above")
                    .scheduler
                    .call_out(me, delay as u64, func, Vec::new());
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
            _ => Err(RtError::new(format!(
                "internal: efun `{name}` not implemented"
            ))),
        }
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
        self.self_stack.push(on);
        let limits = self.limits;
        let mut ticks = self.ticks_left;
        let result = {
            let mut interp = Interpreter::new(&target.module, self, &limits, &mut ticks);
            interp.call(&func_name, args)
        };
        self.ticks_left = ticks;
        self.self_stack.pop();
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
        let id = self.registry.insert(BcObject::new(prog.clone()));
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
    pub fn upgrade(&mut self, id: ObjectId, new_prog: Rc<CompiledProgram>) -> R<()> {
        let old_vars = self
            .registry
            .get(id)
            .ok_or_else(|| RtError::new("upgrade of a destructed object"))?
            .vars
            .clone();
        let mut new_vars = Vars::new();
        let mut plan: Vec<(Rc<CompiledProgram>, Vec<bool>)> = Vec::new();
        for ancestor in new_prog.chain() {
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
            plan.push((ancestor, keep));
        }
        if let Some(o) = self.registry.get_mut(id) {
            o.program = new_prog;
            o.vars = new_vars;
            o.recompute_mem_bytes();
        }
        // The object's program just changed; drop every inline-cache entry
        // rather than reason about which call sites it could affect.
        self.call_cache.clear();
        for (ancestor, keep) in plan {
            self.run_init(id, &ancestor, &keep)?;
        }
        Ok(())
    }

    /// Install the output of [`Compiler::recompile`]: register every new
    /// [`CompiledProgram`] and upgrade every existing object whose
    /// *current* program is one of them, all-or-nothing (spec §7.2) — the
    /// bytecode-VM analogue of `World::install`. On the first failing
    /// object upgrade, every program registration and every object already
    /// upgraded in this call are rolled back to their pre-`install` state,
    /// and the (rendered) error is returned; nothing is left half-migrated.
    pub fn install(&mut self, new_set: HashMap<String, Rc<CompiledProgram>>) -> Result<(), String> {
        let old_programs: Vec<(String, Option<Rc<CompiledProgram>>)> = new_set
            .keys()
            .map(|k| (k.clone(), self.registry.program(k)))
            .collect();
        for v in new_set.values() {
            self.registry.register_program(v.clone());
        }
        let affected: Vec<(ObjectId, Rc<CompiledProgram>)> = self
            .registry
            .ids()
            .into_iter()
            .filter_map(|id| {
                let o = self.registry.get(id)?;
                new_set.get(&*o.program.path).map(|p| (id, p.clone()))
            })
            .collect();
        let mut saved: Vec<(ObjectId, Rc<CompiledProgram>, Vars)> = Vec::new();
        let mut failure: Option<(ObjectId, RtError)> = None;
        for (id, new_prog) in affected {
            let Some(o) = self.registry.get(id) else {
                continue;
            };
            saved.push((id, o.program.clone(), o.vars.clone()));
            if let Err(e) = self.upgrade(id, new_prog) {
                failure = Some((id, e));
                break;
            }
        }
        // Programs were replaced: an old `Rc<CompiledProgram>` may now be
        // freed and its address reused by new code, which would make a
        // stale `CallSite` (keyed by code address) collide with a live one.
        // Clear the per-call-site inline cache on every install outcome.
        self.call_cache.clear();
        let Some((id, e)) = failure else {
            return Ok(());
        };
        // Roll back everything: programs, then every touched object.
        for (k, old) in old_programs {
            match old {
                Some(p) => {
                    self.registry.register_program(p);
                }
                None => {
                    self.registry.programs.remove(&k);
                }
            }
        }
        for (sid, prog, vars) in saved {
            if let Some(o) = self.registry.get_mut(sid) {
                o.program = prog;
                o.vars = vars;
                o.recompute_mem_bytes();
            }
        }
        self.call_cache.clear();
        Err(format!(
            "upgrade of object {id:?} failed, nothing was changed:\n{}",
            e.report()
        ))
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
                    self_obj,
                },
            );
        }
        Ok(HostCall::Enter {
            code,
            func,
            self_obj,
            args,
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
        let Some(entry) = self.call_cache.get(&site) else {
            return Err(args);
        };
        match self.current_guard(recv) {
            Some(g) if Rc::ptr_eq(&g, &entry.guard) => Ok(HostCall::Enter {
                code: entry.target.clone(),
                func: entry.func,
                self_obj: entry.self_obj,
                args,
            }),
            _ => Err(args),
        }
    }

    fn enter_self(&mut self, obj: ObjectId) {
        self.self_stack.push(obj);
    }

    fn leave_self(&mut self) {
        self.self_stack.pop();
    }

    fn call_efun(&mut self, name: &str, args: Vec<Value>) -> R<Value> {
        self.driver_efun(name, args)
    }

    fn load_global(&mut self, owner: &str, name: &str) -> Value {
        let self_id = self.self_object();
        self.registry
            .get(self_id)
            .and_then(|o| o.vars.get(&(Rc::from(owner), Rc::from(name))))
            .cloned()
            .unwrap_or(Value::Null)
    }

    fn store_global(&mut self, owner: &str, name: &str, v: Value) -> R<()> {
        let self_id = self.self_object();
        let quota = self.limits.mem_quota_bytes;
        let key: (Rc<str>, Rc<str>) = (Rc::from(owner), Rc::from(name));
        let new_bytes = heap::shallow_bytes(&v);
        let Some(o) = self.registry.get_mut(self_id) else {
            // A destructed object writing a global is silently dropped,
            // matching the pre-quota behaviour above (nothing left to
            // charge memory to either).
            return Ok(());
        };
        let old_bytes = o.vars.get(&key).map(heap::shallow_bytes).unwrap_or(0);
        let new_total = o.mem_bytes.saturating_sub(old_bytes) + new_bytes;
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
        assert_eq!(registry.get(obj).unwrap().mem_bytes, 40);

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
            0,
            "`blob` was dropped by the upgrade; it must no longer be charged"
        );
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
            let snapshot: Vec<Value> = keys.iter().map(|k| host.load_global("/t/obj", k)).collect();

            let mark = host.begin_atomic();
            for (i, v) in &during {
                host.store_global("/t/obj", keys[*i], v.clone()).unwrap();
            }
            if mutate_xs_element {
                // The nested-element-write case the AC calls out by name:
                // read the container, mutate a copy (COW), write the whole
                // (new) value back over the global slot.
                let mut xs = host.load_global("/t/obj", "xs");
                if let Some(arr) = xs.array_mut()
                    && !arr.is_empty()
                {
                    arr[0] = Value::Int(-1);
                    host.store_global("/t/obj", "xs", xs).unwrap();
                }
            }
            host.rollback_atomic(mark);

            for (k, want) in keys.iter().zip(&snapshot) {
                let got = host.load_global("/t/obj", k);
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
}
