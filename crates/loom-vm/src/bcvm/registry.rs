// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! A minimal, multi-object [`Host`] for the bytecode VM: a program
//! registry with a per-program dispatch table (name → function slot,
//! spec §5.8) and an object table so `call_virtual`/`call_static`/
//! `call_other` resolve against *real* inheritance and object identity
//! instead of the single-module stand-in `bcvm_e2e.rs` used for the first
//! codegen-bridge slice.
//!
//! **Scope of this slice (OBI-31 continuation):** this proves cross-object
//! dispatch, inheritance-aware `super::` calls, and value-semantics
//! aliasing *across* objects on the bytecode VM. It is deliberately not
//! yet wired into [`crate::world::World`] (which still runs the Phase 0
//! tree-walker via `crate::interp`): that swap needs `World`'s disk-backed
//! compile/recompile/upgrade machinery ported to build [`CompiledProgram`]s
//! instead of `crate::program::Program`s, which is the next slice.
//!
//! **Known gap (flagged, not hidden):** [`RegistryHost::call_virtual`]/
//! `call_other` each construct a *new* [`crate::bcvm::Interpreter`] with
//! its own heap-allocated frame `Vec` — no Weft-level recursion limit is
//! bypassed — but constructing that interpreter and driving it to
//! completion is still a plain (recursive) Rust function call from the
//! calling interpreter's `step`. Spec r5 D26 asks for cross-object calls
//! to push a frame onto *one* flat interpreter loop so the whole call
//! chain is suspendable at a `TickCheck`; that trampoline (a single
//! `Interpreter` whose frame stack can hold frames for more than one
//! object/module, with a host-call continuation instead of a nested
//! `call()`) is real work still open on this issue, tracked in the PR
//! description rather than done quietly here.

use std::collections::HashMap;
use std::rc::Rc;

use loom_compiler::bytecode::Module;
use loom_compiler::hir;
use loom_compiler::ty::Ty;

use crate::bcvm::Value;
use crate::bcvm::compile::{CompileError, compile_and_verify};
use crate::bcvm::vm::{Host, Interpreter, Limits, R, RtError};
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
    Ok(CompiledProgram::new(module, version, parent, var_specs))
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
}

/// An object's variables, keyed by (declaring program path, name) exactly
/// like the tree-walker's `crate::object::Vars` (§7.2: hot reload matches
/// state by declaring program + name).
pub type Vars = HashMap<(Rc<str>, Rc<str>), Value>;

pub struct BcObject {
    pub program: Rc<CompiledProgram>,
    pub vars: Vars,
}

struct Slot {
    generation: u32,
    obj: Option<BcObject>,
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
}

impl<'a> RegistryHost<'a> {
    pub fn new(registry: &'a mut Registry, self_object: ObjectId) -> Self {
        RegistryHost {
            registry,
            self_stack: vec![self_object],
            limits: Limits::default(),
            ticks_left: 1_000_000,
        }
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

    /// Call `name` declared in exactly `target` (no virtual dispatch) as
    /// `on`. Used for `$init` (each ancestor's own initialiser, never an
    /// override) and by [`Self::call_static`]/`call_on`/`call_other` once
    /// they have already resolved which program+slot to run.
    fn call_in(
        &mut self,
        on: ObjectId,
        target: &Rc<CompiledProgram>,
        idx: u32,
        args: Vec<Value>,
    ) -> R<Value> {
        self.self_stack.push(on);
        let func_name =
            target.module.strings[target.module.functions[idx as usize].name as usize].to_string();
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
        let id = self.registry.insert(BcObject {
            program: prog.clone(),
            vars: Vars::new(),
        });
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
        }
        for (ancestor, keep) in plan {
            self.run_init(id, &ancestor, &keep)?;
        }
        Ok(())
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
        // `super::name()`: resolve `name` declared in exactly `program`
        // (an ancestor of the caller's own program), never an override
        // further down the chain.
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
        // Same `self`, different (ancestor) program/module.
        self.call_in(self_id, &target, idx, args)
    }

    fn call_virtual(&mut self, name: &str, args: Vec<Value>) -> R<Value> {
        let self_id = self.self_object();
        self.call_other(Value::Object(self_id), name, args)
    }

    fn call_other(&mut self, recv: Value, name: &str, args: Vec<Value>) -> R<Value> {
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
        self.call_in(recv_id, &target, idx, args)
    }

    fn call_efun(&mut self, name: &str, _args: Vec<Value>) -> R<Value> {
        Err(RtError::new(format!(
            "efun `{name}` is not available in this Host (needs full World integration)"
        )))
    }

    fn load_global(&mut self, owner: &str, name: &str) -> Value {
        let self_id = self.self_object();
        self.registry
            .get(self_id)
            .and_then(|o| o.vars.get(&(Rc::from(owner), Rc::from(name))))
            .cloned()
            .unwrap_or(Value::Null)
    }

    fn store_global(&mut self, owner: &str, name: &str, v: Value) {
        let self_id = self.self_object();
        if let Some(o) = self.registry.get_mut(self_id) {
            o.vars.insert((Rc::from(owner), Rc::from(name)), v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_compiler::mudlib::{Outcome, Session};

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
        reg.insert(BcObject {
            program: prog,
            vars: Vars::new(),
        })
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
}
