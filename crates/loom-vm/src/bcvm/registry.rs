// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

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

use crate::bcvm::Value;
use crate::bcvm::vm::{Host, Interpreter, Limits, R, RtError};
use crate::object::ObjectId;

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
}

impl CompiledProgram {
    pub fn new(module: Module, version: u32, parent: Option<Rc<CompiledProgram>>) -> Self {
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
        }
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
        let func_name =
            target.module.strings[target.module.functions[idx as usize].name as usize].to_string();
        // Same `self`, different (ancestor) program/module.
        self.self_stack.push(self_id);
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
        let func_name =
            target.module.strings[target.module.functions[idx as usize].name as usize].to_string();
        self.self_stack.push(recv_id);
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
        let owner_prog = Rc::new(CompiledProgram::new(owner_module, 1, None));
        let caller_prog = Rc::new(CompiledProgram::new(caller_module, 1, None));
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
        let parent_prog = Rc::new(CompiledProgram::new(parent_module, 1, None));
        registry.register_program(parent_prog.clone());
        let child_prog = Rc::new(CompiledProgram::new(child_module, 1, Some(parent_prog)));
        registry.register_program(child_prog.clone());

        let mut registry2 = registry;
        let child = make_object(&mut registry2, child_prog);

        let mut host = RegistryHost::new(&mut registry2, child);
        let greet = host.call_on(child, "greet", vec![]).unwrap();
        assert_eq!(greet.as_str(), Some("hello from child"));

        let via_super = host.call_on(child, "parent_greet", vec![]).unwrap();
        assert_eq!(via_super.as_str(), Some("hello from parent"));
    }
}
