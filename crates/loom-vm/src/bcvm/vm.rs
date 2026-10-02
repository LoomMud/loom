// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The register-bytecode interpreter (spec §5.8/§5.9).
//!
//! **D-P1.3: Weft frames never live on the native stack.** [`Interpreter`]
//! keeps its own heap-allocated `Vec<Frame>` call stack; a Weft call that
//! recurses (directly, or `Static` back into the same module) pushes a
//! [`Frame`] and loops, it never makes a recursive Rust call. Call depth is
//! therefore a Weft-level limit ([`Interpreter::max_depth`]) checked as an
//! ordinary `Vec` length check, independent of the native thread's stack
//! size — a 10k-deep Weft recursion fails with "Too deep recursion" the
//! same way on a 64 KiB thread as on an 8 MiB one (see the test below).
//!
//! **D26: one flat frame stack across objects.** A cross-module call
//! (`Virtual` dispatch, `super::`/`Static` into another program,
//! `CallOther`) is resolved by the [`Host`] via [`Host::dispatch`], which
//! may answer [`HostCall::Enter`]: "run function `func` of `code` as
//! object `self_obj`". The interpreter then pushes that as an ordinary
//! [`Frame`] on the *same* `Vec<Frame>` (bracketed by
//! [`Host::enter_self`]/[`Host::leave_self`]), so the whole Weft call
//! chain — across objects and programs — lives in one heap stack, is
//! bounded by one `max_depth`, and can be suspended at a `TickCheck` and
//! resumed ([`Interpreter::suspend_after_ticks`], [`Interpreter::resume`]).
//! A host that cannot hand out code (the test hosts) answers
//! [`HostCall::Done`] with an already-computed value instead.
//!
//! The one remaining nesting is a *driver efun* that itself runs Weft code
//! (e.g. `load_object` running `create()`): that still builds a fresh
//! [`Interpreter`] inside the host and is not suspendable; see
//! `bcvm::registry`'s module doc.

use loom_compiler::bytecode::{
    BinOp, Callee, CalleeOp, ConstValue, IndexKind, IterKind, Module, Op, OpKind, Reg, Ty, UnOp,
};

use std::rc::Rc;

use crate::bcvm::heap::{self, FnBody, FunctionValue, MapData, Value};
use crate::object::ObjectId;
use crate::security::GuardSet;

/// A Weft runtime error: message (with `path.wf:line:col` when available)
/// plus a call trace, most recent frame first.
#[derive(Clone, Debug)]
pub struct RtError {
    pub message: String,
    pub trace: Vec<String>,
    /// CTO review (OBI-169, PR #72, must-fix 1): the declaring program
    /// path for each matching entry in [`Self::trace`] (same length,
    /// same "most recent frame first" order, `"?"` for a frame with no
    /// known program -- e.g. the interpreter's own hand-assembled base
    /// module in unit tests). This is what lets the error inbox
    /// (`crate::errors`) attribute an error to the program that actually
    /// raised it (the innermost frame) instead of the entry object's own
    /// program, which can be a different, less-privileged one several
    /// `call_other`/apply frames up the chain -- attributing to the
    /// entry object would otherwise leak a `/secure` program's error
    /// message to whatever `valid_read` lets the entry object's own
    /// program see.
    pub trace_programs: Vec<String>,
    /// `false` for tick/call-depth exhaustion (spec: not catchable — a
    /// `try`/`catch` in the unwind path must not stop it). `true` for
    /// everything else, including `throw` and ordinary runtime errors
    /// (division by zero, index out of range, ...).
    pub catchable: bool,
    /// The value passed to `throw`, if this error came from one. `None`
    /// for a built-in runtime error, which a `catch` still sees — as a
    /// string of [`RtError::message`] (see [`RtError::caught_value`]).
    pub thrown: Option<Value>,
}

impl RtError {
    pub fn new(message: impl Into<String>) -> RtError {
        RtError {
            message: message.into(),
            trace: Vec::new(),
            trace_programs: Vec::new(),
            catchable: true,
            thrown: None,
        }
    }

    /// Tick/call-depth exhaustion (spec: not catchable).
    pub fn uncatchable(message: impl Into<String>) -> RtError {
        RtError {
            catchable: false,
            ..RtError::new(message)
        }
    }

    /// `throw value`.
    pub fn thrown(value: Value, message: String) -> RtError {
        RtError {
            message,
            trace: Vec::new(),
            trace_programs: Vec::new(),
            catchable: true,
            thrown: Some(value),
        }
    }

    /// The value a `catch` handler binds: the thrown value itself, or a
    /// string of the message for a built-in runtime error.
    pub fn caught_value(&self) -> Value {
        self.thrown
            .clone()
            .unwrap_or_else(|| Value::str(&self.message))
    }

    pub fn report(&self) -> String {
        let mut s = self.message.clone();
        for t in &self.trace {
            s.push_str("\n  ");
            s.push_str(t);
        }
        s
    }
}

pub type R<T> = Result<T, RtError>;

/// Code a [`Host`] can hand back for the interpreter to run on its own
/// frame stack (D26). Implemented by `bcvm::registry::CompiledProgram`.
pub trait ProgramCode {
    fn module(&self) -> &Module;
    /// The program version (spec r5 §5.2/§7.2, OBI-79's closure
    /// program-version pin): `0` for anything that is not a versioned
    /// hot-reloadable program (the hand-assembled test modules in this
    /// file).
    fn version(&self) -> u32 {
        0
    }
    /// This program's declaring path (`/std/player`, ...), for
    /// [`RtError::trace_programs`] (OBI-169, CTO review on PR #72,
    /// must-fix 1). `None` for anything with no real mudlib path (the
    /// hand-assembled test modules in this file) -- callers fall back to
    /// `"?"`, same as a frame with no trace at all.
    fn program_path(&self) -> Option<&str> {
        None
    }
}

/// A call the interpreter could not resolve inside its own module.
pub enum CallTarget<'s> {
    /// `super::name` / `program::name`.
    Static { program: &'s str, name: &'s str },
    /// Unqualified `name(..)` on `self`.
    Virtual { name: &'s str },
    /// `recv.name(..)`.
    Other { recv: Value, name: &'s str },
}

/// Identifies one `Op::Call`/`Op::CallOther` instruction, for the
/// per-call-site inline cache (spec §5.8 "dispatch tables ... with inline
/// cache"): a [`Host`] implementation may remember what a given call site
/// resolved to last time and skip its dispatch-table hash lookup (and, via
/// [`Host::dispatch_cached`], the interpreter's own name-string lookup/
/// allocation) on the next visit, as long as it re-checks a cheap guard
/// first (see `bcvm::registry::RegistryHost`'s use of this).
///
/// `code` is the identity of the *calling* function's code (a
/// `Rc<dyn ProgramCode>`'s data pointer, or the base module's address for
/// the outermost call) — together with `func`/`pc` this is unique for as
/// long as that compiled program is reachable; a recompile produces a
/// brand new `Rc`/`Module`, so old cache entries simply stop matching any
/// call site that can still execute (no explicit invalidation needed).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct CallSite {
    code: usize,
    func: u32,
    pc: u32,
}

/// How a [`Host`] answers [`Host::dispatch`].
pub enum HostCall {
    /// The host ran the call itself (or it needed no Weft frames).
    Done(Value),
    /// Push function `func` of `code` as a new frame running as `self_obj`
    /// on the caller's flat frame stack.
    Enter {
        code: Rc<dyn ProgramCode>,
        func: u32,
        self_obj: ObjectId,
        args: Vec<Value>,
        /// Preload for the callee's `FunctionCode::capture_targets` (spec
        /// r5 §5.2.2, OBI-79's closure invocation): empty for every
        /// ordinary (non-closure) call.
        captures: Vec<Value>,
    },
}

/// Result of driving an [`Interpreter`]: finished, or parked at a
/// `TickCheck` with every frame intact (D26 suspend/resume hook).
#[derive(Debug)]
pub enum Exec {
    Done(Value),
    Suspended,
}

/// Callbacks for everything the interpreter cannot resolve from the
/// [`Module`] it is running alone (§5.5, §5.9): cross-object/program calls,
/// efuns, and `self`/program-variable access. `World` (OBI-31 follow-up)
/// is the production `Host`; tests use a small in-memory one.
pub trait Host {
    /// The object executing the current call chain.
    fn self_object(&self) -> ObjectId;
    /// `super::name(args)` / a specific program's function.
    fn call_static(&mut self, program: &str, name: &str, args: Vec<Value>) -> R<Value>;
    /// Unqualified `name(args)`: virtual dispatch on the running object's
    /// *current* program.
    fn call_virtual(&mut self, name: &str, args: Vec<Value>) -> R<Value>;
    /// `recv.name(args)`.
    fn call_other(&mut self, recv: Value, name: &str, args: Vec<Value>) -> R<Value>;
    /// An efun call not handled inline by the interpreter (see
    /// [`Interpreter::call_efun`] for the ones that are).
    fn call_efun(&mut self, name: &str, args: Vec<Value>) -> R<Value>;
    /// Load a program variable. `Err` (spec, OBI-85 CTO review) if `self`
    /// has been destructed since -- a plain "missing key defaults to
    /// `null`" would silently paper over a stale reference instead of
    /// surfacing it as the runtime error it is; see
    /// `bcvm::registry::RegistryHost::load_global`.
    fn load_global(&mut self, owner: &str, name: &str) -> R<Value>;
    /// Store a program variable. `Err` (with a Weft stack trace, like any
    /// other [`RtError`]) if the host enforces a per-object memory quota
    /// (spec r5 §5.2.1) and this write would exceed it — see
    /// `bcvm::registry::RegistryHost::store_global`.
    fn store_global(&mut self, owner: &str, name: &str, v: Value) -> R<()>;

    /// Move a program variable's value out for an in-place index-assign
    /// (spec r5 D24, OBI-108): the slot is left holding `Null` until the
    /// matching [`Host::commit_global`] (success) or
    /// [`Host::restore_global`] (any error/tick-abort before that) puts a
    /// value back. A real host implements this as a move out of its own
    /// storage, not a clone — that is the whole point: a container coming
    /// back from here has exactly one owner, so mutating it in place
    /// (`Value::array_mut`/`map_mut`) never has to `Rc::make_mut`-clone the
    /// whole buffer just because the global's own copy was still sitting
    /// there at refcount 2. The default here (used by hosts that never run
    /// an index-assign into a global, e.g. tests) falls back to a plain
    /// `load_global` + `store_global(Null)`, which is correct but pays the
    /// clone this method exists to avoid.
    fn take_global(&mut self, owner: &str, name: &str) -> R<Value> {
        let v = self.load_global(owner, name)?;
        self.store_global(owner, name, Value::Null)?;
        Ok(v)
    }
    /// Commit the (possibly mutated) value [`Host::take_global`] handed
    /// out. `old_bytes` is `shallow_bytes` of the value *as `take_global`
    /// handed it out*, captured by the caller before any mutation — a real
    /// host needs it to correct the per-object memory total for exactly
    /// this write (CTO review of PR #47, OBI-108: `take_global` must not
    /// adjust that total itself, only `commit_global`/`restore_global`
    /// may, or `reserve_global_growth`'s check in between runs against a
    /// total that already excludes the very container being grown — a
    /// quota bypass). Subject to the same per-object memory quota as
    /// [`Host::store_global`] (a map insert can grow the container) —
    /// though a real host checks that *before* mutating
    /// ([`Host::reserve_global_growth`]), so this itself never fails for
    /// that reason once the write has actually reached this call. The
    /// default here ignores `old_bytes`: `store_global` already recomputes
    /// the total from scratch against the `Null` `take_global`'s own
    /// default left behind, so there is nothing left to correct.
    fn commit_global(&mut self, owner: &str, name: &str, _old_bytes: u64, v: Value) -> R<()> {
        self.store_global(owner, name, v)
    }
    /// Put the *untouched* value [`Host::take_global`] handed out straight
    /// back: used when an error (index out of range, a type error) or a
    /// tick/budget abort happens between `take_global` and the matching
    /// `commit_global`, so the write never happened from the program's
    /// point of view (spec r5 OBI-108: no semantic change when a write
    /// fails). Never fails on the size the value already was before it was
    /// taken (it fit then, it fits now) — `self` having been destructed
    /// out from under the call is the only way this can still error.
    /// `old_bytes` — see `commit_global` — is unused by the default for
    /// the same reason.
    fn restore_global(&mut self, owner: &str, name: &str, _old_bytes: u64, v: Value) -> R<()> {
        self.store_global(owner, name, v)
    }
    /// Would committing `added_bytes` more onto the global `take_global`
    /// just emptied (an array element replace, a map key replace, or a
    /// brand new map key -- with deep accounting, OBI-80, every one of
    /// those can grow the container, spec r5 OBI-108) push this object's
    /// memory quota over -- checked *before* the mutation
    /// that would need it, so a rejected write never has to be undone,
    /// only never applied. `Ok(())` by default (used by hosts that do not
    /// enforce a per-object quota at all).
    fn reserve_global_growth(&mut self, _owner: &str, _name: &str, _added_bytes: u64) -> R<()> {
        Ok(())
    }

    /// Resolve a cross-module call. The default runs it to completion via
    /// the `call_*` methods above; a host that can hand out code overrides
    /// this to return [`HostCall::Enter`] so the call stays on the
    /// interpreter's one flat frame stack (D26). `site` identifies the
    /// calling `Op::Call`/`Op::CallOther` instruction, for a host that
    /// implements a per-call-site inline cache.
    fn dispatch(
        &mut self,
        _site: CallSite,
        target: CallTarget<'_>,
        args: Vec<Value>,
    ) -> R<HostCall> {
        Ok(HostCall::Done(match target {
            CallTarget::Static { program, name } => self.call_static(program, name, args)?,
            CallTarget::Virtual { name } => self.call_virtual(name, args)?,
            CallTarget::Other { recv, name } => self.call_other(recv, name, args)?,
        }))
    }
    /// Fast-path probe for [`CallSite`] `site`, tried by the interpreter
    /// *before* it materializes the callee name (which `dispatch` needs but
    /// a cache hit does not) — the actual saving a per-call-site inline
    /// cache buys over always doing [`Host::dispatch`]. `recv` is `None`
    /// for `Virtual`/`Static` (guard is self's own program) or the receiver
    /// value for `Other` (guard is its program). `Err(args)` (cache miss,
    /// or no cache) hands `args` straight back so the slow path
    /// (`dispatch`) can use them without recomputing anything; default
    /// implementation always misses.
    fn dispatch_cached(
        &mut self,
        _site: CallSite,
        _recv: Option<&Value>,
        args: Vec<Value>,
    ) -> Result<HostCall, Vec<Value>> {
        Err(args)
    }
    /// A [`HostCall::Enter`] frame for `obj` was pushed: `self_object()`
    /// must now answer `obj` until the matching [`Host::leave_self`].
    fn enter_self(&mut self, _obj: ObjectId) {}
    /// The current guard set (OBI-35 D-S1.6): what a function value
    /// created right now captures as its creator principal.
    fn current_guard(&self) -> crate::security::GuardSet {
        crate::security::GuardSet::empty()
    }
    /// The uid of the object currently running (OBI-35 D-S1.6): a function
    /// value's `quota_uid` with no roles/tier snapshot available (S2,
    /// OBI-36 falls back to "the creator's uid").
    fn current_uid(&self) -> crate::security::Sym {
        crate::security::ROOT
    }
    /// Push a function value's synthetic creator frame (OBI-35 D-S1.7):
    /// the guard becomes `current ∪ guard` until the matching
    /// [`Host::leave_creator_frame`]. The callee's own frame is pushed
    /// after it through the usual [`Host::enter_self`].
    fn enter_creator_frame(&mut self, _guard: &crate::security::GuardSet) {}
    fn leave_creator_frame(&mut self) {}
    /// Extra ticks the host wants charged for the efun that just returned
    /// (policy-cache misses, OBI-35 D-S1.3). Polled after every
    /// `call_efun`.
    fn take_extra_ticks(&mut self) -> u64 {
        0
    }
    /// The frame pushed by the matching [`Host::enter_self`] was popped.
    fn leave_self(&mut self) {}
    /// `Value::array_mut`/`map_mut` actually cloned a shared buffer
    /// (`loom_cow_copies_total{program}`, spec r5 §5.2.1, D24); `program` is
    /// the path of whichever module's bytecode did the write. No-op unless
    /// a host collects this (see `bcvm::registry::RegistryHost`).
    fn record_cow_copy(&mut self, _program: &str) {}

    /// Resolve a `CallValue` on a function value (spec r5 §5.2.2, OBI-79):
    /// `creator` is [`crate::bcvm::heap::FunctionValue::creator`], `body`
    /// is [`crate::bcvm::heap::FunctionValue::body`]. Checking that
    /// `creator` is still a live object (not destructed — "closures over
    /// destructed objects fail cleanly") is this method's job, so both
    /// function-value shapes get one clean error from one place. The
    /// default refuses every function value: correct for a host that
    /// never lets Weft code construct one (none of the hand-built test
    /// hosts in this crate do).
    fn dispatch_value(
        &mut self,
        _creator: ObjectId,
        _body: &FnBody,
        _args: Vec<Value>,
    ) -> R<HostCall> {
        Err(RtError::new(
            "function values are not supported by this host",
        ))
    }

    /// The `Rc` handle to the program the current call chain is running,
    /// strong enough to outlive a later hot-reload `upgrade()` of the
    /// running object (spec r5 §5.2.2, OBI-79's closure program-version
    /// pin: "anonymous closures keep their program version"). Not derived
    /// from the interpreter's own frame stack because the *outermost*
    /// frame of a driver-started call (`RegistryHost::call_in`) only ever
    /// borrows a `&Module`, never the owning `Rc` — the host is the one
    /// thing that always still has it. Only asked for a base-module frame,
    /// so it must return the program whose module the interpreter was
    /// built with (for an inherited function, that ancestor, not the
    /// object's own program). The default errs: correct for a host that
    /// never lets Weft code construct a closure.
    fn current_program(&self) -> R<Rc<dyn ProgramCode>> {
        Err(RtError::new("closures are not supported by this host"))
    }

    /// `atomic fn` (spec r5 §5.2.1, OBI-32): entering an atomic-marked
    /// function opens a journal scope and returns its mark. Every
    /// object-variable write (including a container mutation — r5: that
    /// is still an object-variable write, journaled as one `Rc` clone of
    /// the old value) and clone/destruct while any scope is open must be
    /// undoable back to that mark. The default (no journal) is correct for
    /// a `Host` that never runs an atomic function.
    fn begin_atomic(&mut self) -> u64 {
        0
    }
    /// The atomic call returned normally: the scope's writes are kept.
    fn commit_atomic(&mut self, _mark: u64) {}
    /// The atomic call ended by propagating an error out of it (not one
    /// caught inside its own body): undo every object-variable write and
    /// clone/destruct recorded since `mark`, in reverse order, exactly
    /// restoring the prior state.
    fn rollback_atomic(&mut self, _mark: u64) {}

    /// `profile <program>` (spec Phase 2 B5, OBI-170): is a sampling
    /// window currently open for `program`? Checked once per
    /// [`Interpreter::push_call`], on *every* Weft function call whether
    /// or not profiling is in use anywhere -- so the default (`false`,
    /// no clock read, no allocation) is the only cost the "profiling off
    /// has unmeasurable overhead" acceptance bar actually has to hold to.
    fn profiling_active(&self, _program: &str) -> bool {
        false
    }
    /// One profiled call just returned (normally, or by unwinding past
    /// its frame): `function` is its name. `ticks`/`wall` are
    /// **inclusive** (gprof "cumulative" -- everything charged/elapsed
    /// while this frame was on the stack, including whatever it called);
    /// `self_ticks`/`self_wall` are the same call's own cost with every
    /// directly-nested call *into the same sampled program* subtracted
    /// out (CTO review, OBI-170, PR #67 must-fix 2: recursion/nested
    /// calls must not be double-counted in the figure a builder actually
    /// reads). Only called when [`Host::profiling_active`] answered
    /// `true` for `program` at the matching `push_call`, so the default
    /// (no-op) never runs on the hot "profiling off" path either.
    fn profile_record(
        &mut self,
        _program: &str,
        _function: &str,
        _ticks: u64,
        _self_ticks: u64,
        _wall: std::time::Duration,
        _self_wall: std::time::Duration,
    ) {
    }
}

/// One activation: which function, at which instruction, with its own
/// register file. Lives on [`Interpreter`]'s `Vec<Frame>`, never on the
/// native stack.
struct Frame {
    /// The module this frame runs; `None` = the interpreter's base module.
    code: Option<Rc<dyn ProgramCode>>,
    /// This function's instruction stream, an `Rc` clone of
    /// `module_of(self)`'s `functions[func].code` taken once at push time
    /// (OBI-107, spec: "cache the current function's consts/strings slice
    /// ... in the frame, and refresh it on call/return"): `step()` clones
    /// this handle (a refcount bump, not a per-`Op` clone) to index it by
    /// reference without holding a borrow of `self` across match arms that
    /// also need `&mut self` (host calls) — see `step()`'s doc comment.
    code_ops: Rc<[Op]>,
    /// Pushed via [`HostCall::Enter`], so popping it must call
    /// [`Host::leave_self`].
    entered: bool,
    func: u32,
    pc: u32,
    regs: Vec<Value>,
    /// Register to write the callee's return value into, in the *caller*
    /// (the frame below this one). `None` for the outermost call.
    ret_into: Option<Reg>,
    /// Active `try`/`catch` handlers on this frame, innermost last
    /// (`Op::PushHandler`/`Op::PopHandler`, spec r5 OBI-32): `(catch_pc,
    /// catch_reg)`. A catchable error unwinds to the innermost handler on
    /// the *nearest* frame (this one, or an outer caller) that still has
    /// one, popping every frame above it.
    handlers: Vec<(u32, Option<Reg>)>,
    /// `Some(mark)` if this frame is running an `atomic fn` (spec r5
    /// §5.2.1): the [`Host::begin_atomic`] mark to [`Host::commit_atomic`]
    /// on a normal return or [`Host::rollback_atomic`] if this frame is
    /// popped while an error unwinds past it.
    atomic_mark: Option<u64>,
    /// `true` iff this frame's push was bracketed by
    /// [`Host::enter_creator_frame`] (a function value's synthetic
    /// creator frame, OBI-35 D-S1.7): [`Interpreter::pop_frame`] must call
    /// [`Host::leave_creator_frame`] to match. The VM stores only this
    /// bit, never the guard itself — "the VM keeps no security state of
    /// its own" (OBI-35 scope): the host is the only place a `GuardSet`
    /// lives.
    creator_frame: bool,
    /// `Some(ProfFrame { .. })` iff [`Host::profiling_active`] answered
    /// `true` for this frame's program when it was pushed (spec Phase 2
    /// B5, OBI-170): `pop_frame` reports this call's cost once via
    /// [`Host::profile_record`] using the wall-clock elapsed since
    /// `start` and the ticks charged since `ticks_before`, inclusive and
    /// self (CTO review, PR #67 must-fix 2: `child_ticks`/`child_wall`
    /// subtracted out). `None` (profiling off, or this isn't the sampled
    /// program) is the common case and the only thing `pop_frame` has to
    /// check on that path.
    // `Box`ed (CTO review follow-up, OBI-170, PR #67 bench evidence):
    // keeps this variant's footprint to one pointer (`Option<Box<T>>`
    // niche-optimizes the same as a raw pointer) instead of inlining
    // `ProfFrame`'s four fields into every `Frame` whether or not
    // profiling is ever used -- `vm_bench`'s `monocall` (minimal
    // per-call payload, maximally sensitive to `Frame`'s own size)
    // showed a small but measurable regression with `ProfFrame`
    // inlined; boxing it removed that (see the PR body's before/after
    // numbers).
    prof: Option<Box<ProfFrame>>,
}

/// A profiled frame's own bookkeeping (CTO review, OBI-170, PR #67
/// must-fix 2): `child_ticks`/`child_wall` accumulate the **inclusive**
/// cost of every direct child call that was *also* into the sampled
/// program (same-program recursion, direct or indirect through this
/// frame) -- [`Interpreter::pop_frame`] adds a popped child's inclusive
/// figures here, on its new top-of-stack parent, right before computing
/// that parent's own self figures when it in turn pops. Subtracting
/// this from the frame's own inclusive ticks/wall at pop time is what
/// turns "every frame's inclusive total summed" (which double-counts
/// recursion depth-many times) into a true per-call self cost.
///
/// **Scope note:** only tracks children whose own frame was pushed with
/// `prof: Some` too, i.e. calls into the *same* sampled program.
/// recursion through an intervening call into a *different* program is
/// not subtracted (consistent with this profiler's existing "one
/// program at a time" scope, `crate::profiler`'s module doc) -- rare in
/// practice (a function recurses into itself, not through someone
/// else's code, to become "hot"), and inclusive ticks/wall are still
/// reported alongside self for exactly this case.
struct ProfFrame {
    start: std::time::Instant,
    ticks_before: u64,
    child_ticks: u64,
    child_wall: std::time::Duration,
}

/// Per-execution limits (spec §5.9): every tick-metered op consumes one
/// tick; the call stack cannot exceed `max_depth` frames; a single
/// program-variable write cannot push its owning object's (deep, see
/// `bcvm::heap::cost`) accounted memory past `mem_quota_bytes`
/// (spec r5 §5.2.1 "memory quotas with per-object accounting").
/// **Flat default, not yet per-tier:** builder/privilege tiers are the
/// CTO's security-model policy and are not modeled in `loom-vm` yet; this
/// is the single hook point a future per-tier quota would plug into.
#[derive(Clone, Copy)]
pub struct Limits {
    pub max_depth: u32,
    pub mem_quota_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_depth: 512,
            // 8 MiB of (deep, transitively-accounted) var storage per
            // object: generous enough
            // that no existing test/benchmark workload trips it by
            // accident, small enough to be a real backstop.
            mem_quota_bytes: 8 * 1024 * 1024,
        }
    }
}

/// What one [`Interpreter::step`] did.
enum Step {
    Continue,
    Returned(Value),
    Suspend,
}

pub struct Interpreter<'a, H: Host> {
    module: &'a Module,
    host: &'a mut H,
    limits: &'a Limits,
    ticks_left: &'a mut u64,
    stack: Vec<Frame>,
    /// Suspend-at-`TickCheck` countdown (D26 test hook); `None` = never.
    suspend_after: Option<u64>,
    /// The declaring program of `module` itself (OBI-169, CTO review on
    /// PR #72, must-fix 1): the base-module fallback for
    /// [`RtError::trace_programs`] when a frame's own `code` is `None`
    /// (every frame actually run by *this* `Interpreter` instance, since
    /// `code: None` means "the module this `Interpreter` itself was
    /// constructed with", not "unknown"). `None` for every call site that
    /// doesn't know/care (every hand-assembled test module in this file,
    /// and the base driver module efun dispatch runs against) -- those
    /// fall back to `"?"`, same as before this field existed. Set via
    /// [`Self::with_base_program`] by [`crate::bcvm::registry::
    /// RegistryHost::call_in`], the one real call site that runs a named
    /// *program's* own module as this `Interpreter`'s base.
    base_program: Option<Rc<str>>,
}

impl<'a, H: Host> Interpreter<'a, H> {
    pub fn new(
        module: &'a Module,
        host: &'a mut H,
        limits: &'a Limits,
        ticks_left: &'a mut u64,
    ) -> Self {
        Interpreter {
            module,
            host,
            limits,
            ticks_left,
            stack: Vec::new(),
            suspend_after: None,
            base_program: None,
        }
    }

    /// See [`Self::base_program`]'s doc.
    pub fn with_base_program(mut self, path: Rc<str>) -> Self {
        self.base_program = Some(path);
        self
    }

    /// D26 test hook: park the whole call chain at the `n`th `TickCheck`
    /// from now (`n >= 1`), returning [`Exec::Suspended`] with every frame
    /// — across objects — left intact for [`Interpreter::resume`].
    pub fn suspend_after_ticks(&mut self, n: u64) {
        self.suspend_after = Some(n.max(1));
    }

    /// Current Weft frame depth (all objects), for tests/diagnostics.
    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    /// Every [`Value`] currently reachable from live frames. Not needed by
    /// the value-semantics heap here (r5: no cycle collector, see the
    /// `heap` module docs), but useful for anything that wants to walk the
    /// live register set — e.g. future per-object memory accounting.
    pub fn roots(&self) -> impl Iterator<Item = &Value> {
        self.stack.iter().flat_map(|f| f.regs.iter())
    }

    fn module_of<'s>(&'s self, f: &'s Frame) -> &'s Module {
        match &f.code {
            Some(c) => c.module(),
            None => self.module,
        }
    }

    /// Identity of `frame`'s code, for [`CallSite`]: the data pointer of
    /// its `Rc<dyn ProgramCode>`, or the base module's address if this
    /// frame runs the interpreter's own (outermost) module.
    fn code_identity(&self, frame: &Frame) -> usize {
        match &frame.code {
            Some(c) => Rc::as_ptr(c) as *const () as usize,
            None => self.module as *const Module as usize,
        }
    }

    /// The module the top frame is running (the base module if idle).
    fn cur(&self) -> &Module {
        match self.stack.last() {
            Some(f) => self.module_of(f),
            None => self.module,
        }
    }

    fn frame_name<'s>(&'s self, f: &'s Frame) -> &'s str {
        let m = self.module_of(f);
        &m.strings[m.functions[f.func as usize].name as usize]
    }

    fn str_of(&self, id: u32) -> &str {
        &self.cur().strings[id as usize]
    }

    fn tick(&mut self) -> R<()> {
        self.charge_ticks(1)
    }

    /// Charge `n` ticks against the running budget (spec §5.9: "efuns
    /// declare costs", `crate::efuns::tick_cost`), the same counter
    /// `Op::TickCheck` decrements one at a time. `n == 0` is a no-op (an
    /// unknown efun, which `call_efun`/`host.call_efun` will itself
    /// reject before this would matter, still must not divide-by-zero
    /// panic or otherwise special-case here).
    ///
    /// Tick exhaustion is **not catchable** (spec: tick accounting is a
    /// security property; if `try`/`catch` could swallow a tick-limit
    /// error, an efun with a large declared cost — e.g. `compile_object`
    /// at 500 ticks — could be looped past the budget with impunity).
    fn charge_ticks(&mut self, n: u64) -> R<()> {
        if n == 0 {
            return Ok(());
        }
        if *self.ticks_left < n {
            *self.ticks_left = 0;
            return Err(
                self.err_with_trace_uncatchable("Too long evaluation (tick limit exceeded)")
            );
        }
        *self.ticks_left -= n;
        Ok(())
    }

    /// A runtime error raised by the current instruction. The frame trace
    /// is appended once, by [`Interpreter::run`], when the error unwinds
    /// the (single, flat) frame stack.
    fn err_with_trace(&self, msg: impl Into<String>) -> RtError {
        RtError::new(msg)
    }

    /// Like [`Interpreter::err_with_trace`], for tick/call-depth exhaustion
    /// (spec: not catchable).
    fn err_with_trace_uncatchable(&self, msg: impl Into<String>) -> RtError {
        RtError::uncatchable(msg)
    }

    /// Call `name` in this module with `args`, from outside any running
    /// frame (the World-facing entry point: `call_apply`, etc.).
    pub fn call(&mut self, name: &str, args: Vec<Value>) -> R<Value> {
        match self.start(name, args)? {
            Exec::Done(v) => Ok(v),
            Exec::Suspended => Err(RtError::new(
                "internal: call suspended; use start/resume to drive a suspendable call",
            )),
        }
    }

    /// Like [`Interpreter::call`], but may return [`Exec::Suspended`] if
    /// [`Interpreter::suspend_after_ticks`] was armed.
    pub fn start(&mut self, name: &str, args: Vec<Value>) -> R<Exec> {
        if !self.stack.is_empty() {
            return Err(RtError::new(
                "internal: interpreter already has a call in flight",
            ));
        }
        let idx = self
            .module
            .functions
            .iter()
            .position(|f| &*self.module.strings[f.name as usize] == name)
            .ok_or_else(|| RtError::new(format!("no function `{name}` in {}", self.module.path)))?;
        self.push_call(None, idx as u32, args, None, false, Vec::new(), None)?;
        self.run()
    }

    /// Continue a call parked by [`Interpreter::suspend_after_ticks`].
    pub fn resume(&mut self) -> R<Exec> {
        if self.stack.is_empty() {
            return Err(RtError::new("internal: nothing to resume"));
        }
        self.run()
    }

    /// `creator_guard` is `Some` iff this frame is a function value's
    /// synthetic creator frame (OBI-35 D-S1.7): the caller must already
    /// have called [`Host::enter_creator_frame`] with the same guard
    /// before this returns, so the pop side ([`Interpreter::pop_frame`])
    /// knows to call [`Host::leave_creator_frame`] to match. The VM itself
    /// never inspects the guard; it only remembers whether one is owed.
    #[allow(clippy::too_many_arguments)]
    fn push_call(
        &mut self,
        code: Option<Rc<dyn ProgramCode>>,
        idx: u32,
        args: Vec<Value>,
        ret_into: Option<Reg>,
        entered: bool,
        captures: Vec<Value>,
        creator_guard: Option<&GuardSet>,
    ) -> R<()> {
        if self.stack.len() as u32 >= self.limits.max_depth {
            return Err(self.err_with_trace_uncatchable(format!(
                "Too deep recursion (call depth limit {} exceeded)",
                self.limits.max_depth
            )));
        }
        let m: &Module = match &code {
            Some(c) => c.module(),
            None => self.module,
        };
        let f = &m.functions[idx as usize];
        if args.len() < f.min_arity as usize || args.len() > f.params as usize {
            let fname = m.strings[f.name as usize].to_string();
            return Err(self.err_with_trace(if f.min_arity == f.params {
                format!(
                    "{fname}() takes {} argument(s), got {}",
                    f.params,
                    args.len()
                )
            } else {
                format!(
                    "{fname}() takes {}..={} argument(s), got {}",
                    f.min_arity,
                    f.params,
                    args.len()
                )
            }));
        }
        let k = args.len() as u32 - f.min_arity;
        let pc = f.entry_points[k as usize];
        let atomic = f.atomic;
        let capture_targets = f.capture_targets.clone();
        let code_ops = f.code.clone();
        let mut regs: Vec<Value> = args;
        regs.resize(f.reg_types.len(), Value::Null);
        // Preload a closure body's captured-by-value snapshot (spec r5
        // §5.2.2, OBI-79) before the body runs — always empty for an
        // ordinary call.
        for (&treg, val) in capture_targets.iter().zip(captures) {
            regs[treg as usize] = val;
        }
        let atomic_mark = atomic.then(|| self.host.begin_atomic());
        if let Some(guard) = creator_guard {
            self.host.enter_creator_frame(guard);
        }
        // Spec Phase 2 B5 (OBI-170): ask the host once, by program path,
        // whether a `profile` window wants this call. `false` (the
        // default, and every ordinary call while profiling is off) skips
        // straight past the `Instant::now()`/tick snapshot below.
        let prof = self.host.profiling_active(&m.path).then(|| {
            Box::new(ProfFrame {
                start: std::time::Instant::now(),
                ticks_before: *self.ticks_left,
                child_ticks: 0,
                child_wall: std::time::Duration::ZERO,
            })
        });
        self.stack.push(Frame {
            code,
            code_ops,
            entered,
            func: idx,
            pc,
            regs,
            ret_into,
            handlers: Vec::new(),
            atomic_mark,
            creator_frame: creator_guard.is_some(),
            prof,
        });
        Ok(())
    }

    /// Pop the top frame, restoring the host's `self` if it was entered,
    /// and the guard stack if this was a function value's synthetic
    /// creator frame (reverse order of [`Interpreter::push_call`]'s
    /// enter: `leave_self` before `leave_creator_frame`, since `enter_self`
    /// ran after `enter_creator_frame`).
    fn pop_frame(&mut self) -> Frame {
        let f = self.stack.pop().unwrap();
        // Spec Phase 2 B5 (OBI-170): report this call's cost exactly
        // once, on whichever path popped it (normal return or error
        // unwind, `pop_frame_on_error` calls through here too). Skipped
        // entirely when `f.prof` is `None` -- profiling off, or this
        // frame's program wasn't the one being sampled.
        if let Some(prof) = &f.prof {
            let wall = prof.start.elapsed();
            let ticks = prof.ticks_before.saturating_sub(*self.ticks_left);
            // CTO review (OBI-170, PR #67, must-fix 2): subtract every
            // direct child call *into the same sampled program*
            // (`ProfFrame`'s own doc) so recursion/nested calls are not
            // double-counted in the self figure.
            let self_ticks = ticks.saturating_sub(prof.child_ticks);
            let self_wall = wall.saturating_sub(prof.child_wall);
            let program = self.module_of(&f).path.to_string();
            let function = self.frame_name(&f).to_string();
            self.host
                .profile_record(&program, &function, ticks, self_ticks, wall, self_wall);
            // Propagate this frame's *inclusive* cost up to its new
            // top-of-stack parent's own child accumulator, but only if
            // that parent is itself being profiled (same sampled
            // program) -- see `ProfFrame`'s doc for the cross-program
            // scope note.
            if let Some(parent) = self.stack.last_mut()
                && let Some(pprof) = &mut parent.prof
            {
                pprof.child_ticks += ticks;
                pprof.child_wall += wall;
            }
        }
        if f.entered {
            self.host.leave_self();
        }
        if f.creator_frame {
            self.host.leave_creator_frame();
        }
        f
    }

    /// Like [`Interpreter::pop_frame`], for a frame being discarded while
    /// an error unwinds past it (not a normal return): an `atomic fn`
    /// frame rolls its journal scope back here (spec r5 §5.2.1) — exactly
    /// once, since this is the only place a frame is dropped without
    /// having returned.
    fn pop_frame_on_error(&mut self) -> Frame {
        let f = self.pop_frame();
        if let Some(mark) = f.atomic_mark {
            self.host.rollback_atomic(mark);
        }
        f
    }

    /// Drive frames until the outermost call returns (or suspends).
    fn run(&mut self) -> R<Exec> {
        loop {
            match self.step() {
                Ok(Step::Returned(v)) if self.stack.is_empty() => return Ok(Exec::Done(v)),
                Ok(Step::Suspend) => return Ok(Exec::Suspended),
                Ok(_) => continue,
                Err(mut e) => {
                    // spec r5 OBI-32: a catchable error (everything except
                    // tick/call-depth exhaustion) unwinds to the innermost
                    // active `try`/`catch` handler anywhere on this flat
                    // frame stack (this frame, or an outer caller across
                    // however many object/program boundaries D26 crossed
                    // to get here) — not necessarily all the way out.
                    if e.catchable
                        && let Some(idx) = self.find_handler_frame()
                    {
                        while self.stack.len() > idx + 1 {
                            self.pop_frame_on_error();
                        }
                        let (catch_pc, catch_reg) = self.stack[idx]
                            .handlers
                            .pop()
                            .expect("find_handler_frame found a frame with a handler");
                        let caught = e.caught_value();
                        let frame = &mut self.stack[idx];
                        frame.pc = catch_pc;
                        if let Some(r) = catch_reg {
                            frame.regs[r as usize] = caught;
                        }
                        continue;
                    }
                    // Any trace already on `e` came from deeper, non-flat
                    // execution (a driver efun's nested run); append every
                    // live frame of this stack beneath it once, then unwind.
                    // `trace_programs` is extended in lockstep (same
                    // length, same order, OBI-169 CTO review on PR #72
                    // must-fix 1) so the error inbox can attribute to the
                    // *innermost* frame's own declaring program rather
                    // than the entry object's.
                    if e.trace.len() < 12 {
                        let take = 12 - e.trace.len();
                        let names: Vec<String> = self
                            .stack
                            .iter()
                            .rev()
                            .take(take)
                            .map(|f| format!("in {}()", self.frame_name(f)))
                            .collect();
                        let programs: Vec<String> = self
                            .stack
                            .iter()
                            .rev()
                            .take(take)
                            .map(|f| {
                                f.code
                                    .as_ref()
                                    .and_then(|c| c.program_path())
                                    .map(str::to_string)
                                    .unwrap_or_else(|| {
                                        self.base_program.as_deref().unwrap_or("?").to_string()
                                    })
                            })
                            .collect();
                        e.trace.extend(names);
                        e.trace_programs.extend(programs);
                    }
                    while !self.stack.is_empty() {
                        self.pop_frame_on_error();
                    }
                    return Err(e);
                }
            }
        }
    }

    /// The topmost frame index with an active `try`/`catch` handler, if
    /// any (searched innermost-frame-first: the deepest call wins).
    fn find_handler_frame(&self) -> Option<usize> {
        self.stack
            .iter()
            .enumerate()
            .rev()
            .find(|(_, f)| !f.handlers.is_empty())
            .map(|(i, _)| i)
    }

    /// Push a resolved cross-module call, or store its already-computed
    /// value, per the host's [`HostCall`] answer. `creator_guard` is
    /// `Some` for a `CallValue`'s synthetic creator frame (OBI-35
    /// D-S1.7); `None` for every ordinary dispatch.
    fn enter_or_store(
        &mut self,
        hc: HostCall,
        dst: Option<Reg>,
        creator_guard: Option<&GuardSet>,
    ) -> R<Step> {
        match hc {
            HostCall::Done(v) => {
                if let Some(dst) = dst {
                    self.stack.last_mut().unwrap().regs[dst as usize] = v;
                }
            }
            HostCall::Enter {
                code,
                func,
                self_obj,
                args,
                captures,
            } => {
                self.push_call(Some(code), func, args, dst, true, captures, creator_guard)?;
                self.host.enter_self(self_obj);
            }
        }
        Ok(Step::Continue)
    }

    /// Execute one instruction of the top frame. `Returned(v)` means a
    /// frame returned `v` (popped); the caller keeps looping until the
    /// frame stack is empty.
    ///
    /// **OBI-107:** `op` is a borrow out of `code_ops`, a local `Rc<[Op]>`
    /// clone of the running function's instruction stream (a refcount
    /// bump, not a per-`Op` clone — `size_of::<Op>() == 80` before this,
    /// with heap-allocating `Vec` fields on `Call`/`NewMap`/...). `code_ops`
    /// is a plain local, independent of `self`, so borrowing `op` out of it
    /// does not hold any borrow of `self` across the match below, which is
    /// exactly what lets the match arms freely use `&mut self` (host
    /// calls, register writes) while still matching on `op`'s fields by
    /// reference.
    fn step(&mut self) -> R<Step> {
        let func_idx = self.stack.last().unwrap().func;
        let pc = self.stack.last().unwrap().pc as usize;
        let code_ops = self.stack.last().unwrap().code_ops.clone();
        let op = code_ops.get(pc).ok_or_else(|| {
            self.err_with_trace("internal: program counter ran off the end of the function")
        })?;
        self.stack.last_mut().unwrap().pc += 1;

        // Owning read: clones the `Value` (a refcount bump for a heap
        // variant, a plain copy otherwise) — needed wherever the register's
        // content must outlive/leave this register (assigned into another
        // register or a container, handed to a callee, kept past a frame
        // pop, ...).
        macro_rules! reg {
            ($r:expr) => {
                self.stack.last().unwrap().regs[$r as usize].clone()
            };
        }
        // Borrowing read (OBI-107 point 2): no clone at all. Only sound for
        // an immediate read-only use (arithmetic/compare operands, a branch
        // condition) that does not need the value past the expression it's
        // used in.
        macro_rules! reg_ref {
            ($r:expr) => {
                &self.stack.last().unwrap().regs[$r as usize]
            };
        }
        macro_rules! set {
            ($r:expr, $v:expr) => {{
                let v = $v;
                self.stack.last_mut().unwrap().regs[$r as usize] = v;
            }};
        }
        macro_rules! jump {
            ($target:expr) => {{
                self.stack.last_mut().unwrap().pc = $target;
            }};
        }

        match op {
            Op::LoadConst { dst, idx } => {
                let v = self.const_value(*idx);
                set!(*dst, v);
                Ok(Step::Continue)
            }
            Op::Copy { dst, src } => {
                set!(*dst, reg!(*src));
                Ok(Step::Continue)
            }
            Op::LoadSelf { dst } => {
                set!(*dst, Value::Object(self.host.self_object()));
                Ok(Step::Continue)
            }
            Op::LoadGlobal {
                dst, owner, name, ..
            } => {
                let (owner, name) = (
                    self.str_of(*owner).to_string(),
                    self.str_of(*name).to_string(),
                );
                let v = self.host.load_global(&owner, &name)?;
                set!(*dst, v);
                Ok(Step::Continue)
            }
            Op::StoreGlobal {
                owner, name, src, ..
            } => {
                let (owner, name) = (
                    self.str_of(*owner).to_string(),
                    self.str_of(*name).to_string(),
                );
                self.host.store_global(&owner, &name, reg!(*src))?;
                Ok(Step::Continue)
            }
            Op::UnOp { dst, op, kind, src } => {
                let v = self.un_op(*op, *kind, reg_ref!(*src))?;
                set!(*dst, v);
                Ok(Step::Continue)
            }
            Op::BinOp {
                dst,
                op,
                kind,
                a,
                b,
            } => {
                let v = self.bin_op(*op, *kind, reg_ref!(*a), reg_ref!(*b))?;
                set!(*dst, v);
                Ok(Step::Continue)
            }
            Op::NewArray { dst, elems, .. } => {
                let v = Value::array(elems.iter().map(|r| reg!(*r)).collect());
                set!(*dst, v);
                Ok(Step::Continue)
            }
            Op::NewMap { dst, entries, .. } => {
                let mut m = MapData::default();
                for (k, v) in entries {
                    m.insert(reg!(*k), reg!(*v));
                }
                set!(*dst, Value::map(m));
                Ok(Step::Continue)
            }
            Op::Index {
                dst,
                base,
                index,
                kind,
            } => {
                let v = self.index(*kind, reg!(*base), reg!(*index))?;
                set!(*dst, v);
                Ok(Step::Continue)
            }
            Op::IndexSet {
                base,
                index,
                kind,
                src,
            } => {
                // Copy-on-write (r5 D24): mutate the container living in
                // `base`'s own register directly (via `Rc::make_mut`), not a
                // clone pulled out through `reg!`. That is what makes an
                // index-assign on a local visible to the rest of that local's
                // lifetime without any aliasing games — the register *is*
                // the value. Whether the same edit must also be written back
                // to a program variable/other place this register was read
                // from is the place-write lowering codegen must emit
                // (OBI-53); this instruction only ever owns one register.
                let key = reg!(*index);
                let val = reg!(*src);
                // `loom_cow_copies_total{program}` (spec r5 §5.2.1, D24):
                // checked before the write that would trigger the clone, and
                // attributed to whichever module's bytecode is doing it.
                let path = self.cur().path.clone();
                let frame = self.stack.last_mut().unwrap();
                let place = &mut frame.regs[*base as usize];
                let shared = place.is_shared();
                Self::index_set(*kind, place, key, val)?;
                if shared {
                    self.host.record_cow_copy(&path);
                }
                Ok(Step::Continue)
            }
            Op::IndexSetGlobal {
                owner,
                name,
                index,
                kind,
                src,
            } => {
                // The real "take" (OBI-108 CTO review of PR #8): unlike
                // `Op::IndexSet`, codegen only ever emits this for a plain
                // `global[i] = v`/`global[i] op= v`, one level deep, never
                // for a value also bound to a live local. That means
                // `Host::take_global` handing back a uniquely-owned value
                // (not a clone) is sound: nothing else can observe it
                // between the take and the matching commit/restore below,
                // both of which run before this instruction returns —
                // through a Weft `try`/`catch`, a full unwind out of the
                // call chain, or a tick/budget abort alike.
                let (owner_s, name_s) = (
                    self.str_of(*owner).to_string(),
                    self.str_of(*name).to_string(),
                );
                let key = reg!(*index);
                let val = reg!(*src);
                let mut container = self.host.take_global(&owner_s, &name_s)?;
                // CTO review of PR #47 (OBI-108): captured *before* any
                // mutation below, so `commit_global`/`restore_global` can
                // correct the per-object memory total for exactly this
                // write. `take_global` must not touch that total itself —
                // `reserve_global_growth` right below needs it to still
                // include this container's own bytes (the pre-take total),
                // or an element write bypasses the quota entirely.
                let old_bytes = heap::cost(&container);
                let shared = container.is_shared();
                // CTO re-review (OBI-108, after OBI-80 deep accounting
                // landed): with *deep* cost, not just OBI-78's shallow
                // slot count, an array element **replace** can grow the
                // container too (`g[0] = big_local_array`), and so can a
                // map key **replace** (`m["k"] = big`), not only a brand
                // new map key — the exact case #18 (OBI-80) closed for
                // whole-var writes would otherwise reopen here.
                // `index_growth` computes the exact `cost(new) -
                // cost(old)` this specific write is about to apply to
                // `container`'s cached `deep_bytes` (0 for anything
                // `index_set` below is instead going to reject: an
                // out-of-range index or a bad key type never mutates, so
                // there is nothing to reserve for it) — reserved *before*
                // mutating, the same way the array bounds check already
                // happens before its own mutation, so a rejected write is
                // simply never applied, nothing to undo.
                let growth = Self::index_growth(*kind, &container, &key, &val);
                if growth > 0
                    && let Err(e) = self.host.reserve_global_growth(&owner_s, &name_s, growth)
                {
                    self.host
                        .restore_global(&owner_s, &name_s, old_bytes, container)?;
                    return Err(e);
                }
                match Self::index_set(*kind, &mut container, key, val) {
                    Ok(()) => {
                        self.host
                            .commit_global(&owner_s, &name_s, old_bytes, container)?;
                        if shared {
                            let path = self.cur().path.clone();
                            self.host.record_cow_copy(&path);
                        }
                        Ok(Step::Continue)
                    }
                    Err(e) => {
                        // `index_set` validates (bounds/key type) before it
                        // ever mutates `container`, so on `Err` it is still
                        // exactly what `take_global` handed out: putting it
                        // straight back undoes the take with no semantic
                        // change (spec r5 OBI-108 acceptance: an out-of-
                        // range index on a global array leaves the global
                        // intact).
                        self.host
                            .restore_global(&owner_s, &name_s, old_bytes, container)?;
                        Err(e)
                    }
                }
            }
            Op::IterElems { dst, src, kind, .. } => {
                let v = self.iter_elems(*kind, reg!(*src))?;
                set!(*dst, v);
                Ok(Step::Continue)
            }
            Op::ToStr { dst, src } => {
                let s = self.show(reg_ref!(*src));
                set!(*dst, Value::str(&s));
                Ok(Step::Continue)
            }
            Op::Cast { dst, src, ty } => {
                let v = reg!(*src);
                if !ty_accepts(ty, &v) {
                    return Err(self.err_with_trace(format!(
                        "expected {}, got {}",
                        ty_name(ty),
                        v.type_name()
                    )));
                }
                set!(*dst, v);
                Ok(Step::Continue)
            }
            Op::Call { dst, callee, args } => {
                let dst = *dst;
                let argv: Vec<Value> = args.iter().map(|r| reg!(*r)).collect();
                match callee {
                    CalleeOp::Static { program, name }
                        if self.str_of(*program) == &*self.cur().path =>
                    {
                        let name = self.str_of(*name).to_string();
                        let idx = self
                            .cur()
                            .functions
                            .iter()
                            .position(|f| self.str_of(f.name) == name)
                            .ok_or_else(|| self.err_with_trace(format!("no function `{name}`")))?;
                        // Same module as the caller: share its code handle.
                        let code = self.stack.last().unwrap().code.clone();
                        self.push_call(code, idx as u32, argv, dst, false, Vec::new(), None)?;
                        Ok(Step::Continue)
                    }
                    CalleeOp::Static { program, name } => {
                        let (program, name) = (*program, *name);
                        let site = CallSite {
                            code: self.code_identity(self.stack.last().unwrap()),
                            func: func_idx,
                            pc: pc as u32,
                        };
                        match self.host.dispatch_cached(site, None, argv) {
                            Ok(hc) => self.enter_or_store(hc, dst, None),
                            Err(argv) => {
                                let (program, name) = (
                                    self.str_of(program).to_string(),
                                    self.str_of(name).to_string(),
                                );
                                let hc = self.host.dispatch(
                                    site,
                                    CallTarget::Static {
                                        program: &program,
                                        name: &name,
                                    },
                                    argv,
                                )?;
                                self.enter_or_store(hc, dst, None)
                            }
                        }
                    }
                    CalleeOp::Virtual { name } => {
                        let name = *name;
                        let site = CallSite {
                            code: self.code_identity(self.stack.last().unwrap()),
                            func: func_idx,
                            pc: pc as u32,
                        };
                        match self.host.dispatch_cached(site, None, argv) {
                            Ok(hc) => self.enter_or_store(hc, dst, None),
                            Err(argv) => {
                                let name = self.str_of(name).to_string();
                                let hc = self.host.dispatch(
                                    site,
                                    CallTarget::Virtual { name: &name },
                                    argv,
                                )?;
                                self.enter_or_store(hc, dst, None)
                            }
                        }
                    }
                }
            }
            Op::CallOther {
                dst,
                recv,
                name,
                args,
            } => {
                let dst = *dst;
                let name = *name;
                let recv = reg!(*recv);
                let argv: Vec<Value> = args.iter().map(|r| reg!(*r)).collect();
                let site = CallSite {
                    code: self.code_identity(self.stack.last().unwrap()),
                    func: func_idx,
                    pc: pc as u32,
                };
                match self.host.dispatch_cached(site, Some(&recv), argv) {
                    Ok(hc) => self.enter_or_store(hc, Some(dst), None),
                    Err(argv) => {
                        let name = self.str_of(name).to_string();
                        let hc = self.host.dispatch(
                            site,
                            CallTarget::Other { recv, name: &name },
                            argv,
                        )?;
                        self.enter_or_store(hc, Some(dst), None)
                    }
                }
            }
            Op::CallEfun { dst, name, args } => {
                let dst = *dst;
                let argv: Vec<Value> = args.iter().map(|r| reg!(*r)).collect();
                let name_s = self.str_of(*name).to_string();
                // Spec §5.9: efuns declare a tick cost (`crate::efuns::
                // tick_cost`); charge it against the same budget
                // `Op::TickCheck` meters, before running the efun, so a
                // loop of expensive efun calls (e.g. `compile_object`)
                // exhausts a frame's ticks sooner than the same loop of
                // cheap ones (e.g. `len`) even with no `TickCheck` between
                // iterations.
                self.charge_ticks(crate::efuns::tick_cost(&name_s).unwrap_or(1) as u64)?;
                let v = match self.call_efun(&name_s, &argv) {
                    Some(v) => v?,
                    None => {
                        let r = self.host.call_efun(&name_s, argv);
                        let extra = self.host.take_extra_ticks();
                        self.charge_ticks(extra)?;
                        r?
                    }
                };
                if let Some(dst) = dst {
                    set!(dst, v);
                }
                Ok(Step::Continue)
            }
            Op::Jump { target } => {
                jump!(*target);
                Ok(Step::Continue)
            }
            Op::Branch {
                cond,
                then_target,
                else_target,
            } => {
                let Value::Bool(b) = reg_ref!(*cond) else {
                    return Err(self.err_with_trace("internal: branch condition was not bool"));
                };
                jump!(if *b { *then_target } else { *else_target });
                Ok(Step::Continue)
            }
            Op::Return { src } => {
                let v = match src {
                    Some(r) => reg!(*r),
                    None => Value::Null,
                };
                let frame = self.pop_frame();
                if let Some(mark) = frame.atomic_mark {
                    self.host.commit_atomic(mark);
                }
                if let Some(caller) = self.stack.last_mut()
                    && let Some(dst) = frame.ret_into
                {
                    caller.regs[dst as usize] = v.clone();
                }
                Ok(Step::Returned(v))
            }
            Op::TickCheck => {
                self.tick()?;
                if let Some(n) = self.suspend_after.as_mut() {
                    *n -= 1;
                    if *n == 0 {
                        self.suspend_after = None;
                        return Ok(Step::Suspend);
                    }
                }
                Ok(Step::Continue)
            }
            Op::Throw { src } => {
                let v = reg!(*src);
                let msg = self.show(&v);
                Err(RtError::thrown(v, msg))
            }
            Op::PushHandler {
                catch_pc,
                catch_reg,
            } => {
                self.stack
                    .last_mut()
                    .unwrap()
                    .handlers
                    .push((*catch_pc, *catch_reg));
                Ok(Step::Continue)
            }
            Op::PopHandler => {
                self.stack.last_mut().unwrap().handlers.pop();
                Ok(Step::Continue)
            }
            Op::MakeFn { dst, callee } => {
                let callee = match callee {
                    CalleeOp::Virtual { name } => Callee::Virtual {
                        name: Rc::from(self.str_of(*name)),
                    },
                    CalleeOp::Static { program, name } => Callee::Static {
                        program: Rc::from(self.str_of(*program)),
                        name: Rc::from(self.str_of(*name)),
                    },
                };
                let creator = self.host.self_object();
                let guard = self.host.current_guard();
                let quota_uid = self.host.current_uid();
                let v = Value::function(FunctionValue {
                    creator,
                    body: FnBody::Named(callee),
                    guard,
                    quota_uid,
                });
                set!(*dst, v);
                Ok(Step::Continue)
            }
            Op::MakeClosure {
                dst,
                func,
                captures,
            } => {
                let captured: Vec<Value> = captures.iter().map(|r| reg!(*r)).collect();
                // The program whose function table `func` indexes: the
                // running frame's own code, or the host's base program for
                // a base-module frame. Never simply the creator object's
                // program, which is wrong for inherited code (OBI-37).
                let code = match self.stack.last().and_then(|f| f.code.clone()) {
                    Some(c) => c,
                    None => self.host.current_program()?,
                };
                let program_version = code.version();
                let creator = self.host.self_object();
                let guard = self.host.current_guard();
                let quota_uid = self.host.current_uid();
                let v = Value::function(FunctionValue {
                    creator,
                    body: FnBody::Closure {
                        code,
                        func: *func,
                        captures: captured,
                        program_version,
                    },
                    guard,
                    quota_uid,
                });
                set!(*dst, v);
                Ok(Step::Continue)
            }
            Op::CallValue { dst, func, args } => {
                let fval = reg!(*func);
                let argv: Vec<Value> = args.iter().map(|r| reg!(*r)).collect();
                let Some(f) = fval.as_fn() else {
                    return Err(self.err_with_trace(format!(
                        "cannot call a {} as a function",
                        fval.type_name()
                    )));
                };
                let creator = f.creator;
                let body = f.body.clone();
                let guard = f.guard.clone();
                let hc = self.host.dispatch_value(creator, &body, argv)?;
                self.enter_or_store(hc, *dst, Some(&guard))
            }
        }
    }

    fn const_value(&self, idx: u32) -> Value {
        match &self.cur().consts[idx as usize] {
            ConstValue::Int(n) => Value::Int(*n),
            ConstValue::Float(x) => Value::Float(*x),
            ConstValue::Bool(b) => Value::Bool(*b),
            ConstValue::Str(s) => Value::str(self.str_of(*s)),
            ConstValue::Null => Value::Null,
        }
    }

    pub fn show(&self, v: &Value) -> String {
        crate::bcvm::heap::display(v, &|_id| "<object>".to_string())
    }

    /// Efuns fundamental enough (no privilege gate, pure over values) to
    /// inline in the interpreter rather than round-trip through [`Host`]:
    /// `len` backs every `for` loop's bound check (see codegen's `IterElems`
    /// lowering), so it is on the hot path; `split`/`join`/`keys`/`trim`/
    /// `lower`/`to_int` are pure string/map efuns (spec §5.5; `lower`/
    /// `to_int` added OBI-85) kept here so a self-contained program (no
    /// `World`/`Host` needed) can still run real `.wf` string processing
    /// end to end — see the `bcvm::compile` integration test.
    fn call_efun(&self, name: &str, args: &[Value]) -> Option<R<Value>> {
        fn len_of(v: &Value) -> Option<i64> {
            if let Some(s) = v.as_str() {
                Some(s.chars().count() as i64)
            } else if let Some(a) = v.as_array() {
                Some(a.len() as i64)
            } else {
                v.as_map().map(|m| m.entries.len() as i64)
            }
        }
        match name {
            "len" => Some(match args.first() {
                Some(v) => match len_of(v) {
                    Some(n) => Ok(Value::Int(n)),
                    None => {
                        Err(self.err_with_trace(format!("len(): {} has no length", v.type_name())))
                    }
                },
                None => Err(self.err_with_trace("len(): missing argument")),
            }),
            "split" => Some((|| {
                let s = args[0]
                    .as_str()
                    .ok_or_else(|| self.err_with_trace("split(): expected string"))?;
                let sep = args[1]
                    .as_str()
                    .ok_or_else(|| self.err_with_trace("split(): expected string"))?;
                if sep.is_empty() {
                    return Err(self.err_with_trace("split(): separator must not be empty"));
                }
                Ok(Value::array(s.split(sep).map(Value::str).collect()))
            })()),
            "join" => Some((|| {
                let a = args[0].as_array().ok_or_else(|| {
                    self.err_with_trace(format!(
                        "join(): expected array, got {}",
                        args[0].type_name()
                    ))
                })?;
                let sep = args[1]
                    .as_str()
                    .ok_or_else(|| self.err_with_trace("join(): expected string"))?;
                let mut parts = Vec::with_capacity(a.len());
                for v in a {
                    let s = v.as_str().ok_or_else(|| {
                        self.err_with_trace(format!(
                            "join(): expected an array of strings, found {}",
                            v.type_name()
                        ))
                    })?;
                    parts.push(s.to_string());
                }
                Ok(Value::str(&parts.join(sep)))
            })()),
            "keys" => Some(match args[0].as_map() {
                Some(m) => Ok(Value::array(
                    m.entries.iter().map(|(k, _)| k.clone()).collect(),
                )),
                None => Err(self
                    .err_with_trace(format!("keys(): expected map, got {}", args[0].type_name()))),
            }),
            "trim" => Some(match args[0].as_str() {
                Some(s) => Ok(Value::str(s.trim())),
                None => Err(self.err_with_trace("trim(): expected string")),
            }),
            "lower" => Some(match args[0].as_str() {
                Some(s) => Ok(Value::str(&s.to_lowercase())),
                None => Err(self.err_with_trace("lower(): expected string")),
            }),
            "to_int" => Some(match args[0].as_str() {
                Some(s) => Ok(parse_to_int(s).map_or(Value::Null, Value::Int)),
                None => Err(self.err_with_trace("to_int(): expected string")),
            }),
            _ => None,
        }
    }

    fn un_op(&self, op: UnOp, _kind: OpKind, v: &Value) -> R<Value> {
        match (op, v) {
            (UnOp::Neg, Value::Int(n)) => n
                .checked_neg()
                .map(Value::Int)
                .ok_or_else(|| self.err_with_trace("integer overflow")),
            (UnOp::Neg, Value::Float(x)) => Ok(Value::Float(-x)),
            (UnOp::Not, Value::Bool(b)) => Ok(Value::Bool(!*b)),
            (op, v) => {
                Err(self.err_with_trace(format!("cannot apply {op:?} to {}", v.type_name())))
            }
        }
    }

    fn bin_op(&self, op: BinOp, _kind: OpKind, l: &Value, r: &Value) -> R<Value> {
        use Value::*;
        let overflow = || self.err_with_trace("integer overflow");
        Ok(match (op, l, r) {
            (BinOp::Add, Int(a), Int(b)) => Int(a.checked_add(*b).ok_or_else(overflow)?),
            (BinOp::Sub, Int(a), Int(b)) => Int(a.checked_sub(*b).ok_or_else(overflow)?),
            (BinOp::Mul, Int(a), Int(b)) => Int(a.checked_mul(*b).ok_or_else(overflow)?),
            (BinOp::Div | BinOp::Rem, Int(_), Int(0)) => {
                return Err(self.err_with_trace("division by zero"));
            }
            (BinOp::Div, Int(a), Int(b)) => Int(a.checked_div(*b).ok_or_else(overflow)?),
            (BinOp::Rem, Int(a), Int(b)) => Int(a.checked_rem(*b).ok_or_else(overflow)?),
            (BinOp::Add, Float(a), Float(b)) => Float(a + b),
            (BinOp::Sub, Float(a), Float(b)) => Float(a - b),
            (BinOp::Mul, Float(a), Float(b)) => Float(a * b),
            (BinOp::Div, Float(a), Float(b)) => Float(a / b),
            (BinOp::Add, a, b) if a.as_str().is_some() && b.as_str().is_some() => {
                let mut s =
                    String::with_capacity(a.as_str().unwrap().len() + b.as_str().unwrap().len());
                s.push_str(a.as_str().unwrap());
                s.push_str(b.as_str().unwrap());
                Value::str(&s)
            }
            (BinOp::Add, a, b) if a.as_array().is_some() && b.as_array().is_some() => {
                let mut v = a.as_array().unwrap().to_vec();
                v.extend(b.as_array().unwrap().iter().cloned());
                Value::array(v)
            }
            (BinOp::Eq, _, _) => Bool(l.equals(r)),
            (BinOp::Ne, _, _) => Bool(!l.equals(r)),
            (BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge, Int(a), Int(b)) => {
                cmp_bool(op, a.cmp(b))
            }
            (BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge, a, b)
                if a.as_str().is_some() && b.as_str().is_some() =>
            {
                cmp_bool(op, a.as_str().unwrap().cmp(b.as_str().unwrap()))
            }
            (BinOp::In, k, v) if v.as_array().is_some() => {
                Bool(v.as_array().unwrap().iter().any(|x| x.equals(k)))
            }
            (BinOp::In, k, v) if v.as_map().is_some() => Bool(v.as_map().unwrap().contains(k)),
            (BinOp::In, a, b) if a.as_str().is_some() && b.as_str().is_some() => {
                Bool(b.as_str().unwrap().contains(a.as_str().unwrap()))
            }
            _ => {
                return Err(self.err_with_trace(format!(
                    "cannot apply {op:?} to {} and {}",
                    l.type_name(),
                    r.type_name()
                )));
            }
        })
    }

    fn array_index(&self, key: &Value, len: usize) -> R<usize> {
        match key {
            Value::Int(i) if *i >= 0 && (*i as u64) < len as u64 => Ok(*i as usize),
            Value::Int(i) => {
                Err(self.err_with_trace(format!("index {i} out of range (length {len})")))
            }
            v => {
                Err(self.err_with_trace(format!("array index must be int, got {}", v.type_name())))
            }
        }
    }

    fn index(&self, kind: IndexKind, base: Value, key: Value) -> R<Value> {
        match kind {
            IndexKind::Array => {
                let a = base
                    .as_array()
                    .ok_or_else(|| self.err_with_trace("internal: Index(Array) on non-array"))?;
                let i = self.array_index(&key, a.len())?;
                Ok(a[i].clone())
            }
            IndexKind::String => {
                let s = base
                    .as_str()
                    .ok_or_else(|| self.err_with_trace("internal: Index(String) on non-string"))?;
                let n = s.chars().count();
                let i = self.array_index(&key, n)?;
                Ok(s.chars()
                    .nth(i)
                    .map_or(Value::Null, |c| Value::str(c.encode_utf8(&mut [0; 4]))))
            }
            IndexKind::Map | IndexKind::MapPresent => {
                let m = base
                    .as_map()
                    .ok_or_else(|| self.err_with_trace("internal: Index(Map) on non-map"))?;
                Ok(m.get(&key).cloned().unwrap_or(Value::Null))
            }
            IndexKind::Dyn => {
                if let Some(a) = base.as_array() {
                    let i = self.array_index(&key, a.len())?;
                    Ok(a[i].clone())
                } else if let Some(m) = base.as_map() {
                    Ok(m.get(&key).cloned().unwrap_or(Value::Null))
                } else if let Some(s) = base.as_str() {
                    let n = s.chars().count();
                    let i = self.array_index(&key, n)?;
                    Ok(s.chars()
                        .nth(i)
                        .map_or(Value::Null, |c| Value::str(c.encode_utf8(&mut [0; 4]))))
                } else {
                    Err(self.err_with_trace(format!("cannot index {}", base.type_name())))
                }
            }
        }
    }

    /// Copy-on-write index-assign (r5 D24): `place` is the exact register
    /// slot holding the container (see the `Op::IndexSet` dispatch above),
    /// mutated in place via `Value::array_mut`/`map_mut` (`Rc::make_mut`
    /// under the hood — clones the buffer only if it is shared).
    fn index_set(kind: IndexKind, place: &mut Value, key: Value, val: Value) -> R<()> {
        let err = |msg: String| RtError::new(msg);
        match kind {
            IndexKind::Array | IndexKind::Dyn if place.as_array().is_some() => {
                let len = place.as_array().unwrap().len();
                let i = match &key {
                    Value::Int(i) if *i >= 0 && (*i as u64) < len as u64 => *i as usize,
                    Value::Int(i) => {
                        return Err(err(format!("index {i} out of range (length {len})")));
                    }
                    v => {
                        return Err(err(format!(
                            "array index must be int, got {}",
                            v.type_name()
                        )));
                    }
                };
                place.array_mut().unwrap().set(i, val);
                Ok(())
            }
            IndexKind::Map | IndexKind::MapPresent | IndexKind::Dyn if place.as_map().is_some() => {
                if !key.is_valid_key() {
                    return Err(err(format!(
                        "map keys must be int, string, bool or object, got {}",
                        key.type_name()
                    )));
                }
                place.map_mut().unwrap().insert(key, val);
                Ok(())
            }
            _ => Err(err(format!(
                "cannot assign into {} (need array or map)",
                place.type_name()
            ))),
        }
    }

    /// The exact `heap::cost` delta an `Op::IndexSetGlobal` write is about
    /// to apply to `place`'s (a taken-out global container's) cached deep
    /// byte total, computed *before* mutating (CTO re-review, OBI-108,
    /// after OBI-80 deep accounting landed): with deep accounting an array
    /// element **replace** can grow the container (`g[0] = big_array`),
    /// not just a map's brand new key, and a map key **replace** can grow
    /// it too (the new value may cost more than the one it overwrites) --
    /// both need the same before-mutation quota reservation an out-of-
    /// range index or a fresh map key already got. Mirrors exactly what
    /// `ArrayData::set`/`MapData::insert` (see `heap.rs`) will actually do
    /// to `deep_bytes`, so the reservation this drives is exact, never an
    /// approximation -- and always `0` (nothing to reserve) for anything
    /// `Self::index_set` is instead about to reject without mutating
    /// (out-of-range index, wrong key type, not an array/map): there is no
    /// growth to charge for a write that never happens.
    fn index_growth(kind: IndexKind, place: &Value, key: &Value, val: &Value) -> u64 {
        let new_cost = heap::cost(val);
        match kind {
            IndexKind::Array | IndexKind::Dyn if place.as_array().is_some() => {
                let Value::Int(i) = key else {
                    return 0;
                };
                let Some(items) = place.as_array() else {
                    return 0;
                };
                let Some(old) = usize::try_from(*i).ok().and_then(|i| items.get(i)) else {
                    return 0;
                };
                new_cost.saturating_sub(heap::cost(old))
            }
            IndexKind::Map | IndexKind::MapPresent | IndexKind::Dyn if place.as_map().is_some() => {
                if !key.is_valid_key() {
                    return 0;
                }
                let Some(m) = place.as_map() else {
                    return 0;
                };
                match m.get(key) {
                    // Key already present: a replace, same growth an
                    // array element replace gets -- the delta between the
                    // new and old value's own cost.
                    Some(old) => new_cost.saturating_sub(heap::cost(old)),
                    // A genuinely new key: `MapData::insert` adds the full
                    // cost of *both* the key and the value (see `heap.rs`
                    // `MapData::insert`'s new-key branch), not just the
                    // value.
                    None => new_cost.saturating_add(heap::cost(key)),
                }
            }
            _ => 0,
        }
    }

    fn iter_elems(&self, kind: IterKind, src: Value) -> R<Value> {
        match kind {
            IterKind::Array => Ok(Value::array(
                src.as_array()
                    .ok_or_else(|| self.err_with_trace("`for` needs an array"))?
                    .to_vec(),
            )),
            IterKind::MapKeys => Ok(Value::array(
                src.as_map()
                    .ok_or_else(|| self.err_with_trace("`for` needs a map"))?
                    .entries
                    .iter()
                    .map(|(k, _)| k.clone())
                    .collect(),
            )),
            IterKind::Dyn => {
                if let Some(a) = src.as_array() {
                    Ok(Value::array(a.to_vec()))
                } else if let Some(m) = src.as_map() {
                    Ok(Value::array(
                        m.entries.iter().map(|(k, _)| k.clone()).collect(),
                    ))
                } else {
                    Err(self.err_with_trace(format!(
                        "`for` needs an array or map, got {}",
                        src.type_name()
                    )))
                }
            }
        }
    }
}

fn cmp_bool(op: BinOp, ord: std::cmp::Ordering) -> Value {
    Value::Bool(match op {
        BinOp::Lt => ord.is_lt(),
        BinOp::Le => ord.is_le(),
        BinOp::Gt => ord.is_gt(),
        _ => ord.is_ge(),
    })
}

/// `to_int()` (spec §5.5, OBI-85): a trimmed decimal with an optional
/// leading `-` (not `+`); `None` if it doesn't parse or overflows `i64`.
fn parse_to_int(s: &str) -> Option<i64> {
    let t = s.trim();
    if t.is_empty() || t.starts_with('+') {
        return None;
    }
    t.parse::<i64>().ok()
}

fn ty_name(ty: &Ty) -> String {
    format!("{ty:?}")
}

fn ty_accepts(ty: &Ty, v: &Value) -> bool {
    match (ty, v) {
        (Ty::Any, _) => true,
        (Ty::Int, Value::Int(_)) => true,
        (Ty::Float, Value::Float(_)) => true,
        (Ty::Bool, Value::Bool(_)) => true,
        (Ty::Null, Value::Null) => true,
        (Ty::Object, Value::Object(_)) => true,
        (Ty::String, v) => v.as_str().is_some(),
        (Ty::Array(_), v) => v.as_array().is_some(),
        (Ty::Map(..), v) => v.as_map().is_some(),
        (Ty::Optional(inner), Value::Null) => {
            let _ = inner;
            true
        }
        (Ty::Optional(inner), v) => ty_accepts(inner, v),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_compiler::bytecode::{ConstValue, FunctionCode};

    /// A `Host` that cannot resolve anything outside the module: enough to
    /// run self-contained arithmetic/recursion tests.
    struct NoHost;
    impl Host for NoHost {
        fn self_object(&self) -> ObjectId {
            ObjectId {
                index: 0,
                generation: 0,
            }
        }
        fn call_static(&mut self, program: &str, name: &str, _args: Vec<Value>) -> R<Value> {
            Err(RtError::new(format!(
                "no such static call {program}::{name}"
            )))
        }
        fn call_virtual(&mut self, name: &str, _args: Vec<Value>) -> R<Value> {
            Err(RtError::new(format!("no such function `{name}`")))
        }
        fn call_other(&mut self, _recv: Value, name: &str, _args: Vec<Value>) -> R<Value> {
            Err(RtError::new(format!("no such function `{name}`")))
        }
        fn call_efun(&mut self, name: &str, _args: Vec<Value>) -> R<Value> {
            Err(RtError::new(format!("unknown efun `{name}`")))
        }
        fn load_global(&mut self, _owner: &str, _name: &str) -> R<Value> {
            Ok(Value::Null)
        }
        fn store_global(&mut self, _owner: &str, _name: &str, _v: Value) -> R<()> {
            Ok(())
        }
    }

    /// `fn countdown(n: int) -> int { if n <= 0 { return n; } return
    /// countdown(n - 1); }` — a self-recursive function, hand-assembled, to
    /// exercise the call-stack path without needing a full codegen
    /// pipeline hookup (that's the World integration follow-up).
    fn countdown_module(max_depth_check: bool) -> Module {
        // Registers: 0 = n (param), 1 = 0 (const), 2 = cond, 3 = one, 4 = n-1, 5 = result
        let code = vec![
            Op::LoadConst { dst: 1, idx: 0 }, // 0
            Op::BinOp {
                dst: 2,
                op: BinOp::Le,
                kind: OpKind::Int,
                a: 0,
                b: 1,
            }, // 1
            Op::Branch {
                cond: 2,
                then_target: 3,
                else_target: 5,
            }, // 2
            Op::Return { src: Some(0) },      // 3 (then: base case)
            Op::Jump { target: 3 },           // 4 unreachable pad
            Op::LoadConst { dst: 3, idx: 1 }, // 5: one = 1
            Op::BinOp {
                dst: 4,
                op: BinOp::Sub,
                kind: OpKind::Int,
                a: 0,
                b: 3,
            }, // 6: n - 1
            Op::TickCheck,                    // 7
            Op::Call {
                dst: Some(5),
                callee: CalleeOp::Static {
                    program: 0,
                    name: 1,
                },
                args: vec![4],
            }, // 8
            Op::Return { src: Some(5) },      // 9
        ];
        let _ = max_depth_check;
        Module {
            path: std::rc::Rc::from("/test/countdown"),
            strings: vec![
                std::rc::Rc::from("/test/countdown"),
                std::rc::Rc::from("countdown"),
            ],
            consts: vec![ConstValue::Int(0), ConstValue::Int(1)],
            functions: vec![FunctionCode {
                name: 1,
                atomic: false,
                params: 1,
                min_arity: 1,
                ret: Ty::Int,
                reg_types: vec![Ty::Int; 6],
                entry_points: vec![0],
                code: code.into(),
                capture_targets: Vec::new(),
            }],
        }
    }

    #[test]
    fn recursive_call_uses_heap_stack_not_native_recursion() {
        let limits = Limits {
            max_depth: 20_000,
            ..Limits::default()
        };

        // Run on a thread with a tiny (64 KiB) native stack: if the
        // interpreter ever recursed on the Rust stack for a Weft call, this
        // would abort the process (stack overflow) long before 10,000
        // frames. Succeeding here is the D-P1.3 evidence. Everything the
        // VM touches (`Module`, `Value`) holds a non-`Send` `Rc`, so the
        // module is built *inside* the spawned closure and only a plain
        // `Result<i64, String>` crosses the thread boundary.
        let result = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || {
                let module = countdown_module(false);
                let mut host = NoHost;
                let mut ticks = 1_000_000u64;
                let mut interp = Interpreter::new(&module, &mut host, &limits, &mut ticks);
                match interp.call("countdown", vec![Value::Int(10_000)]) {
                    Ok(Value::Int(n)) => Ok(n),
                    Ok(v) => Err(format!("unexpected {v:?}")),
                    Err(e) => Err(e.message),
                }
            })
            .unwrap()
            .join()
            .unwrap();

        assert_eq!(result, Ok(0));
    }

    #[test]
    fn recursion_past_the_weft_depth_limit_is_a_weft_error_not_a_crash() {
        let limits = Limits {
            max_depth: 64,
            ..Limits::default()
        };

        let result = std::thread::Builder::new()
            .stack_size(64 * 1024) // default-ish small stack (§ test spec: "default-stack thread")
            .spawn(move || {
                let module = countdown_module(false);
                let mut host = NoHost;
                let mut ticks = 1_000_000u64;
                let mut interp = Interpreter::new(&module, &mut host, &limits, &mut ticks);
                match interp.call("countdown", vec![Value::Int(10_000)]) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e.message),
                }
            })
            .unwrap()
            .join()
            .unwrap();

        let message = result.unwrap_err();
        assert!(message.contains("Too deep recursion"), "{message}");
    }

    /// Spec Phase 2 B5 (OBI-170) integration test: a `Host` that answers
    /// `profiling_active`/`profile_record` like `RegistryHost` does, wired
    /// straight to the interpreter's `push_call`/`pop_frame` hooks --
    /// proves the VM-level wiring (not just `crate::profiler::Profiler`'s
    /// own unit tests) actually counts calls/ticks for a real, hot,
    /// recursive Weft function (`countdown`, this module's existing
    /// fixture) end to end.
    struct ProfHost {
        inner: NoHost,
        target: &'static str,
        calls: std::cell::RefCell<std::collections::HashMap<String, (u64, u64, u64)>>,
    }
    impl Host for ProfHost {
        fn self_object(&self) -> ObjectId {
            self.inner.self_object()
        }
        fn call_static(&mut self, program: &str, name: &str, args: Vec<Value>) -> R<Value> {
            self.inner.call_static(program, name, args)
        }
        fn call_virtual(&mut self, name: &str, args: Vec<Value>) -> R<Value> {
            self.inner.call_virtual(name, args)
        }
        fn call_other(&mut self, recv: Value, name: &str, args: Vec<Value>) -> R<Value> {
            self.inner.call_other(recv, name, args)
        }
        fn call_efun(&mut self, name: &str, args: Vec<Value>) -> R<Value> {
            self.inner.call_efun(name, args)
        }
        fn load_global(&mut self, owner: &str, name: &str) -> R<Value> {
            self.inner.load_global(owner, name)
        }
        fn store_global(&mut self, owner: &str, name: &str, v: Value) -> R<()> {
            self.inner.store_global(owner, name, v)
        }
        fn profiling_active(&self, program: &str) -> bool {
            program == self.target
        }
        fn profile_record(
            &mut self,
            _program: &str,
            function: &str,
            ticks: u64,
            self_ticks: u64,
            _wall: std::time::Duration,
            _self_wall: std::time::Duration,
        ) {
            let mut calls = self.calls.borrow_mut();
            let entry = calls.entry(function.to_string()).or_insert((0, 0, 0));
            entry.0 += 1;
            entry.1 += ticks;
            entry.2 += self_ticks;
        }
    }

    #[test]
    fn profiler_hook_counts_calls_and_ticks_for_a_hot_recursive_function() {
        let module = countdown_module(false);
        let mut host = ProfHost {
            inner: NoHost,
            target: "/test/countdown",
            calls: std::cell::RefCell::new(std::collections::HashMap::new()),
        };
        let limits = Limits::default();
        let total_ticks = 1_000_000u64;
        let mut ticks = total_ticks;
        let mut interp = Interpreter::new(&module, &mut host, &limits, &mut ticks);
        let result = interp.call("countdown", vec![Value::Int(50)]);
        match result.unwrap() {
            Value::Int(0) => {}
            other => panic!("expected Int(0), got {other:?}"),
        }
        let calls = host.calls.borrow();
        let (call_count, inclusive_ticks, self_ticks) =
            *calls.get("countdown").expect("countdown was profiled");
        // One top-level call plus 50 recursive calls down to the base case.
        assert_eq!(call_count, 51);
        assert!(self_ticks > 0, "expected nonzero self ticks charged");
        // CTO review (OBI-170, PR #67, must-fix 2): the old, inclusive-
        // only accounting summed every recursive frame's *inclusive*
        // ticks, which for 51 nested frames could run to roughly 51x the
        // window's own total -- self ticks summed across every call must
        // never exceed what the whole window actually charged.
        let ticks_used = total_ticks - ticks;
        assert!(
            self_ticks <= ticks_used,
            "self ticks ({self_ticks}) must not exceed the window's total ({ticks_used})"
        );
        // Inclusive is still reported, and for genuine recursion is
        // strictly larger than self once there's more than one frame.
        assert!(inclusive_ticks >= self_ticks);
    }

    #[test]
    fn tick_metering_stops_a_runaway_call() {
        let module = countdown_module(false);
        let mut host = NoHost;
        let limits = Limits {
            max_depth: 20_000,
            ..Limits::default()
        };
        let mut ticks = 5u64; // far fewer ticks than the 10,000 needed

        let mut interp = Interpreter::new(&module, &mut host, &limits, &mut ticks);
        let err = interp
            .call("countdown", vec![Value::Int(10_000)])
            .unwrap_err();
        assert!(
            err.message.contains("Too long evaluation"),
            "{}",
            err.message
        );
    }

    #[test]
    fn error_carries_a_stack_trace() {
        let module = countdown_module(false);
        let mut host = NoHost;
        let limits = Limits {
            max_depth: 3,
            ..Limits::default()
        }; // recursion will exceed this quickly
        let mut ticks = 1_000_000u64;

        let mut interp = Interpreter::new(&module, &mut host, &limits, &mut ticks);
        let err = interp.call("countdown", vec![Value::Int(10)]).unwrap_err();
        assert!(!err.trace.is_empty());
        assert!(err.trace.iter().all(|t| t.contains("countdown")));
    }

    /// r5 D24: `IndexSet` writes into the exact register that holds the
    /// container (copy-on-write, in place once uniquely owned) rather than
    /// through a shared `RefCell`. A one-function module keeps a local
    /// array in reg 0, a second array in reg 1 that starts out sharing the
    /// same buffer, writes `arr[0] = 99` into reg 0, and returns both so
    /// the test can check the aliased copy in reg 1 was not mutated.
    #[test]
    fn index_set_is_copy_on_write_not_shared_mutation() {
        // Registers: 0 = arr (built fresh), 1 = alias (Copy of 0), 2 = index 0,
        // 3 = new value 99.
        let code = vec![
            Op::LoadConst { dst: 2, idx: 0 }, // index 0
            Op::LoadConst { dst: 3, idx: 1 }, // value 99
            Op::NewArray {
                dst: 0,
                elem_ty: Ty::Int,
                elems: vec![2],
            }, // arr = [0]
            Op::Copy { dst: 1, src: 0 },      // alias = arr (shares the buffer)
            Op::IndexSet {
                base: 0,
                index: 2,
                kind: IndexKind::Array,
                src: 3,
            }, // arr[0] = 99
            Op::Return { src: Some(1) },      // return the alias, unaffected if COW works
        ];
        let module = Module {
            path: std::rc::Rc::from("/test/cow"),
            strings: vec![std::rc::Rc::from("/test/cow"), std::rc::Rc::from("run")],
            consts: vec![ConstValue::Int(0), ConstValue::Int(99)],
            functions: vec![FunctionCode {
                name: 1,
                atomic: false,
                params: 0,
                min_arity: 0,
                ret: Ty::array(Ty::Int),
                reg_types: vec![Ty::array(Ty::Int), Ty::array(Ty::Int), Ty::Int, Ty::Int],
                entry_points: vec![0],
                code: code.into(),
                capture_targets: Vec::new(),
            }],
        };
        let mut host = NoHost;
        let limits = Limits::default();
        let mut ticks = 1000u64;
        let mut interp = Interpreter::new(&module, &mut host, &limits, &mut ticks);
        let alias = interp.call("run", vec![]).unwrap();
        assert!(
            alias.as_array().unwrap()[0].equals(&Value::Int(0)),
            "the alias must not observe the write made through `arr`"
        );
    }
}
