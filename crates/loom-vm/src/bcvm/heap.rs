// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Bytecode-VM runtime values: a 16-byte tagged [`Value`] (spec §5.8: "16
//! byte values"), with **copy-on-write value semantics** for containers
//! (spec r5 §5.2.1, D24, [OBI-52]).
//!
//! [OBI-52]: /OBI/issues/OBI-52
//!
//! Strings/arrays/maps are boxed behind one [`Rc<HeapObj>`] *thin* pointer
//! (as opposed to `Rc<str>`/`Rc<Vec<_>>`, which are fat pointers), so
//! [`Value`] stays one tag word plus one payload word regardless of which
//! heap kind it holds — see [`SIZE_IS_16_BYTES`] below.
//!
//! **Value semantics, not reference semantics (r5 D24).** There is no
//! `RefCell` here: an array/map's contents are immutable once built, and
//! every in-place-looking mutation ([`Value::array_mut`],
//! [`Value::map_mut`]) goes through `Rc::make_mut`, which clones the buffer
//! the first time it is shared (refcount > 1) and mutates in place after
//! that (refcount == 1). Two consequences fall out of this for free,
//! matching r5 exactly:
//! - **Aliasing is copy semantics.** Assigning, passing, returning, or
//!   capturing a container shares the buffer (cheap `Rc` clone) until
//!   someone writes through one of the copies, at which point that copy's
//!   buffer becomes independent. `==` is therefore defined structurally
//!   (element/entry equality), not by identity — two arrays holding equal
//!   elements are equal even if they started life as unrelated
//!   allocations.
//! - **No reference cycles are constructible.** Building a value cannot
//!   observe or capture a handle to the container currently being built (there is no
//!   `RefCell`/interior mutability to store a self-reference through), so
//!   the heap here is a DAG by construction and needs no cycle collector.
//!   (The collector spec r5 defers is for the *object* heap once
//!   lightweight objects exist — tracked on the issue that adds them, not
//!   this one.)

use std::rc::Rc;

use loom_compiler::bytecode::Callee;
use loom_syntax::ast::{Type, TypeKind};

use crate::bcvm::vm::ProgramCode;
use crate::object::ObjectId;
use crate::security::{GuardSet, Sym};

/// How a [`FunctionValue`] is invoked (spec r5 §5.2.2, OBI-79).
#[derive(Clone)]
pub enum FnBody {
    /// A named reference (`add_verb("x", do_x)`, `&do_x`): no captures, no
    /// pinned version. Late-bound: resolved by (creator, name) on the
    /// creator's *current* program at call time (a missing name is a
    /// runtime error).
    Named(Callee),
    /// An anonymous closure literal: captures by value, snapshotted at
    /// creation (`captures[i]` preloads into `code`'s
    /// `capture_targets[i]` register — see
    /// `loom_compiler::bytecode::FunctionCode::capture_targets`). Pins the
    /// creator's program version at creation time: `code` is the exact
    /// `Rc<CompiledProgram>` alive then, kept alive by this value's own
    /// refcount even across a later hot-reload `upgrade()` of the creator
    /// (the AC's "old version stays alive via the closures' refcount,
    /// freed after the last one dies").
    Closure {
        code: Rc<dyn ProgramCode>,
        func: u32,
        captures: Vec<Value>,
        /// The creator's program version at creation, for the stale-call
        /// warning/metric (`loom_stale_closure_calls_total{program}`):
        /// compared against the creator's *current* program version at
        /// call time by whoever drives the call (`RegistryHost`).
        program_version: u32,
    },
}

impl std::fmt::Debug for FnBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FnBody::Named(c) => write!(f, "Named({c:?})"),
            FnBody::Closure {
                func,
                captures,
                program_version,
                ..
            } => write!(
                f,
                "Closure {{ func: {func}, captures: {captures:?}, program_version: {program_version} }}"
            ),
        }
    }
}

/// A function value (spec r5 §5.2.2, OBI-79; OBI-35 D-S1.6): the runtime
/// representation of a closure literal or a named function reference used
/// as a value.
#[derive(Clone, Debug)]
pub struct FunctionValue {
    /// The object whose code created this value — for a `Named` value,
    /// also who `(creator, name)` late-binding resolves against; for a
    /// `Closure`, who its body runs "as" (its own `self`/globals).
    pub creator: ObjectId,
    pub body: FnBody,
    /// The guard set at the moment of creation (`Host::current_guard()`),
    /// captured once and never re-read: a later `seteuid` by the creator
    /// does not change it, whether it raises or lowers the euid (OBI-35
    /// D-S1.6, AC 5). Invoking this value pushes a synthetic creator frame
    /// of exactly this guard (D-S1.7) via `Host::enter_creator_frame`.
    pub guard: GuardSet,
    /// The uid of the lowest-tier principal in `guard` at creation, ties
    /// going to the most recently pushed (D-S1.6); with no roles/tier
    /// snapshot available yet (S2, OBI-36), the creator's own uid. This is
    /// the quota root uid a scheduled invocation (call_out, a future
    /// `db_query` callback) charges ticks/memory against.
    pub quota_uid: Sym,
}

/// A heap-allocated Weft value: string, array, map, struct, or enum. Always
/// reached through [`Value::Heap`]. No field here is interior-mutable; see
/// the module docs for why that is exactly what makes containers value
/// types.
#[derive(Clone, Debug)]
pub enum HeapObj {
    Str(Box<str>),
    Array(Vec<Value>),
    Map(MapData),
    /// A `struct` value (spec r5 §7.3, D27, [OBI-52]). Fields are stored
    /// positionally (declaration order, matching [`loom_compiler::ty::StructTy::fields`])
    /// for O(1) access by codegen-assigned index; [`StructVal::field`] is
    /// the by-name lookup migration/`upgrade()` code should use instead of
    /// ever assuming index stability across versions.
    ///
    /// [OBI-52]: /OBI/issues/OBI-52
    Struct(StructVal),
    /// An `enum` value. **Never** compared/stored by ordinal (spec r5
    /// §7.3): [`EnumVal::variant`] is the variant's *name*, not its index
    /// in the declaration, precisely so a recompile that reorders variants
    /// cannot silently relabel a live value.
    Enum(EnumVal),
    /// A function value (spec r5 §5.2.2, OBI-79). See [`FunctionValue`].
    Fn(FunctionValue),
}

/// A struct value: the declaring program's path + the struct's name (its
/// nominal identity, matching `loom_compiler::ty::StructTy`), and its
/// fields by name.
#[derive(Clone, Debug)]
pub struct StructVal {
    pub module: Rc<str>,
    pub name: Rc<str>,
    /// `(field name, value)`, declaration order.
    pub fields: Vec<(Rc<str>, Value)>,
}

impl StructVal {
    pub fn field(&self, name: &str) -> Option<&Value> {
        self.fields
            .iter()
            .find(|(n, _)| &**n == name)
            .map(|(_, v)| v)
    }
}

/// An enum value: the declaring program's path + the enum's name, the
/// **variant name** (never an ordinal — see the [`HeapObj::Enum`] docs),
/// and its positional payload.
#[derive(Clone, Debug)]
pub struct EnumVal {
    pub module: Rc<str>,
    pub name: Rc<str>,
    pub variant: Rc<str>,
    pub payload: Vec<Value>,
}

/// Insertion-ordered entries backing a Weft map value. Order is preserved
/// for iteration/display (§5.1 determinism) but is **not** significant to
/// `==` (r5): two maps are equal iff they have the same key set and the
/// same value for every key.
///
/// `index`/`unindexed` (OBI-74) are a lookup accelerator, not part of the
/// map's logical state: rebuilt implicitly as entries are inserted, and
/// ignored by `PartialEq`. The type checker restricts map keys to
/// `int`/`string`/`bool`/`object` (`check.rs` W0264), so
/// [`Value::index_hash`] never sees an `Array`/`Map`/`Struct`/`Enum` key in
/// practice; the `unindexed` fallback exists only so a `NaN`-ish or
/// otherwise unhashable key (should one ever slip through, e.g. via `Any`)
/// degrades to a linear scan among just those entries instead of
/// corrupting lookups for everything else.
#[derive(Clone, Debug, Default)]
pub struct MapData {
    pub entries: Vec<(Value, Value)>,
    /// `hash(key) -> entry indices` sharing that hash bucket (chained;
    /// disambiguated by `Value::equals` on lookup, so a hash collision is
    /// only ever a (rare) extra `equals` check, never a wrong answer).
    index: std::collections::HashMap<u64, Vec<u32>>,
    /// Entry indices whose key had no stable hash ([`Value::index_hash`]
    /// returned `None`); scanned linearly.
    unindexed: Vec<u32>,
}

impl PartialEq for MapData {
    fn eq(&self, other: &Self) -> bool {
        self.entries.len() == other.entries.len()
            && self
                .entries
                .iter()
                .all(|(k, v)| other.get(k).is_some_and(|ov| ov.equals(v)))
    }
}

impl MapData {
    fn find_index(&self, k: &Value) -> Option<usize> {
        if let Some(h) = k.index_hash() {
            return self.index.get(&h).and_then(|bucket| {
                bucket
                    .iter()
                    .copied()
                    .find(|&i| self.entries[i as usize].0.equals(k))
                    .map(|i| i as usize)
            });
        }
        self.unindexed
            .iter()
            .copied()
            .find(|&i| self.entries[i as usize].0.equals(k))
            .map(|i| i as usize)
    }

    pub fn get(&self, k: &Value) -> Option<&Value> {
        self.find_index(k).map(|i| &self.entries[i].1)
    }

    pub fn insert(&mut self, k: Value, v: Value) {
        if let Some(i) = self.find_index(&k) {
            self.entries[i].1 = v;
            return;
        }
        let idx = self.entries.len() as u32;
        match k.index_hash() {
            Some(h) => self.index.entry(h).or_default().push(idx),
            None => self.unindexed.push(idx),
        }
        self.entries.push((k, v));
    }

    pub fn contains(&self, k: &Value) -> bool {
        self.find_index(k).is_some()
    }
}

/// A Weft runtime value. One tag word, one payload word: see
/// [`SIZE_IS_16_BYTES`].
#[derive(Clone, Debug)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Object(ObjectId),
    /// String, array, or map: see [`HeapObj`]. Always logically a *value*
    /// (see module docs) even though the representation is a shared `Rc`.
    Heap(Rc<HeapObj>),
}

/// Compile-time proof that [`Value`] is 16 bytes, per spec §5.8. If this
/// ever fails, something grew a fat pointer (or a niche optimization
/// stopped applying) and the layout needs another look, not a bigger
/// number in this constant.
#[allow(dead_code)]
const SIZE_IS_16_BYTES: () = assert!(std::mem::size_of::<Value>() == 16);

impl Value {
    pub fn str(s: &str) -> Value {
        Value::Heap(Rc::new(HeapObj::Str(s.into())))
    }

    pub fn array(v: Vec<Value>) -> Value {
        Value::Heap(Rc::new(HeapObj::Array(v)))
    }

    pub fn map(m: MapData) -> Value {
        Value::Heap(Rc::new(HeapObj::Map(m)))
    }

    pub fn struct_val(v: StructVal) -> Value {
        Value::Heap(Rc::new(HeapObj::Struct(v)))
    }

    pub fn enum_val(v: EnumVal) -> Value {
        Value::Heap(Rc::new(HeapObj::Enum(v)))
    }

    pub fn as_struct(&self) -> Option<&StructVal> {
        match self {
            Value::Heap(h) => match &**h {
                HeapObj::Struct(s) => Some(s),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn as_enum(&self) -> Option<&EnumVal> {
        match self {
            Value::Heap(h) => match &**h {
                HeapObj::Enum(e) => Some(e),
                _ => None,
            },
            _ => None,
        }
    }

    /// See [`FunctionValue`].
    pub fn function(f: FunctionValue) -> Value {
        Value::Heap(Rc::new(HeapObj::Fn(f)))
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Heap(h) => match &**h {
                HeapObj::Str(s) => Some(s),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Heap(h) => match &**h {
                HeapObj::Array(a) => Some(a),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&MapData> {
        match self {
            Value::Heap(h) => match &**h {
                HeapObj::Map(m) => Some(m),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn as_fn(&self) -> Option<&FunctionValue> {
        match self {
            Value::Heap(h) => match &**h {
                HeapObj::Fn(f) => Some(f),
                _ => None,
            },
            _ => None,
        }
    }

    /// Mutable access to this value's array buffer, cloning it first if it
    /// is shared (`Rc::make_mut`: copy-on-write, r5 D24). `None` if this
    /// value is not an array.
    pub fn array_mut(&mut self) -> Option<&mut Vec<Value>> {
        match self {
            Value::Heap(h) => match Rc::make_mut(h) {
                HeapObj::Array(a) => Some(a),
                _ => None,
            },
            _ => None,
        }
    }

    /// Mutable access to this value's map buffer; see [`Value::array_mut`].
    pub fn map_mut(&mut self) -> Option<&mut MapData> {
        match self {
            Value::Heap(h) => match Rc::make_mut(h) {
                HeapObj::Map(m) => Some(m),
                _ => None,
            },
            _ => None,
        }
    }

    /// True if a write through [`Value::array_mut`]/[`Value::map_mut`]
    /// would have to clone this value's heap buffer first (shared,
    /// `Rc::strong_count() > 1`) rather than mutate it in place. Callers
    /// check this *before* calling `array_mut`/`map_mut` to attribute an
    /// actual clone-on-write to whichever code triggered it
    /// (`loom_cow_copies_total{program}`, spec r5 §5.2.1, D24,
    /// `bcvm::vm::Host::record_cow_copy`). The VM is single-threaded and
    /// nothing else can observe/mutate the refcount between this check and
    /// the `array_mut`/`map_mut` call it guards, so this is equivalent to
    /// instrumenting `Rc::make_mut` itself, without coupling this
    /// program-agnostic heap module to metrics or program identity.
    pub fn is_shared(&self) -> bool {
        matches!(self, Value::Heap(h) if Rc::strong_count(h) > 1)
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::Object(_) => "object",
            Value::Heap(h) => match &**h {
                HeapObj::Str(_) => "string",
                HeapObj::Array(_) => "array",
                HeapObj::Map(_) => "map",
                HeapObj::Struct(_) => "struct",
                HeapObj::Enum(_) => "enum",
                HeapObj::Fn(_) => "function",
            },
        }
    }

    /// `==` semantics (spec r5 §5.2.1): primitives and strings by value,
    /// objects by identity, arrays and maps **structurally** (not by
    /// reference/identity — value semantics means two unrelated arrays
    /// with equal elements are equal). Structs compare by (module, name,
    /// every field); enums by (module, name, **variant name** — never an
    /// ordinal — and payload), so two enum values from differently
    /// ordered variant lists that name the same variant are still equal.
    /// Function values are not given any value equality by the spec; this
    /// compares them by heap identity (the same closure/reference, not
    /// merely an equivalent one), which is at least never wrong to call
    /// "equal" even though it may under-report (two independently-created
    /// references to the same named function are `!=` here).
    pub fn equals(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Float(a), Value::Float(b)) => a == b,
            (Value::Object(a), Value::Object(b)) => a == b,
            (Value::Heap(a), Value::Heap(b)) => match (&**a, &**b) {
                (HeapObj::Str(x), HeapObj::Str(y)) => x == y,
                (HeapObj::Array(x), HeapObj::Array(y)) => {
                    x.len() == y.len() && x.iter().zip(y).all(|(a, b)| a.equals(b))
                }
                (HeapObj::Map(x), HeapObj::Map(y)) => x == y,
                (HeapObj::Struct(x), HeapObj::Struct(y)) => {
                    x.module == y.module
                        && x.name == y.name
                        && x.fields.len() == y.fields.len()
                        && x.fields
                            .iter()
                            .all(|(n, v)| y.field(n).is_some_and(|ov| ov.equals(v)))
                }
                (HeapObj::Enum(x), HeapObj::Enum(y)) => {
                    x.module == y.module
                        && x.name == y.name
                        && x.variant == y.variant
                        && x.payload.len() == y.payload.len()
                        && x.payload.iter().zip(&y.payload).all(|(a, b)| a.equals(b))
                }
                (HeapObj::Fn(_), HeapObj::Fn(_)) => Rc::ptr_eq(a, b),
                _ => false,
            },
            _ => false,
        }
    }

    pub fn is_valid_key(&self) -> bool {
        matches!(self, Value::Bool(_) | Value::Int(_) | Value::Object(_))
            || matches!(self, Value::Heap(h) if matches!(**h, HeapObj::Str(_)))
    }

    /// A hash consistent with [`Value::equals`] for [`MapData`]'s O(1)
    /// lookup index (OBI-74): `a.equals(b)` implies
    /// `a.index_hash() == b.index_hash()` for every `a`/`b` this returns
    /// `Some` for. `None` means "not indexed": [`MapData`] falls back to a
    /// linear scan for that entry rather than guess at a hash. The type
    /// checker limits map keys to `int`/`string`/`bool`/`object`
    /// (`check.rs` W0264, mirrored by [`Value::is_valid_key`]), so `Null`,
    /// `Float`, and the compound heap kinds land here only via `Any`-typed
    /// maps or direct VM construction, not surface-language map literals.
    pub fn index_hash(&self) -> Option<u64> {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        match self {
            Value::Null => 0u8.hash(&mut h),
            Value::Bool(b) => {
                1u8.hash(&mut h);
                b.hash(&mut h);
            }
            Value::Int(i) => {
                2u8.hash(&mut h);
                i.hash(&mut h);
            }
            Value::Object(o) => {
                3u8.hash(&mut h);
                o.hash(&mut h);
            }
            Value::Heap(rc) => match &**rc {
                HeapObj::Str(s) => {
                    4u8.hash(&mut h);
                    s.hash(&mut h);
                }
                // Not a valid map key (checker-enforced); no stable hash
                // worth computing.
                HeapObj::Array(_) | HeapObj::Map(_) | HeapObj::Struct(_) | HeapObj::Enum(_) => {
                    return None;
                }
            },
            // `f64` has no total `Hash` consistent with `PartialEq` (NaN,
            // -0.0/0.0); floats are not a valid map key anyway, so just
            // don't index them.
            Value::Float(_) => return None,
        }
        Some(h.finish())
    }

    /// Shallow runtime type check against a declared type (element types of
    /// arrays/maps are not checked; the verifier already proved static
    /// element types, `Cast` re-checks `any` boundaries).
    pub fn conforms(&self, ty: &Type) -> bool {
        match (&ty.kind, self) {
            (TypeKind::Any, _) => true,
            (TypeKind::Optional(_), Value::Null) => true,
            (TypeKind::Optional(inner), v) => v.conforms(inner),
            (TypeKind::Null, Value::Null) => true,
            (TypeKind::Int, Value::Int(_)) => true,
            (TypeKind::Bool, Value::Bool(_)) => true,
            (TypeKind::String, Value::Heap(h)) => matches!(**h, HeapObj::Str(_)),
            (TypeKind::Object, Value::Object(_)) => true,
            (TypeKind::Array(_), Value::Heap(h)) => matches!(**h, HeapObj::Array(_)),
            (TypeKind::Map(..), Value::Heap(h)) => matches!(**h, HeapObj::Map(_)),
            (TypeKind::Named(n), Value::Heap(h)) => match &**h {
                HeapObj::Struct(s) => &*s.name == n,
                HeapObj::Enum(e) => &*e.name == n,
                _ => false,
            },
            (TypeKind::Fn { .. }, Value::Heap(h)) => matches!(**h, HeapObj::Fn(_)),
            _ => false,
        }
    }
}

/// Approximate byte cost of one [`Value`], used for per-object memory
/// quota accounting (spec r5 §5.2.1). **Shallow, not deep/transitive**: a
/// container's own spine is counted (string bytes; array length ×
/// `size_of::<Value>()`; map entry count × 2 × `size_of::<Value>()`), but
/// an element/entry that is itself a container is counted only as its own
/// 16-byte [`Value`] slot — its contents are not walked into and re-summed.
/// This is a deliberate boundary, not an oversight: containers are
/// copy-on-write value types that freely share their backing `Rc<HeapObj>`
/// (see the module docs), so a deep byte count would either double-count a
/// substructure shared between two objects' vars or attribute it
/// arbitrarily to whichever object happened to write it last — neither is
/// a meaningful "how much memory does this object own" answer. Shallow
/// accounting charges exactly the allocation(s) an object's own write just
/// touched, and is O(size of the value just written), not O(everything the
/// object holds).
pub fn shallow_bytes(v: &Value) -> u64 {
    const SLOT: u64 = std::mem::size_of::<Value>() as u64;
    match v {
        Value::Heap(h) => match &**h {
            HeapObj::Str(s) => s.len() as u64,
            HeapObj::Array(a) => a.len() as u64 * SLOT,
            HeapObj::Map(m) => m.entries.len() as u64 * 2 * SLOT,
            HeapObj::Struct(s) => s.fields.len() as u64 * SLOT,
            HeapObj::Enum(e) => e.payload.len() as u64 * SLOT,
            // A function value's captures already sat in the creator's
            // own vars/regs before capture (or are `Copy` primitives), so
            // memory-quota accounting on this heap slot only charges the
            // fixed cost of the value itself — already covered by `SLOT`
            // at the call site, nothing extra here.
            HeapObj::Fn(_) => 0,
        },
        // Primitives live in the var slot itself, not a separate heap
        // allocation; nothing extra to charge.
        _ => 0,
    }
}

/// Render a value for interpolation / display. `name` resolves object
/// names.
pub fn display(v: &Value, name: &dyn Fn(ObjectId) -> String) -> String {
    let mut out = String::new();
    write_value(&mut out, v, name, 0, false);
    out
}

fn write_value(
    out: &mut String,
    v: &Value,
    name: &dyn Fn(ObjectId) -> String,
    depth: u32,
    quoted: bool,
) {
    use std::fmt::Write as _;
    if depth > 16 || out.len() > 64 * 1024 {
        out.push('…');
        return;
    }
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => {
            let _ = write!(out, "{b}");
        }
        Value::Int(n) => {
            let _ = write!(out, "{n}");
        }
        Value::Float(x) => {
            let _ = write!(out, "{x}");
        }
        Value::Object(id) => out.push_str(&name(*id)),
        Value::Heap(h) => match &**h {
            HeapObj::Str(s) if quoted => {
                let _ = write!(out, "{s:?}");
            }
            HeapObj::Str(s) => out.push_str(s),
            HeapObj::Array(a) => {
                out.push('[');
                for (i, e) in a.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    write_value(out, e, name, depth + 1, true);
                }
                out.push(']');
            }
            HeapObj::Map(m) => {
                if m.entries.is_empty() {
                    out.push_str("{:}");
                    return;
                }
                out.push('{');
                for (i, (k, e)) in m.entries.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    write_value(out, k, name, depth + 1, true);
                    out.push_str(": ");
                    write_value(out, e, name, depth + 1, true);
                }
                out.push('}');
            }
            HeapObj::Struct(s) => {
                let _ = write!(out, "{}", s.name);
                out.push_str(" { ");
                for (i, (n, v)) in s.fields.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    let _ = write!(out, "{n}: ");
                    write_value(out, v, name, depth + 1, true);
                }
                out.push_str(" }");
            }
            HeapObj::Enum(e) => {
                let _ = write!(out, "{}.{}", e.name, e.variant);
                if !e.payload.is_empty() {
                    out.push('(');
                    for (i, v) in e.payload.iter().enumerate() {
                        if i > 0 {
                            out.push_str(", ");
                        }
                        write_value(out, v, name, depth + 1, true);
                    }
                    out.push(')');
                }
            }
            HeapObj::Fn(f) => {
                let _ = write!(out, "<function of {}>", name(f.creator));
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_is_16_bytes() {
        let () = SIZE_IS_16_BYTES;
        assert_eq!(std::mem::size_of::<Value>(), 16);
    }

    #[test]
    fn structural_equality_for_arrays() {
        let a = Value::array(vec![Value::Int(1), Value::str("x")]);
        let b = Value::array(vec![Value::Int(1), Value::str("x")]);
        assert!(
            a.equals(&b),
            "equal elements, unrelated allocations: must be =="
        );
        let c = Value::array(vec![Value::Int(2)]);
        assert!(!a.equals(&c));
    }

    #[test]
    fn structural_equality_for_maps_ignores_insertion_order() {
        let mut m1 = MapData::default();
        m1.insert(Value::str("a"), Value::Int(1));
        m1.insert(Value::str("b"), Value::Int(2));
        let mut m2 = MapData::default();
        m2.insert(Value::str("b"), Value::Int(2));
        m2.insert(Value::str("a"), Value::Int(1));
        assert!(Value::map(m1).equals(&Value::map(m2)));
    }

    /// r5 D24: assign / mutate-the-copy, the original is unchanged
    /// (aliasing test).
    #[test]
    fn assigning_a_copy_and_mutating_it_leaves_the_original_unchanged() {
        let original = Value::array(vec![Value::Int(1), Value::Int(2)]);
        let mut copy = original.clone(); // a plain assignment: shares the Rc
        copy.array_mut().unwrap().push(Value::Int(3)); // make-unique-on-write
        assert_eq!(
            original.as_array().unwrap().len(),
            2,
            "original must be unaffected by mutating the copy"
        );
        assert_eq!(copy.as_array().unwrap().len(), 3);
    }

    #[test]
    fn make_mut_is_in_place_once_uniquely_owned() {
        let mut v = Value::array(vec![Value::Int(1), Value::Int(2)]);
        // Nothing else holds this Rc: make_mut must not allocate a new
        // buffer, it must mutate the existing one in place. (Mutating an
        // existing element, not pushing, so a `Vec` capacity reallocation
        // can't be mistaken for the thing under test.)
        let ptr_before = v.as_array().unwrap().as_ptr();
        v.array_mut().unwrap()[0] = Value::Int(9);
        let ptr_after = v.as_array().unwrap().as_ptr();
        assert_eq!(
            ptr_before, ptr_after,
            "uniquely-owned buffer should be mutated in place, not reallocated"
        );
    }

    /// r5: containers can no longer form reference cycles, because nothing
    /// in `HeapObj` is interior-mutable — there is no way, while building a
    /// value, to obtain and store a handle back to the very container being
    /// built. This test is the closest thing to a runtime witness of that
    /// static property: it exhaustively builds arrays-of-arrays through the
    /// only public constructors ([`Value::array`]/[`Value::array_mut`]) and
    /// checks that a bounded-depth walk always terminates (a walk over a
    /// true cycle would not, since nothing here caps recursion by has-seen
    /// tracking — it relies purely on the graph being acyclic).
    #[test]
    fn containers_built_through_the_public_api_cannot_contain_a_cycle() {
        fn depth(v: &Value, budget: u32) -> u32 {
            assert!(budget > 0, "walk did not terminate: would indicate a cycle");
            match v.as_array() {
                Some(a) => 1 + a.iter().map(|e| depth(e, budget - 1)).max().unwrap_or(0),
                None => 0,
            }
        }
        let mut v = Value::array(vec![Value::Int(1)]);
        for _ in 0..64 {
            let inner = v.clone();
            v = Value::array(vec![inner]);
        }
        // Bounded budget: if this ever looped forever instead of hitting
        // the assertion above, that would itself be evidence of a cycle.
        let d = depth(&v, 1_000);
        assert_eq!(d, 65);
    }
}
