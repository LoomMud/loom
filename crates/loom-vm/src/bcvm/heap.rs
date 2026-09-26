// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Bytecode-VM runtime values: a 16-byte tagged [`Value`] (spec §5.8: "16
//! byte values"), backed by a per-object-kind `Rc` for reference counting
//! plus a simple stop-the-world cycle collector on top (spec §5.8: "RC +
//! cycle collector").
//!
//! Strings/arrays/maps are boxed behind one [`Rc<HeapObj>`] *thin* pointer
//! (as opposed to `Rc<str>`/`Rc<RefCell<Vec<_>>>`, which are fat pointers),
//! so [`Value`] stays one tag word plus one payload word regardless of
//! which heap kind it holds — see [`SIZE_IS_16_BYTES`] below.
//!
//! **RC**: ordinary `Rc` clone/drop reclaims acyclic garbage immediately,
//! same as Phase 0. **Cycle collector**: [`collect_cycles`] is a full
//! mark-sweep over every live allocation (tracked in a thread-local
//! registry, since a World runs on one deterministic thread — no
//! cross-thread sharing to worry about). It marks everything reachable from
//! the given roots, then clears the *contents* of every unreached
//! allocation still in the registry. Clearing (not freeing directly) is
//! what makes this safe: it drops each unreached object's outgoing `Rc`
//! edges through ordinary `Drop`, which is exactly what breaks a cycle and
//! lets `Rc`'s own refcount take every member of the cycle to zero. This is
//! a full-heap mark-sweep rather than Bacon-Rajan trial deletion (which
//! would only re-examine objects whose refcount was decremented since the
//! last collection); trial deletion is the natural next optimization once
//! the driver has enough live objects for full-heap sweeps to show up in a
//! profile.

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::{Rc, Weak};

use loom_syntax::ast::{Type, TypeKind};

use crate::object::ObjectId;

/// A heap-allocated Weft value: string, array, or map. Always reached
/// through [`Value::Heap`].
#[derive(Debug)]
pub enum HeapObj {
    Str(Box<str>),
    Array(RefCell<Vec<Value>>),
    Map(RefCell<Map>),
}

/// Insertion-ordered map (§5.1 determinism); linear lookup, same tradeoff as
/// the Phase 0 evaluator's `value::Map`.
#[derive(Clone, Debug, Default)]
pub struct Map {
    pub entries: Vec<(Value, Value)>,
}

impl Map {
    pub fn get(&self, k: &Value) -> Option<&Value> {
        self.entries
            .iter()
            .find(|(e, _)| e.equals(k))
            .map(|(_, v)| v)
    }

    pub fn insert(&mut self, k: Value, v: Value) {
        if let Some(slot) = self.entries.iter_mut().find(|(e, _)| e.equals(&k)) {
            slot.1 = v;
        } else {
            self.entries.push((k, v));
        }
    }

    pub fn contains(&self, k: &Value) -> bool {
        self.get(k).is_some()
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
    /// String, array, or map: see [`HeapObj`].
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
        Value::Heap(alloc(HeapObj::Str(s.into())))
    }

    pub fn array(v: Vec<Value>) -> Value {
        Value::Heap(alloc(HeapObj::Array(RefCell::new(v))))
    }

    pub fn map(m: Map) -> Value {
        Value::Heap(alloc(HeapObj::Map(RefCell::new(m))))
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

    pub fn as_array(&self) -> Option<&RefCell<Vec<Value>>> {
        match self {
            Value::Heap(h) => match &**h {
                HeapObj::Array(a) => Some(a),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&RefCell<Map>> {
        match self {
            Value::Heap(h) => match &**h {
                HeapObj::Map(m) => Some(m),
                _ => None,
            },
            _ => None,
        }
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
            },
        }
    }

    /// `==` semantics: primitives and strings by value, objects by
    /// identity, arrays and maps by reference (spec §5.2).
    pub fn equals(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Float(a), Value::Float(b)) => a == b,
            (Value::Object(a), Value::Object(b)) => a == b,
            (Value::Heap(a), Value::Heap(b)) => match (&**a, &**b) {
                (HeapObj::Str(x), HeapObj::Str(y)) => x == y,
                (HeapObj::Array(_), HeapObj::Array(_)) | (HeapObj::Map(_), HeapObj::Map(_)) => {
                    Rc::ptr_eq(a, b)
                }
                _ => false,
            },
            _ => false,
        }
    }

    pub fn is_valid_key(&self) -> bool {
        matches!(self, Value::Bool(_) | Value::Int(_) | Value::Object(_))
            || matches!(self, Value::Heap(h) if matches!(**h, HeapObj::Str(_)))
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
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------
// Allocation registry + cycle collector.
// ---------------------------------------------------------------------

thread_local! {
    /// Every live heap allocation, as a weak handle. A World runs on one
    /// deterministic thread (spec §5.1), so a thread-local registry is the
    /// whole heap for that World; nothing here needs to be `Send`/`Sync`.
    static REGISTRY: RefCell<Vec<Weak<HeapObj>>> = const { RefCell::new(Vec::new()) };
}

fn alloc(obj: HeapObj) -> Rc<HeapObj> {
    let rc = Rc::new(obj);
    REGISTRY.with(|r| r.borrow_mut().push(Rc::downgrade(&rc)));
    rc
}

/// Number of live allocations still tracked (includes ones only reachable
/// through a cycle). Exposed for tests and memory-quota accounting.
pub fn live_allocations() -> usize {
    REGISTRY.with(|r| {
        let mut reg = r.borrow_mut();
        reg.retain(|w| w.strong_count() > 0);
        reg.len()
    })
}

/// Trace-and-clear cycle collection (see module docs). `roots` should cover
/// every [`Value`] the collector cannot otherwise reach: object variables,
/// and every register of every live VM frame. Returns the number of
/// allocations whose contents were cleared (an upper bound on cycles
/// broken, since some may not have been part of a true cycle — e.g. an
/// array that was simply unreachable acyclic garbage nobody dropped yet is
/// swept the same way).
pub fn collect_cycles<'a>(roots: impl IntoIterator<Item = &'a Value>) -> usize {
    let mut reached: HashSet<*const HeapObj> = HashSet::new();
    let mut stack: Vec<Value> = roots.into_iter().cloned().collect();
    while let Some(v) = stack.pop() {
        if let Value::Heap(rc) = &v {
            let ptr = Rc::as_ptr(rc);
            if reached.insert(ptr) {
                match &**rc {
                    HeapObj::Str(_) => {}
                    HeapObj::Array(a) => stack.extend(a.borrow().iter().cloned()),
                    HeapObj::Map(m) => {
                        for (k, val) in &m.borrow().entries {
                            stack.push(k.clone());
                            stack.push(val.clone());
                        }
                    }
                }
            }
        }
    }

    let mut cleared = 0usize;
    REGISTRY.with(|r| {
        let mut reg = r.borrow_mut();
        for w in reg.iter() {
            let Some(rc) = w.upgrade() else { continue };
            if reached.contains(&Rc::as_ptr(&rc)) {
                continue;
            }
            match &*rc {
                HeapObj::Str(_) => {}
                HeapObj::Array(a) => {
                    if !a.borrow().is_empty() {
                        a.borrow_mut().clear();
                        cleared += 1;
                    }
                }
                HeapObj::Map(m) => {
                    if !m.borrow().entries.is_empty() {
                        m.borrow_mut().entries.clear();
                        cleared += 1;
                    }
                }
            }
        }
        reg.retain(|w| w.strong_count() > 0);
    });
    cleared
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
                for (i, e) in a.borrow().iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    write_value(out, e, name, depth + 1, true);
                }
                out.push(']');
            }
            HeapObj::Map(m) => {
                let m = m.borrow();
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
    fn equals_semantics() {
        assert!(Value::str("a").equals(&Value::str("a")));
        let a = Value::array(vec![Value::Int(1)]);
        assert!(!a.equals(&Value::array(vec![Value::Int(1)])));
        assert!(a.equals(&a.clone()));
    }

    #[test]
    fn acyclic_garbage_is_reclaimed_immediately_by_rc() {
        let before = live_allocations();
        {
            let _a = Value::array(vec![Value::str("x")]);
        }
        assert_eq!(live_allocations(), before);
    }

    #[test]
    fn cyclic_garbage_is_reclaimed_by_collect_cycles() {
        let a = Value::array(vec![Value::Null]);
        let b = Value::array(vec![Value::Null]);
        let (wa, wb) = match (&a, &b) {
            (Value::Heap(ra), Value::Heap(rb)) => (Rc::downgrade(ra), Rc::downgrade(rb)),
            _ => unreachable!(),
        };
        a.as_array().unwrap().borrow_mut()[0] = b.clone();
        b.as_array().unwrap().borrow_mut()[0] = a.clone();
        drop(a);
        drop(b);

        // Nothing points at either array from the outside anymore, but the
        // cycle keeps both alive: plain `Rc` never reclaims this.
        assert!(wa.upgrade().is_some());
        assert!(wb.upgrade().is_some());

        let cleared = collect_cycles(std::iter::empty());
        assert!(cleared >= 1, "expected at least one cleared allocation");
        assert!(wa.upgrade().is_none(), "a should be reclaimed");
        assert!(wb.upgrade().is_none(), "b should be reclaimed");
    }

    #[test]
    fn reachable_values_survive_collection() {
        let kept = Value::array(vec![Value::str("keep me")]);
        let garbage_a = Value::array(vec![Value::Null]);
        let garbage_b = Value::array(vec![Value::Null]);
        garbage_a.as_array().unwrap().borrow_mut()[0] = garbage_b.clone();
        garbage_b.as_array().unwrap().borrow_mut()[0] = garbage_a.clone();
        drop(garbage_a);
        drop(garbage_b);

        collect_cycles(std::iter::once(&kept));
        assert_eq!(
            kept.as_array().unwrap().borrow()[0].as_str(),
            Some("keep me")
        );
    }
}
