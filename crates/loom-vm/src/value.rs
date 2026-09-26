// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Weft runtime values (§5.2, Phase 0 subset).

use std::cell::RefCell;
use std::fmt::Write as _;
use std::rc::Rc;

use loom_syntax::ast::{Type, TypeKind};

use crate::object::ObjectId;

/// A Weft value. Arrays and maps have reference semantics (shared `Rc`);
/// strings are immutable.
#[derive(Clone, Debug)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Str(Rc<str>),
    Array(Rc<RefCell<Vec<Value>>>),
    Map(Rc<RefCell<Map>>),
    Object(ObjectId),
}

impl Value {
    pub fn str(s: &str) -> Value {
        Value::Str(Rc::from(s))
    }

    pub fn array(v: Vec<Value>) -> Value {
        Value::Array(Rc::new(RefCell::new(v)))
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Str(_) => "string",
            Value::Array(_) => "array",
            Value::Map(_) => "map",
            Value::Object(_) => "object",
        }
    }

    /// `==` semantics: primitives and strings by value, objects by identity,
    /// arrays and maps by reference.
    pub fn equals(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Str(a), Value::Str(b)) => a == b,
            (Value::Object(a), Value::Object(b)) => a == b,
            (Value::Array(a), Value::Array(b)) => Rc::ptr_eq(a, b),
            (Value::Map(a), Value::Map(b)) => Rc::ptr_eq(a, b),
            _ => false,
        }
    }

    pub fn is_valid_key(&self) -> bool {
        matches!(
            self,
            Value::Bool(_) | Value::Int(_) | Value::Str(_) | Value::Object(_)
        )
    }

    /// Shallow runtime type check against a declared type (Phase 0: element
    /// types of arrays/maps are not checked).
    pub fn conforms(&self, ty: &Type) -> bool {
        match (&ty.kind, self) {
            (TypeKind::Any, _) => true,
            (TypeKind::Optional(_), Value::Null) => true,
            (TypeKind::Optional(inner), v) => v.conforms(inner),
            (TypeKind::Null, Value::Null) => true,
            (TypeKind::Int, Value::Int(_)) => true,
            (TypeKind::Bool, Value::Bool(_)) => true,
            (TypeKind::String, Value::Str(_)) => true,
            (TypeKind::Object, Value::Object(_)) => true,
            (TypeKind::Array(_), Value::Array(_)) => true,
            (TypeKind::Map(..), Value::Map(_)) => true,
            _ => false,
        }
    }
}

/// Insertion-ordered map (§5.1 determinism). Linear lookup is fine for the
/// Phase 0 spike; Phase 1 replaces it with an indexed map.
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

/// Render a value for interpolation / display. `name` resolves object names.
/// Nesting is capped so cyclic structures cannot recurse forever.
pub fn display(v: &Value, name: &dyn Fn(crate::object::ObjectId) -> String) -> String {
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
        Value::Str(s) if quoted => {
            let _ = write!(out, "{:?}", &**s);
        }
        Value::Str(s) => out.push_str(s),
        Value::Object(id) => out.push_str(&name(*id)),
        Value::Array(a) => {
            out.push('[');
            for (i, e) in a.borrow().iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_value(out, e, name, depth + 1, true);
            }
            out.push(']');
        }
        Value::Map(m) => {
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
    }
}
