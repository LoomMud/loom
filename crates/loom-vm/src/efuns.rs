// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Efuns (driver built-ins) for the Phase 0 subset (§5.5).
//!
//! Privilege classes are not enforced in Phase 0 except `bind_connection`,
//! which only the master may call.

use std::rc::Rc;

use loom_syntax::Span;

use crate::interp::{Exec, Frame, R};
use crate::object::ObjectId;
use crate::value::Value;
use crate::world::MASTER_PATH;

/// `(name, min args, max args)` for every efun; the linker checks arity.
const EFUNS: &[(&str, usize, usize)] = &[
    ("self", 0, 0),
    ("this_player", 0, 0),
    ("load_object", 1, 1),
    ("clone_object", 1, 1),
    ("find_object", 1, 1),
    ("object_name", 1, 1),
    ("environment", 0, 1),
    ("inventory", 1, 1),
    ("move_to", 1, 1),
    ("send", 2, 2),
    ("disconnect", 1, 1),
    ("bind_connection", 1, 1),
    ("compile_object", 1, 1),
    ("len", 1, 1),
    ("split", 2, 2),
    ("join", 2, 2),
    ("keys", 1, 1),
    ("trim", 1, 1),
];

/// Arity of efun `name`, if it exists.
pub fn arity(name: &str) -> Option<(usize, usize)> {
    EFUNS
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, a, b)| (*a, *b))
}

/// Names of all efuns (for docs and tooling).
pub fn names() -> impl Iterator<Item = &'static str> {
    EFUNS.iter().map(|(n, _, _)| *n)
}

impl Exec<'_> {
    fn want_str(&self, f: &Frame, span: Span, efun: &str, v: &Value) -> R<Rc<str>> {
        match v {
            Value::Str(s) => Ok(s.clone()),
            v => Err(self.err(
                f,
                span,
                format!("{efun}(): expected string, got {}", v.type_name()),
            )),
        }
    }

    fn want_obj(&self, f: &Frame, span: Span, efun: &str, v: &Value) -> R<ObjectId> {
        match v {
            Value::Object(id) if self.st.objects.get(*id).is_some() => Ok(*id),
            Value::Object(_) => Err(self.err(f, span, format!("{efun}(): object was destructed"))),
            v => Err(self.err(
                f,
                span,
                format!("{efun}(): expected object, got {}", v.type_name()),
            )),
        }
    }

    /// Run efun `name`; `None` if there is no such efun.
    pub fn efun(
        &mut self,
        f: &mut Frame,
        name: &str,
        args: Vec<Value>,
        span: Span,
    ) -> Option<R<Value>> {
        let (min, max) = arity(name)?;
        if args.len() < min || args.len() > max {
            return Some(Err(self.err(
                f,
                span,
                format!("{name}() takes {min}..={max} arguments, got {}", args.len()),
            )));
        }
        Some(self.efun_inner(f, name, args, span))
    }

    fn efun_inner(&mut self, f: &mut Frame, name: &str, args: Vec<Value>, span: Span) -> R<Value> {
        let a0 = args.first().cloned().unwrap_or(Value::Null);
        let a1 = args.get(1).cloned().unwrap_or(Value::Null);
        match name {
            "self" => Ok(Value::Object(f.obj)),
            "this_player" => Ok(self.this_player.map_or(Value::Null, Value::Object)),
            "load_object" => {
                let p = self.want_str(f, span, name, &a0)?;
                self.load_object(&p)
                    .map(Value::Object)
                    .map_err(|e| self.err(f, span, format!("load_object(\"{p}\") failed:\n{e}")))
            }
            "clone_object" => {
                let p = self.want_str(f, span, name, &a0)?;
                self.clone_object(&p)
                    .map(Value::Object)
                    .map_err(|e| self.err(f, span, format!("clone_object(\"{p}\") failed:\n{e}")))
            }
            "find_object" => {
                let p = self.want_str(f, span, name, &a0)?;
                let key = p.strip_suffix(".wf").unwrap_or(&p);
                Ok(self
                    .st
                    .names
                    .get(key)
                    .copied()
                    .filter(|id| self.st.objects.get(*id).is_some())
                    .map_or(Value::Null, Value::Object))
            }
            "object_name" => {
                let id = self.want_obj(f, span, name, &a0)?;
                Ok(Value::str(&self.obj_name(id)))
            }
            "environment" => {
                let id = if args.is_empty() {
                    f.obj
                } else {
                    self.want_obj(f, span, name, &a0)?
                };
                Ok(self
                    .st
                    .objects
                    .get(id)
                    .and_then(|o| o.env)
                    .map_or(Value::Null, Value::Object))
            }
            "inventory" => {
                let id = self.want_obj(f, span, name, &a0)?;
                let inv = self
                    .st
                    .objects
                    .get(id)
                    .map(|o| o.inventory.iter().map(|i| Value::Object(*i)).collect())
                    .unwrap_or_default();
                Ok(Value::array(inv))
            }
            "move_to" => {
                let dest = self.want_obj(f, span, name, &a0)?;
                // Refuse to create containment cycles.
                let mut cur = Some(dest);
                while let Some(c) = cur {
                    if c == f.obj {
                        return Err(self.err(
                            f,
                            span,
                            "move_to(): cannot move an object into itself or its contents",
                        ));
                    }
                    cur = self.st.objects.get(c).and_then(|o| o.env);
                }
                self.st.move_object(f.obj, dest);
                Ok(Value::Null)
            }
            "send" => {
                let text = self.want_str(f, span, name, &a1)?;
                if let Value::Object(id) = a0
                    && let Some(conn) = self.st.objects.get(id).and_then(|o| o.conn)
                {
                    self.host.send(conn, &text);
                } else if !matches!(a0, Value::Null | Value::Object(_)) {
                    return Err(self.err(
                        f,
                        span,
                        format!("send(): expected object, got {}", a0.type_name()),
                    ));
                }
                Ok(Value::Null)
            }
            "disconnect" => {
                // Ask the host to close the link; the driver runs `net_dead()`
                // when the network layer reports the disconnect, exactly as
                // for a dropped link.
                if let Value::Object(id) = a0
                    && let Some(conn) = self.st.objects.get(id).and_then(|o| o.conn)
                {
                    self.host.close(conn);
                } else if !matches!(a0, Value::Null | Value::Object(_)) {
                    return Err(self.err(
                        f,
                        span,
                        format!("disconnect(): expected object, got {}", a0.type_name()),
                    ));
                }
                Ok(Value::Null)
            }
            "bind_connection" => {
                if self.st.master != Some(f.obj) {
                    return Err(self.err(
                        f,
                        span,
                        format!("bind_connection() may only be called by {MASTER_PATH}"),
                    ));
                }
                let id = self.want_obj(f, span, name, &a0)?;
                let Some(conn) = self.conn else {
                    return Err(self.err(
                        f,
                        span,
                        "bind_connection(): no connection in this execution",
                    ));
                };
                self.st.bind(conn, id);
                Ok(Value::Null)
            }
            "compile_object" => {
                let p = self.want_str(f, span, name, &a0)?;
                Ok(match self.recompile(&p) {
                    Ok(()) => Value::Null,
                    Err(e) => Value::str(&e),
                })
            }
            "len" => match &a0 {
                Value::Str(s) => Ok(Value::Int(s.chars().count() as i64)),
                Value::Array(a) => Ok(Value::Int(a.borrow().len() as i64)),
                Value::Map(m) => Ok(Value::Int(m.borrow().entries.len() as i64)),
                v => Err(self.err(
                    f,
                    span,
                    format!(
                        "len(): expected string, array or map, got {}",
                        v.type_name()
                    ),
                )),
            },
            "split" => {
                let s = self.want_str(f, span, name, &a0)?;
                let sep = self.want_str(f, span, name, &a1)?;
                if sep.is_empty() {
                    return Err(self.err(f, span, "split(): separator must not be empty"));
                }
                Ok(Value::array(s.split(&*sep).map(Value::str).collect()))
            }
            "join" => {
                let sep = self.want_str(f, span, name, &a1)?;
                let Value::Array(a) = &a0 else {
                    return Err(self.err(
                        f,
                        span,
                        format!("join(): expected array, got {}", a0.type_name()),
                    ));
                };
                let mut parts = Vec::new();
                for v in a.borrow().iter() {
                    match v {
                        Value::Str(s) => parts.push(s.clone()),
                        v => {
                            return Err(self.err(
                                f,
                                span,
                                format!(
                                    "join(): array elements must be strings, found {}",
                                    v.type_name()
                                ),
                            ));
                        }
                    }
                }
                let total: usize = parts.iter().map(|p| p.len() + sep.len()).sum();
                if total > crate::interp::MAX_STRING {
                    return Err(self.err(f, span, "string too long"));
                }
                let parts: Vec<&str> = parts.iter().map(|s| &**s).collect();
                Ok(Value::str(&parts.join(&sep)))
            }
            "keys" => match &a0 {
                Value::Map(m) => Ok(Value::array(
                    m.borrow().entries.iter().map(|(k, _)| k.clone()).collect(),
                )),
                v => Err(self.err(
                    f,
                    span,
                    format!("keys(): expected map, got {}", v.type_name()),
                )),
            },
            "trim" => {
                let s = self.want_str(f, span, name, &a0)?;
                Ok(Value::str(s.trim()))
            }
            _ => Err(self.err(f, span, format!("internal: efun `{name}` not implemented"))),
        }
    }
}
