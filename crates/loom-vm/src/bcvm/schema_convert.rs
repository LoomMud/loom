// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! By-name struct/enum conversion for hot reload (spec r5 §7.3, D27,
//! [OBI-52]) — the runtime half of [`loom_compiler::ty::StructTy`]/
//! [`loom_compiler::ty::EnumTy`]'s schema hash (`crate::bcvm::heap` has the
//! value representation).
//!
//! [OBI-52]: /OBI/issues/OBI-52
//!
//! Wiring this into [`crate::bcvm::registry::RegistryHost::upgrade`]'s
//! by-name var carry-over (today `registry::value_conforms` does only a
//! shallow nominal check for `Ty::Struct`/`Ty::Enum`) is OBI-34's own
//! follow-up, tracked separately from this module — see the OBI-88 task
//! notes. This module is a self-contained, directly testable building
//! block for that wiring.
//!
//! - [`convert_struct`]: **lossless** iff every field the *new* schema
//!   declares either (a) existed in the old value under the same name with
//!   a value that still conforms to its (possibly changed) declared type,
//!   or (b) is new and the new schema gives it a default. Otherwise
//!   **lossy**: the old value is untouched and the caller gets a portable
//!   `{field: value}` map (spec r5 §7.3) to hand to `upgrade()`'s `old`.
//! - [`convert_enum`]: **lossless** iff the old value's variant (by *name*,
//!   never by ordinal — spec r5 §7.3) still exists in the new schema with
//!   an identical payload arity/types. Otherwise **lossy**: a portable
//!   `{"$variant": name, "$payload": [...]}` map.

use std::rc::Rc;

use loom_compiler::ty::{ConstVal, EnumTy, StructTy, Ty};

use crate::bcvm::heap::{EnumVal, MapData, StructVal, Value};

/// The result of converting an old struct/enum value against a new schema.
#[derive(Debug)]
pub enum Migrated {
    /// The value (or an equivalent one under the new schema) is preserved
    /// exactly; no information was lost.
    Lossless(Value),
    /// The old value no longer matches; `portable` is what `upgrade()`'s
    /// `old` map should receive for this var/field instead (spec r5 §7.3).
    Lossy { portable: Value },
}

/// Does `v`'s *runtime shape* still match `ty`? Deeper than
/// `registry::value_conforms` (which only checks a struct/enum by name):
/// this recurses into containers and, for a nested struct/enum, requires
/// the same nominal identity (module + name) — it does not attempt a
/// nested by-name conversion, because a field either still holds a value
/// of its declared type or the containing struct is lossy for this field.
fn value_matches_ty(v: &Value, ty: &Ty) -> bool {
    match ty {
        Ty::Any => true,
        Ty::Optional(inner) => matches!(v, Value::Null) || value_matches_ty(v, inner),
        Ty::Null => matches!(v, Value::Null),
        Ty::Int => matches!(v, Value::Int(_)),
        Ty::Float => matches!(v, Value::Float(_)),
        Ty::Bool => matches!(v, Value::Bool(_)),
        Ty::String => v.as_str().is_some(),
        Ty::Object => matches!(v, Value::Object(_)),
        Ty::Array(elem) => v
            .as_array()
            .is_some_and(|a| a.iter().all(|e| value_matches_ty(e, elem))),
        Ty::Map(_, val_ty) => v
            .as_map()
            .is_some_and(|m| m.entries.iter().all(|(_, mv)| value_matches_ty(mv, val_ty))),
        Ty::Struct(s) => v.as_struct().is_some_and(|sv| sv.name == s.name),
        Ty::Enum(e) => v.as_enum().is_some_and(|ev| ev.name == e.name),
        Ty::Void | Ty::Never | Ty::Fn(_) | Ty::Error => false,
    }
}

/// A compile-time-constant default ([`ConstVal`]) turned into a runtime
/// [`Value`], for filling a field an old value never had.
pub fn const_to_value(c: &ConstVal) -> Value {
    match c {
        ConstVal::Null => Value::Null,
        ConstVal::Bool(b) => Value::Bool(*b),
        ConstVal::Int(n) => Value::Int(*n),
        ConstVal::Float(f) => Value::Float(*f),
        ConstVal::Str(s) => Value::str(s),
        ConstVal::Array(a) => Value::array(a.iter().map(const_to_value).collect()),
    }
}

/// The portable form of an *entire* old struct value (spec r5 §7.3):
/// `{field: value}`, every field the old value actually had, regardless of
/// whether any individual field still matches the new schema. This is what
/// `upgrade()`'s `old` map receives when [`convert_struct`] is lossy.
pub fn struct_portable(old: &StructVal) -> Value {
    let mut m = MapData::default();
    for (name, v) in &old.fields {
        m.insert(Value::str(name), v.clone());
    }
    Value::map(m)
}

/// The portable form of an enum value (spec r5 §7.3):
/// `{"$variant": name, "$payload": [...]}`.
pub fn enum_portable(old: &EnumVal) -> Value {
    let mut m = MapData::default();
    m.insert(Value::str("$variant"), Value::str(&old.variant));
    m.insert(Value::str("$payload"), Value::array(old.payload.clone()));
    Value::map(m)
}

/// By-name, lossless-or-portable struct conversion (spec r5 §7.3).
///
/// Every field `new` declares is looked up by name in `old`: if present and
/// its old value still matches the (possibly changed) declared type, that
/// value carries over; if absent, the field's default (if any) fills it.
/// Any field this cannot resolve makes the whole conversion lossy — the
/// struct is one unit, not a field-by-field patchwork, since a partially
/// migrated struct with a defaulted field the caller cannot tell apart from
/// a genuinely-set one is exactly the silent-data-loss spec r5 rules out.
pub fn convert_struct(old: &StructVal, new: &Rc<StructTy>) -> Migrated {
    let mut fields = Vec::with_capacity(new.fields.len());
    for f in &new.fields {
        match old.field(&f.name) {
            Some(v) if value_matches_ty(v, &f.ty) => fields.push((f.name.clone(), v.clone())),
            Some(_) => {
                return Migrated::Lossy {
                    portable: struct_portable(old),
                };
            }
            None => match &f.default {
                Some(c) => fields.push((f.name.clone(), const_to_value(c))),
                None => {
                    return Migrated::Lossy {
                        portable: struct_portable(old),
                    };
                }
            },
        }
    }
    Migrated::Lossless(Value::struct_val(StructVal {
        module: new.module.clone(),
        name: new.name.clone(),
        fields,
    }))
}

/// By-name, lossless-or-portable enum conversion (spec r5 §7.3). The old
/// value's variant is looked up **by name** in the new schema (never by
/// ordinal — a recompile that reorders variants must not relabel a live
/// value); it carries over iff the variant still exists with an identical
/// payload arity and every payload value still matches its (possibly
/// reordered-within-the-variant-list, but here positional-within-the-
/// variant) declared type.
pub fn convert_enum(old: &EnumVal, new: &Rc<EnumTy>) -> Migrated {
    let Some(variant) = new.variants.iter().find(|v| v.name == old.variant) else {
        return Migrated::Lossy {
            portable: enum_portable(old),
        };
    };
    if variant.payload.len() != old.payload.len()
        || !old
            .payload
            .iter()
            .zip(&variant.payload)
            .all(|(v, ty)| value_matches_ty(v, ty))
    {
        return Migrated::Lossy {
            portable: enum_portable(old),
        };
    }
    Migrated::Lossless(Value::enum_val(EnumVal {
        module: new.module.clone(),
        name: new.name.clone(),
        variant: variant.name.clone(),
        payload: old.payload.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_compiler::ty::{FieldTy, VariantTy};

    fn struct_ty(fields: Vec<FieldTy>) -> Rc<StructTy> {
        Rc::new(StructTy {
            module: Rc::from("/std/item"),
            name: Rc::from("Stats"),
            fields,
        })
    }

    fn field(name: &str, ty: Ty, default: Option<ConstVal>) -> FieldTy {
        FieldTy {
            name: Rc::from(name),
            ty,
            default,
        }
    }

    fn old_struct(fields: &[(&str, Value)]) -> StructVal {
        StructVal {
            module: Rc::from("/std/item"),
            name: Rc::from("Stats"),
            fields: fields
                .iter()
                .map(|(n, v)| (Rc::from(*n), v.clone()))
                .collect(),
        }
    }

    #[test]
    fn struct_carries_over_unchanged_fields_by_name() {
        let old = old_struct(&[("hp", Value::Int(10)), ("name", Value::str("orc"))]);
        // Field order reversed in the new schema: by-name, not positional.
        let new = struct_ty(vec![
            field("name", Ty::String, None),
            field("hp", Ty::Int, None),
        ]);
        match convert_struct(&old, &new) {
            Migrated::Lossless(v) => {
                let s = v.as_struct().unwrap();
                assert!(s.field("hp").unwrap().equals(&Value::Int(10)));
                assert!(s.field("name").unwrap().equals(&Value::str("orc")));
            }
            Migrated::Lossy { .. } => panic!("expected a lossless conversion"),
        }
    }

    #[test]
    fn struct_fills_an_added_field_from_its_default() {
        let old = old_struct(&[("hp", Value::Int(10))]);
        let new = struct_ty(vec![
            field("hp", Ty::Int, None),
            field("shield", Ty::Int, Some(ConstVal::Int(0))),
        ]);
        match convert_struct(&old, &new) {
            Migrated::Lossless(v) => {
                let s = v.as_struct().unwrap();
                assert!(s.field("shield").unwrap().equals(&Value::Int(0)));
            }
            Migrated::Lossy { .. } => panic!("expected the default to fill the new field"),
        }
    }

    #[test]
    fn struct_is_lossy_when_a_field_type_changed() {
        let old = old_struct(&[("hp", Value::Int(10))]);
        let new = struct_ty(vec![field("hp", Ty::String, None)]);
        match convert_struct(&old, &new) {
            Migrated::Lossy { portable } => {
                let m = portable.as_map().unwrap();
                assert!(m.get(&Value::str("hp")).unwrap().equals(&Value::Int(10)));
            }
            Migrated::Lossless(_) => panic!("a bool-typed field became int; must be lossy"),
        }
    }

    #[test]
    fn struct_is_lossy_when_a_required_field_has_no_value_or_default() {
        let old = old_struct(&[]);
        let new = struct_ty(vec![field("hp", Ty::Int, None)]);
        assert!(matches!(convert_struct(&old, &new), Migrated::Lossy { .. }));
    }

    fn enum_ty(variants: Vec<VariantTy>) -> Rc<EnumTy> {
        Rc::new(EnumTy {
            module: Rc::from("/std/combat"),
            name: Rc::from("DamageKind"),
            variants,
        })
    }

    fn variant(name: &str, payload: Vec<Ty>) -> VariantTy {
        VariantTy {
            name: Rc::from(name),
            payload,
        }
    }

    #[test]
    fn enum_carries_over_by_variant_name_even_when_the_variant_list_is_reordered() {
        let old = EnumVal {
            module: Rc::from("/std/combat"),
            name: Rc::from("DamageKind"),
            variant: Rc::from("Fire"),
            payload: vec![Value::Int(5)],
        };
        // `Fire` used to be declared first; now it is declared last. If
        // conversion ever compared by ordinal instead of by name, this
        // would silently turn into `Slash` (ordinal 0 in both lists) or
        // fail to find a match at all.
        let new = enum_ty(vec![
            variant("Slash", vec![]),
            variant("Fire", vec![Ty::Int]),
        ]);
        match convert_enum(&old, &new) {
            Migrated::Lossless(v) => {
                let e = v.as_enum().unwrap();
                assert_eq!(&*e.variant, "Fire", "must resolve by name, not ordinal");
                assert!(e.payload[0].equals(&Value::Int(5)));
            }
            Migrated::Lossy { .. } => panic!("expected the reordered variant to still resolve"),
        }
    }

    #[test]
    fn enum_is_lossy_when_its_variant_is_removed() {
        let old = EnumVal {
            module: Rc::from("/std/combat"),
            name: Rc::from("DamageKind"),
            variant: Rc::from("Poison"),
            payload: vec![],
        };
        let new = enum_ty(vec![variant("Slash", vec![])]);
        match convert_enum(&old, &new) {
            Migrated::Lossy { portable } => {
                let m = portable.as_map().unwrap();
                assert!(
                    m.get(&Value::str("$variant"))
                        .unwrap()
                        .equals(&Value::str("Poison"))
                );
            }
            Migrated::Lossless(_) => panic!("the variant no longer exists; must be lossy"),
        }
    }

    #[test]
    fn enum_is_lossy_when_the_payload_type_changed() {
        let old = EnumVal {
            module: Rc::from("/std/combat"),
            name: Rc::from("DamageKind"),
            variant: Rc::from("Fire"),
            payload: vec![Value::Int(5)],
        };
        let new = enum_ty(vec![variant("Fire", vec![Ty::String])]);
        assert!(matches!(convert_enum(&old, &new), Migrated::Lossy { .. }));
    }
}
