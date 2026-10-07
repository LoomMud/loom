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
        Ty::Map(key_ty, val_ty) => v.as_map().is_some_and(|m| {
            m.entries
                .iter()
                .all(|(k, mv)| value_matches_ty(k, key_ty) && value_matches_ty(mv, val_ty))
        }),
        // A nested struct/enum must match *structurally*, not just by name:
        // a field holding `Stats` whose own schema changed (e.g. `hp: int`
        // -> `hp: string`) would otherwise be carried over "losslessly"
        // with a stale shape. Same nominal identity (module + name), the
        // exact same field-name set, and every field value matching.
        Ty::Struct(s) => v.as_struct().is_some_and(|sv| {
            sv.module == s.module
                && sv.name == s.name
                && sv.fields.len() == s.fields.len()
                && s.fields.iter().all(|f| {
                    sv.field(&f.name)
                        .is_some_and(|fv| value_matches_ty(fv, &f.ty))
                })
        }),
        Ty::Enum(e) => v.as_enum().is_some_and(|ev| {
            ev.module == e.module
                && ev.name == e.name
                && e.variants.iter().any(|var| {
                    var.name == ev.variant
                        && var.payload.len() == ev.payload.len()
                        && ev
                            .payload
                            .iter()
                            .zip(&var.payload)
                            .all(|(pv, pt)| value_matches_ty(pv, pt))
                })
        }),
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

/// By-name, lossless-or-portable conversion of a **type-erased portable
/// value** (spec r5 §7.3: "restored saves" are the same portable form
/// `upgrade()`'s `old` map uses -- struct → `{field: value}`, enum →
/// `{"$variant": name, "$payload": [...]}`) against a *target* schema.
/// This is [`convert_struct`]/[`convert_enum`]'s sibling for
/// [`crate::persist::decode_value`]'s output (OBI-171 `restore_object`):
/// those two take an already-typed *old* runtime value and a *new*
/// schema; `hydrate` takes a plain portable `Value` (scalars/array/map,
/// with no struct/enum identity at all -- a save file was written by
/// some possibly-long-gone program version) and the *current* schema,
/// and tries to build a value that actually conforms to it.
///
/// Every branch mirrors [`value_matches_ty`]'s shape rules but builds a
/// [`Value`] instead of only checking one, and a struct/enum is still one
/// *unit* (lossy as a whole, not field-by-field) for the same silent-
/// data-loss reason [`convert_struct`]'s doc explains. Object-typed
/// fields/vars are always lossy: a live `ObjectId` from a previous driver
/// run cannot mean anything after a restart (spec: function values are
/// never saved, §5.2.2 rule 4; object references are the same kind of
/// not-meaningful-after-restart value, just not spelled out as its own
/// rule).
pub fn hydrate(portable: &Value, ty: &Ty) -> Migrated {
    let lossy = || Migrated::Lossy {
        portable: portable.clone(),
    };
    match ty {
        Ty::Any => Migrated::Lossless(portable.clone()),
        Ty::Optional(inner) => {
            if matches!(portable, Value::Null) {
                Migrated::Lossless(Value::Null)
            } else {
                hydrate(portable, inner)
            }
        }
        Ty::Null => {
            if matches!(portable, Value::Null) {
                Migrated::Lossless(Value::Null)
            } else {
                lossy()
            }
        }
        Ty::Int => match portable {
            Value::Int(n) => Migrated::Lossless(Value::Int(*n)),
            _ => lossy(),
        },
        Ty::Float => match portable {
            Value::Float(f) => Migrated::Lossless(Value::Float(*f)),
            _ => lossy(),
        },
        Ty::Bool => match portable {
            Value::Bool(b) => Migrated::Lossless(Value::Bool(*b)),
            _ => lossy(),
        },
        Ty::String => match portable.as_str() {
            Some(s) => Migrated::Lossless(Value::str(s)),
            None => lossy(),
        },
        // A restored object reference never means anything after a
        // restart (no instance this id named still exists) -- always
        // lossy, regardless of what `portable` happens to hold.
        Ty::Object => lossy(),
        Ty::Array(elem) => match portable.as_array() {
            Some(items) => {
                let mut out = Vec::with_capacity(items.len());
                for it in items {
                    match hydrate(it, elem) {
                        Migrated::Lossless(v) => out.push(v),
                        Migrated::Lossy { .. } => return lossy(),
                    }
                }
                Migrated::Lossless(Value::array(out))
            }
            None => lossy(),
        },
        Ty::Map(key_ty, val_ty) => match portable.as_map() {
            Some(m) => {
                let mut out = MapData::default();
                for (k, v) in &m.entries {
                    match (hydrate(k, key_ty), hydrate(v, val_ty)) {
                        (Migrated::Lossless(kk), Migrated::Lossless(vv)) => out.insert(kk, vv),
                        _ => return lossy(),
                    }
                }
                Migrated::Lossless(Value::map(out))
            }
            None => lossy(),
        },
        Ty::Struct(s) => {
            let Some(m) = portable.as_map() else {
                return lossy();
            };
            let mut fields = Vec::with_capacity(s.fields.len());
            for f in &s.fields {
                let found = m
                    .entries
                    .iter()
                    .find(|(k, _)| k.as_str() == Some(&*f.name))
                    .map(|(_, v)| v);
                match found {
                    Some(v) => match hydrate(v, &f.ty) {
                        Migrated::Lossless(vv) => fields.push((f.name.clone(), vv)),
                        Migrated::Lossy { .. } => return lossy(),
                    },
                    None => match &f.default {
                        Some(c) => fields.push((f.name.clone(), const_to_value(c))),
                        None => return lossy(),
                    },
                }
            }
            Migrated::Lossless(Value::struct_val(StructVal {
                module: s.module.clone(),
                name: s.name.clone(),
                fields,
            }))
        }
        Ty::Enum(e) => {
            let Some(m) = portable.as_map() else {
                return lossy();
            };
            let variant_name = m
                .entries
                .iter()
                .find(|(k, _)| k.as_str() == Some("$variant"))
                .and_then(|(_, v)| v.as_str());
            let payload = m
                .entries
                .iter()
                .find(|(k, _)| k.as_str() == Some("$payload"))
                .and_then(|(_, v)| v.as_array());
            let (Some(vname), Some(payload)) = (variant_name, payload) else {
                return lossy();
            };
            let Some(variant) = e.variants.iter().find(|v| &*v.name == vname) else {
                return lossy();
            };
            if variant.payload.len() != payload.len() {
                return lossy();
            }
            let mut out = Vec::with_capacity(payload.len());
            for (pv, pty) in payload.iter().zip(&variant.payload) {
                match hydrate(pv, pty) {
                    Migrated::Lossless(v) => out.push(v),
                    Migrated::Lossy { .. } => return lossy(),
                }
            }
            Migrated::Lossless(Value::enum_val(EnumVal {
                module: e.module.clone(),
                name: e.name.clone(),
                variant: Rc::from(vname),
                payload: out,
            }))
        }
        Ty::Void | Ty::Never | Ty::Fn(_) | Ty::Error => lossy(),
    }
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

    #[test]
    fn struct_is_lossy_when_a_nested_struct_schema_changed() {
        // `Loadout { stats: Stats }` where `Stats.hp` changed int -> string:
        // the outer field still *names* `Stats`, but the held value has the
        // old shape, so carrying it over would be silent data corruption.
        let inner_old = Value::struct_val(old_struct(&[("hp", Value::Int(10))]));
        let old = StructVal {
            module: Rc::from("/std/item"),
            name: Rc::from("Loadout"),
            fields: vec![(Rc::from("stats"), inner_old)],
        };
        let new_inner = struct_ty(vec![field("hp", Ty::String, None)]);
        let new = Rc::new(StructTy {
            module: Rc::from("/std/item"),
            name: Rc::from("Loadout"),
            fields: vec![field("stats", Ty::Struct(new_inner), None)],
        });
        assert!(matches!(convert_struct(&old, &new), Migrated::Lossy { .. }));
    }

    #[test]
    fn nested_struct_from_another_module_does_not_match() {
        let mut other = old_struct(&[("hp", Value::Int(1))]);
        other.module = Rc::from("/std/other");
        let ty = Ty::Struct(struct_ty(vec![field("hp", Ty::Int, None)]));
        assert!(!value_matches_ty(&Value::struct_val(other), &ty));
    }

    // --- `hydrate`: by-name conversion of a type-erased *portable* value
    // (what `crate::bcvm::persist::decode_value` hands back from a save
    // file) against the *current* schema (OBI-171). ---

    #[test]
    fn hydrate_scalars_from_portable() {
        assert!(matches!(
            hydrate(&Value::Int(5), &Ty::Int),
            Migrated::Lossless(Value::Int(5))
        ));
        assert!(matches!(
            hydrate(&Value::str("hi"), &Ty::String),
            Migrated::Lossless(v) if v.equals(&Value::str("hi"))
        ));
        assert!(matches!(
            hydrate(&Value::Int(5), &Ty::String),
            Migrated::Lossy { .. }
        ));
    }

    #[test]
    fn hydrate_null_into_optional_is_lossless() {
        assert!(matches!(
            hydrate(&Value::Null, &Ty::optional(Ty::Int)),
            Migrated::Lossless(Value::Null)
        ));
    }

    #[test]
    fn hydrate_object_typed_var_is_always_lossy() {
        // A restored object reference never means anything after a
        // restart, regardless of what the save file happened to hold.
        assert!(matches!(
            hydrate(&Value::Null, &Ty::Object),
            Migrated::Lossy { .. }
        ));
    }

    #[test]
    fn hydrate_struct_from_a_field_map_by_name() {
        let portable = Value::struct_val(old_struct(&[
            ("hp", Value::Int(10)),
            ("name", Value::str("orc")),
        ]));
        // `old_struct` built a `StructVal` directly; round it through the
        // same field-map shape a save file decodes to.
        let portable = struct_portable(portable.as_struct().unwrap());
        let new = Ty::Struct(struct_ty(vec![
            field("name", Ty::String, None),
            field("hp", Ty::Int, None),
        ]));
        match hydrate(&portable, &new) {
            Migrated::Lossless(v) => {
                let s = v.as_struct().unwrap();
                assert!(s.field("hp").unwrap().equals(&Value::Int(10)));
                assert!(s.field("name").unwrap().equals(&Value::str("orc")));
            }
            Migrated::Lossy { .. } => panic!("expected a lossless hydrate"),
        }
    }

    #[test]
    fn hydrate_struct_fills_an_added_field_from_its_default() {
        let portable = struct_portable(&old_struct(&[("hp", Value::Int(10))]));
        let new = Ty::Struct(struct_ty(vec![
            field("hp", Ty::Int, None),
            field("shield", Ty::Int, Some(ConstVal::Int(0))),
        ]));
        match hydrate(&portable, &new) {
            Migrated::Lossless(v) => {
                let s = v.as_struct().unwrap();
                assert!(s.field("shield").unwrap().equals(&Value::Int(0)));
            }
            Migrated::Lossy { .. } => panic!("expected the default to fill the new field"),
        }
    }

    #[test]
    fn hydrate_struct_is_lossy_when_a_field_type_changed() {
        let portable = struct_portable(&old_struct(&[("hp", Value::Int(10))]));
        let new = Ty::Struct(struct_ty(vec![field("hp", Ty::String, None)]));
        match hydrate(&portable, &new) {
            Migrated::Lossy { portable } => {
                let m = portable.as_map().unwrap();
                assert!(m.get(&Value::str("hp")).unwrap().equals(&Value::Int(10)));
            }
            Migrated::Lossless(_) => panic!("an int-typed field became string; must be lossy"),
        }
    }

    #[test]
    fn hydrate_enum_from_variant_and_payload_by_name() {
        let ev = EnumVal {
            module: Rc::from("/std/combat"),
            name: Rc::from("DamageKind"),
            variant: Rc::from("Fire"),
            payload: vec![Value::Int(5)],
        };
        let portable = enum_portable(&ev);
        let new = Ty::Enum(enum_ty(vec![
            variant("Slash", vec![]),
            variant("Fire", vec![Ty::Int]),
        ]));
        match hydrate(&portable, &new) {
            Migrated::Lossless(v) => {
                let e = v.as_enum().unwrap();
                assert_eq!(&*e.variant, "Fire");
                assert!(e.payload[0].equals(&Value::Int(5)));
            }
            Migrated::Lossy { .. } => panic!("expected the variant to resolve by name"),
        }
    }

    #[test]
    fn hydrate_enum_is_lossy_when_its_variant_was_removed() {
        let ev = EnumVal {
            module: Rc::from("/std/combat"),
            name: Rc::from("DamageKind"),
            variant: Rc::from("Poison"),
            payload: vec![],
        };
        let portable = enum_portable(&ev);
        let new = Ty::Enum(enum_ty(vec![variant("Slash", vec![])]));
        assert!(matches!(hydrate(&portable, &new), Migrated::Lossy { .. }));
    }

    #[test]
    fn hydrate_array_and_map_recurse_elementwise() {
        let portable = Value::array(vec![Value::Int(1), Value::Int(2)]);
        assert!(matches!(
            hydrate(&portable, &Ty::array(Ty::Int)),
            Migrated::Lossless(_)
        ));
        assert!(matches!(
            hydrate(&portable, &Ty::array(Ty::String)),
            Migrated::Lossy { .. }
        ));

        let mut m = MapData::default();
        m.insert(Value::str("a"), Value::Int(1));
        let portable = Value::map(m);
        assert!(matches!(
            hydrate(&portable, &Ty::map(Ty::String, Ty::Int)),
            Migrated::Lossless(_)
        ));
        assert!(matches!(
            hydrate(&portable, &Ty::map(Ty::String, Ty::String)),
            Migrated::Lossy { .. }
        ));
    }
}
