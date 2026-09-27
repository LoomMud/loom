// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Weft static types (spec §5.2) and the gradual assignability relation.
//!
//! The relation is *consistent subtyping* (Siek & Taha): `any` is consistent
//! with every type in both directions, `T` is a subtype of `T?`, and `null`
//! is a subtype of every `T?`. Containers are invariant up to `any`, because
//! arrays and maps have reference semantics (a `[string]` must not be
//! writable through a `[int]` alias). Wherever a value flows from `any` into a
//! more precise type the checker inserts an explicit [`crate::hir::ExprKind::Cast`]
//! so codegen emits the runtime check: that is the gradual boundary.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::rc::Rc;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Ty {
    Int,
    Float,
    Bool,
    String,
    /// A (non-null) object reference.
    Object,
    /// The type of the `null` literal.
    Null,
    /// Dynamic: checked at use.
    Any,
    /// "No value": the result of a function without `-> T`.
    Void,
    /// The type of an expression that never completes (reserved for `throw`,
    /// and used for error recovery in unreachable code).
    Never,
    Array(Rc<Ty>),
    Map(Rc<Ty>, Rc<Ty>),
    /// `T?`. Never nested, never wraps `any`/`null`/`void` (see [`Ty::optional`]).
    Optional(Rc<Ty>),
    Fn(Rc<FnTy>),
    /// A nominal `struct` (spec r5 §7.3, D27, [OBI-52]): fields carry their
    /// declared source order (positional layout for codegen/HIR), but see
    /// [`Ty::schema_hash`] for the order-independent identity hot reload
    /// compares across versions.
    ///
    /// [OBI-52]: /OBI/issues/OBI-52
    Struct(Rc<StructTy>),
    /// A nominal `enum`: see [`Ty::Struct`] for the schema-hash rationale.
    Enum(Rc<EnumTy>),
    /// Poison: an expression that already produced a diagnostic. Consistent
    /// with everything so one mistake reports once.
    Error,
}

/// `fn(A, B) -> R`: a closure or function-reference type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FnTy {
    pub params: Vec<Ty>,
    pub ret: Ty,
}

/// `[vis] struct Name { field: T [= default], … }` (spec r5 §7.3).
/// Identity for assignability/equality is *nominal*: two `StructTy`s are
/// the same type iff `module` + `name` + every field match (derived
/// `PartialEq`), which is exactly what changes between compiles of the
/// same declaration — see [`Ty::schema_hash`] for the hot-reload-facing
/// notion of "the same shape, maybe reordered".
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StructTy {
    /// Declaring program's path, e.g. `/std/item`.
    pub module: Rc<str>,
    pub name: Rc<str>,
    /// Declaration order (positional layout); [`Ty::schema_hash`] sorts by
    /// name internally so this order does not affect the hash.
    pub fields: Vec<FieldTy>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FieldTy {
    pub name: Rc<str>,
    pub ty: Ty,
    /// A compile-time-constant default (`= expr` where `expr` is a
    /// literal), used to fill this field when an older value being
    /// migrated does not have it (spec r5 §7.3 by-name struct conversion:
    /// "every added field has a default"). `None` means the field is
    /// mandatory at construction and has no fallback for migration.
    pub default: Option<ConstVal>,
}

/// `[vis] enum Name { A, B(int), … }`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EnumTy {
    pub module: Rc<str>,
    pub name: Rc<str>,
    /// Declaration order; [`Ty::schema_hash`] sorts by name internally.
    pub variants: Vec<VariantTy>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VariantTy {
    pub name: Rc<str>,
    /// Positional payload types; empty for a plain tag.
    pub payload: Vec<Ty>,
}

/// A compile-time-constant value: what a struct field's `= default` may be
/// (literals only, so migration can fill a missing field without running
/// any code — see [`FieldTy::default`]). Manual `Eq`/`Hash` because `f64`
/// has neither; two `ConstVal::Float`s compare/hash by bit pattern, which
/// is fine here (these are frozen source-literal defaults, never the
/// result of arithmetic that could produce distinct NaNs worth conflating).
#[derive(Clone, Debug)]
pub enum ConstVal {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(Rc<str>),
    Array(Rc<[ConstVal]>),
}

impl PartialEq for ConstVal {
    fn eq(&self, other: &Self) -> bool {
        use ConstVal::*;
        match (self, other) {
            (Null, Null) => true,
            (Bool(a), Bool(b)) => a == b,
            (Int(a), Int(b)) => a == b,
            (Float(a), Float(b)) => a.to_bits() == b.to_bits(),
            (Str(a), Str(b)) => a == b,
            (Array(a), Array(b)) => a == b,
            _ => false,
        }
    }
}
impl Eq for ConstVal {}
impl Hash for ConstVal {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            ConstVal::Null => {}
            ConstVal::Bool(b) => b.hash(state),
            ConstVal::Int(n) => n.hash(state),
            ConstVal::Float(f) => f.to_bits().hash(state),
            ConstVal::Str(s) => s.hash(state),
            ConstVal::Array(a) => a.iter().for_each(|c| c.hash(state)),
        }
    }
}

impl Ty {
    pub fn array(elem: Ty) -> Ty {
        Ty::Array(Rc::new(elem))
    }

    pub fn map(k: Ty, v: Ty) -> Ty {
        Ty::Map(Rc::new(k), Rc::new(v))
    }

    /// `T?`, normalised: `T??` = `T?`, `any?` = `any`, `null?` = `null`.
    pub fn optional(t: Ty) -> Ty {
        match t {
            Ty::Optional(_) | Ty::Any | Ty::Null | Ty::Error | Ty::Void => t,
            Ty::Never => Ty::Null,
            t => Ty::Optional(Rc::new(t)),
        }
    }

    /// True if `null` is a valid value of this type.
    pub fn is_nullable(&self) -> bool {
        matches!(self, Ty::Optional(_) | Ty::Null | Ty::Any | Ty::Error)
    }

    /// `T` for `T?`, otherwise the type itself.
    pub fn non_null(&self) -> Ty {
        match self {
            Ty::Optional(t) => (**t).clone(),
            t => t.clone(),
        }
    }

    pub fn is_dynamic(&self) -> bool {
        matches!(self, Ty::Any | Ty::Error)
    }

    /// Does not produce a diagnostic when used anywhere (any/poison/never).
    pub fn is_lenient(&self) -> bool {
        matches!(self, Ty::Any | Ty::Error | Ty::Never)
    }

    /// Can a value of type `self` be stored where `to` is expected?
    pub fn assignable_to(&self, to: &Ty) -> bool {
        use Ty::*;
        match (self, to) {
            (Error, _) | (_, Error) | (Never, _) => true,
            (Void, _) | (_, Void) => false,
            (Any, _) | (_, Any) => true,
            (Null, t) => t.is_nullable(),
            (Optional(a), Optional(b)) => a.assignable_to(b),
            (Optional(_), _) => false,
            (a, Optional(b)) => a.assignable_to(b),
            (Array(a), Array(b)) => a.consistent(b),
            (Map(ka, va), Map(kb, vb)) => ka.consistent(kb) && va.consistent(vb),
            (Fn(a), Fn(b)) => {
                a.params.len() == b.params.len()
                    && a.params
                        .iter()
                        .zip(&b.params)
                        .all(|(x, y)| y.assignable_to(x))
                    && a.ret.assignable_to(&b.ret)
            }
            (a, b) => a == b,
        }
    }

    /// Type consistency (`~`): equality up to `any`. Used for invariant
    /// positions (container elements).
    pub fn consistent(&self, other: &Ty) -> bool {
        use Ty::*;
        match (self, other) {
            (Error, _) | (_, Error) | (Any, _) | (_, Any) => true,
            (Array(a), Array(b)) | (Optional(a), Optional(b)) => a.consistent(b),
            (Map(ka, va), Map(kb, vb)) => ka.consistent(kb) && va.consistent(vb),
            (Fn(a), Fn(b)) => {
                a.params.len() == b.params.len()
                    && a.params.iter().zip(&b.params).all(|(x, y)| x.consistent(y))
                    && a.ret.consistent(&b.ret)
            }
            (a, b) => a == b,
        }
    }

    /// True when storing a `self` into a `to` needs a runtime check, i.e. the
    /// static type is less precise than the target (the gradual boundary).
    pub fn needs_cast_to(&self, to: &Ty) -> bool {
        match (self, to) {
            (Ty::Any, t) => !matches!(t, Ty::Any | Ty::Error),
            (Ty::Array(a), Ty::Array(b)) => **a == Ty::Any && **b != Ty::Any,
            (Ty::Map(ka, va), Ty::Map(kb, vb)) => {
                (**ka == Ty::Any && **kb != Ty::Any) || (**va == Ty::Any && **vb != Ty::Any)
            }
            (Ty::Optional(a), Ty::Optional(b)) => a.needs_cast_to(b),
            (a, Ty::Optional(b)) => a.needs_cast_to(b),
            _ => false,
        }
    }

    /// Least upper bound for branches/literal elements; `None` if the types
    /// have no common type other than `any` (the caller reports it).
    pub fn join(&self, other: &Ty) -> Option<Ty> {
        use Ty::*;
        match (self, other) {
            (Error, _) | (_, Error) => Some(Error),
            (Never, t) | (t, Never) => Some(t.clone()),
            (Any, _) | (_, Any) => Some(Any),
            (Null, t) | (t, Null) => Some(Ty::optional(t.clone())),
            (Optional(a), b) | (b, Optional(a)) => a.join(&b.non_null()).map(Ty::optional),
            (a, b) if a.assignable_to(b) && !a.needs_cast_to(b) => Some(b.clone()),
            (a, b) if b.assignable_to(a) && !b.needs_cast_to(a) => Some(a.clone()),
            _ => None,
        }
    }
}

impl fmt::Display for Ty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ty::Int => f.write_str("int"),
            Ty::Float => f.write_str("float"),
            Ty::Bool => f.write_str("bool"),
            Ty::String => f.write_str("string"),
            Ty::Object => f.write_str("object"),
            Ty::Null => f.write_str("null"),
            Ty::Any => f.write_str("any"),
            Ty::Void => f.write_str("no value"),
            Ty::Never => f.write_str("never"),
            Ty::Array(t) => write!(f, "[{t}]"),
            Ty::Map(k, v) => write!(f, "{{{k}: {v}}}"),
            Ty::Optional(t) => match **t {
                Ty::Fn(_) => write!(f, "({t})?"),
                _ => write!(f, "{t}?"),
            },
            Ty::Fn(ft) => {
                f.write_str("fn(")?;
                for (i, p) in ft.params.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{p}")?;
                }
                f.write_str(")")?;
                if ft.ret != Ty::Void {
                    write!(f, " -> {}", ft.ret)?;
                }
                Ok(())
            }
            Ty::Error => f.write_str("{error}"),
            Ty::Struct(s) => f.write_str(&s.name),
            Ty::Enum(e) => f.write_str(&e.name),
        }
    }
}

impl Ty {
    /// Recursive type schema hash (spec r5 §7.3, D27, [OBI-52]): stable
    /// under struct-field/enum-variant *reordering*, sensitive to any type
    /// change anywhere in the type's structure (including a nested
    /// struct/enum reached through an array/map/optional/fn type). Two
    /// `struct`/`enum` declarations that only reordered their
    /// fields/variants hash equal; changing a field's/variant's type, name,
    /// arity, or the type's own module+name changes the hash.
    ///
    /// [OBI-52]: /OBI/issues/OBI-52
    pub fn schema_hash(&self) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.hash_schema(&mut h);
        h.finish()
    }

    fn hash_schema(&self, h: &mut std::collections::hash_map::DefaultHasher) {
        // A leading discriminant tag keeps e.g. `Ty::Array(Ty::Int)` from
        // colliding with a differently-shaped type that happens to hash the
        // same parts in the same order.
        match self {
            Ty::Int => 0u8.hash(h),
            Ty::Float => 1u8.hash(h),
            Ty::Bool => 2u8.hash(h),
            Ty::String => 3u8.hash(h),
            Ty::Object => 4u8.hash(h),
            Ty::Null => 5u8.hash(h),
            Ty::Any => 6u8.hash(h),
            Ty::Void => 7u8.hash(h),
            Ty::Never => 8u8.hash(h),
            Ty::Error => 9u8.hash(h),
            Ty::Array(e) => {
                10u8.hash(h);
                e.hash_schema(h);
            }
            Ty::Map(k, v) => {
                11u8.hash(h);
                k.hash_schema(h);
                v.hash_schema(h);
            }
            Ty::Optional(t) => {
                12u8.hash(h);
                t.hash_schema(h);
            }
            Ty::Fn(ft) => {
                13u8.hash(h);
                ft.params.len().hash(h);
                for p in &ft.params {
                    p.hash_schema(h);
                }
                ft.ret.hash_schema(h);
            }
            Ty::Struct(s) => {
                20u8.hash(h);
                s.module.hash(h);
                s.name.hash(h);
                let mut fields: Vec<&FieldTy> = s.fields.iter().collect();
                fields.sort_by(|a, b| a.name.cmp(&b.name));
                fields.len().hash(h);
                for f in fields {
                    f.name.hash(h);
                    f.ty.hash_schema(h);
                }
            }
            Ty::Enum(e) => {
                21u8.hash(h);
                e.module.hash(h);
                e.name.hash(h);
                let mut variants: Vec<&VariantTy> = e.variants.iter().collect();
                variants.sort_by(|a, b| a.name.cmp(&b.name));
                variants.len().hash(h);
                for v in variants {
                    v.name.hash(h);
                    v.payload.len().hash(h);
                    for p in &v.payload {
                        p.hash_schema(h);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nullability() {
        let so = Ty::optional(Ty::String);
        assert!(Ty::String.assignable_to(&so));
        assert!(Ty::Null.assignable_to(&so));
        assert!(!so.assignable_to(&Ty::String));
        assert!(!Ty::Null.assignable_to(&Ty::Object));
        assert_eq!(Ty::optional(so.clone()), so);
        assert_eq!(Ty::optional(Ty::Any), Ty::Any);
    }

    #[test]
    fn any_is_consistent_both_ways() {
        assert!(Ty::Any.assignable_to(&Ty::Int));
        assert!(Ty::Int.assignable_to(&Ty::Any));
        assert!(Ty::Any.needs_cast_to(&Ty::Int));
        assert!(!Ty::Int.needs_cast_to(&Ty::Any));
        assert!(Ty::array(Ty::Any).assignable_to(&Ty::array(Ty::String)));
        assert!(Ty::array(Ty::Any).needs_cast_to(&Ty::array(Ty::String)));
    }

    #[test]
    fn containers_are_invariant() {
        let a = Ty::array(Ty::String);
        let b = Ty::array(Ty::optional(Ty::String));
        assert!(!a.assignable_to(&b));
        assert!(!b.assignable_to(&a));
        assert!(!Ty::map(Ty::String, Ty::Int).assignable_to(&Ty::map(Ty::String, Ty::Bool)));
    }

    #[test]
    fn fn_types_are_contravariant_in_params() {
        let takes_any = Ty::Fn(Rc::new(FnTy {
            params: vec![Ty::optional(Ty::Object)],
            ret: Ty::Int,
        }));
        let takes_obj = Ty::Fn(Rc::new(FnTy {
            params: vec![Ty::Object],
            ret: Ty::optional(Ty::Int),
        }));
        assert!(takes_any.assignable_to(&takes_obj));
        assert!(!takes_obj.assignable_to(&takes_any));
        assert_eq!(takes_obj.to_string(), "fn(object) -> int?");
    }

    #[test]
    fn joins() {
        assert_eq!(Ty::Int.join(&Ty::Null), Some(Ty::optional(Ty::Int)));
        assert_eq!(Ty::Int.join(&Ty::Int), Some(Ty::Int));
        assert_eq!(Ty::Int.join(&Ty::String), None);
        assert_eq!(
            Ty::optional(Ty::Int).join(&Ty::Int),
            Some(Ty::optional(Ty::Int))
        );
    }

    fn field(name: &str, ty: Ty) -> FieldTy {
        FieldTy {
            name: Rc::from(name),
            ty,
            default: None,
        }
    }

    fn variant(name: &str, payload: Vec<Ty>) -> VariantTy {
        VariantTy {
            name: Rc::from(name),
            payload,
        }
    }

    fn struct_ty(fields: Vec<FieldTy>) -> Ty {
        Ty::Struct(Rc::new(StructTy {
            module: Rc::from("/std/item"),
            name: Rc::from("Stats"),
            fields,
        }))
    }

    fn enum_ty(variants: Vec<VariantTy>) -> Ty {
        Ty::Enum(Rc::new(EnumTy {
            module: Rc::from("/std/combat"),
            name: Rc::from("DamageKind"),
            variants,
        }))
    }

    #[test]
    fn struct_schema_hash_is_stable_under_field_reorder() {
        let a = struct_ty(vec![field("hp", Ty::Int), field("name", Ty::String)]);
        let b = struct_ty(vec![field("name", Ty::String), field("hp", Ty::Int)]);
        assert_eq!(a.schema_hash(), b.schema_hash());
        // But the two `Ty`s are still distinct values (field order is the
        // codegen layout, not just cosmetic).
        assert_ne!(a, b);
    }

    #[test]
    fn struct_schema_hash_changes_with_a_field_type() {
        let a = struct_ty(vec![field("hp", Ty::Int)]);
        let b = struct_ty(vec![field("hp", Ty::Float)]);
        assert_ne!(a.schema_hash(), b.schema_hash());
    }

    #[test]
    fn struct_schema_hash_recurses_through_containers() {
        let inner_a = struct_ty(vec![field("hp", Ty::Int)]);
        let inner_b = struct_ty(vec![field("hp", Ty::Float)]);
        let outer_a = Ty::Struct(Rc::new(StructTy {
            module: Rc::from("/std/item"),
            name: Rc::from("Loadout"),
            fields: vec![field("stats", Ty::array(inner_a))],
        }));
        let outer_b = Ty::Struct(Rc::new(StructTy {
            module: Rc::from("/std/item"),
            name: Rc::from("Loadout"),
            fields: vec![field("stats", Ty::array(inner_b))],
        }));
        assert_ne!(
            outer_a.schema_hash(),
            outer_b.schema_hash(),
            "a change to a nested struct reached through `[T]` must change the outer hash"
        );
    }

    #[test]
    fn enum_schema_hash_is_stable_under_variant_reorder() {
        let a = enum_ty(vec![
            variant("Slash", vec![]),
            variant("Fire", vec![Ty::Int]),
        ]);
        let b = enum_ty(vec![
            variant("Fire", vec![Ty::Int]),
            variant("Slash", vec![]),
        ]);
        assert_eq!(a.schema_hash(), b.schema_hash());
    }

    #[test]
    fn enum_schema_hash_changes_with_a_variant_payload_type() {
        let a = enum_ty(vec![variant("Fire", vec![Ty::Int])]);
        let b = enum_ty(vec![variant("Fire", vec![Ty::Float])]);
        assert_ne!(a.schema_hash(), b.schema_hash());
    }
}
